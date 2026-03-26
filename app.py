from flask import Flask, render_template, request, jsonify, send_file, Response
from flask_socketio import SocketIO, emit
import os
import io
import sqlite3
import uuid
import threading
import socket
import hashlib
import json
import csv
import qrcode
import base64
from io import BytesIO
from dateutil import parser as dateparser
from datetime import datetime, timedelta
from delta import (
    generate_signature, signature_to_bytes, signature_from_bytes,
    compute_delta, delta_to_bytes, delta_from_bytes,
    apply_delta, delta_stats
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, generate_private_key, SECP256R1, EllipticCurvePublicKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser

# ─────────────────────────────────────────────
# App Init
# ─────────────────────────────────────────────

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='eventlet',
    max_http_buffer_size=500 * 1024 * 1024,
    allow_upgrades=False
)

UPLOAD_FOLDER        = 'uploads'
CHUNKS_FOLDER        = 'chunks'
DB_DIR               = os.path.join(os.path.expanduser('~'), '.lanxfer')
DB_PATH              = os.path.join(DB_DIR, 'lanxfer.db')
TRUST_STORE_PATH     = os.path.join(DB_DIR, 'trusted_devices.json')
CHUNK_SIZE           = 4 * 1024 * 1024
PEER_TIMEOUT_SECONDS = 300

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

for folder in [UPLOAD_FOLDER, CHUNKS_FOLDER, DB_DIR]:
    os.makedirs(folder, exist_ok=True)

# ─────────────────────────────────────────────
# Trust Store
# ─────────────────────────────────────────────

def load_trust_store():
    if os.path.exists(TRUST_STORE_PATH):
        with open(TRUST_STORE_PATH, 'r') as f:
            return json.load(f)
    return {}

def save_trust_store(store):
    with open(TRUST_STORE_PATH, 'w') as f:
        json.dump(store, f, indent=2)

def get_device_fingerprint(public_key_bytes: bytes) -> str:
    digest = hashlib.sha256(public_key_bytes).hexdigest()
    return ':'.join(digest[i:i+4] for i in range(0, 32, 4))

trust_store  = load_trust_store()
session_keys = {}

# ─────────────────────────────────────────────
# SQLite
# ─────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS files (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                original_name  TEXT    NOT NULL,
                storage_name   TEXT    NOT NULL UNIQUE,
                sender_ip      TEXT    NOT NULL,
                recipient      TEXT    NOT NULL DEFAULT 'Everyone',
                file_size      INTEGER,
                uploaded_at    TEXT    DEFAULT (datetime('now')),
                status         TEXT    DEFAULT 'complete'
            );

            CREATE TABLE IF NOT EXISTS transfers (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id       TEXT    UNIQUE NOT NULL,
                original_name    TEXT    NOT NULL,
                file_size        INTEGER NOT NULL,
                total_chunks     INTEGER NOT NULL,
                chunks_received  TEXT    DEFAULT '[]',
                sender_ip        TEXT,
                recipient        TEXT    DEFAULT 'Everyone',
                status           TEXT    DEFAULT 'in_progress',
                started_at       TEXT    DEFAULT (datetime('now')),
                completed_at     TEXT
            );

            CREATE TABLE IF NOT EXISTS peers (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL UNIQUE,
                device_name TEXT,
                port        INTEGER DEFAULT 5000,
                last_seen   TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT DEFAULT (datetime('now')),
                event     TEXT NOT NULL,
                ip        TEXT,
                detail    TEXT
            );

            CREATE TABLE IF NOT EXISTS clipboard_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_ip    TEXT    NOT NULL,
            recipient    TEXT    NOT NULL DEFAULT 'Everyone',
            content_type TEXT    NOT NULL DEFAULT 'text',
            preview      TEXT,
            size_bytes   INTEGER,
            sent_at      TEXT    DEFAULT (datetime('now'))
            );

        ''')

def migrate_db():
    with get_db() as conn:
        cols = [row[1] for row in conn.execute("PRAGMA table_info(files)").fetchall()]
        if 'encrypted_name' in cols and 'storage_name' not in cols:
            conn.execute("ALTER TABLE files RENAME COLUMN encrypted_name TO storage_name")
            print("[DB] Migrated: encrypted_name → storage_name")
        elif 'storage_name' not in cols:
            conn.execute("DROP TABLE IF EXISTS files")
            conn.executescript('''
                CREATE TABLE files (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_name  TEXT    NOT NULL,
                    storage_name   TEXT    NOT NULL UNIQUE,
                    sender_ip      TEXT    NOT NULL,
                    recipient      TEXT    NOT NULL DEFAULT 'Everyone',
                    file_size      INTEGER,
                    uploaded_at    TEXT    DEFAULT (datetime('now')),
                    status         TEXT    DEFAULT 'complete'
                );
            ''')
            print("[DB] Recreated files table with correct schema")

init_db()
migrate_db()

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def format_file_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"

def log_event(event, ip=None, detail=None):
    try:
        with get_db() as conn:
            conn.execute(
                'INSERT INTO audit_log (event, ip, detail) VALUES (?, ?, ?)',
                (event, ip, detail)
            )
    except Exception as e:
        print(f"[audit] Error: {e}")

def derive_session_key(shared_secret: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'lanxfer-v2-session',
        backend=default_backend()
    ).derive(shared_secret)

def decrypt_chunk(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, None)

# ─────────────────────────────────────────────
# Peer Tracking
# ─────────────────────────────────────────────

discovered_peers = {}
browser_peers    = {}

def register_browser_peer(ip):
    name = browser_peers.get(ip, {}).get('device_name', f"Device-{ip}")
    browser_peers[ip] = {'device_name': name, 'last_seen': datetime.now()}

def cleanup_browser_peers():
    while True:
        cutoff = datetime.now() - timedelta(seconds=PEER_TIMEOUT_SECONDS)
        stale  = [ip for ip, info in list(browser_peers.items())
                  if info['last_seen'] < cutoff]
        for ip in stale:
            browser_peers.pop(ip, None)
        threading.Event().wait(60)

threading.Thread(target=cleanup_browser_peers, daemon=True).start()

# ─────────────────────────────────────────────
# mDNS
# ─────────────────────────────────────────────

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

LOCAL_IP    = get_local_ip()
DEVICE_NAME = socket.gethostname()

class LANxferListener:
    def add_service(self, zc, service_type, name):
        info = zc.get_service_info(service_type, name)
        if not info:
            return
        try:
            peer_ip = info.parsed_addresses()[0]
        except Exception:
            return
        if peer_ip == LOCAL_IP:
            return
        device_name = info.properties.get(
            b'device', b'Unknown'
        ).decode('utf-8', errors='replace')
        discovered_peers[peer_ip] = {
            'device_name': device_name,
            'port':        info.port,
            'last_seen':   datetime.now().isoformat()
        }
        try:
            with get_db() as conn:
                conn.execute('''
                    INSERT INTO peers (ip, device_name, port, last_seen)
                    VALUES (?, ?, ?, datetime('now'))
                    ON CONFLICT(ip) DO UPDATE SET
                        device_name = excluded.device_name,
                        last_seen   = datetime('now')
                ''', (peer_ip, device_name, info.port))
        except Exception as e:
            print(f"[mDNS] DB error: {e}")
        print(f"[mDNS] Discovered: {device_name} @ {peer_ip}:{info.port}")

    def remove_service(self, zc, service_type, name):
        pass

    def update_service(self, zc, service_type, name):
        self.add_service(zc, service_type, name)

def register_mdns():
    try:
        zc   = Zeroconf()
        info = ServiceInfo(
            "_lanxfer._tcp.local.",
            f"{DEVICE_NAME}._lanxfer._tcp.local.",
            addresses=[socket.inet_aton(LOCAL_IP)],
            port=5000,
            properties={
                b'version': b'2.0',
                b'device':  DEVICE_NAME.encode('utf-8')
            }
        )
        zc.register_service(info)
        ServiceBrowser(zc, "_lanxfer._tcp.local.", LANxferListener())
        print(f"[mDNS] Registered as '{DEVICE_NAME}' at {LOCAL_IP}:5000")
    except Exception as e:
        print(f"[mDNS] Failed: {e}")

threading.Thread(target=register_mdns, daemon=True).start()

# ─────────────────────────────────────────────
# HTTP Routes
# ─────────────────────────────────────────────

@app.route('/')
def index():
    register_browser_peer(request.remote_addr)
    log_event('PAGE_VISIT', request.remote_addr)
    return render_template('index.html')

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    register_browser_peer(request.remote_addr)
    return jsonify({'status': 'ok', 'ip': request.remote_addr})

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/qr_code')
def get_qr_code():
    connect_url = f"https://{LOCAL_IP}:5000"
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=8,
        border=4
    )
    qr.add_data(connect_url)
    qr.make(fit=True)
    img    = qr.make_image(fill_color="#00ff00", back_color="black")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    log_event('QR_GENERATED', request.remote_addr)
    return jsonify({
        'qr_image':    f"data:image/png;base64,{img_b64}",
        'ip':          LOCAL_IP,
        'port':        5000,
        'device_name': DEVICE_NAME,
        'connect_url': connect_url
    })

@app.route('/get_ips')
def get_ips():
    register_browser_peer(request.remote_addr)
    requester = request.remote_addr
    now       = datetime.now()
    result    = {}
    for ip, info in discovered_peers.items():
        if ip != requester:
            result[ip] = {'ip': ip, 'device_name': info['device_name'], 'source': 'mdns'}
    for ip, info in browser_peers.items():
        age = (now - info['last_seen']).total_seconds()
        if ip != requester and age <= PEER_TIMEOUT_SECONDS and ip not in result:
            result[ip] = {'ip': ip, 'device_name': info['device_name'], 'source': 'browser'}
    return jsonify(list(result.values()))

@app.route('/get_files')
def get_files():
    user_ip = request.remote_addr
    register_browser_peer(user_ip)
    log_event('LIST_FILES', user_ip)
    try:
        with get_db() as conn:
            rows = conn.execute('''
                SELECT * FROM files
                WHERE recipient = 'Everyone' OR recipient = ?
                ORDER BY uploaded_at DESC
            ''', (user_ip,)).fetchall()

        sort_by      = request.args.get('sort', 'name')
        sort_order   = request.args.get('order', 'asc')
        sort_key_map = {'name': 'original_name', 'size': 'size', 'modified': 'uploaded_at'}
        sort_key     = sort_key_map.get(sort_by, 'original_name')
        reverse      = sort_order == 'desc'

        result = []
        for f in rows:
            file_path = os.path.join(UPLOAD_FOLDER, f['storage_name'])
            if os.path.exists(file_path):
                result.append({
                    'name':          f['storage_name'],
                    'original_name': f['original_name'],
                    'size':          f['file_size'] or 0,
                    'size_fmt':      format_file_size(f['file_size'] or 0),
                    'uploaded_at':   f['uploaded_at'],
                    'modified_fmt':  f['uploaded_at']
                })

        result.sort(key=lambda x: x.get(sort_key, ''), reverse=reverse)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    user_ip = request.remote_addr
    register_browser_peer(user_ip)
    with get_db() as conn:
        file_info = conn.execute(
            'SELECT * FROM files WHERE storage_name = ?', (filename,)
        ).fetchone()
    if not file_info:
        return jsonify({'error': 'File not found'}), 404
    if file_info['recipient'] != 'Everyone' and file_info['recipient'] != user_ip:
        log_event('ACCESS_DENIED', user_ip, filename)
        return jsonify({'error': 'Access denied'}), 403
    log_event('FILE_DOWNLOAD', user_ip, filename)
    return send_file(
        os.path.join(UPLOAD_FOLDER, filename),
        as_attachment=True,
        download_name=file_info['original_name'],
        mimetype='application/octet-stream'
    )

@app.route('/trust_device', methods=['POST'])
def trust_device():
    data        = request.json
    ip          = data.get('ip')
    fingerprint = data.get('fingerprint')
    device_name = data.get('device_name', f"Device-{ip}")
    if not ip or not fingerprint:
        return jsonify({'error': 'ip and fingerprint required'}), 400
    trust_store[ip] = {
        'fingerprint': fingerprint,
        'device_name': device_name,
        'trusted_at':  datetime.now().isoformat()
    }
    save_trust_store(trust_store)
    log_event('DEVICE_TRUSTED', ip, fingerprint)
    return jsonify({'status': 'trusted', 'ip': ip})

@app.route('/revoke_device', methods=['POST'])
def revoke_device():
    ip = request.json.get('ip')
    if ip in trust_store:
        del trust_store[ip]
        save_trust_store(trust_store)
        log_event('DEVICE_REVOKED', ip)
    return jsonify({'status': 'revoked'})

@app.route('/trust_store', methods=['GET'])
def get_trust_store():
    return jsonify(trust_store)

@app.route('/audit_log')
def get_audit_log():
    with get_db() as conn:
        logs = conn.execute(
            'SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 200'
        ).fetchall()
    return jsonify([dict(row) for row in logs])

@app.route('/transfers')
def get_transfers():
    with get_db() as conn:
        rows = conn.execute(
            'SELECT * FROM transfers ORDER BY started_at DESC LIMIT 100'
        ).fetchall()
    return jsonify([dict(row) for row in rows])

@app.route('/history')
def history_page():
    return render_template('history.html')

@app.route('/clipboard/history')
def get_clipboard_history():
    user_ip = request.remote_addr
    with get_db() as conn:
        rows = conn.execute('''
            SELECT * FROM clipboard_history
            WHERE recipient = 'Everyone' OR recipient = ? OR sender_ip = ?
            ORDER BY sent_at DESC LIMIT 50
        ''', (user_ip, user_ip)).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route('/api/history')
def get_history():
    try:
        page      = max(1, int(request.args.get('page', 1)))
        per_page  = min(100, int(request.args.get('per_page', 20)))
        status    = request.args.get('status', '').strip()
        peer      = request.args.get('peer', '').strip()
        search    = request.args.get('search', '').strip()
        date_from = request.args.get('date_from', '').strip()
        date_to   = request.args.get('date_to', '').strip()
        export    = request.args.get('export', '').strip()

        conditions, params = [], []
        if status:    conditions.append('t.status = ?');           params.append(status)
        if peer:      conditions.append('t.sender_ip LIKE ?');     params.append(f'%{peer}%')
        if search:    conditions.append('t.original_name LIKE ?'); params.append(f'%{search}%')
        if date_from: conditions.append('t.started_at >= ?');      params.append(date_from)
        if date_to:   conditions.append('t.started_at <= ?');      params.append(date_to + ' 23:59:59')

        where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''

        duration_sql = '''CASE WHEN t.completed_at IS NOT NULL
            THEN ROUND((JULIANDAY(t.completed_at) - JULIANDAY(t.started_at)) * 86400, 2)
            ELSE NULL END AS duration_seconds'''

        with get_db() as conn:
            total = conn.execute(
                f'SELECT COUNT(*) FROM transfers t {where}', params
            ).fetchone()[0]
            rows = conn.execute(f'''
                SELECT t.session_id, t.original_name, t.file_size, t.total_chunks,
                       t.chunks_received, t.sender_ip, t.recipient, t.status,
                       t.started_at, t.completed_at, {duration_sql}
                FROM transfers t {where}
                ORDER BY t.started_at DESC
                LIMIT ? OFFSET ?
            ''', params + [per_page, (page - 1) * per_page]).fetchall()

        def build_row(r):
            chunks_done = len(json.loads(r['chunks_received'] or '[]'))
            total_c     = r['total_chunks'] or 1
            dur         = r['duration_seconds']
            sz          = r['file_size'] or 0
            return {
                'session_id':       r['session_id'],
                'original_name':    r['original_name'],
                'file_size':        sz,
                'file_size_fmt':    format_file_size(sz),
                'sender_ip':        r['sender_ip'] or '—',
                'recipient':        r['recipient'] or 'Everyone',
                'status':           r['status'],
                'progress':         round((chunks_done / total_c) * 100),
                'started_at':       r['started_at'],
                'completed_at':     r['completed_at'] or '—',
                'duration_seconds': dur,
                'duration_fmt':     f"{dur:.1f}s" if dur else '—',
                'speed_fmt':        format_file_size(int(sz / dur)) + '/s' if dur and dur > 0 else '—'
            }

        result = [build_row(r) for r in rows]

        if export == 'csv':
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=[
                'session_id', 'original_name', 'file_size_fmt', 'sender_ip',
                'recipient', 'status', 'progress', 'started_at',
                'completed_at', 'duration_fmt', 'speed_fmt'
            ])
            writer.writeheader()
            with get_db() as conn:
                all_rows = conn.execute(f'''
                    SELECT t.*, {duration_sql} FROM transfers t {where}
                    ORDER BY t.started_at DESC
                ''', params).fetchall()
            for r in all_rows:
                row = build_row(r)
                writer.writerow({k: row[k] for k in writer.fieldnames})
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition':
                    f'attachment; filename=lanxfer_history_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
            )

        return jsonify({
            'transfers':  result,
            'pagination': {
                'page':        page,
                'per_page':    per_page,
                'total':       total,
                'total_pages': max(1, -(-total // per_page))
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─────────────────────────────────────────────
# Delta Sync Routes
# ─────────────────────────────────────────────

def find_existing_file(original_name):
    """
    Find most recent stored file matching original_name.
    Searches ALL recipients — not just 'Everyone'.
    """
    with get_db() as conn:
        row = conn.execute('''
            SELECT storage_name, file_size FROM files
            WHERE original_name = ?
            ORDER BY uploaded_at DESC LIMIT 1
        ''', (original_name,)).fetchone()
    if not row:
        return None, None
    path = os.path.join(UPLOAD_FOLDER, row['storage_name'])
    return (path, row['storage_name']) if os.path.exists(path) else (None, None)

@app.route('/delta/check', methods=['POST'])
def delta_check():
    data          = request.json
    original_name = data.get('original_name', '')
    client_hash   = data.get('file_hash', '')

    existing_path, storage_name = find_existing_file(original_name)
    if not existing_path:
        return jsonify({'exists': False})

    sha256 = hashlib.sha256()
    with open(existing_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha256.update(chunk)

    if sha256.hexdigest() == client_hash:
        return jsonify({'exists': True, 'storage_name': storage_name, 'match': True})

    return jsonify({'exists': True, 'storage_name': storage_name, 'match': False})

@app.route('/delta/signature/<storage_name>', methods=['GET'])
def delta_signature(storage_name):
    user_ip = request.remote_addr
    with get_db() as conn:
        row = conn.execute(
            'SELECT * FROM files WHERE storage_name = ?', (storage_name,)
        ).fetchone()
    if not row:
        return jsonify({'error': 'File not found'}), 404
    if row['recipient'] != 'Everyone' and row['recipient'] != user_ip:
        return jsonify({'error': 'Access denied'}), 403

    file_path = os.path.join(UPLOAD_FOLDER, storage_name)
    if not os.path.exists(file_path):
        return jsonify({'error': 'File missing'}), 404

    try:
        sig       = generate_signature(file_path)
        sig_bytes = signature_to_bytes(sig)
        log_event('DELTA_SIGNATURE', user_ip, storage_name)
        return send_file(
            io.BytesIO(sig_bytes),          # ← io.BytesIO now works (import io at top)
            as_attachment=True,
            download_name='signature.sig',
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delta/apply', methods=['POST'])
def delta_apply():
    sender_ip     = request.remote_addr
    new_temp_path = None
    try:
        storage_name  = request.form.get('storage_name')
        original_name = request.form.get('original_name')
        recipient     = request.form.get('recipient', 'Everyone')
        client_hash   = request.form.get('file_hash', '')

        if not storage_name or not original_name:
            return jsonify({'error': 'storage_name and original_name required'}), 400

        base_path = os.path.join(UPLOAD_FOLDER, storage_name)
        if not os.path.exists(base_path):
            return jsonify({'error': 'Base file not found'}), 404

        if 'new_file' not in request.files:
            return jsonify({'error': 'new_file missing'}), 400

        new_file      = request.files['new_file']
        new_temp_path = os.path.join(CHUNKS_FOLDER, f"{uuid.uuid4().hex}_new")
        new_file.save(new_temp_path)

        # Verify hash of received file
        sha256 = hashlib.sha256()
        with open(new_temp_path, 'rb') as f:
            for block in iter(lambda: f.read(65536), b''):
                sha256.update(block)
        actual_hash = sha256.hexdigest()

        if client_hash and actual_hash != client_hash:
            return jsonify({'error': 'Hash mismatch — file corrupted in transit'}), 400

        base_size    = os.path.getsize(base_path)
        new_size     = os.path.getsize(new_temp_path)
        sig          = generate_signature(base_path)
        instructions = compute_delta(new_temp_path, sig)
        stats        = delta_stats(instructions, new_size)

        new_storage_name = f"{uuid.uuid4().hex}_{original_name}"
        new_storage_path = os.path.join(UPLOAD_FOLDER, new_storage_name)
        os.rename(new_temp_path, new_storage_path)
        new_temp_path = None

        with get_db() as conn:
            conn.execute('''
                INSERT INTO files
                    (original_name, storage_name, sender_ip, recipient, file_size)
                VALUES (?, ?, ?, ?, ?)
            ''', (original_name, new_storage_name, sender_ip, recipient, new_size))

        log_event('DELTA_APPLY', sender_ip,
                  f"{original_name} | saved={stats['savings_pct']}%")
        print(f"[Delta] {original_name}: base={format_file_size(base_size)} "
              f"new={format_file_size(new_size)} "
              f"delta={format_file_size(stats['delta_size'])} "
              f"saved={stats['savings_pct']}%")

        return jsonify({
            'status':       'applied',
            'storage_name': new_storage_name,
            'file_size':    format_file_size(new_size),
            'delta_size':   stats['delta_size'],
            'savings_pct':  stats['savings_pct']
        })

    except Exception as e:
        print(f"[Delta] apply error: {e}")
        if new_temp_path and os.path.exists(new_temp_path):
            os.remove(new_temp_path)
        return jsonify({'error': str(e)}), 500

# ─────────────────────────────────────────────
# WebSocket Handlers
# ─────────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    register_browser_peer(request.remote_addr)
    print(f"[WS] Client connected: {request.remote_addr}")
    emit('server_info', {
        'device_name': DEVICE_NAME,
        'ip':          LOCAL_IP,
        'version':     '2.0',
        'security':    'ECDH-P256+AES-256-GCM'
    })

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in session_keys:
        del session_keys[sid]
    print(f"[WS] Client disconnected: {request.remote_addr}")

@socketio.on('key_exchange')
def handle_key_exchange(data):
    try:
        client_pub_bytes = bytes.fromhex(data['client_public_key'])
        client_ip        = request.remote_addr
        sid              = request.sid

        server_private   = generate_private_key(SECP256R1(), default_backend())
        server_public    = server_private.public_key()
        server_pub_bytes = server_public.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        client_public  = EllipticCurvePublicKey.from_encoded_point(SECP256R1(), client_pub_bytes)
        shared_secret  = server_private.exchange(ECDH(), client_public)
        salt           = os.urandom(16)
        session_key    = derive_session_key(shared_secret, salt)
        session_keys[sid] = {'key': session_key, 'ip': client_ip}

        fingerprint = get_device_fingerprint(client_pub_bytes)
        trusted     = (
            client_ip in trust_store and
            trust_store[client_ip]['fingerprint'] == fingerprint
        )

        log_event('KEY_EXCHANGE', client_ip, f"fp={fingerprint} trusted={trusted}")
        print(f"[ECDH] Key established with {client_ip} | fp={fingerprint} | trusted={trusted}")

        emit('key_exchange_reply', {
            'server_public_key': server_pub_bytes.hex(),
            'salt':              salt.hex(),
            'fingerprint':       fingerprint,
            'trusted':           trusted,
            'device_name':       DEVICE_NAME
        })

    except Exception as e:
        emit('key_exchange_error', {'reason': str(e)})
        print(f"[ECDH] key_exchange error: {e}")

@socketio.on('transfer_init')
def handle_transfer_init(data):
    try:
        sid           = request.sid
        session_id    = data.get('session_id') or uuid.uuid4().hex
        original_name = data['original_name']
        file_size     = int(data['file_size'])
        total_chunks  = int(data['total_chunks'])
        recipient     = data.get('recipient', 'Everyone')
        sender_ip     = request.remote_addr

        if sid not in session_keys:
            emit('transfer_error', {'reason': 'key_exchange_required'})
            return

        with get_db() as conn:
            existing = conn.execute(
                'SELECT * FROM transfers WHERE session_id = ?', (session_id,)
            ).fetchone()

            if existing and existing['status'] == 'in_progress':
                received = json.loads(existing['chunks_received'])
                missing  = [i for i in range(total_chunks) if i not in received]
                emit('transfer_ready', {
                    'session_id':     session_id,
                    'missing_chunks': missing,
                    'resume':         True
                })
                print(f"[WS] Resuming {session_id}: {len(missing)} chunks left")
                return

            conn.execute('''
                INSERT OR REPLACE INTO transfers
                    (session_id, original_name, file_size, total_chunks, sender_ip, recipient)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (session_id, original_name, file_size, total_chunks, sender_ip, recipient))

        log_event('TRANSFER_INIT', sender_ip, f"{original_name} | {total_chunks} chunks")
        emit('transfer_ready', {
            'session_id':     session_id,
            'missing_chunks': list(range(total_chunks)),
            'resume':         False
        })
        print(f"[WS] New transfer {session_id}: {original_name} ({total_chunks} chunks)")

    except Exception as e:
        emit('transfer_error', {'reason': str(e)})
        print(f"[WS] transfer_init error: {e}")

@socketio.on('transfer_chunk')
def handle_chunk(data):
    try:
        sid           = request.sid
        session_id    = data['session_id']
        chunk_index   = int(data['chunk_index'])
        nonce         = bytes.fromhex(data['nonce'])
        ciphertext    = bytes(data['ciphertext'])
        expected_hash = data['chunk_hash']

        if sid not in session_keys:
            emit('chunk_error', {'chunk_index': chunk_index, 'reason': 'no_session_key'})
            return

        key = session_keys[sid]['key']

        try:
            plaintext = decrypt_chunk(key, nonce, ciphertext)
        except Exception as dec_err:
            emit('chunk_error', {'chunk_index': chunk_index, 'reason': 'decryption_failed'})
            print(f"[WS] GCM decryption failed chunk {chunk_index}: {dec_err}")
            return

        actual_hash = hashlib.sha256(plaintext).hexdigest()
        if actual_hash != expected_hash:
            emit('chunk_error', {'chunk_index': chunk_index, 'reason': 'hash_mismatch'})
            print(f"[WS] Hash mismatch chunk {chunk_index} in {session_id}")
            return

        chunk_path = os.path.join(CHUNKS_FOLDER, f"{session_id}_{chunk_index}.chunk")
        with open(chunk_path, 'wb') as f:
            f.write(plaintext)

        with get_db() as conn:
            transfer = conn.execute(
                'SELECT * FROM transfers WHERE session_id = ?', (session_id,)
            ).fetchone()
            if not transfer:
                emit('chunk_error', {'chunk_index': chunk_index, 'reason': 'session_not_found'})
                return
            received = json.loads(transfer['chunks_received'])
            if chunk_index not in received:
                received.append(chunk_index)
            conn.execute(
                'UPDATE transfers SET chunks_received = ? WHERE session_id = ?',
                (json.dumps(received), session_id)
            )
            total = transfer['total_chunks']

        emit('chunk_ack', {
            'chunk_index': chunk_index,
            'received':    len(received),
            'total':       total
        })
        print(f"[WS] Chunk {chunk_index + 1}/{total} decrypted OK — {session_id}")

        if len(received) == total:
            assemble_file(session_id, dict(transfer))

    except Exception as e:
        emit('chunk_error', {'chunk_index': data.get('chunk_index'), 'reason': str(e)})
        print(f"[WS] chunk error: {e}")

@socketio.on('clipboard_send')
def handle_clipboard_send(data):
    try:
        sender_ip    = request.remote_addr
        sid          = request.sid
        recipient    = data.get('recipient', 'Everyone')
        content_type = data.get('content_type', 'text')
        preview      = data.get('preview', '')[:80]
        size_bytes   = data.get('size_bytes', 0)

        if sid not in session_keys:
            emit('clipboard_error', {'reason': 'key_exchange_required'})
            return

        # ── Step 1: Decrypt with sender's session key ──
        sender_key = session_keys[sid]['key']
        try:
            nonce_bytes = bytes.fromhex(data['nonce'])
            ct_bytes    = bytes(data['ciphertext'])
            plaintext   = AESGCM(sender_key).decrypt(nonce_bytes, ct_bytes, None)
        except Exception as e:
            emit('clipboard_error', {'reason': f'server_decrypt_failed: {e}'})
            print(f"[Clipboard] Sender decrypt failed: {e}")
            return

        # ── Step 2: Log metadata (plaintext never stored) ──
        with get_db() as conn:
            conn.execute('''
                INSERT INTO clipboard_history
                    (sender_ip, recipient, content_type, preview, size_bytes)
                VALUES (?, ?, ?, ?, ?)
            ''', (sender_ip, recipient, content_type, preview, size_bytes))

        log_event('CLIPBOARD_SEND', sender_ip,
                  f"type={content_type} size={size_bytes} → {recipient}")

        # ── Step 3: Find recipient SID(s) and re-encrypt per recipient ──
        def reencrypt_and_forward(target_sid, target_info):
            """Re-encrypt plaintext with the target's own session key."""
            target_key  = target_info['key']
            new_nonce   = os.urandom(12)
            new_ct      = AESGCM(target_key).encrypt(new_nonce, plaintext, None)
            payload = {
                'from_ip':      sender_ip,
                'from_device':  DEVICE_NAME,
                'content_type': content_type,
                'nonce':        new_nonce.hex(),
                'ciphertext':   list(new_ct),
                'size_bytes':   size_bytes,
                'preview':      preview
            }
            socketio.emit('clipboard_receive', payload, to=target_sid)
            print(f"[Clipboard] Re-encrypted {content_type} ({size_bytes}B) "
                  f"→ {target_info['ip']} (sid={target_sid})")

        sent = False

        if recipient == 'Everyone':
            for s_id, info in list(session_keys.items()):
                if s_id != sid:
                    reencrypt_and_forward(s_id, info)
                    sent = True
        else:
            for s_id, info in list(session_keys.items()):
                if info['ip'] == recipient and s_id != sid:
                    reencrypt_and_forward(s_id, info)
                    sent = True

        if not sent and recipient != 'Everyone':
            emit('clipboard_error', {
                'reason': f'recipient {recipient} not connected'
            })
            return

        emit('clipboard_sent', {
            'status':       'delivered',
            'content_type': content_type,
            'size_bytes':   size_bytes
        })

    except Exception as e:
        emit('clipboard_error', {'reason': str(e)})
        print(f"[Clipboard] Error: {e}")


def assemble_file(session_id, transfer):
    try:
        total_chunks  = transfer['total_chunks']
        original_name = transfer['original_name']
        recipient     = transfer['recipient']
        sender_ip     = transfer['sender_ip']

        storage_name = f"{uuid.uuid4().hex}_{original_name}"
        storage_path = os.path.join(UPLOAD_FOLDER, storage_name)

        with open(storage_path, 'wb') as outfile:
            for i in range(total_chunks):
                chunk_path = os.path.join(CHUNKS_FOLDER, f"{session_id}_{i}.chunk")
                if not os.path.exists(chunk_path):
                    raise FileNotFoundError(f"Missing chunk {i} for {session_id}")
                with open(chunk_path, 'rb') as cf:
                    outfile.write(cf.read())
                os.remove(chunk_path)

        file_size = os.path.getsize(storage_path)

        with get_db() as conn:
            conn.execute('''
                INSERT INTO files
                    (original_name, storage_name, sender_ip, recipient, file_size)
                VALUES (?, ?, ?, ?, ?)
            ''', (original_name, storage_name, sender_ip, recipient, file_size))
            conn.execute('''
                UPDATE transfers
                SET status       = 'complete',
                    completed_at = datetime('now')
                WHERE session_id = ?
            ''', (session_id,))

        log_event('TRANSFER_COMPLETE', sender_ip, f"{original_name} → {recipient}")
        print(f"[WS] Complete: {original_name} ({format_file_size(file_size)})")

        socketio.emit('transfer_complete', {
            'session_id':    session_id,
            'original_name': original_name,
            'file_size':     format_file_size(file_size)
        })

    except Exception as e:
        print(f"[WS] assemble_file error: {e}")
        socketio.emit('transfer_error', {'session_id': session_id, 'reason': str(e)})

# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

if __name__ == '__main__':
    print(f"[LANxfer 2.0] Running on https://{LOCAL_IP}:5000")
    print(f"[LANxfer 2.0] Device: {DEVICE_NAME}")
    print(f"[LANxfer 2.0] Security: ECDH-P256 + AES-256-GCM")
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=True,
        use_reloader=False,
        certfile='cert.pem',
        keyfile='key.pem'
    )
