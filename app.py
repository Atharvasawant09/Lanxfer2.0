from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
import os
import sqlite3
import uuid
import threading
import socket
import hashlib
import json
import qrcode
import base64
from io import BytesIO
from datetime import datetime, timedelta
from flask import redirect
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
    allow_upgrades=False        # disable WS upgrade — college WiFi blocks it
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
session_keys = {}   # { socket_sid: { key: bytes, ip: str } }

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
        ''')

def migrate_db():
    """Auto-migrate schema changes — safe to run on every startup."""
    with get_db() as conn:
        # Check if old 'encrypted_name' column exists, rename to 'storage_name'
        cols = [row[1] for row in conn.execute("PRAGMA table_info(files)").fetchall()]
        if 'encrypted_name' in cols and 'storage_name' not in cols:
            conn.execute("ALTER TABLE files RENAME COLUMN encrypted_name TO storage_name")
            print("[DB] Migrated: encrypted_name → storage_name")
        elif 'storage_name' not in cols:
            # Table exists but is missing the column entirely — recreate
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
migrate_db()   # ← add this line right after init_db()


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
        stale  = [ip for ip, info in list(browser_peers.items())  # ← list() copy
                  if info['last_seen'] < cutoff]
        for ip in stale:
            browser_peers.pop(ip, None)   # ← pop instead of del (safe)
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


@app.route('/qr_code')
def get_qr_code():
    """Generate QR code containing connection info for mobile pairing."""
    payload = f"https://{LOCAL_IP}:5000"

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=8,
        border=4
    )
    qr.add_data(payload)
    qr.make(fit=True)

    img = qr.make_image(fill_color="#00ff00", back_color="black")

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
        'connect_url': f"https://{LOCAL_IP}:5000"
    })



@app.route('/get_ips')
def get_ips():
    register_browser_peer(request.remote_addr)
    requester = request.remote_addr
    now       = datetime.now()
    result    = {}

    for ip, info in discovered_peers.items():
        if ip != requester:
            result[ip] = {
                'ip':          ip,
                'device_name': info['device_name'],
                'source':      'mdns'
            }

    for ip, info in browser_peers.items():
        age = (now - info['last_seen']).total_seconds()
        if ip != requester and age <= PEER_TIMEOUT_SECONDS and ip not in result:
            result[ip] = {
                'ip':          ip,
                'device_name': info['device_name'],
                'source':      'browser'
            }

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
        sort_key_map = {
            'name':     'original_name',
            'size':     'size',
            'modified': 'uploaded_at'
        }
        sort_key = sort_key_map.get(sort_by, 'original_name')
        reverse  = sort_order == 'desc'

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

@app.route('/favicon.ico')
def favicon():
    return '', 204

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

        # Generate ephemeral server P-256 keypair
        server_private   = generate_private_key(SECP256R1(), default_backend())
        server_public    = server_private.public_key()
        server_pub_bytes = server_public.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

        # Import client P-256 public key (65-byte uncompressed point)
        client_public = EllipticCurvePublicKey.from_encoded_point(
            SECP256R1(), client_pub_bytes
        )

        # ECDH shared secret
        shared_secret = server_private.exchange(ECDH(), client_public)

        # HKDF → 32-byte AES-256 session key
        salt        = os.urandom(16)
        session_key = derive_session_key(shared_secret, salt)

        session_keys[sid] = {'key': session_key, 'ip': client_ip}

        fingerprint = get_device_fingerprint(client_pub_bytes)
        trusted     = (
            client_ip in trust_store and
            trust_store[client_ip]['fingerprint'] == fingerprint
        )

        log_event('KEY_EXCHANGE', client_ip, f"fp={fingerprint} trusted={trusted}")
        print(f"[ECDH] Session key established with {client_ip} | fp={fingerprint} | trusted={trusted}")

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
                    (session_id, original_name, file_size,
                     total_chunks, sender_ip, recipient)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (session_id, original_name, file_size,
                  total_chunks, sender_ip, recipient))

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
            emit('chunk_error', {
                'chunk_index': chunk_index,
                'reason':      'no_session_key'
            })
            return

        key = session_keys[sid]['key']

        # AES-256-GCM decrypt
        try:
            plaintext = decrypt_chunk(key, nonce, ciphertext)
        except Exception as dec_err:
            emit('chunk_error', {
                'chunk_index': chunk_index,
                'reason':      'decryption_failed'
            })
            print(f"[WS] GCM decryption failed chunk {chunk_index}: {dec_err}")
            return

        # Verify plaintext integrity
        actual_hash = hashlib.sha256(plaintext).hexdigest()
        if actual_hash != expected_hash:
            emit('chunk_error', {
                'chunk_index': chunk_index,
                'reason':      'hash_mismatch'
            })
            print(f"[WS] Hash mismatch chunk {chunk_index} in {session_id}")
            return

        # Write plaintext chunk to disk
        chunk_path = os.path.join(CHUNKS_FOLDER, f"{session_id}_{chunk_index}.chunk")
        with open(chunk_path, 'wb') as f:
            f.write(plaintext)

        # Update DB
        with get_db() as conn:
            transfer = conn.execute(
                'SELECT * FROM transfers WHERE session_id = ?', (session_id,)
            ).fetchone()
            if not transfer:
                emit('chunk_error', {
                    'chunk_index': chunk_index,
                    'reason':      'session_not_found'
                })
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
        emit('chunk_error', {
            'chunk_index': data.get('chunk_index'),
            'reason':      str(e)
        })
        print(f"[WS] chunk error: {e}")

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
                if not os.path.exists(chunk_path):           # ← ADD THIS GUARD
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
        socketio.emit('transfer_error', {
            'session_id': session_id,
            'reason':     str(e)
        })

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

