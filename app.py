from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
import os
import sqlite3
import uuid
import threading
import socket
import hashlib
import json
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser

# ─────────────────────────────────────────────
# App Init
# ─────────────────────────────────────────────

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', max_http_buffer_size=500 * 1024 * 1024)

UPLOAD_FOLDER        = 'uploads'
CHUNKS_FOLDER        = 'chunks'
DB_DIR               = os.path.join(os.path.expanduser('~'), '.lanxfer')
DB_PATH              = os.path.join(DB_DIR, 'lanxfer.db')
CHUNK_SIZE           = 4 * 1024 * 1024   # 4 MB
PEER_TIMEOUT_SECONDS = 300               # 5 minutes

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Phase 1: static AES key — replaced in Phase 2 with ECDH
SECRET_KEY = b'ThisIsASecretKey1234567890123456'

for folder in [UPLOAD_FOLDER, CHUNKS_FOLDER, DB_DIR]:
    os.makedirs(folder, exist_ok=True)

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
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                original_name    TEXT    NOT NULL,
                encrypted_name   TEXT    NOT NULL UNIQUE,
                sender_ip        TEXT    NOT NULL,
                recipient        TEXT    NOT NULL DEFAULT 'Everyone',
                file_size        INTEGER,
                uploaded_at      TEXT    DEFAULT (datetime('now')),
                status           TEXT    DEFAULT 'complete'
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

init_db()

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def format_file_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"

def encrypt_file(input_path, output_path):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    iv     = cipher.iv
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    padded     = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded)
    with open(output_path, 'wb') as f:
        f.write(iv + ciphertext)

def log_event(event, ip=None, detail=None):
    try:
        with get_db() as conn:
            conn.execute(
                'INSERT INTO audit_log (event, ip, detail) VALUES (?, ?, ?)',
                (event, ip, detail)
            )
    except Exception as e:
        print(f"[audit] Error: {e}")

# ─────────────────────────────────────────────
# Peer Tracking (Hybrid: mDNS + Browser visit)
# ─────────────────────────────────────────────

discovered_peers = {}   # mDNS peers  { ip: { device_name, port, last_seen } }
browser_peers    = {}   # HTTP peers  { ip: { device_name, last_seen } }

def register_browser_peer(ip):
    """Register any device that opens the page or hits any route."""
    name = browser_peers.get(ip, {}).get('device_name', f"Device-{ip}")
    browser_peers[ip] = {
        'device_name': name,
        'last_seen':   datetime.now()
    }

def cleanup_browser_peers():
    """Remove browser peers that haven't been seen for PEER_TIMEOUT_SECONDS."""
    while True:
        cutoff = datetime.now() - timedelta(seconds=PEER_TIMEOUT_SECONDS)
        stale  = [ip for ip, info in browser_peers.items()
                  if info['last_seen'] < cutoff]
        for ip in stale:
            del browser_peers[ip]
            print(f"[Peers] Removed stale browser peer: {ip}")
        threading.Event().wait(60)

threading.Thread(target=cleanup_browser_peers, daemon=True).start()

# ─────────────────────────────────────────────
# mDNS Peer Discovery
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

        device_name = info.properties.get(b'device', b'Unknown').decode('utf-8', errors='replace')
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
        print(f"[mDNS] Failed to register: {e}")

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
    """Keep peer visible while page is open."""
    register_browser_peer(request.remote_addr)
    return jsonify({'status': 'ok', 'ip': request.remote_addr})

@app.route('/get_ips')
def get_ips():
    """Returns merged peer list: mDNS-discovered + browser-visited."""
    register_browser_peer(request.remote_addr)
    requester = request.remote_addr
    now       = datetime.now()
    result    = {}

    # mDNS peers (LANxfer-native)
    for ip, info in discovered_peers.items():
        if ip != requester:
            result[ip] = {
                'ip':          ip,
                'device_name': info['device_name'],
                'source':      'mdns'
            }

    # Browser peers (any device that opened the page)
    for ip, info in browser_peers.items():
        age = (now - info['last_seen']).total_seconds()
        if ip != requester and age <= PEER_TIMEOUT_SECONDS:
            if ip not in result:   # mDNS entry takes priority
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
            file_path = os.path.join(UPLOAD_FOLDER, f['encrypted_name'])
            if os.path.exists(file_path):
                result.append({
                    'name':          f['encrypted_name'],
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

@app.route('/upload', methods=['POST'])
def upload_file():
    """Legacy single-shot upload — fallback for Android browser."""
    sender = request.remote_addr
    register_browser_peer(sender)
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        recipient         = request.form.get('recipient', 'Everyone')
        original_filename = file.filename
        temp_path         = os.path.join(UPLOAD_FOLDER, f"temp_{uuid.uuid4().hex}")
        file.save(temp_path)

        encrypted_filename = f"{uuid.uuid4().hex}.enc"
        encrypted_path     = os.path.join(UPLOAD_FOLDER, encrypted_filename)
        encrypt_file(temp_path, encrypted_path)
        os.remove(temp_path)

        file_size = os.path.getsize(encrypted_path)

        with get_db() as conn:
            conn.execute('''
                INSERT INTO files
                    (original_name, encrypted_name, sender_ip, recipient, file_size)
                VALUES (?, ?, ?, ?, ?)
            ''', (original_filename, encrypted_filename, sender, recipient, file_size))

        log_event('FILE_UPLOAD', sender, f"{original_filename} → {recipient}")
        return jsonify({
            'message': 'File uploaded successfully!',
            'file': {
                'original_name': original_filename,
                'size_fmt':      format_file_size(file_size)
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    user_ip = request.remote_addr
    register_browser_peer(user_ip)
    with get_db() as conn:
        file_info = conn.execute(
            'SELECT * FROM files WHERE encrypted_name = ?', (filename,)
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
        download_name=filename,
        mimetype='application/octet-stream'
    )

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
# WebSocket — Chunked Transfer Protocol
# ─────────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    register_browser_peer(request.remote_addr)
    print(f"[WS] Client connected: {request.remote_addr}")
    emit('server_info', {
        'device_name': DEVICE_NAME,
        'ip':          LOCAL_IP,
        'version':     '2.0'
    })

@socketio.on('disconnect')
def handle_disconnect():
    print(f"[WS] Client disconnected: {request.remote_addr}")

@socketio.on('transfer_init')
def handle_transfer_init(data):
    try:
        session_id    = data.get('session_id') or uuid.uuid4().hex
        original_name = data['original_name']
        file_size     = int(data['file_size'])
        total_chunks  = int(data['total_chunks'])
        recipient     = data.get('recipient', 'Everyone')
        sender_ip     = request.remote_addr

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
        session_id    = data['session_id']
        chunk_index   = int(data['chunk_index'])
        chunk_bytes   = bytes(data['chunk_data'])
        expected_hash = data['chunk_hash']

        # Integrity check
        actual_hash = hashlib.sha256(chunk_bytes).hexdigest()
        if actual_hash != expected_hash:
            emit('chunk_error', {
                'chunk_index': chunk_index,
                'reason':      'hash_mismatch',
                'expected':    expected_hash,
                'actual':      actual_hash
            })
            print(f"[WS] Hash mismatch chunk {chunk_index} in {session_id}")
            return

        # Write chunk to disk
        chunk_path = os.path.join(CHUNKS_FOLDER, f"{session_id}_{chunk_index}.chunk")
        with open(chunk_path, 'wb') as f:
            f.write(chunk_bytes)

        # Update DB
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
        print(f"[WS] Chunk {chunk_index + 1}/{total} OK — session {session_id}")

        if len(received) == total:
            assemble_file(session_id, dict(transfer))

    except Exception as e:
        emit('chunk_error', {'chunk_index': data.get('chunk_index'), 'reason': str(e)})
        print(f"[WS] chunk error: {e}")

def assemble_file(session_id, transfer):
    try:
        total_chunks  = transfer['total_chunks']
        original_name = transfer['original_name']
        recipient     = transfer['recipient']
        sender_ip     = transfer['sender_ip']

        temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{session_id}")
        with open(temp_path, 'wb') as outfile:
            for i in range(total_chunks):
                chunk_path = os.path.join(CHUNKS_FOLDER, f"{session_id}_{i}.chunk")
                with open(chunk_path, 'rb') as cf:
                    outfile.write(cf.read())
                os.remove(chunk_path)

        encrypted_filename = f"{uuid.uuid4().hex}.enc"
        encrypted_path     = os.path.join(UPLOAD_FOLDER, encrypted_filename)
        encrypt_file(temp_path, encrypted_path)
        os.remove(temp_path)

        file_size = os.path.getsize(encrypted_path)

        with get_db() as conn:
            conn.execute('''
                INSERT INTO files
                    (original_name, encrypted_name, sender_ip, recipient, file_size)
                VALUES (?, ?, ?, ?, ?)
            ''', (original_name, encrypted_filename, sender_ip, recipient, file_size))
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
    print(f"[LANxfer 2.0] Running on http://{LOCAL_IP}:5000")
    print(f"[LANxfer 2.0] Device name: {DEVICE_NAME}")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)
