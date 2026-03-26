// ─────────────────────────────────────────────
// Constants & State
// ─────────────────────────────────────────────

const CHUNK_SIZE = 4 * 1024 * 1024;

let currentSort             = { column: 'name', direction: 'asc' };
let activeTransfers         = {};
let sessionKey              = null;
let deviceFingerprint       = null;
let clientKeyPair           = null;
let DEVICE_NAME_FROM_SERVER = '';

// ─────────────────────────────────────────────
// Socket.IO
// ─────────────────────────────────────────────

const socket = io(window.__SOCKET_OPTS || {});

socket.on('connect', () => {
    console.log('[WS] Connected via', socket.io.engine.transport.name);
    setTimeout(() => initKeyExchange(), 300);
});

socket.on('disconnect', () => {
    sessionKey = null;
    console.log('[WS] Disconnected');
    updateSecurityStatus('🔴 Disconnected', 'error');
});

socket.on('server_info', (info) => {
    DEVICE_NAME_FROM_SERVER = info.device_name;
    console.log(`[WS] Server: ${info.device_name} @ ${info.ip} v${info.version} | ${info.security}`);
});

socket.on('transfer_complete', (data) => {
    const { session_id, original_name, file_size } = data;
    const progressWrapper = document.querySelector('.progress-wrapper');
    const progressBar     = document.querySelector('.progress-bar');
    const progressText    = document.querySelector('.progress-text');

    progressBar.style.width      = '100%';
    progressText.textContent     = 'Complete!';
    progressBar.style.background = 'linear-gradient(90deg, #33ff33, #00ffaa)';

    setTimeout(() => {
        progressWrapper.style.display = 'none';
        progressBar.style.width       = '0%';
        progressBar.style.background  = 'linear-gradient(90deg, #33ff33, #00ff00)';
        progressText.textContent      = '0%';
        alert(`✅ ${original_name} transferred successfully! (${file_size})`);
        fetchFiles();
        document.getElementById('selectedFile').style.display = 'none';
        document.getElementById('fileInput').value            = '';
        document.getElementById('recipientSelect').value      = 'Everyone';
    }, 1000);

    delete activeTransfers[session_id];
});

socket.on('transfer_error', (data) => {
    console.error('[WS] Transfer error:', data);
    alert(`Transfer failed: ${data.reason}`);
    const progressWrapper = document.querySelector('.progress-wrapper');
    if (progressWrapper) progressWrapper.style.display = 'none';
});

socket.on('chunk_error', (data) => {
    console.error(`[WS] Chunk ${data.chunk_index} error: ${data.reason}`);
    if (data.reason === 'hash_mismatch' || data.reason === 'decryption_failed') {
        const transfer = Object.values(activeTransfers)[0];
        if (transfer) retryChunk(transfer, data.chunk_index);
    }
});

socket.on('key_exchange_reply', async (data) => {
    try {
        const serverPubRaw = hexToBuffer(data.server_public_key);
        const salt         = hexToBuffer(data.salt);
        deviceFingerprint  = data.fingerprint;

        const serverPubKey = await crypto.subtle.importKey(
            'raw', serverPubRaw,
            { name: 'ECDH', namedCurve: 'P-256' },
            false, []
        );

        const sharedBits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: serverPubKey },
            clientKeyPair.privateKey, 256
        );

        const hkdfKey = await crypto.subtle.importKey(
            'raw', sharedBits, 'HKDF', false, ['deriveKey']
        );

        sessionKey = await crypto.subtle.deriveKey(
            {
                name: 'HKDF', hash: 'SHA-256',
                salt: salt,
                info: new TextEncoder().encode('lanxfer-v2-session')
            },
            hkdfKey,
            { name: 'AES-GCM', length: 256 },
            false, ['encrypt', 'decrypt']
        );

        console.log(`[ECDH] Session key derived | fingerprint: ${deviceFingerprint}`);

        const trustKey       = `lanxfer_trusted_${data.device_name}`;
        const alreadyTrusted = localStorage.getItem(trustKey) === 'yes';

        if (alreadyTrusted || data.trusted) {
            localStorage.setItem(trustKey, 'yes');
            updateSecurityStatus(`🔒 Trusted | ${deviceFingerprint}`, 'secure');
        } else {
            showFingerprintDialog(deviceFingerprint, data.device_name);
        }

    } catch (e) {
        console.error('[ECDH] Key derivation failed:', e);
        updateSecurityStatus('⚠️ Key derivation failed', 'error');
    }
});

socket.on('key_exchange_error', (data) => {
    console.error('[ECDH] Server error:', data.reason);
    updateSecurityStatus('⚠️ Key exchange error: ' + data.reason, 'error');
});

// ─────────────────────────────────────────────
// ECDH Key Exchange
// ─────────────────────────────────────────────

async function initKeyExchange() {
    try {
        clientKeyPair = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true, ['deriveKey', 'deriveBits']
        );
        const pubKeyRaw = await crypto.subtle.exportKey('raw', clientKeyPair.publicKey);
        const pubKeyHex = bufferToHex(pubKeyRaw);
        console.log('[ECDH] P-256 keypair generated, sending to server...');
        updateSecurityStatus('🔑 Performing key exchange...', 'pending');
        socket.emit('key_exchange', { client_public_key: pubKeyHex });
    } catch (e) {
        console.error('[ECDH] Key generation failed:', e);
        updateSecurityStatus('⚠️ Key generation failed: ' + e.message, 'error');
    }
}

// ─────────────────────────────────────────────
// Security Status UI
// ─────────────────────────────────────────────

function updateSecurityStatus(message, state) {
    const el = document.getElementById('securityStatus');
    if (!el) return;
    el.textContent = message;
    el.className   = `security-status ${state}`;
}

function showFingerprintDialog(fingerprint, deviceName) {
    const dialog = document.getElementById('fingerprintDialog');
    const fpEl   = document.getElementById('fingerprintValue');
    const nameEl = document.getElementById('fingerprintDeviceName');
    if (!dialog) return;
    fpEl.textContent   = fingerprint;
    nameEl.textContent = deviceName;
    dialog.style.display = 'flex';
}

function trustDevice() {
    const dialog = document.getElementById('fingerprintDialog');
    if (dialog) dialog.style.display = 'none';
    const trustKey = `lanxfer_trusted_${DEVICE_NAME_FROM_SERVER}`;
    localStorage.setItem(trustKey, 'yes');
    fetch('/trust_device', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
            ip:          window.location.hostname,
            fingerprint: deviceFingerprint,
            device_name: DEVICE_NAME_FROM_SERVER || 'Server'
        })
    })
    .then(() => {
        updateSecurityStatus(`🔒 Trusted | ${deviceFingerprint}`, 'secure');
        console.log('[Trust] Device trusted and saved');
    })
    .catch(err => console.error('[Trust] Failed:', err));
}

function denyDevice() {
    const dialog = document.getElementById('fingerprintDialog');
    if (dialog) dialog.style.display = 'none';
    updateSecurityStatus('⛔ Connection untrusted — uploads blocked', 'untrusted');
    console.warn('[Trust] Device denied — sessionKey cleared');
    sessionKey = null;
}

// ─────────────────────────────────────────────
// DOM Ready
// ─────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {
    const dropZone  = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');

    fileInput.addEventListener('change', function (e) {
        handleFileSelect(e.target.files[0]);
    });

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    ['dragenter', 'dragover'].forEach(e => dropZone.addEventListener(e, highlight,   false));
    ['dragleave', 'drop'].forEach(e =>     dropZone.addEventListener(e, unhighlight, false));
    dropZone.addEventListener('drop', handleDrop, false);

    document.querySelectorAll('th.sortable').forEach(header => {
        header.addEventListener('click', () => {
            const column = header.dataset.sort;
            if (currentSort.column === column) {
                currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
            } else {
                currentSort.column    = column;
                currentSort.direction = 'asc';
            }
            document.querySelectorAll('th.sortable').forEach(th => {
                th.classList.remove('asc', 'desc');
            });
            header.classList.add(currentSort.direction);
            fetchFiles();
        });
    });

    fetchFiles();
    fetchIPs();
    setInterval(fetchIPs, 10000);
    setInterval(() => {
        fetch('/heartbeat', { method: 'POST' }).catch(() => {});
    }, 30000);

    const qrModal = document.getElementById('qrModal');
    if (qrModal) {
        qrModal.addEventListener('click', function (e) {
            if (e.target === this) closeQRModal();
        });
    }
});

// ─────────────────────────────────────────────
// Drag & Drop
// ─────────────────────────────────────────────

function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }
function highlight()   { document.getElementById('dropZone').classList.add('drag-over'); }
function unhighlight() { document.getElementById('dropZone').classList.remove('drag-over'); }
function handleDrop(e) { handleFileSelect(e.dataTransfer.files[0]); }

function handleFileSelect(file) {
    if (!file) return;
    const dt = new DataTransfer();
    dt.items.add(file);
    document.getElementById('fileInput').files = dt.files;
    const div         = document.getElementById('selectedFile');
    div.style.display = 'block';
    div.textContent   = `Selected: ${file.name} (${formatSize(file.size)})`;
}

function formatSize(bytes) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
    return `${bytes.toFixed(1)} ${units[i]}`;
}

// ─────────────────────────────────────────────
// AES-256-GCM Chunk Encryption
// ─────────────────────────────────────────────

async function encryptChunk(plaintext) {
    if (!sessionKey) throw new Error('No session key — key exchange incomplete');
    const nonce      = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce }, sessionKey, plaintext
    );
    return { nonce, ciphertext: new Uint8Array(ciphertext) };
}

// ─────────────────────────────────────────────
// Upload — Delta-aware entry point
// ─────────────────────────────────────────────

function uploadFile() {
    const fileInput       = document.getElementById('fileInput');
    const recipientSelect = document.getElementById('recipientSelect');
    const progressWrapper = document.querySelector('.progress-wrapper');
    const progressBar     = document.querySelector('.progress-bar');
    const progressText    = document.querySelector('.progress-text');

    const file      = fileInput.files[0];
    const recipient = recipientSelect.value || 'Everyone';

    if (!file)       { alert('Please select a file first.'); return; }
    if (!sessionKey) { alert('Security handshake not complete. Please wait.'); return; }

    progressWrapper.style.display = 'block';
    progressText.textContent      = '⚙️ Checking...';
    progressBar.style.width       = '0%';

    console.log(`[Delta] Hashing file: ${file.name} (${file.size} bytes)`);

    hashFile(file).then(fileHash => {
        console.log(`[Delta] Hash: ${fileHash.slice(0, 16)}...`);

        fetch('/delta/check', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ original_name: file.name, file_hash: fileHash })
        })
        .then(r => {
            console.log(`[Delta] /delta/check HTTP ${r.status}`);
            return r.json();
        })
        .then(check => {
            console.log('[Delta] check result:', check);

            if (check.match) {
                // ── Identical file — skip entirely ──
                progressBar.style.width  = '100%';
                progressText.textContent = '✅ Already up to date!';
                setTimeout(() => {
                    progressWrapper.style.display = 'none';
                    progressText.textContent      = '0%';
                    progressBar.style.width       = '0%';
                    alert(`✅ "${file.name}" is already up to date — no transfer needed!`);
                    fetchFiles();
                    document.getElementById('selectedFile').style.display = 'none';
                    document.getElementById('fileInput').value            = '';
                }, 1500);
                return;
            }

            if (check.exists && !check.match) {
                // ── Previous version exists — delta transfer ──
                console.log(`[Delta] Previous version found: ${check.storage_name}`);
                progressText.textContent = '📡 Fetching signature...';
                attemptDeltaTransfer(
                    file, fileHash, check.storage_name, recipient,
                    progressBar, progressText, progressWrapper
                );
            } else {
                // ── No previous version — full WebSocket transfer ──
                console.log('[Delta] No previous version — full transfer');
                progressText.textContent = '0%';
                doFullTransfer(file, recipient, progressBar, progressText, progressWrapper);
            }
        })
        .catch(err => {
            console.error('[Delta] /delta/check failed:', err);
            progressText.textContent = '0%';
            doFullTransfer(file, recipient, progressBar, progressText, progressWrapper);
        });
    }).catch(err => {
        console.error('[Delta] hashFile failed:', err);
        progressText.textContent = '0%';
        doFullTransfer(file, recipient, progressBar, progressText, progressWrapper);
    });
}

// ─────────────────────────────────────────────
// Hash entire file incrementally (no full memory load)
// ─────────────────────────────────────────────

async function hashFile(file) {
    const CHUNK = 4 * 1024 * 1024;
    let wordArray = CryptoJS.lib.WordArray.create([]);
    let offset    = 0;
    while (offset < file.size) {
        const buf  = await file.slice(offset, offset + CHUNK).arrayBuffer();
        wordArray  = wordArray.concat(CryptoJS.lib.WordArray.create(new Uint8Array(buf)));
        offset    += CHUNK;
    }
    return CryptoJS.SHA256(wordArray).toString(CryptoJS.enc.Hex);
}

// ─────────────────────────────────────────────
// Delta Transfer — send new file via HTTP multipart
// Server handles signature + delta computation
// ─────────────────────────────────────────────

async function attemptDeltaTransfer(file, fileHash, storageName, recipient,
                                     progressBar, progressText, progressWrapper) {
    try {
        progressText.textContent = '📤 Sending delta...';

        const formData = new FormData();
        formData.append('new_file',      file);
        formData.append('storage_name',  storageName);
        formData.append('original_name', file.name);
        formData.append('recipient',     recipient);
        formData.append('file_hash',     fileHash);

        await new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/delta/apply');

            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const pct = Math.round((e.loaded / e.total) * 100);
                    progressBar.style.width  = `${pct}%`;
                    progressText.textContent = `📤 ${pct}%`;
                }
            };

            xhr.onload = () => {
                if (xhr.status === 200) {
                    const resp = JSON.parse(xhr.responseText);
                    progressBar.style.width      = '100%';
                    progressText.textContent     = '✅ Delta applied!';
                    progressBar.style.background = 'linear-gradient(90deg, #00ffff, #0088ff)';
                    setTimeout(() => {
                        progressWrapper.style.display = 'none';
                        progressBar.style.width       = '0%';
                        progressBar.style.background  = 'linear-gradient(90deg, #33ff33, #00ff00)';
                        progressText.textContent      = '0%';
                        alert(`⚡ Delta sync complete!\n"${file.name}" updated (${resp.file_size})\nBandwidth saved: ~${resp.savings_pct}%`);
                        fetchFiles();
                        document.getElementById('selectedFile').style.display = 'none';
                        document.getElementById('fileInput').value            = '';
                    }, 1000);
                    resolve();
                } else {
                    reject(new Error(`Server error ${xhr.status}: ${xhr.responseText}`));
                }
            };

            xhr.onerror = () => reject(new Error('Network error during delta upload'));
            xhr.send(formData);
        });

    } catch (err) {
        console.warn(`[Delta] Failed (${err.message}) — falling back to full transfer`);
        progressBar.style.background = 'linear-gradient(90deg, #33ff33, #00ff00)';
        progressText.textContent     = '0%';
        doFullTransfer(file, recipient, progressBar, progressText, progressWrapper);
    }
}

// ─────────────────────────────────────────────
// Full WebSocket Transfer (unchanged from Phase 2)
// ─────────────────────────────────────────────

function doFullTransfer(file, recipient, progressBar, progressText, progressWrapper) {
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

    const sessionId = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });

    activeTransfers[sessionId] = { file, totalChunks, sessionId };

    socket.emit('transfer_init', {
        session_id:    sessionId,
        original_name: file.name,
        file_size:     file.size,
        total_chunks:  totalChunks,
        recipient:     recipient
    });

    socket.once('transfer_ready', async (data) => {
        if (data.session_id !== sessionId) return;

        const missingChunks = data.missing_chunks;
        console.log(`[Upload] ${data.resume ? 'Resuming' : 'Starting'} — ${missingChunks.length} chunks`);

        let sentCount = 0;

        for (const chunkIndex of missingChunks) {
            const start     = chunkIndex * CHUNK_SIZE;
            const end       = Math.min(start + CHUNK_SIZE, file.size);
            const arrayBuf  = await file.slice(start, end).arrayBuffer();
            const plaintext = new Uint8Array(arrayBuf);

            const wordArray = CryptoJS.lib.WordArray.create(plaintext);
            const hashHex   = CryptoJS.SHA256(wordArray).toString(CryptoJS.enc.Hex);
            const { nonce, ciphertext } = await encryptChunk(plaintext);

            socket.emit('transfer_chunk', {
                session_id:  sessionId,
                chunk_index: chunkIndex,
                nonce:       bufferToHex(nonce),
                ciphertext:  Array.from(ciphertext),
                chunk_hash:  hashHex
            });

            await new Promise((resolve) => {
                socket.once('chunk_ack', () => {
                    sentCount++;
                    const percent = Math.round((sentCount / missingChunks.length) * 100);
                    progressBar.style.width  = `${percent}%`;
                    progressText.textContent = `${percent}%`;
                    resolve();
                });
            });
        }
    });
}

async function retryChunk(transfer, chunkIndex) {
    const { file, sessionId } = transfer;
    const start     = chunkIndex * CHUNK_SIZE;
    const end       = Math.min(start + CHUNK_SIZE, file.size);
    const arrayBuf  = await file.slice(start, end).arrayBuffer();
    const plaintext = new Uint8Array(arrayBuf);
    const wordArray = CryptoJS.lib.WordArray.create(plaintext);
    const hashHex   = CryptoJS.SHA256(wordArray).toString(CryptoJS.enc.Hex);
    const { nonce, ciphertext } = await encryptChunk(plaintext);
    console.log(`[Upload] Retrying chunk ${chunkIndex}`);
    socket.emit('transfer_chunk', {
        session_id:  sessionId,
        chunk_index: chunkIndex,
        nonce:       bufferToHex(nonce),
        ciphertext:  Array.from(ciphertext),
        chunk_hash:  hashHex
    });
}

// ─────────────────────────────────────────────
// File Table
// ─────────────────────────────────────────────

function fetchFiles() {
    const queryParams = new URLSearchParams({
        sort:  currentSort.column,
        order: currentSort.direction
    });
    fetch(`/get_files?${queryParams}`)
        .then(r => r.json())
        .then(files => populateFileTable(files))
        .catch(err => {
            document.querySelector('#fileTable tbody').innerHTML =
                `<tr><td colspan="5">Error loading files: ${err.message}</td></tr>`;
        });
}

function populateFileTable(files) {
    const tbody = document.querySelector('#fileTable tbody');
    tbody.innerHTML = '';
    if (!Array.isArray(files) || files.length === 0) {
        tbody.innerHTML = "<tr><td colspan='5'>No files available</td></tr>";
        return;
    }
    files.forEach((file, index) => {
        const row     = document.createElement('tr');
        row.innerHTML = `
            <td>${index + 1}</td>
            <td>${escapeHtml(file.original_name)}</td>
            <td>${file.size_fmt}</td>
            <td>${file.modified_fmt}</td>
            <td>
                <button onclick="downloadFile('${escapeHtml(file.name)}')">
                    📥 Download
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ─────────────────────────────────────────────
// Download
// ─────────────────────────────────────────────

function downloadFile(storageName) {
    const a    = document.createElement('a');
    a.href     = `/download/${storageName}`;
    a.download = '';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// ─────────────────────────────────────────────
// Peer Discovery
// ─────────────────────────────────────────────

function fetchIPs() {
    const recipientSelect = document.getElementById('recipientSelect');
    const currentValue    = recipientSelect.value;
    fetch('/get_ips')
        .then(r => r.json())
        .then(peers => {
            while (recipientSelect.options.length > 1) recipientSelect.remove(1);
            peers.forEach(peer => {
                const option       = document.createElement('option');
                option.value       = peer.ip;
                option.textContent = `${peer.device_name} (${peer.ip})`;
                recipientSelect.appendChild(option);
            });
            const ips = peers.map(p => p.ip);
            recipientSelect.value = ips.includes(currentValue) ? currentValue : 'Everyone';
        })
        .catch(err => console.error('[fetchIPs] Error:', err));
}

// ─────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────

function bufferToHex(buf) {
    return Array.from(buf instanceof Uint8Array ? buf : new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

// ─────────────────────────────────────────────
// QR Code
// ─────────────────────────────────────────────

function showQRCode() {
    const modal   = document.getElementById('qrModal');
    const img     = document.getElementById('qrImage');
    const loading = document.getElementById('qrLoading');
    const urlEl   = document.getElementById('qrUrl');
    const devEl   = document.getElementById('qrDevice');

    img.style.display     = 'none';
    loading.style.display = 'block';
    modal.style.display   = 'flex';

    fetch('/qr_code')
        .then(r => r.json())
        .then(data => {
            img.src               = data.qr_image;
            img.style.display     = 'block';
            loading.style.display = 'none';
            urlEl.textContent     = `🌐 ${data.connect_url}`;
            devEl.textContent     = `💻 ${data.device_name}`;
        })
        .catch(err => { loading.textContent = `❌ Failed: ${err.message}`; });
}

function closeQRModal() {
    document.getElementById('qrModal').style.display = 'none';
}
