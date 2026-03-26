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

// ─────────────────────────────────────────────
// Clipboard Sharing
// ─────────────────────────────────────────────

let pendingClipboard = null; // Stores decrypted incoming clipboard data

// ── Sync recipient dropdown with main peer list ──
function syncClipboardRecipients() {
    const main   = document.getElementById('recipientSelect');
    const cb     = document.getElementById('clipboardRecipient');
    if (!main || !cb) return;

    const current = cb.value;
    while (cb.options.length > 1) cb.remove(1);

    Array.from(main.options).slice(1).forEach(opt => {
        const clone = document.createElement('option');
        clone.value       = opt.value;
        clone.textContent = opt.textContent;
        cb.appendChild(clone);
    });

    if ([...cb.options].some(o => o.value === current)) {
        cb.value = current;
    }
}

// Call syncClipboardRecipients after fetchIPs resolves
// Patch fetchIPs to also sync clipboard dropdown
const _origFetchIPs = fetchIPs;
window.fetchIPs = function () {
    _origFetchIPs();
    // Give 600ms for the dropdown to populate, then sync
    setTimeout(syncClipboardRecipients, 600);
};

// ── Send clipboard to peer ──
async function sendClipboard() {
    if (!sessionKey) {
        alert('Security handshake not complete. Please wait.');
        return;
    }

    const statusEl   = document.getElementById('clipboardStatus');
    const recipient  = document.getElementById('clipboardRecipient').value || 'Everyone';

    statusEl.textContent = '⏳ Reading clipboard...';

    try {
        let contentType = 'text';
        let rawBytes;
        let preview = '';

        // ── Try reading clipboard items (supports images) ──
        let clipboardItems = null;
        try {
            clipboardItems = await navigator.clipboard.read();
        } catch (e) {
            // Fallback: text-only mode (Firefox / HTTP without permissions)
            clipboardItems = null;
        }

        if (clipboardItems) {
            let handled = false;

            for (const item of clipboardItems) {
                // ── Image ──
                if (item.types.includes('image/png')) {
                    const blob    = await item.getType('image/png');
                    const arrBuf  = await blob.arrayBuffer();
                    rawBytes      = new Uint8Array(arrBuf);
                    contentType   = 'image';
                    preview       = `PNG image (${formatSize(rawBytes.length)})`;
                    handled       = true;
                    break;
                }
                // ── Text ──
                if (item.types.includes('text/plain')) {
                    const blob   = await item.getType('text/plain');
                    const text   = await blob.text();
                    rawBytes     = new TextEncoder().encode(text);
                    contentType  = 'text';
                    preview      = text.slice(0, 80);
                    handled      = true;
                    break;
                }
            }

            if (!handled) {
                statusEl.textContent = '⚠️ Clipboard is empty or unsupported type';
                return;
            }

        } else {
            // Fallback text read
            const text = await navigator.clipboard.readText();
            if (!text) {
                statusEl.textContent = '⚠️ Clipboard is empty';
                return;
            }
            rawBytes    = new TextEncoder().encode(text);
            contentType = 'text';
            preview     = text.slice(0, 80);
        }

        statusEl.textContent = `🔒 Encrypting ${contentType}...`;

        // ── AES-256-GCM encrypt ──
        const nonce      = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            sessionKey,
            rawBytes
        );

        statusEl.textContent = '📤 Sending...';

        socket.emit('clipboard_send', {
            recipient:    recipient,
            content_type: contentType,
            nonce:        bufferToHex(nonce),
            ciphertext:   Array.from(new Uint8Array(ciphertext)),
            preview:      preview,
            size_bytes:   rawBytes.length
        });

        // Optimistic status — confirmed on clipboard_sent event
        statusEl.textContent = `✅ Sent ${contentType} (${formatSize(rawBytes.length)}) → ${recipient}`;
        fetchClipboardHistory();

    } catch (err) {
        console.error('[Clipboard] Send error:', err);
        if (err.name === 'NotAllowedError') {
            statusEl.textContent = '⚠️ Clipboard permission denied — click the page first and retry';
        } else {
            statusEl.textContent = `❌ Error: ${err.message}`;
        }
    }
}

socket.on('clipboard_receive', async (data) => {
    try {
        const { from_ip, from_device, content_type, nonce, ciphertext,
                preview, size_bytes } = data;

        const nonceBuf  = hexToBuffer(nonce);
        const ctBuf     = new Uint8Array(ciphertext);

        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonceBuf },
            sessionKey,
            ctBuf
        );

        const plaintextBytes = new Uint8Array(plaintext);
        pendingClipboard     = { plaintext: plaintextBytes, content_type };

        const toast     = document.getElementById('clipboardToast');
        const icon      = document.getElementById('toastIcon');
        const title     = document.getElementById('toastTitle');
        const detail    = document.getElementById('toastDetail');
        const acceptBtn = document.getElementById('toastAcceptBtn');
        const imgPrev   = document.getElementById('toastImgPreview');

        title.textContent = `From ${from_device || from_ip}`;

        if (content_type === 'image') {
            icon.textContent      = '🖼️';
            acceptBtn.textContent = '✅ Copy Image';
            detail.textContent    = `PNG image · ${formatSize(size_bytes)}`;
            detail.style.whiteSpace = 'normal';

            // Show inline preview
            const blob = new Blob([plaintextBytes], { type: 'image/png' });
            if (window._pendingBlobUrl) URL.revokeObjectURL(window._pendingBlobUrl);
            window._pendingBlobUrl = URL.createObjectURL(blob);
            imgPrev.src            = window._pendingBlobUrl;
            imgPrev.style.display  = 'block';

        } else {
            // Full text — not the 80-char preview
            const fullText = new TextDecoder().decode(plaintextBytes);
            icon.textContent      = '📋';
            acceptBtn.textContent = '✅ Copy Text';

            detail.textContent    = fullText.length > 300
                ? fullText.slice(0, 300) + '…'
                : fullText;
            detail.style.cssText  =
                'color:#aaa;font-size:0.82em;max-width:260px;' +
                'white-space:pre-wrap;word-break:break-word;' +
                'max-height:100px;overflow-y:auto;';

            if (imgPrev) imgPrev.style.display = 'none';
        }

        toast.style.display = 'flex';
        clearTimeout(window._toastTimer);
        window._toastTimer  = setTimeout(dismissToast, 15000);

        console.log(`[Clipboard] Received ${content_type} from ${from_device} (${size_bytes}B)`);
        fetchClipboardHistory();

    } catch (err) {
        console.error('[Clipboard] Receive/decrypt error:', err);
        showClipboardStatus(`❌ Failed to decrypt incoming clipboard: ${err.message}`);
    }
});


socket.on('clipboard_sent', (data) => {
    const statusEl = document.getElementById('clipboardStatus');
    if (statusEl) {
        statusEl.textContent = `✅ Delivered — ${data.content_type} (${formatSize(data.size_bytes)})`;
    }
});

socket.on('clipboard_error', (data) => {
    const statusEl = document.getElementById('clipboardStatus');
    if (statusEl) statusEl.textContent = `❌ ${data.reason}`;
    console.error('[Clipboard] Server error:', data.reason);
});

// ── User clicks "Apply" on toast ──
async function acceptClipboard() {
    if (!pendingClipboard) return;

    try {
        const { plaintext, content_type } = pendingClipboard;

        if (content_type === 'image') {
            const blob = new Blob([plaintext], { type: 'image/png' });
            await navigator.clipboard.write([
                new ClipboardItem({ 'image/png': blob })
            ]);
        } else {
            const text = new TextDecoder().decode(plaintext);
            await navigator.clipboard.writeText(text);
        }

        dismissToast();
        showClipboardStatus(`✅ ${content_type === 'image' ? 'Image' : 'Text'} applied to clipboard`);
        pendingClipboard = null;

    } catch (err) {
        console.error('[Clipboard] Write error:', err);
        showClipboardStatus(`❌ Could not write to clipboard: ${err.message}`);
    }
}

function dismissToast() {
    const toast = document.getElementById('clipboardToast');
    if (toast) toast.style.display = 'none';
    clearTimeout(window._toastTimer);

    // Revoke object URL to free memory
    if (window._pendingBlobUrl) {
        URL.revokeObjectURL(window._pendingBlobUrl);
        window._pendingBlobUrl = null;
    }
    const imgPrev = document.getElementById('toastImgPreview');
    if (imgPrev) imgPrev.style.display = 'none';
}


function showClipboardStatus(msg) {
    const el = document.getElementById('clipboardStatus');
    if (el) el.textContent = msg;
}

// ── Clipboard history ──
function fetchClipboardHistory() {
    fetch('/clipboard/history')
        .then(r => r.json())
        .then(items => {
            const list = document.getElementById('clipboardHistoryList');
            if (!list) return;
            list.innerHTML = '';
            if (!items.length) {
                list.innerHTML = '<li style="color:#555">No clipboard activity yet</li>';
                return;
            }
            items.forEach(item => {
                const li = document.createElement('li');
                const typeIcon = item.content_type === 'image' ? '🖼️' : '📋';
                li.innerHTML = `
                    <span>${typeIcon} ${escapeHtml(item.preview || '(image)')} </span>
                    <span style="color:#555">${item.sender_ip} → ${item.recipient} | ${item.sent_at}</span>
                `;
                list.appendChild(li);
            });
        })
        .catch(err => console.error('[Clipboard history]', err));
}

// Load history on page ready
document.addEventListener('DOMContentLoaded', () => {
    fetchClipboardHistory();
});

function populateFileTable(files) {
    const tbody = document.querySelector('#fileTable tbody');
    tbody.innerHTML = '';

    if (!Array.isArray(files) || files.length === 0) {
        tbody.innerHTML = "<tr><td colspan='6'>No files available</td></tr>";
        return;
    }

    files.forEach((file, index) => {
        const row     = document.createElement('tr');
        row.id        = `file-row-${file.name}`;
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
            <td>
                <button class="delete-btn"
                        onclick="deleteFile('${escapeHtml(file.name)}', '${escapeHtml(file.original_name)}')">
                    🗑️ Delete
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function deleteFile(storageName, originalName) {
    if (!confirm(`Delete "${originalName}"?\nThis cannot be undone.`)) return;

    fetch(`/delete_file/${encodeURIComponent(storageName)}`, { method: 'DELETE' })
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                alert(`❌ ${data.error}`);
                return;
            }
            // Animate row out
            const row = document.getElementById(`file-row-${storageName}`);
            if (row) {
                row.style.transition = 'opacity 0.3s';
                row.style.opacity    = '0';
                setTimeout(() => fetchFiles(), 300);
            }
        })
        .catch(err => alert(`Delete failed: ${err.message}`));
}


function fetchClipboardHistory() {
    fetch('/clipboard/history')
        .then(r => r.json())
        .then(items => {
            const list = document.getElementById('clipboardHistoryList');
            if (!list) return;
            list.innerHTML = '';

            if (!items.length) {
                list.innerHTML = '<li style="color:#555">No clipboard activity yet</li>';
                return;
            }

            items.forEach(item => {
                const li       = document.createElement('li');
                li.id          = `cb-entry-${item.id}`;
                const typeIcon = item.content_type === 'image' ? '🖼️' : '📋';
                li.innerHTML   = `
                    <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                        ${typeIcon} ${escapeHtml(item.preview || '(image)')}
                    </span>
                    <span style="color:#555;white-space:nowrap;margin:0 10px;">
                        ${item.sender_ip} → ${item.recipient} | ${item.sent_at}
                    </span>
                    <button class="delete-btn-sm"
                            onclick="deleteClipboardEntry(${item.id})">🗑️</button>
                `;
                list.appendChild(li);
            });
        })
        .catch(err => console.error('[Clipboard history]', err));
}

function deleteClipboardEntry(id) {
    fetch(`/delete_clipboard/${id}`, { method: 'DELETE' })
        .then(r => r.json())
        .then(data => {
            if (data.error) { alert(`❌ ${data.error}`); return; }
            const el = document.getElementById(`cb-entry-${id}`);
            if (el) {
                el.style.transition = 'opacity 0.3s';
                el.style.opacity    = '0';
                setTimeout(() => el.remove(), 300);
            }
        })
        .catch(err => alert(`Delete failed: ${err.message}`));
}
