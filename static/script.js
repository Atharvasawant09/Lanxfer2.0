// ─────────────────────────────────────────────
// Constants & State
// ─────────────────────────────────────────────

// Phase 1: kept for download decrypt — replaced in Phase 2
const SECRET_KEY_HEX = '546869734973415365637265744b657931323334353637383930313233343536';
const CHUNK_SIZE     = 4 * 1024 * 1024; // 4MB

let currentSort    = { column: 'name', direction: 'asc' };
let activeTransfers = {}; // { sessionId: { file, totalChunks, sessionId } }

// ─────────────────────────────────────────────
// Socket.IO
// ─────────────────────────────────────────────

const socket = io();

socket.on('connect', () => {
    console.log('[WS] Connected to LANxfer server');
});

socket.on('disconnect', () => {
    console.log('[WS] Disconnected — transfers will resume on reconnect');
});

socket.on('server_info', (info) => {
    console.log(`[WS] Server: ${info.device_name} @ ${info.ip} v${info.version}`);
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
    if (data.reason === 'hash_mismatch') {
        const transfer = Object.values(activeTransfers)[0];
        if (transfer) retryChunk(transfer, data.chunk_index);
    }
});

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

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, highlight, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, unhighlight, false);
    });

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

    // Auto-refresh peer list every 10 seconds
    setInterval(fetchIPs, 10000);

    // Heartbeat — keeps this device visible to other peers
    setInterval(() => {
        fetch('/heartbeat', { method: 'POST' }).catch(() => {});
    }, 30000);
});

// ─────────────────────────────────────────────
// Drag & Drop
// ─────────────────────────────────────────────

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

function highlight() {
    document.getElementById('dropZone').classList.add('drag-over');
}

function unhighlight() {
    document.getElementById('dropZone').classList.remove('drag-over');
}

function handleDrop(e) {
    handleFileSelect(e.dataTransfer.files[0]);
}

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
// Chunked Upload via WebSocket
// ─────────────────────────────────────────────

function uploadFile() {
    const fileInput       = document.getElementById('fileInput');
    const recipientSelect = document.getElementById('recipientSelect');
    const progressWrapper = document.querySelector('.progress-wrapper');
    const progressBar     = document.querySelector('.progress-bar');
    const progressText    = document.querySelector('.progress-text');

    const file      = fileInput.files[0];
    const recipient = recipientSelect.value || 'Everyone';

    if (!file) { alert('Please select a file first.'); return; }

    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

    // UUID fallback — crypto.randomUUID() requires HTTPS, this works on HTTP LAN
    const sessionId = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });

    progressWrapper.style.display = 'block';
    progressText.textContent      = '0%';
    progressBar.style.width       = '0%';

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
        console.log(`[Upload] ${data.resume ? 'Resuming' : 'Starting'} — ${missingChunks.length} chunks to send`);

        let sentCount = 0;

        for (const chunkIndex of missingChunks) {
            const start      = chunkIndex * CHUNK_SIZE;
            const end        = Math.min(start + CHUNK_SIZE, file.size);
            const chunkBlob  = file.slice(start, end);
            const arrayBuf   = await chunkBlob.arrayBuffer();
            const chunkArray = new Uint8Array(arrayBuf);

            // CryptoJS SHA-256 — works on HTTP (no HTTPS required unlike crypto.subtle)
            const wordArray = CryptoJS.lib.WordArray.create(chunkArray);
            const hashHex   = CryptoJS.SHA256(wordArray).toString(CryptoJS.enc.Hex);

            socket.emit('transfer_chunk', {
                session_id:  sessionId,
                chunk_index: chunkIndex,
                chunk_data:  Array.from(chunkArray),  // safe across all browsers + mobile
                chunk_hash:  hashHex
            });

            // Wait for ACK before next chunk (flow control)
            await new Promise((resolve) => {
                socket.once('chunk_ack', (ack) => {
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
    const start      = chunkIndex * CHUNK_SIZE;
    const end        = Math.min(start + CHUNK_SIZE, file.size);
    const chunkBlob  = file.slice(start, end);
    const arrayBuf   = await chunkBlob.arrayBuffer();
    const chunkArray = new Uint8Array(arrayBuf);
    const wordArray  = CryptoJS.lib.WordArray.create(chunkArray);
    const hashHex    = CryptoJS.SHA256(wordArray).toString(CryptoJS.enc.Hex);

    console.log(`[Upload] Retrying chunk ${chunkIndex}`);
    socket.emit('transfer_chunk', {
        session_id:  sessionId,
        chunk_index: chunkIndex,
        chunk_data:  Array.from(chunkArray),
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
            const tbody = document.querySelector('#fileTable tbody');
            tbody.innerHTML = `<tr><td colspan="5">Error loading files: ${err.message}</td></tr>`;
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
                <button onclick="downloadAndDecrypt('${escapeHtml(file.name)}', '${escapeHtml(file.original_name)}')">
                    📥 Download
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
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
            while (recipientSelect.options.length > 1) {
                recipientSelect.remove(1);
            }
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
// Download & Decrypt
// Phase 1: client-side AES-CBC — replaced in Phase 2
// ─────────────────────────────────────────────

function downloadAndDecrypt(encryptedFilename, originalFilename) {
    fetch(`/download/${encryptedFilename}`)
        .then(response => {
            if (!response.ok) throw new Error('Failed to fetch file');
            return response.arrayBuffer();
        })
        .then(encryptedData => {
            const encryptedBytes = new Uint8Array(encryptedData);
            const iv             = encryptedBytes.slice(0, 16);
            const ciphertext     = encryptedBytes.slice(16);
            const key            = CryptoJS.enc.Hex.parse(SECRET_KEY_HEX);
            const ivWordArray    = CryptoJS.lib.WordArray.create(iv);
            const ciphertextWA   = CryptoJS.lib.WordArray.create(ciphertext);

            const decrypted = CryptoJS.AES.decrypt(
                { ciphertext: ciphertextWA },
                key,
                { iv: ivWordArray, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
            );

            const decryptedHex   = decrypted.toString(CryptoJS.enc.Hex);
            const decryptedBytes = new Uint8Array(
                decryptedHex.match(/.{1,2}/g).map(b => parseInt(b, 16))
            );

            const blob = new Blob([decryptedBytes], { type: 'application/octet-stream' });
            const url  = window.URL.createObjectURL(blob);
            const a    = document.createElement('a');
            a.href     = url;
            a.download = originalFilename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        })
        .catch(err => alert(`Download failed: ${err.message}`));
}
