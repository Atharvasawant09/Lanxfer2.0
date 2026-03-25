// ─────────────────────────────────────────────
// Transfer History — history.js
// ─────────────────────────────────────────────

let currentPage  = 1;
const PER_PAGE   = 20;
let debounceTimer = null;
let allStats     = { total: 0, complete: 0, failed: 0, in_progress: 0 };

// ── Load History ──────────────────────────────

function loadHistory(page = 1) {
    currentPage = page;

    const search    = document.getElementById('searchInput').value.trim();
    const status    = document.getElementById('statusFilter').value;
    const peer      = document.getElementById('peerFilter').value.trim();
    const dateFrom  = document.getElementById('dateFrom').value;
    const dateTo    = document.getElementById('dateTo').value;

    const params = new URLSearchParams({
        page, per_page: PER_PAGE,
        ...(search   && { search }),
        ...(status   && { status }),
        ...(peer     && { peer }),
        ...(dateFrom && { date_from: dateFrom }),
        ...(dateTo   && { date_to: dateTo })
    });

    fetch(`/api/history?${params}`)
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                showError(data.error);
                return;
            }
            renderTable(data.transfers);
            renderPagination(data.pagination);
            updateStats(data.transfers, data.pagination.total);
        })
        .catch(err => showError(err.message));
}

function debounceLoad() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => loadHistory(1), 350);
}

// ── Render Table ──────────────────────────────

function renderTable(transfers) {
    const tbody  = document.getElementById('historyBody');
    tbody.innerHTML = '';

    if (!transfers || transfers.length === 0) {
        tbody.innerHTML = `<tr><td colspan="10" class="no-data">No transfers found</td></tr>`;
        return;
    }

    const offset = (currentPage - 1) * PER_PAGE;

    transfers.forEach((t, i) => {
        const row = document.createElement('tr');
        row.className = `row-${t.status}`;

        row.innerHTML = `
            <td>${offset + i + 1}</td>
            <td class="filename-cell" title="${escHtml(t.original_name)}">
                ${escHtml(truncate(t.original_name, 30))}
            </td>
            <td>${t.file_size_fmt}</td>
            <td class="ip-cell">${escHtml(t.sender_ip)}</td>
            <td class="ip-cell">${escHtml(t.recipient)}</td>
            <td>${statusBadge(t.status)}</td>
            <td>
                <div class="mini-progress-bar">
                    <div class="mini-progress-fill status-${t.status}"
                         style="width:${t.progress}%"></div>
                </div>
                <span class="progress-pct">${t.progress}%</span>
            </td>
            <td>${escHtml(t.speed_fmt)}</td>
            <td>${escHtml(t.duration_fmt)}</td>
            <td class="date-cell">${formatDate(t.started_at)}</td>
        `;
        tbody.appendChild(row);
    });
}

// ── Pagination ────────────────────────────────

function renderPagination(p) {
    const container = document.getElementById('pagination');
    container.innerHTML = '';

    if (p.total_pages <= 1) return;

    const makeBtn = (label, page, disabled = false, active = false) => {
        const btn = document.createElement('button');
        btn.textContent = label;
        btn.className   = `page-btn ${active ? 'active' : ''} ${disabled ? 'disabled' : ''}`;
        if (!disabled) btn.onclick = () => loadHistory(page);
        return btn;
    };

    container.appendChild(makeBtn('«', 1,            currentPage === 1));
    container.appendChild(makeBtn('‹', currentPage - 1, currentPage === 1));

    // Window of 5 pages
    const start = Math.max(1, currentPage - 2);
    const end   = Math.min(p.total_pages, currentPage + 2);
    for (let i = start; i <= end; i++) {
        container.appendChild(makeBtn(i, i, false, i === currentPage));
    }

    container.appendChild(makeBtn('›', currentPage + 1, currentPage === p.total_pages));
    container.appendChild(makeBtn('»', p.total_pages,   currentPage === p.total_pages));

    const info = document.createElement('span');
    info.className   = 'page-info';
    info.textContent = `Page ${currentPage} of ${p.total_pages} (${p.total} records)`;
    container.appendChild(info);
}

// ── Stats Bar ─────────────────────────────────

function updateStats(transfers, total) {
    let complete = 0, failed = 0, in_progress = 0;
    transfers.forEach(t => {
        if (t.status === 'complete')    complete++;
        else if (t.status === 'failed') failed++;
        else                            in_progress++;
    });

    document.getElementById('statTotal').textContent      = `Total: ${total}`;
    document.getElementById('statComplete').textContent   = `✅ Complete: ${complete}`;
    document.getElementById('statFailed').textContent     = `❌ Failed: ${failed}`;
    document.getElementById('statInProgress').textContent = `⏳ Active: ${in_progress}`;
}

// ── CSV Export ────────────────────────────────

function exportCSV() {
    const search   = document.getElementById('searchInput').value.trim();
    const status   = document.getElementById('statusFilter').value;
    const peer     = document.getElementById('peerFilter').value.trim();
    const dateFrom = document.getElementById('dateFrom').value;
    const dateTo   = document.getElementById('dateTo').value;

    const params = new URLSearchParams({
        export: 'csv',
        ...(search   && { search }),
        ...(status   && { status }),
        ...(peer     && { peer }),
        ...(dateFrom && { date_from: dateFrom }),
        ...(dateTo   && { date_to: dateTo })
    });

    // Trigger browser download
    const a    = document.createElement('a');
    a.href     = `/api/history?${params}`;
    a.download = '';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// ── Utilities ─────────────────────────────────

function statusBadge(status) {
    const map = {
        complete:    '<span class="badge badge-complete">✅ Complete</span>',
        in_progress: '<span class="badge badge-progress">⏳ Active</span>',
        failed:      '<span class="badge badge-failed">❌ Failed</span>'
    };
    return map[status] || `<span class="badge">${escHtml(status)}</span>`;
}

function formatDate(iso) {
    if (!iso || iso === '—') return '—';
    try {
        const d = new Date(iso.replace(' ', 'T'));
        return d.toLocaleString('en-IN', {
            day:    '2-digit',
            month:  'short',
            hour:   '2-digit',
            minute: '2-digit'
        });
    } catch { return iso; }
}

function truncate(str, max) {
    return str.length > max ? str.slice(0, max) + '…' : str;
}

function escHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function showError(msg) {
    document.getElementById('historyBody').innerHTML =
        `<tr><td colspan="10" class="error-cell">❌ Error: ${escHtml(msg)}</td></tr>`;
}

// ── Init ──────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => loadHistory(1));
