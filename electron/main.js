const {
    app,
    BrowserWindow,
    Tray,
    Menu,
    globalShortcut,
    Notification,
    ipcMain,
    shell,
    clipboard,
    nativeImage,
    screen
} = require('electron');

const { spawn }   = require('child_process');
const path        = require('path');
const http        = require('http');
const fs          = require('fs');
const https = require('https');
// ── Constants ──────────────────────────────────────────────
const FLASK_PORT  = 5000;
const FLASK_URL = `https://localhost:${FLASK_PORT}`;
const IS_DEV      = process.argv.includes('--dev');
const IS_WIN      = process.platform === 'win32';
const IS_MAC      = process.platform === 'darwin';

// ── State ──────────────────────────────────────────────────
let tray          = null;
let overlayWindow = null;
let mainWindow    = null;
let flaskProcess  = null;
let flaskReady    = false;
let isQuitting    = false;

// ═══════════════════════════════════════════════════════════
// 1. FLASK BACKEND SPAWNER
// ═══════════════════════════════════════════════════════════

function getBackendPath() {
    if (app.isPackaged) {
        return path.join(process.resourcesPath, 'backend');
    }
    // Your app.py is in the ROOT, not a backend/ subfolder
    return path.join(__dirname, '..');  // goes from electron/ up to LANxfer2.0/
}


function getPythonExecutable() {
    if (app.isPackaged) {
        const bundledPython = path.join(process.resourcesPath, 'python', 'python.exe');
        if (fs.existsSync(bundledPython)) return bundledPython;
    }

    // Check for venv inside backend folder first (most reliable)
    const venvPython = [
    path.join(getBackendPath(), '.venv', 'Scripts', 'python.exe'),
    path.join(getBackendPath(), 'venv',  'Scripts', 'python.exe'),
].find(p => fs.existsSync(p));

if (venvPython) {
    console.log(`[Flask] Using venv Python: ${venvPython}`);
    return venvPython;
}

    // Ordered by preference — avoid WindowsApps stub (it's fake)
    const candidates = [
        'C:\\Program Files\\Python311\\python.exe',
        `${process.env.LOCALAPPDATA}\\Programs\\Python\\Python313\\python.exe`,
        `${process.env.LOCALAPPDATA}\\Programs\\Python\\Python39\\python.exe`,
        'C:\\Windows\\py.exe',
    ];

    for (const p of candidates) {
        if (p && fs.existsSync(p)) {
            console.log(`[Flask] Found Python at: ${p}`);
            return p;
        }
    }

    console.error('[Flask] No Python found!');
    return null;
}



function spawnFlask() {
    const backendPath = getBackendPath();
    const pythonExe   = getPythonExecutable();
    const appScript   = path.join(backendPath, 'app.py');

    if (!pythonExe) {
        showNotification('LANxfer — Python Not Found',
            'Install Python 3.x from python.org');
        return;
    }

    console.log(`[Flask] Spawning: "${pythonExe}" "${appScript}"`);
    console.log(`[Flask] CWD: ${backendPath}`);

    flaskProcess = spawn(pythonExe, [appScript], {
        cwd:   backendPath,
        stdio: ['ignore', 'pipe', 'pipe'],
        // shell: true fixes spaces-in-path issues on Windows
        shell: IS_WIN,
        env:   {
            ...process.env,
            FLASK_ENV:        'production',
            PYTHONUNBUFFERED: '1',
            PYTHONPATH:       backendPath
        }
    });

    flaskProcess.stdout.on('data', (data) => {
        const msg = data.toString().trim();
        console.log(`[Flask] ${msg}`);
        // Detect Flask ready
        if (msg.includes('Running on') || msg.includes('Serving Flask')) {
            flaskReady = true;
            console.log('[Flask] ✅ Server ready');
        }
    });

    flaskProcess.stderr.on('data', (data) => {
        const msg = data.toString().trim();
        // Flask dev server uses stderr for startup messages too
        if (msg.includes('Running on') || msg.includes('Serving Flask')) {
            flaskReady = true;
        }
        console.error(`[Flask ERR] ${msg}`);
    });

    flaskProcess.on('close', (code) => {
        console.log(`[Flask] Process exited with code ${code}`);
        if (!isQuitting) {
            // Unexpected crash — notify user
            showNotification('LANxfer Backend Error',
                'Backend server stopped unexpectedly. Please restart the app.');
        }
    });

    flaskProcess.on('error', (err) => {
        console.error('[Flask] Failed to start:', err);
        showNotification('LANxfer Error',
            `Failed to start backend: ${err.message}`);
    });
}

// Poll until Flask is accepting connections
function waitForFlask(maxAttempts = 30, interval = 500) {
    return new Promise((resolve, reject) => {
        let attempts = 0;

        const check = () => {
            attempts++;
            // Use https since your Flask runs with SSL
            const req = https.get({
                hostname: 'localhost',
                port:     FLASK_PORT,
                path:     '/health',
                // Accept self-signed cert (your cert.pem is self-signed)
                rejectUnauthorized: false
            }, (res) => {
                if (res.statusCode === 200) {
                    flaskReady = true;
                    resolve();
                } else {
                    retry();
                }
            });

            req.on('error', () => retry());
            req.setTimeout(300, () => { req.destroy(); retry(); });
        };

        const retry = () => {
            if (attempts >= maxAttempts) {
                reject(new Error('Flask server did not start in time'));
                return;
            }
            setTimeout(check, interval);
        };

        check();
    });
}

// ═══════════════════════════════════════════════════════════
// 2. SYSTEM TRAY
// ═══════════════════════════════════════════════════════════

function createTray() {
    let icon;
    const iconPath = path.join(__dirname, 'assets',
        IS_WIN ? 'icon.ico' : 'icon.png');

    if (fs.existsSync(iconPath)) {
        icon = nativeImage.createFromPath(iconPath);
    } else {
        // Fallback: 16x16 green pixel icon so tray doesn't crash
        icon = nativeImage.createFromDataURL(
            'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABklEQVQ4jWNgYGBg+A8AAQQAAf9h/QAAAABJRU5ErkJggg=='
        );
        console.warn('[Tray] icon not found at', iconPath, '— using fallback');
    }

    tray = new Tray(icon.resize({ width: 16, height: 16 }));
    tray.setToolTip('LANxfer — LAN File Transfer');
    buildTrayMenu();

    tray.on('click', () => toggleOverlay());
    tray.on('right-click', () => {
        buildTrayMenu();
        tray.popUpContextMenu();
    });
}


function buildTrayMenu() {
    const menuTemplate = [
        {
            label: '⚡ Quick Send  (Ctrl+Shift+L)',
            click: () => showOverlay()
        },
        { type: 'separator' },
        {
            label: '📋 Transfer History',
            click: () => openMainWindow('/history')
        },
        {
            label: '🌐 Open Dashboard',
            click: () => openMainWindow('/')
        },
        { type: 'separator' },
        {
            label: `🔗 Status: ${flaskReady ? '✅ Running' : '⏳ Starting...'}`,
            enabled: false
        },
        {
            label: `📡 ${FLASK_URL}`,
            click: () => shell.openExternal(FLASK_URL)
        },
        { type: 'separator' },
        {
            label: '❌ Quit LANxfer',
            click: () => quitApp()
        }
    ];

    const menu = Menu.buildFromTemplate(menuTemplate);
    tray.setContextMenu(menu);
}

// ═══════════════════════════════════════════════════════════
// 3. OVERLAY WINDOW (hotkey-triggered)
// ═══════════════════════════════════════════════════════════

function createOverlayWindow() {
    const display = screen.getPrimaryDisplay();
    const { width: sw, height: sh } = display.workAreaSize;
    const scaleFactor = display.scaleFactor || 1;

    // Window dimensions
    const WIN_W = 1250;
    const WIN_H = 750;

    // Position: bottom-right corner with 20px margin
    const posX = sw - WIN_W - 20;
    const posY = sh - WIN_H - 20;

    overlayWindow = new BrowserWindow({
        width:       WIN_W,
        height:      WIN_H,
        x:           posX,
        y:           posY,
        show:        false,
        frame:       false,
        transparent: true,
        resizable:   true,       // ← allow manual resize if needed
        skipTaskbar: true,
        alwaysOnTop: true,
        webPreferences: {
            preload:          path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration:  false,
            zoomFactor:       1.0
        }
    });

    overlayWindow.loadURL(`${FLASK_URL}?overlay=1`);

    // Inject CSS + force viewport after load
    overlayWindow.webContents.on('did-finish-load', () => {

    // Get the actual page width and zoom to fit the window
    overlayWindow.webContents.executeJavaScript(`
        (function() {
            // Fix viewport
            let meta = document.querySelector('meta[name="viewport"]');
            if (!meta) {
                meta = document.createElement('meta');
                meta.name = 'viewport';
                document.head.appendChild(meta);
            }
            meta.content = 'width=device-width, initial-scale=1.0';

            // Return the actual content width so Electron can zoom to fit
            return document.documentElement.scrollWidth;
        })();
    `).then(contentWidth => {
        const WIN_W = overlayWindow.getBounds().width;
        if (contentWidth > WIN_W) {
            const zoomFactor = WIN_W / contentWidth;
            overlayWindow.webContents.setZoomFactor(zoomFactor);
            console.log(`[Overlay] Zoom: ${contentWidth}px → ${WIN_W}px (factor: ${zoomFactor.toFixed(2)})`);
        }
    });

    overlayWindow.webContents.insertCSS(`
        /* Overlay shell styling */
        html {
            overflow-y: auto !important;
            overflow-x: hidden !important;
        }

        body {
            background: rgba(0, 0, 0, 0.93) !important;
            border: 1px solid #00ff00 !important;
            border-radius: 6px !important;
            box-shadow: 0 0 30px rgba(0, 255, 0, 0.12) !important;
            margin: 0 !important;
        }

        /* Scrollbar */
        ::-webkit-scrollbar       { width: 4px; }
        ::-webkit-scrollbar-track { background: #000; }
        ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 2px; }

        /* Hide nav in overlay */
        .nav-bar { display: none !important; }
    `);
});


    overlayWindow.on('blur', () => {
        if (overlayWindow && !overlayWindow.isDestroyed()) {
            overlayWindow.hide();
        }
    });

    overlayWindow.on('closed', () => { overlayWindow = null; });
}


function showOverlay() {
    if (!flaskReady) {
        showNotification('LANxfer', 'Server is still starting, please wait...');
        return;
    }

    if (!overlayWindow || overlayWindow.isDestroyed()) {
        createOverlayWindow();
        overlayWindow.once('ready-to-show', () => {
            overlayWindow.show();
            overlayWindow.focus();
        });
        return;
    }

    if (overlayWindow.isVisible()) {
        overlayWindow.hide();
    } else {
        // ← FIXED: use actual window dimensions
        const { width: sw, height: sh } = screen.getPrimaryDisplay().workAreaSize;
        const bounds = overlayWindow.getBounds();
        overlayWindow.setPosition(sw - bounds.width - 20, sh - bounds.height - 20);
        overlayWindow.show();
        overlayWindow.focus();
    }
}


function toggleOverlay() {
    if (overlayWindow && !overlayWindow.isDestroyed() && overlayWindow.isVisible()) {
        overlayWindow.hide();
    } else {
        showOverlay();
    }
}

// ═══════════════════════════════════════════════════════════
// 4. MAIN WINDOW (full dashboard)
// ═══════════════════════════════════════════════════════════

function openMainWindow(route = '/') {
    if (!flaskReady) {
        showNotification('LANxfer', 'Server is still starting...');
        return;
    }

    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.loadURL(`${FLASK_URL}${route}`);
        mainWindow.show();
        mainWindow.focus();
        return;
    }

    mainWindow = new BrowserWindow({
        width:       1100,
        height:      700,
        minWidth:    800,
        minHeight:   500,
        title:       'LANxfer 2.0',
        icon:        path.join(__dirname, 'assets', IS_WIN ? 'icon.ico' : 'icon.png'),
        webPreferences: {
    preload:                path.join(__dirname, 'preload.js'),
    contextIsolation:       true,
    nodeIntegration:        false,
}

    });

    mainWindow.loadURL(`${FLASK_URL}${route}`);

    // Hide to tray instead of quitting
    mainWindow.on('close', (e) => {
        if (!isQuitting) {
            e.preventDefault();
            mainWindow.hide();
            if (IS_WIN || process.platform === 'linux') {
                showNotification('LANxfer', 'Running in background. Right-click tray icon to quit.');
            }
        }
    });

    mainWindow.on('closed', () => { mainWindow = null; });

    if (IS_DEV) {
        mainWindow.webContents.openDevTools();
    }
}

// ═══════════════════════════════════════════════════════════
// 5. GLOBAL HOTKEY — Ctrl+Shift+L
// ═══════════════════════════════════════════════════════════

function registerHotkeys() {
    const hotkey = 'CommandOrControl+Shift+L';
    const ok = globalShortcut.register(hotkey, () => {
        console.log('[Hotkey] Ctrl+Shift+L triggered');
        toggleOverlay();
    });

    if (!ok) {
        console.warn('[Hotkey] Registration failed — may be in use by another app');
    } else {
        console.log(`[Hotkey] ✅ ${hotkey} registered`);
    }
}

// ═══════════════════════════════════════════════════════════
// 6. OS NOTIFICATIONS
// ═══════════════════════════════════════════════════════════

function showNotification(title, body, onClick = null) {
    if (!Notification.isSupported()) return;

    const n = new Notification({
        title,
        body,
        icon:   path.join(__dirname, 'assets', 'icon.png'),
        silent: false
    });

    if (onClick) n.on('click', onClick);
    n.show();
}

// IPC handler — Flask can trigger notifications via fetch to /notify
// or frontend JS can call window.electronAPI.notify(title, body)
ipcMain.on('notify', (event, { title, body }) => {
    showNotification(title, body);
});

ipcMain.on('transfer-complete', (event, { filename, peer }) => {
    showNotification(
        '✅ Transfer Complete',
        `${filename} received from ${peer}`,
        () => openMainWindow('/history')
    );
});

ipcMain.on('transfer-failed', (event, { filename, peer }) => {
    showNotification(
        '❌ Transfer Failed',
        `${filename} from ${peer} failed — will retry on reconnect`
    );
});

ipcMain.handle('get-flask-url', () => FLASK_URL);
ipcMain.handle('is-flask-ready', () => flaskReady);

// ═══════════════════════════════════════════════════════════
// 7. APP LIFECYCLE
// ═══════════════════════════════════════════════════════════
app.commandLine.appendSwitch('force-device-scale-factor', '1');

app.whenReady().then(async () => {
    // ← ADD THIS — allows self-signed SSL cert for localhost
    app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
        if (url.startsWith('https://localhost')) {
            event.preventDefault();
            callback(true); // trust it
        } else {
            callback(false);
        }
    });

    console.log('[App] LANxfer starting...');

    // macOS: don't show in dock
    if (IS_MAC) app.dock.hide();

    // Spawn Flask backend
    spawnFlask();

    // Create tray immediately (shows ⏳ Starting...)
    createTray();

    // Wait for Flask to be ready
    try {
        await waitForFlask();
        console.log('[App] ✅ Flask ready — building UI');
        buildTrayMenu();     // refresh tray to show ✅ Running

        // Register hotkey
        registerHotkeys();

        // Pre-create overlay (hidden) for instant response
        createOverlayWindow();

        // Show startup notification
        showNotification(
            'LANxfer 2.0 Started',
            `Press Ctrl+Shift+L for quick send · Running at ${FLASK_URL}`
        );

    } catch (err) {
        console.error('[App] Flask failed to start:', err);
        showNotification('LANxfer Error', 'Backend failed to start. Check logs.');
    }
});

// Prevent app from quitting when all windows closed
app.on('window-all-closed', () => {
    // Stay in tray on all platforms
    // Do NOT call app.quit() here
});

app.on('activate', () => {
    // macOS: re-open when clicking dock icon
    openMainWindow('/');
});

app.on('will-quit', () => {
    globalShortcut.unregisterAll();
});

// ═══════════════════════════════════════════════════════════
// 8. CLEANUP ON QUIT
// ═══════════════════════════════════════════════════════════

function quitApp() {
    isQuitting = true;

    // Kill Flask process
    if (flaskProcess) {
        console.log('[App] Killing Flask process...');
        if (IS_WIN) {
            spawn('taskkill', ['/pid', flaskProcess.pid, '/f', '/t']);
        } else {
            flaskProcess.kill('SIGTERM');
        }
    }

    globalShortcut.unregisterAll();
    app.quit();
}

// Handle unexpected exits
process.on('exit', () => {
    if (flaskProcess && !flaskProcess.killed) {
        flaskProcess.kill();
    }
});
