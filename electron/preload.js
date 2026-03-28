const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    // Send OS notification from frontend JS
    notify: (title, body) =>
        ipcRenderer.send('notify', { title, body }),

    // Trigger transfer notifications
    transferComplete: (filename, peer) =>
        ipcRenderer.send('transfer-complete', { filename, peer }),

    transferFailed: (filename, peer) =>
        ipcRenderer.send('transfer-failed', { filename, peer }),

    // Get Flask URL
    getFlaskUrl: () => ipcRenderer.invoke('get-flask-url'),

    // Check if running inside Electron
    isElectron: true
});
