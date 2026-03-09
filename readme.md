LANxfer is an open-source, offline-first peer-to-peer file transfer tool built for teams and corporate environments where internet access is restricted, unreliable, or simply unnecessary. Unlike relay-based tools (WeTransfer, Filevo) or cloud-dependent services (Google Drive, Dropbox), LANxfer operates entirely within your local network — no accounts, no cloud storage, no internet required, ever.

## The Problem

Transferring files between devices on the same network still involves unnecessary friction — emailing attachments hits size limits, cloud services raise privacy concerns, and manual network share configuration requires IT involvement. Browser-based P2P tools using WebRTC fail silently on corporate NAT/firewall setups. Apple's AirDrop is platform-locked. There is no open-source, cross-platform, offline-native tool with a seamless desktop UX — until LANxfer.

## How It Works

LANxfer runs as a native system tray application (Electron 33) that sits silently in your taskbar. Press a configurable hotkey and a drag-and-drop overlay appears. Peers on your LAN are auto-discovered via mDNS (Zeroconf/Bonjour) — no IP addresses, no QR codes, no configuration needed. Drop a file onto a discovered peer and it transfers instantly, encrypted end-to-end with AES-256-GCM using an ECDH-negotiated session key — a fresh key per transfer, no static secrets.

## Architecture

Electron's main process spawns a Python Flask-SocketIO server on localhost at startup. The React frontend loads inside Electron's BrowserWindow as the tray overlay. The entire transfer engine, encryption, discovery, and state management runs in Python — Electron is purely the native desktop wrapper. This means the backend is fully usable standalone via any browser (including Android), while desktop users get the full native experience.

## Key Features

- **Zero internet dependency** — works over LAN, Wi-Fi Direct, Hotspot, or mobile tethering
- **Native tray app** — hotkey-triggered overlay, OS notifications, background operation (Electron)
- **mDNS auto-discovery** — peers appear automatically via python-zeroconf, no IP entry ever
- **Resumable block transfers** — files split into 4MB SHA-256-verified chunks; resumes from exact offset after disconnection
- **AES-256-GCM + ECDH encryption** — session key negotiated fresh per transfer via Elliptic Curve Diffie-Hellman
- **Delta sync** — re-sending a modified file transmits only changed byte ranges using librsync (rsync algorithm)
- **Clipboard sharing** — share text, URLs, and code snippets from the tray context menu without creating a file
- **Transfer history** — local SQLite audit log; searchable, filterable, exportable
- **Parallel multi-stream chunking** — large files split across concurrent Socket.IO streams to saturate LAN bandwidth
- **Cross-platform** — Windows, macOS, Linux (Electron), and Android (browser peer via Flask)

## Tech Stack

| Layer | Technology |
|---|---|
| Desktop Shell | Electron 33 + electron-builder |
| Transfer Engine | Python, Flask, Flask-SocketIO |
| Frontend | React, TailwindCSS |
| Peer Discovery | python-zeroconf (mDNS/Bonjour) |
| Encryption | AES-256-GCM + ECDH (Python cryptography lib) |
| Block Transfer | Custom chunked transfer + SHA-256 verification |
| Delta Sync | librsync (python-librsync bindings) |
| Transfer State | SQLite (Python built-in sqlite3) |
| Real-time Progress | WebSockets via Flask-SocketIO + socket.io-client |
| Packaging | electron-builder (.exe / .dmg / .deb / .AppImage) |

## Demo Scenario

Two laptops and a phone on a shared hotspot. Press hotkey → tray overlay appears → phone and second laptop auto-discovered via mDNS → drag a 2GB file → live per-chunk progress via Socket.IO → kill the Wi-Fi mid-transfer → reconnect → transfer resumes from exact byte offset → OS notification fires on completion → transfer log entry written to SQLite. Under 60 seconds, zero configuration, zero internet.
