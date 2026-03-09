LANxfer is an open-source, offline-first peer-to-peer file transfer tool built for teams and corporate environments where internet access is restricted, unreliable, or simply unnecessary. Unlike relay-based tools (WeTransfer, file.pizza) or cloud-dependent services (Google Drive, Dropbox), LANxfer operates entirely within your local network — no accounts, no cloud storage, no internet required.

## The Problem

Transferring files between devices in a local network still involves unnecessary friction — emailing attachments (size limits), uploading to cloud (privacy concerns), or manually configuring network shares (requires technical setup). Existing tools like AirDrop are platform-locked, and browser-based P2P tools (WebRTC) fail silently on corporate NAT/firewall setups. There is no open-source, cross-platform, offline-native tool with a seamless desktop UX — until now.

## What LANxfer Does

LANxfer runs as a native system tray application (built with Tauri) that sits quietly in your taskbar. Press a hotkey, and a drag-and-drop overlay appears. Peers on your LAN are auto-discovered via mDNS (Zeroconf) — no IP addresses, no QR codes, no configuration. Drop a file onto a peer and it transfers instantly, encrypted end-to-end using AES-256 with ECDH session key exchange.

## Key Features

- **Zero internet dependency** — works over LAN, Wi-Fi Direct, Hotspot, or mobile tethering
- **Native tray app** — hotkey-triggered overlay, OS notifications, runs silently in background
- **mDNS auto-discovery** — peers appear automatically, no IP entry or manual pairing
- **Resumable block transfers** — chunked transfer with checkpointing; resumes from exact offset after disconnection
- **AES-256 + ECDH encryption** — fresh session key per transfer, no static secrets
- **Delta sync** — only transmits changed blocks when re-sending an existing file (rsync algorithm)
- **Clipboard sharing** — share text, URLs, and code snippets directly from the tray without creating a file
- **Transfer history** — local SQLite audit log with searchable, exportable records
- **Cross-platform** — Windows, macOS, Linux, and Android (browser-based peer)
- **Parallel multi-stream chunking** — saturates LAN bandwidth by splitting large files across concurrent streams

## Tech Stack

| Layer | Technology |
|---|---|
| Desktop Shell | Tauri 2.0 (Rust) |
| Backend / Transfer Engine | Python, Flask, Flask-SocketIO |
| Frontend UI | React, TailwindCSS |
| Peer Discovery | python-zeroconf (mDNS) |
| Encryption | AES-256-GCM + ECDH (cryptography library) |
| Delta Sync | librsync / rolling checksum |
| Transfer State | SQLite |
| Real-time Progress | WebSockets (Socket.IO) |

## Why Tauri over Electron

Tauri uses the OS-native webview and a Rust core, resulting in ~96% smaller bundle size and ~58% less memory usage compared to Electron — critical for a background tray app that should feel invisible.

## Competitive Differentiation

Compared to other submissions in this hackathon:
- **vs. Filevo** — Filevo routes all data through a relay server and requires internet. LANxfer is truly serverless and offline.
- **vs. ECO** — ECO uses WebRTC which fails on corporate NAT. LANxfer uses direct HTTP/WebSocket over LAN with no NAT dependency. Delta sync (rsync) is also more practically useful than Huffman coding for real-world file types.
- **vs. LocalSend / LANDrop** — Closed-architecture or limited extensibility. LANxfer is fully open-source, self-hostable, and hackable.

## Use Cases

- Engineering teams sharing build artifacts, logs, and configs without touching the internet
- Offices with air-gapped or restricted networks
- Field deployments (factories, hospitals, research stations) with no cloud access
- Quick device-to-device transfer without setting up shared folders or USB drives
