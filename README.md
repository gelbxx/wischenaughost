# WischenauGhost

Peer-to-peer encrypted mobile messenger. No servers. No accounts. Just keys.

## What is this?

WischenauGhost is a mobile chat application where messages travel directly between devices — no central server stores or routes your messages. Communication is end-to-end encrypted using the Signal Protocol, and your identity is a cryptographic key pair, not a phone number.

## Features

- **True P2P**: Messages go directly between devices (or via encrypted relay when needed)
- **Signal Protocol encryption**: X3DH + Double Ratchet with Perfect Forward Secrecy
- **No registration**: Your identity is a key pair. No phone, no email, no account.
- **Offline delivery**: Encrypted store-and-forward via voluntary mailbox nodes
- **Group chat**: Efficient Sender Keys encryption for groups up to 256 members
- **File sharing**: Encrypted chunked P2P file transfer
- **Local search**: Full-text search on encrypted-at-rest database
- **Open source**: All crypto in auditable Rust

## Architecture

```
React Native (UI) → uniffi FFI → Rust Core
                                   ├── wghost-crypto (Signal Protocol)
                                   ├── wghost-network (libp2p, QUIC, DHT)
                                   └── wghost-storage (SQLCipher)
```

## Project Structure

| Directory | Description |
|---|---|
| `app/` | React Native mobile application |
| `rust/` | Rust workspace with all native logic |
| `bootstrap-node/` | Standalone bootstrap/relay server |
| `proto/` | Protocol Buffer definitions |
| `docs/` | Architecture and security documentation |

## Development

### Prerequisites

- Node.js 18+
- Rust 1.75+ (with Android/iOS cross-compilation targets)
- Android Studio (for Android development)
- React Native CLI

### Setup

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add Android cross-compilation targets
rustup target add aarch64-linux-android x86_64-linux-android

# Install React Native dependencies
cd app && npm install

# Build Rust workspace
cd rust && cargo build

# Run Android app
cd app && npx react-native run-android
```

## Status

🚧 **Phase 1: Foundation** — Project setup and crypto core implementation.

## License

MIT OR Apache-2.0
