# WischenauGhost Architecture

## Overview

WischenauGhost is a peer-to-peer encrypted mobile messenger. No central servers, no phone numbers, no accounts. Just cryptographic keys and direct communication.

## Layer Architecture

```
┌─────────────────────────────────────────┐
│          React Native (TypeScript)       │  UI Layer
│   Screens, Components, Navigation        │
├─────────────────────────────────────────┤
│          Service Layer (TypeScript)       │  Bridge
│   CryptoService, NetworkService, etc.    │
├─────────────────────────────────────────┤
│          uniffi FFI Bridge               │  FFI
│   Rust ↔ Kotlin (Android) / Swift (iOS) │
├─────────────────────────────────────────┤
│          wghost-core (Rust)              │  Orchestration
│   Event loop, lifecycle, coordination    │
├──────────┬───────────┬──────────────────┤
│ wghost-  │ wghost-   │ wghost-          │
│ crypto   │ network   │ storage          │  Core Modules
│ X3DH,    │ libp2p,   │ SQLCipher,       │
│ Ratchet  │ DHT, NAT  │ messages, keys   │
└──────────┴───────────┴──────────────────┘
```

## Key Design Principles

1. **No central server**: All communication is peer-to-peer
2. **End-to-end encryption**: Signal Protocol (X3DH + Double Ratchet)
3. **Offline-first**: Messages queue locally and deliver when peer is reachable
4. **Identity = public key**: No registration, no phone numbers
5. **Metadata minimization**: Even relay nodes see minimal metadata
6. **Open and auditable**: All crypto is in a standalone Rust crate

## Technology Choices

See the full plan in `.claude/plans/` for detailed rationale on each choice.

- **React Native** (New Architecture) for cross-platform UI
- **Rust** for all native logic (crypto, networking, storage)
- **libp2p** for P2P networking (QUIC, Kademlia DHT, Circuit Relay)
- **Signal Protocol** for E2E encryption
- **SQLite + SQLCipher** for encrypted local storage
- **Protocol Buffers** for wire format
