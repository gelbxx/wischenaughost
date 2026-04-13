# WischenauGhost Security Architecture

## Threat Model

WischenauGhost assumes:
- The network is hostile (all traffic may be observed)
- Relay/mailbox nodes are honest-but-curious (they follow the protocol but try to learn content)
- Endpoints (phones) are trusted while unlocked
- Long-term key compromise should not reveal past messages (forward secrecy)

## Encryption Layers

### Transport Layer (libp2p Noise)
All peer-to-peer connections are encrypted with the Noise protocol framework.
This protects against passive network observers.

### Application Layer (Signal Protocol)
All message content is end-to-end encrypted using:
- **X3DH**: Async key agreement (works even when recipient is offline)
- **Double Ratchet**: Per-message forward secrecy and post-compromise security
- **AES-256-GCM**: Symmetric encryption of message payloads

### Storage Layer (SQLCipher)
The local database is encrypted with AES-256 via SQLCipher.
The encryption key is stored in:
- Android Keystore (hardware-backed TEE)
- iOS Secure Enclave

## Key Hierarchy

```
Identity Key (permanent, hardware-backed)
├── Signed Prekey (rotated monthly)
├── One-Time Prekeys (pool of 100, used once each)
└── Session Keys (per conversation, evolved per message)
```

## Verification

Users can verify each other's identity via:
1. Safety numbers (60-digit code comparison)
2. QR code scanning (in-person verification)

Key changes trigger a visible warning.
