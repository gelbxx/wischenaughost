//! # Double Ratchet Algorithm
//!
//! The Double Ratchet provides end-to-end encryption with **Perfect Forward Secrecy**
//! on a per-message basis. Even if an attacker somehow gets the current encryption
//! key, they cannot decrypt past messages (forward secrecy) or future messages
//! (future secrecy / post-compromise security).
//!
//! ## The Two Ratchets
//!
//! ### 1. DH Ratchet (the "outer" ratchet)
//! Every time the conversation direction changes (Alice sends, then Bob replies),
//! a new Diffie-Hellman key exchange happens. This introduces fresh randomness
//! and provides future secrecy — even if the current state is compromised,
//! the next DH ratchet step "heals" the session.
//!
//! ### 2. Symmetric Ratchet (the "inner" ratchet)
//! Between DH ratchet steps (e.g., Alice sends 5 messages in a row), each
//! message gets a unique key derived from a chain key. The chain key is
//! advanced forward (like a hash chain), and the old chain key is deleted.
//! This provides forward secrecy for consecutive messages.
//!
//! ## Message Flow Example
//!
//! ```text
//! Alice sends msg 1:  [DH_A1] -> derive chain key -> message key 1
//! Alice sends msg 2:  [DH_A1] -> advance chain   -> message key 2
//! Bob receives both, then replies:
//! Bob sends msg 3:    [DH_B1] -> new DH ratchet  -> message key 3
//! Alice receives, then sends:
//! Alice sends msg 4:  [DH_A2] -> new DH ratchet  -> message key 4
//! ```
//!
//! Each `[DH_Xx]` is a new ephemeral DH key pair. The protocol automatically
//! ratchets forward, so old keys are deleted and cannot be recovered.
//!
//! ## Out-of-Order Messages
//!
//! In a P2P network, messages can arrive out of order (msg 3 before msg 2).
//! The Double Ratchet handles this by storing "skipped message keys" — if we
//! need to advance the chain past a message, we save the skipped keys so we
//! can decrypt that message when it eventually arrives.

// TODO: Implement in Week 3-4 (Phase 1: Crypto Core)
// - RatchetState struct (root key, chain keys, DH keys, message counters)
// - Initialize from X3DH shared secret
// - Encrypt message (advance sending chain)
// - Decrypt message (advance receiving chain, handle out-of-order)
// - DH ratchet step (on conversation direction change)
// - Skipped message key storage and retrieval
