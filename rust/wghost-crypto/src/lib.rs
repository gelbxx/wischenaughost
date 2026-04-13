//! # wghost-crypto
//!
//! Cryptographic layer for WischenauGhost P2P messenger.
//!
//! This crate implements the Signal Protocol adapted for peer-to-peer use:
//! - **Identity keys**: Ed25519 (signing) + X25519 (Diffie-Hellman key exchange)
//! - **X3DH**: Extended Triple Diffie-Hellman for async session establishment
//! - **Double Ratchet**: Per-message forward secrecy with DH + symmetric ratchets
//! - **Sender Keys**: Efficient group encryption
//! - **AEAD**: AES-256-GCM for file encryption
//!
//! ## Architecture
//!
//! This crate is pure crypto — no I/O, no networking, no storage.
//! It takes inputs and produces outputs. This makes it testable in isolation
//! and auditable without understanding the rest of the system.

pub mod identity;
pub mod x3dh;
pub mod double_ratchet;
pub mod sender_keys;
pub mod aead;
pub mod kdf;
pub mod safety_numbers;
mod error;

pub use error::{CryptoError, Result};
