//! # wghost-core
//!
//! Core orchestration layer for WischenauGhost.
//!
//! This crate ties together crypto, network, and storage into a coherent
//! application. It implements the main event loop:
//!
//! ```text
//! Incoming message
//!   -> Network receives encrypted envelope
//!   -> Crypto decrypts it (Double Ratchet)
//!   -> Storage persists the message
//!   -> UI is notified via callback
//!
//! Outgoing message
//!   -> UI sends plaintext
//!   -> Crypto encrypts it (Double Ratchet)
//!   -> Network sends to peer (or queues for offline delivery)
//!   -> Storage persists the message
//! ```

pub mod config;
mod error;

pub use error::{CoreError, Result};

// Re-export sub-crates for convenience
pub use wghost_crypto as crypto;
pub use wghost_network as network;
pub use wghost_storage as storage;
