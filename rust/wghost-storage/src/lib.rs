//! # wghost-storage
//!
//! Encrypted local storage for WischenauGhost, built on **SQLite + SQLCipher**.
//!
//! All data is stored in a single encrypted SQLite database on the device.
//! SQLCipher provides transparent AES-256 encryption of the entire database file.
//!
//! ## What's stored
//!
//! - **Messages**: All sent and received messages (decrypted for search, encrypted at rest)
//! - **Contacts**: Friend list with identity keys and verification status
//! - **Sessions**: Double Ratchet session state (root keys, chain keys, counters)
//! - **Keys**: Prekeys, signed prekeys, one-time prekeys
//! - **Queue**: Outbound messages waiting to be delivered

pub mod database;
pub mod messages;
pub mod contacts;
pub mod sessions;
pub mod keys;
pub mod queue;
pub mod migrations;
mod error;

pub use error::{StorageError, Result};
