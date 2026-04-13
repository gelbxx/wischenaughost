//! # Custom Application Protocols
//!
//! These are the application-level protocols that run on top of libp2p.
//! Each protocol defines a specific interaction pattern between peers.

pub mod messaging;
pub mod file_transfer;
pub mod prekey_fetch;
pub mod presence;
