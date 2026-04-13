//! # wghost-network
//!
//! P2P networking layer for WischenauGhost, built on **libp2p**.
//!
//! This crate handles everything related to communication between peers:
//! - **Node lifecycle**: Starting/stopping the libp2p node
//! - **Peer discovery**: Finding other users via Kademlia DHT and mDNS
//! - **NAT traversal**: Getting through firewalls (AutoNAT, DCUtR, Circuit Relay)
//! - **Message transport**: Sending and receiving encrypted message envelopes
//! - **Mailbox protocol**: Store-and-forward for offline peers
//! - **File transfer**: Chunked transfer of encrypted files
//!
//! ## Transport: QUIC
//!
//! We use QUIC as the primary transport because:
//! - **Connection migration**: Seamlessly handles WiFi <-> cellular switches
//! - **Multiplexing**: Many streams over one connection (no head-of-line blocking)
//! - **0-RTT**: Faster reconnection to known peers
//! - **Battery efficient**: Fewer round trips than TCP

pub mod node;
pub mod discovery;
pub mod nat;
pub mod relay;
pub mod mailbox;
pub mod transport;
pub mod connection;
pub mod protocols;
mod error;

pub use error::{NetworkError, Result};
