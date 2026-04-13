//! # WischenauGhost Bootstrap Node
//!
//! A lightweight server that helps new peers join the P2P network.
//!
//! It provides:
//! - **Kademlia DHT**: Helps peers find each other
//! - **Circuit Relay v2**: Relays traffic for peers behind strict NATs
//! - **Identify**: Shares peer info for protocol negotiation
//!
//! The bootstrap node stores NO messages and sees NO message content.
//! It only helps with network connectivity.
//!
//! ## Running
//! ```bash
//! cargo run --release -- --port 4001
//! ```

fn main() {
    println!("WischenauGhost Bootstrap Node v0.1.0");
    println!("TODO: Implement in Phase 1, Week 5-6");
}
