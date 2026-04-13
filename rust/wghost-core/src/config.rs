//! # Application Configuration
//!
//! Global configuration for the WischenauGhost node.

/// Configuration for the WischenauGhost node.
///
/// This is passed from the mobile app (via FFI) when starting the node.
pub struct NodeConfig {
    /// Path to the app's data directory (platform-specific).
    /// On Android: /data/data/com.wischenaughost/files
    /// On iOS: ~/Library/Application Support/WischenauGhost
    pub data_dir: String,

    /// Bootstrap node multiaddresses for initial DHT entry.
    /// Default list is provided, but users can add custom ones.
    pub bootstrap_nodes: Vec<String>,

    /// Maximum number of peer connections to maintain.
    pub max_connections: u32,

    /// Whether to enable mDNS for local network discovery.
    pub enable_mdns: bool,

    /// Whether this node should act as a mailbox relay for others.
    pub enable_mailbox_relay: bool,

    /// Port to listen on (0 = random available port).
    pub listen_port: u16,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: String::new(),
            bootstrap_nodes: vec![
                // Default bootstrap nodes (to be set up later)
                // "/dns4/bootstrap1.wischenaughost.net/tcp/4001/quic-v1".into(),
                // "/dns4/bootstrap2.wischenaughost.net/tcp/4001/quic-v1".into(),
            ],
            max_connections: 50,
            enable_mdns: true,
            enable_mailbox_relay: false,
            listen_port: 0,
        }
    }
}
