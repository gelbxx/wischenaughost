//! Network layer error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("failed to start node: {0}")]
    NodeStartFailed(String),

    #[error("peer not found: {0}")]
    PeerNotFound(String),

    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("NAT traversal failed: {0}")]
    NatTraversalFailed(String),

    #[error("mailbox error: {0}")]
    MailboxError(String),

    #[error("protocol error: {0}")]
    ProtocolError(String),

    #[error("transport error: {0}")]
    TransportError(String),

    #[error("DHT error: {0}")]
    DhtError(String),

    #[error("timeout: {0}")]
    Timeout(String),
}

pub type Result<T> = std::result::Result<T, NetworkError>;
