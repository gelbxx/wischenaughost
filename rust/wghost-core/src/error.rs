//! Core layer error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("crypto error: {0}")]
    Crypto(#[from] wghost_crypto::CryptoError),

    #[error("network error: {0}")]
    Network(#[from] wghost_network::NetworkError),

    #[error("storage error: {0}")]
    Storage(#[from] wghost_storage::StorageError),

    #[error("initialization failed: {0}")]
    InitFailed(String),

    #[error("invalid state: {0}")]
    InvalidState(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;
