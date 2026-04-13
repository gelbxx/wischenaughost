//! Storage layer error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("migration failed: {0}")]
    MigrationFailed(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("encryption key error: {0}")]
    EncryptionKey(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;
