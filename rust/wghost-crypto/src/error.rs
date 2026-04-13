//! Error types for the crypto layer.
//!
//! We define a single `CryptoError` enum that covers all possible failures
//! in cryptographic operations. This keeps error handling consistent across
//! the entire crypto module.

use thiserror::Error;

/// All possible errors from cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The provided key has an invalid length or format.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Signature verification failed — the message was tampered with
    /// or signed by a different key than expected.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// AEAD decryption failed — wrong key, corrupted ciphertext, or tampered data.
    #[error("decryption failed")]
    DecryptionFailed,

    /// The ratchet state is invalid or out of sync.
    #[error("ratchet error: {0}")]
    RatchetError(String),

    /// A required prekey was not found (e.g., the one-time prekey was already used).
    #[error("prekey not found: {0}")]
    PrekeyNotFound(String),

    /// Key derivation failed.
    #[error("key derivation failed: {0}")]
    KdfError(String),

    /// The message number is too far ahead, exceeding the maximum skip limit.
    #[error("too many skipped messages (max: {max}, requested: {requested})")]
    TooManySkippedMessages { max: u32, requested: u32 },
}

/// Convenience type alias for crypto operations.
pub type Result<T> = std::result::Result<T, CryptoError>;
