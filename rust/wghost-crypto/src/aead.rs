//! # Authenticated Encryption with Associated Data (AEAD)
//!
//! This module provides AES-256-GCM encryption, which is used for:
//! - **File encryption**: Each shared file gets a random key, encrypted with AES-256-GCM
//! - **Message payload encryption**: The Double Ratchet's message keys feed into AES-256-GCM
//! - **Database encryption key wrapping**: Protecting the SQLCipher key
//!
//! ## What is AEAD?
//!
//! AEAD provides two guarantees:
//! 1. **Confidentiality**: Nobody can read the data without the key
//! 2. **Authenticity**: Nobody can modify the data without detection
//!
//! The "Associated Data" (AD) part lets you bind extra context to the
//! ciphertext. For example, you might include the sender's ID as AD —
//! this way, even if an attacker copies the ciphertext, they can't make
//! it look like it came from someone else.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

use crate::{CryptoError, Result};

/// Size of the AES-256-GCM nonce (96 bits = 12 bytes).
///
/// Each nonce MUST be unique for a given key. We generate random nonces,
/// which is safe as long as we don't encrypt more than ~2^32 messages
/// with the same key (the Double Ratchet ensures we don't).
const NONCE_SIZE: usize = 12;

/// Encrypt data using AES-256-GCM.
///
/// # Parameters
/// - `key`: 32-byte encryption key (from the Double Ratchet or randomly generated)
/// - `plaintext`: The data to encrypt
/// - `associated_data`: Extra context bound to the ciphertext (can be empty)
///
/// # Returns
/// `nonce || ciphertext || tag` concatenated together.
/// The nonce (12 bytes) is prepended so the decryptor knows what nonce was used.
///
/// # Example
/// ```
/// use wghost_crypto::aead::{encrypt, decrypt};
///
/// let key = [0x42u8; 32]; // In practice, use a key from the ratchet
/// let plaintext = b"Secret message for my friend";
/// let ad = b"sender:alice,recipient:bob";
///
/// let ciphertext = encrypt(&key, plaintext, ad).unwrap();
/// let decrypted = decrypt(&key, &ciphertext, ad).unwrap();
///
/// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
/// ```
pub fn encrypt(key: &[u8; 32], plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::InvalidKey(format!("invalid AES key: {e}")))?;

    // Generate a random nonce — critical for security!
    // Never reuse a nonce with the same key.
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload {
            msg: plaintext,
            aad: associated_data,
        })
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // Prepend nonce to ciphertext so the decryptor can extract it
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data that was encrypted with `encrypt()`.
///
/// # Parameters
/// - `key`: The same 32-byte key used for encryption
/// - `ciphertext`: The output from `encrypt()` (nonce || ciphertext || tag)
/// - `associated_data`: Must be the same AD used during encryption, or decryption fails
///
/// # Errors
/// Returns `DecryptionFailed` if:
/// - The key is wrong
/// - The ciphertext was tampered with
/// - The associated data doesn't match
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < NONCE_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::InvalidKey(format!("invalid AES key: {e}")))?;

    // Split the nonce from the actual ciphertext
    let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, aes_gcm::aead::Payload {
            msg: encrypted,
            aad: associated_data,
        })
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Generate a random 32-byte key for file encryption.
///
/// Each file gets its own random key. The key is then sent to the recipient
/// inside a Double Ratchet-encrypted message.
pub fn generate_file_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_file_key();
        let plaintext = b"Top secret message!";
        let ad = b"context";

        let ciphertext = encrypt(&key, plaintext, ad).unwrap();
        let decrypted = decrypt(&key, &ciphertext, ad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = generate_file_key();
        let key2 = generate_file_key();
        let plaintext = b"Secret";

        let ciphertext = encrypt(&key1, plaintext, b"").unwrap();
        assert!(decrypt(&key2, &ciphertext, b"").is_err());
    }

    #[test]
    fn test_wrong_ad_fails() {
        let key = generate_file_key();
        let plaintext = b"Secret";

        let ciphertext = encrypt(&key, plaintext, b"correct-ad").unwrap();
        assert!(decrypt(&key, &ciphertext, b"wrong-ad").is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = generate_file_key();
        let plaintext = b"Secret";

        let mut ciphertext = encrypt(&key, plaintext, b"").unwrap();
        // Flip a bit in the encrypted payload
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0x01;
        }
        assert!(decrypt(&key, &ciphertext, b"").is_err());
    }

    #[test]
    fn test_ciphertext_is_different_each_time() {
        let key = generate_file_key();
        let plaintext = b"Same message";

        let ct1 = encrypt(&key, plaintext, b"").unwrap();
        let ct2 = encrypt(&key, plaintext, b"").unwrap();

        // Random nonce ensures different ciphertexts even for same plaintext
        assert_ne!(ct1, ct2);
    }
}
