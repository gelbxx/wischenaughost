//! # Key Derivation Functions (KDF)
//!
//! KDFs are used throughout the Signal Protocol to derive new keys from
//! existing key material. Think of them as a secure way to "stretch" or
//! "split" a secret into multiple independent keys.
//!
//! We use **HKDF** (HMAC-based Key Derivation Function) as defined in RFC 5869.
//! HKDF has two steps:
//! 1. **Extract**: Take potentially weak input key material and produce a
//!    pseudorandom key (PRK). This "concentrates" the randomness.
//! 2. **Expand**: Take the PRK and produce as many output bytes as needed.
//!    The `info` parameter allows deriving different keys for different purposes
//!    from the same PRK.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::{CryptoError, Result};

/// Derive a fixed-size key using HKDF-SHA256.
///
/// # Parameters
/// - `ikm`: Input Key Material — the secret to derive from (e.g., a DH shared secret)
/// - `salt`: Optional salt value. Use `None` for a default salt of all zeros.
///   Salt adds extra randomness but is not required to be secret.
/// - `info`: Context string that binds the derived key to a specific purpose.
///   For example, "wg-root-key" vs "wg-chain-key" produce different keys
///   from the same input.
///
/// # Returns
/// A 32-byte derived key.
///
/// # Example
/// ```
/// use wghost_crypto::kdf::derive_key;
///
/// let shared_secret = [0x42u8; 32]; // from a DH exchange
/// let root_key = derive_key(&shared_secret, None, b"wg-root-key").unwrap();
/// let chain_key = derive_key(&shared_secret, None, b"wg-chain-key").unwrap();
///
/// // Same input, different info -> different keys
/// assert_ne!(root_key, chain_key);
/// ```
pub fn derive_key(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut output = [0u8; 32];
    hk.expand(info, &mut output)
        .map_err(|e| CryptoError::KdfError(format!("HKDF expand failed: {e}")))?;
    Ok(output)
}

/// Derive multiple keys at once from the same input material.
///
/// This is useful when you need both a new root key and a chain key
/// from a single DH output (as in the Double Ratchet's DH ratchet step).
///
/// # Parameters
/// - `ikm`: Input Key Material
/// - `salt`: Optional salt
/// - `info`: Context string
/// - `num_keys`: How many 32-byte keys to derive (max 8)
///
/// # Returns
/// A vector of 32-byte keys.
pub fn derive_multiple_keys(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    num_keys: usize,
) -> Result<Vec<[u8; 32]>> {
    if num_keys == 0 || num_keys > 8 {
        return Err(CryptoError::KdfError(
            "num_keys must be between 1 and 8".into(),
        ));
    }

    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let total_len = num_keys * 32;
    let mut output = vec![0u8; total_len];
    hk.expand(info, &mut output)
        .map_err(|e| CryptoError::KdfError(format!("HKDF expand failed: {e}")))?;

    // Split the output into individual 32-byte keys
    let keys: Vec<[u8; 32]> = output
        .chunks_exact(32)
        .map(|chunk| {
            let mut key = [0u8; 32];
            key.copy_from_slice(chunk);
            key
        })
        .collect();

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let ikm = b"test input key material";
        let key1 = derive_key(ikm, None, b"test-purpose").unwrap();
        let key2 = derive_key(ikm, None, b"test-purpose").unwrap();
        assert_eq!(key1, key2, "Same inputs must produce same output");
    }

    #[test]
    fn test_different_info_produces_different_keys() {
        let ikm = b"test input key material";
        let key1 = derive_key(ikm, None, b"purpose-a").unwrap();
        let key2 = derive_key(ikm, None, b"purpose-b").unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_salt_produces_different_keys() {
        let ikm = b"test input key material";
        let key1 = derive_key(ikm, Some(b"salt-a"), b"purpose").unwrap();
        let key2 = derive_key(ikm, Some(b"salt-b"), b"purpose").unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_multiple_keys() {
        let ikm = b"test input key material";
        let keys = derive_multiple_keys(ikm, None, b"multi", 3).unwrap();
        assert_eq!(keys.len(), 3);
        // All keys should be different from each other
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }
}
