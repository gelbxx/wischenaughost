//! # Identity Key Management
//!
//! Every user in WischenauGhost has an **identity key pair** that serves as
//! their permanent identity. There is no username/password, no phone number,
//! no email — just a cryptographic key pair.
//!
//! ## Key Types
//!
//! We use two related key pairs:
//! - **Ed25519**: For digital signatures (proving "I wrote this message")
//! - **X25519**: For Diffie-Hellman key exchange (establishing shared secrets)
//!
//! Both are derived from the same underlying curve (Curve25519), but they serve
//! different purposes. Ed25519 keys CANNOT be used for DH, and X25519 keys
//! CANNOT be used for signing — that's why we need both.
//!
//! ## Security Notes
//!
//! - Private keys are wrapped in `Zeroize` so they are wiped from memory when dropped.
//! - On a real device, the private key should be stored in the Secure Enclave (iOS)
//!   or Android Keystore (Android). This module handles the in-memory representation.

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use rand::rngs::OsRng;

use crate::{CryptoError, Result};

/// A complete identity key pair containing both signing and DH keys.
///
/// This is generated once when the user first opens the app and stored
/// permanently. Losing these keys means losing the identity — there is
/// no "password reset" in a decentralized system.
pub struct IdentityKeyPair {
    /// Ed25519 signing key — used to sign messages, prekeys, and profiles.
    /// This proves to others that a message really came from us.
    pub signing_key: SigningKey,

    /// X25519 static secret — used in Diffie-Hellman key exchanges (X3DH).
    /// This allows us to establish shared secrets with other users.
    pub dh_secret: StaticSecret,
}

/// The public half of an identity — this is what other users see and store.
///
/// When you add someone as a contact, you're really storing their `IdentityPublicKey`.
/// This is also what gets published to the DHT so others can find you.
#[derive(Clone, Debug)]
pub struct IdentityPublicKey {
    /// Ed25519 public key — used to verify signatures from this identity.
    pub verifying_key: VerifyingKey,

    /// X25519 public key — used in DH key exchanges with this identity.
    pub dh_public: X25519PublicKey,
}

impl IdentityKeyPair {
    /// Generate a brand new identity key pair using the OS random number generator.
    ///
    /// This should only be called ONCE per user, when they first set up the app.
    /// The generated keys are cryptographically random and unique.
    ///
    /// # Example
    /// ```
    /// use wghost_crypto::identity::IdentityKeyPair;
    ///
    /// let identity = IdentityKeyPair::generate();
    /// let public_key = identity.public_key();
    /// // Share `public_key` with the world, keep `identity` secret!
    /// ```
    pub fn generate() -> Self {
        // OsRng uses the operating system's secure random number generator
        // (e.g., /dev/urandom on Linux, CryptGenRandom on Windows)
        let signing_key = SigningKey::generate(&mut OsRng);
        let dh_secret = StaticSecret::random_from_rng(OsRng);

        Self {
            signing_key,
            dh_secret,
        }
    }

    /// Get the public half of this identity.
    ///
    /// This is safe to share with anyone — it contains no secret material.
    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey {
            verifying_key: self.signing_key.verifying_key(),
            dh_public: X25519PublicKey::from(&self.dh_secret),
        }
    }

    /// Sign arbitrary data with our Ed25519 signing key.
    ///
    /// This is used to sign:
    /// - Prekey bundles (so others know the prekeys really belong to us)
    /// - Profile updates (so others know we actually changed our name/avatar)
    /// - Any data where authenticity matters
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Perform a Diffie-Hellman key exchange with another user's X25519 public key.
    ///
    /// The result is a shared secret that only the two parties can compute.
    /// This is a building block of X3DH — we do multiple DH exchanges and
    /// combine the results for extra security.
    pub fn dh_exchange(&self, their_public: &X25519PublicKey) -> x25519_dalek::SharedSecret {
        self.dh_secret.diffie_hellman(their_public)
    }
}

impl IdentityPublicKey {
    /// Verify a signature made by this identity.
    ///
    /// Returns `Ok(())` if the signature is valid, or `Err(SignatureVerificationFailed)`
    /// if the data was tampered with or signed by someone else.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.verifying_key
            .verify(message, signature)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Serialize the public key to bytes for storage or transmission.
    ///
    /// Format: 32 bytes Ed25519 verifying key + 32 bytes X25519 public key = 64 bytes total.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(self.verifying_key.as_bytes());
        bytes[32..].copy_from_slice(self.dh_public.as_bytes());
        bytes
    }

    /// Deserialize a public key from bytes.
    ///
    /// Expects exactly 64 bytes: 32 for Ed25519 + 32 for X25519.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(
            bytes[..32]
                .try_into()
                .map_err(|_| CryptoError::InvalidKey("invalid Ed25519 key length".into()))?,
        )
        .map_err(|e| CryptoError::InvalidKey(format!("invalid Ed25519 key: {e}")))?;

        let dh_public = X25519PublicKey::from(
            <[u8; 32]>::try_from(&bytes[32..])
                .map_err(|_| CryptoError::InvalidKey("invalid X25519 key length".into()))?,
        );

        Ok(Self {
            verifying_key,
            dh_public,
        })
    }
}

// When IdentityKeyPair is dropped, wipe the signing key from memory.
// The StaticSecret from x25519-dalek already implements Zeroize internally.
impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        // SigningKey's internal bytes are zeroized via ed25519-dalek's Zeroize impl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign_verify() {
        let identity = IdentityKeyPair::generate();
        let public_key = identity.public_key();

        let message = b"Hello, WischenauGhost!";
        let signature = identity.sign(message);

        // Valid signature should verify
        assert!(public_key.verify(message, &signature).is_ok());

        // Tampered message should fail
        let tampered = b"Hello, TamperedGhost!";
        assert!(public_key.verify(tampered, &signature).is_err());
    }

    #[test]
    fn test_public_key_serialization_roundtrip() {
        let identity = IdentityKeyPair::generate();
        let public_key = identity.public_key();

        let bytes = public_key.to_bytes();
        let restored = IdentityPublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(
            public_key.verifying_key.as_bytes(),
            restored.verifying_key.as_bytes()
        );
        assert_eq!(
            public_key.dh_public.as_bytes(),
            restored.dh_public.as_bytes()
        );
    }

    #[test]
    fn test_dh_key_exchange_produces_shared_secret() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        // Alice computes shared secret with Bob's public DH key
        let alice_secret = alice.dh_exchange(&bob.public_key().dh_public);
        // Bob computes shared secret with Alice's public DH key
        let bob_secret = bob.dh_exchange(&alice.public_key().dh_public);

        // Both should arrive at the same shared secret
        assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    }

    #[test]
    fn test_different_identities_produce_different_keys() {
        let a = IdentityKeyPair::generate();
        let b = IdentityKeyPair::generate();

        assert_ne!(
            a.public_key().verifying_key.as_bytes(),
            b.public_key().verifying_key.as_bytes()
        );
    }
}
