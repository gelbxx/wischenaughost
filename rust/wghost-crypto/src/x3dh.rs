//! # X3DH — Extended Triple Diffie-Hellman Key Agreement
//!
//! X3DH is the protocol that establishes an encrypted session between two users,
//! even when one of them is offline. This is the "handshake" that happens before
//! the Double Ratchet can begin.
//!
//! ## How it works (simplified)
//!
//! 1. **Bob publishes a "prekey bundle"** to the DHT:
//!    - His identity key (IK_B)
//!    - A signed prekey (SPK_B) — rotated monthly
//!    - One-time prekeys (OPK_B_1, OPK_B_2, ...) — each used once
//!
//! 2. **Alice wants to message Bob**:
//!    - She fetches Bob's prekey bundle from the DHT
//!    - She generates an ephemeral key pair (EK_A)
//!    - She computes 3 (or 4) Diffie-Hellman exchanges:
//!      - DH1 = DH(IK_A,  SPK_B)  — identity-to-signed-prekey
//!      - DH2 = DH(EK_A,  IK_B)   — ephemeral-to-identity
//!      - DH3 = DH(EK_A,  SPK_B)  — ephemeral-to-signed-prekey
//!      - DH4 = DH(EK_A,  OPK_B)  — ephemeral-to-one-time (if available)
//!    - She concatenates all DH outputs and runs HKDF → shared secret
//!
//! 3. **Alice sends an "initial message"** to Bob containing:
//!    - Her identity public key (IK_A)
//!    - Her ephemeral public key (EK_A)
//!    - Which OPK she used (index)
//!    - The first message encrypted with the shared secret
//!
//! 4. **Bob receives it and computes the same DH exchanges** from his side.
//!    Both arrive at the same shared secret. The Double Ratchet begins.

use ed25519_dalek::Signature;
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::{
    identity::{IdentityKeyPair, IdentityPublicKey},
    kdf::derive_key,
    Result,
};

// HKDF info strings — these bind each derived key to its specific purpose.
// Using different info strings ensures different outputs even from the same input.
const X3DH_INFO: &[u8] = b"WischenauGhost_X3DH_v1";
const X3DH_SALT: &[u8] = &[0u8; 32]; // Signal spec uses 32 zero bytes as salt

/// A one-time prekey — used exactly once for extra forward secrecy.
///
/// Once used in an X3DH exchange, the private key is permanently deleted.
/// This means that even if someone compromises the device later, they
/// cannot decrypt the first message in a session (that used this OPK).
pub struct OneTimePreKey {
    /// Unique index (so the recipient knows which OPK was used)
    pub index: u32,
    pub secret: StaticSecret,
    pub public: X25519PublicKey,
}

/// The public half of a one-time prekey — published to the DHT.
#[derive(Clone, Debug)]
pub struct OneTimePreKeyPublic {
    pub index: u32,
    pub public: X25519PublicKey,
}

/// A signed prekey — rotated every 30 days.
///
/// The signature (by the identity key) proves this prekey really belongs
/// to the user. Without this, an attacker could substitute their own prekey
/// and intercept messages.
pub struct SignedPreKey {
    pub secret: StaticSecret,
    pub public: X25519PublicKey,
    /// Ed25519 signature over the public key bytes, made by the identity key
    pub signature: Signature,
}

/// The public half of a signed prekey — published to the DHT.
#[derive(Clone, Debug)]
pub struct SignedPreKeyPublic {
    pub public: X25519PublicKey,
    pub signature: Signature,
}

/// A complete prekey bundle — published to the DHT by each user.
///
/// When Alice wants to start a conversation with Bob (even while Bob is offline),
/// she fetches Bob's prekey bundle and uses it to compute a shared secret.
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    /// Bob's long-term identity public key
    pub identity_key: IdentityPublicKey,
    /// Bob's signed prekey (rotated monthly)
    pub signed_prekey: SignedPreKeyPublic,
    /// One optional one-time prekey (the server/DHT provides one per session)
    pub one_time_prekey: Option<OneTimePreKeyPublic>,
}

impl PreKeyBundle {
    /// Verify that the signed prekey is genuinely signed by the identity key.
    ///
    /// Always call this before using a prekey bundle! If someone tampered with
    /// the bundle (e.g., replaced the signed prekey with their own), the signature
    /// check will fail and we abort.
    pub fn verify(&self) -> Result<()> {
        self.identity_key.verify(
            self.signed_prekey.public.as_bytes(),
            &self.signed_prekey.signature,
        )
    }
}

/// Generate a new signed prekey, signed by the identity key.
///
/// Called every 30 days to rotate the signed prekey.
pub fn generate_signed_prekey(identity: &IdentityKeyPair) -> SignedPreKey {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    // Sign the public key bytes with our identity key
    let signature = identity.sign(public.as_bytes());
    SignedPreKey { secret, public, signature }
}

/// Generate a batch of one-time prekeys.
///
/// Call this on first setup (generate 100) and replenish when the pool runs low.
/// Each OPK is used exactly once — after use, the secret is deleted.
pub fn generate_one_time_prekeys(start_index: u32, count: u32) -> Vec<OneTimePreKey> {
    (start_index..start_index + count)
        .map(|index| {
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = X25519PublicKey::from(&secret);
            OneTimePreKey { index, secret, public }
        })
        .collect()
}

/// The result of a successful X3DH key agreement — used to initialize the Double Ratchet.
pub struct X3DHOutput {
    /// The shared secret (32 bytes). Both parties derive the same value.
    /// Feed this into the Double Ratchet as the initial root key.
    pub shared_secret: [u8; 32],

    /// Alice's ephemeral public key — must be sent to Bob in the initial message
    /// so he can reproduce the DH exchanges from his side.
    pub ephemeral_public: X25519PublicKey,

    /// Which one-time prekey was used (Bob needs this to find the right OPK secret).
    pub used_opk_index: Option<u32>,
}

/// **Alice's side**: Initiate an X3DH session with Bob.
///
/// Alice computes the shared secret using Bob's prekey bundle.
/// She does NOT need Bob to be online — just his prekey bundle from the DHT.
///
/// # Arguments
/// - `alice_identity`: Alice's identity key pair
/// - `bob_bundle`: Bob's prekey bundle (fetched from DHT)
///
/// # Returns
/// An `X3DHOutput` containing the shared secret and the data Alice must send to Bob.
///
/// # Errors
/// Returns `SignatureVerificationFailed` if Bob's signed prekey signature is invalid.
pub fn x3dh_initiate(
    alice_identity: &IdentityKeyPair,
    bob_bundle: &PreKeyBundle,
) -> Result<X3DHOutput> {
    // Step 1: Verify Bob's signed prekey is genuine
    // If this fails, someone tampered with the prekey bundle — abort!
    bob_bundle.verify()?;

    // Step 2: Generate Alice's ephemeral key pair
    // This is a fresh random key pair used only for this session.
    let ek_alice_secret = StaticSecret::random_from_rng(OsRng);
    let ek_alice_public = X25519PublicKey::from(&ek_alice_secret);

    // Step 3: Compute the Diffie-Hellman exchanges
    //
    // Each DH() call produces a 32-byte shared secret. We concatenate them all
    // and feed into HKDF. The more DH exchanges, the stronger the guarantee.
    //
    // DH1: Alice's identity <-> Bob's signed prekey
    //   Purpose: Proves Alice's identity to Bob (she used her identity key)
    let dh1 = alice_identity.dh_exchange(&bob_bundle.signed_prekey.public);

    // DH2: Alice's ephemeral <-> Bob's identity
    //   Purpose: Forward secrecy if Alice's identity key is later compromised
    let dh2 = ek_alice_secret.diffie_hellman(&bob_bundle.identity_key.dh_public);

    // DH3: Alice's ephemeral <-> Bob's signed prekey
    //   Purpose: Forward secrecy if Bob's identity key is later compromised
    let dh3 = ek_alice_secret.diffie_hellman(&bob_bundle.signed_prekey.public);

    // DH4 (optional): Alice's ephemeral <-> Bob's one-time prekey
    //   Purpose: Extra forward secrecy — this OPK is used only once and then deleted
    let (dh4_bytes, used_opk_index) = match &bob_bundle.one_time_prekey {
        Some(opk) => {
            let dh4 = ek_alice_secret.diffie_hellman(&opk.public);
            (Some(*dh4.as_bytes()), Some(opk.index))
        }
        None => (None, None),
    };

    // Step 4: Combine all DH outputs with HKDF
    // Concatenate: DH1 || DH2 || DH3 || DH4 (if present)
    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    if let Some(dh4) = dh4_bytes {
        ikm.extend_from_slice(&dh4);
    }

    let shared_secret = derive_key(&ikm, Some(X3DH_SALT), X3DH_INFO)?;

    // Step 5: Wipe intermediate DH secrets from memory
    // (Rust drops them automatically, and the types implement Zeroize)
    drop(dh1);
    drop(dh2);
    drop(dh3);
    ikm.zeroize();

    Ok(X3DHOutput {
        shared_secret,
        ephemeral_public: ek_alice_public,
        used_opk_index,
    })
}

/// The initial message header that Alice sends to Bob.
///
/// Bob needs this information to reproduce the DH exchanges from his side
/// and arrive at the same shared secret.
pub struct X3DHInitialMessage {
    /// Alice's identity public key
    pub alice_identity_public: IdentityPublicKey,
    /// Alice's ephemeral public key (generated fresh for this session)
    pub alice_ephemeral_public: X25519PublicKey,
    /// Which of Bob's one-time prekeys Alice used (if any)
    pub used_opk_index: Option<u32>,
}

/// **Bob's side**: Complete the X3DH session initiated by Alice.
///
/// Bob receives Alice's initial message, finds the relevant prekeys from his
/// local storage, and computes the same shared secret as Alice.
///
/// # Arguments
/// - `bob_identity`: Bob's identity key pair
/// - `bob_signed_prekey`: The signed prekey Bob currently has (must match what Alice used)
/// - `bob_opk`: The one-time prekey Alice used (if any) — deleted after this call!
/// - `msg`: The initial message header from Alice
///
/// # Returns
/// The shared secret — identical to what Alice computed.
pub fn x3dh_respond(
    bob_identity: &IdentityKeyPair,
    bob_signed_prekey: &SignedPreKey,
    bob_opk: Option<OneTimePreKey>,
    msg: &X3DHInitialMessage,
) -> Result<[u8; 32]> {
    // Bob computes the same 3-4 DH exchanges, but from his perspective:
    // (Note: DH is symmetric — DH(a, B) == DH(b, A) where B=b*G, A=a*G)

    // DH1: Bob's signed prekey <-> Alice's identity
    //   (same as Alice's DH1 = DH(IK_A, SPK_B))
    let dh1 = bob_signed_prekey.secret.diffie_hellman(&msg.alice_identity_public.dh_public);

    // DH2: Bob's identity <-> Alice's ephemeral
    //   (same as Alice's DH2 = DH(EK_A, IK_B))
    let dh2 = bob_identity.dh_exchange(&msg.alice_ephemeral_public);

    // DH3: Bob's signed prekey <-> Alice's ephemeral
    //   (same as Alice's DH3 = DH(EK_A, SPK_B))
    let dh3 = bob_signed_prekey.secret.diffie_hellman(&msg.alice_ephemeral_public);

    // DH4 (optional): Bob's one-time prekey <-> Alice's ephemeral
    let dh4_bytes = match bob_opk {
        Some(opk) => {
            let dh4 = opk.secret.diffie_hellman(&msg.alice_ephemeral_public);
            Some(*dh4.as_bytes())
            // opk.secret is dropped here — the one-time prekey is permanently deleted!
        }
        None => None,
    };

    // Combine with HKDF — must use identical parameters as Alice
    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    if let Some(dh4) = dh4_bytes {
        ikm.extend_from_slice(&dh4);
    }

    let shared_secret = derive_key(&ikm, Some(X3DH_SALT), X3DH_INFO)?;

    ikm.zeroize();

    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeyPair;

    /// Helper: generate a complete prekey bundle for a user.
    fn make_bundle(
        identity: &IdentityKeyPair,
        with_opk: bool,
    ) -> (PreKeyBundle, SignedPreKey, Option<OneTimePreKey>) {
        let spk = generate_signed_prekey(identity);
        let spk_public = SignedPreKeyPublic {
            public: spk.public,
            signature: spk.signature,
        };

        let (opk_secret, opk_public) = if with_opk {
            let mut opks = generate_one_time_prekeys(0, 1);
            let opk = opks.remove(0);
            let pub_key = OneTimePreKeyPublic { index: opk.index, public: opk.public };
            (Some(opk), Some(pub_key))
        } else {
            (None, None)
        };

        let bundle = PreKeyBundle {
            identity_key: identity.public_key(),
            signed_prekey: spk_public,
            one_time_prekey: opk_public,
        };

        (bundle, spk, opk_secret)
    }

    #[test]
    fn test_x3dh_with_opk_produces_same_secret() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let (bob_bundle, bob_spk, bob_opk) = make_bundle(&bob, true);

        // Alice initiates
        let alice_output = x3dh_initiate(&alice, &bob_bundle).unwrap();

        // Bob responds
        let bob_secret = x3dh_respond(
            &bob,
            &bob_spk,
            bob_opk,
            &X3DHInitialMessage {
                alice_identity_public: alice.public_key(),
                alice_ephemeral_public: alice_output.ephemeral_public,
                used_opk_index: alice_output.used_opk_index,
            },
        ).unwrap();

        // Both must arrive at the same shared secret
        assert_eq!(alice_output.shared_secret, bob_secret);
    }

    #[test]
    fn test_x3dh_without_opk_produces_same_secret() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let (bob_bundle, bob_spk, _) = make_bundle(&bob, false);

        let alice_output = x3dh_initiate(&alice, &bob_bundle).unwrap();
        assert!(alice_output.used_opk_index.is_none());

        let bob_secret = x3dh_respond(
            &bob,
            &bob_spk,
            None,
            &X3DHInitialMessage {
                alice_identity_public: alice.public_key(),
                alice_ephemeral_public: alice_output.ephemeral_public,
                used_opk_index: None,
            },
        ).unwrap();

        assert_eq!(alice_output.shared_secret, bob_secret);
    }

    #[test]
    fn test_x3dh_different_sessions_produce_different_secrets() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let (bundle1, _, _) = make_bundle(&bob, false);
        let (bundle2, _, _) = make_bundle(&bob, false);

        let out1 = x3dh_initiate(&alice, &bundle1).unwrap();
        let out2 = x3dh_initiate(&alice, &bundle2).unwrap();

        // Each session produces a different shared secret
        assert_ne!(out1.shared_secret, out2.shared_secret);
    }

    #[test]
    fn test_tampered_signed_prekey_fails_verification() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let mallory = IdentityKeyPair::generate(); // attacker

        let (mut bob_bundle, _, _) = make_bundle(&bob, false);

        // Mallory replaces Bob's signed prekey with her own (man-in-the-middle attempt)
        let mallory_spk = generate_signed_prekey(&mallory);
        bob_bundle.signed_prekey = SignedPreKeyPublic {
            public: mallory_spk.public,
            signature: mallory_spk.signature, // signed by Mallory, not Bob!
        };

        // Alice should detect the tampering and refuse to proceed
        let result = x3dh_initiate(&alice, &bob_bundle);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_one_time_prekeys_batch() {
        let opks = generate_one_time_prekeys(0, 100);
        assert_eq!(opks.len(), 100);
        // All indices should be sequential
        for (i, opk) in opks.iter().enumerate() {
            assert_eq!(opk.index, i as u32);
        }
        // All public keys should be unique
        let mut publics: Vec<_> = opks.iter().map(|k| k.public.as_bytes().to_vec()).collect();
        publics.dedup();
        assert_eq!(publics.len(), 100);
    }
}
