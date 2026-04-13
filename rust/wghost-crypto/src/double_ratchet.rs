//! # Double Ratchet Algorithm
//!
//! The Double Ratchet provides end-to-end encryption with **Perfect Forward Secrecy**
//! on a per-message basis. Even if an attacker gets the current encryption key,
//! they cannot decrypt past messages (forward secrecy) or future messages
//! (post-compromise security / future secrecy).
//!
//! ## The Two Ratchets
//!
//! ### 1. DH Ratchet (the "outer" ratchet)
//! Every time the conversation direction changes (Alice sends, then Bob replies),
//! a new Diffie-Hellman key exchange happens automatically. This "heals" the
//! session — even after a compromise, the next DH step introduces fresh randomness.
//!
//! ### 2. Symmetric Ratchet (the "inner" ratchet)
//! Between DH steps, each message advances a chain key (HMAC-based hash chain).
//! Each message gets a unique key derived from the chain. Old chain keys are deleted.
//!
//! ## State diagram
//!
//! ```text
//! [X3DH shared secret]
//!         |
//!         v
//! ┌─────────────────────────────────────┐
//! │           RatchetState              │
//! │                                     │
//! │  root_key: [u8; 32]                 │  ← updated on each DH step
//! │  sending_chain_key: [u8; 32]        │  ← advanced on each send
//! │  receiving_chain_key: [u8; 32]      │  ← advanced on each receive
//! │  dh_sending_key: X25519 keypair     │  ← new on each DH step
//! │  dh_receiving_key: X25519 pubkey    │  ← set when we receive a new DH key
//! │  send_count: u32                    │  ← messages sent in current chain
//! │  recv_count: u32                    │  ← messages received in current chain
//! │  prev_send_count: u32               │  ← length of previous sending chain
//! │  skipped_keys: HashMap<..., key>    │  ← keys for out-of-order messages
//! └─────────────────────────────────────┘
//! ```
//!
//! ## Out-of-Order Messages
//!
//! In a P2P network, messages frequently arrive out of order. The Double Ratchet
//! handles this by storing "skipped" message keys. If message 3 arrives before
//! message 2, we advance the chain to generate key 3 (storing key 2 as skipped),
//! decrypt message 3, then use the stored key 2 when message 2 eventually arrives.

use std::collections::HashMap;
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::{
    aead::{encrypt, decrypt},
    kdf::{derive_key, derive_multiple_keys},
    CryptoError, Result,
};

// KDF context strings — bind each derived key to its specific purpose
const KDF_ROOT_INFO: &[u8]    = b"WischenauGhost_RootKDF_v1";
const KDF_CHAIN_INFO: &[u8]   = b"WischenauGhost_ChainKDF_v1";
const KDF_MSG_INFO: &[u8]     = b"WischenauGhost_MessageKey_v1";

/// Maximum number of skipped message keys we'll store.
///
/// If a peer sends more than this many messages without us receiving them,
/// we refuse to store more skipped keys (protection against DoS attacks).
const MAX_SKIP: u32 = 1000;

/// Identifies a specific message key in the skipped keys map.
/// (DH public key of the chain, message number within that chain)
type SkipKey = ([u8; 32], u32);

/// The full state of a Double Ratchet session between two users.
///
/// This state must be persisted to storage between app sessions
/// (serialized and stored encrypted in SQLCipher).
pub struct RatchetState {
    /// Root key — 32 bytes shared between both parties.
    /// Updated on every DH ratchet step via KDF.
    root_key: [u8; 32],

    /// Sending chain key — advances with every outgoing message.
    /// Becomes None until we've performed the first DH ratchet step.
    sending_chain_key: Option<[u8; 32]>,

    /// Receiving chain key — advances with every incoming message.
    receiving_chain_key: Option<[u8; 32]>,

    /// Our current DH sending key pair.
    /// We generate a new one on every DH ratchet step (when the other side sends).
    dh_sending_secret: StaticSecret,
    dh_sending_public: X25519PublicKey,

    /// The other party's most recent DH public key.
    /// Set when we receive their first message.
    dh_receiving_public: Option<X25519PublicKey>,

    /// How many messages we've sent in the current sending chain.
    send_count: u32,

    /// How many messages we've received in the current receiving chain.
    recv_count: u32,

    /// Length of the previous sending chain.
    /// Sent in message headers so the recipient can handle out-of-order delivery.
    prev_send_count: u32,

    /// Skipped message keys — stored for out-of-order decryption.
    /// Key: (dh_public_key_bytes, message_number), Value: message_key
    skipped_keys: HashMap<SkipKey, [u8; 32]>,
}

/// A message header sent alongside each encrypted message.
///
/// The recipient needs this to:
/// 1. Detect if a DH ratchet step is needed (new dh_public)
/// 2. Know which message key to use (message_number, prev_chain_length)
#[derive(Debug, Clone)]
pub struct MessageHeader {
    /// Sender's current DH ratchet public key
    pub dh_public: X25519PublicKey,
    /// Message number within the current sending chain (starts at 0)
    pub message_number: u32,
    /// Length of the sender's previous sending chain
    /// (used to fill in skipped keys if messages arrive out of order)
    pub prev_chain_length: u32,
}

/// An encrypted message ready to send over the network.
#[derive(Debug)]
pub struct EncryptedMessage {
    pub header: MessageHeader,
    /// AES-256-GCM ciphertext (nonce || ciphertext || tag)
    pub ciphertext: Vec<u8>,
}

impl RatchetState {
    /// Initialize the ratchet for the **sender** (Alice).
    ///
    /// Called after X3DH completes. Alice knows the shared secret and Bob's
    /// signed prekey public key. She performs the first DH ratchet step immediately.
    ///
    /// # Arguments
    /// - `shared_secret`: Output of X3DH (32 bytes)
    /// - `bob_dh_public`: Bob's signed prekey public key (used as initial receiving key)
    pub fn init_sender(shared_secret: [u8; 32], bob_dh_public: X25519PublicKey) -> Result<Self> {
        // Generate our initial DH sending key pair
        let dh_sending_secret = StaticSecret::random_from_rng(OsRng);
        let dh_sending_public = X25519PublicKey::from(&dh_sending_secret);

        // Perform the first DH ratchet step immediately:
        // compute DH(our_new_key, bob's_signed_prekey) and derive new root + chain keys
        let dh_output = dh_sending_secret.diffie_hellman(&bob_dh_public);
        let (new_root_key, sending_chain_key) = kdf_root(&shared_secret, dh_output.as_bytes())?;

        Ok(Self {
            root_key: new_root_key,
            sending_chain_key: Some(sending_chain_key),
            receiving_chain_key: None,
            dh_sending_secret,
            dh_sending_public,
            dh_receiving_public: Some(bob_dh_public),
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_keys: HashMap::new(),
        })
    }

    /// Initialize the ratchet for the **receiver** (Bob).
    ///
    /// Called when Bob receives Alice's first message. Bob knows the shared secret
    /// and his own signed prekey (used as the initial DH key).
    ///
    /// # Arguments
    /// - `shared_secret`: Output of X3DH (32 bytes)
    /// - `bob_spk_secret`: Bob's signed prekey secret (the initial DH key)
    pub fn init_receiver(shared_secret: [u8; 32], bob_spk_secret: StaticSecret) -> Self {
        let bob_spk_public = X25519PublicKey::from(&bob_spk_secret);

        Self {
            root_key: shared_secret,
            sending_chain_key: None,
            receiving_chain_key: None,
            dh_sending_secret: bob_spk_secret,
            dh_sending_public: bob_spk_public,
            dh_receiving_public: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Encrypt a message to send to the other party.
    ///
    /// Advances the sending chain key by one step, derives a fresh message key,
    /// and encrypts the plaintext. The old chain key is overwritten (deleted).
    ///
    /// # Arguments
    /// - `plaintext`: The message content (UTF-8 text or serialized protobuf)
    /// - `associated_data`: Extra context bound to the ciphertext (e.g., conversation ID).
    ///   Must be provided identically on decryption.
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<EncryptedMessage> {
        // Advance the sending symmetric ratchet
        let (new_chain_key, message_key) = kdf_chain(
            self.sending_chain_key
                .as_ref()
                .ok_or_else(|| CryptoError::RatchetError(
                    "no sending chain key — did you call init_sender?".into()
                ))?,
        )?;

        self.sending_chain_key = Some(new_chain_key);

        let header = MessageHeader {
            dh_public: self.dh_sending_public,
            message_number: self.send_count,
            prev_chain_length: self.prev_send_count,
        };

        self.send_count += 1;

        // Encrypt with the message key
        // The header bytes are used as associated data to bind header + ciphertext together
        let header_bytes = header_to_bytes(&header);
        let mut full_ad = Vec::with_capacity(associated_data.len() + header_bytes.len());
        full_ad.extend_from_slice(&header_bytes);
        full_ad.extend_from_slice(associated_data);

        let ciphertext = encrypt(&message_key, plaintext, &full_ad)?;

        Ok(EncryptedMessage { header, ciphertext })
    }

    /// Decrypt a received message.
    ///
    /// Handles:
    /// - Normal in-order messages (just advance the chain)
    /// - DH ratchet steps (when we see a new DH public key in the header)
    /// - Out-of-order messages (stored skipped keys)
    ///
    /// # Arguments
    /// - `msg`: The encrypted message received from the other party
    /// - `associated_data`: Same AD used during encryption
    pub fn decrypt(&mut self, msg: &EncryptedMessage, associated_data: &[u8]) -> Result<Vec<u8>> {
        let header_bytes = header_to_bytes(&msg.header);
        let mut full_ad = Vec::with_capacity(associated_data.len() + header_bytes.len());
        full_ad.extend_from_slice(&header_bytes);
        full_ad.extend_from_slice(associated_data);

        // Check if we already have this key in skipped keys
        // (handles out-of-order messages that were previously fast-forwarded past)
        let skip_key = (*msg.header.dh_public.as_bytes(), msg.header.message_number);
        if let Some(message_key) = self.skipped_keys.remove(&skip_key) {
            return decrypt(&message_key, &msg.ciphertext, &full_ad);
        }

        // Check if the incoming DH key is new → need a DH ratchet step
        let is_new_dh_key = match &self.dh_receiving_public {
            None => true,
            Some(current) => current.as_bytes() != msg.header.dh_public.as_bytes(),
        };

        if is_new_dh_key {
            // Store skipped keys from the current receiving chain
            // (in case messages from the old chain arrive late)
            self.skip_message_keys(msg.header.prev_chain_length)?;

            // Perform the DH ratchet step for the new receiving chain
            self.dh_ratchet_step(&msg.header.dh_public)?;
        }

        // Store any skipped keys in the new receiving chain
        self.skip_message_keys(msg.header.message_number)?;

        // Derive the message key for this specific message
        let (new_chain_key, message_key) = kdf_chain(
            self.receiving_chain_key
                .as_ref()
                .ok_or_else(|| CryptoError::RatchetError(
                    "no receiving chain key after DH ratchet step".into()
                ))?,
        )?;

        self.receiving_chain_key = Some(new_chain_key);
        self.recv_count += 1;

        decrypt(&message_key, &msg.ciphertext, &full_ad)
    }

    /// Perform a DH ratchet step.
    ///
    /// Called when we receive a message with a new DH public key.
    /// This derives a new receiving chain and a new sending chain,
    /// advancing the root key in the process.
    fn dh_ratchet_step(&mut self, their_new_dh_public: &X25519PublicKey) -> Result<()> {
        // Step 1: Derive new receiving chain from current sending key + their new DH key
        let dh_recv = self.dh_sending_secret.diffie_hellman(their_new_dh_public);
        let (new_root_key, recv_chain_key) = kdf_root(&self.root_key, dh_recv.as_bytes())?;

        // Step 2: Generate our new DH sending key pair
        let new_sending_secret = StaticSecret::random_from_rng(OsRng);
        let new_sending_public = X25519PublicKey::from(&new_sending_secret);

        // Step 3: Derive new sending chain from new root key + new DH key exchange
        let dh_send = new_sending_secret.diffie_hellman(their_new_dh_public);
        let (final_root_key, send_chain_key) = kdf_root(&new_root_key, dh_send.as_bytes())?;

        // Update state
        self.prev_send_count = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;
        self.root_key = final_root_key;
        self.receiving_chain_key = Some(recv_chain_key);
        self.sending_chain_key = Some(send_chain_key);
        self.dh_receiving_public = Some(*their_new_dh_public);
        self.dh_sending_secret = new_sending_secret;
        self.dh_sending_public = new_sending_public;

        Ok(())
    }

    /// Store skipped message keys up to `until_count`.
    ///
    /// Called before advancing the chain, so that out-of-order messages
    /// can still be decrypted when they eventually arrive.
    fn skip_message_keys(&mut self, until_count: u32) -> Result<()> {
        if until_count.saturating_sub(self.recv_count) > MAX_SKIP {
            return Err(CryptoError::TooManySkippedMessages {
                max: MAX_SKIP,
                requested: until_count.saturating_sub(self.recv_count),
            });
        }

        if let Some(mut chain_key) = self.receiving_chain_key {
            while self.recv_count < until_count {
                let (new_chain_key, message_key) = kdf_chain(&chain_key)?;
                chain_key = new_chain_key;

                let skip_key = (*self.dh_receiving_public
                    .as_ref()
                    .map(|k| k.as_bytes())
                    .unwrap_or(&[0u8; 32]), self.recv_count);

                self.skipped_keys.insert(skip_key, message_key);
                self.recv_count += 1;
            }
            self.receiving_chain_key = Some(chain_key);
        }

        Ok(())
    }
}

/// Root KDF step: derive new root key + chain key from current root key + DH output.
///
/// This is called on every DH ratchet step. The root key acts as a "master key"
/// that mixes in DH randomness and produces the next chain key.
fn kdf_root(root_key: &[u8; 32], dh_output: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    // Use the root key as HKDF salt and the DH output as input key material
    let keys = derive_multiple_keys(dh_output, Some(root_key), KDF_ROOT_INFO, 2)?;
    Ok((keys[0], keys[1]))
}

/// Chain KDF step: derive new chain key + message key from current chain key.
///
/// Called for every message sent or received. The chain key advances forward
/// (old value is replaced), and the message key is used for one message then discarded.
fn kdf_chain(chain_key: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    // New chain key: HKDF(chain_key, info="chain")
    let new_chain_key = derive_key(chain_key, None, KDF_CHAIN_INFO)?;
    // Message key: HKDF(chain_key, info="message")
    let message_key = derive_key(chain_key, None, KDF_MSG_INFO)?;
    Ok((new_chain_key, message_key))
}

/// Serialize a message header to bytes for use as associated data.
fn header_to_bytes(header: &MessageHeader) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 4 + 4);
    bytes.extend_from_slice(header.dh_public.as_bytes());
    bytes.extend_from_slice(&header.message_number.to_le_bytes());
    bytes.extend_from_slice(&header.prev_chain_length.to_le_bytes());
    bytes
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        // Zeroize sensitive key material when the state is dropped
        self.root_key.zeroize();
        if let Some(ref mut k) = self.sending_chain_key { k.zeroize(); }
        if let Some(ref mut k) = self.receiving_chain_key { k.zeroize(); }
        for (_, v) in self.skipped_keys.iter_mut() { v.zeroize(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::IdentityKeyPair,
        x3dh::{
            generate_signed_prekey, generate_one_time_prekeys,
            x3dh_initiate, x3dh_respond,
            PreKeyBundle, SignedPreKeyPublic, OneTimePreKeyPublic, X3DHInitialMessage,
        },
    };

    /// Set up a full X3DH + Double Ratchet session between Alice and Bob.
    fn setup_session() -> (RatchetState, RatchetState) {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();

        // Bob generates his prekeys
        let bob_spk = generate_signed_prekey(&bob_identity);
        let bob_spk_public = SignedPreKeyPublic {
            public: bob_spk.public,
            signature: bob_spk.signature,
        };
        let mut bob_opks = generate_one_time_prekeys(0, 1);
        let bob_opk = bob_opks.remove(0);
        let bob_opk_public = OneTimePreKeyPublic { index: bob_opk.index, public: bob_opk.public };

        let bob_bundle = PreKeyBundle {
            identity_key: bob_identity.public_key(),
            signed_prekey: bob_spk_public,
            one_time_prekey: Some(bob_opk_public),
        };

        // Alice performs X3DH
        let alice_x3dh = x3dh_initiate(&alice_identity, &bob_bundle).unwrap();

        // Bob performs X3DH
        let bob_secret = x3dh_respond(
            &bob_identity,
            &bob_spk,
            Some(bob_opk),
            &X3DHInitialMessage {
                alice_identity_public: alice_identity.public_key(),
                alice_ephemeral_public: alice_x3dh.ephemeral_public,
                used_opk_index: alice_x3dh.used_opk_index,
            },
        ).unwrap();

        // Initialize Double Ratchet
        // Alice knows bob_spk.public (from the bundle), Bob knows his own spk_secret
        let alice_ratchet = RatchetState::init_sender(
            alice_x3dh.shared_secret,
            bob_bundle.signed_prekey.public,
        ).unwrap();

        let bob_ratchet = RatchetState::init_receiver(bob_secret, bob_spk.secret);

        (alice_ratchet, bob_ratchet)
    }

    #[test]
    fn test_basic_send_receive() {
        let (mut alice, mut bob) = setup_session();
        let ad = b"alice-bob-conversation";

        let msg = alice.encrypt(b"Hello Bob!", ad).unwrap();
        let plaintext = bob.decrypt(&msg, ad).unwrap();

        assert_eq!(plaintext, b"Hello Bob!");
    }

    #[test]
    fn test_multiple_messages_alice_to_bob() {
        let (mut alice, mut bob) = setup_session();
        let ad = b"conversation";

        let messages = [b"msg 1".as_slice(), b"msg 2", b"msg 3", b"msg 4", b"msg 5"];
        let mut encrypted = Vec::new();
        for msg in &messages {
            encrypted.push(alice.encrypt(msg, ad).unwrap());
        }
        for (i, enc) in encrypted.into_iter().enumerate() {
            let plain = bob.decrypt(&enc, ad).unwrap();
            assert_eq!(plain, messages[i]);
        }
    }

    #[test]
    fn test_bidirectional_conversation() {
        let (mut alice, mut bob) = setup_session();
        let ad = b"conversation";

        // Alice sends first
        let msg1 = alice.encrypt(b"Hey Bob", ad).unwrap();
        assert_eq!(bob.decrypt(&msg1, ad).unwrap(), b"Hey Bob");

        // Bob replies — triggers DH ratchet step
        let msg2 = bob.encrypt(b"Hey Alice", ad).unwrap();
        assert_eq!(alice.decrypt(&msg2, ad).unwrap(), b"Hey Alice");

        // Alice sends again — another DH ratchet step
        let msg3 = alice.encrypt(b"How are you?", ad).unwrap();
        assert_eq!(bob.decrypt(&msg3, ad).unwrap(), b"How are you?");

        // Bob replies
        let msg4 = bob.encrypt(b"All good!", ad).unwrap();
        assert_eq!(alice.decrypt(&msg4, ad).unwrap(), b"All good!");
    }

    #[test]
    fn test_out_of_order_messages() {
        let (mut alice, mut bob) = setup_session();
        let ad = b"conversation";

        // Alice sends 3 messages
        let msg1 = alice.encrypt(b"first", ad).unwrap();
        let msg2 = alice.encrypt(b"second", ad).unwrap();
        let msg3 = alice.encrypt(b"third", ad).unwrap();

        // Bob receives them out of order: 3, 1, 2
        assert_eq!(bob.decrypt(&msg3, ad).unwrap(), b"third");
        assert_eq!(bob.decrypt(&msg1, ad).unwrap(), b"first");
        assert_eq!(bob.decrypt(&msg2, ad).unwrap(), b"second");
    }

    #[test]
    fn test_wrong_associated_data_fails() {
        let (mut alice, mut bob) = setup_session();

        let msg = alice.encrypt(b"Secret", b"correct-ad").unwrap();
        assert!(bob.decrypt(&msg, b"wrong-ad").is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (mut alice, mut bob) = setup_session();
        let ad = b"conversation";

        let mut msg = alice.encrypt(b"Secret", ad).unwrap();
        // Flip a bit in the ciphertext
        if let Some(byte) = msg.ciphertext.last_mut() {
            *byte ^= 0x01;
        }
        assert!(bob.decrypt(&msg, ad).is_err());
    }

    #[test]
    fn test_each_message_has_different_ciphertext() {
        let (mut alice, _) = setup_session();
        let ad = b"conversation";

        // Same plaintext, different message keys → different ciphertexts
        let ct1 = alice.encrypt(b"same message", ad).unwrap();
        let ct2 = alice.encrypt(b"same message", ad).unwrap();
        assert_ne!(ct1.ciphertext, ct2.ciphertext);
    }

    #[test]
    fn test_long_conversation_stays_consistent() {
        let (mut alice, mut bob) = setup_session();
        let ad = b"conversation";

        // Simulate a long back-and-forth conversation
        for i in 0..50u32 {
            let plaintext = format!("message {i}");
            if i % 2 == 0 {
                let enc = alice.encrypt(plaintext.as_bytes(), ad).unwrap();
                assert_eq!(bob.decrypt(&enc, ad).unwrap(), plaintext.as_bytes());
            } else {
                let enc = bob.encrypt(plaintext.as_bytes(), ad).unwrap();
                assert_eq!(alice.decrypt(&enc, ad).unwrap(), plaintext.as_bytes());
            }
        }
    }
}
