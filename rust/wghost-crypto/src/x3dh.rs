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
//!      - DH1 = DH(IK_A, SPK_B)     — identity-to-signed-prekey
//!      - DH2 = DH(EK_A, IK_B)      — ephemeral-to-identity
//!      - DH3 = DH(EK_A, SPK_B)     — ephemeral-to-signed-prekey
//!      - DH4 = DH(EK_A, OPK_B)     — ephemeral-to-one-time (if available)
//!    - She combines all DH outputs with HKDF to get a shared secret
//!
//! 3. **Alice sends an "initial message"** to Bob containing:
//!    - Her identity key (IK_A)
//!    - Her ephemeral key (EK_A)
//!    - Which OPK she used
//!    - The first Double Ratchet message (encrypted with the shared secret)
//!
//! 4. **Bob receives it and computes the same 3-4 DH exchanges** from his side.
//!    Both arrive at the same shared secret. The Double Ratchet begins.
//!
//! ## Why "Triple"?
//!
//! The three mandatory DH exchanges provide different security properties:
//! - DH1 (IK_A, SPK_B): Authenticates Alice to Bob
//! - DH2 (EK_A, IK_B): Provides forward secrecy if Alice's IK is later compromised
//! - DH3 (EK_A, SPK_B): Provides forward secrecy if Bob's IK is later compromised
//! - DH4 (EK_A, OPK_B): Extra forward secrecy (each OPK is used only once)
//!
//! ## P2P Adaptation
//!
//! In Signal's original design, a central server hosts prekey bundles.
//! In WischenauGhost, we publish them to the Kademlia DHT and cache them
//! on mailbox nodes. The cryptography is identical.

// TODO: Implement in Week 3-4 (Phase 1: Crypto Core)
// - PreKeyBundle struct
// - X3DH initiator (Alice's side)
// - X3DH responder (Bob's side)
// - Prekey generation and rotation
