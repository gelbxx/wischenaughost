//! # Sender Keys — Group Encryption
//!
//! Sender Keys is an efficient protocol for group messaging. Instead of
//! encrypting each message N times (once for each group member), each
//! member shares a "sender key" with the group, and then uses that single
//! key to encrypt all their messages to the group.
//!
//! ## How It Works
//!
//! 1. When Alice joins a group, she generates a Sender Key:
//!    - A random symmetric chain key (for encryption)
//!    - A signing key pair (for authentication)
//!
//! 2. She distributes her Sender Key to every group member via their
//!    individual Double Ratchet sessions (so it's encrypted end-to-end).
//!
//! 3. When Alice sends a group message:
//!    - She derives a message key from her chain key (and ratchets forward)
//!    - She encrypts the message with AES-256-CBC + HMAC-SHA256
//!    - She signs it with her signing key
//!    - She sends ONE copy to the group
//!
//! 4. Every group member has Alice's Sender Key, so they can:
//!    - Derive the same message key (they track Alice's chain independently)
//!    - Decrypt the message
//!    - Verify the signature (confirm it's really from Alice)
//!
//! ## Member Changes
//!
//! - **Member added**: Existing members send their current Sender Keys to the new member
//! - **Member removed**: ALL members generate NEW Sender Keys and redistribute them
//!   (this ensures the removed member can't decrypt future messages)
//!
//! ## Trade-offs vs. Pairwise Encryption
//!
//! - **Sender Keys**: O(1) encryption per message (fast!), but requires O(n) key
//!   distribution when a member is removed
//! - **Pairwise**: O(n) encryption per message (slow for large groups), but
//!   no special handling needed for member changes
//!
//! For groups up to ~256 members, Sender Keys is the clear winner.
//! Signal uses this same approach.

// TODO: Implement in Phase 3, Week 15-16
// - SenderKey struct (chain key + signing key)
// - SenderKeyState (tracks chain position per sender)
// - Generate sender key
// - Encrypt group message
// - Decrypt group message
// - Handle member add/remove (re-keying)
