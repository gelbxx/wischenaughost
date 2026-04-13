//! # Mailbox Protocol (Store-and-Forward)
//!
//! The hardest problem in P2P messaging: delivering messages when the
//! recipient is offline.
//!
//! Each user designates 2-3 "mailbox nodes" — volunteer peers that agree
//! to temporarily store encrypted envelopes. When a sender can't reach
//! the recipient directly, they deposit the encrypted message at the
//! recipient's mailbox. When the recipient comes online, they check
//! their mailbox and retrieve pending messages.
//!
//! Mailbox nodes see ONLY:
//! - Recipient's PeerId
//! - Encrypted blob (they can't read it)
//! - Timestamp and size
//!
//! They do NOT see who sent the message (sender ID is inside the encryption).

// TODO: Implement in Phase 2, Week 11-12
