//! # NAT Traversal
//!
//! Most devices are behind NAT (Network Address Translation), which means
//! they can't receive incoming connections directly. This module handles
//! getting through NAT so peers can communicate.
//!
//! Strategy (in order of preference):
//! 1. Direct connection (if peer has a public IP)
//! 2. DCUtR hole punching (coordinate through a relay to punch through NAT)
//! 3. Circuit Relay v2 (relay traffic through a third peer as fallback)

// TODO: Implement in Phase 3, Week 21-22
