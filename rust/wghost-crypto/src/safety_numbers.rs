//! # Safety Numbers
//!
//! Safety numbers allow two users to verify that they're really talking to
//! each other and not to a man-in-the-middle attacker.
//!
//! When Alice and Bob meet in person, they compare their safety number.
//! If it matches, they know their encrypted session is secure. If it doesn't
//! match, someone might be intercepting their messages.
//!
//! The safety number is computed as:
//! `SHA-256(sort(alice_identity_key || bob_identity_key))`
//! and displayed as a 60-digit number (in groups of 5 for readability).

use sha2::{Sha256, Digest};

/// Compute the safety number between two identity public keys.
///
/// The result is deterministic and symmetric — Alice computing the safety
/// number with Bob's key produces the same result as Bob computing it
/// with Alice's key. This is achieved by sorting the keys before hashing.
///
/// # Returns
/// A 60-character string of digits, formatted as groups of 5 separated by spaces.
/// Example: "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"
pub fn compute_safety_number(key_a: &[u8; 32], key_b: &[u8; 32]) -> String {
    // Sort keys so the result is the same regardless of who computes it
    let (first, second) = if key_a <= key_b {
        (key_a, key_b)
    } else {
        (key_b, key_a)
    };

    // Hash the concatenated sorted keys
    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    let hash = hasher.finalize();

    // Convert hash bytes to a numeric string
    // We iterate through the hash bytes and convert each to a 2-3 digit number,
    // then take the first 60 digits
    let mut digits = String::with_capacity(80);
    for byte in hash.iter() {
        // Each byte contributes 3 digits (000-255, zero-padded)
        digits.push_str(&format!("{:03}", byte));
        if digits.len() >= 60 {
            break;
        }
    }
    digits.truncate(60);

    // Format as groups of 5 digits separated by spaces
    digits
        .as_bytes()
        .chunks(5)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<&str>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_number_is_symmetric() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];

        let sn_ab = compute_safety_number(&key_a, &key_b);
        let sn_ba = compute_safety_number(&key_b, &key_a);

        assert_eq!(sn_ab, sn_ba, "Safety number must be the same regardless of order");
    }

    #[test]
    fn test_safety_number_format() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];

        let sn = compute_safety_number(&key_a, &key_b);
        let groups: Vec<&str> = sn.split(' ').collect();

        assert_eq!(groups.len(), 12, "Should have 12 groups");
        for group in &groups {
            assert_eq!(group.len(), 5, "Each group should be 5 digits");
            assert!(group.chars().all(|c| c.is_ascii_digit()), "Only digits");
        }
    }

    #[test]
    fn test_different_keys_produce_different_numbers() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let key_c = [3u8; 32];

        let sn_ab = compute_safety_number(&key_a, &key_b);
        let sn_ac = compute_safety_number(&key_a, &key_c);

        assert_ne!(sn_ab, sn_ac);
    }
}
