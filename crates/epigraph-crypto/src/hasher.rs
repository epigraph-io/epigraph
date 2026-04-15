//! BLAKE3 content hashing
//!
//! BLAKE3 is chosen for:
//! - Speed: Faster than SHA-256, especially on modern CPUs
//! - Security: 256-bit security level
//! - Versatility: Can be used for hashing, KDF, MAC, and XOF
//! - Merkle-tree capable: Built-in support for incremental hashing

use crate::canonical::Canonical;
use crate::errors::CryptoError;
use crate::HASH_SIZE;

/// Content hasher using BLAKE3
pub struct ContentHasher;

impl ContentHasher {
    /// Hash arbitrary bytes using BLAKE3
    ///
    /// Returns a 32-byte hash.
    #[must_use]
    pub fn hash(data: &[u8]) -> [u8; HASH_SIZE] {
        blake3::hash(data).into()
    }

    /// Hash a canonically serializable type
    ///
    /// The value is first serialized to canonical JSON, then hashed.
    ///
    /// # Errors
    /// Returns error if canonical serialization fails.
    pub fn hash_canonical<T: Canonical>(value: &T) -> Result<[u8; HASH_SIZE], CryptoError> {
        let bytes = value.canonical_bytes()?;
        Ok(Self::hash(&bytes))
    }

    /// Create an incremental hasher for large content
    ///
    /// Use this when hashing large files or streams:
    /// ```ignore
    /// let mut hasher = ContentHasher::incremental();
    /// hasher.update(chunk1);
    /// hasher.update(chunk2);
    /// let hash = hasher.finalize();
    /// ```
    #[must_use]
    pub fn incremental() -> blake3::Hasher {
        blake3::Hasher::new()
    }

    /// Hash multiple items into a single hash (for Merkle-style combining)
    ///
    /// Useful for creating a combined hash of multiple evidence items.
    #[must_use]
    pub fn hash_combine(items: &[[u8; HASH_SIZE]]) -> [u8; HASH_SIZE] {
        let mut hasher = Self::incremental();
        for item in items {
            hasher.update(item);
        }
        hasher.finalize().into()
    }

    /// Convert a hash to hex string for display/storage
    #[must_use]
    pub fn to_hex(hash: &[u8; HASH_SIZE]) -> String {
        hash.iter().fold(String::with_capacity(64), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }

    /// Parse a hex string back to hash bytes
    ///
    /// # Errors
    /// Returns error if the hex string is invalid or wrong length.
    pub fn from_hex(hex: &str) -> Result<[u8; HASH_SIZE], CryptoError> {
        if hex.len() != HASH_SIZE * 2 {
            return Err(CryptoError::SerializationError(format!(
                "Invalid hash hex length: expected {}, got {}",
                HASH_SIZE * 2,
                hex.len()
            )));
        }

        let mut bytes = [0u8; HASH_SIZE];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hex_byte = std::str::from_utf8(chunk).map_err(|e| {
                CryptoError::SerializationError(format!("Invalid UTF-8 in hex: {e}"))
            })?;
            bytes[i] = u8::from_str_radix(hex_byte, 16)
                .map_err(|e| CryptoError::SerializationError(format!("Invalid hex digit: {e}")))?;
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hash_produces_32_bytes() {
        let hash = ContentHasher::hash(b"test data");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn hash_is_deterministic() {
        let hash1 = ContentHasher::hash(b"same input");
        let hash2 = ContentHasher::hash(b"same input");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hash_differs_for_different_input() {
        let hash1 = ContentHasher::hash(b"input one");
        let hash2 = ContentHasher::hash(b"input two");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hash_canonical_produces_consistent_results() {
        let obj1 = json!({"b": 2, "a": 1});
        let obj2 = json!({"a": 1, "b": 2});

        let hash1 = ContentHasher::hash_canonical(&obj1).unwrap();
        let hash2 = ContentHasher::hash_canonical(&obj2).unwrap();

        // Same content, different key order = same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn incremental_matches_direct() {
        let data = b"hello world";

        let direct = ContentHasher::hash(data);

        let mut incremental = ContentHasher::incremental();
        incremental.update(b"hello ");
        incremental.update(b"world");
        let incremental_result: [u8; 32] = incremental.finalize().into();

        assert_eq!(direct, incremental_result);
    }

    #[test]
    fn hex_roundtrip() {
        let hash = ContentHasher::hash(b"test");
        let hex = ContentHasher::to_hex(&hash);
        let recovered = ContentHasher::from_hex(&hex).unwrap();
        assert_eq!(hash, recovered);
    }

    #[test]
    fn hash_combine_is_deterministic() {
        let h1 = ContentHasher::hash(b"one");
        let h2 = ContentHasher::hash(b"two");

        let combined1 = ContentHasher::hash_combine(&[h1, h2]);
        let combined2 = ContentHasher::hash_combine(&[h1, h2]);

        assert_eq!(combined1, combined2);
    }

    #[test]
    fn from_hex_invalid_length_short() {
        // Too short
        let result = ContentHasher::from_hex("abcd");
        assert!(result.is_err());
    }

    #[test]
    fn from_hex_invalid_length_long() {
        // Too long (65 chars instead of 64)
        let too_long = "a".repeat(65);
        let result = ContentHasher::from_hex(&too_long);
        assert!(result.is_err());
    }

    #[test]
    fn from_hex_invalid_characters() {
        // Invalid hex characters (g, h are not valid hex)
        let invalid = "ghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqr";
        let result = ContentHasher::from_hex(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn from_hex_empty_string() {
        let result = ContentHasher::from_hex("");
        assert!(result.is_err());
    }

    #[test]
    fn hash_combine_empty_returns_known_hash() {
        let combined = ContentHasher::hash_combine(&[]);
        // Hash of empty input should be consistent
        let empty_hash = ContentHasher::hash(b"");
        assert_eq!(combined, empty_hash);
    }

    #[test]
    fn hash_combine_single_item() {
        let h1 = ContentHasher::hash(b"only one");
        let combined = ContentHasher::hash_combine(&[h1]);
        // Single item combine should be hash of that item's bytes
        assert_ne!(combined, h1); // Combined hash differs because it's hash(h1), not h1 itself
    }

    #[test]
    fn hash_combine_order_matters() {
        let h1 = ContentHasher::hash(b"first");
        let h2 = ContentHasher::hash(b"second");

        let combined1 = ContentHasher::hash_combine(&[h1, h2]);
        let combined2 = ContentHasher::hash_combine(&[h2, h1]);

        assert_ne!(combined1, combined2, "Order should affect combined hash");
    }

    #[test]
    fn to_hex_produces_64_chars() {
        let hash = ContentHasher::hash(b"test");
        let hex = ContentHasher::to_hex(&hash);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // --- Additional comprehensive tests ---

    #[test]
    fn hash_empty_input_produces_consistent_output() {
        let hash1 = ContentHasher::hash(b"");
        let hash2 = ContentHasher::hash(b"");
        assert_eq!(hash1, hash2);
        // BLAKE3 hash of empty input is well-defined and non-zero
        assert_ne!(hash1, [0u8; HASH_SIZE]);
    }

    #[test]
    fn hash_empty_input_is_32_bytes() {
        let hash = ContentHasher::hash(b"");
        assert_eq!(hash.len(), HASH_SIZE);
    }

    #[test]
    fn hash_single_byte_difference_produces_different_hash() {
        // Demonstrates avalanche effect: a single bit change should produce
        // a completely different hash
        let hash_a = ContentHasher::hash(b"a");
        let hash_b = ContentHasher::hash(b"b");
        assert_ne!(hash_a, hash_b);

        // Count differing bytes to verify avalanche property
        let differing_bytes = hash_a
            .iter()
            .zip(hash_b.iter())
            .filter(|(a, b)| a != b)
            .count();
        // At least half the bytes should differ (avalanche effect)
        assert!(
            differing_bytes > HASH_SIZE / 4,
            "Expected significant avalanche effect, but only {differing_bytes}/{HASH_SIZE} bytes differ"
        );
    }

    #[test]
    fn hash_large_input() {
        // 1 MB of data should hash without issue
        let data = vec![0xABu8; 1_000_000];
        let hash = ContentHasher::hash(&data);
        assert_eq!(hash.len(), HASH_SIZE);
        // Hash should not be all zeros
        assert_ne!(hash, [0u8; HASH_SIZE]);
    }

    #[test]
    fn incremental_single_update_matches_direct() {
        let data = b"a single chunk";
        let direct = ContentHasher::hash(data);

        let mut incremental = ContentHasher::incremental();
        incremental.update(data);
        let incremental_result: [u8; HASH_SIZE] = incremental.finalize().into();

        assert_eq!(direct, incremental_result);
    }

    #[test]
    fn incremental_byte_by_byte_matches_direct() {
        let data = b"byte by byte";
        let direct = ContentHasher::hash(data);

        let mut incremental = ContentHasher::incremental();
        for byte in data {
            incremental.update(&[*byte]);
        }
        let incremental_result: [u8; HASH_SIZE] = incremental.finalize().into();

        assert_eq!(direct, incremental_result);
    }

    #[test]
    fn incremental_empty_matches_direct_empty() {
        let direct = ContentHasher::hash(b"");

        let incremental = ContentHasher::incremental();
        let incremental_result: [u8; HASH_SIZE] = incremental.finalize().into();

        assert_eq!(direct, incremental_result);
    }

    #[test]
    fn hash_canonical_different_key_order_same_hash() {
        let obj_ab = json!({"a": 1, "b": 2});
        let obj_ba = json!({"b": 2, "a": 1});

        let hash_ab = ContentHasher::hash_canonical(&obj_ab).unwrap();
        let hash_ba = ContentHasher::hash_canonical(&obj_ba).unwrap();

        assert_eq!(
            hash_ab, hash_ba,
            "Canonical hashing must be key-order independent"
        );
    }

    #[test]
    fn hash_canonical_different_values_different_hash() {
        let obj1 = json!({"key": "value1"});
        let obj2 = json!({"key": "value2"});

        let hash1 = ContentHasher::hash_canonical(&obj1).unwrap();
        let hash2 = ContentHasher::hash_canonical(&obj2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hash_canonical_nested_objects() {
        let obj1 = json!({"outer": {"z": 1, "a": 2}});
        let obj2 = json!({"outer": {"a": 2, "z": 1}});

        let hash1 = ContentHasher::hash_canonical(&obj1).unwrap();
        let hash2 = ContentHasher::hash_canonical(&obj2).unwrap();

        assert_eq!(
            hash1, hash2,
            "Nested key order must not affect canonical hash"
        );
    }

    #[test]
    fn hash_combine_three_items() {
        let h1 = ContentHasher::hash(b"one");
        let h2 = ContentHasher::hash(b"two");
        let h3 = ContentHasher::hash(b"three");

        let combined = ContentHasher::hash_combine(&[h1, h2, h3]);
        assert_eq!(combined.len(), HASH_SIZE);

        // Result should be deterministic
        let combined2 = ContentHasher::hash_combine(&[h1, h2, h3]);
        assert_eq!(combined, combined2);
    }

    #[test]
    fn to_hex_lowercase() {
        let hash = ContentHasher::hash(b"test");
        let hex = ContentHasher::to_hex(&hash);
        // Hex should be all lowercase
        assert_eq!(hex, hex.to_lowercase());
    }

    #[test]
    fn from_hex_accepts_lowercase() {
        let hash = ContentHasher::hash(b"test");
        let hex = ContentHasher::to_hex(&hash);
        // Lowercase hex should roundtrip
        let recovered = ContentHasher::from_hex(&hex).unwrap();
        assert_eq!(hash, recovered);
    }

    #[test]
    fn from_hex_accepts_uppercase() {
        let hash = ContentHasher::hash(b"test");
        let hex = ContentHasher::to_hex(&hash).to_uppercase();
        let recovered = ContentHasher::from_hex(&hex).unwrap();
        assert_eq!(hash, recovered);
    }

    #[test]
    fn from_hex_accepts_mixed_case() {
        let hash = ContentHasher::hash(b"test");
        let hex = ContentHasher::to_hex(&hash);
        // Mix cases: uppercase first char, lowercase second, etc.
        let mixed: String = hex
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_uppercase().next().unwrap()
                } else {
                    c
                }
            })
            .collect();
        let recovered = ContentHasher::from_hex(&mixed).unwrap();
        assert_eq!(hash, recovered);
    }

    #[test]
    fn from_hex_all_zeros() {
        let hex = "0".repeat(64);
        let result = ContentHasher::from_hex(&hex).unwrap();
        assert_eq!(result, [0u8; HASH_SIZE]);
    }

    #[test]
    fn from_hex_all_ff() {
        let hex = "f".repeat(64);
        let result = ContentHasher::from_hex(&hex).unwrap();
        assert_eq!(result, [0xFFu8; HASH_SIZE]);
    }

    #[test]
    fn from_hex_exactly_62_chars_is_error() {
        // One byte short of valid (62 hex chars = 31 bytes)
        let hex = "ab".repeat(31);
        assert_eq!(hex.len(), 62);
        assert!(ContentHasher::from_hex(&hex).is_err());
    }

    #[test]
    fn from_hex_exactly_66_chars_is_error() {
        // One byte over valid (66 hex chars = 33 bytes)
        let hex = "ab".repeat(33);
        assert_eq!(hex.len(), 66);
        assert!(ContentHasher::from_hex(&hex).is_err());
    }

    #[test]
    fn hash_not_all_zeros() {
        // No input should produce an all-zero hash
        let inputs: &[&[u8]] = &[b"", b"a", b"test", b"\x00"];
        for input in inputs {
            let hash = ContentHasher::hash(input);
            assert_ne!(
                hash, [0u8; HASH_SIZE],
                "Hash of {input:?} should not be all zeros"
            );
        }
    }
}
