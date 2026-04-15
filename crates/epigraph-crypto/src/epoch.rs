//! Epoch-based key derivation using BLAKE3's dedicated KDF mode.
//!
//! Each group key epoch derives a unique symmetric key from the group's
//! base key. This allows key rotation without re-distributing the base key.

/// Derive an epoch-specific AES-256 key from a base group key.
///
/// Uses `blake3::derive_key` which provides proper domain separation
/// via BLAKE3's built-in KDF context parameter.
pub fn derive_epoch_key(base_key: &[u8; 32], epoch: u32) -> [u8; 32] {
    let mut input = Vec::with_capacity(36);
    input.extend_from_slice(base_key);
    input.extend_from_slice(&epoch.to_le_bytes());
    blake3::derive_key("epigraph-epoch-key-v1", &input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_epoch_key_deterministic() {
        let base = [1u8; 32];
        let k1 = derive_epoch_key(&base, 0);
        let k2 = derive_epoch_key(&base, 0);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_different_epochs_produce_different_keys() {
        let base = [1u8; 32];
        let k0 = derive_epoch_key(&base, 0);
        let k1 = derive_epoch_key(&base, 1);
        assert_ne!(k0, k1);
    }

    #[test]
    fn test_different_base_keys_produce_different_epoch_keys() {
        let base_a = [1u8; 32];
        let base_b = [2u8; 32];
        let ka = derive_epoch_key(&base_a, 0);
        let kb = derive_epoch_key(&base_b, 0);
        assert_ne!(ka, kb);
    }

    #[test]
    fn test_epoch_key_is_32_bytes() {
        let base = [0u8; 32];
        let key = derive_epoch_key(&base, 42);
        assert_eq!(key.len(), 32);
    }
}
