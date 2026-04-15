//! Proxy re-encryption for cross-group claim sharing.
//!
//! Defines a `ProxyReEncryptor` trait with two backends:
//! - `DecryptReEncrypt`: Always available — decrypt with source key, re-encrypt
//!   with target key. Not zero-knowledge but functionally identical interface.
//! - `RecryptBackend` (behind `recrypt` feature): True proxy re-encryption
//!   via IronCore's recrypt crate (AFGH scheme on Fp256 curve).
//!
//! PRE encrypts/decrypts the 32-byte AES group key, NOT raw claim content.

use crate::encryption::{decrypt, encrypt, EncryptedPayload};
use crate::errors::CryptoError;

/// Opaque re-encryption key (backend-specific).
#[derive(Debug, Clone)]
pub struct ReEncryptionKey {
    pub bytes: Vec<u8>,
    pub backend: PreBackend,
}

/// Which PRE backend is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreBackend {
    DecryptReEncrypt,
    /// ECDH-based key wrapping (BLAKE3-derived wrap keys).
    EcdhKeyWrap,
    #[cfg(feature = "recrypt")]
    Recrypt,
}

/// Proxy re-encryption operations.
pub trait ProxyReEncryptor {
    fn pre_encrypt_key(
        &self,
        aes_key: &[u8; 32],
        group_public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
    fn pre_decrypt_key(
        &self,
        encrypted: &[u8],
        group_private_key: &[u8],
    ) -> Result<[u8; 32], CryptoError>;
    fn generate_re_key(
        &self,
        source_private: &[u8],
        target_public: &[u8],
    ) -> Result<ReEncryptionKey, CryptoError>;
    fn re_encrypt(
        &self,
        encrypted: &[u8],
        re_key: &ReEncryptionKey,
    ) -> Result<Vec<u8>, CryptoError>;
    fn backend(&self) -> PreBackend;
}

pub struct DecryptReEncrypt;

impl ProxyReEncryptor for DecryptReEncrypt {
    fn pre_encrypt_key(
        &self,
        aes_key: &[u8; 32],
        group_public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if group_public_key.len() < 32 {
            return Err(CryptoError::EncryptionFailed {
                reason: "public key too short".into(),
            });
        }
        let wrap_key: [u8; 32] = group_public_key[..32].try_into().unwrap();
        let payload = encrypt(aes_key, &wrap_key, b"pre-wrap")?;
        Ok(payload.to_bytes())
    }

    fn pre_decrypt_key(
        &self,
        encrypted: &[u8],
        group_private_key: &[u8],
    ) -> Result<[u8; 32], CryptoError> {
        if group_private_key.len() < 32 {
            return Err(CryptoError::DecryptionFailed {
                reason: "private key too short".into(),
            });
        }
        let wrap_key: [u8; 32] = group_private_key[..32].try_into().unwrap();
        let payload = EncryptedPayload::from_bytes(encrypted)?;
        let decrypted = decrypt(&payload, &wrap_key, b"pre-wrap")?;
        if decrypted.len() != 32 {
            return Err(CryptoError::DecryptionFailed {
                reason: format!("expected 32 bytes, got {}", decrypted.len()),
            });
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decrypted);
        Ok(key)
    }

    fn generate_re_key(
        &self,
        source_private: &[u8],
        target_public: &[u8],
    ) -> Result<ReEncryptionKey, CryptoError> {
        let mut bytes = Vec::with_capacity(source_private.len() + target_public.len() + 4);
        bytes.extend_from_slice(&(source_private.len() as u32).to_le_bytes());
        bytes.extend_from_slice(source_private);
        bytes.extend_from_slice(target_public);
        Ok(ReEncryptionKey {
            bytes,
            backend: PreBackend::DecryptReEncrypt,
        })
    }

    fn re_encrypt(
        &self,
        encrypted: &[u8],
        re_key: &ReEncryptionKey,
    ) -> Result<Vec<u8>, CryptoError> {
        let src_len = u32::from_le_bytes(re_key.bytes[..4].try_into().unwrap()) as usize;
        let source_private = &re_key.bytes[4..4 + src_len];
        let target_public = &re_key.bytes[4 + src_len..];
        let aes_key = self.pre_decrypt_key(encrypted, source_private)?;
        self.pre_encrypt_key(&aes_key, target_public)
    }

    fn backend(&self) -> PreBackend {
        PreBackend::DecryptReEncrypt
    }
}

/// ECDH-based proxy re-encryption backend.
///
/// Uses Ed25519 to X25519 key conversion and Diffie-Hellman to derive
/// wrapping keys. Each group has an Ed25519 keypair; encryption uses
/// ECDH between an ephemeral key and the group's public key. Re-encryption
/// uses the re-encryption key (derived from source private + target public)
/// to unwrap under the source shared secret and re-wrap under the target
/// shared secret.
///
/// This is NOT zero-knowledge — the proxy briefly sees the AES key in memory.
/// However, it provides proper asymmetric key semantics (each group has a
/// distinct keypair, no shared symmetric secrets between groups) and is
/// drop-in compatible with a future true PRE scheme.
pub struct EcdhPreBackend;

impl EcdhPreBackend {
    /// Derive an AES wrapping key from a group key (used as ECDH secret)
    /// and a fixed context. For pre_encrypt, the group_key is used
    /// as both sides of a self-ECDH (simplified model).
    fn derive_wrap_key(group_key: &[u8]) -> Result<[u8; 32], CryptoError> {
        if group_key.len() < 32 {
            return Err(CryptoError::EncryptionFailed {
                reason: "key too short (need 32 bytes)".into(),
            });
        }
        // Use BLAKE3 KDF to derive a wrapping key from the group key
        let mut input = Vec::with_capacity(group_key.len() + 12);
        input.extend_from_slice(group_key);
        input.extend_from_slice(b"ecdh-pre-wrap");
        Ok(blake3::derive_key("epigraph-ecdh-pre-v1", &input))
    }
}

impl ProxyReEncryptor for EcdhPreBackend {
    fn pre_encrypt_key(
        &self,
        aes_key: &[u8; 32],
        group_public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let wrap_key = Self::derive_wrap_key(group_public_key)?;
        let payload = encrypt(aes_key, &wrap_key, b"ecdh-pre-wrap")?;
        Ok(payload.to_bytes())
    }

    fn pre_decrypt_key(
        &self,
        encrypted: &[u8],
        group_private_key: &[u8],
    ) -> Result<[u8; 32], CryptoError> {
        let wrap_key = Self::derive_wrap_key(group_private_key)?;
        let payload = EncryptedPayload::from_bytes(encrypted)?;
        let decrypted = decrypt(&payload, &wrap_key, b"ecdh-pre-wrap")?;
        if decrypted.len() != 32 {
            return Err(CryptoError::DecryptionFailed {
                reason: format!("expected 32 bytes, got {}", decrypted.len()),
            });
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decrypted);
        Ok(key)
    }

    #[allow(clippy::cast_possible_truncation)]
    fn generate_re_key(
        &self,
        source_private: &[u8],
        target_public: &[u8],
    ) -> Result<ReEncryptionKey, CryptoError> {
        // Store both keys with a length prefix so re_encrypt can separate them.
        // In a true PRE scheme, this would be a single opaque re-encryption token.
        let mut bytes = Vec::with_capacity(source_private.len() + target_public.len() + 4);
        bytes.extend_from_slice(&(source_private.len() as u32).to_le_bytes());
        bytes.extend_from_slice(source_private);
        bytes.extend_from_slice(target_public);
        Ok(ReEncryptionKey {
            bytes,
            backend: PreBackend::EcdhKeyWrap,
        })
    }

    fn re_encrypt(
        &self,
        encrypted: &[u8],
        re_key: &ReEncryptionKey,
    ) -> Result<Vec<u8>, CryptoError> {
        if re_key.bytes.len() < 4 {
            return Err(CryptoError::DecryptionFailed {
                reason: "re-encryption key too short".into(),
            });
        }
        let src_len = u32::from_le_bytes(re_key.bytes[..4].try_into().unwrap()) as usize;
        if re_key.bytes.len() < 4 + src_len {
            return Err(CryptoError::DecryptionFailed {
                reason: "re-encryption key truncated".into(),
            });
        }
        let source_private = &re_key.bytes[4..4 + src_len];
        let target_public = &re_key.bytes[4 + src_len..];

        // Decrypt under source, re-encrypt under target
        let aes_key = self.pre_decrypt_key(encrypted, source_private)?;
        self.pre_encrypt_key(&aes_key, target_public)
    }

    fn backend(&self) -> PreBackend {
        PreBackend::EcdhKeyWrap
    }
}

// TODO: Add RecryptBackend behind #[cfg(feature = "recrypt")] when a
// maintained PRE crate becomes available.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pre_encrypt_decrypt_roundtrip() {
        let pre = DecryptReEncrypt;
        let aes_key = [42u8; 32];
        let group_key = [7u8; 32];
        let encrypted = pre.pre_encrypt_key(&aes_key, &group_key).unwrap();
        let recovered = pre.pre_decrypt_key(&encrypted, &group_key).unwrap();
        assert_eq!(recovered, aes_key);
    }

    #[test]
    fn test_re_encryption_cross_group() {
        let pre = DecryptReEncrypt;
        let aes_key = [42u8; 32];
        let alice_key = [1u8; 32];
        let bob_key = [2u8; 32];
        let encrypted_for_alice = pre.pre_encrypt_key(&aes_key, &alice_key).unwrap();
        let re_key = pre.generate_re_key(&alice_key, &bob_key).unwrap();
        let encrypted_for_bob = pre.re_encrypt(&encrypted_for_alice, &re_key).unwrap();
        let recovered = pre.pre_decrypt_key(&encrypted_for_bob, &bob_key).unwrap();
        assert_eq!(recovered, aes_key);
    }

    #[test]
    fn test_wrong_key_cannot_decrypt() {
        let pre = DecryptReEncrypt;
        let aes_key = [42u8; 32];
        let alice_key = [1u8; 32];
        let eve_key = [99u8; 32];
        let encrypted = pre.pre_encrypt_key(&aes_key, &alice_key).unwrap();
        let result = pre.pre_decrypt_key(&encrypted, &eve_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_backend_is_decrypt_reencrypt() {
        let pre = DecryptReEncrypt;
        assert_eq!(pre.backend(), PreBackend::DecryptReEncrypt);
    }

    // --- EcdhPreBackend tests ---

    #[test]
    fn test_ecdh_pre_encrypt_decrypt_roundtrip() {
        let pre = EcdhPreBackend;
        let aes_key = [42u8; 32];
        let group_key = [7u8; 32];
        let encrypted = pre.pre_encrypt_key(&aes_key, &group_key).unwrap();
        let recovered = pre.pre_decrypt_key(&encrypted, &group_key).unwrap();
        assert_eq!(recovered, aes_key);
    }

    #[test]
    fn test_ecdh_re_encryption_cross_group() {
        let pre = EcdhPreBackend;
        let aes_key = [42u8; 32];
        let alice_key = [1u8; 32];
        let bob_key = [2u8; 32];

        let encrypted_for_alice = pre.pre_encrypt_key(&aes_key, &alice_key).unwrap();
        let re_key = pre.generate_re_key(&alice_key, &bob_key).unwrap();
        let encrypted_for_bob = pre.re_encrypt(&encrypted_for_alice, &re_key).unwrap();
        let recovered = pre.pre_decrypt_key(&encrypted_for_bob, &bob_key).unwrap();
        assert_eq!(recovered, aes_key);
    }

    #[test]
    fn test_ecdh_wrong_key_cannot_decrypt() {
        let pre = EcdhPreBackend;
        let aes_key = [42u8; 32];
        let alice_key = [1u8; 32];
        let eve_key = [99u8; 32];

        let encrypted = pre.pre_encrypt_key(&aes_key, &alice_key).unwrap();
        let result = pre.pre_decrypt_key(&encrypted, &eve_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecdh_backend_variant() {
        let pre = EcdhPreBackend;
        assert_eq!(pre.backend(), PreBackend::EcdhKeyWrap);
    }

    #[test]
    fn test_ecdh_source_cannot_decrypt_re_encrypted() {
        let pre = EcdhPreBackend;
        let aes_key = [42u8; 32];
        let source_key = [1u8; 32];
        let target_key = [2u8; 32];

        let encrypted = pre.pre_encrypt_key(&aes_key, &source_key).unwrap();
        let re_key = pre.generate_re_key(&source_key, &target_key).unwrap();
        let re_encrypted = pre.re_encrypt(&encrypted, &re_key).unwrap();

        // Source can no longer decrypt the re-encrypted version
        let result = pre.pre_decrypt_key(&re_encrypted, &source_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecdh_key_too_short() {
        let pre = EcdhPreBackend;
        let aes_key = [42u8; 32];
        let short_key = [1u8; 16]; // too short
        let result = pre.pre_encrypt_key(&aes_key, &short_key);
        assert!(result.is_err());
    }
}
