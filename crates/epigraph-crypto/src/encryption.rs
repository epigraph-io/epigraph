//! AES-256-GCM authenticated encryption for claim content.
//!
//! Wire format for `EncryptedPayload` stored as BYTEA:
//!   nonce (12 bytes) || ciphertext (variable) || tag (16 bytes)

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Nonce,
};

use crate::errors::CryptoError;

/// Maximum size of a serialized [`EncryptedPayload`] accepted during parsing.
///
/// 10 MiB: nonce (12 bytes) + ciphertext + tag (16 bytes). Payloads larger than
/// this indicate either a programming error or a malicious/corrupted input and
/// are rejected before any heap allocation.
const MAX_ENCRYPTED_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;

/// Encrypted content with nonce and authentication tag.
///
/// Wire format: `nonce (12 bytes) || ciphertext+tag (variable)`.
/// The `ciphertext` field contains the AES-GCM output which is the
/// encrypted data with the 16-byte authentication tag appended.
/// This is intentionally a two-field struct (not three) because `aes-gcm`
/// always concatenates ciphertext and tag — splitting them provides no
/// benefit and invites desync bugs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPayload {
    pub nonce: [u8; 12],
    /// Ciphertext with the 16-byte GCM authentication tag appended.
    pub ciphertext: Vec<u8>,
}

impl EncryptedPayload {
    /// Wire format: nonce (12 bytes) || ciphertext+tag (variable).
    /// AES-GCM appends the 16-byte tag to the ciphertext automatically.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + self.ciphertext.len());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Parse from wire format bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 12 + 16 {
            return Err(CryptoError::InvalidPayload {
                reason: format!("payload too short: {} bytes (min 28)", bytes.len()),
            });
        }
        if bytes.len() > MAX_ENCRYPTED_PAYLOAD_BYTES {
            return Err(CryptoError::InvalidPayload {
                reason: format!(
                    "payload exceeds 10 MiB limit: {} bytes",
                    bytes.len()
                ),
            });
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[..12]);
        let ciphertext = bytes[12..].to_vec();
        Ok(Self { nonce, ciphertext })
    }
}

/// Encrypt plaintext with AES-256-GCM.
///
/// - `key`: 32-byte AES key
/// - `aad`: additional authenticated data (e.g., `claim_id || epoch`)
///   bound to the ciphertext — tampering with AAD causes decryption failure.
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8; 32],
    aad: &[u8],
) -> Result<EncryptedPayload, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::EncryptionFailed {
        reason: e.to_string(),
    })?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CryptoError::EncryptionFailed {
            reason: e.to_string(),
        })?;
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);
    Ok(EncryptedPayload {
        nonce: nonce_arr,
        ciphertext,
    })
}

/// Decrypt ciphertext with AES-256-GCM.
///
/// - `key`: same 32-byte key used for encryption
/// - `aad`: same AAD used during encryption — mismatch causes failure
pub fn decrypt(
    payload: &EncryptedPayload,
    key: &[u8; 32],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::DecryptionFailed {
        reason: e.to_string(),
    })?;
    let nonce = Nonce::from_slice(&payload.nonce);
    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &payload.ciphertext,
                aad,
            },
        )
        .map_err(|e| CryptoError::DecryptionFailed {
            reason: e.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"epistemic claim content";
        let aad = b"claim-id-123epoch-1";

        let payload = encrypt(plaintext, &key, aad).unwrap();
        let recovered = decrypt(&payload, &key, aad).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let plaintext = b"secret";
        let aad = b"aad";

        let payload = encrypt(plaintext, &key, aad).unwrap();
        let result = decrypt(&payload, &wrong_key, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = [42u8; 32];
        let plaintext = b"secret";

        let payload = encrypt(plaintext, &key, b"correct-aad").unwrap();
        let result = decrypt(&payload, &key, b"wrong-aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_payload_wire_format_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"roundtrip test";
        let aad = b"";

        let payload = encrypt(plaintext, &key, aad).unwrap();
        let bytes = payload.to_bytes();
        let parsed = EncryptedPayload::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, payload);

        let recovered = decrypt(&parsed, &key, aad).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_payload_too_short() {
        let result = EncryptedPayload::from_bytes(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let key = [42u8; 32];
        let plaintext = b"same content";
        let aad = b"";

        let p1 = encrypt(plaintext, &key, aad).unwrap();
        let p2 = encrypt(plaintext, &key, aad).unwrap();
        assert_ne!(p1.ciphertext, p2.ciphertext);
    }
}
