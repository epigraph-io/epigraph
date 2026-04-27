//! ECDH key exchange for group member onboarding.
//!
//! Converts Ed25519 keys to X25519 (Curve25519 Montgomery form) for
//! Diffie-Hellman key agreement. The shared secret is used to wrap
//! group keys for distribution to new members.

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::encryption::{decrypt, encrypt, EncryptedPayload};
use crate::errors::CryptoError;

/// Convert an Ed25519 signing key to an X25519 static secret.
///
/// Per RFC 8032: hash the secret key with SHA-512, take the lower 32 bytes,
/// and apply X25519 clamping (clear bits 0,1,2,255; set bit 254).
#[must_use]
pub fn ed25519_to_x25519_secret(signing_key: &SigningKey) -> X25519Secret {
    let hash = Sha512::digest(signing_key.as_bytes());
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    // X25519 clamping — use hex literals for clarity (clippy::decimal_bitwise_operands)
    scalar[0] &= 0xf8; // clear bits 0, 1, 2
    scalar[31] &= 0x7f; // clear bit 255
    scalar[31] |= 0x40; // set bit 254
    X25519Secret::from(scalar)
}

/// Convert an Ed25519 verifying key to an X25519 public key.
///
/// Uses the birational map from Edwards to Montgomery form.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPublicKey`] if `verifying_key` encodes an
/// invalid (low-order) Edwards point that cannot be decompressed. In practice
/// `ed25519_dalek::VerifyingKey` always holds a valid compressed Edwards-y
/// coordinate, but we propagate errors rather than panic on malformed input.
pub fn ed25519_to_x25519_public(verifying_key: &VerifyingKey) -> Result<X25519Public, CryptoError> {
    let edwards = curve25519_dalek::edwards::CompressedEdwardsY(verifying_key.to_bytes());
    let point = edwards
        .decompress()
        .ok_or_else(|| CryptoError::InvalidPublicKey {
            reason: "Ed25519 public key decompression failed (invalid Edwards point)".into(),
        })?;
    let montgomery = point.to_montgomery();
    Ok(X25519Public::from(montgomery.to_bytes()))
}

/// Compute ECDH shared secret between two parties.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPublicKey`] if `their_public` cannot be
/// converted to an X25519 key (see [`ed25519_to_x25519_public`]).
pub fn ecdh_shared_secret(
    our_secret: &SigningKey,
    their_public: &VerifyingKey,
) -> Result<[u8; 32], CryptoError> {
    let x_secret = ed25519_to_x25519_secret(our_secret);
    let x_public = ed25519_to_x25519_public(their_public)?;
    let shared = x_secret.diffie_hellman(&x_public);
    Ok(*shared.as_bytes())
}

/// Wrap a 32-byte group key using an ECDH-derived shared secret.
///
/// # Errors
///
/// Returns [`CryptoError::EncryptionFailed`] if AES-GCM encryption fails.
pub fn wrap_group_key(
    group_key: &[u8; 32],
    shared_secret: &[u8; 32],
) -> Result<EncryptedPayload, CryptoError> {
    encrypt(group_key, shared_secret, b"epigraph-key-wrap")
}

/// Unwrap a group key from an ECDH-wrapped payload.
///
/// # Errors
///
/// Returns [`CryptoError::DecryptionFailed`] if the shared secret is wrong or
/// the ciphertext is corrupted. Returns [`CryptoError::KeyExchangeFailed`] if
/// the decrypted payload is not exactly 32 bytes.
pub fn unwrap_group_key(
    wrapped: &EncryptedPayload,
    shared_secret: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let bytes = decrypt(wrapped, shared_secret, b"epigraph-key-wrap")?;
    if bytes.len() != 32 {
        return Err(CryptoError::KeyExchangeFailed {
            reason: format!("expected 32-byte key, got {}", bytes.len()),
        });
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_ecdh_shared_secret_symmetric() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);

        let secret_ab = ecdh_shared_secret(&alice, &bob.verifying_key()).unwrap();
        let secret_ba = ecdh_shared_secret(&bob, &alice.verifying_key()).unwrap();
        assert_eq!(secret_ab, secret_ba);
    }

    #[test]
    fn test_ecdh_different_parties_different_secrets() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let carol = SigningKey::generate(&mut OsRng);

        let ab = ecdh_shared_secret(&alice, &bob.verifying_key()).unwrap();
        let ac = ecdh_shared_secret(&alice, &carol.verifying_key()).unwrap();
        assert_ne!(ab, ac);
    }

    #[test]
    fn test_wrap_unwrap_group_key() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);

        let shared = ecdh_shared_secret(&alice, &bob.verifying_key()).unwrap();
        let group_key = [77u8; 32];

        let wrapped = wrap_group_key(&group_key, &shared).unwrap();
        let unwrapped = unwrap_group_key(&wrapped, &shared).unwrap();
        assert_eq!(unwrapped, group_key);
    }

    #[test]
    fn test_wrong_shared_secret_fails_unwrap() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);

        let shared = ecdh_shared_secret(&alice, &bob.verifying_key()).unwrap();
        let group_key = [77u8; 32];

        let wrapped = wrap_group_key(&group_key, &shared).unwrap();
        let wrong_secret = [0u8; 32];
        let result = unwrap_group_key(&wrapped, &wrong_secret);
        assert!(result.is_err());
    }
}
