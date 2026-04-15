//! Ed25519 signature verification
//!
//! Verifies that data was signed by the holder of a specific public key.

use crate::canonical::Canonical;
use crate::errors::CryptoError;
use crate::{PUBLIC_KEY_SIZE, SIGNATURE_SIZE};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use subtle::ConstantTimeEq;

/// Signature verifier for Ed25519 signatures
///
/// Stateless utility for verifying signatures against public keys.
pub struct SignatureVerifier;

impl SignatureVerifier {
    /// Verify a signature against a public key and message
    ///
    /// # Security Notes
    ///
    /// - Uses constant-time comparison internally (via ed25519-dalek)
    /// - The inner `is_ok()` check avoids leaking timing information about
    ///   which step of verification failed
    ///
    /// # Errors
    /// Returns error if public key or signature format is invalid (parsing errors only).
    /// Verification failures return `Ok(false)`, not errors.
    pub fn verify(
        public_key: &[u8; PUBLIC_KEY_SIZE],
        message: &[u8],
        signature: &[u8; SIGNATURE_SIZE],
    ) -> Result<bool, CryptoError> {
        let verifying_key =
            VerifyingKey::from_bytes(public_key).map_err(|e| CryptoError::InvalidPublicKey {
                reason: e.to_string(),
            })?;

        let sig = Signature::from_bytes(signature);

        Ok(verifying_key.verify(message, &sig).is_ok())
    }

    /// Verify a signature over a canonically serialized value
    ///
    /// # Errors
    /// Returns error if serialization fails or key/signature format is invalid.
    pub fn verify_canonical<T: Canonical>(
        public_key: &[u8; PUBLIC_KEY_SIZE],
        value: &T,
        signature: &[u8; SIGNATURE_SIZE],
    ) -> Result<bool, CryptoError> {
        let bytes = value.canonical_bytes()?;
        Self::verify(public_key, &bytes, signature)
    }

    /// Constant-time comparison of two byte slices
    ///
    /// Use this when comparing hashes or signatures to prevent timing attacks.
    #[must_use]
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::AgentSigner;

    #[test]
    fn verify_valid_signature() {
        let signer = AgentSigner::generate();
        let message = b"test message";

        let signature = signer.sign(message);
        let public_key = signer.public_key();

        let is_valid = SignatureVerifier::verify(&public_key, message, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn reject_tampered_message() {
        let signer = AgentSigner::generate();
        let original = b"original message";
        let tampered = b"tampered message";

        let signature = signer.sign(original);
        let public_key = signer.public_key();

        let is_valid = SignatureVerifier::verify(&public_key, tampered, &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn reject_wrong_public_key() {
        let signer1 = AgentSigner::generate();
        let signer2 = AgentSigner::generate();
        let message = b"test message";

        let signature = signer1.sign(message);
        let wrong_public_key = signer2.public_key();

        let is_valid = SignatureVerifier::verify(&wrong_public_key, message, &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn verify_canonical_works() {
        let signer = AgentSigner::generate();
        let obj = serde_json::json!({"key": "value", "num": 42});

        let signature = signer.sign_canonical(&obj).unwrap();
        let public_key = signer.public_key();

        let is_valid = SignatureVerifier::verify_canonical(&public_key, &obj, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn verify_canonical_with_reordered_keys() {
        let signer = AgentSigner::generate();

        // Sign with one key order
        let obj1 = serde_json::json!({"b": 2, "a": 1});
        let signature = signer.sign_canonical(&obj1).unwrap();

        // Verify with different key order (should still work due to canonicalization)
        let obj2 = serde_json::json!({"a": 1, "b": 2});
        let public_key = signer.public_key();

        let is_valid = SignatureVerifier::verify_canonical(&public_key, &obj2, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn constant_time_eq_works() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(SignatureVerifier::constant_time_eq(&a, &b));
        assert!(!SignatureVerifier::constant_time_eq(&a, &c));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3, 4];

        assert!(!SignatureVerifier::constant_time_eq(&a, &b));
    }
}
