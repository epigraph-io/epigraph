//! Ed25519 signing for agents
//!
//! Each agent in `EpiGraph` has an Ed25519 keypair. The private key signs
//! evidence and reasoning traces; the public key is stored for verification.

use crate::canonical::Canonical;
use crate::errors::CryptoError;
use crate::{PUBLIC_KEY_SIZE, SIGNATURE_SIZE};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

/// Agent signer for creating Ed25519 signatures
///
/// # Security Notes
///
/// - The signing key should NEVER be stored in the database
/// - Keys should be stored in secure enclaves or HSMs in production
/// - This implementation uses OS-provided randomness for key generation
pub struct AgentSigner {
    /// `ed25519_dalek::SigningKey` derives `ZeroizeOnDrop`, so the secret key
    /// bytes are automatically overwritten when `AgentSigner` is dropped.
    /// No manual `Drop` impl is required.
    signing_key: SigningKey,
}

impl AgentSigner {
    /// Create a signer from existing secret key bytes
    ///
    /// # Errors
    /// Returns error if the key bytes are invalid.
    pub fn from_bytes(secret_key_bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        Ok(Self {
            signing_key: SigningKey::from_bytes(secret_key_bytes),
        })
    }

    /// Generate a new random keypair
    ///
    /// Uses the operating system's secure random number generator.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Get the public key bytes for this signer
    ///
    /// This is what gets stored in the database to identify the agent.
    #[must_use]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the secret key bytes (use with extreme caution)
    ///
    /// # Security Warning
    /// Only use this for key backup/export. Never log or transmit.
    #[must_use = "secret key material must be zeroized after use"]
    pub fn secret_key(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Sign arbitrary message bytes
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Sign a canonically serializable value
    ///
    /// The value is first serialized to canonical JSON, then signed.
    ///
    /// # Errors
    /// Returns error if canonical serialization fails.
    pub fn sign_canonical<T: Canonical>(
        &self,
        value: &T,
    ) -> Result<[u8; SIGNATURE_SIZE], CryptoError> {
        let bytes = value.canonical_bytes()?;
        Ok(self.sign(&bytes))
    }
}

impl std::fmt::Debug for AgentSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret key
        f.debug_struct("AgentSigner")
            .field("public_key", &hex::encode(&self.public_key()))
            .finish()
    }
}

/// Helper module for hex encoding (avoid adding dependency)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_creates_valid_keypair() {
        let signer = AgentSigner::generate();
        let public_key = signer.public_key();
        assert_eq!(public_key.len(), 32);
    }

    #[test]
    fn sign_produces_64_byte_signature() {
        let signer = AgentSigner::generate();
        let signature = signer.sign(b"test message");
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn sign_is_deterministic_for_same_key_and_message() {
        let signer = AgentSigner::generate();
        let sig1 = signer.sign(b"same message");
        let sig2 = signer.sign(b"same message");
        // Note: Ed25519 signatures are deterministic given the same key and message
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn different_messages_produce_different_signatures() {
        let signer = AgentSigner::generate();
        let sig1 = signer.sign(b"message one");
        let sig2 = signer.sign(b"message two");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn roundtrip_secret_key() {
        let signer1 = AgentSigner::generate();
        let secret = signer1.secret_key();

        let signer2 = AgentSigner::from_bytes(&secret).unwrap();

        assert_eq!(signer1.public_key(), signer2.public_key());

        let message = b"test roundtrip";
        assert_eq!(signer1.sign(message), signer2.sign(message));
    }

    #[test]
    fn sign_canonical_handles_json() {
        let signer = AgentSigner::generate();

        let obj = serde_json::json!({"claim": "test", "value": 42});
        let signature = signer.sign_canonical(&obj).unwrap();

        assert_eq!(signature.len(), 64);
    }

    // --- Additional comprehensive tests ---

    #[test]
    fn generate_produces_unique_keys_each_time() {
        let signer1 = AgentSigner::generate();
        let signer2 = AgentSigner::generate();
        let signer3 = AgentSigner::generate();

        // All three public keys must be different
        assert_ne!(
            signer1.public_key(),
            signer2.public_key(),
            "Two independently generated keys must differ"
        );
        assert_ne!(signer2.public_key(), signer3.public_key());
        assert_ne!(signer1.public_key(), signer3.public_key());

        // Secret keys must also differ
        assert_ne!(signer1.secret_key(), signer2.secret_key());
    }

    #[test]
    fn public_key_is_consistent_across_calls() {
        let signer = AgentSigner::generate();
        let pk1 = signer.public_key();
        let pk2 = signer.public_key();
        let pk3 = signer.public_key();

        assert_eq!(pk1, pk2, "Public key must be stable across calls");
        assert_eq!(pk2, pk3);
    }

    #[test]
    fn public_key_is_32_bytes() {
        let signer = AgentSigner::generate();
        let pk = signer.public_key();
        assert_eq!(pk.len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn secret_key_is_32_bytes() {
        let signer = AgentSigner::generate();
        let sk = signer.secret_key();
        assert_eq!(sk.len(), 32);
    }

    #[test]
    fn sign_empty_message() {
        let signer = AgentSigner::generate();
        let sig = signer.sign(b"");
        assert_eq!(sig.len(), SIGNATURE_SIZE);
        // Signature of empty message should not be all zeros
        assert_ne!(sig, [0u8; SIGNATURE_SIZE]);
    }

    #[test]
    fn sign_large_message() {
        let signer = AgentSigner::generate();
        let large_msg = vec![0xABu8; 100_000];
        let sig = signer.sign(&large_msg);
        assert_eq!(sig.len(), SIGNATURE_SIZE);
    }

    #[test]
    fn from_bytes_roundtrip_preserves_signing_behavior() {
        let original = AgentSigner::generate();
        let secret = original.secret_key();

        let restored = AgentSigner::from_bytes(&secret).unwrap();

        // Public keys match
        assert_eq!(original.public_key(), restored.public_key());

        // Signatures match for any message
        let messages: &[&[u8]] = &[b"", b"short", b"a longer test message for roundtrip"];
        for msg in messages {
            assert_eq!(
                original.sign(msg),
                restored.sign(msg),
                "Signing must produce same result after secret key roundtrip"
            );
        }
    }

    #[test]
    fn from_bytes_with_all_zeros() {
        // All-zero secret key is technically valid for Ed25519 (it's just a specific key)
        let zero_key = [0u8; 32];
        let signer = AgentSigner::from_bytes(&zero_key).unwrap();
        let pk = signer.public_key();
        assert_eq!(pk.len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn sign_canonical_key_order_invariant() {
        let signer = AgentSigner::generate();

        let obj1 = serde_json::json!({"b": 2, "a": 1});
        let obj2 = serde_json::json!({"a": 1, "b": 2});

        let sig1 = signer.sign_canonical(&obj1).unwrap();
        let sig2 = signer.sign_canonical(&obj2).unwrap();

        assert_eq!(
            sig1, sig2,
            "Canonical signing must produce same signature regardless of key order"
        );
    }

    #[test]
    fn sign_canonical_nested_key_order_invariant() {
        let signer = AgentSigner::generate();

        let obj1 = serde_json::json!({"outer": {"z": 1, "a": 2}, "first": true});
        let obj2 = serde_json::json!({"first": true, "outer": {"a": 2, "z": 1}});

        let sig1 = signer.sign_canonical(&obj1).unwrap();
        let sig2 = signer.sign_canonical(&obj2).unwrap();

        assert_eq!(
            sig1, sig2,
            "Nested canonical signing must be key-order invariant"
        );
    }

    #[test]
    fn different_keys_produce_different_signatures_for_same_message() {
        let signer1 = AgentSigner::generate();
        let signer2 = AgentSigner::generate();
        let message = b"same message for both signers";

        let sig1 = signer1.sign(message);
        let sig2 = signer2.sign(message);

        assert_ne!(
            sig1, sig2,
            "Different keys must produce different signatures for the same message"
        );
    }

    #[test]
    fn debug_does_not_leak_secret_key() {
        let signer = AgentSigner::generate();
        let secret_hex = crate::hasher::ContentHasher::to_hex(&{
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&signer.secret_key());
            arr
        });
        let debug_output = format!("{signer:?}");

        // Debug output should contain "AgentSigner" and "public_key"
        assert!(
            debug_output.contains("AgentSigner"),
            "Debug should identify the type"
        );
        assert!(
            debug_output.contains("public_key"),
            "Debug should show public key field"
        );

        // Debug output must NOT contain the secret key
        // (Unless the public and secret key happen to share hex digits, which is
        // astronomically unlikely for random keys)
        assert!(
            !debug_output.contains(&secret_hex),
            "Debug output must never contain the secret key"
        );
    }

    #[test]
    fn signature_is_not_all_zeros() {
        let signer = AgentSigner::generate();
        let messages: &[&[u8]] = &[b"hello", b"world", b"test"];
        for msg in messages {
            let sig = signer.sign(msg);
            assert_ne!(
                sig, [0u8; SIGNATURE_SIZE],
                "Signature must not be all zeros"
            );
        }
    }
}
