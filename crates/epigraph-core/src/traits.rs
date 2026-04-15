//! Core traits for cryptographic operations on domain types
//!
//! These traits define how domain entities (Evidence, `ReasoningTrace`, etc.)
//! interact with the cryptographic layer.

use epigraph_crypto::{AgentSigner, ContentHasher, CryptoError, SignatureVerifier, SIGNATURE_SIZE};
use serde::Serialize;

/// Trait for entities that can be cryptographically signed
///
/// Implementors define which portion of the struct is signed (excluding the
/// signature field itself to avoid circular dependencies).
pub trait Signable {
    /// The type that represents the signable content
    type SignableContent: Serialize;

    /// Returns the content that should be signed
    ///
    /// This should exclude the signature field and any derived fields.
    fn signable_content(&self) -> Self::SignableContent;

    /// Get the current signature if present
    fn signature(&self) -> Option<&[u8; SIGNATURE_SIZE]>;

    /// Set the signature on this entity
    fn set_signature(&mut self, signature: [u8; SIGNATURE_SIZE]);

    /// Sign this entity with the given signer
    ///
    /// # Errors
    /// Returns error if canonical serialization fails.
    fn sign(&mut self, signer: &AgentSigner) -> Result<(), CryptoError> {
        let content = self.signable_content();
        let signature = signer.sign_canonical(&content)?;
        self.set_signature(signature);
        Ok(())
    }
}

/// Trait for entities whose signatures can be verified
pub trait Verifiable: Signable {
    /// Get the public key of the signer
    fn signer_public_key(&self) -> &[u8; 32];

    /// Verify the signature on this entity
    ///
    /// # Errors
    /// Returns error if verification fails or signature is missing.
    fn verify(&self) -> Result<bool, CryptoError> {
        let signature = self
            .signature()
            .ok_or_else(|| CryptoError::InvalidSignature {
                reason: "No signature present".to_string(),
            })?;

        let content = self.signable_content();
        SignatureVerifier::verify_canonical(self.signer_public_key(), &content, signature)
    }
}

/// Trait for entities that have a content hash
pub trait ContentAddressable: Serialize {
    /// Get the stored content hash of this entity
    fn content_hash(&self) -> &[u8; 32];

    /// Set the content hash on this entity
    fn set_content_hash(&mut self, hash: [u8; 32]);

    /// Compute the content hash from current state
    ///
    /// # Errors
    /// Returns error if serialization fails.
    fn compute_hash(&self) -> Result<[u8; 32], CryptoError>
    where
        Self: Sized,
    {
        ContentHasher::hash_canonical(self)
    }

    /// Verify the stored hash matches the computed hash
    ///
    /// Uses constant-time comparison to prevent timing side-channels.
    ///
    /// # Errors
    /// Returns `CryptoError` if hash computation (serialization) fails.
    fn verify_hash(&self) -> Result<bool, CryptoError>
    where
        Self: Sized,
    {
        let computed = self.compute_hash()?;
        Ok(SignatureVerifier::constant_time_eq(
            &computed,
            self.content_hash(),
        ))
    }

    /// Compute and set the content hash
    ///
    /// # Errors
    /// Returns error if serialization fails.
    fn update_hash(&mut self) -> Result<(), CryptoError>
    where
        Self: Sized,
    {
        let hash = self.compute_hash()?;
        self.set_content_hash(hash);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    // Test struct for Signable and Verifiable traits
    #[derive(Debug, Clone)]
    struct TestSignable {
        data: String,
        value: i32,
        signature: Option<[u8; SIGNATURE_SIZE]>,
        public_key: [u8; 32],
    }

    #[derive(Debug, Clone, Serialize)]
    struct TestSignableContent {
        data: String,
        value: i32,
    }

    impl Signable for TestSignable {
        type SignableContent = TestSignableContent;

        fn signable_content(&self) -> Self::SignableContent {
            TestSignableContent {
                data: self.data.clone(),
                value: self.value,
            }
        }

        fn signature(&self) -> Option<&[u8; SIGNATURE_SIZE]> {
            self.signature.as_ref()
        }

        fn set_signature(&mut self, signature: [u8; SIGNATURE_SIZE]) {
            self.signature = Some(signature);
        }
    }

    impl Verifiable for TestSignable {
        fn signer_public_key(&self) -> &[u8; 32] {
            &self.public_key
        }
    }

    // Test struct for ContentAddressable trait
    #[derive(Debug, Clone, Serialize)]
    struct TestHashable {
        content: String,
        number: i64,
        #[serde(skip)]
        stored_hash: [u8; 32],
    }

    impl ContentAddressable for TestHashable {
        fn content_hash(&self) -> &[u8; 32] {
            &self.stored_hash
        }

        fn set_content_hash(&mut self, hash: [u8; 32]) {
            self.stored_hash = hash;
        }
    }

    // ==================== Signable Tests ====================

    #[test]
    fn test_sign_sets_signature() {
        let signer = AgentSigner::generate();

        let mut entity = TestSignable {
            data: "test data".to_string(),
            value: 42,
            signature: None,
            public_key: signer.public_key(),
        };

        assert!(entity.signature().is_none());
        entity.sign(&signer).unwrap();
        assert!(entity.signature().is_some());
    }

    #[test]
    fn test_different_content_different_signatures() {
        let signer = AgentSigner::generate();

        let mut entity1 = TestSignable {
            data: "data one".to_string(),
            value: 1,
            signature: None,
            public_key: signer.public_key(),
        };

        let mut entity2 = TestSignable {
            data: "data two".to_string(),
            value: 2,
            signature: None,
            public_key: signer.public_key(),
        };

        entity1.sign(&signer).unwrap();
        entity2.sign(&signer).unwrap();

        assert_ne!(entity1.signature(), entity2.signature());
    }

    #[test]
    fn test_sign_is_deterministic() {
        let signer = AgentSigner::generate();

        let mut entity1 = TestSignable {
            data: "same data".to_string(),
            value: 100,
            signature: None,
            public_key: signer.public_key(),
        };

        let mut entity2 = TestSignable {
            data: "same data".to_string(),
            value: 100,
            signature: None,
            public_key: signer.public_key(),
        };

        entity1.sign(&signer).unwrap();
        entity2.sign(&signer).unwrap();

        assert_eq!(
            entity1.signature(),
            entity2.signature(),
            "Same content with same key should produce same signature"
        );
    }

    // ==================== Verifiable Tests ====================

    #[test]
    fn test_verify_valid_signature() {
        let signer = AgentSigner::generate();

        let mut entity = TestSignable {
            data: "verifiable data".to_string(),
            value: 123,
            signature: None,
            public_key: signer.public_key(),
        };

        entity.sign(&signer).unwrap();
        let is_valid = entity.verify().unwrap();
        assert!(is_valid, "Valid signature should verify successfully");
    }

    #[test]
    fn test_verify_wrong_public_key_fails() {
        let signer1 = AgentSigner::generate();
        let signer2 = AgentSigner::generate();

        let mut entity = TestSignable {
            data: "some data".to_string(),
            value: 456,
            signature: None,
            public_key: signer2.public_key(), // Wrong public key
        };

        // Sign with signer1 but entity has signer2's public key
        entity.sign(&signer1).unwrap();
        let is_valid = entity.verify().unwrap();
        assert!(!is_valid, "Wrong public key should fail verification");
    }

    #[test]
    fn test_verify_missing_signature_errors() {
        let signer = AgentSigner::generate();

        let entity = TestSignable {
            data: "unsigned data".to_string(),
            value: 789,
            signature: None, // No signature
            public_key: signer.public_key(),
        };

        let result = entity.verify();
        assert!(result.is_err(), "Missing signature should return error");
    }

    #[test]
    fn test_verify_tampered_data_fails() {
        let signer = AgentSigner::generate();

        let mut entity = TestSignable {
            data: "original data".to_string(),
            value: 100,
            signature: None,
            public_key: signer.public_key(),
        };

        entity.sign(&signer).unwrap();

        // Tamper with the data after signing
        entity.data = "tampered data".to_string();

        let is_valid = entity.verify().unwrap();
        assert!(!is_valid, "Tampered data should fail verification");
    }

    #[test]
    fn test_verify_tampered_value_fails() {
        let signer = AgentSigner::generate();

        let mut entity = TestSignable {
            data: "fixed data".to_string(),
            value: 100,
            signature: None,
            public_key: signer.public_key(),
        };

        entity.sign(&signer).unwrap();

        // Tamper with the value after signing
        entity.value = 999;

        let is_valid = entity.verify().unwrap();
        assert!(!is_valid, "Tampered value should fail verification");
    }

    // ==================== ContentAddressable Tests ====================

    #[test]
    fn test_content_addressable_compute_hash() {
        let entity = TestHashable {
            content: "test content".to_string(),
            number: 42,
            stored_hash: [0u8; 32],
        };

        let hash = entity.compute_hash().unwrap();
        assert_ne!(hash, [0u8; 32], "Computed hash should not be all zeros");
        assert_eq!(hash.len(), 32, "Hash should be 32 bytes");
    }

    #[test]
    fn test_content_addressable_same_content_same_hash() {
        let entity1 = TestHashable {
            content: "identical".to_string(),
            number: 123,
            stored_hash: [0u8; 32],
        };

        let entity2 = TestHashable {
            content: "identical".to_string(),
            number: 123,
            stored_hash: [0u8; 32],
        };

        let hash1 = entity1.compute_hash().unwrap();
        let hash2 = entity2.compute_hash().unwrap();

        assert_eq!(hash1, hash2, "Same content should produce same hash");
    }

    #[test]
    fn test_content_addressable_different_content_different_hash() {
        let entity1 = TestHashable {
            content: "content one".to_string(),
            number: 1,
            stored_hash: [0u8; 32],
        };

        let entity2 = TestHashable {
            content: "content two".to_string(),
            number: 2,
            stored_hash: [0u8; 32],
        };

        let hash1 = entity1.compute_hash().unwrap();
        let hash2 = entity2.compute_hash().unwrap();

        assert_ne!(
            hash1, hash2,
            "Different content should produce different hash"
        );
    }

    #[test]
    fn test_content_addressable_update_hash() {
        let mut entity = TestHashable {
            content: "hashable content".to_string(),
            number: 999,
            stored_hash: [0u8; 32],
        };

        assert_eq!(
            entity.content_hash(),
            &[0u8; 32],
            "Initial hash should be zero"
        );

        entity.update_hash().unwrap();

        assert_ne!(
            entity.content_hash(),
            &[0u8; 32],
            "Hash should be updated after update_hash()"
        );
    }

    #[test]
    fn test_content_addressable_verify_hash_success() {
        let mut entity = TestHashable {
            content: "verify me".to_string(),
            number: 555,
            stored_hash: [0u8; 32],
        };

        entity.update_hash().unwrap();

        let is_valid = entity.verify_hash().unwrap();
        assert!(is_valid, "Hash should verify successfully after update");
    }

    #[test]
    fn test_content_addressable_verify_hash_mismatch() {
        let mut entity = TestHashable {
            content: "original".to_string(),
            number: 111,
            stored_hash: [0u8; 32],
        };

        entity.update_hash().unwrap();

        // Modify content after hashing
        entity.content = "modified".to_string();

        let is_valid = entity.verify_hash().unwrap();
        assert!(
            !is_valid,
            "Hash should fail verification after content change"
        );
    }

    #[test]
    fn test_content_addressable_single_byte_corruption_detected() {
        let mut entity = TestHashable {
            content: "corruption test".to_string(),
            number: 777,
            stored_hash: [0u8; 32],
        };

        entity.update_hash().unwrap();

        // Corrupt one byte of the hash
        entity.stored_hash[0] ^= 0xFF;

        let is_valid = entity.verify_hash().unwrap();
        assert!(!is_valid, "Single byte corruption should fail verification");
    }

    #[test]
    fn test_content_addressable_hash_excludes_stored_hash() {
        let mut entity = TestHashable {
            content: "test".to_string(),
            number: 1,
            stored_hash: [0u8; 32],
        };

        entity.update_hash().unwrap();
        let hash1 = *entity.content_hash();

        // Change the stored hash and recompute - should get same result
        // because stored_hash is marked #[serde(skip)]
        entity.stored_hash = [0xFF; 32];
        let hash2 = entity.compute_hash().unwrap();

        assert_eq!(hash1, hash2, "Stored hash should not affect computed hash");
    }
}
