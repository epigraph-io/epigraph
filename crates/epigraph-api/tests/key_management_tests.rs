//! Comprehensive TDD tests for KeyManager key lifecycle management
//!
//! These tests drive the implementation of the KeyManager stub methods:
//! - `get_active_key()` - Key lookup by agent
//! - `rotate_key()` - Key rotation with dual-signature verification
//! - `revoke_key()` - Key revocation with reason tracking
//!
//! # Test Categories
//!
//! 1. **Key Lookup Tests**: Finding active keys for agents
//! 2. **Key Rotation Tests**: Dual-signature verification and status transitions
//! 3. **Key Revocation Tests**: Revocation with reason and audit trail
//! 4. **Expiration Tests**: Time-based key invalidation
//!
//! # Design Notes
//!
//! These tests use a mock repository pattern to isolate the KeyManager logic
//! from database concerns. The actual implementation will inject a repository
//! trait for persistence.

use chrono::{Duration, Utc};
use epigraph_api::security::keys::{
    AgentKey, KeyError, KeyRevocationRequest, KeyRotationRequest, KeyStatus, Signature,
};
use epigraph_core::domain::AgentId;
use epigraph_crypto::{AgentSigner, SignatureVerifier};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

// =============================================================================
// MOCK REPOSITORY FOR TESTING
// =============================================================================

/// Mock repository for storing agent keys in memory
///
/// This enables testing KeyManager logic without a real database.
/// The actual implementation will use a trait-based repository.
#[derive(Clone, Default)]
pub struct MockKeyRepository {
    keys: Arc<RwLock<HashMap<Uuid, AgentKey>>>,
    agent_active_keys: Arc<RwLock<HashMap<AgentId, Uuid>>>,
}

impl MockKeyRepository {
    /// Create a new empty mock repository
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a key in the repository
    pub fn store_key(&self, key: AgentKey) {
        let mut keys = self.keys.write().unwrap();
        let mut active = self.agent_active_keys.write().unwrap();

        // If this key is active, update the agent's active key mapping
        if key.status == KeyStatus::Active {
            active.insert(key.agent_id, key.id);
        }

        keys.insert(key.id, key);
    }

    /// Get a key by ID
    pub fn get_key(&self, key_id: Uuid) -> Option<AgentKey> {
        self.keys.read().unwrap().get(&key_id).cloned()
    }

    /// Get the active key for an agent
    pub fn get_active_key(&self, agent_id: AgentId) -> Option<AgentKey> {
        let active = self.agent_active_keys.read().unwrap();
        let keys = self.keys.read().unwrap();

        active
            .get(&agent_id)
            .and_then(|key_id| keys.get(key_id))
            .cloned()
    }

    /// Get all keys for an agent
    pub fn get_agent_keys(&self, agent_id: AgentId) -> Vec<AgentKey> {
        self.keys
            .read()
            .unwrap()
            .values()
            .filter(|k| k.agent_id == agent_id)
            .cloned()
            .collect()
    }

    /// Update a key in the repository
    pub fn update_key(&self, key: AgentKey) {
        let mut keys = self.keys.write().unwrap();
        let mut active = self.agent_active_keys.write().unwrap();

        // Handle status changes for active key mapping
        match key.status {
            KeyStatus::Active => {
                active.insert(key.agent_id, key.id);
            }
            KeyStatus::Rotated | KeyStatus::Revoked | KeyStatus::Expired => {
                // Remove from active if this was the active key
                if active.get(&key.agent_id) == Some(&key.id) {
                    active.remove(&key.agent_id);
                }
            }
            KeyStatus::Pending => {}
        }

        keys.insert(key.id, key);
    }

    /// Clear all keys (for test isolation)
    pub fn clear(&self) {
        self.keys.write().unwrap().clear();
        self.agent_active_keys.write().unwrap().clear();
    }
}

// =============================================================================
// TESTABLE KEY MANAGER
// =============================================================================

/// A testable version of KeyManager that uses a mock repository
///
/// This struct mirrors the interface of the production KeyManager but
/// uses injected dependencies for testing.
pub struct TestableKeyManager {
    repo: MockKeyRepository,
}

impl TestableKeyManager {
    /// Create a new key manager with the given repository
    pub fn new(repo: MockKeyRepository) -> Self {
        Self { repo }
    }

    /// Get the currently active key for an agent
    ///
    /// # Errors
    ///
    /// Returns `KeyError::KeyNotFound` if no active key exists for the agent
    pub fn get_active_key(&self, agent_id: AgentId) -> Result<AgentKey, KeyError> {
        self.repo.get_active_key(agent_id).ok_or_else(|| {
            KeyError::KeyNotFound {
                key_id: Uuid::nil(), // No specific key ID when searching by agent
                agent_id,
            }
        })
    }

    /// Rotate an agent's key with dual-signature verification
    ///
    /// # Process
    ///
    /// 1. Look up the current active key
    /// 2. Verify the old key signature over the rotation message
    /// 3. Verify the new key signature over the rotation message
    /// 4. Mark the current key as Rotated
    /// 5. Create and activate the new key
    ///
    /// # Errors
    ///
    /// - `KeyError::KeyNotFound` if no active key exists
    /// - `KeyError::InvalidKeyStatus` if current key is not active
    /// - `KeyError::InvalidOldKeySignature` if old key signature fails
    /// - `KeyError::InvalidNewKeySignature` if new key signature fails
    pub fn rotate_key(&self, request: KeyRotationRequest) -> Result<AgentKey, KeyError> {
        // 1. Get current active key
        let mut current_key = self.get_active_key(request.agent_id)?;

        // 2. Verify current key is active
        if current_key.status != KeyStatus::Active {
            return Err(KeyError::InvalidKeyStatus {
                key_id: current_key.id,
                status: current_key.status,
                operation: "key rotation".to_string(),
            });
        }

        // 3. Verify old key signature
        let message = request.message_to_sign();
        let old_sig_valid = SignatureVerifier::verify(
            &current_key.public_key,
            &message,
            request.old_key_signature.as_bytes(),
        )
        .unwrap_or(false);

        if !old_sig_valid {
            return Err(KeyError::InvalidOldKeySignature);
        }

        // 4. Verify new key signature
        let new_sig_valid = SignatureVerifier::verify(
            &request.new_public_key,
            &message,
            request.new_key_signature.as_bytes(),
        )
        .unwrap_or(false);

        if !new_sig_valid {
            return Err(KeyError::InvalidNewKeySignature);
        }

        // 5. Mark current key as rotated
        current_key.mark_rotated();
        self.repo.update_key(current_key);

        // 6. Create and store new active key
        let new_key = AgentKey::new(request.agent_id, request.new_public_key);
        self.repo.store_key(new_key.clone());

        Ok(new_key)
    }

    /// Revoke an agent's key
    ///
    /// # Errors
    ///
    /// - `KeyError::KeyNotFound` if key doesn't exist
    /// - `KeyError::InvalidKeyStatus` if key is already revoked
    pub fn revoke_key(&self, request: KeyRevocationRequest) -> Result<(), KeyError> {
        // Get the key to revoke
        let mut key = self
            .repo
            .get_key(request.key_id)
            .ok_or(KeyError::KeyNotFound {
                key_id: request.key_id,
                agent_id: request.agent_id,
            })?;

        // Verify the key belongs to the agent
        if key.agent_id != request.agent_id {
            return Err(KeyError::KeyNotFound {
                key_id: request.key_id,
                agent_id: request.agent_id,
            });
        }

        // Check if already revoked
        if key.status == KeyStatus::Revoked {
            return Err(KeyError::InvalidKeyStatus {
                key_id: key.id,
                status: KeyStatus::Revoked,
                operation: "revocation".to_string(),
            });
        }

        // Revoke the key
        key.revoke(request.reason, request.revoked_by);
        self.repo.update_key(key);

        Ok(())
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Create a signed key rotation request
fn create_signed_rotation_request(
    agent_id: AgentId,
    old_signer: &AgentSigner,
    new_signer: &AgentSigner,
    reason: &str,
) -> KeyRotationRequest {
    let new_public_key = new_signer.public_key();

    // Create an unsigned request first to get the message
    let unsigned_request = KeyRotationRequest::new(
        agent_id,
        new_public_key,
        Signature::from_bytes([0u8; 64]), // Placeholder
        Signature::from_bytes([0u8; 64]), // Placeholder
        reason.to_string(),
    );

    let message = unsigned_request.message_to_sign();

    // Sign with both keys
    let old_signature = Signature::from_bytes(old_signer.sign(&message));
    let new_signature = Signature::from_bytes(new_signer.sign(&message));

    KeyRotationRequest::new(
        agent_id,
        new_public_key,
        old_signature,
        new_signature,
        reason.to_string(),
    )
}

// =============================================================================
// KEY LOOKUP TESTS
// =============================================================================

/// Test 1: get_active_key finds the active key for an agent
#[test]
fn test_get_active_key_finds_existing_key() {
    // Given: A repository with an active key for an agent
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let signer = AgentSigner::generate();
    let key = AgentKey::new(agent_id, signer.public_key());
    let expected_key_id = key.id;
    repo.store_key(key);

    let manager = TestableKeyManager::new(repo);

    // When: We look up the active key
    let result = manager.get_active_key(agent_id);

    // Then: The key should be found
    assert!(result.is_ok(), "Should find active key");
    let found_key = result.unwrap();
    assert_eq!(found_key.id, expected_key_id);
    assert_eq!(found_key.agent_id, agent_id);
    assert_eq!(found_key.status, KeyStatus::Active);
}

/// Test 2: get_active_key returns KeyError::KeyNotFound for unknown agent
#[test]
fn test_get_active_key_returns_error_for_unknown_agent() {
    // Given: An empty repository
    let repo = MockKeyRepository::new();
    let manager = TestableKeyManager::new(repo);
    let unknown_agent = AgentId::new();

    // When: We look up the active key for an unknown agent
    let result = manager.get_active_key(unknown_agent);

    // Then: Should return KeyNotFound error
    assert!(result.is_err(), "Should not find key for unknown agent");
    match result.unwrap_err() {
        KeyError::KeyNotFound { agent_id, .. } => {
            assert_eq!(agent_id, unknown_agent);
        }
        other => panic!("Expected KeyNotFound error, got: {:?}", other),
    }
}

/// Test 3: get_active_key returns the most recent active key if multiple exist
#[test]
fn test_get_active_key_returns_most_recent_active() {
    // Given: An agent with multiple keys, only one active
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();

    // Create an old rotated key
    let old_signer = AgentSigner::generate();
    let mut old_key = AgentKey::new(agent_id, old_signer.public_key());
    old_key.mark_rotated();
    repo.store_key(old_key.clone());

    // Create a new active key
    let new_signer = AgentSigner::generate();
    let new_key = AgentKey::new(agent_id, new_signer.public_key());
    let expected_key_id = new_key.id;
    repo.store_key(new_key);

    let manager = TestableKeyManager::new(repo);

    // When: We look up the active key
    let result = manager.get_active_key(agent_id);

    // Then: Should return the new (active) key, not the old (rotated) one
    assert!(result.is_ok(), "Should find active key");
    let found_key = result.unwrap();
    assert_eq!(found_key.id, expected_key_id);
    assert_eq!(found_key.status, KeyStatus::Active);
    assert_ne!(found_key.id, old_key.id, "Should not return rotated key");
}

// =============================================================================
// KEY ROTATION TESTS
// =============================================================================

/// Test 4: Rotation with valid dual signatures succeeds
#[test]
fn test_rotation_with_valid_dual_signatures_succeeds() {
    // Given: An agent with an active key
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let old_key = AgentKey::new(agent_id, old_signer.public_key());
    repo.store_key(old_key.clone());

    let manager = TestableKeyManager::new(repo.clone());

    // When: We rotate with valid signatures from both old and new keys
    let new_signer = AgentSigner::generate();
    let request =
        create_signed_rotation_request(agent_id, &old_signer, &new_signer, "Scheduled rotation");

    let result = manager.rotate_key(request);

    // Then: Rotation should succeed
    assert!(
        result.is_ok(),
        "Rotation should succeed with valid signatures"
    );
    let new_key = result.unwrap();
    assert_eq!(new_key.agent_id, agent_id);
    assert_eq!(new_key.status, KeyStatus::Active);
    assert_eq!(new_key.public_key, new_signer.public_key());
}

/// Test 5: Old key is marked as Rotated after rotation
#[test]
fn test_old_key_marked_rotated_after_rotation() {
    // Given: An agent with an active key
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let old_key = AgentKey::new(agent_id, old_signer.public_key());
    let old_key_id = old_key.id;
    repo.store_key(old_key);

    let manager = TestableKeyManager::new(repo.clone());

    // When: We rotate the key
    let new_signer = AgentSigner::generate();
    let request =
        create_signed_rotation_request(agent_id, &old_signer, &new_signer, "Scheduled rotation");
    let _ = manager.rotate_key(request);

    // Then: The old key should be marked as Rotated
    let old_key_after = repo.get_key(old_key_id).unwrap();
    assert_eq!(
        old_key_after.status,
        KeyStatus::Rotated,
        "Old key should be marked as Rotated"
    );
}

/// Test 6: New key is marked as Active after rotation
#[test]
fn test_new_key_marked_active_after_rotation() {
    // Given: An agent with an active key
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let old_key = AgentKey::new(agent_id, old_signer.public_key());
    repo.store_key(old_key);

    let manager = TestableKeyManager::new(repo.clone());

    // When: We rotate the key
    let new_signer = AgentSigner::generate();
    let request =
        create_signed_rotation_request(agent_id, &old_signer, &new_signer, "Scheduled rotation");
    let result = manager.rotate_key(request);

    // Then: The new key should be Active and be the current active key
    let new_key = result.unwrap();
    assert_eq!(new_key.status, KeyStatus::Active);

    let active_key = manager.get_active_key(agent_id).unwrap();
    assert_eq!(active_key.id, new_key.id);
    assert_eq!(active_key.public_key, new_signer.public_key());
}

/// Test 7: Invalid old key signature returns KeyError::InvalidOldKeySignature
#[test]
fn test_invalid_old_key_signature_returns_error() {
    // Given: An agent with an active key
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let old_key = AgentKey::new(agent_id, old_signer.public_key());
    repo.store_key(old_key);

    let manager = TestableKeyManager::new(repo);

    // When: We rotate with an invalid old key signature
    let new_signer = AgentSigner::generate();
    let wrong_signer = AgentSigner::generate(); // Wrong signer for old key

    // Create message and sign with wrong signer for old key
    let unsigned_request = KeyRotationRequest::new(
        agent_id,
        new_signer.public_key(),
        Signature::from_bytes([0u8; 64]),
        Signature::from_bytes([0u8; 64]),
        "Test rotation".to_string(),
    );
    let message = unsigned_request.message_to_sign();

    let request = KeyRotationRequest::new(
        agent_id,
        new_signer.public_key(),
        Signature::from_bytes(wrong_signer.sign(&message)), // Invalid!
        Signature::from_bytes(new_signer.sign(&message)),
        "Test rotation".to_string(),
    );

    let result = manager.rotate_key(request);

    // Then: Should return InvalidOldKeySignature error
    assert!(
        result.is_err(),
        "Rotation should fail with invalid old key signature"
    );
    match result.unwrap_err() {
        KeyError::InvalidOldKeySignature => {} // Expected
        other => panic!("Expected InvalidOldKeySignature, got: {:?}", other),
    }
}

/// Test 8: Invalid new key signature returns KeyError::InvalidNewKeySignature
#[test]
fn test_invalid_new_key_signature_returns_error() {
    // Given: An agent with an active key
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let old_key = AgentKey::new(agent_id, old_signer.public_key());
    repo.store_key(old_key);

    let manager = TestableKeyManager::new(repo);

    // When: We rotate with an invalid new key signature
    let new_signer = AgentSigner::generate();
    let wrong_signer = AgentSigner::generate(); // Wrong signer for new key

    // Create message and sign with wrong signer for new key
    let unsigned_request = KeyRotationRequest::new(
        agent_id,
        new_signer.public_key(),
        Signature::from_bytes([0u8; 64]),
        Signature::from_bytes([0u8; 64]),
        "Test rotation".to_string(),
    );
    let message = unsigned_request.message_to_sign();

    let request = KeyRotationRequest::new(
        agent_id,
        new_signer.public_key(),
        Signature::from_bytes(old_signer.sign(&message)),
        Signature::from_bytes(wrong_signer.sign(&message)), // Invalid!
        "Test rotation".to_string(),
    );

    let result = manager.rotate_key(request);

    // Then: Should return InvalidNewKeySignature error
    assert!(
        result.is_err(),
        "Rotation should fail with invalid new key signature"
    );
    match result.unwrap_err() {
        KeyError::InvalidNewKeySignature => {} // Expected
        other => panic!("Expected InvalidNewKeySignature, got: {:?}", other),
    }
}

/// Test 9: Rotation on non-active key returns KeyError::InvalidKeyStatus
#[test]
fn test_rotation_on_non_active_key_returns_error() {
    // Given: An agent with only a rotated key (no active key)
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let mut old_key = AgentKey::new(agent_id, old_signer.public_key());
    old_key.mark_rotated(); // Make it non-active
    repo.store_key(old_key);

    let manager = TestableKeyManager::new(repo);

    // When: We try to rotate (will fail to find active key)
    let new_signer = AgentSigner::generate();
    let request =
        create_signed_rotation_request(agent_id, &old_signer, &new_signer, "Test rotation");

    let result = manager.rotate_key(request);

    // Then: Should return KeyNotFound (no active key)
    assert!(
        result.is_err(),
        "Rotation should fail when no active key exists"
    );
    match result.unwrap_err() {
        KeyError::KeyNotFound { .. } => {} // Expected - no active key
        other => panic!("Expected KeyNotFound error, got: {:?}", other),
    }
}

/// Test 10: Rotated key still allows verification (but not signing)
#[test]
fn test_rotated_key_allows_verification_but_not_signing() {
    // Given: A key that has been rotated
    let agent_id = AgentId::new();
    let signer = AgentSigner::generate();
    let mut key = AgentKey::new(agent_id, signer.public_key());
    key.mark_rotated();

    // When: We check signing and verification capabilities
    let can_sign = key.can_sign();
    let can_verify = key.can_verify();

    // Then: Should not allow signing but should allow verification
    assert!(can_sign.is_err(), "Rotated key should not allow signing");
    assert!(can_verify.is_ok(), "Rotated key should allow verification");
    assert_eq!(key.status, KeyStatus::Rotated);

    // Verify we get the right error type for signing
    match can_sign.unwrap_err() {
        KeyError::InvalidKeyStatus {
            status, operation, ..
        } => {
            assert_eq!(status, KeyStatus::Rotated);
            assert!(operation.contains("signing"));
        }
        other => panic!("Expected InvalidKeyStatus error, got: {:?}", other),
    }
}

// =============================================================================
// KEY REVOCATION TESTS
// =============================================================================

/// Test 11: Revocation stores reason and revoked_by
#[test]
fn test_revocation_stores_reason_and_revoked_by() {
    // Given: An agent with an active key
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let signer = AgentSigner::generate();
    let key = AgentKey::new(agent_id, signer.public_key());
    let key_id = key.id;
    repo.store_key(key);

    let manager = TestableKeyManager::new(repo.clone());

    // When: We revoke the key with a reason
    let reason = "Key compromised - emergency revocation".to_string();
    let request = KeyRevocationRequest::new(agent_id, key_id, reason.clone(), admin_id);
    let result = manager.revoke_key(request);

    // Then: Revocation should succeed and store metadata
    assert!(result.is_ok(), "Revocation should succeed");

    let revoked_key = repo.get_key(key_id).unwrap();
    assert_eq!(revoked_key.status, KeyStatus::Revoked);
    assert_eq!(revoked_key.revocation_reason, Some(reason));
    assert_eq!(revoked_key.revoked_by, Some(admin_id));
}

/// Test 12: Revoked key returns KeyError::InvalidKeyStatus for signing
#[test]
fn test_revoked_key_rejects_signing() {
    // Given: A revoked key
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let signer = AgentSigner::generate();
    let mut key = AgentKey::new(agent_id, signer.public_key());
    key.revoke("Test revocation".to_string(), admin_id);

    // When: We check if signing is allowed
    let result = key.can_sign();

    // Then: Should return InvalidKeyStatus error
    assert!(result.is_err(), "Revoked key should not allow signing");
    match result.unwrap_err() {
        KeyError::InvalidKeyStatus {
            status, operation, ..
        } => {
            assert_eq!(status, KeyStatus::Revoked);
            assert!(operation.contains("signing"));
        }
        other => panic!("Expected InvalidKeyStatus error, got: {:?}", other),
    }
}

/// Test 13: Revoked key returns KeyError::InvalidKeyStatus for verification
#[test]
fn test_revoked_key_rejects_verification() {
    // Given: A revoked key
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let signer = AgentSigner::generate();
    let mut key = AgentKey::new(agent_id, signer.public_key());
    key.revoke("Test revocation".to_string(), admin_id);

    // When: We check if verification is allowed
    let result = key.can_verify();

    // Then: Should return InvalidKeyStatus error
    assert!(result.is_err(), "Revoked key should not allow verification");
    match result.unwrap_err() {
        KeyError::InvalidKeyStatus {
            status, operation, ..
        } => {
            assert_eq!(status, KeyStatus::Revoked);
            assert!(operation.contains("verification"));
        }
        other => panic!("Expected InvalidKeyStatus error, got: {:?}", other),
    }
}

/// Test 14: Cannot revoke already-revoked key
#[test]
fn test_cannot_revoke_already_revoked_key() {
    // Given: A key that is already revoked
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let signer = AgentSigner::generate();
    let mut key = AgentKey::new(agent_id, signer.public_key());
    let key_id = key.id;
    key.revoke("First revocation".to_string(), admin_id);
    repo.store_key(key);

    let manager = TestableKeyManager::new(repo);

    // When: We try to revoke it again
    let second_admin = AgentId::new();
    let request = KeyRevocationRequest::new(
        agent_id,
        key_id,
        "Second revocation".to_string(),
        second_admin,
    );
    let result = manager.revoke_key(request);

    // Then: Should return InvalidKeyStatus error
    assert!(result.is_err(), "Cannot revoke already-revoked key");
    match result.unwrap_err() {
        KeyError::InvalidKeyStatus {
            status, operation, ..
        } => {
            assert_eq!(status, KeyStatus::Revoked);
            assert!(operation.contains("revocation"));
        }
        other => panic!("Expected InvalidKeyStatus error, got: {:?}", other),
    }
}

// =============================================================================
// EXPIRATION TESTS
// =============================================================================

/// Test 15: Expired key (valid_until in past) cannot sign
#[test]
fn test_expired_key_cannot_sign() {
    // Given: A key that has expired
    let agent_id = AgentId::new();
    let signer = AgentSigner::generate();
    let past_time = Utc::now() - Duration::hours(2);
    let past_expiry = Some(Utc::now() - Duration::hours(1));

    let mut key = AgentKey::new_pending(agent_id, signer.public_key(), past_time, past_expiry);
    key.status = KeyStatus::Active; // Manually activate for testing

    // When: We check if signing is allowed
    let result = key.can_sign();

    // Then: Should return KeyExpired error
    assert!(result.is_err(), "Expired key should not allow signing");
    match result.unwrap_err() {
        KeyError::KeyExpired {
            key_id,
            valid_until,
        } => {
            assert_eq!(key_id, key.id);
            assert!(valid_until < Utc::now());
        }
        other => panic!("Expected KeyExpired error, got: {:?}", other),
    }
}

/// Test 16: check_expiration() updates status to Expired
#[test]
fn test_check_expiration_updates_status_to_expired() {
    // Given: An active key with a past expiration time
    let agent_id = AgentId::new();
    let signer = AgentSigner::generate();
    let past_time = Utc::now() - Duration::hours(2);
    let past_expiry = Some(Utc::now() - Duration::hours(1));

    let mut key = AgentKey::new_pending(agent_id, signer.public_key(), past_time, past_expiry);
    key.status = KeyStatus::Active; // Manually activate
    assert_eq!(key.status, KeyStatus::Active);

    // When: We call check_expiration
    key.check_expiration();

    // Then: Status should be updated to Expired
    assert_eq!(
        key.status,
        KeyStatus::Expired,
        "check_expiration should set status to Expired"
    );
}

/// Test 16b: check_expiration() does not change non-Active keys
#[test]
fn test_check_expiration_does_not_change_non_active_keys() {
    // Given: A rotated key with a past expiration time
    let agent_id = AgentId::new();
    let signer = AgentSigner::generate();
    let past_time = Utc::now() - Duration::hours(2);
    let past_expiry = Some(Utc::now() - Duration::hours(1));

    let mut key = AgentKey::new_pending(agent_id, signer.public_key(), past_time, past_expiry);
    key.status = KeyStatus::Rotated; // Not active

    // When: We call check_expiration
    key.check_expiration();

    // Then: Status should remain Rotated (only Active keys become Expired)
    assert_eq!(
        key.status,
        KeyStatus::Rotated,
        "check_expiration should not change non-Active keys"
    );
}

/// Test 16c: Key without expiration does not expire
#[test]
fn test_key_without_expiration_does_not_expire() {
    // Given: An active key with no expiration time
    let agent_id = AgentId::new();
    let signer = AgentSigner::generate();
    let key = AgentKey::new(agent_id, signer.public_key());
    assert!(key.valid_until.is_none());

    // When: We check if it's expired
    let is_expired = key.is_expired();

    // Then: Should not be expired
    assert!(!is_expired, "Key without expiration should not expire");
}

// =============================================================================
// EDGE CASES AND INTEGRATION TESTS
// =============================================================================

/// Test: Revoke key that doesn't exist returns KeyNotFound
#[test]
fn test_revoke_nonexistent_key_returns_error() {
    // Given: An empty repository
    let repo = MockKeyRepository::new();
    let manager = TestableKeyManager::new(repo);
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let nonexistent_key_id = Uuid::new_v4();

    // When: We try to revoke a nonexistent key
    let request =
        KeyRevocationRequest::new(agent_id, nonexistent_key_id, "Test".to_string(), admin_id);
    let result = manager.revoke_key(request);

    // Then: Should return KeyNotFound error
    assert!(result.is_err(), "Cannot revoke nonexistent key");
    match result.unwrap_err() {
        KeyError::KeyNotFound { key_id, .. } => {
            assert_eq!(key_id, nonexistent_key_id);
        }
        other => panic!("Expected KeyNotFound error, got: {:?}", other),
    }
}

/// Test: Revoke key belonging to different agent returns KeyNotFound
#[test]
fn test_revoke_key_wrong_agent_returns_error() {
    // Given: A key belonging to agent1
    let repo = MockKeyRepository::new();
    let agent1 = AgentId::new();
    let agent2 = AgentId::new();
    let admin_id = AgentId::new();
    let signer = AgentSigner::generate();
    let key = AgentKey::new(agent1, signer.public_key());
    let key_id = key.id;
    repo.store_key(key);

    let manager = TestableKeyManager::new(repo);

    // When: agent2 tries to revoke agent1's key
    let request = KeyRevocationRequest::new(agent2, key_id, "Test".to_string(), admin_id);
    let result = manager.revoke_key(request);

    // Then: Should return KeyNotFound (agent mismatch)
    assert!(result.is_err(), "Cannot revoke another agent's key");
    match result.unwrap_err() {
        KeyError::KeyNotFound { agent_id, .. } => {
            assert_eq!(agent_id, agent2);
        }
        other => panic!("Expected KeyNotFound error, got: {:?}", other),
    }
}

/// Test: Full key lifecycle (create -> rotate -> revoke)
#[test]
fn test_full_key_lifecycle() {
    // Given: A fresh agent
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();

    // Step 1: Create initial key
    let initial_signer = AgentSigner::generate();
    let initial_key = AgentKey::new(agent_id, initial_signer.public_key());
    let initial_key_id = initial_key.id;
    repo.store_key(initial_key);

    let manager = TestableKeyManager::new(repo.clone());

    // Verify initial key is active
    let active = manager.get_active_key(agent_id).unwrap();
    assert_eq!(active.id, initial_key_id);
    assert_eq!(active.status, KeyStatus::Active);

    // Step 2: Rotate the key
    let second_signer = AgentSigner::generate();
    let rotation_request = create_signed_rotation_request(
        agent_id,
        &initial_signer,
        &second_signer,
        "Scheduled rotation",
    );
    let new_key = manager.rotate_key(rotation_request).unwrap();
    let second_key_id = new_key.id;

    // Verify rotation effects
    let old_key = repo.get_key(initial_key_id).unwrap();
    assert_eq!(old_key.status, KeyStatus::Rotated);
    assert!(old_key.can_verify().is_ok(), "Old key can still verify");
    assert!(old_key.can_sign().is_err(), "Old key cannot sign");

    let active = manager.get_active_key(agent_id).unwrap();
    assert_eq!(active.id, second_key_id);
    assert_eq!(active.status, KeyStatus::Active);

    // Step 3: Revoke the old (rotated) key
    let revoke_request = KeyRevocationRequest::new(
        agent_id,
        initial_key_id,
        "Decommissioning old key".to_string(),
        admin_id,
    );
    manager.revoke_key(revoke_request).unwrap();

    // Verify revocation
    let revoked_key = repo.get_key(initial_key_id).unwrap();
    assert_eq!(revoked_key.status, KeyStatus::Revoked);
    assert!(
        revoked_key.can_verify().is_err(),
        "Revoked key cannot verify"
    );
    assert_eq!(
        revoked_key.revocation_reason.as_deref(),
        Some("Decommissioning old key")
    );
    assert_eq!(revoked_key.revoked_by, Some(admin_id));

    // New key should still be active
    let still_active = manager.get_active_key(agent_id).unwrap();
    assert_eq!(still_active.id, second_key_id);
    assert_eq!(still_active.status, KeyStatus::Active);
}

/// Test: Multiple agents with independent keys
#[test]
fn test_multiple_agents_independent_keys() {
    // Given: Two agents with their own keys
    let repo = MockKeyRepository::new();
    let agent1 = AgentId::new();
    let agent2 = AgentId::new();

    let signer1 = AgentSigner::generate();
    let signer2 = AgentSigner::generate();

    let key1 = AgentKey::new(agent1, signer1.public_key());
    let key2 = AgentKey::new(agent2, signer2.public_key());

    repo.store_key(key1.clone());
    repo.store_key(key2.clone());

    let manager = TestableKeyManager::new(repo);

    // When: We look up each agent's key
    let found1 = manager.get_active_key(agent1).unwrap();
    let found2 = manager.get_active_key(agent2).unwrap();

    // Then: Each agent gets their own key
    assert_eq!(found1.id, key1.id);
    assert_eq!(found1.agent_id, agent1);
    assert_eq!(found1.public_key, signer1.public_key());

    assert_eq!(found2.id, key2.id);
    assert_eq!(found2.agent_id, agent2);
    assert_eq!(found2.public_key, signer2.public_key());
}

// =============================================================================
// SECURITY PROPERTY TESTS
// =============================================================================

/// Security Test: Rotation signatures must be over the correct message
#[test]
fn test_rotation_signature_message_format() {
    // Given: A rotation request
    let agent_id = AgentId::new();
    let new_public_key = [42u8; 32];

    let request = KeyRotationRequest::new(
        agent_id,
        new_public_key,
        Signature::from_bytes([0u8; 64]),
        Signature::from_bytes([0u8; 64]),
        "Test".to_string(),
    );

    // When: We get the message to sign
    let message = request.message_to_sign();

    // Then: Message should contain expected components
    assert!(!message.is_empty(), "Message should not be empty");

    // Should contain "rotate:" prefix
    assert!(
        message.starts_with(b"rotate:"),
        "Message should start with 'rotate:'"
    );

    // Should contain agent ID bytes
    let agent_uuid = agent_id.as_uuid();
    let agent_uuid_bytes = agent_uuid.as_bytes();
    assert!(
        message
            .windows(agent_uuid_bytes.len())
            .any(|w| w == agent_uuid_bytes),
        "Message should contain agent ID"
    );

    // Should contain new public key bytes
    assert!(
        message.windows(32).any(|w| w == new_public_key),
        "Message should contain new public key"
    );
}

/// Security Test: Key rotation prevents key substitution attack
#[test]
fn test_rotation_prevents_key_substitution() {
    // Given: An agent with an active key
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let old_key = AgentKey::new(agent_id, old_signer.public_key());
    repo.store_key(old_key);

    let manager = TestableKeyManager::new(repo);

    // When: An attacker tries to substitute a different new public key
    let legitimate_new_signer = AgentSigner::generate();
    let attacker_signer = AgentSigner::generate();

    // Attacker signs with their key but claims a different public key
    let unsigned_request = KeyRotationRequest::new(
        agent_id,
        attacker_signer.public_key(), // Attacker's key
        Signature::from_bytes([0u8; 64]),
        Signature::from_bytes([0u8; 64]),
        "Test".to_string(),
    );
    let message = unsigned_request.message_to_sign();

    let request = KeyRotationRequest::new(
        agent_id,
        attacker_signer.public_key(),
        Signature::from_bytes(old_signer.sign(&message)),
        // Signed with legitimate new key, but public key field shows attacker's key
        Signature::from_bytes(legitimate_new_signer.sign(&message)),
        "Test".to_string(),
    );

    let result = manager.rotate_key(request);

    // Then: Attack should fail - signature doesn't match the claimed public key
    assert!(
        result.is_err(),
        "Key substitution attack should be prevented"
    );
    match result.unwrap_err() {
        KeyError::InvalidNewKeySignature => {} // Expected
        other => panic!("Expected InvalidNewKeySignature, got: {:?}", other),
    }
}

/// Security Test: Revoked old key cannot be used to rotate
#[test]
fn test_revoked_old_key_cannot_rotate() {
    // Given: An agent whose key has been revoked
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let mut old_key = AgentKey::new(agent_id, old_signer.public_key());
    old_key.revoke("Compromised key".to_string(), admin_id);
    repo.store_key(old_key);

    let manager = TestableKeyManager::new(repo);

    // When: Someone tries to rotate using the revoked key
    let new_signer = AgentSigner::generate();
    let request =
        create_signed_rotation_request(agent_id, &old_signer, &new_signer, "Attempted rotation");

    let result = manager.rotate_key(request);

    // Then: Rotation should fail because there's no active key
    assert!(
        result.is_err(),
        "Rotation should fail when old key is revoked"
    );
    match result.unwrap_err() {
        KeyError::KeyNotFound { .. } => {} // Expected - no active key
        other => panic!("Expected KeyNotFound error, got: {:?}", other),
    }
}

// =============================================================================
// PRODUCTION KEY MANAGER TESTS (using KeyRepository trait)
// =============================================================================

use epigraph_api::security::keys::{KeyManager, KeyRepository};

/// Implement KeyRepository trait for MockKeyRepository to test production KeyManager
impl KeyRepository for MockKeyRepository {
    fn store_key(&self, key: AgentKey) {
        // Delegate to the existing method
        MockKeyRepository::store_key(self, key)
    }

    fn get_key(&self, key_id: Uuid) -> Option<AgentKey> {
        MockKeyRepository::get_key(self, key_id)
    }

    fn get_active_key(&self, agent_id: AgentId) -> Option<AgentKey> {
        MockKeyRepository::get_active_key(self, agent_id)
    }

    fn update_key(&self, key: AgentKey) {
        MockKeyRepository::update_key(self, key)
    }
}

/// Test: Production KeyManager with valid dual signatures succeeds
#[test]
fn test_production_key_manager_rotation_with_valid_signatures() {
    // Given: An agent with an active key
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let old_key = AgentKey::new(agent_id, old_signer.public_key());
    repo.store_key(old_key.clone());

    let manager = KeyManager::new(repo.clone());

    // When: We rotate with valid signatures from both old and new keys
    let new_signer = AgentSigner::generate();
    let request =
        create_signed_rotation_request(agent_id, &old_signer, &new_signer, "Scheduled rotation");

    let result = manager.rotate_key(request);

    // Then: Rotation should succeed
    assert!(
        result.is_ok(),
        "Production KeyManager rotation should succeed with valid signatures: {:?}",
        result.err()
    );
    let new_key = result.unwrap();
    assert_eq!(new_key.agent_id, agent_id);
    assert_eq!(new_key.status, KeyStatus::Active);
    assert_eq!(new_key.public_key, new_signer.public_key());
}

/// Test: Production KeyManager rejects invalid old key signature
#[test]
fn test_production_key_manager_rejects_invalid_old_signature() {
    // Given: An agent with an active key
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let old_key = AgentKey::new(agent_id, old_signer.public_key());
    repo.store_key(old_key);

    let manager = KeyManager::new(repo);

    // When: We rotate with an invalid old key signature
    let new_signer = AgentSigner::generate();
    let wrong_signer = AgentSigner::generate();

    let unsigned_request = KeyRotationRequest::new(
        agent_id,
        new_signer.public_key(),
        Signature::from_bytes([0u8; 64]),
        Signature::from_bytes([0u8; 64]),
        "Test rotation".to_string(),
    );
    let message = unsigned_request.message_to_sign();

    let request = KeyRotationRequest::new(
        agent_id,
        new_signer.public_key(),
        Signature::from_bytes(wrong_signer.sign(&message)), // Invalid!
        Signature::from_bytes(new_signer.sign(&message)),
        "Test rotation".to_string(),
    );

    let result = manager.rotate_key(request);

    // Then: Should return InvalidOldKeySignature error
    assert!(
        result.is_err(),
        "Production KeyManager should reject invalid old key signature"
    );
    match result.unwrap_err() {
        KeyError::InvalidOldKeySignature => {} // Expected
        other => panic!("Expected InvalidOldKeySignature, got: {:?}", other),
    }
}

/// Test: Production KeyManager rejects invalid new key signature
#[test]
fn test_production_key_manager_rejects_invalid_new_signature() {
    // Given: An agent with an active key
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let old_key = AgentKey::new(agent_id, old_signer.public_key());
    repo.store_key(old_key);

    let manager = KeyManager::new(repo);

    // When: We rotate with an invalid new key signature
    let new_signer = AgentSigner::generate();
    let wrong_signer = AgentSigner::generate();

    let unsigned_request = KeyRotationRequest::new(
        agent_id,
        new_signer.public_key(),
        Signature::from_bytes([0u8; 64]),
        Signature::from_bytes([0u8; 64]),
        "Test rotation".to_string(),
    );
    let message = unsigned_request.message_to_sign();

    let request = KeyRotationRequest::new(
        agent_id,
        new_signer.public_key(),
        Signature::from_bytes(old_signer.sign(&message)),
        Signature::from_bytes(wrong_signer.sign(&message)), // Invalid!
        "Test rotation".to_string(),
    );

    let result = manager.rotate_key(request);

    // Then: Should return InvalidNewKeySignature error
    assert!(
        result.is_err(),
        "Production KeyManager should reject invalid new key signature"
    );
    match result.unwrap_err() {
        KeyError::InvalidNewKeySignature => {} // Expected
        other => panic!("Expected InvalidNewKeySignature, got: {:?}", other),
    }
}

/// Test: Production KeyManager revoked key cannot rotate
#[test]
fn test_production_key_manager_revoked_key_cannot_rotate() {
    // Given: An agent whose key has been revoked
    let repo = MockKeyRepository::new();
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let mut old_key = AgentKey::new(agent_id, old_signer.public_key());
    old_key.revoke("Key compromised".to_string(), admin_id);
    repo.store_key(old_key);

    let manager = KeyManager::new(repo);

    // When: Someone tries to rotate using the revoked key
    let new_signer = AgentSigner::generate();
    let request =
        create_signed_rotation_request(agent_id, &old_signer, &new_signer, "Attempted rotation");

    let result = manager.rotate_key(request);

    // Then: Rotation should fail because there's no active key
    assert!(
        result.is_err(),
        "Production KeyManager should reject rotation when old key is revoked"
    );
    match result.unwrap_err() {
        KeyError::KeyNotFound { .. } => {} // Expected - no active key
        other => panic!("Expected KeyNotFound error, got: {:?}", other),
    }
}

// =============================================================================
// KEY ROTATION REQUEST VERIFY METHOD TESTS
// =============================================================================

/// Test: KeyRotationRequest::verify() with valid signatures returns Ok
#[test]
fn test_rotation_request_verify_with_valid_signatures() {
    // Given: An active key and a valid rotation request
    let agent_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let current_key = AgentKey::new(agent_id, old_signer.public_key());

    let new_signer = AgentSigner::generate();
    let request =
        create_signed_rotation_request(agent_id, &old_signer, &new_signer, "Scheduled rotation");

    // When: We verify the request
    let result = request.verify(&current_key);

    // Then: Verification should succeed
    assert!(
        result.is_ok(),
        "KeyRotationRequest::verify should succeed with valid signatures: {:?}",
        result.err()
    );
}

/// Test: KeyRotationRequest::verify() with invalid old signature returns error
#[test]
fn test_rotation_request_verify_rejects_invalid_old_signature() {
    // Given: An active key and a request with invalid old signature
    let agent_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let current_key = AgentKey::new(agent_id, old_signer.public_key());

    let new_signer = AgentSigner::generate();
    let wrong_signer = AgentSigner::generate();

    let unsigned_request = KeyRotationRequest::new(
        agent_id,
        new_signer.public_key(),
        Signature::from_bytes([0u8; 64]),
        Signature::from_bytes([0u8; 64]),
        "Test".to_string(),
    );
    let message = unsigned_request.message_to_sign();

    let request = KeyRotationRequest::new(
        agent_id,
        new_signer.public_key(),
        Signature::from_bytes(wrong_signer.sign(&message)), // Wrong signer!
        Signature::from_bytes(new_signer.sign(&message)),
        "Test".to_string(),
    );

    // When: We verify the request
    let result = request.verify(&current_key);

    // Then: Should return InvalidOldKeySignature
    assert!(result.is_err());
    match result.unwrap_err() {
        KeyError::InvalidOldKeySignature => {} // Expected
        other => panic!("Expected InvalidOldKeySignature, got: {:?}", other),
    }
}

/// Test: KeyRotationRequest::verify() with invalid new signature returns error
#[test]
fn test_rotation_request_verify_rejects_invalid_new_signature() {
    // Given: An active key and a request with invalid new signature
    let agent_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let current_key = AgentKey::new(agent_id, old_signer.public_key());

    let new_signer = AgentSigner::generate();
    let wrong_signer = AgentSigner::generate();

    let unsigned_request = KeyRotationRequest::new(
        agent_id,
        new_signer.public_key(),
        Signature::from_bytes([0u8; 64]),
        Signature::from_bytes([0u8; 64]),
        "Test".to_string(),
    );
    let message = unsigned_request.message_to_sign();

    let request = KeyRotationRequest::new(
        agent_id,
        new_signer.public_key(),
        Signature::from_bytes(old_signer.sign(&message)),
        Signature::from_bytes(wrong_signer.sign(&message)), // Wrong signer!
        "Test".to_string(),
    );

    // When: We verify the request
    let result = request.verify(&current_key);

    // Then: Should return InvalidNewKeySignature
    assert!(result.is_err());
    match result.unwrap_err() {
        KeyError::InvalidNewKeySignature => {} // Expected
        other => panic!("Expected InvalidNewKeySignature, got: {:?}", other),
    }
}

/// Test: KeyRotationRequest::verify() rejects non-active current key
#[test]
fn test_rotation_request_verify_rejects_non_active_key() {
    // Given: A rotated key and a rotation request
    let agent_id = AgentId::new();
    let old_signer = AgentSigner::generate();
    let mut current_key = AgentKey::new(agent_id, old_signer.public_key());
    current_key.mark_rotated(); // Make it non-active

    let new_signer = AgentSigner::generate();
    let request =
        create_signed_rotation_request(agent_id, &old_signer, &new_signer, "Test rotation");

    // When: We verify the request
    let result = request.verify(&current_key);

    // Then: Should return InvalidKeyStatus
    assert!(result.is_err());
    match result.unwrap_err() {
        KeyError::InvalidKeyStatus {
            status, operation, ..
        } => {
            assert_eq!(status, KeyStatus::Rotated);
            assert!(operation.contains("rotation"));
        }
        other => panic!("Expected InvalidKeyStatus error, got: {:?}", other),
    }
}

/// Test: KeyRotationRequest::verify() rejects wrong agent's key
#[test]
fn test_rotation_request_verify_rejects_wrong_agent_key() {
    // Given: A key belonging to a different agent
    let agent1 = AgentId::new();
    let agent2 = AgentId::new();
    let signer1 = AgentSigner::generate();
    let signer2 = AgentSigner::generate();

    let current_key = AgentKey::new(agent1, signer1.public_key()); // Belongs to agent1

    // Create request for agent2
    let new_signer = AgentSigner::generate();
    let request = create_signed_rotation_request(agent2, &signer2, &new_signer, "Test rotation");

    // When: We verify the request against agent1's key
    let result = request.verify(&current_key);

    // Then: Should return RotationFailed (agent mismatch)
    assert!(result.is_err());
    match result.unwrap_err() {
        KeyError::RotationFailed { reason } => {
            assert!(reason.contains("does not belong"));
        }
        other => panic!("Expected RotationFailed error, got: {:?}", other),
    }
}
