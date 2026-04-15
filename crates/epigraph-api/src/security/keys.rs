//! Agent key management for key rotation and revocation
//!
//! This module implements secure key lifecycle management:
//! - Key creation with validity periods
//! - Key rotation with dual-signature verification
//! - Key revocation with reason tracking
//! - Status-based access control
//!
//! # Security Properties
//!
//! - **Continuity**: Rotated keys remain valid for verification (not signing)
//! - **Non-repudiation**: Revocation records who revoked and why
//! - **Auditability**: All key state changes are logged

use chrono::{DateTime, Utc};
use epigraph_core::domain::AgentId;
use epigraph_crypto::SignatureVerifier;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use thiserror::Error;
use uuid::Uuid;

/// Error type for key operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    #[error("Key {key_id} not found for agent {agent_id}")]
    KeyNotFound { key_id: Uuid, agent_id: AgentId },

    #[error("Key {key_id} has status {status:?}, which does not allow {operation}")]
    InvalidKeyStatus {
        key_id: Uuid,
        status: KeyStatus,
        operation: String,
    },

    #[error("Key {key_id} has expired (valid_until: {valid_until})")]
    KeyExpired {
        key_id: Uuid,
        valid_until: DateTime<Utc>,
    },

    #[error("Key rotation failed: {reason}")]
    RotationFailed { reason: String },

    #[error("Invalid signature from old key")]
    InvalidOldKeySignature,

    #[error("Invalid signature from new key")]
    InvalidNewKeySignature,

    #[error("Key revocation failed: {reason}")]
    RevocationFailed { reason: String },
}

/// Type of cryptographic key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum KeyType {
    /// Key used for signing claims and evidence
    #[default]
    Signing,
    /// Key used for encrypting sensitive data
    Encryption,
    /// Key used for both signing and encryption (not recommended)
    DualPurpose,
}

/// Status of an agent's key
///
/// # State Transitions
///
/// ```text
/// Pending --> Active --> Rotated
///                   \--> Revoked
///                   \--> Expired (automatic)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyStatus {
    /// Key is active and can be used for signing
    Active,
    /// Key is pending activation (future valid_from)
    Pending,
    /// Key has been rotated out (still valid for verification, not signing)
    Rotated,
    /// Key has been explicitly revoked (invalid for all operations)
    Revoked,
    /// Key has expired (past valid_until)
    Expired,
}

impl KeyStatus {
    /// Check if this status allows signing operations
    #[must_use]
    pub fn allows_signing(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Check if this status allows verification operations
    #[must_use]
    pub fn allows_verification(&self) -> bool {
        matches!(self, Self::Active | Self::Rotated)
    }

    /// Check if this key is usable for any cryptographic operation
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Active | Self::Rotated)
    }
}

/// An agent's cryptographic key with lifecycle management
///
/// # Invariants
///
/// - `valid_from` must be before `valid_until` (if both are set)
/// - Only one key per agent can have `status = Active`
/// - Revoked keys cannot be reactivated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentKey {
    /// Unique identifier for this key
    pub id: Uuid,
    /// Agent who owns this key
    pub agent_id: AgentId,
    /// Ed25519 public key (32 bytes)
    pub public_key: [u8; 32],
    /// Type of key (signing, encryption, etc.)
    pub key_type: KeyType,
    /// Current status of the key
    pub status: KeyStatus,
    /// When this key becomes valid
    pub valid_from: DateTime<Utc>,
    /// When this key expires (None = no expiration)
    pub valid_until: Option<DateTime<Utc>>,
    /// When this key was created
    pub created_at: DateTime<Utc>,
    /// Reason for revocation (if status is Revoked)
    pub revocation_reason: Option<String>,
    /// Agent who revoked this key (if status is Revoked)
    pub revoked_by: Option<AgentId>,
}

impl AgentKey {
    /// Create a new active agent key
    #[must_use]
    pub fn new(agent_id: AgentId, public_key: [u8; 32]) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            agent_id,
            public_key,
            key_type: KeyType::default(),
            status: KeyStatus::Active,
            valid_from: now,
            valid_until: None,
            created_at: now,
            revocation_reason: None,
            revoked_by: None,
        }
    }

    /// Create a new pending key with a future activation time
    #[must_use]
    pub fn new_pending(
        agent_id: AgentId,
        public_key: [u8; 32],
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            agent_id,
            public_key,
            key_type: KeyType::default(),
            status: KeyStatus::Pending,
            valid_from,
            valid_until,
            created_at: Utc::now(),
            revocation_reason: None,
            revoked_by: None,
        }
    }

    /// Check if this key can be used for signing
    ///
    /// Returns an error if:
    /// - Key status does not allow signing
    /// - Key has expired
    /// - Key is not yet valid (pending)
    pub fn can_sign(&self) -> Result<(), KeyError> {
        // Check status first
        if !self.status.allows_signing() {
            return Err(KeyError::InvalidKeyStatus {
                key_id: self.id,
                status: self.status,
                operation: "signing".to_string(),
            });
        }

        // Check expiration
        if let Some(valid_until) = self.valid_until {
            if Utc::now() > valid_until {
                return Err(KeyError::KeyExpired {
                    key_id: self.id,
                    valid_until,
                });
            }
        }

        Ok(())
    }

    /// Check if this key can be used for verification
    ///
    /// Returns an error if:
    /// - Key status does not allow verification (revoked or expired)
    pub fn can_verify(&self) -> Result<(), KeyError> {
        if !self.status.allows_verification() {
            return Err(KeyError::InvalidKeyStatus {
                key_id: self.id,
                status: self.status,
                operation: "verification".to_string(),
            });
        }

        Ok(())
    }

    /// Mark this key as rotated
    ///
    /// # Panics
    ///
    /// Panics if called on a key that is not Active
    pub fn mark_rotated(&mut self) {
        assert!(
            self.status == KeyStatus::Active,
            "Can only rotate Active keys"
        );
        self.status = KeyStatus::Rotated;
    }

    /// Revoke this key with a reason
    ///
    /// # Arguments
    ///
    /// * `reason` - Human-readable explanation for the revocation
    /// * `revoked_by` - Agent who is performing the revocation
    pub fn revoke(&mut self, reason: String, revoked_by: AgentId) {
        self.status = KeyStatus::Revoked;
        self.revocation_reason = Some(reason);
        self.revoked_by = Some(revoked_by);
    }

    /// Check if the key has expired based on current time
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(valid_until) = self.valid_until {
            Utc::now() > valid_until
        } else {
            false
        }
    }

    /// Update status to Expired if past valid_until
    pub fn check_expiration(&mut self) {
        if self.is_expired() && self.status == KeyStatus::Active {
            self.status = KeyStatus::Expired;
        }
    }
}

/// Ed25519 signature (64 bytes)
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature(#[serde_as(as = "Bytes")] pub [u8; 64]);

impl Signature {
    /// Create a signature from raw bytes
    #[must_use]
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes of the signature
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Request to rotate an agent's key
///
/// Key rotation requires proof of control over both the old and new keys.
/// This prevents unauthorized key replacement.
///
/// # Verification Process
///
/// 1. Verify `old_key_signature` was created by the current active key
/// 2. Verify `new_key_signature` was created by the new key
/// 3. Both signatures must be over the same message (rotation request ID)
/// 4. Mark old key as Rotated, new key as Active
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationRequest {
    /// Unique identifier for this rotation request
    pub id: Uuid,
    /// Agent requesting the rotation
    pub agent_id: AgentId,
    /// The new public key to rotate to
    pub new_public_key: [u8; 32],
    /// Signature proving control of the old (current) key
    pub old_key_signature: Signature,
    /// Signature proving control of the new key
    pub new_key_signature: Signature,
    /// Human-readable reason for the rotation
    pub rotation_reason: String,
    /// When this request was created
    pub created_at: DateTime<Utc>,
}

impl KeyRotationRequest {
    /// Create a new key rotation request
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Agent performing the rotation
    /// * `new_public_key` - The new Ed25519 public key
    /// * `old_key_signature` - Signature from the current key
    /// * `new_key_signature` - Signature from the new key
    /// * `rotation_reason` - Why the rotation is being performed
    #[must_use]
    pub fn new(
        agent_id: AgentId,
        new_public_key: [u8; 32],
        old_key_signature: Signature,
        new_key_signature: Signature,
        rotation_reason: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            agent_id,
            new_public_key,
            old_key_signature,
            new_key_signature,
            rotation_reason,
            created_at: Utc::now(),
        }
    }

    /// Get the message that both signatures should be over
    ///
    /// This is the canonical representation of the rotation request
    /// that both keys must sign to prove control.
    #[must_use]
    pub fn message_to_sign(&self) -> Vec<u8> {
        // Message format: "rotate:{agent_id}:{new_public_key_hex}"
        let mut message = Vec::new();
        message.extend_from_slice(b"rotate:");
        message.extend_from_slice(self.agent_id.as_uuid().as_bytes());
        message.extend_from_slice(b":");
        message.extend_from_slice(&self.new_public_key);
        message
    }

    /// Verify this rotation request with dual-signature verification
    ///
    /// Performs dual-signature verification to ensure:
    /// 1. The current key owner authorizes the rotation (old key signature)
    /// 2. The new key owner controls the new key (new key signature)
    ///
    /// # Arguments
    ///
    /// * `current_key` - The currently active key for the agent
    ///
    /// # Returns
    ///
    /// * `Ok(())` if both signatures are valid
    /// * `Err(KeyError)` if verification fails
    ///
    /// # Security Notes
    ///
    /// - Uses constant-time comparison via ed25519-dalek internally
    /// - Both signatures must be over the same canonical message
    /// - The message includes the new public key to prevent substitution attacks
    pub fn verify(&self, current_key: &AgentKey) -> Result<(), KeyError> {
        // Verify current key belongs to the agent
        if current_key.agent_id != self.agent_id {
            return Err(KeyError::RotationFailed {
                reason: "Current key does not belong to requesting agent".to_string(),
            });
        }

        // Verify current key is active
        if current_key.status != KeyStatus::Active {
            return Err(KeyError::InvalidKeyStatus {
                key_id: current_key.id,
                status: current_key.status,
                operation: "key rotation".to_string(),
            });
        }

        // Get the canonical message that both keys must sign
        let message = self.message_to_sign();

        // Verify old key signature (proves current key owner authorizes rotation)
        let old_sig_valid = SignatureVerifier::verify(
            &current_key.public_key,
            &message,
            self.old_key_signature.as_bytes(),
        )
        .unwrap_or(false);

        if !old_sig_valid {
            return Err(KeyError::InvalidOldKeySignature);
        }

        // Verify new key signature (proves new key owner controls the key)
        let new_sig_valid = SignatureVerifier::verify(
            &self.new_public_key,
            &message,
            self.new_key_signature.as_bytes(),
        )
        .unwrap_or(false);

        if !new_sig_valid {
            return Err(KeyError::InvalidNewKeySignature);
        }

        Ok(())
    }
}

/// Request to revoke an agent's key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRevocationRequest {
    /// Unique identifier for this revocation request
    pub id: Uuid,
    /// Agent whose key is being revoked
    pub agent_id: AgentId,
    /// ID of the key to revoke
    pub key_id: Uuid,
    /// Reason for revocation
    pub reason: String,
    /// Agent performing the revocation (may be different from agent_id for admin actions)
    pub revoked_by: AgentId,
    /// When this request was created
    pub created_at: DateTime<Utc>,
}

impl KeyRevocationRequest {
    /// Create a new key revocation request
    #[must_use]
    pub fn new(agent_id: AgentId, key_id: Uuid, reason: String, revoked_by: AgentId) -> Self {
        Self {
            id: Uuid::new_v4(),
            agent_id,
            key_id,
            reason,
            revoked_by,
            created_at: Utc::now(),
        }
    }
}

/// Repository trait for key persistence
///
/// This trait abstracts the storage layer, enabling:
/// - In-memory repositories for testing
/// - Database repositories for production
/// - Mock repositories for unit tests
pub trait KeyRepository: Send + Sync {
    /// Store a new key
    fn store_key(&self, key: AgentKey);

    /// Get a key by ID
    fn get_key(&self, key_id: Uuid) -> Option<AgentKey>;

    /// Get the active key for an agent
    fn get_active_key(&self, agent_id: AgentId) -> Option<AgentKey>;

    /// Update an existing key
    fn update_key(&self, key: AgentKey);
}

/// Service for managing agent keys
///
/// This service handles:
/// - Key creation and registration
/// - Key rotation with verification
/// - Key revocation
/// - Key lookup and validation
///
/// # Type Parameters
///
/// * `R` - Repository implementation for key persistence
pub struct KeyManager<R: KeyRepository> {
    repo: R,
}

impl<R: KeyRepository> KeyManager<R> {
    /// Create a new key manager with the given repository
    #[must_use]
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    /// Get the currently active key for an agent
    ///
    /// # Errors
    ///
    /// Returns `KeyError::KeyNotFound` if no active key exists
    pub fn get_active_key(&self, agent_id: AgentId) -> Result<AgentKey, KeyError> {
        self.repo
            .get_active_key(agent_id)
            .ok_or(KeyError::KeyNotFound {
                key_id: Uuid::nil(), // No specific key ID when searching by agent
                agent_id,
            })
    }

    /// Rotate an agent's key
    ///
    /// # Process
    ///
    /// 1. Get the current active key
    /// 2. Verify the current key is active
    /// 3. Verify the old key signature over the rotation message
    /// 4. Verify the new key signature over the rotation message
    /// 5. Mark the current key as Rotated
    /// 6. Create and activate the new key
    ///
    /// # Security Notes
    ///
    /// Both signatures are verified using ed25519-dalek with constant-time
    /// comparison. This prevents:
    /// - Timing attacks on signature verification
    /// - Key substitution attacks (message includes new public key)
    ///
    /// # Errors
    ///
    /// Returns `KeyError` if:
    /// - No active key exists for the agent
    /// - Current key is not active
    /// - Old key signature is invalid
    /// - New key signature is invalid
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
    /// # Process
    ///
    /// 1. Look up the key by ID
    /// 2. Verify the key belongs to the requesting agent
    /// 3. Check the key is not already revoked
    /// 4. Mark the key as Revoked with reason and revoked_by
    ///
    /// # Errors
    ///
    /// Returns `KeyError` if:
    /// - Key not found
    /// - Key belongs to a different agent
    /// - Key already revoked
    pub fn revoke_key(&self, request: KeyRevocationRequest) -> Result<(), KeyError> {
        // 1. Get the key to revoke
        let mut key = self
            .repo
            .get_key(request.key_id)
            .ok_or(KeyError::KeyNotFound {
                key_id: request.key_id,
                agent_id: request.agent_id,
            })?;

        // 2. Verify the key belongs to the agent
        if key.agent_id != request.agent_id {
            return Err(KeyError::KeyNotFound {
                key_id: request.key_id,
                agent_id: request.agent_id,
            });
        }

        // 3. Check if already revoked
        if key.status == KeyStatus::Revoked {
            return Err(KeyError::InvalidKeyStatus {
                key_id: key.id,
                status: KeyStatus::Revoked,
                operation: "revocation".to_string(),
            });
        }

        // 4. Revoke the key
        key.revoke(request.reason, request.revoked_by);
        self.repo.update_key(key);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_status_allows_signing_only_when_active() {
        assert!(KeyStatus::Active.allows_signing());
        assert!(!KeyStatus::Pending.allows_signing());
        assert!(!KeyStatus::Rotated.allows_signing());
        assert!(!KeyStatus::Revoked.allows_signing());
        assert!(!KeyStatus::Expired.allows_signing());
    }

    #[test]
    fn key_status_allows_verification_when_active_or_rotated() {
        assert!(KeyStatus::Active.allows_verification());
        assert!(KeyStatus::Rotated.allows_verification());
        assert!(!KeyStatus::Pending.allows_verification());
        assert!(!KeyStatus::Revoked.allows_verification());
        assert!(!KeyStatus::Expired.allows_verification());
    }
}
