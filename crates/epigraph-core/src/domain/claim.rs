//! Claim domain model
//!
//! A Claim represents an epistemic assertion with a probabilistic truth value.
//!
//! # Key Principles
//!
//! - Every claim MUST have a reasoning trace (no naked assertions)
//! - Truth values are probabilistic [0.0, 1.0], not binary
//! - Claims can reference the agent who made them, but agent reputation
//!   NEVER influences the initial truth value (anti-authority bias)

use super::ids::{AgentId, ClaimId, TraceId};
use crate::traits::{ContentAddressable, Signable, Verifiable};
use crate::TruthValue;
use chrono::{DateTime, Utc};
use epigraph_crypto::SIGNATURE_SIZE;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};

/// A claim represents an epistemic assertion with a truth value
///
/// # Design Notes
///
/// - `content`: The actual claim text/statement
/// - `truth_value`: Probabilistic truth in [0.0, 1.0]
/// - `trace_id`: REQUIRED - the reasoning that led to this claim
/// - `agent_id`: Who made this claim (for tracking, not for truth calculation)
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    /// Unique identifier for this claim
    pub id: ClaimId,

    /// The statement content of this claim
    pub content: String,

    /// The truth value of this claim [0.0, 1.0]
    pub truth_value: TruthValue,

    /// The agent who made this claim
    pub agent_id: AgentId,

    /// Ed25519 public key of the signing agent (32 bytes)
    /// Required for signature verification without database lookup
    #[serde_as(as = "Bytes")]
    pub public_key: [u8; 32],

    /// BLAKE3 content hash (32 bytes) for content addressing
    #[serde_as(as = "Bytes")]
    pub content_hash: [u8; 32],

    /// The reasoning trace that supports this claim
    /// CRITICAL: This should ALWAYS be `Some()` - claims without reasoning are suspect
    pub trace_id: Option<TraceId>,

    /// Ed25519 signature from the agent (64 bytes)
    #[serde_as(as = "Option<Bytes>")]
    pub signature: Option<[u8; 64]>,

    /// When this claim was created
    pub created_at: DateTime<Utc>,

    /// When this claim was last updated (e.g., truth value changed)
    pub updated_at: DateTime<Utc>,

    /// The ID of the claim this supersedes, if any
    ///
    /// When a claim is updated with new information, a new claim is created
    /// that supersedes the old one. This field links to the previous version.
    pub supersedes: Option<ClaimId>,

    /// Whether this claim is the current (latest) version
    ///
    /// When a claim is superseded, this is set to `false` on the old claim.
    /// New claims default to `true`.
    pub is_current: bool,
}

/// Content that is signed for Claim
///
/// Excludes the signature field to avoid circular dependency.
/// Uses deterministic field ordering for canonical serialization.
#[derive(Debug, Clone, Serialize)]
pub struct ClaimSignableContent {
    pub id: ClaimId,
    pub content: String,
    pub truth_value: TruthValue,
    pub agent_id: AgentId,
    pub content_hash: [u8; 32],
    pub trace_id: Option<TraceId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Content that is hashed for Claim
///
/// Excludes the `content_hash` and signature fields to avoid circular dependency.
/// Uses deterministic field ordering for canonical serialization.
#[derive(Debug, Clone, Serialize)]
pub struct ClaimHashableContent {
    pub id: ClaimId,
    pub content: String,
    pub truth_value: TruthValue,
    pub agent_id: AgentId,
    pub trace_id: Option<TraceId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Claim {
    /// Create a new claim
    ///
    /// Claims start with `trace_id: None` due to the circular FK between
    /// `claims.trace_id → reasoning_traces` and `reasoning_traces.claim_id → claims`.
    /// Create the claim first, then the trace, then link via `set_trace_id`.
    ///
    /// # Arguments
    /// * `content` - The claim statement
    /// * `agent_id` - The agent making this claim
    /// * `public_key` - The Ed25519 public key of the signing agent
    /// * `initial_truth` - The initial truth value (typically calculated from evidence)
    #[must_use]
    pub fn new(
        content: String,
        agent_id: AgentId,
        public_key: [u8; 32],
        initial_truth: TruthValue,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: ClaimId::new(),
            content,
            truth_value: initial_truth,
            agent_id,
            public_key,
            content_hash: [0u8; 32],
            trace_id: None,
            signature: None,
            created_at: now,
            updated_at: now,
            supersedes: None,
            is_current: true,
        }
    }

    /// Create a new claim with a pre-existing reasoning trace
    ///
    /// Use this when the trace ID is already known (e.g., the API client
    /// provides a trace_id in the request body, or the harvester pre-creates
    /// the trace before the claim).
    ///
    /// # Arguments
    /// * `content` - The claim statement
    /// * `agent_id` - The agent making this claim
    /// * `public_key` - The Ed25519 public key of the signing agent
    /// * `trace_id` - The reasoning trace supporting this claim
    /// * `initial_truth` - The initial truth value
    #[must_use]
    pub fn new_with_trace(
        content: String,
        agent_id: AgentId,
        public_key: [u8; 32],
        trace_id: TraceId,
        initial_truth: TruthValue,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: ClaimId::new(),
            content,
            truth_value: initial_truth,
            agent_id,
            public_key,
            content_hash: [0u8; 32],
            trace_id: Some(trace_id),
            signature: None,
            created_at: now,
            updated_at: now,
            supersedes: None,
            is_current: true,
        }
    }

    /// Create a new claim without a reasoning trace
    #[deprecated(note = "Use Claim::new() — trace_id is now always None on construction")]
    #[must_use]
    pub fn new_without_trace(
        content: String,
        agent_id: AgentId,
        public_key: [u8; 32],
        initial_truth: TruthValue,
    ) -> Self {
        Self::new(content, agent_id, public_key, initial_truth)
    }

    /// Set the `trace_id` for this claim
    ///
    /// Use this after creating a claim with `new_without_trace` to associate
    /// it with a reasoning trace.
    pub fn set_trace_id(&mut self, trace_id: TraceId) {
        self.trace_id = Some(trace_id);
        self.updated_at = Utc::now();
    }

    /// Check if this claim has been signed
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Create a claim with a specific ID (for database deserialization)
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn with_id(
        id: ClaimId,
        content: String,
        agent_id: AgentId,
        public_key: [u8; 32],
        content_hash: [u8; 32],
        trace_id: Option<TraceId>,
        signature: Option<[u8; 64]>,
        truth_value: TruthValue,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            content,
            truth_value,
            agent_id,
            public_key,
            content_hash,
            trace_id,
            signature,
            created_at,
            updated_at,
            supersedes: None,
            is_current: true,
        }
    }

    /// Update the truth value of this claim
    pub fn update_truth_value(&mut self, new_value: TruthValue) {
        self.truth_value = new_value;
        self.updated_at = Utc::now();
    }

    /// Check if this claim is verified as true (truth >= 0.8)
    #[must_use]
    pub fn is_verified_true(&self) -> bool {
        self.truth_value.is_verified_true()
    }

    /// Check if this claim is verified as false (truth <= 0.2)
    #[must_use]
    pub fn is_verified_false(&self) -> bool {
        self.truth_value.is_verified_false()
    }

    /// Check if this claim is in the uncertain range (0.2 < truth < 0.8)
    #[must_use]
    pub fn is_uncertain(&self) -> bool {
        self.truth_value.is_uncertain()
    }

    /// Check if this claim has a reasoning trace
    ///
    /// Returns false if `trace_id` is None, which indicates a potentially invalid claim.
    #[must_use]
    pub const fn has_reasoning_trace(&self) -> bool {
        self.trace_id.is_some()
    }

    /// Check if this claim has been superseded by a newer version
    #[must_use]
    pub const fn is_superseded(&self) -> bool {
        !self.is_current
    }

    /// Get the ID of the claim this supersedes, if any
    #[must_use]
    pub const fn superseded_claim(&self) -> Option<ClaimId> {
        self.supersedes
    }
}

impl std::hash::Hash for Claim {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

// Only compare by ID for equality (structural equivalence)
impl PartialEq for Claim {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Claim {}

// ==================== Trait Implementations ====================

impl Signable for Claim {
    type SignableContent = ClaimSignableContent;

    fn signable_content(&self) -> Self::SignableContent {
        ClaimSignableContent {
            id: self.id,
            content: self.content.clone(),
            truth_value: self.truth_value,
            agent_id: self.agent_id,
            content_hash: self.content_hash,
            trace_id: self.trace_id,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    fn signature(&self) -> Option<&[u8; SIGNATURE_SIZE]> {
        self.signature.as_ref()
    }

    fn set_signature(&mut self, signature: [u8; SIGNATURE_SIZE]) {
        self.signature = Some(signature);
    }
}

impl Verifiable for Claim {
    fn signer_public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

impl ContentAddressable for Claim {
    fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }

    fn set_content_hash(&mut self, hash: [u8; 32]) {
        self.content_hash = hash;
    }

    fn compute_hash(&self) -> Result<[u8; 32], epigraph_crypto::CryptoError> {
        let hashable = ClaimHashableContent {
            id: self.id,
            content: self.content.clone(),
            truth_value: self.truth_value,
            agent_id: self.agent_id,
            trace_id: self.trace_id,
            created_at: self.created_at,
            updated_at: self.updated_at,
        };
        epigraph_crypto::ContentHasher::hash_canonical(&hashable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_crypto::AgentSigner;

    #[test]
    fn create_claim_with_trace() {
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let trace_id = TraceId::new();
        let truth = TruthValue::new(0.75).unwrap();

        let claim = Claim::new_with_trace(
            "The Earth is round".to_string(),
            agent_id,
            public_key,
            trace_id,
            truth,
        );

        assert_eq!(claim.content, "The Earth is round");
        assert_eq!(claim.truth_value, truth);
        assert_eq!(claim.agent_id, agent_id);
        assert_eq!(claim.trace_id, Some(trace_id));
        assert!(claim.has_reasoning_trace());
    }

    #[test]
    fn claim_verification_thresholds() {
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];

        let high_truth = Claim::new(
            "verified true".to_string(),
            agent_id,
            public_key,
            TruthValue::new(0.9).unwrap(),
        );
        assert!(high_truth.is_verified_true());
        assert!(!high_truth.is_uncertain());

        let low_truth = Claim::new(
            "verified false".to_string(),
            agent_id,
            public_key,
            TruthValue::new(0.1).unwrap(),
        );
        assert!(low_truth.is_verified_false());
        assert!(!low_truth.is_uncertain());

        let uncertain = Claim::new(
            "uncertain".to_string(),
            agent_id,
            public_key,
            TruthValue::new(0.5).unwrap(),
        );
        assert!(uncertain.is_uncertain());
        assert!(!uncertain.is_verified_true());
        assert!(!uncertain.is_verified_false());
    }

    #[test]
    fn update_truth_value_updates_timestamp() {
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let mut claim = Claim::new(
            "test".to_string(),
            agent_id,
            public_key,
            TruthValue::new(0.5).unwrap(),
        );

        let original_updated = claim.updated_at;

        // Small delay to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_millis(10));

        claim.update_truth_value(TruthValue::new(0.8).unwrap());

        assert!(claim.updated_at > original_updated);
        assert_eq!(claim.truth_value.value(), 0.8);
    }

    #[test]
    fn claims_with_same_id_are_equal() {
        let id = ClaimId::new();
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let content_hash = [0u8; 32];
        let trace_id = TraceId::new();
        let truth = TruthValue::new(0.5).unwrap();
        let now = Utc::now();

        let claim1 = Claim::with_id(
            id,
            "claim 1".to_string(),
            agent_id,
            public_key,
            content_hash,
            Some(trace_id),
            None,
            truth,
            now,
            now,
        );

        let claim2 = Claim::with_id(
            id,
            "claim 2".to_string(),
            agent_id,
            public_key,
            content_hash,
            Some(trace_id),
            None,
            truth,
            now,
            now,
        );

        assert_eq!(claim1, claim2); // Equal because same ID
    }

    #[test]
    fn claim_without_reasoning_trace() {
        let id = ClaimId::new();
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let content_hash = [0u8; 32];
        let truth = TruthValue::new(0.5).unwrap();
        let now = Utc::now();

        // Create claim without trace (using with_id since new() requires trace)
        let claim = Claim::with_id(
            id,
            "Naked assertion".to_string(),
            agent_id,
            public_key,
            content_hash,
            None, // No reasoning trace - this is suspect!
            None,
            truth,
            now,
            now,
        );

        assert!(!claim.has_reasoning_trace());
        assert!(claim.trace_id.is_none());
    }

    #[test]
    fn claim_hash_by_id() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let id = ClaimId::new();
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let content_hash = [0u8; 32];
        let trace_id = TraceId::new();
        let now = Utc::now();

        let claim1 = Claim::with_id(
            id,
            "content 1".to_string(),
            agent_id,
            public_key,
            content_hash,
            Some(trace_id),
            None,
            TruthValue::new(0.5).unwrap(),
            now,
            now,
        );

        let claim2 = Claim::with_id(
            id,
            "content 2".to_string(), // Different content
            agent_id,
            public_key,
            content_hash,
            Some(trace_id),
            None,
            TruthValue::new(0.9).unwrap(), // Different truth
            now,
            now,
        );

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        claim1.hash(&mut hasher1);
        claim2.hash(&mut hasher2);

        assert_eq!(
            hasher1.finish(),
            hasher2.finish(),
            "Claims with same ID should have same hash"
        );
    }

    #[test]
    fn claim_serialization() {
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let claim = Claim::new(
            "Test claim".to_string(),
            agent_id,
            public_key,
            TruthValue::new(0.75).unwrap(),
        );

        let json = serde_json::to_string(&claim).unwrap();
        let deserialized: Claim = serde_json::from_str(&json).unwrap();

        assert_eq!(claim.id, deserialized.id);
        assert_eq!(claim.content, deserialized.content);
        assert_eq!(claim.truth_value, deserialized.truth_value);
    }

    // ==================== Signable Trait Tests ====================

    #[test]
    fn claim_sign_and_verify() {
        let signer = AgentSigner::generate();
        let agent_id = AgentId::new();

        let mut claim = Claim::new(
            "Test claim".to_string(),
            agent_id,
            signer.public_key(),
            TruthValue::new(0.8).unwrap(),
        );

        assert!(claim.signature().is_none());
        assert!(!claim.is_signed());

        // Sign the claim
        claim.sign(&signer).expect("signing should succeed");

        assert!(claim.signature().is_some());
        assert!(claim.is_signed());

        // Verify the signature
        let is_valid = claim.verify().expect("verification should succeed");
        assert!(is_valid, "Valid signature should verify");
    }

    #[test]
    fn claim_verify_fails_with_wrong_public_key() {
        let signer1 = AgentSigner::generate();
        let signer2 = AgentSigner::generate();
        let agent_id = AgentId::new();

        let mut claim = Claim::new(
            "Test claim".to_string(),
            agent_id,
            signer2.public_key(), // Wrong public key
            TruthValue::new(0.8).unwrap(),
        );

        // Sign with signer1 but claim has signer2's public key
        claim.sign(&signer1).expect("signing should succeed");

        let is_valid = claim.verify().expect("verification should complete");
        assert!(!is_valid, "Wrong public key should fail verification");
    }

    #[test]
    fn claim_verify_fails_with_tampered_content() {
        let signer = AgentSigner::generate();
        let agent_id = AgentId::new();

        let mut claim = Claim::new(
            "Original claim".to_string(),
            agent_id,
            signer.public_key(),
            TruthValue::new(0.8).unwrap(),
        );

        claim.sign(&signer).expect("signing should succeed");

        // Tamper with the content
        claim.content = "Tampered claim".to_string();

        let is_valid = claim.verify().expect("verification should complete");
        assert!(!is_valid, "Tampered content should fail verification");
    }

    #[test]
    fn claim_verify_missing_signature_returns_error() {
        let signer = AgentSigner::generate();
        let agent_id = AgentId::new();

        let claim = Claim::new(
            "Test claim".to_string(),
            agent_id,
            signer.public_key(),
            TruthValue::new(0.8).unwrap(),
        );

        // Attempt to verify without signature
        let result = claim.verify();
        assert!(result.is_err(), "Missing signature should return error");
    }

    // ==================== ContentAddressable Trait Tests ====================

    #[test]
    fn claim_content_hash_compute_and_verify() {
        let signer = AgentSigner::generate();
        let agent_id = AgentId::new();

        let mut claim = Claim::new(
            "Content to hash".to_string(),
            agent_id,
            signer.public_key(),
            TruthValue::new(0.7).unwrap(),
        );

        // Initial hash should be zero
        assert_eq!(claim.content_hash(), &[0u8; 32]);

        // Update the hash
        claim.update_hash().expect("hash update should succeed");

        assert_ne!(
            claim.content_hash(),
            &[0u8; 32],
            "Hash should be updated from zero"
        );

        // Verify the hash
        let is_valid = claim
            .verify_hash()
            .expect("hash verification should succeed");
        assert!(is_valid, "Hash should verify after update");
    }

    #[test]
    fn claim_hash_changes_with_content() {
        let signer = AgentSigner::generate();
        let agent_id = AgentId::new();

        let mut claim1 = Claim::new(
            "Content one".to_string(),
            agent_id,
            signer.public_key(),
            TruthValue::new(0.8).unwrap(),
        );

        let mut claim2 = Claim::new(
            "Content two".to_string(),
            agent_id,
            signer.public_key(),
            TruthValue::new(0.8).unwrap(),
        );

        claim1.update_hash().unwrap();
        claim2.update_hash().unwrap();

        assert_ne!(
            claim1.content_hash(),
            claim2.content_hash(),
            "Different content should produce different hashes"
        );
    }

    #[test]
    fn claim_hash_detects_tampering() {
        let signer = AgentSigner::generate();
        let agent_id = AgentId::new();

        let mut claim = Claim::new(
            "Original content".to_string(),
            agent_id,
            signer.public_key(),
            TruthValue::new(0.6).unwrap(),
        );

        claim.update_hash().unwrap();

        // Tamper with content
        claim.content = "Tampered content".to_string();

        let is_valid = claim.verify_hash().unwrap();
        assert!(!is_valid, "Tampered content should fail hash verification");
    }

    #[test]
    fn claim_initialization_is_decoupled_from_postgres() {
        // This test explicitly validates that the Core `Claim` structure
        // works perfectly in memory without any Database/SQLx traits.
        let agent_id = AgentId::new();

        let claim = Claim::new(
            "Epigraph Core is strictly decoupled from DB layers".to_string(),
            agent_id,
            [0u8; 32],
            TruthValue::new(0.99).unwrap(),
        );

        let serialized = serde_json::to_string(&claim).expect("Serialization failed");
        assert!(serialized.contains("Epigraph Core is strictly decoupled"));
    }
}
