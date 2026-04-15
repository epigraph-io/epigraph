//! Semantic link domain model
//!
//! A `SemanticLink` represents a semantic relationship between two claims in the
//! epistemic knowledge graph. These links capture how claims relate to each other:
//! - Supports: One claim provides evidence for another
//! - Contradicts: One claim negates or conflicts with another
//! - `DerivesFrom`: One claim is logically derived from another
//! - Refines: One claim is a more specific version of another
//! - Analogous: Claims share structural or conceptual similarity
//!
//! # Key Principles
//!
//! - Self-links are forbidden (a claim cannot link to itself)
//! - Strength values are bounded to [0.0, 1.0] representing confidence
//! - Every link must have a creating agent for provenance tracking

use super::ids::{AgentId, ClaimId};
use crate::errors::CoreError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Unique identifier for a `SemanticLink`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SemanticLinkId(Uuid);

impl SemanticLinkId {
    /// Create a new random `SemanticLinkId`
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a `SemanticLinkId` from an existing UUID
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the underlying UUID
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for SemanticLinkId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SemanticLinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "semantic_link:{}", self.0)
    }
}

impl From<Uuid> for SemanticLinkId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<SemanticLinkId> for Uuid {
    fn from(id: SemanticLinkId) -> Self {
        id.0
    }
}

/// The type of semantic relationship between two claims
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticLinkType {
    /// Source claim provides evidence supporting target claim
    Supports,
    /// Source claim contradicts or conflicts with target claim
    Contradicts,
    /// Source claim is logically derived from target claim
    DerivesFrom,
    /// Source claim is a more specific/refined version of target claim
    Refines,
    /// Source and target claims share structural or conceptual similarity
    Analogous,
}

impl fmt::Display for SemanticLinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Supports => write!(f, "supports"),
            Self::Contradicts => write!(f, "contradicts"),
            Self::DerivesFrom => write!(f, "derives_from"),
            Self::Refines => write!(f, "refines"),
            Self::Analogous => write!(f, "analogous"),
        }
    }
}

/// A link strength bounded to [0.0, 1.0]
///
/// Represents the confidence/strength of the semantic relationship.
/// - 0.0: Minimal relationship strength
/// - 0.5: Moderate relationship strength
/// - 1.0: Maximum relationship strength
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct LinkStrength(f64);

impl LinkStrength {
    /// Minimum valid strength value
    pub const MIN: f64 = 0.0;

    /// Maximum valid strength value
    pub const MAX: f64 = 1.0;

    /// Default strength representing moderate confidence
    pub const DEFAULT: f64 = 0.5;

    /// Create a new link strength with bounds checking
    ///
    /// # Errors
    /// Returns `CoreError::InvalidLinkStrength` if value is outside [0.0, 1.0] or NaN.
    pub fn new(value: f64) -> Result<Self, CoreError> {
        if value.is_nan() || !(Self::MIN..=Self::MAX).contains(&value) {
            return Err(CoreError::InvalidLinkStrength { value });
        }
        Ok(Self(value))
    }

    /// Create a link strength, clamping to valid bounds
    ///
    /// NaN values become 0.5 (default).
    #[must_use]
    pub const fn clamped(value: f64) -> Self {
        if value.is_nan() {
            Self(Self::DEFAULT)
        } else {
            Self(value.clamp(Self::MIN, Self::MAX))
        }
    }

    /// Create a default link strength
    #[must_use]
    pub const fn default_strength() -> Self {
        Self(Self::DEFAULT)
    }

    /// Get the raw f64 value
    #[must_use]
    pub const fn value(&self) -> f64 {
        self.0
    }
}

impl Default for LinkStrength {
    fn default() -> Self {
        Self::default_strength()
    }
}

impl fmt::Display for LinkStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.3}", self.0)
    }
}

impl TryFrom<f64> for LinkStrength {
    type Error = CoreError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<LinkStrength> for f64 {
    fn from(ls: LinkStrength) -> Self {
        ls.0
    }
}

/// A semantic link representing a relationship between two claims
///
/// # Design Notes
///
/// - `source_claim_id`: The claim initiating the relationship
/// - `target_claim_id`: The claim receiving the relationship
/// - `link_type`: The type of semantic relationship
/// - `strength`: Confidence in this relationship [0.0, 1.0]
/// - `created_by`: The agent who established this link (for provenance)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticLink {
    /// Unique identifier for this link
    pub id: SemanticLinkId,

    /// The source claim (initiator of the relationship)
    pub source_claim_id: ClaimId,

    /// The target claim (receiver of the relationship)
    pub target_claim_id: ClaimId,

    /// The type of semantic relationship
    pub link_type: SemanticLinkType,

    /// The strength/confidence of this relationship [0.0, 1.0]
    pub strength: LinkStrength,

    /// When this link was created
    pub created_at: DateTime<Utc>,

    /// The agent who created this link
    pub created_by: AgentId,
}

impl SemanticLink {
    /// Create a new semantic link between two claims
    ///
    /// # Arguments
    /// * `source_claim_id` - The source claim
    /// * `target_claim_id` - The target claim
    /// * `link_type` - The type of relationship
    /// * `strength` - The confidence in this relationship
    /// * `created_by` - The agent creating this link
    ///
    /// # Errors
    /// Returns `CoreError::SelfReferentialEdge` if source and target are the same claim.
    pub fn new(
        source_claim_id: ClaimId,
        target_claim_id: ClaimId,
        link_type: SemanticLinkType,
        strength: LinkStrength,
        created_by: AgentId,
    ) -> Result<Self, CoreError> {
        if source_claim_id == target_claim_id {
            return Err(CoreError::SelfReferentialEdge(source_claim_id.as_uuid()));
        }

        Ok(Self {
            id: SemanticLinkId::new(),
            source_claim_id,
            target_claim_id,
            link_type,
            strength,
            created_at: Utc::now(),
            created_by,
        })
    }

    /// Create a semantic link with a specific ID (for database deserialization)
    ///
    /// # Errors
    /// Returns `CoreError::SelfReferentialEdge` if source and target are the same claim.
    pub fn with_id(
        id: SemanticLinkId,
        source_claim_id: ClaimId,
        target_claim_id: ClaimId,
        link_type: SemanticLinkType,
        strength: LinkStrength,
        created_at: DateTime<Utc>,
        created_by: AgentId,
    ) -> Result<Self, CoreError> {
        if source_claim_id == target_claim_id {
            return Err(CoreError::SelfReferentialEdge(source_claim_id.as_uuid()));
        }

        Ok(Self {
            id,
            source_claim_id,
            target_claim_id,
            link_type,
            strength,
            created_at,
            created_by,
        })
    }

    /// Check if this link represents a supporting relationship
    #[must_use]
    pub const fn is_supporting(&self) -> bool {
        matches!(self.link_type, SemanticLinkType::Supports)
    }

    /// Check if this link represents a contradicting relationship
    #[must_use]
    pub const fn is_contradicting(&self) -> bool {
        matches!(self.link_type, SemanticLinkType::Contradicts)
    }

    /// Check if this link represents a derivation relationship
    #[must_use]
    pub const fn is_derivation(&self) -> bool {
        matches!(self.link_type, SemanticLinkType::DerivesFrom)
    }
}

impl std::hash::Hash for SemanticLink {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl PartialEq for SemanticLink {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for SemanticLink {}

#[cfg(test)]
mod tests {
    use super::*;

    // =============================================================================
    // SemanticLinkId Tests
    // =============================================================================

    #[test]
    fn semantic_link_id_is_distinct_from_other_ids() {
        let link_id = SemanticLinkId::new();
        let claim_id = ClaimId::new();

        // They use the same underlying UUID type but are distinct types
        // This would fail to compile: let _: SemanticLinkId = claim_id;
        assert_ne!(link_id.as_uuid(), claim_id.as_uuid());
    }

    #[test]
    fn semantic_link_id_display_has_prefix() {
        let id = SemanticLinkId::from_uuid(Uuid::nil());
        assert!(id.to_string().starts_with("semantic_link:"));
    }

    #[test]
    fn semantic_link_id_serializes_as_uuid() {
        let id = SemanticLinkId::from_uuid(Uuid::nil());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"00000000-0000-0000-0000-000000000000\"");
    }

    // =============================================================================
    // SemanticLinkType Tests
    // =============================================================================

    #[test]
    fn semantic_link_type_display() {
        assert_eq!(SemanticLinkType::Supports.to_string(), "supports");
        assert_eq!(SemanticLinkType::Contradicts.to_string(), "contradicts");
        assert_eq!(SemanticLinkType::DerivesFrom.to_string(), "derives_from");
        assert_eq!(SemanticLinkType::Refines.to_string(), "refines");
        assert_eq!(SemanticLinkType::Analogous.to_string(), "analogous");
    }

    #[test]
    fn semantic_link_type_serialization() {
        let link_type = SemanticLinkType::DerivesFrom;
        let json = serde_json::to_string(&link_type).unwrap();
        assert_eq!(json, "\"derives_from\"");

        let parsed: SemanticLinkType = serde_json::from_str("\"supports\"").unwrap();
        assert_eq!(parsed, SemanticLinkType::Supports);
    }

    // =============================================================================
    // LinkStrength Tests
    // =============================================================================

    #[test]
    fn valid_link_strength_values() {
        assert!(LinkStrength::new(0.0).is_ok());
        assert!(LinkStrength::new(0.5).is_ok());
        assert!(LinkStrength::new(1.0).is_ok());
        assert!(LinkStrength::new(0.73).is_ok());
    }

    #[test]
    fn invalid_link_strength_values() {
        assert!(LinkStrength::new(-0.1).is_err());
        assert!(LinkStrength::new(1.1).is_err());
        assert!(LinkStrength::new(f64::NAN).is_err());
        assert!(LinkStrength::new(f64::INFINITY).is_err());
        assert!(LinkStrength::new(f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn link_strength_error_message() {
        let err = LinkStrength::new(-0.5).unwrap_err();
        assert!(err.to_string().contains("-0.5"));
        assert!(err.to_string().contains("[0.0, 1.0]"));
    }

    #[test]
    fn link_strength_clamped_handles_out_of_bounds() {
        assert_eq!(LinkStrength::clamped(-5.0).value(), 0.0);
        assert_eq!(LinkStrength::clamped(10.0).value(), 1.0);
        assert_eq!(LinkStrength::clamped(f64::NAN).value(), 0.5);
    }

    #[test]
    fn link_strength_default() {
        let strength = LinkStrength::default();
        assert_eq!(strength.value(), 0.5);
    }

    #[test]
    fn link_strength_serialization() {
        let strength = LinkStrength::new(0.75).unwrap();
        let json = serde_json::to_string(&strength).unwrap();
        assert_eq!(json, "0.75");

        let parsed: LinkStrength = serde_json::from_str("0.75").unwrap();
        assert_eq!(parsed, strength);
    }

    #[test]
    fn link_strength_deserialization_rejects_invalid() {
        let result: Result<LinkStrength, _> = serde_json::from_str("1.5");
        assert!(result.is_err());
    }

    // =============================================================================
    // SemanticLink Tests
    // =============================================================================

    #[test]
    fn create_semantic_link_success() {
        let source = ClaimId::new();
        let target = ClaimId::new();
        let agent = AgentId::new();
        let strength = LinkStrength::new(0.8).unwrap();

        let link =
            SemanticLink::new(source, target, SemanticLinkType::Supports, strength, agent).unwrap();

        assert_eq!(link.source_claim_id, source);
        assert_eq!(link.target_claim_id, target);
        assert_eq!(link.link_type, SemanticLinkType::Supports);
        assert_eq!(link.strength, strength);
        assert_eq!(link.created_by, agent);
        assert!(link.is_supporting());
        assert!(!link.is_contradicting());
    }

    #[test]
    fn semantic_link_rejects_self_reference() {
        let claim = ClaimId::new();
        let agent = AgentId::new();
        let strength = LinkStrength::new(0.5).unwrap();

        let result = SemanticLink::new(
            claim,
            claim, // Same as source - should fail
            SemanticLinkType::Supports,
            strength,
            agent,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            CoreError::SelfReferentialEdge(uuid) => {
                assert_eq!(uuid, claim.as_uuid());
            }
            _ => panic!("Expected SelfReferentialEdge error"),
        }
    }

    #[test]
    fn semantic_link_with_id_rejects_self_reference() {
        let claim = ClaimId::new();
        let agent = AgentId::new();
        let id = SemanticLinkId::new();
        let strength = LinkStrength::new(0.5).unwrap();

        let result = SemanticLink::with_id(
            id,
            claim,
            claim, // Same as source - should fail
            SemanticLinkType::Supports,
            strength,
            Utc::now(),
            agent,
        );

        assert!(result.is_err());
    }

    #[test]
    fn semantic_link_type_predicates() {
        let source = ClaimId::new();
        let target = ClaimId::new();
        let agent = AgentId::new();
        let strength = LinkStrength::default();

        let supports =
            SemanticLink::new(source, target, SemanticLinkType::Supports, strength, agent).unwrap();
        assert!(supports.is_supporting());
        assert!(!supports.is_contradicting());
        assert!(!supports.is_derivation());

        let contradicts = SemanticLink::new(
            source,
            target,
            SemanticLinkType::Contradicts,
            strength,
            agent,
        )
        .unwrap();
        assert!(contradicts.is_contradicting());
        assert!(!contradicts.is_supporting());

        let derives = SemanticLink::new(
            source,
            target,
            SemanticLinkType::DerivesFrom,
            strength,
            agent,
        )
        .unwrap();
        assert!(derives.is_derivation());
    }

    #[test]
    fn semantic_links_with_same_id_are_equal() {
        let id = SemanticLinkId::new();
        let source = ClaimId::new();
        let target = ClaimId::new();
        let agent = AgentId::new();
        let now = Utc::now();

        let link1 = SemanticLink::with_id(
            id,
            source,
            target,
            SemanticLinkType::Supports,
            LinkStrength::new(0.5).unwrap(),
            now,
            agent,
        )
        .unwrap();

        // Different link type and strength, but same ID
        let link2 = SemanticLink::with_id(
            id,
            source,
            target,
            SemanticLinkType::Contradicts,
            LinkStrength::new(0.9).unwrap(),
            now,
            agent,
        )
        .unwrap();

        assert_eq!(link1, link2);
    }

    #[test]
    fn semantic_link_hash_by_id() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let id = SemanticLinkId::new();
        let source = ClaimId::new();
        let target = ClaimId::new();
        let agent = AgentId::new();
        let now = Utc::now();

        let link1 = SemanticLink::with_id(
            id,
            source,
            target,
            SemanticLinkType::Supports,
            LinkStrength::new(0.5).unwrap(),
            now,
            agent,
        )
        .unwrap();

        let link2 = SemanticLink::with_id(
            id,
            source,
            target,
            SemanticLinkType::Contradicts,   // Different type
            LinkStrength::new(0.9).unwrap(), // Different strength
            now,
            agent,
        )
        .unwrap();

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        link1.hash(&mut hasher1);
        link2.hash(&mut hasher2);

        assert_eq!(
            hasher1.finish(),
            hasher2.finish(),
            "Links with same ID should have same hash"
        );
    }

    #[test]
    fn semantic_link_serialization() {
        let source = ClaimId::new();
        let target = ClaimId::new();
        let agent = AgentId::new();

        let link = SemanticLink::new(
            source,
            target,
            SemanticLinkType::DerivesFrom,
            LinkStrength::new(0.85).unwrap(),
            agent,
        )
        .unwrap();

        let json = serde_json::to_string(&link).unwrap();
        let deserialized: SemanticLink = serde_json::from_str(&json).unwrap();

        assert_eq!(link.id, deserialized.id);
        assert_eq!(link.source_claim_id, deserialized.source_claim_id);
        assert_eq!(link.target_claim_id, deserialized.target_claim_id);
        assert_eq!(link.link_type, deserialized.link_type);
        assert_eq!(link.strength, deserialized.strength);
        assert_eq!(link.created_by, deserialized.created_by);
    }

    #[test]
    fn all_link_types_can_be_created() {
        let source = ClaimId::new();
        let target = ClaimId::new();
        let agent = AgentId::new();
        let strength = LinkStrength::default();

        for link_type in [
            SemanticLinkType::Supports,
            SemanticLinkType::Contradicts,
            SemanticLinkType::DerivesFrom,
            SemanticLinkType::Refines,
            SemanticLinkType::Analogous,
        ] {
            let link = SemanticLink::new(source, target, link_type, strength, agent);
            assert!(link.is_ok(), "Failed to create link of type {link_type:?}");
        }
    }
}
