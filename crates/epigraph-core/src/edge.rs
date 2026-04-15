//! Edge type for the label property graph
//!
//! Edges are directed relationships between nodes with a type and properties.

use crate::errors::CoreError;
use crate::ids::{EdgeId, NodeId};
use crate::properties::PropertyMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A directed edge in the label property graph
///
/// Edges connect two nodes with:
/// - A relationship type (string, enabling dynamic ontology)
/// - Arbitrary properties (key-value pairs)
/// - Timestamps for auditing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    /// Unique identifier for this edge
    pub id: EdgeId,

    /// Source node of the relationship
    pub source: NodeId,

    /// Target node of the relationship
    pub target: NodeId,

    /// Relationship type (e.g., "supports", "refutes", "`authored_by`")
    pub relationship: String,

    /// Properties stored on this edge
    pub properties: PropertyMap,

    /// When this edge was created
    pub created_at: DateTime<Utc>,

    /// Start of temporal validity (None = atemporal or ongoing)
    pub valid_from: Option<DateTime<Utc>>,

    /// End of temporal validity (None = still valid / atemporal)
    pub valid_to: Option<DateTime<Utc>>,
}

impl Edge {
    /// Create a new edge between two nodes
    ///
    /// # Errors
    /// Returns `CoreError::SelfReferentialEdge` if source and target are the same.
    pub fn new(
        source: NodeId,
        target: NodeId,
        relationship: impl Into<String>,
    ) -> Result<Self, CoreError> {
        if source == target {
            return Err(CoreError::SelfReferentialEdge(source.as_uuid()));
        }

        Ok(Self {
            id: EdgeId::new(),
            source,
            target,
            relationship: relationship.into(),
            properties: PropertyMap::new(),
            created_at: Utc::now(),
            valid_from: None,
            valid_to: None,
        })
    }

    /// Create a new edge with a specific ID
    ///
    /// # Errors
    /// Returns `CoreError::SelfReferentialEdge` if source and target are the same.
    pub fn with_id(
        id: EdgeId,
        source: NodeId,
        target: NodeId,
        relationship: impl Into<String>,
    ) -> Result<Self, CoreError> {
        if source == target {
            return Err(CoreError::SelfReferentialEdge(source.as_uuid()));
        }

        Ok(Self {
            id,
            source,
            target,
            relationship: relationship.into(),
            properties: PropertyMap::new(),
            created_at: Utc::now(),
            valid_from: None,
            valid_to: None,
        })
    }

    /// Set a property on this edge
    pub fn set_property(
        &mut self,
        key: impl Into<String>,
        value: impl Into<crate::properties::PropertyValue>,
    ) {
        self.properties.insert(key, value);
    }

    /// Get a property from this edge
    #[must_use]
    pub fn get_property(&self, key: &str) -> Option<&crate::properties::PropertyValue> {
        self.properties.get(key)
    }
}

impl PartialEq for Edge {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Edge {}

impl std::hash::Hash for Edge {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// Well-known relationship types for `EpiGraph`
pub mod relationships {
    /// Claim A supports Claim B (evidence relationship)
    pub const SUPPORTS: &str = "supports";

    /// Claim A refutes Claim B (contradiction)
    pub const REFUTES: &str = "refutes";

    /// Claim A relates to Claim B (general semantic link)
    pub const RELATES_TO: &str = "relates_to";

    /// Claim A generalizes Claim B (abstraction)
    pub const GENERALIZES: &str = "generalizes";

    /// Claim A specializes Claim B (instantiation)
    pub const SPECIALIZES: &str = "specializes";

    /// Claim A elaborates on Claim B (provides detail)
    pub const ELABORATES: &str = "elaborates";

    /// Agent authored this Claim/Evidence
    pub const AUTHORED_BY: &str = "authored_by";

    /// Claim was derived from this `ReasoningTrace`
    pub const DERIVED_FROM: &str = "derived_from";

    /// `ReasoningTrace` uses this Evidence as input
    pub const USES_EVIDENCE: &str = "uses_evidence";

    /// Claim supersedes an older version
    pub const SUPERSEDES: &str = "supersedes";

    /// Two claims describe the same entity from different sources
    pub const EQUIVALENT_TO: &str = "equivalent_to";

    /// A product/material is used in an experiment or process
    pub const USED_IN: &str = "used_in";

    /// A product is supplied by a vendor/manufacturer
    pub const SUPPLIED_BY: &str = "supplied_by";

    // ── Political Network Monitoring edge types ──────────────────────────

    /// Claim was first publicly asserted by this agent (origination, not amplification)
    pub const ORIGINATED_BY: &str = "ORIGINATED_BY";

    /// Agent repeated, endorsed, or spread an existing claim
    pub const AMPLIFIED_BY: &str = "AMPLIFIED_BY";

    /// Two claims from different agents are structurally similar and temporally close
    pub const COORDINATED_WITH: &str = "COORDINATED_WITH";

    /// Claim employs a specific propaganda technique
    pub const USES_TECHNIQUE: &str = "USES_TECHNIQUE";

    /// Two narrative coalitions are structural mirrors with opposite factual content
    pub const MIRROR_NARRATIVE: &str = "MIRROR_NARRATIVE";

    // ── PROV-O Agent Relationship Types ──────────────────────────

    /// Person is affiliated with an organization (temporal)
    pub const AFFILIATED_WITH: &str = "AFFILIATED_WITH";

    /// Person is employed by an organization (temporal)
    pub const EMPLOYED_BY: &str = "EMPLOYED_BY";

    /// Software agent or instrument is operated by a person (prov:actedOnBehalfOf)
    pub const OPERATED_BY: &str = "OPERATED_BY";

    /// Organization is a member of another organization (temporal)
    /// Note: already exists in edges API as uppercase MEMBER_OF, but adding here for completeness
    pub const MEMBER_OF: &str = "MEMBER_OF";

    /// Instrument is manufactured by an organization
    pub const MANUFACTURED_BY: &str = "MANUFACTURED_BY";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_edge_between_nodes() {
        let source = NodeId::new();
        let target = NodeId::new();

        let edge = Edge::new(source, target, relationships::SUPPORTS).unwrap();

        assert_eq!(edge.source, source);
        assert_eq!(edge.target, target);
        assert_eq!(edge.relationship, relationships::SUPPORTS);
    }

    #[test]
    fn self_referential_edge_rejected() {
        let node = NodeId::new();
        let result = Edge::new(node, node, relationships::SUPPORTS);

        assert!(matches!(result, Err(CoreError::SelfReferentialEdge(_))));
    }

    #[test]
    fn edge_has_temporal_fields() {
        let source = NodeId::new();
        let target = NodeId::new();
        let edge = Edge::new(source, target, relationships::SUPPORTS).unwrap();
        assert!(edge.valid_from.is_none());
        assert!(edge.valid_to.is_none());
    }

    #[test]
    fn new_relationship_constants_exist() {
        assert_eq!(relationships::AFFILIATED_WITH, "AFFILIATED_WITH");
        assert_eq!(relationships::EMPLOYED_BY, "EMPLOYED_BY");
        assert_eq!(relationships::OPERATED_BY, "OPERATED_BY");
        assert_eq!(relationships::MANUFACTURED_BY, "MANUFACTURED_BY");
    }

    #[test]
    fn edge_with_properties() {
        let source = NodeId::new();
        let target = NodeId::new();

        let mut edge = Edge::new(source, target, relationships::SUPPORTS).unwrap();
        edge.set_property("weight", 0.85);
        edge.set_property("confidence", 0.9);

        assert_eq!(
            edge.get_property("weight")
                .and_then(super::super::properties::PropertyValue::as_float),
            Some(0.85)
        );
    }
}
