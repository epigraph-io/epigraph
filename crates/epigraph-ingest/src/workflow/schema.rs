//! Schema types for hierarchical workflow extraction. Isomorphic to
//! `document::schema::DocumentExtraction` but with workflow-native field
//! names (phases/steps/operations) and workflow-specific source metadata
//! (canonical_name, generation, parent_canonical_name).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::schema::{AuthorEntry, ClaimRelationship, ThesisDerivation};
use crate::document::schema::default_confidence;

/// Top-level extraction result from a workflow.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WorkflowExtraction {
    pub source: WorkflowSource,
    #[serde(default)]
    pub thesis: Option<String>,
    #[serde(default)]
    pub thesis_derivation: ThesisDerivation,
    #[serde(default)]
    pub phases: Vec<Phase>,
    #[serde(default)]
    pub relationships: Vec<ClaimRelationship>,
}

/// Metadata about the workflow.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WorkflowSource {
    /// Required slug; drives the deterministic root ID.
    pub canonical_name: String,
    /// Free-text statement of the workflow's goal.
    pub goal: String,
    #[serde(default)]
    pub generation: u32,
    #[serde(default)]
    pub parent_canonical_name: Option<String>,
    #[serde(default)]
    pub authors: Vec<AuthorEntry>,
    #[serde(default)]
    pub expected_outcome: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// A phase within a workflow (analog of `document::schema::Section`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Phase {
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub steps: Vec<Step>,
}

/// A step within a phase (analog of `document::schema::Paragraph`).
/// Remaining paper-specific fields (methodology, page, instruments_used,
/// reagents_involved, conditions) are intentionally absent.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Step {
    pub compound: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub generality: Vec<i32>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    /// Evidence type for this step and its operation atoms. The extractor picks
    /// ONE canonical value from [`crate::common::evidence_type::EVIDENCE_TYPES`]
    /// (regulatory, empirical, statistical, logical, testimonial,
    /// circumstantial, conversational). Normalised at plan-build time; any
    /// unrecognised value is dropped to `None`. Mirrors
    /// `document::schema::Paragraph::evidence_type` so workflow-ingested
    /// operation BBAs participate in the evidence-type reliability tier.
    #[serde(default)]
    pub evidence_type: Option<String>,
}
