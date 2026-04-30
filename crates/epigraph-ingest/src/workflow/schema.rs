//! Schema types for hierarchical workflow extraction. Isomorphic to
//! `document::schema::DocumentExtraction` but with workflow-native field
//! names (phases/steps/operations) and workflow-specific source metadata
//! (canonical_name, generation, parent_canonical_name).

use serde::{Deserialize, Serialize};

use crate::common::schema::{AuthorEntry, ClaimRelationship, ThesisDerivation};
use crate::document::schema::default_confidence;

/// Top-level extraction result from a workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase {
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub steps: Vec<Step>,
}

/// A step within a phase (analog of `document::schema::Paragraph`).
/// Paper-specific fields (methodology, evidence_type, page, instruments_used,
/// reagents_involved, conditions) are intentionally absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}
