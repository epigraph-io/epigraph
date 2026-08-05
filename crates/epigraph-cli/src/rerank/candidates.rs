//! Candidate-pair types shared between the global-join and candidates-table paths.
//!
//! The shapes here are the historical types from `bin/rerank_bridges.rs` —
//! deserialization of the LLM response depends on the exact field names
//! (`pair_index`, `valid`), so any rename is a breaking JSON-schema change.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One candidate claim pair under consideration by the LLM reranker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePair {
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub source_content: String,
    pub target_content: String,
    pub source_doi: Option<String>,
    pub target_doi: Option<String>,
    pub similarity: f64,
}

/// Per-pair LLM verdict, parsed from the model's JSON array response.
///
/// Field names are part of the LLM contract — `pair_index` and `valid`
/// are required by the prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub pair_index: usize,
    pub valid: bool,
    pub relationship: Option<String>,
    pub strength: Option<f64>,
    pub rationale: String,
}

/// Relationship strings the LLM is allowed to emit.
pub const VALID_RELATIONSHIPS: &[&str] = &[
    "supports",
    "contradicts",
    "derives_from",
    "refines",
    "analogous",
];
