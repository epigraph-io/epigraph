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

/// Why a model-returned entry never became a [`ValidationResult`].
///
/// Every one of these used to be a bare `continue` inside
/// `parse_validation_response`, which left the pair looking identical to a
/// pair the model was simply silent about. Carrying the reason out is what
/// lets `match_candidates.verifier_rationale` say *which* thing went wrong —
/// in particular whether the model ever emitted a relationship outside
/// [`VALID_RELATIONSHIPS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardReason {
    /// The whole response was not a JSON array. Applies to every pair in the
    /// batch.
    ResponseNotArray,
    /// An entry failed to deserialize and carried a usable `pair_index`.
    EntrySchemaMismatch,
    /// An entry failed to deserialize badly enough that no `pair_index` could
    /// be recovered — we know the batch was damaged, not which pair.
    UnattributableEntry,
    /// An entry named a `pair_index` outside the batch (batch misalignment).
    PairIndexOutOfBounds,
    /// An accepted entry named a relationship outside [`VALID_RELATIONSHIPS`].
    RelationshipOutOfVocabulary,
    /// An accepted entry named a strength outside the prompt's `[0.3, 1.0]`.
    StrengthOutOfRange,
}

impl DiscardReason {
    /// Stable, human-readable tail for the rationale string. Grep-able in
    /// `match_candidates.verifier_rationale`, so treat changes as breaking for
    /// anyone querying historical rows.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ResponseNotArray => "response was not a JSON array",
            Self::EntrySchemaMismatch => "entry did not match the verdict schema",
            Self::UnattributableEntry => {
                "an entry in this batch was unparseable and could not be attributed to a pair"
            }
            Self::PairIndexOutOfBounds => "an entry named a pair_index outside the batch",
            Self::RelationshipOutOfVocabulary => "relationship outside the accepted vocabulary",
            Self::StrengthOutOfRange => "strength outside [0.3, 1.0]",
        }
    }
}

/// One entry the parser threw away, with the reason and — when recoverable —
/// the batch index it claimed.
#[derive(Debug, Clone, Copy)]
pub struct DiscardedEntry {
    /// Batch index the entry named. `None` when the damage is batch-wide or
    /// the index could not be read back out of the raw JSON.
    pub pair_index: Option<usize>,
    pub reason: DiscardReason,
}
