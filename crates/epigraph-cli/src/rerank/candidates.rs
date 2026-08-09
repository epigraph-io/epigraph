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

/// Why a pair got no usable verdict out of a batch.
///
/// Most of these used to be a bare `continue` inside
/// `parse_validation_response`, which left the pair looking identical to a pair
/// the model was simply silent about. Carrying the reason out is what lets the
/// reranker's own summary say *which* thing went wrong.
///
/// # Where these strings go — and where they do not
///
/// **Nothing here is persisted.** The only surface is
/// [`crate::rerank::RerankSummary::discard_breakdown`], which
/// `rerank::core::rerank_inner` renders into one `eprintln!` line per run
/// (journald, for the cross-source sweep). No code path writes a
/// [`Self::as_str`] text to `match_candidates.verifier_rationale` or to any
/// other database column, and this PR deliberately adds none: a rationale is
/// read as evidence, and PR #381 was reverted for putting a precise-but-false
/// string there.
///
/// The variants split into two scopes, and the split is load-bearing because
/// the emitted string has to be true for the pair it is counted against:
///
/// - **Pair-scoped** ([`Self::EntrySchemaMismatch`],
///   [`Self::RelationshipOutOfVocabulary`], [`Self::StrengthOutOfRange`]) — the
///   discarded entry named an in-range `pair_index`, so we know whose entry it
///   was.
/// - **Batch-scoped** ([`Self::BatchCallFailed`], [`Self::ResponseNotArray`],
///   [`Self::UnattributableEntry`], [`Self::PairIndexOutOfBounds`]) — we know
///   the batch was damaged but not which pair paid for it. Their [`Self::as_str`]
///   text is therefore phrased as a statement about *the batch*, never about
///   this pair's own entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardReason {
    /// The LLM call for this batch failed outright (after the rate-limit
    /// retry), so no response was ever parsed. Batch-scoped: applies to every
    /// pair in the batch, and none of them were ever answered.
    BatchCallFailed,
    /// The whole response was not a JSON array. Batch-scoped.
    ResponseNotArray,
    /// An entry failed to deserialize and carried a usable `pair_index`.
    /// Pair-scoped.
    EntrySchemaMismatch,
    /// An entry failed to deserialize badly enough that no `pair_index` could
    /// be recovered — we know the batch was damaged, not which pair.
    /// Batch-scoped.
    UnattributableEntry,
    /// An entry named a `pair_index` outside the batch (batch misalignment).
    /// The index points at no real pair, so this is batch-scoped too.
    PairIndexOutOfBounds,
    /// An accepted entry named a relationship outside [`VALID_RELATIONSHIPS`].
    /// Pair-scoped.
    RelationshipOutOfVocabulary,
    /// An accepted entry named a strength outside the prompt's `[0.3, 1.0]`.
    /// Pair-scoped.
    StrengthOutOfRange,
}

impl DiscardReason {
    /// Human-readable reason text, aggregated by
    /// [`crate::rerank::RerankSummary::discard_breakdown`] and printed to
    /// **stderr only**. It is not written to any database column, so changing
    /// one breaks log-scrapers, not historical-row queries.
    ///
    /// Batch-scoped variants say "this batch"; they must never read as a claim
    /// about the individual pair they are counted against.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BatchCallFailed => "the LLM call for this batch failed",
            Self::ResponseNotArray => "the batch response was not a JSON array",
            Self::EntrySchemaMismatch => "this pair's entry did not match the verdict schema",
            Self::UnattributableEntry => {
                "the batch response contained an entry that could not be attributed to any pair"
            }
            Self::PairIndexOutOfBounds => {
                "the batch response contained an entry naming a pair_index outside the batch"
            }
            Self::RelationshipOutOfVocabulary => {
                "this pair's relationship was outside the accepted vocabulary"
            }
            Self::StrengthOutOfRange => "this pair's strength was outside [0.3, 1.0]",
        }
    }

    /// Whether the reason is a statement about one identified pair (`true`) or
    /// about the whole batch (`false`).
    ///
    /// Only pair-scoped reasons may be attributed to a specific pair; the rest
    /// are reported against every unanswered pair in the batch precisely
    /// *because* they cannot be narrowed further.
    pub fn is_pair_scoped(self) -> bool {
        matches!(
            self,
            Self::EntrySchemaMismatch
                | Self::RelationshipOutOfVocabulary
                | Self::StrengthOutOfRange
        )
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
