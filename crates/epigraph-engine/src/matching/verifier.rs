//! LLM verifier interface for the mid score band.
//!
//! See `docs/superpowers/specs/2026-05-21-cross-source-matching-design.md` §4
//! ("LLM Verifier"). High-band pairs auto-promote; mid-band pairs invoke a
//! verifier; low-band pairs are dropped.
//!
//! The engine crate only owns:
//! - The [`Verdict`] / [`MatchVerdict`] data types.
//! - The [`VerifierClient`] trait — pluggable so tests can inject a fake.
//! - [`map_relationship`] — translates the reranker's relationship vocabulary
//!   (`supports | contradicts | derives_from | refines | analogous`) into the
//!   matcher's coarser [`MatchVerdict`] enum that drives the policy layer.
//!
//! The production implementation lives outside this crate (planned in
//! `epigraph-cli`, alongside `rerank::rerank_candidates_table`), to avoid the
//! `epigraph-cli` → `epigraph-engine` → `epigraph-cli` cycle that would result
//! from importing it here. The binary/pipeline glue constructs the concrete
//! client and hands it to the orchestrator (T16) as `&dyn VerifierClient`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Raw verdict emitted by an LLM verifier for a single candidate pair.
///
/// Mirrors the per-pair shape of `epigraph-cli`'s `ValidationResult` so a thin
/// adapter in the CLI crate can map between them. `relationship` is the
/// reranker's vocabulary; downstream code coerces via [`map_relationship`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub relationship: String,
    pub strength: f32,
    pub rationale: String,
}

/// Matcher-level interpretation of a verdict — what the policy layer cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchVerdict {
    /// Same underlying claim (corroboration target).
    Same,
    /// Paraphrase / analogous restatement of the same idea.
    Paraphrase,
    /// Overlapping but distinct (e.g. one refines the other).
    Overlapping,
    /// Contradicts — surfaces a contradiction signal (spec §Failure Modes).
    Contradicts,
    /// Related but not the same claim — drop from matcher's perspective.
    Distinct,
}

impl MatchVerdict {
    /// String form persisted in `match_candidates.verifier_verdict`.
    /// Vocabulary is fixed by spec §5: `same|paraphrase|overlapping|
    /// contradicts|distinct`. T19/T20 consumers depend on this exact set.
    pub fn as_column_str(self) -> &'static str {
        match self {
            MatchVerdict::Same => "same",
            MatchVerdict::Paraphrase => "paraphrase",
            MatchVerdict::Overlapping => "overlapping",
            MatchVerdict::Contradicts => "contradicts",
            MatchVerdict::Distinct => "distinct",
        }
    }
}

/// Map the LLM-reranker relationship vocabulary onto a [`MatchVerdict`].
///
/// Vocabulary defined in `epigraph_cli::rerank::candidates::VALID_RELATIONSHIPS`
/// (`supports | contradicts | derives_from | refines | analogous`).
/// `elaborates` is also accepted here for forward-compatibility — the spec
/// lists it even though the current prompt does not emit it. Unknown strings
/// default to [`MatchVerdict::Distinct`] (conservative: do not corroborate).
pub fn map_relationship(rel: &str, _strength: f32) -> MatchVerdict {
    match rel {
        "supports" | "elaborates" => MatchVerdict::Same,
        "analogous" => MatchVerdict::Paraphrase,
        "refines" => MatchVerdict::Overlapping,
        "contradicts" => MatchVerdict::Contradicts,
        _ => MatchVerdict::Distinct,
    }
}

/// Pluggable LLM verifier. The production impl wraps
/// `epigraph_cli::rerank::rerank_candidates_table` (created in T18 binary
/// wiring); tests inject a fake.
#[async_trait]
pub trait VerifierClient: Send + Sync {
    /// Return one verdict per input pair, in the same order. Implementations
    /// MUST preserve `pairs[i]` ↔ `result[i]` alignment so the pipeline can
    /// attribute verdicts back to `match_candidates` rows without a second
    /// lookup.
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Verdict>>;
}
