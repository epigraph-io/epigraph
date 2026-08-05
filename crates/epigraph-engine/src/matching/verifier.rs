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

    /// Inverse of [`Self::as_column_str`] — read a stored
    /// `match_candidates.verifier_verdict` back into the enum. Returns `None`
    /// for anything outside the spec §5 vocabulary (which the
    /// `match_candidates_verdict_valid` CHECK in migration 036 also enforces
    /// at the database level).
    pub fn from_column_str(s: &str) -> Option<Self> {
        match s {
            "same" => Some(MatchVerdict::Same),
            "paraphrase" => Some(MatchVerdict::Paraphrase),
            "overlapping" => Some(MatchVerdict::Overlapping),
            "contradicts" => Some(MatchVerdict::Contradicts),
            "distinct" => Some(MatchVerdict::Distinct),
            _ => None,
        }
    }

    /// What a *promote* decision on a candidate carrying this verdict should
    /// record. See [`PromotionDisposition`].
    pub fn promotion_disposition(self) -> PromotionDisposition {
        match self {
            MatchVerdict::Same | MatchVerdict::Paraphrase | MatchVerdict::Overlapping => {
                PromotionDisposition::Corroborate
            }
            MatchVerdict::Contradicts => PromotionDisposition::Contradict,
            MatchVerdict::Distinct => PromotionDisposition::Drop,
        }
    }
}

/// Edge relationship for a corroborating promotion.
pub const CORROBORATES_RELATIONSHIP: &str = "CORROBORATES";

/// Edge relationship for a contradicting promotion.
///
/// **Lowercase on purpose.** [`EdgeRepository::create_symmetric_if_absent`] and
/// every consumer query dedup/filter on an exact `relationship = <string>`
/// comparison, so casing is identity, not style. Both the automatic path
/// (`matching::policy`'s `WriteContradicts` arm) and the human-decide path must
/// emit the same byte string or the same pair acquires two edges and every
/// `WHERE relationship = 'contradicts'` query sees half the population.
///
/// [`EdgeRepository::create_symmetric_if_absent`]: epigraph_db::EdgeRepository::create_symmetric_if_absent
pub const CONTRADICTS_RELATIONSHIP: &str = "contradicts";

/// What promoting a `match_candidates` row should write to the graph.
///
/// Promotion is an operator saying "yes, act on this pair" — *not* "these two
/// claims agree". The verifier already decided the polarity; the decide path's
/// job is to record it faithfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromotionDisposition {
    /// The pair states the same thing: write a `CORROBORATES` edge.
    Corroborate,
    /// The pair conflicts: write a `contradicts` edge.
    Contradict,
    /// The pair is unrelated — there is no true edge in either polarity, so
    /// promoting is a category error. Callers must refuse rather than invent
    /// a relationship.
    Drop,
}

impl PromotionDisposition {
    /// Edge relationship to write, or `None` when nothing should be written.
    pub fn edge_relationship(self) -> Option<&'static str> {
        match self {
            PromotionDisposition::Corroborate => Some(CORROBORATES_RELATIONSHIP),
            PromotionDisposition::Contradict => Some(CONTRADICTS_RELATIONSHIP),
            PromotionDisposition::Drop => None,
        }
    }
}

/// A stored `verifier_verdict` outside the spec §5 vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized verifier_verdict '{0}'")]
pub struct UnknownVerdict(pub String);

/// Resolve a stored `match_candidates.verifier_verdict` into the edge a
/// *promote* decision should record.
///
/// This is the single mapping shared by the HTTP route
/// (`epigraph-api` `decide_candidate`) and its MCP twin
/// (`decide_match_candidate`) so the two surfaces cannot drift apart.
///
/// - `None` (verdict column NULL — rows the verifier never scored) resolves to
///   [`PromotionDisposition::Corroborate`]. That is the historical behaviour of
///   both surfaces, and refusing here would make every unverified pending row
///   permanently un-promotable — a regression on the human review queue rather
///   than a fix.
/// - Any string outside the vocabulary is an error, so callers fail closed
///   instead of guessing a polarity. Unreachable through the database (the
///   `match_candidates_verdict_valid` CHECK blocks it), kept as a belt-and-braces
///   guard against a future migration widening the column.
pub fn promotion_disposition_for_column(
    verdict: Option<&str>,
) -> Result<PromotionDisposition, UnknownVerdict> {
    match verdict {
        None => Ok(PromotionDisposition::Corroborate),
        Some(s) => MatchVerdict::from_column_str(s)
            .map(MatchVerdict::promotion_disposition)
            .ok_or_else(|| UnknownVerdict(s.to_string())),
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

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [MatchVerdict; 5] = [
        MatchVerdict::Same,
        MatchVerdict::Paraphrase,
        MatchVerdict::Overlapping,
        MatchVerdict::Contradicts,
        MatchVerdict::Distinct,
    ];

    /// `from_column_str` must be the exact inverse of `as_column_str` for every
    /// variant. If someone adds a sixth verdict and only extends one direction,
    /// promotion silently falls through to the unrecognized branch.
    #[test]
    fn column_str_round_trips_for_every_verdict() {
        for v in ALL {
            assert_eq!(
                MatchVerdict::from_column_str(v.as_column_str()),
                Some(v),
                "round-trip failed for {v:?}"
            );
        }
    }

    /// The five column values the `match_candidates_verdict_valid` CHECK
    /// (migration 036) admits must all be decidable — no promotable row can
    /// land in the unrecognized branch.
    #[test]
    fn every_check_constrained_verdict_has_a_disposition() {
        use PromotionDisposition::{Contradict, Corroborate, Drop};
        let expected = [
            ("same", Corroborate),
            ("paraphrase", Corroborate),
            ("overlapping", Corroborate),
            ("contradicts", Contradict),
            ("distinct", Drop),
        ];
        for (col, want) in expected {
            assert_eq!(
                promotion_disposition_for_column(Some(col)),
                Ok(want),
                "wrong disposition for '{col}'"
            );
        }
    }

    /// A contradiction must never be recorded as a corroboration — the exact
    /// inversion this mapping exists to prevent.
    #[test]
    fn contradicts_maps_to_the_lowercase_contradicts_edge() {
        let rel = promotion_disposition_for_column(Some("contradicts"))
            .unwrap()
            .edge_relationship();
        assert_eq!(rel, Some("contradicts"));
        assert_ne!(rel, Some(CORROBORATES_RELATIONSHIP));
        // Casing is identity for edge dedup, so pin the byte string.
        assert_eq!(CONTRADICTS_RELATIONSHIP, "contradicts");
    }

    /// `distinct` has no truthful edge in either polarity.
    #[test]
    fn distinct_yields_no_edge_relationship() {
        assert_eq!(
            promotion_disposition_for_column(Some("distinct"))
                .unwrap()
                .edge_relationship(),
            None
        );
    }

    /// NULL verdict keeps the pre-fix behaviour so unverified pending rows stay
    /// promotable.
    #[test]
    fn null_verdict_still_corroborates() {
        assert_eq!(
            promotion_disposition_for_column(None),
            Ok(PromotionDisposition::Corroborate)
        );
    }

    /// Out-of-vocabulary strings fail closed rather than defaulting to
    /// corroboration.
    #[test]
    fn unrecognized_verdict_is_an_error() {
        let err = promotion_disposition_for_column(Some("REFUTES")).unwrap_err();
        assert_eq!(err, UnknownVerdict("REFUTES".to_string()));
        assert!(err.to_string().contains("REFUTES"));
    }
}
