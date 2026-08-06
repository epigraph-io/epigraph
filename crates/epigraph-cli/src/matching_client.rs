//! Production [`VerifierClient`] for the cross-source matcher.
//!
//! The engine crate (`epigraph-engine::matching::verifier`) defines the trait;
//! we cannot define this impl there because `epigraph-cli` already depends on
//! `epigraph-engine`. This module wraps [`crate::rerank::rerank_candidates_table`]
//! and harvests per-pair verdicts from the extended [`RerankSummary::per_pair_verdicts`]
//! channel (no edges written — dry-run only).
//!
//! # Rationale family
//!
//! A verifier writes exactly two kinds of string that are a *statement about
//! the pair*: the model explicitly rejected it ([`RATIONALE_REJECTED_PREFIX`]),
//! or no verifier ran at all ([`RATIONALE_COUNT_ONLY`]). Both start with
//! `verifier: ` and neither is a prefix of the other, so a
//! `WHERE verifier_rationale LIKE 'verifier: %'` sweep over `match_candidates`
//! separates them. The model's own explanation is kept after the prefix — it
//! is the most useful thing on the row.
//!
//! The invariant is that each string is **true for every path that can reach
//! it**. Rationales are read as evidence, so a precise falsehood is worse than
//! a vague truth. That is why the no-verdict placeholder below is left as the
//! deliberately vague `"verifier returned no verdict for this pair"`: several
//! very different things reach it (see [`verdicts_for_pairs`]) and any string
//! naming one of them would be false for the others. The *reasons* are
//! reported through [`crate::rerank::RerankSummary::discard_breakdown`]
//! instead, where they can be exact without being attributed to a pair that
//! did not earn them.
//!
//! [`VerifierClient`]: epigraph_engine::matching::verifier::VerifierClient
//! [`RerankSummary::per_pair_verdicts`]: crate::rerank::RerankSummary::per_pair_verdicts

use std::collections::HashMap;

use async_trait::async_trait;
use epigraph_engine::matching::verifier::{Verdict, VerifierClient};
use sqlx::PgPool;
use uuid::Uuid;

use crate::rerank::{rerank_candidates_table, PerPairVerdict, RerankConfig};

/// Placeholder for a pair the reranker returned no row for. Deliberately
/// unchanged and deliberately vague — see the module docs and
/// [`verdicts_for_pairs`].
const RATIONALE_NO_VERDICT: &str = "verifier returned no verdict for this pair";

/// The model answered and explicitly rejected the pair (`valid: false`). The
/// model's own explanation is appended, because a fixed literal here would
/// throw away the only account of *why* it was rejected.
pub const RATIONALE_REJECTED_PREFIX: &str = "verifier: model rejected pair (valid=false): ";
/// No verifier ran at all — `cross_source_sweep --count-only`.
pub const RATIONALE_COUNT_ONLY: &str = "verifier: skipped (count-only run)";

/// Wraps the Phase 7 reranker as a [`VerifierClient`].
///
/// Each `verify()` call:
/// 1. Creates a transient temp table named `matcher_verify_<uuid>` (safe
///    identifier characters only).
/// 2. Inserts the pairs, deduplicated to canonical `(min, max)` order so the
///    reranker doesn't bill us twice for `(A,B)` and `(B,A)`.
/// 3. Calls `rerank_candidates_table` with `dry_run=true`. Edges are NOT
///    written by the reranker — the matcher policy layer owns that.
/// 4. Joins the per-pair verdicts back to the input order. Pairs the LLM
///    skipped or rejected receive a `derives_from` placeholder (mapped to
///    `MatchVerdict::Distinct` upstream) so the trait contract — one verdict
///    per input pair — is preserved.
pub struct RerankBridgesClient {
    pool: PgPool,
    config: RerankConfig,
}

impl RerankBridgesClient {
    /// New client with default rerank config (dry-run forced, batch=10).
    pub fn new(pool: PgPool) -> Self {
        let config = RerankConfig {
            dry_run: true,
            ..RerankConfig::default()
        };
        Self { pool, config }
    }

    /// Override the rerank config; `dry_run` is forced to `true` regardless of
    /// what the caller passes, since edge-writing is the matcher policy's job.
    pub fn with_config(pool: PgPool, mut config: RerankConfig) -> Self {
        config.dry_run = true;
        Self { pool, config }
    }
}

#[async_trait]
impl VerifierClient for RerankBridgesClient {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Verdict>> {
        if pairs.is_empty() {
            return Ok(Vec::new());
        }

        // Canonical-order dedup before insertion: the reranker's internal
        // similarity-DESC sort is stable, but it would otherwise see (a,b)
        // and (b,a) as two distinct rows and burn tokens twice.
        let mut canon: Vec<(Uuid, Uuid)> = pairs
            .iter()
            .map(|(a, b)| if a < b { (*a, *b) } else { (*b, *a) })
            .collect();
        canon.sort_unstable();
        canon.dedup();

        let table = format!("matcher_verify_{}", Uuid::new_v4().simple());
        // CREATE TEMP TABLE is per-session, but sqlx's pool routes successive
        // .execute(&pool) calls to different connections — the temp table
        // wouldn't be visible from the connection that later runs the
        // rerank query. Use a regular table with a UUID-suffixed name
        // (still safe-identifier per find_candidates_from_table) and drop
        // it explicitly at the end.
        sqlx::query(&format!(
            "CREATE TABLE {table}
             (source_id uuid NOT NULL, target_id uuid NOT NULL)"
        ))
        .execute(&self.pool)
        .await?;

        // Always attempt to clean up the table, even if subsequent work
        // errors. Defer via a guard wouldn't help across an early-return
        // through `?`; explicit cleanup after the body is simpler.
        let result = async {
            for (a, b) in &canon {
                sqlx::query(&format!(
                    "INSERT INTO {table} (source_id, target_id) VALUES ($1, $2)"
                ))
                .bind(a)
                .bind(b)
                .execute(&self.pool)
                .await?;
            }

            rerank_candidates_table(&self.pool, &table, &self.config)
                .await
                .map_err(|e| anyhow::anyhow!(e))
        }
        .await;

        let _ = sqlx::query(&format!("DROP TABLE IF EXISTS {table}"))
            .execute(&self.pool)
            .await;

        let summary = result?;

        Ok(verdicts_for_pairs(pairs, &summary.per_pair_verdicts))
    }
}

fn canonical(a: Uuid, b: Uuid) -> (Uuid, Uuid) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
}

/// Align reranker output back to the caller's pair list, one [`Verdict`] each.
///
/// Split out of [`RerankBridgesClient::verify`] so the mapping — the part that
/// decides what rationale a pair ends up carrying into
/// `match_candidates.verifier_rationale` — is testable without a database or a
/// live LLM.
///
/// Pairs the verifier could not endorse receive a `derives_from` placeholder
/// (mapped to `MatchVerdict::Distinct` upstream) so the trait contract — one
/// verdict per input pair — is preserved.
///
/// # Why the no-row placeholder stays vague
///
/// At least four unrelated things land a pair here with no row from the
/// reranker, and none of them is a finding about the pair:
/// the batch's LLM call failed outright (`rerank::core::rerank_inner`'s
/// `call_llm_with_retry` `Err` arm `continue`s before any parsing); the model
/// answered and omitted the pair; the model's entry for it was discarded; or
/// the pair never reached the model at all, because
/// `rerank::core::find_candidates_from_table` drops pairs already connected by
/// an edge in either direction while `matching::pipeline::run_pipeline`
/// applies no such filter — so on a re-run the highest-scoring pairs are
/// systematically absent. Naming any one of those here would write a precise
/// falsehood into an evidence column for the other three. The reasons are
/// reported as counts through
/// [`crate::rerank::RerankSummary::discard_breakdown`] instead.
pub fn verdicts_for_pairs(
    pairs: &[(Uuid, Uuid)],
    per_pair_verdicts: &[PerPairVerdict],
) -> Vec<Verdict> {
    // Index verdicts by canonical pair so we can re-align to caller order.
    let mut by_pair: HashMap<(Uuid, Uuid), &PerPairVerdict> = HashMap::new();
    for v in per_pair_verdicts {
        by_pair.insert(canonical(v.source_id, v.target_id), v);
    }

    pairs
        .iter()
        .map(|(a, b)| {
            let key = canonical(*a, *b);
            let Some(per_pair) = by_pair.get(&key) else {
                return Verdict {
                    source_id: *a,
                    target_id: *b,
                    relationship: "derives_from".to_string(),
                    strength: 0.0,
                    rationale: RATIONALE_NO_VERDICT.to_string(),
                };
            };
            if !per_pair.valid {
                return Verdict {
                    source_id: *a,
                    target_id: *b,
                    relationship: "derives_from".to_string(),
                    strength: per_pair.strength.unwrap_or(0.0) as f32,
                    // Prefix rather than replace: the model's own account of
                    // why it rejected the pair is the most useful thing on the
                    // row, and discarding it in a change about diagnosability
                    // would be self-defeating.
                    rationale: format!("{RATIONALE_REJECTED_PREFIX}{}", per_pair.rationale),
                };
            }
            Verdict {
                source_id: *a,
                target_id: *b,
                relationship: per_pair
                    .relationship
                    .clone()
                    .unwrap_or_else(|| "analogous".to_string()),
                strength: per_pair.strength.unwrap_or(0.5) as f32,
                rationale: per_pair.rationale.clone(),
            }
        })
        .collect()
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rerank::candidates::CandidatePair;
    use crate::rerank::core::{interpret_batch_response, interpret_failed_batch};
    use crate::rerank::RerankSummary;

    fn candidate(tag: &str) -> CandidatePair {
        CandidatePair {
            source_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            source_content: format!("{tag}-source"),
            target_content: format!("{tag}-target"),
            source_doi: None,
            target_doi: None,
            similarity: 0.5,
        }
    }

    /// Accumulate batches into a `RerankSummary` the way `rerank_inner` does,
    /// so the tests read the same struct a production caller reads.
    fn summarize(batches: Vec<crate::rerank::core::BatchInterpretation>) -> RerankSummary {
        let mut s = RerankSummary::default();
        for b in batches {
            s.errors += b.unanswered.len();
            s.per_pair_verdicts.extend(b.verdicts);
            s.per_pair_discards.extend(b.discards);
        }
        s
    }

    /// The headline defect, at the level where it is actually observable.
    ///
    /// A batch whose LLM call failed outright and a pair the model answered
    /// about and omitted are completely different events — one means the
    /// verifier never ran, the other means it ran and had nothing to say — and
    /// they call for opposite operator responses. Before this change both
    /// showed up as nothing but `+1 errors`, so a run reporting `errors: 300`
    /// could be one dead API key or three hundred genuinely-silent pairs and
    /// there was no way to tell.
    #[test]
    fn failed_llm_call_and_model_silence_are_distinguishable_in_the_summary() {
        let call_failed = candidate("call-failed");
        let silent = candidate("silent");

        let s = summarize(vec![
            interpret_failed_batch(std::slice::from_ref(&call_failed)),
            // Well-formed empty array: the model answered and named nobody.
            interpret_batch_response(std::slice::from_ref(&silent), &serde_json::json!([])),
        ]);

        assert_eq!(s.errors, 2, "both pairs are still counted as errors");
        let breakdown = s.discard_breakdown();
        assert_eq!(
            breakdown,
            [("the LLM call for this batch failed", 1)]
                .into_iter()
                .collect(),
            "a failed call must be named, and model silence must NOT be — the \
             absence of a reason is what marks genuine silence"
        );
    }

    /// The other bypass the reverted PR #381 got wrong. An out-of-vocabulary
    /// relationship is a real model answer we threw away; silence is not. Both
    /// used to be a bare `continue` plus `+1 errors`.
    #[test]
    fn discarded_entry_and_model_silence_are_distinguishable_in_the_summary() {
        let silent = candidate("silent");
        let oov = candidate("oov");
        let batch = vec![silent.clone(), oov.clone()];
        let json = serde_json::json!([
            {"pair_index": 1, "valid": true, "relationship": "causes",
             "strength": 0.7, "rationale": "A causes B"}
        ]);

        let s = summarize(vec![interpret_batch_response(&batch, &json)]);

        assert_eq!(s.errors, 2);
        assert_eq!(s.per_pair_discards.len(), 1, "only the discarded pair");
        assert_eq!(s.per_pair_discards[0].source_id, oov.source_id);
        assert_eq!(
            s.discard_breakdown(),
            [(
                "this pair's relationship was outside the accepted vocabulary",
                1
            )]
            .into_iter()
            .collect()
        );
    }

    /// An explicit `valid: false` is the model doing its job — a real verdict,
    /// still persisted after the Defect B fix lands. The prefix makes it
    /// separable from the machine placeholder in a `verifier_rationale` sweep;
    /// the model's own text is what makes the row useful, so it is kept.
    #[test]
    fn explicit_rejection_is_prefixed_and_keeps_the_models_own_reason() {
        let batch = vec![candidate("rejected")];
        let json = serde_json::json!([
            {"pair_index": 0, "valid": false, "relationship": null, "strength": null,
             "rationale": "shared vocabulary only"}
        ]);
        let s = summarize(vec![interpret_batch_response(&batch, &json)]);
        let ids: Vec<(Uuid, Uuid)> = batch.iter().map(|p| (p.source_id, p.target_id)).collect();

        let v = verdicts_for_pairs(&ids, &s.per_pair_verdicts);

        assert_eq!(
            v[0].rationale,
            format!("{RATIONALE_REJECTED_PREFIX}shared vocabulary only")
        );
        assert_ne!(
            v[0].rationale, RATIONALE_NO_VERDICT,
            "an explicit rejection must not read like a missing verdict"
        );
        // Unchanged: this is still Distinct → Reject. This PR does not alter
        // any polarity.
        assert_eq!(v[0].relationship, "derives_from");
    }

    /// A pair the reranker returned no row for keeps the historical, vague —
    /// but true — placeholder. Pinning a specific cause here is what got
    /// PR #381 reverted.
    #[test]
    fn a_pair_with_no_row_keeps_the_deliberately_vague_placeholder() {
        let batch = vec![candidate("silent")];
        let s = summarize(vec![interpret_batch_response(
            &batch,
            &serde_json::json!([]),
        )]);
        let ids: Vec<(Uuid, Uuid)> = batch.iter().map(|p| (p.source_id, p.target_id)).collect();

        let v = verdicts_for_pairs(&ids, &s.per_pair_verdicts);

        assert_eq!(v[0].rationale, RATIONALE_NO_VERDICT);
    }

    /// The two strings this module deliberately writes must be greppable as a
    /// family and unambiguous by prefix.
    #[test]
    fn rationale_family_shares_a_prefix_and_no_member_prefixes_another() {
        let family = [RATIONALE_REJECTED_PREFIX, RATIONALE_COUNT_ONLY];
        for s in family {
            assert!(s.starts_with("verifier: "), "{s:?} is outside the family");
        }
        for (i, a) in family.iter().enumerate() {
            for (j, b) in family.iter().enumerate() {
                if i != j {
                    assert!(!a.starts_with(b), "{a:?} is prefixed by {b:?}");
                }
            }
        }
        // The legacy placeholder is deliberately NOT in the family: it must
        // stay distinguishable from the strings that assert something.
        assert!(!RATIONALE_NO_VERDICT.starts_with("verifier: "));
    }
}
