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
//! Every string a verifier writes for a pair it could not endorse starts with
//! `verifier: ` and no member is a prefix of another, so one
//! `WHERE verifier_rationale LIKE 'verifier: %'` plus a prefix breakdown
//! separates the failure modes on `match_candidates`. Before this, model
//! silence, an unparseable entry, a `pair_index` outside the batch, an
//! out-of-vocabulary relationship and an out-of-range strength all wrote the
//! single string `"verifier returned no verdict for this pair"` — which is why
//! ~1.7k rows carrying it cannot be told apart. See [`RATIONALE_NO_ENTRY`],
//! [`RATIONALE_REJECTED_PREFIX`], [`RATIONALE_UNPARSEABLE_PREFIX`] and
//! [`RATIONALE_COUNT_ONLY`].
//!
//! [`VerifierClient`]: epigraph_engine::matching::verifier::VerifierClient
//! [`RerankSummary::per_pair_verdicts`]: crate::rerank::RerankSummary::per_pair_verdicts

use std::collections::HashMap;

use async_trait::async_trait;
use epigraph_engine::matching::verifier::{Verdict, VerifierClient};
use sqlx::PgPool;
use uuid::Uuid;

use crate::rerank::{rerank_candidates_table, PerPairDiscard, PerPairVerdict, RerankConfig};

/// The model was silent about this pair — no entry at all in the response.
pub const RATIONALE_NO_ENTRY: &str = "verifier: model returned no entry for pair";
/// The model answered and explicitly rejected the pair (`valid: false`). The
/// model's own explanation is appended, because a fixed literal here would
/// throw away the only account of *why* it was rejected.
pub const RATIONALE_REJECTED_PREFIX: &str = "verifier: model rejected pair (valid=false): ";
/// The model produced an entry that never survived parsing/validation. The
/// specific [`crate::rerank::DiscardReason`] is appended in parentheses.
pub const RATIONALE_UNPARSEABLE_PREFIX: &str = "verifier: response unparseable for pair";
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

        Ok(verdicts_for_pairs(
            pairs,
            &summary.per_pair_verdicts,
            &summary.per_pair_discards,
        ))
    }
}

/// Align reranker verdicts back to the caller's pair list.
///
/// Split out of [`RerankBridgesClient::verify`] so the mapping — the part
/// that decides what rationale a pair ends up carrying into
/// `match_candidates.verifier_rationale` — is testable without a database or
/// a live LLM.
///
/// Pairs the LLM skipped or rejected receive a `derives_from` placeholder
/// (mapped to `MatchVerdict::Distinct` upstream) so the trait contract — one
/// verdict per input pair — is preserved.
pub(crate) fn verdicts_for_pairs(
    pairs: &[(Uuid, Uuid)],
    per_pair_verdicts: &[PerPairVerdict],
    per_pair_discards: &[PerPairDiscard],
) -> Vec<Verdict> {
    fn canonical(a: Uuid, b: Uuid) -> (Uuid, Uuid) {
        if a < b {
            (a, b)
        } else {
            (b, a)
        }
    }

    // Index verdicts by canonical pair so we can re-align to caller order.
    let mut by_pair: HashMap<(Uuid, Uuid), &PerPairVerdict> = HashMap::new();
    for v in per_pair_verdicts {
        by_pair.insert(canonical(v.source_id, v.target_id), v);
    }
    // Same for the pairs whose entry the parser threw away — this is what
    // separates "the model said something we could not use" from "the model
    // said nothing".
    let mut by_discard: HashMap<(Uuid, Uuid), &PerPairDiscard> = HashMap::new();
    for d in per_pair_discards {
        by_discard.insert(canonical(d.source_id, d.target_id), d);
    }

    pairs
        .iter()
        .map(|(a, b)| {
            let key = canonical(*a, *b);
            let no_verdict = |rationale: String| Verdict {
                source_id: *a,
                target_id: *b,
                relationship: "derives_from".to_string(),
                strength: 0.0,
                rationale,
            };
            let Some(per_pair) = by_pair.get(&key) else {
                return match by_discard.get(&key) {
                    Some(d) => no_verdict(format!(
                        "{RATIONALE_UNPARSEABLE_PREFIX} ({})",
                        d.reason.as_str()
                    )),
                    None => no_verdict(RATIONALE_NO_ENTRY.to_string()),
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
    use crate::rerank::core::interpret_batch_response;

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

    /// Drive the real path a batch takes: parse the raw model response,
    /// attribute the entries back to their pairs, then map to `Verdict`s
    /// exactly as `RerankBridgesClient::verify` does. Returns one rationale per
    /// input pair, in input order — i.e. the strings that reach
    /// `match_candidates.verifier_rationale`.
    fn rationales(batch: &[CandidatePair], json: serde_json::Value) -> Vec<String> {
        let interpretation = interpret_batch_response(batch, &json);
        let ids: Vec<(Uuid, Uuid)> = batch.iter().map(|p| (p.source_id, p.target_id)).collect();
        verdicts_for_pairs(&ids, &interpretation.verdicts, &interpretation.discards)
            .into_iter()
            .map(|v| v.rationale)
            .collect()
    }

    /// The instrument this change exists for: an out-of-vocabulary relationship
    /// is discarded by `parse_validation_response`, so the pair reaches the
    /// verdict mapper with no entry — exactly like a pair the model never
    /// mentioned. If both land the same rationale, no query over
    /// `match_candidates.verifier_rationale` can tell whether the model ever
    /// emitted a category outside `VALID_RELATIONSHIPS`.
    #[test]
    fn model_silence_and_out_of_vocabulary_relationship_get_different_rationales() {
        let batch = vec![candidate("silent"), candidate("oov")];
        // Pair 0: no entry at all. Pair 1: answered, but with a relationship
        // outside VALID_RELATIONSHIPS.
        let json = serde_json::json!([
            {
                "pair_index": 1,
                "valid": true,
                "relationship": "causes",
                "strength": 0.7,
                "rationale": "A causes B"
            }
        ]);

        let r = rationales(&batch, json);

        assert_ne!(
            r[0], r[1],
            "model silence and an out-of-vocabulary relationship must not share \
             a rationale; both produced {:?}",
            r[0]
        );
        assert_eq!(r[0], RATIONALE_NO_ENTRY);
        assert_eq!(
            r[1],
            "verifier: response unparseable for pair (relationship outside the accepted vocabulary)"
        );
    }

    /// The four ways a pair can fail to get a usable verdict must produce four
    /// different strings in one batch — otherwise the counts are meaningless.
    #[test]
    fn every_no_verdict_failure_mode_produces_a_distinct_rationale() {
        let batch = vec![
            candidate("silent"),
            candidate("rejected"),
            candidate("oov"),
            candidate("strength"),
        ];
        let json = serde_json::json!([
            // pair 0 omitted entirely — model silence.
            {"pair_index": 1, "valid": false, "relationship": null, "strength": null,
             "rationale": "shared vocabulary only"},
            {"pair_index": 2, "valid": true, "relationship": "causes",
             "strength": 0.7, "rationale": "A causes B"},
            {"pair_index": 3, "valid": true, "relationship": "supports",
             "strength": 1.5, "rationale": "very strong"},
        ]);

        let r = rationales(&batch, json);

        let unique: std::collections::HashSet<&String> = r.iter().collect();
        assert_eq!(unique.len(), 4, "expected 4 distinct rationales, got {r:?}");

        assert_eq!(r[0], RATIONALE_NO_ENTRY);
        // Explicit rejection keeps the model's own reason appended — the
        // prefix is what makes it groupable, the tail is what makes it useful.
        assert_eq!(
            r[1],
            format!("{RATIONALE_REJECTED_PREFIX}shared vocabulary only")
        );
        // Exact, not `contains`: these are the strings prod analysts will
        // group on, so a reword has to break a test rather than silently
        // orphan historical rows.
        assert_eq!(
            r[2],
            "verifier: response unparseable for pair (relationship outside the accepted vocabulary)"
        );
        assert_eq!(
            r[3],
            "verifier: response unparseable for pair (strength outside [0.3, 1.0])"
        );
    }

    /// A response that is not a JSON array damages the whole batch. Every pair
    /// should say so — and say only that, not a fabricated per-pair cause.
    #[test]
    fn non_array_response_reports_batch_wide_damage_for_every_pair() {
        let batch = vec![candidate("a"), candidate("b")];
        let r = rationales(&batch, serde_json::json!({"error": "model refused"}));

        for rationale in &r {
            assert_eq!(
                *rationale,
                "verifier: response unparseable for pair (response was not a JSON array)"
            );
        }
    }

    /// An entry too broken to carry a `pair_index` tells us the batch is
    /// damaged but not which pair. The rationale must admit that rather than
    /// blame a pair we cannot identify.
    #[test]
    fn unattributable_parse_failure_does_not_fabricate_a_pair() {
        let batch = vec![candidate("a"), candidate("b")];
        let json = serde_json::json!([
            {"garbage": true},
            {"pair_index": 1, "valid": true, "relationship": "supports",
             "strength": 0.8, "rationale": "genuine link"},
        ]);

        let r = rationales(&batch, json);

        assert_eq!(
            r[0],
            "verifier: response unparseable for pair \
             (an entry in this batch was unparseable and could not be attributed to a pair)"
        );
        // Pair 1 answered cleanly and keeps the model's rationale verbatim.
        assert_eq!(r[1], "genuine link");
    }

    /// The family only works as an instrument if a `LIKE 'verifier: %'` sweep
    /// can be split by prefix without ambiguity.
    #[test]
    fn rationale_family_shares_a_prefix_and_no_member_prefixes_another() {
        let family = [
            RATIONALE_NO_ENTRY,
            RATIONALE_REJECTED_PREFIX,
            RATIONALE_UNPARSEABLE_PREFIX,
            RATIONALE_COUNT_ONLY,
        ];
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
    }
}
