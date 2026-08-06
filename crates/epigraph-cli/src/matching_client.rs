//! Production [`VerifierClient`] for the cross-source matcher.
//!
//! The engine crate (`epigraph-engine::matching::verifier`) defines the trait;
//! we cannot define this impl there because `epigraph-cli` already depends on
//! `epigraph-engine`. This module wraps [`crate::rerank::rerank_candidates_table`]
//! and harvests per-pair verdicts from the extended [`RerankSummary::per_pair_verdicts`]
//! channel (no edges written — dry-run only).
//!
//! [`VerifierClient`]: epigraph_engine::matching::verifier::VerifierClient
//! [`RerankSummary::per_pair_verdicts`]: crate::rerank::RerankSummary::per_pair_verdicts

use std::collections::HashMap;

use async_trait::async_trait;
use epigraph_engine::matching::verifier::{Verdict, VerifierClient};
use sqlx::PgPool;
use uuid::Uuid;

use crate::rerank::{rerank_candidates_table, PerPairVerdict, RerankConfig};

/// Wraps the Phase 7 reranker as a [`VerifierClient`].
///
/// Each `verify()` call:
/// 1. Creates a transient temp table named `matcher_verify_<uuid>` (safe
///    identifier characters only).
/// 2. Inserts the pairs, deduplicated to canonical `(min, max)` order so the
///    reranker doesn't bill us twice for `(A,B)` and `(B,A)`.
/// 3. Calls `rerank_candidates_table` with `dry_run=true`. Edges are NOT
///    written by the reranker — the matcher policy layer owns that.
/// 4. Joins the per-pair verdicts back to the input order via
///    [`align_verdicts`]. Pairs the reranker returned no row for yield `None`
///    ("no answer"), which the pipeline skips; the LLM's own `valid: false`
///    rejections are a real answer and still map to `derives_from`.
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

/// Join the reranker's per-pair output back onto the caller's pair list,
/// preserving order and the one-slot-per-input-pair contract.
///
/// `None` is returned for any pair the reranker produced **no row** for. That
/// is the verifier saying *"I have no answer"*, and it must stay distinct from
/// every verdict value. Three different upstream paths land here and none of
/// them is a finding about the pair:
///
/// - the model answered the batch but omitted this pair
///   ([`crate::rerank::prompt::parse_validation_response`] drops unattributable
///   entries),
/// - the batch's LLM call failed outright — `rerank::core::rerank_inner`'s
///   `call_llm_with_retry` `Err` arm bumps `summary.errors` and `continue`s, so
///   every pair in that batch is absent,
/// - the pair never reached the model at all —
///   `rerank::core::find_candidates_from_table` filters out pairs already
///   connected by any edge in either direction (and anything without an
///   embedding), while the matcher pipeline applies no such filter, so on a
///   re-run the highest-scoring pairs are systematically absent.
///
/// Because a `None` causes the pipeline to write nothing, we do not have to
/// tell those three apart — which matters, since PR #381 tried to and shipped a
/// rationale string that asserted "the model returned no entry" for pairs the
/// model was demonstrably never asked about.
///
/// `valid: false` is the opposite case: the model *did* answer and said the
/// pair is not a real bridge. That keeps the `derives_from` mapping (→
/// `MatchVerdict::Distinct` → Reject) it has always had.
pub fn align_verdicts(
    pairs: &[(Uuid, Uuid)],
    per_pair_verdicts: Vec<PerPairVerdict>,
) -> Vec<Option<Verdict>> {
    // Index verdicts by canonical pair so we can re-align to caller order.
    let mut by_pair: HashMap<(Uuid, Uuid), PerPairVerdict> = HashMap::new();
    for v in per_pair_verdicts {
        let key = if v.source_id < v.target_id {
            (v.source_id, v.target_id)
        } else {
            (v.target_id, v.source_id)
        };
        by_pair.insert(key, v);
    }

    pairs
        .iter()
        .map(|(a, b)| {
            let key = if a < b { (*a, *b) } else { (*b, *a) };
            // No row from the reranker => no answer. Do NOT fabricate one.
            let per_pair = by_pair.get(&key)?;
            if !per_pair.valid {
                return Some(Verdict {
                    source_id: *a,
                    target_id: *b,
                    relationship: "derives_from".to_string(),
                    strength: per_pair.strength.unwrap_or(0.0) as f32,
                    rationale: per_pair.rationale.clone(),
                });
            }
            Some(Verdict {
                source_id: *a,
                target_id: *b,
                relationship: per_pair
                    .relationship
                    .clone()
                    .unwrap_or_else(|| "analogous".to_string()),
                strength: per_pair.strength.unwrap_or(0.5) as f32,
                rationale: per_pair.rationale.clone(),
            })
        })
        .collect()
}

#[async_trait]
impl VerifierClient for RerankBridgesClient {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Option<Verdict>>> {
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

        Ok(align_verdicts(pairs, summary.per_pair_verdicts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn per_pair(a: Uuid, b: Uuid, valid: bool) -> PerPairVerdict {
        PerPairVerdict {
            source_id: a,
            target_id: b,
            valid,
            relationship: valid.then(|| "supports".to_string()),
            strength: Some(0.9),
            rationale: "model spoke".to_string(),
        }
    }

    /// THE regression guard for defect B: a pair the reranker produced no row
    /// for must come back as `None`, not as a synthetic verdict. Before this,
    /// the miss returned `derives_from`/0.0, which `map_relationship` sends to
    /// `MatchVerdict::Distinct` → Reject → `patch_verdict('distinct')`.
    #[test]
    fn a_pair_the_reranker_did_not_answer_on_yields_no_verdict() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let out = align_verdicts(&[(a, b)], Vec::new());
        assert_eq!(out.len(), 1, "one slot per input pair");
        assert!(
            out[0].is_none(),
            "silence must not be laundered into a verdict, got {:?}",
            out[0]
        );
    }

    /// The complement: an explicit `valid: false` IS an answer — the model was
    /// asked and said no. Skipping those too would throw away real rejections.
    #[test]
    fn an_explicit_llm_rejection_is_still_a_verdict() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let out = align_verdicts(&[(a, b)], vec![per_pair(a, b, false)]);
        let v = out[0]
            .as_ref()
            .expect("valid:false is an answer, not silence");
        assert_eq!(v.relationship, "derives_from");
        assert_eq!(v.rationale, "model spoke");
    }

    /// Alignment is by canonical pair, so a verdict reported in the opposite
    /// orientation still matches — and every input slot is filled, silent or
    /// not, so the pipeline's length check cannot be tripped by a `None`.
    #[test]
    fn alignment_is_orientation_independent_and_positional() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        // Answer only for the (a,b) pair, reported as (b,a).
        let out = align_verdicts(&[(a, c), (a, b)], vec![per_pair(b, a, true)]);
        assert_eq!(out.len(), 2);
        assert!(out[0].is_none(), "unanswered pair keeps its slot as None");
        let v = out[1]
            .as_ref()
            .expect("reversed-orientation answer must match");
        assert_eq!(v.relationship, "supports");
        assert_eq!(
            (v.source_id, v.target_id),
            (a, b),
            "caller's orientation is preserved"
        );
    }
}
