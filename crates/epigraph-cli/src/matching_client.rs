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
        // The safe-identifier check inside rerank::core::find_candidates_from_table
        // (alphanumeric + underscore) will accept this since `simple()` strips
        // hyphens.
        sqlx::query(&format!(
            "CREATE TEMP TABLE {table}
             (source_id uuid NOT NULL, target_id uuid NOT NULL)
             ON COMMIT DROP"
        ))
        .execute(&self.pool)
        .await?;

        for (a, b) in &canon {
            sqlx::query(&format!(
                "INSERT INTO {table} (source_id, target_id) VALUES ($1, $2)"
            ))
            .bind(a)
            .bind(b)
            .execute(&self.pool)
            .await?;
        }

        let summary = rerank_candidates_table(&self.pool, &table, &self.config)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        // Index verdicts by canonical pair so we can re-align to caller order.
        let mut by_pair: HashMap<(Uuid, Uuid), PerPairVerdict> = HashMap::new();
        for v in summary.per_pair_verdicts {
            let key = if v.source_id < v.target_id {
                (v.source_id, v.target_id)
            } else {
                (v.target_id, v.source_id)
            };
            by_pair.insert(key, v);
        }

        // Map each input pair to a Verdict. Missing/invalid verdicts get a
        // safe `derives_from` placeholder which the engine maps to
        // MatchVerdict::Distinct (i.e. Reject).
        Ok(pairs
            .iter()
            .map(|(a, b)| {
                let key = if a < b { (*a, *b) } else { (*b, *a) };
                let placeholder = || Verdict {
                    source_id: *a,
                    target_id: *b,
                    relationship: "derives_from".to_string(),
                    strength: 0.0,
                    rationale: "verifier returned no verdict for this pair".to_string(),
                };
                let Some(per_pair) = by_pair.get(&key) else {
                    return placeholder();
                };
                if !per_pair.valid {
                    return Verdict {
                        source_id: *a,
                        target_id: *b,
                        relationship: "derives_from".to_string(),
                        strength: per_pair.strength.unwrap_or(0.0) as f32,
                        rationale: per_pair.rationale.clone(),
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
            .collect())
    }
}
