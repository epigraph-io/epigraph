//! `mcp__epigraph__suggest_alternative_sets` — surface candidate
//! `alternative_of` pairs by finding `contradicts` edges between supporters of
//! a shared target.
//!
//! Pure suggestion: the operator promotes a pair by submitting an explicit
//! `alternative_of` edge. Auto-promotion would risk false positives (two
//! claims that contradict each other on a different axis may still both be
//! valid independent supporters of T).
//!
//! v1 keeps the candidate-finder SQL inline rather than threading it through
//! `epigraph-db` repos because the cross-supporter / dual-relationship
//! heuristic has no existing repo equivalent; promote to a repo helper if a
//! second caller ever appears.

use rmcp::model::{CallToolResult, Content};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::{internal_error, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

fn default_min_strength() -> f64 {
    0.5
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SuggestAlternativeSetsParams {
    /// Restrict suggestions to candidate pairs that both support this target.
    /// Omit to scan the whole graph.
    pub target_claim_id: Option<String>,

    /// Minimum `min(BetP_a, BetP_b)` to surface a candidate. Default `0.5`.
    #[serde(default = "default_min_strength")]
    pub min_pair_strength: f64,
}

#[derive(Debug, Serialize)]
pub struct SuggestedAlternativePair {
    pub claim_a: Uuid,
    pub claim_b: Uuid,
    pub target_claim: Uuid,
    pub score: f64,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct SuggestAlternativeSetsResponse {
    pub candidates: Vec<SuggestedAlternativePair>,
}

pub async fn suggest_alternative_sets(
    server: &EpiGraphMcpFull,
    params: SuggestAlternativeSetsParams,
) -> Result<CallToolResult, McpError> {
    let target_filter = match params.target_claim_id.as_deref() {
        Some(s) => Some(parse_uuid(s)?),
        None => None,
    };
    let min_strength = params.min_pair_strength.clamp(0.0, 1.0);

    let candidates = scan_candidates(&server.pool, target_filter, min_strength)
        .await
        .map_err(internal_error)?;

    success_json(&SuggestAlternativeSetsResponse { candidates })
}

/// Find pairs `(A, B)` such that
/// - both `A` and `B` have a `supports` edge to a common target `T`,
/// - there exists a `contradicts` edge between `A` and `B` in either direction,
/// - no explicit `alternative_of` edge between `A` and `B` already exists, and
/// - `min(BetP_A, BetP_B) >= min_strength`.
///
/// Pairs are de-duplicated symmetrically with `s1.source_id < s2.source_id`
/// in the WHERE clause; the SELECT's `LEAST`/`GREATEST` keep the returned
/// `(claim_a, claim_b)` ordering canonical even if the upstream invariant
/// ever drifts. Ordered by `score DESC`, capped at 200 rows per call.
async fn scan_candidates(
    pool: &PgPool,
    target_filter: Option<Uuid>,
    min_strength: f64,
) -> Result<Vec<SuggestedAlternativePair>, sqlx::Error> {
    let rows: Vec<(Uuid, Uuid, Uuid, f64)> = sqlx::query_as(
        r#"
        SELECT
            LEAST(s1.source_id, s2.source_id)   AS claim_a,
            GREATEST(s1.source_id, s2.source_id) AS claim_b,
            s1.target_id                         AS target_claim,
            LEAST(
                COALESCE(ca.pignistic_prob, 0.0),
                COALESCE(cb.pignistic_prob, 0.0)
            ) AS score
        FROM edges s1
        JOIN edges s2
          ON s2.target_id = s1.target_id
         AND s2.relationship = 'supports'
         AND s2.source_id <> s1.source_id
        JOIN edges contr
          ON ((contr.source_id = s1.source_id AND contr.target_id = s2.source_id)
            OR (contr.source_id = s2.source_id AND contr.target_id = s1.source_id))
         AND contr.relationship = 'contradicts'
        JOIN claims ca ON ca.id = s1.source_id
        JOIN claims cb ON cb.id = s2.source_id
        LEFT JOIN edges existing
          ON existing.relationship = 'alternative_of'
         AND ((existing.source_id = s1.source_id AND existing.target_id = s2.source_id)
           OR (existing.source_id = s2.source_id AND existing.target_id = s1.source_id))
        WHERE s1.relationship = 'supports'
          AND s1.source_id < s2.source_id  -- symmetric self-join dedup
          AND ($1::uuid IS NULL OR s1.target_id = $1)
          AND existing.id IS NULL
          AND LEAST(
                COALESCE(ca.pignistic_prob, 0.0),
                COALESCE(cb.pignistic_prob, 0.0)
              ) >= $2
        ORDER BY score DESC
        LIMIT 200
        "#,
    )
    .bind(target_filter)
    .bind(min_strength)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(a, b, t, score)| SuggestedAlternativePair {
            claim_a: a,
            claim_b: b,
            target_claim: t,
            score,
            reason: format!("contradicts edge between supporters of {t}"),
        })
        .collect())
}
