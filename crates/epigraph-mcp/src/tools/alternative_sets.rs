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

fn default_exclude_settled() -> bool {
    true
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SuggestAlternativeSetsParams {
    /// Restrict suggestions to candidate pairs that both support this target.
    /// Omit to scan the whole graph.
    pub target_claim_id: Option<String>,

    /// Minimum `min(BetP_a, BetP_b)` to surface a candidate. Default `0.5`.
    #[serde(default = "default_min_strength")]
    pub min_pair_strength: f64,

    /// Drop candidate pairs whose members are already labelled alt-chosen or
    /// alt-rejected (settled). Default true — settled pairs are not useful
    /// suggestions. Set false to surface everything (pre-PR behavior).
    #[serde(default = "default_exclude_settled")]
    pub exclude_settled: bool,

    /// Surface pairs where one member is alt-rejected and the rival has BetP
    /// higher by at least `min_pair_strength`. Useful for reconsidering
    /// previously-rejected pathways when a stronger alternative appears.
    /// Default false — opt-in only.
    #[serde(default)]
    pub surface_reconsiderations: bool,
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

    let candidates = scan_candidates(
        &server.pool,
        target_filter,
        min_strength,
        params.exclude_settled,
        params.surface_reconsiderations,
    )
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
    exclude_settled: bool,
    surface_reconsiderations: bool,
) -> Result<Vec<SuggestedAlternativePair>, sqlx::Error> {
    let rows: Vec<(Uuid, Uuid, Uuid, f64, String)> = sqlx::query_as(
        r#"
        WITH base AS (
            SELECT
                LEAST(s1.source_id, s2.source_id)    AS claim_a,
                GREATEST(s1.source_id, s2.source_id) AS claim_b,
                s1.target_id                         AS target_claim,
                LEAST(
                    COALESCE(ca.pignistic_prob, 0.0),
                    COALESCE(cb.pignistic_prob, 0.0)
                ) AS score,
                COALESCE(ca.pignistic_prob, 0.0) AS bp_a,
                COALESCE(cb.pignistic_prob, 0.0) AS bp_b,
                COALESCE(ca.labels, ARRAY[]::text[]) AS labels_a,
                COALESCE(cb.labels, ARRAY[]::text[]) AS labels_b
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
              AND s1.source_id < s2.source_id
              AND ($1::uuid IS NULL OR s1.target_id = $1)
              AND existing.id IS NULL
        )
        SELECT
            claim_a, claim_b, target_claim, score,
            CASE
                WHEN $4 AND ('alt-rejected' = ANY(labels_a) OR 'alt-rejected' = ANY(labels_b))
                  THEN format(
                      'reconsider: one supporter is alt-rejected; rivals'' BetPs are %s and %s',
                      bp_a::text, bp_b::text)
                ELSE format('contradicts edge between supporters of %s', target_claim::text)
            END AS reason
        FROM base
        WHERE
            -- Pure heuristic gate: at least one supporter has BetP >= threshold
            score >= $2
            -- Exclusion of settled pairs (chosen/rejected) when exclude_settled = true,
            -- unless surface_reconsiderations is on and exactly one member is alt-rejected
            -- with a sufficient BetP gap to its rival.
            AND (
                NOT $3                     -- if exclude_settled is false, accept everything past score
                OR (
                    NOT ('alt-chosen'   = ANY(labels_a) OR 'alt-chosen'   = ANY(labels_b))
                    AND (
                        NOT ('alt-rejected' = ANY(labels_a) OR 'alt-rejected' = ANY(labels_b))
                        OR (
                            $4  -- surface_reconsiderations
                            AND (
                                -- exactly-one rejected
                                ('alt-rejected' = ANY(labels_a)) <> ('alt-rejected' = ANY(labels_b))
                            )
                            AND abs(bp_a - bp_b) >= $2
                        )
                    )
                )
            )
        ORDER BY score DESC
        LIMIT 200
        "#,
    )
    .bind(target_filter)
    .bind(min_strength)
    .bind(exclude_settled)
    .bind(surface_reconsiderations)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(a, b, t, score, reason)| SuggestedAlternativePair {
            claim_a: a,
            claim_b: b,
            target_claim: t,
            score,
            reason,
        })
        .collect())
}
