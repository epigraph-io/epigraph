//! `mcp__epigraph__suggest_alternative_sets` — surface candidate
//! `alternative_of` pairs by finding `contradicts` edges between supporters of
//! a shared target.
//!
//! Pure suggestion: the operator promotes a pair by submitting an explicit
//! `alternative_of` edge. Auto-promotion would risk false positives (two
//! claims that contradict each other on a different axis may still both be
//! valid independent supporters of T).
//!
//! PR-09 moved the candidate-finder SQL to
//! `epigraph_db::AlternativeSetRepository::scan_candidates`. The previous note
//! here said it would move "if a second caller ever appears"; the actual rule
//! (CLAUDE.md) has no such condition, and the statement was reading
//! `pignistic_prob`, `labels` and claim ids corpus-wide with no `Viewer` in
//! scope. It is now viewer-scoped on all three claims in a candidate.

use rmcp::model::{CallToolResult, Content};
use serde::{Deserialize, Serialize};
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
    viewer: &epigraph_db::visibility::Viewer,
    params: SuggestAlternativeSetsParams,
) -> Result<CallToolResult, McpError> {
    let target_filter = match params.target_claim_id.as_deref() {
        Some(s) => Some(parse_uuid(s)?),
        None => None,
    };
    let min_strength = params.min_pair_strength.clamp(0.0, 1.0);

    let candidates = epigraph_db::AlternativeSetRepository::scan_candidates(
        &server.pool,
        viewer,
        target_filter,
        min_strength,
        params.exclude_settled,
        params.surface_reconsiderations,
    )
    .await
    .map_err(internal_error)?
    .into_iter()
    .map(|r| SuggestedAlternativePair {
        claim_a: r.claim_a,
        claim_b: r.claim_b,
        target_claim: r.target_claim,
        score: r.score,
        reason: r.reason,
    })
    .collect();

    success_json(&SuggestAlternativeSetsResponse { candidates })
}
