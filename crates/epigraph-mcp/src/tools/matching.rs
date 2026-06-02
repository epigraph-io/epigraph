//! MCP tools for the cross-source matcher (T19).
//!
//! Three read-or-decide tools — no pipeline invocation here. The actual
//! matching runs in the `cross_source_sweep` CLI batch job; MCP exposes the
//! review surface:
//!
//! - `find_cross_source_matches`: return existing match_candidates + CORROBORATES
//!   edges for a claim. Read-only.
//! - `list_match_candidates`: list the queue, sorted by score desc, optionally
//!   filtered by status.
//! - `decide_match_candidate`: promote (write CORROBORATES edge) or reject a row.
//!   Honours `reject_if_read_only` like other write tools.

#![allow(clippy::wildcard_imports)]

use rmcp::model::*;
use serde::Serialize;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::{ClaimRepository, EdgeRepository, MatchCandidateRepo};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

#[derive(Serialize)]
struct CandidateOut {
    id: String,
    claim_a: String,
    claim_b: String,
    score: f32,
    status: String,
    verifier_verdict: Option<String>,
    verifier_rationale: Option<String>,
    matcher_run_id: Option<String>,
    features: serde_json::Value,
    created_at: String,
}

fn row_to_out(r: epigraph_db::MatchCandidateRow) -> CandidateOut {
    CandidateOut {
        id: r.id.to_string(),
        claim_a: r.claim_a.to_string(),
        claim_b: r.claim_b.to_string(),
        score: r.score,
        status: r.status,
        verifier_verdict: r.verifier_verdict,
        verifier_rationale: r.verifier_rationale,
        matcher_run_id: r.matcher_run_id.map(|u| u.to_string()),
        features: r.features,
        created_at: r.created_at.to_rfc3339(),
    }
}

pub async fn find_cross_source_matches(
    server: &EpiGraphMcpFull,
    params: FindCrossSourceMatchesParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;
    let repo = MatchCandidateRepo::new(server.pool.clone());

    let candidates = repo
        .list_for_claim(claim_id)
        .await
        .map_err(internal_error)?;
    let candidates_out: Vec<CandidateOut> = candidates.into_iter().map(row_to_out).collect();

    // Pull CORROBORATES edges incident on the claim — already-promoted matches.
    let edges: Vec<(uuid::Uuid, uuid::Uuid, uuid::Uuid, serde_json::Value)> = sqlx::query_as(
        "SELECT id, source_id, target_id, properties FROM edges
         WHERE relationship = 'CORROBORATES'
           AND (source_id = $1 OR target_id = $1)",
    )
    .bind(claim_id)
    .fetch_all(&server.pool)
    .await
    .map_err(internal_error)?;

    let corroborates: Vec<serde_json::Value> = edges
        .into_iter()
        .map(|(id, source_id, target_id, properties)| {
            serde_json::json!({
                "edge_id":    id.to_string(),
                "source_id":  source_id.to_string(),
                "target_id":  target_id.to_string(),
                "properties": properties,
            })
        })
        .collect();

    success_json(&serde_json::json!({
        "claim_id":     claim_id.to_string(),
        "candidates":   candidates_out,
        "corroborates": corroborates,
    }))
}

pub async fn list_match_candidates(
    server: &EpiGraphMcpFull,
    params: ListMatchCandidatesParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 500);

    let status_owned = params.status.as_deref().map(|s| s.to_lowercase());
    let status_ref = match status_owned.as_deref() {
        Some(s @ ("pending" | "promoted" | "rejected" | "stale")) => Some(s),
        Some(other) => {
            return Err(invalid_params(format!(
                "status must be one of pending|promoted|rejected|stale, got {other}"
            )));
        }
        None => None,
    };

    let repo = MatchCandidateRepo::new(server.pool.clone());
    let rows = repo.list(status_ref, limit).await.map_err(internal_error)?;
    let out: Vec<CandidateOut> = rows.into_iter().map(row_to_out).collect();
    success_json(&out)
}

pub async fn decide_match_candidate(
    server: &EpiGraphMcpFull,
    params: DecideMatchCandidateParams,
) -> Result<CallToolResult, McpError> {
    server.reject_if_read_only()?;
    let candidate_id = parse_uuid(&params.candidate_id)?;
    let decision = params.verdict.to_lowercase();

    let repo = MatchCandidateRepo::new(server.pool.clone());
    let row = repo.get(candidate_id).await.map_err(internal_error)?;

    let acting_agent = server.agent_id().await?;

    match decision.as_str() {
        "promote" => {
            // Guard: a CORROBORATES edge must connect two live claims. If
            // either endpoint was superseded or marked duplicate (is_current =
            // false) since the candidate was generated, promoting would create
            // a structural inconsistency — an edge incident on a retired claim
            // (backlog bug 5c7fc645). Refuse rather than write it.
            if !ClaimRepository::are_all_current(&server.pool, &[row.claim_a, row.claim_b])
                .await
                .map_err(internal_error)?
            {
                return Err(invalid_params(format!(
                    "cannot promote candidate {candidate_id}: a CORROBORATES edge requires both \
                     claims to be current (is_current=true). One of {} / {} is superseded, a \
                     duplicate, or missing.",
                    row.claim_a, row.claim_b
                )));
            }

            repo.set_status(candidate_id, "promoted", Some(acting_agent))
                .await
                .map_err(internal_error)?;

            // Write CORROBORATES edge if it doesn't already exist (either
            // direction). The unique-triple index was dropped in migrations
            // 017/018, so this explicit existence check — now centralized in
            // `EdgeRepository::create_symmetric_if_absent` — is the only guard
            // against duplicates from repeated `decide` calls. The
            // are_all_current guard above stays here at the call site.
            let props = serde_json::json!({
                "candidate_id":     candidate_id,
                "score":            row.score,
                "features":         row.features,
                "verifier_verdict": row.verifier_verdict,
                "decided_by":       acting_agent,
                "source":           "cross_source_matcher",
            });
            EdgeRepository::create_symmetric_if_absent(
                &server.pool,
                row.claim_a,
                row.claim_b,
                "CORROBORATES",
                props,
            )
            .await
            .map_err(internal_error)?;
        }
        "reject" => {
            repo.set_status(candidate_id, "rejected", Some(acting_agent))
                .await
                .map_err(internal_error)?;
        }
        other => {
            return Err(invalid_params(format!(
                "verdict must be 'promote' or 'reject', got {other}"
            )));
        }
    }

    let updated = repo.get(candidate_id).await.map_err(internal_error)?;
    success_json(&row_to_out(updated))
}
