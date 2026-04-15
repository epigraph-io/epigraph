#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::{ChallengeRepository, EventRepository};

const VALID_CHALLENGE_TYPES: &[&str] = &[
    "insufficient_evidence",
    "outdated_evidence",
    "flawed_methodology",
    "contradicting_evidence",
    "factual_error",
];

/// Submit a typed challenge against a claim.
pub async fn challenge_claim(
    server: &EpiGraphMcpFull,
    params: ChallengeclaimParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;

    if !VALID_CHALLENGE_TYPES.contains(&params.challenge_type.as_str()) {
        return Err(invalid_params(format!(
            "Invalid challenge_type '{}'. Valid: {}",
            params.challenge_type,
            VALID_CHALLENGE_TYPES.join(", ")
        )));
    }

    if params.explanation.trim().is_empty() {
        return Err(invalid_params("explanation cannot be empty"));
    }

    let agent_id = server.agent_id().await?;

    let challenge_id = ChallengeRepository::create(
        &server.pool,
        claim_id,
        Some(agent_id),
        &params.challenge_type,
        &params.explanation,
    )
    .await
    .map_err(internal_error)?;

    // Emit event
    let _ = EventRepository::insert(
        &server.pool,
        "claim.challenged",
        Some(agent_id),
        &serde_json::json!({
            "challenge_id": challenge_id,
            "claim_id": claim_id,
            "challenge_type": params.challenge_type,
        }),
    )
    .await;

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::json!({
            "challenge_id": challenge_id,
            "claim_id": claim_id,
            "challenge_type": params.challenge_type,
            "state": "pending",
        })
        .to_string(),
    )]))
}

/// List challenges for a claim.
pub async fn list_challenges(
    server: &EpiGraphMcpFull,
    params: ListChallengesParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;

    let challenges = ChallengeRepository::list_for_claim(&server.pool, claim_id)
        .await
        .map_err(internal_error)?;

    let results: Vec<serde_json::Value> = challenges
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "claim_id": c.claim_id,
                "challenger_id": c.challenger_id,
                "challenge_type": c.challenge_type,
                "explanation": c.explanation,
                "state": c.state,
                "created_at": c.created_at.to_rfc3339(),
            })
        })
        .collect();

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::json!({
            "challenges": results,
            "total": results.len(),
        })
        .to_string(),
    )]))
}
