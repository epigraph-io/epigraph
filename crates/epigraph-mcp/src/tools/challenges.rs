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
///
/// # One author-stamped transaction
///
/// `challenges` is a tier-A table with migration 077's strict
/// `WITH CHECK (owner_group_id = ANY(epigraph_writable_groups()))`, and nothing
/// on the MCP request path stamped that GUC, so on a cleanly-migrated schema
/// this tool was refused with `42501` on every call — loudly, which is why it
/// was one of the safest to convert. The write now runs on a connection stamped
/// from the challenger's own viewer, through
/// `claim_helper::begin_author_stamped_tx`, the same construction `submit_claim`
/// and `memorize` use.
///
/// # Why the event INSERT moved to `publish_or_log_conn`
///
/// The event was `let _ = EventRepository::insert(&server.pool, …)` —
/// fire-and-forget, on a second pool checkout. Inside a transaction that spelling
/// is actively harmful: PostgreSQL aborts the whole transaction on the first
/// failed statement, so a swallowed error resurfaces at `COMMIT` as `25P02
/// current transaction is aborted` with the real cause nowhere in the error the
/// caller receives. `EventRepository::publish_or_log_conn` keeps the
/// fire-and-forget contract by wrapping the INSERT in a SAVEPOINT, and it makes
/// the event share the challenge's fate: no `claim.challenged` event for a
/// challenge that was rolled back.
///
/// # What is still refused, and it is a policy question rather than a bug
///
/// The row's `(visibility, owner_group_id)` is inherited from the CHALLENGED
/// CLAIM by migration 074's BEFORE-row trigger and re-stamped unconditionally by
/// 070 arm (c) — see `ChallengeRepository::create`'s doc. So a challenger can
/// write a challenge against a claim in a group it can write, and is refused for
/// one it cannot. Before this conversion it was refused for BOTH, so this is
/// strictly a narrowing of the refusal; deciding whether an outsider's objection
/// should be owned by the objector instead is a tenancy-model change, not this
/// change.
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

    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, agent_id, "challenge_claim").await?;

    let challenge_id = ChallengeRepository::create(
        &mut *tx,
        claim_id,
        Some(agent_id),
        &params.challenge_type,
        &params.explanation,
    )
    .await
    .map_err(internal_error)?;

    // Durable event, in the same transaction and SAVEPOINT-wrapped: it rides the
    // challenge's fate, and a refused event cannot abort the challenge.
    EventRepository::publish_or_log_conn(
        &mut tx,
        "claim.challenged",
        Some(agent_id),
        &serde_json::json!({
            "challenge_id": challenge_id,
            "claim_id": claim_id,
            "challenge_type": params.challenge_type,
        }),
    )
    .await;

    tx.commit().await.map_err(internal_error)?;

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
    viewer: &epigraph_db::visibility::Viewer,
    params: ListChallengesParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;

    let challenges = ChallengeRepository::list_for_claim(&server.pool, viewer, claim_id)
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
