#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::{ChallengeRepository, ClaimRepository, EventRepository};

/// The `data.rule` of [`challenge_not_writer`].
pub const CHALLENGE_NOT_WRITER_RULE: &str = "challenge_requires_claim_group_writer";

/// The named refusal for a challenge against a claim the challenger can read
/// but whose owning group it cannot write. The challenge row INHERITS that
/// group (see [`challenge_claim`]'s doc), so the database would refuse the
/// INSERT; this says so by name instead of passing on the row-security error.
/// `INVALID_REQUEST`, like `crate::errors::claim_not_writer`: a denial of
/// authority, not a server fault and not a bad parameter. Not that helper
/// itself, because its text offers `claims:admin` as a way in, and a
/// `claims:admin` token does not change whose group this row is written into.
///
/// It does NOT name the claim's owning group: no claim read surface returns
/// `owner_group_id`, and for another agent's public claim it is usually that
/// agent's personal group. Same shape as `claim_not_writer`'s `data`.
fn challenge_not_writer(claim_id: uuid::Uuid) -> McpError {
    McpError {
        code: ErrorCode::INVALID_REQUEST,
        message: std::borrow::Cow::from(format!(
            "cannot challenge claim {claim_id}: a challenge is owned by the challenged claim's \
             group, and the challenger holds no live writer or admin membership in it; nothing \
             was written"
        )),
        data: Some(serde_json::json!({
            "error": "not_writer",
            "rule": CHALLENGE_NOT_WRITER_RULE,
            "claim_id": claim_id,
            "retryable": false,
        })),
    }
}

/// A `42501` from the challenge INSERT AFTER [`challenge_claim`]'s preflight
/// admitted the challenger. That is not the caller's denial (the preflight
/// already answers that by name): it is a membership revoked in between, or a
/// server-side GRANT / policy fault. So it is logged, and answered as an
/// `INTERNAL_ERROR` with a fixed message: neither the raw row-security text
/// nor a `not_writer` refusal that would blame the caller.
fn challenge_refused_after_preflight(claim_id: uuid::Uuid, e: &sqlx::Error) -> McpError {
    tracing::error!(
        target: "tenancy.scoped_write",
        tool = "challenge_claim",
        claim_id = %claim_id,
        error = %e,
        "challenge INSERT refused (insufficient_privilege) after the writer preflight admitted \
         the challenger. Nothing was written."
    );
    McpError {
        code: ErrorCode::INTERNAL_ERROR,
        message: std::borrow::Cow::from(format!(
            "challenge_claim: the database refused the challenge on claim {claim_id} after the \
             writer check admitted it (a membership change in between, or a server-side policy \
             fault; the detail is in the server log); nothing was written"
        )),
        data: Some(serde_json::json!({
            "error": "write_refused_after_preflight",
            "claim_id": claim_id,
        })),
    }
}

/// `true` for PostgreSQL's `insufficient_privilege` (SQLSTATE `42501`), which
/// a row-security `WITH CHECK` raises.
fn is_insufficient_privilege(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .as_deref()
        == Some("42501")
}

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
///
/// That refusal is answered BY NAME ([`challenge_not_writer`], before the
/// INSERT): the claim's owning group is read on the stamped transaction and
/// compared with the challenger's own writable groups, the set the stamp
/// carries. It used to surface as an `INTERNAL_ERROR` carrying the raw
/// `new row violates row-level security policy for table "challenges"`
/// (backlog deebc487). A claim the caller cannot read stays "not found". A
/// `42501` from the INSERT itself, past the preflight, is a server-side fault
/// or a race, not the caller's denial ([`challenge_refused_after_preflight`]).
pub async fn challenge_claim(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ChallengeclaimParams,
    auth: Option<&epigraph_auth::AuthContext>,
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

    // The challenger is the request's principal (batch H-b, D1): the caller
    // over HTTP, this server's agent on stdio.
    let challenger = server.write_identity(auth, viewer).await?;
    let agent_id = challenger.agent_id();

    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, challenger, "challenge_claim").await?;

    // Preflight: the group the challenge row would inherit, read through the
    // request's viewer (an unreadable claim is not found), against the
    // challenger's own writable groups, which are the stamp's.
    let (_author, owner_group) = ClaimRepository::write_target_of(&mut *tx, viewer, claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {claim_id} not found")))?;
    let challenger_viewer = epigraph_db::visibility::Viewer::resolve(&server.pool, agent_id)
        .await
        .map_err(internal_error)?;
    if !challenger_viewer.writable_groups().contains(&owner_group) {
        return Err(challenge_not_writer(claim_id));
    }

    let challenge_id = ChallengeRepository::create(
        &mut *tx,
        claim_id,
        Some(agent_id),
        &params.challenge_type,
        &params.explanation,
    )
    .await
    .map_err(|e| {
        if is_insufficient_privilege(&e) {
            challenge_refused_after_preflight(claim_id, &e)
        } else {
            internal_error(e)
        }
    })?;

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

    Ok(CallToolResult::success(vec![ContentBlock::text(
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

    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::json!({
            "challenges": results,
            "total": results.len(),
        })
        .to_string(),
    )]))
}
