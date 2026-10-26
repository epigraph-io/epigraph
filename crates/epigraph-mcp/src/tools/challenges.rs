#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::repos::challenge::ChallengeAdmission;
use epigraph_db::{ChallengeRepository, EventRepository};

/// The `data.rule` of [`challenge_not_writer`].
pub const CHALLENGE_NOT_WRITER_RULE: &str = "challenge_requires_claim_group_writer";

/// The named refusal for a challenge against a NON-PUBLIC claim the challenger
/// can read but whose owning group it cannot write (ruling R-CH1: an outsider's
/// challenge is the outsider's own row, and on a non-public claim such a row
/// would be hidden from the claim's own owners, so it is not written). The
/// database would refuse the INSERT too; this says so by name instead of
/// passing on the row-security error. `INVALID_REQUEST`, like
/// `crate::errors::claim_not_writer`: a denial of authority, not a server fault
/// and not a bad parameter. Not that helper itself, because its text offers
/// `claims:admin` as a way in, and a `claims:admin` token changes nothing here.
///
/// It does NOT name the claim's owning group: no claim read surface returns
/// `owner_group_id`. Same shape as `claim_not_writer`'s `data`.
fn challenge_not_writer(claim_id: uuid::Uuid) -> McpError {
    McpError {
        code: ErrorCode::INVALID_REQUEST,
        message: std::borrow::Cow::from(format!(
            "cannot challenge claim {claim_id}: it is not public, and the challenger holds no \
             live writer or admin membership in its group (a challenger outside the claim's \
             group may challenge only a public claim); nothing was written"
        )),
        data: Some(serde_json::json!({
            "error": "not_writer",
            "rule": CHALLENGE_NOT_WRITER_RULE,
            "claim_id": claim_id,
            "retryable": false,
        })),
    }
}

/// The `data.rule` of [`challenge_no_writer_group`].
pub const CHALLENGE_NO_WRITER_GROUP_RULE: &str = "challenge_requires_an_own_write_group";

/// An outsider's challenge on a public claim is owned by the challenger's own
/// write group (`epigraph_writer_group()`: its operator's personal group, else
/// its own), and this challenger has none it can write. Nothing could own the
/// row, so the database would refuse it; this says so by name.
fn challenge_no_writer_group(claim_id: uuid::Uuid) -> McpError {
    McpError {
        code: ErrorCode::INVALID_REQUEST,
        message: std::borrow::Cow::from(format!(
            "cannot challenge claim {claim_id}: a challenge from outside the claim's group is \
             owned by the challenger's own personal (or operator's) group, and the challenger \
             can write neither; nothing was written"
        )),
        data: Some(serde_json::json!({
            "error": "no_writer_group",
            "rule": CHALLENGE_NO_WRITER_GROUP_RULE,
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
/// # Whose row it is (ruling R-CH1, migration 168)
///
/// * An INSIDER (the challenger writes the claim's owning group): the row
///   inherits the claim's tenancy, as every claim-derived row does.
/// * An OUTSIDER on a PUBLIC claim: the row is owned by the challenger's own
///   write group, public, `writer_owned`, and never follows the claim (a later
///   privatization does not drag it along). Before 168 this was refused.
/// * An outsider on a NON-public claim it can read: refused by name
///   ([`challenge_not_writer`]); an outsider with no write group of its own:
///   refused by name ([`challenge_no_writer_group`]).
/// * A claim the challenger cannot read: "not found", with exactly the text a
///   nonexistent claim id gets (ruling R-CH1b), so the refusal is no existence
///   oracle.
///
/// The decision is `ChallengeRepository::admission_of`, read on the stamped
/// transaction with the functions the INSERT's triggers use, so the preflight
/// and the row cannot disagree. A `42501` from the INSERT itself, past the
/// preflight, is a server-side fault or a race, not the caller's denial
/// ([`challenge_refused_after_preflight`]).
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

    // Preflight (R-CH1): where the row would land, read through the request's
    // viewer (an unreadable claim is not found, worded exactly as a missing
    // one) on the stamped transaction the INSERT uses.
    let admission = ChallengeRepository::admission_of(&mut *tx, viewer, claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {claim_id} not found")))?;
    match admission {
        ChallengeAdmission::Insider | ChallengeAdmission::Outsider { .. } => {}
        ChallengeAdmission::NotWriter => return Err(challenge_not_writer(claim_id)),
        ChallengeAdmission::NoWriterGroup => return Err(challenge_no_writer_group(claim_id)),
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
