//! `publicize_claims`, `share_claims_with_team` and `set_default_group`: the
//! MCP side of the user-level claim visibility controls
//! (`docs/tenancy/claim-visibility-controls.md`, migration 206).
//!
//! Each tool runs ONE transaction stamped from the caller's own write identity
//! (`claim_helper::begin_author_stamped_tx`), and calls the migration-206
//! definer on it. The definer reads the caller from that stamp
//! (`epigraph_principal_id()`), makes the authority decision, and writes the
//! audit row in the same transaction. The tool decides nothing about authority
//! itself, so the HTTP twins (`epigraph-api` `routes/claim_visibility.rs`)
//! cannot drift from it.

use rmcp::model::{CallToolResult, ContentBlock};
use uuid::Uuid;

use crate::claim_helper::visibility_caller_error;
use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{
    PublicizeClaimsParams, SetDefaultGroupParams, ShareClaimsWithTeamParams, VisibilityActItem,
    VisibilityActResponse,
};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

fn parse_ids(raw: &[String]) -> Result<Vec<Uuid>, McpError> {
    if raw.is_empty() || raw.len() > 500 {
        return Err(invalid_params("claim_ids takes 1 to 500 claim UUIDs"));
    }
    raw.iter()
        .map(|s| {
            Uuid::parse_str(s.trim())
                .map_err(|_| invalid_params(format!("claim id {s:?} is not a uuid")))
        })
        .collect()
}

fn respond(outcomes: Vec<epigraph_db::VisibilityActOutcome>) -> Result<CallToolResult, McpError> {
    success_json(&VisibilityActResponse {
        results: outcomes
            .into_iter()
            .map(|o| VisibilityActItem {
                claim_id: o.claim_id.to_string(),
                outcome: o.outcome,
            })
            .collect(),
    })
}

/// `publicize_claims`: group → public, team admins only (D-V2), all or nothing.
///
/// # Errors
/// `INVALID_PARAMS` for a bad request or a claim the caller cannot read (as if
/// missing); `INVALID_REQUEST` for a refusal (not an admin, sealed), with
/// nothing changed.
pub async fn publicize_claims(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: PublicizeClaimsParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let ids = parse_ids(&params.claim_ids)?;
    let caller = server.write_identity(auth, viewer).await?;
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, caller, "publicize_claims").await?;
    let outcomes = epigraph_db::ClaimRepository::publicize_conn(&mut tx, &ids, &params.reason)
        .await
        .map_err(visibility_caller_error)?;
    tx.commit().await.map_err(internal_error)?;
    respond(outcomes)
}

/// `share_claims_with_team`: private → a team the caller writes.
///
/// # Errors
/// As [`publicize_claims`].
pub async fn share_claims_with_team(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ShareClaimsWithTeamParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let ids = parse_ids(&params.claim_ids)?;
    let group = Uuid::parse_str(params.group_id.trim())
        .map_err(|_| invalid_params(format!("group_id {:?} is not a uuid", params.group_id)))?;
    let caller = server.write_identity(auth, viewer).await?;
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, caller, "share_claims_with_team")
            .await?;
    let outcomes =
        epigraph_db::ClaimRepository::share_with_team_conn(&mut tx, &ids, group, &params.reason)
            .await
            .map_err(visibility_caller_error)?;
    tx.commit().await.map_err(internal_error)?;
    respond(outcomes)
}

/// `set_default_group`: the default of the caller, or (`agent_id`, migration
/// 209) of an agent the caller operates through a live operator link: a team,
/// private, or clear.
///
/// # Errors
/// `INVALID_PARAMS` for a malformed id or a group together with `private`;
/// `INVALID_REQUEST` for a group that is not one of the agent's writable teams,
/// or a caller that is neither the agent nor its live human operator.
pub async fn set_default_group(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: SetDefaultGroupParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let uuid_of = |field: &str, raw: Option<&str>| -> Result<Option<Uuid>, McpError> {
        match raw.map(str::trim) {
            None | Some("") => Ok(None),
            Some(s) => Uuid::parse_str(s)
                .map(Some)
                .map_err(|_| invalid_params(format!("{field} {s:?} is not a uuid"))),
        }
    };
    let group = uuid_of("group_id", params.group_id.as_deref())?;
    let target = uuid_of("agent_id", params.agent_id.as_deref())?;
    let setting = match (group, params.private.unwrap_or(false)) {
        (Some(_), true) => {
            return Err(invalid_params(
                "a default is a team (group_id) or private, not both",
            ))
        }
        (Some(g), false) => epigraph_db::DefaultGroupSetting::Team(g),
        (None, true) => epigraph_db::DefaultGroupSetting::Private,
        (None, false) => epigraph_db::DefaultGroupSetting::Clear,
    };
    let caller = server.write_identity(auth, viewer).await?;
    let agent = target.unwrap_or_else(|| caller.agent_id());
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, caller, "set_default_group").await?;
    let set_by = epigraph_db::ClaimRepository::set_agent_default_conn(&mut tx, agent, setting)
        .await
        .map_err(visibility_caller_error)?;
    let teams = epigraph_db::ClaimRepository::writable_teams(&mut tx, agent)
        .await
        .map_err(internal_error)?;
    tx.commit().await.map_err(internal_error)?;
    success_json(&serde_json::json!({
        "agent_id": agent.to_string(),
        "default_group_id": setting.group().map(|g| g.to_string()),
        "default_private": setting.private(),
        "set_by": set_by,
        "writable_teams": teams
            .into_iter()
            .map(|(g, via)| serde_json::json!({"group_id": g.to_string(), "via": via}))
            .collect::<Vec<_>>(),
    }))
}
