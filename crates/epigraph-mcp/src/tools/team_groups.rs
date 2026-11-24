//! `create_team_group`, `list_my_groups`, `invite_to_group`,
//! `accept_group_invitation` and `decline_group_invitation`: the MCP side of
//! person-facing keyless team groups and consented invitations (migration
//! 263, backlog ee9e05b4).
//!
//! Each write runs ONE transaction stamped from the caller's own write
//! identity (`claim_helper::begin_author_stamped_tx`) and calls the migration-
//! 263 definer on it through `PersonTeamGroupRepository`; the list reads on
//! the request viewer's stamped transaction. The definer reads the caller
//! from that stamp, makes every authority decision and writes the audit row,
//! so the HTTP twins (`epigraph-api` `routes/team_groups.rs`) cannot drift
//! from it. Refusals map as every visibility tool maps them
//! (`claim_helper::visibility_caller_error`): input `INVALID_PARAMS`,
//! authority and state `INVALID_REQUEST`, and a group or invitation the
//! caller may not see `INVALID_PARAMS` "not found", exactly as a missing one.

use rmcp::model::{CallToolResult, ContentBlock};
use uuid::Uuid;

use crate::claim_helper::visibility_caller_error;
use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{
    AcceptGroupInvitationParams, CreateTeamGroupParams, DeclineGroupInvitationParams,
    InviteToGroupParams, ListMyGroupsParams,
};
use epigraph_db::PersonTeamGroupRepository;

fn success_json(value: &serde_json::Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

fn uuid_param(field: &str, raw: &str) -> Result<Uuid, McpError> {
    Uuid::parse_str(raw.trim())
        .map_err(|_| invalid_params(format!("{field} {raw:?} is not a uuid")))
}

/// Spaces only, as SQL `btrim` and the REST twin (which passes the reason
/// through to it) strip them.
fn reason_param(raw: Option<&str>) -> Option<&str> {
    raw.map(|s| s.trim_matches(' ')).filter(|s| !s.is_empty())
}

/// `create_team_group`: a keyless team group whose one admin is the caller.
///
/// # Errors
/// `INVALID_PARAMS` for a blank or over-long name or reason;
/// `INVALID_REQUEST` when the caller is not a Person signed in as themselves,
/// or already has an active team group of that name.
pub async fn create_team_group(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: CreateTeamGroupParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let caller = server.write_identity(auth, viewer).await?;
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, caller, "create_team_group").await?;
    let group = PersonTeamGroupRepository::create_conn(
        &mut tx,
        &params.name,
        reason_param(params.reason.as_deref()),
    )
    .await
    .map_err(visibility_caller_error)?;
    tx.commit().await.map_err(internal_error)?;
    success_json(&serde_json::json!({
        "group_id": group.to_string(),
        "did_key": format!("did:epigraph:group:{group}"),
        // SQL `btrim` strips spaces only, so echo exactly what was stored
        // (as the REST twin does).
        "display_name": params.name.trim_matches(' '),
        "role": "admin",
    }))
}

/// `list_my_groups`: the caller's live memberships and pending invitations.
///
/// # Errors
/// `INVALID_REQUEST` for a principal-less caller; internal for a failed read.
pub async fn list_my_groups(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    _params: ListMyGroupsParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    if auth.is_some_and(crate::auth::is_principal_less) {
        return Err(McpError {
            code: rmcp::model::ErrorCode::INVALID_REQUEST,
            message: std::borrow::Cow::Borrowed(
                "list_my_groups needs an authenticated principal; a principal-less listener \
                 has no groups",
            ),
            data: None,
        });
    }
    let scoped = server.scoped.as_ref().ok_or_else(|| {
        crate::errors::internal_error_text(
            "list_my_groups: this process was not built from a ScopedPool, so the read cannot \
             be stamped with the caller's viewer",
        )
    })?;
    let mut tx = scoped
        .begin_as(viewer)
        .await
        .map_err(crate::errors::db_caller_error)?;
    let groups = PersonTeamGroupRepository::my_groups_conn(&mut tx)
        .await
        .map_err(visibility_caller_error)?;
    let invitations = PersonTeamGroupRepository::my_invitations_conn(&mut tx)
        .await
        .map_err(visibility_caller_error)?;
    tx.rollback().await.map_err(internal_error)?;
    success_json(&serde_json::json!({
        "groups": groups.into_iter().map(|g| serde_json::json!({
            "group_id": g.group_id.to_string(),
            "display_name": g.display_name,
            "kind": g.kind,
            "status": g.status,
            "role": g.role,
            "created_by": g.created_by.map(|a| a.to_string()),
            "invitable": g.invitable,
        })).collect::<Vec<_>>(),
        "invitations": invitations.into_iter().map(|i| serde_json::json!({
            "invitation_id": i.invitation_id.to_string(),
            "group_id": i.group_id.to_string(),
            "display_name": i.display_name,
            "role": i.role,
            "invited_by": i.invited_by.to_string(),
            "reason": i.reason,
            "created_at": i.created_at.to_rfc3339(),
        })).collect::<Vec<_>>(),
    }))
}

/// `invite_to_group`: a pending invitation; no membership is written.
///
/// # Errors
/// `INVALID_PARAMS` for a malformed id, an invitee that names no agent, is a
/// role's node or a system identity, or is the caller (whether it is a Person
/// is never answered here, migration 284), a bad role or reason, or a group the caller holds no live
/// membership of (as for a missing one); `INVALID_REQUEST` when the caller is
/// not a Person or not an admin of the group, the invitee is already a member
/// or already invited, or the group takes no invitations.
pub async fn invite_to_group(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: InviteToGroupParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let group = uuid_param("group_id", &params.group_id)?;
    let invitee = uuid_param("agent_id", &params.agent_id)?;
    let role = params.role.as_deref().map_or("reader", str::trim);
    let caller = server.write_identity(auth, viewer).await?;
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, caller, "invite_to_group").await?;
    let invitation = PersonTeamGroupRepository::invite_conn(
        &mut tx,
        group,
        invitee,
        role,
        reason_param(params.reason.as_deref()),
    )
    .await
    .map_err(visibility_caller_error)?;
    tx.commit().await.map_err(internal_error)?;
    success_json(&serde_json::json!({
        "invitation_id": invitation.to_string(),
        "group_id": group.to_string(),
        "agent_id": invitee.to_string(),
        "role": role,
        "status": "pending",
    }))
}

/// `accept_group_invitation`: the invitee accepts; the membership goes live.
///
/// # Errors
/// `INVALID_PARAMS` for a malformed id or an invitation not addressed to the
/// caller; `INVALID_REQUEST` when the caller is not a Person signed in as
/// themselves, or the invitation was already answered or has lapsed.
pub async fn accept_group_invitation(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: AcceptGroupInvitationParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let invitation = uuid_param("invitation_id", &params.invitation_id)?;
    let caller = server.write_identity(auth, viewer).await?;
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, caller, "accept_group_invitation")
            .await?;
    let accepted = PersonTeamGroupRepository::accept_conn(&mut tx, invitation)
        .await
        .map_err(visibility_caller_error)?;
    tx.commit().await.map_err(internal_error)?;
    success_json(&serde_json::json!({
        "invitation_id": invitation.to_string(),
        "group_id": accepted.group_id.to_string(),
        "membership_id": accepted.membership_id.to_string(),
        "role": accepted.role,
        "status": "accepted",
    }))
}

/// `decline_group_invitation`: the invitee declines; nothing is joined.
///
/// # Errors
/// `INVALID_PARAMS` for a malformed id or an invitation not addressed to the
/// caller; `INVALID_REQUEST` when it was already answered.
pub async fn decline_group_invitation(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: DeclineGroupInvitationParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let invitation = uuid_param("invitation_id", &params.invitation_id)?;
    let caller = server.write_identity(auth, viewer).await?;
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, caller, "decline_group_invitation")
            .await?;
    let group = PersonTeamGroupRepository::decline_conn(&mut tx, invitation)
        .await
        .map_err(visibility_caller_error)?;
    tx.commit().await.map_err(internal_error)?;
    success_json(&serde_json::json!({
        "invitation_id": invitation.to_string(),
        "group_id": group.to_string(),
        "status": "declined",
    }))
}
