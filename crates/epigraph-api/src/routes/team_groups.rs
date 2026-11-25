//! Person-facing keyless team groups and consented invitations (migration 263,
//! backlog ee9e05b4): the REST twins of the MCP team-group tools.
//!
//! | Route | Scope |
//! |---|---|
//! | `POST /api/v1/groups/team` `{name, reason?}` | `groups:write` |
//! | `GET /api/v1/groups/mine` | `groups:read` |
//! | `POST /api/v1/groups/:id/invitations` `{agent_id, role?, reason?}` | `groups:write` |
//! | `POST /api/v1/group-invitations/:id/accept` | `groups:write` |
//! | `POST /api/v1/group-invitations/:id/decline` | `groups:write` |
//!
//! Each runs ONE transaction stamped as the caller (`AppState::write_as`, or
//! `read_as` for the list) and calls the migration-263 definer on it through
//! `PersonTeamGroupRepository`. The definer makes every authority decision
//! (only a registered human operator signed in as themselves creates, invites
//! or accepts; only a live admin invites; only the invitee answers) and
//! writes the audit row, so this file and `epigraph-mcp`'s
//! `tools/team_groups.rs` cannot disagree. A refusal maps by its kind
//! (`ApiError::from(DbError)`: input 400, authority 403, state 409), and a
//! group or invitation the caller may not see is a 404, exactly as a missing
//! one.
//!
//! The scope says the token class may manage groups; the membership the
//! definer checks says which ones. `groups:write` (not the admin-only
//! `groups:admin` the keyed roster routes take) is the invite scope because
//! the authority is the caller's live admin row in the group, re-read by the
//! definer under the group's row lock, and because an invitation places no
//! one: the invitee's accept does. This departs from the keyed routes'
//! convention (`groups:admin` for an existing group's roster); see the note
//! at `RequireScopeGroupsAdmin` in `middleware/bearer.rs`.
//!
//! An invitation places no one: the membership goes live only when the
//! invitee accepts. The keyed `POST /api/v1/groups/:id/members` route still
//! adds members directly to KEYED groups (a key share must be wrapped for each
//! member), and is unchanged.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::{RequireScopeGroupsWrite, ViewerExtractor};
use crate::state::AppState;
use epigraph_db::PersonTeamGroupRepository;

/// `POST /api/v1/groups/team`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateTeamGroupRequest {
    /// 1 to 255 characters (surrounding space trimmed). Unique among the
    /// caller's own active team groups, case-insensitively.
    pub name: String,
    /// Optional; recorded in the `group.team_created` audit event.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The answer to `POST /api/v1/groups/team`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreateTeamGroupResponse {
    pub group_id: Uuid,
    /// `did:epigraph:group:<group_id>`.
    pub did_key: String,
    pub display_name: String,
    /// Always `admin`: the creator is the group's one admin.
    pub role: &'static str,
}

/// `POST /api/v1/groups/:id/invitations`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct InviteToGroupRequest {
    /// The Person (a registered human operator's agent id) to invite.
    pub agent_id: Uuid,
    /// `reader` (the default), `writer` or `admin`: the role the membership
    /// will have if the invitee accepts.
    #[serde(default = "default_role")]
    pub role: String,
    /// Optional; shown to the invitee and recorded in the audit event.
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_role() -> String {
    "reader".to_string()
}

/// The answer to `POST /api/v1/groups/:id/invitations`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct InvitationResponse {
    pub invitation_id: Uuid,
    pub group_id: Uuid,
    pub agent_id: Uuid,
    pub role: String,
    /// Always `pending`: no membership exists until the invitee accepts.
    pub status: &'static str,
}

/// The answer to `POST /api/v1/group-invitations/:id/accept`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AcceptInvitationResponse {
    pub invitation_id: Uuid,
    pub group_id: Uuid,
    /// The live membership row the acceptance wrote.
    pub membership_id: Uuid,
    pub role: String,
    pub status: &'static str,
}

/// The answer to `POST /api/v1/group-invitations/:id/decline`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DeclineInvitationResponse {
    pub invitation_id: Uuid,
    pub group_id: Uuid,
    pub status: &'static str,
}

/// One of the caller's groups.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MyGroupEntry {
    pub group_id: Uuid,
    pub display_name: Option<String>,
    pub kind: String,
    pub status: String,
    /// The caller's highest live role in it.
    pub role: String,
    pub created_by: Option<Uuid>,
    /// `true` for an active team group a Person made with
    /// `POST /api/v1/groups/team`: one its admins may invite into. A team
    /// group the operator made is managed by the operator and is `false`.
    pub invitable: bool,
}

/// An invitation waiting for the caller.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MyInvitationEntry {
    pub invitation_id: Uuid,
    pub group_id: Uuid,
    pub display_name: Option<String>,
    pub role: String,
    pub invited_by: Uuid,
    pub reason: Option<String>,
    /// RFC 3339.
    pub created_at: String,
}

/// The answer to `GET /api/v1/groups/mine`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MyGroupsResponse {
    pub groups: Vec<MyGroupEntry>,
    /// Pending invitations addressed to the caller; accept or decline each.
    pub invitations: Vec<MyInvitationEntry>,
}

fn commit_error(e: epigraph_db::DbError) -> ApiError {
    ApiError::DatabaseError {
        message: format!("Failed to commit: {e}"),
    }
}

/// `POST /api/v1/groups/team`: create a keyless team group; the caller
/// becomes its one admin.
///
/// # Errors
/// 400 a blank or over-long name or reason; 403 the caller is not a Person
/// signed in as themselves; 409 the caller already has an active team group
/// of that name.
pub async fn create_team_group(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    RequireScopeGroupsWrite(_auth): RequireScopeGroupsWrite,
    Json(body): Json<CreateTeamGroupRequest>,
) -> Result<(StatusCode, Json<CreateTeamGroupResponse>), ApiError> {
    let mut tx = state
        .write_as(&viewer, "team_groups::create_team_group")
        .await?;
    let group_id =
        PersonTeamGroupRepository::create_conn(&mut tx, &body.name, body.reason.as_deref()).await?;
    tx.commit().await.map_err(commit_error)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateTeamGroupResponse {
            group_id,
            did_key: format!("did:epigraph:group:{group_id}"),
            // SQL `btrim` strips spaces only, so echo exactly what was stored.
            display_name: body.name.trim_matches(' ').to_string(),
            role: "admin",
        }),
    ))
}

/// `GET /api/v1/groups/mine`: the caller's live memberships and the
/// invitations waiting for them.
///
/// # Errors
/// 401 / 403 without a token or `groups:read`.
pub async fn my_groups(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    axum::Extension(auth_ctx): axum::Extension<crate::middleware::bearer::AuthContext>,
) -> Result<Json<MyGroupsResponse>, ApiError> {
    crate::middleware::scopes::check_scopes(&auth_ctx, &["groups:read"])?;
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "team_groups::my_groups",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;
    let groups = PersonTeamGroupRepository::my_groups_conn(&mut read).await?;
    let invitations = PersonTeamGroupRepository::my_invitations_conn(&mut read).await?;
    Ok(Json(MyGroupsResponse {
        groups: groups
            .into_iter()
            .map(|g| MyGroupEntry {
                group_id: g.group_id,
                display_name: g.display_name,
                kind: g.kind,
                status: g.status,
                role: g.role,
                created_by: g.created_by,
                invitable: g.invitable,
            })
            .collect(),
        invitations: invitations
            .into_iter()
            .map(|i| MyInvitationEntry {
                invitation_id: i.invitation_id,
                group_id: i.group_id,
                display_name: i.display_name,
                role: i.role,
                invited_by: i.invited_by,
                reason: i.reason,
                created_at: i.created_at.to_rfc3339(),
            })
            .collect(),
    }))
}

/// `POST /api/v1/groups/:id/invitations`: invite a Person. Writes a pending
/// invitation and NO membership. Only a group a Person made with
/// `POST /api/v1/groups/team` takes invitations. Once the invitee accepts,
/// their live-linked agents also read the group, and write in it at `writer`
/// or `admin`.
///
/// # Errors
/// 400 the invitee names no agent, is a role's node or a system identity, is
/// the caller, or a bad role or reason (whether the invitee is a Person is
/// never answered here, migration 286: only a registered Person can accept);
/// 403 the caller is not a Person, or not an admin of the group; 404 the
/// caller holds no live membership of it (as for a missing group); 409 the
/// invitee is already a member or already invited, or the group takes no
/// invitations (it is not an active team group a Person made, e.g. one the
/// operator made).
pub async fn invite_to_group(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    RequireScopeGroupsWrite(_auth): RequireScopeGroupsWrite,
    Path(group_id): Path<Uuid>,
    Json(body): Json<InviteToGroupRequest>,
) -> Result<(StatusCode, Json<InvitationResponse>), ApiError> {
    // Trimmed as the MCP twin trims it, so `" writer"` means the same on both.
    let role = body.role.trim().to_string();
    let mut tx = state
        .write_as(&viewer, "team_groups::invite_to_group")
        .await?;
    let invitation_id = PersonTeamGroupRepository::invite_conn(
        &mut tx,
        group_id,
        body.agent_id,
        &role,
        body.reason.as_deref(),
    )
    .await?;
    tx.commit().await.map_err(commit_error)?;
    Ok((
        StatusCode::CREATED,
        Json(InvitationResponse {
            invitation_id,
            group_id,
            agent_id: body.agent_id,
            role,
            status: "pending",
        }),
    ))
}

/// `POST /api/v1/group-invitations/:id/accept`: the invitee accepts; the
/// membership goes live now, and with it the invitee's live-linked agents'
/// access (read, and write at `writer` or `admin`).
///
/// # Errors
/// 403 the caller is not a Person signed in as themselves (an agent cannot
/// accept for its human); 404 the invitation is not addressed to the caller;
/// 409 it was already answered, has lapsed, or the caller is already a member.
pub async fn accept_invitation(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    RequireScopeGroupsWrite(_auth): RequireScopeGroupsWrite,
    Path(invitation_id): Path<Uuid>,
) -> Result<Json<AcceptInvitationResponse>, ApiError> {
    let mut tx = state
        .write_as(&viewer, "team_groups::accept_invitation")
        .await?;
    let accepted = PersonTeamGroupRepository::accept_conn(&mut tx, invitation_id).await?;
    tx.commit().await.map_err(commit_error)?;
    Ok(Json(AcceptInvitationResponse {
        invitation_id,
        group_id: accepted.group_id,
        membership_id: accepted.membership_id,
        role: accepted.role,
        status: "accepted",
    }))
}

/// `POST /api/v1/group-invitations/:id/decline`: the invitee declines; no
/// membership is written.
///
/// # Errors
/// 404 the invitation is not addressed to the caller; 409 it was already
/// answered.
pub async fn decline_invitation(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    RequireScopeGroupsWrite(_auth): RequireScopeGroupsWrite,
    Path(invitation_id): Path<Uuid>,
) -> Result<Json<DeclineInvitationResponse>, ApiError> {
    let mut tx = state
        .write_as(&viewer, "team_groups::decline_invitation")
        .await?;
    let group_id = PersonTeamGroupRepository::decline_conn(&mut tx, invitation_id).await?;
    tx.commit().await.map_err(commit_error)?;
    Ok(Json(DeclineInvitationResponse {
        invitation_id,
        group_id,
        status: "declined",
    }))
}
