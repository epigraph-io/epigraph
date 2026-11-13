//! HTTP twins of the MCP visibility tools (docs/tenancy/claim-visibility-controls.md,
//! migration 206):
//!
//! * `POST /api/v1/claims/publicize` `{claim_ids, reason}`: group → public,
//!   team admins only (owner decision D-V2);
//! * `POST /api/v1/claims/share-with-team` `{claim_ids, group_id, reason}`:
//!   private → a team the caller writes;
//! * `PUT /api/v1/agents/me/default-group` `{group_id}` | `{private: true}` |
//!   `{}` / `null`: the caller's default (D-V1; private since migration 209);
//! * `PUT /api/v1/agents/:id/default-group`, the same body: the default of an
//!   agent the caller operates through a live, non-retired operator link (or
//!   of the caller itself), migration 209.
//!
//! Each runs ONE transaction stamped as the caller (`AppState::write_as`) and
//! calls the migration-206 (or 209) definer on it. The definer makes the authority
//! decision and writes the audit row, so this file and `epigraph-mcp`'s
//! `tools/visibility.rs` cannot disagree about who may do what. A refusal maps
//! by its kind (`ApiError::from(DbError)`: input 400, authority 403, state 409),
//! and a claim the caller cannot read is a 404, exactly as a missing one.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;
use epigraph_db::{ClaimRepository, DefaultGroupSetting};

/// `POST /api/v1/claims/publicize`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PublicizeClaimsRequest {
    /// 1 to 500 claim ids. All or nothing.
    pub claim_ids: Vec<Uuid>,
    /// Required; recorded in the `claim.publicized` audit event.
    pub reason: String,
}

/// `POST /api/v1/claims/share-with-team`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ShareClaimsWithTeamRequest {
    /// 1 to 500 private claim ids. All or nothing.
    pub claim_ids: Vec<Uuid>,
    /// The team to move them into.
    pub group_id: Uuid,
    /// Required; recorded in the `claim.shared_with_team` audit event.
    pub reason: String,
}

/// `PUT /api/v1/agents/me/default-group` and `PUT /api/v1/agents/:id/default-group`.
///
/// `{"group_id": "<team>"}` sets a team; `{"private": true}` makes the default
/// private (a write that names no visibility lands in the agent's home group,
/// whatever its human's default); `{}`, `{"group_id": null}` or a `null` body
/// clears it, so the agent inherits its live human's default again. Both a
/// group and `private: true` is a 400.
#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub struct SetDefaultGroupRequest {
    /// The team, or `null`.
    #[serde(default)]
    pub group_id: Option<Uuid>,
    /// `true` for a private default (migration 209).
    #[serde(default)]
    pub private: bool,
}

impl SetDefaultGroupRequest {
    fn setting(&self) -> Result<DefaultGroupSetting, ApiError> {
        match (self.group_id, self.private) {
            (Some(_), true) => Err(ApiError::ValidationError {
                field: "private".to_string(),
                reason: "a default is a team (group_id) or private, not both".to_string(),
            }),
            (Some(g), false) => Ok(DefaultGroupSetting::Team(g)),
            (None, true) => Ok(DefaultGroupSetting::Private),
            (None, false) => Ok(DefaultGroupSetting::Clear),
        }
    }
}

/// One claim's outcome.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct VisibilityActItem {
    pub claim_id: Uuid,
    /// `publicized` / `already_public`, or `shared`.
    pub outcome: String,
}

/// The response of both claim acts.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct VisibilityActResponse {
    pub results: Vec<VisibilityActItem>,
}

/// The response of both default-group routes.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DefaultGroupResponse {
    /// The agent whose default it is.
    pub agent_id: Uuid,
    pub default_group_id: Option<Uuid>,
    /// `true` when the default is private (migration 209).
    pub default_private: bool,
    /// How the caller was admitted: `self`, or `operator` (its live human
    /// operator, through a live operator link).
    pub set_by: String,
    /// `[{group_id, via: own | operator}]`: the teams the agent may write.
    pub writable_teams: Vec<serde_json::Value>,
}

fn require_write(
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    route: &str,
) -> Result<(), ApiError> {
    let auth = auth_ctx
        .ok_or_else(|| ApiError::Unauthorized {
            reason: format!("{route} requires authentication"),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])
}

fn bounded(ids: &[Uuid]) -> Result<(), ApiError> {
    if ids.is_empty() || ids.len() > 500 {
        return Err(ApiError::ValidationError {
            field: "claim_ids".to_string(),
            reason: "1 to 500 claim ids".to_string(),
        });
    }
    Ok(())
}

fn respond(outcomes: Vec<epigraph_db::VisibilityActOutcome>) -> Json<VisibilityActResponse> {
    Json(VisibilityActResponse {
        results: outcomes
            .into_iter()
            .map(|o| VisibilityActItem {
                claim_id: o.claim_id,
                outcome: o.outcome,
            })
            .collect(),
    })
}

/// `POST /api/v1/claims/publicize`
///
/// # Errors
/// 400 bad request, 404 a claim the caller cannot read, 403 not a team admin,
/// 409 a sealed claim; nothing changes on any of them.
pub async fn publicize_claims(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(body): Json<PublicizeClaimsRequest>,
) -> Result<Json<VisibilityActResponse>, ApiError> {
    require_write(auth_ctx, "POST /api/v1/claims/publicize")?;
    bounded(&body.claim_ids)?;
    let mut tx = state.write_as(&viewer, "publicize_claims").await?;
    let outcomes = ClaimRepository::publicize_conn(&mut tx, &body.claim_ids, &body.reason).await?;
    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit: {e}"),
    })?;
    Ok(respond(outcomes))
}

/// `POST /api/v1/claims/share-with-team`
///
/// # Errors
/// As [`publicize_claims`].
pub async fn share_claims_with_team(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(body): Json<ShareClaimsWithTeamRequest>,
) -> Result<Json<VisibilityActResponse>, ApiError> {
    require_write(auth_ctx, "POST /api/v1/claims/share-with-team")?;
    bounded(&body.claim_ids)?;
    let mut tx = state.write_as(&viewer, "share_claims_with_team").await?;
    let outcomes = ClaimRepository::share_with_team_conn(
        &mut tx,
        &body.claim_ids,
        body.group_id,
        &body.reason,
    )
    .await?;
    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit: {e}"),
    })?;
    Ok(respond(outcomes))
}

/// Set `agent`'s default on one transaction stamped as the caller; the
/// definer decides who may.
async fn set_default_for(
    state: &AppState,
    viewer: &epigraph_db::Viewer,
    agent: Uuid,
    body: Option<SetDefaultGroupRequest>,
) -> Result<Json<DefaultGroupResponse>, ApiError> {
    let setting = body.unwrap_or_default().setting()?;
    let mut tx = state.write_as(viewer, "set_default_group").await?;
    let set_by = ClaimRepository::set_agent_default_conn(&mut tx, agent, setting).await?;
    let teams = ClaimRepository::writable_teams(&mut tx, agent).await?;
    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit: {e}"),
    })?;
    Ok(Json(DefaultGroupResponse {
        agent_id: agent,
        default_group_id: setting.group(),
        default_private: setting.private(),
        set_by,
        writable_teams: teams
            .into_iter()
            .map(|(g, via)| serde_json::json!({"group_id": g, "via": via}))
            .collect(),
    }))
}

/// `PUT /api/v1/agents/me/default-group`
///
/// # Errors
/// 400 for a group together with `private: true`; 403 for a group that is not
/// one of the caller's writable teams.
pub async fn set_default_group(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(body): Json<Option<SetDefaultGroupRequest>>,
) -> Result<Json<DefaultGroupResponse>, ApiError> {
    require_write(auth_ctx, "PUT /api/v1/agents/me/default-group")?;
    let agent = viewer.principal().ok_or_else(|| ApiError::Unauthorized {
        reason: "a default team belongs to an authenticated agent".to_string(),
    })?;
    set_default_for(&state, &viewer, agent, body).await
}

/// `PUT /api/v1/agents/:id/default-group` (migration 209): the default of an
/// agent the caller operates through a live, non-retired operator link, or of
/// the caller itself.
///
/// # Errors
/// 400 for a group together with `private: true`; 403 when the caller is
/// neither the agent nor its live human operator (whether or not the agent
/// exists), or for a team the AGENT may not write. Nothing changes on either.
pub async fn set_agent_default_group(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(agent): Path<Uuid>,
    Json(body): Json<Option<SetDefaultGroupRequest>>,
) -> Result<Json<DefaultGroupResponse>, ApiError> {
    require_write(auth_ctx, "PUT /api/v1/agents/:id/default-group")?;
    if viewer.principal().is_none() {
        return Err(ApiError::Unauthorized {
            reason: "setting a default needs an authenticated agent".to_string(),
        });
    }
    set_default_for(&state, &viewer, agent, body).await
}
