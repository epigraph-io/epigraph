//! HTTP twins of the MCP visibility tools (docs/tenancy/claim-visibility-controls.md,
//! migration 200):
//!
//! * `POST /api/v1/claims/publicize` `{claim_ids, reason}`: group → public,
//!   team admins only (owner decision D-V2);
//! * `POST /api/v1/claims/share-with-team` `{claim_ids, group_id, reason}`:
//!   private → a team the caller writes;
//! * `PUT /api/v1/agents/me/default-group` `{group_id | null}`: the caller's
//!   default team (D-V1).
//!
//! Each runs ONE transaction stamped as the caller (`AppState::write_as`) and
//! calls the migration-200 definer on it. The definer makes the authority
//! decision and writes the audit row, so this file and `epigraph-mcp`'s
//! `tools/visibility.rs` cannot disagree about who may do what. A refusal maps
//! by its kind (`ApiError::from(DbError)`: input 400, authority 403, state 409),
//! and a claim the caller cannot read is a 404, exactly as a missing one.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;
use epigraph_db::ClaimRepository;

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

/// `PUT /api/v1/agents/me/default-group`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SetDefaultGroupRequest {
    /// The team, or `null` to clear the default.
    #[serde(default)]
    pub group_id: Option<Uuid>,
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

/// The response of `PUT /api/v1/agents/me/default-group`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DefaultGroupResponse {
    pub agent_id: Uuid,
    pub default_group_id: Option<Uuid>,
    /// `[{group_id, via: own | operator}]`: the teams the caller may write.
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

/// `PUT /api/v1/agents/me/default-group`
///
/// # Errors
/// 403 for a group that is not one of the caller's writable teams.
pub async fn set_default_group(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(body): Json<SetDefaultGroupRequest>,
) -> Result<Json<DefaultGroupResponse>, ApiError> {
    require_write(auth_ctx, "PUT /api/v1/agents/me/default-group")?;
    let agent = viewer.principal().ok_or_else(|| ApiError::Unauthorized {
        reason: "a default team belongs to an authenticated agent".to_string(),
    })?;
    let mut tx = state.write_as(&viewer, "set_default_group").await?;
    ClaimRepository::set_default_group_conn(&mut tx, body.group_id).await?;
    let teams = ClaimRepository::writable_teams(&mut tx, agent).await?;
    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit: {e}"),
    })?;
    Ok(Json(DefaultGroupResponse {
        agent_id: agent,
        default_group_id: body.group_id,
        writable_teams: teams
            .into_iter()
            .map(|(g, via)| serde_json::json!({"group_id": g, "via": via}))
            .collect(),
    }))
}
