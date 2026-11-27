//! HTTP twins of the MCP visibility tools (docs/tenancy/claim-visibility-controls.md,
//! migration 206):
//!
//! * `POST /api/v1/claims/publicize` `{claim_ids | selection, dry_run?, reason}`:
//!   group → public,
//!   team admins only (owner decision D-V2), never an operated agent
//!   (migration 242);
//! * `POST /api/v1/claims/share-with-team`
//!   `{claim_ids | selection, dry_run?, group_id, reason}`:
//!   private → a team the caller writes by its own membership, never by an
//!   operated agent (migration 242);
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
use epigraph_engine::visibility_act::{self, ActReport, ActTarget, Selection, WideningAct};

/// `POST /api/v1/claims/publicize`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PublicizeClaimsRequest {
    /// 1 to 500 claim ids. All or nothing. Omit when giving `selection`.
    #[serde(default)]
    pub claim_ids: Vec<Uuid>,
    /// Instead of `claim_ids`: a root and the closure walked from it (backlog
    /// 02d9e9a1).
    #[serde(default)]
    pub selection: Option<SelectionRequest>,
    /// `true`: change nothing, return the plan.
    #[serde(default)]
    pub dry_run: bool,
    /// Required; recorded in the `claim.publicized` audit event.
    pub reason: String,
}

/// `POST /api/v1/claims/share-with-team`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ShareClaimsWithTeamRequest {
    /// 1 to 500 private claim ids. All or nothing. Omit when giving
    /// `selection`.
    #[serde(default)]
    pub claim_ids: Vec<Uuid>,
    /// Instead of `claim_ids`: a root and the closure walked from it (backlog
    /// 02d9e9a1).
    #[serde(default)]
    pub selection: Option<SelectionRequest>,
    /// `true`: change nothing, return the plan.
    #[serde(default)]
    pub dry_run: bool,
    /// The team to move them into.
    pub group_id: Uuid,
    /// Required; recorded in the `claim.shared_with_team` audit event.
    pub reason: String,
}

/// A root claim and the closure to walk from it
/// (`epigraph_engine::visibility_act::Selection`). Every claim reached that
/// the act may move goes with the root; every other is a boundary, reported
/// with its reason, left untouched and not walked through.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SelectionRequest {
    /// The claim to start from.
    pub root: Uuid,
    /// Edge types to follow (default `decomposes_to`, `supports`).
    #[serde(default)]
    pub edge_types: Option<Vec<String>>,
    /// `outgoing` (default), `incoming` or `both`.
    #[serde(default)]
    pub direction: Option<String>,
    /// Edges walked from the root, 0 to 10 (default 3).
    #[serde(default)]
    pub max_depth: Option<u32>,
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
    /// Present for a selection or a dry run: whether this was a dry run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
    /// Present for a selection or a dry run: `{selection, claims,
    /// boundaries, capped, effects?}`
    /// (`epigraph_engine::visibility_act::VisibilityPlan`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub plan: Option<serde_json::Value>,
    /// Empty on a dry run.
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

/// What the request names: `claim_ids` or a `selection`, exactly one.
fn target_of(
    claim_ids: &[Uuid],
    selection: Option<&SelectionRequest>,
) -> Result<ActTarget, ApiError> {
    match selection {
        None => {
            bounded(claim_ids)?;
            Ok(ActTarget::Ids(claim_ids.to_vec()))
        }
        Some(_) if !claim_ids.is_empty() => Err(ApiError::ValidationError {
            field: "selection".to_string(),
            reason: "give claim_ids or selection, not both".to_string(),
        }),
        Some(sel) => Selection::new(
            sel.root,
            sel.edge_types.as_deref(),
            sel.direction.as_deref(),
            sel.max_depth,
        )
        .map(ActTarget::Selection)
        .map_err(|reason| ApiError::ValidationError {
            field: "selection".to_string(),
            reason,
        }),
    }
}

fn respond(report: ActReport, dry_run: bool) -> Result<Json<VisibilityActResponse>, ApiError> {
    let plan = report
        .plan
        .map(serde_json::to_value)
        .transpose()
        .map_err(|e| ApiError::InternalError {
            message: format!("plan: {e}"),
        })?;
    Ok(Json(VisibilityActResponse {
        dry_run: plan.as_ref().map(|_| dry_run),
        plan,
        results: report
            .results
            .into_iter()
            .map(|o| VisibilityActItem {
                claim_id: o.claim_id,
                outcome: o.outcome,
            })
            .collect(),
    }))
}

/// A widening act's failure: a refusal or database error as every
/// visibility route maps it, a failed cached-belief refold as a 500 (the
/// transaction is dropped, so nothing was changed).
fn act_error(e: epigraph_engine::visibility_act::VisibilityActError) -> ApiError {
    match e {
        epigraph_engine::visibility_act::VisibilityActError::Db(e) => ApiError::from(e),
        epigraph_engine::visibility_act::VisibilityActError::Cache(message) => {
            ApiError::InternalError { message }
        }
    }
}

/// `POST /api/v1/claims/publicize`: by `claim_ids`, or by a `selection`
/// walked from a root (backlog 02d9e9a1); `dry_run` returns the plan and
/// changes nothing.
///
/// # Errors
/// 400 bad request (or a selection over 500 claims), 404 a claim (or root)
/// the caller cannot read, 403 not a team admin or an operated agent
/// (migration 242), 409 a sealed claim; nothing changes on any of them.
pub async fn publicize_claims(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(body): Json<PublicizeClaimsRequest>,
) -> Result<Json<VisibilityActResponse>, ApiError> {
    require_write(auth_ctx, "POST /api/v1/claims/publicize")?;
    let target = target_of(&body.claim_ids, body.selection.as_ref())?;
    let mut tx = state.write_as(&viewer, "publicize_claims").await?;
    // The act and the moved claims' cached-belief refold, in this transaction
    // (`epigraph_engine::visibility_act`; backlog 31285392).
    let report = visibility_act::act(
        &mut tx,
        &viewer,
        WideningAct::Publicize,
        &target,
        &body.reason,
        body.dry_run,
    )
    .await
    .map_err(act_error)?;
    // A dry run changes nothing: its transaction is dropped, not committed.
    let done = if body.dry_run {
        tx.rollback().await
    } else {
        tx.commit().await
    };
    done.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit: {e}"),
    })?;
    respond(report, body.dry_run)
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
    let target = target_of(&body.claim_ids, body.selection.as_ref())?;
    let mut tx = state.write_as(&viewer, "share_claims_with_team").await?;
    let report = visibility_act::act(
        &mut tx,
        &viewer,
        WideningAct::ShareWithTeam {
            group_id: body.group_id,
        },
        &target,
        &body.reason,
        body.dry_run,
    )
    .await
    .map_err(act_error)?;
    // A dry run changes nothing: its transaction is dropped, not committed.
    let done = if body.dry_run {
        tx.rollback().await
    } else {
        tx.commit().await
    };
    done.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit: {e}"),
    })?;
    respond(report, body.dry_run)
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
