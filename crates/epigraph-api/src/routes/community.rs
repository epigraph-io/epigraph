//! Community endpoints
//!
//! Public (GET):
//! - `GET /api/v1/communities` — list communities
//! - `GET /api/v1/communities/:id` — get community with members
//!
//! Protected (POST/DELETE):
//! - `POST /api/v1/communities` — create a community (`groups:write`)
//! - `POST /api/v1/communities/:id/members` — add perspective member
//!   (`groups:admin` **and** live membership)
//! - `DELETE /api/v1/communities/:id/members/:perspective_id` — remove member
//!   (`groups:admin` **and** live membership, or own perspective)
//!
//! Every route here is on the `protected` chain, so all five take a token. The
//! three writes take a scope on top of it, at the tier `routes/groups.rs` charges
//! for the same effect: migration 068 projects a community onto a `groups` row
//! ID-preservingly, so creating a community creates a group and a membership
//! granted here is the same `group_memberships` row
//! `POST /api/v1/groups/:id/members` grants. Create costs `groups:write` and
//! managing an existing membership costs `groups:admin`, which is the split
//! `epigraph_core::canonical_scopes` prescribes. See `create_community`'s and
//! `add_member`'s docs for the arguments and for what each choice costs.
//!
//! **The create and manage tiers are deliberately different, and the gap is
//! real.** A principal holding only `groups:write` can create a community and
//! cannot then add a member to it — not even itself, and not even as the
//! community's own sole live member. That is not an oversight here: it is
//! `routes/groups.rs`'s existing shape, where `create_group` makes the caller the
//! new group's `role='admin'` member *by construction* so no separate add is
//! needed, and community creation gets the same treatment via
//! `CommunityRepository::create`'s creator argument. Populating a community with
//! *other* perspectives is admin-only. Stated here because a reader comparing the
//! two scopes above will otherwise read the difference as an accident.
//!
//! # Tenancy: 2 of this file's 5 raw-pool sites are converted
//!
//! Conversion shard 6. `list_communities` and `get_community` each read through
//! one viewer-stamped connection from [`AppState::read_as`]; `CommunityRepository`
//! already spliced the viewer into `list`, `get_by_id` and `get_members`, so what
//! changed is which connection carries the session GUCs migration 077's
//! `communities_tenancy` policy reads.
//!
//! `get_community` is the reason this file is not "counter-only", and the pairing
//! is worth naming rather than simplifying: `communities` carries RLS and filters,
//! while `community_members` — the join `get_members` traverses — carries none at
//! migration head 92. The suppression `get_community` gains comes from the
//! `communities` row and from the `perspectives` rows `get_members` projects,
//! both FORCEd; the membership join itself narrows nothing and is not claimed to.
//!
//! `create_community`, `add_member` and `remove_member` are NOT converted: all
//! three WRITE, [`AppState::read_as`] is documented read-only, and a write routed
//! through a `ScopedRead` is rolled back on drop under
//! `SessionGucMode::Transaction` while still type-checking. Their owner is
//! `ScopedPool::begin_as` plus `Viewer::splice_write`.
//!
//! [`AppState::read_as`]: crate::AppState::read_as

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
#[cfg(feature = "db")]
use crate::state::AppState;
#[cfg(feature = "db")]
use axum::extract::State;
use axum::{
    extract::{Path, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// Request to create a new community
#[derive(Debug, Deserialize)]
pub struct CreateCommunityRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "default_governance_type")]
    pub governance_type: String,
    #[serde(default = "default_ownership_type")]
    pub ownership_type: String,
    /// Optional mass override: frame_id → mass assignments.
    /// When set, community-scoped belief for that frame uses this instead of combining member BBAs.
    pub mass_override: Option<serde_json::Value>,
}

fn default_governance_type() -> String {
    "open".to_string()
}

fn default_ownership_type() -> String {
    "public".to_string()
}

/// Request to add a member to a community
#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub perspective_id: Uuid,
}

/// Response for a community
#[derive(Debug, Serialize)]
pub struct CommunityResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub governance_type: Option<String>,
    pub ownership_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mass_override: Option<serde_json::Value>,
    pub created_at: String,
}

/// Response for a community with members
#[derive(Debug, Serialize)]
pub struct CommunityDetailResponse {
    pub community: CommunityResponse,
    pub member_count: usize,
    pub members: Vec<CommunityMemberEntry>,
}

/// A member entry in a community detail response
#[derive(Debug, Serialize)]
pub struct CommunityMemberEntry {
    pub perspective_id: Uuid,
    pub name: String,
    pub owner_agent_id: Option<Uuid>,
}

/// Query parameters for listing communities
#[derive(Debug, Deserialize)]
pub struct ListCommunitiesQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

// =============================================================================
// HANDLERS (db feature)
// =============================================================================

/// Create a new community
///
/// `POST /api/v1/communities`
///
/// # Requires `groups:write`
///
/// The same scope `routes/groups.rs::create_group` takes, for the same reason and
/// at the same tier. `CommunityRepository::create` inserts a `groups` row —
/// migration 068's ID-preserving projection — and, when the creator is `Some`,
/// a `group_memberships` row at `role = 'admin'`. So this route creates a
/// control-plane object and installs the caller as its administrator. Doing that
/// for the price of any token, while the route that spells the same effect
/// `POST /api/v1/groups` charges `groups:write`, is the cheaper-path asymmetry
/// that [`add_member`]'s doc argues against one layer down; leaving it here
/// while raising the two membership writes would have made the asymmetry
/// sharper rather than flatter.
///
/// `groups:write` and not `groups:admin`: `canonical_scopes` states that
/// `groups:write` is the CREATE tier ("any read-write principal may create a
/// group; it becomes that group's sole `role='admin'` member by construction")
/// and `groups:admin` the manage-an-existing-group tier. This is a create. The
/// availability cost is correspondingly small — `groups:write` is in the
/// read-write role, so `epigraph-wo` tokens keep working; `epigraph-ro` does not
/// and did not need to.
///
/// The gate is an extractor rather than an in-handler check for the reason given
/// on [`add_member`]: this handler takes a `Json` body, `FromRequestParts` runs
/// first, and a wrong scope must be 403 rather than 422 (issue #128).
///
/// # Errors
///
/// - 401 Unauthorized: no token, or a token naming no `agents.id`
/// - 403 Forbidden: missing `groups:write`
/// - 422 Unprocessable Entity: a name outside 1..=200 characters
#[cfg(feature = "db")]
pub async fn create_community(
    _scope: crate::middleware::bearer::RequireScopeGroupsWrite,
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Json(request): Json<CreateCommunityRequest>,
) -> Result<(StatusCode, Json<CommunityResponse>), ApiError> {
    if request.name.is_empty() || request.name.len() > 200 {
        return Err(ApiError::ValidationError {
            field: "name".to_string(),
            reason: "Name must be between 1 and 200 characters".to_string(),
        });
    }

    let pool = &state.db_pool;
    let row = epigraph_db::CommunityRepository::create(
        pool,
        &request.name,
        request.description.as_deref(),
        Some(&request.governance_type),
        Some(&request.ownership_type),
        // THE CREATOR, which is what closes migration 068's "a projected
        // community group has ZERO administrators until PR-12 gives it one".
        // `Viewer::principal()` is `None` only for a bypass/system viewer,
        // which is not a principal that should own a community — that case
        // still lands on the memberless-group bootstrap path, which
        // `CommunityRepository::add_member` treats as open.
        //
        // This route is on the PROTECTED router, so `ViewerExtractor` already
        // 401s an unauthenticated caller; taking the viewer here changes who
        // the creator IS, not whether the route is reachable. It touches
        // neither register in `viewer_route_table_lint.rs` — `community.rs`
        // appears in neither.
        viewer.principal(),
    )
    .await?;

    // Emit community.formed event
    let event_store = super::events::global_event_store();
    event_store
        .push(
            "community.formed".to_string(),
            None,
            serde_json::json!({
                "community_id": row.id,
                "name": row.name,
                "governance_type": request.governance_type,
            }),
        )
        .await;

    Ok((StatusCode::CREATED, Json(community_to_response(row))))
}

/// List all communities
///
/// `GET /api/v1/communities`
#[cfg(feature = "db")]
pub async fn list_communities(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Query(params): Query<ListCommunitiesQuery>,
) -> Result<Json<Vec<CommunityResponse>>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "list_communities",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;
    let rows =
        epigraph_db::CommunityRepository::list(&mut *read, &viewer, params.limit, params.offset)
            .await?;

    Ok(Json(rows.into_iter().map(community_to_response).collect()))
}

/// Get a community by ID with members
///
/// `GET /api/v1/communities/:id`
#[cfg(feature = "db")]
pub async fn get_community(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<CommunityDetailResponse>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_community",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let row = epigraph_db::CommunityRepository::get_by_id(&mut *read, &viewer, id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "community".to_string(),
            id: id.to_string(),
        })?;

    let members = epigraph_db::CommunityRepository::get_members(&mut *read, &viewer, id).await?;

    let member_entries: Vec<CommunityMemberEntry> = members
        .into_iter()
        .map(|p| CommunityMemberEntry {
            perspective_id: p.id,
            name: p.name,
            owner_agent_id: p.owner_agent_id,
        })
        .collect();

    Ok(Json(CommunityDetailResponse {
        community: community_to_response(row),
        member_count: member_entries.len(),
        members: member_entries,
    }))
}

/// Add a perspective member to a community
///
/// `POST /api/v1/communities/:id/members`
///
/// # Requires `groups:admin`
///
/// Scope AND membership, never OR — the shape `routes/groups.rs::add_member`
/// already uses and the one `epigraph_core::canonical_scopes` prescribes for
/// managing an existing group's membership. Membership is enforced in the repo
/// layer (`CommunityRepository::add_member`: the acting agent must hold a live
/// membership in the community's projected group, with a bootstrap exception for
/// a group that has none). Scope was the missing half, and it is the half a
/// scope-less route cannot supply: without it a token that may not manage a
/// group through `POST /api/v1/groups/:id/members` could grant the same
/// `group_memberships` row through this route, because migration 068 projects a
/// community onto a group ID-preservingly and this handler's write is projected
/// onto that group. Read authority granted here is read authority, however it
/// was spelled.
///
/// `groups:admin` rather than `groups:write` because `groups:write` gates
/// *creating* a group — "any read-write principal may create a group; it becomes
/// that group's sole `role='admin'` member by construction, which is why managing
/// an EXISTING group needs `groups:admin` plus membership rather than this
/// scope", per `canonical_scopes`' own comment. This route manages an existing
/// group's membership, so it takes the tier that names that operation. The
/// repo-layer rule here is already *weaker* than `groups.rs`'s
/// (`require_group_admin` demands a live `role='admin'` membership; a projected
/// community group has no admins to demand, so "a live member" is the strongest
/// available rule), which is a reason to match the scope tier rather than
/// discount it: weakening both halves is what made this route the cheaper path.
///
/// **Availability cost.** `groups:admin` is in `ADMIN_ONLY_SCOPES`, so it is
/// absent from `read_only_scopes()`, from the read-write role, from
/// `AGENT_PROVISION_SCOPES` and from `PUBLIC_CLIENT_READ_SCOPES`. Every
/// `epigraph-ro` and `epigraph-wo` token and every auto-provisioned agent now
/// gets 403 on this route and on the DELETE below. The alternative considered
/// was minting a `communities:write` scope, which would mean editing
/// `canonical_scopes.rs`, its role-boundary assertions and `bootstrap_clients`;
/// it was rejected on the precedent `routes/webhooks.rs::list_webhooks` set when
/// it declined a `webhooks:read` scope for the same reason, and because a new
/// scope would recreate the asymmetry this fix exists to remove.
///
/// The gate is an extractor, not an in-handler check: this handler takes a
/// `Json` body, and `FromRequestParts` runs first, so a wrong scope is 403 rather
/// than 422 (issue #128). It also introduces no occurrence of the optional-
/// `Extension` idiom that `viewer_route_table_lint.rs` counts, so neither of that
/// file's registers moves — `community.rs` appears in none of them.
///
/// # Errors
///
/// - 401 Unauthorized: no token, or a token naming no `agents.id`
/// - 403 Forbidden: missing `groups:admin`, or not a live member of the community
/// - 404 Not Found: no such community, or no such perspective
#[cfg(feature = "db")]
pub async fn add_member(
    _scope: crate::middleware::bearer::RequireScopeGroupsAdmin,
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(community_id): Path<Uuid>,
    Json(request): Json<AddMemberRequest>,
) -> Result<StatusCode, ApiError> {
    let pool = &state.db_pool;

    // Verify community exists
    epigraph_db::CommunityRepository::get_by_id(pool, &viewer, community_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "community".to_string(),
            id: community_id.to_string(),
        })?;

    // Verify perspective exists
    epigraph_db::PerspectiveRepository::get_by_id(pool, &viewer, request.perspective_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "perspective".to_string(),
            id: request.perspective_id.to_string(),
        })?;

    // CLOSED MEMBERSHIP (PR-12). `POST /api/v1/communities/:id/members` had no
    // authorization at all beyond the two existence checks above, and PR-12 is
    // what makes that a confidentiality problem rather than a bookkeeping one:
    // the projected `group_memberships` row is read authority the moment PR-17
    // arms the predicate, so a stranger could create a perspective, POST it
    // into any community, and read that community's private corpus. The rule —
    // and why it is "a live member" and not "an admin" — is in
    // `epigraph-db/src/repos/community.rs`'s module docs.
    //
    // This is the MEMBERSHIP half. The SCOPE half is the `RequireScopeGroupsAdmin`
    // extractor in the signature, which ran before this body was entered. Both,
    // never either: see the handler doc.
    //
    // Batch F: the rule and the write are ONE statement in a SECURITY DEFINER
    // function, on a transaction stamped from the caller's viewer, so the actor
    // the function trusts is the stamped principal (see migration 106).
    let mut tx = membership_tx(&state, &viewer, "community::add_member").await?;
    let outcome = epigraph_db::CommunityRepository::add_member(
        &mut *tx,
        viewer.principal(),
        community_id,
        request.perspective_id,
    )
    .await?;
    match outcome {
        epigraph_db::MembershipOutcome::DeniedNotAMember => {
            return Err(ApiError::Forbidden {
                reason: "only a live member of this community may add members".to_string(),
            })
        }
        epigraph_db::MembershipOutcome::DeniedReadmitNeedsAdmin => {
            return Err(ApiError::Forbidden {
                reason: "this perspective's owner was removed from the community; only a \
                         live admin of the community may re-admit it"
                    .to_string(),
            })
        }
        // `add_member` never removes anyone, so it cannot report this; mapped
        // rather than panicked on, because a refusal is never a 500.
        epigraph_db::MembershipOutcome::LastAdmin => {
            return Err(ApiError::Conflict {
                reason: "the membership change would leave the community without an admin"
                    .to_string(),
            })
        }
        epigraph_db::MembershipOutcome::Applied | epigraph_db::MembershipOutcome::NotFound => {}
    }
    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit the membership change: {e}"),
    })?;

    // Materialize MEMBER_OF edge (perspective → community)
    let _ = epigraph_db::EdgeRepository::create(
        pool,
        request.perspective_id,
        "perspective",
        community_id,
        "community",
        "MEMBER_OF",
        None,
        None,
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Remove a perspective member from a community
///
/// `DELETE /api/v1/communities/:id/members/:perspective_id`
///
/// # Requires `groups:admin`
///
/// The integrity twin of [`add_member`], and gated identically for the same
/// reason: the write revokes a projected `group_memberships` row, so it is
/// group-membership management whichever route reaches it. See [`add_member`]'s
/// doc for the scope-tier argument, the availability cost, and the rejected
/// alternative. The repo layer keeps its own rule on top — a live ADMIN of the
/// community evicting, or the perspective's own owner removing itself — and
/// never removes the community's last live admin (batch F).
///
/// # Errors
///
/// - 401 Unauthorized: no token, or a token naming no `agents.id`
/// - 403 Forbidden: missing `groups:admin`, or neither a live admin nor the
///   perspective's owner
/// - 404 Not Found: no such membership
/// - 409 Conflict: the removal would leave the community with no live admin
#[cfg(feature = "db")]
pub async fn remove_member(
    _scope: crate::middleware::bearer::RequireScopeGroupsAdmin,
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path((community_id, perspective_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    // THE VIEWER IS NEW HERE. This handler previously extracted nothing at all,
    // so self-service EVICTION was as open as self-service joining: any caller
    // could revoke any member. PR-12 makes the revocation real (`revoked_at =
    // now()` on the projected `group_memberships` row), which turns that from a
    // bookkeeping no-op into a denial of read against a legitimate member.
    // Adding the extractor here does not touch `viewer_route_table_lint.rs` —
    // `community.rs` appears in neither of its registers. The scope half, which
    // the viewer does not supply, is the `RequireScopeGroupsAdmin` extractor
    // above it.
    //
    // Batch F: decided and written in ONE statement under the roster lock, on a
    // transaction stamped from the caller's viewer (migration 106). Only an
    // admin evicts, a member may leave, and the last admin is never removed.
    let mut tx = membership_tx(&state, &viewer, "community::remove_member").await?;
    let outcome = epigraph_db::CommunityRepository::remove_member(
        &mut *tx,
        viewer.principal(),
        community_id,
        perspective_id,
    )
    .await?;
    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit the membership change: {e}"),
    })?;
    match outcome {
        epigraph_db::MembershipOutcome::Applied => Ok(StatusCode::NO_CONTENT),
        epigraph_db::MembershipOutcome::LastAdmin => Err(ApiError::Conflict {
            reason: "cannot remove the community's last admin; promote another member to \
                     admin first"
                .to_string(),
        }),
        epigraph_db::MembershipOutcome::DeniedNotAMember
        | epigraph_db::MembershipOutcome::DeniedReadmitNeedsAdmin => Err(ApiError::Forbidden {
            reason: "only an admin of this community, or the perspective's own owner, may \
                     remove members"
                .to_string(),
        }),
        epigraph_db::MembershipOutcome::NotFound => Err(ApiError::NotFound {
            entity: "community_member".to_string(),
            id: format!("{community_id}/{perspective_id}"),
        }),
    }
}

/// A transaction stamped from `viewer`, for the two membership writes.
///
/// `epigraph_community_add_member` / `_remove_member` (migration 106) take the
/// actor from the connection's stamped principal on a non-maintenance session,
/// so an unstamped `state.db_pool` checkout would deny every call. Refuses
/// rather than falling back to the pool, as `groups::rotate_key` does.
#[cfg(feature = "db")]
async fn membership_tx<'s>(
    state: &'s AppState,
    viewer: &epigraph_db::Viewer,
    handler: &'static str,
) -> Result<epigraph_db::ScopedTx<'s>, ApiError> {
    let scoped = state.scoped.as_ref().ok_or_else(|| {
        tracing::error!(
            target: "tenancy.scoped_write",
            handler,
            "membership change refused: this process was not built from a ScopedPool"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped transaction".to_string(),
        }
    })?;
    scoped.begin_as(viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_write",
            error = %e,
            handler,
            "could not begin a viewer-stamped transaction"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped transaction".to_string(),
        }
    })
}

#[cfg(feature = "db")]
fn community_to_response(row: epigraph_db::CommunityRow) -> CommunityResponse {
    CommunityResponse {
        id: row.id,
        name: row.name,
        description: row.description,
        governance_type: row.governance_type,
        ownership_type: row.ownership_type,
        mass_override: row.mass_override,
        created_at: row.created_at.to_rfc3339(),
    }
}

// =============================================================================
// HANDLERS (non-db stubs)
// =============================================================================

#[cfg(not(feature = "db"))]
pub async fn create_community(
    Json(request): Json<CreateCommunityRequest>,
) -> Result<(StatusCode, Json<CommunityResponse>), ApiError> {
    if request.name.is_empty() || request.name.len() > 200 {
        return Err(ApiError::ValidationError {
            field: "name".to_string(),
            reason: "Name must be between 1 and 200 characters".to_string(),
        });
    }

    Ok((
        StatusCode::CREATED,
        Json(CommunityResponse {
            id: Uuid::new_v4(),
            name: request.name,
            description: request.description,
            governance_type: Some(request.governance_type),
            ownership_type: Some(request.ownership_type),
            mass_override: request.mass_override,
            created_at: chrono::Utc::now().to_rfc3339(),
        }),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn list_communities(
    Query(_params): Query<ListCommunitiesQuery>,
) -> Result<Json<Vec<CommunityResponse>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[cfg(not(feature = "db"))]
pub async fn get_community(
    Path(id): Path<Uuid>,
) -> Result<Json<CommunityDetailResponse>, ApiError> {
    Err(ApiError::NotFound {
        entity: "community".to_string(),
        id: id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn add_member(
    Path(_community_id): Path<Uuid>,
    Json(_request): Json<AddMemberRequest>,
) -> Result<StatusCode, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Community membership requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn remove_member(
    Path((_community_id, _perspective_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Community membership requires database".to_string(),
    })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_community_request_defaults() {
        let req: CreateCommunityRequest =
            serde_json::from_str(r#"{"name":"test_community"}"#).unwrap();
        assert_eq!(req.name, "test_community");
        assert_eq!(req.governance_type, "open");
        assert_eq!(req.ownership_type, "public");
        assert!(req.description.is_none());
    }

    #[test]
    fn list_communities_query_defaults() {
        let q: ListCommunitiesQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.limit, 50);
        assert_eq!(q.offset, 0);
    }

    #[test]
    fn add_member_request_parses() {
        let id = Uuid::new_v4();
        let json = format!(r#"{{"perspective_id":"{}"}}"#, id);
        let req: AddMemberRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.perspective_id, id);
    }
}
