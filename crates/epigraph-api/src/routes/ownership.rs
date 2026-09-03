//! Ownership & partition endpoints (§3 Ownership/Privacy Layer)
//!
//! Public (GET):
//! - `GET /api/v1/ownership/:node_id` — get ownership info for a node
//! - `GET /api/v1/agents/:id/owned-nodes` — list nodes owned by an agent
//!
//! Protected (POST/PUT):
//! - `POST /api/v1/ownership` — assign ownership partition
//! - `PUT /api/v1/ownership/:node_id` — update partition type

use crate::errors::ApiError;
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

/// Request to assign ownership of a node.
///
/// For `community` partitions, pass `community_id` to specify which community
/// gates access. The `owner_id` must still be a valid agent UUID (FK constraint).
#[derive(Debug, Deserialize)]
pub struct AssignOwnershipRequest {
    pub node_id: Uuid,
    pub node_type: String,
    #[serde(default = "default_partition")]
    pub partition_type: String,
    pub owner_id: Uuid,
    /// For community partitions: the community UUID that gates read access.
    pub community_id: Option<Uuid>,
}

fn default_partition() -> String {
    "public".to_string()
}

/// Request to update the partition type of a node
#[derive(Debug, Deserialize)]
pub struct UpdatePartitionRequest {
    pub partition_type: String,
}

/// Response for ownership info
#[derive(Debug, Serialize)]
pub struct OwnershipResponse {
    pub node_id: Uuid,
    pub node_type: String,
    pub partition_type: String,
    pub owner_id: Uuid,
    /// DEPRECATED. Always `None` for anything this handler writes after
    /// migration 068; retained on the wire until the column is dropped in 084
    /// so an existing client's deserializer does not break.
    pub encryption_key_id: Option<String>,
    /// The gating community for `partition_type = "community"` (migration 068).
    pub community_id: Option<Uuid>,
    pub created_at: String,
    pub updated_at: String,
}

/// Query parameters for listing owned nodes
#[derive(Debug, Deserialize)]
pub struct OwnedNodesQuery {
    pub node_type: Option<String>,
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

/// Build the [`Principal`] the write gate decides against.
///
/// The write-capable group set comes from the same resolved `Viewer` the read
/// path uses — `Viewer::resolve` already filtered it to roles `admin` and
/// `writer` (migration 060's `group_memberships_role_check`), so a `reader`
/// cannot arrive here holding write authority.
///
/// A `Bypass` viewer has no principal. It cannot reach an HTTP handler
/// (`no_bypass_in_handlers.rs` forbids minting one in `routes/`, and
/// `ViewerExtractor` only ever yields `Scoped`), so this returns 403 rather
/// than inventing an identity.
#[cfg(feature = "db")]
fn principal_of(viewer: &epigraph_db::Viewer) -> Result<epigraph_interfaces::Principal, ApiError> {
    let id = viewer.principal().ok_or_else(|| ApiError::Forbidden {
        reason: "this operation requires an authenticated principal".to_string(),
    })?;
    Ok(epigraph_interfaces::Principal::new(
        id,
        viewer.writable_groups().to_vec(),
    ))
}

/// Ask the installed [`PolicyGate`](epigraph_interfaces::PolicyGate) and turn a
/// denial into a 403.
///
/// The denial reason is logged, **not** returned: it names the resource's owner,
/// which the caller may not be entitled to learn.
///
/// # Where the owner in the decision comes from
///
/// `owner_of_record` is `Some` only when the `ownership` row exists, and is then
/// the value the **database** holds. `requested_owner` is the value the *caller*
/// named; it reaches the gate's owner slot in exactly one case — when it equals
/// the caller's own principal, i.e. a self-claim of a node nobody has claimed.
/// In every other combination the [`ResourceRef`] is left **undeclared**, and
/// `GroupPolicyGate` denies an undeclared resource outright ("nothing is
/// authorized by absence"). Caller-supplied input can therefore never widen the
/// decision; the widest thing it can do is name the caller.
///
/// `update_partition` passes `requested_owner: None` — it 404s on a node with no
/// row, so its owner slot can only ever hold the database's value.
#[cfg(feature = "db")]
async fn require_declassify_authority(
    state: &AppState,
    viewer: &epigraph_db::Viewer,
    node_id: Uuid,
    owner_of_record: Option<Uuid>,
    requested_owner: Option<Uuid>,
) -> Result<(), ApiError> {
    // `PolicyGate` is not imported: `state.policy_gate` is an `Arc<dyn
    // PolicyGate>`, whose methods are reached through the vtable without the
    // trait in scope.
    use epigraph_interfaces::{Action, ResourceKind, ResourceRef};

    let principal = principal_of(viewer)?;
    let resource = ResourceRef::new(ResourceKind::Ownership, node_id);
    let resource = match (owner_of_record, requested_owner) {
        // A row exists: decide against the owner the DATABASE holds.
        (Some(owner), _) => resource.owned_by_agent(owner),
        // No row, and the caller asked for the node to be theirs.
        (None, Some(requested)) if requested == principal.id() => {
            resource.owned_by_agent(principal.id())
        }
        // No row and a third-party (or absent) requested owner: undeclared, and
        // the gate refuses it.
        (None, _) => resource,
    };

    let decision = state
        .policy_gate
        .authorize(&principal, &Action::Declassify, &resource)
        .await;

    if decision.is_allowed() {
        return Ok(());
    }

    tracing::warn!(
        target: "authz.write.denied",
        node_id = %node_id,
        principal = %principal.id(),
        action = "Declassify",
        reason = decision.denial_reason().unwrap_or("unspecified"),
        "write gate denied an ownership change"
    );
    Err(ApiError::Forbidden {
        reason: "you may not change the ownership or partition of this node".to_string(),
    })
}

/// Assign ownership of a node to an agent
///
/// `POST /api/v1/ownership`
///
/// # Authorization — PR-11
///
/// `claims:admin` is necessary and, since PR-11, **no longer sufficient**. The
/// scope says the *client* is allowed to reach this route; the gate says the
/// *principal* is allowed to touch this *node*. A scope check cannot express
/// the second, which is the whole reason `PolicyGate` exists (plan §0.6: RLS
/// `WITH CHECK` cannot express role semantics either).
///
/// The owner of record is the existing `ownership.owner_id` when there is a
/// row; when there is none, the only permitted assignment is **to yourself**.
///
/// # Two consequences, stated rather than left to be discovered
///
/// * **A `claims:admin` token can no longer assign a node to a third party.**
///   Before PR-11 it could, and could reassign anyone's node. Ops tooling that
///   records a document's author as its owner on the author's behalf now gets a
///   403. Recorded as a breaking change in the PR body.
/// * **Self-claiming an unowned node is a privatization primitive, not a
///   no-op.** `access_control.rs::check_content_access` maps a missing
///   `ownership` row to `ContentAccess::Full` (`progress.json`'s
///   `F-access-control-none-full`), so an unclaimed node is *public*. Claiming
///   it and then calling `update_partition` is therefore a two-call
///   public → private seizure by whoever gets there first, and `ownership.node_id`
///   carries no FK, so the node need not even exist. The gate narrows this
///   relative to pre-PR-11 (assign-to-anyone became assign-to-self-only) but
///   does not close it; the seizure class is PR-18's and the structural fix —
///   an `assign_if_unowned` repo function whose `ON CONFLICT` re-checks the
///   authorized precondition atomically — needs the tenancy columns PR-16 adds.
///   Filed as `F-PR11-assign-ownership-self-claim-is-a-seizure`.
///
/// `owned_by_group` is deliberately NOT supplied. `ownership.community_id`
/// references `communities`, not `groups` (migration 068), so this table has no
/// link to the group whose write roll-call `Viewer::writable_groups()`
/// describes; naming a community id as a group id would be a type confusion of
/// exactly the kind PR-09 removed from `request_viewer`. The group arm of the
/// gate therefore does not fire here. It fires at PR-16's `INSERT INTO claims`
/// sites, where `claims.owner_group_id` is the real thing.
#[cfg(feature = "db")]
pub async fn assign_ownership(
    State(state): State<AppState>,
    _scope: crate::middleware::bearer::RequireScopeAdmin,
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    Json(request): Json<AssignOwnershipRequest>,
) -> Result<(StatusCode, Json<OwnershipResponse>), ApiError> {
    // Scope gate ran in the extractor; if we reach the body, the caller has
    // `claims:admin`. See `RequireScopeAdmin` in `middleware::bearer`.

    let pool = &state.db_pool;

    // CONTROL-PLANE READ, deliberately not viewer-spliced. `OwnershipRepository::get`
    // is an unfiltered `SELECT ... WHERE node_id = $1` and must stay that way: this
    // read feeds the authorization decision, and filtering it would make "the row is
    // invisible to me" indistinguishable from "there is no row", which the branch
    // below resolves toward self-claim. A future PR that splices a viewer here would
    // convert an invisible row into a claimable one.
    let owner_of_record = epigraph_db::OwnershipRepository::get(pool, request.node_id)
        .await?
        .map(|row| row.owner_id);
    require_declassify_authority(
        &state,
        &viewer,
        request.node_id,
        owner_of_record,
        Some(request.owner_id),
    )
    .await?;

    let row = epigraph_db::OwnershipRepository::assign_with_community(
        pool,
        request.node_id,
        &request.node_type,
        &request.partition_type,
        request.owner_id,
        request.community_id,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(ownership_to_response(row))))
}

/// Get ownership info for a node
///
/// `GET /api/v1/ownership/:node_id`
#[cfg(feature = "db")]
pub async fn get_ownership(
    State(state): State<AppState>,
    Path(node_id): Path<Uuid>,
) -> Result<Json<OwnershipResponse>, ApiError> {
    let pool = &state.db_pool;

    let row = epigraph_db::OwnershipRepository::get(pool, node_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "ownership".to_string(),
            id: node_id.to_string(),
        })?;

    Ok(Json(ownership_to_response(row)))
}

/// List nodes owned by an agent
///
/// `GET /api/v1/agents/:id/owned-nodes`
#[cfg(feature = "db")]
pub async fn owned_nodes(
    State(state): State<AppState>,
    Path(owner_id): Path<Uuid>,
    Query(params): Query<OwnedNodesQuery>,
) -> Result<Json<Vec<OwnershipResponse>>, ApiError> {
    let pool = &state.db_pool;

    let rows = epigraph_db::OwnershipRepository::get_for_owner(
        pool,
        owner_id,
        params.node_type.as_deref(),
        params.limit,
        params.offset,
    )
    .await?;

    Ok(Json(rows.into_iter().map(ownership_to_response).collect()))
}

/// Update the partition type of a node
///
/// `PUT /api/v1/ownership/:node_id`
///
/// # Authorization — PR-11
///
/// This is the declassification primitive: it is what turns a `private` node
/// `public`. See [`assign_ownership`] for why `claims:admin` is not enough and
/// why no group is named.
///
/// There is no "no row" case here: `update_partition` 404s on a node with no
/// ownership row, so the owner of record always exists. The lookup is done
/// **before** the update so the decision is made against the pre-change owner.
#[cfg(feature = "db")]
pub async fn update_partition(
    State(state): State<AppState>,
    _scope: crate::middleware::bearer::RequireScopeAdmin,
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    Path(node_id): Path<Uuid>,
    Json(request): Json<UpdatePartitionRequest>,
) -> Result<Json<OwnershipResponse>, ApiError> {
    // Scope gate ran in the extractor; if we reach the body, the caller has
    // `claims:admin`. See `RequireScopeAdmin` in `middleware::bearer`.

    let pool = &state.db_pool;

    // CONTROL-PLANE READ, deliberately not viewer-spliced — see the twin note in
    // `assign_ownership`.
    let existing = epigraph_db::OwnershipRepository::get(pool, node_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "ownership".to_string(),
            id: node_id.to_string(),
        })?;
    require_declassify_authority(&state, &viewer, node_id, Some(existing.owner_id), None).await?;

    let row =
        epigraph_db::OwnershipRepository::update_partition(pool, node_id, &request.partition_type)
            .await?
            .ok_or(ApiError::NotFound {
                entity: "ownership".to_string(),
                id: node_id.to_string(),
            })?;

    Ok(Json(ownership_to_response(row)))
}

#[cfg(feature = "db")]
fn ownership_to_response(row: epigraph_db::OwnershipRow) -> OwnershipResponse {
    OwnershipResponse {
        node_id: row.node_id,
        node_type: row.node_type,
        partition_type: row.partition_type,
        owner_id: row.owner_id,
        encryption_key_id: row.encryption_key_id,
        community_id: row.community_id,
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    }
}

// =============================================================================
// HANDLERS (non-db stubs)
// =============================================================================
//
// PR-11 does NOT add the write gate here, and the asymmetry is deliberate.
// These four are `cfg`-twins with independent signatures (the `db` arm already
// carried `RequireScopeAdmin` and these never did), so the gate's absence
// cannot break the `--no-default-features` build the way a mismatched *shared*
// signature would — which is the hazard that cost PR-08 18 CI errors.
//
// The reason not to gate them is that there is nothing to gate: `epigraph-db`
// is `optional = true`, so this build has no `OwnershipRepository`, no
// `ownership` table and therefore no owner of record to authorize against.
// `assign_ownership` here echoes the request back and writes nothing. Adding a
// gate whose only possible input is a fabricated owner would be theatre, and
// `middleware::bearer::NoDbViewer`'s own doc makes the converse point: the two
// builds must not disagree about *when a request is refused*, which they do not
// — the `not(db)` build refuses to persist anything at all.

#[cfg(not(feature = "db"))]
pub async fn assign_ownership(
    Json(request): Json<AssignOwnershipRequest>,
) -> Result<(StatusCode, Json<OwnershipResponse>), ApiError> {
    Ok((
        StatusCode::CREATED,
        Json(OwnershipResponse {
            node_id: request.node_id,
            node_type: request.node_type,
            partition_type: request.partition_type,
            owner_id: request.owner_id,
            encryption_key_id: None,
            community_id: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        }),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn get_ownership(Path(node_id): Path<Uuid>) -> Result<Json<OwnershipResponse>, ApiError> {
    Err(ApiError::NotFound {
        entity: "ownership".to_string(),
        id: node_id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn owned_nodes(
    Path(_owner_id): Path<Uuid>,
    Query(_params): Query<OwnedNodesQuery>,
) -> Result<Json<Vec<OwnershipResponse>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[cfg(not(feature = "db"))]
pub async fn update_partition(
    Path(node_id): Path<Uuid>,
    Json(_request): Json<UpdatePartitionRequest>,
) -> Result<Json<OwnershipResponse>, ApiError> {
    Err(ApiError::NotFound {
        entity: "ownership".to_string(),
        id: node_id.to_string(),
    })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assign_ownership_request_defaults() {
        let req: AssignOwnershipRequest = serde_json::from_str(&format!(
            r#"{{"node_id":"{}","node_type":"claim","owner_id":"{}"}}"#,
            Uuid::new_v4(),
            Uuid::new_v4()
        ))
        .unwrap();
        assert_eq!(req.partition_type, "public");
        assert_eq!(req.node_type, "claim");
    }

    #[test]
    fn update_partition_request_parses() {
        let req: UpdatePartitionRequest =
            serde_json::from_str(r#"{"partition_type":"private"}"#).unwrap();
        assert_eq!(req.partition_type, "private");
    }

    #[test]
    fn owned_nodes_query_defaults() {
        let q: OwnedNodesQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.limit, 50);
        assert_eq!(q.offset, 0);
        assert!(q.node_type.is_none());
    }

    #[test]
    fn ownership_response_serializes() {
        let resp = OwnershipResponse {
            node_id: Uuid::new_v4(),
            node_type: "claim".to_string(),
            partition_type: "public".to_string(),
            owner_id: Uuid::new_v4(),
            encryption_key_id: None,
            community_id: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("partition_type"));
        assert!(json.contains("public"));
    }
}
