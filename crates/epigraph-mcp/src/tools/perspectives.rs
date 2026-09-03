#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::{EdgeRepository, OwnershipRepository, PerspectiveRepository};

/// Ask the **installed** fail-closed write gate whether `viewer`'s principal
/// may change the ownership or partition of `node_id`.
///
/// # Why this exists on the MCP surface specifically
///
/// `scope_map.rs` gates HTTP `update_partition` at `claims:admin` but MCP
/// `assign_ownership` at **`claims:write`** — so before PR-11 a `claims:write`
/// token could set `partition_type` on any node over MCP, obtaining a
/// declassification power the same operation is denied over HTTP and its own
/// sibling tool is denied over MCP. `oauth/metadata.rs`'s comment claims the
/// admin gate covers "`mark_duplicate` / `supersede_claim` / `update_partition`"
/// and conspicuously omits `assign_ownership`. Widening the scope entry would
/// be the smaller change; it would also be a scope check, which cannot say
/// *this principal, this node*.
///
/// The gate comes from `server.policy_gate`, **not** from a
/// `GroupPolicyGate::new()` constructed here. PR-11's first pass built one
/// inline, which made `AppState::with_policy_gate` reach the HTTP surface and
/// silently not this one; `EpiGraphMcpFull::with_policy_gate` is the MCP half
/// of that seam.
///
/// # What the gate does and does not constrain on each transport
///
/// `server.rs::call_tool` runs `enforce_tool_scope` only when `is_http_call`,
/// so on stdio this gate is the only authorization that runs at all. That is a
/// statement about what else is absent, **not** a claim that the gate is
/// strong there: this gate binds a caller to the *resolved principal*, and on
/// stdio (and on the `--allow-unauthenticated-http` unix-socket listener) that
/// principal is the shared server agent
/// (`tools/viewer.rs`'s per-request acquisition helper, plus
/// `auth.rs::unauthenticated_context`). On
/// those transports it therefore constrains callers only relative to *other*
/// agents' nodes — every node the server itself claimed is already owned by the
/// principal asking. On the production HTTPS transport the principal is the
/// caller's own agent and the gate is load-bearing.
///
/// # The owner of record
///
/// `owner_of_record` is `Some` only when the `ownership` row exists, and it is
/// then the value the **database** holds. `requested_owner` is the value the
/// *caller* named, and it is admitted to the gate's owner slot in exactly one
/// case: when it equals the caller's own principal, i.e. a self-claim of a node
/// nobody has claimed. Any other combination leaves the [`ResourceRef`]
/// undeclared, and `GroupPolicyGate` denies an undeclared resource ("nothing is
/// authorized by absence"). Caller-supplied input can therefore never *widen*
/// the decision.
///
/// No `owned_by_group`: `ownership.community_id` references `communities`, not
/// `groups`, so there is no group here whose write roll-call
/// `Viewer::writable_groups()` describes. See the twin note in
/// `epigraph-api/src/routes/ownership.rs::assign_ownership`.
async fn require_declassify_authority(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    node_id: uuid::Uuid,
    owner_of_record: Option<uuid::Uuid>,
    requested_owner: Option<uuid::Uuid>,
) -> Result<(), McpError> {
    use epigraph_interfaces::{Action, Principal, ResourceKind, ResourceRef};

    let Some(id) = viewer.principal() else {
        return Err(invalid_params(
            "this tool requires an authenticated principal",
        ));
    };
    let principal = Principal::new(id, viewer.writable_groups().to_vec());
    let resource = ResourceRef::new(ResourceKind::Ownership, node_id);
    let resource = match (owner_of_record, requested_owner) {
        // A row exists: the gate decides against the owner the DATABASE holds.
        (Some(owner), _) => resource.owned_by_agent(owner),
        // No row, and the caller asked for the node to be theirs. A self-claim
        // is the one request-derived value that may reach the owner slot.
        (None, Some(requested)) if requested == id => resource.owned_by_agent(id),
        // No row and a third-party (or absent) requested owner: the resource
        // stays undeclared and the gate refuses it.
        (None, _) => resource,
    };

    // `PolicyGate` is not imported: `server.policy_gate` is an
    // `Arc<dyn PolicyGate>`, whose methods are reached through the vtable.
    let decision = server
        .policy_gate
        .authorize(&principal, &Action::Declassify, &resource)
        .await;

    if decision.is_allowed() {
        return Ok(());
    }

    tracing::warn!(
        target: "authz.write.denied",
        node_id = %node_id,
        principal = %id,
        action = "Declassify",
        reason = decision.denial_reason().unwrap_or("unspecified"),
        "write gate denied an ownership change"
    );
    // The denial reason names the owner; the caller may not be entitled to it.
    Err(invalid_params(
        "you may not change the ownership or partition of this node",
    ))
}

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

/// Create a new perspective (frame of discernment viewpoint).
pub async fn create_perspective(
    server: &EpiGraphMcpFull,
    params: CreatePerspectiveParams,
) -> Result<CallToolResult, McpError> {
    if params.name.is_empty() || params.name.len() > 200 {
        return Err(invalid_params("name must be between 1 and 200 characters"));
    }

    let calibration = params.confidence_calibration.unwrap_or(0.5);
    if !(0.0..=1.0).contains(&calibration) {
        return Err(invalid_params("confidence_calibration must be in [0, 1]"));
    }

    let owner_agent_id = if let Some(ref id) = params.owner_agent_id {
        Some(parse_uuid(id)?)
    } else {
        Some(server.agent_id().await?)
    };

    let frame_ids: Vec<uuid::Uuid> = params
        .frame_ids
        .unwrap_or_default()
        .iter()
        .map(|s| parse_uuid(s))
        .collect::<Result<Vec<_>, _>>()?;

    let perspective_type = params.perspective_type.as_deref().unwrap_or("analytical");
    let extraction_method = params
        .extraction_method
        .as_deref()
        .unwrap_or("ai_generated");

    let row = PerspectiveRepository::create(
        &server.pool,
        &params.name,
        params.description.as_deref(),
        owner_agent_id,
        Some(perspective_type),
        &frame_ids,
        Some(extraction_method),
        Some(calibration),
    )
    .await
    .map_err(internal_error)?;

    // Materialize PERSPECTIVE_OF edge if owner specified
    if let Some(agent_id) = owner_agent_id {
        let _ = EdgeRepository::create(
            &server.pool,
            row.id,
            "perspective",
            agent_id,
            "agent",
            "PERSPECTIVE_OF",
            None,
            None,
            None,
        )
        .await;
    }

    success_json(&serde_json::json!({
        "perspective_id": row.id.to_string(),
        "name": row.name,
        "description": row.description,
        "owner_agent_id": row.owner_agent_id.map(|id| id.to_string()),
        "perspective_type": row.perspective_type,
        "frame_ids": row.frame_ids.map(|ids| ids.iter().map(|id| id.to_string()).collect::<Vec<_>>()),
        "confidence_calibration": row.confidence_calibration,
        "created_at": row.created_at.to_rfc3339(),
    }))
}

/// Set a perspective's source-reliability map (the frame-function lens): evidence-type
/// tag -> alpha in [0,1], merged into `properties.source_reliability`. Empty map clears it.
pub async fn set_source_reliability(
    server: &EpiGraphMcpFull,
    params: SetSourceReliabilityParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.perspective_id)?;
    for (tag, &alpha) in &params.source_reliability {
        if alpha.is_nan() || !(0.0..=1.0).contains(&alpha) {
            return Err(invalid_params(format!(
                "reliability for '{tag}' must be in [0, 1]"
            )));
        }
    }
    PerspectiveRepository::set_source_reliability(&server.pool, id, &params.source_reliability)
        .await
        .map_err(internal_error)?;
    success_json(&serde_json::json!({
        "perspective_id": id.to_string(),
        "source_reliability": params.source_reliability,
        "status": "set",
    }))
}

/// List all perspectives with optional pagination.
pub async fn list_perspectives(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ListPerspectivesParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    let rows = PerspectiveRepository::list(&server.pool, viewer, limit, 0)
        .await
        .map_err(internal_error)?;

    let results: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "perspective_id": r.id.to_string(),
                "name": r.name,
                "description": r.description,
                "owner_agent_id": r.owner_agent_id.map(|id| id.to_string()),
                "perspective_type": r.perspective_type,
                "confidence_calibration": r.confidence_calibration,
                "created_at": r.created_at.to_rfc3339(),
                // Lens maps so an agent can SEE what a perspective up/down-weights
                // before choosing it as a (frame, perspective) lens. Serialize as
                // a JSON object when present, `null` when the perspective sets no
                // override (Option<HashMap> → object/null).
                "source_reliability": r.source_reliability(),
                "locality_reliability": r.locality_reliability(),
            })
        })
        .collect();

    success_json(&results)
}

/// Get a single perspective by ID.
pub async fn get_perspective(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: GetPerspectiveParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.perspective_id)?;

    let row = PerspectiveRepository::get_by_id(&server.pool, viewer, id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("perspective {id} not found")))?;

    success_json(&serde_json::json!({
        "perspective_id": row.id.to_string(),
        "name": row.name,
        "description": row.description,
        "owner_agent_id": row.owner_agent_id.map(|id| id.to_string()),
        "perspective_type": row.perspective_type,
        "frame_ids": row.frame_ids.map(|ids| ids.iter().map(|id| id.to_string()).collect::<Vec<_>>()),
        "extraction_method": row.extraction_method,
        "confidence_calibration": row.confidence_calibration,
        "created_at": row.created_at.to_rfc3339(),
    }))
}

/// Assign ownership of a node to an agent with a partition type.
///
/// Gated by [`require_declassify_authority`] since PR-11: a node that already
/// has an `ownership` row may be reassigned only by the owner the database
/// records, and a node that has none may be claimed only **to yourself**.
///
/// # `owner_id` defaults to the CALLER, not to the server (PR-11 fix)
///
/// This tool previously defaulted an omitted `owner_id` to
/// `EpiGraphMcpFull::agent_id()` — the server's own signing-key agent row, not
/// the requester. On stdio those are the same identity
/// (`tools/viewer.rs`'s acquisition helper resolves `server.agent_id()` when there is
/// no `AuthContext`), so the difference was invisible; on the HTTP transport the
/// principal is the *caller's* agent, so "claim this node" silently meant
/// "give this node to the server", and once the gate landed it meant "denied for
/// everyone but the server". Defaulting to `viewer.principal()` is a provable
/// no-op on stdio and makes the HTTP arm mean what the tool description says.
pub async fn assign_ownership(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: AssignOwnershipParams,
) -> Result<CallToolResult, McpError> {
    let node_id = parse_uuid(&params.node_id)?;
    let owner_id = if let Some(ref id) = params.owner_id {
        parse_uuid(id)?
    } else {
        viewer
            .principal()
            .ok_or_else(|| invalid_params("this tool requires an authenticated principal"))?
    };

    // CONTROL-PLANE READ, deliberately not viewer-spliced. `OwnershipRepository::get`
    // is an unfiltered `SELECT ... WHERE node_id = $1` and must stay that way: this
    // read feeds the authorization decision, and filtering it would make "the row is
    // invisible to me" indistinguishable from "there is no row", which the branch in
    // `require_declassify_authority` resolves toward self-claim.
    let owner_of_record = OwnershipRepository::get(&server.pool, node_id)
        .await
        .map_err(internal_error)?
        .map(|row| row.owner_id);
    require_declassify_authority(server, viewer, node_id, owner_of_record, Some(owner_id)).await?;

    let community_id = if let Some(ref id) = params.community_id {
        Some(parse_uuid(id)?)
    } else {
        None
    };

    let partition = params.partition_type.as_deref().unwrap_or("public");
    let node_type = params.node_type.as_deref().unwrap_or("claim");

    let row = OwnershipRepository::assign_with_community(
        &server.pool,
        node_id,
        node_type,
        partition,
        owner_id,
        community_id,
    )
    .await
    .map_err(internal_error)?;

    success_json(&serde_json::json!({
        "node_id": row.node_id.to_string(),
        "node_type": row.node_type,
        "partition_type": row.partition_type,
        "owner_id": row.owner_id.to_string(),
        "encryption_key_id": row.encryption_key_id,
        "community_id": row.community_id.map(|id| id.to_string()),
        "created_at": row.created_at.to_rfc3339(),
    }))
}

/// Get ownership info for a node.
pub async fn get_ownership(
    server: &EpiGraphMcpFull,
    params: GetOwnershipParams,
) -> Result<CallToolResult, McpError> {
    let node_id = parse_uuid(&params.node_id)?;

    let row = OwnershipRepository::get(&server.pool, node_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("no ownership record for {node_id}")))?;

    success_json(&serde_json::json!({
        "node_id": row.node_id.to_string(),
        "node_type": row.node_type,
        "partition_type": row.partition_type,
        "owner_id": row.owner_id.to_string(),
        "encryption_key_id": row.encryption_key_id,
        "community_id": row.community_id.map(|id| id.to_string()),
        "created_at": row.created_at.to_rfc3339(),
        "updated_at": row.updated_at.to_rfc3339(),
    }))
}

/// Update the partition type of a node.
///
/// The declassification primitive, and gated as one since PR-11. The owner
/// lookup happens before the update so the decision is made against the
/// pre-change owner.
///
/// There is no self-claim case here — this tool refuses a node with no
/// `ownership` row — so `requested_owner` is `None` and the gate's owner slot
/// can only ever hold the database's value.
pub async fn update_partition(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: UpdatePartitionParams,
) -> Result<CallToolResult, McpError> {
    let node_id = parse_uuid(&params.node_id)?;

    // CONTROL-PLANE READ, deliberately not viewer-spliced — see the twin note in
    // `assign_ownership`.
    let existing = OwnershipRepository::get(&server.pool, node_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("no ownership record for {node_id}")))?;
    require_declassify_authority(server, viewer, node_id, Some(existing.owner_id), None).await?;

    let row = OwnershipRepository::update_partition(&server.pool, node_id, &params.partition_type)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("no ownership record for {node_id}")))?;

    success_json(&serde_json::json!({
        "node_id": row.node_id.to_string(),
        "node_type": row.node_type,
        "partition_type": row.partition_type,
        "owner_id": row.owner_id.to_string(),
        "updated_at": row.updated_at.to_rfc3339(),
    }))
}
