//! `link_hierarchical` — cross-tier structural edge creation between claims.
//!
//! Counterpart to the new `POST /api/v1/edges/hierarchical` HTTP endpoint.
//! Bypasses HTTP and goes directly through `EdgeRepository::create_if_not_exists`
//! so per-chapter ingest wiring (e.g. chapter thesis → book thesis,
//! chapter[N] → chapter[N+1]) can continue from a Claude Code session even
//! when the API binary is unavailable.
//!
//! Tight contract — narrower than the generic `POST /api/v1/edges` route:
//! - `relationship` must be one of `HIERARCHICAL_RELATIONSHIPS` (claim to
//!   claim) or `WORKFLOW_REFERENCE_RELATIONSHIPS` (backlogs 03d87e3a and
//!   41d7b27a: `executes` workflow -> claim, `invokes` workflow|claim ->
//!   workflow, `depends_on` workflow -> workflow),
//! - both endpoints must exist and be readable; their types default to
//!   `"claim"`, are validated against the `entity_types` registry, and must be
//!   a pair the relationship admits ([`endpoint_types_for`]),
//! - a workflow SOURCE requires authority over that workflow
//!   (`require_workflow_authority`, the gate `add_step` uses), and the write
//!   is recorded as that gate's writes are,
//! - `invokes` and `depends_on` refuse an edge that would close a cycle,
//! - the call is idempotent on `(source, target, relationship)`.
//!
//! Intentionally side-effect-free vs the generic POST: no DS recomputation,
//! no factor inserts, no `edge.added` event, no provenance. These structural
//! edges carry no evidential semantics and the matching `ingest_document`
//! flow treats them the same way.

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{LinkHierarchicalParams, LinkHierarchicalResponse};

use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, EdgeRepository};

/// Allowed relationship strings — mirror of
/// `epigraph_api::routes::edges::HIERARCHICAL_RELATIONSHIPS`. Kept as a local
/// constant so the MCP crate does not take a code dep on the API crate.
pub const HIERARCHICAL_RELATIONSHIPS: &[&str] =
    &["decomposes_to", "section_follows", "continues_argument"];

/// The workflow references (backlogs 03d87e3a, 41d7b27a), all structural and
/// belief-neutral. Kept apart from [`HIERARCHICAL_RELATIONSHIPS`], which
/// mirrors the HTTP hierarchical route's claim-only list.
pub const WORKFLOW_REFERENCE_RELATIONSHIPS: &[&str] = &["executes", "invokes", "depends_on"];

/// The `(source_type, target_type)` pairs `relationship` admits; empty for a
/// relationship this tool does not write.
///
/// - the document-structure relationships stay claim to claim;
/// - `executes`: a workflow runs a step claim (the edge `store_workflow` and
///   `add_step` write; this is its repair path);
/// - `invokes`: a sub-workflow reference, from a workflow or from one of its
///   step claims;
/// - `depends_on`: a prerequisite workflow.
#[must_use]
pub fn endpoint_types_for(relationship: &str) -> &'static [(&'static str, &'static str)] {
    match relationship {
        "decomposes_to" | "section_follows" | "continues_argument" => &[("claim", "claim")],
        "executes" => &[("workflow", "claim")],
        "invokes" => &[("workflow", "workflow"), ("claim", "workflow")],
        "depends_on" => &[("workflow", "workflow")],
        _ => &[],
    }
}

/// The relationships a cycle through a new `relationship` edge is walked
/// along, or `None` when the relationship is not cycle-checked.
///
/// `invokes` walks `executes` too: a step claim's `invokes` belongs to the
/// workflow that executes the step, so `W1 -executes-> S1 -invokes-> W2`
/// followed by `W2 -invokes-> W1` is a cycle.
#[must_use]
pub fn cycle_walk_for(relationship: &str) -> Option<&'static [&'static str]> {
    match relationship {
        "invokes" => Some(&["invokes", "executes"]),
        "depends_on" => Some(&["depends_on"]),
        _ => None,
    }
}

fn is_hierarchical_relationship(s: &str) -> bool {
    HIERARCHICAL_RELATIONSHIPS.contains(&s) || WORKFLOW_REFERENCE_RELATIONSHIPS.contains(&s)
}

/// Whether the `(id, entity_type)` endpoint exists for `viewer`, on the
/// stamped transaction. Only the types [`endpoint_types_for`] names reach
/// here.
async fn endpoint_exists(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    id: uuid::Uuid,
    entity_type: &str,
) -> Result<bool, McpError> {
    match entity_type {
        "claim" => Ok(
            ClaimRepository::get_by_id(&mut *conn, viewer, ClaimId::from_uuid(id))
                .await
                .map_err(internal_error)?
                .is_some(),
        ),
        "workflow" => epigraph_db::WorkflowRepository::viewer_reads_row(&mut *conn, viewer, id)
            .await
            .map_err(internal_error),
        other => Err(internal_error(format!(
            "link_hierarchical: no existence check for entity type '{other}'"
        ))),
    }
}

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

pub async fn link_hierarchical(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: LinkHierarchicalParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    do_link_hierarchical(server, viewer, params, auth).await
}

/// Core wiring logic factored out so integration tests can call it directly
/// without round-tripping through the rmcp dispatch layer. Mirrors the
/// `do_ingest_document` factoring in `tools/ingestion.rs`.
pub async fn do_link_hierarchical(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: LinkHierarchicalParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let source_id = parse_uuid(&params.source_claim_id)?;
    let target_id = parse_uuid(&params.target_claim_id)?;
    let source_type = params.source_type.as_deref().unwrap_or("claim");
    let target_type = params.target_type.as_deref().unwrap_or("claim");

    // Tight allow-list — narrower than VALID_RELATIONSHIPS on purpose. New
    // entries must come from `HIERARCHICAL_RELATIONSHIPS` or
    // `WORKFLOW_REFERENCE_RELATIONSHIPS`.
    if !is_hierarchical_relationship(&params.relationship) {
        return Err(invalid_params(format!(
            "invalid relationship '{}'. Valid hierarchical types: {}. Valid workflow references: {}",
            params.relationship,
            HIERARCHICAL_RELATIONSHIPS.join(", "),
            WORKFLOW_REFERENCE_RELATIONSHIPS.join(", "),
        )));
    }

    // No self-loops: equal UUIDs always loop (ids are unique across tables).
    if source_id == target_id {
        return Err(invalid_params(
            "self-loops are not allowed (source and target are the same entity)",
        ));
    }
    if params.at_step.is_some() && params.relationship != "invokes" {
        return Err(invalid_params(format!(
            "at_step is only meaningful for invokes, not '{}'",
            params.relationship
        )));
    }

    // ONE TRANSACTION, STAMPED FROM THE WRITE IDENTITY (the caller over HTTP, the server's own agent on stdio; batch H-b D1). The two
    // existence reads and the INSERT all run on it.
    //
    // The INSERT used to run on the unstamped pool. `edges_tenancy`'s WITH CHECK
    // then admitted only what its static arm admits: an edge between two PUBLIC
    // claims, which 070's BEFORE trigger makes world-owned. An edge touching a
    // group-private claim is owned by that claim's group, and on a
    // cleanly-migrated schema it was refused. Production admitted it only through
    // the orphan `edges_privacy` policy that R3 drops.
    //
    // The READS move too, and they are what make the stamp able to succeed. On
    // an unstamped session `claims_tenancy`'s USING admits only public rows, so a
    // group-private endpoint read "not found" before the INSERT was reached.
    // Converting only the INSERT would have been a conversion its own target
    // population could never reach.
    //
    // THE STAMP IS THE WRITE IDENTITY's (`EpiGraphMcpFull::write_identity`), as for every other MCP write: the edge
    // is owned by an endpoint's group, and the population this admits is the
    // server agent's own claims. An endpoint in another agent's private group is
    // refused loudly by the WITH CHECK (or, for a co-owned edge, by RETURNING's
    // intersection read) and nothing is written. Whether a caller should carry
    // write authority into a group this process cannot write is the cross-agent
    // ownership question (#374), not a stamping one.
    let actor = server.write_identity(auth, viewer).await?;
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, actor, "link_hierarchical").await?;

    // Endpoint types: registered (the `entity_types` registry, as the HTTP
    // edges route validates them), then a pair this relationship admits.
    for (side, ty) in [("source_type", source_type), ("target_type", target_type)] {
        if epigraph_db::EntityTypeRepository::get_by_name_conn(&mut tx, ty)
            .await
            .map_err(internal_error)?
            .is_none()
        {
            return Err(invalid_params(format!(
                "{side} '{ty}' is not a registered entity type"
            )));
        }
    }
    let admitted = endpoint_types_for(&params.relationship);
    if !admitted.contains(&(source_type, target_type)) {
        let pairs: Vec<String> = admitted
            .iter()
            .map(|(s, t)| format!("{s} -> {t}"))
            .collect();
        return Err(invalid_params(format!(
            "'{}' does not link {source_type} -> {target_type}. It links: {}",
            params.relationship,
            pairs.join(", "),
        )));
    }

    // Verify both endpoints exist via the repo layer (per CLAUDE.md, SQL stays
    // in epigraph-db). Disambiguate which side is missing so the caller can
    // fix the right end of the link.
    if !endpoint_exists(&mut tx, viewer, source_id, source_type).await? {
        return Err(invalid_params(format!(
            "source_claim_id {source_id} not found (no readable {source_type} has that id)"
        )));
    }
    if !endpoint_exists(&mut tx, viewer, target_id, target_type).await? {
        return Err(invalid_params(format!(
            "target_claim_id {target_id} not found (no readable {target_type} has that id)"
        )));
    }

    // A workflow SOURCE changes what that workflow runs or references, so it
    // takes the authority `add_step` takes over it (backlog 03d87e3a: "under
    // the same authority checks"), decided before anything is written.
    let grant = if source_type == "workflow" {
        let not_found = move || invalid_params(format!("source workflow {source_id} not found"));
        Some(
            crate::tools::workflow_authority::require_workflow_authority(
                server,
                &mut tx,
                auth,
                actor,
                source_id,
                "link_hierarchical",
                &not_found,
            )
            .await?,
        )
    } else {
        None
    };

    // Cycle refusal (backlog 41d7b27a): `source -rel-> target` closes a cycle
    // exactly when `target` already reaches `source`.
    if let Some(walk) = cycle_walk_for(&params.relationship) {
        if EdgeRepository::reaches_in_force_conn(&mut tx, target_id, source_id, walk)
            .await
            .map_err(internal_error)?
        {
            return Err(invalid_params(format!(
                "refused: {source_type} {source_id} {} {target_type} {target_id} would close a \
                 cycle ({target_id} already reaches {source_id} through {}). Nothing was written.",
                params.relationship,
                walk.join(" / "),
            )));
        }
    }

    let mut properties = params.properties.clone();
    if let Some(step) = params.at_step {
        let mut obj = match properties.take() {
            None => serde_json::Map::new(),
            Some(serde_json::Value::Object(m)) => m,
            Some(_) => {
                return Err(invalid_params(
                    "properties must be a JSON object when at_step is given",
                ))
            }
        };
        obj.insert("at_step".to_string(), serde_json::json!(step));
        properties = Some(serde_json::Value::Object(obj));
    }

    // Attested at INSERT by this server's key (R-49/R-50); a dedup hit
    // returns the existing edge unchanged.
    let (edge_row, was_created) = EdgeRepository::create_if_not_exists_signed_conn(
        &mut tx,
        Some(server.edge_signing_key().await?),
        source_id,
        source_type,
        target_id,
        target_type,
        &params.relationship,
        properties,
        None,
        None,
    )
    .await
    .map_err(internal_error)?;
    if let Some(grant) = grant {
        crate::tools::workflow_authority::record_workflow_write(
            &mut tx,
            auth,
            actor,
            "link_hierarchical",
            source_id,
            grant,
            serde_json::json!({
                "edge_id": edge_row.id,
                "relationship": params.relationship,
                "target_id": target_id,
                "target_type": target_type,
                "created": was_created,
            }),
        )
        .await?;
    }
    let owned_by_caller = EdgeRepository::owned_by_session(&mut *tx, edge_row.id)
        .await
        .map_err(internal_error)?;
    tx.commit().await.map_err(internal_error)?;

    success_json(&LinkHierarchicalResponse {
        edge_id: edge_row.id.to_string(),
        created: was_created,
        owned_by_caller,
    })
}
