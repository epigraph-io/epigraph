//! The frozen-plan read shared by REST `GET /api/v1/workflows/:id/plan` and
//! MCP `get_workflow_plan`: [`WorkflowRepository::frozen_plan`]'s rows, run
//! through [`epigraph_ingest::workflow::frozen_plan::assemble`].
//!
//! This crate is the one that depends on both halves, so the two transports
//! call this function and cannot answer differently.

use epigraph_db::errors::DbError;
use epigraph_db::repos::FrozenPlanEdgeRow;
use epigraph_db::visibility::Viewer;
use epigraph_db::WorkflowRepository;
use epigraph_ingest::workflow::frozen_plan::{
    assemble, ExecutesEdge, FrozenPlan, FrozenPlanInput, PlanClaim,
};
use uuid::Uuid;

/// The frozen plan of `workflow_id` as `viewer` reads it, on the request's
/// viewer-stamped connection.
///
/// `Ok(None)` (a 404 on REST) when no `workflows` row has this id, AND when the
/// row exists but `viewer` can see none of its `executes` edges. The second
/// case is what a non-member of a group-private plan gets. It is not reported
/// as a 200 with a count, because the count is not knowable here: each
/// `executes` edge takes its target's tenancy, so on an RLS-bound connection a
/// non-member sees no edge to count, and a clean-looking empty plan would be a
/// false statement. Every ingest writes at least one `executes` edge (an empty
/// plan is refused before any write), so an existing row with no visible edge
/// means the plan is hidden, not empty. A legacy row written before that
/// refusal answers the same, which is also right: it has no plan to pin.
///
/// The not-found answer is what a non-member gets only when EVERY item of the
/// plan is private to groups it is not in. A plan that also executes public
/// claims (a reused, content-addressed atom, say) shows a non-member those
/// public edges, so it reads 200 with gaps and no digest echo. That discloses
/// nothing new (public edges and their properties are readable on their own),
/// but "not found" is not a general sign of hiding.
///
/// # Errors
/// [`DbError`] for a query fault, and [`DbError::InvalidData`] for a row whose
/// `generation` is negative (no ingest path writes one).
pub async fn frozen_plan(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    workflow_id: Uuid,
) -> Result<Option<FrozenPlan>, DbError> {
    let Some(read) = WorkflowRepository::frozen_plan(conn, viewer, workflow_id).await? else {
        return Ok(None);
    };
    if read.edges.is_empty() {
        return Ok(None);
    }
    let row = read.row;
    let generation = u32::try_from(row.generation).map_err(|_| DbError::InvalidData {
        reason: format!(
            "workflow {} has a negative generation {}",
            row.id, row.generation
        ),
    })?;
    let submitter = row
        .metadata
        .as_object()
        .and_then(|m| m.get(WorkflowRepository::SUBMITTER_KEY))
        .and_then(serde_json::Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok());
    Ok(Some(assemble(FrozenPlanInput {
        workflow_id: row.id,
        canonical_name: row.canonical_name,
        generation,
        goal: row.goal,
        parent_id: row.parent_id,
        truth_value: row.truth_value,
        submitter,
        edges: read.edges.into_iter().map(executes_edge).collect(),
        chain_order: read.chain_order,
    })))
}

/// A row whose target is readable but lacks a NOT NULL claim column cannot
/// occur; if it did, it is treated as unreadable (counted, never shown) rather
/// than given invented values.
fn executes_edge(e: FrozenPlanEdgeRow) -> ExecutesEdge {
    let target = match (
        e.readable,
        e.content,
        e.content_hash,
        e.visibility,
        e.owner_group_id,
        e.truth_value,
        e.is_current,
    ) {
        (
            true,
            Some(content),
            Some(content_hash),
            Some(visibility),
            Some(owner_group_id),
            Some(truth_value),
            Some(is_current),
        ) => Some(PlanClaim {
            content,
            content_hash,
            properties: e.claim_properties.unwrap_or(serde_json::Value::Null),
            visibility,
            owner_group_id,
            truth_value,
            is_current,
            heads_diverged: e.heads_diverged.unwrap_or(false),
        }),
        _ => None,
    };
    ExecutesEdge {
        properties: e.edge_properties.unwrap_or(serde_json::Value::Null),
        retracted: e.retracted,
        target_id: e.target_id,
        target,
    }
}
