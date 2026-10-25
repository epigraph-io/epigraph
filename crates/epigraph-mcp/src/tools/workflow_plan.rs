//! `get_workflow_plan`: the frozen plan of one workflow generation, read as the
//! caller. The MCP twin of REST `GET /api/v1/workflows/:id/plan`; both call
//! `epigraph_ingest_executor::workflow_plan::frozen_plan`, so they cannot
//! answer differently for the same viewer.

use rmcp::model::{CallToolResult, ContentBlock};

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::GetWorkflowPlanParams;

/// Read the plan on ONE connection stamped with `viewer` (the server's
/// tenancy-aware pool, `read_as`), so the in-query predicates and the session's
/// GUCs agree under forced RLS. A server built without a tenancy-aware pool
/// refuses rather than reading on its plain pool: an unstamped session reads
/// public rows only, so a member of a private plan would get a plan with holes
/// in it instead of an error.
///
/// # Errors
/// `invalid_params` for a malformed id and for a plan that is not found (no
/// such workflow, or none of its `executes` edges visible to the caller);
/// `internal_error` for a server with no tenancy-aware pool and for a
/// database fault.
pub async fn get_workflow_plan(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: GetWorkflowPlanParams,
) -> Result<CallToolResult, McpError> {
    let workflow_id = parse_uuid(&params.workflow_id)?;
    let scoped = server.scoped.as_ref().ok_or_else(|| {
        crate::errors::internal_error_text(
            "get_workflow_plan needs a tenancy-aware pool; this server has none",
        )
    })?;
    let mut read = scoped.read_as(viewer).await.map_err(internal_error)?;
    let plan = epigraph_ingest_executor::workflow_plan::frozen_plan(&mut read, viewer, workflow_id)
        .await
        .map_err(internal_error)?;
    read.commit().await.map_err(internal_error)?;
    let plan =
        plan.ok_or_else(|| invalid_params(format!("workflow plan {workflow_id} not found")))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&plan).map_err(internal_error)?,
    )]))
}
