//! MCP wrappers for `add_step` and `delete_step`. Persistence lives in
//! [`epigraph_ingest_executor::workflow_steps`]; this module is a thin
//! parameter/response shim for the MCP tool surface.

use rmcp::model::{CallToolResult, Content};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AddStepParams {
    /// Workflow's canonical_name (slug).
    pub canonical_name: String,
    /// Step text to append/insert.
    pub step_text: String,
    /// 0-indexed insertion slot. `None` (or out-of-range) appends.
    #[serde(default)]
    pub position: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct AddStepResponse {
    pub workflow_id: Uuid,
    pub step_claim_id: Uuid,
    pub step_index: u32,
    pub step_lineage_id: Uuid,
    pub already_present: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeleteStepParams {
    pub canonical_name: String,
    /// Lineage UUID of the step to soft-delete.
    pub step_lineage_id: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteStepResponse {
    pub workflow_id: Uuid,
    pub step_claim_id: Uuid,
    pub step_lineage_id: Uuid,
    pub truth_value: f64,
}

fn success_json<T: Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

fn map_step_err(e: epigraph_ingest_executor::StepOpError) -> McpError {
    use epigraph_ingest_executor::StepOpError as E;
    match e {
        E::Invalid(msg) | E::WorkflowNotFound(msg) => invalid_params(msg),
        E::StepNotFound { .. } | E::PhaseMissing => invalid_params(e.to_string()),
        E::Db(_) | E::Repo(_) | E::Executor(_) => internal_error(e.to_string()),
    }
}

pub async fn add_step(
    server: &EpiGraphMcpFull,
    params: AddStepParams,
) -> Result<CallToolResult, McpError> {
    let r = epigraph_ingest_executor::add_step(
        &server.pool,
        &params.canonical_name,
        &params.step_text,
        params.position,
    )
    .await
    .map_err(map_step_err)?;
    success_json(&AddStepResponse {
        workflow_id: r.workflow_id,
        step_claim_id: r.step_claim_id,
        step_index: r.step_index,
        step_lineage_id: r.step_lineage_id,
        already_present: r.already_present,
    })
}

pub async fn delete_step(
    server: &EpiGraphMcpFull,
    params: DeleteStepParams,
) -> Result<CallToolResult, McpError> {
    let lineage = parse_uuid(&params.step_lineage_id)?;
    let r = epigraph_ingest_executor::delete_step(&server.pool, &params.canonical_name, lineage)
        .await
        .map_err(map_step_err)?;
    success_json(&DeleteStepResponse {
        workflow_id: r.workflow_id,
        step_claim_id: r.step_claim_id,
        step_lineage_id: r.step_lineage_id,
        truth_value: r.truth_value,
    })
}
