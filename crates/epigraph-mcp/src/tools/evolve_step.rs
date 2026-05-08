//! `evolve_step` — atomic creation of a versioned claim + supersedes/revises edge.
//!
//! See docs/superpowers/specs/2026-05-05-step-level-versioning-design.md §5, §9.9.
//!
//! Use `supersedes` for linear refinement (new claim takes over from parent);
//! use `revises` for a concurrent branch sharing a common ancestor. The new
//! claim shares the same `step_lineage_id` as the parent.

use rmcp::model::{CallToolResult, Content};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EvolveStepParams {
    /// Existing lineage UUID. Required.
    pub step_lineage_id: String,
    /// Claim being superseded or branched from. Required.
    pub parent_id: String,
    /// New step content.
    pub content: String,
    /// "supersedes" (linear refinement) or "revises" (concurrent branch).
    pub edge_type: String,
    /// Optional human-readable rationale.
    pub rationale: Option<String>,
    /// 2 (step) or 3 (operation). Default 2.
    pub level: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct EvolveStepResponse {
    pub claim_id: Uuid,
    pub step_lineage_id: Uuid,
    pub edge_id: Uuid,
}

pub async fn evolve_step(
    server: &EpiGraphMcpFull,
    params: EvolveStepParams,
) -> Result<CallToolResult, McpError> {
    let level = params.level.unwrap_or(2);
    if level != 2 && level != 3 {
        return Err(invalid_params(format!(
            "level must be 2 or 3 (got {level})"
        )));
    }
    if params.content.trim().is_empty() {
        return Err(invalid_params("content must not be empty".to_string()));
    }

    let parent_uuid = parse_uuid(&params.parent_id)?;
    let agent_id = server.agent_id().await?;

    let result = epigraph_db::ClaimRepository::evolve_step(
        &server.pool,
        epigraph_core::ClaimId::from_uuid(parent_uuid),
        &params.content,
        &params.edge_type,
        params.rationale.as_deref(),
        level,
        agent_id,
    )
    .await
    .map_err(internal_error)?;

    success_json(&EvolveStepResponse {
        claim_id: result.new_claim_id,
        step_lineage_id: result.step_lineage_id,
        edge_id: result.edge_id,
    })
}

fn success_json<T: Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}
