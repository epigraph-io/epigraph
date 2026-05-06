//! `evolve_step` — atomic creation of a versioned claim + supersedes/revises edge.
//!
//! See docs/superpowers/specs/2026-05-05-step-level-versioning-design.md §5, §9.9.
//!
//! Use `supersedes` for linear refinement (new claim takes over from parent);
//! use `revises` for a concurrent branch sharing a common ancestor. The new
//! claim shares the same `step_lineage_id` as the parent.

use epigraph_crypto::ContentHasher;
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
    if params.edge_type != "supersedes" && params.edge_type != "revises" {
        return Err(invalid_params(format!(
            "edge_type must be \"supersedes\" or \"revises\", got: {}",
            params.edge_type
        )));
    }
    let level = params.level.unwrap_or(2);
    if level != 2 && level != 3 {
        return Err(invalid_params(format!(
            "level must be 2 or 3 (got {level})"
        )));
    }
    if params.content.trim().is_empty() {
        return Err(invalid_params("content must not be empty".to_string()));
    }

    let step_lineage_id = parse_uuid(&params.step_lineage_id)?;
    let parent_id = parse_uuid(&params.parent_id)?;

    let agent_id = server.agent_id().await?;

    let mut tx = server
        .pool
        .begin()
        .await
        .map_err(|e| internal_error(format!("begin tx: {e}")))?;

    let claim_id = Uuid::new_v4();
    let content_hash = ContentHasher::hash(params.content.as_bytes());
    let properties = serde_json::json!({
        "level": level,
        "step_lineage_id": step_lineage_id.to_string(),
    });

    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, step_lineage_id) \
         VALUES ($1, $2, $3, $4, 0.5, $5, $6)",
    )
    .bind(claim_id)
    .bind(&params.content)
    .bind(content_hash.as_slice())
    .bind(agent_id)
    .bind(&properties)
    .bind(step_lineage_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| internal_error(format!("insert claim: {e}")))?;

    let edge_id = Uuid::new_v4();
    // `evolved_at` covers both supersedes (linear) and revises (branch)
    // semantically; the spec (§5, §9.9) does not pin the field name.
    let edge_props = serde_json::json!({
        "rationale": params.rationale,
        "evolved_at": chrono::Utc::now().to_rfc3339(),
    });
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES ($1, $2, 'claim', $3, 'claim', $4, $5)",
    )
    .bind(edge_id)
    .bind(claim_id)
    .bind(parent_id)
    .bind(&params.edge_type)
    .bind(&edge_props)
    .execute(&mut *tx)
    .await
    .map_err(|e| internal_error(format!("insert edge: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| internal_error(format!("commit: {e}")))?;

    success_json(&EvolveStepResponse {
        claim_id,
        step_lineage_id,
        edge_id,
    })
}

fn success_json<T: Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}
