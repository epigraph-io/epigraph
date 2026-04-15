#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::{EdgeRepository, OwnershipRepository, PerspectiveRepository};

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

/// List all perspectives with optional pagination.
pub async fn list_perspectives(
    server: &EpiGraphMcpFull,
    params: ListPerspectivesParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    let rows = PerspectiveRepository::list(&server.pool, limit, 0)
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
            })
        })
        .collect();

    success_json(&results)
}

/// Get a single perspective by ID.
pub async fn get_perspective(
    server: &EpiGraphMcpFull,
    params: GetPerspectiveParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.perspective_id)?;

    let row = PerspectiveRepository::get_by_id(&server.pool, id)
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
pub async fn assign_ownership(
    server: &EpiGraphMcpFull,
    params: AssignOwnershipParams,
) -> Result<CallToolResult, McpError> {
    let node_id = parse_uuid(&params.node_id)?;
    let owner_id = if let Some(ref id) = params.owner_id {
        parse_uuid(id)?
    } else {
        server.agent_id().await?
    };

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
        "created_at": row.created_at.to_rfc3339(),
        "updated_at": row.updated_at.to_rfc3339(),
    }))
}

/// Update the partition type of a node.
pub async fn update_partition(
    server: &EpiGraphMcpFull,
    params: UpdatePartitionParams,
) -> Result<CallToolResult, McpError> {
    let node_id = parse_uuid(&params.node_id)?;

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
