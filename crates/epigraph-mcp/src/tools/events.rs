#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::EventRepository;

/// List events with optional filtering.
pub async fn list_events(
    server: &EpiGraphMcpFull,
    params: ListEventsParams,
) -> Result<CallToolResult, McpError> {
    let actor_id = params
        .actor_id
        .as_ref()
        .map(|s| {
            uuid::Uuid::parse_str(s)
                .map_err(|_| invalid_params(format!("Invalid actor_id UUID: {s}")))
        })
        .transpose()?;

    let limit = params.limit.unwrap_or(50).min(500);

    let events = EventRepository::list(&server.pool, params.event_type.as_deref(), actor_id, limit)
        .await
        .map_err(internal_error)?;

    let results: Vec<serde_json::Value> = events
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "event_type": e.event_type,
                "actor_id": e.actor_id,
                "payload": e.payload,
                "graph_version": e.graph_version,
                "created_at": e.created_at.to_rfc3339(),
            })
        })
        .collect();

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::json!({
            "events": results,
            "total": results.len(),
        })
        .to_string(),
    )]))
}

/// Publish a manual event.
pub async fn publish_event(
    server: &EpiGraphMcpFull,
    params: PublishEventParams,
) -> Result<CallToolResult, McpError> {
    if params.event_type.trim().is_empty() {
        return Err(invalid_params("event_type cannot be empty"));
    }

    let actor_id = params
        .actor_id
        .as_ref()
        .map(|s| {
            uuid::Uuid::parse_str(s)
                .map_err(|_| invalid_params(format!("Invalid actor_id UUID: {s}")))
        })
        .transpose()?;

    let event_id =
        EventRepository::insert(&server.pool, &params.event_type, actor_id, &params.payload)
            .await
            .map_err(internal_error)?;

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::json!({
            "event_id": event_id,
            "event_type": params.event_type,
        })
        .to_string(),
    )]))
}
