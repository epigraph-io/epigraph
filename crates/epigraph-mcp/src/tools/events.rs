#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::EventRepository;

/// List events with optional filtering.
///
/// # Tenancy (PR-09)
///
/// Viewer-scoped via `EventRepository::list`: an event whose payload names a
/// claim the viewer cannot read is absent. The payload is not metadata — it
/// carries `claim_id`, `agent_id` and `initial_truth`.
pub async fn list_events(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
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

    let events = EventRepository::list(
        &server.pool,
        viewer,
        params.event_type.as_deref(),
        actor_id,
        limit,
    )
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
/// Publish one event to the log.
///
/// # The actor is the caller over HTTP (batch H-b review)
///
/// `actor_id` used to be taken from the caller verbatim on every transport, so
/// an OAuth caller recorded events attributed to ANOTHER agent (measured: one
/// event with `actor_id` = a foreign agent, config A and B). Over the
/// authenticated transport the actor is now the write identity: an omitted
/// `actor_id` defaults to it, and a different one is refused with nothing
/// written. stdio keeps the parameter as given (the batch H-b bar: stdio
/// changes only for #374).
pub async fn publish_event(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: PublishEventParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    if params.event_type.trim().is_empty() {
        return Err(invalid_params("event_type cannot be empty"));
    }

    let requested = params
        .actor_id
        .as_ref()
        .map(|s| {
            uuid::Uuid::parse_str(s)
                .map_err(|_| invalid_params(format!("Invalid actor_id UUID: {s}")))
        })
        .transpose()?;
    let actor_id = if auth.is_some() {
        let me = server.write_identity(auth, viewer).await?.agent_id();
        if let Some(other) = requested.filter(|a| *a != me) {
            return Err(invalid_params(format!(
                "actor_id {other} is not the calling agent ({me}); over an authenticated \
                 connection an event is attributed to its caller. Omit actor_id or pass your \
                 own. Nothing was written."
            )));
        }
        Some(me)
    } else {
        requested
    };

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
