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

/// The attribution rule for a caller-facing event write. It is the MCP twin of
/// `epigraph-api`'s `routes/events.rs::bind_actor`, and the two must stay
/// identical.
///
/// An absent `actor_id` is the principal. An `actor_id` equal to the principal
/// is accepted. Anything else is refused. The error is `invalid_params`, the
/// code `claims::require_owner_or_admin` already uses to refuse a caller acting
/// on another agent's behalf, because MCP has no 403.
pub(crate) fn bind_actor(
    requested: Option<uuid::Uuid>,
    principal: uuid::Uuid,
) -> Result<uuid::Uuid, McpError> {
    match requested {
        None => Ok(principal),
        Some(actor) if actor == principal => Ok(principal),
        Some(actor) => Err(invalid_params(format!(
            "actor_id {actor} is not the calling principal ({principal}); an event can \
             only be attributed to its caller, so omit actor_id or set it to your own \
             agent id"
        ))),
    }
}

/// Publish a manual event, attributed to the calling principal.
///
/// # Attribution (deferred-commitment `events-actor-id-binding`)
///
/// `auth` is the per-request `AuthContext` on HTTP and `None` on stdio, the
/// same argument `supersede_claim` takes. The caller's `agents.id` comes from
/// [`crate::tools::viewer::request_principal`], which is the resolution
/// `request_viewer` uses. HTTP gets `auth.agent_id`, and a token without one is
/// refused. stdio gets the server's own agent, because there the process IS the
/// principal. [`bind_actor`] then applies the rule, and the resolved actor is
/// what reaches `EventRepository::insert`.
///
/// Before this change `params.actor_id` went into the insert unchecked, so a
/// `claims:write` caller could record an event attributed to any existing agent
/// (`events_actor_id_fkey` bounds it to real `agents` rows and no further), and
/// `list_events`' `actor_id` filter would return it as that agent's. The rule
/// is not relaxed on stdio. A stdio caller naming another agent is refused too,
/// so "an event's actor is the principal that published it" holds on every
/// transport.
///
/// Not `server.agent_id()` on every transport. On HTTP that is the server's own
/// signer identity, shared by every caller of the listener, so it would stamp
/// every multi-user caller's events with one agent. That is unforgeable, but it
/// attributes nothing.
pub async fn publish_event(
    server: &EpiGraphMcpFull,
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

    let principal = crate::tools::viewer::request_principal(server, auth).await?;
    let actor_id = bind_actor(requested, principal)?;

    let event_id = EventRepository::insert(
        &server.pool,
        &params.event_type,
        Some(actor_id),
        &params.payload,
    )
    .await
    .map_err(internal_error)?;

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::json!({
            "event_id": event_id,
            "event_type": params.event_type,
            "actor_id": actor_id,
        })
        .to_string(),
    )]))
}

#[cfg(test)]
mod tests {
    use super::bind_actor;
    use uuid::Uuid;

    #[test]
    fn an_absent_actor_is_the_principal() {
        let p = Uuid::new_v4();
        assert_eq!(bind_actor(None, p).unwrap(), p);
    }

    #[test]
    fn the_principal_naming_itself_is_accepted() {
        let p = Uuid::new_v4();
        assert_eq!(bind_actor(Some(p), p).unwrap(), p);
    }

    #[test]
    fn any_other_actor_is_refused_as_invalid_params() {
        let p = Uuid::new_v4();
        let other = Uuid::new_v4();
        let err = bind_actor(Some(other), p).expect_err("a forged actor must be refused");
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(err.message.contains(&other.to_string()), "{}", err.message);
    }

    /// The nil UUID is not a wildcard. A client that sends it as a placeholder
    /// is refused like any other agent id that is not its own.
    #[test]
    fn the_nil_uuid_is_not_a_wildcard() {
        let p = Uuid::new_v4();
        assert!(bind_actor(Some(Uuid::nil()), p).is_err());
    }
}
