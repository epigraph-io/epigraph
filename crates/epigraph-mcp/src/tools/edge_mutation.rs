//! `patch_edge` / `delete_edge` — MCP wrappers for the edge lifecycle
//! mutations that previously existed only as HTTP routes.
//!
//! Counterparts to `epigraph-api::routes::edges::patch_edge` and
//! `epigraph-api::routes::edges::delete_edge`. Before these tools, an MCP-only
//! agent could **create** edges (`link_epistemic`, `link_hierarchical`,
//! `link_alternative`) but could never retire or remove one: the only way to
//! act on a self-diagnosed mislabeled edge was raw OAuth + `curl` against
//! `PATCH`/`DELETE /api/v1/edges/:id`, which the scheduled-agent workflows
//! forbid. Backlog claim `450236b0-f2f6-4058-9076-54944f4c975d`.
//!
//! # Parity with the HTTP routes
//!
//! Both tools go straight through `EdgeRepository` — the same repo calls the
//! routes make — and reproduce the routes' guards verbatim:
//!
//! * empty patch body (neither `valid_to` nor `properties`) → `INVALID_PARAMS`,
//!   mirroring the route's 400;
//! * non-object `properties` → `INVALID_PARAMS`. This one is load-bearing, not
//!   cosmetic: Postgres evaluates `'{"a":1}'::jsonb || '5'::jsonb` to
//!   `[{"a":1}, 5]`, silently converting the column from object to array. The
//!   repo's shallow-merge `||` relies on object-||-object semantics, so a
//!   non-object patch is a data-corruption path, not a user error;
//! * unknown edge id → `INVALID_PARAMS` naming the id. `DbError::NotFound` is
//!   mapped explicitly rather than through `internal_error`, because
//!   `epigraph-mcp::errors` has no 404 equivalent and an opaque
//!   `INTERNAL_ERROR` is exactly the failure an autonomous agent cannot
//!   recover from.
//!
//! Events mirror the routes' emissions (`edge.updated` always on patch,
//! `edge.retired` additionally when the patch closes the lifecycle window,
//! `edge.deleted` on delete) but travel through
//! `EventRepository::publish_or_log_conn` on the mutation's own transaction —
//! the durable MCP path `link_epistemic` also uses — rather than the
//! API-crate-local `global_event_store`, which is not reachable from this crate.
//!
//! # Tenancy
//!
//! Both mutations run on ONE transaction stamped from the write identity (the caller over HTTP, the server's own
//! agent (`claim_helper::begin_author_stamped_tx`), with their events on the
//! same transaction. WRITE authority is the server agent's, as for every other
//! MCP write. READ authority is the CALLER's: before either write, the edge is
//! read through the caller's viewer on that transaction
//! (`EdgeRepository::visible_to`), and an edge the caller cannot see is
//! reported as "not found" with nothing written. Before that gate (batch H-a
//! review) neither tool took a viewer, so any `claims:write` caller could
//! retire or relabel an edge touching a server-group-private claim it could not
//! read. Whether the caller should also need OWNERSHIP of the edge (edges carry
//! no author column; the candidates are its endpoints' authors) is the
//! cross-agent authority question (H-b, #374), not this gate's.
//!
//! # `valid_to: "now"`
//!
//! The one deliberate divergence from the HTTP contract. The route takes an
//! RFC3339 timestamp; an LLM-driven MCP client has no wall clock, so
//! requiring one would make the primary use case ("retire this wrong edge")
//! depend on the model guessing the time. `"now"` resolves server-side to
//! `Utc::now()`. Any other value must still parse as RFC3339.
//!
//! # Deferred, matching `link_epistemic`'s precedent
//!
//! * **Per-edge provenance.** The routes call
//!   `epigraph-api::middleware::provenance::record_provenance`, which lives in
//!   the API crate and is keyed on an HTTP `AuthContext`. `link_epistemic`
//!   already documents per-edge provenance as deferred for MCP writes; these
//!   tools follow that precedent rather than inventing a second provenance
//!   path.
//! * **BBA invalidation.** Neither the HTTP routes nor these wrappers touch
//!   the `perspective_id = edge_id` mass function that
//!   `edge_factor::auto_wire_ds_for_edge` stored when an epistemic edge was
//!   created. Retiring or deleting the edge therefore leaves the target's
//!   combined belief still carrying the retracted edge's contribution — the
//!   exact invalidation-vs-recombination problem
//!   `epigraph_engine::retraction_cascade` was written for. Wiring that
//!   cascade into the edge-mutation path is a belief-semantics decision with
//!   its own design surface (cross-frame BBAs, the unbacked/`clear_claim_belief`
//!   rule) and is intentionally NOT bundled into a wrapper that claims REST
//!   parity.

use chrono::{DateTime, Utc};
use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{DeleteEdgeParams, DeleteEdgeResponse, PatchEdgeParams, PatchEdgeResponse};

use epigraph_db::{DbError, EdgeRepository, EventRepository};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

/// Resolve the `valid_to` parameter: the literal `"now"` (case-insensitive,
/// trimmed) becomes the current UTC instant; anything else must be RFC3339.
fn resolve_valid_to(raw: Option<&str>) -> Result<Option<DateTime<Utc>>, McpError> {
    let Some(raw) = raw else { return Ok(None) };
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("now") {
        return Ok(Some(Utc::now()));
    }
    DateTime::parse_from_rfc3339(trimmed)
        .map(|dt| Some(dt.with_timezone(&Utc)))
        .map_err(|e| {
            invalid_params(format!(
                "valid_to must be an RFC3339 timestamp or the literal \"now\"; got {raw:?} ({e})"
            ))
        })
}

/// Map a repo error to an MCP error, translating `DbError::NotFound` into a
/// caller-actionable `INVALID_PARAMS` instead of an opaque internal error.
fn map_edge_err(e: DbError) -> McpError {
    match e {
        DbError::NotFound { id, .. } => invalid_params(format!("edge {id} not found")),
        other => internal_error(other),
    }
}

pub async fn patch_edge(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: PatchEdgeParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    do_patch_edge(server, viewer, params, auth).await
}

/// The caller-read gate both tools apply, on the write transaction.
async fn require_visible_edge(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    edge_id: uuid::Uuid,
) -> Result<(), McpError> {
    if EdgeRepository::visible_to(&mut *conn, viewer, edge_id)
        .await
        .map_err(internal_error)?
    {
        Ok(())
    } else {
        Err(invalid_params(format!("edge {edge_id} not found")))
    }
}

/// Core logic factored out so integration tests can call it directly without
/// round-tripping through the rmcp dispatch layer (mirrors
/// `do_link_epistemic`).
pub async fn do_patch_edge(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: PatchEdgeParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let edge_id = parse_uuid(&params.edge_id)?;

    if params.valid_to.is_none() && params.properties.is_none() {
        return Err(invalid_params(
            "patch_edge requires at least one of valid_to or properties",
        ));
    }

    // See the module doc: a non-object `properties` turns the JSONB column
    // into an array via `||` with no error from Postgres.
    if let Some(ref props) = params.properties {
        if !props.is_object() {
            return Err(invalid_params("properties must be a JSON object"));
        }
    }

    let valid_to = resolve_valid_to(params.valid_to.as_deref())?;

    // ONE TRANSACTION, STAMPED FROM THE WRITE IDENTITY (the caller over HTTP, the server's own agent on stdio; batch H-b D1): the UPDATE and
    // both events.
    //
    // The UPDATE used to run on the unstamped pool. `edges_tenancy` then let it
    // reach only a PUBLIC edge (USING) and keep it only if world-owned (WITH
    // CHECK's static arm). A group-owned edge (one touching a group-private claim)
    // read as "not found" on a cleanly-migrated schema. Production reached it only
    // through the orphan `edges_privacy` policy that R3 drops. Stamped, the
    // server agent's own group's edges are reachable too. An edge in another
    // agent's private group is still invisible to this session and reports "not
    // found", with nothing written. Whether a caller should carry write authority
    // into a group this process cannot write is the cross-agent ownership
    // question (#374), not a stamping one.
    //
    // The events used to be separate auto-committing statements after the
    // UPDATE. They now ride the UPDATE's transaction, each SAVEPOINT-wrapped
    // inside `publish_or_log_conn`: a refused event cannot abort the patch, and
    // no `edge.updated` is emitted for a patch that was rolled back.
    let actor = server.write_identity(auth, viewer).await?;
    let actor_id = actor.agent_id();
    let mut tx = crate::claim_helper::begin_author_stamped_tx(server, actor, "patch_edge").await?;
    require_visible_edge(&mut tx, viewer, edge_id).await?;
    let updated = EdgeRepository::update_valid_to_and_properties(
        &mut *tx,
        edge_id,
        valid_to,
        params.properties,
    )
    .await
    .map_err(map_edge_err)?;

    // Best-effort durable events, mirroring the HTTP route's pair.
    let _ = EventRepository::publish_or_log_conn(
        &mut tx,
        "edge.updated",
        Some(actor_id),
        &serde_json::json!({
            "edge_id": updated.id,
            "source_type": updated.source_type,
            "source_id": updated.source_id,
            "target_type": updated.target_type,
            "target_id": updated.target_id,
            "relationship": updated.relationship,
        }),
    )
    .await;

    // `edge.retired` is the more specific signal — fired only when this call
    // closed the lifecycle window.
    if valid_to.is_some() {
        let _ = EventRepository::publish_or_log_conn(
            &mut tx,
            "edge.retired",
            Some(actor_id),
            &serde_json::json!({
                "edge_id": updated.id,
                "valid_to": updated.valid_to,
            }),
        )
        .await;
    }
    tx.commit().await.map_err(internal_error)?;

    success_json(&PatchEdgeResponse {
        edge_id: updated.id.to_string(),
        source_id: updated.source_id.to_string(),
        source_type: updated.source_type,
        target_id: updated.target_id.to_string(),
        target_type: updated.target_type,
        relationship: updated.relationship,
        properties: updated.properties,
        valid_from: updated.valid_from.map(|t| t.to_rfc3339()),
        valid_to: updated.valid_to.map(|t| t.to_rfc3339()),
        retired: valid_to.is_some(),
    })
}

pub async fn delete_edge(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: DeleteEdgeParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    do_delete_edge(server, viewer, params, auth).await
}

/// Core logic factored out for direct test invocation (see `do_patch_edge`).
pub async fn do_delete_edge(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: DeleteEdgeParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let edge_id = parse_uuid(&params.edge_id)?;

    // ONE TRANSACTION, STAMPED FROM THE WRITE IDENTITY (the caller over HTTP, the server's own agent on stdio; batch H-b D1): the retraction
    // and its event. Same reasoning as `do_patch_edge`. On the unstamped pool
    // only a public, world-owned edge was retractable on a cleanly-migrated
    // schema. Stamped, the server agent's own group's edges are too, and an edge
    // in another agent's private group still reports "not found" with nothing
    // written (#374 owns whether it should).
    let actor = server.write_identity(auth, viewer).await?;
    let actor_id = actor.agent_id();
    let mut tx = crate::claim_helper::begin_author_stamped_tx(server, actor, "delete_edge").await?;
    require_visible_edge(&mut tx, viewer, edge_id).await?;

    // `EdgeRepository::delete` reports absence as `Ok(false)`, not
    // `DbError::NotFound`, so the 404-equivalent is raised here. Returning
    // before COMMIT drops `tx`, which rolls back; nothing was written anyway.
    let deleted = EdgeRepository::retract_by_id(&mut *tx, edge_id)
        .await
        .map_err(map_edge_err)?;
    if !deleted {
        return Err(invalid_params(format!("edge {edge_id} not found")));
    }

    // SAVEPOINT-wrapped inside `publish_or_log_conn`: a refused event cannot
    // abort the retraction, and it shares the retraction's fate.
    let _ = EventRepository::publish_or_log_conn(
        &mut tx,
        "edge.deleted",
        Some(actor_id),
        &serde_json::json!({ "edge_id": edge_id }),
    )
    .await;
    tx.commit().await.map_err(internal_error)?;

    success_json(&DeleteEdgeResponse {
        edge_id: edge_id.to_string(),
        deleted: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `"now"` is the documented divergence from the HTTP contract — an MCP
    /// client has no wall clock. It must resolve to roughly the current
    /// instant, case-insensitively and tolerant of surrounding whitespace.
    #[test]
    fn valid_to_now_resolves_to_current_instant() {
        for literal in ["now", "NOW", "  Now  "] {
            let before = Utc::now();
            let resolved = resolve_valid_to(Some(literal))
                .expect("\"now\" must be accepted")
                .expect("\"now\" must resolve to Some");
            let after = Utc::now();
            assert!(
                resolved >= before && resolved <= after,
                "{literal:?} resolved to {resolved}, outside [{before}, {after}]"
            );
        }
    }

    /// RFC3339 passes through with its offset normalised to UTC — the caller's
    /// timestamp must not be silently reinterpreted as local time.
    #[test]
    fn valid_to_rfc3339_is_normalised_to_utc() {
        let resolved = resolve_valid_to(Some("2026-01-02T03:04:05+02:00"))
            .expect("RFC3339 must be accepted")
            .expect("must resolve to Some");
        assert_eq!(
            resolved.to_rfc3339(),
            "2026-01-02T01:04:05+00:00",
            "a +02:00 offset must be converted to the equivalent UTC instant"
        );
    }

    /// A garbage timestamp must be a caller-fixable INVALID_PARAMS, not an
    /// opaque internal error, and must not be silently coerced to `None`
    /// (which would turn "retire this edge" into a no-op patch).
    #[test]
    fn valid_to_garbage_is_invalid_params() {
        let err = resolve_valid_to(Some("yesterday")).expect_err("garbage must be rejected");
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        assert!(
            err.message.contains("RFC3339"),
            "error must tell the caller the expected format, got: {}",
            err.message
        );
        // A bare date is not a valid instant either.
        assert!(resolve_valid_to(Some("2026-01-02")).is_err());
        // Empty string must not be mistaken for "unset".
        assert!(resolve_valid_to(Some("")).is_err());
    }

    /// Absent `valid_to` stays absent — `COALESCE($2, valid_to)` in the repo
    /// relies on NULL meaning "leave the existing value alone".
    #[test]
    fn valid_to_absent_resolves_to_none() {
        assert!(resolve_valid_to(None).expect("None is valid").is_none());
    }

    /// `DbError::NotFound` must surface as INVALID_PARAMS naming the edge, so
    /// an agent can distinguish "wrong id" from "server broken"; every other
    /// DbError must stay INTERNAL_ERROR.
    #[test]
    fn not_found_maps_to_invalid_params_other_errors_stay_internal() {
        let id = uuid::Uuid::new_v4();
        let err = map_edge_err(DbError::NotFound {
            entity: "edge".to_string(),
            id,
        });
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        assert!(
            err.message.contains(&id.to_string()),
            "not-found message must name the edge id, got: {}",
            err.message
        );

        let other = map_edge_err(DbError::InvalidData {
            reason: "connection reset".to_string(),
        });
        assert_eq!(
            other.code,
            ErrorCode::INTERNAL_ERROR,
            "non-NotFound repo failures must not be reported as caller errors"
        );
    }
}
