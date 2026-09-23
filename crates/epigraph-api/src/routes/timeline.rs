//! Agent activity timeline endpoint
//!
//! Merges security events and PROV-O activities for a single agent into a
//! unified, time-ordered audit view.  Read-only, and — since PR-03 moved the
//! registration onto the `protected` router — authenticated: an agent's audit
//! trail is exactly the kind of activity map an anonymous scanner should not
//! be able to assemble.

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::{errors::ApiError, state::AppState};

// =============================================================================
// RESPONSE TYPES
// =============================================================================

/// A single entry in the merged agent timeline
#[derive(Serialize, Debug)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    /// "security_event" or "activity"
    pub entry_type: String,
    /// Human-readable one-liner describing the event
    pub summary: String,
    /// Full event details (verbatim row fields as JSON)
    pub details: serde_json::Value,
}

// =============================================================================
// HANDLER (db feature)
// =============================================================================

/// Get merged agent timeline
///
/// GET /api/v1/agents/:id/timeline
///
/// Returns up to 100 timeline entries (security events + activities) for the
/// given agent, merged and ordered by timestamp descending.
///
/// # The security-event half is the caller's to read, not the path's
///
/// `:id` comes from the path and this route checks no scope, so it cannot decide
/// whose security events a caller sees. The security-event half is therefore
/// read the way `GET /api/v1/audit/security` reads it: on a connection stamped
/// with the caller's viewer, through
/// `SecurityEventRepository::query_for_principal_conn`, which narrows to the
/// caller's own principal unless the caller is a live instance administrator.
/// Before this, the read was `SecurityEventRepository::query(&state.db_pool, ..)`
/// with the path's `:id` as its only filter, so any authenticated caller could
/// read any agent's security events here, without the `audit:read` scope the
/// audit route requires.
///
/// Another agent's timeline is still served, with its activity half and no
/// security events, unless the caller is an instance admin. That is the same
/// answer the policy gives, and it is not a 403 because the activity half is
/// readable. Found while re-deriving `F-PR18a-B1`; see that entry's
/// `sibling_route` in `docs/tenancy/progress.json`.
///
/// This route still checks no scope, so a caller without `audit:read` reads
/// its OWN security events here. Whether that half should require the scope
/// is `open_findings::F-timeline-security-events-scope`, an operator decision.
///
/// The activity half still reads `state.db_pool`. `activities` has no tenancy
/// columns and no RLS policy, so a stamped connection would change nothing
/// there. Whether it should be narrowed is a separate question, and
/// `routes/activities.rs` reads the same table the same way.
#[cfg(feature = "db")]
pub async fn get_agent_timeline(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<TimelineEntry>>, ApiError> {
    use epigraph_db::repos::activity::ActivityRow;
    use epigraph_db::repos::security_event::{SecurityEventFilter, SecurityEventRepository};
    use epigraph_db::ActivityRepository;

    // `ViewerExtractor` only ever yields a `Scoped` viewer; see audit.rs.
    let Some(principal) = viewer.principal() else {
        return Err(ApiError::Forbidden {
            reason: "the agent timeline is read as a principal".to_string(),
        });
    };

    // --- 1. Fetch security events for this agent (newest 50) ----------------
    // On the caller's stamped connection, narrowed to what the caller may read.
    // Error shape as in `routes/voids.rs`: logged in full, answered opaquely.
    let scoped_read_error = |e: epigraph_db::DbError| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_agent_timeline",
            "viewer-stamped read failed"
        );
        ApiError::InternalError {
            message: "Failed to read on a scoped connection".to_string(),
        }
    };
    let mut read = state.read_as(&viewer).await.map_err(scoped_read_error)?;
    let sec_events = SecurityEventRepository::query_for_principal_conn(
        &mut read,
        principal,
        SecurityEventFilter {
            agent_id: Some(id),
            limit: Some(50),
            ..Default::default()
        },
    )
    .await?;
    read.commit().await.map_err(scoped_read_error)?;

    // --- 2. Fetch activities for this agent (newest 50) ---------------------
    // `list_by_agent` is already ordered by started_at DESC; we take the first 50.
    let activities: Vec<ActivityRow> = ActivityRepository::list_by_agent(&state.db_pool, id)
        .await?
        .into_iter()
        .take(50)
        .collect();

    // --- 3. Convert security events to TimelineEntry ------------------------
    let mut entries: Vec<TimelineEntry> = sec_events
        .into_iter()
        .map(|ev| {
            let summary = format!(
                "{} — {}",
                ev.event_type,
                if ev.success == Some(false) {
                    "failure"
                } else if ev.success == Some(true) {
                    "success"
                } else {
                    "n/a"
                }
            );
            TimelineEntry {
                timestamp: ev.created_at,
                entry_type: "security_event".to_string(),
                summary,
                details: serde_json::json!({
                    "id": ev.id,
                    "event_type": ev.event_type,
                    "success": ev.success,
                    "ip_address": ev.ip_address,
                    "correlation_id": ev.correlation_id,
                    "details": ev.details,
                }),
            }
        })
        .collect();

    // --- 4. Convert activities to TimelineEntry -----------------------------
    let act_entries = activities.into_iter().map(|act| {
        let summary = format!(
            "{} — {}",
            act.activity_type,
            act.description.as_deref().unwrap_or("no description")
        );
        TimelineEntry {
            timestamp: act.started_at,
            entry_type: "activity".to_string(),
            summary,
            details: serde_json::json!({
                "id": act.id,
                "activity_type": act.activity_type,
                "started_at": act.started_at,
                "ended_at": act.ended_at,
                "description": act.description,
                "properties": act.properties,
            }),
        }
    });
    entries.extend(act_entries);

    // --- 5. Sort by timestamp DESC, take top 100 ----------------------------
    entries.sort_unstable_by_key(|b| std::cmp::Reverse(b.timestamp));
    entries.truncate(100);

    Ok(Json(entries))
}

/// Placeholder when database feature is disabled
///
/// GET /api/v1/agents/:id/timeline
///
/// Takes the same `ViewerExtractor` as the `db` arm, so both builds give the
/// same 401 first.
#[cfg(not(feature = "db"))]
pub async fn get_agent_timeline(
    crate::middleware::bearer::ViewerExtractor(_viewer): crate::middleware::bearer::ViewerExtractor,
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
) -> Result<Json<Vec<TimelineEntry>>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Agent timeline requires database".to_string(),
    })
}
