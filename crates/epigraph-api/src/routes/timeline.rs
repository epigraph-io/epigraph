//! Agent activity timeline endpoint
//!
//! Merges security events and PROV-O activities for a single agent into a
//! unified, time-ordered audit view.  Read-only; no authentication required.

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
#[cfg(feature = "db")]
pub async fn get_agent_timeline(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<TimelineEntry>>, ApiError> {
    use epigraph_db::repos::activity::ActivityRow;
    use epigraph_db::repos::security_event::{SecurityEventFilter, SecurityEventRepository};
    use epigraph_db::ActivityRepository;

    // --- 1. Fetch security events for this agent (newest 50) ----------------
    let sec_events = SecurityEventRepository::query(
        &state.db_pool,
        SecurityEventFilter {
            agent_id: Some(id),
            limit: Some(50),
            ..Default::default()
        },
    )
    .await?;

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
#[cfg(not(feature = "db"))]
pub async fn get_agent_timeline(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
) -> Result<Json<Vec<TimelineEntry>>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Agent timeline requires database".to_string(),
    })
}
