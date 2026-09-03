//! Event sourcing endpoints for the epistemic knowledge graph.
//!
//! Provides an append-only event log that records all graph mutations,
//! enabling auditability, replay, and time-travel queries.
//!
//! ## Endpoints
//!
//! - `GET  /api/v1/events`                - Paginated event log with filtering
//! - `POST /api/v1/events`                - Record a new graph event
//! - `GET  /api/v1/graph/snapshot/:version` - Reconstruct graph state at a version
//!
//! ## Design
//!
//! The in-memory `EventStore` uses a module-level `OnceLock` so that all
//! handlers share the same store without modifying `AppState`. Each event
//! receives a monotonically increasing `graph_version`, making it trivial
//! to request "all events since version N" for incremental synchronisation.

use crate::errors::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::{atomic::AtomicI64, atomic::Ordering, Arc, OnceLock};
use tokio::sync::RwLock;
use uuid::Uuid;

// ── Event store singleton ────────────────────────────────────────────────────

/// Module-level singleton so all handlers share the same store.
///
/// Exposed as `pub` so integration tests (and any future cross-crate consumer
/// that needs to drive the in-memory event bus) can push to the same store
/// the route handlers read from. The store has no externally observable
/// state beyond what its own methods expose, so widening visibility doesn't
/// break encapsulation.
pub fn global_event_store() -> &'static Arc<EventStore> {
    static STORE: OnceLock<Arc<EventStore>> = OnceLock::new();
    STORE.get_or_init(|| Arc::new(EventStore::new()))
}

// ── Core types ───────────────────────────────────────────────────────────────

/// A single event in the epistemic graph's history.
///
/// Events are immutable once created. The `graph_version` field provides
/// a total ordering that is cheaper to compare than timestamps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEvent {
    /// Unique identifier for this event
    pub id: Uuid,
    /// The kind of mutation (e.g. "claim.created", "edge.deleted")
    pub event_type: String,
    /// The agent that triggered the event, if attributable
    pub actor_id: Option<Uuid>,
    /// Arbitrary structured payload describing the mutation
    pub payload: serde_json::Value,
    /// Monotonically increasing version counter for ordering
    pub graph_version: i64,
    /// When this event was recorded
    pub created_at: DateTime<Utc>,
}

/// Thread-safe, append-only event store backed by a `Vec`.
///
/// The atomic version counter guarantees monotonicity even under
/// concurrent writes (each event gets a unique, increasing version).
pub struct EventStore {
    events: RwLock<Vec<GraphEvent>>,
    version_counter: AtomicI64,
}

impl EventStore {
    /// Create an empty event store starting at version 0.
    pub fn new() -> Self {
        Self {
            events: RwLock::new(Vec::new()),
            version_counter: AtomicI64::new(0),
        }
    }

    /// Append a new event, assigning it a monotonic version and timestamp.
    pub async fn push(
        &self,
        event_type: String,
        actor_id: Option<Uuid>,
        payload: serde_json::Value,
    ) -> GraphEvent {
        let version = self.version_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let event = GraphEvent {
            id: Uuid::new_v4(),
            event_type,
            actor_id,
            payload,
            graph_version: version,
            created_at: Utc::now(),
        };
        self.events.write().await.push(event.clone());
        event
    }

    /// List events matching the given filter, with pagination.
    pub async fn list(&self, filter: &EventFilter) -> (Vec<GraphEvent>, usize) {
        let events = self.events.read().await;
        let filtered: Vec<&GraphEvent> = events
            .iter()
            .filter(|e| {
                if let Some(ref event_type) = filter.event_type {
                    if e.event_type != *event_type {
                        return false;
                    }
                }
                if let Some(since) = filter.since {
                    if e.created_at < since {
                        return false;
                    }
                }
                true
            })
            .collect();

        let total = filtered.len();
        let offset = filter.offset.unwrap_or(0);
        let limit = filter.limit.unwrap_or(100).min(1000);

        let page: Vec<GraphEvent> = filtered
            .into_iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();

        (page, total)
    }

    /// Return all events with `graph_version <= target_version`.
    pub async fn get_up_to_version(&self, target_version: i64) -> Vec<GraphEvent> {
        let events = self.events.read().await;
        events
            .iter()
            .filter(|e| e.graph_version <= target_version)
            .cloned()
            .collect()
    }

    /// Current graph version (0 if no events recorded).
    pub fn current_version(&self) -> i64 {
        self.version_counter.load(Ordering::SeqCst)
    }
}

impl Default for EventStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Request / Response types ─────────────────────────────────────────────────

/// Query parameters for `GET /api/v1/events`.
#[derive(Debug, Deserialize)]
pub struct EventFilter {
    /// Only return events created at or after this timestamp
    pub since: Option<DateTime<Utc>>,
    /// Only return events of this type
    pub event_type: Option<String>,
    /// Maximum number of events to return (default 100, max 1000)
    pub limit: Option<usize>,
    /// Number of events to skip for pagination
    pub offset: Option<usize>,
}

/// Response body for `GET /api/v1/events`.
#[derive(Debug, Serialize, Deserialize)]
pub struct EventListResponse {
    pub events: Vec<GraphEvent>,
    pub total: usize,
}

/// Request body for `POST /api/v1/events`.
#[derive(Debug, Deserialize)]
pub struct CreateEventRequest {
    /// The kind of mutation (e.g. "claim.created")
    pub event_type: String,
    /// The agent that triggered the event, if attributable
    pub actor_id: Option<Uuid>,
    /// Arbitrary structured payload
    pub payload: serde_json::Value,
}

/// Response body for `GET /api/v1/graph/snapshot/:version`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotResponse {
    /// The version this snapshot represents
    pub version: i64,
    /// Current latest version in the store
    pub current_version: i64,
    /// All events up to the requested version
    pub events: Vec<GraphEvent>,
    /// Number of events in this snapshot
    pub event_count: usize,
}

// ── Validation constants ─────────────────────────────────────────────────────

/// Maximum length of an event_type string in bytes.
const MAX_EVENT_TYPE_LENGTH: usize = 200;

/// Maximum payload size in bytes (64 KB, matching claim content limits).
const MAX_PAYLOAD_SIZE: usize = 65_536;

// ── Handlers ─────────────────────────────────────────────────────────────────

/// `GET /api/v1/events` - Paginated, filterable event log.
///
/// Returns events ordered by `graph_version` (ascending). Supports
/// filtering by `event_type` and `since` timestamp, with `limit`/`offset`
/// pagination.
///
/// # Tenancy (PR-09)
///
/// **Both** halves of the merge are viewer-scoped, by the same rule.
///
/// * The persisted half goes through `EventRepository::list`, whose doc states
///   the rule: an event is returned unless some uuid appearing anywhere in its
///   payload names a `claims` row the caller cannot read.
/// * The in-process half — `global_event_store()`, a ring buffer with no claim
///   join to hang a SQL predicate on — is filtered in Rust by
///   [`retain_visible_events`], which extracts the same uuids with
///   [`payload_uuids`] and asks `ClaimRepository::hidden_claim_ids` the same
///   question.
///
/// An earlier revision filtered only the persisted half and recorded the merge
/// as "not fixed, an in-process bus is not SQL" (plan §4.12's rationale for
/// deferring webhook fan-out to PR-10). That does not transfer: the ring buffer
/// is not a no-db artefact. `routes/edges.rs` pushes `edge.added` (payload:
/// `source_id`, `target_id`) and `claim.superseded`, `routes/belief.rs` pushes
/// `frame.created`, and `routes/community.rs` pushes too — all from
/// `#[cfg(feature = "db")]` handlers. Leaving step 2 open would have made the
/// merge the trivial bypass for the filter added one function up.
///
/// This is the HTTP twin of MCP `list_events`; both are fixed in the same
/// change so the two transports agree.
///
/// The signature is deliberately **not** `#[cfg]`-split. `ViewerExtractor` is
/// defined in both configurations (`middleware/bearer.rs` — `epigraph_db::Viewer`
/// under `db`, `NoDbViewer` under `not(db)`, with the same two 401 branches in
/// the same order) precisely so a handler can name it once and branch only its
/// body, per the convention `routes/rag.rs` states verbatim. An earlier revision
/// split the signature on the false premise that the extractor is db-only; the
/// result was a `not(db)` build whose `/api/v1/events` had no authentication
/// precondition at all while the `db` build 401s an `agent_id`-less token —
/// "a strictly weaker second implementation of the same route table", which is
/// the exact divergence `bearer.rs`'s own doc says `NoDbViewer` exists to
/// prevent.
pub async fn list_events(
    State(_state): State<AppState>,
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    Query(filter): Query<EventFilter>,
) -> Result<Json<EventListResponse>, ApiError> {
    // Bound in both configurations so the extractor — and therefore its two
    // 401 branches — runs identically in both. Under `not(db)` the value is a
    // `NoDbViewer` unit and nothing reads it.
    let _ = &viewer;
    #[cfg(feature = "db")]
    {
        let limit = filter.limit.unwrap_or(100).min(1000);
        let offset = filter.offset.unwrap_or(0);

        // 1. Pull from the persisted events table. Overfetch (limit + offset)
        //    plus headroom so dedup against the in-memory store doesn't
        //    starve the page. We still apply the final limit/offset post-merge.
        let overfetch = (limit.saturating_add(offset)).saturating_mul(2).max(limit);
        let rows = epigraph_db::EventRepository::list(
            &_state.db_pool,
            &viewer,
            filter.event_type.as_deref(),
            None, // actor_id — not part of the public filter
            overfetch as i64,
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to list persisted events: {e}"),
        })?;

        let mut events: Vec<GraphEvent> = rows
            .into_iter()
            .map(|r| GraphEvent {
                id: r.id,
                event_type: r.event_type,
                actor_id: r.actor_id,
                payload: r.payload,
                graph_version: r.graph_version,
                created_at: r.created_at,
            })
            .collect();

        // 2. Drain the in-memory event store, filtered by event_type and
        //    since. EventStore::list also caps at `limit` internally, so we
        //    pass a large limit here and re-page after merging.
        let in_mem_filter = EventFilter {
            since: filter.since,
            event_type: filter.event_type.clone(),
            limit: Some(usize::MAX),
            offset: None,
        };
        let (mut in_mem, _) = global_event_store().list(&in_mem_filter).await;
        // 2b. Apply the SAME visibility rule the persisted half got. See this
        //     handler's doc: the ring buffer is written by db-build handlers,
        //     so an unfiltered merge would hand back the private claim ids the
        //     step-1 filter just withheld.
        retain_visible_events(&_state.db_pool, &viewer, &mut in_mem).await?;
        events.extend(in_mem);

        // 3. Defensive since-filter on the merged set. The DB query above
        //    didn't narrow by `since`, so persisted events older than the
        //    cutoff need to be dropped here.
        if let Some(since) = filter.since {
            events.retain(|e| e.created_at >= since);
        }

        // 4. Dedup by event id. Persisted rows are first in the vec, so
        //    `retain` keeps the persisted copy when the same id appears in
        //    both stores.
        let mut seen: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
        events.retain(|e| seen.insert(e.id));

        // 5. Sort by `created_at` ascending. ASC matches the natural
        //    polling semantics of `since`-based subscribers (oldest-first
        //    so the next `since` cursor is just the last event's `created_at`).
        events.sort_by_key(|e| e.created_at);

        // 6. Apply offset + limit to the merged, sorted, deduped set.
        let total = events.len();
        let events = events.into_iter().skip(offset).take(limit).collect();

        Ok(Json(EventListResponse { events, total }))
    }
    #[cfg(not(feature = "db"))]
    {
        let store = global_event_store();
        let (events, total) = store.list(&filter).await;
        Ok(Json(EventListResponse { events, total }))
    }
}

/// Every uuid-shaped token anywhere in `payload`'s JSON text.
///
/// The Rust mirror of the `regexp_matches(e.payload::text, '<uuid>', 'g')` in
/// `epigraph_db::EventRepository::list`. Both are deliberately blunt — they
/// scan the *serialised document*, so nested objects, arrays, object keys and
/// uuids quoted inside free text are all found. Over-collecting is the safe
/// direction: a token that names no `claims` row cannot suppress anything,
/// because `ClaimRepository::hidden_claim_ids` returns only ids that exist
/// *and* are invisible.
///
/// Hand-written rather than a `regex` compile, because the shape is fixed: 36
/// characters, hex except for `-` at offsets 8, 13, 18 and 23.
///
/// # The two implementations are not identical, and the asymmetry is the safe
/// # one — do NOT "fix" it
///
/// Postgres `regexp_matches(..., 'g')` returns **non-overlapping** matches: it
/// resumes scanning after the end of each match. This scanner slides over
/// **every** byte offset, so on a long hex-and-dash run it collects overlapping
/// windows that Postgres skips. The Rust set is therefore a **superset** of the
/// SQL set, which means the in-memory half can only drop MORE events than the
/// persisted half — fail-closed.
///
/// Narrowing the Rust side to match Postgres exactly would make the in-memory
/// half the more permissive of the two, which is the direction that produces a
/// leak. The property to preserve is `rust ⊇ sql`, not `rust == sql`. Both
/// sides are pinned by
/// `payload_uuid_tests::an_over_long_hex_run_yields_its_prefix_in_both_implementations`,
/// which records the Postgres output verbatim.
#[cfg(feature = "db")]
fn payload_uuids(payload: &serde_json::Value) -> Vec<Uuid> {
    const DASHES: [usize; 4] = [8, 13, 18, 23];
    let text = payload.to_string();
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    if bytes.len() < 36 {
        return out;
    }
    for start in 0..=(bytes.len() - 36) {
        let w = &bytes[start..start + 36];
        let shaped = w.iter().enumerate().all(|(i, &b)| {
            if DASHES.contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        });
        if shaped {
            if let Ok(id) = std::str::from_utf8(w).unwrap_or("").parse::<Uuid>() {
                out.push(id);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Drop every event carrying a uuid that names a claim `viewer` cannot read.
///
/// The in-process half of the rule `EventRepository::list` applies in SQL. One
/// round-trip for the whole batch, and none at all when no event carries a
/// uuid.
#[cfg(feature = "db")]
async fn retain_visible_events(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::Viewer,
    events: &mut Vec<GraphEvent>,
) -> Result<(), ApiError> {
    let per_event: Vec<Vec<Uuid>> = events.iter().map(|e| payload_uuids(&e.payload)).collect();
    let mut all: Vec<Uuid> = per_event.iter().flatten().copied().collect();
    all.sort_unstable();
    all.dedup();
    if all.is_empty() {
        return Ok(());
    }
    let hidden = epigraph_db::ClaimRepository::hidden_claim_ids(pool, viewer, &all)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to resolve event payload visibility: {e}"),
        })?;
    if hidden.is_empty() {
        return Ok(());
    }
    let mut keep = per_event
        .iter()
        .map(|ids| !ids.iter().any(|i| hidden.contains(i)));
    events.retain(|_| keep.next().unwrap_or(true));
    Ok(())
}

/// `POST /api/v1/events` - Record a new graph event.
///
/// Auto-generates `id`, `graph_version` (monotonic), and `created_at`.
/// Validates that `event_type` is non-empty and payload is within size limits.
pub async fn create_event(
    State(_state): State<AppState>,
    Json(request): Json<CreateEventRequest>,
) -> Result<Json<GraphEvent>, ApiError> {
    // Validate event_type is non-empty and bounded
    let event_type = request.event_type.trim().to_string();
    if event_type.is_empty() {
        return Err(ApiError::ValidationError {
            field: "event_type".to_string(),
            reason: "event_type cannot be empty".to_string(),
        });
    }
    if event_type.len() > MAX_EVENT_TYPE_LENGTH {
        return Err(ApiError::ValidationError {
            field: "event_type".to_string(),
            reason: format!(
                "event_type exceeds maximum length of {} bytes",
                MAX_EVENT_TYPE_LENGTH
            ),
        });
    }

    // Validate payload size to prevent memory exhaustion
    let payload_str =
        serde_json::to_string(&request.payload).map_err(|e| ApiError::ValidationError {
            field: "payload".to_string(),
            reason: format!("Invalid payload: {e}"),
        })?;
    if payload_str.len() > MAX_PAYLOAD_SIZE {
        return Err(ApiError::ValidationError {
            field: "payload".to_string(),
            reason: format!("Payload exceeds maximum size of {} bytes", MAX_PAYLOAD_SIZE),
        });
    }

    #[cfg(feature = "db")]
    {
        let id = epigraph_db::EventRepository::insert(
            &_state.db_pool,
            &event_type,
            request.actor_id,
            &request.payload,
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to persist event: {e}"),
        })?;
        let event = GraphEvent {
            id,
            event_type,
            actor_id: request.actor_id,
            payload: request.payload,
            graph_version: epigraph_db::EventRepository::get_latest_version(&_state.db_pool)
                .await
                .unwrap_or(0),
            created_at: Utc::now(),
        };
        Ok(Json(event))
    }
    #[cfg(not(feature = "db"))]
    {
        let store = global_event_store();
        let event = store
            .push(event_type, request.actor_id, request.payload)
            .await;
        Ok(Json(event))
    }
}

/// `GET /api/v1/graph/snapshot/:version` - Graph state at a specific version.
///
/// Returns all events with `graph_version <= version`, providing the
/// information needed to reconstruct the graph as it existed at that point.
/// A future enhancement will replay events from periodic checkpoints for
/// efficiency.
///
/// # Tenancy (PR-09)
///
/// Viewer-scoped for the same reason `list_events` is — it replays the same
/// rows through the same repo function, so leaving it unfiltered would have
/// made it the trivial bypass for the filter added one function up.
///
/// Two consequences worth stating, because neither is a tenancy property:
/// `event_count` is now viewer-dependent (it counts the events *this* caller
/// may see, not the events that exist), and an event whose payload names a
/// claim the caller cannot read is absent from the replay. An event naming a
/// uuid that resolves to no `claims` row is deliberately **kept** — see
/// `EventRepository::list` — so snapshot fidelity does not depend on
/// referential integrity.
///
/// The signature is **not** `#[cfg]`-split; see `list_events`'s doc for why.
pub async fn graph_snapshot(
    State(_state): State<AppState>,
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    Path(version): Path<i64>,
) -> Result<Json<SnapshotResponse>, ApiError> {
    let _ = &viewer;
    if version < 0 {
        return Err(ApiError::ValidationError {
            field: "version".to_string(),
            reason: "Version must be non-negative".to_string(),
        });
    }

    #[cfg(feature = "db")]
    {
        let current = epigraph_db::EventRepository::get_latest_version(&_state.db_pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to get latest version: {e}"),
            })?;

        if version > current {
            return Err(ApiError::NotFound {
                entity: "graph_version".to_string(),
                id: format!("{version} (current version is {current})"),
            });
        }

        // Fetch all events up to version via the event list (filter by version not yet in repo,
        // so we fetch all and filter client-side for now)
        let rows =
            epigraph_db::EventRepository::list(&_state.db_pool, &viewer, None, None, version + 1)
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("Failed to fetch events for snapshot: {e}"),
                })?;
        let events: Vec<GraphEvent> = rows
            .into_iter()
            .filter(|r| r.graph_version <= version)
            .map(|r| GraphEvent {
                id: r.id,
                event_type: r.event_type,
                actor_id: r.actor_id,
                payload: r.payload,
                graph_version: r.graph_version,
                created_at: r.created_at,
            })
            .collect();
        let event_count = events.len();

        Ok(Json(SnapshotResponse {
            version,
            current_version: current,
            events,
            event_count,
        }))
    }
    #[cfg(not(feature = "db"))]
    {
        let store = global_event_store();
        let current = store.current_version();

        if version > current {
            return Err(ApiError::NotFound {
                entity: "graph_version".to_string(),
                id: format!("{version} (current version is {current})"),
            });
        }

        let events = store.get_up_to_version(version).await;
        let event_count = events.len();

        Ok(Json(SnapshotResponse {
            version,
            current_version: current,
            events,
            event_count,
        }))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, not(feature = "db")))]
mod tests {
    use super::*;
    use crate::state::ApiConfig;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt as _;

    /// Build a minimal router with just the event endpoints for testing.
    fn test_router() -> Router {
        let state = AppState::new(ApiConfig::default());
        Router::new()
            .route("/api/v1/events", get(list_events).post(create_event))
            .route("/api/v1/graph/snapshot/:version", get(graph_snapshot))
            .with_state(state)
    }

    /// Helper: POST an event and return the response status and body as `Vec<u8>`.
    async fn post_event(
        router: &Router,
        event_type: &str,
        payload: serde_json::Value,
    ) -> (StatusCode, Vec<u8>) {
        let body = serde_json::json!({
            "event_type": event_type,
            "actor_id": null,
            "payload": payload,
        });
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/events")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, bytes.to_vec())
    }

    // Because the OnceLock is global, tests that share the same binary
    // share the same store. Each test uses a unique event_type prefix
    // to avoid cross-contamination when filtering.

    #[tokio::test]
    async fn recording_event_increments_graph_version() {
        let router = test_router();

        let (status1, body1) = post_event(
            &router,
            "test.version_increment_1",
            serde_json::json!({"step": 1}),
        )
        .await;
        assert_eq!(status1, StatusCode::OK);
        let event1: GraphEvent = serde_json::from_slice(&body1).unwrap();

        let (status2, body2) = post_event(
            &router,
            "test.version_increment_2",
            serde_json::json!({"step": 2}),
        )
        .await;
        assert_eq!(status2, StatusCode::OK);
        let event2: GraphEvent = serde_json::from_slice(&body2).unwrap();

        assert!(
            event2.graph_version > event1.graph_version,
            "Second event version ({}) should be greater than first ({})",
            event2.graph_version,
            event1.graph_version,
        );
    }

    #[tokio::test]
    async fn listing_events_returns_all_events() {
        let router = test_router();

        // Record a few events with a unique prefix
        post_event(&router, "test.list_all_a", serde_json::json!({"x": 1})).await;
        post_event(&router, "test.list_all_b", serde_json::json!({"x": 2})).await;

        // List without filter
        let request = Request::builder()
            .uri("/api/v1/events")
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let list: EventListResponse = serde_json::from_slice(&body).unwrap();

        // total should be >= 2 (may include events from other tests via shared store)
        assert!(
            list.total >= 2,
            "Expected at least 2 events, got {}",
            list.total
        );
    }

    #[tokio::test]
    async fn listing_with_event_type_filter_works() {
        let router = test_router();
        let unique_type = "test.filter_unique_xyz";

        post_event(&router, unique_type, serde_json::json!({"a": 1})).await;
        post_event(&router, "test.filter_other", serde_json::json!({"b": 2})).await;

        let request = Request::builder()
            .uri(format!("/api/v1/events?event_type={unique_type}"))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let list: EventListResponse = serde_json::from_slice(&body).unwrap();

        // All returned events must match the filter
        for event in &list.events {
            assert_eq!(event.event_type, unique_type);
        }
        assert!(
            list.total >= 1,
            "Should find at least 1 event of type {unique_type}"
        );
    }

    #[tokio::test]
    async fn listing_with_limit_works() {
        let router = test_router();

        // Ensure at least 3 events exist
        for i in 0..3 {
            post_event(&router, "test.limit_check", serde_json::json!({"i": i})).await;
        }

        let request = Request::builder()
            .uri("/api/v1/events?limit=2")
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let list: EventListResponse = serde_json::from_slice(&body).unwrap();

        assert!(
            list.events.len() <= 2,
            "Limit=2 but got {} events",
            list.events.len()
        );
    }

    #[tokio::test]
    async fn snapshot_returns_events_up_to_version() {
        let router = test_router();

        // Record events and capture their versions
        let (_, body1) =
            post_event(&router, "test.snapshot_a", serde_json::json!({"v": "a"})).await;
        let event1: GraphEvent = serde_json::from_slice(&body1).unwrap();

        post_event(&router, "test.snapshot_b", serde_json::json!({"v": "b"})).await;

        // Request snapshot at the first event's version
        let request = Request::builder()
            .uri(format!("/api/v1/graph/snapshot/{}", event1.graph_version))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let snapshot: SnapshotResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(snapshot.version, event1.graph_version);
        // All returned events should have version <= requested version
        for event in &snapshot.events {
            assert!(
                event.graph_version <= event1.graph_version,
                "Snapshot at version {} should not contain event at version {}",
                event1.graph_version,
                event.graph_version,
            );
        }
    }

    #[tokio::test]
    async fn empty_event_store_returns_empty_list() {
        // The global store may have events from other tests, but filtering
        // by a type that was never used should return empty.
        let router = test_router();
        let request = Request::builder()
            .uri("/api/v1/events?event_type=nonexistent.type.abc123")
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let list: EventListResponse = serde_json::from_slice(&body).unwrap();

        assert!(list.events.is_empty());
        assert_eq!(list.total, 0);
    }

    #[tokio::test]
    async fn create_event_rejects_empty_event_type() {
        let router = test_router();
        let (status, _) = post_event(&router, "   ", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_event_rejects_oversized_event_type() {
        let router = test_router();
        let long_type = "x".repeat(MAX_EVENT_TYPE_LENGTH + 1);
        let (status, _) = post_event(&router, &long_type, serde_json::json!({})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn snapshot_rejects_future_version() {
        let router = test_router();
        let request = Request::builder()
            .uri("/api/v1/graph/snapshot/999999999")
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn graph_event_serialization_roundtrip() {
        let event = GraphEvent {
            id: Uuid::new_v4(),
            event_type: "claim.created".to_string(),
            actor_id: Some(Uuid::new_v4()),
            payload: serde_json::json!({"claim_id": "abc"}),
            graph_version: 42,
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let roundtripped: GraphEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped.event_type, "claim.created");
        assert_eq!(roundtripped.graph_version, 42);
    }

    #[tokio::test]
    async fn event_store_push_assigns_unique_ids() {
        let store = EventStore::new();
        let e1 = store.push("a".into(), None, serde_json::json!({})).await;
        let e2 = store.push("b".into(), None, serde_json::json!({})).await;
        assert_ne!(e1.id, e2.id, "Each event must have a unique id");
        assert_ne!(
            e1.graph_version, e2.graph_version,
            "Each event must have a unique version"
        );
    }
}

// ── payload_uuids unit tests ────────────────────────────────────────────────
//
// `payload_uuids` is hand-rolled (no `regex` compile) and must agree with the
// `regexp_matches(payload::text, '<uuid>', 'g')` in
// `epigraph_db::EventRepository::list`. It is the half of `list_events`'s
// visibility rule that a database test cannot reach, so it is pinned here.

#[cfg(all(test, feature = "db"))]
mod payload_uuid_tests {
    use super::payload_uuids;
    use uuid::Uuid;

    #[test]
    fn finds_a_uuid_under_any_key() {
        let a = Uuid::new_v4();
        let v = serde_json::json!({ "winner_id": a.to_string() });
        assert_eq!(payload_uuids(&v), vec![a]);
    }

    /// The blocker this rule exists for: the `conflict.resolved` shape names
    /// three claims and none of them under `claim_id`.
    #[test]
    fn finds_every_uuid_in_a_conflict_resolved_payload() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let v = serde_json::json!({
            "claim_a_id": a.to_string(),
            "claim_b_id": b.to_string(),
            "winner_id": a.to_string(),
        });
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(payload_uuids(&v), want, "all three ids, deduplicated");
    }

    /// `publish_event` and `POST /api/v1/events` accept arbitrary payloads, so
    /// a one-level scan would be a fail-open one nesting level down.
    #[test]
    fn descends_into_nested_objects_and_arrays() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let v = serde_json::json!({
            "outer": { "inner": { "id": a.to_string() } },
            "list": [ { "id": b.to_string() } ],
        });
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(payload_uuids(&v), want);
    }

    /// Deliberately blunt: a uuid quoted inside free text counts. That
    /// over-collects, which is the safe direction — an id naming no `claims`
    /// row cannot suppress anything.
    #[test]
    fn finds_a_uuid_embedded_in_free_text() {
        let a = Uuid::new_v4();
        let v = serde_json::json!({ "goal": format!("reconcile {a} with the log") });
        assert_eq!(payload_uuids(&v), vec![a]);
    }

    #[test]
    fn returns_nothing_for_a_payload_with_no_uuid() {
        let v = serde_json::json!({ "note": "no claim here", "n": 7 });
        assert!(payload_uuids(&v).is_empty());
    }

    /// A near-miss must not be reported, or every event would be dropped the
    /// moment one such string appeared beside a private id.
    #[test]
    fn rejects_strings_that_are_not_uuid_shaped() {
        for bad in [
            "not-a-uuid",
            "12345678-1234-1234-1234-12345678901",  // 35 chars
            "12345678_1234_1234_1234_123456789012", // wrong separators
            "gggggggg-1234-1234-1234-123456789012", // non-hex
        ] {
            let v = serde_json::json!({ "x": bad });
            assert!(
                payload_uuids(&v).is_empty(),
                "{bad} must not be read as a uuid"
            );
        }
    }

    /// An over-long hex-and-dash run DOES yield the 36-character prefix, from
    /// both implementations, and that is the correct outcome to pin.
    ///
    /// The SQL side is `regexp_matches(payload::text, '<uuid>', 'g')` with no
    /// anchors, so Postgres returns the same prefix — verified by hand against
    /// the test database:
    ///
    /// ```sql
    /// SELECT m[1] FROM regexp_matches(
    ///   '{"x": "12345678-1234-1234-1234-1234567890123"}',
    ///   '[0-9a-fA-F]{8}-...-[0-9a-fA-F]{12}', 'g') AS m;
    /// -- 12345678-1234-1234-1234-123456789012
    /// ```
    ///
    /// An earlier draft of this test asserted the opposite (that a 37-character
    /// run yields nothing) and failed. Tightening the Rust side to match that
    /// assertion would have been the wrong fix: it would have made the two
    /// halves of one visibility rule disagree, which is the only property here
    /// that can produce a leak. What matters is that neither side ever
    /// fabricates an id that is not literally present in the payload.
    #[test]
    fn an_over_long_hex_run_yields_its_prefix_in_both_implementations() {
        let v = serde_json::json!({
            "x": "12345678-1234-1234-1234-1234567890123"
        });
        let found = payload_uuids(&v);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].to_string(), "12345678-1234-1234-1234-123456789012");
        assert!(
            v.to_string().contains(&found[0].to_string()),
            "never fabricate an id that is not a substring of the payload"
        );
    }
}
