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
pub async fn list_events(
    State(_state): State<AppState>,
    Query(filter): Query<EventFilter>,
) -> Result<Json<EventListResponse>, ApiError> {
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
        let (in_mem, _) = global_event_store().list(&in_mem_filter).await;
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
pub async fn graph_snapshot(
    State(_state): State<AppState>,
    Path(version): Path<i64>,
) -> Result<Json<SnapshotResponse>, ApiError> {
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
        let rows = epigraph_db::EventRepository::list(&_state.db_pool, None, None, version + 1)
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
