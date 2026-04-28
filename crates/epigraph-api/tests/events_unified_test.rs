//! Integration tests for the unified `GET /api/v1/events` endpoint.
//!
//! The handler drains both the persisted `events` table and the in-process
//! `EventStore`, deduplicates by event id, and returns time-ordered results.
//! These tests exercise the merge logic end-to-end via HTTP, against the
//! same test server fixture used by other db-feature integration tests.

#![cfg(feature = "db")]

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

mod common;

/// Test 1 — events pushed to the in-memory `EventStore` are visible via
/// `GET /api/v1/events`. Before this PR, the `feature = "db"` handler read
/// only from the persisted table, so transient events emitted to the
/// in-process bus (Task 0.3 emissions, etc.) were invisible to HTTP pollers.
#[tokio::test(flavor = "multi_thread")]
async fn list_events_returns_in_memory_events_via_http() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let unique_type = format!("test.unified_inmem_{}", Uuid::new_v4().simple());

    // Push directly to the global in-memory store. The handler shares
    // this same OnceLock-backed singleton at runtime.
    let pushed = epigraph_api::routes::events::global_event_store()
        .push(
            unique_type.clone(),
            None,
            serde_json::json!({"source": "in_memory_test"}),
        )
        .await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/events?event_type={unique_type}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let body: Value = resp.json().await.unwrap();
    let events = body["events"].as_array().expect("events array");
    assert_eq!(
        events.len(),
        1,
        "expected exactly one in-memory event of type {unique_type}, got {body}"
    );
    assert_eq!(events[0]["id"], serde_json::json!(pushed.id));
    assert_eq!(events[0]["event_type"], unique_type);
    assert_eq!(events[0]["payload"]["source"], "in_memory_test");
}

/// Test 2 — when the same event id appears in both the persisted table and
/// the in-memory store, the unified endpoint returns it exactly once.
/// Persisted-first ordering means the DB row wins (its `graph_version` is
/// the canonical one), but either way the consumer must not see duplicates.
#[tokio::test(flavor = "multi_thread")]
async fn list_events_dedupes_by_id_when_event_in_both_stores() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let unique_type = format!("test.unified_dedup_{}", Uuid::new_v4().simple());

    // 1. Push to in-memory first so we capture the auto-generated id.
    let pushed = epigraph_api::routes::events::global_event_store()
        .push(
            unique_type.clone(),
            None,
            serde_json::json!({"source": "dedup_test"}),
        )
        .await;

    // 2. Insert a row into the DB events table reusing the same id. We
    //    can't use EventRepository::insert (it generates a fresh uuid), so
    //    drop to raw SQL — this mirrors how a future shared-id write path
    //    might land the same event in both stores.
    sqlx::query(
        "INSERT INTO events (id, event_type, actor_id, payload, graph_version, created_at) \
         VALUES ($1, $2, NULL, $3, nextval('events_graph_version_seq'), NOW())",
    )
    .bind(pushed.id)
    .bind(&unique_type)
    .bind(serde_json::json!({"source": "dedup_test_db_copy"}))
    .execute(&pool)
    .await
    .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/events?event_type={unique_type}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let body: Value = resp.json().await.unwrap();
    let events = body["events"].as_array().expect("events array");
    let matching: Vec<&Value> = events
        .iter()
        .filter(|e| e["id"] == serde_json::json!(pushed.id))
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "expected exactly one event with id {} after dedup, found {}: {body}",
        pushed.id,
        matching.len()
    );
    // Persisted row appears first in the merge order, so dedup keeps the
    // DB copy. Verify by checking the payload reflects the DB-side write.
    assert_eq!(matching[0]["payload"]["source"], "dedup_test_db_copy");
}

/// Test 3 — when the in-memory store has no events of a given type but
/// the DB does, the endpoint returns the persisted rows. This is the
/// pre-existing behavior; the test guards against regressions in the
/// merge path that might silently drop persisted-only events.
#[tokio::test(flavor = "multi_thread")]
async fn list_events_returns_persisted_only_when_in_memory_empty() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let unique_type = format!("test.unified_db_only_{}", Uuid::new_v4().simple());
    let event_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO events (id, event_type, actor_id, payload, graph_version, created_at) \
         VALUES ($1, $2, NULL, $3, nextval('events_graph_version_seq'), NOW())",
    )
    .bind(event_id)
    .bind(&unique_type)
    .bind(serde_json::json!({"source": "db_only_test"}))
    .execute(&pool)
    .await
    .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/events?event_type={unique_type}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let body: Value = resp.json().await.unwrap();
    let events = body["events"].as_array().expect("events array");
    assert_eq!(
        events.len(),
        1,
        "expected exactly one persisted event of type {unique_type}, got {body}"
    );
    assert_eq!(events[0]["id"], serde_json::json!(event_id));
    assert_eq!(events[0]["payload"]["source"], "db_only_test");
}
