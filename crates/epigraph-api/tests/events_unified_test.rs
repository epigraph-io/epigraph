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
    // PR-03: this route moved to the protected router. The token must carry a
    // non-null `agent_id`; `mint_token_with_agent` is the only tests/common
    // helper that sets one.
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/events?event_type={unique_type}"
        ))
        .bearer_auth(&token)
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
    // PR-03: this route moved to the protected router. The token must carry a
    // non-null `agent_id`; `mint_token_with_agent` is the only tests/common
    // helper that sets one.
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/events?event_type={unique_type}"
        ))
        .bearer_auth(&token)
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
    // PR-03: this route moved to the protected router. The token must carry a
    // non-null `agent_id`; `mint_token_with_agent` is the only tests/common
    // helper that sets one.
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/events?event_type={unique_type}"
        ))
        .bearer_auth(&token)
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

// ── `since` cursor: backlog truncation and keyset liveness (drain U045) ──────

/// A whole-second instant one day in the past, so a `since` cursor built from
/// it round-trips exactly through Postgres' microsecond `timestamptz` and the
/// rows these tests insert never crowd the newest-N window of another test
/// that lists `/events` without a `since`.
fn past_base() -> chrono::DateTime<chrono::Utc> {
    let t = chrono::Utc::now() - chrono::Duration::days(1);
    chrono::DateTime::from_timestamp(t.timestamp(), 0).expect("whole-second instant")
}

/// Insert `n` persisted events of `event_type`, the i-th stamped
/// `base + i * step_ms` milliseconds. Payload `{}` carries no uuid, so the
/// visibility filter has nothing to classify and every row is readable.
async fn insert_events(
    pool: &sqlx::PgPool,
    event_type: &str,
    base: chrono::DateTime<chrono::Utc>,
    n: i32,
    step_ms: i32,
) {
    sqlx::query(
        "INSERT INTO events (id, event_type, actor_id, payload, graph_version, created_at) \
         SELECT gen_random_uuid(), $1, NULL, '{}', nextval('events_graph_version_seq'), \
                $2 + (i * $4) * interval '1 millisecond' \
         FROM generate_series(0, $3 - 1) AS i",
    )
    .bind(event_type)
    .bind(base)
    .bind(n)
    .bind(step_ms)
    .execute(pool)
    .await
    .unwrap();
}

fn cursor_param(t: chrono::DateTime<chrono::Utc>) -> String {
    // RFC 3339 with a literal `Z`: a `+00:00` offset in a query string decodes
    // its `+` to a space and the timestamp no longer parses.
    t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn created_at(e: &Value) -> chrono::DateTime<chrono::Utc> {
    e["created_at"]
        .as_str()
        .expect("created_at string")
        .parse()
        .expect("created_at parses as RFC 3339")
}

/// With more than `2 * limit` matching events at or after the cursor, a
/// `since` page must still start at the OLDEST of them.
///
/// Before the fix the persisted half fetched the NEWEST `(limit+offset)*2`
/// rows and only then dropped those older than `since`, so with 250 events
/// after the cursor the page began at #51 and a poller advancing to the last
/// returned `created_at` skipped #1–#50 for good.
///
/// 250 more rows sit just BEFORE the cursor, more than the route's
/// `2 * limit` overfetch, so the cursor must be applied in SQL: a query that
/// ordered oldest-first but did not filter by `since` would fetch only
/// pre-cursor rows, and the route's defensive Rust filter would empty the page.
///
/// The first assertion also pins the route's `since` as INCLUSIVE (the cursor
/// equals the first row's `created_at` and that row is returned): the
/// epiclaw-host synthesis watcher's test mock models exactly that contract.
#[tokio::test(flavor = "multi_thread")]
async fn since_page_starts_at_the_oldest_event_after_the_cursor_even_with_a_backlog() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let unique_type = format!("test.since_backlog_{}", Uuid::new_v4().simple());
    let base = past_base();
    insert_events(
        &pool,
        &unique_type,
        base - chrono::Duration::milliseconds(250),
        250,
        1,
    )
    .await;
    insert_events(&pool, &unique_type, base, 250, 1).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/events"))
        .query(&[
            ("event_type", unique_type.as_str()),
            ("since", cursor_param(base).as_str()),
            ("limit", "100"),
        ])
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let body: Value = resp.json().await.unwrap();
    let events = body["events"].as_array().expect("events array");
    assert_eq!(events.len(), 100, "a full page of 100 expected");
    assert_eq!(
        created_at(&events[0]),
        base,
        "the page must start at the oldest event at or after `since` (inclusive \
         cursor); got first created_at {} — offset {} ms from the cursor",
        created_at(&events[0]),
        (created_at(&events[0]) - base).num_milliseconds()
    );
    assert_eq!(
        created_at(&events[99]),
        base + chrono::Duration::milliseconds(99),
        "the page must be the 100 oldest events after the cursor, in order"
    );
}

/// One transaction stamps every event it publishes with ONE `created_at`
/// (`NOW()` is the transaction start), so a block of same-timestamp events can
/// be larger than a page. Following the documented cursor
/// `(since = last.created_at, after_id = last.id)` must deliver every event of
/// such a block exactly once.
///
/// With a `since`-only cursor every page is drawn from the same block (the
/// cursor cannot move inside it) and is always full, so pigeonhole guarantees
/// a re-served row by the third call (3 * 100 > 250). Bounded at 5 calls so a
/// stalling cursor fails instead of hanging. The block is larger than the
/// route's `2 * limit` overfetch, so `after_id` must be applied in SQL: a
/// query that ignored it would fetch the same lowest 200 ids every time, and
/// the route's defensive Rust filter would stall the cursor at 200 delivered.
#[tokio::test(flavor = "multi_thread")]
async fn a_same_timestamp_block_larger_than_the_page_is_fully_delivered() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let unique_type = format!("test.since_block_{}", Uuid::new_v4().simple());
    let base = past_base();
    insert_events(&pool, &unique_type, base, 250, 0).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let client = reqwest::Client::new();

    let mut delivered: Vec<Uuid> = Vec::new();
    let mut cursor: (chrono::DateTime<chrono::Utc>, Option<Uuid>) = (base, None);
    let mut calls = 0;
    loop {
        calls += 1;
        let mut params = vec![
            ("event_type", unique_type.clone()),
            ("since", cursor_param(cursor.0)),
            ("limit", "100".to_string()),
        ];
        if let Some(after) = cursor.1 {
            params.push(("after_id", after.to_string()));
        }
        let resp = client
            .get(format!("http://{addr}/api/v1/events"))
            .query(&params)
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let body: Value = resp.json().await.unwrap();
        let page = body["events"].as_array().expect("events array").clone();

        for e in &page {
            let id: Uuid = serde_json::from_value(e["id"].clone()).expect("event id");
            assert!(
                !delivered.contains(&id),
                "event {id} was delivered twice (call {calls}): the cursor \
                 (since={}, after_id={:?}) re-served a row it had already passed",
                cursor_param(cursor.0),
                cursor.1
            );
            delivered.push(id);
        }

        if page.len() < 100 || calls >= 5 {
            break;
        }
        let last = page.last().expect("non-empty full page");
        cursor = (
            created_at(last),
            Some(serde_json::from_value(last["id"].clone()).expect("event id")),
        );
    }

    assert_eq!(
        delivered.len(),
        250,
        "every event of the 250-row same-timestamp block must be delivered"
    );
    assert!(
        calls <= 3,
        "took {calls} calls to drain a 250-row block at limit 100"
    );
}

/// `after_id` is a tiebreaker WITHIN a `since` cursor. Alone it names no
/// position, and silently ignoring it would hand a misconfigured poller the
/// "recent events" view — the newest rows, not the next ones — which is the
/// very skip this cursor exists to prevent. It is rejected instead, while the
/// same request WITH `since` is accepted (so the 400 is about the pairing,
/// not about the parameter).
#[tokio::test(flavor = "multi_thread")]
async fn after_id_without_since_is_rejected() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let client = reqwest::Client::new();
    let after = Uuid::new_v4().to_string();

    let alone = client
        .get(format!("http://{addr}/api/v1/events"))
        .query(&[("after_id", after.as_str())])
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(alone.status().as_u16(), 400, "after_id without since");
    let body: Value = alone.json().await.unwrap();
    assert_eq!(
        body["details"]["field"], "after_id",
        "the 400 must name the offending parameter; body was {body}"
    );

    let paired = client
        .get(format!("http://{addr}/api/v1/events"))
        .query(&[
            ("after_id", after.as_str()),
            ("since", cursor_param(past_base()).as_str()),
        ])
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(paired.status().as_u16(), 200, "after_id with since");
}

/// The `(since, after_id)` cursor must also hold for events that live ONLY in
/// the in-process `EventStore` — `edge.added`, belief and community events are
/// pushed to `global_event_store()` and never persisted. The SQL tests above
/// cannot see that half: the database filters their rows before the route's
/// in-process predicate and merge sort ever run.
///
/// The cursor is the first returned event's `created_at` STRING exactly as the
/// route serialised it, plus its id. In-memory timestamps carry nanoseconds,
/// so rebuilding the cursor at microsecond precision would let the cursor
/// event back in even with a correct predicate. Which of the three pushes
/// sorts first is not assumed (two `Utc::now()` stamps can tie, and then the
/// random ids decide): the expectation is "everything after page[0]".
#[tokio::test(flavor = "multi_thread")]
async fn after_id_cursor_skips_the_cursor_event_in_the_in_memory_store() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let unique_type = format!("test.inmem_cursor_{}", Uuid::new_v4().simple());
    for i in 0..3 {
        epigraph_api::routes::events::global_event_store()
            .push(unique_type.clone(), None, serde_json::json!({"i": i}))
            .await;
    }

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let client = reqwest::Client::new();
    let get = |params: Vec<(&'static str, String)>| {
        let req = client
            .get(format!("http://{addr}/api/v1/events"))
            .query(&params)
            .bearer_auth(&token);
        async move {
            let resp = req.send().await.unwrap();
            assert_eq!(resp.status().as_u16(), 200);
            let body: Value = resp.json().await.unwrap();
            body["events"].as_array().expect("events array").clone()
        }
    };

    let all = get(vec![("event_type", unique_type.clone())]).await;
    assert_eq!(all.len(), 3, "the three in-memory events, got {all:?}");
    let first = &all[0];
    let since = first["created_at"]
        .as_str()
        .expect("created_at string")
        .to_string();
    let after_id = first["id"].as_str().expect("id string").to_string();

    let page = get(vec![
        ("event_type", unique_type.clone()),
        ("since", since.clone()),
        ("after_id", after_id.clone()),
    ])
    .await;
    let ids = |events: &[Value]| -> Vec<String> {
        events
            .iter()
            .map(|e| e["id"].as_str().expect("id string").to_string())
            .collect()
    };
    assert_eq!(
        ids(&page),
        ids(&all[1..]),
        "with cursor (since={since}, after_id={after_id}) the page must be \
         exactly the events after the cursor event, which must not be re-served"
    );
}
