#![cfg(feature = "db")]
//! Regression test for backlog bug `c11c1295`: POST /api/v1/claims with the
//! default `if_not_exists=false` silently inserted duplicate
//! `(content_hash, agent_id)` rows (20+ identical refuted claims accumulated
//! this way) because the UNIQUE constraint create_strict relied on for its
//! documented "409 on duplicate" contract was dropped in migration 107.
//!
//! The fix re-asserts that contract at the app layer. A second identical create
//! must now return 409 Conflict instead of inserting a duplicate.

use sqlx::postgres::PgPoolOptions;
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_create_strict_returns_409() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let agent = common::seed_system_agent(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;

    // Unique content per run so the test is independent of prior DB state.
    let content = format!("c11c1295 dedup regression {}", uuid::Uuid::new_v4());
    let body = serde_json::json!({ "content": content, "agent_id": agent });
    let client = reqwest::Client::new();
    let endpoint = format!("http://{addr}/api/v1/claims");

    // First create (if_not_exists omitted → defaults false) succeeds.
    let r1 = client
        .post(&endpoint)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let s1 = r1.status();
    assert!(
        s1.is_success(),
        "first create should succeed; got {s1} body={}",
        r1.text().await.unwrap_or_default()
    );

    // Second identical create must be refused with 409 — NOT a silent duplicate.
    let r2 = client
        .post(&endpoint)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let s2 = r2.status();
    assert_eq!(
        s2,
        409,
        "duplicate create must return 409 Conflict; got {s2} body={}",
        r2.text().await.unwrap_or_default()
    );

    // And exactly one row exists for this (content, agent) — no duplicate landed.
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1 AND agent_id = $2")
            .bind(&content)
            .bind(agent)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1, "exactly one claim row should exist, found {count}");
}
