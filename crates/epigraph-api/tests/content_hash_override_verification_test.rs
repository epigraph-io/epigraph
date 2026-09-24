#![cfg(feature = "db")]
//! Regression test: `POST /api/v1/claims` accepted a caller-supplied
//! `content_hash` hex override without verifying it against BLAKE3(content),
//! letting a claims:write caller create a claim whose stored content_hash
//! disagrees with its actual content.
//!
//! The fix verifies the override equals BLAKE3(content) for non-compound
//! claims (the normal single-claim create path in this handler) and rejects
//! a mismatch with 400 ValidationError instead of applying it.

use sqlx::postgres::PgPoolOptions;
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn mismatched_content_hash_override_is_rejected() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let agent = common::seed_system_agent(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;

    let content = format!("content_hash override regression {}", uuid::Uuid::new_v4());
    // Deliberately wrong hash: BLAKE3 of a *different* string, not `content`.
    let wrong_hash = blake3::hash(b"not the actual content").to_hex().to_string();

    let body = serde_json::json!({
        "content": content,
        "agent_id": agent,
        "content_hash": wrong_hash,
    });
    let client = reqwest::Client::new();
    let endpoint = format!("http://{addr}/api/v1/claims");

    let resp = client
        .post(&endpoint)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let resp_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        status, 400,
        "mismatched content_hash override must be rejected with 400; got {status} body={resp_body}"
    );
    assert_eq!(
        resp_body["error"], "ValidationError",
        "expected ValidationError, got {resp_body}"
    );
    assert_eq!(
        resp_body["details"]["field"], "content_hash",
        "expected field=content_hash, got {resp_body}"
    );

    // The claim must not have been persisted with the wrong hash — nor
    // silently persisted with the correct one either, since the whole
    // request should be rejected up front.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(&content)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "no claim row should have been created when content_hash override is wrong"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn matching_content_hash_override_is_accepted() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let agent = common::seed_system_agent(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;

    let content = format!("content_hash override correct {}", uuid::Uuid::new_v4());
    let correct_hash = blake3::hash(content.as_bytes()).to_hex().to_string();

    let body = serde_json::json!({
        "content": content,
        "agent_id": agent,
        "content_hash": correct_hash,
    });
    let client = reqwest::Client::new();
    let endpoint = format!("http://{addr}/api/v1/claims");

    let resp = client
        .post(&endpoint)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert!(
        status.is_success(),
        "matching content_hash override should be accepted; got {status} body={}",
        resp.text().await.unwrap_or_default()
    );

    let stored_hash: Vec<u8> =
        sqlx::query_scalar("SELECT content_hash FROM claims WHERE content = $1")
            .bind(&content)
            .fetch_one(&pool)
            .await
            .unwrap();
    let expected_hash = blake3::hash(content.as_bytes()).as_bytes().to_vec();
    assert_eq!(
        stored_hash, expected_hash,
        "stored content_hash must equal BLAKE3(content)"
    );
}
