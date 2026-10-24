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

/// Characterization of the create path's properties write: `properties` alone
/// (no `content_hash`) is stored, and the stored digest is the server's
/// BLAKE3(content). Pins the behaviour across the removal of the dead
/// `content_hash = COALESCE($1, content_hash)` override.
#[tokio::test(flavor = "multi_thread")]
async fn properties_only_create_stores_properties() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let agent = common::seed_system_agent(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;

    let content = format!("properties only create {}", uuid::Uuid::new_v4());
    let body = serde_json::json!({
        "content": content,
        "agent_id": agent,
        "properties": {"k": "v", "n": 3},
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert!(
        status.is_success(),
        "properties-only create should succeed; got {status} body={}",
        resp.text().await.unwrap_or_default()
    );

    let (props, stored_hash): (serde_json::Value, Vec<u8>) =
        sqlx::query_as("SELECT properties, content_hash FROM claims WHERE content = $1")
            .bind(&content)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(props["k"], "v", "stored properties: {props}");
    assert_eq!(props["n"], 3, "stored properties: {props}");
    assert_eq!(
        stored_hash,
        blake3::hash(content.as_bytes()).as_bytes().to_vec(),
        "stored content_hash must equal BLAKE3(content)"
    );
}

/// A matching `content_hash` together with `properties`: both requests are
/// honoured — the properties are stored and the digest is BLAKE3(content).
#[tokio::test(flavor = "multi_thread")]
async fn matching_override_with_properties_stores_both() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let agent = common::seed_system_agent(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;

    let content = format!("override plus properties {}", uuid::Uuid::new_v4());
    let correct_hash = blake3::hash(content.as_bytes()).to_hex().to_string();
    let body = serde_json::json!({
        "content": content,
        "agent_id": agent,
        "content_hash": correct_hash,
        "properties": {"section": "methods"},
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert!(
        status.is_success(),
        "matching override + properties should succeed; got {status} body={}",
        resp.text().await.unwrap_or_default()
    );

    let (props, stored_hash): (serde_json::Value, Vec<u8>) =
        sqlx::query_as("SELECT properties, content_hash FROM claims WHERE content = $1")
            .bind(&content)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(props["section"], "methods", "stored properties: {props}");
    assert_eq!(
        stored_hash,
        blake3::hash(content.as_bytes()).as_bytes().to_vec(),
        "stored content_hash must equal BLAKE3(content)"
    );
}

/// Characterization of the `if_not_exists` dedup hit (`was_created = false`),
/// pinned across the rewrite of the create path's guard: a second POST of the
/// same content by the same agent returns the EXISTING claim and must not
/// overwrite its properties (another caller's metadata), and the stored digest
/// stays BLAKE3(content). A dedup request that also carries a `content_hash`
/// is refused up front (400 on `if_not_exists`), before any persist step, and
/// changes nothing either.
#[tokio::test(flavor = "multi_thread")]
async fn dedup_hit_keeps_the_existing_claims_properties_and_digest() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let agent = common::seed_system_agent(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let client = reqwest::Client::new();
    let post = |body: serde_json::Value| {
        client
            .post(format!("http://{addr}/api/v1/claims"))
            .bearer_auth(&token)
            .json(&body)
            .send()
    };

    let content = format!("dedup hit characterization {}", uuid::Uuid::new_v4());
    let first = post(serde_json::json!({
        "content": content,
        "agent_id": agent,
        "if_not_exists": true,
        "properties": {"a": 1},
    }))
    .await
    .unwrap();
    let status = first.status();
    let first: serde_json::Value = first.json().await.unwrap_or_default();
    assert!(status.is_success(), "first create: {status} {first}");
    let first_id = first["id"].as_str().expect("created claim id").to_string();

    let second = post(serde_json::json!({
        "content": content,
        "agent_id": agent,
        "if_not_exists": true,
        "properties": {"a": 2},
    }))
    .await
    .unwrap();
    let status = second.status();
    let second: serde_json::Value = second.json().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "dedup hit must succeed: {status} {second}"
    );
    assert_eq!(
        second["id"].as_str(),
        Some(first_id.as_str()),
        "a dedup hit returns the existing claim"
    );

    let mismatched = post(serde_json::json!({
        "content": content,
        "agent_id": agent,
        "if_not_exists": true,
        "content_hash": "00".repeat(32),
        "properties": {"a": 3},
    }))
    .await
    .unwrap();
    let status = mismatched.status();
    let mismatched: serde_json::Value = mismatched.json().await.unwrap_or_default();
    assert_eq!(status, 400, "if_not_exists + content_hash: {mismatched}");
    assert_eq!(
        mismatched["details"]["field"], "if_not_exists",
        "{mismatched}"
    );

    let rows: Vec<(uuid::Uuid, serde_json::Value, Vec<u8>)> =
        sqlx::query_as("SELECT id, properties, content_hash FROM claims WHERE content = $1")
            .bind(&content)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(rows.len(), 1, "one claim for the content, not a duplicate");
    let (id, props, stored_hash) = &rows[0];
    assert_eq!(id.to_string(), first_id);
    assert_eq!(
        props["a"], 1,
        "a dedup hit must not overwrite the existing claim's properties: {props}"
    );
    assert_eq!(
        stored_hash,
        &blake3::hash(content.as_bytes()).as_bytes().to_vec(),
        "stored content_hash stays BLAKE3(content)"
    );
}
