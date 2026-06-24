//! Integration tests verifying that entity and triple write endpoints enforce
//! `claims:write` scope.
//!
//! All three POST write handlers were previously missing a `RequireScopeWrite`
//! extractor, allowing any valid JWT — regardless of granted scopes — to create
//! entities and triples. These tests guard against regression.
//!
//! # Why no positive (200) case for batch endpoints
//! `POST /api/v1/entity-mentions/batch` and `POST /api/v1/triples/batch` require
//! seeded FK rows (entity_id, claim_id) in the database. Building that fixture
//! is non-trivial and out of scope here. The scope guard (403-before-body-parse)
//! fires from the extractor, so the 401/403 path is fully exercised without DB
//! write fixtures.

#![cfg(feature = "db")]
mod common;

// ─── POST /api/v1/entities ──────────────────────────────────────────────────

/// No token → 401
#[tokio::test(flavor = "multi_thread")]
async fn create_entity_no_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/entities"))
        .json(&serde_json::json!({
            "canonical_name": "Test Entity",
            "type_top": "organization"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// Token with `claims:read` only (missing `claims:write`) → 403
#[tokio::test(flavor = "multi_thread")]
async fn create_entity_missing_scope_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:read"]);

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/entities"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "canonical_name": "Test Entity",
            "type_top": "organization"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ─── POST /api/v1/entity-mentions/batch ─────────────────────────────────────

/// No token → 401
#[tokio::test(flavor = "multi_thread")]
async fn batch_create_mentions_no_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/entity-mentions/batch"))
        .json(&serde_json::json!({ "mentions": [] }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// Token with `claims:read` only (missing `claims:write`) → 403
#[tokio::test(flavor = "multi_thread")]
async fn batch_create_mentions_missing_scope_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:read"]);

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/entity-mentions/batch"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "mentions": [] }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ─── POST /api/v1/triples/batch ─────────────────────────────────────────────

/// No token → 401
#[tokio::test(flavor = "multi_thread")]
async fn batch_create_triples_no_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/triples/batch"))
        .json(&serde_json::json!({ "triples": [] }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// Token with `claims:read` only (missing `claims:write`) → 403
#[tokio::test(flavor = "multi_thread")]
async fn batch_create_triples_missing_scope_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:read"]);

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/triples/batch"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "triples": [] }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}
