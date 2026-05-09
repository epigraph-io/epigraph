#![cfg(feature = "db")]
use sqlx::postgres::PgPoolOptions;
mod common;

/// PATCH /api/v1/claims/:id with a valid claims:write token (matching owner)
/// returns 200.
#[tokio::test(flavor = "multi_thread")]
async fn patch_claim_happy_path_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;

    // Seed claim whose agent_id == client_id so ownership check passes.
    let claim_id =
        common::seed_claim_with_agent(&pool, "patch happy path content", client_id).await;

    let body = serde_json::json!({
        "add_labels": ["test-label"],
    });

    let resp = reqwest::Client::new()
        .patch(format!("http://{addr}/api/v1/claims/{claim_id}"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(status, 200, "expected 200 OK, got {status} — body={text}");
}

/// PATCH /api/v1/claims/:id with a claims:admin token on someone else's claim
/// returns 200 (admin override).
#[tokio::test(flavor = "multi_thread")]
async fn patch_claim_admin_token_overrides_ownership() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    // Admin token — client_id different from claim's agent_id
    let (admin_token, _) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write", "claims:admin"])
            .await;
    // Claim owned by a different agent
    let claim_id = common::seed_claim(&pool, "admin override target").await;

    let body = serde_json::json!({ "add_labels": ["admin-label"] });

    let resp = reqwest::Client::new()
        .patch(format!("http://{addr}/api/v1/claims/{claim_id}"))
        .bearer_auth(&admin_token)
        .json(&body)
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(
        status, 200,
        "admin should pass ownership check; got {status} — body={text}"
    );
}

/// PATCH /api/v1/claims/:id with a claims:write token for a different principal
/// returns 403.
#[tokio::test(flavor = "multi_thread")]
async fn patch_claim_mismatched_owner_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    // Token for principal A
    let (token_a, _client_a) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    // Claim owned by principal B (different client)
    let (_, client_b) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let claim_id = common::seed_claim_with_agent(&pool, "ownership mismatch claim", client_b).await;

    let body = serde_json::json!({ "add_labels": ["forbidden-label"] });

    let resp = reqwest::Client::new()
        .patch(format!("http://{addr}/api/v1/claims/{claim_id}"))
        .bearer_auth(&token_a)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403 for mismatched owner; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// PATCH /api/v1/claims/:id with no Authorization header must return 401.
/// Auth check fires before any DB lookup, so a random UUID is sufficient.
#[tokio::test(flavor = "multi_thread")]
async fn patch_claim_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let fake_id = uuid::Uuid::new_v4();
    let body = serde_json::json!({
        "add_labels": ["some-label"],
    });

    let resp = reqwest::Client::new()
        .patch(format!("http://{addr}/api/v1/claims/{fake_id}"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 Unauthorized, got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// PATCH /api/v1/claims/:id with a claims:read-only token must return 403.
#[tokio::test(flavor = "multi_thread")]
async fn patch_claim_with_read_only_token_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:read"]);
    let fake_id = uuid::Uuid::new_v4();
    let body = serde_json::json!({
        "add_labels": ["some-label"],
    });

    let resp = reqwest::Client::new()
        .patch(format!("http://{addr}/api/v1/claims/{fake_id}"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403 Forbidden, got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// PATCH /api/v1/claims/:id with a valid token but non-existent UUID returns 404.
/// The handler maps DbError::NotFound → ApiError::NotFound → HTTP 404.
#[tokio::test(flavor = "multi_thread")]
async fn patch_claim_nonexistent_claim_returns_404() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;

    let nonexistent = uuid::Uuid::new_v4();
    let body = serde_json::json!({
        "add_labels": ["some-label"],
    });

    let resp = reqwest::Client::new()
        .patch(format!("http://{addr}/api/v1/claims/{nonexistent}"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        404,
        "expected 404 for non-existent claim; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// PATCH /api/v1/claims/:id with a body that has no patchable fields returns 400.
/// The handler checks `request.is_empty()` → 400 before touching the DB.
#[tokio::test(flavor = "multi_thread")]
async fn patch_claim_invalid_body_returns_400() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;

    // Claim owned by the same client so we reach the is_empty() check.
    let claim_id = common::seed_claim_with_agent(&pool, "patch 400 test content", client_id).await;

    // Empty body: no trace_id, no properties, no add_labels, no remove_labels.
    // The handler's is_empty() check returns true → 400.
    let body = serde_json::json!({});

    let resp = reqwest::Client::new()
        .patch(format!("http://{addr}/api/v1/claims/{claim_id}"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        400,
        "expected 400 for empty patch body; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}
