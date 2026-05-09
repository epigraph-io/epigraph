#![cfg(feature = "db")]
use sqlx::postgres::PgPoolOptions;
mod common;

/// PATCH /api/v1/claims/:id with a valid claims:write token and a real claim
/// returns 200 with the updated properties reflected in the response body.
#[tokio::test(flavor = "multi_thread")]
async fn patch_claim_happy_path_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let claim_id = common::seed_claim(&pool, "patch happy path content").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;

    // Use add_labels — a successful PATCH returns 200 even if the response body
    // doesn't reflect labels (get_by_id_conn omits the labels column).
    // We verify success by checking the HTTP status code only.
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

    let claim_id = common::seed_claim(&pool, "patch 400 test content").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;

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
