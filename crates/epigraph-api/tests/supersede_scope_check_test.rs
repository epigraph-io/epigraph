#![cfg(feature = "db")]
mod common;
use sqlx::postgres::PgPoolOptions;

/// POST /api/v1/claims/:id/supersede with no Authorization header must return 401.
/// Auth check fires before any DB lookup, so a non-existent UUID is sufficient.
#[tokio::test(flavor = "multi_thread")]
async fn supersede_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let fake_id = uuid::Uuid::new_v4();
    let body = serde_json::json!({
        "content": "new content",
        "truth_value": 0.8,
        "reason": "test reason",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{fake_id}/supersede"))
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

/// POST /api/v1/claims/:id/supersede with a claims:read-only token must return 403.
#[tokio::test(flavor = "multi_thread")]
async fn supersede_with_read_only_token_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:read"]);
    let fake_id = uuid::Uuid::new_v4();
    let body = serde_json::json!({
        "content": "new content",
        "truth_value": 0.8,
        "reason": "test reason",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{fake_id}/supersede"))
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

/// POST /api/v1/claims/:id/supersede with a matching-owner token → 200/201.
#[tokio::test(flavor = "multi_thread")]
async fn supersede_matching_owner_returns_success() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let claim_id = common::seed_claim_with_agent(&pool, "supersede owner match", client_id).await;

    let body = serde_json::json!({
        "content": "superseded content",
        "truth_value": 0.7,
        "reason": "ownership test",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{claim_id}/supersede"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert!(
        status == 200 || status == 201,
        "expected 200/201 for matching owner; got {status} — body={text}"
    );
}

/// POST /api/v1/claims/:id/supersede with a mismatched owner → 403.
#[tokio::test(flavor = "multi_thread")]
async fn supersede_mismatched_owner_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    // Token for principal A
    let (token_a, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    // Claim owned by principal B
    let (_, client_b) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let claim_id = common::seed_claim_with_agent(&pool, "supersede owner mismatch", client_b).await;

    let body = serde_json::json!({
        "content": "unauthorized supersede",
        "truth_value": 0.7,
        "reason": "should fail",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{claim_id}/supersede"))
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

/// POST /api/v1/claims/:id/supersede with a valid claims:write token but
/// a non-existent claim UUID → 404.
#[tokio::test(flavor = "multi_thread")]
async fn supersede_nonexistent_claim_returns_404() {
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
        "content": "new content",
        "truth_value": 0.8,
        "reason": "test reason",
    });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/claims/{nonexistent}/supersede"
        ))
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
