#![cfg(feature = "db")]
mod common;

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
