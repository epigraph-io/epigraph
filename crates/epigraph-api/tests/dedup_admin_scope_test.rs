#![cfg(feature = "db")]
mod common;

/// claims:write-only token must NOT pass the claims:admin gate on dedup.
#[tokio::test(flavor = "multi_thread")]
async fn dedup_with_claims_write_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let dup = uuid::Uuid::new_v4();
    let canonical = uuid::Uuid::new_v4();
    let body = serde_json::json!({ "canonical_id": canonical, "reason": "test" });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{dup}/dedup"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403 (claims:write should not satisfy claims:admin); got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// No token at all must return 401.
#[tokio::test(flavor = "multi_thread")]
async fn dedup_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let dup = uuid::Uuid::new_v4();
    let canonical = uuid::Uuid::new_v4();
    let body = serde_json::json!({ "canonical_id": canonical, "reason": "test" });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{dup}/dedup"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 Unauthorized; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}
