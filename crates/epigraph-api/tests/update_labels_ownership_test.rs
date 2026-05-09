#![cfg(feature = "db")]
mod common;
use sqlx::postgres::PgPoolOptions;

/// PATCH /api/v1/claims/:id/labels with a matching-owner token returns 200.
#[tokio::test(flavor = "multi_thread")]
async fn update_labels_matching_owner_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let claim_id =
        common::seed_claim_with_agent(&pool, "update labels owner match", client_id).await;

    let body = serde_json::json!({ "add": ["owner-label"] });
    let resp = reqwest::Client::new()
        .patch(format!("http://{addr}/api/v1/claims/{claim_id}/labels"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(
        status, 200,
        "expected 200 for matching owner; got {status} — body={text}"
    );
}

/// PATCH /api/v1/claims/:id/labels with a claims:admin token on someone else's claim returns 200.
#[tokio::test(flavor = "multi_thread")]
async fn update_labels_admin_token_overrides_ownership() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (admin_token, _) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write", "claims:admin"])
            .await;
    // Claim owned by a completely different agent
    let claim_id = common::seed_claim(&pool, "update labels admin override").await;

    let body = serde_json::json!({ "add": ["admin-label"] });
    let resp = reqwest::Client::new()
        .patch(format!("http://{addr}/api/v1/claims/{claim_id}/labels"))
        .bearer_auth(&admin_token)
        .json(&body)
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(
        status, 200,
        "admin should bypass ownership check; got {status} — body={text}"
    );
}

/// PATCH /api/v1/claims/:id/labels with a mismatched-owner token returns 403.
#[tokio::test(flavor = "multi_thread")]
async fn update_labels_mismatched_owner_returns_403() {
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
    let claim_id =
        common::seed_claim_with_agent(&pool, "update labels owner mismatch", client_b).await;

    let body = serde_json::json!({ "add": ["forbidden-label"] });
    let resp = reqwest::Client::new()
        .patch(format!("http://{addr}/api/v1/claims/{claim_id}/labels"))
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

/// PATCH /api/v1/claims/:id/labels with no token returns 401.
#[tokio::test(flavor = "multi_thread")]
async fn update_labels_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let fake_id = uuid::Uuid::new_v4();
    let body = serde_json::json!({ "add": ["some-label"] });
    let resp = reqwest::Client::new()
        .patch(format!("http://{addr}/api/v1/claims/{fake_id}/labels"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 without token; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}
