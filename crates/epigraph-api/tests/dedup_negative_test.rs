#![cfg(feature = "db")]
use sqlx::postgres::PgPoolOptions;
mod common;

/// Calling dedup where the dup_id UUID does not exist → 404.
/// The handler checks dup_id == canonical_id first (400), then calls
/// ClaimRepository::mark_duplicate which returns DbError::NotFound when
/// the dup row is absent → handler maps that to ApiError::NotFound → 404.
#[tokio::test(flavor = "multi_thread")]
async fn dedup_nonexistent_dup_returns_404() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    // We need a real canonical claim so the DB doesn't 404 on the canonical check first.
    let canonical = common::seed_claim(&pool, "canonical for 404 test").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:admin"]).await;

    let nonexistent_dup = uuid::Uuid::new_v4();
    let body = serde_json::json!({
        "canonical_id": canonical,
        "reason": "test 404",
    });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/claims/{nonexistent_dup}/dedup"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        404,
        "expected 404 for non-existent dup_id; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// Calling dedup against a claim that already has supersedes set → 409.
/// ClaimRepository::mark_duplicate returns DbError::QueryFailed when
/// the dup row already has supersedes != NULL → handler maps to ApiError::Conflict → 409.
#[tokio::test(flavor = "multi_thread")]
async fn dedup_already_superseded_dup_returns_409() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let canonical = common::seed_claim(&pool, "canonical for 409 test").await;
    // Seed the dup claim, then set ONLY supersedes (the column the handler
    // actually reads — see ClaimRepository::mark_duplicate). Avoid touching
    // is_current here so this test pins regression to the precise column.
    let dup = common::seed_claim(&pool, "dup already superseded").await;
    sqlx::query("UPDATE claims SET supersedes = $1 WHERE id = $2")
        .bind(canonical)
        .bind(dup)
        .execute(&pool)
        .await
        .expect("set up already-superseded claim");

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:admin"]).await;

    let body = serde_json::json!({
        "canonical_id": canonical,
        "reason": "test 409",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{dup}/dedup"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        409,
        "expected 409 for already-superseded dup; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// Calling dedup where dup_id == canonical_id → 400 (handler rejects before DB call).
#[tokio::test(flavor = "multi_thread")]
async fn dedup_self_dedup_returns_400() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let claim = common::seed_claim(&pool, "self-dedup test claim").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:admin"]).await;

    let body = serde_json::json!({
        "canonical_id": claim,
        "reason": "test self-dedup",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{claim}/dedup"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        400,
        "expected 400 for self-dedup (dup_id == canonical_id); got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}
