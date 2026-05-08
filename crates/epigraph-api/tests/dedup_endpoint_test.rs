#![cfg(feature = "db")]
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn dedup_marks_duplicate_without_creating_new_claim() {
    let url = std::env::var("DATABASE_URL").unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let canonical = common::seed_claim(&pool, "canonical content").await;
    let dup = common::seed_claim(&pool, "duplicate content").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let body = serde_json::json!({
        "canonical_id": canonical,
        "reason": "auto-detected duplicate by content_hash",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{dup}/dedup"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(status, 200, "body={text}");

    let (sup, is_current): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(sup, Some(canonical));
    assert!(!is_current);

    // Canonical untouched.
    let (canon_current,): (bool,) =
        sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
            .bind(canonical)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(canon_current);
}
