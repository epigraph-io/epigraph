#![cfg(feature = "db")]
//! Review finding (Task 1 fix round 1): `create_claim_core`'s scope check
//! (`crates/epigraph-api/src/routes/claims.rs`, `if let Some(auth) = auth_ctx
//! { check_scopes(auth, &["claims:write"])? }`) was not exercised by any test
//! in the create-claim guard suite — all 13 named tests mint a token holding
//! `claims:write`. A caller holding only `claims:read` must be refused with
//! 403 before anything is written.
//!
//! The 403 alone would not pin the cause: `ApiError::Forbidden` is also
//! raised elsewhere on this path (e.g. `require_claim_act_authority`'s
//! `ClaimNotWritable`), so this test also asserts the body names
//! `claims:write`, and runs a same-body positive control with a
//! `claims:write` token to prove the content itself was writable and only
//! the scope blocked it.

use sqlx::postgres::PgPoolOptions;
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn claims_read_only_token_is_403_on_create_with_zero_rows_written() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let agent = common::seed_system_agent(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (read_only_token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["claims:read"], agent)
            .await;

    let content = format!("create_claim_core scope guard {}", uuid::Uuid::new_v4());
    let body = serde_json::json!({ "content": content, "agent_id": agent });
    let client = reqwest::Client::new();
    let endpoint = format!("http://{addr}/api/v1/claims");

    let resp = client
        .post(&endpoint)
        .bearer_auth(&read_only_token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    assert_eq!(
        status, 403,
        "a claims:read-only token must be refused with 403 on POST /api/v1/claims; got {status} body={text}"
    );
    assert!(
        text.contains("claims:write"),
        "the 403 must name the missing scope (claims:write), not an unrelated \
         Forbidden raised later on this path: {text}"
    );

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1 AND agent_id = $2")
            .bind(&content)
            .bind(agent)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        count, 0,
        "no row may land when the scope check refuses the request; found {count}"
    );

    // Positive control: the SAME body, with a claims:write token, must
    // succeed and write exactly one row. This proves the content was
    // writable and only the missing scope blocked the first request —
    // otherwise the 403/zero-rows assertions above could pass for an
    // unrelated reason (e.g. a 400 on malformed content).
    let (write_token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["claims:write"], agent)
            .await;
    let resp2 = client
        .post(&endpoint)
        .bearer_auth(&write_token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status2 = resp2.status();
    assert!(
        status2.is_success(),
        "positive control with claims:write must succeed; got {status2} body={}",
        resp2.text().await.unwrap_or_default()
    );
    let count2: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1 AND agent_id = $2")
            .bind(&content)
            .bind(agent)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        count2, 1,
        "the claims:write token must have written exactly one row, found {count2}"
    );
}
