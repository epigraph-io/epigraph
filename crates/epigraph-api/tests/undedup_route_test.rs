#![cfg(feature = "db")]
//! `POST /api/v1/claims/{id}/undedup`: the HTTP reverse of `/dedup`.
//!
//! With the administrative connection a dedup followed by an undedup puts the
//! duplicate back (current, its edge re-pointed back onto it) and answers with
//! counts only; without it the undedup is refused with 409 before anything is
//! written. Shares the `DATABASE_URL` database with the other integration
//! tests, so every assertion is scoped to the ids this test created.

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn edge(pool: &sqlx::PgPool, source: Uuid, target: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("edge")
}

async fn dup_state(pool: &sqlx::PgPool, dup: Uuid) -> (Option<Uuid>, bool) {
    sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
        .bind(dup)
        .fetch_one(pool)
        .await
        .expect("dup")
}

async fn post(
    addr: &std::net::SocketAddr,
    path: String,
    token: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("body");
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::json!({ "raw": text })),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn dedup_then_undedup_restores_the_duplicate() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app_with_admin_cascade(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write", "claims:admin"])
            .await;
    let tag = Uuid::new_v4();
    let canonical = common::seed_claim(&pool, &format!("undedup canonical {tag}")).await;
    let dup =
        common::seed_claim_with_agent(&pool, &format!("undedup duplicate {tag}"), client_id).await;
    let supporter = common::seed_claim(&pool, &format!("undedup supporter {tag}")).await;
    let e = edge(&pool, supporter, dup).await;

    let (status, b) = post(
        &addr,
        format!("/api/v1/claims/{dup}/dedup"),
        &token,
        serde_json::json!({"canonical_id": canonical, "reason": "undedup fixture"}),
    )
    .await;
    assert_eq!(status, 200, "{b}");
    assert_eq!(dup_state(&pool, dup).await, (Some(canonical), false));

    let (status, b) = post(
        &addr,
        format!("/api/v1/claims/{dup}/undedup"),
        &token,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "{b}");
    assert_eq!(b["mode"], "unmark_duplicate", "{b}");
    assert_eq!(b["canonical_id"], serde_json::json!(canonical), "{b}");
    assert_eq!(b["cascade"]["status"], "applied", "{b}");
    assert_eq!(b["cascade"]["touched"]["edges_retargeted_back"], 1, "{b}");
    assert!(!b.to_string().contains(&e.to_string()), "counts only: {b}");
    assert_eq!(dup_state(&pool, dup).await, (None, true));
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(target, dup, "the edge is back on the duplicate");
}

#[tokio::test(flavor = "multi_thread")]
async fn undedup_without_an_admin_connection_is_refused_and_writes_nothing() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write", "claims:admin"])
            .await;
    let tag = Uuid::new_v4();
    let canonical = common::seed_claim(&pool, &format!("undedup canonical {tag}")).await;
    let dup =
        common::seed_claim_with_agent(&pool, &format!("undedup duplicate {tag}"), client_id).await;
    let (status, b) = post(
        &addr,
        format!("/api/v1/claims/{dup}/dedup"),
        &token,
        serde_json::json!({"canonical_id": canonical}),
    )
    .await;
    assert_eq!(status, 200, "{b}");
    assert_eq!(b["cascade"]["status"], "deferred", "{b}");

    let (status, b) = post(
        &addr,
        format!("/api/v1/claims/{dup}/undedup"),
        &token,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 409, "{b}");
    assert!(b.to_string().contains("administrative"), "{b}");
    assert_eq!(
        dup_state(&pool, dup).await,
        (Some(canonical), false),
        "nothing changed"
    );
}
