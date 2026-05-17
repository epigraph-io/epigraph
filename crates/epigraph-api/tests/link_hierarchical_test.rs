//! HTTP integration tests for `POST /api/v1/edges/hierarchical`.
//!
//! Mirrors the MCP smoke test (crates/epigraph-mcp/tests/link_hierarchical_smoke.rs)
//! through the auth+route stack: validation, 404 disambiguation, idempotency,
//! and the tight relationship allow-list.

#![cfg(feature = "db")]

use sqlx::postgres::PgPoolOptions;
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn link_hierarchical_happy_path_is_idempotent() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["edges:write"]).await;

    let source_id = common::seed_claim(&pool, "link_hierarchical happy source").await;
    let target_id = common::seed_claim(&pool, "link_hierarchical happy target").await;

    let body = serde_json::json!({
        "source_claim_id": source_id,
        "target_claim_id": target_id,
        "relationship": "decomposes_to",
        "properties": { "chapter": 1 },
    });

    let client = reqwest::Client::new();

    // First call — fresh insert.
    let resp = client
        .post(format!("http://{addr}/api/v1/edges/hierarchical"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "first call should 200 OK");
    let first: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(first["created"], serde_json::json!(true));
    let edge_id = first["edge_id"].as_str().unwrap().to_string();

    // Second call — dedup hit, same edge_id, created=false, still 200.
    let resp2 = client
        .post(format!("http://{addr}/api/v1/edges/hierarchical"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        200,
        "idempotent re-run should also 200 OK (not 201)"
    );
    let second: serde_json::Value = resp2.json().await.unwrap();
    assert_eq!(second["created"], serde_json::json!(false));
    assert_eq!(second["edge_id"].as_str().unwrap(), edge_id);

    // DB has exactly one edge row.
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges \
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'decomposes_to'",
    )
    .bind(source_id)
    .bind(target_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 1, "must have exactly one edge after re-run");
}

#[tokio::test(flavor = "multi_thread")]
async fn link_hierarchical_rejects_non_structural_relationship() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["edges:write"]).await;

    let source_id = common::seed_claim(&pool, "link_hierarchical bad-rel source").await;
    let target_id = common::seed_claim(&pool, "link_hierarchical bad-rel target").await;

    // `supports` is valid for the generic POST /api/v1/edges but must be
    // rejected by this tight endpoint.
    let body = serde_json::json!({
        "source_claim_id": source_id,
        "target_claim_id": target_id,
        "relationship": "supports",
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/edges/hierarchical"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(
        status, 400,
        "non-structural relationship must 400; got {status} — body={text}"
    );
    assert!(
        text.contains("decomposes_to"),
        "error body should list valid types; got: {text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn link_hierarchical_missing_source_returns_404() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["edges:write"]).await;

    let target_id = common::seed_claim(&pool, "link_hierarchical 404-source target").await;
    let bogus = uuid::Uuid::new_v4();

    let body = serde_json::json!({
        "source_claim_id": bogus,
        "target_claim_id": target_id,
        "relationship": "section_follows",
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/edges/hierarchical"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(
        status, 404,
        "missing source must 404; got {status} — body={text}"
    );
    assert!(
        text.contains("source_claim"),
        "error body should disambiguate which side is missing; got: {text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn link_hierarchical_missing_target_returns_404() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["edges:write"]).await;

    let source_id = common::seed_claim(&pool, "link_hierarchical 404-target source").await;
    let bogus = uuid::Uuid::new_v4();

    let body = serde_json::json!({
        "source_claim_id": source_id,
        "target_claim_id": bogus,
        "relationship": "continues_argument",
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/edges/hierarchical"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(
        status, 404,
        "missing target must 404; got {status} — body={text}"
    );
    assert!(
        text.contains("target_claim"),
        "error body should disambiguate which side is missing; got: {text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn link_hierarchical_rejects_self_loop() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["edges:write"]).await;

    let claim_id = common::seed_claim(&pool, "link_hierarchical self-loop").await;

    let body = serde_json::json!({
        "source_claim_id": claim_id,
        "target_claim_id": claim_id,
        "relationship": "decomposes_to",
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/edges/hierarchical"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(
        status, 400,
        "self-loops must 400 before hitting the DB CHECK; got {status} — body={text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn link_hierarchical_requires_edges_write_scope() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    // Token has graph:read only — must be rejected by the scope guard.
    let token = common::test_bearer_token_with_scopes(&["graph:read"]);

    let source_id = common::seed_claim(&pool, "link_hierarchical scope source").await;
    let target_id = common::seed_claim(&pool, "link_hierarchical scope target").await;

    let body = serde_json::json!({
        "source_claim_id": source_id,
        "target_claim_id": target_id,
        "relationship": "decomposes_to",
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/edges/hierarchical"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(
        status, 403,
        "missing edges:write scope must 403; got {status} — body={text}"
    );
}
