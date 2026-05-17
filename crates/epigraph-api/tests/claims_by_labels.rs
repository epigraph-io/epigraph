//! HTTP integration test for `GET /api/v1/claims/by-labels` (Task 5 of the
//! backlog-retirement plan). Mirrors the MCP integration test in
//! `crates/epigraph-mcp/tests/query_claims_by_label.rs`: seeds three backlog
//! claims (open / resolved / superseded) and exercises the filter
//! cross-product through the public HTTP route.
#![cfg(feature = "db")]

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn by_labels_returns_filtered_claims() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let agent = seed_agent(&pool).await;
    let backlog_open = seed_claim(&pool, agent, &["backlog"], true, None).await;
    let _backlog_resolved = seed_claim(&pool, agent, &["backlog", "resolved"], true, None).await;
    let _backlog_superseded =
        seed_claim(&pool, agent, &["backlog"], false, Some(backlog_open)).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::new();

    // No filters: all 3 claims, with labels/is_current/supersedes populated.
    let resp = client
        .get(format!(
            "http://{addr}/api/v1/claims/by-labels?labels=backlog"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    let arr = body.as_array().expect("response is JSON array");
    let ours: Vec<&Value> = arr
        .iter()
        .filter(|c| {
            let id = c["id"].as_str().unwrap();
            id == backlog_open.to_string()
                || id == _backlog_resolved.to_string()
                || id == _backlog_superseded.to_string()
        })
        .collect();
    assert_eq!(
        ours.len(),
        3,
        "expected our 3 seeded backlog claims (filtered): got body={body}"
    );

    let open = ours
        .iter()
        .find(|c| c["id"].as_str().unwrap() == backlog_open.to_string())
        .unwrap();
    assert_eq!(open["labels"], serde_json::json!(["backlog"]));
    assert_eq!(open["is_current"], Value::Bool(true));
    assert!(
        open.get("supersedes").map(|v| v.is_null()).unwrap_or(true),
        "open claim should not supersede anything: {open:?}"
    );

    let superseded = ours
        .iter()
        .find(|c| c["id"].as_str().unwrap() == _backlog_superseded.to_string())
        .unwrap();
    assert_eq!(superseded["is_current"], Value::Bool(false));
    assert_eq!(
        superseded["supersedes"].as_str().unwrap(),
        backlog_open.to_string(),
        "superseded.supersedes should point at backlog_open"
    );

    // exclude_labels=resolved + current_only=true → only the open backlog claim survives.
    let resp = client
        .get(format!(
            "http://{addr}/api/v1/claims/by-labels?labels=backlog&exclude_labels=resolved&current_only=true"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    let arr = body.as_array().expect("response is JSON array");
    let ours: Vec<&Value> = arr
        .iter()
        .filter(|c| {
            let id = c["id"].as_str().unwrap();
            id == backlog_open.to_string()
                || id == _backlog_resolved.to_string()
                || id == _backlog_superseded.to_string()
        })
        .collect();
    assert_eq!(
        ours.len(),
        1,
        "exclude_labels=resolved + current_only=true must leave only backlog_open: got {ours:?}"
    );
    assert_eq!(ours[0]["id"].as_str().unwrap(), backlog_open.to_string());

    // Missing labels query parameter → 400.
    let resp = client
        .get(format!("http://{addr}/api/v1/claims/by-labels"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "missing labels query parameter must yield 400"
    );
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    // Per-test-binary distinct prefix (DD) so we don't collide with other test
    // binaries' agent public_keys (graph_routes_test uses AA, themes BB,
    // neighborhoods CC, mcp query_claims_by_label uses BB-pattern via `bb`).
    let pk: Vec<u8> = std::iter::repeat(0xDD)
        .take(16)
        .chain(id.as_bytes().iter().copied())
        .take(32)
        .collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(
    pool: &PgPool,
    agent_id: Uuid,
    labels: &[&str],
    is_current: bool,
    supersedes: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat(0).take(16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             labels, is_current, supersedes) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(format!("test claim {}", id))
    .bind(hash)
    .bind(agent_id)
    .bind(labels.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .bind(is_current)
    .bind(supersedes)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}
