#![cfg(feature = "db")]
//! GET /api/v1/claims/:id/history walks `claims.supersedes` backward to a
//! root and then forward. `mark_duplicate` writes `dup.supersedes = canonical`
//! and checks neither side for cycles, so two calls in opposite directions
//! make an X↔Y loop; the walk used to follow it forever, holding a pooled
//! connection and growing the version list without bound.
mod common;

use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use sqlx::postgres::PgPoolOptions;
use std::collections::HashSet;
use uuid::Uuid;

async fn pool_and_app() -> (
    sqlx::PgPool,
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    reqwest::Client,
) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, shutdown) = common::spawn_app(&url).await;
    // A looping handler never answers; the timeout turns that into a failure
    // instead of a hung test.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap();
    (pool, addr, shutdown, client)
}

async fn history(
    client: &reqwest::Client,
    addr: std::net::SocketAddr,
    claim_id: Uuid,
) -> serde_json::Value {
    let resp = client
        .get(format!("http://{addr}/api/v1/claims/{claim_id}/history"))
        .send()
        .await
        .unwrap_or_else(|e| panic!("history for {claim_id} did not answer (cycle?): {e}"));
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

/// The test DB is shared, so leave no supersedes loop behind for other
/// suites' walks to trip over.
async fn unlink(pool: &sqlx::PgPool, ids: &[Uuid]) {
    sqlx::query("UPDATE claims SET supersedes = NULL WHERE id = ANY($1)")
        .bind(ids)
        .execute(pool)
        .await
        .unwrap();
}

fn version_ids(body: &serde_json::Value) -> Vec<Uuid> {
    body["versions"]
        .as_array()
        .expect("versions array")
        .iter()
        .map(|v| v["claim_id"].as_str().unwrap().parse().unwrap())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn history_terminates_on_a_mark_duplicate_cycle() {
    let (pool, addr, _shutdown, client) = pool_and_app().await;
    let x = common::seed_claim(&pool, "history cycle X").await;
    let y = common::seed_claim(&pool, "history cycle Y").await;

    // X → Y, then Y → X: both calls pass mark_duplicate's own checks.
    ClaimRepository::mark_duplicate(&pool, ClaimId::from_uuid(x), ClaimId::from_uuid(y))
        .await
        .unwrap();
    ClaimRepository::mark_duplicate(&pool, ClaimId::from_uuid(y), ClaimId::from_uuid(x))
        .await
        .unwrap();

    for start in [x, y] {
        let body = history(&client, addr, start).await;
        let ids = version_ids(&body);
        assert_eq!(
            ids.len(),
            2,
            "start {start}: each version exactly once: {ids:?}"
        );
        assert_eq!(
            ids.iter().copied().collect::<HashSet<_>>(),
            HashSet::from([x, y]),
            "start {start}"
        );
        assert_eq!(body["total_versions"], 2);
        assert_eq!(body["claim_id"], start.to_string());
    }
    unlink(&pool, &[x, y]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn history_terminates_on_a_self_supersedes_loop() {
    let (pool, addr, _shutdown, client) = pool_and_app().await;
    let z = common::seed_claim(&pool, "history self-loop Z").await;
    sqlx::query("UPDATE claims SET supersedes = id WHERE id = $1")
        .bind(z)
        .execute(&pool)
        .await
        .unwrap();

    let body = history(&client, addr, z).await;
    assert_eq!(version_ids(&body), vec![z]);
    unlink(&pool, &[z]).await;
}

/// Non-regression: an ordinary A ← B chain still lists oldest first, links
/// forward, and reports the current version.
#[tokio::test(flavor = "multi_thread")]
async fn history_of_a_linear_chain_is_unchanged() {
    let (pool, addr, _shutdown, client) = pool_and_app().await;
    let a = common::seed_claim(&pool, "history chain A").await;
    let b = common::seed_claim(&pool, "history chain B").await;
    sqlx::query("UPDATE claims SET is_current = false, embedding = NULL WHERE id = $1")
        .bind(a)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE claims SET supersedes = $1 WHERE id = $2")
        .bind(a)
        .bind(b)
        .execute(&pool)
        .await
        .unwrap();

    for start in [a, b] {
        let body = history(&client, addr, start).await;
        assert_eq!(version_ids(&body), vec![a, b], "start {start}");
        assert_eq!(body["versions"][0]["superseded_by"], b.to_string());
        assert_eq!(
            body["versions"][1]["superseded_by"],
            serde_json::Value::Null
        );
        assert_eq!(body["current_version"], 2);
    }
}
