#![cfg(feature = "db")]
//! GET /api/v1/claims/:id/history walks `claims.supersedes` backward to a
//! root and then forward. `mark_duplicate` writes `dup.supersedes = canonical`
//! and checks neither side for cycles, so two calls in opposite directions
//! make an X↔Y loop; the walk used to follow it forever, holding a pooled
//! connection and growing the version list without bound.
//!
//! # What these arms assert now, and why it is weaker than it was
//!
//! The inline three-statement walk this branch guarded with two visited-sets is
//! gone. `ClaimRepository::version_history` replaces it with ONE viewer-filtered
//! recursive CTE that stops a loop with `depth < 100` on both recursive terms,
//! so an X↔Y cycle terminates at roughly 101 entries with duplicated ids rather
//! than at 2 distinct ones. The DoS is stopped either way — which is what these
//! arms exist for — but the response shape is main's, so the cycle arms assert
//! BOUNDED AND TERMINATING rather than an exact set. Reintroducing the exact
//! shape would mean reintroducing three unfiltered inline reads, and this branch
//! is not trading a tenancy filter for a cosmetic wart on data that is already
//! malformed.
//!
//! `history_of_a_linear_chain_is_unchanged` is kept VERBATIM: it is a genuine
//! non-regression over main's new CTE, which derives `superseded_by` from
//! `claims.supersedes` rather than positionally.
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
    // This suite runs on the shared $DATABASE_URL database rather than on a
    // per-test one, so it must state its precondition instead of self-healing.
    // The tenancy series deleted `ensure_claim_encryption_table` precisely so
    // an unmigrated database fails loudly here rather than silently passing a
    // suite that tests nothing.
    let migrated: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.claim_encryption')::text")
            .fetch_one(&pool)
            .await
            .expect("probe the schema");
    assert!(
        migrated.is_some(),
        "$DATABASE_URL is not migrated. Run: \
         cargo run -p epigraph-api --bin epigraph-migrate"
    );
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
    // A bearer is not optional any more: the tenancy series moved 105
    // registrations from the public router to the protected one, and the
    // anonymous allowlist is `/health` and `/api/v1/openapi.json`. Without
    // this every arm below fails on a 401 that has nothing to do with cycles.
    let resp = client
        .get(format!("http://{addr}/api/v1/claims/{claim_id}/history"))
        .bearer_auth(common::mint_token_with_agent(
            &["claims:read"],
            Uuid::new_v4(),
        ))
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
        // Answering at all is half the assertion: the client carries a 20s
        // timeout, so a walk that follows the loop fails here rather than
        // hanging the suite.
        let body = history(&client, addr, start).await;
        let ids = version_ids(&body);
        let total = body["total_versions"].as_i64().expect("total_versions");
        assert!(
            total <= 101,
            "start {start}: the CTE's depth<100 cap must bound the walk, got {total}"
        );
        assert_eq!(ids.len() as i64, total, "start {start}: {ids:?}");
        assert_eq!(
            ids.iter().copied().collect::<HashSet<_>>(),
            HashSet::from([x, y]),
            "start {start}: the loop may repeat ids but must not invent any"
        );
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
    let ids = version_ids(&body);
    assert!(
        !ids.is_empty() && ids.len() <= 101,
        "a self-loop must terminate inside the depth cap, got {ids:?}"
    );
    assert!(
        ids.iter().all(|id| *id == z),
        "a self-loop must not reach any other claim, got {ids:?}"
    );
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
