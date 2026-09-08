#![cfg(feature = "db")]
//! # Why the cluster arms here take an injected `pool`
//!
//! The four community-graph arms assert **whole-table** properties: "no runs
//! exist anywhere", "the latest run has exactly 2 clusters / 1 cluster edge",
//! "this cluster expands to exactly 5 nodes", and "an unknown cluster id is
//! 404". The routes answer from the LATEST run, so those counts are global by
//! design and cannot be narrowed to self-created rows without deleting the
//! run-selection logic from the test.
//!
//! They used to manufacture that global precondition by TRUNCATING
//! `graph_cluster_runs`, `cluster_edges`, `claim_cluster_membership` and
//! `graph_clusters` on a shared database — which made them destructive to every
//! sibling binary and dependent on the order they ran in. This is the recorded
//! finding F-tests-depend-on-accumulated-shared-db-fixtures.
//!
//! `#[sqlx::test]` supplies the empty database directly, so the assertions are
//! UNCHANGED and the truncation is simply unnecessary. One arm was worse than
//! flaky: `expand_returns_404_for_unknown_cluster` can pass FOR THE WRONG
//! REASON on a shared database, because the handler returns 404 both for "no
//! such cluster in the latest run" (the branch under test) and for "no runs at
//! all" (what a sibling's truncation leaves behind). A private database makes
//! the seeded run a guarantee rather than a race, so only the intended branch
//! can produce the 404.
//!
//! `spawn_app` builds its own pool FROM A URL, so each arm hands it
//! `fixture::database_url_for(&pool)` — the per-test database's own URL. Passing
//! the ambient `DATABASE_URL` here would seed the private database and then
//! assert against the shared one, which is the silent-vacuous-pass failure this
//! note exists to prevent.
//!
//! The two remaining `#[tokio::test]` arms are deliberately left alone:
//! `legacy_neighborhood_endpoint_returns_410_gone` and
//! `graph_endpoints_require_bearer` assert 410/401 unconditionally, read no
//! table and mutate none, so per-test provisioning would cost time and buy no
//! isolation.

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

#[sqlx::test(migrations = "../../migrations")]
async fn overview_with_no_runs_returns_no_clusters_computed(pool: PgPool) {
    // No truncation and no seeding: #[sqlx::test] IS the "no runs exist" state
    // this arm previously tried to create by emptying four shared tables.
    let url = fixture::database_url_for(&pool).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/api/v1/graph/communities/overview"))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "no_clusters_computed");
    assert_eq!(body["supernodes"].as_array().unwrap().len(), 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_returns_seeded_supernodes(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let run_id = uuid::Uuid::new_v4();
    let c1 = uuid::Uuid::new_v4();
    let c2 = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO graph_clusters (id, run_id, label, size, mean_betp, dominant_type, dominant_frame_id, degraded) VALUES ($1, $2, 'A', 5, 0.7, 'claim', NULL, FALSE), ($3, $2, 'B', 3, 0.4, 'claim', NULL, FALSE)")
        .bind(c1).bind(run_id).bind(c2)
        .execute(&pool).await.unwrap();
    let (lo, hi) = if c1 < c2 { (c1, c2) } else { (c2, c1) };
    sqlx::query(
        "INSERT INTO cluster_edges (run_id, cluster_a, cluster_b, weight) VALUES ($1, $2, $3, 4)",
    )
    .bind(run_id)
    .bind(lo)
    .bind(hi)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 2, FALSE)",
    )
    .bind(run_id)
    .execute(&pool)
    .await
    .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/graph/communities/overview"))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["supernodes"].as_array().unwrap().len(), 2);
    assert_eq!(body["cluster_edges"].as_array().unwrap().len(), 1);
    assert_eq!(body["cluster_edges"][0]["weight"], 4);
    assert_eq!(body["degraded"], false);
}

#[sqlx::test(migrations = "../../migrations")]
async fn expand_returns_cluster_members_with_induced_edges(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let cluster_id = common::seed_one_cluster(&pool, 5).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/graph/communities/{cluster_id}/expand?budget=10"
        ))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["nodes"].as_array().unwrap().len(), 5);
    assert_eq!(body["truncated"], false);
}

#[sqlx::test(migrations = "../../migrations")]
async fn expand_returns_404_for_unknown_cluster(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    // Need at least one run row so the handler reaches the per-cluster check (404
    // also happens when no run exists, but we want to specifically test the
    // "no such cluster in latest run" branch). seed_one_cluster sets that up.
    //
    // On a shared database that was a HOPE, not a guarantee: any sibling arm
    // truncating graph_cluster_runs between this seed and the request sent the
    // handler down the "no runs at all" branch, which returns the same 404 and
    // made the assertion pass while testing nothing. The per-test database is
    // what makes the seeded run survive to the assertion.
    let _ = common::seed_one_cluster(&pool, 1).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let bogus = uuid::Uuid::new_v4();
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/graph/communities/{bogus}/expand"
        ))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_neighborhood_endpoint_returns_410_gone() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    // We don't need to seed anything — handler returns 410 unconditionally.
    let _ = pool;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/graph/neighborhood?node_id={}&hops=1&budget=20",
            uuid::Uuid::new_v4()
        ))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        410,
        "legacy /graph/neighborhood must return 410 Gone"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn graph_endpoints_require_bearer() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;
    for path in [
        "/api/v1/graph/communities/overview".to_string(),
        format!("/api/v1/graph/communities/{}/expand", uuid::Uuid::new_v4()),
        format!(
            "/api/v1/graph/neighborhood?node_id={}",
            uuid::Uuid::new_v4()
        ),
    ] {
        let resp = reqwest::Client::new()
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401, "missing auth path={path}");
    }
}
