//! `ClusterRunRepository::latest` resolves the newest LOUVAIN run, never a
//! `louvain_bridge` one (backlog 523dcb4f).
//!
//! `POST /api/v1/clusters/build-from-bridges` writes `algo = 'louvain_bridge'`
//! rows into the same `graph_cluster_runs` table the nightly Louvain job
//! writes (migration 028's discriminator). A bridge run has no
//! neighbourhoods, so when the shared lookup let one become "latest", every
//! route resolving through it (`routes/graph.rs` overview / expand /
//! themes_expand, `routes/graph_neighborhood.rs` expand and
//! `GET /claims/:id/placement`) answered 404 for the clusters and
//! neighbourhoods of the real Louvain run. Route-level coverage follows from
//! `epigraph-api/tests/cluster_run_lookup_is_shared_test.rs`, which pins that
//! every one of those routes goes through this one function.
//!
//! Every arm seeds the bridge run LATER than the Louvain run, so an
//! implementation that orders by `completed_at` alone fails here.

mod viewer_fixture;

use epigraph_db::{ClaimRepository, ClusterRunRepository};
use sqlx::PgPool;
use uuid::Uuid;

/// A run row with an explicit `algo` and a `completed_at` offset from now.
async fn seed_run(pool: &PgPool, algo: &str, offset_minutes: i32) -> Uuid {
    let run_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded, algo, completed_at) \
         VALUES ($1, 1, FALSE, $2, now() + make_interval(mins => $3))",
    )
    .bind(run_id)
    .bind(algo)
    .bind(offset_minutes)
    .execute(pool)
    .await
    .expect("seed run");
    run_id
}

/// A cluster in `run_id` with `claim` as its one member.
async fn seed_membership(pool: &PgPool, run_id: Uuid, claim: Uuid) -> Uuid {
    let cluster_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_clusters (id, run_id, label, size, mean_betp, dominant_type, degraded) \
         VALUES ($1, $2, 'cluster-0', 1, 0.5, 'claim', FALSE)",
    )
    .bind(cluster_id)
    .bind(run_id)
    .execute(pool)
    .await
    .expect("seed cluster");
    sqlx::query(
        "INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id) VALUES ($1, $2, $3)",
    )
    .bind(claim)
    .bind(cluster_id)
    .bind(run_id)
    .execute(pool)
    .await
    .expect("seed membership");
    cluster_id
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_newer_bridge_run_does_not_displace_the_louvain_run(pool: PgPool) {
    // The default-algo insert is how the jobs runner writes its run row
    // (`cluster_graph/runner.rs`, no `algo` column), so seed one that way too
    // and check the default really is the literal the lookup filters on.
    let louvain = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded, completed_at) \
         VALUES ($1, 1, FALSE, now() - interval '1 hour')",
    )
    .bind(louvain)
    .execute(&pool)
    .await
    .expect("seed a runner-shaped louvain run");
    let algo: String = sqlx::query_scalar("SELECT algo FROM graph_cluster_runs WHERE run_id = $1")
        .bind(louvain)
        .fetch_one(&pool)
        .await
        .expect("read algo back");
    assert_eq!(
        algo, "louvain",
        "CALIBRATION: migration 028's default is the literal the runner's rows carry"
    );
    let bridge = seed_run(&pool, "louvain_bridge", 0).await;

    let latest = ClusterRunRepository::latest(&pool)
        .await
        .expect("latest")
        .expect("a louvain run exists");
    assert_eq!(
        latest.run_id, louvain,
        "a louvain_bridge run ({bridge}) completing after the Louvain run must not become \
         \"latest\": it has no neighbourhoods, so every expand route 404s against it"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_newest_of_several_louvain_runs_still_wins(pool: PgPool) {
    let _older = seed_run(&pool, "louvain", -120).await;
    let newer = seed_run(&pool, "louvain", -60).await;
    let _bridge = seed_run(&pool, "louvain_bridge", 0).await;

    let latest = ClusterRunRepository::latest(&pool)
        .await
        .expect("latest")
        .expect("a louvain run exists");
    assert_eq!(
        latest.run_id, newer,
        "the filter must not lose the ordering: the newest Louvain run is current"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_a_bridge_run_means_no_current_run(pool: PgPool) {
    seed_run(&pool, "louvain_bridge", 0).await;
    let latest = ClusterRunRepository::latest(&pool).await.expect("latest");
    assert!(
        latest.is_none(),
        "a bridge run alone is not a Louvain run, so there is no current run: {latest:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn placement_resolves_the_louvain_cluster_not_the_bridge_one(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let (agent, _group) = viewer_fixture::seed_agent_with_group(&pool, "placement-algo").await;
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "placement algo claim").await;

    let louvain = seed_run(&pool, "louvain", -60).await;
    let louvain_cluster = seed_membership(&pool, louvain, claim).await;
    // The bridge clusterer puts paragraphs in clusters too, so the claim is a
    // member of BOTH runs; the newer one must still not be the one resolved.
    let bridge = seed_run(&pool, "louvain_bridge", 0).await;
    let bridge_cluster = seed_membership(&pool, bridge, claim).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let placement = ClusterRunRepository::claim_placement(&mut conn, &viewer, claim)
        .await
        .expect("claim_placement")
        .expect("the public claim is visible");
    assert_eq!(
        placement.cluster_run_id,
        Some(louvain),
        "placement must resolve against the Louvain run, the one expand recognises"
    );
    assert_eq!(
        placement.cluster_id,
        Some(louvain_cluster),
        "placement handed out the bridge cluster {bridge_cluster}, which expand 404s"
    );
}

/// A 1536-d pgvector literal; the semantic read ranks on `claims.embedding`
/// and decodes `similarity` as a non-null `f64`, so the claim needs one.
fn probe_vec() -> String {
    format!("[{}]", vec!["0.1"; 1536].join(","))
}

#[sqlx::test(migrations = "../../migrations")]
async fn semantic_search_cluster_id_comes_from_the_louvain_run(pool: PgPool) {
    // `ClaimRepository::semantic_selected_claims` (the diverse
    // `/search/semantic` row) carries its own "newest run" subquery for
    // `cluster_id`. The bridge clusterer makes paragraph claims members of a
    // bridge run too; without the algo filter the newer bridge cluster id
    // came back here, and `routes/graph.rs::expand` (pinned to
    // `ClusterRunRepository::latest`) answers 404 for it.
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let (agent, _group) = viewer_fixture::seed_agent_with_group(&pool, "search-algo").await;
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "search algo claim").await;
    let vec = probe_vec();
    viewer_fixture::set_claim_embedding(&pool, claim, &vec).await;

    let louvain = seed_run(&pool, "louvain", -60).await;
    let louvain_cluster = seed_membership(&pool, louvain, claim).await;
    let bridge = seed_run(&pool, "louvain_bridge", 0).await;
    let bridge_cluster = seed_membership(&pool, bridge, claim).await;

    let rows =
        ClaimRepository::semantic_selected_claims(&pool, &viewer, "embedding", &vec, &[claim])
            .await
            .expect("semantic_selected_claims");
    assert_eq!(rows.len(), 1, "the public claim is selected: {rows:?}");
    assert_eq!(
        rows[0].cluster_id,
        Some(louvain_cluster),
        "search handed out the bridge cluster {bridge_cluster}, which expand 404s"
    );
}
