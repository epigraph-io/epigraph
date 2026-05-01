//! Integration tests for the per-theme Louvain neighborhood pass.
//!
//! Run with:
//!   DATABASE_URL=postgres://... cargo test --features integration \
//!     --package epigraph-jobs --test cluster_graph_neighborhoods_test -- --nocapture

#![cfg(feature = "integration")]

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn run_theme_neighborhoods_seeds_two_neighborhoods_per_theme() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    common::reset_neighborhood_tables(&pool).await;

    // Seed: one theme T with 6 atoms split into two clearly-separated SUPPORTS
    // cliques (a-b-c, d-e-f), one weak cross-edge a→d, and one truly-standalone
    // claim s with no edges in either direction (forms its own singleton).
    // See common::seed_two_clique_theme for the full topology comment.
    let (run_id, theme_id, _atoms, _standalone) = common::seed_two_clique_theme(&pool).await;

    // Pass Some(&[theme_id]) to scope the run to just this test theme.
    // This avoids processing the ~68 real themes already in the live DB,
    // which would take many minutes and produce cross-run noise in assertions.
    // Set skip_threshold_nodes/edges to 0 so Louvain always runs even on this
    // small fixture (production defaults are 50 nodes / 10 edges).
    epigraph_jobs::cluster_graph::neighborhood::run_theme_neighborhoods(
        &pool,
        run_id,
        &epigraph_jobs::cluster_graph::neighborhood::Config {
            resolution: 1.0,
            skip_threshold_nodes: 0,
            skip_threshold_edges: 0,
        },
        Some(&[theme_id]),
    )
    .await
    .unwrap();

    // Expect exactly 3 neighborhoods: clique-a-b-c, clique-d-e-f, singleton-s.
    // Total size = 7 (6 atoms + 1 standalone).
    let neighborhoods: Vec<(Uuid, i32)> = sqlx::query_as(
        "SELECT id, size FROM graph_neighborhoods
         WHERE run_id = $1 AND theme_id = $2
         ORDER BY size DESC",
    )
    .bind(run_id)
    .bind(theme_id)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(
        neighborhoods.len(),
        3,
        "expected 3 neighborhoods: two cliques + singleton"
    );
    let total_size: i32 = neighborhoods.iter().map(|(_, s)| *s).sum();
    assert_eq!(
        total_size, 7,
        "all 6 atoms + 1 standalone in some neighborhood"
    );

    // The cross-clique edge a→d (SUPPORTS, forward_strength=0.7) should
    // produce exactly one neighborhood_edge for this theme's run.
    // Scope the query through graph_neighborhoods so run_id + theme_id is
    // unambiguous even if other themes share the same run_id in future.
    let edges: Vec<(f64,)> = sqlx::query_as(
        "SELECT ne.weight
         FROM neighborhood_edges ne
         JOIN graph_neighborhoods na ON na.id = ne.neighborhood_a
         WHERE ne.run_id = $1 AND na.theme_id = $2",
    )
    .bind(run_id)
    .bind(theme_id)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(
        edges.len(),
        1,
        "cross-clique edge should produce exactly one neighborhood_edge"
    );
    assert!(
        (edges[0].0 - 0.7).abs() < 1e-9,
        "weight should equal forward_strength (0.7) of the single cross-clique SUPPORTS edge, got {}",
        edges[0].0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn run_clustering_populates_neighborhoods_when_themes_exist() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    common::reset_neighborhood_tables(&pool).await;
    common::seed_two_clique_theme(&pool).await; // claims+theme exist; runner allocates its own run_id

    let summary = epigraph_jobs::cluster_graph::runner::run_clustering(
        &pool,
        &epigraph_jobs::cluster_graph::runner::RunConfig {
            resolution: 1.0,
            retain_runs: 3,
        },
    )
    .await
    .unwrap();

    let n_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM graph_neighborhoods WHERE run_id = $1")
            .bind(summary.run_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    // The runner uses Config::default() (thresholds 50/10). With our seed of 7 atoms in
    // the test theme, this hits the synthetic-single-neighborhood path: one neighborhood
    // covering the whole theme. The point of this test is to verify the runner *calls*
    // the neighborhood pass — exact community count is exercised by the
    // run_theme_neighborhoods test above with thresholds=0.
    assert!(
        n_count.0 >= 1,
        "runner should populate at least one neighborhood for the seeded theme"
    );
}
