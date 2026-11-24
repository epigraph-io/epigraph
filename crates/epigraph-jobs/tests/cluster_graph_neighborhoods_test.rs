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

/// Backlog 01e0b839: a Louvain neighbourhood's stored label is the positional
/// placeholder `neighborhood-N`, never its dominant frame's id. The frame is
/// still recorded, in `dominant_frame_id`. Before the fix every atom below,
/// carrying one frame, gave each multi-member community the frame's UUID
/// string as its `label`, which is no name and is computed over every member
/// (private ones included).
#[tokio::test(flavor = "multi_thread")]
async fn louvain_neighborhood_labels_are_placeholders_not_the_dominant_frame_id() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    common::reset_neighborhood_tables(&pool).await;
    let (run_id, theme_id, atoms, _standalone) = common::seed_two_clique_theme(&pool).await;

    let frame_id: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0', 'h1']) RETURNING id",
    )
    .bind(format!("nbr-label-frame-{}", Uuid::new_v4().simple()))
    .fetch_one(&pool)
    .await
    .unwrap();
    for atom in &atoms {
        sqlx::query("INSERT INTO claim_frames (claim_id, frame_id) VALUES ($1, $2)")
            .bind(atom)
            .bind(frame_id)
            .execute(&pool)
            .await
            .unwrap();
    }

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

    let rows: Vec<(String, Option<Uuid>)> = sqlx::query_as(
        "SELECT label, dominant_frame_id FROM graph_neighborhoods
         WHERE run_id = $1 AND theme_id = $2",
    )
    .bind(run_id)
    .bind(theme_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 3, "two cliques + singleton: {rows:?}");
    let framed = rows.iter().filter(|(_, f)| *f == Some(frame_id)).count();
    assert_eq!(
        framed, 2,
        "CALIBRATION: both cliques record the frame as dominant: {rows:?}"
    );
    for (label, _) in &rows {
        assert_ne!(label, &frame_id.to_string(), "{rows:?}");
        let n = label
            .strip_prefix("neighborhood-")
            .unwrap_or_else(|| panic!("label {label:?} is not a placeholder"));
        assert!(n.parse::<u32>().is_ok(), "{label:?}");
    }
}

// ── backlog 30633061: rebuild a split theme's neighbourhoods ────────────────

use epigraph_jobs::cluster_graph::neighborhood::{self as nbr, LatestRebuild};
use std::collections::BTreeSet;

fn louvain_always() -> nbr::Config {
    nbr::Config {
        resolution: 1.0,
        skip_threshold_nodes: 0,
        skip_threshold_edges: 0,
    }
}

/// The claims `theme_id`'s neighbourhoods hold in `run_id`.
async fn members_of(pool: &sqlx::PgPool, run_id: Uuid, theme_id: Uuid) -> BTreeSet<Uuid> {
    sqlx::query_scalar(
        "SELECT m.claim_id FROM claim_neighborhood_membership m
         JOIN graph_neighborhoods n ON n.id = m.neighborhood_id AND n.run_id = m.run_id
         WHERE n.run_id = $1 AND n.theme_id = $2",
    )
    .bind(run_id)
    .bind(theme_id)
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .collect()
}

/// A built run for the two-clique theme, then the second clique moved to a
/// new theme the way `scripts/theme_cap_split.py apply` moves a part
/// (`UPDATE claims SET theme_id`). Returns (pool, run, parent, part, parent's
/// remaining claims, the moved claims).
async fn split_after_the_run() -> (
    sqlx::PgPool,
    Uuid,
    Uuid,
    Uuid,
    BTreeSet<Uuid>,
    BTreeSet<Uuid>,
) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .unwrap();
    common::reset_neighborhood_tables(&pool).await;
    let (run_id, parent, atoms, standalone) = common::seed_two_clique_theme(&pool).await;
    nbr::run_theme_neighborhoods(&pool, run_id, &louvain_always(), Some(&[parent]))
        .await
        .unwrap();

    let part = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claim_themes (id, label, description, claim_count)
         VALUES ($1, 'TestTheme · part 2', '', 3)",
    )
    .bind(part)
    .execute(&pool)
    .await
    .unwrap();
    let moved: Vec<Uuid> = atoms[3..6].to_vec();
    sqlx::query("UPDATE claims SET theme_id = $1 WHERE id = ANY($2)")
        .bind(part)
        .bind(&moved)
        .execute(&pool)
        .await
        .unwrap();
    let kept: BTreeSet<Uuid> = atoms[0..3].iter().copied().chain([standalone]).collect();
    (
        pool,
        run_id,
        parent,
        part,
        kept,
        moved.into_iter().collect(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_split_themes_neighborhoods_are_rebuilt_in_the_served_run() {
    let (pool, run_id, parent, part, kept, moved) = split_after_the_run().await;
    let all: BTreeSet<Uuid> = kept.union(&moved).copied().collect();

    // CALIBRATION, the defect: the run still files the moved claims under the
    // parent, the part has nothing, and re-running the existing per-theme
    // pass over both themes repairs neither (the moved claims' memberships
    // collide on (run_id, claim_id); the pass logs and skips the theme).
    assert_eq!(members_of(&pool, run_id, parent).await, all);
    nbr::run_theme_neighborhoods(&pool, run_id, &louvain_always(), Some(&[parent, part]))
        .await
        .unwrap();
    assert_eq!(members_of(&pool, run_id, parent).await, all);
    assert!(members_of(&pool, run_id, part).await.is_empty());

    let report =
        nbr::rebuild_theme_neighborhoods_in_run(&pool, run_id, &louvain_always(), &[parent, part])
            .await
            .unwrap();

    assert_eq!(members_of(&pool, run_id, parent).await, kept);
    assert_eq!(members_of(&pool, run_id, part).await, moved);
    let mut expected = vec![parent, part];
    expected.sort();
    assert_eq!(
        report
            .rebuilt
            .iter()
            .map(|r| r.theme_id)
            .collect::<Vec<_>>(),
        expected
    );
    for r in &report.rebuilt {
        let want = if r.theme_id == parent {
            kept.len()
        } else {
            moved.len()
        };
        assert_eq!(r.members, want as i64, "{report:?}");
        assert!(r.neighborhoods >= 1, "{report:?}");
    }
    assert!(report.missing.is_empty(), "{report:?}");
    // The only cross-neighbourhood edge (a -> d) now joins two themes, and
    // neighbourhood edges are per theme: none is left in the run.
    let edges: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM neighborhood_edges WHERE run_id = $1")
            .bind(run_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(edges, 0);

    // A reverse moves the claims back and deletes the part (its rows cascade):
    // rebuilding the parent and the deleted part restores the parent whole and
    // reports the part missing.
    sqlx::query("UPDATE claims SET theme_id = $1 WHERE theme_id = $2")
        .bind(parent)
        .bind(part)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM claim_themes WHERE id = $1")
        .bind(part)
        .execute(&pool)
        .await
        .unwrap();
    let report =
        nbr::rebuild_theme_neighborhoods_in_run(&pool, run_id, &louvain_always(), &[parent, part])
            .await
            .unwrap();
    assert_eq!(members_of(&pool, run_id, parent).await, all);
    assert_eq!(report.missing, vec![part]);
    assert_eq!(report.rebuilt.len(), 1, "{report:?}");
}

/// Naming only the new part is enough: the parent, whose neighbourhoods
/// still hold the part's claims in the run, is rebuilt with it.
#[tokio::test(flavor = "multi_thread")]
async fn rebuilding_a_part_alone_also_rebuilds_the_theme_its_claims_left() {
    let (pool, run_id, parent, part, kept, moved) = split_after_the_run().await;

    let report = nbr::rebuild_theme_neighborhoods_in_run(&pool, run_id, &louvain_always(), &[part])
        .await
        .unwrap();

    assert_eq!(members_of(&pool, run_id, parent).await, kept);
    assert_eq!(members_of(&pool, run_id, part).await, moved);
    assert!(
        report.rebuilt.iter().any(|r| r.theme_id == parent),
        "{report:?}"
    );
}

/// The latest-run entry point rebuilds the run the readers serve, and yields
/// (writing nothing) while the clustering job's lock is held.
#[tokio::test(flavor = "multi_thread")]
async fn the_latest_run_rebuild_waits_for_no_clustering_run_and_rebuilds_the_newest() {
    let (pool, run_id, parent, part, kept, moved) = split_after_the_run().await;
    let all: BTreeSet<Uuid> = kept.union(&moved).copied().collect();

    let mut holder = pool.acquire().await.unwrap();
    let held: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(epigraph_jobs::CLUSTER_GRAPH_LOCK_KEY)
        .fetch_one(&mut *holder)
        .await
        .unwrap();
    assert!(held, "CALIBRATION: the test holds the clustering lock");
    let outcome = nbr::rebuild_theme_neighborhoods_latest(&pool, &louvain_always(), &[part])
        .await
        .unwrap();
    assert_eq!(outcome, LatestRebuild::Locked);
    assert_eq!(members_of(&pool, run_id, parent).await, all);
    let _: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
        .bind(epigraph_jobs::CLUSTER_GRAPH_LOCK_KEY)
        .fetch_one(&mut *holder)
        .await
        .unwrap();
    drop(holder);

    let outcome = nbr::rebuild_theme_neighborhoods_latest(&pool, &louvain_always(), &[part])
        .await
        .unwrap();
    let LatestRebuild::Rebuilt(report) = outcome else {
        panic!("expected a rebuild, got {outcome:?}");
    };
    assert_eq!(report.run_id, run_id, "the seeded run is the newest");
    assert_eq!(members_of(&pool, run_id, parent).await, kept);
    assert_eq!(members_of(&pool, run_id, part).await, moved);
}
