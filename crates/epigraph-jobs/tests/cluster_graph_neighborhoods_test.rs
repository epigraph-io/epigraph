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

/// Insert one claim into `theme_id` with a cached `pignistic_prob`.
async fn theme_claim(
    pool: &sqlx::PgPool,
    agent: Uuid,
    theme_id: Option<Uuid>,
    what: &str,
    betp: f64,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .chain(id.as_bytes().iter())
        .copied()
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, pignistic_prob, theme_id)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(format!("{what} {id}"))
    .bind(hash)
    .bind(agent)
    .bind(betp)
    .bind(theme_id)
    .execute(pool)
    .await
    .unwrap();
    id
}

/// The `workflow-ingest` system agent (migration 148), the only author whose
/// `source_type: workflow` root stamp makes a tree procedural: the one already
/// registered in this shared test database, else `agent`, planted directly
/// with triggers off (the role is the registry's primary key).
async fn workflow_ingest_agent(pool: &sqlx::PgPool, agent: Uuid) -> Uuid {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO public.system_agents (role, agent_id, registered_public_key, reason)
         SELECT 'workflow-ingest', a.id, a.public_key, 'neighbourhood test plant'
           FROM public.agents a WHERE a.id = $1
         ON CONFLICT DO NOTHING",
    )
    .bind(agent)
    .execute(&mut *tx)
    .await
    .unwrap();
    let registered: Uuid = sqlx::query_scalar(
        "SELECT agent_id FROM public.system_agents WHERE role = 'workflow-ingest'",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    registered
}

/// Backlog fe1cdcdf: the theme subgraph is atoms-only by the ONE role
/// predicate (`claim_role::IS_COMPOUND_SQL`), not a hand-rolled "has any
/// `decomposes_to` out-edge" test. A compound's cached BetP stays out of the
/// neighbourhood's `mean_betp`, and a claim whose only decomposition is
/// RETIRED (`valid_to` in the past) is no compound and counts as the atom it
/// now is. The old predicate read every `decomposes_to` row, in force or not,
/// so it dropped that claim and averaged the remaining atom alone.
///
/// A workflow tree (`claim_role::IS_PROCEDURAL_SQL`) is out too, its LEAF
/// included: a workflow claim's truth is a lifecycle marker, not a belief
/// (the procedural ruling the role-blind register's ByDesign rows cite). The
/// old predicate kept a workflow leaf, which has no out-edge.
#[tokio::test(flavor = "multi_thread")]
async fn neighbourhood_betp_reads_atoms_by_the_role_predicate() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    common::reset_neighborhood_tables(&pool).await;
    let (run_id, _theme, atoms, _standalone) = common::seed_two_clique_theme(&pool).await;
    let agent: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(atoms[0])
        .fetch_one(&pool)
        .await
        .unwrap();

    let theme_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claim_themes (id, label, description, claim_count)
         VALUES ($1, 'RoleTheme', '', 2)",
    )
    .bind(theme_id)
    .execute(&pool)
    .await
    .unwrap();
    let atom = theme_claim(&pool, agent, Some(theme_id), "atom", 0.2).await;
    let compound = theme_claim(&pool, agent, Some(theme_id), "compound", 0.9).await;
    let retired_parent = theme_claim(&pool, agent, Some(theme_id), "retired parent", 0.8).await;
    let child = theme_claim(&pool, agent, None, "child", 0.5).await;
    let workflow_author = workflow_ingest_agent(&pool, agent).await;
    let workflow_root =
        theme_claim(&pool, workflow_author, Some(theme_id), "workflow root", 0.9).await;
    sqlx::query(
        "UPDATE claims SET properties = properties || '{\"source_type\": \"workflow\"}'
          WHERE id = $1",
    )
    .bind(workflow_root)
    .execute(&pool)
    .await
    .unwrap();
    let workflow_leaf =
        theme_claim(&pool, workflow_author, Some(theme_id), "workflow leaf", 0.9).await;
    for (parent, child, valid_to) in [
        (compound, child, "NULL"),
        (retired_parent, child, "now() - interval '1 day'"),
        (workflow_root, workflow_leaf, "NULL"),
    ] {
        sqlx::query(&format!(
            "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship,
                                valid_from, valid_to)
             VALUES ($1, $2, 'claim', 'claim', 'decomposes_to',
                     now() - interval '2 days', {valid_to})"
        ))
        .bind(parent)
        .bind(child)
        .execute(&pool)
        .await
        .unwrap();
    }
    // Calibration: the workflow leaf IS procedural, so its absence below is
    // the role predicate's doing and not a fixture that missed the stamp.
    let leaf_is_procedural: bool = sqlx::query_scalar(&format!(
        "SELECT {} FROM claims c WHERE c.id = $1",
        epigraph_db::repos::claim_role::is_procedural_sql("c"),
    ))
    .bind(workflow_leaf)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        leaf_is_procedural,
        "calibration: the workflow leaf is procedural"
    );

    epigraph_jobs::cluster_graph::neighborhood::run_theme_neighborhoods(
        &pool,
        run_id,
        &epigraph_jobs::cluster_graph::neighborhood::Config::default(),
        Some(&[theme_id]),
    )
    .await
    .unwrap();

    let (size, mean_betp): (i32, Option<f64>) = sqlx::query_as(
        "SELECT size, mean_betp FROM graph_neighborhoods WHERE run_id = $1 AND theme_id = $2",
    )
    .bind(run_id)
    .bind(theme_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let members: std::collections::BTreeSet<Uuid> = sqlx::query_scalar(
        "SELECT claim_id FROM claim_neighborhood_membership m
           JOIN graph_neighborhoods n ON n.id = m.neighborhood_id
          WHERE m.run_id = $1 AND n.theme_id = $2",
    )
    .bind(run_id)
    .bind(theme_id)
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .collect();
    assert_eq!(
        members,
        [atom, retired_parent].into_iter().collect(),
        "the compound {compound} is no member, nor is the workflow tree \
         ({workflow_root}, its leaf {workflow_leaf}); the retired parent is an atom"
    );
    assert_eq!(size, 2);
    let mean = mean_betp.expect("mean_betp over two atoms");
    assert!(
        (mean - 0.5).abs() < 1e-9,
        "mean_betp = (0.2 + 0.8) / 2, the compound's and the workflow tree's 0.9 \
         excluded; got {mean}"
    );
}
