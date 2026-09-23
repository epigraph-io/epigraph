//! The `cluster_graph` job clusters over edges IN FORCE only.
//!
//! Communities (`graph_clusters` / `cluster_edges`) and per-theme
//! neighborhoods (`graph_neighborhoods` / `neighborhood_edges`) are the
//! precomputed layer the explorer's overview and neighborhood views render.
//! Edge removal is a retraction (the row keeps `valid_to`), so before this
//! job filtered on `valid_to` a deleted edge kept tying communities together
//! and kept a retracted decomposition classifying its source as a compound.
//!
//! Each test runs the job twice on one private database — once with the edge
//! in force (the precondition), once after retracting it — and compares the
//! two runs, so neither assertion can pass on a fixture that never produced
//! the structure in question.

use epigraph_db::repos::edge::EdgeRepository;
use epigraph_jobs::cluster_graph::neighborhood::{run_theme_neighborhoods, Config};
use epigraph_jobs::cluster_graph::runner::{run_clustering, RunConfig};
use sqlx::PgPool;
use uuid::Uuid;

async fn world(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM groups WHERE kind = 'world' LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("world group")
}

async fn agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'cluster-retraction', 'system') \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("agent")
}

async fn claim(pool: &PgPool, agent: Uuid, theme: Option<Uuid>, label: &str) -> Uuid {
    let world = world(pool).await;
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, pignistic_prob, \
                             theme_id, visibility, owner_group_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, 0.5, $3, 'public', $4) RETURNING id",
    )
    .bind(format!("{label} {}", Uuid::new_v4()))
    .bind(agent)
    .bind(theme)
    .bind(world)
    .fetch_one(pool)
    .await
    .expect("claim")
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("edge")
}

/// Two SUPPORTS triangles joined by one cross edge `atoms[0] -> atoms[3]`,
/// whose id is returned with the atoms.
async fn two_cliques(pool: &PgPool, theme: Option<Uuid>) -> (Vec<Uuid>, Uuid) {
    let a = agent(pool).await;
    let mut atoms = Vec::new();
    for i in 0..6 {
        atoms.push(claim(pool, a, theme, &format!("atom-{i}")).await);
    }
    for (s, t) in [(0, 1), (1, 2), (2, 0), (3, 4), (4, 5), (5, 3)] {
        edge(pool, atoms[s], atoms[t], "SUPPORTS").await;
    }
    let cross = edge(pool, atoms[0], atoms[3], "SUPPORTS").await;
    (atoms, cross)
}

async fn cluster_edge_count(pool: &PgPool, run_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM cluster_edges WHERE run_id = $1")
        .bind(run_id)
        .fetch_one(pool)
        .await
        .expect("count cluster_edges")
}

#[sqlx::test(migrations = "../../migrations")]
async fn run_clustering_ignores_a_retracted_cross_edge(pool: PgPool) {
    let (_atoms, cross) = two_cliques(&pool, None).await;
    let cfg = RunConfig {
        resolution: 1.0,
        retain_runs: 10,
    };

    let before = run_clustering(&pool, &cfg).await.expect("run 1");
    assert_eq!(before.cluster_count, 2, "precondition: two communities");
    assert_eq!(
        cluster_edge_count(&pool, before.run_id).await,
        1,
        "precondition: the in-force cross edge links the two communities"
    );

    EdgeRepository::retract(&pool, &[cross])
        .await
        .expect("retract");
    let after = run_clustering(&pool, &cfg).await.expect("run 2");
    assert_eq!(
        after.cluster_count, 2,
        "the two triangles are still two communities"
    );
    assert_eq!(
        cluster_edge_count(&pool, after.run_id).await,
        0,
        "the only edge between the communities was retracted; it must not produce \
         a cluster edge"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn run_theme_neighborhoods_ignore_retracted_edges(pool: PgPool) {
    let theme = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claim_themes (id, label, description, claim_count) VALUES ($1, 'T', '', 7)",
    )
    .bind(theme)
    .execute(&pool)
    .await
    .expect("theme");
    let (atoms, cross) = two_cliques(&pool, Some(theme)).await;
    // A compound in the same theme, decomposing into atoms[0].
    let a = agent(&pool).await;
    let compound = claim(&pool, a, Some(theme), "compound P").await;
    let decomposition = edge(&pool, compound, atoms[0], "decomposes_to").await;

    let cfg = Config {
        resolution: 1.0,
        skip_threshold_nodes: 0,
        skip_threshold_edges: 0,
    };
    let cfg = &cfg;
    let run = |label: &'static str| {
        let pool = pool.clone();
        async move {
            let run_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) \
                 VALUES ($1, 0, FALSE)",
            )
            .bind(run_id)
            .execute(&pool)
            .await
            .expect(label);
            run_theme_neighborhoods(&pool, run_id, cfg, Some(&[theme]))
                .await
                .expect(label);
            let edges: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM neighborhood_edges WHERE run_id = $1")
                    .bind(run_id)
                    .fetch_one(&pool)
                    .await
                    .expect("count neighborhood_edges");
            let members: Vec<Uuid> = sqlx::query_scalar(
                "SELECT claim_id FROM claim_neighborhood_membership WHERE run_id = $1",
            )
            .bind(run_id)
            .fetch_all(&pool)
            .await
            .expect("members");
            (edges, members)
        }
    };

    let (edges_before, members_before) = run("run 1").await;
    assert_eq!(
        edges_before, 1,
        "precondition: the in-force cross edge links the two neighborhoods"
    );
    assert!(
        !members_before.contains(&compound),
        "precondition: P has an in-force decomposes_to child, so it is not an atom"
    );

    EdgeRepository::retract(&pool, &[cross, decomposition])
        .await
        .expect("retract");
    let (edges_after, members_after) = run("run 2").await;
    assert_eq!(
        edges_after, 0,
        "the retracted cross edge must not produce a neighborhood edge"
    );
    assert!(
        members_after.contains(&compound),
        "P's only decomposition was retracted, so it is now a leaf and gets a \
         neighborhood like any other atom"
    );
}
