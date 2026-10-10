//! `cluster_graph::runner` clusters on `EPISTEMIC_RELATIONSHIPS`, which listed
//! only the upper-case `SUPPORTS` / `CONTRADICTS`. MCP `link_epistemic` writes
//! `supports` / `contradicts`, and the planned normalise-on-write and data fold
//! (U014 PR-2/PR-3, backlog 3ce5e00c) make every row lower case, so a clique
//! wired in lower case must cluster exactly like one wired in upper case.

use epigraph_jobs::cluster_graph::runner::{run_clustering, RunConfig};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'cluster-spelling', 'system', \
                 ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, pignistic_prob) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, 0.5) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn seed_edge(pool: &PgPool, s: Uuid, t: Uuid, rel: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3)",
    )
    .bind(s)
    .bind(t)
    .bind(rel)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {rel} edge: {e}"));
}

/// Clique A is wired in upper case (the control), clique B in lower case, and
/// one lower-case `contradicts` edge bridges them. Two clusters and one
/// inter-cluster edge is the answer whichever spelling each edge carries; a
/// reader blind to lower case sees clique A plus three singletons and no
/// bridge.
#[sqlx::test(migrations = "../../migrations")]
async fn lower_case_epistemic_edges_cluster_like_upper_case(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let mut a = Vec::new();
    let mut b = Vec::new();
    for i in 0..3 {
        a.push(seed_claim(&pool, agent, &format!("clique-a-{i}")).await);
        b.push(seed_claim(&pool, agent, &format!("clique-b-{i}")).await);
    }
    seed_edge(&pool, a[0], a[1], "SUPPORTS").await;
    seed_edge(&pool, a[0], a[2], "SUPPORTS").await;
    seed_edge(&pool, a[1], a[2], "CONTRADICTS").await;
    seed_edge(&pool, b[0], b[1], "supports").await;
    seed_edge(&pool, b[0], b[2], "supports").await;
    seed_edge(&pool, b[1], b[2], "contradicts").await;
    seed_edge(&pool, a[0], b[0], "contradicts").await;

    let summary = run_clustering(
        &pool,
        &RunConfig {
            resolution: 1.0,
            retain_runs: 3,
        },
    )
    .await
    .expect("run_clustering");

    assert!(!summary.degraded, "Louvain found real structure");
    assert_eq!(
        summary.cluster_count, 2,
        "the lower-case clique is one cluster, not three singletons"
    );

    let mut clusters = Vec::new();
    for clique in [&a, &b] {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT cluster_id FROM claim_cluster_membership \
              WHERE run_id = $1 AND claim_id = ANY($2)",
        )
        .bind(summary.run_id)
        .bind(clique)
        .fetch_all(&pool)
        .await
        .expect("membership");
        clusters.push(ids);
    }
    let (ca, cb) = (&clusters[0], &clusters[1]);
    assert_eq!(ca.len(), 1, "clique A shares one cluster");
    assert_eq!(cb.len(), 1, "clique B shares one cluster");
    assert_ne!(ca, cb, "the two cliques are different clusters");

    let bridge: Vec<i32> = sqlx::query_scalar("SELECT weight FROM cluster_edges WHERE run_id = $1")
        .bind(summary.run_id)
        .fetch_all(&pool)
        .await
        .expect("cluster_edges");
    assert_eq!(
        bridge,
        vec![1],
        "the lower-case contradicts bridge is the one inter-cluster edge"
    );
}
