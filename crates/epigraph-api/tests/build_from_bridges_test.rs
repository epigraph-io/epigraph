#![cfg(feature = "db")]

//! Integration test for `POST /api/v1/clusters/build-from-bridges` (Phase 5.B).
//!
//! Seeds 5 paragraph-level claims (level=2) and a set of atom-level children
//! such that:
//!   - paragraphs 1+2 share 2 atoms (bridge weight = 2)
//!   - paragraphs 3+4 share 1 atom (bridge weight = 1)
//!   - paragraph 5 is isolated (no atoms shared with the rest)
//!
//! Asserts cluster_count, paragraph_count, bridge_edge_count, and persistence
//! invariants on the run row + memberships.

use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn build_from_bridges_clusters_paragraphs() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();

    // Wipe cluster fixture state. We DELETE memberships before runs to avoid
    // FK trouble with `claim_cluster_membership.cluster_id → graph_clusters`.
    // We also wipe neighborhood tables if present, since they FK back to runs.
    let _ = sqlx::query("DELETE FROM neighborhood_edges")
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM claim_neighborhood_membership")
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM graph_neighborhoods")
        .execute(&pool)
        .await;
    sqlx::query("DELETE FROM claim_cluster_membership")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM cluster_edges")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM graph_clusters")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM graph_cluster_runs")
        .execute(&pool)
        .await
        .unwrap();

    // The test DB (`epigraph_5b_test`) is dedicated to this Phase-5.B test.
    // Wipe all bridge-relevant data from prior runs: decomposes_to edges and
    // every claim that was tagged as paragraph (level=2) or atom (level=3).
    sqlx::query("DELETE FROM edges WHERE relationship = 'decomposes_to'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM claims WHERE (properties->>'level')::int IN (2, 3)")
        .execute(&pool)
        .await
        .unwrap();
    let agent_id = Uuid::parse_str("00000000-0000-0000-0000-0000000000dd").unwrap();

    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type) \
         VALUES ($1, decode(repeat('DD', 32), 'hex'), 'bridge-test', 'system') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .execute(&pool)
    .await
    .unwrap();

    // Helper: insert a claim with a level marker in `properties`.
    async fn ins_claim(pool: &sqlx::PgPool, content: &str, agent: Uuid, level: i32) -> Uuid {
        let id = Uuid::new_v4();
        let hash: Vec<u8> = id
            .as_bytes()
            .iter()
            .chain(id.as_bytes().iter())
            .copied()
            .collect();
        let props = serde_json::json!({"level": level});
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, pignistic_prob, properties) \
             VALUES ($1, $2, $3, $4, 0.5, $5)",
        )
        .bind(id)
        .bind(content)
        .bind(hash)
        .bind(agent)
        .bind(&props)
        .execute(pool)
        .await
        .unwrap();
        id
    }
    async fn ins_decomposes(pool: &sqlx::PgPool, parent: Uuid, child: Uuid) {
        sqlx::query(
            "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship) \
             VALUES ($1, $2, 'claim', 'claim', 'decomposes_to')",
        )
        .bind(parent)
        .bind(child)
        .execute(pool)
        .await
        .unwrap();
    }

    // 5 paragraph-level claims (level=2). One of them is a bridge isolate.
    let p1 = ins_claim(&pool, "paragraph-1", agent_id, 2).await;
    let p2 = ins_claim(&pool, "paragraph-2", agent_id, 2).await;
    let p3 = ins_claim(&pool, "paragraph-3", agent_id, 2).await;
    let p4 = ins_claim(&pool, "paragraph-4", agent_id, 2).await;
    let p5 = ins_claim(&pool, "paragraph-5", agent_id, 2).await;

    // Atoms (level=3). Some are shared between paragraphs.
    let a_shared_12_x = ins_claim(&pool, "atom-shared-12-x", agent_id, 3).await;
    let a_shared_12_y = ins_claim(&pool, "atom-shared-12-y", agent_id, 3).await;
    let a_shared_34 = ins_claim(&pool, "atom-shared-34", agent_id, 3).await;
    let a_p1_only = ins_claim(&pool, "atom-p1-only", agent_id, 3).await;
    let a_p2_only = ins_claim(&pool, "atom-p2-only", agent_id, 3).await;
    let a_p3_only = ins_claim(&pool, "atom-p3-only", agent_id, 3).await;
    let a_p4_only = ins_claim(&pool, "atom-p4-only", agent_id, 3).await;
    let a_p5_only_a = ins_claim(&pool, "atom-p5-only-a", agent_id, 3).await;
    let a_p5_only_b = ins_claim(&pool, "atom-p5-only-b", agent_id, 3).await;
    let a_p5_only_c = ins_claim(&pool, "atom-p5-only-c", agent_id, 3).await;

    // p1 children: shared_12_x, shared_12_y, p1_only
    ins_decomposes(&pool, p1, a_shared_12_x).await;
    ins_decomposes(&pool, p1, a_shared_12_y).await;
    ins_decomposes(&pool, p1, a_p1_only).await;

    // p2 children: shared_12_x, shared_12_y, p2_only — shares 2 atoms with p1
    ins_decomposes(&pool, p2, a_shared_12_x).await;
    ins_decomposes(&pool, p2, a_shared_12_y).await;
    ins_decomposes(&pool, p2, a_p2_only).await;

    // p3 children: shared_34, p3_only
    ins_decomposes(&pool, p3, a_shared_34).await;
    ins_decomposes(&pool, p3, a_p3_only).await;

    // p4 children: shared_34, p4_only — shares 1 atom with p3
    ins_decomposes(&pool, p4, a_shared_34).await;
    ins_decomposes(&pool, p4, a_p4_only).await;

    // p5 children: 3 unique atoms, no overlap → isolated
    ins_decomposes(&pool, p5, a_p5_only_a).await;
    ins_decomposes(&pool, p5, a_p5_only_b).await;
    ins_decomposes(&pool, p5, a_p5_only_c).await;

    // Spin up the app and call the endpoint.
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let body = json!({
        "min_shared_atoms": 1,
        "resolution": 1.0,
        "retain_runs": 5
    });
    let token = common::test_bearer_token_with_scopes(&["claims:admin"]);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/clusters/build-from-bridges"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "build_from_bridges should return 200"
    );
    let resp_json: Value = resp.json().await.unwrap();

    let cluster_count = resp_json["cluster_count"].as_u64().unwrap() as usize;
    let paragraph_count = resp_json["paragraph_count"].as_u64().unwrap() as usize;
    let bridge_edge_count = resp_json["bridge_edge_count"].as_u64().unwrap() as usize;
    let run_id_str = resp_json["run_id"].as_str().unwrap();
    let run_id = Uuid::parse_str(run_id_str).unwrap();

    // Bridge graph contains exactly two edges: (p1,p2) weight 2 and (p3,p4)
    // weight 1. p5 has no shared atoms so it has no bridge edges.
    assert_eq!(
        bridge_edge_count, 2,
        "expected 2 bridge edges (p1↔p2, p3↔p4); got {bridge_edge_count}"
    );

    // All 5 paragraphs are nodes in the bridge graph because each has at
    // least one decomposes_to atom child. p5 is a singleton node with no
    // bridge edges; the other 4 form two pair-clusters.
    assert_eq!(
        paragraph_count, 5,
        "expected 5 paragraph nodes (incl. p5 isolate); got {paragraph_count}"
    );

    // Three components → three clusters: {p1, p2}, {p3, p4}, {p5}.
    assert_eq!(
        cluster_count, 3,
        "expected 3 clusters: {{p1,p2}}, {{p3,p4}}, {{p5}}; got {cluster_count}"
    );

    // Run row landed with algo='louvain_bridge'.
    let runs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM graph_cluster_runs WHERE algo = 'louvain_bridge' AND run_id = $1",
    )
    .bind(run_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(runs, 1, "run row missing or wrong algo");

    // Memberships persisted: one row per paragraph node.
    let memberships: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claim_cluster_membership WHERE run_id = $1")
            .bind(run_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(memberships, 5, "expected 5 membership rows");

    // p1 and p2 share a cluster; p3 and p4 share a different cluster; p5 has
    // its own cluster distinct from both pairs.
    async fn cluster_of(pool: &sqlx::PgPool, run_id: Uuid, claim_id: Uuid) -> Option<Uuid> {
        sqlx::query_scalar(
            "SELECT cluster_id FROM claim_cluster_membership WHERE run_id = $1 AND claim_id = $2",
        )
        .bind(run_id)
        .bind(claim_id)
        .fetch_optional(pool)
        .await
        .unwrap()
    }
    let c_p1 = cluster_of(&pool, run_id, p1).await.expect("p1 has cluster");
    let c_p2 = cluster_of(&pool, run_id, p2).await.expect("p2 has cluster");
    let c_p3 = cluster_of(&pool, run_id, p3).await.expect("p3 has cluster");
    let c_p4 = cluster_of(&pool, run_id, p4).await.expect("p4 has cluster");
    let c_p5 = cluster_of(&pool, run_id, p5).await.expect("p5 has cluster");
    assert_eq!(c_p1, c_p2, "p1 and p2 should share a bridge cluster");
    assert_eq!(c_p3, c_p4, "p3 and p4 should share a bridge cluster");
    assert_ne!(c_p1, c_p3, "p1 and p3 must be in different bridge clusters");
    assert_ne!(c_p1, c_p5, "p5 must be in its own cluster");
    assert_ne!(c_p3, c_p5, "p5 must be in its own cluster");
}
