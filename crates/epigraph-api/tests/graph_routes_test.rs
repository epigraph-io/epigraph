#![cfg(feature = "db")]

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn overview_with_no_runs_returns_no_clusters_computed() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    sqlx::query("DELETE FROM graph_cluster_runs")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM cluster_edges")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM claim_cluster_membership")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM graph_clusters")
        .execute(&pool)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/api/v1/graph/overview"))
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

#[tokio::test(flavor = "multi_thread")]
async fn overview_returns_seeded_supernodes() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query("DELETE FROM graph_cluster_runs")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM cluster_edges")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM claim_cluster_membership")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM graph_clusters")
        .execute(&pool)
        .await
        .unwrap();
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
        .get(format!("http://{addr}/api/v1/graph/overview"))
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

#[tokio::test(flavor = "multi_thread")]
async fn expand_returns_cluster_members_with_induced_edges() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let cluster_id = common::seed_one_cluster(&pool, 5).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/graph/clusters/{cluster_id}/expand?budget=10"
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

#[tokio::test(flavor = "multi_thread")]
async fn expand_returns_404_for_unknown_cluster() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    // Need at least one run row so the handler reaches the per-cluster check (404
    // also happens when no run exists, but we want to specifically test the
    // "no such cluster in latest run" branch). seed_one_cluster sets that up.
    let _ = common::seed_one_cluster(&pool, 1).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let bogus = uuid::Uuid::new_v4();
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/graph/clusters/{bogus}/expand"
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
async fn neighborhood_returns_one_hop_seed_and_neighbors() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let seed = common::seed_three_node_chain(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/graph/neighborhood?node_id={seed}&hops=1&budget=20"
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
    let nodes = body["nodes"].as_array().unwrap();
    assert!(nodes.len() >= 2, "seed + at least one neighbor");
}

#[tokio::test(flavor = "multi_thread")]
async fn graph_endpoints_require_bearer() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;
    for path in [
        "/api/v1/graph/overview".to_string(),
        format!("/api/v1/graph/clusters/{}/expand", uuid::Uuid::new_v4()),
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
