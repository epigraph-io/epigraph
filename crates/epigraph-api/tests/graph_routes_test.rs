#![cfg(feature = "db")]

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn overview_with_no_runs_returns_no_clusters_computed() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();

    sqlx::query("DELETE FROM graph_cluster_runs").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM cluster_edges").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM claim_cluster_membership").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM graph_clusters").execute(&pool).await.unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/api/v1/graph/overview"))
        .header("Authorization", format!("Bearer {}", common::test_bearer_token()))
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
    let pool = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();
    sqlx::query("DELETE FROM graph_cluster_runs").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM cluster_edges").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM claim_cluster_membership").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM graph_clusters").execute(&pool).await.unwrap();
    let run_id = uuid::Uuid::new_v4();
    let c1 = uuid::Uuid::new_v4();
    let c2 = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO graph_clusters (id, run_id, label, size, mean_betp, dominant_type, dominant_frame_id, degraded) VALUES ($1, $2, 'A', 5, 0.7, 'claim', NULL, FALSE), ($3, $2, 'B', 3, 0.4, 'claim', NULL, FALSE)")
        .bind(c1).bind(run_id).bind(c2)
        .execute(&pool).await.unwrap();
    let (lo, hi) = if c1 < c2 { (c1, c2) } else { (c2, c1) };
    sqlx::query("INSERT INTO cluster_edges (run_id, cluster_a, cluster_b, weight) VALUES ($1, $2, $3, 4)")
        .bind(run_id).bind(lo).bind(hi)
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 2, FALSE)")
        .bind(run_id).execute(&pool).await.unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/graph/overview"))
        .header("Authorization", format!("Bearer {}", common::test_bearer_token()))
        .send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["supernodes"].as_array().unwrap().len(), 2);
    assert_eq!(body["cluster_edges"].as_array().unwrap().len(), 1);
    assert_eq!(body["cluster_edges"][0]["weight"], 4);
    assert_eq!(body["degraded"], false);
}
