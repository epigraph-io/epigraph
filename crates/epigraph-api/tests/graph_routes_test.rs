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
