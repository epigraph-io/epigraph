#![cfg(feature = "db")]
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn find_workflow_hierarchical_resolve_to_latest_includes_resolved_steps() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    // Seed a workflow row in the workflows table; the search filters on goal/canonical_name ILIKE.
    // The workflows table has columns: id, canonical_name, goal, generation, parent_id, metadata, created_at.
    let workflow_id = Uuid::new_v4();
    let unique_goal = format!("resolve_test_goal_{workflow_id}");
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal, generation, metadata) \
         VALUES ($1, $2, $3, 0, '{}'::jsonb)",
    )
    .bind(workflow_id)
    .bind(format!("test_workflow_{workflow_id}"))
    .bind(&unique_goal)
    .execute(&pool)
    .await
    .expect("seed workflow");

    let (addr, _shutdown) = common::spawn_app(&url).await;

    // Default: resolve_to_latest=false → no resolved_steps key.
    let resp_default: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/workflows/hierarchical/search?q={unique_goal}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp_default["resolve_to_latest"], serde_json::json!(false));
    assert!(resp_default["workflows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|w| w.get("resolved_steps").is_none()));

    // resolve_to_latest=true → each workflow has a resolved_steps array.
    let resp_resolved: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/workflows/hierarchical/search?q={unique_goal}&resolve_to_latest=true"))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(resp_resolved["resolve_to_latest"], serde_json::json!(true));
    let workflows = resp_resolved["workflows"].as_array().unwrap();
    assert!(!workflows.is_empty(), "search should find seeded workflow");
    assert!(
        workflows.iter().all(|w| w["resolved_steps"].is_array()),
        "every workflow must have resolved_steps array when resolve_to_latest=true"
    );
}
