#![cfg(feature = "db")]

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn themes_overview_returns_seeded_themes() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();
    sqlx::query("DELETE FROM claim_themes WHERE label IN ('A', 'B')").execute(&pool).await.unwrap();
    let theme_a = uuid::Uuid::new_v4();
    let theme_b = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claim_themes (id, label, description, claim_count) \
         VALUES ($1, 'A', '', 12), ($2, 'B', '', 7)"
    )
    .bind(theme_a).bind(theme_b).execute(&pool).await.unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/graph/themes/overview"))
        .header("Authorization", format!("Bearer {}", common::test_bearer_token()))
        .send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    let themes = body["themes"].as_array().unwrap();
    let by_label: std::collections::HashMap<String, &Value> = themes.iter()
        .filter_map(|t| t["label"].as_str().map(|l| (l.to_string(), t)))
        .collect();
    assert!(by_label.contains_key("A"), "expected theme A in response");
    assert!(by_label.contains_key("B"), "expected theme B in response");
    // Verify ordering by claim_count DESC: A(12) should come before B(7) in raw response.
    let order: Vec<i64> = themes.iter().filter_map(|t| t["claim_count"].as_i64()).collect();
    let mut sorted = order.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(order, sorted, "themes should be ordered by claim_count DESC");
}
