#![cfg(feature = "db")]

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn themes_overview_returns_seeded_themes() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query("DELETE FROM claim_themes WHERE label IN ('A', 'B')")
        .execute(&pool)
        .await
        .unwrap();
    let theme_a = uuid::Uuid::new_v4();
    let theme_b = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claim_themes (id, label, description, claim_count) \
         VALUES ($1, 'A', '', 12), ($2, 'B', '', 7)",
    )
    .bind(theme_a)
    .bind(theme_b)
    .execute(&pool)
    .await
    .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/graph/themes/overview"))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    let themes = body["themes"].as_array().unwrap();
    let by_label: std::collections::HashMap<String, &Value> = themes
        .iter()
        .filter_map(|t| t["label"].as_str().map(|l| (l.to_string(), t)))
        .collect();
    assert!(by_label.contains_key("A"), "expected theme A in response");
    assert!(by_label.contains_key("B"), "expected theme B in response");
    // Verify ordering by claim_count DESC: A(12) should come before B(7) in raw response.
    let order: Vec<i64> = themes
        .iter()
        .filter_map(|t| t["claim_count"].as_i64())
        .collect();
    let mut sorted = order.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(
        order, sorted,
        "themes should be ordered by claim_count DESC"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn themes_expand_returns_neighborhoods_for_seeded_theme() {
    use uuid::Uuid;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    // Clean local fixture rows.
    sqlx::query("DELETE FROM neighborhood_edges")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM claim_neighborhood_membership")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM graph_neighborhoods")
        .execute(&pool)
        .await
        .unwrap();

    // Inline minimal seed: agent + run + theme + 2 atoms + 1 edge.
    let agent_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000bb").unwrap();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type) \
         VALUES ($1, decode(repeat('BB', 32), 'hex'), 'themes-expand-test', 'system') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .execute(&pool)
    .await
    .unwrap();

    let run_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 0, FALSE)",
    )
    .bind(run_id)
    .execute(&pool)
    .await
    .unwrap();

    let theme_id = Uuid::new_v4();
    sqlx::query("INSERT INTO claim_themes (id, label, description, claim_count) VALUES ($1, 'Expand', '', 2)")
        .bind(theme_id).execute(&pool).await.unwrap();

    let claim_a = Uuid::new_v4();
    let claim_b = Uuid::new_v4();
    for (id, content) in [(claim_a, "atom-a"), (claim_b, "atom-b")] {
        let hash: Vec<u8> = id
            .as_bytes()
            .iter()
            .chain(id.as_bytes().iter())
            .copied()
            .collect();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, pignistic_prob, theme_id) \
             VALUES ($1, $2, $3, $4, 0.5, $5)",
        )
        .bind(id)
        .bind(content)
        .bind(hash)
        .bind(agent_id)
        .bind(theme_id)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Seed two neighborhoods directly (skip Louvain for fast unit-test scope).
    let nbr_a = Uuid::new_v4();
    let nbr_b = Uuid::new_v4();
    for (id, label, size) in [(nbr_a, "nbr-a", 1_i32), (nbr_b, "nbr-b", 1_i32)] {
        sqlx::query(
            "INSERT INTO graph_neighborhoods (id, run_id, theme_id, label, size, mean_betp, dominant_frame_id) \
             VALUES ($1, $2, $3, $4, $5, NULL, NULL)"
        )
        .bind(id).bind(run_id).bind(theme_id).bind(label).bind(size)
        .execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) VALUES ($1, $2, $3)")
        .bind(run_id).bind(claim_a).bind(nbr_a).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) VALUES ($1, $2, $3)")
        .bind(run_id).bind(claim_b).bind(nbr_b).execute(&pool).await.unwrap();

    // Inter-neighborhood edge — store canonical (a < b).
    let (lo, hi) = if nbr_a < nbr_b {
        (nbr_a, nbr_b)
    } else {
        (nbr_b, nbr_a)
    };
    sqlx::query(
        "INSERT INTO neighborhood_edges (run_id, neighborhood_a, neighborhood_b, weight) \
         VALUES ($1, $2, $3, 0.7)",
    )
    .bind(run_id)
    .bind(lo)
    .bind(hi)
    .execute(&pool)
    .await
    .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/graph/themes/{theme_id}/expand"
        ))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "themes/expand should return 200"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["theme_id"].as_str().unwrap(), theme_id.to_string());
    let nbrs = body["neighborhoods"].as_array().unwrap();
    assert_eq!(
        nbrs.len(),
        2,
        "expected exactly 2 neighborhoods for the seeded theme"
    );
    let edges = body["neighborhood_edges"].as_array().unwrap();
    assert_eq!(edges.len(), 1, "expected one inter-neighborhood edge");
    assert!((edges[0]["weight"].as_f64().unwrap() - 0.7).abs() < 1e-9);
}
