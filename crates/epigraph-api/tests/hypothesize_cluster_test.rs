#![cfg(feature = "db")]

//! Verifies that hypothesize() with cluster_count=N returns N clusters of
//! similar claims with centroid summaries. Per spec
//! 2026-05-18-cross-source-anchor §Component 0b.

use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn hypothesize_returns_clusters_when_cluster_count_set() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    // Wipe both our own seeds and the density-test seeds from the other test
    // module — they share the test DB and the density seeds use the mock
    // embedding of a different query string but at high similarity, polluting
    // our cluster count.
    sqlx::query(
        "DELETE FROM claims WHERE content LIKE 'hyp-cluster-%' OR content LIKE 'density-test-%'",
    )
    .execute(&pool)
    .await
    .unwrap();

    let agent_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000aa").unwrap();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type) \
         VALUES ($1, decode(repeat('AA', 32), 'hex'), 'hyp-cluster-test', 'system') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .execute(&pool)
    .await
    .unwrap();

    // Compute the mock embedding the handler will use for the query string,
    // so seeded claims land inside the search radius. Then perturb half the
    // members along two orthogonal directions so k-means produces 2 clusters.
    let provider: Arc<dyn EmbeddingService> =
        Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)));
    let query_text = "hyp cluster test";
    let base = provider.generate(query_text).await.unwrap();

    for i in 0..20 {
        let cluster_a = i < 10;
        // Small perturbation: nudge cluster A toward axis 0..8, cluster B
        // toward axis 1500..1508. Magnitude small enough to keep cosine
        // similarity ≥ 0.8 (well within search_radius=0.5).
        let mut v = base.clone();
        let nudge = 0.05f32 * ((i % 10) as f32 + 1.0) / 10.0;
        if cluster_a {
            for j in 0..8 {
                v[j] += nudge;
            }
        } else {
            for j in 1500..1508 {
                v[j] += nudge;
            }
        }
        let vstr = format!(
            "[{}]",
            v.iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        sqlx::query(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value, is_current, properties, embedding) \
             VALUES ($1, decode(md5($1) || md5($1), 'hex'), $2, $3, true, '{}'::jsonb, $4::vector)",
        )
        .bind(format!("hyp-cluster-{i}"))
        .bind(agent_id)
        .bind(if cluster_a { 0.8 } else { 0.4 })
        .bind(&vstr)
        .execute(&pool)
        .await
        .unwrap();
    }

    let (addr, _shutdown) = common::spawn_app_with_mock_embedding(&url).await;
    let token = common::test_bearer_token_with_scopes(&["claims:read"]);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/experiments/hypothesize"))
        .bearer_auth(&token)
        .json(&json!({ "statement": "hyp cluster test", "search_radius": 0.2, "cluster_count": 2 }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body_text = resp.text().await.unwrap_or_default();
    assert_eq!(status, 200, "expected 200; body: {body_text}");
    let body: Value = serde_json::from_str(&body_text).expect("response is JSON");

    let clusters = body["clusters"].as_array().expect("clusters field present");
    assert_eq!(
        clusters.len(),
        2,
        "expected 2 clusters, got {}; body: {body}",
        clusters.len()
    );
    for c in clusters {
        assert!(c["claim_ids"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false));
        assert!(c["centroid_summary"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false));
        assert!(c["mean_prior_belief"].as_f64().is_some());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hypothesize_without_cluster_count_omits_clusters_field() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let _pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app_with_mock_embedding(&url).await;
    let token = common::test_bearer_token_with_scopes(&["claims:read"]);

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/experiments/hypothesize"))
        .bearer_auth(&token)
        .json(&json!({ "statement": "anything", "search_radius": 0.5 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();

    assert!(
        body.get("clusters").is_none() || body["clusters"].is_null(),
        "clusters field must not appear when cluster_count is absent"
    );
}
