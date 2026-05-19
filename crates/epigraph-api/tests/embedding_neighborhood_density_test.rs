#![cfg(feature = "db")]

//! Integration test for POST /api/v1/embeddings/neighborhood-density.
//!
//! Seeds 5 claims with the MockProvider embedding of the query text (so the
//! handler's query vector matches them exactly when it embeds the same string)
//! plus 1 far claim, then asserts the endpoint reports n_claims >= 5, the
//! correct per-level breakdown, and a high mean similarity. The test
//! verifies SQL aggregation behaviour, not embedding generation.

use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn neighborhood_density_returns_count_and_breakdown() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    sqlx::query("DELETE FROM claims WHERE content LIKE 'density-test-%'")
        .execute(&pool)
        .await
        .unwrap();

    let agent_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000aa").unwrap();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type) \
         VALUES ($1, decode(repeat('AA', 32), 'hex'), 'density-test', 'system') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .execute(&pool)
    .await
    .unwrap();

    // Use MockProvider directly to compute the embedding the handler will use
    // when it embeds the same query string. Seeding rows with this exact
    // vector gives cosine distance 0 (similarity 1.0).
    let provider: Arc<dyn EmbeddingService> =
        Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)));
    let query_text = "density test near";
    let query_emb = provider.generate(query_text).await.unwrap();
    let query_str = format!(
        "[{}]",
        query_emb
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );

    // Seed 3 atoms (level=3) + 2 paragraphs (level=2) with the same embedding
    // as the mock query — distance is zero, similarity 1.0.
    for i in 0..5 {
        let level = if i < 3 { 3 } else { 2 };
        sqlx::query(
            "INSERT INTO claims (content, content_hash, agent_id, properties, embedding) \
             VALUES ($1, decode(md5($1) || md5($1), 'hex'), $2, \
                     jsonb_build_object('level', $3::text, 'source_type', 'Textbook'), \
                     $4::vector)",
        )
        .bind(format!("density-test-near-{i}"))
        .bind(agent_id)
        .bind(level.to_string())
        .bind(&query_str)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Far claim: an orthogonal vector so it won't be in the radius.
    let far_vec: Vec<f32> = (0..1536)
        .map(|i| if i >= 1500 { 1.0 } else { 0.0 })
        .collect();
    let norm: f32 = far_vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    let far_vec: Vec<f32> = far_vec.iter().map(|x| x / norm).collect();
    let far_str = format!(
        "[{}]",
        far_vec
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    sqlx::query(
        "INSERT INTO claims (content, content_hash, agent_id, properties, embedding) \
         VALUES ('density-test-far', decode(md5('density-test-far') || md5('density-test-far'), 'hex'), \
                 $1, '{}'::jsonb, $2::vector)",
    )
    .bind(agent_id)
    .bind(&far_str)
    .execute(&pool)
    .await
    .unwrap();

    let (addr, _shutdown) = common::spawn_app_with_mock_embedding(&url).await;
    let token = common::test_bearer_token_with_scopes(&["claims:read"]);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/embeddings/neighborhood-density"
        ))
        .bearer_auth(&token)
        .json(&json!({ "query": query_text, "radius": 0.3, "max_sample": 50 }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body_text = resp.text().await.unwrap_or_default();
    assert_eq!(
        status, 200,
        "endpoint should return 200; body: {body_text}"
    );
    let body: Value = serde_json::from_str(&body_text).expect("response body is JSON");
    let n = body["n_claims"].as_i64().expect("n_claims field");
    assert!(n >= 5, "expected >=5 near claims, got {n}; body: {body}");
    assert!(body["by_level"]["2"].as_i64().unwrap_or(0) >= 2);
    assert!(body["by_level"]["3"].as_i64().unwrap_or(0) >= 3);
    assert!(body["mean_similarity"].as_f64().unwrap_or(0.0) > 0.5);
}
