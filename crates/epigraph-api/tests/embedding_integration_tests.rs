//! Integration tests for embedding service in semantic search
//!
//! These tests verify that the embedding service is properly integrated
//! into the API state and handlers.

use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};

/// Test that AppState can be created without an embedding service (backward compatibility)
///
/// Only runs when `db` feature is disabled — with `db` enabled, AppState::new()
/// requires a PgPool, so this test cannot construct the state directly.
#[cfg(not(feature = "db"))]
#[test]
fn test_app_state_without_embedding_service() {
    let state = AppState::new(ApiConfig::default());
    assert!(state.embedding_service.is_none());
}

/// Test that embedding service can be added to AppState via builder
///
/// Only runs when `db` feature is disabled — see above.
#[cfg(not(feature = "db"))]
#[test]
fn test_app_state_with_embedding_service() {
    let config = EmbeddingConfig::openai(1536);
    let provider = MockProvider::new(config);
    let service: Arc<dyn EmbeddingService> = Arc::new(provider);

    let state = AppState::new(ApiConfig::default()).with_embedding_service(service.clone());

    assert!(state.embedding_service.is_some());
    assert_eq!(state.embedding_service().unwrap().dimension(), 1536);
}

/// Test that embedding service getter works correctly
///
/// Only runs when `db` feature is disabled — see above.
#[cfg(not(feature = "db"))]
#[test]
fn test_embedding_service_getter() {
    // Without service
    let state = AppState::new(ApiConfig::default());
    assert!(state.embedding_service().is_none());

    // With service
    let config = EmbeddingConfig::openai(1536);
    let provider = MockProvider::new(config);
    let service: Arc<dyn EmbeddingService> = Arc::new(provider);

    let state_with_service = AppState::new(ApiConfig::default()).with_embedding_service(service);
    assert!(state_with_service.embedding_service().is_some());
}

/// Test that MockProvider can generate embeddings
#[tokio::test]
async fn test_mock_provider_generates_embeddings() {
    let config = EmbeddingConfig::openai(1536);
    let provider = MockProvider::new(config);

    let embedding = provider.generate("test query").await.unwrap();

    assert_eq!(embedding.len(), 1536);

    // Verify embedding is normalized (magnitude should be close to 1)
    let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!(
        (magnitude - 1.0).abs() < 0.001,
        "Embedding should be normalized"
    );
}

/// Test that similar queries produce similar embeddings
#[tokio::test]
async fn test_similar_queries_produce_similar_embeddings() {
    let config = EmbeddingConfig::openai(1536);
    let provider = MockProvider::new(config);

    let embedding1 = provider.generate("climate change effects").await.unwrap();
    let embedding2 = provider
        .generate("climate change effects on agriculture")
        .await
        .unwrap();
    let embedding3 = provider.generate("quantum computing").await.unwrap();

    // Calculate cosine similarity
    fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let mag_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let mag_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        dot / (mag_a * mag_b)
    }

    let sim_12 = cosine_similarity(&embedding1, &embedding2);
    let sim_13 = cosine_similarity(&embedding1, &embedding3);

    // Similar queries should have higher similarity than dissimilar ones
    // Note: MockProvider creates deterministic embeddings based on text bytes,
    // so overlapping text should produce somewhat similar embeddings
    assert!(
        sim_12 > sim_13,
        "Similar queries should produce more similar embeddings. sim_12={}, sim_13={}",
        sim_12,
        sim_13
    );
}

/// Test that embedding service can store and retrieve embeddings
#[tokio::test]
async fn test_embedding_store_and_retrieve() {
    let config = EmbeddingConfig::openai(1536);
    let provider = MockProvider::new(config);

    let claim_id = uuid::Uuid::new_v4();
    let embedding = provider.generate("test claim content").await.unwrap();

    // Store the embedding
    provider.store(claim_id, &embedding).await.unwrap();

    // Retrieve it back
    let retrieved = provider.get(claim_id).await.unwrap();

    assert_eq!(embedding.len(), retrieved.len());
    for (a, b) in embedding.iter().zip(retrieved.iter()) {
        assert!(
            (a - b).abs() < 0.0001,
            "Retrieved embedding should match stored"
        );
    }
}

/// Test that embedding service returns error for non-existent claim
#[tokio::test]
async fn test_embedding_get_nonexistent_returns_error() {
    let config = EmbeddingConfig::openai(1536);
    let provider = MockProvider::new(config);

    let claim_id = uuid::Uuid::new_v4();
    let result = provider.get(claim_id).await;

    assert!(
        result.is_err(),
        "Should return error for non-existent claim"
    );
}

/// Test that empty text returns error
#[tokio::test]
async fn test_embedding_empty_text_error() {
    let config = EmbeddingConfig::openai(1536);
    let provider = MockProvider::new(config);

    let result = provider.generate("").await;

    assert!(result.is_err(), "Should return error for empty text");
}

/// Test that similar claims can be found by embedding
#[tokio::test]
async fn test_embedding_similarity_search() {
    let config = EmbeddingConfig::openai(1536);
    let provider = MockProvider::new(config);

    // Store some claims with embeddings
    let claim1_id = uuid::Uuid::new_v4();
    let claim2_id = uuid::Uuid::new_v4();
    let claim3_id = uuid::Uuid::new_v4();

    let emb1 = provider.generate("The Earth is round").await.unwrap();
    let emb2 = provider.generate("The Earth is a sphere").await.unwrap();
    let emb3 = provider.generate("Quantum entanglement").await.unwrap();

    provider.store(claim1_id, &emb1).await.unwrap();
    provider.store(claim2_id, &emb2).await.unwrap();
    provider.store(claim3_id, &emb3).await.unwrap();

    // Search for similar to "Earth shape"
    let query_embedding = provider.generate("shape of Earth").await.unwrap();
    let similar = provider.similar(&query_embedding, 10, 0.0).await.unwrap();

    assert!(!similar.is_empty(), "Should find similar claims");

    // The Earth-related claims should have higher similarity than quantum claim
    let earth_ids: std::collections::HashSet<_> = [claim1_id, claim2_id].into_iter().collect();

    // At least one Earth-related claim should be in the top results
    let has_earth_claim = similar.iter().any(|s| earth_ids.contains(&s.claim_id));
    assert!(
        has_earth_claim,
        "Should find Earth-related claims as similar"
    );
}

/// Test dimension configuration
#[test]
fn test_embedding_config_dimension() {
    let config_1536 = EmbeddingConfig::openai(1536);
    let config_384 = EmbeddingConfig::local(384);

    assert_eq!(config_1536.dimension, 1536);
    assert_eq!(config_384.dimension, 384);
}

/// Test that builder pattern preserves state correctly
///
/// Only runs when `db` feature is disabled — see above.
#[cfg(not(feature = "db"))]
#[test]
fn test_builder_pattern_preserves_state() {
    use epigraph_api::{AgentRateLimiter, RateLimitConfig};

    let config = EmbeddingConfig::openai(1536);
    let provider = MockProvider::new(config);
    let service: Arc<dyn EmbeddingService> = Arc::new(provider);

    let rate_limiter = AgentRateLimiter::new(RateLimitConfig {
        default_rpm: 60,
        global_rpm: 1000,
        replenish_interval_secs: 1,
        enable_global_limit: true,
    });

    let state = AppState::new(ApiConfig {
        require_signatures: true,
        max_request_size: 2048,
    })
    .with_embedding_service(service)
    .with_rate_limiter(rate_limiter);

    // All settings should be preserved
    assert!(state.config.require_signatures);
    assert_eq!(state.config.max_request_size, 2048);
    assert!(state.embedding_service.is_some());
    assert!(state.rate_limiter.is_some());
}
