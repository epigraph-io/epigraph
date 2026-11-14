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

/// Test that empty text returns error
#[tokio::test]
async fn test_embedding_empty_text_error() {
    let config = EmbeddingConfig::openai(1536);
    let provider = MockProvider::new(config);

    let result = provider.generate("").await;

    assert!(result.is_err(), "Should return error for empty text");
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
        require_packet_signatures: true,
        max_request_size: 2048,
        public_base_url: "http://localhost:8080".to_string(),
        ..ApiConfig::default()
    })
    .with_embedding_service(service)
    .with_rate_limiter(rate_limiter);

    // All settings should be preserved
    assert!(state.config.require_packet_signatures);
    assert_eq!(state.config.max_request_size, 2048);
    assert!(state.embedding_service.is_some());
    assert!(state.rate_limiter.is_some());
}
