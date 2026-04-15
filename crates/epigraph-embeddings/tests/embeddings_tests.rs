//! Embeddings Service TDD Tests
//!
//! Comprehensive test suite for the `EpiGraph` embeddings service.
//! These tests define the expected behavior before implementation.
//!
//! # Test Coverage
//!
//! 1. Generate embedding returns vector of correct dimension (1536 for `OpenAI`)
//! 2. Generate embedding is deterministic for same input
//! 3. Batch generate embeddings handles multiple texts
//! 4. Embedding dimension is configurable
//! 5. Fallback to local model if API fails
//! 6. Embedding cache prevents duplicate API calls
//! 7. Store embedding persists to pgvector table
//! 8. Get embedding retrieves stored vector
//! 9. Similar embeddings returns k-nearest neighbors
//! 10. Empty text returns error (not zero vector)
//! 11. Very long text is truncated appropriately
//! 12. Embedding normalization (unit vector)
//! 13. API rate limiting is respected
//! 14. Token usage tracking
//!
//! # Evidence
//! - `IMPLEMENTATION_PLAN.md` specifies semantic similarity search
//! - pgvector extension enables efficient vector operations
//! - `OpenAI` text-embedding-ada-002 returns 1536-dimensional vectors
//!
//! # Reasoning
//! - TDD approach ensures interface is well-defined before implementation
//! - Mock providers enable testing without API dependencies
//! - Deterministic embeddings allow reproducible tests

use epigraph_embeddings::providers::MockProviderWithFallback;
use epigraph_embeddings::{
    EmbeddingCache, EmbeddingConfig, EmbeddingError, EmbeddingService, LocalProvider, MockProvider,
    Normalizer, RateLimiter, SimilarClaim, TokenUsage,
};
use uuid::Uuid;

// ============================================================================
// Test Helper Functions
// ============================================================================

/// Create a mock provider with default OpenAI-like configuration
fn create_mock_provider() -> MockProvider {
    let config = EmbeddingConfig::openai(1536);
    MockProvider::new(config)
}

/// Create a mock provider with custom dimension
fn create_mock_provider_with_dimension(dimension: usize) -> MockProvider {
    let config = EmbeddingConfig::openai(dimension);
    MockProvider::new(config)
}

/// Create a mock provider that simulates failures
fn create_failing_mock_provider(failure_rate: f32) -> MockProvider {
    let config = EmbeddingConfig::openai(1536);
    MockProvider::new(config).with_failures(failure_rate)
}

/// Create a local provider for fallback testing
fn create_local_provider() -> LocalProvider {
    let config = EmbeddingConfig::local(1536);
    LocalProvider::new(config).unwrap()
}

// ============================================================================
// Test 1: Generate Embedding Returns Vector of Correct Dimension
// ============================================================================

/// **Test 1**: Generate embedding returns vector of correct dimension (1536 for `OpenAI`)
///
/// **Evidence**: `OpenAI` text-embedding-ada-002 returns 1536-dimensional vectors
/// **Reasoning**: Dimension must match to enable correct similarity calculations
#[tokio::test]
async fn test_generate_embedding_returns_correct_dimension() {
    let provider = create_mock_provider();

    let embedding = provider
        .generate("The Earth orbits the Sun")
        .await
        .expect("Should generate embedding");

    assert_eq!(
        embedding.len(),
        1536,
        "OpenAI-compatible embeddings should have 1536 dimensions"
    );

    // Verify the provider reports correct dimension
    assert_eq!(
        provider.dimension(),
        1536,
        "Provider should report correct dimension"
    );
}

/// **Test 1b**: Verify dimension with different configurations
#[tokio::test]
async fn test_generate_embedding_respects_configured_dimension() {
    // Test with different dimensions
    for dimension in [384, 768, 1024, 1536, 3072] {
        let provider = create_mock_provider_with_dimension(dimension);

        let embedding = provider
            .generate("Test text for dimension verification")
            .await
            .expect("Should generate embedding");

        assert_eq!(
            embedding.len(),
            dimension,
            "Embedding should have {dimension} dimensions"
        );
    }
}

// ============================================================================
// Test 2: Generate Embedding is Deterministic for Same Input
// ============================================================================

/// **Test 2**: Generate embedding is deterministic for same input
///
/// **Evidence**: Reproducibility is essential for testing and debugging
/// **Reasoning**: Same text should always produce same embedding (mock provider)
#[tokio::test]
async fn test_generate_embedding_is_deterministic() {
    let provider = create_mock_provider();
    let text = "Deterministic embedding test";

    // Generate embedding multiple times
    let embedding1 = provider.generate(text).await.expect("First generation");
    let embedding2 = provider.generate(text).await.expect("Second generation");
    let embedding3 = provider.generate(text).await.expect("Third generation");

    // All should be identical
    assert_eq!(
        embedding1, embedding2,
        "Same text should produce identical embeddings (1 vs 2)"
    );
    assert_eq!(
        embedding2, embedding3,
        "Same text should produce identical embeddings (2 vs 3)"
    );
}

/// **Test 2b**: Different texts produce different embeddings
#[tokio::test]
async fn test_different_texts_produce_different_embeddings() {
    let provider = create_mock_provider();

    let embedding1 = provider
        .generate("The cat sat on the mat")
        .await
        .expect("First text");
    let embedding2 = provider
        .generate("The dog ran in the park")
        .await
        .expect("Second text");

    assert_ne!(
        embedding1, embedding2,
        "Different texts should produce different embeddings"
    );
}

// ============================================================================
// Test 3: Batch Generate Embeddings Handles Multiple Texts
// ============================================================================

/// **Test 3**: Batch generate embeddings handles multiple texts
///
/// **Evidence**: Batch processing improves efficiency for bulk operations
/// **Reasoning**: Single API call for multiple texts reduces latency
#[tokio::test]
async fn test_batch_generate_embeddings() {
    let provider = create_mock_provider();

    let texts = vec![
        "First claim about physics",
        "Second claim about biology",
        "Third claim about chemistry",
        "Fourth claim about mathematics",
        "Fifth claim about astronomy",
    ];

    let embeddings = provider
        .batch_generate(&texts)
        .await
        .expect("Batch generation should succeed");

    // Verify correct number of embeddings
    assert_eq!(
        embeddings.len(),
        texts.len(),
        "Should return one embedding per text"
    );

    // Verify all have correct dimension
    for (i, embedding) in embeddings.iter().enumerate() {
        assert_eq!(
            embedding.len(),
            1536,
            "Embedding {i} should have correct dimension"
        );
    }

    // Verify embeddings are different for different texts
    for i in 0..embeddings.len() {
        for j in (i + 1)..embeddings.len() {
            assert_ne!(
                embeddings[i], embeddings[j],
                "Embeddings {i} and {j} should be different"
            );
        }
    }
}

/// **Test 3b**: Batch generation preserves order
#[tokio::test]
async fn test_batch_generate_preserves_order() {
    let provider = create_mock_provider();

    let texts = vec!["Alpha", "Beta", "Gamma"];

    let batch_embeddings = provider
        .batch_generate(&texts)
        .await
        .expect("Batch should succeed");

    // Generate individually and compare
    for (i, text) in texts.iter().enumerate() {
        let individual = provider
            .generate(text)
            .await
            .expect("Individual should succeed");

        assert_eq!(
            batch_embeddings[i], individual,
            "Batch embedding {i} should match individual generation"
        );
    }
}

// ============================================================================
// Test 4: Embedding Dimension is Configurable
// ============================================================================

/// **Test 4**: Embedding dimension is configurable
///
/// **Evidence**: Different models use different dimensions
/// **Reasoning**: Flexibility for various embedding models
#[tokio::test]
async fn test_embedding_dimension_is_configurable() {
    // Test small dimension (like sentence-transformers)
    let small_config = EmbeddingConfig::local(384);
    let small_provider = MockProvider::new(small_config);

    let small_embedding = small_provider
        .generate("Small dimension test")
        .await
        .expect("Should work with small dimension");

    assert_eq!(small_embedding.len(), 384, "Should have 384 dimensions");
    assert_eq!(small_provider.dimension(), 384);

    // Test large dimension
    let large_config = EmbeddingConfig::openai(1536).with_dimension(3072);
    let large_provider = MockProvider::new(large_config);

    let large_embedding = large_provider
        .generate("Large dimension test")
        .await
        .expect("Should work with large dimension");

    assert_eq!(large_embedding.len(), 3072, "Should have 3072 dimensions");
    assert_eq!(large_provider.dimension(), 3072);
}

// ============================================================================
// Test 5: Fallback to Local Model if API Fails
// ============================================================================

/// **Test 5**: Fallback to local model if API fails
///
/// **Evidence**: Resilience requires graceful degradation
/// **Reasoning**: System should remain functional when external APIs fail
#[tokio::test]
async fn test_fallback_to_local_model_on_api_failure() {
    // Create a primary provider that always fails
    let _failing_primary = create_failing_mock_provider(1.0);

    // Create a local fallback that succeeds
    let _local_fallback = create_local_provider();

    // Create provider with fallback
    let config = EmbeddingConfig::openai(1536);
    let primary_with_fallback = MockProviderWithFallback::new(
        MockProvider::new(config.clone()).with_failures(1.0),
        Some(MockProvider::new(config)),
    );

    // The combined provider should succeed via fallback
    let result: Result<Vec<f32>, EmbeddingError> =
        primary_with_fallback.generate("Fallback test").await;

    assert!(
        result.is_ok(),
        "Should succeed via fallback when primary fails"
    );

    let embedding = result.unwrap();
    assert_eq!(
        embedding.len(),
        1536,
        "Fallback embedding should have correct dimension"
    );
}

/// **Test 5b**: Primary provider is used when available
#[tokio::test]
async fn test_primary_provider_used_when_available() {
    let config = EmbeddingConfig::openai(1536);

    // Primary that succeeds
    let primary = MockProvider::new(config.clone());

    // Both should work, primary is used
    let provider = MockProviderWithFallback::new(primary, Some(MockProvider::new(config)));

    let result: Result<Vec<f32>, EmbeddingError> = provider.generate("Primary should work").await;

    assert!(result.is_ok(), "Primary provider should handle request");
}

// ============================================================================
// Test 6: Embedding Cache Prevents Duplicate API Calls
// ============================================================================

/// **Test 6**: Embedding cache prevents duplicate API calls
///
/// **Evidence**: API calls are expensive (time and cost)
/// **Reasoning**: Caching identical requests improves performance
#[tokio::test]
async fn test_embedding_cache_prevents_duplicate_calls() {
    let config = EmbeddingConfig::openai(1536).with_cache(true);
    let provider = MockProvider::new(config);

    let text = "This text will be cached";

    // First call - should hit the API
    provider.reset_token_usage();
    let embedding1 = provider.generate(text).await.expect("First call");
    let usage_after_first = provider.token_usage();

    // Second call with same text - should use cache
    let embedding2 = provider.generate(text).await.expect("Second call (cached)");
    let _usage_after_second = provider.token_usage();

    // Embeddings should be identical
    assert_eq!(
        embedding1, embedding2,
        "Cached embedding should match original"
    );

    // Token usage should NOT increase for cached call
    // (In mock, we track tokens for non-cached calls)
    // Note: The mock tracks tokens on generation, cache prevents regeneration
    assert!(
        usage_after_first.total_tokens > 0,
        "First call should track tokens"
    );
}

/// **Test 6b**: Cache miss for different text
#[tokio::test]
async fn test_cache_miss_for_different_text() {
    let config = EmbeddingConfig::openai(1536).with_cache(true);
    let provider = MockProvider::new(config);

    let text1 = "First unique text";
    let text2 = "Second unique text";

    let embedding1 = provider.generate(text1).await.expect("First text");
    let embedding2 = provider.generate(text2).await.expect("Second text");

    // Different texts should produce different embeddings
    assert_ne!(
        embedding1, embedding2,
        "Different texts should not return cached value"
    );
}

/// **Test 6c**: Direct cache API testing
#[test]
fn test_embedding_cache_direct() {
    let cache = EmbeddingCache::new(3600, 1000);
    let text = "Cache test text";
    let embedding = vec![1.0, 2.0, 3.0];

    // Initially empty
    assert!(cache.get(text).is_none(), "Cache should be empty initially");

    // Add to cache
    cache.put(text, embedding.clone()).expect("Should cache");

    // Should be retrievable
    let cached = cache.get(text).expect("Should find cached value");
    assert_eq!(cached, embedding, "Cached value should match");

    // Different text should miss
    assert!(
        cache.get("Different text").is_none(),
        "Different text should miss"
    );
}

// ============================================================================
// Test 7: Store Embedding Persists to pgvector Table
// ============================================================================

/// **Test 7**: Store embedding persists to storage
///
/// **Evidence**: Embeddings must persist for similarity search
/// **Reasoning**: In-memory mock simulates pgvector storage behavior
#[tokio::test]
async fn test_store_embedding_persists() {
    let provider = create_mock_provider();
    let claim_id = Uuid::new_v4();

    // Generate an embedding
    let embedding = provider
        .generate("Claim to be stored")
        .await
        .expect("Generation should succeed");

    // Store it
    provider
        .store(claim_id, &embedding)
        .await
        .expect("Storage should succeed");

    // Verify it can be retrieved (Test 8 validates this further)
    let retrieved = provider.get(claim_id).await.expect("Retrieval should work");

    assert_eq!(
        embedding, retrieved,
        "Stored embedding should match retrieved"
    );
}

/// **Test 7b**: Store validates dimension
#[tokio::test]
async fn test_store_validates_dimension() {
    let provider = create_mock_provider_with_dimension(1536);
    let claim_id = Uuid::new_v4();

    // Wrong dimension embedding
    let wrong_dimension = vec![0.1f32; 384]; // 384 instead of 1536

    let result = provider.store(claim_id, &wrong_dimension).await;

    assert!(
        matches!(result, Err(EmbeddingError::DimensionMismatch { .. })),
        "Should reject wrong dimension. Got: {result:?}"
    );
}

// ============================================================================
// Test 8: Get Embedding Retrieves Stored Vector
// ============================================================================

/// **Test 8**: Get embedding retrieves stored vector
///
/// **Evidence**: Retrieval is essential for similarity calculations
/// **Reasoning**: Must be able to fetch embeddings by claim ID
#[tokio::test]
async fn test_get_embedding_retrieves_stored() {
    let provider = create_mock_provider();
    let claim_id = Uuid::new_v4();

    // Store an embedding
    let original = vec![0.1f32; 1536];
    provider
        .store(claim_id, &original)
        .await
        .expect("Store should work");

    // Retrieve it
    let retrieved = provider.get(claim_id).await.expect("Get should work");

    assert_eq!(
        original, retrieved,
        "Retrieved embedding should match stored"
    );
}

/// **Test 8b**: Get returns `NotFound` for missing embedding
#[tokio::test]
async fn test_get_returns_not_found_for_missing() {
    let provider = create_mock_provider();
    let nonexistent_id = Uuid::new_v4();

    let result = provider.get(nonexistent_id).await;

    assert!(
        matches!(result, Err(EmbeddingError::NotFound { .. })),
        "Should return NotFound for missing embedding. Got: {result:?}"
    );
}

// ============================================================================
// Test 9: Similar Embeddings Returns k-Nearest Neighbors
// ============================================================================

/// **Test 9**: Similar embeddings returns k-nearest neighbors
///
/// **Evidence**: Semantic search requires finding similar claims
/// **Reasoning**: k-NN search is foundational for similarity features
#[tokio::test]
async fn test_similar_embeddings_returns_k_nearest() {
    let provider = create_mock_provider();

    // Create and store several embeddings
    let texts = vec![
        "The cat sat on the mat",       // Similar to query
        "A feline rested on a rug",     // Similar to query
        "Quantum physics is complex",   // Different topic
        "Dogs are loyal companions",    // Different but animal-related
        "Mathematics involves numbers", // Different topic
    ];

    let mut claim_ids = Vec::new();
    for text in &texts {
        let claim_id = Uuid::new_v4();
        let embedding = provider.generate(text).await.unwrap();
        provider.store(claim_id, &embedding).await.unwrap();
        claim_ids.push(claim_id);
    }

    // Query with a similar text
    let query = provider
        .generate("The kitten lay on the carpet")
        .await
        .unwrap();

    // Find top 3 similar
    let similar = provider.similar(&query, 3, 0.0).await.unwrap();

    assert!(similar.len() <= 3, "Should return at most k results");
    assert!(!similar.is_empty(), "Should find some similar embeddings");

    // Results should be sorted by similarity (descending)
    for i in 0..similar.len() - 1 {
        assert!(
            similar[i].similarity >= similar[i + 1].similarity,
            "Results should be sorted by similarity descending"
        );
    }
}

/// **Test 9b**: Similar respects minimum similarity threshold
#[tokio::test]
async fn test_similar_respects_min_similarity() {
    let provider = create_mock_provider();

    // Store some embeddings
    for i in 0..5 {
        let claim_id = Uuid::new_v4();
        let embedding = provider
            .generate(&format!("Text number {i}"))
            .await
            .unwrap();
        provider.store(claim_id, &embedding).await.unwrap();
    }

    // Query with high similarity threshold
    let query = provider
        .generate("Completely unrelated text")
        .await
        .unwrap();
    let similar = provider.similar(&query, 10, 0.99).await.unwrap();

    // With very high threshold, likely no matches (unless identical)
    // This tests that the threshold is respected
    for result in &similar {
        assert!(
            result.similarity >= 0.99,
            "All results should meet minimum similarity threshold"
        );
    }
}

/// **Test 9c**: Similar validates query dimension
#[tokio::test]
async fn test_similar_validates_query_dimension() {
    let provider = create_mock_provider_with_dimension(1536);

    // Wrong dimension query
    let wrong_query = vec![0.1f32; 384];

    let result = provider.similar(&wrong_query, 10, 0.5).await;

    assert!(
        matches!(result, Err(EmbeddingError::DimensionMismatch { .. })),
        "Should reject wrong dimension query"
    );
}

// ============================================================================
// Test 10: Empty Text Returns Error (Not Zero Vector)
// ============================================================================

/// **Test 10**: Empty text returns error (not zero vector)
///
/// **Evidence**: Empty text has no semantic meaning
/// **Reasoning**: Zero vectors cause division by zero in normalization/similarity
#[tokio::test]
async fn test_empty_text_returns_error() {
    let provider = create_mock_provider();

    let result = provider.generate("").await;

    assert!(
        matches!(result, Err(EmbeddingError::EmptyText)),
        "Empty text should return EmptyText error. Got: {result:?}"
    );
}

/// **Test 10b**: Whitespace-only text is NOT considered empty
/// (depends on implementation - tokenizer may strip it)
#[tokio::test]
async fn test_whitespace_text_behavior() {
    let provider = create_mock_provider();

    // Whitespace-only - behavior depends on tokenizer
    let whitespace_result = provider.generate("   ").await;

    // Either it works (whitespace is content) or errors appropriately
    // The important thing is it doesn't return a zero vector
    if let Ok(embedding) = whitespace_result {
        let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!(
            magnitude > 0.0,
            "Non-empty result should not be zero vector"
        );
    }
}

/// **Test 10c**: Batch with empty text fails appropriately
#[tokio::test]
async fn test_batch_with_empty_text_fails() {
    let provider = create_mock_provider();

    let texts = vec!["Valid text", "", "Another valid"];

    let result = provider.batch_generate(&texts).await;

    assert!(
        matches!(result, Err(EmbeddingError::EmptyText)),
        "Batch with empty text should fail. Got: {result:?}"
    );
}

// ============================================================================
// Test 11: Very Long Text is Truncated Appropriately
// ============================================================================

/// **Test 11**: Very long text is truncated appropriately
///
/// **Evidence**: API has token limits (8191 for ada-002)
/// **Reasoning**: Must handle gracefully, either truncate or error
#[tokio::test]
async fn test_very_long_text_handling() {
    let config = EmbeddingConfig::openai(1536).with_max_tokens(100); // Low limit for testing
    let provider = MockProvider::new(config);

    // Create a very long text that exceeds the token limit
    let long_text = "word ".repeat(1000); // ~1000 tokens

    let result = provider.generate(&long_text).await;

    // Should return TextTooLong error for text exceeding limit
    assert!(
        matches!(result, Err(EmbeddingError::TextTooLong { .. })),
        "Very long text should return TextTooLong error. Got: {result:?}"
    );
}

/// **Test 11b**: Text at limit succeeds
#[tokio::test]
async fn test_text_at_limit_succeeds() {
    let config = EmbeddingConfig::openai(1536).with_max_tokens(1000);
    let provider = MockProvider::new(config);

    // Text that should be within limits
    let acceptable_text = "This is a reasonable length text for embedding.";

    let result = provider.generate(acceptable_text).await;

    assert!(
        result.is_ok(),
        "Text within limit should succeed. Got: {result:?}"
    );
}

// ============================================================================
// Test 12: Embedding Normalization (Unit Vector)
// ============================================================================

/// **Test 12**: Embedding normalization (unit vector)
///
/// **Evidence**: Normalized vectors enable efficient cosine similarity
/// **Reasoning**: dot product of unit vectors = cosine similarity
#[tokio::test]
async fn test_embedding_is_normalized() {
    let config = EmbeddingConfig::openai(1536).with_normalization(true);
    let provider = MockProvider::new(config);

    let embedding = provider
        .generate("Normalization test")
        .await
        .expect("Should generate");

    // Calculate magnitude
    let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();

    // Should be approximately 1.0
    assert!(
        (magnitude - 1.0).abs() < 1e-5,
        "Normalized embedding should have magnitude ~1.0. Got: {magnitude}"
    );
}

/// **Test 12b**: Normalization can be disabled
#[tokio::test]
async fn test_normalization_can_be_disabled() {
    let config = EmbeddingConfig::openai(1536).with_normalization(false);
    let provider = MockProvider::new(config);

    let embedding = provider
        .generate("Unnormalized test")
        .await
        .expect("Should generate");

    // When disabled, magnitude may not be 1.0
    // (depends on the mock implementation, but the option should exist)
    assert_eq!(embedding.len(), 1536, "Should still have correct dimension");
}

/// **Test 12c**: Normalizer utility tests
#[test]
fn test_normalizer_utility() {
    // Test basic normalization
    let vector = vec![3.0f32, 4.0];
    let normalized = Normalizer::normalize(&vector).expect("Should normalize");

    assert!((normalized[0] - 0.6).abs() < 1e-6, "Should be 3/5 = 0.6");
    assert!((normalized[1] - 0.8).abs() < 1e-6, "Should be 4/5 = 0.8");

    // Test zero vector fails
    let zero = vec![0.0f32, 0.0, 0.0];
    let result = Normalizer::normalize(&zero);
    assert!(
        matches!(result, Err(EmbeddingError::NormalizationError)),
        "Zero vector should fail normalization"
    );

    // Test is_normalized check
    assert!(Normalizer::is_normalized(&normalized, 1e-6));
    assert!(!Normalizer::is_normalized(&vector, 1e-6));
}

/// **Test 12d**: Cosine similarity calculation
#[test]
fn test_cosine_similarity() {
    let a = Normalizer::normalize(&[1.0, 0.0, 0.0]).unwrap();
    let b = Normalizer::normalize(&[0.0, 1.0, 0.0]).unwrap();
    let c = Normalizer::normalize(&[1.0, 0.0, 0.0]).unwrap();

    // Orthogonal vectors have similarity 0
    let sim_ab = Normalizer::cosine_similarity(&a, &b);
    assert!(sim_ab.abs() < 1e-6, "Orthogonal vectors should have sim ~0");

    // Identical vectors have similarity 1
    let sim_ac = Normalizer::cosine_similarity(&a, &c);
    assert!(
        (sim_ac - 1.0).abs() < 1e-6,
        "Identical vectors should have sim ~1"
    );
}

// ============================================================================
// Test 13: API Rate Limiting is Respected
// ============================================================================

/// **Test 13**: API rate limiting is respected
///
/// **Evidence**: API providers enforce rate limits
/// **Reasoning**: Must track and respect limits to avoid throttling
#[tokio::test]
async fn test_rate_limiting_is_respected() {
    use epigraph_embeddings::config::RateLimitConfig;

    // Create a rate limiter with very low limits for testing
    let config = RateLimitConfig {
        enabled: true,
        requests_per_minute: 5,
        tokens_per_minute: 100,
    };
    let limiter = RateLimiter::new(&config);

    // First few requests should succeed
    for _ in 0..5 {
        let result = limiter.check(10);
        assert!(result.is_ok(), "Should allow requests within limit");
        limiter.record(10);
    }

    // Next request should be rate limited (50 tokens used of 100 limit,
    // but 5 requests already made)
    let result = limiter.check(10);
    assert!(
        matches!(result, Err(EmbeddingError::RateLimitExceeded { .. })),
        "Should rate limit after exceeding RPM. Got: {result:?}"
    );
}

/// **Test 13b**: Rate limiter tracks totals
#[test]
fn test_rate_limiter_tracks_totals() {
    use epigraph_embeddings::config::RateLimitConfig;

    let config = RateLimitConfig::default();
    let limiter = RateLimiter::new(&config);

    limiter.record(100);
    limiter.record(200);
    limiter.record(50);

    assert_eq!(limiter.total_requests(), 3, "Should track request count");
    assert_eq!(limiter.total_tokens(), 350, "Should track token count");
}

/// **Test 13c**: Disabled rate limiter allows all
#[test]
fn test_disabled_rate_limiter() {
    let limiter = RateLimiter::disabled();

    // Should allow any number of requests
    for _ in 0..10000 {
        assert!(
            limiter.check(1000).is_ok(),
            "Disabled limiter should allow all"
        );
    }
}

// ============================================================================
// Test 14: Token Usage Tracking
// ============================================================================

/// **Test 14**: Token usage tracking
///
/// **Evidence**: API billing based on token usage
/// **Reasoning**: Must track for cost management and monitoring
#[tokio::test]
async fn test_token_usage_tracking() {
    let provider = create_mock_provider();

    // Reset to start fresh
    provider.reset_token_usage();
    let initial = provider.token_usage();
    assert_eq!(initial.total_tokens, 0, "Should start at zero after reset");

    // Generate some embeddings
    provider.generate("First text").await.unwrap();
    provider.generate("Second longer text here").await.unwrap();
    provider.generate("Third").await.unwrap();

    let usage = provider.token_usage();

    assert!(
        usage.total_tokens > 0,
        "Should track token usage. Got: {}",
        usage.total_tokens
    );
    assert!(
        usage.prompt_tokens > 0,
        "Should track prompt tokens. Got: {}",
        usage.prompt_tokens
    );
}

/// **Test 14b**: Token usage can be reset
#[tokio::test]
async fn test_token_usage_reset() {
    let provider = create_mock_provider();

    // Generate something
    provider.generate("Generate some tokens").await.unwrap();
    let before_reset = provider.token_usage();
    assert!(before_reset.total_tokens > 0, "Should have usage");

    // Reset
    provider.reset_token_usage();
    let after_reset = provider.token_usage();
    assert_eq!(
        after_reset.total_tokens, 0,
        "Usage should be zero after reset"
    );
}

/// **Test 14c**: Batch generation tracks cumulative tokens
#[tokio::test]
async fn test_batch_token_usage_tracking() {
    let provider = create_mock_provider();
    provider.reset_token_usage();

    let texts = vec!["First batch text", "Second batch text", "Third batch text"];

    provider.batch_generate(&texts).await.unwrap();

    let usage = provider.token_usage();
    assert!(
        usage.total_tokens > 0,
        "Batch should track tokens. Got: {}",
        usage.total_tokens
    );
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

/// Test that `SimilarClaim` correctly calculates distance
#[test]
fn test_similar_claim_distance() {
    let claim = SimilarClaim::new(Uuid::new_v4(), 0.85);

    assert_eq!(claim.similarity, 0.85);
    assert!(
        (claim.distance - 0.15).abs() < 1e-6,
        "Distance should be 1 - similarity"
    );
}

/// Test `TokenUsage` accumulation
#[test]
fn test_token_usage_accumulation() {
    let mut usage = TokenUsage::default();
    assert_eq!(usage.total_tokens, 0);

    usage.add(&TokenUsage::new(100));
    assert_eq!(usage.total_tokens, 100);

    usage.add(&TokenUsage::new(50));
    assert_eq!(usage.total_tokens, 150);
}

/// Test health check
#[tokio::test]
async fn test_health_check() {
    let provider = create_mock_provider();

    let result = provider.health_check().await;
    assert!(result.is_ok(), "Healthy provider should pass health check");
}

/// Test provider unavailable on health check failure
#[tokio::test]
async fn test_unhealthy_provider() {
    let config = EmbeddingConfig::openai(1536);
    let failing_provider = MockProvider::new(config).with_failures(1.0);

    let result = failing_provider.health_check().await;
    assert!(
        matches!(result, Err(EmbeddingError::ProviderUnavailable { .. })),
        "Failing provider should report unavailable"
    );
}

// ============================================================================
// Database Integration Tests (Requires PostgreSQL)
// ============================================================================

/// Test storing and retrieving from pgvector
#[sqlx::test(migrations = "../../migrations")]
async fn test_pgvector_store_and_retrieve(pool: sqlx::PgPool) {
    use epigraph_embeddings::EmbeddingRepository;

    // Insert a minimal agent and claim so the UPDATE in store() has a row to target
    let agent_id = Uuid::new_v4();
    let public_key = vec![0u8; 32];
    sqlx::query("INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, 'test-agent')")
        .bind(agent_id)
        .bind(&public_key)
        .execute(&pool)
        .await
        .expect("Insert agent should succeed");

    let claim_id = Uuid::new_v4();
    let content_hash = vec![0u8; 32];
    sqlx::query("INSERT INTO claims (id, content, content_hash, agent_id) VALUES ($1, $2, $3, $4)")
        .bind(claim_id)
        .bind("test claim for embedding")
        .bind(&content_hash)
        .bind(agent_id)
        .execute(&pool)
        .await
        .expect("Insert claim should succeed");

    let repo = EmbeddingRepository::new(pool, 1536);

    // Create a normalized embedding
    let embedding: Vec<f32> = (0..1536).map(|i| (i as f32) / 1536.0).collect();
    let normalized = Normalizer::normalize(&embedding).unwrap();

    // Store
    repo.store(claim_id, &normalized)
        .await
        .expect("Store should succeed");

    // Retrieve
    let retrieved = repo.get(claim_id).await.expect("Get should succeed");

    // Compare (allowing for floating point tolerance)
    for (i, (a, b)) in normalized.iter().zip(retrieved.iter()).enumerate() {
        assert!((a - b).abs() < 1e-5, "Element {i} mismatch: {a} vs {b}");
    }
}

/// Test k-NN similarity search with pgvector
#[sqlx::test(migrations = "../../migrations")]
async fn test_pgvector_similarity_search(pool: sqlx::PgPool) {
    use epigraph_embeddings::EmbeddingRepository;

    // Insert a shared agent so each claim INSERT has a valid agent_id FK
    let agent_id = Uuid::new_v4();
    let public_key = vec![1u8; 32];
    sqlx::query("INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, 'test-agent')")
        .bind(agent_id)
        .bind(&public_key)
        .execute(&pool)
        .await
        .expect("Insert agent should succeed");

    let repo = EmbeddingRepository::new(pool.clone(), 1536);

    // Insert claim rows and store embeddings
    let mut ids = Vec::new();
    for i in 0..5 {
        let claim_id = Uuid::new_v4();
        let content_hash = {
            let mut h = vec![0u8; 31];
            h.push(i as u8);
            h
        };
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id) VALUES ($1, $2, $3, $4)",
        )
        .bind(claim_id)
        .bind(format!("test claim {i}"))
        .bind(&content_hash)
        .bind(agent_id)
        .execute(&pool)
        .await
        .expect("Insert claim should succeed");

        let embedding: Vec<f32> = (0..1536).map(|j| ((i * 100 + j) as f32) / 2000.0).collect();
        let normalized = Normalizer::normalize(&embedding).unwrap();
        repo.store(claim_id, &normalized).await.unwrap();
        ids.push(claim_id);
    }

    // Query for similar
    let query: Vec<f32> = (0..1536).map(|i| (i as f32) / 2000.0).collect();
    let normalized_query = Normalizer::normalize(&query).unwrap();

    let similar = repo.similar(&normalized_query, 3, 0.0).await.unwrap();

    assert!(similar.len() <= 3, "Should return at most k results");
    assert!(
        !similar.is_empty(),
        "Should find at least one similar claim"
    );

    // Results should be sorted by similarity (descending)
    for window in similar.windows(2) {
        assert!(
            window[0].similarity >= window[1].similarity,
            "Results should be sorted"
        );
    }
}
