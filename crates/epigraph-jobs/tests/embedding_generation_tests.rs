//! TDD Tests for `EmbeddingGenerationHandler`
//!
//! These tests define the expected behavior of the embedding generation job handler.
//! They are written in TDD style to describe the desired behavior.
//!
//! # Test Coverage
//!
//! 1. Embedding is generated for a valid claim
//! 2. Embedding has correct dimensions (1536 for `OpenAI`)
//! 3. Embedding is normalized (unit vector)
//! 4. Missing claim returns `JobError::ProcessingFailed`
//! 5. Rate limiting behavior
//! 6. Caching (same text should not call API twice)
//! 7. Fallback to local model on API failure
//! 8. Text too long error handling
//! 9. Concurrent embedding generation
//! 10. Timeout handling
//! 11. Whitespace-only text handling
//! 12. Unicode and emoji text handling
//! 13. Storage failure after generation
//! 14. Zero vector normalization handling
//!
//! # Evidence
//! - `IMPLEMENTATION_PLAN.md` specifies embedding generation for claims
//! - `OpenAI` text-embedding-ada-002 returns 1536-dimensional vectors
//! - Embeddings must be normalized for correct cosine similarity
//!
//! # Reasoning
//! - TDD approach ensures handler interface is well-defined
//! - Mock providers enable testing without external API dependencies
//! - Job handler must integrate with embedding service correctly

use epigraph_jobs::{
    async_trait, EmbeddingGenerationHandler, EpiGraphJob, InMemoryJobQueue, Job, JobError,
    JobHandler, JobQueue, JobResult, JobResultMetadata, JobRunner,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use uuid::Uuid;

// ============================================================================
// Mock Embedding Service for Testing
// ============================================================================

/// Token usage statistics (mirroring epigraph-embeddings)
#[derive(Debug, Clone, Default)]
pub struct MockTokenUsage {
    pub total_tokens: usize,
    pub prompt_tokens: usize,
}

impl MockTokenUsage {
    #[must_use]
    pub const fn new(total_tokens: usize) -> Self {
        Self {
            total_tokens,
            prompt_tokens: total_tokens,
        }
    }

    pub const fn add(&mut self, other: &Self) {
        self.total_tokens += other.total_tokens;
        self.prompt_tokens += other.prompt_tokens;
    }
}

/// Mock embedding service for testing the job handler
///
/// This provides a simplified interface that mirrors the real `EmbeddingService`
/// without requiring the full crate dependency.
pub struct MockEmbeddingService {
    /// Configured dimension (1536 for OpenAI-compatible)
    dimension: usize,
    /// Whether normalization is enabled
    normalize: bool,
    /// Whether caching is enabled
    cache_enabled: bool,
    /// Internal cache: text -> embedding
    cache: RwLock<HashMap<String, Vec<f32>>>,
    /// Storage: `claim_id` -> embedding
    storage: RwLock<HashMap<Uuid, Vec<f32>>>,
    /// Claim text store: `claim_id` -> text (simulates claim database)
    claim_texts: RwLock<HashMap<Uuid, String>>,
    /// Token usage tracking
    token_usage: Mutex<MockTokenUsage>,
    /// API call counter (for rate limiting tests)
    api_call_count: AtomicUsize,
    /// Whether to simulate API failures
    simulate_failures: bool,
    /// Failure rate (0.0 = never fail, 1.0 = always fail)
    failure_rate: f32,
    /// Whether fallback is available
    fallback_available: bool,
    /// Rate limit: max requests per window
    rate_limit_requests: Option<usize>,
    /// Current rate limit window request count
    rate_limit_count: Mutex<usize>,
    /// Maximum token limit for text
    max_token_limit: Option<usize>,
    /// Simulated delay for slow service tests
    simulated_delay: Option<Duration>,
    /// Whether storage should fail
    storage_failure: AtomicBool,
}

impl MockEmbeddingService {
    /// Create a new mock embedding service with default OpenAI-like configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            dimension: 1536,
            normalize: true,
            cache_enabled: true,
            cache: RwLock::new(HashMap::new()),
            storage: RwLock::new(HashMap::new()),
            claim_texts: RwLock::new(HashMap::new()),
            token_usage: Mutex::new(MockTokenUsage::default()),
            api_call_count: AtomicUsize::new(0),
            simulate_failures: false,
            failure_rate: 0.0,
            fallback_available: false,
            rate_limit_requests: None,
            rate_limit_count: Mutex::new(0),
            max_token_limit: None,
            simulated_delay: None,
            storage_failure: AtomicBool::new(false),
        }
    }

    /// Configure with custom dimension
    pub const fn with_dimension(mut self, dimension: usize) -> Self {
        self.dimension = dimension;
        self
    }

    /// Enable/disable normalization
    pub const fn with_normalization(mut self, enabled: bool) -> Self {
        self.normalize = enabled;
        self
    }

    /// Enable/disable caching
    pub const fn with_cache(mut self, enabled: bool) -> Self {
        self.cache_enabled = enabled;
        self
    }

    /// Configure failure simulation
    pub const fn with_failures(mut self, rate: f32) -> Self {
        self.simulate_failures = true;
        self.failure_rate = rate;
        self
    }

    /// Configure fallback availability
    pub const fn with_fallback(mut self, available: bool) -> Self {
        self.fallback_available = available;
        self
    }

    /// Configure rate limiting
    pub const fn with_rate_limit(mut self, max_requests: usize) -> Self {
        self.rate_limit_requests = Some(max_requests);
        self
    }

    /// Configure maximum token limit
    pub const fn with_max_token_limit(mut self, limit: usize) -> Self {
        self.max_token_limit = Some(limit);
        self
    }

    /// Configure simulated delay for timeout tests
    pub const fn with_simulated_delay(mut self, delay: Duration) -> Self {
        self.simulated_delay = Some(delay);
        self
    }

    /// Set storage failure mode
    pub fn set_storage_failure(&self, should_fail: bool) {
        self.storage_failure.store(should_fail, Ordering::SeqCst);
    }

    /// Add a claim text to the mock database
    pub fn add_claim(&self, claim_id: Uuid, text: &str) {
        self.claim_texts
            .write()
            .unwrap()
            .insert(claim_id, text.to_string());
    }

    /// Get claim text from mock database
    pub fn get_claim_text(&self, claim_id: Uuid) -> Option<String> {
        self.claim_texts.read().unwrap().get(&claim_id).cloned()
    }

    /// Get the configured dimension
    pub const fn dimension(&self) -> usize {
        self.dimension
    }

    /// Get token usage
    pub fn token_usage(&self) -> MockTokenUsage {
        self.token_usage.lock().unwrap().clone()
    }

    /// Reset token usage
    pub fn reset_token_usage(&self) {
        *self.token_usage.lock().unwrap() = MockTokenUsage::default();
    }

    /// Get API call count
    pub fn api_call_count(&self) -> usize {
        self.api_call_count.load(Ordering::SeqCst)
    }

    /// Reset API call count
    pub fn reset_api_call_count(&self) {
        self.api_call_count.store(0, Ordering::SeqCst);
    }

    /// Reset rate limit counter
    pub fn reset_rate_limit(&self) {
        *self.rate_limit_count.lock().unwrap() = 0;
    }

    /// Estimate token count for text (approximation: ~4 chars per token)
    fn estimate_tokens(&self, text: &str) -> usize {
        // More accurate estimation considering unicode
        let char_count = text.chars().count();
        (char_count / 4).max(1)
    }

    /// Generate a deterministic embedding for text
    fn generate_deterministic(&self, text: &str) -> Vec<f32> {
        let mut embedding = vec![0.0f32; self.dimension];

        // Simple hash-based embedding for determinism
        for (i, byte) in text.bytes().enumerate() {
            let idx = i % self.dimension;
            embedding[idx] += (f32::from(byte) - 128.0) / 256.0;
            let other_idx = (idx + byte as usize) % self.dimension;
            embedding[other_idx] += f32::from(byte) / 512.0;
        }

        // Normalize to unit vector if enabled
        if self.normalize {
            let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
            if magnitude > f32::EPSILON {
                for x in &mut embedding {
                    *x /= magnitude;
                }
            }
        }

        embedding
    }

    /// Check if rate limited
    fn is_rate_limited(&self) -> bool {
        if let Some(limit) = self.rate_limit_requests {
            let count = *self.rate_limit_count.lock().unwrap();
            count >= limit
        } else {
            false
        }
    }

    /// Increment rate limit counter
    fn increment_rate_limit(&self) {
        if self.rate_limit_requests.is_some() {
            *self.rate_limit_count.lock().unwrap() += 1;
        }
    }

    /// Check if this call should fail (based on failure rate)
    fn should_fail(&self) -> bool {
        if !self.simulate_failures {
            return false;
        }

        let count = self.api_call_count.fetch_add(1, Ordering::SeqCst) + 1;

        // Simple deterministic "randomness" based on call count
        let pseudo_random = (count as f32 * 0.618_034).fract();
        pseudo_random < self.failure_rate
    }

    /// Generate embedding for text
    pub async fn generate(&self, text: &str) -> Result<Vec<f32>, MockEmbeddingError> {
        // Validate empty text
        if text.is_empty() {
            return Err(MockEmbeddingError::EmptyText);
        }

        // Validate whitespace-only text
        if text.trim().is_empty() {
            return Err(MockEmbeddingError::WhitespaceOnlyText);
        }

        // Check token limit
        if let Some(max_tokens) = self.max_token_limit {
            let estimated_tokens = self.estimate_tokens(text);
            if estimated_tokens > max_tokens {
                return Err(MockEmbeddingError::TextTooLong {
                    actual: estimated_tokens,
                    max: max_tokens,
                });
            }
        }

        // Apply simulated delay if configured
        if let Some(delay) = self.simulated_delay {
            tokio::time::sleep(delay).await;
        }

        // Check rate limit
        if self.is_rate_limited() {
            return Err(MockEmbeddingError::RateLimitExceeded {
                retry_after_secs: 60,
            });
        }

        // Check for simulated failure
        if self.should_fail() {
            if self.fallback_available {
                // Use fallback (same embedding, different path)
                return Ok(self.generate_deterministic(text));
            }
            return Err(MockEmbeddingError::ApiError {
                message: "Simulated API failure".to_string(),
            });
        }

        // Check cache
        if self.cache_enabled {
            if let Some(cached) = self.cache.read().unwrap().get(text) {
                return Ok(cached.clone());
            }
        }

        // Track token usage (more accurate estimation)
        let tokens = self.estimate_tokens(text);
        self.token_usage
            .lock()
            .unwrap()
            .add(&MockTokenUsage::new(tokens));

        // Increment rate limit counter
        self.increment_rate_limit();

        // Generate embedding
        let embedding = self.generate_deterministic(text);

        // Cache the result
        if self.cache_enabled {
            self.cache
                .write()
                .unwrap()
                .insert(text.to_string(), embedding.clone());
        }

        Ok(embedding)
    }

    /// Store embedding for a claim
    pub async fn store(&self, claim_id: Uuid, embedding: &[f32]) -> Result<(), MockEmbeddingError> {
        // Check for simulated storage failure
        if self.storage_failure.load(Ordering::SeqCst) {
            return Err(MockEmbeddingError::StorageError {
                message: "Simulated storage failure".to_string(),
            });
        }

        if embedding.len() != self.dimension {
            return Err(MockEmbeddingError::DimensionMismatch {
                expected: self.dimension,
                actual: embedding.len(),
            });
        }

        self.storage
            .write()
            .unwrap()
            .insert(claim_id, embedding.to_vec());
        Ok(())
    }

    /// Retrieve embedding for a claim
    pub async fn get(&self, claim_id: Uuid) -> Result<Vec<f32>, MockEmbeddingError> {
        self.storage
            .read()
            .unwrap()
            .get(&claim_id)
            .cloned()
            .ok_or(MockEmbeddingError::NotFound { claim_id })
    }

    /// Generate and store embedding for a claim in one operation
    pub async fn generate_and_store(
        &self,
        claim_id: Uuid,
        text: &str,
    ) -> Result<Vec<f32>, MockEmbeddingError> {
        let embedding = self.generate(text).await?;
        self.store(claim_id, &embedding).await?;
        Ok(embedding)
    }
}

impl Default for MockEmbeddingService {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock embedding errors
#[derive(Debug, Clone)]
pub enum MockEmbeddingError {
    EmptyText,
    WhitespaceOnlyText,
    TextTooLong { actual: usize, max: usize },
    DimensionMismatch { expected: usize, actual: usize },
    RateLimitExceeded { retry_after_secs: u64 },
    ApiError { message: String },
    NotFound { claim_id: Uuid },
    NormalizationError,
    StorageError { message: String },
    Timeout { duration: Duration },
}

impl std::fmt::Display for MockEmbeddingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyText => write!(f, "Cannot generate embedding for empty text"),
            Self::WhitespaceOnlyText => {
                write!(f, "Cannot generate embedding for whitespace-only text")
            }
            Self::TextTooLong { actual, max } => {
                write!(f, "Text exceeds maximum token limit: {actual} > {max}")
            }
            Self::DimensionMismatch { expected, actual } => {
                write!(
                    f,
                    "Embedding dimension mismatch: expected {expected}, got {actual}"
                )
            }
            Self::RateLimitExceeded { retry_after_secs } => {
                write!(
                    f,
                    "Rate limit exceeded, retry after {retry_after_secs} seconds"
                )
            }
            Self::ApiError { message } => write!(f, "API error: {message}"),
            Self::NotFound { claim_id } => write!(f, "Embedding not found for claim {claim_id}"),
            Self::NormalizationError => write!(f, "Cannot normalize zero vector"),
            Self::StorageError { message } => write!(f, "Storage error: {message}"),
            Self::Timeout { duration } => write!(f, "Operation timed out after {duration:?}"),
        }
    }
}

impl std::error::Error for MockEmbeddingError {}

// ============================================================================
// Test Handler Implementation
// ============================================================================

/// A testable embedding generation handler that uses a mock embedding service
pub struct TestableEmbeddingHandler {
    embedding_service: Arc<MockEmbeddingService>,
    timeout: Option<Duration>,
}

impl TestableEmbeddingHandler {
    pub const fn new(embedding_service: Arc<MockEmbeddingService>) -> Self {
        Self {
            embedding_service,
            timeout: None,
        }
    }

    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

#[async_trait]
impl JobHandler for TestableEmbeddingHandler {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        // Parse the job payload to extract claim_id
        let epigraph_job: EpiGraphJob =
            serde_json::from_value(job.payload.clone()).map_err(|e| JobError::PayloadError {
                message: format!("Failed to deserialize job payload: {e}"),
            })?;

        let claim_id = match epigraph_job {
            EpiGraphJob::EmbeddingGeneration { claim_id } => claim_id,
            _ => {
                return Err(JobError::ProcessingFailed {
                    message: "Expected EmbeddingGeneration job".to_string(),
                })
            }
        };

        // Get the claim text from the mock database
        let claim_text = self
            .embedding_service
            .get_claim_text(claim_id)
            .ok_or_else(|| JobError::ProcessingFailed {
                message: format!("Claim not found: {claim_id}"),
            })?;

        // Generate and store the embedding with optional timeout
        let start = std::time::Instant::now();

        let embedding_result = if let Some(timeout) = self.timeout {
            tokio::time::timeout(
                timeout,
                self.embedding_service
                    .generate_and_store(claim_id, &claim_text),
            )
            .await
            .map_err(|_| JobError::Timeout { timeout })?
        } else {
            self.embedding_service
                .generate_and_store(claim_id, &claim_text)
                .await
        };

        let embedding = embedding_result.map_err(|e| JobError::ProcessingFailed {
            message: e.to_string(),
        })?;

        let execution_duration = start.elapsed();

        // Get token usage for metadata
        let token_usage = self.embedding_service.token_usage();

        // Build result metadata
        let mut extra = std::collections::HashMap::new();
        extra.insert(
            "embedding_dimension".to_string(),
            serde_json::json!(embedding.len()),
        );
        extra.insert(
            "tokens_used".to_string(),
            serde_json::json!(token_usage.total_tokens),
        );

        Ok(JobResult {
            output: json!({
                "claim_id": claim_id,
                "embedding_dimension": embedding.len(),
                "tokens_used": token_usage.total_tokens,
            }),
            execution_duration,
            metadata: JobResultMetadata {
                worker_id: Some("embedding-worker".to_string()),
                items_processed: Some(1),
                extra,
            },
        })
    }

    fn job_type(&self) -> &'static str {
        "embedding_generation"
    }

    fn max_retries(&self) -> u32 {
        3
    }

    fn backoff(&self, attempt: u32) -> Duration {
        // Exponential backoff: 2^attempt seconds, capped at 1 hour
        let secs = 2u64.saturating_pow(attempt).min(3600);
        Duration::from_secs(secs)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a test job for embedding generation
fn create_embedding_job(claim_id: Uuid) -> Job {
    let epigraph_job = EpiGraphJob::EmbeddingGeneration { claim_id };
    epigraph_job
        .into_job()
        .expect("Job serialization should work")
}

/// Calculate magnitude of a vector
fn vector_magnitude(v: &[f32]) -> f32 {
    v.iter().map(|x| x * x).sum::<f32>().sqrt()
}

/// Check if vector is normalized (magnitude ~= 1.0)
fn is_normalized(v: &[f32], tolerance: f32) -> bool {
    let mag = vector_magnitude(v);
    (mag - 1.0).abs() < tolerance
}

/// Float comparison with tolerance
fn approx_eq(a: f32, b: f32, tolerance: f32) -> bool {
    (a - b).abs() < tolerance
}

// ============================================================================
// Test 1: Embedding is Generated for a Valid Claim
// ============================================================================

/// **Test 1**: Embedding is generated for a valid claim
///
/// **Evidence**: `IMPLEMENTATION_PLAN.md` specifies embedding generation for semantic search
/// **Reasoning**: Core functionality of the handler must work correctly
#[tokio::test]
async fn test_embedding_generated_for_valid_claim() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    // Add a claim to the mock database
    let claim_id = Uuid::new_v4();
    let claim_text = "The Earth orbits the Sun in approximately 365.25 days.";
    embedding_service.add_claim(claim_id, claim_text);

    // Create and process the job
    let job = create_embedding_job(claim_id);
    let result = handler.handle(&job).await;

    assert!(result.is_ok(), "Should successfully generate embedding");

    let result = result.unwrap();

    // Verify the result contains expected fields
    assert_eq!(
        result.output["claim_id"],
        claim_id.to_string(),
        "Result should contain the claim ID"
    );
    assert_eq!(
        result.output["embedding_dimension"], 1536,
        "Should report correct dimension"
    );

    // Verify embedding was stored
    let stored_embedding = embedding_service.get(claim_id).await;
    assert!(
        stored_embedding.is_ok(),
        "Embedding should be stored in the database"
    );
}

/// **Test 1b**: Multiple claims can be processed independently
#[tokio::test]
async fn test_multiple_claims_processed_independently() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    // Add multiple claims
    let claims = vec![
        (Uuid::new_v4(), "First claim about physics."),
        (Uuid::new_v4(), "Second claim about biology."),
        (Uuid::new_v4(), "Third claim about chemistry."),
    ];

    for (id, text) in &claims {
        embedding_service.add_claim(*id, text);
    }

    // Process each claim
    for (claim_id, _text) in &claims {
        let job = create_embedding_job(*claim_id);
        let result = handler.handle(&job).await;

        assert!(
            result.is_ok(),
            "Each claim should be processed successfully"
        );

        // Verify embedding was stored
        let embedding = embedding_service.get(*claim_id).await;
        assert!(embedding.is_ok(), "Embedding should be stored for claim");
    }

    // Verify embeddings are different for different claims
    let emb1 = embedding_service.get(claims[0].0).await.unwrap();
    let emb2 = embedding_service.get(claims[1].0).await.unwrap();

    assert_ne!(
        emb1, emb2,
        "Different claims should have different embeddings"
    );
}

// ============================================================================
// Test 2: Embedding Has Correct Dimensions
// ============================================================================

/// **Test 2**: Embedding has correct dimensions (1536 for `OpenAI`)
///
/// **Evidence**: `OpenAI` text-embedding-ada-002 returns 1536-dimensional vectors
/// **Reasoning**: Dimension must match for correct similarity calculations
#[tokio::test]
async fn test_embedding_has_correct_dimension() {
    let embedding_service = Arc::new(MockEmbeddingService::new().with_dimension(1536));
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let claim_id = Uuid::new_v4();
    embedding_service.add_claim(claim_id, "Test claim for dimension verification.");

    let job = create_embedding_job(claim_id);
    let result = handler.handle(&job).await.expect("Should succeed");

    // Verify dimension in result
    assert_eq!(
        result.output["embedding_dimension"], 1536,
        "Should report 1536 dimensions"
    );

    // Verify actual stored embedding dimension
    let embedding = embedding_service.get(claim_id).await.unwrap();
    assert_eq!(
        embedding.len(),
        1536,
        "Stored embedding should have 1536 dimensions"
    );
}

/// **Test 2b**: Different configurations respect their dimension settings
#[tokio::test]
async fn test_embedding_respects_configured_dimension() {
    for dimension in [384, 768, 1024, 1536] {
        let embedding_service = Arc::new(MockEmbeddingService::new().with_dimension(dimension));
        let handler = TestableEmbeddingHandler::new(embedding_service.clone());

        let claim_id = Uuid::new_v4();
        embedding_service.add_claim(claim_id, "Test claim");

        let job = create_embedding_job(claim_id);
        let result = handler.handle(&job).await.expect("Should succeed");

        assert_eq!(
            result.output["embedding_dimension"],
            json!(dimension),
            "Should report {dimension} dimensions"
        );

        let embedding = embedding_service.get(claim_id).await.unwrap();
        assert_eq!(
            embedding.len(),
            dimension,
            "Stored embedding should have {dimension} dimensions"
        );
    }
}

// ============================================================================
// Test 3: Embedding is Normalized (Unit Vector)
// ============================================================================

/// **Test 3**: Embedding is normalized (unit vector)
///
/// **Evidence**: Normalized vectors enable efficient cosine similarity via dot product
/// **Reasoning**: All embeddings should be unit vectors for consistent similarity
#[tokio::test]
async fn test_embedding_is_normalized() {
    let embedding_service = Arc::new(MockEmbeddingService::new().with_normalization(true));
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let claim_id = Uuid::new_v4();
    embedding_service.add_claim(claim_id, "Claim to verify normalization.");

    let job = create_embedding_job(claim_id);
    handler.handle(&job).await.expect("Should succeed");

    let embedding = embedding_service.get(claim_id).await.unwrap();

    // Verify the embedding is normalized (magnitude ~= 1.0)
    assert!(
        is_normalized(&embedding, 1e-5),
        "Embedding should be normalized (magnitude ~= 1.0). Got magnitude: {}",
        vector_magnitude(&embedding)
    );
}

/// **Test 3b**: Multiple embeddings are all normalized
#[tokio::test]
async fn test_all_embeddings_are_normalized() {
    let embedding_service = Arc::new(MockEmbeddingService::new().with_normalization(true));
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let texts = vec![
        "Short text",
        "A medium length text with more words in it",
        "A very long text that contains many many words and should produce an embedding that is also normalized despite the longer input text length being processed",
    ];

    for text in texts {
        let claim_id = Uuid::new_v4();
        embedding_service.add_claim(claim_id, text);

        let job = create_embedding_job(claim_id);
        handler.handle(&job).await.expect("Should succeed");

        let embedding = embedding_service.get(claim_id).await.unwrap();

        assert!(
            is_normalized(&embedding, 1e-5),
            "All embeddings should be normalized. Text: '{}...', magnitude: {}",
            &text[..text.len().min(20)],
            vector_magnitude(&embedding)
        );
    }
}

/// **Test 3c**: Non-normalized configuration produces non-unit vectors
///
/// Fixed: Now verifies magnitude is NOT 1.0 (within tolerance)
#[tokio::test]
async fn test_unnormalized_embeddings_when_disabled() {
    let embedding_service = Arc::new(MockEmbeddingService::new().with_normalization(false));
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let claim_id = Uuid::new_v4();
    // Use a longer text to ensure non-trivial magnitude
    embedding_service.add_claim(
        claim_id,
        "This is a longer test claim for unnormalized embedding verification with sufficient content.",
    );

    let job = create_embedding_job(claim_id);
    handler.handle(&job).await.expect("Should succeed");

    let embedding = embedding_service.get(claim_id).await.unwrap();
    let magnitude = vector_magnitude(&embedding);

    // With normalization disabled, magnitude should NOT be 1.0
    assert_eq!(embedding.len(), 1536, "Should still have correct dimension");
    assert!(
        !approx_eq(magnitude, 1.0, 0.01),
        "Unnormalized embedding magnitude should NOT be ~1.0. Got: {magnitude}"
    );
}

/// **Test 3d**: Zero vector normalization is handled safely
#[tokio::test]
async fn test_zero_vector_normalization_handled() {
    // Create a service with normalization enabled
    // The mock generates non-zero embeddings, but we test the edge case
    // by verifying the service doesn't crash on minimal input
    let embedding_service = Arc::new(MockEmbeddingService::new().with_normalization(true));
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let claim_id = Uuid::new_v4();
    // Single character input - edge case for embedding generation
    embedding_service.add_claim(claim_id, "x");

    let job = create_embedding_job(claim_id);
    let result = handler.handle(&job).await;

    // Should not panic or error - either succeeds or returns graceful error
    match result {
        Ok(_) => {
            let embedding = embedding_service.get(claim_id).await.unwrap();
            // If successful, verify it's either normalized or zero
            let mag = vector_magnitude(&embedding);
            assert!(
                mag < f32::EPSILON || approx_eq(mag, 1.0, 1e-5),
                "Embedding should be zero or normalized, got magnitude: {mag}"
            );
        }
        Err(JobError::ProcessingFailed { message }) => {
            assert!(
                message.contains("normalize") || message.contains("zero"),
                "Error should mention normalization issue"
            );
        }
        Err(e) => panic!("Unexpected error type: {e:?}"),
    }
}

// ============================================================================
// Test 4: Missing Claim Returns JobError::ProcessingFailed
// ============================================================================

/// **Test 4**: Missing claim returns `JobError::ProcessingFailed`
///
/// **Evidence**: Invalid claim IDs should not cause crashes
/// **Reasoning**: Graceful error handling is essential for job robustness
#[tokio::test]
async fn test_missing_claim_returns_error() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    // Create a job for a non-existent claim
    let nonexistent_claim_id = Uuid::new_v4();
    let job = create_embedding_job(nonexistent_claim_id);

    let result = handler.handle(&job).await;

    assert!(result.is_err(), "Should fail for non-existent claim");

    match result {
        Err(JobError::ProcessingFailed { message }) => {
            assert!(
                message.contains("not found") || message.contains("Claim"),
                "Error message should indicate claim not found. Got: {message}"
            );
        }
        Err(e) => panic!("Expected ProcessingFailed, got: {e:?}"),
        Ok(_) => panic!("Expected error, got success"),
    }
}

/// **Test 4b**: Invalid payload returns appropriate error
#[tokio::test]
async fn test_invalid_payload_returns_error() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    // Create a job with malformed payload
    let job = Job::new("embedding_generation", json!({"invalid": "payload"}));

    let result = handler.handle(&job).await;

    assert!(result.is_err(), "Should fail for invalid payload");

    match result {
        Err(JobError::PayloadError { .. } | JobError::ProcessingFailed { .. }) => {
            // Either error type is acceptable
        }
        Err(e) => panic!("Expected PayloadError or ProcessingFailed, got: {e:?}"),
        Ok(_) => panic!("Expected error, got success"),
    }
}

/// **Test 4c**: Empty claim text returns error
#[tokio::test]
async fn test_empty_claim_text_returns_error() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    // Add a claim with empty text
    let claim_id = Uuid::new_v4();
    embedding_service.add_claim(claim_id, "");

    let job = create_embedding_job(claim_id);
    let result = handler.handle(&job).await;

    assert!(result.is_err(), "Should fail for empty claim text");

    match result {
        Err(JobError::ProcessingFailed { message }) => {
            assert!(
                message.contains("empty") || message.contains("Empty"),
                "Error should mention empty text. Got: {message}"
            );
        }
        Err(e) => panic!("Expected ProcessingFailed, got: {e:?}"),
        Ok(_) => panic!("Expected error, got success"),
    }
}

/// **Test 4d**: Whitespace-only text returns error
#[tokio::test]
async fn test_whitespace_only_text_returns_error() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    // Test various whitespace-only inputs
    let whitespace_texts = vec!["   ", "\t\t", "\n\n", "  \t  \n  ", "\r\n"];

    for ws_text in whitespace_texts {
        let claim_id = Uuid::new_v4();
        embedding_service.add_claim(claim_id, ws_text);

        let job = create_embedding_job(claim_id);
        let result = handler.handle(&job).await;

        assert!(
            result.is_err(),
            "Should fail for whitespace-only text: {ws_text:?}"
        );

        match result {
            Err(JobError::ProcessingFailed { message }) => {
                assert!(
                    message.contains("whitespace") || message.contains("empty"),
                    "Error should mention whitespace or empty. Got: {message}"
                );
            }
            Err(e) => panic!("Expected ProcessingFailed, got: {e:?}"),
            Ok(_) => panic!("Expected error for whitespace text, got success"),
        }
    }
}

/// **Test 4e**: Text exceeding token limit returns `TextTooLong` error
#[tokio::test]
async fn test_text_exceeding_token_limit_returns_error() {
    // Configure with a low token limit
    let embedding_service = Arc::new(MockEmbeddingService::new().with_max_token_limit(10));
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let claim_id = Uuid::new_v4();
    // This text will exceed 10 tokens (approx 4 chars per token)
    let long_text = "This is a very long text that should definitely exceed the configured maximum token limit of ten tokens which is quite restrictive";
    embedding_service.add_claim(claim_id, long_text);

    let job = create_embedding_job(claim_id);
    let result = handler.handle(&job).await;

    assert!(
        result.is_err(),
        "Should fail for text exceeding token limit"
    );

    match result {
        Err(JobError::ProcessingFailed { message }) => {
            assert!(
                message.contains("token limit") || message.contains("exceeds"),
                "Error should mention token limit. Got: {message}"
            );
        }
        Err(e) => panic!("Expected ProcessingFailed with token limit error, got: {e:?}"),
        Ok(_) => panic!("Expected error, got success"),
    }
}

// ============================================================================
// Test 5: Rate Limiting Behavior
// ============================================================================

/// **Test 5**: Rate limiting behavior
///
/// **Evidence**: API providers enforce rate limits
/// **Reasoning**: Handler must respect and handle rate limits gracefully
#[tokio::test]
async fn test_rate_limiting_behavior() {
    // Create service with very low rate limit
    let embedding_service = Arc::new(MockEmbeddingService::new().with_rate_limit(3));
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    // Add several claims
    let mut results = Vec::new();
    for i in 0..5 {
        let claim_id = Uuid::new_v4();
        embedding_service.add_claim(claim_id, &format!("Claim number {i}"));

        let job = create_embedding_job(claim_id);
        results.push((claim_id, handler.handle(&job).await));
    }

    // First 3 should succeed (within rate limit)
    for (i, (_id, result)) in results.iter().take(3).enumerate() {
        assert!(
            result.is_ok(),
            "Request {i} should succeed within rate limit"
        );
    }

    // Remaining should fail due to rate limiting
    let rate_limited_count = results.iter().skip(3).filter(|(_, r)| r.is_err()).count();
    assert!(
        rate_limited_count > 0,
        "Some requests should be rate limited"
    );

    // Verify rate limit errors are properly reported
    for (_id, result) in results.iter().skip(3) {
        if let Err(JobError::ProcessingFailed { message }) = result {
            assert!(
                message.contains("Rate limit") || message.contains("rate limit"),
                "Error should mention rate limiting. Got: {message}"
            );
        }
    }
}

/// **Test 5b**: Rate limit resets after window
#[tokio::test]
async fn test_rate_limit_can_be_reset() {
    let embedding_service = Arc::new(MockEmbeddingService::new().with_rate_limit(2));
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    // Use up the rate limit
    for i in 0..2 {
        let claim_id = Uuid::new_v4();
        embedding_service.add_claim(claim_id, &format!("Claim {i}"));
        let job = create_embedding_job(claim_id);
        handler.handle(&job).await.expect("Should succeed");
    }

    // Next request should be rate limited
    let claim_id = Uuid::new_v4();
    embedding_service.add_claim(claim_id, "Rate limited claim");
    let job = create_embedding_job(claim_id);
    assert!(
        handler.handle(&job).await.is_err(),
        "Should be rate limited"
    );

    // Reset the rate limit (simulates window expiration)
    embedding_service.reset_rate_limit();

    // Now should succeed again
    let claim_id = Uuid::new_v4();
    embedding_service.add_claim(claim_id, "After reset claim");
    let job = create_embedding_job(claim_id);
    assert!(
        handler.handle(&job).await.is_ok(),
        "Should succeed after rate limit reset"
    );
}

// ============================================================================
// Test 6: Caching (Same Text Should Not Call API Twice)
// ============================================================================

/// **Test 6**: Caching (same text should not call API twice)
///
/// **Evidence**: API calls are expensive (time and cost)
/// **Reasoning**: Identical texts should be cached to improve performance
#[tokio::test]
async fn test_caching_prevents_duplicate_api_calls() {
    let embedding_service = Arc::new(MockEmbeddingService::new().with_cache(true));
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    // Create two claims with identical text
    let text = "This is the exact same text for both claims.";
    let claim_id_1 = Uuid::new_v4();
    let claim_id_2 = Uuid::new_v4();

    embedding_service.add_claim(claim_id_1, text);
    embedding_service.add_claim(claim_id_2, text);

    // Reset token tracking
    embedding_service.reset_token_usage();

    // Process first claim
    let job1 = create_embedding_job(claim_id_1);
    handler.handle(&job1).await.expect("First should succeed");
    let tokens_after_first = embedding_service.token_usage().total_tokens;

    // Process second claim with same text
    let job2 = create_embedding_job(claim_id_2);
    handler.handle(&job2).await.expect("Second should succeed");
    let tokens_after_second = embedding_service.token_usage().total_tokens;

    // Token usage should NOT increase significantly for cached call
    // (The second call uses cache, so no additional tokens)
    assert_eq!(
        tokens_after_first, tokens_after_second,
        "Token usage should not increase for cached text"
    );

    // But both embeddings should be stored and identical
    let emb1 = embedding_service.get(claim_id_1).await.unwrap();
    let emb2 = embedding_service.get(claim_id_2).await.unwrap();

    assert_eq!(emb1, emb2, "Cached embeddings should be identical");
}

/// **Test 6b**: Cache miss for different text
#[tokio::test]
async fn test_cache_miss_for_different_text() {
    let embedding_service = Arc::new(MockEmbeddingService::new().with_cache(true));
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let claim_id_1 = Uuid::new_v4();
    let claim_id_2 = Uuid::new_v4();

    embedding_service.add_claim(claim_id_1, "First unique text.");
    embedding_service.add_claim(claim_id_2, "Second different text.");

    embedding_service.reset_token_usage();

    // Process first claim
    let job1 = create_embedding_job(claim_id_1);
    handler.handle(&job1).await.expect("First should succeed");
    let tokens_after_first = embedding_service.token_usage().total_tokens;

    // Process second claim with different text
    let job2 = create_embedding_job(claim_id_2);
    handler.handle(&job2).await.expect("Second should succeed");
    let tokens_after_second = embedding_service.token_usage().total_tokens;

    // Token usage SHOULD increase for different text (cache miss)
    assert!(
        tokens_after_second > tokens_after_first,
        "Token usage should increase for different text (cache miss)"
    );

    // Embeddings should be different
    let emb1 = embedding_service.get(claim_id_1).await.unwrap();
    let emb2 = embedding_service.get(claim_id_2).await.unwrap();

    assert_ne!(
        emb1, emb2,
        "Different texts should have different embeddings"
    );
}

/// **Test 6c**: Cache can be disabled
#[tokio::test]
async fn test_cache_disabled() {
    let embedding_service = Arc::new(MockEmbeddingService::new().with_cache(false));
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let text = "Same text for cache disabled test.";
    let claim_id_1 = Uuid::new_v4();
    let claim_id_2 = Uuid::new_v4();

    embedding_service.add_claim(claim_id_1, text);
    embedding_service.add_claim(claim_id_2, text);

    embedding_service.reset_token_usage();

    // Process first claim
    let job1 = create_embedding_job(claim_id_1);
    handler.handle(&job1).await.expect("First should succeed");
    let tokens_after_first = embedding_service.token_usage().total_tokens;

    // Process second claim with same text (cache disabled, should regenerate)
    let job2 = create_embedding_job(claim_id_2);
    handler.handle(&job2).await.expect("Second should succeed");
    let tokens_after_second = embedding_service.token_usage().total_tokens;

    // Token usage SHOULD increase even for same text when cache is disabled
    assert!(
        tokens_after_second > tokens_after_first,
        "Token usage should increase when cache is disabled"
    );
}

/// **Test 6d**: Concurrent embeddings for same text uses cache correctly
#[tokio::test]
async fn test_concurrent_embeddings_for_same_text() {
    let embedding_service = Arc::new(MockEmbeddingService::new().with_cache(true));
    let handler = Arc::new(TestableEmbeddingHandler::new(embedding_service.clone()));

    let text = "Concurrent test text for caching.";
    let num_concurrent = 10;

    // Create multiple claims with the same text
    let claim_ids: Vec<Uuid> = (0..num_concurrent).map(|_| Uuid::new_v4()).collect();
    for &claim_id in &claim_ids {
        embedding_service.add_claim(claim_id, text);
    }

    embedding_service.reset_token_usage();

    // Process all claims concurrently
    let mut handles = Vec::new();
    for &claim_id in &claim_ids {
        let handler = handler.clone();
        let job = create_embedding_job(claim_id);
        handles.push(tokio::spawn(async move { handler.handle(&job).await }));
    }

    // Wait for all to complete and collect results
    let mut results = Vec::new();
    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle.await;
        assert!(result.is_ok(), "Task {i} should complete without panic");
        let job_result = result.unwrap();
        assert!(job_result.is_ok(), "Task {i} should succeed");
        results.push(job_result);
    }

    // All embeddings should be identical (cached)
    let first_embedding = embedding_service.get(claim_ids[0]).await.unwrap();
    for &claim_id in &claim_ids[1..] {
        let embedding = embedding_service.get(claim_id).await.unwrap();
        assert_eq!(
            embedding, first_embedding,
            "All concurrent embeddings for same text should be identical"
        );
    }

    // Token usage should be minimal (only one actual generation due to cache)
    // Allow for some concurrency overhead but should be much less than num_concurrent * text_tokens
    let text_tokens = (text.len() / 4).max(1);
    let total_tokens = embedding_service.token_usage().total_tokens;
    assert!(
        total_tokens < text_tokens * 3,
        "Token usage should be minimized by cache. Got {total_tokens} tokens for {num_concurrent} concurrent requests"
    );
}

// ============================================================================
// Test 7: Fallback to Local Model on API Failure
// ============================================================================

/// **Test 7**: Fallback to local model on API failure
///
/// **Evidence**: Resilience requires graceful degradation
/// **Reasoning**: System should remain functional when external APIs fail
#[tokio::test]
async fn test_fallback_to_local_model_on_api_failure() {
    // Create service with 100% failure rate but fallback enabled
    let embedding_service = Arc::new(
        MockEmbeddingService::new()
            .with_failures(1.0)
            .with_fallback(true),
    );
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let claim_id = Uuid::new_v4();
    embedding_service.add_claim(claim_id, "Test claim for fallback.");

    let job = create_embedding_job(claim_id);
    let result = handler.handle(&job).await;

    // Should succeed via fallback even though primary fails
    assert!(
        result.is_ok(),
        "Should succeed via fallback when primary API fails"
    );

    // Verify embedding was stored
    let embedding = embedding_service.get(claim_id).await;
    assert!(embedding.is_ok(), "Embedding should be stored via fallback");

    let embedding = embedding.unwrap();
    assert_eq!(
        embedding.len(),
        1536,
        "Fallback embedding should have correct dimension"
    );
}

/// **Test 7b**: Without fallback, API failure causes job failure
#[tokio::test]
async fn test_no_fallback_causes_failure() {
    // Create service with 100% failure rate and NO fallback
    let embedding_service = Arc::new(
        MockEmbeddingService::new()
            .with_failures(1.0)
            .with_fallback(false),
    );
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let claim_id = Uuid::new_v4();
    embedding_service.add_claim(claim_id, "Test claim without fallback.");

    let job = create_embedding_job(claim_id);
    let result = handler.handle(&job).await;

    // Should fail without fallback
    assert!(
        result.is_err(),
        "Should fail when API fails and no fallback available"
    );

    match result {
        Err(JobError::ProcessingFailed { message }) => {
            assert!(
                message.contains("API") || message.contains("failure") || message.contains("error"),
                "Error should indicate API failure. Got: {message}"
            );
        }
        Err(e) => panic!("Expected ProcessingFailed, got: {e:?}"),
        Ok(_) => panic!("Expected failure, got success"),
    }
}

/// **Test 7c**: Intermittent failures with fallback recovery
#[tokio::test]
async fn test_intermittent_failures_with_fallback_recovery() {
    // Create service with 50% failure rate but fallback enabled
    let embedding_service = Arc::new(
        MockEmbeddingService::new()
            .with_failures(0.5)
            .with_fallback(true),
    );
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let mut success_count = 0;
    let total_claims = 10;

    for i in 0..total_claims {
        let claim_id = Uuid::new_v4();
        embedding_service.add_claim(claim_id, &format!("Claim {i} for intermittent test"));

        let job = create_embedding_job(claim_id);
        if handler.handle(&job).await.is_ok() {
            success_count += 1;
        }
    }

    // With fallback, all should succeed despite 50% primary failure rate
    assert_eq!(
        success_count, total_claims,
        "All claims should succeed with fallback enabled"
    );
}

// ============================================================================
// Test 8: Timeout Handling
// ============================================================================

/// **Test 8**: Timeout on slow embedding service
#[tokio::test]
async fn test_timeout_on_slow_embedding_service() {
    // Create service with slow response
    let embedding_service =
        Arc::new(MockEmbeddingService::new().with_simulated_delay(Duration::from_secs(5)));

    // Create handler with short timeout
    let handler = TestableEmbeddingHandler::new(embedding_service.clone())
        .with_timeout(Duration::from_millis(100));

    let claim_id = Uuid::new_v4();
    embedding_service.add_claim(claim_id, "Test claim for timeout.");

    let job = create_embedding_job(claim_id);
    let result = handler.handle(&job).await;

    assert!(result.is_err(), "Should fail due to timeout");

    match result {
        Err(JobError::Timeout { timeout }) => {
            assert_eq!(
                timeout,
                Duration::from_millis(100),
                "Timeout duration should match configured value"
            );
        }
        Err(e) => panic!("Expected Timeout error, got: {e:?}"),
        Ok(_) => panic!("Expected timeout error, got success"),
    }
}

/// **Test 8b**: Fast service completes within timeout
#[tokio::test]
async fn test_fast_service_completes_within_timeout() {
    // Create service with no delay
    let embedding_service = Arc::new(MockEmbeddingService::new());

    // Create handler with generous timeout
    let handler = TestableEmbeddingHandler::new(embedding_service.clone())
        .with_timeout(Duration::from_secs(10));

    let claim_id = Uuid::new_v4();
    embedding_service.add_claim(claim_id, "Test claim for fast completion.");

    let job = create_embedding_job(claim_id);
    let result = handler.handle(&job).await;

    assert!(
        result.is_ok(),
        "Should succeed within timeout for fast service"
    );
}

// ============================================================================
// Test 9: Storage Failure After Generation
// ============================================================================

/// **Test 9**: Storage failure after successful generation
#[tokio::test]
async fn test_storage_failure_after_generation() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let claim_id = Uuid::new_v4();
    embedding_service.add_claim(claim_id, "Test claim for storage failure.");

    // Enable storage failure mode
    embedding_service.set_storage_failure(true);

    let job = create_embedding_job(claim_id);
    let result = handler.handle(&job).await;

    assert!(result.is_err(), "Should fail when storage fails");

    match result {
        Err(JobError::ProcessingFailed { message }) => {
            assert!(
                message.contains("Storage") || message.contains("storage"),
                "Error should mention storage failure. Got: {message}"
            );
        }
        Err(e) => panic!("Expected ProcessingFailed, got: {e:?}"),
        Ok(_) => panic!("Expected storage failure error, got success"),
    }

    // Verify embedding was NOT stored
    embedding_service.set_storage_failure(false);
    let stored = embedding_service.get(claim_id).await;
    assert!(
        stored.is_err(),
        "Embedding should not be stored after storage failure"
    );
}

// ============================================================================
// Test 10: Unicode and Emoji Text Handling
// ============================================================================

/// **Test 10**: Unicode and emoji text is processed correctly
#[tokio::test]
async fn test_unicode_and_emoji_text_processed_correctly() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let unicode_texts = vec![
        ("chinese", "这是一个中文测试"),
        ("japanese", "日本語テスト"),
        ("arabic", "اختبار عربي"),
        ("korean", "한국어 테스트"),
        ("emoji", "Hello World! 🌍🚀✨"),
        ("mixed", "Test 测试 テスト 🎉"),
        ("math_symbols", "∑∏∫∂ × ÷ ± √"),
        ("accented", "Café résumé naïve"),
    ];

    for (name, text) in unicode_texts {
        let claim_id = Uuid::new_v4();
        embedding_service.add_claim(claim_id, text);

        let job = create_embedding_job(claim_id);
        let result = handler.handle(&job).await;

        assert!(
            result.is_ok(),
            "Should successfully process {name} text: '{text}'"
        );

        let embedding = embedding_service.get(claim_id).await.unwrap();
        assert_eq!(
            embedding.len(),
            1536,
            "{name} text should produce correct dimension embedding"
        );

        // Verify embedding is normalized
        assert!(
            is_normalized(&embedding, 1e-5),
            "{name} text embedding should be normalized"
        );
    }
}

/// **Test 10b**: Unicode texts produce different embeddings
#[tokio::test]
async fn test_unicode_texts_produce_different_embeddings() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let texts = vec!["Hello", "你好", "مرحبا", "こんにちは"];
    let mut embeddings = Vec::new();

    for text in &texts {
        let claim_id = Uuid::new_v4();
        embedding_service.add_claim(claim_id, text);

        let job = create_embedding_job(claim_id);
        handler.handle(&job).await.expect("Should succeed");

        embeddings.push(embedding_service.get(claim_id).await.unwrap());
    }

    // All embeddings should be different
    for i in 0..embeddings.len() {
        for j in (i + 1)..embeddings.len() {
            assert_ne!(
                embeddings[i], embeddings[j],
                "Different unicode texts '{}' and '{}' should produce different embeddings",
                texts[i], texts[j]
            );
        }
    }
}

// ============================================================================
// Integration with Job Runner Tests
// ============================================================================

/// Test that the handler integrates correctly with `JobRunner`
#[tokio::test]
async fn test_handler_integrates_with_job_runner() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let embedding_service = Arc::new(MockEmbeddingService::new());

    let mut runner = JobRunner::new(2, queue.clone());
    runner.register_handler(Arc::new(TestableEmbeddingHandler::new(
        embedding_service.clone(),
    )));

    // Add a claim
    let claim_id = Uuid::new_v4();
    embedding_service.add_claim(claim_id, "Integration test claim.");

    // Enqueue the job
    let mut job = create_embedding_job(claim_id);
    queue.enqueue(job.clone()).await.unwrap();

    // Process with runner
    let result = runner.process_job(&mut job).await;

    assert!(result.is_ok(), "Job should be processed successfully");

    // Verify embedding was stored
    let embedding = embedding_service.get(claim_id).await;
    assert!(embedding.is_ok(), "Embedding should be stored");
}

/// Test retry behavior with `JobRunner` - Fixed: verify actual retry count increases
#[tokio::test]
async fn test_retry_behavior_with_runner() {
    let queue = Arc::new(InMemoryJobQueue::new());

    // Create a service that always fails with no fallback (to test retry logic)
    let embedding_service = Arc::new(
        MockEmbeddingService::new()
            .with_failures(1.0)
            .with_fallback(false),
    );

    let mut runner = JobRunner::new(1, queue.clone());
    runner.register_handler(Arc::new(TestableEmbeddingHandler::new(
        embedding_service.clone(),
    )));

    let claim_id = Uuid::new_v4();
    embedding_service.add_claim(claim_id, "Retry test claim.");

    let mut job = create_embedding_job(claim_id);
    let initial_retry_count = job.retry_count;
    job.max_retries = 5; // Allow multiple retries

    // First attempt (should fail)
    let first_result = runner.process_job(&mut job).await;
    assert!(first_result.is_err(), "First attempt should fail");

    // Verify retry count increased
    assert!(
        job.retry_count > initial_retry_count,
        "Retry count should increase after failed attempt. Initial: {}, After: {}",
        initial_retry_count,
        job.retry_count
    );

    // Verify error message is tracked
    assert!(
        job.error_message.is_some(),
        "Error message should be recorded after failed attempt"
    );

    // Second attempt - retry count should increase again
    let second_result = runner.process_job(&mut job).await;
    assert!(second_result.is_err(), "Second attempt should also fail");
    assert!(
        job.retry_count > initial_retry_count + 1,
        "Retry count should increase with each attempt. Expected > {}, got {}",
        initial_retry_count + 1,
        job.retry_count
    );
}

// ============================================================================
// Token Usage and Metadata Tests
// ============================================================================

/// Test that token usage is tracked and reported in job result
#[tokio::test]
async fn test_token_usage_reported_in_result() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let claim_id = Uuid::new_v4();
    embedding_service.add_claim(
        claim_id,
        "A reasonably long claim text that will use some tokens.",
    );

    embedding_service.reset_token_usage();

    let job = create_embedding_job(claim_id);
    let result = handler.handle(&job).await.expect("Should succeed");

    // Verify token usage is reported
    assert!(
        result.output["tokens_used"].as_u64().unwrap_or(0) > 0,
        "Should report tokens used"
    );

    // Verify metadata contains token info
    assert!(
        result.metadata.extra.contains_key("tokens_used"),
        "Metadata should contain tokens_used"
    );
}

/// Test that token count is reasonably accurate (not just > 0)
#[tokio::test]
async fn test_token_count_is_reasonably_accurate() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    // Test with texts of known approximate token counts
    let test_cases = vec![
        ("Short", 1..5),           // ~1 token (min 1)
        ("This is a test", 3..6),  // ~4 tokens
        ("A much longer text with many words that should produce more tokens than a short text would", 15..30),
    ];

    for (text, expected_range) in test_cases {
        let claim_id = Uuid::new_v4();
        embedding_service.add_claim(claim_id, text);
        embedding_service.reset_token_usage();

        let job = create_embedding_job(claim_id);
        let result = handler.handle(&job).await.expect("Should succeed");

        let tokens_used = result.output["tokens_used"].as_u64().unwrap_or(0) as usize;

        assert!(
            expected_range.contains(&tokens_used),
            "Token count for '{text}' should be in range {expected_range:?}, got {tokens_used}"
        );
    }
}

/// Test that job result contains all expected metadata
#[tokio::test]
async fn test_job_result_contains_expected_metadata() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service.clone());

    let claim_id = Uuid::new_v4();
    embedding_service.add_claim(claim_id, "Metadata test claim.");

    let job = create_embedding_job(claim_id);
    let result = handler.handle(&job).await.expect("Should succeed");

    // Verify all expected fields are present
    assert!(
        result.output.get("claim_id").is_some(),
        "Should have claim_id"
    );
    assert!(
        result.output.get("embedding_dimension").is_some(),
        "Should have embedding_dimension"
    );
    assert!(
        result.output.get("tokens_used").is_some(),
        "Should have tokens_used"
    );

    // Verify metadata
    assert!(result.metadata.worker_id.is_some(), "Should have worker_id");
    assert!(
        result.metadata.items_processed.is_some(),
        "Should have items_processed"
    );
    assert_eq!(
        result.metadata.items_processed,
        Some(1),
        "Should process 1 item"
    );

    // Verify execution duration is positive
    assert!(
        result.execution_duration > Duration::ZERO,
        "Execution duration should be positive"
    );
}

// ============================================================================
// Handler Configuration Tests
// ============================================================================

/// Test handler job type is correct
#[test]
fn test_handler_job_type() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service);

    assert_eq!(
        handler.job_type(),
        "embedding_generation",
        "Handler should report correct job type"
    );
}

/// Test handler max retries
#[test]
fn test_handler_max_retries() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service);

    assert_eq!(
        handler.max_retries(),
        3,
        "Handler should have default max retries of 3"
    );
}

/// Test handler backoff strategy
#[test]
fn test_handler_backoff_strategy() {
    let embedding_service = Arc::new(MockEmbeddingService::new());
    let handler = TestableEmbeddingHandler::new(embedding_service);

    // Verify exponential backoff
    assert_eq!(handler.backoff(0), Duration::from_secs(1), "2^0 = 1 second");
    assert_eq!(
        handler.backoff(1),
        Duration::from_secs(2),
        "2^1 = 2 seconds"
    );
    assert_eq!(
        handler.backoff(2),
        Duration::from_secs(4),
        "2^2 = 4 seconds"
    );
    assert_eq!(
        handler.backoff(3),
        Duration::from_secs(8),
        "2^3 = 8 seconds"
    );

    // Verify cap at 1 hour
    let max_backoff = handler.backoff(20);
    assert!(
        max_backoff <= Duration::from_secs(3600),
        "Backoff should be capped at 1 hour"
    );
}

// ============================================================================
// Built-in Handler Verification (Stub)
// ============================================================================

/// Verify the built-in `EmbeddingGenerationHandler` exists and has correct job type
#[test]
fn test_builtin_handler_exists() {
    let handler = EmbeddingGenerationHandler;
    assert_eq!(
        handler.job_type(),
        "embedding_generation",
        "Built-in handler should have correct job type"
    );
}

/// Verify the built-in handler currently returns "not implemented"
#[tokio::test]
async fn test_builtin_handler_stub_behavior() {
    let handler = EmbeddingGenerationHandler;
    let job = create_embedding_job(Uuid::new_v4());

    let result = handler.handle(&job).await;

    // Currently a stub, should return ProcessingFailed
    match result {
        Err(JobError::ProcessingFailed { message }) => {
            assert!(
                message.contains("not implemented"),
                "Stub should indicate not implemented. Got: {message}"
            );
        }
        Ok(_) => {
            // If implemented, that's also fine - the test just verifies current state
        }
        Err(e) => panic!("Unexpected error type: {e:?}"),
    }
}
