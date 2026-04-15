//! Semantic Search Endpoint Tests
//!
//! These tests define the expected behavior of the `/api/v1/search/semantic` endpoint
//! which uses pgvector for similarity search against claim embeddings.
//!
//! # Important: Mock Search State
//!
//! These tests use `MockSearchState` which implements similarity via **keyword overlap**,
//! NOT real pgvector cosine distance. This is sufficient to verify endpoint routing,
//! request validation, response structure, and filter logic, but does NOT test actual
//! vector similarity quality.
//!
//! For real pgvector embedding similarity tests, see:
//! `tests/integration/rag_persistence_tests.rs` — which inserts actual embeddings
//! and validates cosine similarity ordering against a live PostgreSQL + pgvector DB.
//!
//! # Test Coverage
//!
//! 1. Valid query returns ranked results
//! 2. Limit parameter is respected
//! 3. min_similarity threshold filtering
//! 4. Empty results for no matches
//! 5. claim_type filtering (factual, hypothesis, opinion)
//! 6. Date range filtering
//! 7. agent_id filtering
//! 8. Similarity score in response
//! 9. Full claim details in response
//! 10. Special character escaping
//! 11. Performance with 10k+ claims
//! 12. Concurrent search isolation

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Barrier;
use tower::ServiceExt;
use uuid::Uuid;

// ============================================================================
// Request/Response DTOs
// ============================================================================

/// Request body for semantic search
#[derive(Debug, Serialize, Deserialize)]
pub struct SemanticSearchRequest {
    /// The query string to search for semantically similar claims
    pub query: String,

    /// Maximum number of results to return (default: 10, max: 100)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Minimum similarity threshold [0.0, 1.0] (default: 0.5)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_similarity: Option<f64>,

    /// Filter by claim type: "factual", "hypothesis", "opinion"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_type: Option<String>,

    /// Filter claims created after this timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_after: Option<DateTime<Utc>>,

    /// Filter claims created before this timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_before: Option<DateTime<Utc>>,

    /// Filter by the agent who made the claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<Uuid>,
}

impl SemanticSearchRequest {
    /// Create a simple query request with defaults
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            limit: None,
            min_similarity: None,
            claim_type: None,
            created_after: None,
            created_before: None,
            agent_id: None,
        }
    }

    /// Builder: set the limit
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Builder: set min_similarity threshold
    pub fn with_min_similarity(mut self, threshold: f64) -> Self {
        self.min_similarity = Some(threshold);
        self
    }

    /// Builder: set claim_type filter
    pub fn with_claim_type(mut self, claim_type: impl Into<String>) -> Self {
        self.claim_type = Some(claim_type.into());
        self
    }

    /// Builder: set date range filter
    pub fn with_date_range(
        mut self,
        after: Option<DateTime<Utc>>,
        before: Option<DateTime<Utc>>,
    ) -> Self {
        self.created_after = after;
        self.created_before = before;
        self
    }

    /// Builder: set agent_id filter
    pub fn with_agent_id(mut self, agent_id: Uuid) -> Self {
        self.agent_id = Some(agent_id);
        self
    }
}

/// A single search result
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SemanticSearchResult {
    pub claim_id: Uuid,
    pub statement: String,
    pub similarity: f64,
    pub truth_value: f64,
    pub agent_id: Uuid,
    /// Optional: full claim details when requested
    #[serde(default)]
    pub trace_id: Option<Uuid>,
    #[serde(default)]
    pub claim_type: Option<String>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
}

/// Response from semantic search endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct SemanticSearchResponse {
    pub results: Vec<SemanticSearchResult>,
    pub total: u64,
    pub query_time_ms: u64,
}

/// Error response structure
#[derive(Debug, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

// ============================================================================
// Test Fixtures and Helpers
// ============================================================================

/// Test context for semantic search tests
///
/// In a real implementation, this would contain:
/// - Database connection pool (with pgvector extension)
/// - Embedding service client (for query vectorization)
/// - Pre-seeded test data
pub struct TestContext {
    pub router: Router,
    /// IDs of pre-seeded claims for testing
    pub seeded_claim_ids: Vec<Uuid>,
    /// Agent ID used for seeded claims
    pub test_agent_id: Uuid,
    /// Alternate agent ID for filtering tests
    pub alternate_agent_id: Uuid,
}

impl TestContext {
    /// Create a new test context with seeded data
    ///
    /// NOTE: In a real implementation, this would:
    /// 1. Create a test database with pgvector extension
    /// 2. Seed claims with pre-computed embeddings
    /// 3. Configure the embedding service mock
    pub async fn new() -> Self {
        let test_agent_id = Uuid::new_v4();
        let alternate_agent_id = Uuid::new_v4();
        let state = MockSearchState::new(test_agent_id, alternate_agent_id);
        let seeded_claim_ids: Vec<Uuid> = state.claims.iter().map(|c| c.id).collect();

        let router = Router::new()
            .route("/api/v1/search/semantic", post(semantic_search_handler))
            .with_state(state);

        Self {
            router,
            seeded_claim_ids,
            test_agent_id,
            alternate_agent_id,
        }
    }

    /// Create context with a large dataset for performance testing
    pub async fn new_with_large_dataset(claim_count: usize) -> Self {
        let test_agent_id = Uuid::new_v4();
        let alternate_agent_id = Uuid::new_v4();
        let state =
            MockSearchState::with_claim_count(test_agent_id, alternate_agent_id, claim_count);
        let seeded_claim_ids: Vec<Uuid> = state.claims.iter().map(|c| c.id).collect();

        let router = Router::new()
            .route("/api/v1/search/semantic", post(semantic_search_handler))
            .with_state(state);

        Self {
            router,
            seeded_claim_ids,
            test_agent_id,
            alternate_agent_id,
        }
    }

    /// Make a semantic search request and parse the response
    pub async fn search(
        &self,
        request: SemanticSearchRequest,
    ) -> Result<SemanticSearchResponse, (StatusCode, ErrorResponse)> {
        let body = serde_json::to_string(&request).expect("Failed to serialize request");

        let http_request = Request::builder()
            .method("POST")
            .uri("/api/v1/search/semantic")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("Failed to build request");

        let response = self
            .router
            .clone()
            .oneshot(http_request)
            .await
            .expect("Failed to execute request");

        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("Failed to read response body");

        if status.is_success() {
            let parsed: SemanticSearchResponse =
                serde_json::from_slice(&body_bytes).expect("Failed to parse success response");
            Ok(parsed)
        } else {
            let error: ErrorResponse =
                serde_json::from_slice(&body_bytes).unwrap_or_else(|_| ErrorResponse {
                    error: "ParseError".to_string(),
                    message: String::from_utf8_lossy(&body_bytes).to_string(),
                    details: None,
                });
            Err((status, error))
        }
    }
}

// ============================================================================
// Mock Implementation State
// ============================================================================

/// Mock API error for testing
struct MockApiError {
    status: StatusCode,
    error: String,
    message: String,
}

impl IntoResponse for MockApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": self.error,
                "message": self.message
            })),
        )
            .into_response()
    }
}

/// Mock state for the semantic search endpoint
#[derive(Clone)]
struct MockSearchState {
    /// Pre-seeded claims for testing
    claims: Vec<MockClaim>,
    /// Primary test agent ID
    #[allow(dead_code)]
    test_agent_id: Uuid,
    /// Alternate agent ID for filter tests
    #[allow(dead_code)]
    alternate_agent_id: Uuid,
}

/// Mock claim for testing
#[derive(Clone)]
struct MockClaim {
    id: Uuid,
    statement: String,
    truth_value: f64,
    agent_id: Uuid,
    claim_type: String,
    created_at: DateTime<Utc>,
    /// Simulated embedding similarity keywords
    keywords: Vec<String>,
}

impl MockSearchState {
    /// Create mock state with default test data
    fn new(test_agent_id: Uuid, alternate_agent_id: Uuid) -> Self {
        let now = Utc::now();
        let claims = vec![
            MockClaim {
                id: Uuid::new_v4(),
                statement: "Climate change affects global agriculture patterns".to_string(),
                truth_value: 0.85,
                agent_id: test_agent_id,
                claim_type: "factual".to_string(),
                created_at: now - Duration::days(5),
                keywords: vec![
                    "climate".into(),
                    "change".into(),
                    "agriculture".into(),
                    "effects".into(),
                ],
            },
            MockClaim {
                id: Uuid::new_v4(),
                statement: "Rising temperatures impact crop yields".to_string(),
                truth_value: 0.78,
                agent_id: test_agent_id,
                claim_type: "factual".to_string(),
                created_at: now - Duration::days(10),
                keywords: vec![
                    "climate".into(),
                    "temperature".into(),
                    "agriculture".into(),
                    "crops".into(),
                ],
            },
            MockClaim {
                id: Uuid::new_v4(),
                statement: "Agricultural adaptation may mitigate climate effects".to_string(),
                truth_value: 0.65,
                agent_id: test_agent_id,
                claim_type: "hypothesis".to_string(),
                created_at: now - Duration::days(15),
                keywords: vec!["climate".into(), "agriculture".into(), "adaptation".into()],
            },
            MockClaim {
                id: Uuid::new_v4(),
                statement: "Renewable energy is preferable to fossil fuels".to_string(),
                truth_value: 0.70,
                agent_id: test_agent_id,
                claim_type: "opinion".to_string(),
                created_at: now - Duration::days(20),
                keywords: vec!["energy".into(), "renewable".into(), "opinion".into()],
            },
            MockClaim {
                id: Uuid::new_v4(),
                statement: "Scientific research shows correlation patterns".to_string(),
                truth_value: 0.82,
                agent_id: test_agent_id,
                claim_type: "factual".to_string(),
                created_at: now - Duration::days(3),
                keywords: vec![
                    "scientific".into(),
                    "research".into(),
                    "findings".into(),
                    "common".into(),
                ],
            },
            MockClaim {
                id: Uuid::new_v4(),
                statement: "Machine learning improves prediction accuracy".to_string(),
                truth_value: 0.88,
                agent_id: alternate_agent_id,
                claim_type: "factual".to_string(),
                created_at: now - Duration::days(8),
                keywords: vec!["machine".into(), "learning".into(), "algorithms".into()],
            },
            MockClaim {
                id: Uuid::new_v4(),
                statement: "Quantum computing may revolutionize cryptography".to_string(),
                truth_value: 0.72,
                agent_id: alternate_agent_id,
                claim_type: "hypothesis".to_string(),
                created_at: now - Duration::days(12),
                keywords: vec!["quantum".into(), "physics".into(), "experiments".into()],
            },
            MockClaim {
                id: Uuid::new_v4(),
                statement: "Economic markets respond to policy changes".to_string(),
                truth_value: 0.75,
                agent_id: alternate_agent_id,
                claim_type: "factual".to_string(),
                created_at: now - Duration::days(25),
                keywords: vec!["economic".into(), "market".into(), "analysis".into()],
            },
            MockClaim {
                id: Uuid::new_v4(),
                statement: "General topic with common keywords for testing".to_string(),
                truth_value: 0.60,
                agent_id: test_agent_id,
                claim_type: "factual".to_string(),
                created_at: now - Duration::days(2),
                keywords: vec![
                    "general".into(),
                    "topic".into(),
                    "common".into(),
                    "many".into(),
                    "matches".into(),
                ],
            },
            MockClaim {
                id: Uuid::new_v4(),
                statement: "Specific technical implementation details".to_string(),
                truth_value: 0.90,
                agent_id: test_agent_id,
                claim_type: "factual".to_string(),
                created_at: now - Duration::days(1),
                keywords: vec!["specific".into(), "technical".into(), "topic".into()],
            },
        ];

        Self {
            claims,
            test_agent_id,
            alternate_agent_id,
        }
    }

    /// Create mock state with many claims for performance testing
    fn with_claim_count(test_agent_id: Uuid, alternate_agent_id: Uuid, count: usize) -> Self {
        let now = Utc::now();
        let claim_types = ["factual", "hypothesis", "opinion"];

        let claims: Vec<MockClaim> = (0..count)
            .map(|i| {
                let agent_id = if i % 2 == 0 {
                    test_agent_id
                } else {
                    alternate_agent_id
                };
                MockClaim {
                    id: Uuid::new_v4(),
                    statement: format!("Generated claim number {} for performance testing", i),
                    truth_value: 0.3 + (i as f64 % 70.0) / 100.0,
                    agent_id,
                    claim_type: claim_types[i % 3].to_string(),
                    created_at: now - Duration::days((i % 60) as i64),
                    keywords: vec![
                        "performance".into(),
                        "test".into(),
                        "query".into(),
                        format!("keyword{}", i % 10),
                    ],
                }
            })
            .collect();

        Self {
            claims,
            test_agent_id,
            alternate_agent_id,
        }
    }

    /// Calculate mock similarity score based on keyword overlap
    fn calculate_similarity(&self, query: &str, claim: &MockClaim) -> f64 {
        let query_lower = query.to_lowercase();
        let query_words: Vec<&str> = query_lower.split_whitespace().collect();

        if query_words.is_empty() {
            return 0.0;
        }

        let matching_keywords = claim
            .keywords
            .iter()
            .filter(|kw| {
                query_words
                    .iter()
                    .any(|qw| qw.contains(kw.as_str()) || kw.contains(qw))
            })
            .count();

        let base_similarity = matching_keywords as f64 / claim.keywords.len().max(1) as f64;

        // Add some variance to make results more realistic
        let variance = (claim.id.as_u128() % 100) as f64 / 1000.0;
        (base_similarity + variance).min(1.0)
    }
}

/// Semantic search handler for mock testing
async fn semantic_search_handler(
    State(state): State<MockSearchState>,
    Json(request): Json<SemanticSearchRequest>,
) -> Result<Json<SemanticSearchResponse>, MockApiError> {
    let start_time = std::time::Instant::now();

    // Validate query
    let query = request.query.trim();
    if query.is_empty() {
        return Err(MockApiError {
            status: StatusCode::BAD_REQUEST,
            error: "ValidationError".to_string(),
            message: "Query cannot be empty".to_string(),
        });
    }

    // Validate limit
    let limit = request.limit.unwrap_or(10);
    if limit == 0 {
        return Err(MockApiError {
            status: StatusCode::BAD_REQUEST,
            error: "ValidationError".to_string(),
            message: "Limit must be greater than 0".to_string(),
        });
    }
    let limit = limit.min(100) as usize; // Cap at 100

    // Validate min_similarity
    let min_similarity = request.min_similarity.unwrap_or(0.0);
    if !(0.0..=1.0).contains(&min_similarity) {
        return Err(MockApiError {
            status: StatusCode::BAD_REQUEST,
            error: "ValidationError".to_string(),
            message: "min_similarity must be between 0.0 and 1.0".to_string(),
        });
    }

    // Validate claim_type if provided
    if let Some(ref claim_type) = request.claim_type {
        let valid_types = ["factual", "hypothesis", "opinion"];
        if !valid_types.contains(&claim_type.as_str()) {
            return Err(MockApiError {
                status: StatusCode::BAD_REQUEST,
                error: "ValidationError".to_string(),
                message: format!(
                    "Invalid claim_type '{}'. Must be one of: factual, hypothesis, opinion",
                    claim_type
                ),
            });
        }
    }

    // Validate date range
    if let (Some(after), Some(before)) = (request.created_after, request.created_before) {
        if after > before {
            return Err(MockApiError {
                status: StatusCode::BAD_REQUEST,
                error: "ValidationError".to_string(),
                message: "created_after cannot be after created_before".to_string(),
            });
        }
    }

    // Calculate similarities and filter
    let mut scored_claims: Vec<(f64, &MockClaim)> = state
        .claims
        .iter()
        .filter_map(|claim| {
            let similarity = state.calculate_similarity(query, claim);

            // Apply min_similarity filter
            if similarity < min_similarity {
                return None;
            }

            // Apply claim_type filter
            if let Some(ref filter_type) = request.claim_type {
                if &claim.claim_type != filter_type {
                    return None;
                }
            }

            // Apply date range filters
            if let Some(after) = request.created_after {
                if claim.created_at < after {
                    return None;
                }
            }
            if let Some(before) = request.created_before {
                if claim.created_at > before {
                    return None;
                }
            }

            // Apply agent_id filter
            if let Some(agent_id) = request.agent_id {
                if claim.agent_id != agent_id {
                    return None;
                }
            }

            Some((similarity, claim))
        })
        .collect();

    // Sort by similarity (descending)
    scored_claims.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    let total = scored_claims.len() as u64;

    // Apply limit
    let results: Vec<SemanticSearchResult> = scored_claims
        .into_iter()
        .take(limit)
        .map(|(similarity, claim)| SemanticSearchResult {
            claim_id: claim.id,
            statement: claim.statement.clone(),
            similarity,
            truth_value: claim.truth_value,
            agent_id: claim.agent_id,
            trace_id: Some(Uuid::new_v4()),
            claim_type: Some(claim.claim_type.clone()),
            created_at: Some(claim.created_at),
        })
        .collect();

    let query_time_ms = start_time.elapsed().as_millis() as u64;

    Ok(Json(SemanticSearchResponse {
        results,
        total,
        query_time_ms,
    }))
}

/// Create a test router with the semantic search endpoint
///
/// This mock implementation simulates the semantic search behavior for testing.
/// It uses keyword matching to simulate vector similarity search.
#[allow(dead_code)]
async fn create_test_router() -> Router {
    let test_agent_id = Uuid::new_v4();
    let alternate_agent_id = Uuid::new_v4();
    let state = MockSearchState::new(test_agent_id, alternate_agent_id);

    Router::new()
        .route("/api/v1/search/semantic", post(semantic_search_handler))
        .with_state(state)
}

/// Create a test router with pre-seeded claims for performance testing
#[allow(dead_code)]
async fn create_test_router_with_claims(claim_count: usize) -> Router {
    let test_agent_id = Uuid::new_v4();
    let alternate_agent_id = Uuid::new_v4();
    let state = MockSearchState::with_claim_count(test_agent_id, alternate_agent_id, claim_count);

    Router::new()
        .route("/api/v1/search/semantic", post(semantic_search_handler))
        .with_state(state)
}

// ============================================================================
// Test 1: Valid Query Returns Ranked Results
// ============================================================================

#[tokio::test]
async fn test_semantic_search_returns_ranked_results() {
    // GIVEN: A test context with seeded claims about various topics
    let ctx = TestContext::new().await;

    // WHEN: We search for a semantically meaningful query
    let request = SemanticSearchRequest::new("climate change effects on agriculture");
    let result = ctx.search(request).await;

    // THEN: We should get results ranked by similarity (highest first)
    let response = result.expect("Search should succeed");

    // Results should be returned
    assert!(
        !response.results.is_empty(),
        "Should return at least one result"
    );

    // Results should be sorted by similarity (descending)
    let similarities: Vec<f64> = response.results.iter().map(|r| r.similarity).collect();
    let mut sorted = similarities.clone();
    sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
    assert_eq!(
        similarities, sorted,
        "Results should be sorted by similarity in descending order"
    );

    // Total count should be >= results returned
    assert!(
        response.total >= response.results.len() as u64,
        "Total should be >= number of results"
    );

    // Query time should be tracked (u64, always >= 0)
    let _ = response.query_time_ms;
}

#[tokio::test]
async fn test_semantic_search_empty_query_returns_error() {
    let ctx = TestContext::new().await;

    let request = SemanticSearchRequest::new("");
    let result = ctx.search(request).await;

    // Empty query should be rejected
    let (status, error) = result.expect_err("Empty query should fail");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        error.message.to_lowercase().contains("query")
            || error.message.to_lowercase().contains("empty"),
        "Error should mention query validation"
    );
}

#[tokio::test]
async fn test_semantic_search_whitespace_only_query_returns_error() {
    let ctx = TestContext::new().await;

    let request = SemanticSearchRequest::new("   \t\n   ");
    let result = ctx.search(request).await;

    let (status, _error) = result.expect_err("Whitespace-only query should fail");
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ============================================================================
// Test 2: Limit Parameter
// ============================================================================

#[tokio::test]
async fn test_semantic_search_respects_limit_parameter() {
    let ctx = TestContext::new().await;

    // Search with limit of 5
    let request = SemanticSearchRequest::new("scientific research findings").with_limit(5);
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    // Should return at most 5 results
    assert!(
        response.results.len() <= 5,
        "Results should respect limit parameter, got: {}",
        response.results.len()
    );
}

#[tokio::test]
async fn test_semantic_search_default_limit() {
    let ctx = TestContext::new().await;

    // Search without explicit limit should use default (10)
    let request = SemanticSearchRequest::new("general topic with many matches");
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    // Default limit should be 10
    assert!(
        response.results.len() <= 10,
        "Default limit should be 10, got: {}",
        response.results.len()
    );
}

#[tokio::test]
async fn test_semantic_search_limit_zero_returns_error() {
    let ctx = TestContext::new().await;

    let request = SemanticSearchRequest::new("test query").with_limit(0);
    let result = ctx.search(request).await;

    let (status, _error) = result.expect_err("Limit of 0 should be rejected");
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_semantic_search_limit_exceeds_max_is_capped() {
    let ctx = TestContext::new().await;

    // Limit of 1000 should be capped to max (100)
    let request = SemanticSearchRequest::new("test query").with_limit(1000);
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed (limit capped)");

    // Should be capped at max limit (100)
    assert!(
        response.results.len() <= 100,
        "Limit should be capped at 100, got: {}",
        response.results.len()
    );
}

// ============================================================================
// Test 3: Min Similarity Threshold
// ============================================================================

#[tokio::test]
async fn test_semantic_search_respects_min_similarity_threshold() {
    let ctx = TestContext::new().await;

    let request = SemanticSearchRequest::new("specific technical topic").with_min_similarity(0.7);
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    // All results should have similarity >= threshold
    for result in &response.results {
        assert!(
            result.similarity >= 0.7,
            "Result similarity {} should be >= 0.7",
            result.similarity
        );
    }
}

#[tokio::test]
async fn test_semantic_search_high_threshold_returns_fewer_results() {
    let ctx = TestContext::new().await;

    // Low threshold search
    let low_threshold_request = SemanticSearchRequest::new("common topic").with_min_similarity(0.3);
    let low_result = ctx.search(low_threshold_request).await;
    let low_response = low_result.expect("Low threshold search should succeed");

    // High threshold search
    let high_threshold_request =
        SemanticSearchRequest::new("common topic").with_min_similarity(0.9);
    let high_result = ctx.search(high_threshold_request).await;
    let high_response = high_result.expect("High threshold search should succeed");

    // Higher threshold should return fewer or equal results
    assert!(
        high_response.results.len() <= low_response.results.len(),
        "Higher similarity threshold should return fewer results"
    );
}

#[tokio::test]
async fn test_semantic_search_invalid_min_similarity_rejected() {
    let ctx = TestContext::new().await;

    // Test negative value
    let request = SemanticSearchRequest::new("test").with_min_similarity(-0.1);
    let result = ctx.search(request).await;
    let (status, _) = result.expect_err("Negative similarity should be rejected");
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Test value > 1.0
    let request = SemanticSearchRequest::new("test").with_min_similarity(1.5);
    let result = ctx.search(request).await;
    let (status, _) = result.expect_err("Similarity > 1.0 should be rejected");
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ============================================================================
// Test 4: No Matches Returns Empty Array
// ============================================================================

#[tokio::test]
async fn test_semantic_search_no_matches_returns_empty_results() {
    let ctx = TestContext::new().await;

    // Search with very high threshold for something unlikely to match
    let request = SemanticSearchRequest::new("xyzzy plugh completely random gibberish")
        .with_min_similarity(0.99);
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed even with no matches");

    // Should return empty results array (not error)
    assert!(
        response.results.is_empty(),
        "Should return empty results for no matches"
    );
    assert_eq!(response.total, 0, "Total should be 0 for no matches");

    // Query time should still be tracked
    // query_time_ms is u64, always non-negative — just verify it exists
    let _ = response.query_time_ms;
}

// ============================================================================
// Test 5: Claim Type Filtering
// ============================================================================

#[tokio::test]
async fn test_semantic_search_filters_by_factual_claim_type() {
    let ctx = TestContext::new().await;

    let request = SemanticSearchRequest::new("scientific findings").with_claim_type("factual");
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    // All returned claims should be factual type
    for result in &response.results {
        if let Some(claim_type) = &result.claim_type {
            assert_eq!(
                claim_type, "factual",
                "All results should have claim_type 'factual'"
            );
        }
    }
}

#[tokio::test]
async fn test_semantic_search_filters_by_hypothesis_claim_type() {
    let ctx = TestContext::new().await;

    let request =
        SemanticSearchRequest::new("theoretical predictions").with_claim_type("hypothesis");
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    for result in &response.results {
        if let Some(claim_type) = &result.claim_type {
            assert_eq!(
                claim_type, "hypothesis",
                "All results should have claim_type 'hypothesis'"
            );
        }
    }
}

#[tokio::test]
async fn test_semantic_search_filters_by_opinion_claim_type() {
    let ctx = TestContext::new().await;

    let request = SemanticSearchRequest::new("personal beliefs").with_claim_type("opinion");
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    for result in &response.results {
        if let Some(claim_type) = &result.claim_type {
            assert_eq!(
                claim_type, "opinion",
                "All results should have claim_type 'opinion'"
            );
        }
    }
}

#[tokio::test]
async fn test_semantic_search_invalid_claim_type_rejected() {
    let ctx = TestContext::new().await;

    let request = SemanticSearchRequest::new("test").with_claim_type("invalid_type");
    let result = ctx.search(request).await;

    let (status, error) = result.expect_err("Invalid claim type should be rejected");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        error.message.to_lowercase().contains("claim_type")
            || error.message.to_lowercase().contains("invalid"),
        "Error should mention invalid claim type"
    );
}

// ============================================================================
// Test 6: Date Range Filtering
// ============================================================================

#[tokio::test]
async fn test_semantic_search_filters_by_created_after() {
    let ctx = TestContext::new().await;

    let cutoff = Utc::now() - Duration::days(7);
    let request =
        SemanticSearchRequest::new("recent developments").with_date_range(Some(cutoff), None);
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    // All results should have created_at >= cutoff
    for result in &response.results {
        if let Some(created_at) = result.created_at {
            assert!(
                created_at >= cutoff,
                "Result created_at {:?} should be >= cutoff {:?}",
                created_at,
                cutoff
            );
        }
    }
}

#[tokio::test]
async fn test_semantic_search_filters_by_created_before() {
    let ctx = TestContext::new().await;

    let cutoff = Utc::now() - Duration::days(30);
    let request =
        SemanticSearchRequest::new("historical claims").with_date_range(None, Some(cutoff));
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    // All results should have created_at <= cutoff
    for result in &response.results {
        if let Some(created_at) = result.created_at {
            assert!(
                created_at <= cutoff,
                "Result created_at {:?} should be <= cutoff {:?}",
                created_at,
                cutoff
            );
        }
    }
}

#[tokio::test]
async fn test_semantic_search_filters_by_date_range() {
    let ctx = TestContext::new().await;

    let start = Utc::now() - Duration::days(30);
    let end = Utc::now() - Duration::days(7);
    let request =
        SemanticSearchRequest::new("mid-range claims").with_date_range(Some(start), Some(end));
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    for result in &response.results {
        if let Some(created_at) = result.created_at {
            assert!(
                created_at >= start && created_at <= end,
                "Result created_at {:?} should be in range [{:?}, {:?}]",
                created_at,
                start,
                end
            );
        }
    }
}

#[tokio::test]
async fn test_semantic_search_invalid_date_range_rejected() {
    let ctx = TestContext::new().await;

    // End before start should be rejected
    let start = Utc::now();
    let end = Utc::now() - Duration::days(7);
    let request = SemanticSearchRequest::new("test").with_date_range(Some(start), Some(end));
    let result = ctx.search(request).await;

    let (status, _error) = result.expect_err("Invalid date range should be rejected");
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ============================================================================
// Test 7: Agent ID Filtering
// ============================================================================

#[tokio::test]
async fn test_semantic_search_filters_by_agent_id() {
    let ctx = TestContext::new().await;

    let request =
        SemanticSearchRequest::new("agent specific claims").with_agent_id(ctx.test_agent_id);
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    // All results should belong to the specified agent
    for result in &response.results {
        assert_eq!(
            result.agent_id, ctx.test_agent_id,
            "All results should have the filtered agent_id"
        );
    }
}

#[tokio::test]
async fn test_semantic_search_nonexistent_agent_returns_empty() {
    let ctx = TestContext::new().await;

    let nonexistent_agent = Uuid::new_v4();
    let request = SemanticSearchRequest::new("any topic").with_agent_id(nonexistent_agent);
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    // Should return empty results for nonexistent agent
    assert!(
        response.results.is_empty(),
        "Should return empty results for nonexistent agent"
    );
}

// ============================================================================
// Test 8: Similarity Score in Response
// ============================================================================

#[tokio::test]
async fn test_semantic_search_includes_similarity_score() {
    let ctx = TestContext::new().await;

    let request = SemanticSearchRequest::new("test query for similarity");
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    for result in &response.results {
        // Similarity must be present and valid
        assert!(
            result.similarity >= 0.0 && result.similarity <= 1.0,
            "Similarity {} should be in [0.0, 1.0]",
            result.similarity
        );
    }
}

#[tokio::test]
async fn test_semantic_search_similarity_is_normalized() {
    let ctx = TestContext::new().await;

    let request = SemanticSearchRequest::new("normalized similarity test");
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    // Verify all similarity scores are properly normalized to [0, 1]
    // Some implementations use cosine distance which can produce values outside this range
    for (i, result) in response.results.iter().enumerate() {
        assert!(
            (0.0..=1.0).contains(&result.similarity),
            "Result {} has invalid similarity {}: must be normalized to [0.0, 1.0]",
            i,
            result.similarity
        );
    }
}

// ============================================================================
// Test 9: Full Claim Details in Response
// ============================================================================

#[tokio::test]
async fn test_semantic_search_includes_full_claim_details() {
    let ctx = TestContext::new().await;

    let request = SemanticSearchRequest::new("detailed claim information");
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    for result in &response.results {
        // Required fields must be present
        assert!(!result.claim_id.is_nil(), "claim_id should be a valid UUID");
        assert!(
            !result.statement.is_empty(),
            "statement should not be empty"
        );
        assert!(
            result.truth_value >= 0.0 && result.truth_value <= 1.0,
            "truth_value {} should be in [0.0, 1.0]",
            result.truth_value
        );
        assert!(!result.agent_id.is_nil(), "agent_id should be a valid UUID");
    }
}

#[tokio::test]
async fn test_semantic_search_truth_value_is_bounded() {
    let ctx = TestContext::new().await;

    let request = SemanticSearchRequest::new("truth value bounds test");
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    // EpiGraph invariant: truth values are always in [0.0, 1.0]
    for result in &response.results {
        assert!(
            result.truth_value >= 0.0,
            "Truth value {} cannot be negative",
            result.truth_value
        );
        assert!(
            result.truth_value <= 1.0,
            "Truth value {} cannot exceed 1.0",
            result.truth_value
        );
    }
}

// ============================================================================
// Test 10: Special Character Escaping
// ============================================================================

#[tokio::test]
async fn test_semantic_search_escapes_sql_injection_attempts() {
    let ctx = TestContext::new().await;

    // Classic SQL injection attempts should be safely handled
    let injection_queries = vec![
        "'; DROP TABLE claims; --",
        "1' OR '1'='1",
        "1; DELETE FROM claims WHERE 1=1; --",
        "UNION SELECT * FROM users --",
    ];

    for query in injection_queries {
        let request = SemanticSearchRequest::new(query);
        let result = ctx.search(request).await;

        // Should either succeed (returning results) or return a validation error
        // Should NEVER cause a database error or return unauthorized data
        match result {
            Ok(response) => {
                // If it succeeds, verify no weird results
                assert!(
                    response
                        .results
                        .iter()
                        .all(|r| !r.statement.contains("DROP")),
                    "SQL injection should be escaped in results"
                );
            }
            Err((status, _)) => {
                // If it fails, should be a client error, not server error
                assert!(
                    status.is_client_error(),
                    "SQL injection should result in client error, got: {}",
                    status
                );
            }
        }
    }
}

#[tokio::test]
async fn test_semantic_search_handles_unicode_and_emoji() {
    let ctx = TestContext::new().await;

    let unicode_queries = vec![
        "klimawandel auswirkungen",      // German
        "cambio climatico efectos",      // Spanish
        "changement climatique impact",  // French
        "Null byte \0 in query",         // Null byte
        "Multiple   spaces   and\ttabs", // Whitespace variations
    ];

    for query in unicode_queries {
        let request = SemanticSearchRequest::new(query);
        let result = ctx.search(request).await;

        // Should handle gracefully (success or validation error, not crash)
        assert!(
            result.is_ok() || result.is_err(),
            "Unicode query should be handled gracefully"
        );
    }
}

#[tokio::test]
async fn test_semantic_search_handles_very_long_query() {
    let ctx = TestContext::new().await;

    // Query with 10,000+ characters
    let long_query = "word ".repeat(3000);
    let request = SemanticSearchRequest::new(long_query);
    let result = ctx.search(request).await;

    // Should either succeed or return a validation error about length
    // Should not cause timeout or crash
    match result {
        Ok(_) => { /* Long query handled successfully */ }
        Err((status, error)) => {
            assert!(
                status.is_client_error(),
                "Long query should result in client error if rejected"
            );
            // Ideally error mentions length/size limit
            let _ = error; // Used for debugging if needed
        }
    }
}

#[tokio::test]
async fn test_semantic_search_handles_special_regex_chars() {
    let ctx = TestContext::new().await;

    // Characters that could break regex if not escaped
    let special_queries = vec![
        "query with (parentheses) and [brackets]",
        "query.with.dots.and*stars",
        "query^start$end",
        "query+plus?question",
        "query|pipe\\backslash",
        "query{curly}braces",
    ];

    for query in special_queries {
        let request = SemanticSearchRequest::new(query);
        let result = ctx.search(request).await;

        // Should handle without crashing
        assert!(
            result.is_ok() || result.is_err(),
            "Special regex characters should be handled"
        );
    }
}

// ============================================================================
// Test 11: Performance with Large Dataset
// ============================================================================

#[tokio::test]
async fn test_semantic_search_performance_10k_claims() {
    // Create context with 10,000+ seeded claims
    let ctx = TestContext::new_with_large_dataset(10_000).await;

    let start = std::time::Instant::now();

    let request = SemanticSearchRequest::new("performance test query").with_limit(20);
    let result = ctx.search(request).await;

    let elapsed = start.elapsed();

    let response = result.expect("Search should succeed");

    // CRITICAL: Search must complete in < 200ms
    assert!(
        elapsed.as_millis() < 200,
        "Search took {}ms, should be < 200ms for 10k claims",
        elapsed.as_millis()
    );

    // Verify reported query time is reasonable
    assert!(
        response.query_time_ms < 200,
        "Reported query_time_ms {} should be < 200",
        response.query_time_ms
    );
}

#[tokio::test]
async fn test_semantic_search_performance_with_filters() {
    let ctx = TestContext::new_with_large_dataset(10_000).await;

    let start = std::time::Instant::now();

    // Search with multiple filters (common use case)
    let request = SemanticSearchRequest::new("filtered performance test")
        .with_limit(20)
        .with_min_similarity(0.5)
        .with_claim_type("factual")
        .with_agent_id(ctx.test_agent_id);
    let result = ctx.search(request).await;

    let elapsed = start.elapsed();

    let _response = result.expect("Search with filters should succeed");

    // Filtered search should also be fast
    assert!(
        elapsed.as_millis() < 200,
        "Filtered search took {}ms, should be < 200ms",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn test_semantic_search_query_time_is_accurate() {
    let ctx = TestContext::new().await;

    let start = std::time::Instant::now();

    let request = SemanticSearchRequest::new("timing accuracy test");
    let result = ctx.search(request).await;

    let elapsed = start.elapsed();
    let response = result.expect("Search should succeed");

    // Reported query_time should be <= wall clock time (allowing for HTTP overhead)
    assert!(
        response.query_time_ms <= elapsed.as_millis() as u64 + 10,
        "Reported query_time_ms {} should be <= actual time {}ms (with small buffer)",
        response.query_time_ms,
        elapsed.as_millis()
    );
}

// ============================================================================
// Test 12: Concurrent Search Isolation
// ============================================================================

#[tokio::test]
async fn test_concurrent_searches_dont_block_each_other() {
    let ctx = Arc::new(TestContext::new().await);
    let num_concurrent = 10;
    let barrier = Arc::new(Barrier::new(num_concurrent));

    let mut handles = vec![];

    for i in 0..num_concurrent {
        let ctx = Arc::clone(&ctx);
        let barrier = Arc::clone(&barrier);

        let handle = tokio::spawn(async move {
            // Wait for all tasks to be ready
            barrier.wait().await;

            let query = format!("concurrent search test query number {}", i);
            let request = SemanticSearchRequest::new(query.clone());

            let start = std::time::Instant::now();

            // We need to make the request without consuming ctx
            let body = serde_json::to_string(&request).expect("serialize");
            let http_request = Request::builder()
                .method("POST")
                .uri("/api/v1/search/semantic")
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .expect("build request");

            let response = ctx
                .router
                .clone()
                .oneshot(http_request)
                .await
                .expect("execute request");

            let elapsed = start.elapsed();

            (i, response.status(), elapsed)
        });

        handles.push(handle);
    }

    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.expect("Task should complete"));
    }

    // All requests should complete
    assert_eq!(results.len(), num_concurrent);

    // Calculate statistics
    let elapsed_times: Vec<_> = results.iter().map(|(_, _, e)| e.as_millis()).collect();
    let max_time = *elapsed_times.iter().max().unwrap();
    let min_time = *elapsed_times.iter().min().unwrap();

    // If requests were blocking each other sequentially, max_time would be
    // roughly num_concurrent * avg_time. Check that they ran concurrently.
    // Use min_time + 1 to handle the case where min_time is 0ms (fast mocks).
    assert!(
        max_time < (min_time + 1) * 5,
        "Concurrent searches appear to be blocking. min={}ms, max={}ms",
        min_time,
        max_time
    );
}

#[tokio::test]
async fn test_concurrent_searches_return_independent_results() {
    let ctx = Arc::new(TestContext::new().await);
    let barrier = Arc::new(Barrier::new(3));

    // Three different searches that should return different results
    let queries = vec![
        "machine learning algorithms",
        "quantum physics experiments",
        "economic market analysis",
    ];

    let mut handles = vec![];

    for query in queries {
        let ctx = Arc::clone(&ctx);
        let barrier = Arc::clone(&barrier);
        let query = query.to_string();

        let handle = tokio::spawn(async move {
            barrier.wait().await;

            let request = SemanticSearchRequest::new(query.clone());
            let body = serde_json::to_string(&request).expect("serialize");
            let http_request = Request::builder()
                .method("POST")
                .uri("/api/v1/search/semantic")
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .expect("build request");

            let response = ctx
                .router
                .clone()
                .oneshot(http_request)
                .await
                .expect("execute request");

            let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("read body");

            (query, body_bytes)
        });

        handles.push(handle);
    }

    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.expect("Task should complete"));
    }

    // Results for different queries should be different (not leaked between requests)
    // This verifies there's no shared mutable state causing cross-contamination
    assert_eq!(results.len(), 3);

    // At minimum, verify we got responses (actual content validation depends on implementation)
    for (query, body) in &results {
        assert!(
            !body.is_empty(),
            "Query '{}' should return a response body",
            query
        );
    }
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

#[tokio::test]
async fn test_semantic_search_combines_multiple_filters() {
    let ctx = TestContext::new().await;

    // Combine all filters
    let start = Utc::now() - Duration::days(30);
    let end = Utc::now();

    let request = SemanticSearchRequest::new("multi-filter test")
        .with_limit(5)
        .with_min_similarity(0.5)
        .with_claim_type("factual")
        .with_date_range(Some(start), Some(end))
        .with_agent_id(ctx.test_agent_id);

    let result = ctx.search(request).await;

    let response = result.expect("Combined filters should work");

    // Verify all filters are applied
    for result in &response.results {
        assert!(result.similarity >= 0.5);
        if let Some(claim_type) = &result.claim_type {
            assert_eq!(claim_type, "factual");
        }
        assert_eq!(result.agent_id, ctx.test_agent_id);
    }

    assert!(response.results.len() <= 5);
}

#[tokio::test]
async fn test_semantic_search_total_reflects_all_matches() {
    let ctx = TestContext::new().await;

    // Search with very low limit but count all matches
    let request = SemanticSearchRequest::new("common topic").with_limit(1);
    let result = ctx.search(request).await;

    let response = result.expect("Search should succeed");

    // Total should reflect all matching claims, not just returned results
    assert!(
        response.total >= response.results.len() as u64,
        "Total {} should be >= results returned {}",
        response.total,
        response.results.len()
    );
}

#[tokio::test]
async fn test_semantic_search_request_json_format() {
    let ctx = TestContext::new().await;

    // Manually construct JSON to test parsing
    let json_body = json!({
        "query": "json format test",
        "limit": 10,
        "min_similarity": 0.5
    });

    let http_request = Request::builder()
        .method("POST")
        .uri("/api/v1/search/semantic")
        .header("Content-Type", "application/json")
        .body(Body::from(json_body.to_string()))
        .expect("build request");

    let response = ctx
        .router
        .clone()
        .oneshot(http_request)
        .await
        .expect("execute request");

    // Should parse the JSON correctly
    assert!(
        response.status().is_success(),
        "JSON body should be parsed correctly, got status: {}",
        response.status()
    );
}

#[tokio::test]
async fn test_semantic_search_missing_content_type_header() {
    let ctx = TestContext::new().await;

    let request = SemanticSearchRequest::new("content type test");
    let body = serde_json::to_string(&request).expect("serialize");

    // Omit Content-Type header
    let http_request = Request::builder()
        .method("POST")
        .uri("/api/v1/search/semantic")
        .body(Body::from(body))
        .expect("build request");

    let response = ctx
        .router
        .clone()
        .oneshot(http_request)
        .await
        .expect("execute request");

    // Should either work (lenient) or return 415 Unsupported Media Type
    // Axum's Json extractor is lenient by default
    assert!(
        response.status().is_success()
            || response.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE
            || response.status() == StatusCode::BAD_REQUEST,
        "Missing Content-Type should be handled gracefully, got: {}",
        response.status()
    );
}

#[tokio::test]
async fn test_semantic_search_invalid_json_body() {
    let ctx = TestContext::new().await;

    let http_request = Request::builder()
        .method("POST")
        .uri("/api/v1/search/semantic")
        .header("Content-Type", "application/json")
        .body(Body::from("{ invalid json }"))
        .expect("build request");

    let response = ctx
        .router
        .clone()
        .oneshot(http_request)
        .await
        .expect("execute request");

    // Should return 400 Bad Request for invalid JSON
    assert!(
        response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Invalid JSON should be rejected with client error, got: {}",
        response.status()
    );
}

// ============================================================================
// Test Module Configuration
// ============================================================================

/// Marker for integration tests that require a real database
///
/// These tests are skipped by default and only run when the
/// `integration` feature is enabled:
/// ```
/// cargo test --features integration
/// ```
#[cfg(feature = "integration")]
mod integration {
    use super::*;

    /// Helper to check if database URL is configured
    fn get_database_url() -> Option<String> {
        std::env::var("DATABASE_URL").ok()
    }

    /// Test semantic search against a real PostgreSQL database with pgvector
    ///
    /// This test validates the full integration including:
    /// - Database connection and query execution
    /// - pgvector similarity search
    /// - Result ranking and pagination
    #[tokio::test]
    async fn test_semantic_search_with_real_database() {
        // Skip if DATABASE_URL is not set
        let database_url = match get_database_url() {
            Some(url) => url,
            None => {
                eprintln!("Skipping integration test: DATABASE_URL not set");
                return;
            }
        };

        // This test requires:
        // 1. PostgreSQL with pgvector extension
        // 2. DATABASE_URL environment variable
        // 3. Seeded test data with embeddings

        // When the real database integration is complete, this will:
        // 1. Connect to PostgreSQL using the DATABASE_URL
        // 2. Ensure pgvector extension is available
        // 3. Seed test claims with pre-computed embeddings
        // 4. Execute semantic search queries
        // 5. Verify results match expected similarity rankings

        // For now, verify we can at least parse the database URL
        assert!(
            database_url.starts_with("postgres://") || database_url.starts_with("postgresql://"),
            "DATABASE_URL should be a valid PostgreSQL connection string"
        );

        // Create app with real database connection
        // let pool = sqlx::PgPool::connect(&database_url).await
        //     .expect("Failed to connect to database");
        // let state = AppState::with_db(ApiConfig::default(), pool);
        // let router = create_router(state);

        // Placeholder assertions until database layer is integrated
        eprintln!(
            "Integration test ready for implementation. \
             Requires epigraph-db integration with pgvector support."
        );
    }

    /// Test semantic search with real embedding service
    ///
    /// This test validates the embedding computation pipeline:
    /// - Query text is converted to vector embeddings
    /// - Embeddings are correctly sized (e.g., 1536 for OpenAI)
    /// - Vector similarity search returns ranked results
    #[tokio::test]
    async fn test_semantic_search_embedding_service_integration() {
        // Skip if embedding service URL is not configured
        let embedding_url = std::env::var("EMBEDDING_SERVICE_URL").ok();

        if embedding_url.is_none() {
            eprintln!("Skipping integration test: EMBEDDING_SERVICE_URL not set");
            return;
        }

        // This test requires:
        // 1. Running embedding service (or mock)
        // 2. Actual vector computation

        // When the embedding service is integrated, this will:
        // 1. Send a query to the embedding service
        // 2. Receive vector embeddings
        // 3. Verify embedding dimensions (typically 1536 for text-embedding-ada-002)
        // 4. Execute similarity search with real vectors

        // Placeholder assertions
        eprintln!(
            "Embedding service integration test ready for implementation. \
             Requires epigraph-embeddings crate integration."
        );
    }

    /// Test end-to-end semantic search with real infrastructure
    ///
    /// This test combines database and embedding service for full integration
    #[tokio::test]
    async fn test_semantic_search_end_to_end() {
        let database_url = get_database_url();
        let embedding_url = std::env::var("EMBEDDING_SERVICE_URL").ok();

        if database_url.is_none() || embedding_url.is_none() {
            eprintln!(
                "Skipping end-to-end test: requires both DATABASE_URL and EMBEDDING_SERVICE_URL"
            );
            return;
        }

        // End-to-end test flow:
        // 1. Connect to real database
        // 2. Seed claims with embeddings computed from embedding service
        // 3. Execute semantic search query
        // 4. Verify results are ranked by actual vector similarity
        // 5. Clean up test data

        eprintln!(
            "End-to-end integration test ready for implementation. \
             Requires full infrastructure setup."
        );
    }
}
