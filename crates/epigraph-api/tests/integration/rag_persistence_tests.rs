//! RAG Context Retrieval Database Integration Tests
//!
//! GET /api/v1/query/rag - pgvector Similarity Search
//!
//! These tests validate that the RAG endpoint correctly queries PostgreSQL
//! with pgvector embeddings and applies the epistemic quality gate (min_truth).
//!
//! # Test Coverage
//!
//! 1. RAG query returns claims with embeddings sorted by similarity
//! 2. min_truth filter excludes low-truth claims
//! 3. Empty results when no claims match
//! 4. Domain filter restricts results
//! 5. Limit parameter caps result count
//!
//! # Prerequisites
//!
//! Requires PostgreSQL with pgvector extension.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    Router,
};
use epigraph_api::middleware::SignatureVerificationState;
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_core::Agent;
use epigraph_db::{AgentRepository, PgPool};
use http_body_util::BodyExt;
use serde::Deserialize;
use tower::ServiceExt;
use uuid::Uuid;

// =============================================================================
// RESPONSE TYPES
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct RagContextResult {
    pub claim_id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub similarity: f64,
    pub domain: Option<String>,
    pub trace_id: Option<Uuid>,
    pub agent_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct RagContextResponse {
    pub results: Vec<RagContextResult>,
    pub count: usize,
    pub min_truth_applied: f64,
    pub query_time_ms: u64,
    #[serde(default)]
    pub embedding_mode: Option<String>,
}

// =============================================================================
// TEST FIXTURES
// =============================================================================

const EMBEDDING_DIM: usize = 1536;

/// Create a test agent with a random Ed25519 public key
fn create_test_agent(display_name: Option<&str>) -> Agent {
    let mut public_key = [0u8; 32];
    for (i, byte) in public_key.iter_mut().enumerate() {
        *byte = (i as u8)
            .wrapping_mul(17)
            .wrapping_add(Uuid::new_v4().as_bytes()[i % 16]);
    }
    Agent::new(public_key, display_name.map(String::from))
}

/// Generate a deterministic mock embedding vector from text.
/// Mirrors the generate_mock_embedding function in rag.rs.
fn generate_mock_embedding(text: &str) -> Vec<f32> {
    let mut embedding = vec![0.0f32; EMBEDDING_DIM];

    let text_bytes = text.as_bytes();
    for (i, byte) in text_bytes.iter().enumerate() {
        let idx = i % EMBEDDING_DIM;
        embedding[idx] += (*byte as f32) / 255.0;
    }

    // Normalize to unit vector
    let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
    if magnitude > 0.0 {
        for val in embedding.iter_mut() {
            *val /= magnitude;
        }
    }

    embedding
}

/// Format embedding as pgvector string literal
fn format_embedding_for_pgvector(embedding: &[f32]) -> String {
    format!(
        "[{}]",
        embedding
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// Create a router configured for testing with DB pool (bypasses auth)
fn create_test_router(pool: PgPool) -> Router {
    let config = ApiConfig {
        require_signatures: false,
        max_request_size: 1024 * 1024,
    };
    let signature_state = SignatureVerificationState::with_bypass_routes(vec!["/".to_string()]);
    let state = AppState::with_db_and_signature_state(pool, config, signature_state);
    create_router(state)
}

/// Insert a claim with embedding directly into the database.
///
/// Uses raw SQL rather than ClaimRepository::create() because:
/// 1. ClaimRepository::create() does not support the `embedding` column (pgvector),
///    which is managed separately via EvidenceRepository::store_embedding()
/// 2. ClaimRepository::create() does not support the `labels` column directly
/// 3. These tests need to set up specific embedding vectors for similarity assertions,
///    which requires inserting the embedding in the same INSERT statement
async fn insert_claim_with_embedding(
    pool: &PgPool,
    agent_id: Uuid,
    content: &str,
    truth_value: f64,
    labels: &[&str],
) -> Uuid {
    let claim_id = Uuid::new_v4();
    let content_hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    let embedding = generate_mock_embedding(content);
    let embedding_str = format_embedding_for_pgvector(&embedding);
    let now = chrono::Utc::now();
    let labels_vec: Vec<String> = labels.iter().map(|s| s.to_string()).collect();

    sqlx::query(
        r#"
        INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, embedding, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7::vector, $8, $8)
        "#,
    )
    .bind(claim_id)
    .bind(content)
    .bind(content_hash.as_slice())
    .bind(truth_value)
    .bind(agent_id)
    .bind(&labels_vec)
    .bind(&embedding_str)
    .bind(now)
    .execute(pool)
    .await
    .expect("Insert claim should succeed");

    claim_id
}

/// Make a GET request to the RAG endpoint
async fn rag_query(router: &Router, query: &str, params: &str) -> (StatusCode, String) {
    // Simple URL encoding: replace spaces with +
    let encoded_query = query.replace(' ', "+");
    let uri = if params.is_empty() {
        format!("/api/v1/query/rag?query={}", encoded_query)
    } else {
        format!("/api/v1/query/rag?query={}&{}", encoded_query, params)
    };

    let request = Request::builder()
        .method(Method::GET)
        .uri(&uri)
        .body(Body::empty())
        .expect("Failed to build request");

    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    let status = response.status();
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Failed to collect body")
        .to_bytes();
    let body_string = String::from_utf8(body_bytes.to_vec()).expect("Body is not valid UTF-8");

    (status, body_string)
}

// =============================================================================
// TEST 1: RAG Query Returns Claims with Embeddings Sorted by Similarity
// =============================================================================

/// Validates that the RAG endpoint returns claims ordered by vector similarity.
///
/// # Invariant Tested
/// - Claims with embeddings are returned
/// - Results are sorted by descending similarity
/// - Response includes required fields (claim_id, content, truth_value, similarity)
///
/// # Evidence
/// IMPLEMENTATION_PLAN.md requires RAG context retrieval with truth quality gate
#[sqlx::test(migrations = "../../migrations")]
async fn test_rag_returns_claims_sorted_by_similarity(pool: PgPool) {
    // Arrange: Create agent and claims with embeddings
    let agent = create_test_agent(Some("RAG Test Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");
    let agent_uuid: Uuid = created_agent.id.into();

    // Insert claims with different content but all high truth
    insert_claim_with_embedding(
        &pool,
        agent_uuid,
        "Climate change causes rising sea levels worldwide",
        0.9,
        &["factual"],
    )
    .await;

    insert_claim_with_embedding(
        &pool,
        agent_uuid,
        "Carbon dioxide concentration increases with industrialization",
        0.85,
        &["factual"],
    )
    .await;

    insert_claim_with_embedding(
        &pool,
        agent_uuid,
        "Quantum computing uses superposition for parallel computation",
        0.8,
        &["factual"],
    )
    .await;

    let router = create_test_router(pool.clone());

    // Act: Query for climate-related claims
    let (status, body) = rag_query(
        &router,
        "climate change sea levels",
        "limit=3&min_truth=0.7",
    )
    .await;

    // Assert
    assert_eq!(status, StatusCode::OK, "RAG query should succeed: {}", body);

    let response: RagContextResponse =
        serde_json::from_str(&body).expect("Failed to parse RAG response");

    assert!(
        response.count > 0,
        "Should return at least one result for climate query"
    );

    assert!(
        response.count <= 3,
        "Should not exceed requested limit of 3"
    );

    // Results are sorted by hybrid_score (similarity*0.6 + truth*0.2 + connectivity*0.2),
    // so raw similarity values may not be strictly descending when hybrid scores are close.
    // The endpoint returns similarity (not hybrid_score), so allow small inversions from
    // hybrid reranking. Tolerance is tight (0.001) to catch actual sorting bugs.
    for window in response.results.windows(2) {
        assert!(
            window[0].similarity >= window[1].similarity - 0.001,
            "Results should be approximately sorted by descending similarity: {} >= {} (diff: {:.6})",
            window[0].similarity, window[1].similarity,
            window[1].similarity - window[0].similarity,
        );
    }

    // All results should have truth >= 0.7 (quality gate)
    for result in &response.results {
        assert!(
            result.truth_value >= 0.7,
            "All RAG results should have truth >= 0.7, got {}",
            result.truth_value
        );
    }

    assert!(
        (response.min_truth_applied - 0.7).abs() < f64::EPSILON,
        "min_truth_applied should be 0.7"
    );
}

// =============================================================================
// TEST 2: min_truth Filter Excludes Low-Truth Claims
// =============================================================================

/// Validates that the epistemic quality gate filters out low-truth claims.
///
/// # CRITICAL INVARIANT
/// The min_truth gate is what distinguishes RAG from general search.
/// Without it, LLM context could include unverified assertions.
///
/// # Evidence
/// CLAUDE.md: "Low-confidence results are flagged, not silently accepted"
#[sqlx::test(migrations = "../../migrations")]
async fn test_rag_min_truth_filters_low_truth_claims(pool: PgPool) {
    // Arrange: Create claims with varying truth values
    let agent = create_test_agent(Some("Truth Filter Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");
    let agent_uuid: Uuid = created_agent.id.into();

    // High truth - should appear
    let high_truth_id = insert_claim_with_embedding(
        &pool,
        agent_uuid,
        "Water boils at 100 degrees Celsius at standard pressure",
        0.95,
        &["factual"],
    )
    .await;

    // Low truth - should be filtered
    let _low_truth_id = insert_claim_with_embedding(
        &pool,
        agent_uuid,
        "Water has magical healing properties beyond hydration",
        0.2,
        &["factual"],
    )
    .await;

    // Borderline truth - should be filtered at 0.8 threshold
    let _borderline_id = insert_claim_with_embedding(
        &pool,
        agent_uuid,
        "Water temperature affects its density",
        0.75,
        &["factual"],
    )
    .await;

    let router = create_test_router(pool.clone());

    // Act: Query with strict truth threshold
    let (status, body) = rag_query(&router, "water properties boiling", "min_truth=0.8").await;

    // Assert
    assert_eq!(status, StatusCode::OK, "RAG query should succeed: {}", body);

    let response: RagContextResponse =
        serde_json::from_str(&body).expect("Failed to parse RAG response");

    // Only the high-truth claim should pass the 0.8 filter
    for result in &response.results {
        assert!(
            result.truth_value >= 0.8,
            "All results should have truth >= 0.8, got {} for '{}'",
            result.truth_value,
            result.content
        );
    }

    // The high-truth claim should be present
    let has_high_truth = response.results.iter().any(|r| r.claim_id == high_truth_id);
    assert!(has_high_truth, "High-truth claim should be in results");

    assert!(
        (response.min_truth_applied - 0.8).abs() < f64::EPSILON,
        "min_truth_applied should be 0.8"
    );
}

// =============================================================================
// TEST 3: Empty Results When No Claims Have Embeddings
// =============================================================================

/// Validates graceful handling when no claims match the query.
///
/// # Invariant Tested
/// - Empty result set returns 200 (not error)
/// - Response count is 0
/// - Results array is empty
#[sqlx::test(migrations = "../../migrations")]
async fn test_rag_empty_results_when_no_embeddings(pool: PgPool) {
    let router = create_test_router(pool.clone());

    // Act: Query an empty database
    let (status, body) = rag_query(&router, "nonexistent topic with no claims", "").await;

    // Assert
    assert_eq!(
        status,
        StatusCode::OK,
        "RAG query should succeed even with no results: {}",
        body
    );

    let response: RagContextResponse =
        serde_json::from_str(&body).expect("Failed to parse RAG response");

    assert_eq!(response.count, 0, "Should return 0 results");
    assert!(response.results.is_empty(), "Results should be empty");
}

// =============================================================================
// TEST 4: Domain Filter Restricts Results
// =============================================================================

/// Validates that the domain parameter filters claims by label.
///
/// # Invariant Tested
/// - Only claims with matching domain label are returned
/// - Claims without the requested domain are excluded
#[sqlx::test(migrations = "../../migrations")]
async fn test_rag_domain_filter(pool: PgPool) {
    let agent = create_test_agent(Some("Domain Filter Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");
    let agent_uuid: Uuid = created_agent.id.into();

    // Factual claim
    let factual_id = insert_claim_with_embedding(
        &pool,
        agent_uuid,
        "The Earth orbits the Sun once per year",
        0.95,
        &["factual"],
    )
    .await;

    // Hypothesis claim
    let _hypothesis_id = insert_claim_with_embedding(
        &pool,
        agent_uuid,
        "Dark matter may explain galactic rotation curves",
        0.85,
        &["hypothesis"],
    )
    .await;

    let router = create_test_router(pool.clone());

    // Act: Query with domain=factual
    let (status, body) = rag_query(
        &router,
        "Earth Sun orbit astronomy",
        "domain=factual&min_truth=0.7",
    )
    .await;

    // Assert
    assert_eq!(status, StatusCode::OK, "RAG query should succeed: {}", body);

    let response: RagContextResponse =
        serde_json::from_str(&body).expect("Failed to parse RAG response");

    // Only factual claims should be returned
    for result in &response.results {
        assert_eq!(
            result.domain.as_deref(),
            Some("factual"),
            "All results should have domain 'factual'"
        );
    }

    // Factual claim should be present
    let has_factual = response.results.iter().any(|r| r.claim_id == factual_id);
    assert!(has_factual, "Factual claim should be in results");
}

// =============================================================================
// TEST 5: Limit Parameter Caps Result Count
// =============================================================================

/// Validates that the limit parameter restricts the number of results.
#[sqlx::test(migrations = "../../migrations")]
async fn test_rag_limit_parameter(pool: PgPool) {
    let agent = create_test_agent(Some("Limit Test Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");
    let agent_uuid: Uuid = created_agent.id.into();

    // Insert 5 claims
    for i in 0..5 {
        insert_claim_with_embedding(
            &pool,
            agent_uuid,
            &format!("Scientific claim number {} about physics", i),
            0.9,
            &["factual"],
        )
        .await;
    }

    let router = create_test_router(pool.clone());

    // Act: Query with limit=2
    let (status, body) = rag_query(
        &router,
        "scientific physics claims",
        "limit=2&min_truth=0.7",
    )
    .await;

    // Assert
    assert_eq!(status, StatusCode::OK, "RAG query should succeed: {}", body);

    let response: RagContextResponse =
        serde_json::from_str(&body).expect("Failed to parse RAG response");

    assert!(
        response.count <= 2,
        "Should return at most 2 results, got {}",
        response.count
    );
}
