//! RAG Context Retrieval Routes
//!
//! Implements the `/api/v1/query/rag` endpoint for retrieving high-truth,
//! verified claims suitable for LLM context retrieval (Retrieval-Augmented Generation).
//!
//! # Overview
//!
//! Unlike the general semantic search endpoint, the RAG context endpoint applies
//! an epistemic quality gate: only claims with truth values above a configurable
//! threshold (default 0.7) are returned. This ensures that LLM context is grounded
//! in verified, high-confidence claims rather than unverified assertions.
//!
//! # Example
//!
//! ```text
//! GET /api/v1/query/rag?query=climate+change+effects&limit=5&min_truth=0.8&domain=factual
//! ```

use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "db")]
use sqlx::Row;

use crate::{errors::ApiError, state::AppState};

// ============================================================================
// Constants
// ============================================================================

/// Default number of results to return.
/// Smaller than semantic search (10) because RAG context should be focused.
const DEFAULT_LIMIT: u32 = 5;

/// Maximum number of results that can be requested.
/// Capped at 20 to prevent excessive context injection into LLM prompts.
const MAX_LIMIT: u32 = 20;

/// Default minimum truth value threshold.
/// Acts as an epistemic quality gate: only verified claims pass through.
/// 0.7 represents "more likely true than not, with reasonable confidence."
const DEFAULT_MIN_TRUTH: f64 = 0.7;

/// Valid claim domain/type values for filtering
const VALID_DOMAINS: &[&str] = &["factual", "hypothesis", "opinion"];

/// Maximum query string length in bytes.
/// Prevents DoS attacks via excessively long queries that could consume
/// excessive memory in embedding generation or database operations.
const MAX_QUERY_LENGTH: usize = 10_240;

/// Maximum domain filter length in bytes.
/// Prevents buffer overflow or injection attempts via oversized filter values.
const MAX_DOMAIN_LENGTH: usize = 64;

/// Embedding dimension for OpenAI text-embedding-3-small
#[cfg(feature = "db")]
const EMBEDDING_DIM: usize = 1536;

// ============================================================================
// Request/Response DTOs
// ============================================================================

/// Query parameters for RAG context retrieval
///
/// # Fields
///
/// - `query`: The natural language query to find relevant claims
/// - `limit`: Maximum results (default: 5, max: 20)
/// - `min_truth`: Minimum truth value threshold (default: 0.7)
/// - `domain`: Filter by claim domain/type: "factual", "hypothesis", "opinion"
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RagQueryParams {
    /// The query string to find relevant high-truth claims
    pub query: Option<String>,

    /// Maximum number of results to return (default: 5, max: 20)
    #[serde(default)]
    pub limit: Option<u32>,

    /// Minimum truth value threshold [0.0, 1.0] (default: 0.7)
    #[serde(default)]
    pub min_truth: Option<f64>,

    /// Filter by claim domain/type: "factual", "hypothesis", "opinion"
    #[serde(default)]
    pub domain: Option<String>,
}

/// A single RAG context result containing a verified claim
///
/// Includes the claim content, truth value, and evidence summary
/// for transparent provenance in LLM context.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RagContextResult {
    /// The unique identifier of the claim
    pub claim_id: Uuid,

    /// The claim statement text
    pub content: String,

    /// The truth value of the claim [0.0, 1.0]
    pub truth_value: f64,

    /// Cosine similarity score between query and claim embedding
    pub similarity: f64,

    /// The domain/type of this claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    /// The reasoning trace ID for provenance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<Uuid>,

    /// The agent who made the claim
    pub agent_id: Uuid,

    /// When the claim was created
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,

    /// Number of edges connected to this claim (connectivity score)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_count: Option<i64>,

    /// Composite hybrid score combining similarity, truth, and connectivity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hybrid_score: Option<f64>,
}

/// Response from RAG context retrieval endpoint
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RagContextResponse {
    /// The high-truth claims suitable for LLM context
    pub results: Vec<RagContextResult>,

    /// Number of results returned
    pub count: usize,

    /// The minimum truth threshold that was applied
    pub min_truth_applied: f64,

    /// Time taken to execute the query in milliseconds
    pub query_time_ms: u64,

    /// Indicates whether embeddings came from a real service ("real") or
    /// the deterministic mock fallback ("mock").
    pub embedding_mode: String,
}

// ============================================================================
// Embedding Helpers
// ============================================================================

/// Generate a mock embedding vector for the given text.
///
/// Creates a deterministic embedding based on the input text for testing.
/// Used as a fallback when no embedding service is configured.
#[cfg(feature = "db")]
fn generate_mock_embedding(text: &str) -> Vec<f32> {
    let mut embedding = vec![0.0f32; EMBEDDING_DIM];

    let text_bytes = text.as_bytes();
    for (i, byte) in text_bytes.iter().enumerate() {
        let idx = i % EMBEDDING_DIM;
        embedding[idx] += (*byte as f32) / 255.0;
    }

    // Normalize to unit vector (required for cosine similarity)
    let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
    if magnitude > 0.0 {
        for val in embedding.iter_mut() {
            *val /= magnitude;
        }
    }

    embedding
}

/// Generate embedding for query text using the embedding service if available,
/// falling back to mock embedding generation if the service is unavailable.
///
/// Returns `(embedding, is_real)` where `is_real` is `true` when the embedding
/// was produced by a configured embedding service and `false` when the mock
/// deterministic fallback was used.
#[cfg(feature = "db")]
async fn generate_query_embedding(state: &AppState, text: &str) -> (Vec<f32>, bool) {
    if let Some(ref embedding_service) = state.embedding_service {
        match embedding_service.generate_query(text).await {
            Ok(embedding) => {
                tracing::debug!(
                    text_len = text.len(),
                    embedding_dim = embedding.len(),
                    "Generated real embedding for RAG query"
                );
                return (embedding, true);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Embedding service failed, falling back to mock embedding"
                );
            }
        }
    }

    tracing::debug!(
        text_len = text.len(),
        "Using mock embedding for RAG query (no service configured or service failed)"
    );
    (generate_mock_embedding(text), false)
}

/// Format embedding vector as pgvector string literal
#[cfg(feature = "db")]
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

// ============================================================================
// Handler
// ============================================================================

/// RAG context retrieval handler
///
/// GET /api/v1/query/rag
///
/// Returns high-truth, verified claims suitable for LLM context retrieval.
/// Applies an epistemic quality gate (min_truth >= 0.7 by default) to ensure
/// only well-verified claims are used as context for language model generation.
///
/// # Validation
///
/// - `query` is required and cannot be empty or whitespace-only
/// - `query` max length is 10KB (DoS prevention)
/// - `limit` capped at 20 (focused context)
/// - `min_truth` must be in [0.0, 1.0]
/// - `domain` must be one of: factual, hypothesis, opinion
///
/// # Security
///
/// - All database parameters are bound via sqlx (no SQL injection)
/// - Query length bounded to prevent memory exhaustion
/// - Result count bounded to prevent large response payloads
pub async fn rag_context(
    #[allow(unused_variables)] State(state): State<AppState>,
    Query(params): Query<RagQueryParams>,
) -> Result<Json<RagContextResponse>, ApiError> {
    let start_time = std::time::Instant::now();

    // ---- Validate query parameter ----
    let raw_query = params.query.ok_or_else(|| ApiError::ValidationError {
        field: "query".to_string(),
        reason: "Query parameter is required".to_string(),
    })?;

    let query = raw_query.trim();
    if query.is_empty() {
        return Err(ApiError::ValidationError {
            field: "query".to_string(),
            reason: "Query cannot be empty".to_string(),
        });
    }

    if raw_query.len() > MAX_QUERY_LENGTH {
        return Err(ApiError::ValidationError {
            field: "query".to_string(),
            reason: format!(
                "Query too long: {} bytes, maximum is {} bytes",
                raw_query.len(),
                MAX_QUERY_LENGTH
            ),
        });
    }

    // ---- Validate and apply limit ----
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_LIMIT {
        return Err(ApiError::ValidationError {
            field: "limit".to_string(),
            reason: format!("Limit must be between 1 and {}", MAX_LIMIT),
        });
    }
    // Used in the db path; suppressed when compiling without db feature.
    #[allow(unused_variables)]
    let limit = limit as usize;

    // ---- Validate min_truth ----
    let min_truth = params.min_truth.unwrap_or(DEFAULT_MIN_TRUTH);
    if !(0.0..=1.0).contains(&min_truth) {
        return Err(ApiError::ValidationError {
            field: "min_truth".to_string(),
            reason: "min_truth must be between 0.0 and 1.0".to_string(),
        });
    }

    // ---- Validate domain filter ----
    if let Some(ref domain) = params.domain {
        if domain.len() > MAX_DOMAIN_LENGTH {
            return Err(ApiError::ValidationError {
                field: "domain".to_string(),
                reason: format!(
                    "domain too long: {} bytes, maximum is {} bytes",
                    domain.len(),
                    MAX_DOMAIN_LENGTH
                ),
            });
        }
        if !VALID_DOMAINS.contains(&domain.as_str()) {
            return Err(ApiError::ValidationError {
                field: "domain".to_string(),
                reason: format!(
                    "Invalid domain '{}'. Must be one of: factual, hypothesis, opinion",
                    domain
                ),
            });
        }
    }

    // ---- Execute query ----
    #[cfg(feature = "db")]
    {
        // Step 1: Generate embedding for the query
        let (query_embedding, is_real_embedding) = generate_query_embedding(&state, query).await;
        let embedding_str = format_embedding_for_pgvector(&query_embedding);
        let embedding_mode = if is_real_embedding { "real" } else { "mock" }.to_string();

        // Step 2: Execute hybrid search combining vector similarity, truth, and connectivity
        //
        // Hybrid scoring formula:
        //   hybrid_score = similarity * 0.6 + truth_value * 0.2 + connectivity * 0.2
        //
        // Where:
        //   - similarity: cosine similarity between query and claim embedding
        //   - truth_value: epistemic quality gate (already filtered by min_truth)
        //   - connectivity: min(edge_count / 10.0, 1.0) — well-connected claims ranked higher
        //
        // The truth_value >= $2 clause is the epistemic quality gate that
        // distinguishes this from general semantic search.
        let rows = sqlx::query(
            r#"
            WITH query_vec AS (
                SELECT $1::vector AS vec
            ),
            base AS (
                SELECT
                    c.id as claim_id,
                    c.content,
                    c.truth_value,
                    1 - (c.embedding <=> q.vec) as similarity,
                    c.labels[1] as domain,
                    c.trace_id,
                    c.agent_id,
                    c.created_at,
                    COALESCE((
                        SELECT COUNT(*)
                        FROM edges e
                        WHERE e.source_id = c.id OR e.target_id = c.id
                    ), 0) as edge_count
                FROM claims c, query_vec q
                WHERE c.embedding IS NOT NULL
                  AND c.truth_value >= $2
                  AND 1 - (c.embedding <=> q.vec) >= 0.0
                  AND ($3::text IS NULL OR $3 = ANY(c.labels))
            )
            SELECT *,
                similarity * 0.6
                    + truth_value * 0.2
                    + LEAST(edge_count::float / 10.0, 1.0) * 0.2
                as hybrid_score
            FROM base
            ORDER BY hybrid_score DESC
            LIMIT $4
            "#,
        )
        .bind(&embedding_str)
        .bind(min_truth)
        .bind(params.domain.as_deref())
        .bind(limit as i64)
        .fetch_all(&state.db_pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Database query failed: {}", e),
        })?;

        // Step 3: Convert rows to response DTOs
        let results: Vec<RagContextResult> = rows
            .iter()
            .map(|row| RagContextResult {
                claim_id: row.get("claim_id"),
                content: row.get("content"),
                truth_value: row.get("truth_value"),
                similarity: row.get("similarity"),
                domain: row.get("domain"),
                trace_id: row.get("trace_id"),
                agent_id: row.get("agent_id"),
                created_at: row.get("created_at"),
                edge_count: row.get("edge_count"),
                hybrid_score: row.get("hybrid_score"),
            })
            .collect();

        let count = results.len();
        let query_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(Json(RagContextResponse {
            results,
            count,
            min_truth_applied: min_truth,
            query_time_ms,
            embedding_mode,
        }))
    }

    // Fallback when db feature is disabled
    #[cfg(not(feature = "db"))]
    {
        let results: Vec<RagContextResult> = Vec::new();
        let count = 0;
        let query_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(Json(RagContextResponse {
            results,
            count,
            min_truth_applied: min_truth,
            query_time_ms,
            embedding_mode: "mock".to_string(),
        }))
    }
}

// ============================================================================
// Embedding Generation Endpoint
// ============================================================================

/// Request body for PUT /api/v1/claims/:id/embedding
#[derive(Debug, Deserialize)]
pub struct GenerateEmbeddingRequest {
    /// The text to embed (typically the claim content)
    pub text: String,
}

/// Response from PUT /api/v1/claims/:id/embedding
#[derive(Debug, Serialize)]
pub struct EmbeddingResponse {
    pub claim_id: Uuid,
    pub dimension: usize,
    pub stored: bool,
}

/// Generate and store an embedding for a claim.
///
/// `PUT /api/v1/claims/:id/embedding`
///
/// Uses the configured embedding service to generate a vector embedding
/// for the provided text and stores it in the claim's embedding column.
///
/// Protected route — requires Ed25519 signature verification.
#[cfg(feature = "db")]
pub async fn generate_claim_embedding(
    State(state): State<AppState>,
    axum::extract::Path(claim_id): axum::extract::Path<Uuid>,
    Json(request): Json<GenerateEmbeddingRequest>,
) -> Result<Json<EmbeddingResponse>, ApiError> {
    if request.text.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "text".to_string(),
            reason: "Text cannot be empty".to_string(),
        });
    }

    // Generate embedding (ignore mode flag — we always store regardless)
    let (embedding, _is_real) = generate_query_embedding(&state, &request.text).await;
    let dimension = embedding.len();

    // Format and store in DB
    let pgvector_str = format_embedding_for_pgvector(&embedding);
    let pool = &state.db_pool;

    sqlx::query("UPDATE claims SET embedding = $1::vector WHERE id = $2")
        .bind(&pgvector_str)
        .bind(claim_id)
        .execute(pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to store embedding: {e}"),
        })?;

    Ok(Json(EmbeddingResponse {
        claim_id,
        dimension,
        stored: true,
    }))
}

/// Generate and store an embedding for an evidence item.
///
/// `PUT /api/v1/evidence/:id/embedding`
///
/// Uses the configured embedding service to generate a vector embedding
/// for the provided text (typically evidence raw_content) and stores it
/// in the evidence's embedding column.
///
/// Protected route — requires Ed25519 signature verification.
#[cfg(feature = "db")]
pub async fn generate_evidence_embedding(
    State(state): State<AppState>,
    axum::extract::Path(evidence_id): axum::extract::Path<Uuid>,
    Json(request): Json<GenerateEmbeddingRequest>,
) -> Result<Json<EvidenceEmbeddingResponse>, ApiError> {
    if request.text.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "text".to_string(),
            reason: "Text cannot be empty".to_string(),
        });
    }

    // Generate embedding (ignore mode flag — we always store regardless)
    let (embedding, _is_real) = generate_query_embedding(&state, &request.text).await;
    let dimension = embedding.len();

    // Format and store in DB
    let pgvector_str = format_embedding_for_pgvector(&embedding);
    let pool = &state.db_pool;

    sqlx::query("UPDATE evidence SET embedding = $1::vector WHERE id = $2")
        .bind(&pgvector_str)
        .bind(evidence_id)
        .execute(pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to store evidence embedding: {e}"),
        })?;

    Ok(Json(EvidenceEmbeddingResponse {
        evidence_id,
        dimension,
        stored: true,
    }))
}

/// Non-DB stub for evidence embedding generation
#[cfg(not(feature = "db"))]
pub async fn generate_evidence_embedding(
    State(_state): State<AppState>,
    axum::extract::Path(_evidence_id): axum::extract::Path<Uuid>,
    Json(_request): Json<GenerateEmbeddingRequest>,
) -> Result<Json<EvidenceEmbeddingResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database".to_string(),
    })
}

/// Response from PUT /api/v1/evidence/:id/embedding
#[derive(Debug, Serialize, Deserialize)]
pub struct EvidenceEmbeddingResponse {
    pub evidence_id: Uuid,
    pub dimension: usize,
    pub stored: bool,
}

/// Search evidence by semantic similarity
///
/// `GET /api/v1/search/evidence`
///
/// Returns evidence items ranked by vector similarity to the query.
/// Public endpoint — no authentication required.
#[cfg(feature = "db")]
pub async fn search_evidence(
    State(state): State<AppState>,
    Query(params): Query<EvidenceSearchParams>,
) -> Result<Json<EvidenceSearchResponse>, ApiError> {
    let raw_query = params.query.ok_or_else(|| ApiError::ValidationError {
        field: "query".to_string(),
        reason: "Query parameter is required".to_string(),
    })?;

    let query = raw_query.trim();
    if query.is_empty() {
        return Err(ApiError::ValidationError {
            field: "query".to_string(),
            reason: "Query cannot be empty".to_string(),
        });
    }

    if raw_query.len() > MAX_QUERY_LENGTH {
        return Err(ApiError::ValidationError {
            field: "query".to_string(),
            reason: format!(
                "Query too long: {} bytes, maximum is {} bytes",
                raw_query.len(),
                MAX_QUERY_LENGTH
            ),
        });
    }

    let limit = params.limit.unwrap_or(10).min(50) as i64;
    if limit <= 0 {
        return Err(ApiError::ValidationError {
            field: "limit".to_string(),
            reason: "Limit must be greater than 0".to_string(),
        });
    }

    let (query_embedding, _is_real) = generate_query_embedding(&state, query).await;
    let embedding_str = format_embedding_for_pgvector(&query_embedding);

    let rows = sqlx::query_as::<_, EvidenceSearchRow>(
        r#"
        SELECT
            e.id as evidence_id,
            e.claim_id,
            e.raw_content,
            e.evidence_type,
            1 - (e.embedding <=> $1::vector) AS similarity
        FROM evidence e
        WHERE e.embedding IS NOT NULL
        ORDER BY e.embedding <=> $1::vector
        LIMIT $2
        "#,
    )
    .bind(&embedding_str)
    .bind(limit)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Database query failed: {}", e),
    })?;

    let results: Vec<EvidenceSearchResultDto> = rows
        .into_iter()
        .map(|row| EvidenceSearchResultDto {
            evidence_id: row.evidence_id,
            claim_id: row.claim_id,
            raw_content: row.raw_content,
            evidence_type: row.evidence_type,
            similarity: row.similarity,
        })
        .collect();

    let count = results.len();

    Ok(Json(EvidenceSearchResponse { results, count }))
}

/// Non-DB stub for evidence search
#[cfg(not(feature = "db"))]
pub async fn search_evidence(
    State(_state): State<AppState>,
    Query(params): Query<EvidenceSearchParams>,
) -> Result<Json<EvidenceSearchResponse>, ApiError> {
    // Validate params even without DB
    let raw_query = params.query.ok_or_else(|| ApiError::ValidationError {
        field: "query".to_string(),
        reason: "Query parameter is required".to_string(),
    })?;
    let query = raw_query.trim();
    if query.is_empty() {
        return Err(ApiError::ValidationError {
            field: "query".to_string(),
            reason: "Query cannot be empty".to_string(),
        });
    }

    Ok(Json(EvidenceSearchResponse {
        results: Vec::new(),
        count: 0,
    }))
}

/// Query parameters for evidence semantic search
#[derive(Debug, Deserialize)]
pub struct EvidenceSearchParams {
    pub query: Option<String>,
    pub limit: Option<u32>,
}

/// A single evidence search result
#[derive(Debug, Serialize, Deserialize)]
pub struct EvidenceSearchResultDto {
    pub evidence_id: Uuid,
    pub claim_id: Uuid,
    pub raw_content: Option<String>,
    pub evidence_type: String,
    pub similarity: f64,
}

/// Response from evidence semantic search
#[derive(Debug, Serialize, Deserialize)]
pub struct EvidenceSearchResponse {
    pub results: Vec<EvidenceSearchResultDto>,
    pub count: usize,
}

/// Row struct for evidence search query results
#[cfg(feature = "db")]
#[derive(sqlx::FromRow)]
struct EvidenceSearchRow {
    evidence_id: Uuid,
    claim_id: Uuid,
    raw_content: Option<String>,
    evidence_type: String,
    similarity: f64,
}

/// Non-DB stub for embedding generation
#[cfg(not(feature = "db"))]
pub async fn generate_claim_embedding(
    State(_state): State<AppState>,
    axum::extract::Path(_claim_id): axum::extract::Path<Uuid>,
    Json(_request): Json<GenerateEmbeddingRequest>,
) -> Result<Json<EmbeddingResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database".to_string(),
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Constant Tests ----

    #[test]
    fn test_default_limit_is_five() {
        assert_eq!(
            DEFAULT_LIMIT, 5,
            "RAG context should default to 5 results for focused context"
        );
    }

    #[test]
    fn test_max_limit_is_twenty() {
        assert_eq!(
            MAX_LIMIT, 20,
            "RAG context should cap at 20 to prevent excessive LLM context"
        );
    }

    #[test]
    fn test_default_min_truth_is_epistemic_gate() {
        assert!(
            (DEFAULT_MIN_TRUTH - 0.7).abs() < f64::EPSILON,
            "Default min_truth must be 0.7 (epistemic quality gate)"
        );
    }

    #[test]
    fn test_valid_domains() {
        assert!(VALID_DOMAINS.contains(&"factual"));
        assert!(VALID_DOMAINS.contains(&"hypothesis"));
        assert!(VALID_DOMAINS.contains(&"opinion"));
        assert!(!VALID_DOMAINS.contains(&"rumor"));
    }

    // ---- DTO Deserialization Tests ----

    #[test]
    fn test_rag_query_params_full_deserialize() {
        let json = r#"{
            "query": "test query",
            "limit": 10,
            "min_truth": 0.8,
            "domain": "factual"
        }"#;

        let params: RagQueryParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.query, Some("test query".to_string()));
        assert_eq!(params.limit, Some(10));
        assert_eq!(params.min_truth, Some(0.8));
        assert_eq!(params.domain, Some("factual".to_string()));
    }

    #[test]
    fn test_rag_query_params_minimal_deserialize() {
        let json = r#"{"query": "test"}"#;

        let params: RagQueryParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.query, Some("test".to_string()));
        assert!(params.limit.is_none());
        assert!(params.min_truth.is_none());
        assert!(params.domain.is_none());
    }

    #[test]
    fn test_rag_query_params_missing_query() {
        let json = r#"{}"#;

        let params: RagQueryParams = serde_json::from_str(json).unwrap();
        assert!(params.query.is_none());
    }

    // ---- Response Serialization Tests ----

    #[test]
    fn test_rag_context_response_serializes() {
        let response = RagContextResponse {
            results: vec![RagContextResult {
                claim_id: Uuid::nil(),
                content: "Verified claim".to_string(),
                truth_value: 0.85,
                similarity: 0.92,
                domain: Some("factual".to_string()),
                trace_id: Some(Uuid::nil()),
                agent_id: Uuid::nil(),
                created_at: None,
                edge_count: None,
                hybrid_score: None,
            }],
            count: 1,
            min_truth_applied: 0.7,
            query_time_ms: 12,
            embedding_mode: "mock".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"count\":1"));
        assert!(json.contains("\"min_truth_applied\":0.7"));
        assert!(json.contains("\"truth_value\":0.85"));
        assert!(json.contains("\"similarity\":0.92"));
        assert!(json.contains("\"content\":\"Verified claim\""));
        assert!(json.contains("\"embedding_mode\":\"mock\""));
    }

    #[test]
    fn test_rag_result_optional_fields_skipped() {
        let result = RagContextResult {
            claim_id: Uuid::nil(),
            content: "Test".to_string(),
            truth_value: 0.9,
            similarity: 0.8,
            domain: None,
            trace_id: None,
            agent_id: Uuid::nil(),
            created_at: None,
            edge_count: None,
            hybrid_score: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("domain"));
        assert!(!json.contains("trace_id"));
        assert!(!json.contains("created_at"));
        assert!(!json.contains("edge_count"));
        assert!(!json.contains("hybrid_score"));
    }

    #[test]
    fn test_rag_result_with_all_fields() {
        let now = Utc::now();
        let result = RagContextResult {
            claim_id: Uuid::new_v4(),
            content: "Full claim".to_string(),
            truth_value: 0.95,
            similarity: 0.88,
            domain: Some("hypothesis".to_string()),
            trace_id: Some(Uuid::new_v4()),
            agent_id: Uuid::new_v4(),
            created_at: Some(now),
            edge_count: Some(5),
            hybrid_score: Some(0.91),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"domain\":\"hypothesis\""));
        assert!(json.contains("\"trace_id\":"));
        assert!(json.contains("\"created_at\":"));
        assert!(json.contains("\"edge_count\":5"));
        assert!(json.contains("\"hybrid_score\":0.91"));
    }

    // ---- Handler Validation Tests (no-db path) ----
    // These tests exercise the validation logic in the handler without needing
    // a real database, by using the non-db feature gate path.

    #[cfg(not(feature = "db"))]
    mod handler_tests {
        use super::*;
        use crate::state::ApiConfig;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        fn test_router() -> Router {
            let state = AppState::new(ApiConfig::default());
            Router::new()
                .route("/api/v1/query/rag", get(rag_context))
                .with_state(state)
        }

        #[tokio::test]
        async fn test_valid_query_returns_200() {
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/query/rag?query=climate+change")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = http_body_util::BodyExt::collect(response.into_body())
                .await
                .unwrap()
                .to_bytes();
            let resp: RagContextResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(resp.count, 0); // no DB, so empty results
            assert!((resp.min_truth_applied - 0.7).abs() < f64::EPSILON);
        }

        #[tokio::test]
        async fn test_missing_query_returns_400() {
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/query/rag")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_empty_query_returns_400() {
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/query/rag?query=")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_whitespace_only_query_returns_400() {
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/query/rag?query=%20%20%20")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_custom_min_truth_applied() {
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/query/rag?query=test&min_truth=0.9")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = http_body_util::BodyExt::collect(response.into_body())
                .await
                .unwrap()
                .to_bytes();
            let resp: RagContextResponse = serde_json::from_slice(&body).unwrap();
            assert!((resp.min_truth_applied - 0.9).abs() < f64::EPSILON);
        }

        #[tokio::test]
        async fn test_invalid_min_truth_above_one_returns_400() {
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/query/rag?query=test&min_truth=1.5")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_invalid_min_truth_negative_returns_400() {
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/query/rag?query=test&min_truth=-0.1")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_limit_zero_returns_400() {
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/query/rag?query=test&limit=0")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_limit_exceeding_max_returns_400() {
            // Limit of 50 exceeds MAX_LIMIT (20) and should be rejected
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/query/rag?query=test&limit=50")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_valid_domain_filter_accepted() {
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/query/rag?query=test&domain=factual")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn test_invalid_domain_filter_returns_400() {
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/query/rag?query=test&domain=rumor")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_all_domain_types_accepted() {
            for domain in &["factual", "hypothesis", "opinion"] {
                let router = test_router();
                let uri = format!("/api/v1/query/rag?query=test&domain={}", domain);
                let request = Request::builder().uri(&uri).body(Body::empty()).unwrap();

                let response = router.oneshot(request).await.unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::OK,
                    "Domain '{}' should be accepted",
                    domain
                );
            }
        }

        #[tokio::test]
        async fn test_response_structure() {
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/query/rag?query=test")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            let body = http_body_util::BodyExt::collect(response.into_body())
                .await
                .unwrap()
                .to_bytes();
            let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();

            // Verify all expected top-level fields exist
            assert!(resp.get("results").is_some());
            assert!(resp.get("count").is_some());
            assert!(resp.get("min_truth_applied").is_some());
            assert!(resp.get("query_time_ms").is_some());
            assert!(resp.get("embedding_mode").is_some());
            assert_eq!(resp["embedding_mode"], "mock");
        }

        /// Test RAG endpoint is accessible as a public (unauthenticated) route
        /// through the full application router, including rate-limiting and
        /// signature verification middleware layers.
        #[tokio::test]
        async fn test_rag_returns_200_via_full_router() {
            let state = AppState::new(ApiConfig {
                require_signatures: true,
                ..ApiConfig::default()
            });
            let router = crate::routes::create_router(state);

            let request = Request::builder()
                .uri("/api/v1/query/rag?query=test+query")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "RAG endpoint should be publicly accessible even with require_signatures enabled"
            );

            let body = http_body_util::BodyExt::collect(response.into_body())
                .await
                .unwrap()
                .to_bytes();
            let resp: RagContextResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(resp.count, 0, "No DB means empty results");
            assert!(
                (resp.min_truth_applied - 0.7).abs() < f64::EPSILON,
                "Default min_truth should be 0.7"
            );
        }

        /// Test that the min_truth parameter correctly flows through the full
        /// router and is reflected in the response.
        #[tokio::test]
        async fn test_rag_min_truth_via_full_router() {
            let state = AppState::new(ApiConfig::default());
            let router = crate::routes::create_router(state);

            let request = Request::builder()
                .uri("/api/v1/query/rag?query=test&min_truth=0.95")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = http_body_util::BodyExt::collect(response.into_body())
                .await
                .unwrap()
                .to_bytes();
            let resp: RagContextResponse = serde_json::from_slice(&body).unwrap();
            assert!(
                (resp.min_truth_applied - 0.95).abs() < f64::EPSILON,
                "min_truth=0.95 should be reflected in response, got {}",
                resp.min_truth_applied
            );
        }
    }

    // ---- Embedding Endpoint Tests ----

    #[test]
    fn test_generate_embedding_request_deserializes() {
        let json = serde_json::json!({"text": "test claim content"});
        let request: GenerateEmbeddingRequest = serde_json::from_value(json).unwrap();
        assert_eq!(request.text, "test claim content");
    }

    #[test]
    fn test_embedding_response_serializes() {
        let response = EmbeddingResponse {
            claim_id: Uuid::new_v4(),
            dimension: 1536,
            stored: true,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["dimension"], 1536);
        assert_eq!(json["stored"], true);
    }

    // ---- Evidence Embedding Tests ----

    #[test]
    fn test_evidence_embedding_response_serializes() {
        let response = EvidenceEmbeddingResponse {
            evidence_id: Uuid::new_v4(),
            dimension: 1536,
            stored: true,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["dimension"], 1536);
        assert_eq!(json["stored"], true);
        assert!(json["evidence_id"].is_string());
    }

    #[test]
    fn test_evidence_embedding_response_roundtrip() {
        let id = Uuid::new_v4();
        let response = EvidenceEmbeddingResponse {
            evidence_id: id,
            dimension: 768,
            stored: false,
        };
        let json_str = serde_json::to_string(&response).unwrap();
        let deserialized: EvidenceEmbeddingResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.evidence_id, id);
        assert_eq!(deserialized.dimension, 768);
        assert!(!deserialized.stored);
    }

    // ---- Evidence Search DTO Tests ----

    #[test]
    fn test_evidence_search_params_deserializes() {
        let json = r#"{"query": "cryptographic signing", "limit": 10}"#;
        let params: EvidenceSearchParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.query, Some("cryptographic signing".to_string()));
        assert_eq!(params.limit, Some(10));
    }

    #[test]
    fn test_evidence_search_params_minimal() {
        let json = r#"{"query": "test"}"#;
        let params: EvidenceSearchParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.query, Some("test".to_string()));
        assert!(params.limit.is_none());
    }

    #[test]
    fn test_evidence_search_result_dto_serializes() {
        let result = EvidenceSearchResultDto {
            evidence_id: Uuid::nil(),
            claim_id: Uuid::nil(),
            raw_content: Some("Security audit flagged timing attack".to_string()),
            evidence_type: "document".to_string(),
            similarity: 0.92,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"similarity\":0.92"));
        assert!(json.contains("\"evidence_type\":\"document\""));
        assert!(json.contains("Security audit flagged timing attack"));
    }

    #[test]
    fn test_evidence_search_response_serializes() {
        let response = EvidenceSearchResponse {
            results: vec![EvidenceSearchResultDto {
                evidence_id: Uuid::nil(),
                claim_id: Uuid::nil(),
                raw_content: None,
                evidence_type: "observation".to_string(),
                similarity: 0.5,
            }],
            count: 1,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"count\":1"));
        assert!(json.contains("\"evidence_type\":\"observation\""));
    }

    #[test]
    fn test_evidence_search_response_empty() {
        let response = EvidenceSearchResponse {
            results: Vec::new(),
            count: 0,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"count\":0"));
        assert!(json.contains("\"results\":[]"));
    }

    // ---- Evidence Search Handler Tests (non-DB) ----

    #[cfg(not(feature = "db"))]
    mod evidence_search_handler_tests {
        use super::*;
        use crate::state::ApiConfig;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        fn test_router() -> Router {
            let state = AppState::new(ApiConfig::default());
            Router::new()
                .route("/api/v1/search/evidence", get(search_evidence))
                .with_state(state)
        }

        #[tokio::test]
        async fn test_evidence_search_valid_query_returns_200() {
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/search/evidence?query=timing+attack")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = http_body_util::BodyExt::collect(response.into_body())
                .await
                .unwrap()
                .to_bytes();
            let resp: EvidenceSearchResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(resp.count, 0); // no DB
        }

        #[tokio::test]
        async fn test_evidence_search_missing_query_returns_400() {
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/search/evidence")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_evidence_search_empty_query_returns_400() {
            let router = test_router();
            let request = Request::builder()
                .uri("/api/v1/search/evidence?query=")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_evidence_search_via_full_router() {
            let state = AppState::new(ApiConfig::default());
            let router = crate::routes::create_router(state);

            let request = Request::builder()
                .uri("/api/v1/search/evidence?query=test")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Evidence search should be publicly accessible"
            );
        }
    }

    // ---- Evidence Embedding Handler Test (non-DB) ----

    #[cfg(not(feature = "db"))]
    mod evidence_embedding_handler_tests {
        use super::*;
        use crate::state::ApiConfig;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::put;
        use axum::Router;
        use tower::ServiceExt;

        #[tokio::test]
        async fn test_evidence_embedding_without_db_returns_503() {
            let state = AppState::new(ApiConfig::default());
            let router = Router::new()
                .route(
                    "/api/v1/evidence/:id/embedding",
                    put(generate_evidence_embedding),
                )
                .with_state(state);

            let id = Uuid::new_v4();
            let body = serde_json::json!({"text": "test evidence"});
            let request = Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/evidence/{id}/embedding"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }
}
