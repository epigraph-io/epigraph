//! Semantic Search Routes
//!
//! Implements the `/api/v1/search/semantic` endpoint for vector similarity
//! search against claim embeddings using pgvector.
//!
//! # Overview
//!
//! The semantic search endpoint allows clients to find claims that are
//! semantically similar to a natural language query. Results are ranked
//! by cosine similarity and can be filtered by various criteria.
//!
//! # Example
//!
//! ```json
//! POST /api/v1/search/semantic
//! {
//!   "query": "climate change effects on agriculture",
//!   "limit": 10,
//!   "min_similarity": 0.5,
//!   "claim_type": "factual"
//! }
//! ```

use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[cfg(feature = "db")]
use sqlx::Row;

#[cfg(feature = "db")]
use epigraph_db::ClaimThemeRepository;

#[cfg(feature = "db")]
use epigraph_engine::diverse_select::diverse_select;

use crate::{errors::ApiError, state::AppState};

// ============================================================================
// Request/Response DTOs
// ============================================================================

/// Request body for semantic search
///
/// # Fields
///
/// - `query`: The natural language query to search for semantically similar claims
/// - `limit`: Maximum number of results to return (default: 10, max: 100)
/// - `min_similarity`: Minimum similarity threshold [0.0, 1.0] (default: 0.0)
/// - `claim_type`: Filter by claim type: "factual", "hypothesis", "opinion"
/// - `created_after`: Filter claims created after this timestamp
/// - `created_before`: Filter claims created before this timestamp
/// - `agent_id`: Filter by the agent who made the claim
#[derive(Debug, Deserialize)]
pub struct SemanticSearchRequest {
    /// The query string to search for semantically similar claims
    pub query: String,

    /// Maximum number of results to return (default: 10, max: 100)
    #[serde(default)]
    pub limit: Option<u32>,

    /// Minimum similarity threshold [0.0, 1.0] (default: 0.0)
    #[serde(default)]
    pub min_similarity: Option<f64>,

    /// Filter by claim type: "factual", "hypothesis", "opinion"
    #[serde(default)]
    pub claim_type: Option<String>,

    /// Filter claims created after this timestamp
    #[serde(default)]
    pub created_after: Option<DateTime<Utc>>,

    /// Filter claims created before this timestamp
    #[serde(default)]
    pub created_before: Option<DateTime<Utc>>,

    /// Filter by the agent who made the claim
    #[serde(default)]
    pub agent_id: Option<Uuid>,

    /// Enable diverse hierarchical retrieval (theme-based + coverage selection)
    #[serde(default)]
    pub diverse: Option<bool>,

    /// Maximum number of themes to consider in diverse mode (default: 5)
    #[serde(default)]
    pub max_themes: Option<u32>,

    /// Coverage vs relevance tradeoff for diverse mode (0.0 = pure relevance, 1.0 = pure coverage, default: 0.5)
    #[serde(default)]
    pub diversity_weight: Option<f32>,
}

/// CDST belief interval for a claim — more informative than a single truth value
#[derive(Debug, Clone, Serialize)]
pub struct EpistemicState {
    /// Dempster-Shafer belief (lower bound of the belief interval)
    pub belief: Option<f64>,
    /// Dempster-Shafer plausibility (upper bound of the belief interval)
    pub plausibility: Option<f64>,
    /// Epistemic ignorance: plausibility - belief (width of the interval)
    pub ignorance: Option<f64>,
    /// Legacy truth value (point estimate)
    pub truth_value: f64,
}

impl EpistemicState {
    fn from_row(truth_value: f64, belief: Option<f64>, plausibility: Option<f64>) -> Self {
        let ignorance = match (belief, plausibility) {
            (Some(b), Some(p)) => Some((p - b).max(0.0)),
            _ => None,
        };
        Self {
            belief,
            plausibility,
            ignorance,
            truth_value,
        }
    }
}

/// A single search result with similarity score
#[derive(Debug, Serialize)]
pub struct SemanticSearchResult {
    /// The unique identifier of the claim
    pub claim_id: Uuid,

    /// The claim statement text
    pub statement: String,

    /// Cosine similarity score [0.0, 1.0] between query and claim embedding
    pub similarity: f64,

    /// CDST epistemic state: belief interval [Bel, Pl] + ignorance + legacy truth
    pub epistemic: EpistemicState,

    /// The agent who made the claim
    pub agent_id: Uuid,

    /// The reasoning trace ID associated with this claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<Uuid>,

    /// The type of claim: factual, hypothesis, or opinion
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_type: Option<String>,

    /// When the claim was created
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,

    /// Graph neighbors providing epistemic context (only in diverse mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_neighbors: Option<Vec<GraphNeighbor>>,
}

/// A graph neighbor of a search result, providing epistemic context
#[derive(Debug, Serialize)]
pub struct GraphNeighbor {
    /// The neighbor claim ID
    pub claim_id: Uuid,
    /// The claim content
    pub statement: String,
    /// Cosine similarity to the query
    pub similarity: f64,
    /// CDST epistemic state
    pub epistemic: EpistemicState,
    /// The edge relationship type (e.g., "CORROBORATES", "supports", "contradicts")
    pub edge_type: String,
    /// Whether this is inbound or outbound from the picked claim
    pub direction: String,
}

/// Response from semantic search endpoint
#[derive(Debug, Serialize)]
pub struct SemanticSearchResponse {
    /// The search results, sorted by similarity descending
    pub results: Vec<SemanticSearchResult>,

    /// Total number of matching claims (before limit applied)
    pub total: u64,

    /// Time taken to execute the query in milliseconds
    pub query_time_ms: u64,
}

// ============================================================================
// Constants
// ============================================================================

/// Default number of results to return
const DEFAULT_LIMIT: u32 = 10;

/// Maximum number of results that can be requested
const MAX_LIMIT: u32 = 100;

/// Valid claim types for filtering
const VALID_CLAIM_TYPES: &[&str] = &["factual", "hypothesis", "opinion"];

/// Embedding dimension for OpenAI text-embedding-3-small
#[cfg(feature = "db")]
const EMBEDDING_DIM: usize = 1536;

/// Maximum query string length in bytes.
/// Prevents DoS attacks via excessively long queries that could consume
/// excessive memory in embedding generation or database operations.
/// 10KB is sufficient for complex semantic queries.
const MAX_QUERY_LENGTH: usize = 10_240;

/// Maximum claim_type filter length in bytes.
/// Prevents buffer overflow or injection attempts via oversized filter values.
const MAX_CLAIM_TYPE_LENGTH: usize = 64;

// ============================================================================
// Embedding Generation
// ============================================================================

/// Generate a mock embedding vector for the given text.
///
/// This creates a deterministic embedding based on the input text for testing purposes.
/// Used as a fallback when no embedding service is configured.
///
/// # Arguments
/// * `text` - The text to embed
///
/// # Returns
/// A normalized 1536-dimensional vector
#[cfg(feature = "db")]
fn generate_mock_embedding(text: &str) -> Vec<f32> {
    let mut embedding = vec![0.0f32; EMBEDDING_DIM];

    // Create a deterministic "embedding" based on text bytes
    // This is NOT a real embedding, just for testing similarity ranking
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
/// falling back to mock embedding generation if the service is unavailable or fails.
///
/// # Arguments
/// * `state` - Application state containing the optional embedding service
/// * `text` - The text to embed
///
/// # Returns
/// A vector of floats representing the text embedding
///
/// # Behavior
/// - If embedding service is configured and succeeds: returns real embedding
/// - If embedding service fails: logs warning and falls back to mock
/// - If no embedding service configured: uses mock embedding
#[cfg(feature = "db")]
async fn generate_query_embedding(state: &AppState, text: &str) -> Vec<f32> {
    // Try to use the real embedding service if available
    if let Some(ref embedding_service) = state.embedding_service {
        match embedding_service.generate_query(text).await {
            Ok(embedding) => {
                tracing::debug!(
                    text_len = text.len(),
                    embedding_dim = embedding.len(),
                    "Generated real embedding for search query"
                );
                return embedding;
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Embedding service failed, falling back to mock embedding"
                );
                // Fall through to mock embedding
            }
        }
    }

    // Fallback to mock embedding
    tracing::debug!(
        text_len = text.len(),
        "Using mock embedding for search query (no service configured or service failed)"
    );
    generate_mock_embedding(text)
}

/// Format embedding vector as pgvector string literal
///
/// Converts a Vec<f32> to the format "[0.1,0.2,0.3,...]" expected by pgvector.
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

/// Build a similarity-based kNN neighborhood graph from a candidate list.
///
/// For each candidate `i`, the `k` most similar other candidates (by their
/// similarity scores — a proxy for shared semantic neighbourhood) are added as
/// neighbours.  This gives `diverse_select` enough graph structure to avoid
/// picking redundant near-duplicates.
///
/// `candidates` is a slice of `(id, content, similarity)` tuples already
/// ranked by the query vector.  Since cosine similarity is a monotone proxy
/// for embedding proximity, items close together in the ranked list are likely
/// to be semantically close to each other.
#[cfg(feature = "db")]
fn build_similarity_neighbors(
    candidates: &[(uuid::Uuid, String, f64)],
    k: usize,
) -> Vec<Vec<usize>> {
    let n = candidates.len();
    let mut neighbors = vec![Vec::new(); n];

    for i in 0..n {
        let sim_i = candidates[i].2;
        // Score proximity as negative absolute difference in similarity score
        let mut scored: Vec<(usize, f64)> = (0..n)
            .filter(|&j| j != i)
            .map(|j| (j, -(sim_i - candidates[j].2).abs()))
            .collect();
        // Sort descending by score (smallest difference = most similar rank)
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        neighbors[i] = scored.into_iter().take(k).map(|(j, _)| j).collect();
    }

    neighbors
}

// ============================================================================
// Handler
// ============================================================================

/// Semantic search handler
///
/// POST /api/v1/search/semantic
///
/// Searches for claims semantically similar to the query using pgvector.
/// Results are ranked by cosine similarity and filtered according to
/// the provided criteria.
///
/// # Validation
///
/// - Query cannot be empty or whitespace-only
/// - Limit must be > 0 (capped at 100)
/// - min_similarity must be in [0.0, 1.0]
/// - claim_type must be one of: factual, hypothesis, opinion
/// - created_after must be <= created_before if both provided
///
/// # Security
///
/// - Query is parameterized to prevent SQL injection
/// - Special characters are safely handled by sqlx
pub async fn semantic_search(
    #[allow(unused_variables)] State(state): State<AppState>,
    Json(request): Json<SemanticSearchRequest>,
) -> Result<Json<SemanticSearchResponse>, ApiError> {
    let start_time = std::time::Instant::now();

    // Validate query is not empty
    let query = request.query.trim();
    if query.is_empty() {
        return Err(ApiError::ValidationError {
            field: "query".to_string(),
            reason: "Query cannot be empty".to_string(),
        });
    }

    // Validate query length (DoS prevention)
    if request.query.len() > MAX_QUERY_LENGTH {
        return Err(ApiError::ValidationError {
            field: "query".to_string(),
            reason: format!(
                "Query too long: {} bytes, maximum is {} bytes",
                request.query.len(),
                MAX_QUERY_LENGTH
            ),
        });
    }

    // Validate and apply limit
    let limit = request.limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 {
        return Err(ApiError::ValidationError {
            field: "limit".to_string(),
            reason: "Limit must be greater than 0".to_string(),
        });
    }
    #[allow(unused_variables)]
    let limit = limit.min(MAX_LIMIT) as usize;

    // Validate min_similarity
    #[allow(unused_variables)]
    let min_similarity = request.min_similarity.unwrap_or(0.0);
    if !(0.0..=1.0).contains(&min_similarity) {
        return Err(ApiError::ValidationError {
            field: "min_similarity".to_string(),
            reason: "min_similarity must be between 0.0 and 1.0".to_string(),
        });
    }

    // Validate claim_type if provided
    if let Some(ref claim_type) = request.claim_type {
        // Validate claim_type length (DoS prevention)
        if claim_type.len() > MAX_CLAIM_TYPE_LENGTH {
            return Err(ApiError::ValidationError {
                field: "claim_type".to_string(),
                reason: format!(
                    "claim_type too long: {} bytes, maximum is {} bytes",
                    claim_type.len(),
                    MAX_CLAIM_TYPE_LENGTH
                ),
            });
        }
        if !VALID_CLAIM_TYPES.contains(&claim_type.as_str()) {
            return Err(ApiError::ValidationError {
                field: "claim_type".to_string(),
                reason: format!(
                    "Invalid claim_type '{}'. Must be one of: factual, hypothesis, opinion",
                    claim_type
                ),
            });
        }
    }

    // Validate date range
    if let (Some(after), Some(before)) = (request.created_after, request.created_before) {
        if after > before {
            return Err(ApiError::ValidationError {
                field: "created_after".to_string(),
                reason: "created_after cannot be after created_before".to_string(),
            });
        }
    }

    // Execute semantic search with pgvector
    #[cfg(feature = "db")]
    {
        // Step 1: Generate embedding for the query
        // Uses real embedding service when configured, falls back to mock if unavailable
        let query_embedding = generate_query_embedding(&state, query).await;
        let embedding_str = format_embedding_for_pgvector(&query_embedding);

        // Step 2a: Diverse hierarchical retrieval path (theme-based + coverage selection)
        // When `diverse=true`, navigate themes first, then apply submodular selection.
        // Falls through to flat search if no themes exist yet (clustering hasn't run).
        if request.diverse.unwrap_or(false) {
            let max_themes = request.max_themes.unwrap_or(5) as i32;
            let alpha = request.diversity_weight.unwrap_or(0.5);

            // Find the most relevant themes for the query
            let themes = ClaimThemeRepository::find_similar_themes(
                &state.db_pool,
                &embedding_str,
                max_themes,
            )
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Theme search failed: {}", e),
            })?;

            // Only enter diverse mode if themes have been populated
            if !themes.is_empty() {
                let theme_ids: Vec<Uuid> = themes.iter().map(|(id, _, _)| *id).collect();

                // Retrieve candidate claims from those themes
                let candidates = ClaimThemeRepository::claims_in_themes(
                    &state.db_pool,
                    &theme_ids,
                    &embedding_str,
                    100,
                )
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("Candidate retrieval failed: {}", e),
                })?;

                // Build a proximity graph from the ranked candidate list (top-5 neighbours each)
                let neighbors = build_similarity_neighbors(&candidates, 5);
                let similarities: Vec<f32> = candidates.iter().map(|(_, _, s)| *s as f32).collect();

                // Greedy submodular selection balancing coverage and relevance
                let selected = diverse_select(&neighbors, &similarities, limit, alpha);

                // Collect the selected claim IDs for enrichment queries
                let selected_claim_ids: Vec<Uuid> =
                    selected.iter().map(|&idx| candidates[idx].0).collect();

                // Fetch full claim data for the selected IDs (including CDST columns)
                let full_rows = sqlx::query(
                    r#"
                    SELECT c.id, c.content, c.truth_value, c.belief, c.plausibility,
                           c.agent_id, c.trace_id,
                           c.labels[1] as claim_type, c.created_at,
                           1 - (c.embedding <=> $1::vector) as similarity
                    FROM claims c
                    WHERE c.id = ANY($2)
                    ORDER BY c.embedding <=> $1::vector
                    "#,
                )
                .bind(&embedding_str)
                .bind(&selected_claim_ids)
                .fetch_all(&state.db_pool)
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("Claim fetch failed: {e}"),
                })?;

                // Fetch graph neighbors for all selected claims
                let neighbor_rows = sqlx::query(
                    r#"
                    SELECT
                        e.source_id, e.target_id, e.relationship,
                        c.id as neighbor_id, left(c.content, 200) as content,
                        c.truth_value, c.belief as nb_belief, c.plausibility as nb_plausibility,
                        (1 - (c.embedding <=> $1::vector))::float8 as similarity,
                        CASE WHEN e.source_id = ANY($2) THEN 'outbound' ELSE 'inbound' END as direction
                    FROM edges e
                    JOIN claims c ON c.id = CASE WHEN e.source_id = ANY($2) THEN e.target_id ELSE e.source_id END
                    WHERE (e.source_id = ANY($2) OR e.target_id = ANY($2))
                      AND e.source_type = 'claim' AND e.target_type = 'claim'
                      AND e.relationship IN ('CORROBORATES', 'supports', 'refines', 'continues_argument', 'contradicts')
                    ORDER BY c.embedding <=> $1::vector
                    LIMIT 50
                    "#,
                )
                .bind(&embedding_str)
                .bind(&selected_claim_ids)
                .fetch_all(&state.db_pool)
                .await
                .unwrap_or_default();

                // Group neighbors by the selected claim they connect to
                let mut neighbor_map: HashMap<Uuid, Vec<GraphNeighbor>> = HashMap::new();
                for row in &neighbor_rows {
                    let source_id: Uuid = row.get("source_id");
                    let target_id: Uuid = row.get("target_id");
                    let direction: String = row.get("direction");

                    // Determine which selected claim this neighbor connects to
                    let parent_id = if selected_claim_ids.contains(&source_id) {
                        source_id
                    } else {
                        target_id
                    };

                    let neighbor = GraphNeighbor {
                        claim_id: row.get("neighbor_id"),
                        statement: row.get::<String, _>("content"),
                        similarity: row.get("similarity"),
                        epistemic: EpistemicState::from_row(
                            row.get("truth_value"),
                            row.get("nb_belief"),
                            row.get("nb_plausibility"),
                        ),
                        edge_type: row.get("relationship"),
                        direction,
                    };

                    neighbor_map.entry(parent_id).or_default().push(neighbor);
                }

                // Build response DTOs with full claim data and neighbors
                let mut results: Vec<SemanticSearchResult> = full_rows
                    .iter()
                    .map(|row| {
                        let claim_id: Uuid = row.get("id");
                        let neighbors = neighbor_map.remove(&claim_id).filter(|n| !n.is_empty());
                        SemanticSearchResult {
                            claim_id,
                            statement: row.get("content"),
                            similarity: row.get("similarity"),
                            epistemic: EpistemicState::from_row(
                                row.get("truth_value"),
                                row.get("belief"),
                                row.get("plausibility"),
                            ),
                            agent_id: row.get("agent_id"),
                            trace_id: row.get("trace_id"),
                            claim_type: row.get("claim_type"),
                            created_at: row.get("created_at"),
                            graph_neighbors: neighbors,
                        }
                    })
                    .collect();

                // Restore original diverse_select ordering (full_rows is ordered by DB)
                // Re-sort to match selected order for deterministic output
                let id_order: HashMap<Uuid, usize> = selected_claim_ids
                    .iter()
                    .enumerate()
                    .map(|(i, &id)| (id, i))
                    .collect();
                results.sort_by_key(|r| id_order.get(&r.claim_id).copied().unwrap_or(usize::MAX));

                let total = results.len() as u64;
                let query_time_ms = start_time.elapsed().as_millis() as u64;

                return Ok(Json(SemanticSearchResponse {
                    results,
                    total,
                    query_time_ms,
                }));
            }
            // No themes yet — fall through to flat search below
        }

        // Step 2b: Flat pgvector similarity search (default path)
        // Uses parameterized query to prevent SQL injection.
        // The <=> operator computes cosine distance; we subtract from 1 to get similarity.
        let rows = sqlx::query(
            r#"
            WITH query_vec AS (
                SELECT $1::vector AS vec
            )
            SELECT
                c.id as claim_id,
                c.content as statement,
                1 - (c.embedding <=> q.vec) as similarity,
                c.truth_value,
                c.belief,
                c.plausibility,
                c.agent_id,
                c.trace_id,
                c.labels[1] as claim_type,
                c.created_at
            FROM claims c, query_vec q
            WHERE c.embedding IS NOT NULL
              AND 1 - (c.embedding <=> q.vec) >= $2
              AND ($3::text IS NULL OR $3 = ANY(c.labels))
              AND ($4::timestamptz IS NULL OR c.created_at >= $4)
              AND ($5::timestamptz IS NULL OR c.created_at <= $5)
              AND ($6::uuid IS NULL OR c.agent_id = $6)
            ORDER BY similarity DESC
            LIMIT $7
            "#,
        )
        .bind(&embedding_str)
        .bind(min_similarity)
        .bind(request.claim_type.as_deref())
        .bind(request.created_after)
        .bind(request.created_before)
        .bind(request.agent_id)
        .bind(limit as i64)
        .fetch_all(&state.db_pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Database query failed: {}", e),
        })?;

        // Step 3: Convert rows to response DTOs
        let results: Vec<SemanticSearchResult> = rows
            .iter()
            .map(|row| SemanticSearchResult {
                claim_id: row.get("claim_id"),
                statement: row.get("statement"),
                similarity: row.get("similarity"),
                epistemic: EpistemicState::from_row(
                    row.get("truth_value"),
                    row.get("belief"),
                    row.get("plausibility"),
                ),
                agent_id: row.get("agent_id"),
                trace_id: row.get("trace_id"),
                claim_type: row.get("claim_type"),
                created_at: row.get("created_at"),
                graph_neighbors: None,
            })
            .collect();

        let total = results.len() as u64;
        let query_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(Json(SemanticSearchResponse {
            results,
            total,
            query_time_ms,
        }))
    }

    // Fallback when db feature is disabled
    #[cfg(not(feature = "db"))]
    {
        let results: Vec<SemanticSearchResult> = Vec::new();
        let total = 0u64;
        let query_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(Json(SemanticSearchResponse {
            results,
            total,
            query_time_ms,
        }))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests for request/response serialization and constants.
    /// Handler tests that require database access are in tests/routes/semantic_search_tests.rs

    #[test]
    fn test_default_limit_constant() {
        assert_eq!(DEFAULT_LIMIT, 10);
    }

    #[test]
    fn test_max_limit_constant() {
        assert_eq!(MAX_LIMIT, 100);
    }

    #[test]
    fn test_valid_claim_types_constant() {
        assert!(VALID_CLAIM_TYPES.contains(&"factual"));
        assert!(VALID_CLAIM_TYPES.contains(&"hypothesis"));
        assert!(VALID_CLAIM_TYPES.contains(&"opinion"));
        assert!(!VALID_CLAIM_TYPES.contains(&"invalid"));
    }

    #[test]
    fn test_semantic_search_request_deserialize() {
        let json = r#"{
            "query": "test query",
            "limit": 20,
            "min_similarity": 0.7,
            "claim_type": "factual"
        }"#;

        let request: SemanticSearchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.query, "test query");
        assert_eq!(request.limit, Some(20));
        assert_eq!(request.min_similarity, Some(0.7));
        assert_eq!(request.claim_type, Some("factual".to_string()));
        assert!(request.created_after.is_none());
        assert!(request.created_before.is_none());
        assert!(request.agent_id.is_none());
    }

    #[test]
    fn test_semantic_search_request_minimal() {
        let json = r#"{"query": "test"}"#;

        let request: SemanticSearchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.query, "test");
        assert!(request.limit.is_none());
        assert!(request.min_similarity.is_none());
        assert!(request.claim_type.is_none());
    }

    #[test]
    fn test_semantic_search_response_serialize() {
        let response = SemanticSearchResponse {
            results: vec![SemanticSearchResult {
                claim_id: Uuid::nil(),
                statement: "Test claim".to_string(),
                similarity: 0.85,
                epistemic: EpistemicState::from_row(0.75, Some(0.3), Some(0.9)),
                agent_id: Uuid::nil(),
                trace_id: None,
                claim_type: Some("factual".to_string()),
                created_at: None,
                graph_neighbors: None,
            }],
            total: 1,
            query_time_ms: 15,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total\":1"));
        assert!(json.contains("\"query_time_ms\":15"));
        assert!(json.contains("\"similarity\":0.85"));
        assert!(json.contains("\"truth_value\":0.75"));
        assert!(json.contains("\"belief\":0.3"));
        assert!(json.contains("\"plausibility\":0.9"));
        assert!(json.contains("\"ignorance\":"));
    }

    #[test]
    fn test_semantic_search_result_optional_fields_skipped() {
        let result = SemanticSearchResult {
            claim_id: Uuid::nil(),
            statement: "Test".to_string(),
            similarity: 0.5,
            epistemic: EpistemicState::from_row(0.5, None, None),
            agent_id: Uuid::nil(),
            trace_id: None,
            claim_type: None,
            created_at: None,
            graph_neighbors: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        // Optional None fields should be skipped
        assert!(!json.contains("trace_id"));
        assert!(!json.contains("claim_type"));
        assert!(!json.contains("created_at"));
        assert!(!json.contains("graph_neighbors"));
    }

    #[test]
    fn test_semantic_search_result_with_all_fields() {
        let now = Utc::now();
        let claim_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let trace_id = Uuid::new_v4();

        let result = SemanticSearchResult {
            claim_id,
            statement: "Full claim".to_string(),
            similarity: 0.95,
            epistemic: EpistemicState::from_row(0.88, Some(0.7), Some(0.95)),
            agent_id,
            trace_id: Some(trace_id),
            claim_type: Some("hypothesis".to_string()),
            created_at: Some(now),
            graph_neighbors: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"trace_id\":"));
        assert!(json.contains("\"claim_type\":\"hypothesis\""));
        assert!(json.contains("\"created_at\":"));
    }

    #[test]
    fn test_semantic_search_request_with_date_range() {
        let json = r#"{
            "query": "test",
            "created_after": "2024-01-01T00:00:00Z",
            "created_before": "2024-12-31T23:59:59Z"
        }"#;

        let request: SemanticSearchRequest = serde_json::from_str(json).unwrap();
        assert!(request.created_after.is_some());
        assert!(request.created_before.is_some());
    }

    #[test]
    fn test_semantic_search_request_with_agent_id() {
        let agent_id = Uuid::new_v4();
        let json = format!(r#"{{"query": "test", "agent_id": "{}"}}"#, agent_id);

        let request: SemanticSearchRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.agent_id, Some(agent_id));
    }
}
