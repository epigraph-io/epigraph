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
use epigraph_engine::diverse_retrieval::{
    candidates_in_themes_at_dim, find_similar_themes_at_dim, DEFAULT_CANDIDATE_POOL,
    MAX_CANDIDATE_POOL,
};

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

    /// Centroid dimension to query against in diverse mode. `None` =
    /// auto-detect (picks 3072 when ≥50% of `claim_themes` rows have
    /// `centroid_3072` populated, else 1536). `Some(1536)` forces the
    /// legacy `claim_themes.centroid` + `claims.embedding` columns;
    /// `Some(3072)` forces `claim_themes.centroid_3072` +
    /// `claims.embedding_3072` (operator must have run
    /// `epigraph-cli reembed --target claims` and rebuilt themes
    /// with `centroid_dim=3072` first, otherwise this returns 400
    /// ValidationError). Ignored when `diverse=false`.
    #[serde(default)]
    pub centroid_dim: Option<u32>,

    /// Candidate-pool top-K — the second-stage cutoff after theme
    /// selection. The diverse pipeline first picks the `max_themes`
    /// most-similar themes, then pulls up to this many claims across
    /// them as the input to submodular `diverse_select`. Higher values
    /// = better diversity coverage but more SQL work and a quadratic
    /// in-memory similarity matrix inside `build_similarity_neighbors`.
    ///
    /// Default is
    /// [`DEFAULT_CANDIDATE_POOL`](epigraph_engine::diverse_retrieval::DEFAULT_CANDIDATE_POOL)
    /// (100, matching the historical hard-coded value). Clamped to
    /// [`MAX_CANDIDATE_POOL`](epigraph_engine::diverse_retrieval::MAX_CANDIDATE_POOL)
    /// (1000) to prevent runaway matrices. Ignored when
    /// `diverse=false`.
    #[serde(default)]
    pub candidate_pool: Option<u32>,
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

    /// Theme this claim belongs to (k-means partition over `claim_themes`).
    /// `Some` when populated by `POST /api/v1/themes/build-from-corpus`;
    /// always emitted in diverse mode so callers can render or filter by
    /// theme. `None` if the claim hasn't been assigned. Flat-search results
    /// omit this field via `skip_serializing_if`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme_id: Option<Uuid>,

    /// Graph community this claim belongs to in the latest cluster run
    /// (Louvain over edges, populated by the cluster_graph job). Same
    /// emission semantics as `theme_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<Uuid>,
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

    /// Centroid dimension actually used in diverse mode (1536 or 3072).
    /// `None` for non-diverse / flat searches. Reflects either the
    /// caller's explicit `centroid_dim` hint or the auto-detect
    /// outcome, so callers can verify which embedding space was
    /// queried.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub centroid_dim_used: Option<u32>,
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

/// Embedding dimension for OpenAI text-embedding-3-small (legacy default)
#[cfg(feature = "db")]
const EMBEDDING_DIM: usize = 1536;

/// Embedding dimension for OpenAI text-embedding-3-large (Phase 5 3072d path)
#[cfg(feature = "db")]
const EMBEDDING_DIM_LARGE: usize = 3072;

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

/// Generate a mock embedding vector for the given text at the requested dimension.
///
/// This creates a deterministic embedding based on the input text for testing
/// purposes. Used as a fallback when no embedding service is configured, or
/// when the configured service's dimension doesn't match the centroid dim
/// the caller is querying against (e.g. diverse-mode 3072d path).
///
/// # Arguments
/// * `text` - The text to embed
/// * `dim` - Target embedding dimension (e.g. 1536 or 3072)
///
/// # Returns
/// A normalized `dim`-dimensional vector
#[cfg(feature = "db")]
fn generate_mock_embedding_with_dim(text: &str, dim: usize) -> Vec<f32> {
    let mut embedding = vec![0.0f32; dim];

    // Create a deterministic "embedding" based on text bytes
    // This is NOT a real embedding, just for testing similarity ranking
    let text_bytes = text.as_bytes();
    for (i, byte) in text_bytes.iter().enumerate() {
        let idx = i % dim;
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
/// A vector of floats representing the text embedding (1536d, legacy default).
///
/// # Behavior
/// - If embedding service is configured and succeeds: returns real embedding
/// - If embedding service fails: logs warning and falls back to mock
/// - If no embedding service configured: uses mock embedding
#[cfg(feature = "db")]
async fn generate_query_embedding(state: &AppState, text: &str) -> Vec<f32> {
    generate_query_embedding_with_dim(state, text, EMBEDDING_DIM).await
}

/// Generate query embedding at a target dimension.
///
/// Used by the diverse-search 3072d path: when the caller asks for
/// `centroid_dim=3072` the centroid lookup runs against `claim_themes.centroid_3072`,
/// so the query vector must also be 3072-dimensional. If the configured embedding
/// service produces a different dimension (e.g. it's pinned to
/// `text-embedding-3-small`/1536d while we need 3072d), we fall back to a
/// deterministic mock at the target dim — the caller will get degraded
/// similarity quality but the query won't fail. Operators running the 3072d
/// path in production are expected to configure a service whose
/// `dimension()` matches.
#[cfg(feature = "db")]
async fn generate_query_embedding_with_dim(
    state: &AppState,
    text: &str,
    target_dim: usize,
) -> Vec<f32> {
    // Try to use the real embedding service if available AND its dimension matches.
    if let Some(ref embedding_service) = state.embedding_service {
        if embedding_service.dimension() == target_dim {
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
        } else {
            tracing::warn!(
                service_dim = embedding_service.dimension(),
                target_dim = target_dim,
                "Configured embedding service dimension differs from requested centroid_dim; using mock at target dim"
            );
        }
    }

    // Fallback to mock embedding at the target dim.
    tracing::debug!(
        text_len = text.len(),
        target_dim = target_dim,
        "Using mock embedding for search query (no service configured, dim mismatch, or service failed)"
    );
    generate_mock_embedding_with_dim(text, target_dim)
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

// `build_similarity_neighbors` and the diverse-pipeline helpers live in
// `epigraph_engine::diverse_retrieval` so the MCP `recall_with_context`
// tool can share the same retrieval logic. See the module docs for the
// pipeline shape.

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
        // Validate centroid_dim hint up front (only meaningful when diverse=true,
        // but reject obvious garbage values regardless so callers get a clear error).
        if let Some(dim) = request.centroid_dim {
            if dim != 1536 && dim != 3072 {
                return Err(ApiError::ValidationError {
                    field: "centroid_dim".to_string(),
                    reason: format!("centroid_dim must be 1536 or 3072 (got {dim})"),
                });
            }
        }

        // Step 2a: Diverse hierarchical retrieval path (theme-based + coverage selection)
        // When `diverse=true`, navigate themes first, then apply submodular selection.
        // Falls through to flat search if no themes exist yet (clustering hasn't run).
        if request.diverse.unwrap_or(false) {
            let max_themes = request.max_themes.unwrap_or(5) as i32;
            let alpha = request.diversity_weight.unwrap_or(0.5);

            // Clamp the candidate-pool top-K at the request boundary so the
            // caller sees the value they will actually get (vs. silently
            // capping deep in `build_similarity_neighbors`). Default to the
            // pre-refactor `DEFAULT_CANDIDATE_POOL` (100) when unset.
            let candidate_pool = request
                .candidate_pool
                .map(|n| n.min(MAX_CANDIDATE_POOL))
                .map(|n| n as i32)
                .unwrap_or(DEFAULT_CANDIDATE_POOL);

            // Resolve which centroid dimension to query against. Explicit hint
            // wins; otherwise auto-detect via the population fraction of
            // `claim_themes.centroid_3072` (≥50% → 3072, else 1536). This lets
            // operators flip the corpus to 3072d theme-by-theme and have the
            // search path follow automatically once the majority is migrated.
            let frac_3072 = sqlx::query_scalar::<_, Option<f64>>(
                "SELECT \
                    COUNT(*) FILTER (WHERE centroid_3072 IS NOT NULL)::float8 \
                      / NULLIF(COUNT(*), 0)::float8 \
                  FROM claim_themes",
            )
            .fetch_one(&state.db_pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("centroid_dim auto-detect failed: {e}"),
            })?
            .unwrap_or(0.0);

            let centroid_dim_used: u32 = match request.centroid_dim {
                Some(d) => d,
                None => {
                    if frac_3072 >= 0.5 {
                        3072
                    } else {
                        1536
                    }
                }
            };

            // Operator-misordering guard: caller asked for 3072d but no
            // themes have a centroid_3072 populated. Match PR #84's pattern
            // (BadRequest body) using ValidationError for the clearer
            // `field` surface — spec calls for 412 Precondition Failed but
            // ApiError has no PreconditionFailed variant yet.
            if centroid_dim_used == 3072 && frac_3072 == 0.0 {
                return Err(ApiError::ValidationError {
                    field: "centroid_dim".to_string(),
                    reason: "no 3072d centroids populated; run \
                             `epigraph-cli reembed --target claims` and rebuild \
                             themes with centroid_dim=3072 first"
                        .to_string(),
                });
            }

            // Step 1: generate the query embedding at the centroid's
            // dimension so the pgvector `<=>` operator can compare them.
            let target_dim = if centroid_dim_used == 3072 {
                EMBEDDING_DIM_LARGE
            } else {
                EMBEDDING_DIM
            };
            let query_embedding =
                generate_query_embedding_with_dim(&state, query, target_dim).await;
            let embedding_str = format_embedding_for_pgvector(&query_embedding);

            // The claim-embedding column name (still used by the post-
            // selection full-row + graph-neighbor queries below). Column
            // names are not user input (only `1536` or `3072` reach this
            // point), so `format!`-interpolating them is injection-safe.
            let claim_embedding_col = if centroid_dim_used == 3072 {
                "embedding_3072"
            } else {
                "embedding"
            };

            // Pre-flight: cheap theme lookup ONLY to determine whether
            // the corpus has themes at all. If empty, fall through to
            // flat ANN (matching pre-helper behaviour); otherwise run
            // the shared pipeline.
            let themes = find_similar_themes_at_dim(
                &state.db_pool,
                &embedding_str,
                max_themes,
                centroid_dim_used,
            )
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Theme search failed: {e}"),
            })?;

            // Only enter diverse mode if themes have been populated
            if !themes.is_empty() {
                let theme_ids: Vec<Uuid> = themes.iter().map(|(id, _, _)| *id).collect();

                // Retrieve candidate claims via the shared helper — same
                // SQL shape as before, plus the level-filter knob for
                // MCP. REST passes `paragraph_only=false` to preserve
                // pre-helper behaviour.
                let candidates = candidates_in_themes_at_dim(
                    &state.db_pool,
                    &theme_ids,
                    &embedding_str,
                    candidate_pool,
                    centroid_dim_used,
                    /*paragraph_only=*/ false,
                )
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("Candidate retrieval failed: {e}"),
                })?;

                // Build proximity graph + run greedy submodular selection.
                // Helper centralises this (k=5, alpha=user-supplied) so MCP
                // and REST agree.
                let selected_rows = {
                    use epigraph_engine::diverse_retrieval::{
                        build_similarity_neighbors, DEFAULT_SIMILARITY_K,
                    };
                    use epigraph_engine::diverse_select::diverse_select;
                    let neighbors =
                        build_similarity_neighbors(&candidates, DEFAULT_SIMILARITY_K);
                    let similarities: Vec<f32> =
                        candidates.iter().map(|(_, _, s)| *s as f32).collect();
                    let selected = diverse_select(&neighbors, &similarities, limit, alpha);
                    selected
                        .into_iter()
                        .map(|idx| candidates[idx].clone())
                        .collect::<Vec<_>>()
                };

                // Collect the selected claim IDs for enrichment queries
                let selected_claim_ids: Vec<Uuid> =
                    selected_rows.iter().map(|(id, _, _)| *id).collect();

                // Fetch full claim data for the selected IDs (including CDST
                // columns + theme_id and the latest cluster_id from
                // claim_cluster_membership). #49: surface the partition
                // labels so callers can render or filter by them.
                let full_sql = format!(
                    r#"
                    SELECT c.id, c.content, c.truth_value, c.belief, c.plausibility,
                           c.agent_id, c.trace_id,
                           c.labels[1] as claim_type, c.created_at,
                           c.theme_id,
                           (
                               SELECT m.cluster_id
                               FROM claim_cluster_membership m
                               JOIN graph_cluster_runs r ON r.run_id = m.run_id
                               WHERE m.claim_id = c.id
                               ORDER BY r.completed_at DESC
                               LIMIT 1
                           ) AS cluster_id,
                           1 - (c.{claim_embedding_col} <=> $1::vector) as similarity
                    FROM claims c
                    WHERE c.id = ANY($2)
                    ORDER BY c.{claim_embedding_col} <=> $1::vector
                    "#
                );
                let full_rows = sqlx::query(&full_sql)
                    .bind(&embedding_str)
                    .bind(&selected_claim_ids)
                    .fetch_all(&state.db_pool)
                    .await
                    .map_err(|e| ApiError::InternalError {
                        message: format!("Claim fetch failed: {e}"),
                    })?;

                // Fetch graph neighbors for all selected claims
                let neighbor_sql = format!(
                    r#"
                    SELECT
                        e.source_id, e.target_id, e.relationship,
                        c.id as neighbor_id, left(c.content, 200) as content,
                        c.truth_value, c.belief as nb_belief, c.plausibility as nb_plausibility,
                        (1 - (c.{claim_embedding_col} <=> $1::vector))::float8 as similarity,
                        CASE WHEN e.source_id = ANY($2) THEN 'outbound' ELSE 'inbound' END as direction
                    FROM edges e
                    JOIN claims c ON c.id = CASE WHEN e.source_id = ANY($2) THEN e.target_id ELSE e.source_id END
                    WHERE (e.source_id = ANY($2) OR e.target_id = ANY($2))
                      AND e.source_type = 'claim' AND e.target_type = 'claim'
                      AND e.relationship IN ('CORROBORATES', 'supports', 'refines', 'continues_argument', 'contradicts')
                    ORDER BY c.{claim_embedding_col} <=> $1::vector
                    LIMIT 50
                    "#
                );
                let neighbor_rows = sqlx::query(&neighbor_sql)
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
                            theme_id: row.try_get::<Option<Uuid>, _>("theme_id").ok().flatten(),
                            cluster_id: row.try_get::<Option<Uuid>, _>("cluster_id").ok().flatten(),
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
                    centroid_dim_used: Some(centroid_dim_used),
                }));
            }
            // No themes yet — fall through to flat search below
        }

        // Flat-path uses the legacy 1536d `claims.embedding` column directly,
        // so generate the query embedding at that dim. Diverse-path generates
        // its own (possibly 3072d) embedding above.
        let query_embedding = generate_query_embedding(&state, query).await;
        let embedding_str = format_embedding_for_pgvector(&query_embedding);

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
                theme_id: None,
                cluster_id: None,
            })
            .collect();

        let total = results.len() as u64;
        let query_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(Json(SemanticSearchResponse {
            results,
            total,
            query_time_ms,
            centroid_dim_used: None,
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
            centroid_dim_used: None,
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
                theme_id: None,
                cluster_id: None,
            }],
            total: 1,
            query_time_ms: 15,
            centroid_dim_used: None,
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
            theme_id: None,
            cluster_id: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        // Optional None fields should be skipped
        assert!(!json.contains("trace_id"));
        assert!(!json.contains("claim_type"));
        assert!(!json.contains("created_at"));
        assert!(!json.contains("graph_neighbors"));
        assert!(!json.contains("theme_id"));
        assert!(!json.contains("cluster_id"));
    }

    #[test]
    fn test_semantic_search_result_with_all_fields() {
        let now = Utc::now();
        let claim_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let trace_id = Uuid::new_v4();

        let theme_id = Uuid::new_v4();
        let cluster_id = Uuid::new_v4();
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
            theme_id: Some(theme_id),
            cluster_id: Some(cluster_id),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"trace_id\":"));
        assert!(json.contains("\"claim_type\":\"hypothesis\""));
        assert!(json.contains("\"created_at\":"));
        assert!(json.contains(&format!("\"theme_id\":\"{theme_id}\"")));
        assert!(json.contains(&format!("\"cluster_id\":\"{cluster_id}\"")));
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

    #[test]
    fn test_semantic_search_request_centroid_dim_field() {
        // 3072d hint deserializes into the new field.
        let json = r#"{"query": "test", "diverse": true, "centroid_dim": 3072}"#;
        let request: SemanticSearchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.centroid_dim, Some(3072));

        // Absent field defaults to None (auto-detect).
        let json2 = r#"{"query": "test", "diverse": true}"#;
        let request2: SemanticSearchRequest = serde_json::from_str(json2).unwrap();
        assert!(request2.centroid_dim.is_none());
    }

    #[test]
    fn test_semantic_search_response_serializes_centroid_dim_used() {
        // Some(3072) → field is present in JSON.
        let resp_with = SemanticSearchResponse {
            results: vec![],
            total: 0,
            query_time_ms: 1,
            centroid_dim_used: Some(3072),
        };
        let json = serde_json::to_string(&resp_with).unwrap();
        assert!(json.contains("\"centroid_dim_used\":3072"));

        // None → field is skipped (flat-search responses stay backwards-compat).
        let resp_without = SemanticSearchResponse {
            results: vec![],
            total: 0,
            query_time_ms: 1,
            centroid_dim_used: None,
        };
        let json2 = serde_json::to_string(&resp_without).unwrap();
        assert!(!json2.contains("centroid_dim_used"));
    }
}

// ============================================================================
// DB integration tests for the diverse-search centroid_dim path
// ============================================================================

#[cfg(all(test, feature = "db"))]
mod db_integration_tests {
    use super::*;
    use crate::state::{ApiConfig, AppState};
    use sqlx::Row;

    async fn try_test_pool() -> Option<sqlx::PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .ok()?;
        sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
        Some(pool)
    }

    macro_rules! test_pool_or_skip {
        () => {{
            match try_test_pool().await {
                Some(p) => p,
                None => {
                    eprintln!("Skipping DB test: DATABASE_URL not set or unreachable");
                    return;
                }
            }
        }};
    }

    /// Wipe `claim_themes` and unassign all claims so each test starts with
    /// a known empty theme table. Necessary because the DB is shared across
    /// tests and prior k-means runs could otherwise leak themes.
    async fn reset_themes(pool: &sqlx::PgPool) {
        let _ = sqlx::query("UPDATE claims SET theme_id = NULL")
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM claim_themes").execute(pool).await;
    }

    /// Insert a fresh agent for the test scope (returns its UUID).
    async fn seed_agent(pool: &sqlx::PgPool, label: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels) \
             VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'system', ARRAY['test']) \
             RETURNING id",
        )
        .bind(label)
        .fetch_one(pool)
        .await
        .expect("seed agent")
    }

    /// Build a deterministic pgvector literal at the given dim, biased toward
    /// `seed` so two calls with the same seed produce similar (but not equal)
    /// vectors after normalization.
    fn pgvec_at_dim(seed: f32, dim: usize) -> String {
        let mut v = vec![0.0f32; dim];
        for (i, slot) in v.iter_mut().enumerate() {
            *slot = if i == 0 { seed + 0.5 } else { seed * 1e-3 };
        }
        let inner: Vec<String> = v.iter().map(|x| x.to_string()).collect();
        format!("[{}]", inner.join(","))
    }

    /// Insert N themes with `centroid_3072` populated. Returns the inserted ids.
    async fn seed_themes_with_3072_centroids(pool: &sqlx::PgPool, n: usize) -> Vec<Uuid> {
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let theme_id = sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO claim_themes (label, description) VALUES ($1, $2) RETURNING id",
            )
            .bind(format!("test-3072-theme-{i}"))
            .bind("3072d test theme")
            .fetch_one(pool)
            .await
            .expect("create theme");

            let pgvec = pgvec_at_dim(i as f32 * 0.1, EMBEDDING_DIM_LARGE);
            sqlx::query("UPDATE claim_themes SET centroid_3072 = $2::vector WHERE id = $1")
                .bind(theme_id)
                .bind(&pgvec)
                .execute(pool)
                .await
                .expect("set 3072 centroid");
            ids.push(theme_id);
        }
        ids
    }

    /// Insert N themes with ONLY the legacy 1536d `centroid` populated. Used
    /// to assert the rejection path when the caller asks for 3072d but the
    /// corpus hasn't been migrated.
    async fn seed_themes_with_only_1536_centroids(pool: &sqlx::PgPool, n: usize) -> Vec<Uuid> {
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let theme_id = sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO claim_themes (label, description) VALUES ($1, $2) RETURNING id",
            )
            .bind(format!("test-1536-only-theme-{i}"))
            .bind("1536d-only test theme")
            .fetch_one(pool)
            .await
            .expect("create theme");

            let pgvec = pgvec_at_dim(i as f32 * 0.1, EMBEDDING_DIM);
            sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
                .bind(theme_id)
                .bind(&pgvec)
                .execute(pool)
                .await
                .expect("set 1536 centroid");
            ids.push(theme_id);
        }
        ids
    }

    /// Insert N themes; `n_3072_populated` of them get `centroid_3072` set,
    /// the rest get only the legacy `centroid` set. Used for the auto-detect
    /// majority test.
    async fn seed_themes_with_mixed_centroids(
        pool: &sqlx::PgPool,
        total: usize,
        n_3072_populated: usize,
    ) -> Vec<Uuid> {
        let mut ids = Vec::with_capacity(total);
        for i in 0..total {
            let theme_id = sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO claim_themes (label, description) VALUES ($1, $2) RETURNING id",
            )
            .bind(format!("test-mixed-theme-{i}"))
            .bind("mixed-dim test theme")
            .fetch_one(pool)
            .await
            .expect("create theme");

            if i < n_3072_populated {
                let pgvec = pgvec_at_dim(i as f32 * 0.1, EMBEDDING_DIM_LARGE);
                sqlx::query("UPDATE claim_themes SET centroid_3072 = $2::vector WHERE id = $1")
                    .bind(theme_id)
                    .bind(&pgvec)
                    .execute(pool)
                    .await
                    .expect("set 3072 centroid");
            } else {
                let pgvec = pgvec_at_dim(i as f32 * 0.1, EMBEDDING_DIM);
                sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
                    .bind(theme_id)
                    .bind(&pgvec)
                    .execute(pool)
                    .await
                    .expect("set 1536 centroid");
            }
            ids.push(theme_id);
        }
        ids
    }

    /// Insert N claims with `embedding_3072` populated and assigned to the
    /// given themes (round-robin). Returns inserted claim ids.
    async fn seed_claims_with_3072_embeddings(
        pool: &sqlx::PgPool,
        n: usize,
        theme_ids: &[Uuid],
        agent_id: Uuid,
    ) -> Vec<Uuid> {
        assert!(
            !theme_ids.is_empty(),
            "need at least one theme to attach claims"
        );
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let theme_id = theme_ids[i % theme_ids.len()];
            let pgvec = pgvec_at_dim(i as f32 * 0.05, EMBEDDING_DIM_LARGE);
            let content = format!("test-3072-claim-{}-{}", i, Uuid::new_v4());
            let claim_id = sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding_3072, theme_id) \
                 VALUES ($1, sha256($1::bytea), 0.5, $2, $3::vector, $4) \
                 RETURNING id",
            )
            .bind(&content)
            .bind(agent_id)
            .bind(&pgvec)
            .bind(theme_id)
            .fetch_one(pool)
            .await
            .expect("seed 3072 claim");
            ids.push(claim_id);
        }
        ids
    }

    /// Helper that invokes `semantic_search` with diverse mode on. Returns
    /// the parsed response or the raw `ApiError`.
    async fn call_diverse_search(
        pool: sqlx::PgPool,
        centroid_dim: Option<u32>,
    ) -> Result<SemanticSearchResponse, ApiError> {
        let state = AppState::with_db(pool, ApiConfig::default());
        let request = SemanticSearchRequest {
            query: "test query for diverse search".to_string(),
            limit: Some(5),
            min_similarity: None,
            claim_type: None,
            created_after: None,
            created_before: None,
            agent_id: None,
            diverse: Some(true),
            max_themes: Some(3),
            diversity_weight: Some(0.5),
            centroid_dim,
            candidate_pool: None,
        };
        let response = semantic_search(axum::extract::State(state), axum::Json(request)).await?;
        Ok(response.0)
    }

    /// Test 1 — explicit 3072d hint queries the 3072d centroids and
    /// surfaces `centroid_dim_used: 3072`.
    #[tokio::test]
    async fn diverse_search_uses_3072d_centroids_when_hinted() {
        let pool = test_pool_or_skip!();
        reset_themes(&pool).await;

        let agent = seed_agent(&pool, "diverse-3072-test").await;
        let theme_ids = seed_themes_with_3072_centroids(&pool, 5).await;
        let _claims = seed_claims_with_3072_embeddings(&pool, 50, &theme_ids, agent).await;

        let resp = call_diverse_search(pool.clone(), Some(3072))
            .await
            .expect("3072d diverse search must succeed");

        assert_eq!(
            resp.centroid_dim_used,
            Some(3072),
            "response must surface centroid_dim_used=3072"
        );
        assert!(
            !resp.results.is_empty(),
            "should return at least one claim from the 3072d themes"
        );
    }

    /// Test 2 — explicit 3072d hint with NO 3072d centroids populated:
    /// must reject with ValidationError on field=centroid_dim.
    #[tokio::test]
    async fn diverse_search_rejects_when_3072d_centroids_missing() {
        let pool = test_pool_or_skip!();
        reset_themes(&pool).await;

        let _ids = seed_themes_with_only_1536_centroids(&pool, 5).await;

        let result = call_diverse_search(pool.clone(), Some(3072)).await;

        match result {
            Err(ApiError::ValidationError { field, .. }) => {
                assert_eq!(field, "centroid_dim", "validation must blame centroid_dim");
            }
            other => panic!(
                "expected ValidationError on centroid_dim, got: {:?}",
                other.map(|r| format!("Ok(results={})", r.results.len()))
            ),
        }
    }

    /// Test 3 — auto-detect: when ≥50% of themes have `centroid_3072`
    /// populated and the caller does NOT hint, the search picks 3072d.
    #[tokio::test]
    async fn diverse_search_auto_picks_3072d_when_majority_populated() {
        let pool = test_pool_or_skip!();
        reset_themes(&pool).await;

        // 8/10 themes have centroid_3072 (80% > 50% threshold)
        let theme_ids = seed_themes_with_mixed_centroids(&pool, 10, 8).await;
        let agent = seed_agent(&pool, "diverse-auto-test").await;
        // Attach claims to the 3072-populated themes only so the search has
        // candidates after theme selection.
        let theme_ids_3072 = &theme_ids[..8];
        let _claims = seed_claims_with_3072_embeddings(&pool, 50, theme_ids_3072, agent).await;

        let resp = call_diverse_search(pool.clone(), None)
            .await
            .expect("auto-detected diverse search must succeed");

        assert_eq!(
            resp.centroid_dim_used,
            Some(3072),
            "auto-detect should pick 3072 when ≥50% of themes have centroid_3072 set"
        );
    }
}
