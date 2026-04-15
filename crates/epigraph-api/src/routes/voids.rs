//! Knowledge void detection endpoints.
//!
//! ## Endpoints
//!
//! - `POST /api/v1/voids/detect`   - Detect knowledge voids for a list of concepts
//! - `GET  /api/v1/voids/density`  - Measure embedding neighborhood density

#[cfg(feature = "db")]
use axum::{
    extract::{Query, State},
    Json,
};
#[cfg(feature = "db")]
use serde::Deserialize;

#[cfg(feature = "db")]
use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;

// ── Request types ──

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct DetectVoidsRequest {
    pub concepts: Vec<String>,
    pub threshold: Option<f64>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct DensityQuery {
    pub query: String,
    pub radius: Option<f64>,
}

// ── Handlers ──

/// POST /api/v1/voids/detect - Detect knowledge voids for concepts.
///
/// For each concept, finds the nearest claim embedding and classifies
/// as void (< 0.50), sparse (0.50-threshold), or covered (>= threshold).
#[cfg(feature = "db")]
pub async fn detect_voids(
    State(state): State<AppState>,
    Json(request): Json<DetectVoidsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let embedder = state.embedding_service().ok_or(ApiError::InternalError {
        message: "Embedding service not configured".into(),
    })?;

    let threshold = request.threshold.unwrap_or(0.70);
    let sparse_threshold = 0.50;

    let mut voids = Vec::new();
    let mut sparse = Vec::new();
    let mut covered = Vec::new();

    for concept in &request.concepts {
        let embedding = embedder
            .generate(concept)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to embed concept '{concept}': {e}"),
            })?;

        // Find nearest claim
        let nearest: Option<NearestClaimRow> = sqlx::query_as(
            "SELECT id, content, \
                    1 - (embedding <=> $1::vector) AS similarity \
             FROM claims \
             WHERE embedding IS NOT NULL \
             ORDER BY embedding <=> $1::vector \
             LIMIT 1",
        )
        .bind(format_embedding(&embedding))
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to search embeddings: {e}"),
        })?;

        let (sim, nearest_claim) = match nearest {
            Some(ref row) => (
                row.similarity.unwrap_or(0.0),
                Some(row.content.chars().take(200).collect::<String>()),
            ),
            None => (0.0, None),
        };

        let entry = serde_json::json!({
            "concept": concept,
            "nearest_similarity": sim,
            "nearest_claim": nearest_claim,
        });

        if sim < sparse_threshold {
            voids.push(entry);
        } else if sim < threshold {
            sparse.push(entry);
        } else {
            covered.push(entry);
        }
    }

    Ok(Json(serde_json::json!({
        "total_concepts": request.concepts.len(),
        "void_concepts": voids,
        "sparse_concepts": sparse,
        "covered_concepts": covered,
    })))
}

/// GET /api/v1/voids/density - Measure embedding neighborhood density.
///
/// Counts how many claims fall within a cosine similarity radius of the query.
#[cfg(feature = "db")]
pub async fn embedding_density(
    State(state): State<AppState>,
    Query(params): Query<DensityQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let embedder = state.embedding_service().ok_or(ApiError::InternalError {
        message: "Embedding service not configured".into(),
    })?;

    let radius = params.radius.unwrap_or(0.60);

    let embedding =
        embedder
            .generate(&params.query)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to embed query: {e}"),
            })?;

    // Count claims within radius and get stats
    let stats: Option<DensityStatsRow> = sqlx::query_as(
        "SELECT COUNT(*) AS claim_count, \
                AVG(1 - (embedding <=> $1::vector)) AS avg_similarity \
         FROM claims \
         WHERE embedding IS NOT NULL \
           AND 1 - (embedding <=> $1::vector) >= $2",
    )
    .bind(format_embedding(&embedding))
    .bind(radius)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to compute density: {e}"),
    })?;

    // Get nearest claim
    let nearest: Option<NearestClaimRow> = sqlx::query_as(
        "SELECT id, content, \
                1 - (embedding <=> $1::vector) AS similarity \
         FROM claims \
         WHERE embedding IS NOT NULL \
         ORDER BY embedding <=> $1::vector \
         LIMIT 1",
    )
    .bind(format_embedding(&embedding))
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to find nearest: {e}"),
    })?;

    Ok(Json(serde_json::json!({
        "query": params.query,
        "radius": radius,
        "claim_count": stats.as_ref().and_then(|s| s.claim_count).unwrap_or(0),
        "avg_similarity": stats.as_ref().and_then(|s| s.avg_similarity).unwrap_or(0.0),
        "nearest_claim": nearest.as_ref().map(|n| n.content.chars().take(200).collect::<String>()),
        "nearest_similarity": nearest.as_ref().and_then(|n| n.similarity).unwrap_or(0.0),
    })))
}

// ── Internal helpers ──

#[cfg(feature = "db")]
fn format_embedding(embedding: &[f32]) -> String {
    format!(
        "[{}]",
        embedding
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

// ── Internal types ──

#[cfg(feature = "db")]
#[derive(sqlx::FromRow)]
struct NearestClaimRow {
    #[allow(dead_code)]
    id: uuid::Uuid,
    content: String,
    similarity: Option<f64>,
}

#[cfg(feature = "db")]
#[derive(sqlx::FromRow)]
struct DensityStatsRow {
    claim_count: Option<i64>,
    avg_similarity: Option<f64>,
}
