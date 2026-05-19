//! Embedding-space diagnostics endpoints.
//!
//! ## Endpoints
//! - `POST /api/v1/embeddings/neighborhood-density` — count + summary stats
//!   for claims within a cosine radius of a query embedding. Used by the
//!   nightly theme-maintenance workflow (`mcp__epigraph__embedding_neighborhood_density`)
//!   and by the cross-source anchor pass to detect dense regions that warrant
//!   theme sub-splitting.
//!
//! See docs/superpowers/specs/2026-05-18-cross-source-anchor-design.md §Component 0.

#[cfg(feature = "db")]
use axum::{extract::State, Json};
#[cfg(feature = "db")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "db")]
use std::collections::BTreeMap;

#[cfg(feature = "db")]
use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct NeighborhoodDensityRequest {
    pub query: String,
    pub radius: Option<f64>,
    pub max_sample: Option<i64>,
}

#[cfg(feature = "db")]
#[derive(Debug, Serialize)]
pub struct NeighborhoodDensityResponse {
    pub n_claims: i64,
    pub mean_similarity: f64,
    pub median_similarity: f64,
    pub sparsity: f64,
    pub by_level: BTreeMap<String, i64>,
    pub by_source_type: BTreeMap<String, i64>,
    pub radius: f64,
    pub embedding_dim: u32,
}

/// POST /api/v1/embeddings/neighborhood-density
#[cfg(feature = "db")]
pub async fn neighborhood_density(
    State(state): State<AppState>,
    Json(req): Json<NeighborhoodDensityRequest>,
) -> Result<Json<NeighborhoodDensityResponse>, ApiError> {
    let radius = req.radius.unwrap_or(0.30);
    let max_sample = req.max_sample.unwrap_or(500).clamp(1, 5000);

    let embedder = state.embedding_service().ok_or(ApiError::InternalError {
        message: "Embedding service not configured".into(),
    })?;
    let embedding = embedder
        .generate(&req.query)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to embed query: {e}"),
        })?;
    let embedding_dim = embedding.len() as u32;
    let embedding_str = format!(
        "[{}]",
        embedding
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );

    // Aggregate stats in one round trip. Uses the existing HNSW index on
    // claims.embedding via the `<=>` cosine-distance operator. Cosine
    // similarity = 1 - cosine_distance. Filter is `similarity >= 1 - radius`
    // in distance space because pgvector indexes operate on distance.
    let row = sqlx::query_as::<_, (i64, Option<f64>, Option<f64>)>(
        "SELECT COUNT(*)::bigint AS n, \
                AVG(1 - (embedding <=> $1::vector))::float8 AS mean_sim, \
                percentile_cont(0.5) WITHIN GROUP \
                    (ORDER BY 1 - (embedding <=> $1::vector))::float8 AS median_sim \
         FROM claims \
         WHERE embedding IS NOT NULL \
           AND is_current = true \
           AND (embedding <=> $1::vector) <= $2",
    )
    .bind(&embedding_str)
    .bind(radius)
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("density aggregate failed: {e}"),
    })?;
    let n_claims = row.0;
    let mean_similarity = row.1.unwrap_or(0.0);
    let median_similarity = row.2.unwrap_or(0.0);

    // Sample for level + source_type breakdown. Use max_sample to bound
    // worst-case scan even when n_claims is huge.
    let breakdown_rows: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT properties->>'level' AS lvl, properties->>'source_type' AS src \
         FROM claims \
         WHERE embedding IS NOT NULL \
           AND is_current = true \
           AND (embedding <=> $1::vector) <= $2 \
         ORDER BY embedding <=> $1::vector \
         LIMIT $3",
    )
    .bind(&embedding_str)
    .bind(radius)
    .bind(max_sample)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("density breakdown failed: {e}"),
    })?;

    let mut by_level: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_source_type: BTreeMap<String, i64> = BTreeMap::new();
    for (lvl, src) in &breakdown_rows {
        let l = lvl.clone().unwrap_or_else(|| "unknown".into());
        let s = src.clone().unwrap_or_else(|| "unknown".into());
        *by_level.entry(l).or_insert(0) += 1;
        *by_source_type.entry(s).or_insert(0) += 1;
    }

    // Sparsity: squashed inverse of n_claims with target_n=200 as the
    // "comfortable" density. Bounded (0, 1]. Lower = denser.
    let sparsity = 1.0 / (1.0 + (n_claims as f64) / 200.0);

    Ok(Json(NeighborhoodDensityResponse {
        n_claims,
        mean_similarity,
        median_similarity,
        sparsity,
        by_level,
        by_source_type,
        radius,
        embedding_dim,
    }))
}
