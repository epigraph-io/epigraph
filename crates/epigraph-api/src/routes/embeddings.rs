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
use crate::middleware::bearer::ViewerExtractor;
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
///
/// Both statements are read through the caller's [`Viewer`](epigraph_db::Viewer).
/// Until `F-inline-claim-content-reads` was discharged they ran inline on the
/// raw pool with no viewer at all, so the count, the mean/median similarity and
/// the level/source-type histogram were computed over every tenant's claims: a
/// semantic membership oracle that answered "is there private material near this
/// topic, and what kind" without returning a single id. They now call the same
/// repo functions the MCP twin `embedding_neighborhood_density` has used since
/// PR-09, so there is one copy of this SQL, filtered.
#[cfg(feature = "db")]
pub async fn neighborhood_density(
    ViewerExtractor(viewer): ViewerExtractor,
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

    // Both statements on ONE viewer-stamped connection, so the in-query `$V`
    // predicate and the session GUCs migration 077's policies read come from
    // the same `Viewer`. The error shape is the template's: log the reason,
    // answer with a fixed message.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "neighborhood_density",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // Aggregate stats in one round trip. Uses the existing HNSW index on
    // claims.embedding via the `<=>` cosine-distance operator. Cosine
    // similarity = 1 - cosine_distance. Filter is `similarity >= 1 - radius`
    // in distance space because pgvector indexes operate on distance.
    let (n_claims, mean_sim, median_sim) = epigraph_db::ClaimRepository::embedding_radius_density(
        &mut *read,
        &viewer,
        &embedding_str,
        radius,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("density aggregate failed: {e}"),
    })?;
    let mean_similarity = mean_sim.unwrap_or(0.0);
    let median_similarity = median_sim.unwrap_or(0.0);

    // Sample for level + source_type breakdown. Use max_sample to bound
    // worst-case scan even when n_claims is huge.
    let breakdown_rows = epigraph_db::ClaimRepository::embedding_radius_breakdown(
        &mut *read,
        &viewer,
        &embedding_str,
        radius,
        max_sample,
    )
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
