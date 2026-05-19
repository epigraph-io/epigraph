//! `embedding_neighborhood_density` MCP tool. Wraps the HTTP endpoint
//! `POST /api/v1/embeddings/neighborhood-density` so MCP clients (EpiClaw,
//! the nightly theme-maintenance workflow) can query density without an HTTP
//! detour. Per design 2026-05-18-cross-source-anchor §Component 0a.

#![allow(clippy::wildcard_imports)]

use rmcp::model::*;
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EmbeddingNeighborhoodDensityParams {
    /// Free-text query — embedded server-side via the configured embedder.
    pub query: String,
    /// Cosine distance radius (0.0 = identical, 1.0 = orthogonal). Default 0.30.
    pub radius: Option<f64>,
    /// Cap on sample size used to compute level/source breakdowns. Default 500.
    pub max_sample: Option<i64>,
}

pub async fn embedding_neighborhood_density(
    server: &EpiGraphMcpFull,
    params: EmbeddingNeighborhoodDensityParams,
) -> Result<CallToolResult, McpError> {
    let radius = params.radius.unwrap_or(0.30);
    let max_sample = params.max_sample.unwrap_or(500).clamp(1, 5000);

    let embedding = server
        .embedder
        .generate(&params.query)
        .await
        .map_err(|e| internal_error(format!("embed failed: {e}")))?;
    let embedding_dim = embedding.len() as u32;
    let embedding_str = crate::embed::format_pgvector(&embedding);

    let row: (i64, Option<f64>, Option<f64>) = sqlx::query_as(
        "SELECT COUNT(*)::bigint, \
                AVG(1 - (embedding <=> $1::vector))::float8, \
                percentile_cont(0.5) WITHIN GROUP \
                    (ORDER BY 1 - (embedding <=> $1::vector))::float8 \
         FROM claims \
         WHERE embedding IS NOT NULL \
           AND is_current = true \
           AND (embedding <=> $1::vector) <= $2",
    )
    .bind(&embedding_str)
    .bind(radius)
    .fetch_one(&server.pool)
    .await
    .map_err(internal_error)?;
    let n_claims = row.0;
    let mean_similarity = row.1.unwrap_or(0.0);
    let median_similarity = row.2.unwrap_or(0.0);

    let breakdown_rows: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT properties->>'level', properties->>'source_type' \
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
    .fetch_all(&server.pool)
    .await
    .map_err(internal_error)?;

    let mut by_level: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_source_type: BTreeMap<String, i64> = BTreeMap::new();
    for (lvl, src) in &breakdown_rows {
        let l = lvl.clone().unwrap_or_else(|| "unknown".into());
        let s = src.clone().unwrap_or_else(|| "unknown".into());
        *by_level.entry(l).or_insert(0) += 1;
        *by_source_type.entry(s).or_insert(0) += 1;
    }

    let sparsity = 1.0 / (1.0 + (n_claims as f64) / 200.0);

    let body = serde_json::json!({
        "n_claims": n_claims,
        "mean_similarity": mean_similarity,
        "median_similarity": median_similarity,
        "sparsity": sparsity,
        "by_level": by_level,
        "by_source_type": by_source_type,
        "radius": radius,
        "embedding_dim": embedding_dim,
    });

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&body).map_err(internal_error)?,
    )]))
}
