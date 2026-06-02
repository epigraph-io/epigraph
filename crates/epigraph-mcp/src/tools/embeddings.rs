//! `embedding_neighborhood_density` MCP tool. Wraps the HTTP endpoint
//! `POST /api/v1/embeddings/neighborhood-density` so MCP clients (EpiClaw,
//! the nightly theme-maintenance workflow) can query density without an HTTP
//! detour. Per design 2026-05-18-cross-source-anchor §Component 0a.

#![allow(clippy::wildcard_imports)]

use rmcp::model::*;
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::errors::{internal_error, invalid_params, McpError};
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

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BackfillEmbeddingsParams {
    /// Max claims to embed this run (default 200, clamped to 1..=2000). The
    /// selection is ordered oldest-first so repeated scheduled runs drain the
    /// backlog monotonically.
    pub limit: Option<i64>,
    /// When true, only count how many claims need embeddings and write nothing
    /// (safe to run with no OpenAI key). Default false.
    pub dry_run: Option<bool>,
}

/// `backfill_embeddings` — generate and store the missing `claims.embedding`
/// vector for current, non-telemetry claims that lack one.
///
/// This is the server-side, MCP-executable counterpart to the `embed_backfill`
/// CLI binary: it lets the scheduled decomposition-cycle task close the
/// embedding gap (the `is_current AND embedding IS NULL` population the
/// embedding-policy invariant in CLAUDE.md tracks) without shelling out. It is
/// the `embed` stage of the decompose→embed→cross-source-match pipeline; the
/// `decompose` stage stays the prepaid-LLM CLI primitive (no LLM provider is
/// registered in the MCP process) and `cross-source-match` is already exposed
/// as `find_cross_source_matches`.
///
/// Selection reuses `ClaimRepository::find_claims_needing_embeddings`, which
/// excludes host-provenance telemetry and `is_current = false` rows per the
/// invariant. Each vector is stored via `ClaimRepository::store_embedding`
/// (an `UPDATE claims SET embedding`), so a failure on one claim is reported,
/// not fatal — mirroring the CLI's per-row accounting.
pub async fn backfill_embeddings(
    server: &EpiGraphMcpFull,
    params: BackfillEmbeddingsParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(200).clamp(1, 2000);
    let dry_run = params.dry_run.unwrap_or(false);

    let rows = epigraph_db::ClaimRepository::find_claims_needing_embeddings(&server.pool, limit)
        .await
        .map_err(internal_error)?;
    let candidates = rows.len();

    if dry_run || candidates == 0 {
        let body = serde_json::json!({
            "candidates": candidates,
            "embedded": 0,
            "failed": 0,
            "dry_run": dry_run,
        });
        return Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&body).map_err(internal_error)?,
        )]));
    }

    // A mock embedder (no OPENAI_API_KEY on the server) would fail every
    // `generate`. Fail loudly up front rather than reporting "all failed",
    // so the scheduled task surfaces a config error instead of churning.
    if server.embedder.embeddings_disabled() {
        return Err(invalid_params(
            "embeddings disabled: no OPENAI_API_KEY configured on the MCP server; \
             cannot backfill (re-run with dry_run=true to only count candidates)",
        ));
    }

    let mut embedded = 0usize;
    let mut failed = 0usize;
    let mut errors: Vec<String> = Vec::new();
    for (claim_id, content) in rows {
        match server.embedder.generate(&content).await {
            Ok(vec) => {
                let pgvec = crate::embed::format_pgvector(&vec);
                match epigraph_db::ClaimRepository::store_embedding(&server.pool, claim_id, &pgvec)
                    .await
                {
                    Ok(true) => embedded += 1,
                    Ok(false) => {
                        failed += 1;
                        push_capped(&mut errors, format!("{claim_id}: store affected 0 rows"));
                    }
                    Err(e) => {
                        failed += 1;
                        push_capped(&mut errors, format!("{claim_id}: store failed: {e}"));
                    }
                }
            }
            Err(e) => {
                failed += 1;
                push_capped(&mut errors, format!("{claim_id}: embed failed: {e}"));
            }
        }
    }

    let body = serde_json::json!({
        "candidates": candidates,
        "embedded": embedded,
        "failed": failed,
        "dry_run": false,
        "errors": errors,
    });
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&body).map_err(internal_error)?,
    )]))
}

/// Append to a bounded error sample so a large failing batch does not return a
/// multi-megabyte payload. Caps at 20 entries.
fn push_capped(errors: &mut Vec<String>, msg: String) {
    if errors.len() < 20 {
        errors.push(msg);
    }
}
