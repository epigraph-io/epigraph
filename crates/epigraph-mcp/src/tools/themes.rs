//! Theme k-means MCP tool. Wraps
//! [`epigraph_engine::theme_kmeans::run_theme_kmeans`] so MCP clients (e.g.
//! EpiClaw) can trigger server-side theme clustering instead of falling back
//! to manual sampling. Mirrors the HTTP route
//! `POST /api/v1/themes/build-from-corpus` (`build_themes_from_corpus` in
//! `epigraph-api/src/routes/crud.rs`) with the same defaults.
//!
//! ## Safety
//! - `limit` is capped at 500 (per `feedback_memory_limits.md`: VM OOMs at
//!   ~2000 embeddings).
//! - `wipe_first` defaults to `true`. Rationale: the `claim_themes` table
//!   currently has no `UNIQUE(label)` constraint and `ClaimThemeRepository::create`
//!   has no `ON CONFLICT` clause, so the additive path (`wipe_first=false`)
//!   silently accumulates duplicate `auto-00`, `auto-01`, ... rows on every
//!   call. Because this MCP tool is invoked by automated scheduled tasks, the
//!   safe-by-default behaviour is a clean rebuild on each call. Callers that
//!   genuinely want additive runs (e.g. with a unique `label_prefix` per call)
//!   can pass `wipe_first=false` and will receive a warning in the response
//!   when new themes are created. See backlog: missing UNIQUE constraint on
//!   `claim_themes.label`.

#![allow(clippy::wildcard_imports)]

use rmcp::model::*;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;

use epigraph_engine::theme_kmeans::{run_theme_kmeans, RunThemeKmeansConfig, ThemeKmeansError};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ThemeClusterParams {
    /// Explicit k. When omitted, runs elbow-penalised search over `k_min..=k_max`.
    pub k: Option<u32>,
    /// Lower bound for k search (inclusive). Default 4.
    pub k_min: Option<u32>,
    /// Upper bound for k search (inclusive). Default 16.
    pub k_max: Option<u32>,
    /// Drop clusters with fewer than this many claims. Default 5.
    pub min_claims_per_theme: Option<u32>,
    /// Cap on number of `claims` rows pulled. Default 500; capped at 500
    /// regardless of input to defend against VM OOM at ~2000 embeddings.
    pub limit: Option<u32>,
    /// Theme label prefix. Default `"auto"` (produces `auto-00`, `auto-01`, …).
    pub label_prefix: Option<String>,
    /// Embedding dimensionality. Must be 1536 or 3072. Default 1536.
    pub centroid_dim: Option<u32>,
    /// Whether to wipe existing themes with this `label_prefix` before
    /// clustering. **Default `true`** — see module docstring. Pass `false`
    /// only for additive runs with a unique `label_prefix`; otherwise
    /// duplicate themes accumulate (no UNIQUE constraint on
    /// `claim_themes.label`).
    pub wipe_first: Option<bool>,
}

const MCP_LIMIT_CAP: u32 = 500;

pub async fn theme_cluster(
    server: &EpiGraphMcpFull,
    params: ThemeClusterParams,
) -> Result<CallToolResult, McpError> {
    let wipe_first = params.wipe_first.unwrap_or(true);

    let config = RunThemeKmeansConfig {
        k: params.k,
        k_min: params.k_min.unwrap_or(4),
        k_max: params.k_max.unwrap_or(16),
        min_claims_per_theme: params.min_claims_per_theme.unwrap_or(5),
        limit: params.limit.unwrap_or(500).clamp(1, MCP_LIMIT_CAP),
        label_prefix: params.label_prefix.unwrap_or_else(|| "auto".to_string()),
        wipe_first,
        centroid_dim: params.centroid_dim.unwrap_or(1536),
    };

    let summary = run_theme_kmeans(&server.pool, &config)
        .await
        .map_err(|e| match e {
            ThemeKmeansError::BadRequest(msg) => crate::errors::invalid_params(msg),
            ThemeKmeansError::Centroid3072Empty => crate::errors::invalid_params(e.to_string()),
            other => internal_error(other),
        })?;

    // Mirror the HTTP handler's JSON shape so EpiClaw and the route share a
    // single observable contract.
    let mut body = if let Some(k_used) = summary.k_used {
        serde_json::json!({
            "themes_created": summary.themes_created,
            "claims_assigned": summary.claims_assigned,
            "k_used": k_used,
            "claims_with_embeddings": summary.claims_with_embeddings,
            "centroid_dim": summary.centroid_dim,
        })
    } else {
        serde_json::json!({
            "themes_created": summary.themes_created,
            "claims_assigned": summary.claims_assigned,
            "k_used": serde_json::Value::Null,
            "claims_with_embeddings": summary.claims_with_embeddings,
            "centroid_dim": summary.centroid_dim,
            "skipped_reason": summary.skipped_reason.unwrap_or_default(),
        })
    };

    // Warn callers that opted out of `wipe_first`: with no DB-level UNIQUE
    // constraint on `claim_themes.label`, repeated calls with the same
    // `label_prefix` proliferate duplicate rows.
    if !wipe_first && summary.themes_created > 0 {
        body["warning"] = serde_json::json!(
            "wipe_first=false: created themes are additive. Repeated calls with the same label_prefix will produce duplicate rows. See claim_themes UNIQUE constraint backlog."
        );
    }

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&body).map_err(internal_error)?,
    )]))
}
