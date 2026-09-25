//! `GET /api/v1/stats` (plan §2.4) — corpus counts for the Explorer's landing
//! page.
//!
//! `GET /api/v1/admin/stats` looks like the right route and is not: it reports
//! process diagnostics (uptime, pool state), never how much is in the graph.
//! The counts existed only behind MCP `system_stats`; both surfaces now read
//! `epigraph_db::StatsRepository`, so they cannot drift.

use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use epigraph_db::CorpusStatsRepository;
use serde::Serialize;

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub claims: i64,
    pub edges: i64,
    pub evidence: i64,
    pub embeddings: i64,
    pub agents: i64,
    pub frames: i64,
    /// Claims carrying the `workflow` label — the definition MCP
    /// `system_stats` reports, not a count of `workflows` rows.
    pub workflows: i64,
    /// When these counts were read. They are not a consistent snapshot: the
    /// two queries behind them are not in one transaction.
    pub computed_at: DateTime<Utc>,
}

/// `GET /api/v1/stats`
pub async fn corpus_stats(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
) -> Result<Json<StatsResponse>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "corpus_stats",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // Tenant-scoped, matching what MCP `system_stats` reports: the unscoped
    // `StatsRepository::corpus_counts` counted the WHOLE corpus regardless of
    // viewer, so this endpoint reported other tenants' totals to any caller. It
    // compiled either way — nothing here was a deleted symbol — so the drift was
    // silent. `detailed = true` populates the three Option fields below.
    //
    // The VIEWER ALONE IS NOT ENOUGH: the policy's group functions read session
    // state, so an unstamped connection evaluates them empty and this degrades to
    // public-only rows. The stamped connection and the viewer are both required.
    let counts = CorpusStatsRepository::tenant_counts(&mut read, &viewer, true).await?;
    let agents = CorpusStatsRepository::agent_count(&mut *read, &viewer).await?;

    Ok(Json(StatsResponse {
        claims: counts.claims,
        edges: counts.edges,
        evidence: counts.evidence,
        // Response KEYS are unchanged; only the source and the scoping move.
        embeddings: counts.embedded_claims.unwrap_or(0),
        agents,
        frames: counts.frames,
        workflows: counts.workflow_claims.unwrap_or(0),
        computed_at: Utc::now(),
    }))
}
