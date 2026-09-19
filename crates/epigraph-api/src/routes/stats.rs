//! `GET /api/v1/stats` (plan §2.4) — corpus counts for the Explorer's landing
//! page.
//!
//! `GET /api/v1/admin/stats` looks like the right route and is not: it reports
//! process diagnostics (uptime, pool state), never how much is in the graph.
//! The counts existed only behind MCP `system_stats`; both surfaces now read
//! `epigraph_db::StatsRepository`, so they cannot drift.

use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use epigraph_db::StatsRepository;
use serde::Serialize;

use crate::errors::ApiError;
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
pub async fn corpus_stats(State(state): State<AppState>) -> Result<Json<StatsResponse>, ApiError> {
    let pool = &state.db_pool;
    let counts = StatsRepository::corpus_counts(pool).await?;
    let detailed = StatsRepository::detailed_counts(pool).await?;

    Ok(Json(StatsResponse {
        claims: counts.claims,
        edges: counts.edges,
        evidence: counts.evidence,
        embeddings: detailed.embeddings,
        agents: counts.agents,
        frames: counts.frames,
        workflows: detailed.workflows,
        computed_at: Utc::now(),
    }))
}
