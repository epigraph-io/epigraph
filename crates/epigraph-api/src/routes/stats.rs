//! `GET /api/v1/stats` (plan §2.4) — corpus counts for the Explorer's landing
//! page.
//!
//! `GET /api/v1/admin/stats` looks like the right route and is not: it reports
//! process diagnostics (uptime, pool state) behind `claims:admin`, never how
//! much is in the graph. The corpus counts existed only behind MCP
//! `system_stats`; both surfaces now read
//! [`epigraph_db::CorpusStatsRepository`], so they cannot drift.
//!
//! # These numbers are per-viewer
//!
//! `tenant_counts` answers "rows you can read", not "rows that exist", so two
//! signed-in users legitimately see different totals and the Explorer's copy
//! has to say so. The alternative — an instance-wide count, exempted the way
//! `agent_count` is — would restore exactly the membership oracle the tenancy
//! series deleted: a non-member would learn the size of every group's corpus.
//!
//! Gated with `ViewerExtractor` rather than `RequireScopeAdmin`, matching the
//! MCP tool that reports the same aggregate. `claims:admin` is in
//! `ADMIN_ONLY_SCOPES` and excluded from `read_only_scopes()`, so an admin gate
//! here would mean the Explorer needs an admin token to render its landing
//! page.

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
    /// queries behind them are not in one transaction under
    /// `SessionGucMode::Session`.
    pub computed_at: DateTime<Utc>,
}

/// `GET /api/v1/stats`
pub async fn corpus_stats(
    ViewerExtractor(viewer): ViewerExtractor,
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

    // `detailed` is not a query parameter: `embeddings` and `workflows` are
    // part of this route's response shape rather than an opt-in, so asking for
    // the cheap variant would only produce a body with two fields missing.
    let counts = CorpusStatsRepository::tenant_counts_conn(&mut read, &viewer, true).await?;
    let agents = CorpusStatsRepository::agent_count(&mut *read, &viewer).await?;

    crate::routes::finish_scoped_read(read, "corpus_stats").await?;

    Ok(Json(StatsResponse {
        claims: counts.claims,
        edges: counts.edges,
        evidence: counts.evidence,
        // `detailed` was true, so both are `Some`; `unwrap_or_default` is the
        // shape-preserving reading of a contract change rather than a panic.
        embeddings: counts.embedded_claims.unwrap_or_default(),
        agents,
        frames: counts.frames,
        workflows: counts.workflow_claims.unwrap_or_default(),
        computed_at: Utc::now(),
    }))
}
