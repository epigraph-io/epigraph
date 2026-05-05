//! Workflow ingest executor — applies an [`epigraph_ingest::workflow::IngestPlan`]
//! to the database.
//!
//! Stub: implementation is ported from the duplicated MCP/API call sites in
//! the next commit (see `feat: port workflow ingest execution` in this PR's
//! history).

use uuid::Uuid;

use crate::error::IngestExecutorError;

/// Summary of what the executor wrote (or skipped) for a single plan.
#[derive(Debug, Clone)]
pub struct WorkflowIngestExecutionResult {
    pub workflow_id: Uuid,
    pub canonical_name: String,
    pub generation: i32,
    pub claims_ingested: usize,
    pub claims_skipped_dedup: usize,
    pub executes_edges_created: usize,
    /// Reserved for Phase 4.3 — set by the upcoming `variant_of` edge work
    /// (issue #51). Always `false` in this phase.
    pub variant_of_edge_created: bool,
    pub relationship_edges_created: usize,
    /// `true` when the idempotency gate short-circuited (workflow already
    /// has `executes` edges); the other counters are zero in that case.
    pub already_ingested: bool,
}

/// Execute a workflow ingest plan against the database.
///
/// Idempotent. If the canonical workflow already has `executes` edges, this
/// returns early with `already_ingested: true` and no DB writes. Otherwise
/// inserts the workflow row, ensures author and system agents, persists each
/// planned claim with dedup, writes `workflow —executes→ claim` edges, and
/// emits the intra-claim plan edges.
pub async fn execute_workflow_ingest_plan(
    _pool: &sqlx::PgPool,
    _plan: &epigraph_ingest::common::plan::IngestPlan,
    _extraction: &epigraph_ingest::workflow::WorkflowExtraction,
) -> Result<WorkflowIngestExecutionResult, IngestExecutorError> {
    todo!("ported in next commit (Phase 4.2.C)")
}
