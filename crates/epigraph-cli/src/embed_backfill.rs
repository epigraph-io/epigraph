//! The `workflows.goal_embedding` leg of the `embed_backfill` CLI.
//!
//! Every hierarchical-workflow write path (`ingest_workflow`,
//! `improve_workflow_hierarchy`, `store_workflow`, and the HTTP ingest routes)
//! embeds the goal best-effort: an embedder failure logs a warning and leaves
//! the row's `goal_embedding` NULL, on the stated assumption that "embedding is
//! recoverable via backfill". This module is that backfill. Without it a NULL
//! row is permanently invisible to the three embedding searches over
//! `workflows`, which all filter `goal_embedding IS NOT NULL`.
//!
//! It embeds exactly `workflows.goal`, the text the write paths embed, so a
//! backfilled row lands where a write-path row would.

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_db::WorkflowRepository;
use epigraph_embeddings::EmbeddingService;

/// Outcome of one run of the workflows leg.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkflowBackfillSummary {
    /// Rows selected (NULL `goal_embedding`, non-blank goal), at most `limit`.
    pub candidates: usize,
    /// Rows whose `goal_embedding` this run wrote.
    pub written: usize,
    /// Rows that could not be embedded or written; they stay NULL.
    pub failed: usize,
}

/// Embed and store the goal of each `(id, goal)` row, as selected by
/// [`WorkflowRepository::find_needing_goal_embedding`].
///
/// The caller selects first so that it can report a dry run, or skip building
/// a provider when there is nothing to do, without this function. Per-row
/// failures (embedding error, write error, or a row deleted between the select
/// and the update) are counted in `failed` and logged to stderr; they never
/// abort the run, and the row stays NULL for the next one.
pub async fn backfill_workflow_goal_embeddings(
    pool: &PgPool,
    provider: &dyn EmbeddingService,
    rows: Vec<(Uuid, String)>,
) -> WorkflowBackfillSummary {
    let mut summary = WorkflowBackfillSummary {
        candidates: rows.len(),
        ..WorkflowBackfillSummary::default()
    };
    for (workflow_id, goal) in rows {
        match provider.generate(&goal).await {
            Ok(embedding) => {
                match WorkflowRepository::set_goal_embedding(pool, workflow_id, &embedding).await {
                    Ok(n) if n > 0 => summary.written += 1,
                    Ok(_) => {
                        summary.failed += 1;
                        eprintln!("workflow {workflow_id}: store affected 0 rows");
                    }
                    Err(e) => {
                        summary.failed += 1;
                        eprintln!("workflow {workflow_id}: store failed: {e}");
                    }
                }
            }
            Err(e) => {
                summary.failed += 1;
                eprintln!("workflow {workflow_id}: embedding failed: {e}");
            }
        }
    }
    summary
}
