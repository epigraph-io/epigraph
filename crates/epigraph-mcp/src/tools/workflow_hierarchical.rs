//! Hierarchical workflow query and outcome tools.
//!
//! Companions to `workflow_ingest::do_ingest_workflow`. These operate on the
//! `workflows` table (hierarchical roots) — distinct from the legacy flat
//! workflow claims handled in `workflows.rs`.
//!
//! - `find_workflow_hierarchical` — ILIKE search over goal and a
//!   hyphen-normalized canonical_name; filters by `min_truth` so deprecated
//!   rows (truth=0.05) drop out by default.
//! - `report_hierarchical_outcome` — updates `workflows.metadata` counters
//!   and writes per-step `behavioral_executions` rows with `step_claim_id`
//!   resolved from the workflow's `executes` edges in plan order.
//!
//! Mirrors the API routes
//! `GET /api/v1/workflows/hierarchical/search` and
//! `POST /api/v1/workflows/hierarchical/:id/outcome`.

use rmcp::model::*;
use uuid::Uuid;

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{
    FindWorkflowHierarchicalParams, HierarchicalStepExecution, ReportHierarchicalOutcomeParams,
};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

fn invalid_uuid(field: &'static str) -> McpError {
    McpError {
        code: rmcp::model::ErrorCode::INVALID_PARAMS,
        message: std::borrow::Cow::Owned(format!("invalid UUID for `{field}`")),
        data: None,
    }
}

fn not_found(workflow_id: Uuid) -> McpError {
    McpError {
        code: rmcp::model::ErrorCode::INVALID_PARAMS,
        message: std::borrow::Cow::Owned(format!(
            "no hierarchical workflow with id {workflow_id} (use ingest_workflow first, or check whether this is a flat workflow)"
        )),
        data: None,
    }
}

// ── find_workflow_hierarchical ─────────────────────────────────────────────

pub async fn find_workflow_hierarchical(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: FindWorkflowHierarchicalParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);
    let resolve_to_latest = params.resolve_to_latest.unwrap_or(false);
    // Default 0.3 hides deprecated rows (truth=0.05) while leaving room
    // for future probabilistic discounting; callers can pass 0.0 to see
    // the deprecated cemetery.
    let min_truth = params.min_truth.unwrap_or(0.3);
    // Cosine-similarity floor for embedding hits. 0.5 mirrors the
    // behavioral_affinity_lineage default used by flat find_workflow.
    let similarity_threshold = 0.5_f64;

    // Try embedding-first to tolerate paraphrasing, punctuation drift, and
    // word-order differences. Falls through to ILIKE substring match (the
    // legacy search_hierarchical_by_text path) when the embedder is
    // unavailable, the API call fails, or zero workflows have an embedding
    // similar enough to clear the threshold.
    let mut search_path = "ilike";
    let qvec = if server.embedder.is_mock() {
        None
    } else {
        match server.embedder.generate(&params.query).await {
            Ok(qvec) => Some(qvec),
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    "embedder.generate failed; falling back to ILIKE"
                );
                None
            }
        }
    };

    // Both searches read `workflows` rows, which carry their plan's tenancy
    // (ruling R-74, migration 183): run them as the CALLER, on one
    // viewer-stamped read taken after the embedding round trip, so a member
    // finds its group's workflows and nobody else does. A server with no
    // tenancy-aware pool (a development superuser) reads its plain pool.
    let mut read = match server.scoped.as_ref() {
        Some(scoped) => Some(scoped.read_as(viewer).await.map_err(internal_error)?),
        None => None,
    };
    let mut rows = match qvec {
        Some(qvec) => {
            let found = match read.as_mut() {
                Some(read) => {
                    epigraph_db::WorkflowRepository::find_hierarchical_by_embedding(
                        &mut **read,
                        &qvec,
                        similarity_threshold,
                        min_truth,
                        limit,
                        resolve_to_latest,
                    )
                    .await
                }
                None => {
                    epigraph_db::WorkflowRepository::find_hierarchical_by_embedding(
                        &server.pool,
                        &qvec,
                        similarity_threshold,
                        min_truth,
                        limit,
                        resolve_to_latest,
                    )
                    .await
                }
            };
            match found {
                Ok(rs) if !rs.is_empty() => {
                    search_path = "embedding";
                    rs
                }
                Ok(_) => Vec::new(), // embedding ran but no rows cleared threshold
                Err(e) => {
                    tracing::warn!(
                        error = ?e,
                        "find_hierarchical_by_embedding failed; falling back to ILIKE"
                    );
                    Vec::new()
                }
            }
        }
        None => Vec::new(),
    };

    if rows.is_empty() {
        rows = match read.as_mut() {
            Some(read) => {
                epigraph_db::WorkflowRepository::search_hierarchical_by_text(
                    &mut **read,
                    &params.query,
                    limit,
                    min_truth,
                    resolve_to_latest,
                )
                .await
            }
            None => {
                epigraph_db::WorkflowRepository::search_hierarchical_by_text(
                    &server.pool,
                    &params.query,
                    limit,
                    min_truth,
                    resolve_to_latest,
                )
                .await
            }
        }
        .map_err(internal_error)?;
    }
    if let Some(read) = read {
        read.commit().await.map_err(internal_error)?;
    }

    // With `resolve_to_latest` both searches add the head of every matched
    // canonical_name (the row `improve_workflow_hierarchy` builds on), so the
    // highest generation per group in `rows` IS the lineage head.
    let heads = resolve_to_latest.then(|| epigraph_db::repos::workflow::lineage_heads_in(&rows));

    let mut workflows: Vec<serde_json::Value> = Vec::with_capacity(rows.len());
    for r in rows {
        let lineage = heads
            .as_ref()
            .and_then(|h| h.get(&r.canonical_name))
            .copied();
        let mut entry = serde_json::json!({
            "workflow_id": r.id,
            "canonical_name": r.canonical_name,
            "generation": r.generation,
            "goal": r.goal,
            "parent_id": r.parent_id,
            "metadata": r.metadata,
            "created_at": r.created_at,
            "truth_value": r.truth_value,
        });

        if let Some((head_id, head_generation, head_truth)) = lineage {
            entry["is_lineage_head"] = serde_json::json!(head_id == r.id);
            entry["lineage_head_generation"] = serde_json::json!(head_generation);
            // A deprecated head is still the head; it is disclosed, not hidden.
            entry["lineage_head_deprecated"] = serde_json::json!(head_truth < min_truth);
        }

        if resolve_to_latest {
            let resolved =
                epigraph_db::WorkflowRepository::resolve_steps_to_heads(&server.pool, viewer, r.id)
                    .await
                    .map_err(internal_error)?;
            entry["resolved_steps"] = serde_json::to_value(resolved).map_err(internal_error)?;
        }

        workflows.push(entry);
    }

    success_json(&serde_json::json!({
        "workflows": workflows,
        "total": workflows.len(),
        "resolve_to_latest": resolve_to_latest,
        "min_truth": min_truth,
        "search_path": search_path,
    }))
}

// ── report_hierarchical_outcome ────────────────────────────────────────────

pub async fn report_hierarchical_outcome(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ReportHierarchicalOutcomeParams,
) -> Result<CallToolResult, McpError> {
    let workflow_id =
        Uuid::parse_str(&params.workflow_id).map_err(|_| invalid_uuid("workflow_id"))?;

    do_report_hierarchical_outcome_with_embedder(
        server.scoped.as_ref(),
        viewer,
        server.embedder.as_ref(),
        workflow_id,
        params.success,
        &params.step_executions,
        params.quality,
        params.goal_text.as_deref(),
        params.run_label.as_deref(),
    )
    .await
}

/// The `goal_text` the step rows fall back to when a report names no goal.
const GOAL_PLACEHOLDER: &str = "hierarchical";

/// The goal text a hierarchical outcome report should embed, if any: the
/// trimmed `goal_text`, unless it is blank or the `"hierarchical"`
/// placeholder. Embedding a placeholder would make every goal-less report
/// "similar" to every other one in `behavioral_affinity_hierarchical`.
fn report_goal_to_embed(goal_text: Option<&str>) -> Option<&str> {
    goal_text
        .map(str::trim)
        .filter(|g| !g.is_empty() && *g != GOAL_PLACEHOLDER)
}

/// Embed the report's goal, best-effort, BEFORE the transaction (embedder
/// latency stays out of the `workflows` row lock), then report. An embedder
/// failure is a NULL `goal_embedding`, never a failed report: the same
/// contract as the flat `report_workflow_outcome` path's "Embed the goal text
/// for affinity matching". Shared by `report_hierarchical_outcome` and the
/// hierarchical branch of `report_workflow_outcome`.
#[allow(clippy::too_many_arguments)]
pub async fn do_report_hierarchical_outcome_with_embedder(
    scoped: Option<&epigraph_db::ScopedPool>,
    viewer: &epigraph_db::visibility::Viewer,
    embedder: &dyn epigraph_embeddings::EmbeddingService,
    workflow_id: Uuid,
    success: bool,
    step_executions: &[HierarchicalStepExecution],
    quality: Option<f64>,
    goal_text: Option<&str>,
    run_label: Option<&str>,
) -> Result<CallToolResult, McpError> {
    // Refuse a bad report before paying for an embedding.
    validate_quality(quality)?;
    let goal_embedding = match report_goal_to_embed(goal_text) {
        Some(goal) => match embedder.generate(goal).await {
            Ok(vec) => Some(vec),
            Err(e) => {
                tracing::warn!(workflow_id = %workflow_id, "hierarchical goal embedding failed: {e}");
                None
            }
        },
        None => None,
    };
    do_report_hierarchical_outcome_as(
        scoped,
        viewer,
        workflow_id,
        success,
        step_executions,
        quality,
        goal_text,
        run_label,
        goal_embedding.as_deref(),
    )
    .await
}

/// Refuse a `quality` the `behavioral_executions` CHECK (migration 002:
/// `quality IS NULL OR quality BETWEEN 0 AND 1`) would refuse anyway, before
/// anything is written. NaN is refused too: it fails every comparison, so
/// the CHECK would refuse it as well.
fn validate_quality(quality: Option<f64>) -> Result<(), McpError> {
    match quality {
        Some(q) if !(q.is_finite() && (0.0..=1.0).contains(&q)) => Err(McpError {
            code: rmcp::model::ErrorCode::INVALID_PARAMS,
            message: std::borrow::Cow::Owned(format!(
                "`quality` must be a finite number in [0, 1]; got {q}"
            )),
            data: None,
        }),
        _ => Ok(()),
    }
}

/// The disclosure a report carries when some of its rows could not be
/// attributed to a step: which `step_index` values were recorded with a NULL
/// `step_claim_id`, and a warning saying why. `None` when every row resolved.
///
/// The warning names BOTH causes and never says which applied, and never how
/// many steps the plan has: telling "out of range" apart from "not visible to
/// you" would disclose that a step the caller cannot read exists. Shared with
/// the HTTP route (`epigraph-api` `routes/workflows.rs`) so both transports
/// say the same thing.
#[must_use]
pub fn unresolved_steps_warning(unresolved: &[usize]) -> Option<String> {
    if unresolved.is_empty() {
        return None;
    }
    Some(format!(
        "{} step row(s) were recorded with a null step_claim_id: step_index {:?} did not match \
         a step of this workflow that you can read (the index is out of range, or the step is \
         not visible to you). The run and its counters were recorded.",
        unresolved.len(),
        unresolved
    ))
}

/// Outcome reporting for hierarchical workflows, on ONE transaction stamped
/// with the REPORTER's viewer. Updates `workflows.metadata` rolling counters and
/// writes per-step `behavioral_executions` rows with `step_claim_id` resolved
/// from the workflow's `executes` edges (level=2 claims, in plan order) that
/// the reporter can read.
///
/// ALL OR NOTHING (U033 / I229). The counter read, the counter write, the
/// step lookup and every step row run on ONE transaction, and the counter
/// read takes `FOR UPDATE` on the `workflows` row, so two concurrent reports
/// serialize instead of both writing `use_count = n + 1`. A step row the
/// database refuses fails the whole report and rolls the counters back; it
/// used to be logged and skipped while the tool answered success.
///
/// # Why the transaction is stamped
///
/// `behavioral_executions` has no row security; the counter write on
/// `workflows` (row security since migration 183) reaches only a row the
/// stamp reads. The step LOOKUP reads `claims` and `edges`,
/// and on an UNSTAMPED application session row security admits only public
/// rows. This used to run on a plain `pool.begin()`, so for a workflow whose
/// steps are group-private EVERY reporter, the group's own members included,
/// had each row written with a NULL `step_claim_id`, silently. Stamped, a
/// member resolves its group's steps, and a step_index it cannot resolve is
/// recorded with a NULL id and disclosed ([`unresolved_steps_warning`], plus a
/// WARN log line per report).
///
/// # A reporter that reads none of the plan is refused
///
/// A reporter that does not read the PLAN gets the same [`not_found`] error as
/// an unknown id, and nothing is written: its `workflows` row (which carries
/// the plan's tenancy and row security since migration 183, ruling R-74) and
/// at least one STEP `executes` edge (a visible thesis, phase or shared
/// level-3 atom does not count, so a step-less plan is refused to every
/// reporter: `WorkflowRepository::viewer_reads_plan_structure`, on the stamped
/// transaction). It used to record the run with every step NULL,
/// so any `claims:write` holder could move the counters of a workflow it
/// cannot read.
///
/// Refuses, rather than falling back to an unstamped transaction, when this
/// process has no [`epigraph_db::ScopedPool`]: a fallback would be the
/// silently-NULL path again.
///
/// `goal_embedding` is computed by the caller BEFORE this runs (embedder
/// latency stays out of the row lock) and is written on every step row, so
/// the report feeds `behavioral_affinity_hierarchical`.
#[allow(clippy::too_many_arguments)]
pub async fn do_report_hierarchical_outcome_as(
    scoped: Option<&epigraph_db::ScopedPool>,
    viewer: &epigraph_db::visibility::Viewer,
    workflow_id: Uuid,
    success: bool,
    step_executions: &[HierarchicalStepExecution],
    quality: Option<f64>,
    goal_text: Option<&str>,
    run_label: Option<&str>,
    goal_embedding: Option<&[f32]>,
) -> Result<CallToolResult, McpError> {
    // 0. Validate before touching the database.
    validate_quality(quality)?;

    let scoped = scoped.ok_or_else(|| {
        tracing::error!(
            target: "tenancy.scoped_write",
            tool = "report_hierarchical_outcome",
            "report refused: this process was not built from a ScopedPool"
        );
        crate::errors::internal_error_text(
            "report_hierarchical_outcome: this process was not built from a ScopedPool, so the \
             step lookup cannot be stamped with the caller's viewer. Nothing was written.",
        )
    })?;
    let mut tx = scoped
        .begin_as(viewer)
        .await
        .map_err(crate::errors::db_caller_error)?;

    // 1. Confirm hierarchical workflow exists, and lock its row for the
    //    read-modify-write of the counters below.
    //
    // VISIBILITY-EXEMPT: this statement and the counter `UPDATE` touch only
    // `workflows` by primary key, on this transaction stamped with the viewer:
    // since migration 183 that row carries its plan's tenancy under FORCEd
    // row security, so a row the viewer does not read is absent here and
    // reported as an unknown id. The viewer is ALSO spent in the plan reads
    // below (`viewer_reads_plan_structure`, which requires the row through
    // `{VISIBILITY:w}` and a readable step, and `plan_step_claim_ids`), which
    // splice the row, edge and claim predicates.
    let row: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT metadata FROM workflows WHERE id = $1 FOR UPDATE")
            .bind(workflow_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal_error)?;
    let mut metadata = match row {
        Some((m,)) => m,
        None => return Err(not_found(workflow_id)),
    };
    // A reporter that reads none of the plan's STEP `executes` edges is
    // refused exactly like a missing id, before any write.
    if !epigraph_db::WorkflowRepository::viewer_reads_plan_structure(&mut tx, viewer, workflow_id)
        .await
        .map_err(internal_error)?
    {
        return Err(not_found(workflow_id));
    }

    // 2. Compute deltas.
    let variance = if step_executions.is_empty() {
        0.0
    } else {
        let dev = step_executions.iter().filter(|s| s.deviated).count();
        dev as f64 / step_executions.len() as f64
    };
    let quality = quality.unwrap_or(if success { 1.0 } else { 0.0 });

    // 3. Update rolling counters in metadata.
    let use_count = metadata
        .get("use_count")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
        + 1;
    let success_count = metadata
        .get("success_count")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
        + i64::from(success);
    let failure_count = metadata
        .get("failure_count")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
        + i64::from(!success);
    let prev_avg_var = metadata
        .get("avg_variance")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0);
    let avg_variance = if use_count > 0 {
        (prev_avg_var * (use_count - 1) as f64 + variance) / use_count as f64
    } else {
        variance
    };
    metadata["use_count"] = serde_json::json!(use_count);
    metadata["success_count"] = serde_json::json!(success_count);
    metadata["failure_count"] = serde_json::json!(failure_count);
    metadata["avg_variance"] = serde_json::json!(avg_variance);

    sqlx::query("UPDATE workflows SET metadata = $1 WHERE id = $2")
        .bind(&metadata)
        .bind(workflow_id)
        .execute(&mut *tx)
        .await
        .map_err(internal_error)?;

    // 4. Resolve step_index → step_claim_id via this workflow's `executes`
    //    edges, restricted to level=2 (steps), in PLAN order, through the
    //    reporter's viewer on this stamped transaction. The order key (the
    //    `plan_index` ordinal, `created_at` only as the fallback) lives in
    //    `WorkflowRepository::plan_step_claim_ids`, which the HTTP route
    //    shares, so "step N" means one step on both transports.
    let step_claim_ids =
        epigraph_db::WorkflowRepository::plan_step_claim_ids(&mut tx, viewer, workflow_id)
            .await
            .map_err(internal_error)?;

    // 5. Per-step behavioral_executions rows. Single timestamp groups them.
    //    A refused row fails the report: `?` drops `tx`, which rolls back the
    //    counter UPDATE and every earlier step row.
    let report_ts = chrono::Utc::now();
    let goal_text_owned = goal_text.unwrap_or(GOAL_PLACEHOLDER).to_string();
    let goal_embedding_pgvec = goal_embedding.map(crate::embed::format_pgvector);
    let mut unresolved: Vec<usize> = Vec::new();
    for step_exec in step_executions {
        let step_claim_id = step_claim_ids.get(step_exec.step_index).copied();
        if step_claim_id.is_none() {
            unresolved.push(step_exec.step_index);
        }
        let step_beliefs = serde_json::json!({
            "deviated": step_exec.deviated,
            "deviation_reason": step_exec.deviation_reason,
        });
        let row = epigraph_db::BehavioralExecutionRow {
            id: Uuid::new_v4(),
            workflow_id,
            goal_text: goal_text_owned.clone(),
            success,
            step_beliefs,
            tool_pattern: vec![step_exec.planned.clone()],
            quality: Some(quality),
            deviation_count: i32::from(step_exec.deviated),
            total_steps: 1,
            created_at: report_ts,
            step_claim_id,
            run_label: run_label.map(str::to_string),
        };
        epigraph_db::BehavioralExecutionRepository::create(
            &mut *tx,
            row,
            goal_embedding_pgvec.as_deref(),
        )
        .await
        .map_err(internal_error)?;
    }

    tx.commit().await.map_err(internal_error)?;

    let warning = unresolved_steps_warning(&unresolved);
    if warning.is_some() {
        // Every unattributed row is logged, the all-invisible case included:
        // the old guard (`!step_claim_ids.is_empty()`) is what kept that case
        // silent. The count of visible steps is deliberately not logged
        // alongside the principal, for the same reason the warning omits it.
        tracing::warn!(
            workflow_id = %workflow_id,
            principal = ?viewer.principal(),
            unresolved_step_indices = ?unresolved,
            "outcome report: behavioral_executions rows recorded with a NULL step_claim_id \
             (step_index out of range, or the step is not visible to the reporter)"
        );
    }

    let mut response = serde_json::json!({
        "workflow_id": workflow_id,
        "use_count": use_count,
        "success_count": success_count,
        "failure_count": failure_count,
        "avg_variance": avg_variance,
        "variance": variance,
        // All or nothing: every requested step row was written, or the call
        // returned an error and none was.
        "step_executions_written": step_executions.len(),
        // The rows written with a NULL step_claim_id, in request order.
        "unresolved_step_indices": unresolved,
    });
    if let Some(w) = warning {
        response["warning"] = serde_json::Value::String(w);
    }
    success_json(&response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::workflow_ingest::do_ingest_workflow_via_pool;
    use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
    use epigraph_ingest::workflow::WorkflowExtraction;

    /// A [`epigraph_db::ScopedPool`] over the `#[sqlx::test]` database, built
    /// from the pool's own connect options (no query: see
    /// `crate::maintenance`'s `scoped_pool_over` for why a `sqlx::query*` here
    /// would trip `tests/no_inline_sql_in_tools.rs`).
    async fn scoped_over(pool: &sqlx::PgPool) -> epigraph_db::ScopedPool {
        let db = pool
            .connect_options()
            .get_database()
            .expect("the #[sqlx::test] pool names its ephemeral database")
            .to_string();
        let base = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let (authority, query) = match base.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (base.as_str(), None),
        };
        let prefix = authority
            .trim_end_matches('/')
            .rsplit_once('/')
            .expect("DATABASE_URL must carry a database path")
            .0;
        let url = match query {
            Some(q) => format!("{prefix}/{db}?{q}"),
            None => format!("{prefix}/{db}"),
        };
        epigraph_db::ScopedPool::connect(&url, epigraph_db::SessionGucMode::Session)
            .await
            .expect("ScopedPool::connect over the ephemeral test database")
    }

    /// The viewer these unit tests report as: a principal with no groups. The
    /// test pool is the superuser, so row security filters nothing here and
    /// these tests pin the counters / atomicity / ordering contract only. What
    /// a stamped reporter can and cannot resolve is pinned on the application
    /// role in `tests/hierarchical_outcome_stamped_reads.rs`.
    async fn test_viewer(pool: &sqlx::PgPool) -> epigraph_db::visibility::Viewer {
        epigraph_db::visibility::Viewer::resolve(pool, Uuid::nil())
            .await
            .expect("resolve viewer")
    }

    #[allow(clippy::too_many_arguments)]
    async fn report_on_test_scope(
        pool: &sqlx::PgPool,
        workflow_id: Uuid,
        success: bool,
        step_executions: &[HierarchicalStepExecution],
        quality: Option<f64>,
        goal_text: Option<&str>,
        run_label: Option<&str>,
        goal_embedding: Option<&[f32]>,
    ) -> Result<CallToolResult, McpError> {
        let scoped = scoped_over(pool).await;
        do_report_hierarchical_outcome_as(
            Some(&scoped),
            &test_viewer(pool).await,
            workflow_id,
            success,
            step_executions,
            quality,
            goal_text,
            run_label,
            goal_embedding,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn report_with_embedder_on_test_scope(
        pool: &sqlx::PgPool,
        embedder: &dyn epigraph_embeddings::EmbeddingService,
        workflow_id: Uuid,
        success: bool,
        step_executions: &[HierarchicalStepExecution],
        quality: Option<f64>,
        goal_text: Option<&str>,
        run_label: Option<&str>,
    ) -> Result<CallToolResult, McpError> {
        let scoped = scoped_over(pool).await;
        do_report_hierarchical_outcome_with_embedder(
            Some(&scoped),
            &test_viewer(pool).await,
            embedder,
            workflow_id,
            success,
            step_executions,
            quality,
            goal_text,
            run_label,
        )
        .await
    }

    fn extraction(canonical_name: &str) -> WorkflowExtraction {
        WorkflowExtraction {
            source: WorkflowSource {
                canonical_name: canonical_name.to_string(),
                goal: "Validate hierarchical outcome reporting".to_string(),
                generation: 0,
                parent_canonical_name: None,
                authors: vec![],
                expected_outcome: None,
                tags: vec![],
                metadata: serde_json::json!({}),
            },
            thesis: Some("This workflow validates outcome reporting".to_string()),
            thesis_derivation: epigraph_ingest::common::schema::ThesisDerivation::TopDown,
            phases: vec![Phase {
                title: "Phase 1".to_string(),
                summary: "Single phase".to_string(),
                steps: vec![
                    Step {
                        compound: "Step A".to_string(),
                        rationale: String::new(),
                        operations: vec!["op a1".to_string()],
                        generality: vec![1],
                        confidence: 0.9,
                        evidence_type: None,
                    },
                    Step {
                        compound: "Step B".to_string(),
                        rationale: String::new(),
                        operations: vec!["op b1".to_string()],
                        generality: vec![1],
                        confidence: 0.9,
                        evidence_type: None,
                    },
                ],
            }],
            relationships: vec![],
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn report_outcome_updates_counters_and_writes_step_rows(pool: sqlx::PgPool) {
        let ext = extraction("test-outcome-counters");
        let ingest = do_ingest_workflow_via_pool(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            &ext,
        )
        .await
        .unwrap();
        let workflow_id = Uuid::parse_str(&ingest.workflow_id).unwrap();

        let steps = vec![
            HierarchicalStepExecution {
                step_index: 0,
                planned: "Step A".to_string(),
                actual: "Step A — done".to_string(),
                deviated: false,
                deviation_reason: None,
            },
            HierarchicalStepExecution {
                step_index: 1,
                planned: "Step B".to_string(),
                actual: "Step B — pivoted".to_string(),
                deviated: true,
                deviation_reason: Some("blocked".to_string()),
            },
        ];

        report_on_test_scope(
            &pool,
            workflow_id,
            true,
            &steps,
            None,
            Some("smoke run"),
            None,
            None,
        )
        .await
        .expect("outcome must succeed");

        let (metadata,): (serde_json::Value,) =
            sqlx::query_as("SELECT metadata FROM workflows WHERE id = $1")
                .bind(workflow_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(metadata["use_count"].as_i64(), Some(1));
        assert_eq!(metadata["success_count"].as_i64(), Some(1));
        assert_eq!(metadata["failure_count"].as_i64(), Some(0));

        let exec_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM behavioral_executions WHERE workflow_id = $1")
                .bind(workflow_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(exec_count, 2, "one row per step_execution");

        let with_step_claim: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM behavioral_executions \
             WHERE workflow_id = $1 AND step_claim_id IS NOT NULL",
        )
        .bind(workflow_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            with_step_claim, 2,
            "every step_execution must resolve to a step claim node"
        );
    }

    fn two_steps() -> Vec<HierarchicalStepExecution> {
        vec![
            HierarchicalStepExecution {
                step_index: 0,
                planned: "Step A".to_string(),
                actual: "Step A done".to_string(),
                deviated: false,
                deviation_reason: None,
            },
            HierarchicalStepExecution {
                step_index: 1,
                planned: "Step B".to_string(),
                actual: "Step B done".to_string(),
                deviated: false,
                deviation_reason: None,
            },
        ]
    }

    async fn ingest_fixture(pool: &sqlx::PgPool, canonical_name: &str) -> Uuid {
        let viewer = epigraph_db::visibility::Viewer::resolve(pool, uuid::Uuid::nil())
            .await
            .expect("resolve viewer");
        let ingest = do_ingest_workflow_via_pool(pool, &viewer, &extraction(canonical_name))
            .await
            .unwrap();
        Uuid::parse_str(&ingest.workflow_id).unwrap()
    }

    async fn counters_and_rows(pool: &sqlx::PgPool, workflow_id: Uuid) -> (serde_json::Value, i64) {
        let (metadata,): (serde_json::Value,) =
            sqlx::query_as("SELECT metadata FROM workflows WHERE id = $1")
                .bind(workflow_id)
                .fetch_one(pool)
                .await
                .unwrap();
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM behavioral_executions WHERE workflow_id = $1")
                .bind(workflow_id)
                .fetch_one(pool)
                .await
                .unwrap();
        (metadata, rows)
    }

    /// U033 / I229: a step row the database refuses must fail the whole
    /// report. Real DB failure injection (a BEFORE INSERT trigger that
    /// refuses only the second step), not a mock. On the pre-fix code the
    /// counters were written first in their own autocommit, step A landed,
    /// step B was skipped with a warn, and the tool reported success.
    #[sqlx::test(migrations = "../../migrations")]
    async fn report_outcome_is_all_or_nothing_when_a_step_row_fails(pool: sqlx::PgPool) {
        let workflow_id = ingest_fixture(&pool, "test-outcome-atomic").await;
        // A sequence is not transactional, so the trigger's `nextval` survives
        // the rollback its own RAISE causes: it is what ties the failure to the
        // injected refusal now that the driver text no longer reaches the
        // caller (backlog 49863d2c).
        sqlx::query("CREATE SEQUENCE u033_refusals")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE FUNCTION u033_fail() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF NEW.tool_pattern[1] = 'Step B' THEN \
               PERFORM nextval('u033_refusals'); RAISE EXCEPTION 'u033 injected'; END IF; \
             RETURN NEW; END $$",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER u033_fail BEFORE INSERT ON behavioral_executions \
             FOR EACH ROW EXECUTE FUNCTION u033_fail()",
        )
        .execute(&pool)
        .await
        .unwrap();

        let res = report_on_test_scope(
            &pool,
            workflow_id,
            true,
            &two_steps(),
            None,
            Some("atomicity run"),
            None,
            None,
        )
        .await;
        let err = res.expect_err("a refused step row must fail the report");
        // Tie the failure to the injected refusal of step B, so an unrelated
        // early error (begin, lookup) cannot satisfy this test.
        assert_eq!(err.code, ErrorCode::INTERNAL_ERROR, "{err:?}");
        let (refusals, fired): (i64, bool) =
            sqlx::query_as("SELECT last_value, is_called FROM u033_refusals")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            fired && refusals == 1,
            "the failure must be the injected refusal of step B: {err:?}"
        );
        assert!(
            !err.message.contains("u033 injected"),
            "the database's error text must not reach the caller: {err:?}"
        );

        let (metadata, rows) = counters_and_rows(&pool, workflow_id).await;
        assert!(
            metadata.get("use_count").is_none(),
            "counters must not move when a step row fails: {metadata}"
        );
        assert_eq!(rows, 0, "step A must roll back with step B");
    }

    /// U033 / I229: `quality` is client-supplied and
    /// `behavioral_executions.quality` carries CHECK (0..=1). An out-of-range
    /// value must be refused as INVALID_PARAMS before anything is written. On
    /// the pre-fix code the counters moved, the CHECK silently refused every
    /// step row, and the tool reported success.
    #[sqlx::test(migrations = "../../migrations")]
    async fn report_outcome_rejects_out_of_range_quality_without_side_effects(pool: sqlx::PgPool) {
        let workflow_id = ingest_fixture(&pool, "test-outcome-quality").await;
        for bad in [1.5_f64, -0.1, f64::NAN] {
            let err = report_on_test_scope(
                &pool,
                workflow_id,
                true,
                &two_steps(),
                Some(bad),
                Some("quality run"),
                None,
                None,
            )
            .await
            .expect_err("out-of-range quality must be refused");
            assert_eq!(
                err.code,
                ErrorCode::INVALID_PARAMS,
                "quality {bad}: {err:?}"
            );
        }
        let (metadata, rows) = counters_and_rows(&pool, workflow_id).await;
        assert!(
            metadata.get("use_count").is_none(),
            "a refused report must not move counters: {metadata}"
        );
        assert_eq!(rows, 0, "a refused report must write no step rows");

        // Positive control: the boundary value 1.0 is accepted and lands.
        report_on_test_scope(
            &pool,
            workflow_id,
            true,
            &two_steps(),
            Some(1.0),
            Some("quality run"),
            None,
            None,
        )
        .await
        .expect("quality 1.0 is in range");
        let (metadata, rows) = counters_and_rows(&pool, workflow_id).await;
        assert_eq!(metadata["use_count"].as_i64(), Some(1));
        assert_eq!(rows, 2);
    }

    /// U033 / I229 regression guard (not a red test: an unlocked
    /// read-modify-write can pass by luck). Concurrent reports must not lose
    /// increments; `FOR UPDATE` on the `workflows` row serializes them.
    #[sqlx::test(migrations = "../../migrations")]
    async fn concurrent_reports_do_not_lose_increments(pool: sqlx::PgPool) {
        let workflow_id = ingest_fixture(&pool, "test-outcome-concurrent").await;
        let mut handles = Vec::new();
        for i in 0..8 {
            let pool = pool.clone();
            handles.push(tokio::spawn(async move {
                report_on_test_scope(
                    &pool,
                    workflow_id,
                    i % 2 == 0,
                    &two_steps(),
                    None,
                    Some("concurrency run"),
                    None,
                    None,
                )
                .await
                .map(|_| ())
                .map_err(|e| e.message.to_string())
            }));
        }
        for h in handles {
            h.await.expect("join").expect("report must succeed");
        }
        let (metadata, rows) = counters_and_rows(&pool, workflow_id).await;
        assert_eq!(metadata["use_count"].as_i64(), Some(8), "{metadata}");
        assert_eq!(metadata["success_count"].as_i64(), Some(4), "{metadata}");
        assert_eq!(metadata["failure_count"].as_i64(), Some(4), "{metadata}");
        assert_eq!(rows, 16, "two step rows per report");
    }

    /// U033 / I229: the counter read takes `FOR UPDATE`, so a report that
    /// arrives while another transaction holds the `workflows` row WAITS and
    /// then increments the committed value. Deterministic, unlike
    /// `concurrent_reports_do_not_lose_increments`: the holder writes
    /// `use_count = 5` and keeps its lock until the report is observed blocked
    /// in `pg_stat_activity`. Without the lock the report reads the stale row
    /// (no `use_count`), blocks only at its UPDATE, and then overwrites the
    /// holder's 5 with 1.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_report_waits_for_a_held_counter_row_and_increments_the_committed_value(
        pool: sqlx::PgPool,
    ) {
        let workflow_id = ingest_fixture(&pool, "test-outcome-row-lock").await;
        let mut holder = pool.begin().await.unwrap();
        sqlx::query("SELECT metadata FROM workflows WHERE id = $1 FOR UPDATE")
            .bind(workflow_id)
            .execute(&mut *holder)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE workflows \
             SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{use_count}', '5') \
             WHERE id = $1",
        )
        .bind(workflow_id)
        .execute(&mut *holder)
        .await
        .unwrap();

        let report_pool = pool.clone();
        let report = tokio::spawn(async move {
            report_on_test_scope(
                &report_pool,
                workflow_id,
                true,
                &two_steps(),
                None,
                Some("row lock run"),
                None,
                None,
            )
            .await
            .map(|_| ())
            .map_err(|e| e.message.to_string())
        });

        // Sync point: the report is blocked on the held row. Bounded by
        // iterations, not wall time.
        let mut blocked = false;
        for _ in 0..1000 {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE datname = current_database() AND wait_event_type = 'Lock'",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting > 0 {
                blocked = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            blocked,
            "the report never blocked on the held workflows row"
        );

        holder.commit().await.unwrap();
        report.await.expect("join").expect("report must succeed");
        let (metadata, rows) = counters_and_rows(&pool, workflow_id).await;
        assert_eq!(
            metadata["use_count"].as_i64(),
            Some(6),
            "the report must increment the committed 5, not overwrite it: {metadata}"
        );
        assert_eq!(rows, 2);
    }

    fn mock_embedder() -> epigraph_embeddings::MockProvider {
        epigraph_embeddings::MockProvider::new(epigraph_embeddings::EmbeddingConfig::openai(1536))
    }

    /// U033 / I229: only a real goal is embedded. The `"hierarchical"`
    /// placeholder the step rows fall back to, and blank text, are not goals:
    /// embedding them would make every such report "similar" to every other.
    #[test]
    fn report_goal_to_embed_skips_blank_and_placeholder() {
        assert_eq!(report_goal_to_embed(None), None);
        assert_eq!(report_goal_to_embed(Some("")), None);
        assert_eq!(report_goal_to_embed(Some("   ")), None);
        assert_eq!(report_goal_to_embed(Some("hierarchical")), None);
        assert_eq!(
            report_goal_to_embed(Some("  Deploy with zero downtime ")),
            Some("Deploy with zero downtime")
        );
    }

    /// U033 / I229 part (4): the report's goal is embedded once and written on
    /// every step row, and those rows then reach `behavioral_affinity_hierarchical`
    /// under the workflow's own id, which is what `find_workflow`'s
    /// hierarchical leg looks up. Before U033 every row had a NULL
    /// `goal_embedding`. The embedder is the deterministic `MockProvider` (the
    /// OpenAI boundary); the database is real.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_reported_goal_is_embedded_on_every_step_row_and_reaches_affinity(
        pool: sqlx::PgPool,
    ) {
        let workflow_id = ingest_fixture(&pool, "test-outcome-embedding").await;
        let goal = "Validate hierarchical outcome reporting";
        let embedder = mock_embedder();
        report_with_embedder_on_test_scope(
            &pool,
            &embedder,
            workflow_id,
            true,
            &two_steps(),
            None,
            Some(goal),
            None,
        )
        .await
        .expect("report must succeed");

        let embedded: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM behavioral_executions \
             WHERE workflow_id = $1 AND goal_embedding IS NOT NULL",
        )
        .bind(workflow_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(embedded, 2, "every step row carries the goal embedding");

        let qvec = epigraph_embeddings::EmbeddingService::generate(&embedder, goal)
            .await
            .unwrap();
        let hits = epigraph_db::BehavioralExecutionRepository::behavioral_affinity_hierarchical(
            &pool,
            &crate::embed::format_pgvector(&qvec),
            0.5,
            1,
            20,
        )
        .await
        .unwrap();
        assert!(
            hits.iter()
                .any(|(id, sim, n)| *id == workflow_id && *sim > 0.99 && *n == 1),
            "the report must feed affinity under the workflow's id: {hits:?}"
        );
    }

    /// Best-effort: an embedder failure leaves the rows un-embedded but never
    /// fails the report (the flat `report_workflow_outcome` path's contract).
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_embedder_failure_does_not_fail_the_report(pool: sqlx::PgPool) {
        let workflow_id = ingest_fixture(&pool, "test-outcome-embed-fail").await;
        let failing = mock_embedder().with_failures(1.0);
        report_with_embedder_on_test_scope(
            &pool,
            &failing,
            workflow_id,
            true,
            &two_steps(),
            None,
            Some("Validate hierarchical outcome reporting"),
            None,
        )
        .await
        .expect("an embedder failure must not fail the report");
        let (metadata, rows) = counters_and_rows(&pool, workflow_id).await;
        assert_eq!(metadata["use_count"].as_i64(), Some(1));
        assert_eq!(rows, 2);
        let embedded: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM behavioral_executions \
             WHERE workflow_id = $1 AND goal_embedding IS NOT NULL",
        )
        .bind(workflow_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(embedded, 0);
    }

    /// A process with no `ScopedPool` cannot stamp the step lookup, so the
    /// report is REFUSED and writes nothing: no fallback to an unstamped
    /// transaction, which would be the silently-NULL path this replaced.
    /// Positive control on the same workflow: with a `ScopedPool` the same
    /// report lands.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_report_without_a_scoped_pool_is_refused_and_writes_nothing(pool: sqlx::PgPool) {
        let workflow_id = ingest_fixture(&pool, "test-outcome-no-scope").await;
        let err = do_report_hierarchical_outcome_as(
            None,
            &test_viewer(&pool).await,
            workflow_id,
            true,
            &two_steps(),
            Some(0.5),
            Some("no scope"),
            None,
            None,
        )
        .await
        .expect_err("no ScopedPool: the report must be refused");
        assert!(err.message.contains("ScopedPool"), "{err:?}");
        let (metadata, rows) = counters_and_rows(&pool, workflow_id).await;
        assert!(
            metadata.get("use_count").is_none(),
            "a refused report must not move counters: {metadata}"
        );
        assert_eq!(rows, 0, "a refused report must write no step rows");

        report_on_test_scope(
            &pool,
            workflow_id,
            true,
            &two_steps(),
            Some(0.5),
            Some("no scope"),
            None,
            None,
        )
        .await
        .expect("with a ScopedPool the report lands");
        let (metadata, rows) = counters_and_rows(&pool, workflow_id).await;
        assert_eq!(metadata["use_count"].as_i64(), Some(1));
        assert_eq!(rows, 2);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn report_outcome_404s_for_unknown_workflow(pool: sqlx::PgPool) {
        let bogus = Uuid::new_v4();
        let err = report_on_test_scope(&pool, bogus, true, &[], None, None, None, None)
            .await
            .expect_err("unknown workflow id must error");
        assert!(err.message.contains("no hierarchical workflow"));
    }
}
