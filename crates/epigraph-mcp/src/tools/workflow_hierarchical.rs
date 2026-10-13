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
    Ok(CallToolResult::success(vec![Content::text(
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
    let mut rows = if server.embedder.is_mock() {
        Vec::new()
    } else {
        match server.embedder.generate(&params.query).await {
            Ok(qvec) => {
                match epigraph_db::WorkflowRepository::find_hierarchical_by_embedding(
                    &server.pool,
                    &qvec,
                    similarity_threshold,
                    min_truth,
                    limit,
                    resolve_to_latest,
                )
                .await
                {
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
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    "embedder.generate failed; falling back to ILIKE"
                );
                Vec::new()
            }
        }
    };

    if rows.is_empty() {
        rows = epigraph_db::WorkflowRepository::search_hierarchical_by_text(
            &server.pool,
            &params.query,
            limit,
            min_truth,
            resolve_to_latest,
        )
        .await
        .map_err(internal_error)?;
    }

    let mut workflows: Vec<serde_json::Value> = Vec::with_capacity(rows.len());
    for r in rows {
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
    params: ReportHierarchicalOutcomeParams,
) -> Result<CallToolResult, McpError> {
    let workflow_id =
        Uuid::parse_str(&params.workflow_id).map_err(|_| invalid_uuid("workflow_id"))?;

    do_report_hierarchical_outcome_via_pool(
        &server.pool,
        workflow_id,
        params.success,
        &params.step_executions,
        params.quality,
        params.goal_text.as_deref(),
        params.run_label.as_deref(),
        None,
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

/// Pool-only outcome reporting for hierarchical workflows. Updates
/// `workflows.metadata` rolling counters and writes per-step
/// `behavioral_executions` rows with `step_claim_id` resolved from the
/// workflow's `executes` edges (level=2 claims, in plan order).
///
/// ALL OR NOTHING (U033 / I229). The counter read, the counter write, the
/// step lookup and every step row run on ONE transaction, and the counter
/// read takes `FOR UPDATE` on the `workflows` row, so two concurrent reports
/// serialize instead of both writing `use_count = n + 1`. A step row the
/// database refuses fails the whole report and rolls the counters back; it
/// used to be logged and skipped while the tool answered success.
///
/// The transaction is a plain `pool.begin()`, not an author-stamped one:
/// neither `workflows` nor `behavioral_executions` has row security, so there
/// is no `WITH CHECK` for a stamp to satisfy. It is named `unstamped_tx` so
/// `tests/residual_unstamped_writes.rs` does not count it as stamped.
///
/// `goal_embedding` is computed by the caller BEFORE this runs (embedder
/// latency stays out of the row lock) and is written on every step row, so
/// the report feeds `behavioral_affinity_lineage`.
#[allow(clippy::too_many_arguments)]
pub async fn do_report_hierarchical_outcome_via_pool(
    pool: &sqlx::PgPool,
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

    let mut unstamped_tx = pool.begin().await.map_err(internal_error)?;

    // 1. Confirm hierarchical workflow exists, and lock its row for the
    //    read-modify-write of the counters below.
    let row: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT metadata FROM workflows WHERE id = $1 FOR UPDATE")
            .bind(workflow_id)
            .fetch_optional(&mut *unstamped_tx)
            .await
            .map_err(internal_error)?;
    let mut metadata = match row {
        Some((m,)) => m,
        None => return Err(not_found(workflow_id)),
    };

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
        .execute(&mut *unstamped_tx)
        .await
        .map_err(internal_error)?;

    // 4. Resolve step_index → step_claim_id via this workflow's `executes`
    //    edges, restricted to level=2 (steps), in PLAN order.
    //
    //    The leading key is the `plan_index` ordinal the ingest executor records
    //    on each `executes` edge — the same key `resolve_steps_to_heads` uses, so
    //    "step N" means one step everywhere. `e.created_at` is only the fallback
    //    for edges written before the ordinal existed (and for `add_step`'s,
    //    which carry none). It CANNOT be the primary key any more: the executor
    //    writes a whole plan in one transaction, `NOW()` is transaction-start
    //    time, so every edge ties and `c.id` — a content-derived UUID — decided
    //    the order. MEASURED on the real binary as `epigraph_app`, 6 steps
    //    reported 0..5: 2 attached to the right step claim, 4 to the wrong one,
    //    tool result `isError: false`.
    let step_claim_rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT c.id \
         FROM edges e \
         JOIN claims c ON c.id = e.target_id \
         WHERE e.source_id = $1 AND e.relationship = 'executes' AND (c.properties->>'level')::int = 2 \
         ORDER BY CASE WHEN e.properties->>'plan_index' ~ '^[0-9]{1,9}$' \
                       THEN (e.properties->>'plan_index')::int \
                       ELSE 2147483647 END, \
                  e.created_at ASC, c.id ASC",
    )
    .bind(workflow_id)
    .fetch_all(&mut *unstamped_tx)
    .await
    .map_err(internal_error)?;
    let step_claim_ids: Vec<Uuid> = step_claim_rows.into_iter().map(|(id,)| id).collect();

    // 5. Per-step behavioral_executions rows. Single timestamp groups them.
    //    A refused row fails the report: `?` drops `unstamped_tx`, which rolls
    //    back the counter UPDATE and every earlier step row.
    let report_ts = chrono::Utc::now();
    let goal_text_owned = goal_text.unwrap_or("hierarchical").to_string();
    let goal_embedding_pgvec = goal_embedding.map(crate::embed::format_pgvector);
    for step_exec in step_executions {
        let step_claim_id = step_claim_ids.get(step_exec.step_index).copied();
        if step_claim_id.is_none() && !step_claim_ids.is_empty() {
            tracing::warn!(
                workflow_id = %workflow_id,
                step_index = step_exec.step_index,
                known_steps = step_claim_ids.len(),
                "step_index out of range; behavioral_executions row will have NULL step_claim_id"
            );
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
            &mut *unstamped_tx,
            row,
            goal_embedding_pgvec.as_deref(),
        )
        .await
        .map_err(internal_error)?;
    }

    unstamped_tx.commit().await.map_err(internal_error)?;

    success_json(&serde_json::json!({
        "workflow_id": workflow_id,
        "use_count": use_count,
        "success_count": success_count,
        "failure_count": failure_count,
        "avg_variance": avg_variance,
        "variance": variance,
        // All or nothing: every requested step row was written, or the call
        // returned an error and none was.
        "step_executions_written": step_executions.len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::workflow_ingest::do_ingest_workflow_via_pool;
    use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
    use epigraph_ingest::workflow::WorkflowExtraction;

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

        do_report_hierarchical_outcome_via_pool(
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
        sqlx::query(
            "CREATE FUNCTION u033_fail() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF NEW.tool_pattern[1] = 'Step B' THEN RAISE EXCEPTION 'u033 injected'; END IF; \
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

        let res = do_report_hierarchical_outcome_via_pool(
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
        assert!(res.is_err(), "a refused step row must fail the report");

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
            let err = do_report_hierarchical_outcome_via_pool(
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
        do_report_hierarchical_outcome_via_pool(
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
                do_report_hierarchical_outcome_via_pool(
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

    #[sqlx::test(migrations = "../../migrations")]
    async fn report_outcome_404s_for_unknown_workflow(pool: sqlx::PgPool) {
        let bogus = Uuid::new_v4();
        let err = do_report_hierarchical_outcome_via_pool(
            &pool,
            bogus,
            true,
            &[],
            None,
            None,
            None,
            None,
        )
        .await
        .expect_err("unknown workflow id must error");
        assert!(err.message.contains("no hierarchical workflow"));
    }
}
