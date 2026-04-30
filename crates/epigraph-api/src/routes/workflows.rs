//! Workflow management endpoints.
//!
//! Workflows are epistemic claims with the "workflow" label, containing
//! structured goal/steps/prerequisites content.
//!
//! ## Endpoints
//!
//! - `POST   /api/v1/workflows`              - Store a new workflow
//! - `GET    /api/v1/workflows/search`        - Search workflows by goal
//! - `GET    /api/v1/workflows`               - List workflows
//! - `POST   /api/v1/workflows/:id/outcome`   - Report execution outcome
//! - `POST   /api/v1/workflows/:id/improve`   - Create improved variant
//! - `DELETE /api/v1/workflows/:id`            - Deprecate workflow
//! - `POST   /api/v1/workflows/:id/behavioral-executions` - Record behavioral execution

#[cfg(feature = "db")]
use axum::{
    extract::{Path, Query, State},
    Json,
};
#[cfg(feature = "db")]
use serde::Deserialize;
#[cfg(feature = "db")]
use uuid::Uuid;

#[cfg(feature = "db")]
use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;

// ── Request types ──

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct StoreWorkflowRequest {
    pub goal: String,
    pub steps: Vec<String>,
    pub prerequisites: Option<Vec<String>>,
    pub expected_outcome: Option<String>,
    pub confidence: Option<f64>,
    pub tags: Option<Vec<String>>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct SearchWorkflowsQuery {
    pub goal: String,
    pub min_truth: Option<f64>,
    pub limit: Option<i64>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct ListWorkflowsQuery {
    pub limit: Option<i64>,
    pub min_truth: Option<f64>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct ReportOutcomeRequest {
    pub success: bool,
    pub outcome_details: String,
    pub quality: Option<f64>,
    pub step_executions: Option<Vec<StepExecution>>,
    pub goal_text: Option<String>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct StepExecution {
    pub step_index: usize,
    pub planned: String,
    pub actual: String,
    pub deviated: bool,
    pub deviation_reason: Option<String>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct ImproveWorkflowRequest {
    pub goal: Option<String>,
    pub steps: Option<Vec<String>>,
    pub prerequisites: Option<Vec<String>>,
    pub expected_outcome: Option<String>,
    pub change_rationale: String,
    pub tags: Option<Vec<String>>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct DeprecateQuery {
    pub reason: String,
    pub cascade: Option<bool>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct HierarchicalSearchQuery {
    pub q: String,
    pub limit: Option<i64>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct RecordBehavioralExecutionRequest {
    pub goal_text: String,
    pub success: bool,
    pub step_beliefs: serde_json::Value,
    pub tool_pattern: Vec<String>,
    pub quality: Option<f64>,
    pub deviation_count: i32,
    pub total_steps: i32,
}

// ── Handlers ──

/// POST /api/v1/workflows - Store a new workflow as a claim.
#[cfg(feature = "db")]
pub async fn store_workflow(
    State(state): State<AppState>,
    Json(request): Json<StoreWorkflowRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let confidence = request.confidence.unwrap_or(0.5).clamp(0.0, 1.0);
    let initial_truth = 0.25 + (confidence * 0.25); // [0.25, 0.5]

    let content = serde_json::json!({
        "goal": request.goal,
        "steps": request.steps,
        "prerequisites": request.prerequisites.as_deref().unwrap_or(&[]),
        "expected_outcome": request.expected_outcome,
        "tags": request.tags.as_deref().unwrap_or(&[]),
    });

    // Ensure system agent exists
    let sys_agent_id = get_or_create_system_agent(&state.db_pool).await?;

    // Create workflow claim
    let content_str = content.to_string();
    let content_hash = epigraph_crypto::ContentHasher::hash(content_str.as_bytes());
    let workflow_id: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties) \
         VALUES ($1, $2, $3, $4, ARRAY['workflow'], $5) \
         RETURNING id",
    )
    .bind(&content_str)
    .bind(content_hash.as_slice())
    .bind(sys_agent_id)
    .bind(initial_truth)
    .bind(serde_json::json!({
        "generation": 0,
        "use_count": 0,
        "success_count": 0,
        "failure_count": 0,
        "avg_variance": 0.0,
    }))
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to create workflow: {e}"),
    })?;

    // Generate embedding if service available
    let mut embedded = false;
    if let Some(embedder) = state.embedding_service() {
        let embed_text = format!("{}\n{}", request.goal, request.steps.join("\n"));
        if let Ok(vec) = embedder.generate(&embed_text).await {
            let emb_str = format_embedding(&vec);
            let _ = sqlx::query("UPDATE claims SET embedding = $2::vector WHERE id = $1")
                .bind(workflow_id)
                .bind(&emb_str)
                .execute(&state.db_pool)
                .await;
            embedded = true;
        }
    }

    // Materialize agent --AUTHORED--> claim edge
    let _ = epigraph_db::EdgeRepository::create(
        &state.db_pool,
        sys_agent_id,
        "agent",
        workflow_id,
        "claim",
        "AUTHORED",
        None,
        None,
        None,
    )
    .await;

    // Emit event
    let _ = epigraph_db::EventRepository::insert(
        &state.db_pool,
        "workflow.created",
        None,
        &serde_json::json!({
            "workflow_id": workflow_id,
            "goal": request.goal,
            "step_count": request.steps.len(),
        }),
    )
    .await;

    Ok(Json(serde_json::json!({
        "workflow_id": workflow_id,
        "goal": request.goal,
        "step_count": request.steps.len(),
        "truth_value": initial_truth,
        "embedded": embedded,
    })))
}

/// Extract behavioral metadata from a WorkflowRecallResult's properties JSONB.
#[cfg(feature = "db")]
fn workflow_recall_to_json(r: &epigraph_db::WorkflowRecallResult) -> serde_json::Value {
    serde_json::json!({
        "workflow_id": r.claim_id,
        "content": r.content,
        "truth_value": r.truth_value,
        "similarity": r.similarity,
        "hybrid_score": r.hybrid_score,
        "edge_count": r.edge_count,
        "use_count": r.properties.get("use_count").and_then(|v| v.as_i64()).unwrap_or(0),
        "success_count": r.properties.get("success_count").and_then(|v| v.as_i64()).unwrap_or(0),
        "failure_count": r.properties.get("failure_count").and_then(|v| v.as_i64()).unwrap_or(0),
        "generation": r.properties.get("generation").and_then(|v| v.as_i64()).unwrap_or(0),
    })
}

/// GET /api/v1/workflows/search - Search workflows by semantic goal similarity.
#[cfg(feature = "db")]
pub async fn search_workflows(
    State(state): State<AppState>,
    Query(params): Query<SearchWorkflowsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let min_truth = params.min_truth.unwrap_or(0.3);
    let limit = params.limit.unwrap_or(5).clamp(1, 50);

    // Try embedding search first
    if let Some(embedder) = state.embedding_service() {
        if let Ok(query_vec) = embedder.generate(&params.goal).await {
            let results = epigraph_db::WorkflowRepository::find_by_embedding(
                &state.db_pool,
                &query_vec,
                min_truth,
                limit,
            )
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to search workflows: {e}"),
            })?;

            // Behavioral affinity lookup (best-effort)
            let pgvec = format!(
                "[{}]",
                query_vec
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            let affinity_map: std::collections::HashMap<uuid::Uuid, (f64, i64)> =
                match epigraph_db::BehavioralExecutionRepository::behavioral_affinity_lineage(
                    &state.db_pool,
                    &pgvec,
                    0.5,
                    1,
                    20,
                )
                .await
                {
                    Ok(rows) => rows
                        .into_iter()
                        .map(|(id, sim, count)| (id, (sim, count)))
                        .collect(),
                    Err(_) => std::collections::HashMap::new(),
                };

            let mut workflows: Vec<serde_json::Value> = Vec::new();
            for r in &results {
                let mut json = workflow_recall_to_json(r);

                let lineage_root = epigraph_db::WorkflowRepository::find_lineage_root(
                    &state.db_pool,
                    r.claim_id,
                )
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(workflow_id = %r.claim_id, "find_lineage_root failed: {e}");
                    r.claim_id
                });

                if let Some(&(affinity, count)) = affinity_map.get(&lineage_root) {
                    json["behavioral_affinity"] = serde_json::json!(affinity);
                    json["behavioral_execution_count"] = serde_json::json!(count);

                    if let Ok(rate) =
                        epigraph_db::BehavioralExecutionRepository::rolling_success_rate(
                            &state.db_pool,
                            r.claim_id,
                            20,
                        )
                        .await
                    {
                        if rate > 0.0 {
                            json["behavioral_success_rate"] = serde_json::json!(rate);
                        }
                    }
                }

                workflows.push(json);
            }

            return Ok(Json(serde_json::json!({
                "workflows": workflows,
                "total": workflows.len(),
            })));
        }
    }

    // Fallback: text search
    let results = epigraph_db::WorkflowRepository::find_by_text(
        &state.db_pool,
        &params.goal,
        min_truth,
        limit,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to search workflows: {e}"),
    })?;

    let mut workflows: Vec<serde_json::Value> = Vec::new();
    for r in &results {
        let mut json = workflow_recall_to_json(r);

        if let Ok(rate) = epigraph_db::BehavioralExecutionRepository::rolling_success_rate(
            &state.db_pool,
            r.claim_id,
            20,
        )
        .await
        {
            if rate > 0.0 {
                json["behavioral_success_rate"] = serde_json::json!(rate);
            }
        }

        workflows.push(json);
    }

    Ok(Json(serde_json::json!({
        "workflows": workflows,
        "total": workflows.len(),
    })))
}

/// GET /api/v1/workflows - List workflows.
#[cfg(feature = "db")]
pub async fn list_workflows(
    State(state): State<AppState>,
    Query(params): Query<ListWorkflowsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let min_truth = params.min_truth.unwrap_or(0.0);

    let workflows = epigraph_db::WorkflowRepository::list(&state.db_pool, min_truth, None, limit)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to list workflows: {e}"),
        })?;

    let results: Vec<serde_json::Value> = workflows
        .iter()
        .map(|w| {
            serde_json::json!({
                "workflow_id": w.id,
                "content": w.content,
                "truth_value": w.truth_value,
                "properties": w.properties,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "workflows": results,
        "total": results.len(),
    })))
}

/// POST /api/v1/workflows/:id/outcome - Report execution outcome.
#[cfg(feature = "db")]
pub async fn report_outcome(
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    Json(request): Json<ReportOutcomeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Verify workflow exists
    let workflow = sqlx::query_as::<_, WorkflowRow>(
        "SELECT id, truth_value, properties FROM claims WHERE id = $1 AND 'workflow' = ANY(labels)",
    )
    .bind(workflow_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch workflow: {e}"),
    })?
    .ok_or(ApiError::NotFound {
        entity: "workflow".into(),
        id: workflow_id.to_string(),
    })?;

    let before_truth = workflow.truth_value.unwrap_or(0.5);

    // Compute variance from step executions
    let variance = if let Some(ref steps) = request.step_executions {
        let deviated = steps.iter().filter(|s| s.deviated).count();
        if steps.is_empty() {
            0.0
        } else {
            deviated as f64 / steps.len() as f64
        }
    } else {
        0.0
    };

    let quality = request
        .quality
        .unwrap_or(if request.success { 1.0 } else { 0.0 });

    // Update truth via Bayesian update
    // TODO: migrate to CDST pignistic probability (BayesianUpdater is deprecated)
    #[allow(deprecated)]
    let updater = epigraph_engine::BayesianUpdater::new();
    let prior = epigraph_core::TruthValue::clamped(before_truth);
    let strength = quality * (1.0 - variance * 0.5); // Variance reduces update strength
    let after_truth = if request.success {
        updater
            .update_with_support(prior, strength)
            .unwrap_or(prior)
            .value()
    } else {
        updater
            .update_with_refutation(prior, strength)
            .unwrap_or(prior)
            .value()
    };

    // Update claim truth
    let _ = sqlx::query("UPDATE claims SET truth_value = $1 WHERE id = $2")
        .bind(after_truth)
        .bind(workflow_id)
        .execute(&state.db_pool)
        .await;

    // Update properties counters
    let mut props = workflow.properties.clone().unwrap_or(serde_json::json!({}));
    let use_count = props.get("use_count").and_then(|v| v.as_i64()).unwrap_or(0) + 1;
    let success_count = props
        .get("success_count")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        + if request.success { 1 } else { 0 };
    let failure_count = props
        .get("failure_count")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        + if request.success { 0 } else { 1 };
    let prev_avg_var = props
        .get("avg_variance")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let avg_variance = if use_count > 0 {
        (prev_avg_var * (use_count - 1) as f64 + variance) / use_count as f64
    } else {
        variance
    };

    props["use_count"] = serde_json::json!(use_count);
    props["success_count"] = serde_json::json!(success_count);
    props["failure_count"] = serde_json::json!(failure_count);
    props["avg_variance"] = serde_json::json!(avg_variance);

    let _ = sqlx::query("UPDATE claims SET properties = $1 WHERE id = $2")
        .bind(&props)
        .bind(workflow_id)
        .execute(&state.db_pool)
        .await;

    // ── Behavioral execution row (best-effort) ──────────────────────────
    // Parse workflow goal for fallback
    let parsed_goal: String = sqlx::query_scalar("SELECT content FROM claims WHERE id = $1")
        .bind(workflow_id)
        .fetch_optional(&state.db_pool)
        .await
        .ok()
        .flatten()
        .and_then(|content: String| {
            serde_json::from_str::<serde_json::Value>(&content)
                .ok()
                .and_then(|v| v.get("goal").and_then(|g| g.as_str()).map(String::from))
        })
        .unwrap_or_default();

    let behavioral_goal = request.goal_text.unwrap_or(parsed_goal);

    let (deviation_count, total_steps, tool_pattern, step_beliefs) =
        if let Some(ref steps) = request.step_executions {
            let dev_count = steps.iter().filter(|s| s.deviated).count() as i32;
            let tot = steps.len() as i32;
            let pattern: Vec<String> = steps.iter().map(|s| s.planned.clone()).collect();
            let beliefs: serde_json::Value = steps
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    (
                        i.to_string(),
                        serde_json::json!({
                            "deviated": s.deviated,
                            "deviation_reason": s.deviation_reason,
                        }),
                    )
                })
                .collect::<serde_json::Map<String, serde_json::Value>>()
                .into();
            (dev_count, tot, pattern, beliefs)
        } else {
            (0, 0, vec![], serde_json::json!({}))
        };

    // Embed goal text for affinity matching
    let goal_embedding_pgvec = if let Some(embedder) = state.embedding_service() {
        match embedder.generate(&behavioral_goal).await {
            Ok(vec) => {
                let pgvec = format!(
                    "[{}]",
                    vec.iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );
                Some(pgvec)
            }
            Err(e) => {
                tracing::warn!("behavioral goal embedding failed: {e}");
                None
            }
        }
    } else {
        None
    };

    let behavioral_row = epigraph_db::BehavioralExecutionRow {
        id: Uuid::new_v4(),
        workflow_id,
        goal_text: behavioral_goal,
        success: request.success,
        step_beliefs,
        tool_pattern,
        quality: Some(quality),
        deviation_count,
        total_steps,
        created_at: chrono::Utc::now(),
        step_claim_id: None,
    };

    if let Err(e) = epigraph_db::BehavioralExecutionRepository::create(
        &state.db_pool,
        behavioral_row,
        goal_embedding_pgvec.as_deref(),
    )
    .await
    {
        tracing::warn!(workflow_id = %workflow_id, "behavioral execution write failed: {e}");
    }

    let success_rate = if use_count > 0 {
        success_count as f64 / use_count as f64
    } else {
        0.0
    };

    Ok(Json(serde_json::json!({
        "workflow_id": workflow_id,
        "before_truth": before_truth,
        "after_truth": after_truth,
        "variance": variance,
        "total_uses": use_count,
        "success_rate": success_rate,
    })))
}

/// GET /api/v1/workflows/hierarchical/search?q=...&limit=N - Search
/// hierarchical workflows by free-text query.
///
/// Returns workflows whose `goal` or `canonical_name` matches `q` (ILIKE),
/// ordered newest first. Limit defaults to 10, max 50.
///
/// Use `GET /api/v1/workflows/search` for flat-JSON workflows.
#[cfg(feature = "db")]
pub async fn find_workflow_hierarchical(
    State(state): State<AppState>,
    Query(params): Query<HierarchicalSearchQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);
    let rows = epigraph_db::WorkflowRepository::search_hierarchical_by_text(
        &state.db_pool,
        &params.q,
        limit,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("hierarchical search failed: {e}"),
    })?;
    let workflows: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "workflow_id": r.id,
                "canonical_name": r.canonical_name,
                "generation": r.generation,
                "goal": r.goal,
                "parent_id": r.parent_id,
                "metadata": r.metadata,
                "created_at": r.created_at,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "workflows": workflows,
        "total": workflows.len(),
    })))
}

/// POST /api/v1/workflows/hierarchical/:id/outcome - Report execution outcome
/// for a hierarchical workflow (one whose root lives in the `workflows` table).
///
/// Updates `workflows.metadata` counters (use_count, success_count, failure_count,
/// avg_variance) and writes per-step `behavioral_executions` rows with
/// `step_claim_id` populated for each step in `step_executions`.
///
/// Returns 404 if the id does not correspond to a `workflows` row. Use
/// `POST /api/v1/workflows/:id/outcome` for flat-JSON workflows.
#[cfg(feature = "db")]
pub async fn report_hierarchical_outcome(
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    Json(request): Json<ReportOutcomeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // 1. Confirm this is a hierarchical workflow root
    let row: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT metadata FROM workflows WHERE id = $1")
            .bind(workflow_id)
            .fetch_optional(&state.db_pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("workflows lookup failed: {e}"),
            })?;
    let mut metadata = match row {
        Some((m,)) => m,
        None => {
            return Err(ApiError::NotFound {
                entity: "hierarchical workflow".into(),
                id: workflow_id.to_string(),
            });
        }
    };

    // 2. Compute deltas
    let success = request.success;
    let variance = request.step_executions.as_ref().map_or(0.0, |steps| {
        if steps.is_empty() {
            0.0
        } else {
            let dev = steps.iter().filter(|s| s.deviated).count();
            dev as f64 / steps.len() as f64
        }
    });
    let quality = request.quality.unwrap_or(if success { 1.0 } else { 0.0 });

    // 3. Update metadata counters
    let use_count = metadata.get("use_count").and_then(|v| v.as_i64()).unwrap_or(0) + 1;
    let success_count = metadata
        .get("success_count")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        + i64::from(success);
    let failure_count = metadata
        .get("failure_count")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        + i64::from(!success);
    let prev_avg_var = metadata
        .get("avg_variance")
        .and_then(|v| v.as_f64())
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
        .execute(&state.db_pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("metadata update failed: {e}"),
        })?;

    // 4. Resolve step_index → step_claim_id via the workflow's executes edges,
    //    sorted by claim level=2 (steps), in plan order. Plan order is the
    //    insertion order of `executes` edges; we use edges.created_at as proxy.
    let step_claim_rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT c.id \
         FROM edges e \
         JOIN claims c ON c.id = e.target_id \
         WHERE e.source_id = $1 AND e.relationship = 'executes' AND (c.properties->>'level')::int = 2 \
         ORDER BY e.created_at ASC, c.id ASC",
    )
    .bind(workflow_id)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("step lookup failed: {e}"),
    })?;
    let step_claim_ids: Vec<Uuid> = step_claim_rows.into_iter().map(|(id,)| id).collect();

    // 5. Write per-step behavioral_executions rows. Capture timestamp once so
    //    rows from a single outcome report group cleanly downstream.
    let report_ts = chrono::Utc::now();
    if let Some(ref step_execs) = request.step_executions {
        for step_exec in step_execs {
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
                goal_text: request
                    .goal_text
                    .clone()
                    .unwrap_or_else(|| String::from("hierarchical")),
                success,
                step_beliefs,
                tool_pattern: vec![step_exec.planned.clone()],
                quality: Some(quality),
                deviation_count: i32::from(step_exec.deviated),
                total_steps: 1,
                created_at: report_ts,
                step_claim_id,
            };
            if let Err(e) =
                epigraph_db::BehavioralExecutionRepository::create(&state.db_pool, row, None).await
            {
                tracing::warn!(workflow_id = %workflow_id, "behavioral_executions write failed: {e}");
            }
        }
    }

    Ok(Json(serde_json::json!({
        "workflow_id": workflow_id,
        "use_count": use_count,
        "success_count": success_count,
        "failure_count": failure_count,
        "variance": variance,
    })))
}

/// POST /api/v1/workflows/:id/improve - Create an improved variant.
#[cfg(feature = "db")]
pub async fn improve_workflow(
    State(state): State<AppState>,
    Path(parent_id): Path<Uuid>,
    Json(request): Json<ImproveWorkflowRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Fetch parent workflow
    let parent = sqlx::query_as::<_, WorkflowContentRow>(
        "SELECT id, content, truth_value, properties FROM claims \
         WHERE id = $1 AND 'workflow' = ANY(labels)",
    )
    .bind(parent_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch parent workflow: {e}"),
    })?
    .ok_or(ApiError::NotFound {
        entity: "workflow".into(),
        id: parent_id.to_string(),
    })?;

    // Parse parent content
    let parent_content: serde_json::Value =
        serde_json::from_str(&parent.content).unwrap_or(serde_json::json!({}));

    let parent_gen = parent
        .properties
        .as_ref()
        .and_then(|p| p.get("generation"))
        .and_then(|g| g.as_i64())
        .unwrap_or(0);

    // Build variant content (inherit from parent where not overridden)
    let goal = request
        .goal
        .unwrap_or_else(|| parent_content["goal"].as_str().unwrap_or("").to_string());
    let steps: Vec<String> = request.steps.unwrap_or_else(|| {
        parent_content["steps"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    });

    let content = serde_json::json!({
        "goal": goal,
        "steps": steps,
        "prerequisites": request.prerequisites.as_deref()
            .unwrap_or(parent_content["prerequisites"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
                .unwrap_or_default()
                .as_slice()),
        "expected_outcome": request.expected_outcome
            .as_deref()
            .unwrap_or(parent_content["expected_outcome"].as_str().unwrap_or("")),
        "tags": request.tags.as_deref().unwrap_or(&[]),
        "change_rationale": request.change_rationale,
    });

    // Create variant claim
    let sys_agent_id = get_or_create_system_agent(&state.db_pool).await?;
    let variant_content_str = content.to_string();
    let variant_hash = epigraph_crypto::ContentHasher::hash(variant_content_str.as_bytes());
    let variant_id: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties) \
         VALUES ($1, $2, $3, 0.5, ARRAY['workflow'], $4) \
         RETURNING id",
    )
    .bind(&variant_content_str)
    .bind(variant_hash.as_slice())
    .bind(sys_agent_id)
    .bind(serde_json::json!({
        "generation": parent_gen + 1,
        "use_count": 0,
        "success_count": 0,
        "failure_count": 0,
        "avg_variance": 0.0,
        "parent_id": parent_id,
    }))
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to create variant: {e}"),
    })?;

    // Create variant_of edge
    let _ = sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship, properties) \
         VALUES ($1, $2, 'claim', 'claim', 'variant_of', $3)",
    )
    .bind(variant_id)
    .bind(parent_id)
    .bind(serde_json::json!({
        "change_rationale": request.change_rationale,
        "parent_truth_at_fork": parent.truth_value,
    }))
    .execute(&state.db_pool)
    .await;

    // Materialize agent --AUTHORED--> variant edge
    let _ = epigraph_db::EdgeRepository::create(
        &state.db_pool,
        sys_agent_id,
        "agent",
        variant_id,
        "claim",
        "AUTHORED",
        None,
        None,
        None,
    )
    .await;

    // Embed variant
    let mut embedded = false;
    if let Some(embedder) = state.embedding_service() {
        let embed_text = format!("{}\n{}", goal, steps.join("\n"));
        if let Ok(vec) = embedder.generate(&embed_text).await {
            let emb_str = format_embedding(&vec);
            let _ = sqlx::query("UPDATE claims SET embedding = $2::vector WHERE id = $1")
                .bind(variant_id)
                .bind(&emb_str)
                .execute(&state.db_pool)
                .await;
            embedded = true;
        }
    }

    Ok(Json(serde_json::json!({
        "variant_id": variant_id,
        "parent_id": parent_id,
        "goal": goal,
        "step_count": steps.len(),
        "generation": parent_gen + 1,
        "truth_value": 0.5,
        "embedded": embedded,
    })))
}

/// DELETE /api/v1/workflows/:id - Deprecate a workflow.
#[cfg(feature = "db")]
pub async fn deprecate_workflow(
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    Query(params): Query<DeprecateQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let cascade = params.cascade.unwrap_or(false);

    // Verify workflow exists
    let _exists = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM claims WHERE id = $1 AND 'workflow' = ANY(labels)",
    )
    .bind(workflow_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to check workflow: {e}"),
    })?
    .ok_or(ApiError::NotFound {
        entity: "workflow".into(),
        id: workflow_id.to_string(),
    })?;

    // Collect IDs to deprecate
    let mut ids_to_deprecate = vec![workflow_id];
    if cascade {
        let descendants =
            epigraph_db::WorkflowRepository::find_descendants(&state.db_pool, workflow_id)
                .await
                .unwrap_or_default();
        ids_to_deprecate.extend(descendants);
    }

    // Set truth to near-zero for all
    for id in &ids_to_deprecate {
        let _ = sqlx::query("UPDATE claims SET truth_value = 0.05 WHERE id = $1")
            .bind(id)
            .execute(&state.db_pool)
            .await;
    }

    // Emit event
    let _ = epigraph_db::EventRepository::insert(
        &state.db_pool,
        "workflow.deprecated",
        None,
        &serde_json::json!({
            "workflow_id": workflow_id,
            "reason": params.reason,
            "cascade": cascade,
            "deprecated_count": ids_to_deprecate.len(),
        }),
    )
    .await;

    Ok(Json(serde_json::json!({
        "deprecated_ids": ids_to_deprecate,
        "reason": params.reason,
    })))
}

/// POST /api/v1/workflows/:id/behavioral-executions - Record a behavioral execution.
///
/// Stores a per-execution record with an optional goal embedding so downstream
/// agents can answer "which workflow works best for goals like THIS one?"
#[cfg(feature = "db")]
pub async fn record_behavioral_execution(
    Path(workflow_id): Path<Uuid>,
    State(state): State<AppState>,
    Json(body): Json<RecordBehavioralExecutionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Verify the referenced workflow exists
    let _exists = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM claims WHERE id = $1 AND 'workflow' = ANY(labels)",
    )
    .bind(workflow_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to check workflow: {e}"),
    })?
    .ok_or(ApiError::NotFound {
        entity: "workflow".into(),
        id: workflow_id.to_string(),
    })?;

    // Attempt to generate a goal embedding if an embedder is available
    let mut embedding_pgvec: Option<String> = None;
    let mut embedded = false;
    if let Some(embedder) = state.embedding_service() {
        if let Ok(vec) = embedder.generate(&body.goal_text).await {
            embedding_pgvec = Some(format_embedding(&vec));
            embedded = true;
        }
    }

    // Build the row — id and created_at are DB-assigned but we supply them
    // so the struct round-trips cleanly through RETURNING.
    let row = epigraph_db::BehavioralExecutionRow {
        id: Uuid::new_v4(),
        workflow_id,
        goal_text: body.goal_text.clone(),
        success: body.success,
        step_beliefs: body.step_beliefs,
        tool_pattern: body.tool_pattern,
        quality: body.quality,
        deviation_count: body.deviation_count,
        total_steps: body.total_steps,
        created_at: chrono::Utc::now(),
        step_claim_id: None,
    };

    let created = epigraph_db::BehavioralExecutionRepository::create(
        &state.db_pool,
        row,
        embedding_pgvec.as_deref(),
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to record behavioral execution: {e}"),
    })?;

    Ok(Json(serde_json::json!({
        "execution_id": created.id,
        "workflow_id": workflow_id,
        "success": created.success,
        "embedded": embedded,
    })))
}

/// POST /api/v1/workflows/ingest - Ingest a hierarchical `WorkflowExtraction`.
///
/// Parses a `WorkflowExtraction` JSON body, persists the claim hierarchy
/// (thesis → phases → steps → operation atoms), writes `workflow —executes→ claim`
/// edges, resolves author-placeholder edges, and returns a summary. Idempotent:
/// if the workflow row already has `executes` edges, returns `already_ingested: true`
/// without touching the DB further.
#[cfg(feature = "db")]
pub async fn ingest_workflow(
    State(state): State<AppState>,
    Json(extraction): Json<epigraph_ingest::workflow::WorkflowExtraction>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use std::collections::HashMap;
    use epigraph_core::{AgentId, TruthValue};
    use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, WorkflowRepository};
    use epigraph_ingest::workflow::builder::root_workflow_id;

    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);
    let pool = &state.db_pool;

    let canonical_name = &extraction.source.canonical_name;
    let generation = extraction.source.generation as i32;
    let goal = &extraction.source.goal;
    let workflow_id = root_workflow_id(&extraction);

    // ── 1. Idempotency gate ──────────────────────────────────────────────
    if let Some(existing_id) = WorkflowRepository::find_root_by_canonical(pool, canonical_name, generation)
        .await
        .map_err(|e| ApiError::InternalError { message: e.to_string() })?
    {
        let edge_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM edges \
             WHERE source_id = $1 AND source_type = 'workflow' AND relationship = 'executes'",
        )
        .bind(existing_id)
        .fetch_one(pool)
        .await
        .map_err(|e| ApiError::InternalError { message: e.to_string() })?;

        if edge_count > 0 {
            return Ok(Json(serde_json::json!({
                "workflow_id": existing_id,
                "canonical_name": canonical_name,
                "generation": generation,
                "claims_ingested": 0,
                "claims_skipped_dedup": 0,
                "executes_edges": edge_count,
                "relationships_created": 0,
                "already_ingested": true,
            })));
        }
    }

    // ── 2. System agent ──────────────────────────────────────────────────
    let system_agent_id = get_or_create_system_agent(pool).await?;
    let _agent_id_typed = AgentId::from_uuid(system_agent_id);

    // ── 3. Workflow row (idempotent) ──────────────────────────────────────
    let parent_id = if let Some(ref pcn) = extraction.source.parent_canonical_name {
        WorkflowRepository::find_root_by_canonical(pool, pcn, generation.saturating_sub(1))
            .await
            .map_err(|e| ApiError::InternalError { message: e.to_string() })?
    } else {
        None
    };

    WorkflowRepository::insert_root(
        pool,
        workflow_id,
        canonical_name,
        generation,
        goal,
        parent_id,
        extraction.source.metadata.clone(),
    )
    .await
    .map_err(|e| ApiError::InternalError { message: e.to_string() })?;

    // ── 4. Author agents ─────────────────────────────────────────────────
    let mut author_agent_map: HashMap<usize, Uuid> = HashMap::new();
    for (idx, author) in extraction.source.authors.iter().enumerate() {
        if author.name.is_empty() {
            continue;
        }
        let (_did, pub_key_bytes) =
            epigraph_crypto::did_key::did_key_for_author(None, &author.name);
        let agent_uuid: Uuid = if let Some(existing) =
            AgentRepository::get_by_public_key(pool, &pub_key_bytes)
                .await
                .map_err(|e| ApiError::InternalError { message: e.to_string() })?
        {
            existing.id.into()
        } else {
            let author_agent = epigraph_core::Agent::new(pub_key_bytes, Some(author.name.clone()));
            let created = AgentRepository::create(pool, &author_agent)
                .await
                .map_err(|e| ApiError::InternalError { message: e.to_string() })?;
            created.id.into()
        };
        author_agent_map.insert(idx, agent_uuid);
    }

    // ── 5. Claims ────────────────────────────────────────────────────────
    let mut claims_ingested = 0_usize;
    let mut claims_skipped_dedup = 0_usize;
    let mut id_map: HashMap<Uuid, Uuid> = HashMap::new();

    for planned in &plan.claims {
        let confidence = planned.confidence.clamp(0.0, 1.0);
        let truth = TruthValue::clamped(confidence.clamp(0.01, 0.99));
        let kind = planned
            .properties
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("workflow_claim");
        let labels = vec!["claim".to_string(), kind.to_string()];

        let was_new = ClaimRepository::create_with_id_if_absent(
            pool,
            planned.id,
            &planned.content,
            &planned.content_hash,
            system_agent_id,
            truth,
            &labels,
        )
        .await
        .map_err(|e| ApiError::InternalError { message: e.to_string() })?;

        if was_new {
            sqlx::query("UPDATE claims SET properties = $1 WHERE id = $2")
                .bind(&planned.properties)
                .bind(planned.id)
                .execute(pool)
                .await
                .map_err(|e| ApiError::InternalError { message: e.to_string() })?;
            claims_ingested += 1;
        } else {
            claims_skipped_dedup += 1;
        }
        id_map.insert(planned.id, planned.id);
    }

    // ── 6. executes edges ────────────────────────────────────────────────
    let mut executes_edges = 0_usize;
    for planned in &plan.claims {
        EdgeRepository::create_if_not_exists(
            pool,
            workflow_id,
            "workflow",
            planned.id,
            "claim",
            "executes",
            Some(serde_json::json!({"level": planned.level})),
            None,
            None,
        )
        .await
        .map_err(|e| ApiError::InternalError { message: e.to_string() })?;
        executes_edges += 1;
    }

    // ── 7. Intra-claim plan edges ─────────────────────────────────────────
    let mut relationships_created = 0_usize;
    for edge in &plan.edges {
        let (src, src_type) = if edge.source_type == "author_placeholder" {
            let idx = edge.properties["author_index"].as_u64().unwrap_or(0) as usize;
            let Some(&agent_uuid) = author_agent_map.get(&idx) else {
                continue;
            };
            (agent_uuid, "agent".to_string())
        } else {
            let mapped = id_map
                .get(&edge.source_id)
                .copied()
                .unwrap_or(edge.source_id);
            (mapped, edge.source_type.clone())
        };
        let tgt = id_map
            .get(&edge.target_id)
            .copied()
            .unwrap_or(edge.target_id);

        EdgeRepository::create_if_not_exists(
            pool,
            src,
            &src_type,
            tgt,
            &edge.target_type,
            &edge.relationship,
            Some(edge.properties.clone()),
            None,
            None,
        )
        .await
        .map_err(|e| ApiError::InternalError { message: e.to_string() })?;
        relationships_created += 1;
    }

    Ok(Json(serde_json::json!({
        "workflow_id": workflow_id,
        "canonical_name": canonical_name,
        "generation": generation,
        "claims_ingested": claims_ingested,
        "claims_skipped_dedup": claims_skipped_dedup,
        "executes_edges": executes_edges,
        "relationships_created": relationships_created,
        "already_ingested": false,
    })))
}

// ── Internal helpers ──

#[cfg(feature = "db")]
async fn get_or_create_system_agent(pool: &sqlx::PgPool) -> Result<Uuid, ApiError> {
    let (_did, pub_key_bytes) =
        epigraph_crypto::did_key::did_key_for_author(None, "workflow-ingest-system");
    if let Some(a) = epigraph_db::AgentRepository::get_by_public_key(pool, &pub_key_bytes)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
    {
        Ok(a.id.as_uuid())
    } else {
        let agent = epigraph_core::Agent::new(
            pub_key_bytes,
            Some("workflow-ingest-system".to_string()),
        );
        let created = epigraph_db::AgentRepository::create(pool, &agent)
            .await
            .map_err(|e| ApiError::InternalError {
                message: e.to_string(),
            })?;
        Ok(created.id.as_uuid())
    }
}

#[cfg(feature = "db")]
fn format_embedding(embedding: &[f32]) -> String {
    format!(
        "[{}]",
        embedding
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

// ── Internal types ──

#[cfg(feature = "db")]
#[derive(sqlx::FromRow)]
struct WorkflowRow {
    #[allow(dead_code)]
    id: Uuid,
    truth_value: Option<f64>,
    properties: Option<serde_json::Value>,
}

#[cfg(feature = "db")]
#[derive(sqlx::FromRow)]
struct WorkflowContentRow {
    #[allow(dead_code)]
    id: Uuid,
    content: String,
    truth_value: Option<f64>,
    properties: Option<serde_json::Value>,
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn try_test_pool() -> Option<sqlx::PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .ok()?;
        sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
        Some(pool)
    }

    macro_rules! test_pool_or_skip {
        () => {{
            match try_test_pool().await {
                Some(p) => p,
                None => {
                    eprintln!("Skipping DB test: DATABASE_URL not set or unreachable");
                    return;
                }
            }
        }};
    }

    fn parse_body(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).unwrap_or_else(|_| {
            serde_json::json!({"error": String::from_utf8_lossy(bytes).to_string()})
        })
    }

    fn test_router(pool: sqlx::PgPool) -> axum::Router {
        use axum::routing::post;
        use crate::state::{AppState, ApiConfig};
        let state = AppState::with_db(pool, ApiConfig::default());
        axum::Router::new()
            .route("/api/v1/workflows/ingest", post(ingest_workflow))
            .with_state(state)
    }

    fn ingest_payload(canonical_name: &str) -> serde_json::Value {
        serde_json::json!({
            "source": {
                "canonical_name": canonical_name,
                "goal": "HTTP ingest test workflow",
                "generation": 0,
                "authors": []
            },
            "thesis": "Test that the HTTP endpoint persists claims correctly",
            "thesis_derivation": "TopDown",
            "phases": [{
                "title": "Phase One",
                "summary": "Single test phase",
                "steps": [{
                    "compound": "Execute the HTTP ingest handler",
                    "rationale": "Verify end-to-end",
                    "operations": ["POST /api/v1/workflows/ingest"],
                    "generality": [1],
                    "confidence": 0.85
                }]
            }],
            "relationships": []
        })
    }

    #[tokio::test]
    async fn ingest_workflow_http_returns_workflow_id() {
        let pool = test_pool_or_skip!();
        let app = test_router(pool);

        let body = serde_json::to_vec(&ingest_payload("http-test-ingest-workflow")).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/workflows/ingest")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = parse_body(&bytes);

        assert_eq!(status, StatusCode::OK, "response: {json}");
        assert!(
            json.get("workflow_id").is_some(),
            "must return workflow_id; got: {json}"
        );
        assert_eq!(
            json["already_ingested"].as_bool(),
            Some(false),
            "first ingest must not be a no-op"
        );
    }

    #[tokio::test]
    async fn report_hierarchical_outcome_updates_workflow_metadata() {
        let pool = match try_test_pool().await {
            Some(p) => p,
            None => return,
        };

        // Seed a hierarchical workflow directly via the DB layer so we don't depend on
        // the full HTTP ingest flow inside this test.
        let workflow_id = uuid::Uuid::new_v4();
        epigraph_db::WorkflowRepository::insert_root(
            &pool,
            workflow_id,
            "outcome-test",
            0,
            "Test workflow for outcome reporting.",
            None,
            serde_json::json!({"use_count": 0, "success_count": 0, "failure_count": 0, "avg_variance": 0.0}),
        )
        .await
        .unwrap();

        // Build a minimal axum app with just the outcome route.
        use crate::state::{AppState, ApiConfig};
        let state = AppState::with_db(pool.clone(), ApiConfig::default());
        let app = axum::Router::new()
            .route(
                "/api/v1/workflows/hierarchical/:id/outcome",
                axum::routing::post(report_hierarchical_outcome),
            )
            .with_state(state);

        let body = serde_json::json!({
            "success": true,
            "outcome_details": "ok",
            "step_executions": []
        });

        let response = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/workflows/hierarchical/{workflow_id}/outcome"))
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let metadata: serde_json::Value = sqlx::query_scalar(
            "SELECT metadata FROM workflows WHERE id = $1",
        )
        .bind(workflow_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(metadata["use_count"], 1);
        assert_eq!(metadata["success_count"], 1);
    }

    #[tokio::test]
    async fn report_hierarchical_outcome_404s_on_unknown_id() {
        let pool = match try_test_pool().await {
            Some(p) => p,
            None => return,
        };

        use crate::state::{AppState, ApiConfig};
        let state = AppState::with_db(pool.clone(), ApiConfig::default());
        let app = axum::Router::new()
            .route(
                "/api/v1/workflows/hierarchical/:id/outcome",
                axum::routing::post(report_hierarchical_outcome),
            )
            .with_state(state);

        let body = serde_json::json!({"success": true, "outcome_details": "ok"});
        let unknown = uuid::Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/workflows/hierarchical/{unknown}/outcome"))
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn find_workflow_hierarchical_returns_match() {
        let pool = match try_test_pool().await {
            Some(p) => p,
            None => return,
        };

        // Seed a hierarchical workflow.
        let workflow_id = uuid::Uuid::new_v4();
        let canonical = "search-e2e-test";
        epigraph_db::WorkflowRepository::insert_root(
            &pool,
            workflow_id,
            canonical,
            0,
            "A workflow for end-to-end search testing.",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();

        use crate::state::{AppState, ApiConfig};
        let state = AppState::with_db(pool.clone(), ApiConfig::default());
        let app = axum::Router::new()
            .route(
                "/api/v1/workflows/hierarchical/search",
                axum::routing::get(find_workflow_hierarchical),
            )
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/workflows/hierarchical/search?q={canonical}"))
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert!(body["total"].as_u64().unwrap_or(0) >= 1);
        let found = body["workflows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["canonical_name"].as_str() == Some(canonical));
        assert!(found, "expected to find the seeded canonical_name in results");
    }
}
