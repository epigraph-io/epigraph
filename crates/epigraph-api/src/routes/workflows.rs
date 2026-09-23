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
//! - `DELETE /api/v1/workflows/:id`            - Deprecate workflow
//! - `POST   /api/v1/workflows/:id/behavioral-executions` - Record behavioral execution
//!
//! # Tenancy: 10 of this file's 40 raw-pool sites are converted
//!
//! Conversion shard 7 — the last read shard. `search_workflows` (6 sites),
//! `find_workflow_hierarchical` (3) and `list_workflows` (1) each assemble their
//! whole answer on ONE viewer-stamped connection from [`AppState::read_as`].
//! The repository statements already spliced the viewer where they had one to
//! spend; what changed is which connection carries the session GUCs migration
//! 077's `claims` and `edges` policies read.
//!
//! **`find_workflow_hierarchical`'s suppression is CONDITIONAL, and saying so
//! is the point.** `resolve_to_latest` is `#[serde(default)] bool`, i.e. false
//! unless the caller opts in. On that default path the handler runs only
//! `find_hierarchical_by_embedding` and/or `search_hierarchical_by_text`, both
//! widened WITHOUT a `&Viewer`, and both read `workflows` alone — a table which
//! at migration head 92 has neither `relrowsecurity` nor a `visibility` or
//! `owner_group_id` column. So on a default request the stamp selects no policy
//! and the viewer filters no row: THE VISIBLE ROW SET IS UNCHANGED BY THE
//! CONVERSION. The ONE statement in the handler that narrows is
//! `resolve_steps_to_heads_batched`, and it is inside `if resolve_to_latest`.
//! The table-level gap is already recorded, with its owner, under
//! `D-PR16-per-id-claim-oracles-write-half`; nothing further is recorded here —
//! see `docs/tenancy/progress.json`.
//!
//! **Both search handlers take the connection AFTER their embedding call, not at
//! the handler head.** `embedder.generate` leaves the process, and holding one of
//! the request pool's connections across a round trip to a third party buys
//! nothing.
//!
//! **THE COST THIS BUYS THE SINGLE-STAMP PROPERTY WITH, STATED RATHER THAN
//! DISCOVERED IN PRODUCTION.** `limit` clamps to `[1, 50]`, and the per-result
//! reads are sequential inside the borrow, so `search_workflows` holds ONE
//! `ScopedRead` across up to ~102 round trips on the embedding branch and ~51 on
//! the text branch; `find_workflow_hierarchical` holds one across its ANN read,
//! ILIKE fallback and `resolve_steps_to_heads_batched`. Before the conversion
//! each statement drew from the pool independently. Under
//! `SessionGucMode::Transaction` a `ScopedRead` IS a transaction, so on a
//! pooler deployment that is one open transaction and one pinned pool slot per
//! in-flight search. This is the class `F-PR26-lineage-holds-one-connection-for-n-round-trips`
//! owns (`routes/lineage.rs::get_lineage`); that entry stays open and this shard
//! does not discharge it. `rolling_success_rate` and `find_lineage_root` are
//! both batchable over `r.claim_id`, which would collapse the ~100 to 2, but
//! that is a separable change with its own acceptance.
//!
//! **Errors that were previously swallowed now propagate**, and that is a
//! consequence of the conversion rather than an unrelated tidy-up: once every
//! statement shares one connection, a failure is evidence about the connection
//! the rest of the handler is about to reuse, not an isolated per-statement
//! miss. Four defaults were removed —
//! `behavioral_affinity_lineage`'s empty-map fallback, `find_lineage_root`'s
//! substitution of the row's own id, and `rolling_success_rate`'s two
//! `if let Ok(..)` arms — plus `find_hierarchical_by_embedding`'s
//! `.unwrap_or_default()`, which turned a database failure into "the ANN search
//! matched nothing" and fell through to the ILIKE path with a 200. An ABSENT
//! embedder is still not an error and still falls through.
//!
//! **That propagation is a POLICY choice, not one the conversion forces, and
//! the distinction is measured rather than assumed.** `SessionGucMode::from_env`
//! selects `Session` for everything except the exact string `transaction`, so
//! `Session` is the DEFAULT deployment. Only under `Transaction` does a failed
//! statement abort the surrounding transaction and make every later statement on
//! the same `ScopedRead` fail anyway; under `Session` the connection stays
//! usable and the old degrade-gracefully behaviour would still have worked. It
//! was dropped because a silently truncated answer is a worse failure than a
//! 500 — not because the borrow made it impossible. The five newly-propagating
//! sites log through `tracing::error!` and return a FIXED message, matching what
//! the `read_as` acquisition sites in this file do; the pre-existing
//! `find_by_embedding` / `find_by_text` / `search_hierarchical_by_text` sites
//! still interpolate their `DbError` and are left alone, because that class
//! belongs to `F-route-error-text-remainder` and not to a read shard.
//!
//! The other 30 sites are NOT converted. 28 sit in WRITE handlers
//! (`store_workflow`, `report_outcome`, `deprecate_workflow`,
//! `report_hierarchical_outcome`, `ingest_workflow`,
//! `record_behavioral_execution`, `evolve_step`, `add_step`, `delete_step`):
//! [`AppState::read_as`] is documented read-only, and a write routed through a
//! `ScopedRead` is rolled back on drop under `SessionGucMode::Transaction` while
//! still type-checking. Their owner is `ScopedPool::begin_as` plus
//! `Viewer::splice_write`. The remaining 2 are `get_workflow`, a routed GET that
//! holds no `Viewer` at all — adding a `ViewerExtractor` to a routed handler is
//! a route-table change with its own acceptance, not a read-shard conversion.
//! Its owner is `F-inline-claim-content-reads`, whose UNCOMPENSATED half carries
//! this file's 4 and whose `assigned` field calls it LIVE rather than latent;
//! `viewer_route_table_lint.rs::UNCOMPENSATED_INLINE_READS` still carries
//! `("workflows.rs", 4)` accordingly. Nothing further about it is recorded
//! here — see `docs/tenancy/progress.json`.
//!
//! `deprecate_workflow` additionally carries an open entry whose owner is the
//! write-gate programme, not a read shard: `F-write-authz-reads-unfiltered`.
//! This shard does not touch it and it stays open. Nothing further about it is
//! recorded here — see `docs/tenancy/progress.json`.
//!
//! `viewer_route_table_lint.rs::UNCOMPENSATED_INLINE_READS` still carries
//! `("workflows.rs", 4)` and `ROUTE_LAYER_WRITES` still carries
//! `("workflows.rs", 4)`; all eight sit in unconverted handlers and no inline
//! statement was relocated.
//!
//! [`AppState::read_as`]: crate::AppState::read_as

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
use crate::middleware::bearer::ViewerExtractor;
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
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ReportOutcomeRequest {
    pub success: bool,
    pub outcome_details: String,
    pub quality: Option<f64>,
    pub step_executions: Option<Vec<StepExecution>>,
    pub goal_text: Option<String>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct StepExecution {
    pub step_index: usize,
    pub planned: String,
    pub actual: String,
    pub deviated: bool,
    pub deviation_reason: Option<String>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct DeprecateQuery {
    pub reason: String,
    pub cascade: Option<bool>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct HierarchicalSearchQuery {
    pub q: String,
    pub limit: Option<i64>,
    #[serde(default)]
    pub resolve_to_latest: bool,
    /// Minimum `truth_value` to surface. Defaults to 0.3 so rows
    /// deprecated via `deprecate_workflow` (truth=0.05) drop out.
    pub min_truth: Option<f64>,
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

/// Response body for `GET /api/v1/workflows/hierarchical/search`.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct HierarchicalSearchResponse {
    pub workflows: Vec<HierarchicalWorkflowResult>,
    pub total: usize,
    pub resolve_to_latest: bool,
}

/// A single workflow entry within [`HierarchicalSearchResponse`].
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct HierarchicalWorkflowResult {
    pub workflow_id: uuid::Uuid,
    pub canonical_name: String,
    pub generation: i32,
    pub goal: String,
    pub parent_id: Option<uuid::Uuid>,
    pub metadata: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Deprecation signal: 1.0 for live rows; `deprecate_workflow`
    /// cascades 0.05 onto this column.
    pub truth_value: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_steps: Option<Vec<ResolvedStepResult>>,
}

/// Per-step resolution result within [`HierarchicalWorkflowResult`].
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct ResolvedStepResult {
    pub step_index: usize,
    pub frozen_claim_id: uuid::Uuid,
    pub step_lineage_id: Option<uuid::Uuid>,
    pub heads: Vec<LineageHeadResult>,
    pub pending_resolution: bool,
}

/// A lineage head within [`ResolvedStepResult`].
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct LineageHeadResult {
    pub id: uuid::Uuid,
    pub content: String,
    pub truth_value: f64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ── Handlers ──

/// Slugify a free-text goal into a `canonical_name`. Inlined here to avoid
/// pulling `epigraph-mcp` as a dep for one helper. Will collapse with the
/// migrate_flat::slugify duplicate when migrate_flat is deleted.
fn slugify_goal(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// POST /api/v1/workflows — store a hierarchical workflow.
///
/// Input shape stays simple (`goal` + `steps[]`); internally constructs a
/// `WorkflowExtraction` (single `"Body"` phase, thesis = goal) and runs
/// `execute_workflow_ingest_plan`. Each step becomes a first-class claim.
/// Idempotent on `(slugify(goal), generation=0)`.
#[cfg(feature = "db")]
pub async fn store_workflow(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Json(request): Json<StoreWorkflowRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use epigraph_ingest::common::schema::ThesisDerivation;
    use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
    use epigraph_ingest::workflow::WorkflowExtraction;

    let canonical_name = slugify_goal(&request.goal);
    let prereqs = request.prerequisites.unwrap_or_default();
    let tags = request.tags.unwrap_or_default();
    let confidence = request.confidence.unwrap_or(0.8).clamp(0.0, 1.0);

    let phases = if request.steps.is_empty() {
        vec![]
    } else {
        vec![Phase {
            title: "Body".to_string(),
            // Phase claim content = summary; DB enforces non-empty. Using
            // "Body" matches the migrate_flat convention and avoids a hash
            // collision with the thesis claim (which uses goal).
            summary: "Body".to_string(),
            steps: request
                .steps
                .iter()
                .map(|t| Step {
                    compound: t.clone(),
                    rationale: String::new(),
                    operations: vec![],
                    generality: vec![],
                    confidence,
                    // Flat steps have no operation atoms → no evidence_type source.
                    evidence_type: None,
                })
                .collect(),
        }]
    };

    let extraction = WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical_name.clone(),
            goal: request.goal.clone(),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: request.expected_outcome.clone(),
            tags: tags.clone(),
            metadata: serde_json::json!({"prerequisites": prereqs}),
        },
        thesis: Some(request.goal.clone()),
        thesis_derivation: ThesisDerivation::default(),
        phases,
        relationships: vec![],
    };

    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);
    let mut tx = begin_system_ingest_stamped_tx(&state, "workflows/ingest").await?;
    let result =
        epigraph_ingest_executor::execute_workflow_ingest_plan(&mut tx, &plan, &extraction)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("workflow ingest: {e}"),
            })?;
    tx.commit().await.map_err(|e| ApiError::InternalError {
        message: format!("workflow ingest: could not commit: {e}"),
    })?;

    auto_wire_inserted_edges(&state, &viewer, &result).await;

    // Embed inline, best-effort. Satisfies the is_current=true → has-embedding
    // invariant (CLAUDE.md "Embedding policy"). Failures warn and continue.
    if let Some(embedder) = state.embedding_service() {
        let wf_id = result.workflow_id;
        for (claim_id, content) in &result.inserted {
            match embedder.generate(content).await {
                Ok(embedding) => {
                    let pgvector_str = format_embedding(&embedding);
                    if let Err(e) =
                        sqlx::query("UPDATE claims SET embedding = $1::vector WHERE id = $2")
                            .bind(&pgvector_str)
                            .bind(*claim_id)
                            .execute(&state.db_pool)
                            .await
                    {
                        tracing::warn!(claim_id = %claim_id, error = %e, "Failed to store embedding for ingested workflow claim");
                    }
                }
                Err(e) => {
                    tracing::warn!(claim_id = %claim_id, error = %e, "Failed to generate embedding for ingested workflow claim");
                }
            }
        }
        // Also embed into workflows.goal_embedding for find_workflow_hierarchical.
        match embedder.generate(&request.goal).await {
            Ok(qvec) => {
                if let Err(e) = epigraph_db::WorkflowRepository::set_goal_embedding(
                    &state.db_pool,
                    wf_id,
                    &qvec,
                )
                .await
                {
                    tracing::warn!(workflow_id=%wf_id, error=?e, "set_goal_embedding failed");
                }
            }
            Err(e) => {
                tracing::warn!(workflow_id=%wf_id, error=?e, "goal embedding generation failed for workflow goal");
            }
        }
    }

    // Emit event
    let _ = epigraph_db::EventRepository::insert(
        &state.db_pool,
        "workflow.created",
        None,
        &serde_json::json!({
            "workflow_id": result.workflow_id,
            "canonical_name": result.canonical_name,
            "goal": request.goal,
            "step_count": request.steps.len(),
            "already_ingested": result.already_ingested,
        }),
    )
    .await;

    Ok(Json(serde_json::json!({
        "workflow_id": result.workflow_id,
        "canonical_name": result.canonical_name,
        "goal": request.goal,
        "generation": result.generation,
        "step_count": request.steps.len(),
        "claims_ingested": result.claims_ingested,
        "already_ingested": result.already_ingested,
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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Query(params): Query<SearchWorkflowsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let min_truth = params.min_truth.unwrap_or(0.3);
    let limit = params.limit.unwrap_or(5).clamp(1, 50);

    // Try embedding search first
    if let Some(embedder) = state.embedding_service() {
        if let Ok(query_vec) = embedder.generate(&params.goal).await {
            // THE CONNECTION IS TAKEN HERE, NOT AT THE HANDLER HEAD.
            // `embedder.generate` above leaves the process; acquiring before it
            // would hold one of the request pool's connections across a network
            // round trip to a third party for no benefit. Everything below this
            // point — the ANN search, the affinity lookup, and the per-result
            // lineage-root and success-rate reads — runs on this ONE stamped
            // connection, so the whole answer is assembled under one tenancy
            // stamp.
            let mut read = state.read_as(&viewer).await.map_err(|e| {
                tracing::error!(
                    target: "tenancy.scoped_read",
                    error = %e,
                    handler = "search_workflows",
                    "could not acquire a viewer-stamped connection"
                );
                ApiError::InternalError {
                    message: "Failed to acquire a scoped connection".to_string(),
                }
            })?;

            let results = epigraph_db::WorkflowRepository::find_by_embedding(
                &mut *read, &viewer, &query_vec, min_truth, limit,
            )
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to search workflows: {e}"),
            })?;

            // Behavioral affinity lookup
            let pgvec = format!(
                "[{}]",
                query_vec
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            //
            // PROPAGATE, do not default. This read now shares one connection
            // with every other statement in the handler, so a failure here is
            // no longer an isolated per-statement miss: it is evidence that the
            // stamped connection is unusable, and defaulting to an empty map
            // would answer 200 with silently degraded results computed on a
            // connection whose tenancy state is in doubt.
            let affinity_map: std::collections::HashMap<uuid::Uuid, (f64, i64)> =
                epigraph_db::BehavioralExecutionRepository::behavioral_affinity_lineage(
                    &mut *read, &viewer, &pgvec, 0.5, 1, 20,
                )
                .await
                .map_err(|e| {
                    tracing::error!(
                        target: "tenancy.scoped_read",
                        error = %e,
                        handler = "search_workflows",
                        statement = "behavioral_affinity_lineage",
                        "statement failed on the viewer-stamped connection"
                    );
                    ApiError::InternalError {
                        message: "Failed to search workflows".to_string(),
                    }
                })?
                .into_iter()
                .map(|(id, sim, count)| (id, (sim, count)))
                .collect();

            let mut workflows: Vec<serde_json::Value> = Vec::new();
            for r in &results {
                let mut json = workflow_recall_to_json(r);

                // PROPAGATE, do not substitute. Defaulting to `r.claim_id`
                // silently turned a failed lineage walk into "this workflow IS
                // its own lineage root", which is a different answer rather
                // than a missing one — and on a shared connection the failure
                // is a property of the connection, not of this row.
                let lineage_root = epigraph_db::WorkflowRepository::find_lineage_root(
                    &mut *read, &viewer, r.claim_id,
                )
                .await
                .map_err(|e| {
                    tracing::error!(
                        target: "tenancy.scoped_read",
                        error = %e,
                        handler = "search_workflows",
                        statement = "find_lineage_root",
                        "statement failed on the viewer-stamped connection"
                    );
                    ApiError::InternalError {
                        message: "Failed to search workflows".to_string(),
                    }
                })?;

                if let Some(&(affinity, count)) = affinity_map.get(&lineage_root) {
                    json["behavioral_affinity"] = serde_json::json!(affinity);
                    json["behavioral_execution_count"] = serde_json::json!(count);

                    let rate = epigraph_db::BehavioralExecutionRepository::rolling_success_rate(
                        &mut *read, r.claim_id, 20,
                    )
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            target: "tenancy.scoped_read",
                            error = %e,
                            handler = "search_workflows",
                            statement = "rolling_success_rate",
                            "statement failed on the viewer-stamped connection"
                        );
                        ApiError::InternalError {
                            message: "Failed to search workflows".to_string(),
                        }
                    })?;
                    if rate > 0.0 {
                        json["behavioral_success_rate"] = serde_json::json!(rate);
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

    // Fallback: text search. A SECOND acquisition rather than one hoisted to
    // the handler head, for the same reason the embedding branch takes its own:
    // this path is reached when there is no embedder OR when `generate` failed,
    // i.e. after the same outbound call, and hoisting would hold a connection
    // across it.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "search_workflows",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let results = epigraph_db::WorkflowRepository::find_by_text(
        &mut *read,
        &viewer,
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

        // PROPAGATE, do not default: see the embedding branch above.
        let rate = epigraph_db::BehavioralExecutionRepository::rolling_success_rate(
            &mut *read, r.claim_id, 20,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                target: "tenancy.scoped_read",
                error = %e,
                handler = "search_workflows",
                statement = "rolling_success_rate",
                "statement failed on the viewer-stamped connection"
            );
            ApiError::InternalError {
                message: "Failed to search workflows".to_string(),
            }
        })?;
        if rate > 0.0 {
            json["behavioral_success_rate"] = serde_json::json!(rate);
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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Query(params): Query<ListWorkflowsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let min_truth = params.min_truth.unwrap_or(0.0);

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "list_workflows",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let workflows =
        epigraph_db::WorkflowRepository::list(&mut *read, &viewer, min_truth, None, limit)
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

/// GET /api/v1/workflows/:id - Fetch a single workflow by ID.
///
/// Probes the `workflows` table (hierarchical) first; falls through to the
/// legacy flat-workflow claims path. Returns 404 only when the id is absent
/// from both tables.
///
/// Response fields common to both paths:
/// - `workflow_id`: the UUID
/// - `content`: goal text (hierarchical) or claim content (flat, may be JSON)
/// - `goal`: goal text (hierarchical) or `null` (flat)
/// - `truth_value`: workflow truth / claim truth_value
/// - `properties`: metadata JSONB (hierarchical) or claim properties (flat)
/// - `canonical_name`: canonical_name (hierarchical) or `null` (flat)
#[cfg(feature = "db")]
pub async fn get_workflow(
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // ── 1. Try hierarchical workflows table ─────────────────────────────────
    let hier: Option<WorkflowHierarchicalRow> = sqlx::query_as::<_, WorkflowHierarchicalRow>(
        "SELECT id, canonical_name, goal, truth_value, metadata \
         FROM workflows WHERE id = $1",
    )
    .bind(workflow_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch hierarchical workflow: {e}"),
    })?;

    if let Some(row) = hier {
        return Ok(Json(serde_json::json!({
            "workflow_id": row.id,
            "content": row.goal,
            "goal": row.goal,
            "truth_value": row.truth_value,
            "properties": row.metadata,
            "canonical_name": row.canonical_name,
        })));
    }

    // ── 2. Fall through to legacy flat-workflow claims ───────────────────────
    let row = sqlx::query_as::<_, WorkflowContentRow>(
        "SELECT id, content, truth_value, properties \
         FROM claims WHERE id = $1 AND 'workflow' = ANY(labels)",
    )
    .bind(workflow_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch workflow claim: {e}"),
    })?
    .ok_or(ApiError::NotFound {
        entity: "workflow".to_string(),
        id: workflow_id.to_string(),
    })?;

    Ok(Json(serde_json::json!({
        "workflow_id": row.id,
        "content": serde_json::from_str::<serde_json::Value>(&row.content)
            .unwrap_or(serde_json::Value::String(row.content)),
        "goal": serde_json::Value::Null,
        "truth_value": row.truth_value,
        "properties": row.properties,
        "canonical_name": serde_json::Value::Null,
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
        run_label: None,
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
#[utoipa::path(
    get,
    path = "/api/v1/workflows/hierarchical/search",
    params(HierarchicalSearchQuery),
    responses(
        (status = 200, body = HierarchicalSearchResponse),
        (status = 500),
    ),
    security(("ed25519_signature" = [])),
    tag = "workflows"
)]
pub async fn find_workflow_hierarchical(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Query(params): Query<HierarchicalSearchQuery>,
) -> Result<Json<HierarchicalSearchResponse>, ApiError> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);
    let min_truth = params.min_truth.unwrap_or(0.3);
    let similarity_threshold = 0.5_f64;

    // Embedding-first to tolerate paraphrasing; ILIKE fallback for short
    // queries, when embedder is unavailable, or when no embedded rows clear
    // the similarity floor.
    // The embedding attempt comes FIRST and the connection is taken after it:
    // `embedder.generate` leaves the process, and holding a pooled connection
    // across that round trip buys nothing. Every statement below this point —
    // the ANN read, the ILIKE fallback and `resolve_steps_to_heads_batched`'s
    // two round trips — then runs on the ONE stamped connection.
    let qvec = match state.embedding_service() {
        Some(embedder) => embedder.generate(&params.q).await.ok(),
        None => None,
    };

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "find_workflow_hierarchical",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // PROPAGATE, do not default. `.unwrap_or_default()` here turned a database
    // failure into an empty `rows`, which then fell through to the ILIKE path
    // and answered 200 — indistinguishable from "the ANN search matched
    // nothing". On a shared connection that is no longer a per-statement miss:
    // a failure is a property of the connection the rest of the handler is
    // about to reuse. An ABSENT embedder or an embedder that could not produce
    // a vector is still the fallback case, and still not an error; only a
    // failed READ propagates.
    let mut rows = match qvec {
        Some(qvec) => epigraph_db::WorkflowRepository::find_hierarchical_by_embedding(
            &mut *read,
            &qvec,
            similarity_threshold,
            min_truth,
            limit,
            params.resolve_to_latest,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                target: "tenancy.scoped_read",
                error = %e,
                handler = "find_workflow_hierarchical",
                statement = "find_hierarchical_by_embedding",
                "statement failed on the viewer-stamped connection"
            );
            ApiError::InternalError {
                message: "hierarchical search failed".to_string(),
            }
        })?,
        None => Vec::new(),
    };

    if rows.is_empty() {
        rows = epigraph_db::WorkflowRepository::search_hierarchical_by_text(
            &mut *read,
            &params.q,
            limit,
            min_truth,
            params.resolve_to_latest,
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("hierarchical search failed: {e}"),
        })?;
    }

    let mut workflows: Vec<HierarchicalWorkflowResult> = rows
        .into_iter()
        .map(|r| HierarchicalWorkflowResult {
            workflow_id: r.id,
            canonical_name: r.canonical_name,
            generation: r.generation,
            goal: r.goal,
            parent_id: r.parent_id,
            metadata: r.metadata,
            created_at: r.created_at,
            truth_value: r.truth_value,
            resolved_steps: None,
        })
        .collect();

    if params.resolve_to_latest {
        let workflow_ids: Vec<uuid::Uuid> = workflows.iter().map(|w| w.workflow_id).collect();
        let mut resolved_by_workflow =
            epigraph_db::WorkflowRepository::resolve_steps_to_heads_batched(
                &mut read,
                &viewer,
                &workflow_ids,
            )
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("resolve_to_latest failed: {e}"),
            })?;
        for w in &mut workflows {
            let resolved = resolved_by_workflow
                .remove(&w.workflow_id)
                .unwrap_or_default();
            w.resolved_steps = Some(
                resolved
                    .into_iter()
                    .map(|s| ResolvedStepResult {
                        step_index: s.step_index,
                        frozen_claim_id: s.frozen_claim_id,
                        step_lineage_id: s.step_lineage_id,
                        heads: s
                            .heads
                            .into_iter()
                            .map(|h| LineageHeadResult {
                                id: h.id,
                                content: h.content,
                                truth_value: h.truth_value,
                                created_at: h.created_at,
                            })
                            .collect(),
                        pending_resolution: s.pending_resolution,
                    })
                    .collect(),
            );
        }
    }

    let total = workflows.len();
    Ok(Json(HierarchicalSearchResponse {
        workflows,
        total,
        resolve_to_latest: params.resolve_to_latest,
    }))
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
#[utoipa::path(
    post,
    path = "/api/v1/workflows/hierarchical/{id}/outcome",
    params(("id" = uuid::Uuid, Path, description = "UUID of the hierarchical workflow")),
    request_body = serde_json::Value,
    responses(
        (status = 200, body = serde_json::Value),
        (status = 404),
        (status = 500),
    ),
    security(("ed25519_signature" = [])),
    tag = "workflows"
)]
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
    let use_count = metadata
        .get("use_count")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        + 1;
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
                run_label: None,
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

/// POST /api/v1/workflows/steps/:id/evolve — atomically evolve a step claim.
#[derive(Debug, serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
pub struct EvolveStepRequest {
    pub parent_id: uuid::Uuid,
    pub content: String,
    /// "supersedes" (linear; flips is_current) or "revises" (parallel branch).
    pub edge_type: String,
    pub reason: Option<String>,
    /// 2 (step) or 3 (operation). Default 2.
    pub level: Option<u32>,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct EvolveStepResponse {
    pub claim_id: uuid::Uuid,
    pub step_lineage_id: uuid::Uuid,
    pub edge_type: String,
    pub edge_id: uuid::Uuid,
}

#[cfg(feature = "db")]
#[utoipa::path(
    post,
    path = "/api/v1/workflows/steps/{id}/evolve",
    params(("id" = uuid::Uuid, Path, description = "UUID of the parent step claim")),
    request_body = EvolveStepRequest,
    responses(
        (status = 200, body = EvolveStepResponse),
        (status = 400),
        (status = 401),
        (status = 404),
    ),
    security(("ed25519_signature" = [])),
    tag = "workflows"
)]
pub async fn evolve_step(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(parent_id): Path<Uuid>,
    Json(req): Json<EvolveStepRequest>,
) -> Result<Json<EvolveStepResponse>, ApiError> {
    let auth = match auth_ctx {
        Some(axum::Extension(ref a)) => a.clone(),
        None => {
            return Err(ApiError::Unauthorized {
                reason: "evolve_step requires authentication".into(),
            });
        }
    };
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])?;

    if req.parent_id != parent_id {
        return Err(ApiError::BadRequest {
            message: "parent_id in path and body must match".into(),
        });
    }
    let agent = auth.owner_id.unwrap_or(auth.client_id);
    let level = req.level.unwrap_or(2);
    let result = epigraph_db::ClaimRepository::evolve_step(
        &state.db_pool,
        epigraph_core::ClaimId::from_uuid(parent_id),
        &req.content,
        &req.edge_type,
        req.reason.as_deref(),
        level,
        agent,
    )
    .await
    .map_err(|e| match e {
        epigraph_db::DbError::NotFound { id, .. } => ApiError::NotFound {
            entity: "Claim".into(),
            id: id.to_string(),
        },
        other => ApiError::InternalError {
            message: other.to_string(),
        },
    })?;

    Ok(Json(EvolveStepResponse {
        claim_id: result.new_claim_id,
        step_lineage_id: result.step_lineage_id,
        edge_type: result.edge_type,
        edge_id: result.edge_id,
    }))
}

/// DELETE /api/v1/workflows/:id - Deprecate a workflow.
#[cfg(feature = "db")]
#[utoipa::path(
    delete,
    path = "/api/v1/workflows/{id}",
    params(
        ("id" = uuid::Uuid, Path, description = "UUID of the workflow to deprecate"),
        ("reason" = String, Query, description = "Reason for deprecation"),
        ("cascade" = Option<bool>, Query, description = "Whether to cascade deprecation to descendants"),
    ),
    responses(
        (status = 200, body = serde_json::Value),
        (status = 404),
        (status = 500),
    ),
    security(("ed25519_signature" = [])),
    tag = "workflows"
)]
pub async fn deprecate_workflow(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
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
            epigraph_db::WorkflowRepository::find_descendants(&state.db_pool, &viewer, workflow_id)
                .await
                .unwrap_or_default();
        ids_to_deprecate.extend(descendants);
    }

    // Set truth to near-zero AND mark not-current for all.
    //
    // `is_current = false` is required so the deprecated workflow disappears
    // from `WorkflowRepository::list` regardless of the caller's `min_truth`
    // parameter. Before this fix, callers passing `min_truth = 0.0` (the
    // common default) still saw deprecated workflows because 0.05 > 0.0.
    // See epigraph-io/epigraph#36.
    for id in &ids_to_deprecate {
        // deprecate_claim also nulls the embedding (CLAUDE.md "Embedding
        // policy → Cleanup paths"); the prior bare UPDATE left a non-NULL
        // embedding on an is_current=false row, inflating `stale_present`.
        // (It additionally sets `updated_at = NOW()`, which the prior bare
        // UPDATE here omitted — a benign, more-correct side effect of
        // unifying on the repo method.)
        let _ = epigraph_db::ClaimRepository::deprecate_claim(
            &state.db_pool,
            epigraph_core::ClaimId::from_uuid(*id),
        )
        .await;
        // Mirror onto the hierarchical `workflows` row when one exists
        // (no-op for flat-only workflows). Without this, deprecated
        // hierarchical workflows keep surfacing in
        // `GET /api/v1/workflows/hierarchical/search`.
        let _ = epigraph_db::WorkflowRepository::set_truth_value(&state.db_pool, *id, 0.05).await;
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
        run_label: None,
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
#[utoipa::path(
    post,
    path = "/api/v1/workflows/ingest",
    request_body = serde_json::Value,
    responses(
        (status = 200, body = serde_json::Value),
        (status = 500),
    ),
    security(("ed25519_signature" = [])),
    tag = "workflows"
)]
pub async fn ingest_workflow(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Json(extraction): Json<epigraph_ingest::workflow::WorkflowExtraction>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);
    let mut tx = begin_system_ingest_stamped_tx(&state, "workflows/ingest").await?;
    let result =
        epigraph_ingest_executor::execute_workflow_ingest_plan(&mut tx, &plan, &extraction)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("workflow ingest: {e}"),
            })?;
    tx.commit().await.map_err(|e| ApiError::InternalError {
        message: format!("workflow ingest: could not commit: {e}"),
    })?;

    auto_wire_inserted_edges(&state, &viewer, &result).await;

    // Embed inline, best-effort. Satisfies the is_current=true → has-embedding
    // invariant (CLAUDE.md "Embedding policy"). Failures warn and continue.
    if let Some(embedder) = state.embedding_service() {
        let wf_id = result.workflow_id;
        for (claim_id, content) in &result.inserted {
            match embedder.generate(content).await {
                Ok(embedding) => {
                    let pgvector_str = format_embedding(&embedding);
                    if let Err(e) =
                        sqlx::query("UPDATE claims SET embedding = $1::vector WHERE id = $2")
                            .bind(&pgvector_str)
                            .bind(*claim_id)
                            .execute(&state.db_pool)
                            .await
                    {
                        tracing::warn!(claim_id = %claim_id, error = %e, "Failed to store embedding for ingested workflow claim");
                    }
                }
                Err(e) => {
                    tracing::warn!(claim_id = %claim_id, error = %e, "Failed to generate embedding for ingested workflow claim");
                }
            }
        }
        // Also embed into workflows.goal_embedding for find_workflow_hierarchical.
        match embedder.generate(&extraction.source.goal).await {
            Ok(qvec) => {
                if let Err(e) = epigraph_db::WorkflowRepository::set_goal_embedding(
                    &state.db_pool,
                    wf_id,
                    &qvec,
                )
                .await
                {
                    tracing::warn!(workflow_id=%wf_id, error=?e, "set_goal_embedding failed");
                }
            }
            Err(e) => {
                tracing::warn!(workflow_id=%wf_id, error=?e, "goal embedding generation failed for workflow goal");
            }
        }
    }

    Ok(Json(serde_json::json!({
        "workflow_id": result.workflow_id,
        "canonical_name": result.canonical_name,
        "generation": result.generation,
        "claims_ingested": result.claims_ingested,
        "claims_skipped_dedup": result.claims_skipped_dedup,
        "executes_edges": result.executes_edges_created,
        "relationships_created": result.relationship_edges_created,
        "already_ingested": result.already_ingested,
    })))
}

// ── Internal helpers ──

/// Begin the ONE transaction a workflow-ingest write runs in, stamped from the
/// **`workflow-ingest-system`** agent's viewer.
///
/// The HTTP twin of `epigraph-mcp`'s
/// `claim_helper::begin_system_ingest_stamped_tx`, and identical in substance:
/// `epigraph_ingest_executor` authors every row as
/// `get_or_create_system_agent` and owns it with that agent's personal group, so
/// migration 077's `WITH CHECK` on `claims` refuses the walk on an unstamped
/// connection and refuses it just as firmly when stamped from the HTTP
/// PRINCIPAL. The principal's viewer is the wrong answer here for exactly the
/// reason `server.agent_id()` is on the MCP side — see
/// `epigraph_ingest_executor::system_agent_write_authority` for the measurement.
///
/// # Errors
/// `ApiError::InternalError` if the system agent has no write authority, if the
/// process was not built through `AppState::with_scoped_pool`, or if the stamp
/// fails. Never a fallback to `state.db_pool`.
#[cfg(feature = "db")]
pub(crate) async fn begin_system_ingest_stamped_tx<'s>(
    state: &'s AppState,
    route: &'static str,
) -> Result<epigraph_db::ScopedTx<'s>, ApiError> {
    let scoped = state.scoped.as_ref().ok_or_else(|| {
        tracing::error!(
            target: "tenancy.scoped_write",
            route = route,
            "write refused: this process was not built from a ScopedPool, so no connection can \
             be stamped with the ingest system agent's tenancy context."
        );
        ApiError::InternalError {
            message: format!(
                "{route}: this server was not built from a ScopedPool, so the workflow ingest \
                 path cannot stamp a connection. Nothing was written."
            ),
        }
    })?;

    let authority = epigraph_ingest_executor::system_agent_write_authority(scoped)
        .await
        .map_err(|e| {
            tracing::error!(
                target: "tenancy.scoped_write",
                route = route,
                error = %e,
                "write refused: could not establish the workflow-ingest-system agent's write \
                 authority. Nothing was written."
            );
            ApiError::InternalError {
                message: format!(
                    "{route}: could not establish the workflow-ingest-system agent's write \
                     authority: {e}. Nothing was written."
                ),
            }
        })?;

    scoped
        .begin_as(&authority.viewer)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("{route}: could not begin a system-agent-stamped transaction: {e}"),
        })
}

#[cfg(feature = "db")]
pub(crate) async fn get_or_create_system_agent(pool: &sqlx::PgPool) -> Result<Uuid, ApiError> {
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
        let agent =
            epigraph_core::Agent::new(pub_key_bytes, Some("workflow-ingest-system".to_string()));
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

/// Fire `auto_wire_edge_if_epistemic` for each plan edge the executor newly
/// inserted. Best-effort (the helper logs and swallows individual failures).
/// Source-claim agent attribution is handled by the engine helper via
/// `system_agent_id` from the executor result.
/// Stamped from the `workflow-ingest-system` agent's viewer, like the plan walk
/// it follows: the `claim_frames` / `mass_functions` / cached-belief rows it
/// writes are claim-derived, so migrations 074/070 fill their tenancy from the
/// ingest's own claims and the `WITH CHECK` asks about the SYSTEM agent's group.
/// On the unstamped pool these were refused on BOTH schema configurations —
/// `claim_frames` carries no orphan `*_privacy` policy.
///
/// Its own transaction rather than the ingest's, because this half is
/// best-effort: a DS failure must not roll back a workflow that landed. Inside
/// it, `auto_wire_edge_if_epistemic` SAVEPOINT-wraps each edge, so one failure
/// does not abort the rest.
async fn auto_wire_inserted_edges(
    state: &AppState,
    viewer: &epigraph_db::visibility::Viewer,
    result: &epigraph_ingest_executor::WorkflowIngestExecutionResult,
) {
    let Some(agent_id) = result.system_agent_id else {
        return;
    };
    let mut tx = match begin_system_ingest_stamped_tx(state, "workflows/ingest:ds").await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::warn!(
                workflow_id = %result.workflow_id,
                "workflow ds wiring skipped: {e}. The ingest is stored and intact"
            );
            return;
        }
    };
    for e in &result.inserted_edges {
        epigraph_engine::edge_factor::auto_wire_edge_if_epistemic(
            &mut tx,
            viewer,
            true, // executor only emits InsertedPlanEdge when was_created=true
            e.edge_id,
            e.source_id,
            &e.source_type,
            e.target_id,
            &e.target_type,
            &e.relationship,
            agent_id,
        )
        .await;
    }
    if let Err(e) = tx.commit().await {
        tracing::warn!(
            workflow_id = %result.workflow_id,
            "workflow ds wiring could not commit: {e}. The ingest is stored; its claims carry \
             no edge-factor BBA until a recompute reaches them"
        );
    }
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

#[cfg(feature = "db")]
#[derive(sqlx::FromRow)]
struct WorkflowHierarchicalRow {
    id: Uuid,
    canonical_name: String,
    goal: String,
    truth_value: f64,
    metadata: serde_json::Value,
}

// ── add_step / delete_step ──────────────────────────────────────────────────

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct AddStepRequest {
    pub canonical_name: String,
    pub step_text: String,
    #[serde(default)]
    pub position: Option<u32>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct DeleteStepRequest {
    pub canonical_name: String,
    pub step_lineage_id: Uuid,
}

/// Map executor's StepOpError to ApiError. WorkflowNotFound + StepNotFound
/// are 404; Invalid is 400; Db/Executor are 500.
#[cfg(feature = "db")]
fn map_step_err(e: epigraph_ingest_executor::StepOpError) -> ApiError {
    use epigraph_ingest_executor::StepOpError as E;
    match e {
        E::WorkflowNotFound(name) => ApiError::NotFound {
            entity: "workflow".into(),
            id: name,
        },
        E::StepNotFound { lineage, .. } => ApiError::NotFound {
            entity: "step".into(),
            id: lineage.to_string(),
        },
        E::PhaseMissing => ApiError::InternalError {
            message: "workflow has no level-1 phase claim".into(),
        },
        E::Invalid(msg) => ApiError::BadRequest { message: msg },
        E::Db(e) => ApiError::InternalError {
            message: format!("db: {e}"),
        },
        E::Repo(e) => ApiError::InternalError {
            message: format!("repo: {e}"),
        },
        E::Executor(e) => ApiError::InternalError {
            message: format!("executor: {e}"),
        },
    }
}

/// POST /api/v1/workflows/steps - add a step to a hierarchical workflow.
#[cfg(feature = "db")]
pub async fn add_step(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(req): Json<AddStepRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = auth_ctx.ok_or_else(|| ApiError::Unauthorized {
        reason: "add_step requires authentication".into(),
    })?;
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])?;

    let mut tx = begin_system_ingest_stamped_tx(&state, "workflows/steps").await?;
    let r = epigraph_ingest_executor::add_step(
        &mut tx,
        &req.canonical_name,
        &req.step_text,
        req.position,
    )
    .await
    .map_err(map_step_err)?;
    tx.commit().await.map_err(|e| ApiError::InternalError {
        message: format!("add_step: could not commit: {e}"),
    })?;

    Ok(Json(serde_json::json!({
        "workflow_id": r.workflow_id,
        "step_claim_id": r.step_claim_id,
        "step_index": r.step_index,
        "step_lineage_id": r.step_lineage_id,
        "already_present": r.already_present,
    })))
}

/// POST /api/v1/workflows/steps/delete - soft-delete a step lineage.
#[cfg(feature = "db")]
pub async fn delete_step(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(req): Json<DeleteStepRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = auth_ctx.ok_or_else(|| ApiError::Unauthorized {
        reason: "delete_step requires authentication".into(),
    })?;
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])?;

    let mut tx = begin_system_ingest_stamped_tx(&state, "workflows/steps/delete").await?;
    let r =
        epigraph_ingest_executor::delete_step(&mut tx, &req.canonical_name, req.step_lineage_id)
            .await
            .map_err(map_step_err)?;
    tx.commit().await.map_err(|e| ApiError::InternalError {
        message: format!("delete_step: could not commit: {e}"),
    })?;

    Ok(Json(serde_json::json!({
        "workflow_id": r.workflow_id,
        "step_claim_id": r.step_claim_id,
        "step_lineage_id": r.step_lineage_id,
        "truth_value": r.truth_value,
    })))
}

#[cfg(all(test, feature = "db"))]
mod tests {
    use super::*;
    use crate::state::{ApiConfig, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use sqlx::PgPool;
    use tower::ServiceExt;

    // ── Test scaffolding (modern style: #[sqlx::test]) ──

    /// Build a minimal AppState backed by the given pool.
    fn test_state(pool: PgPool) -> AppState {
        AppState::with_db(pool, ApiConfig::default())
    }

    /// Build a router exposing just the workflow GET-by-id route under test.
    fn workflow_router(state: AppState) -> Router {
        Router::new()
            .route("/api/v1/workflows/:id", get(get_workflow))
            .with_state(state)
    }

    /// Insert a system agent (mirrors `get_or_create_system_agent` but without
    /// going through the public API) and return its id.
    async fn ensure_system_agent(pool: &PgPool) -> Uuid {
        let pub_key = vec![0u8; 32];
        // Try existing first
        if let Some(id) =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM agents WHERE public_key = $1")
                .bind(&pub_key)
                .fetch_optional(pool)
                .await
                .unwrap()
        {
            return id;
        }
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
        )
        .bind(&pub_key)
        .bind("api-system-test")
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// Insert a workflow-labeled claim with the given goal and steps.
    /// Mirrors the canonical `store_workflow` SQL at workflows.rs:135.
    async fn seed_test_workflow(pool: &PgPool, goal: &str, steps: &[&str]) -> Uuid {
        let agent_id = ensure_system_agent(pool).await;
        let empty: Vec<&str> = vec![];
        let content = serde_json::json!({
            "goal": goal,
            "steps": steps,
            "prerequisites": empty,
            "expected_outcome": serde_json::Value::Null,
            "tags": empty,
        });
        let content_str = content.to_string();
        let content_hash = epigraph_crypto::ContentHasher::hash(content_str.as_bytes());
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties) \
             VALUES ($1, $2, $3, $4, ARRAY['workflow'], $5) RETURNING id",
        )
        .bind(&content_str)
        .bind(content_hash.as_slice())
        .bind(agent_id)
        .bind(0.5_f64)
        .bind(serde_json::json!({
            "generation": 0,
            "use_count": 0,
            "success_count": 0,
            "failure_count": 0,
            "avg_variance": 0.0,
        }))
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// Insert a plain (non-workflow-labeled) claim and return its id.
    async fn seed_plain_claim(pool: &PgPool, content: &str) -> Uuid {
        let agent_id = ensure_system_agent(pool).await;
        let content_hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(content)
        .bind(content_hash.as_slice())
        .bind(agent_id)
        .bind(0.5_f64)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn parse_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn parse_body_bytes(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).unwrap_or_else(
            |_| serde_json::json!({"error": String::from_utf8_lossy(bytes).to_string()}),
        )
    }

    /// PR-06: `ViewerExtractor` requires an `AuthContext` on the request, which
    /// the bearer middleware installs in production. Test routers built from a
    /// bare `Router::new()` carry none, so they 401 before reaching the handler.
    fn test_auth() -> crate::middleware::bearer::AuthContext {
        let id = uuid::Uuid::new_v4();
        crate::middleware::bearer::AuthContext {
            client_id: id,
            agent_id: Some(id),
            owner_id: Some(id),
            client_type: crate::middleware::bearer::ClientType::Service,
            scopes: vec![
                "claims:read".to_string(),
                "claims:write".to_string(),
                "edges:read".to_string(),
                "edges:write".to_string(),
                "workflows:read".to_string(),
                "workflows:write".to_string(),
            ],
            jti: uuid::Uuid::new_v4(),
        }
    }

    /// `POST /api/v1/workflows/ingest` now REFUSES rather than falling back to
    /// `state.db_pool`: the rows the executor writes are owned by the
    /// `workflow-ingest-system` agent's personal group, and a connection that
    /// cannot be stamped with that group's write authority is not one this
    /// handler will write on. So the router needs a state carrying a
    /// `ScopedPool`; `AppState::with_db` leaves `scoped: None` and the handler
    /// answers 500 with "this server was not built from a ScopedPool", which is
    /// the conversion working rather than an inconvenience to route around.
    ///
    /// Same caveat as [`scoped_test_state`]: this is NOT a conversion control.
    /// `with_scoped_pool` sets `db_pool = scoped.inner().clone()`, and
    /// `#[sqlx::test]` connects as a BYPASSRLS superuser, so the stamp is inert
    /// here. `scripts/e2e/probe-workflow.sh` is the instrument that observes it.
    async fn test_router(pool: sqlx::PgPool) -> axum::Router {
        use axum::routing::post;
        let state = scoped_test_state(&pool).await;
        axum::Router::new()
            .route("/api/v1/workflows/ingest", post(ingest_workflow))
            .layer(axum::Extension(test_auth()))
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

    // ── Tests ──

    #[sqlx::test(migrations = "../../migrations")]
    async fn get_workflow_returns_single_workflow(pool: PgPool) {
        let state = test_state(pool.clone());
        let workflow_id = seed_test_workflow(&pool, "deploy-canary", &["step1", "step2"]).await;

        let router = workflow_router(state);
        let response = router
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/workflows/{workflow_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = parse_body(response).await;
        assert_eq!(body["workflow_id"], workflow_id.to_string());
        assert!(body["content"].is_string() || body["content"].is_object());
        assert!(body["truth_value"].is_number());
        assert!(body["properties"].is_object());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn get_workflow_returns_404_for_non_workflow_claim(pool: PgPool) {
        let state = test_state(pool.clone());
        let claim_id = seed_plain_claim(&pool, "not a workflow").await;

        let router = workflow_router(state);
        let response = router
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/workflows/{claim_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn get_workflow_returns_hierarchical_workflow_by_id(pool: PgPool) {
        // Seed a row directly into the `workflows` table (same table that
        // `ingest_workflow`/`store_workflow` write to). The id is the
        // deterministic UUID that epiclaw-host's `workflow_id` field holds.
        let wf_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO workflows (id, canonical_name, generation, goal, metadata) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(wf_id)
        .bind("test-hier-workflow")
        .bind(0_i32)
        .bind("Synthesise recent nanofabrication findings.")
        .bind(serde_json::json!({"use_count": 0, "success_count": 0, "failure_count": 0}))
        .execute(&pool)
        .await
        .unwrap();

        let state = test_state(pool.clone());
        let router = workflow_router(state);
        let response = router
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/workflows/{wf_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = parse_body(response).await;
        assert_eq!(body["workflow_id"], wf_id.to_string());
        assert_eq!(
            body["goal"].as_str(),
            Some("Synthesise recent nanofabrication findings."),
            "goal must be the workflows.goal text"
        );
        assert_eq!(
            body["content"].as_str(),
            Some("Synthesise recent nanofabrication findings."),
            "content must equal goal for hierarchical workflows"
        );
        assert!(body["canonical_name"].as_str().is_some());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn ingest_workflow_http_returns_workflow_id(pool: PgPool) {
        let app = test_router(pool).await;

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
        let json = parse_body_bytes(&bytes);

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

    #[sqlx::test(migrations = "../../migrations")]
    async fn report_hierarchical_outcome_updates_workflow_metadata(pool: PgPool) {
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
        use crate::state::{ApiConfig, AppState};
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
                    .uri(format!(
                        "/api/v1/workflows/hierarchical/{workflow_id}/outcome"
                    ))
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let metadata: serde_json::Value =
            sqlx::query_scalar("SELECT metadata FROM workflows WHERE id = $1")
                .bind(workflow_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(metadata["use_count"], 1);
        assert_eq!(metadata["success_count"], 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn report_hierarchical_outcome_404s_on_unknown_id(pool: PgPool) {
        use crate::state::{ApiConfig, AppState};
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
                    .uri(format!("/api/v1/workflows/hierarchical/{unknown}/outcome"))
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Rebuild a connection URL for the database `pool` is connected to.
    ///
    /// `#[sqlx::test]` hands each arm a randomly-named private database but no
    /// URL, and [`scoped_test_state`] needs one to build its `ScopedPool`. Same
    /// move as `tests/viewer_fixture.rs::database_url_for` and
    /// `routes/edges.rs::tests::database_url_for`; duplicated because this is an
    /// in-crate `#[cfg(test)]` module and cannot reach the integration-test
    /// fixture. Without it the arm would seed the private database and the
    /// handler would read the SHARED one — a silent vacuous pass.
    async fn database_url_for(pool: &PgPool) -> String {
        let db: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(pool)
            .await
            .expect("current_database()");
        let base = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        // Strip the query string before touching the path, or `?sslmode=require`
        // would be mistaken for part of the database name.
        let (authority, query) = match base.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (base.as_str(), None),
        };
        let prefix = authority
            .trim_end_matches('/')
            .rsplit_once('/')
            .expect("DATABASE_URL must carry a database path")
            .0;
        match query {
            Some(q) => format!("{prefix}/{db}?{q}"),
            None => format!("{prefix}/{db}"),
        }
    }

    /// An `AppState` whose `scoped` pool is populated.
    ///
    /// Conversion shard 7 moved `find_workflow_hierarchical` onto
    /// [`AppState::read_as`], which HARD-REFUSES a state whose `scoped` is
    /// `None` — that refusal is the fail-closed behaviour the conversion exists
    /// to establish, not an inconvenience to route around. [`test_state`] above
    /// calls `AppState::with_db`, which leaves `scoped: None`, so the arm below
    /// would have started answering 500.
    ///
    /// THIS IS NOT A CONVERSION CONTROL. `with_scoped_pool` sets
    /// `db_pool = scoped.inner().clone()`, so the converted and the unconverted
    /// spellings read the SAME pool here and reverting the handler to
    /// `&state.db_pool` changes not one observable row in the arm below. The
    /// instrument that DOES observe it is
    /// `crates/epigraph-api/tests/shard7_routes_scoped_read.rs::split_state`,
    /// which gives `db_pool` a separate downgraded pool.
    ///
    /// `DATABASE_URL` is read again rather than taken from `state.db_pool` on
    /// purpose: `no_unscoped_pool.rs`'s scanner does not cut `#[cfg(test)]` and
    /// its `SCAN_ROOT` is `crates/epigraph-api/src`, so a `state.db_pool`
    /// written in this helper would count as an unconverted site and silently
    /// re-raise the row this shard just lowered.
    ///
    /// [`AppState::read_as`]: crate::AppState::read_as
    async fn scoped_test_state(pool: &PgPool) -> AppState {
        let url = database_url_for(pool).await;
        let scoped = epigraph_db::ScopedPool::connect(&url, epigraph_db::SessionGucMode::Session)
            .await
            .expect("connect a scoped pool");
        AppState::with_scoped_pool(scoped, ApiConfig::default())
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn find_workflow_hierarchical_returns_match(pool: PgPool) {
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

        let state = scoped_test_state(&pool).await;
        let app = axum::Router::new()
            .route(
                "/api/v1/workflows/hierarchical/search",
                axum::routing::get(find_workflow_hierarchical),
            )
            .layer(axum::Extension(test_auth()))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/workflows/hierarchical/search?q={canonical}"
                    ))
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
        assert!(
            found,
            "expected to find the seeded canonical_name in results"
        );
    }
}
