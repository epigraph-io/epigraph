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
//! described (`routes/lineage.rs::get_lineage`). That entry is now closed by the
//! lineage walk's own projection, which does not touch this handler: its
//! footprint above is unchanged. `rolling_success_rate` and `find_lineage_root` are
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
//! `deprecate_workflow`'s existence gate (`F-write-authz-reads-unfiltered`) is
//! now viewer-filtered on a stamped connection (batch H6): a caller cannot
//! deprecate a workflow claim it cannot read. Its writes are still among the
//! unconverted sites above.
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
    /// Stored on the workflows row as `metadata.tags` (trimmed, empties
    /// dropped, de-duplicated) on the first store only: a re-store of the
    /// same goal is a no-op that keeps the original tags. Not added as claim
    /// labels.
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
    /// `true` only if the workflow's goal or expected outcome was achieved:
    /// every gate and check passed. A run that ran every step but a gate or
    /// check failed is `success=false`; record what the steps did in
    /// `outcome_details` / `step_executions` instead.
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
    /// deprecated via `deprecate_workflow` (truth=0.05) drop out. Exception:
    /// with `resolve_to_latest=true` the lineage head of each matched
    /// `canonical_name` is always returned, flagged `lineage_head_deprecated`
    /// when its truth is below `min_truth`.
    pub min_truth: Option<f64>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct RecordBehavioralExecutionRequest {
    pub goal_text: String,
    /// `true` only if the run's goal or expected outcome was achieved: every
    /// gate and check passed. Running every step is not success.
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
    /// `resolve_to_latest` only: this row is its lineage's head, the highest
    /// `generation` of its `canonical_name` (what `improve_workflow_hierarchy`
    /// builds on). The head of every matched lineage is always returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_lineage_head: Option<bool>,
    /// `resolve_to_latest` only: the head's generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineage_head_generation: Option<i32>,
    /// `resolve_to_latest` only: the head's `truth_value` is below
    /// `min_truth` (deprecated). It is returned anyway, so this says so.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineage_head_deprecated: Option<bool>,
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
    /// `false` for a head retired without a `supersedes` edge: it is still the
    /// lineage's head, but `evolve_step` refuses to supersede it.
    pub is_current: bool,
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
    let mut tx =
        begin_system_ingest_stamped_tx(&state, "workflows/ingest", viewer.principal()).await?;
    let decision = workflow_ingest_submitter(&mut tx, None, &viewer, &extraction).await?;
    let result =
        epigraph_ingest_executor::execute_workflow_ingest_plan(&mut tx, &plan, &extraction)
            .await
            .map_err(workflow_ingest_error)?;
    let created: Vec<Uuid> = result.inserted.iter().map(|(id, _)| *id).collect();
    record_api_authorship(&mut tx, viewer.principal(), &created, "workflow_ingest").await?;
    record_workflow_submitter(
        &mut tx,
        None,
        &viewer,
        &extraction,
        result.workflow_id,
        &decision,
    )
    .await?;
    tx.commit().await.map_err(|e| ApiError::InternalError {
        message: format!("workflow ingest: could not commit: {e}"),
    })?;

    auto_wire_inserted_edges(&state, &viewer, &result).await;

    // Embed inline, best-effort. Satisfies the is_current=true → has-embedding
    // invariant (CLAUDE.md "Embedding policy"). Failures warn and continue.
    if let Some(embedder) = state.embedding_service() {
        let wf_id = result.workflow_id;
        embed_inserted_workflow_claims(&state, embedder.as_ref(), "workflows", &result.inserted)
            .await;
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

/// GET /api/v1/workflows/:id/plan - The frozen plan of one workflow
/// generation, read as the caller (`claims:read`).
///
/// Every `executes` target of THIS `workflow_id`, at every level, in the order
/// the edges' `plan_index` values give, with content, stored hash, the
/// seed-aware `content_hash_ok`, tenancy, truth, `is_current` and
/// `heads_diverged`; the `workflows` row's name, generation, goal, parent,
/// truth and recorded submitter; integrity counts (`hidden_count`,
/// `unindexed_edges`, `plan_index_gaps`, `duplicate_plan_indices`,
/// `retracted_edges`); and a `wfd1` `digest_echo` only when every count is
/// zero. Lineage heads are never read as content: an `evolve_step` shows as
/// `heads_diverged`, not as a different plan.
///
/// `plan_index` is a mutable edge property (a writer of the plan's group can
/// rewrite or retract an `executes` edge), so the read reports the order as
/// stored and never repairs it. A caller that pins a plan compares its own
/// digest; the echo is informational.
///
/// 404 when the row does not exist and when the caller can see none of its
/// `executes` edges (a non-member of a group-private plan); see
/// `epigraph_ingest_executor::workflow_plan::frozen_plan` for why that is not a
/// 200 with a count.
///
/// The `workflows` row and every edge and claim are read on ONE connection
/// stamped with the caller's viewer, so the in-query predicates and the
/// session's tenancy GUCs agree under forced RLS.
#[cfg(feature = "db")]
pub async fn get_workflow_plan(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
) -> Result<Json<epigraph_ingest::workflow::frozen_plan::FrozenPlan>, ApiError> {
    // `else return Unauthorized`, not `if let Some(..)`: the conditional form
    // is a fail-open scope site (see `routes/crud.rs::list_evidence`).
    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };
    crate::middleware::scopes::check_scopes(auth, &["claims:read"])?;

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_workflow_plan",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;
    let plan =
        epigraph_ingest_executor::workflow_plan::frozen_plan(&mut read, &viewer, workflow_id)
            .await
            .map_err(|e| {
                tracing::error!(
                    target: "tenancy.scoped_read",
                    error = %e,
                    handler = "get_workflow_plan",
                    "frozen plan read failed on the viewer-stamped connection"
                );
                ApiError::InternalError {
                    message: "Failed to read the workflow plan".to_string(),
                }
            })?;
    read.commit().await.map_err(|e| ApiError::InternalError {
        message: format!("Failed to close the scoped read: {e}"),
    })?;
    plan.map(Json).ok_or(ApiError::NotFound {
        entity: "workflow plan".to_string(),
        id: workflow_id.to_string(),
    })
}

/// POST /api/v1/workflows/:id/outcome - Report execution outcome.
///
/// The truth update, the usage counters and the behavioral-execution row are
/// written on ONE transaction stamped with the caller's viewer, and every error
/// propagates. They used to be three independent writes on the raw pool, the
/// two `claims` UPDATEs with their results discarded (`let _ =`): on a schema
/// without the orphan `*_privacy` policies `claims_tenancy` refused both, and
/// the route answered 200 with the new truth value while only the
/// behavioral-execution row landed (MEASURED, batch H-a review, owner reporting
/// on its own flat workflow claim).
#[cfg(feature = "db")]
pub async fn report_outcome(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    Json(request): Json<ReportOutcomeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // ── The target, read through the CALLER's viewer ──
    //
    // An unreadable workflow is 404, exactly like a missing one. The read also
    // yields the goal the behavioral row falls back to, so the embedding round
    // trip below can happen BEFORE the write transaction opens rather than
    // holding it across an external call.
    let (workflow_claim, labels) = {
        let mut read = state.read_as(&viewer).await.map_err(|e| {
            tracing::error!(
                target: "tenancy.scoped_read",
                error = %e,
                handler = "report_outcome",
                "could not acquire a viewer-stamped connection"
            );
            ApiError::InternalError {
                message: "Failed to acquire a scoped connection".to_string(),
            }
        })?;
        epigraph_db::ClaimRepository::get_by_id_with_labels(
            &mut *read,
            &viewer,
            epigraph_core::ClaimId::from_uuid(workflow_id),
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to fetch workflow: {e}"),
        })?
        .ok_or(ApiError::NotFound {
            entity: "workflow".into(),
            id: workflow_id.to_string(),
        })?
    };
    if !labels.iter().any(|l| l == "workflow") {
        return Err(ApiError::NotFound {
            entity: "workflow".into(),
            id: workflow_id.to_string(),
        });
    }

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

    // ── Behavioral execution inputs, and the goal embedding, before BEGIN ──
    let parsed_goal: String = serde_json::from_str::<serde_json::Value>(&workflow_claim.content)
        .ok()
        .and_then(|v| v.get("goal").and_then(|g| g.as_str()).map(String::from))
        .unwrap_or_default();

    let behavioral_goal = request.goal_text.clone().unwrap_or(parsed_goal);

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

    // Embed goal text for affinity matching. Best-effort: a missing vector is a
    // NULL column, not a failed report.
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

    // ── ONE stamped transaction for the three writes ──
    let mut tx = state.write_as(&viewer, "report_outcome").await?;
    let refused = |e: &epigraph_db::DbError| {
        tracing::warn!(
            target: "tenancy.scoped_write",
            handler = "report_outcome",
            workflow = %workflow_id,
            error = %e,
            "the database refused the outcome report"
        );
        crate::errors::write_refused("workflow claim")
    };

    // The counters are read on the transaction that writes them.
    let workflow = sqlx::query_as::<_, WorkflowRow>(
        "SELECT id, truth_value, properties FROM claims WHERE id = $1 AND 'workflow' = ANY(labels)",
    )
    .bind(workflow_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch workflow: {e}"),
    })?
    .ok_or(ApiError::NotFound {
        entity: "workflow".into(),
        id: workflow_id.to_string(),
    })?;

    let before_truth = workflow.truth_value.unwrap_or(0.5);

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

    // Update claim truth. `update_truth_value_conn` reports a row the UPDATE did
    // not reach as NotFound, so an UPDATE hidden by row security cannot read as
    // success either.
    epigraph_db::ClaimRepository::update_truth_value_conn(
        &mut tx,
        epigraph_core::ClaimId::from_uuid(workflow_id),
        epigraph_core::TruthValue::clamped(after_truth),
    )
    .await
    .map_err(|e| {
        if crate::errors::db_is_insufficient_privilege(&e) {
            return refused(&e);
        }
        ApiError::InternalError {
            message: format!("Failed to update the workflow's truth value: {e}"),
        }
    })?;

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

    epigraph_db::ClaimRepository::set_properties_conn(
        &mut tx,
        epigraph_core::ClaimId::from_uuid(workflow_id),
        props,
    )
    .await
    .map_err(|e| {
        if crate::errors::db_is_insufficient_privilege(&e) {
            return refused(&e);
        }
        ApiError::InternalError {
            message: format!("Failed to update the workflow's counters: {e}"),
        }
    })?;

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

    // No longer best-effort: it commits with the counters it is the record of,
    // or neither does.
    epigraph_db::BehavioralExecutionRepository::create(
        &mut *tx,
        behavioral_row,
        goal_embedding_pgvec.as_deref(),
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to record the behavioral execution: {e}"),
    })?;

    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit the outcome report: {e}"),
    })?;

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
/// With `resolve_to_latest=true` the lineage head (highest `generation`) of
/// every matched `canonical_name` is always returned, even when its goal does
/// not match `q`, it has no goal embedding, or its truth is below `min_truth`;
/// each entry carries `is_lineage_head`, `lineage_head_generation` and
/// `lineage_head_deprecated`. The result can then exceed `limit` by one head
/// per matched lineage. A live head leads its lineage group; a deprecated head
/// (truth below `min_truth`) sorts after the live rows of its group.
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

    // With `resolve_to_latest` both searches add the head of every matched
    // canonical_name, so the highest generation per group in `rows` IS the
    // lineage head (`lineage_heads_in`).
    let heads = params
        .resolve_to_latest
        .then(|| epigraph_db::repos::workflow::lineage_heads_in(&rows));
    let mut workflows: Vec<HierarchicalWorkflowResult> = rows
        .into_iter()
        .map(|r| {
            let lineage = heads
                .as_ref()
                .and_then(|h| h.get(&r.canonical_name))
                .copied();
            HierarchicalWorkflowResult {
                is_lineage_head: lineage.map(|(id, _, _)| id == r.id),
                lineage_head_generation: lineage.map(|(_, generation, _)| generation),
                lineage_head_deprecated: lineage.map(|(_, _, truth)| truth < min_truth),
                workflow_id: r.id,
                canonical_name: r.canonical_name,
                generation: r.generation,
                goal: r.goal,
                parent_id: r.parent_id,
                metadata: r.metadata,
                created_at: r.created_at,
                truth_value: r.truth_value,
                resolved_steps: None,
            }
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
                                is_current: h.is_current,
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
/// `step_claim_id` populated for each step in `step_executions`, all on one
/// transaction: a refused step row is a 500 and nothing is written. An
/// out-of-range `quality` is a 400. A non-blank `goal_text` is embedded
/// (best-effort) onto every step row so the report feeds behavioral affinity.
/// NOT idempotent: a retried report counts twice.
///
/// Returns 404 if the id does not correspond to a `workflows` row, or if the
/// caller can read none of the workflow's `executes` edges (the two are not
/// told apart, and nothing is written). Use
/// `POST /api/v1/workflows/:id/outcome` for flat-JSON workflows.
///
/// # Authority
///
/// Requires `claims:write`, as the MCP twin does (`scope_map.rs`); a request
/// with no `AuthContext` is 401, never a skipped check. The route used to take
/// no `AuthContext` at all, so any authenticated bearer, a read-only client
/// included, could move a workflow's counters.
///
/// # Step attribution runs through the CALLER's viewer
///
/// The whole report runs on one transaction stamped with the caller's viewer
/// ([`AppState::write_as`]). `workflows` and `behavioral_executions` have no
/// row security, so that changes nothing about the two writes; it changes the
/// reads of `claims` and `edges`. On the plain transaction this used to run
/// on, row security admitted only public rows, so a group's own member got
/// every row of a group-private workflow written with a NULL `step_claim_id`,
/// silently. A caller that reads NONE of the plan's `executes` edges
/// (`WorkflowRepository::viewer_reads_any_executes_edge`) is refused with the
/// missing-id 404 before anything is written: `workflows` has no row security,
/// so without that check any `claims:write` holder could move the counters of
/// a workflow it cannot read. A reader of the plan resolves its steps, and any
/// `step_index` that matches no step the caller can read is listed in
/// `unresolved_step_indices` with a `warning` (out of range and not visible are
/// deliberately not told apart). Shared with MCP:
/// `WorkflowRepository::plan_step_claim_ids` and
/// `epigraph_mcp::tools::workflow_hierarchical::unresolved_steps_warning`.
#[cfg(feature = "db")]
#[utoipa::path(
    post,
    path = "/api/v1/workflows/hierarchical/{id}/outcome",
    params(("id" = uuid::Uuid, Path, description = "UUID of the hierarchical workflow")),
    request_body = serde_json::Value,
    responses(
        (status = 200, body = serde_json::Value),
        (status = 400, description = "quality outside [0, 1]"),
        (status = 401, description = "no authenticated caller"),
        (status = 403, description = "the token lacks claims:write"),
        (status = 404, description = "no such workflow, or the caller reads none of its plan"),
        (status = 500),
    ),
    security(("ed25519_signature" = [])),
    tag = "workflows"
)]
pub async fn report_hierarchical_outcome(
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    Json(request): Json<ReportOutcomeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = auth_ctx
        .map(|axum::Extension(a)| a)
        .ok_or_else(|| ApiError::Unauthorized {
            reason: "report_hierarchical_outcome requires authentication".into(),
        })?;
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])?;

    // 0. Validate before touching the database (U033). `behavioral_executions`
    //    carries CHECK (quality BETWEEN 0 AND 1); an out-of-range value used to
    //    move the counters and then have every step row silently refused.
    if let Some(q) = request.quality {
        if !(q.is_finite() && (0.0..=1.0).contains(&q)) {
            return Err(ApiError::BadRequest {
                message: format!("`quality` must be a finite number in [0, 1]; got {q}"),
            });
        }
    }

    // Embed the goal for affinity matching, best-effort and BEFORE the
    // transaction so embedder latency stays out of the row lock. Blank goals and
    // the "hierarchical" placeholder are not goals. Mirrors the MCP tool's
    // `do_report_hierarchical_outcome_with_embedder`.
    let goal_text = request
        .goal_text
        .clone()
        .unwrap_or_else(|| String::from("hierarchical"));
    let goal_to_embed = request
        .goal_text
        .as_deref()
        .map(str::trim)
        .filter(|g| !g.is_empty() && *g != "hierarchical");
    let goal_embedding_pgvec = match (goal_to_embed, state.embedding_service()) {
        (Some(goal), Some(embedder)) => match embedder.generate(goal).await {
            Ok(vec) => Some(format!(
                "[{}]",
                vec.iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )),
            Err(e) => {
                tracing::warn!(workflow_id = %workflow_id, "hierarchical goal embedding failed: {e}");
                None
            }
        },
        _ => None,
    };

    // ONE transaction for the counters and every step row (U033): a refused row
    // fails the report and rolls the counters back. Stamped with the caller's
    // viewer so the step lookup (step 4) reads what the CALLER may read; the
    // two writes are to tables with no row security.
    let mut tx = state
        .write_as(&viewer, "report_hierarchical_outcome")
        .await?;

    // 1. Confirm this is a hierarchical workflow root, and lock its row so two
    //    concurrent reports cannot both read `use_count = n` and write `n + 1`.
    let row: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT metadata FROM workflows WHERE id = $1 FOR UPDATE")
            .bind(workflow_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("workflows lookup failed: {e}"),
            })?;
    let not_found = || ApiError::NotFound {
        entity: "hierarchical workflow".into(),
        id: workflow_id.to_string(),
    };
    let mut metadata = match row {
        Some((m,)) => m,
        None => return Err(not_found()),
    };
    // A caller that reads none of the plan's `executes` edges cannot read this
    // workflow (`workflows` has no row security; its plan does): 404 exactly
    // like a missing id, before any write. Shared with MCP.
    if !epigraph_db::WorkflowRepository::viewer_reads_any_executes_edge(
        &mut tx,
        &viewer,
        workflow_id,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("workflow visibility check failed: {e}"),
    })? {
        return Err(not_found());
    }

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
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("metadata update failed: {e}"),
        })?;

    // 4. Resolve step_index → step_claim_id via the workflow's executes edges,
    //    restricted to level=2 (steps), in PLAN order, through the caller's
    //    viewer on this stamped transaction. The order key (the `plan_index`
    //    ordinal; `e.created_at` only for edges that predate it) lives in the
    //    repository, shared with the MCP tool, so step N is one step on both
    //    transports.
    let step_claim_ids =
        epigraph_db::WorkflowRepository::plan_step_claim_ids(&mut tx, &viewer, workflow_id)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("step lookup failed: {e}"),
            })?;

    // 5. Write per-step behavioral_executions rows on the same transaction; a
    //    refused row returns 500 and rolls back everything above. Capture the
    //    timestamp once so rows from a single outcome report group cleanly
    //    downstream (and count as ONE report in `behavioral_affinity_hierarchical`).
    let report_ts = chrono::Utc::now();
    let mut unresolved: Vec<usize> = Vec::new();
    if let Some(ref step_execs) = request.step_executions {
        for step_exec in step_execs {
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
                goal_text: goal_text.clone(),
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
            epigraph_db::BehavioralExecutionRepository::create(
                &mut *tx,
                row,
                goal_embedding_pgvec.as_deref(),
            )
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("behavioral_executions write failed: {e}"),
            })?;
        }
    }

    tx.commit().await.map_err(|e| ApiError::InternalError {
        message: format!("outcome commit failed: {e}"),
    })?;

    let warning = epigraph_mcp::tools::workflow_hierarchical::unresolved_steps_warning(&unresolved);
    if warning.is_some() {
        // Every unattributed row is logged, the all-invisible case included;
        // the old guard (`!step_claim_ids.is_empty()`) kept that case silent.
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
        "variance": variance,
        // The rows written with a NULL step_claim_id, in request order.
        "unresolved_step_indices": unresolved,
    });
    if let Some(w) = warning {
        response["warning"] = serde_json::Value::String(w);
    }
    Ok(Json(response))
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
    /// `supersedes` only: the Supersede admin cascade (migration 117) that
    /// carries the retired step's edges onto the new one, as
    /// `POST /api/v1/claims/:id/supersede` reports it (`applied`, `deferred`
    /// or `failed`, with its `security_events` row id). Absent for `revises`,
    /// which supersedes nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Object)]
    pub cascade: Option<epigraph_engine::admin_cascade::CascadeStatus>,
    /// `supersedes` only: what the downstream belief cascade repaired.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Object)]
    pub belief_cascade: Option<epigraph_engine::retraction_cascade::CascadeReport>,
}

/// POST /api/v1/workflows/steps/{id}/evolve - Evolve a versioned step.
///
/// Creates a new claim in the step's lineage that `supersedes` (linear
/// refinement; the parent is retired) or `revises` (a concurrent branch; both
/// stay current) the parent. With `supersedes` the new claim records
/// `supersedes = parent` and the administrative Supersede cascade (as
/// `POST /api/v1/claims/{id}/supersede` runs it) carries the retired step's
/// edges onto it, reported in `cascade` (`applied`; `deferred` to the replay
/// timer when no maintenance connection is configured; or `failed`, and
/// replayable) and `belief_cascade`. The workflow's `executes` edge, its step
/// chain (`step_follows` / `phase_follows`), the lineage's `revises` history
/// and other agents' `asserts` / `AUTHORED` stay on the retired step.
/// `revises` retires nothing and runs no cascade.
///
/// Authority: when any workflow executes the parent's step lineage (the
/// parent or any claim sharing its `step_lineage_id`, retracted `executes`
/// edges included), the caller needs workflow authority over EVERY such
/// workflow, as `add_step` / `delete_step` need over theirs: its recorded
/// submitter, the submitter's operator, or the audited `claims:admin` path (a
/// workflow with no recorded submitter admits only that path). Anyone else is
/// refused 403 with nothing written. Each admitted write records one
/// `workflows.caller_write` (or `workflows.admin_write`) row per workflow. A
/// claim no workflow executes is unaffected.
///
/// Refusals write nothing: 400 for a `level` other than 2 or 3, blank
/// `content` or an `edge_type` other than `supersedes` / `revises`; 404 for a
/// parent that does not exist or that the caller cannot see; 409 for
/// `supersedes` on a parent that is no longer current (`revises` may still
/// branch from it).
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
        (status = 403),
        (status = 404),
        (status = 409),
    ),
    security(("ed25519_signature" = [])),
    tag = "workflows"
)]
pub async fn evolve_step(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
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
    // The request checks MCP `evolve_step` makes before any write, with its
    // wording (backlog 769989ae): without them a bad level was written as is
    // and blank content reached the claims CHECK as a 500.
    let level = req.level.unwrap_or(2);
    if level != 2 && level != 3 {
        return Err(ApiError::BadRequest {
            message: format!("level must be 2 or 3 (got {level})"),
        });
    }
    if req.content.trim().is_empty() {
        return Err(ApiError::BadRequest {
            message: "content must not be empty".into(),
        });
    }
    // The step claim is AUTHORED by, and written on a transaction STAMPED
    // with, the authenticated caller: the viewer's principal (the token's
    // `agent_id`). NOT `owner_id` / `client_id`: those are `oauth_clients.id`
    // values, never an agent, so authoring as one broke the agents foreign
    // key before migration 122 and is refused OPL01 once armed. Migration
    // 122's claims trigger then sees writer = author = the caller.
    let Some(agent) = viewer.principal() else {
        return Err(ApiError::Unauthorized {
            reason: "evolve_step requires an authenticated principal".into(),
        });
    };
    let mut tx = state.begin_claim_write(&viewer, "evolve_step").await?;
    // Workflow authority over every workflow executing the parent's
    // step lineage, checked for the SAME principal the step is authored as,
    // on the act's own transaction and before it, so a refusal writes nothing.
    let grants = require_api_lineage_authority(&mut tx, &auth, agent, parent_id).await?;
    let result = epigraph_db::ClaimRepository::evolve_step_conn(
        &mut tx,
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
        // The repo's refusals are the caller's to act on (backlog 769989ae):
        // `InvalidData` (an edge_type outside the vocabulary) is a 400 and
        // `Conflict` (superseding a non-current step) a 409, as
        // `From<DbError>` maps them everywhere else. These are the only two
        // refusals `evolve_step_conn` raises besides `NotFound`. Its other
        // `InvalidData`, a parent whose stored visibility is outside the
        // vocabulary, is a data fault but also reads as a 400: the column is
        // NOT NULL with a CHECK, so it is unreachable unless that constraint
        // is dropped out of band.
        e @ (epigraph_db::DbError::InvalidData { .. } | epigraph_db::DbError::Conflict { .. }) => {
            ApiError::from(e)
        }
        e if e.is_write_authority_refusal() => ApiError::from(e),
        other => ApiError::InternalError {
            message: other.to_string(),
        },
    })?;
    record_api_lineage_writes(
        &mut tx,
        &auth,
        agent,
        &grants,
        serde_json::json!({
            "parent_claim_id": parent_id,
            "claim_id": result.new_claim_id,
            "step_lineage_id": result.step_lineage_id,
            "edge_type": result.edge_type,
            "level": level,
        }),
    )
    .await?;
    // A `supersedes` step is a supersession (`claims.supersedes` names the
    // parent), so it runs `versioning::supersede_claim`'s administrative
    // cascade (backlog 8d3b4527): the act above moved no edge, and the retired
    // step's decomposition, argument and support edges belong to other
    // writers. `migrate_superseded_edges`' step-lineage rule leaves the
    // workflow's `executes` and its `step_follows` / `phase_follows` chain,
    // the lineage's `revises` history and agents' authorship edges on the
    // retired step.
    // The maintenance session is acquired BEFORE the act commits; without one
    // the deferral commits with the act, under the caller's stamp.
    let supersession = if result.edge_type == "supersedes" {
        let trigger = epigraph_engine::admin_cascade::CascadeTrigger::new(
            epigraph_engine::admin_cascade::CascadeCause::Supersede,
            Some(agent),
            Some(crate::routes::versioning::oauth_principal(&auth)),
            parent_id,
            Some(result.new_claim_id),
        );
        let (session, deferred) =
            crate::routes::versioning::admin_session_or_deferral(&state, &mut tx, &trigger).await?;
        Some((trigger, session, deferred))
    } else {
        None
    };
    tx.commit().await.map_err(|e| ApiError::InternalError {
        message: format!("evolve_step: commit failed: {e}"),
    })?;

    // Best-effort, as in `supersede_claim`: the act has committed, so a
    // cascade failure is reported in `cascade`, never as an error.
    let (cascade, belief_cascade) = match supersession {
        Some((trigger, Some(mut session), _)) => {
            let (conn, admin_viewer) = session.split();
            let (c, b) = epigraph_engine::admin_cascade::apply_after_supersede(
                conn,
                admin_viewer,
                &viewer,
                &trigger,
                parent_id,
                result.new_claim_id,
            )
            .await;
            (Some(c), Some(b))
        }
        Some((_, None, status)) => (Some(status), Some(Default::default())),
        None => (None, None),
    };

    Ok(Json(EvolveStepResponse {
        claim_id: result.new_claim_id,
        step_lineage_id: result.step_lineage_id,
        edge_type: result.edge_type,
        edge_id: result.edge_id,
        cascade,
        belief_cascade,
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

    // The existence gate, read through the CALLER's viewer on a viewer-stamped
    // connection. It was `SELECT id FROM claims WHERE id = $1 AND 'workflow' =
    // ANY(labels)` on the raw pool, unfiltered while the handler held a Viewer
    // (F-write-authz-reads-unfiltered, backlog 30c29c52), and it is this handler's
    // ONLY gate. A caller could therefore deprecate a workflow claim it cannot
    // read. An invisible workflow is now 404, exactly like a missing one. Read
    // authority, not `{WRITABLE:c}`, for the reason given at the same gate in
    // `versioning.rs::supersede_claim`: the writes below run on a transaction
    // stamped with the caller's viewer, so the DATABASE decides write authority
    // (a claim whose owner group the caller cannot write is refused, 403,
    // nothing written). Whether a caller should be able to deprecate a workflow
    // it can WRITE but does not own is the open ownership question (#374 /
    // backlog 84b2a98d), not this read's.
    {
        let mut read = state.read_as(&viewer).await.map_err(|e| {
            tracing::error!(
                target: "tenancy.scoped_read",
                error = %e,
                handler = "deprecate_workflow",
                "could not acquire a viewer-stamped connection"
            );
            ApiError::InternalError {
                message: "Failed to acquire a scoped connection".to_string(),
            }
        })?;
        let found = epigraph_db::ClaimRepository::get_by_id_with_labels(
            &mut *read,
            &viewer,
            epigraph_core::ClaimId::from_uuid(workflow_id),
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to check workflow: {e}"),
        })?;
        match found {
            Some((_, labels)) if labels.iter().any(|l| l == "workflow") => {}
            _ => {
                return Err(ApiError::NotFound {
                    entity: "workflow".into(),
                    id: workflow_id.to_string(),
                })
            }
        }
    }

    // ONE transaction, stamped with the CALLER's viewer, for the descendant read
    // and every write.
    //
    // The writes used to be `let _ = deprecate_claim(&state.db_pool, ..)` and
    // `let _ = set_truth_value(&state.db_pool, ..)`: unstamped, and their
    // results discarded. On a schema without the orphan `*_privacy` policies
    // (config A) `claims_tenancy` refused the UPDATE, the error was dropped, and
    // the route answered 200 with `deprecated_ids` while `is_current` stayed
    // true (MEASURED, batch H-a review, owner deprecating its own flat workflow
    // claim). Now every error propagates, a claim UPDATE that touches no row is
    // a failure, and nothing commits unless every id was deprecated.
    let mut tx = state.write_as(&viewer, "deprecate_workflow").await?;

    // Collect IDs to deprecate. A failed read is an error now, not an empty
    // cascade: swallowed inside the transaction it would abort it silently.
    let mut ids_to_deprecate = vec![workflow_id];
    if cascade {
        let descendants =
            epigraph_db::WorkflowRepository::find_descendants(&mut *tx, &viewer, workflow_id)
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("Failed to read the workflow's descendants: {e}"),
                })?;
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
        let touched = epigraph_db::ClaimRepository::deprecate_claim(
            &mut *tx,
            epigraph_core::ClaimId::from_uuid(*id),
        )
        .await
        .map_err(|e| {
            if crate::errors::db_is_insufficient_privilege(&e) {
                tracing::warn!(
                    target: "tenancy.scoped_write",
                    handler = "deprecate_workflow",
                    claim = %id,
                    error = %e,
                    "the database refused the deprecation"
                );
                crate::errors::write_refused("workflow claim")
            } else {
                ApiError::InternalError {
                    message: format!("Failed to deprecate workflow claim {id}: {e}"),
                }
            }
        })?;
        // Zero rows means the row is not there for this caller to write: gone,
        // or (for a cascaded descendant, which the read gate above did not
        // check) invisible to it. Reporting it in `deprecated_ids` would be the
        // success-over-nothing this conversion removes.
        if touched != 1 {
            return Err(ApiError::Conflict {
                reason: format!(
                    "workflow claim {id} could not be deprecated (no row updated); nothing was \
                     written"
                ),
            });
        }
        // Mirror onto the hierarchical `workflows` row when one exists
        // (no-op for flat-only workflows). Without this, deprecated
        // hierarchical workflows keep surfacing in
        // `GET /api/v1/workflows/hierarchical/search`. Zero rows is the normal
        // answer for a flat workflow, so only an ERROR fails the request.
        epigraph_db::WorkflowRepository::set_truth_value(&mut *tx, *id, 0.05)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to mirror the deprecation onto workflow {id}: {e}"),
            })?;
    }

    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit the deprecation: {e}"),
    })?;

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

/// The body of `POST /api/v1/workflows/ingest`: a `WorkflowExtraction`, with
/// two optional keys beside its own.
///
/// * `tenancy`: `{"visibility": "group", "owner_group_id": G}` declares
///   `('group', G)` for every claim the ingest creates (absent: public).
/// * `embed`: `false` embeds nothing (default `true`).
#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct IngestWorkflowRequest {
    #[serde(flatten)]
    pub extraction: epigraph_ingest::workflow::WorkflowExtraction,
    #[serde(default)]
    pub tenancy: Option<epigraph_ingest::workflow::WorkflowTenancy>,
    #[serde(default)]
    pub embed: Option<bool>,
}

/// POST /api/v1/workflows/ingest - Ingest a hierarchical `WorkflowExtraction`.
///
/// Parses a `WorkflowExtraction` JSON body, persists the claim hierarchy
/// (thesis → phases → steps → operation atoms), writes `workflow —executes→ claim`
/// edges, resolves author-placeholder edges, and returns a summary. Idempotent:
/// if the workflow row already has `executes` edges, returns `already_ingested: true`
/// without touching the DB further. `executes_edges` then counts only the
/// existing plan's edges the caller can read.
///
/// # A declared tenancy
///
/// With `tenancy` (see [`IngestWorkflowRequest`]) every claim the ingest
/// creates is `('group', G)`. The REQUEST's principal itself must hold a live
/// writer or admin membership of G (checked on its own viewer before any
/// transaction, so a refusal writes nothing; its operator's membership does
/// not count), and so must the workflow-ingest system agent (checked by the
/// executor on the stamped transaction). Both refusals are 403. The response
/// then carries `reused_items`: every planned claim the call did not create
/// whose tenancy is not `('group', G)`, with its tenancy (`null` when the
/// caller cannot read it, which only a re-ingest can report). Nothing
/// re-tenants a reused claim, and a plan that reuses a claim private to a group
/// the caller does not write is refused (403) before any edge is written.
///
/// The `workflows` row itself has no row security: its `canonical_name`,
/// `goal`, `metadata` and (unless `embed` is `false`) `goal_embedding` stay
/// instance-readable whatever the tenancy, so a caller must keep them neutral.
#[cfg(feature = "db")]
#[utoipa::path(
    post,
    path = "/api/v1/workflows/ingest",
    request_body = serde_json::Value,
    responses(
        (status = 200, body = serde_json::Value),
        (status = 400, description = "EmptyGeneration: a step-less generation > 0 or a claim-less plan; InvalidContent: blank thesis, phase, step or operation content"),
        (status = 401, description = "no authenticated caller"),
        (status = 403, description = "the token lacks claims:write, or a declared group the caller or the ingest system agent does not write"),
        (status = 500),
    ),
    security(("ed25519_signature" = [])),
    tag = "workflows"
)]
pub async fn ingest_workflow(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<IngestWorkflowRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // `claims:write` first, before any read or write, as the sibling step
    // routes and the MCP twin (`scope_map.rs`) require (backlog 05eb8b4a). A
    // request with no `AuthContext` is 401, never a skipped check.
    let Some(axum::Extension(auth)) = auth_ctx.as_ref() else {
        return Err(ApiError::Unauthorized {
            reason: "ingest_workflow requires authentication".into(),
        });
    };
    crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;
    let IngestWorkflowRequest {
        mut extraction,
        tenancy,
        embed,
    } = request;
    let declared_group = tenancy.map(|t| t.owner_group_id);
    // The caller's OWN membership of a declared group, before anything is
    // begun (`require_caller_writes_group`). A viewer with no principal names
    // no caller and is refused.
    if let Some(group) = declared_group {
        let caller = viewer.principal().ok_or_else(|| ApiError::Forbidden {
            reason: "workflow ingest: a declared tenancy needs an authenticated agent principal"
                .to_string(),
        })?;
        epigraph_ingest_executor::require_caller_writes_group(&viewer, caller, group)
            .map_err(workflow_ingest_error)?;
    }
    // H3 (batch H-b): the submitter key is this route's to write, never the
    // caller's; see `workflow_ingest_submitter`.
    if let Some(obj) = extraction.source.metadata.as_object_mut() {
        obj.remove(epigraph_db::WorkflowRepository::SUBMITTER_KEY);
    }
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);
    let mut tx =
        begin_system_ingest_stamped_tx(&state, "workflows/ingest", viewer.principal()).await?;
    let auth = Some(auth);
    let decision = workflow_ingest_submitter(&mut tx, auth, &viewer, &extraction).await?;
    let result = epigraph_ingest_executor::execute_workflow_ingest_plan_in_group(
        &mut tx,
        &plan,
        &extraction,
        &viewer,
        declared_group,
    )
    .await
    .map_err(workflow_ingest_error)?;
    let created: Vec<Uuid> = result.inserted.iter().map(|(id, _)| *id).collect();
    record_api_authorship(&mut tx, viewer.principal(), &created, "workflow_ingest").await?;
    record_workflow_submitter(
        &mut tx,
        auth,
        &viewer,
        &extraction,
        result.workflow_id,
        &decision,
    )
    .await?;
    tx.commit().await.map_err(|e| ApiError::InternalError {
        message: format!("workflow ingest: could not commit: {e}"),
    })?;

    auto_wire_inserted_edges(&state, &viewer, &result).await;

    // Embed inline, best-effort. Satisfies the is_current=true → has-embedding
    // invariant (CLAUDE.md "Embedding policy"). Failures warn and continue.
    // `embed: false` (OD-6) sends no text to the embedder at all.
    let embedder = if embed.unwrap_or(true) {
        state.embedding_service()
    } else {
        None
    };
    if let Some(embedder) = embedder {
        let wf_id = result.workflow_id;
        embed_inserted_workflow_claims(
            &state,
            embedder.as_ref(),
            "workflows/ingest",
            &result.inserted,
        )
        .await;
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

    let mut body = serde_json::json!({
        "workflow_id": result.workflow_id,
        "canonical_name": result.canonical_name,
        "generation": result.generation,
        "claims_ingested": result.claims_ingested,
        "claims_skipped_dedup": result.claims_skipped_dedup,
        "executes_edges": result.executes_edges_created,
        "relationships_created": result.relationship_edges_created,
        "already_ingested": result.already_ingested,
    });
    if declared_group.is_some() {
        body["reused_items"] = result
            .reused_items
            .iter()
            .map(|r| {
                serde_json::json!({
                    "claim_id": r.claim_id,
                    "visibility": r.visibility,
                    "owner_group_id": r.owner_group_id,
                })
            })
            .collect();
    }
    Ok(Json(body))
}

// ── Internal helpers ──

/// Begin the ONE transaction a workflow-ingest write runs in, stamped from the
/// **workflow-ingest system agent's** viewer (the agent migration 148's
/// `system_agents` registry names; see `get_or_create_system_agent`).
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
///
/// # RESIDUAL, stated so the R3 policy drop is not read as closing it
///
/// This stamps the transaction with the SYSTEM agent's authority, and nothing on
/// this path asks whether the CALLER has any authority over the workflow it
/// names. `add_step`, `delete_step`, `ingest_workflow` and
/// `improve_workflow_hierarchy` (MCP), and `POST /api/v1/workflows/steps` and
/// `/steps/delete` (HTTP, gated only by the `claims:write` scope) reach this on
/// caller-supplied input (`canonical_name`, `step_lineage_id`). So any
/// `claims:write` caller can mutate any system-owned workflow — the harness's
/// `delete_step` arm drives a step's truth to 0.05 with no ownership relation
/// between caller and workflow. Same residual as `epigraph_mcp::claim_helper::begin_system_ingest_stamped_tx`,
/// which carries the MCP half. MEASURED by review; not a regression: config B
/// (production today) admits the same writes through the orphan `*_privacy`
/// policies, and main behaves the same there.
///
/// What it means for R3: dropping the orphan policies does NOT tighten workflow
/// mutation at all, because these writes no longer depend on them. Tightening
/// needs a caller-side check against the TARGET workflow before the stamp, and
/// a decision about who "owns" a workflow the system agent authored — neither
/// of which is a mechanical conversion. Tracked as open work, not fixed here.
///
/// # The CALLER is bound before anything is written (migration 122)
///
/// As on the MCP side: the claims trigger sees only the shared system agent,
/// so this binds `caller` (the request's principal; `None` is unbound) on the
/// stamped transaction, through
/// `epigraph_ingest_executor::require_caller_write_authority`. Once the
/// database is armed an unbound caller is refused (`OPL01`) and a caller whose
/// human does not write the system agent's owner group is refused (`OPL02`),
/// both as 403.
///
/// # Errors
/// `ApiError::InternalError` if the system agent has no write authority, if the
/// process was not built through `AppState::with_scoped_pool`, or if the stamp
/// fails. Never a fallback to `state.db_pool`. A 403 for the caller refusals.
#[cfg(feature = "db")]
pub(crate) async fn begin_system_ingest_stamped_tx<'s>(
    state: &'s AppState,
    route: &'static str,
    caller: Option<Uuid>,
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
            match e {
                epigraph_ingest_executor::IngestExecutorError::SystemAgentUnregistered { role } => {
                    system_agent_unregistered(role)
                }
                e => ApiError::InternalError {
                    message: format!(
                        "{route}: could not establish the workflow-ingest-system agent's write \
                         authority: {e}. Nothing was written."
                    ),
                },
            }
        })?;

    let mut tx = scoped
        .begin_as(&authority.viewer)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("{route}: could not begin a system-agent-stamped transaction: {e}"),
        })?;
    epigraph_ingest_executor::require_caller_write_authority(&mut tx, authority.agent_id, caller)
        .await
        .map_err(|e| {
            tracing::warn!(
                target: "tenancy.scoped_write",
                route = route,
                caller = ?caller,
                error = %e,
                "workflow write refused: the caller may not write through the ingest system agent"
            );
            if e.is_write_authority_refusal() {
                ApiError::from(e)
            } else {
                ApiError::InternalError {
                    message: format!("{route}: could not check the caller's authority: {e}"),
                }
            }
        })?;
    Ok(tx)
}

/// The workflow-ingest system agent, for `routes/policies.rs::create_challenge`.
///
/// Delegates to [`epigraph_ingest_executor::get_or_create_system_agent`], the
/// ONE resolver (migration 148: the registered agent, a refusal on an armed
/// database with no registration, the public-constant key only on an unarmed
/// unregistered one). A second copy of the key lookup here would keep policy
/// challenges on the pre-148 rule while workflow ingest moved, and after a key
/// rotation it would try to re-create the public-constant identity
/// (`system_agent_single_resolver.rs` pins that this body holds no such copy).
#[cfg(feature = "db")]
pub(crate) async fn get_or_create_system_agent(pool: &sqlx::PgPool) -> Result<Uuid, ApiError> {
    let mut conn = pool.acquire().await.map_err(|e| ApiError::InternalError {
        message: e.to_string(),
    })?;
    epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
        .await
        .map_err(|e| match e {
            epigraph_ingest_executor::IngestExecutorError::SystemAgentUnregistered { role } => {
                system_agent_unregistered(role)
            }
            other => ApiError::InternalError {
                message: other.to_string(),
            },
        })
}

/// The armed-and-unregistered refusal (migration 148), as a 500 the CALLER
/// can read: its text is the operator's remedy, not a driver error, so it is
/// [`ApiError::InternalErrorStatic`] and survives the 500 body redaction that
/// every other `InternalError` gets. One literal per
/// [`epigraph_db::SystemAgentRole`]; `role` is that enum's `as_str()`.
#[cfg(feature = "db")]
pub(crate) fn system_agent_unregistered(role: &'static str) -> ApiError {
    ApiError::InternalErrorStatic {
        message: if role == epigraph_db::SystemAgentRole::WorkflowIngest.as_str() {
            "the workflow-ingest system agent is not registered in system_agents and this \
             database is armed (migration 122): workflow ingest is refused until a maintenance \
             session registers it (epigraph-operator register-system-agent --role \
             workflow-ingest --agent <id> --reason <text> --apply). Nothing was written"
        } else {
            "a system agent is not registered in system_agents and this database is armed \
             (migration 122): the request is refused until a maintenance session registers it \
             (epigraph-operator register-system-agent). Nothing was written"
        },
    }
}

/// Embed the claims a workflow ingest just committed. This runs post-commit and
/// best-effort, on a transaction stamped from the **workflow-ingest system
/// agent's** viewer: the same authority [`begin_system_ingest_stamped_tx`] wrote
/// the claims with.
///
/// # Why not `state.db_pool`
///
/// The claims are authored by the system agent and owned by its personal
/// group. An `UPDATE claims SET embedding` on the unstamped pool carries no
/// viewer, so row security on `claims` refuses it. Before this helper existed,
/// both `store_workflow` and `ingest_workflow` did exactly that and only
/// WARN-logged the refusal. The route answered 200 and every claim it had
/// written was left without a vector (backlog 5ce88457), invisible to dense
/// recall against CLAUDE.md's "Embedding policy". The CALLER's viewer is wrong
/// too: the `{WRITABLE:c}` splice in `store_embedding_if_unsealed` would render
/// the caller's groups, and no system-owned row satisfies them.
///
/// No caller re-binding is needed. Migration 122's claims trigger fires on
/// `UPDATE OF agent_id, supersedes, is_current`, not on `embedding`.
///
/// # Shape
///
/// * Every vector is generated FIRST, with no connection held, so a provider
///   round trip never holds a transaction open. This is the rule
///   `epigraph-mcp`'s `claim_helper::embed_claim_author_stamped` states.
/// * Then ONE stamped transaction stores them all through
///   [`epigraph_db::ClaimRepository::store_embedding_if_unsealed`]. That call
///   takes the row lock, re-checks seal and `is_current`, and runs in its own
///   savepoint, so one refused row does not abort the rest.
/// * Every failure is logged and swallowed. The claims are already committed,
///   and the embedding policy forbids a failed embed from unwinding them. A
///   missing `ScopedPool` or system authority is logged at ERROR on
///   `tenancy.scoped_write`. There is never a fallback to `state.db_pool`.
#[cfg(feature = "db")]
async fn embed_inserted_workflow_claims(
    state: &AppState,
    embedder: &dyn epigraph_embeddings::EmbeddingService,
    route: &'static str,
    inserted: &[(Uuid, String)],
) {
    if inserted.is_empty() {
        return;
    }

    let mut vectors: Vec<(Uuid, String)> = Vec::with_capacity(inserted.len());
    for (claim_id, content) in inserted {
        match embedder.generate(content).await {
            Ok(embedding) => vectors.push((*claim_id, format_embedding(&embedding))),
            Err(e) => {
                tracing::warn!(claim_id = %claim_id, route = route, error = %e, "Failed to generate embedding for ingested workflow claim");
            }
        }
    }
    if vectors.is_empty() {
        return;
    }

    let Some(scoped) = state.scoped.as_ref() else {
        tracing::error!(
            target: "tenancy.scoped_write",
            route = route,
            claims = vectors.len(),
            "workflow claim embeddings not stored: this process was not built from a \
             ScopedPool, so no connection can be stamped with the ingest system agent's \
             authority. The claims are stored but carry no vector."
        );
        return;
    };
    let authority = match epigraph_ingest_executor::system_agent_write_authority(scoped).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(
                target: "tenancy.scoped_write",
                route = route,
                claims = vectors.len(),
                error = %e,
                "workflow claim embeddings not stored: could not establish the \
                 workflow-ingest-system agent's write authority. The claims are stored but \
                 carry no vector."
            );
            return;
        }
    };
    let mut tx = match scoped.begin_as(&authority.viewer).await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::warn!(route = route, claims = vectors.len(), error = %e, "workflow claim embeddings not stored: could not begin a system-agent-stamped transaction");
            return;
        }
    };

    let mut stored = 0usize;
    for (claim_id, pgvec) in &vectors {
        match epigraph_db::ClaimRepository::store_embedding_if_unsealed(
            &mut tx,
            &authority.viewer,
            *claim_id,
            pgvec,
        )
        .await
        {
            Ok(true) => stored += 1,
            Ok(false) => {
                tracing::warn!(claim_id = %claim_id, route = route, "workflow claim embedding matched no row (claim missing, sealed, superseded, or not writable by the system agent)");
            }
            Err(e) => {
                tracing::warn!(claim_id = %claim_id, route = route, error = %e, "Failed to store embedding for ingested workflow claim");
            }
        }
    }
    if let Err(e) = tx.commit().await {
        tracing::warn!(route = route, claims = stored, error = %e, "workflow claim embeddings could not commit; the claims are stored but carry no vector");
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
/// Stamped from the workflow-ingest system agent's viewer, like the plan walk
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
    let mut tx = match begin_system_ingest_stamped_tx(
        state,
        "workflows/ingest:ds",
        viewer.principal(),
    )
    .await
    {
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

/// Map a workflow-ingest executor error. Migration 105's personal-group
/// refusals (`DbError::is_personal_group_refusal`), carried as
/// `IngestExecutorError::Repository`, go through `From<DbError>`: 403 with the
/// detail logged and kept out of the body. A content-less generation
/// (`EmptyGeneration`, U032) and blank claim content (`InvalidContent`) are
/// the caller's payload errors: 400. Everything else stays a 500.
///
/// On these routes `system_agent_write_authority` refuses a revoked system
/// agent first, with its own `AgentCreation` error (#498's 500, unchanged), so
/// this arm is what a revocation racing that preflight would surface.
#[cfg(feature = "db")]
fn workflow_ingest_error(e: epigraph_ingest_executor::IngestExecutorError) -> ApiError {
    match e {
        epigraph_ingest_executor::IngestExecutorError::Repository(db)
            if db.is_write_authority_refusal() =>
        {
            ApiError::from(db)
        }
        // U032: a content-less generation is the caller's payload error: 400,
        // not a 500 that invites the retry loop that minted the stubs.
        e @ epigraph_ingest_executor::IngestExecutorError::EmptyGeneration { .. } => {
            ApiError::BadRequest {
                message: format!("workflow ingest: {e}"),
            }
        }
        // Blank claim content in the payload (thesis, phase, step or
        // operation), refused by the executor's pre-flight: 400 naming the
        // field.
        e @ epigraph_ingest_executor::IngestExecutorError::InvalidContent { .. } => {
            ApiError::BadRequest {
                message: format!("workflow ingest: {e}"),
            }
        }
        // A declared group the caller, or the system agent, does not write.
        e if e.is_declared_tenancy_refusal() => ApiError::Forbidden {
            reason: format!("workflow ingest: {e}"),
        },
        epigraph_ingest_executor::IngestExecutorError::SystemAgentUnregistered { role } => {
            system_agent_unregistered(role)
        }
        other => ApiError::InternalError {
            message: format!("workflow ingest: {other}"),
        },
    }
}

/// Map executor's StepOpError to ApiError. WorkflowNotFound + StepNotFound
/// are 404; Invalid is 400; migration 105's personal-group refusal is 403;
/// Db/Executor are otherwise 500.
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
        e @ (E::ChainRewireRefused { .. } | E::StepNotWritable { .. }) => ApiError::Forbidden {
            reason: e.to_string(),
        },
        E::Repo(db) if db.is_write_authority_refusal() => ApiError::from(db),
        E::Executor(epigraph_ingest_executor::IngestExecutorError::Repository(db))
            if db.is_write_authority_refusal() =>
        {
            ApiError::from(db)
        }
        E::Executor(epigraph_ingest_executor::IngestExecutorError::SystemAgentUnregistered {
            role,
        }) => system_agent_unregistered(role),
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

/// Which arm of [`workflow_authority`] admitted the caller (the MCP twin's
/// `WorkflowArm`, without its stdio arm: every route here is authenticated or
/// names its caller through the viewer).
#[cfg(feature = "db")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApiWorkflowArm {
    /// The caller is the recorded submitter.
    Submitter,
    /// The caller is the operator of the submitter (#503).
    Operator,
    /// The AUDITED admin arm.
    Admin,
}

/// What [`workflow_authority`] admitted (batch H-b, H3).
#[cfg(feature = "db")]
#[derive(Clone, Copy, Debug)]
struct ApiWorkflowGrant {
    /// The recorded submitter, if any.
    owner: Option<Uuid>,
    /// The arm that admitted the caller. The admin arm's write must record
    /// [`audit_api_admin_workflow_write`] on its own transaction; every other
    /// arm's write records [`record_api_caller_workflow_write`].
    arm: ApiWorkflowArm,
}

#[cfg(feature = "db")]
impl ApiWorkflowGrant {
    fn is_admin(&self) -> bool {
        matches!(self.arm, ApiWorkflowArm::Admin)
    }
}

/// H3 (batch H-b; the MCP twin is `epigraph-mcp/src/tools/workflow_authority.rs`,
/// whose module doc records the measurements and the rule). Refuse unless the
/// caller has authority over workflow `workflow_id`: when a submitter is
/// recorded, in this order, the submitter, its operator, or the AUDITED admin
/// arm — `claims:admin` in the token AND a live grant on the token's client
/// record (migration 111's predicate), never the scope alone. A workflow with
/// no record (written before batch H-b) is platform corpus (U005, default
/// decision A): only the audited admin arm admits it, and a caller with no
/// token is refused.
#[cfg(feature = "db")]
async fn workflow_authority(
    conn: &mut sqlx::PgConnection,
    auth: Option<&crate::middleware::bearer::AuthContext>,
    caller: Option<Uuid>,
    workflow_id: Uuid,
) -> Result<ApiWorkflowGrant, ApiError> {
    let owner = epigraph_db::WorkflowRepository::submitter_of(&mut *conn, workflow_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("could not read the workflow's submitter: {e}"),
        })?;
    // U005 (default decision A): a workflow with NO recorded submitter
    // (written before batch H-b) is platform corpus. There is no submitter to
    // match and no operator to derive, so the only arm is the audited admin
    // arm; with no token there is none, and the caller is refused. When the
    // custodian role lands (#529), its check replaces `claims:admin` here.
    let Some(owner) = owner else {
        let subject = format!(
            "workflow {workflow_id} has no recorded submitter (legacy platform workflow, \
             written before batch H-b)"
        );
        if api_admin_arm(conn, auth, caller, &subject).await? {
            return Ok(ApiWorkflowGrant {
                owner: None,
                arm: ApiWorkflowArm::Admin,
            });
        }
        return Err(ApiError::Forbidden {
            reason: format!(
                "{subject}; it is mutable only through the audited claims:admin path, and the \
                 caller holds no claims:admin. Nothing was written."
            ),
        });
    };
    let allowed = |arm| ApiWorkflowGrant {
        owner: Some(owner),
        arm,
    };
    if caller == Some(owner) {
        return Ok(allowed(ApiWorkflowArm::Submitter));
    }
    if let Some(caller) = caller {
        // On the request's own transaction, not the raw pool (`no_unscoped_pool`).
        let op = epigraph_db::AgentRepository::operator_of_author(&mut *conn, owner)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("could not read the submitter's operator: {e}"),
            })?;
        if op.is_some_and(|l| l.operator_id == caller) {
            return Ok(allowed(ApiWorkflowArm::Operator));
        }
    }
    let subject = format!("workflow {workflow_id} was submitted by agent {owner}");
    if api_admin_arm(conn, auth, caller, &subject).await? {
        return Ok(allowed(ApiWorkflowArm::Admin));
    }
    Err(ApiError::Forbidden {
        reason: format!(
            "workflow {workflow_id} was submitted by agent {owner}; the caller is neither its \
             submitter, its submitter's operator, nor a live claims:admin holder. Nothing was \
             written."
        ),
    })
}

/// The PROVENANCE of a write admitted through the submitter or operator arm
/// (the MCP twin's `record_caller_workflow_write`, the same
/// `workflows.caller_write` row and fields), on the write's own transaction.
/// A no-op for an admin grant, which records [`audit_api_admin_workflow_write`].
/// The token fields are null on a route that carries no token
/// (`store_workflow`, which names its caller through the viewer).
#[cfg(feature = "db")]
#[allow(clippy::too_many_arguments)]
async fn record_api_caller_workflow_write(
    conn: &mut sqlx::PgConnection,
    auth: Option<&crate::middleware::bearer::AuthContext>,
    acting: Uuid,
    action: &str,
    workflow_id: Uuid,
    grant: ApiWorkflowGrant,
    details: serde_json::Value,
) -> Result<(), ApiError> {
    let (arm, operator) = match grant.arm {
        ApiWorkflowArm::Admin => return Ok(()),
        ApiWorkflowArm::Submitter => ("submitter", None),
        ApiWorkflowArm::Operator => ("operator", Some(acting)),
    };
    let record = serde_json::json!({
        "action": action,
        "workflow_id": workflow_id,
        "submitter": grant.owner,
        "arm": arm,
        "acting_agent": acting,
        "operator": operator,
        "client_id": auth.map(|a| a.client_id),
        "token_jti": auth.map(|a| a.jti),
        "write": details,
    });
    epigraph_db::SecurityEventRepository::workflow_caller_write(&mut *conn, &record)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!(
                "{action}: could not record the write's provenance: {e}. Nothing was written."
            ),
        })
}

/// The AUDITED admin arm of [`workflow_authority`], shared by a submitted
/// workflow (after its submitter and operator arms) and a legacy one (its only
/// arm): `claims:admin` in the token AND a live grant on the token's client
/// record (migration 111's predicate), never the scope alone. `Ok(true)`:
/// admitted. `Ok(false)`: no token, no principal, or no `claims:admin` scope.
/// A `claims:admin` token whose client record grants none is refused ADM02,
/// with `subject` naming the workflow.
#[cfg(feature = "db")]
async fn api_admin_arm(
    conn: &mut sqlx::PgConnection,
    auth: Option<&crate::middleware::bearer::AuthContext>,
    caller: Option<Uuid>,
    subject: &str,
) -> Result<bool, ApiError> {
    let (Some(a), Some(caller)) = (auth, caller) else {
        return Ok(false);
    };
    if !a.has_scope("claims:admin") {
        return Ok(false);
    }
    let live = epigraph_db::SecurityEventRepository::admin_grant_is_live(
        &mut *conn,
        a.client_id,
        caller,
        a.admin_scopes == epigraph_auth::AdminScopePosture::Armed,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("could not re-check the admin grant: {e}"),
    })?;
    if live {
        return Ok(true);
    }
    Err(ApiError::Forbidden {
        reason: format!(
            "{subject}; the token carries claims:admin, but its client record grants no live \
             claims:admin to this principal, so the audited admin path refused it (ADM02). \
             Nothing was written."
        ),
    })
}

/// Record a cross-owner workflow write admitted through the audited admin arm
/// (`workflows.admin_write`, the MCP twin's event type) on the write's own
/// transaction, so the two commit together or not at all.
#[cfg(feature = "db")]
async fn audit_api_admin_workflow_write(
    conn: &mut sqlx::PgConnection,
    auth: &crate::middleware::bearer::AuthContext,
    admin: Uuid,
    action: &str,
    workflow_id: Uuid,
    submitter: Option<Uuid>,
    details: serde_json::Value,
) -> Result<(), ApiError> {
    let record = serde_json::json!({
        "action": action,
        "workflow_id": workflow_id,
        "submitter": submitter,
        "write": details,
    });
    // Migration 112's definer: this transaction is stamped from the system
    // agent, whose session `security_events_append` would refuse an admin row.
    epigraph_db::SecurityEventRepository::admin_audit_write(
        &mut *conn,
        auth.client_id,
        auth.jti,
        admin,
        "workflows.admin_write",
        &record,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!(
            "{action}: could not write the admin audit row: {e}. Nothing was written."
        ),
    })
}

/// [`workflow_authority`] over the head of `canonical_name`, for the step routes.
/// An unknown name is left to the executor, which reports it as not found.
/// Returns the head and the grant, for the admin audit row.
#[cfg(feature = "db")]
async fn require_api_workflow_authority(
    conn: &mut sqlx::PgConnection,
    auth: &crate::middleware::bearer::AuthContext,
    canonical_name: &str,
) -> Result<Option<(Uuid, ApiWorkflowGrant)>, ApiError> {
    let head = epigraph_db::WorkflowRepository::head_by_canonical(&mut *conn, canonical_name)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("could not resolve the workflow: {e}"),
        })?;
    let Some(head) = head else {
        return Ok(None);
    };
    let grant = workflow_authority(conn, Some(auth), auth.agent_id, head).await?;
    Ok(Some((head, grant)))
}

/// Lineage-wide authority (the MCP twin is
/// `tools/evolve_step.rs::require_lineage_authority`):
/// [`workflow_authority`] for `caller` over EVERY workflow that executes the
/// step lineage of `parent`
/// (`WorkflowRepository::workflows_executing_step_lineage`: the parent and
/// every claim sharing its `step_lineage_id`, retracted `executes` edges
/// included). A step two workflows execute needs authority over both; the
/// head an earlier evolve left unexecuted is still gated through its lineage;
/// a lineage no workflow executes returns no grant and is unaffected.
///
/// `caller` must be the principal the step is authored as (the viewer's), so
/// the identity checked is the identity that writes. Run on the act's own
/// transaction, before the act. Returns each workflow with its grant, for
/// [`record_api_lineage_writes`].
#[cfg(feature = "db")]
async fn require_api_lineage_authority(
    conn: &mut sqlx::PgConnection,
    auth: &crate::middleware::bearer::AuthContext,
    caller: Uuid,
    parent: Uuid,
) -> Result<Vec<(Uuid, ApiWorkflowGrant)>, ApiError> {
    let workflows =
        epigraph_db::WorkflowRepository::workflows_executing_step_lineage(&mut *conn, parent)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!(
                    "evolve_step: could not read the workflows executing the step's lineage: {e}"
                ),
            })?;
    let mut grants = Vec::with_capacity(workflows.len());
    for workflow in workflows {
        let grant = workflow_authority(&mut *conn, Some(auth), Some(caller), workflow).await?;
        grants.push((workflow, grant));
    }
    Ok(grants)
}

/// Record an admitted `evolve_step` once per workflow
/// [`require_api_lineage_authority`] checked, on the act's own transaction:
/// [`audit_api_admin_workflow_write`] for the audited admin arm,
/// [`record_api_caller_workflow_write`] for the submitter and operator arms.
/// The rows are attributed to the session principal, here the caller itself,
/// whose stamp the step claim is written on.
#[cfg(feature = "db")]
async fn record_api_lineage_writes(
    conn: &mut sqlx::PgConnection,
    auth: &crate::middleware::bearer::AuthContext,
    caller: Uuid,
    grants: &[(Uuid, ApiWorkflowGrant)],
    details: serde_json::Value,
) -> Result<(), ApiError> {
    for (workflow, grant) in grants {
        if grant.is_admin() {
            audit_api_admin_workflow_write(
                &mut *conn,
                auth,
                caller,
                "evolve_step",
                *workflow,
                grant.owner,
                details.clone(),
            )
            .await?;
        } else {
            record_api_caller_workflow_write(
                &mut *conn,
                Some(auth),
                caller,
                "evolve_step",
                *workflow,
                *grant,
                details.clone(),
            )
            .await?;
        }
    }
    Ok(())
}

/// AUTHORSHIP (operator rulings, 2026-10-13; the MCP twin's
/// `epigraph_ingest_executor::record_caller_authorship` call): one `AUTHORED`
/// edge from the acting principal to each claim this request CREATED, on its
/// own (system-stamped) transaction. The claims stay the system agent's. A
/// request with no principal records nothing (it names no agent).
#[cfg(feature = "db")]
async fn record_api_authorship(
    conn: &mut sqlx::PgConnection,
    acting: Option<Uuid>,
    created: &[Uuid],
    route: &str,
) -> Result<(), ApiError> {
    let Some(acting) = acting else {
        return Ok(());
    };
    epigraph_ingest_executor::record_caller_authorship(conn, acting, created, route)
        .await
        .map(|_| ())
        .map_err(|e| ApiError::InternalError {
            message: format!("{route}: could not record authorship: {e}. Nothing was written."),
        })
}

/// What an ingest records, decided BEFORE the plan walk on the same
/// transaction (see [`workflow_ingest_submitter`]).
#[cfg(feature = "db")]
struct ApiIngestDecision {
    /// Whether this call creates the row (only then is a submitter recorded).
    creating: bool,
    /// The submitter to record when creating, if any.
    submitter: Option<Uuid>,
    /// Admitted through the audited admin arm over an existing lineage.
    admin: bool,
    /// Every anchor checked and the grant that admitted the caller over it,
    /// for the provenance rows.
    grants: Vec<(Uuid, ApiWorkflowGrant)>,
    /// The anchors checked, for the audit row.
    anchors: epigraph_db::repos::workflow::IngestAnchors,
}

/// The submitter an ingest should record, and the authority it needs, decided
/// BEFORE the plan walk on the same transaction. The rule is the MCP twin's
/// (`execute_workflow_ingest_with_inserted`): a re-ingest of an existing row
/// records nothing and needs nothing (the executor writes nothing); a NEW
/// generation of a canonical name that already has rows needs authority over
/// that lineage's head and inherits its submitter, parent or no parent (the
/// review's takeover: `generation + 1` with no parent recorded the attacker);
/// a variant also needs authority over exactly the row the executor links as
/// `parent_id`; a brand-new lineage records the caller, the viewer's principal.
#[cfg(feature = "db")]
async fn workflow_ingest_submitter(
    conn: &mut sqlx::PgConnection,
    auth: Option<&crate::middleware::bearer::AuthContext>,
    viewer: &epigraph_db::Viewer,
    extraction: &epigraph_ingest::workflow::WorkflowExtraction,
) -> Result<ApiIngestDecision, ApiError> {
    let caller = viewer.principal();
    let anchors = epigraph_db::WorkflowRepository::ingest_anchors(
        &mut *conn,
        &extraction.source.canonical_name,
        extraction.source.generation as i32,
        extraction.source.parent_canonical_name.as_deref(),
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("workflow ingest: {e}"),
    })?;
    let creating = anchors.existing.is_none();
    let mut inherited: Option<Option<Uuid>> = None;
    let mut admin = false;
    let mut grants = Vec::with_capacity(2);
    if creating {
        let mut checked: Vec<Uuid> = Vec::with_capacity(2);
        for anchor in [anchors.lineage_head, anchors.linked_parent]
            .into_iter()
            .flatten()
        {
            if checked.contains(&anchor) {
                continue;
            }
            checked.push(anchor);
            let grant = workflow_authority(conn, auth, caller, anchor).await?;
            admin |= grant.is_admin();
            inherited.get_or_insert(grant.owner);
            grants.push((anchor, grant));
        }
    }
    Ok(ApiIngestDecision {
        creating,
        submitter: inherited.unwrap_or(caller),
        admin,
        grants,
        anchors,
    })
}

/// Record the submitter [`workflow_ingest_submitter`] decided, once, and the
/// admin audit row when the ingest was admitted through the admin arm.
#[cfg(feature = "db")]
async fn record_workflow_submitter(
    conn: &mut sqlx::PgConnection,
    auth: Option<&crate::middleware::bearer::AuthContext>,
    viewer: &epigraph_db::Viewer,
    extraction: &epigraph_ingest::workflow::WorkflowExtraction,
    workflow_id: Uuid,
    decision: &ApiIngestDecision,
) -> Result<(), ApiError> {
    if decision.creating {
        if let Some(agent) = decision.submitter {
            epigraph_db::WorkflowRepository::record_submitter(&mut *conn, workflow_id, agent)
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("workflow ingest: could not record the submitter: {e}"),
                })?;
        }
    }
    // The provenance of the authority exercised over each existing anchor
    // through a non-admin arm (the MCP twin's per-anchor rows).
    if let Some(acting) = viewer.principal() {
        for (anchor, grant) in &decision.grants {
            record_api_caller_workflow_write(
                conn,
                auth,
                acting,
                "workflow_ingest",
                *anchor,
                *grant,
                serde_json::json!({
                    "created_workflow_id": workflow_id,
                    "canonical_name": extraction.source.canonical_name,
                    "generation": extraction.source.generation,
                    "parent_canonical_name": extraction.source.parent_canonical_name,
                    "lineage_head_before": decision.anchors.lineage_head,
                    "linked_parent": decision.anchors.linked_parent,
                    "recorded_submitter": decision.submitter,
                }),
            )
            .await?;
        }
    }
    if decision.admin {
        if let (Some(auth), Some(admin)) = (auth, viewer.principal()) {
            audit_api_admin_workflow_write(
                conn,
                auth,
                admin,
                "workflow_ingest",
                workflow_id,
                decision.submitter,
                serde_json::json!({
                    "canonical_name": extraction.source.canonical_name,
                    "generation": extraction.source.generation,
                    "parent_canonical_name": extraction.source.parent_canonical_name,
                    "lineage_head_before": decision.anchors.lineage_head,
                    "linked_parent": decision.anchors.linked_parent,
                }),
            )
            .await?;
        }
    }
    Ok(())
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

    let mut tx = begin_system_ingest_stamped_tx(&state, "workflows/steps", auth.agent_id).await?;
    let authority = require_api_workflow_authority(&mut tx, &auth, &req.canonical_name).await?;
    let r = epigraph_ingest_executor::add_step(
        &mut tx,
        &req.canonical_name,
        &req.step_text,
        req.position,
    )
    .await
    .map_err(map_step_err)?;
    if r.claim_created {
        record_api_authorship(&mut tx, auth.agent_id, &[r.step_claim_id], "add_step").await?;
    }
    if let (Some((head, grant)), Some(acting)) = (authority, auth.agent_id) {
        let details = serde_json::json!({
            "canonical_name": req.canonical_name,
            "step_claim_id": r.step_claim_id,
            "step_lineage_id": r.step_lineage_id,
            "step_index": r.step_index,
            "already_present": r.already_present,
        });
        if grant.is_admin() {
            audit_api_admin_workflow_write(
                &mut tx,
                &auth,
                acting,
                "add_step",
                head,
                grant.owner,
                details,
            )
            .await?;
        } else {
            record_api_caller_workflow_write(
                &mut tx,
                Some(&auth),
                acting,
                "add_step",
                head,
                grant,
                details,
            )
            .await?;
        }
    }
    tx.commit().await.map_err(|e| ApiError::InternalError {
        message: format!("add_step: could not commit: {e}"),
    })?;

    Ok(Json(serde_json::json!({
        "workflow_id": r.workflow_id,
        "step_claim_id": r.step_claim_id,
        "step_index": r.step_index,
        "plan_index": r.plan_index,
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

    let mut tx =
        begin_system_ingest_stamped_tx(&state, "workflows/steps/delete", auth.agent_id).await?;
    let authority = require_api_workflow_authority(&mut tx, &auth, &req.canonical_name).await?;
    let r =
        epigraph_ingest_executor::delete_step(&mut tx, &req.canonical_name, req.step_lineage_id)
            .await
            .map_err(map_step_err)?;
    if let (Some((head, grant)), Some(acting)) = (authority, auth.agent_id) {
        let details = serde_json::json!({
            "canonical_name": req.canonical_name,
            "step_claim_id": r.step_claim_id,
            "step_lineage_id": r.step_lineage_id,
            "truth_value_after": r.truth_value,
        });
        if grant.is_admin() {
            audit_api_admin_workflow_write(
                &mut tx,
                &auth,
                acting,
                "delete_step",
                head,
                grant.owner,
                details,
            )
            .await?;
        } else {
            record_api_caller_workflow_write(
                &mut tx,
                Some(&auth),
                acting,
                "delete_step",
                head,
                grant,
                details,
            )
            .await?;
        }
    }
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

    /// Backlog 563165f2 (HTTP twin of the MCP `success` definition): the
    /// OpenAPI schema of the outcome body both outcome routes take must say
    /// that `success` means the goal was achieved, not that the steps ran.
    #[test]
    fn report_outcome_success_is_defined_as_goal_achieved() {
        let schema =
            serde_json::to_value(<ReportOutcomeRequest as utoipa::PartialSchema>::schema())
                .expect("schema serializes");
        let d = schema["properties"]["success"]["description"]
            .as_str()
            .unwrap_or_else(|| panic!("`success` carries a description: {schema}"));
        for needle in [
            "goal or expected outcome was achieved",
            "every gate and check passed",
            "ran every step but a gate or",
        ] {
            assert!(
                d.contains(needle),
                "`success` must say {needle:?}; got: {d}"
            );
        }
    }

    /// U032: a step-less new generation (or an empty plan) is the caller's
    /// payload error — 400 with the executor's reason, not a 500 that invites
    /// a retry (the retry loop is what minted the empty generations).
    #[test]
    fn an_empty_generation_is_a_bad_request() {
        let e = workflow_ingest_error(
            epigraph_ingest_executor::IngestExecutorError::EmptyGeneration {
                canonical_name: "weekly-capability-audit".to_string(),
                generation: 3,
                level2: 0,
                claims: 1,
            },
        );
        match e {
            ApiError::BadRequest { message } => assert!(
                message.contains("empty workflow generation")
                    && message.contains("weekly-capability-audit"),
                "{message}"
            ),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// The executor's pre-flight refusal of blank claim content in the
    /// caller's payload is a 400 carrying the field path, not a 500 that
    /// invites a retry of a payload that can never succeed.
    #[test]
    fn blank_claim_content_is_a_bad_request() {
        let e = workflow_ingest_error(
            epigraph_ingest_executor::IngestExecutorError::InvalidContent {
                path: "phases[0].steps[0].operations[0]".to_string(),
            },
        );
        match e {
            ApiError::BadRequest { message } => assert!(
                message.starts_with("workflow ingest: ")
                    && message.contains("blank claim content at phases[0].steps[0].operations[0]"),
                "{message}"
            ),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// Render an `ApiError` the way a route answers it: status and JSON body.
    async fn rendered(e: ApiError) -> (StatusCode, serde_json::Value) {
        let response = axum::response::IntoResponse::into_response(e);
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("an in-memory body")
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).expect("a JSON error body"),
        )
    }

    /// The armed-and-unregistered refusal (migration 148) is the operator's
    /// remedy, so it is answered verbatim through the 500 redaction on both
    /// executor mapping sites, while any other executor 500 keeps its detail
    /// out of the body.
    #[tokio::test]
    async fn the_unregistered_system_agent_remedy_survives_the_500_redaction() {
        let role = epigraph_db::SystemAgentRole::WorkflowIngest.as_str();
        let unregistered =
            || epigraph_ingest_executor::IngestExecutorError::SystemAgentUnregistered { role };
        for (site, e) in [
            (
                "workflow_ingest_error",
                workflow_ingest_error(unregistered()),
            ),
            (
                "map_step_err",
                map_step_err(epigraph_ingest_executor::StepOpError::Executor(
                    unregistered(),
                )),
            ),
        ] {
            let (status, body) = rendered(e).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{site}: {body}");
            assert_eq!(body["error"], "InternalError", "{site}: {body}");
            let text = body.to_string();
            assert!(
                text.contains("not registered in system_agents")
                    && text.contains("register-system-agent --role workflow-ingest"),
                "{site}: the remedy reaches the caller: {body}"
            );
        }

        for (site, e) in [
            (
                "workflow_ingest_error",
                workflow_ingest_error(
                    epigraph_ingest_executor::IngestExecutorError::AgentCreation(
                        "secret-detail-3e91".to_string(),
                    ),
                ),
            ),
            (
                "map_step_err",
                map_step_err(epigraph_ingest_executor::StepOpError::Executor(
                    epigraph_ingest_executor::IngestExecutorError::AgentCreation(
                        "secret-detail-3e91".to_string(),
                    ),
                )),
            ),
        ] {
            let (status, body) = rendered(e).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{site}: {body}");
            assert!(
                !body.to_string().contains("secret-detail-3e91"),
                "{site}: any other executor 500 is redacted: {body}"
            );
        }
    }

    /// `system_agent_unregistered` hand-copies the executor's `Display` text
    /// (the variant needs a `&'static str`). Pin the copy to the source for
    /// every registered role, so an edit to the executor's remedy (CLI flags,
    /// migration number), or a new role landing on the generic fallback,
    /// fails here instead of drifting from what HTTP callers read.
    #[test]
    fn the_unregistered_system_agent_literal_matches_the_executor_text() {
        for role in epigraph_db::SystemAgentRole::ALL {
            let role = role.as_str();
            let ApiError::InternalErrorStatic { message } = system_agent_unregistered(role) else {
                panic!("{role}: expected InternalErrorStatic");
            };
            assert_eq!(
                message,
                epigraph_ingest_executor::IngestExecutorError::SystemAgentUnregistered { role }
                    .to_string(),
                "{role}: the HTTP literal drifted from the executor's error text"
            );
        }
    }

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

    /// Find or insert an agent holding the all-zero key, straight into `agents`,
    /// to stand in as a system author for these unit tests. It is NOT the
    /// registered workflow-ingest agent and never goes through
    /// `get_or_create_system_agent` (migration 148's registry).
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
    /// The admin scope the audited-arm tests add to a token: one spelling,
    /// so the admin-only literal ratchet (`tests/admin_scope_literals.rs`)
    /// counts test data once.
    const CLAIMS_ADMIN: &str = "claims:admin";

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
            family_id: None,
            elevation_claim: None,
            elevation: None,
            admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
            delegated_by: None,
        }
    }

    /// [`test_auth`] whose principal is a registered `agents` row, for a caller
    /// whose write succeeds: the `AUTHORED` edge it gets from every claim it
    /// creates is refused by `edges_validate_refs` for an agent that does not
    /// exist (in production a token's agent always does).
    async fn registered_auth(pool: &PgPool) -> crate::middleware::bearer::AuthContext {
        let auth = test_auth();
        sqlx::query(
            "INSERT INTO agents (id, public_key, display_name) \
             VALUES ($1, decode(md5(random()::text) || md5(random()::text), 'hex'), 'test caller')",
        )
        .bind(auth.agent_id)
        .execute(pool)
        .await
        .unwrap();
        auth
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
        let auth = registered_auth(&pool).await;
        axum::Router::new()
            .route("/api/v1/workflows/ingest", post(ingest_workflow))
            .layer(axum::Extension(auth))
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

    /// Through the route: a payload whose only step has a blank `compound` is
    /// answered 400 naming the field, and no `workflows` row is written.
    /// Positive control: the same payload with its content intact is a 200.
    #[sqlx::test(migrations = "../../migrations")]
    async fn ingest_workflow_http_refuses_blank_step_content_as_400(pool: PgPool) {
        let post = |app: axum::Router, payload: serde_json::Value| async move {
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/workflows/ingest")
                        .header("Content-Type", "application/json")
                        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, String::from_utf8_lossy(&bytes).into_owned())
        };
        let count = |pool: PgPool, name: &'static str| async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM workflows WHERE canonical_name = $1")
                .bind(name)
                .fetch_one(&pool)
                .await
                .unwrap()
        };
        let app = test_router(pool.clone()).await;

        let mut blank = ingest_payload("http-blank-step-content");
        blank["phases"][0]["steps"][0]["compound"] = serde_json::json!("   ");
        let (status, text) = post(app.clone(), blank).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
        assert!(
            text.contains("blank claim content at phases[0].steps[0]"),
            "the 400 names the field: {text}"
        );
        assert_eq!(count(pool.clone(), "http-blank-step-content").await, 0);

        let (status, text) = post(app, ingest_payload("http-intact-step-content")).await;
        assert_eq!(status, StatusCode::OK, "{text}");
        assert_eq!(count(pool, "http-intact-step-content").await, 1);
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
        attach_public_thesis(&pool, workflow_id).await;

        // Build a minimal axum app with just the outcome route, on a state
        // that can stamp the report's transaction (the route refuses to run
        // unstamped).
        let state = scoped_test_state(&pool).await;
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
                    .extension(outcome_reporter())
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

    /// Give a bare test root the one thing the outcome route requires of a
    /// workflow besides its row: a plan claim the reporter can read. One public
    /// level-0 (thesis) claim at `plan_index` 0, so no `step_index` resolves
    /// and the row counts these tests assert are unchanged.
    async fn attach_public_thesis(pool: &PgPool, workflow_id: uuid::Uuid) {
        // Inserted with its level rather than updated afterwards: the
        // route-layer write ratchet (`tests/viewer_route_table_lint.rs`) counts
        // an `UPDATE` of `claims` anywhere in this file.
        let content = format!("outcome test thesis {workflow_id}");
        let content_hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
        let thesis = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value, properties) \
             VALUES ($1, $2, $3, 0.5, jsonb_build_object('level', 0)) RETURNING id",
        )
        .bind(&content)
        .bind(content_hash.as_slice())
        .bind(ensure_system_agent(pool).await)
        .fetch_one(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
             VALUES ($1, 'workflow', $2, 'claim', 'executes', jsonb_build_object('plan_index', 0))",
        )
        .bind(workflow_id)
        .bind(thesis)
        .execute(pool)
        .await
        .unwrap();
    }

    /// The caller every outcome-route test reports as: an agent token holding
    /// `claims:write`, the scope the route requires. Its principal belongs to
    /// no group; the superuser test pool filters nothing, so these tests pin
    /// the counters / atomicity / embedding contract, not visibility (that is
    /// `tests/hierarchical_outcome_route_authority.rs`, on the app role).
    fn outcome_reporter() -> crate::middleware::bearer::AuthContext {
        let agent = uuid::Uuid::new_v4();
        crate::middleware::bearer::AuthContext {
            client_id: uuid::Uuid::new_v4(),
            agent_id: Some(agent),
            owner_id: Some(agent),
            client_type: crate::middleware::ClientType::Agent,
            scopes: vec!["claims:write".to_string()],
            jti: uuid::Uuid::new_v4(),
            family_id: None,
            elevation_claim: None,
            elevation: None,
            admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
            delegated_by: None,
        }
    }

    /// A bare hierarchical root plus the outcome route alone (U033 fixtures).
    async fn outcome_fixture(pool: &PgPool, canonical_name: &str) -> (axum::Router, uuid::Uuid) {
        let workflow_id = uuid::Uuid::new_v4();
        epigraph_db::WorkflowRepository::insert_root(
            pool,
            workflow_id,
            canonical_name,
            0,
            "Test workflow for outcome atomicity.",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();
        attach_public_thesis(pool, workflow_id).await;
        let state = scoped_test_state(pool).await;
        let app = axum::Router::new()
            .route(
                "/api/v1/workflows/hierarchical/:id/outcome",
                axum::routing::post(report_hierarchical_outcome),
            )
            .with_state(state);
        (app, workflow_id)
    }

    async fn post_outcome(
        app: axum::Router,
        workflow_id: uuid::Uuid,
        body: serde_json::Value,
    ) -> StatusCode {
        app.oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/workflows/hierarchical/{workflow_id}/outcome"
                ))
                .method("POST")
                .header("content-type", "application/json")
                .extension(outcome_reporter())
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    fn two_step_body(quality: Option<f64>) -> serde_json::Value {
        serde_json::json!({
            "success": true,
            "outcome_details": "ok",
            "quality": quality,
            "step_executions": [
                {"step_index": 0, "planned": "Step A", "actual": "done", "deviated": false},
                {"step_index": 1, "planned": "Step B", "actual": "done", "deviated": false}
            ]
        })
    }

    async fn outcome_counters_and_rows(
        pool: &PgPool,
        workflow_id: uuid::Uuid,
    ) -> (serde_json::Value, i64) {
        let metadata: serde_json::Value =
            sqlx::query_scalar("SELECT metadata FROM workflows WHERE id = $1")
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

    /// U033 / I229, HTTP twin: a step row the database refuses fails the
    /// whole report (5xx) and moves nothing. Real DB failure injection: a
    /// BEFORE INSERT trigger refusing only the second step. Before U033 the
    /// counters autocommitted first, step A landed, step B was logged and
    /// skipped, and the handler answered 200.
    #[sqlx::test(migrations = "../../migrations")]
    async fn report_hierarchical_outcome_is_all_or_nothing_when_a_step_row_fails(pool: PgPool) {
        let (app, workflow_id) = outcome_fixture(&pool, "outcome-atomic-http").await;
        // A SEQUENCE counts the step-row INSERTs the trigger saw: `nextval` is
        // not transactional, so the count survives the rollback and ties the
        // 500 to step B's refusal (the 500 body is redacted, so the error
        // text can no longer do that).
        sqlx::query("CREATE SEQUENCE u033_http_attempts")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE FUNCTION u033_http_fail() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN PERFORM nextval('u033_http_attempts'); \
             IF NEW.tool_pattern[1] = 'Step B' THEN RAISE EXCEPTION 'u033 injected'; END IF; \
             RETURN NEW; END $$",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER u033_http_fail BEFORE INSERT ON behavioral_executions \
             FOR EACH ROW EXECUTE FUNCTION u033_http_fail()",
        )
        .execute(&pool)
        .await
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/workflows/hierarchical/{workflow_id}/outcome"
                    ))
                    .method("POST")
                    .header("content-type", "application/json")
                    .extension(outcome_reporter())
                    .body(Body::from(two_step_body(None).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        // Tie the 500 to the injected refusal of step B, so an unrelated
        // early error (begin, lookup) cannot satisfy this test: the trigger
        // saw BOTH step rows, and step B's always raises.
        let attempts: i64 = sqlx::query_scalar("SELECT last_value FROM u033_http_attempts")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            attempts, 2,
            "the 500 must come from step B's refused row, after step A's INSERT ran"
        );
        // And the 500 body does not carry the database's error text
        // (F-route-error-text-remainder).
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body);
        assert!(
            !body.contains("u033 injected"),
            "the 500 body must not carry the database's error text: {body}"
        );
        let (metadata, rows) = outcome_counters_and_rows(&pool, workflow_id).await;
        assert!(
            metadata.get("use_count").is_none(),
            "counters must not move when a step row fails: {metadata}"
        );
        assert_eq!(rows, 0, "step A must roll back with step B");
    }

    /// U033 / I229, HTTP twin: an out-of-range `quality` is a 400 with no side
    /// effects, not a 200 whose step rows the CHECK silently refused.
    #[sqlx::test(migrations = "../../migrations")]
    async fn report_hierarchical_outcome_rejects_out_of_range_quality(pool: PgPool) {
        let (app, workflow_id) = outcome_fixture(&pool, "outcome-quality-http").await;
        for bad in [1.5_f64, -0.1] {
            let status = post_outcome(app.clone(), workflow_id, two_step_body(Some(bad))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "quality {bad}");
        }
        let (metadata, rows) = outcome_counters_and_rows(&pool, workflow_id).await;
        assert!(
            metadata.get("use_count").is_none(),
            "a refused report must not move counters: {metadata}"
        );
        assert_eq!(rows, 0, "a refused report must write no step rows");

        // Positive control: the boundary value lands, both rows included.
        let status = post_outcome(app, workflow_id, two_step_body(Some(1.0))).await;
        assert_eq!(status, StatusCode::OK);
        let (metadata, rows) = outcome_counters_and_rows(&pool, workflow_id).await;
        assert_eq!(metadata["use_count"], 1);
        assert_eq!(rows, 2);
    }

    /// U033 / I229, HTTP twin of the MCP row-lock test: the route's counter
    /// read takes `FOR UPDATE`, so a report arriving while another
    /// transaction holds the `workflows` row waits and then increments the
    /// committed value. The holder writes `use_count = 5` and keeps its lock
    /// until the report is observed blocked in `pg_stat_activity`. Without
    /// the lock the route reads the stale row, blocks only at its UPDATE, and
    /// then overwrites the 5 with 1.
    #[sqlx::test(migrations = "../../migrations")]
    async fn report_hierarchical_outcome_waits_for_a_held_counter_row(pool: PgPool) {
        let (app, workflow_id) = outcome_fixture(&pool, "outcome-row-lock-http").await;
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

        let report = tokio::spawn(post_outcome(app, workflow_id, two_step_body(None)));

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
        assert_eq!(report.await.expect("join"), StatusCode::OK);
        let (metadata, rows) = outcome_counters_and_rows(&pool, workflow_id).await;
        assert_eq!(
            metadata["use_count"], 6,
            "the report must increment the committed 5, not overwrite it: {metadata}"
        );
        assert_eq!(rows, 2);
    }

    /// `outcome_fixture` with a deterministic `MockProvider` as the embedding
    /// service: the OpenAI boundary is the only thing stood in for.
    async fn embedding_outcome_fixture(
        pool: &PgPool,
        canonical_name: &str,
    ) -> (axum::Router, uuid::Uuid) {
        use epigraph_embeddings::{EmbeddingConfig, MockProvider};
        let workflow_id = uuid::Uuid::new_v4();
        epigraph_db::WorkflowRepository::insert_root(
            pool,
            workflow_id,
            canonical_name,
            0,
            "Test workflow for outcome goal embedding.",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();
        attach_public_thesis(pool, workflow_id).await;
        let state = scoped_test_state(pool)
            .await
            .with_embedding_service(std::sync::Arc::new(MockProvider::new(
                EmbeddingConfig::openai(1536),
            )));
        let app = axum::Router::new()
            .route(
                "/api/v1/workflows/hierarchical/:id/outcome",
                axum::routing::post(report_hierarchical_outcome),
            )
            .with_state(state);
        (app, workflow_id)
    }

    async fn embedded_rows(pool: &PgPool, workflow_id: uuid::Uuid) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM behavioral_executions \
             WHERE workflow_id = $1 AND goal_embedding IS NOT NULL",
        )
        .bind(workflow_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// U033 / I229 part (4), HTTP twin: a real `goal_text` is embedded once
    /// and written on every step row, so the report feeds
    /// `behavioral_affinity_hierarchical`. Before U033 the route passed `None`
    /// and every row's `goal_embedding` was NULL.
    #[sqlx::test(migrations = "../../migrations")]
    async fn report_hierarchical_outcome_embeds_a_real_goal_on_every_step_row(pool: PgPool) {
        let (app, workflow_id) = embedding_outcome_fixture(&pool, "outcome-embed-http").await;
        let mut body = two_step_body(None);
        body["goal_text"] = serde_json::json!("Deploy with zero downtime");
        let status = post_outcome(app, workflow_id, body).await;
        assert_eq!(status, StatusCode::OK);
        let (_, rows) = outcome_counters_and_rows(&pool, workflow_id).await;
        assert_eq!(rows, 2, "both step rows land");
        assert_eq!(
            embedded_rows(&pool, workflow_id).await,
            2,
            "every step row carries the goal embedding"
        );
    }

    /// The other half of the route's goal filter: the `"hierarchical"`
    /// placeholder, blank text and an absent goal are not goals, and embedding
    /// them would make every such report "similar" to every other. The
    /// embedding service is configured, so a 0 here is the filter and nothing
    /// else (the positive twin above shows the same fixture does embed).
    #[sqlx::test(migrations = "../../migrations")]
    async fn report_hierarchical_outcome_does_not_embed_a_placeholder_or_blank_goal(pool: PgPool) {
        let (app, workflow_id) = embedding_outcome_fixture(&pool, "outcome-no-embed-http").await;
        for goal in [
            Some(serde_json::json!("hierarchical")),
            Some(serde_json::json!("   ")),
            None,
        ] {
            let mut body = two_step_body(None);
            if let Some(g) = goal {
                body["goal_text"] = g;
            }
            let status = post_outcome(app.clone(), workflow_id, body).await;
            assert_eq!(status, StatusCode::OK);
        }
        let (metadata, rows) = outcome_counters_and_rows(&pool, workflow_id).await;
        assert_eq!(metadata["use_count"], 3, "all three reports landed");
        assert_eq!(rows, 6);
        assert_eq!(
            embedded_rows(&pool, workflow_id).await,
            0,
            "no placeholder, blank or absent goal is embedded"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn report_hierarchical_outcome_404s_on_unknown_id(pool: PgPool) {
        let state = scoped_test_state(&pool).await;
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
                    .extension(outcome_reporter())
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

    /// Migration 105's personal-group refusal, wrapped by the executor, is a
    /// 403 on the workflow-ingest and step routes; every other executor failure
    /// stays a 500 (batch F review).
    #[test]
    fn a_personal_group_refusal_from_the_executor_is_a_403() {
        use epigraph_ingest_executor::{IngestExecutorError as X, StepOpError as S};
        let revoked = || epigraph_db::DbError::MembershipRevoked {
            message: "agent a holds only REVOKED membership(s) of its personal group g".into(),
        };
        assert!(matches!(
            workflow_ingest_error(X::Repository(revoked())),
            ApiError::Forbidden { .. }
        ));
        assert!(matches!(
            workflow_ingest_error(X::AgentCreation("preflight".into())),
            ApiError::InternalError { .. }
        ));
        assert!(matches!(
            map_step_err(S::Repo(revoked())),
            ApiError::Forbidden { .. }
        ));
        assert!(matches!(
            map_step_err(S::Executor(X::Repository(revoked()))),
            ApiError::Forbidden { .. }
        ));
        assert!(matches!(
            map_step_err(S::Executor(X::AgentCreation("preflight".into()))),
            ApiError::InternalError { .. }
        ));
    }

    /// Batch H-b, H3 over HTTP: the ingest records its caller as submitter,
    /// and `POST /api/v1/workflows/steps` then refuses a different caller
    /// (403, nothing written) while the submitter is admitted. The MCP twin is
    /// `epigraph-mcp/tests/workflow_caller_authority.rs`. Load-bearing: with
    /// `require_api_workflow_authority` a no-op the stranger's step lands and
    /// the 403 assertion fails.
    #[sqlx::test(migrations = "../../migrations")]
    async fn workflow_steps_refuse_a_caller_who_did_not_submit_the_workflow(pool: PgPool) {
        use axum::routing::post;
        let state = scoped_test_state(&pool).await;
        let owner = registered_auth(&pool).await;
        let stranger = test_auth();
        let router_as = |auth: crate::middleware::bearer::AuthContext| {
            axum::Router::new()
                .route("/api/v1/workflows/ingest", post(ingest_workflow))
                .route("/api/v1/workflows/steps", post(add_step))
                .layer(axum::Extension(auth))
                .with_state(state.clone())
        };
        let post_json = |uri: &str, body: serde_json::Value| {
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        };

        let resp = router_as(owner.clone())
            .oneshot(post_json(
                "/api/v1/workflows/ingest",
                ingest_payload("h3-http-owned"),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let recorded: Option<String> = sqlx::query_scalar(
            "SELECT metadata->>'epigraph_submitted_by' FROM workflows \
              WHERE canonical_name = 'h3-http-owned'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(recorded, owner.agent_id.map(|a| a.to_string()));

        // Counted through the workflow's `executes` edges, not a `claims`
        // content read: the route layer may not select claim content inline
        // (`viewer_route_table_lint`), its test module included.
        let executes_sql = "SELECT count(*) FROM edges e JOIN workflows w ON w.id = e.source_id \
                            WHERE w.canonical_name = 'h3-http-owned' AND e.relationship = 'executes'";
        let before: i64 = sqlx::query_scalar(executes_sql)
            .fetch_one(&pool)
            .await
            .unwrap();
        let step = serde_json::json!({
            "canonical_name": "h3-http-owned",
            "step_text": "a stranger's step",
        });
        let resp = router_as(stranger)
            .oneshot(post_json("/api/v1/workflows/steps", step.clone()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let after: i64 = sqlx::query_scalar(executes_sql)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(after, before, "nothing written");

        let resp = router_as(owner)
            .oneshot(post_json(
                "/api/v1/workflows/steps",
                serde_json::json!({"canonical_name": "h3-http-owned", "step_text": "the owner's step"}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "the submitter adds a step");
    }

    /// Batch H-b review, the HTTP twin of the MCP lineage-takeover and
    /// admin-arm findings: a stranger's `generation + 1` ingest with NO parent
    /// is refused (it used to record the stranger as submitter), a
    /// `claims:admin` token whose client record grants nothing is refused on
    /// the step route (it used to pass on the scope alone), and a live grant is
    /// admitted with one `workflows.admin_write` audit row.
    #[sqlx::test(migrations = "../../migrations")]
    async fn workflow_lineage_and_admin_arm_are_checked_over_http(pool: PgPool) {
        use axum::routing::post;
        let state = scoped_test_state(&pool).await;
        let owner = registered_auth(&pool).await;
        let stranger = test_auth();
        let router_as = |auth: crate::middleware::bearer::AuthContext| {
            axum::Router::new()
                .route("/api/v1/workflows/ingest", post(ingest_workflow))
                .route("/api/v1/workflows/steps", post(add_step))
                .layer(axum::Extension(auth))
                .with_state(state.clone())
        };
        let post_json = |uri: &str, body: serde_json::Value| {
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        };
        let resp = router_as(owner.clone())
            .oneshot(post_json(
                "/api/v1/workflows/ingest",
                ingest_payload("h3-http-lineage"),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut hijack = ingest_payload("h3-http-lineage");
        hijack["source"]["generation"] = serde_json::json!(1);
        hijack["phases"][0]["summary"] = serde_json::json!("the stranger's generation");
        let resp = router_as(stranger)
            .oneshot(post_json("/api/v1/workflows/ingest", hijack))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a parentless new generation of another caller's lineage"
        );
        let generations: Vec<(i32, Option<String>)> = sqlx::query_as(
            "SELECT generation, metadata->>'epigraph_submitted_by' FROM workflows \
              WHERE canonical_name = 'h3-http-lineage' ORDER BY generation",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            generations,
            vec![(0, owner.agent_id.map(|a| a.to_string()))],
            "nothing written"
        );

        let executes_sql = "SELECT count(*) FROM edges e JOIN workflows w ON w.id = e.source_id \
                            WHERE w.canonical_name = 'h3-http-lineage' AND e.relationship = 'executes'";
        let audits_sql = "SELECT count(*) FROM security_events \
                          WHERE event_type = 'workflows.admin_write' AND agent_id = $1";
        let before: i64 = sqlx::query_scalar(executes_sql)
            .fetch_one(&pool)
            .await
            .unwrap();
        let mut admin = test_auth();
        admin.scopes.push(CLAIMS_ADMIN.to_string());
        let admin_agent = admin.agent_id.unwrap();
        let resp = router_as(admin.clone())
            .oneshot(post_json(
                "/api/v1/workflows/steps",
                serde_json::json!({"canonical_name": "h3-http-lineage", "step_text": "a grantless admin's step"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "claims:admin in the token alone is not the audited admin path"
        );
        let after: i64 = sqlx::query_scalar(executes_sql)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(after, before, "nothing written");

        // The same token once its client record grants claims:admin.
        sqlx::query(
            "INSERT INTO agents (id, public_key, display_name) \
             VALUES ($1, decode(md5(random()::text) || md5(random()::text), 'hex'), 'h3 http admin')",
        )
        .bind(admin_agent)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, \
                                        granted_scopes, status, agent_id) \
             VALUES ($1, $2, 'h3 http admin', 'human', ARRAY['claims:admin'], \
                     ARRAY['claims:admin'], 'active', $3)",
        )
        .bind(admin.client_id)
        .bind(format!("h3-http-admin-{}", admin.client_id))
        .bind(admin_agent)
        .execute(&pool)
        .await
        .unwrap();
        let resp = router_as(admin)
            .oneshot(post_json(
                "/api/v1/workflows/steps",
                serde_json::json!({"canonical_name": "h3-http-lineage", "step_text": "an audited admin's step"}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "a live grant is admitted");
        let audits: i64 = sqlx::query_scalar(audits_sql)
            .bind(admin_agent)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(audits, 1, "and the admin write is audited");
    }

    /// U005 (backlog 84b2a98d), default decision A, the HTTP twin of
    /// `epigraph-mcp/tests/workflow_caller_authority.rs`: a workflow with no
    /// recorded submitter (every workflow written before batch H-b) is
    /// platform corpus. A `claims:write` stranger — and the agent that happened
    /// to ingest it, since nothing records that — is refused on the step route
    /// and on a new generation (403, nothing written); a live `claims:admin`
    /// grant is admitted and audited with `"submitter": null`. Before U005 the
    /// stranger's step and generation landed behind a WARN.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_legacy_workflow_is_refused_to_a_stranger_over_http(pool: PgPool) {
        use axum::routing::post;
        let state = scoped_test_state(&pool).await;
        let ingester = registered_auth(&pool).await;
        let stranger = test_auth();
        let router_as = |auth: crate::middleware::bearer::AuthContext| {
            axum::Router::new()
                .route("/api/v1/workflows/ingest", post(ingest_workflow))
                .route("/api/v1/workflows/steps", post(add_step))
                .route("/api/v1/workflows/steps/delete", post(delete_step))
                .layer(axum::Extension(auth))
                .with_state(state.clone())
        };
        let post_json = |uri: &str, body: serde_json::Value| {
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        };
        let resp = router_as(ingester.clone())
            .oneshot(post_json(
                "/api/v1/workflows/ingest",
                ingest_payload("h3-http-legacy"),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // The shape of every workflow written before batch H-b.
        sqlx::query(
            "UPDATE workflows SET metadata = metadata - 'epigraph_submitted_by' \
              WHERE canonical_name = 'h3-http-legacy'",
        )
        .execute(&pool)
        .await
        .unwrap();

        let executes_sql = "SELECT count(*) FROM edges e JOIN workflows w ON w.id = e.source_id \
                            WHERE w.canonical_name = 'h3-http-legacy' AND e.relationship = 'executes'";
        let before: i64 = sqlx::query_scalar(executes_sql)
            .fetch_one(&pool)
            .await
            .unwrap();
        for (who, auth) in [("a stranger", stranger.clone()), ("the ingester", ingester)] {
            let resp = router_as(auth)
                .oneshot(post_json(
                    "/api/v1/workflows/steps",
                    serde_json::json!({"canonical_name": "h3-http-legacy", "step_text": format!("{who}'s step")}),
                ))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{who}: a legacy workflow is platform corpus"
            );
            let body =
                String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes())
                    .to_string();
            assert!(body.contains("no recorded submitter"), "{who}: {body}");
            let after: i64 = sqlx::query_scalar(executes_sql)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(after, before, "{who}: nothing written");
        }

        // The delete route: refused for the same reason, the step's truth
        // untouched (main drove it to 0.05 behind the WARN).
        let lineage: Uuid = sqlx::query_scalar(
            "SELECT c.step_lineage_id FROM claims c JOIN edges e ON e.target_id = c.id \
               JOIN workflows w ON w.id = e.source_id \
              WHERE w.canonical_name = 'h3-http-legacy' AND c.step_lineage_id IS NOT NULL \
              LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let truths_sql = "SELECT truth_value FROM claims WHERE step_lineage_id = $1 ORDER BY id";
        let truths: Vec<f64> = sqlx::query_scalar(truths_sql)
            .bind(lineage)
            .fetch_all(&pool)
            .await
            .unwrap();
        let resp = router_as(stranger.clone())
            .oneshot(post_json(
                "/api/v1/workflows/steps/delete",
                serde_json::json!({"canonical_name": "h3-http-legacy", "step_lineage_id": lineage}),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a stranger's delete on a legacy workflow"
        );
        let body = String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes())
            .to_string();
        assert!(body.contains("no recorded submitter"), "delete: {body}");
        let truths_after: Vec<f64> = sqlx::query_scalar(truths_sql)
            .bind(lineage)
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(
            truths_after, truths,
            "delete: the step's truth is untouched"
        );

        let mut next = ingest_payload("h3-http-legacy");
        next["source"]["generation"] = serde_json::json!(1);
        next["phases"][0]["summary"] = serde_json::json!("a stranger's generation");
        let resp = router_as(stranger)
            .oneshot(post_json("/api/v1/workflows/ingest", next))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a new generation of a legacy lineage"
        );
        let body = String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes())
            .to_string();
        assert!(
            body.contains("no recorded submitter"),
            "generation 1 is refused by the legacy rule, not another 403: {body}"
        );
        let generations: Vec<(i32, Option<String>)> = sqlx::query_as(
            "SELECT generation, metadata->>'epigraph_submitted_by' FROM workflows \
              WHERE canonical_name = 'h3-http-legacy' ORDER BY generation",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(generations, vec![(0, None)], "nothing written");

        // CALIBRATION: the audited admin arm admits, and records no submitter.
        let mut admin = test_auth();
        admin.scopes.push(CLAIMS_ADMIN.to_string());
        let admin_agent = admin.agent_id.unwrap();
        let audits_sql = "SELECT count(*) FROM security_events \
                          WHERE event_type = 'workflows.admin_write' AND agent_id = $1";

        // claims:admin in the token alone, before its client record grants it:
        // the audited admin arm refuses it ADM02 (not a silent "no admin"),
        // naming the legacy workflow, and nothing is written or audited.
        let resp = router_as(admin.clone())
            .oneshot(post_json(
                "/api/v1/workflows/steps",
                serde_json::json!({"canonical_name": "h3-http-legacy", "step_text": "a grantless admin's step"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "claims:admin in the token alone does not admit a legacy workflow"
        );
        let body = String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes())
            .to_string();
        assert!(body.contains("ADM02"), "grantless admin: {body}");
        assert!(
            body.contains("no recorded submitter"),
            "grantless admin: {body}"
        );
        let after: i64 = sqlx::query_scalar(executes_sql)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(after, before, "grantless admin: nothing written");
        let audits: i64 = sqlx::query_scalar(audits_sql)
            .bind(admin_agent)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(audits, 0, "grantless admin: nothing audited");

        sqlx::query(
            "INSERT INTO agents (id, public_key, display_name) \
             VALUES ($1, decode(md5(random()::text) || md5(random()::text), 'hex'), 'u005 http admin')",
        )
        .bind(admin_agent)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, \
                                        granted_scopes, status, agent_id) \
             VALUES ($1, $2, 'u005 http admin', 'human', ARRAY['claims:admin'], \
                     ARRAY['claims:admin'], 'active', $3)",
        )
        .bind(admin.client_id)
        .bind(format!("u005-http-admin-{}", admin.client_id))
        .bind(admin_agent)
        .execute(&pool)
        .await
        .unwrap();
        let resp = router_as(admin)
            .oneshot(post_json(
                "/api/v1/workflows/steps",
                serde_json::json!({"canonical_name": "h3-http-legacy", "step_text": "an audited admin's step"}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "a live grant is admitted");
        let after: i64 = sqlx::query_scalar(executes_sql)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(after, before + 1);
        let submitter_kinds: Vec<Option<String>> = sqlx::query_scalar(
            "SELECT jsonb_typeof(details->'submitter') FROM security_events \
              WHERE event_type = 'workflows.admin_write' AND agent_id = $1",
        )
        .bind(admin_agent)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            submitter_kinds,
            vec![Some("null".to_string())],
            "one audit row, \"submitter\": null"
        );
    }

    /// An agent row, and (when `client_type` is given) an ACTIVE OAuth client
    /// of that type for it; returns `(agent, client)`.
    async fn seed_bound_agent(pool: &PgPool, label: &str, client_type: &str) -> (Uuid, Uuid) {
        let agent: Uuid = sqlx::query_scalar(
            "INSERT INTO agents (public_key, display_name) \
             VALUES (decode(md5(random()::text) || md5(random()::text), 'hex'), $1) RETURNING id",
        )
        .bind(label)
        .fetch_one(pool)
        .await
        .unwrap();
        let client: Uuid = sqlx::query_scalar(
            "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                        status, agent_id, legal_entity_name, legal_contact_email) \
             VALUES ($1, $2, $3, ARRAY['claims:write'], 'active', $4, \
                     'Fixture Org', 'fixture@example.invalid') RETURNING id",
        )
        .bind(format!("{label}-{agent}"))
        .bind(label)
        .bind(client_type)
        .bind(agent)
        .fetch_one(pool)
        .await
        .unwrap();
        (agent, client)
    }

    /// A registered human operator (migration 122 section 1c).
    async fn seed_human_operator(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
        let (agent, client) = seed_bound_agent(pool, label, "human").await;
        sqlx::query(
            "INSERT INTO human_operators (agent_id, client_id, reason) VALUES ($1, $2, 'test')",
        )
        .bind(agent)
        .bind(client)
        .execute(pool)
        .await
        .unwrap();
        (agent, client)
    }

    /// The agent of a service client ALLOWLISTED for `operator` (migration
    /// 149, arm (c)), through the real maintenance definer.
    async fn seed_allowlisted_agent(pool: &PgPool, operator: Uuid, label: &str) -> (Uuid, Uuid) {
        use sqlx::Executor;
        let (agent, client) = seed_bound_agent(pool, label, "service").await;
        let mut conn = pool.acquire().await.unwrap();
        conn.execute("SET SESSION AUTHORIZATION epigraph_maintenance")
            .await
            .unwrap();
        let binding: Option<String> = sqlx::query_scalar(
            "SELECT effective_binding \
               FROM public.epigraph_allow_author_binding_client($1, $2, 'test')",
        )
        .bind(client)
        .bind(operator)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        conn.execute("RESET SESSION AUTHORIZATION").await.unwrap();
        assert_eq!(
            binding.as_deref(),
            Some(epigraph_db::CLIENT_ALLOWLIST_BINDING),
            "calibration: {label} is allowlisted"
        );
        (agent, client)
    }

    /// The operator ruling over HTTP (2026-10-13; the MCP twin is
    /// `epigraph-mcp/tests/workflow_write_provenance.rs`): on a workflow whose
    /// recorded submitter is the human H, an agent bound to H (an allowlisted
    /// client of H, the shape a host's shared credential takes) is REFUSED 403
    /// with nothing written and no provenance row; H itself is admitted (the
    /// submitter arm) with one `workflows.caller_write` row naming it.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_bound_agent_is_refused_and_the_submitting_human_admitted_over_http(pool: PgPool) {
        use axum::routing::post;
        let state = scoped_test_state(&pool).await;
        let router_as = |auth: crate::middleware::bearer::AuthContext| {
            axum::Router::new()
                .route("/api/v1/workflows/ingest", post(ingest_workflow))
                .route("/api/v1/workflows/steps", post(add_step))
                .layer(axum::Extension(auth))
                .with_state(state.clone())
        };
        let post_json = |uri: &str, body: serde_json::Value| {
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        };
        let as_agent = |agent: Uuid, client: Uuid| {
            let mut a = test_auth();
            a.client_id = client;
            a.owner_id = Some(client);
            a.agent_id = Some(agent);
            a
        };
        let (h, h_client) = seed_human_operator(&pool, "h3-la-human").await;
        let (agent, client) = seed_allowlisted_agent(&pool, h, "h3-la-agent").await;
        let authored_sql = "SELECT source_id FROM edges \
                            WHERE relationship = 'AUTHORED' AND source_type = 'agent' \
                              AND target_type = 'claim' AND target_id = $1";
        let authored_total = "SELECT count(*) FROM edges WHERE relationship = 'AUTHORED'";

        let ingester = registered_auth(&pool).await;
        let resp = router_as(ingester.clone())
            .oneshot(post_json(
                "/api/v1/workflows/ingest",
                ingest_payload("h3-http-linked"),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let wf: Uuid = sqlx::query_scalar(
            "UPDATE workflows \
                SET metadata = jsonb_set(metadata, '{epigraph_submitted_by}', to_jsonb($1::text)) \
              WHERE canonical_name = 'h3-http-linked' RETURNING id",
        )
        .bind(h)
        .fetch_one(&pool)
        .await
        .unwrap();
        // Authorship of what the ingest created: one AUTHORED edge from the
        // ingesting principal per executed claim (all new in this database).
        let executed: Vec<Uuid> = sqlx::query_scalar(
            "SELECT target_id FROM edges WHERE source_id = $1 AND relationship = 'executes'",
        )
        .bind(wf)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(!executed.is_empty());
        for c in &executed {
            let sources: Vec<Uuid> = sqlx::query_scalar(authored_sql)
                .bind(c)
                .fetch_all(&pool)
                .await
                .unwrap();
            assert_eq!(sources, vec![ingester.agent_id.unwrap()], "claim {c}");
        }
        let authored_before: i64 = sqlx::query_scalar(authored_total)
            .fetch_one(&pool)
            .await
            .unwrap();
        let executes_sql = "SELECT count(*) FROM edges e JOIN workflows w ON w.id = e.source_id \
                            WHERE w.canonical_name = 'h3-http-linked' AND e.relationship = 'executes'";
        let provenance_sql = "SELECT agent_id, details FROM security_events \
                              WHERE event_type = 'workflows.caller_write' \
                                AND details->>'workflow_id' = $1::text";
        let before: i64 = sqlx::query_scalar(executes_sql)
            .fetch_one(&pool)
            .await
            .unwrap();

        let resp = router_as(as_agent(agent, client))
            .oneshot(post_json(
                "/api/v1/workflows/steps",
                serde_json::json!({"canonical_name": "h3-http-linked", "step_text": "H's agent's step"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "an agent bound to the submitting human is not admitted over HTTP"
        );
        let mid: i64 = sqlx::query_scalar(executes_sql)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(mid, before, "nothing written");
        let rows: Vec<(Option<Uuid>, serde_json::Value)> = sqlx::query_as(provenance_sql)
            .bind(wf)
            .fetch_all(&pool)
            .await
            .unwrap();
        assert!(rows.is_empty(), "no provenance for a refusal: {rows:?}");
        let authored_mid: i64 = sqlx::query_scalar(authored_total)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            authored_mid, authored_before,
            "no AUTHORED edge for a refusal"
        );

        let auth = as_agent(h, h_client);
        let resp = router_as(auth.clone())
            .oneshot(post_json(
                "/api/v1/workflows/steps",
                serde_json::json!({"canonical_name": "h3-http-linked", "step_text": "H's own step"}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "the submitting human");
        let step = parse_body(resp).await["step_claim_id"]
            .as_str()
            .unwrap()
            .to_string();
        let after: i64 = sqlx::query_scalar(executes_sql)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(after, before + 1);
        let stamp: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1::uuid")
            .bind(&step)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_ne!(stamp, h, "the system agent still authors the step");
        let sources: Vec<Uuid> = sqlx::query_scalar(authored_sql)
            .bind(Uuid::parse_str(&step).unwrap())
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(
            sources,
            vec![h],
            "one AUTHORED edge from the acting principal"
        );
        let rows: Vec<(Option<Uuid>, serde_json::Value)> = sqlx::query_as(provenance_sql)
            .bind(wf)
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        let (row_agent, d) = &rows[0];
        assert_eq!(
            *row_agent,
            Some(stamp),
            "attributed to the session's system stamp"
        );
        assert_eq!(d["action"], "add_step");
        assert_eq!(d["submitter"], h.to_string());
        assert_eq!(d["arm"], "submitter");
        assert_eq!(d["acting_agent"], h.to_string());
        assert_eq!(d["operator"], serde_json::Value::Null);
        assert_eq!(d["client_id"], h_client.to_string());
        assert_eq!(d["token_jti"], auth.jti.to_string());
        assert_eq!(d["write"]["step_claim_id"], step.as_str());
    }
}
