#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::ds_auto;
use crate::types::*;

use epigraph_core::{AgentId, Claim, ClaimId, Evidence, EvidenceType, TruthValue};
use epigraph_crypto::ContentHasher;
use epigraph_db::{
    BehavioralExecutionRepository, ClaimRepository, EdgeRepository, EvidenceRepository,
    WorkflowRepository,
};

use crate::embed::format_pgvector;

/// Load the evidence-type weight from CalibrationConfig.
///
/// Checks `CALIBRATION_PATH` env var first, then falls back to the
/// relative path "calibration.toml". On any failure silently returns 0.7.
fn load_evidence_type_weight(evidence_type: &str) -> f64 {
    let path = std::env::var("CALIBRATION_PATH").unwrap_or_else(|_| "calibration.toml".to_string());
    epigraph_engine::calibration::CalibrationConfig::load(std::path::Path::new(&path))
        .ok()
        .map(|c| c.get_evidence_type_weight(evidence_type))
        .unwrap_or(0.7)
}

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

/// Read-only window into a workflow's recent behavioral executions, newest
/// first: per-run `success`, `quality`, `tool_pattern`, `deviation_count`, and
/// `step_beliefs` (per-step `deviation_reason`), plus a `window_success_rate`.
/// This is the telemetry the workflow-evolution proposer reads before
/// proposing a variant; an invalid `workflow_id` errors rather than returning
/// an empty set (which would read as "no runs" and mislead the proposer).
pub async fn get_workflow_executions(
    server: &EpiGraphMcpFull,
    params: GetWorkflowExecutionsParams,
) -> Result<CallToolResult, McpError> {
    let workflow_id = parse_uuid(params.workflow_id.trim())?;
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    let rows = BehavioralExecutionRepository::recent_executions(&server.pool, workflow_id, limit)
        .await
        .map_err(internal_error)?;

    let returned = rows.len();
    let successes = rows.iter().filter(|r| r.success).count();
    let window_success_rate = if returned > 0 {
        successes as f64 / returned as f64
    } else {
        0.0
    };
    let executions: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "goal_text": r.goal_text,
                "success": r.success,
                "quality": r.quality,
                "deviation_count": r.deviation_count,
                "total_steps": r.total_steps,
                "tool_pattern": r.tool_pattern,
                "step_beliefs": r.step_beliefs,
                "run_label": r.run_label,
                "created_at": r.created_at,
            })
        })
        .collect();

    success_json(&serde_json::json!({
        "workflow_id": workflow_id,
        "returned": returned,
        "window_success_rate": window_success_rate,
        "executions": executions,
    }))
}

/// Evaluate whether a workflow variant is statistically ready to be promoted
/// over its immediate (`variant_of`) parent — the autonomous-statistical-gate
/// verdict the workflow-evolution maintenance pass consumes. Resolves the
/// parent, compares both sides over the SAME execution window with the Wilson
/// lower-bound gate, and returns the verdict. READ-ONLY: it decides, it does
/// not promote (applying a promotion is a separate, deliberate step).
pub async fn evaluate_workflow_promotion(
    server: &EpiGraphMcpFull,
    params: EvaluateWorkflowPromotionParams,
) -> Result<CallToolResult, McpError> {
    let variant_id = parse_uuid(params.workflow_id.trim())?;
    let window = params.window.unwrap_or(50).clamp(1, 500);
    let assessment = assess_workflow_promotion(server, variant_id, window).await?;
    success_json(&assessment.to_json())
}

/// One workflow variant's promotion assessment: its parent (if any), both
/// sides' counts over the same window, and the gate verdict. Shared by the
/// read-only `evaluate_workflow_promotion` tool and the write-side
/// `refresh_workflow_promotion` pass so both compute the verdict identically.
struct PromotionAssessment {
    variant_id: uuid::Uuid,
    parent_id: Option<uuid::Uuid>,
    window: i64,
    min_executions: i64,
    variant: (i64, i64),
    parent: (i64, i64),
    /// `None` exactly when the workflow has no parent (a lineage root).
    verdict: Option<epigraph_engine::workflow_promotion::WorkflowPromotionVerdict>,
}

impl PromotionAssessment {
    fn parent_rate(&self) -> f64 {
        let (s, t) = self.parent;
        if t <= 0 {
            0.0
        } else {
            s as f64 / t as f64
        }
    }

    fn to_json(&self) -> serde_json::Value {
        match &self.verdict {
            None => serde_json::json!({
                "workflow_id": self.variant_id,
                "parent_id": serde_json::Value::Null,
                "promotable": false,
                "reason": "workflow has no variant_of/supersedes parent (it is a lineage root); nothing to promote over",
            }),
            Some(v) => serde_json::json!({
                "workflow_id": self.variant_id,
                "parent_id": self.parent_id,
                "window": self.window,
                "min_executions": self.min_executions,
                "variant": { "successes": self.variant.0, "total": self.variant.1 },
                "parent": { "successes": self.parent.0, "total": self.parent.1, "success_rate": self.parent_rate() },
                "promotable": v.promotable,
                "variant_lower_bound": v.variant_lower_bound,
                "parent_rate": v.parent_rate,
                "reason": v.reason,
            }),
        }
    }
}

/// Resolve the variant's immediate parent, pull both sides' (successes, total)
/// over the SAME window (mixing windows would be apples-to-oranges), and apply
/// the Wilson gate. A lineage root yields `verdict: None`.
async fn assess_workflow_promotion(
    server: &EpiGraphMcpFull,
    variant_id: uuid::Uuid,
    window: i64,
) -> Result<PromotionAssessment, McpError> {
    use epigraph_engine::workflow_promotion::{
        evaluate_workflow_promotion as gate, WorkflowPromotionConfig, WorkflowSampleStats,
    };
    let config = WorkflowPromotionConfig::default();

    let parent_id = WorkflowRepository::immediate_variant_parent(&server.pool, variant_id)
        .await
        .map_err(|e| internal_error(e.to_string()))?;

    let variant = BehavioralExecutionRepository::success_stats(&server.pool, variant_id, window)
        .await
        .map_err(internal_error)?;

    let (parent, verdict) = match parent_id {
        None => ((0, 0), None),
        Some(pid) => {
            let parent = BehavioralExecutionRepository::success_stats(&server.pool, pid, window)
                .await
                .map_err(internal_error)?;
            let parent_rate = if parent.1 <= 0 {
                0.0
            } else {
                parent.0 as f64 / parent.1 as f64
            };
            let v = gate(
                &WorkflowSampleStats {
                    successes: variant.0,
                    total: variant.1,
                },
                parent_rate,
                &config,
            );
            (parent, Some(v))
        }
    };

    Ok(PromotionAssessment {
        variant_id,
        parent_id,
        window,
        min_executions: config.min_executions,
        variant,
        parent,
        verdict,
    })
}

/// Apply layer (additive promotable flag). Re-evaluate a workflow variant's
/// promotion verdict and write it to the variant claim's
/// `properties.promotion`, OVERWRITING any prior value. This is bidirectional
/// by construction: a variant that has regressed below threshold gets
/// `promotable: false` on the next run rather than keeping a stale `true`. A
/// lineage root (no parent) is left untouched. The maintenance pass / scheduled
/// job calls this per candidate variant; `find_workflow` surfaces the flag.
pub async fn refresh_workflow_promotion(
    server: &EpiGraphMcpFull,
    params: EvaluateWorkflowPromotionParams,
) -> Result<CallToolResult, McpError> {
    let variant_id = parse_uuid(params.workflow_id.trim())?;
    let window = params.window.unwrap_or(50).clamp(1, 500);
    let assessment = assess_workflow_promotion(server, variant_id, window).await?;

    let Some(verdict) = &assessment.verdict else {
        return success_json(&serde_json::json!({
            "workflow_id": variant_id,
            "refreshed": false,
            "reason": "lineage root (no variant_of parent); nothing to promote over",
        }));
    };

    // Overwrite properties.promotion with the CURRENT verdict (provenance for
    // audit + demotion). Overwriting — not a write-once set — is what keeps the
    // flag honest as more executions accrue.
    let promotion = serde_json::json!({
        "promotion": {
            "promotable": verdict.promotable,
            "lower_bound": verdict.variant_lower_bound,
            "parent_rate": verdict.parent_rate,
            "parent_id": assessment.parent_id,
            "n": assessment.variant.1,
            "evaluated_at": chrono::Utc::now().to_rfc3339(),
        }
    });
    ClaimRepository::merge_properties(
        &server.pool,
        epigraph_core::ClaimId::from_uuid(variant_id),
        &promotion,
    )
    .await
    .map_err(internal_error)?;

    success_json(&serde_json::json!({
        "workflow_id": variant_id,
        "parent_id": assessment.parent_id,
        "refreshed": true,
        "promotable": verdict.promotable,
        "variant_lower_bound": verdict.variant_lower_bound,
        "parent_rate": verdict.parent_rate,
        "reason": verdict.reason,
    }))
}

fn parse_workflow_content(content: &str) -> (String, Vec<String>, Vec<String>, Option<String>) {
    serde_json::from_str::<serde_json::Value>(content).map_or_else(
        |_| (content.to_string(), vec![], vec![], None),
        |val| {
            let goal = val
                .get("goal")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            let steps: Vec<String> = val
                .get("steps")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            let prereqs: Vec<String> = val
                .get("prerequisites")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            let expected_outcome = val
                .get("expected_outcome")
                .and_then(serde_json::Value::as_str)
                .map(String::from);
            (goal, steps, prereqs, expected_outcome)
        },
    )
}

/// Lowercase ASCII slug; non-alnum -> `-`; collapse runs; trim.
fn slugify_workflow_goal(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Override for the goal-similarity floor at which `store_workflow` treats a
/// paraphrased goal as the SAME lineage rather than a new one.
const GOAL_MERGE_THRESHOLD_ENV: &str = "EPIGRAPH_WORKFLOW_MERGE_THRESHOLD";

/// Default identity-merge floor. Deliberately far stricter than
/// `find_workflow_hierarchical`'s 0.5 retrieval floor: a loose RETRIEVAL floor
/// is recoverable (the caller just ignores a bad hit), a loose IDENTITY floor
/// is not — the workflow id is deterministic in `(canonical_name, generation)`,
/// so there is no un-merge once two lineages have been welded together.
const DEFAULT_GOAL_MERGE_THRESHOLD: f64 = 0.92;

/// Parse the merge threshold from its env var, falling back to
/// [`DEFAULT_GOAL_MERGE_THRESHOLD`] on absent, unparseable, or non-finite input.
///
/// Pure so it can be unit-tested without touching the process environment.
/// Setting a value above 1.0 disables goal merging outright — cosine similarity
/// never exceeds 1, so no candidate can ever clear the floor and every call
/// falls back to today's slug-only identity.
fn merge_threshold_from_env(raw: Option<&str>) -> f64 {
    raw.and_then(|s| s.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite())
        .unwrap_or(DEFAULT_GOAL_MERGE_THRESHOLD)
}

/// Outcome of resolving a `store_workflow` goal against existing lineages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GoalIdentity {
    /// No semantic match (or an exact-slug lineage already exists): mint/reuse
    /// the slug lineage at generation 0, exactly as `store_workflow` always did.
    NewRoot(String),
    /// A row in a matched lineage already carries this exact goal text — reuse
    /// its `(canonical_name, generation)` so repeat calls stay idempotent.
    Existing {
        canonical_name: String,
        generation: u32,
    },
    /// The goal is a paraphrase of a matched lineage: add a generation to it
    /// instead of forking a brand-new root.
    DriftedInto { canonical_name: String },
}

/// Decide which lineage a `store_workflow` goal belongs to. Pure — no DB, no
/// embedder — so the whole decision table is unit-testable offline.
///
/// `candidates` MUST already be threshold-filtered and ordered closest-first;
/// that is exactly `WorkflowRepository::find_hierarchical_by_embedding`'s
/// contract, so `candidates[0]` is the nearest surviving lineage.
///
/// Rules, in order:
/// 1. An exact-slug lineage wins outright — identity beats semantics, and this
///    reproduces today's behaviour verbatim for every goal already in the graph.
/// 2. Otherwise a candidate carrying this exact goal text (case- and
///    whitespace-insensitive) is reused at its own generation. This is what
///    keeps the drift path idempotent: calling twice with the same paraphrase
///    re-attaches instead of stacking a fresh generation each time.
/// 3. Otherwise the closest candidate's lineage absorbs the goal as drift.
/// 4. Otherwise mint a new root from the slug.
pub(crate) fn resolve_goal_identity(
    goal: &str,
    slug: &str,
    slug_lineage_exists: bool,
    candidates: &[epigraph_db::HierarchicalWorkflowRow],
) -> GoalIdentity {
    if slug_lineage_exists {
        return GoalIdentity::NewRoot(slug.to_string());
    }

    let needle = goal.trim();
    for row in candidates {
        if row.goal.trim().eq_ignore_ascii_case(needle) {
            // A negative generation is not representable upstream
            // (`WorkflowSource::generation` is u32); skip such a row rather
            // than error, and let the drift rule handle the lineage.
            if let Ok(generation) = u32::try_from(row.generation) {
                return GoalIdentity::Existing {
                    canonical_name: row.canonical_name.clone(),
                    generation,
                };
            }
        }
    }

    match candidates.first() {
        Some(row) => GoalIdentity::DriftedInto {
            canonical_name: row.canonical_name.clone(),
        },
        None => GoalIdentity::NewRoot(slug.to_string()),
    }
}

/// Project a [`GoalIdentity`] onto the `(canonical_name, generation,
/// parent_canonical_name)` triple that `WorkflowSource` needs. Pure.
///
/// `parent_canonical_name` is only meaningful in concert with `generation`:
/// `epigraph-ingest-executor/src/workflow.rs` resolves the parent row as
/// `find_root_by_canonical(parent_canonical_name, generation - 1)`, so a drift
/// MUST land at `lineage_max_generation + 1` or neither `parent_id` nor the
/// `variant_of` edge resolves. This mirrors `improve_workflow_hierarchy`
/// exactly.
///
/// The `Existing` arm leaves the parent `None` on purpose: that row already
/// exists, so the executor's idempotency gate short-circuits. If it is a zombie
/// row with zero `executes` edges, `insert_root`'s `ON CONFLICT DO NOTHING`
/// leaves it untouched and the call merely backfills the claims and edges.
fn source_identity(
    identity: GoalIdentity,
    lineage_max_generation: u32,
) -> (String, u32, Option<String>) {
    match identity {
        GoalIdentity::NewRoot(name) => (name, 0, None),
        GoalIdentity::Existing {
            canonical_name,
            generation,
        } => (canonical_name, generation, None),
        GoalIdentity::DriftedInto { canonical_name } => (
            canonical_name.clone(),
            lineage_max_generation.saturating_add(1),
            Some(canonical_name),
        ),
    }
}

/// Store a new hierarchical workflow.
///
/// Input shape stays simple (`goal` + `steps[]`); internally builds a
/// `WorkflowExtraction` and runs the hierarchical ingest pipeline. Each step
/// becomes a first-class claim under a single `"Body"` phase. The workflow
/// itself is a row in the `workflows` table, identified by a deterministic
/// UUID from `(canonical_name, generation)`. Idempotent on `canonical_name`.
///
/// Identity is NOT slug-only. `slugify_workflow_goal` alone forks a fresh
/// lineage root for every paraphrase ("Deploy the API" vs "Deploy API
/// service"), so when an embedder is available the goal is matched against
/// existing lineages at a strict floor and drift is absorbed as a new
/// generation of the matched lineage. `identity_resolution` /
/// `merged_into_goal` in the response make that merge visible to the caller.
pub async fn store_workflow(
    server: &EpiGraphMcpFull,
    params: StoreWorkflowParams,
) -> Result<CallToolResult, McpError> {
    use epigraph_ingest::common::schema::ThesisDerivation;
    use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
    use epigraph_ingest::workflow::WorkflowExtraction;

    let slug = slugify_workflow_goal(&params.goal);

    // Hoisted from the post-ingest embedding block below so ONE embedding
    // serves both lineage matching and `workflows.goal_embedding` — this is a
    // move, not an extra OpenAI call. A mock or disabled embedder returns Err
    // here, which collapses the whole path back to today's slug-only identity;
    // no separate `is_mock()` guard is needed.
    let goal_vec: Option<Vec<f32>> = server
        .embedder
        .generate(&params.goal)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "store_workflow: goal embedding unavailable; falling back to slug identity");
        })
        .ok();

    // `lineage_max` is only read on the drift arm; every other arm ignores it.
    let (identity, lineage_max, merged_into_goal) = match goal_vec.as_ref() {
        // Offline path: byte-for-byte today's behaviour, and zero DB round-trips.
        None => (GoalIdentity::NewRoot(slug.clone()), 0, None),
        Some(qvec) => {
            let slug_lineage_exists =
                WorkflowRepository::max_generation_by_canonical(&server.pool, &slug)
                    .await
                    .map_err(internal_error)?
                    .is_some();

            // min_truth 0.3 keeps deprecated lineages (deprecate_workflow
            // writes 0.05) from ever becoming a merge target;
            // resolve_to_latest breaks equal-distance ties toward the newest
            // generation. A lookup failure must not fail the tool — it just
            // means we mint a new lineage, which is the pre-existing behaviour.
            let candidates = WorkflowRepository::find_hierarchical_by_embedding(
                &server.pool,
                qvec,
                merge_threshold_from_env(std::env::var(GOAL_MERGE_THRESHOLD_ENV).ok().as_deref()),
                0.3,
                5,
                true,
            )
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = ?e, "store_workflow: lineage lookup failed; minting a new lineage");
                Vec::new()
            });

            let identity =
                resolve_goal_identity(&params.goal, &slug, slug_lineage_exists, &candidates);
            let merged_into_goal = match &identity {
                GoalIdentity::DriftedInto { .. } => candidates.first().map(|row| row.goal.clone()),
                _ => None,
            };
            let lineage_max = match &identity {
                GoalIdentity::DriftedInto { canonical_name } => u32::try_from(
                    WorkflowRepository::max_generation_by_canonical(&server.pool, canonical_name)
                        .await
                        .map_err(internal_error)?
                        .unwrap_or(0),
                )
                .unwrap_or(0),
                _ => 0,
            };
            (identity, lineage_max, merged_into_goal)
        }
    };

    let identity_resolution = match identity {
        GoalIdentity::NewRoot(_) => "new_root",
        GoalIdentity::Existing { .. } => "existing_generation",
        GoalIdentity::DriftedInto { .. } => "goal_drift",
    };
    let (canonical_name, generation, parent_canonical_name) =
        source_identity(identity, lineage_max);

    let prereqs = params.prerequisites.unwrap_or_default();
    let tags = params.tags.unwrap_or_default();

    let phases = if params.steps.is_empty() {
        vec![]
    } else {
        vec![Phase {
            title: "Body".to_string(),
            // `summary = "Body"` (not goal) avoids a `compound_claim_id`
            // collision with the thesis claim — both would hash the same
            // (content_hash, canonical_name) tuple if both used the goal.
            summary: "Body".to_string(),
            steps: params
                .steps
                .iter()
                .map(|t| Step {
                    compound: t.clone(),
                    rationale: String::new(),
                    operations: vec![],
                    generality: vec![],
                    confidence: 0.8,
                    // Flat store_workflow steps have no operation atoms, so no
                    // evidence_type source; the BBA-wiring loop only fires for
                    // level-3 atoms.
                    evidence_type: None,
                })
                .collect(),
        }]
    };

    let extraction = WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical_name.clone(),
            goal: params.goal.clone(),
            generation,
            parent_canonical_name,
            authors: vec![],
            expected_outcome: params.expected_outcome.clone(),
            tags,
            metadata: serde_json::json!({ "prerequisites": prereqs }),
        },
        thesis: Some(params.goal.clone()),
        thesis_derivation: ThesisDerivation::default(),
        phases,
        relationships: vec![],
    };

    let (response, inserted) =
        crate::tools::workflow_ingest::execute_workflow_ingest_with_inserted(
            &server.pool,
            &extraction,
        )
        .await?;

    // Embed inline, best-effort. Satisfies the is_current=true → has-embedding
    // invariant (CLAUDE.md "Embedding policy"). Mirrors `do_ingest_workflow` —
    // without this, step claims created via `store_workflow` land without
    // embeddings and break semantic search.
    // `embed_and_store` logs tracing::warn on failure internally; no outer handling needed.
    for (claim_id, content) in &inserted {
        let _ = server.embedder.embed_and_store(*claim_id, content).await;
    }

    // Also embed the workflow goal into workflows.goal_embedding for
    // embedding-first find_workflow_hierarchical. Omitted from the original
    // store_workflow; do_ingest_workflow embeds it correctly. Reuses the
    // vector generated above rather than asking the embedder twice.
    // Best-effort: a failure here must never fail the tool.
    if let (Ok(wf_id), Some(qvec)) = (
        uuid::Uuid::parse_str(&response.workflow_id),
        goal_vec.as_ref(),
    ) {
        if let Err(e) = WorkflowRepository::set_goal_embedding(&server.pool, wf_id, qvec).await {
            tracing::warn!(workflow_id=%wf_id, error=?e, "set_goal_embedding failed");
        }
    }

    success_json(&StoreWorkflowResponse {
        workflow_id: response.workflow_id,
        canonical_name: response.canonical_name,
        goal: params.goal,
        generation: response.generation,
        step_count: params.steps.len(),
        claims_ingested: response.claims_ingested,
        already_ingested: response.already_ingested,
        identity_resolution,
        merged_into_goal,
    })
}

pub async fn find_workflow(
    server: &EpiGraphMcpFull,
    params: FindWorkflowParams,
) -> Result<CallToolResult, McpError> {
    // Generate embedding once — reused for both semantic search and behavioral
    // affinity. Failure here is non-fatal: we still want the ILIKE fallback to
    // run (offline embedders shouldn't blank the whole tool). The post-embed
    // pipeline (extracted to mirror recall.rs's recall_with_context split) lets
    // integration tests skip the OpenAI embedder via `__test_only`.
    // Kept as a raw Vec<f32> as well as a pgvector literal: the claims leg and
    // behavioral affinity consume the literal, while the hierarchical ANN
    // helper (`find_hierarchical_by_embedding`) takes `&[f32]` and formats its
    // own literal.
    let qvec_opt: Option<Vec<f32>> = match server.embedder.generate(&params.goal).await {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!("embedder failed in find_workflow; relying on text fallback: {e}");
            None
        }
    };
    let pgvec_opt = qvec_opt.as_deref().map(format_pgvector);

    find_workflow_post_embed(server, &params, pgvec_opt, qvec_opt.as_deref()).await
}

/// Post-embedding pipeline: shared by `find_workflow` and the
/// `__test_only::find_workflow_with_pgvec` entry point that lets integration
/// tests skip the OpenAI embedder (no API key available in CI / sandbox).
///
/// Recomputes `limit`/`min_truth` from `params` internally (rather than taking
/// them as args) so the public wrapper stays minimal and the two extraction
/// sites cannot drift, mirroring recall.rs's wrapper pattern.
///
/// `pgvec_opt` is the pgvector literal consumed by the claims leg and the
/// behavioral-affinity lookup; `qvec_opt` is the same embedding in raw form,
/// needed by the hierarchical ANN helper. `qvec_opt` may be `None` while
/// `pgvec_opt` is `Some` (the `__test_only` entry point), in which case the
/// hierarchical leg degrades to its ILIKE path.
async fn find_workflow_post_embed(
    server: &EpiGraphMcpFull,
    params: &FindWorkflowParams,
    pgvec_opt: Option<String>,
    qvec_opt: Option<&[f32]>,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(5).clamp(1, 20);
    let min_truth = params.min_truth.unwrap_or(0.3);

    // Semantic search over claims.embedding (workflow vectors live on claims,
    // not evidence; evidence.embedding is 100% empty in prod). Scoped to the
    // "workflow" label so only workflow claims compete for the budget.
    let workflow_tag = vec!["workflow".to_string()];
    let semantic_hits = if let Some(pgvec) = pgvec_opt.as_deref() {
        ClaimRepository::search_by_embedding_scoped(
            &server.pool,
            pgvec,
            limit * 3,
            Some(&workflow_tag),
            None,
        )
        .await
        .map_err(internal_error)?
    } else {
        Vec::new()
    };

    // Behavioral affinity lookup (best-effort; only when embedding is available).
    let affinity_map: std::collections::HashMap<uuid::Uuid, (f64, i64)> =
        if let Some(pgvec) = pgvec_opt.as_deref() {
            match BehavioralExecutionRepository::behavioral_affinity_lineage(
                &server.pool,
                pgvec,
                0.5, // min_similarity
                1,   // min_executions
                20,  // limit
            )
            .await
            {
                Ok(rows) => rows
                    .into_iter()
                    .map(|(id, sim, count)| (id, (sim, count)))
                    .collect(),
                Err(e) => {
                    tracing::warn!("behavioral affinity lookup failed: {e}");
                    std::collections::HashMap::new()
                }
            }
        } else {
            std::collections::HashMap::new()
        };

    // Build results, enriching with behavioral data
    let mut results = Vec::new();
    for hit in semantic_hits {
        if let Ok(Some(claim)) = ClaimRepository::get_by_id(
            &server.pool,
            epigraph_core::ClaimId::from_uuid(hit.claim_id),
        )
        .await
        {
            if let Some(r) = enrich_workflow_result(
                &server.pool,
                hit.claim_id,
                &claim,
                hit.similarity,
                min_truth,
                &affinity_map,
            )
            .await
            {
                results.push(r);
            }
        }
        if results.len() >= limit as usize {
            break;
        }
    }

    // find_workflow reads BOTH workflow stores and merges them below:
    //   * legacy FLAT workflow claims — a single claim labelled `workflow`
    //     carrying goal + steps as JSON. That is the leg above and the ILIKE
    //     fallback immediately below.
    //   * HIERARCHICAL `workflows` rows — what `store_workflow` /
    //     `ingest_workflow` write. Their claims are labelled
    //     ["claim","workflow_thesis"|"workflow_step"], never `workflow`, so
    //     NOTHING those tools store can ever match a `workflow`-label scope.
    //     `hierarchical_workflow_results` below is the leg that reads them.
    //
    // The ILIKE pass here is the CLAIMS-side fallback only: workflow claims
    // usually have no associated evidence with embeddings, so the semantic path
    // above frequently returns empty even when a perfectly good substring match
    // exists. When semantic hits came in below half the requested limit,
    // augment with an ILIKE pass on workflow-labeled claims.
    // Resolves claim 903e5120.
    let limit_usize = limit as usize;
    let half = (limit_usize / 2).max(1);
    if results.len() < half {
        let text_hits = ClaimRepository::search_by_label_and_text(
            &server.pool,
            &["workflow".to_string()],
            &params.goal,
            min_truth,
            limit * 2,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("search_by_label_and_text fallback failed: {e}");
            Vec::new()
        });

        let already_seen: std::collections::HashSet<String> =
            results.iter().map(|r| r.workflow_id.clone()).collect();

        for claim in text_hits {
            if results.len() >= limit_usize {
                break;
            }
            let claim_uuid = claim.id.as_uuid();
            if already_seen.contains(&claim_uuid.to_string()) {
                continue;
            }
            if let Some(r) = enrich_workflow_result(
                &server.pool,
                claim_uuid,
                &claim,
                0.0, // text-fallback hit; no semantic similarity score
                min_truth,
                &affinity_map,
            )
            .await
            {
                results.push(r);
            }
        }
    }

    // Second store: hierarchical `workflows` rows. Best-effort throughout — a
    // broken hierarchical leg must never blank the claim-side results.
    let hier = hierarchical_workflow_results(
        &server.pool,
        &params.goal,
        qvec_opt,
        pgvec_opt.as_deref(),
        min_truth,
        limit,
    )
    .await;

    success_json(&merge_workflow_results(results, hier, limit_usize))
}

/// Build a `FindWorkflowResult` from a workflow claim, applying the shared
/// filters (min_truth, non-empty goal/steps) and behavioral enrichment.
///
/// Returns `None` when the claim fails the truth-value floor or has neither
/// a goal nor steps. Used by both the semantic and text-fallback loops in
/// `find_workflow` to keep enrichment behavior identical.
async fn enrich_workflow_result(
    pool: &sqlx::PgPool,
    workflow_id: uuid::Uuid,
    claim: &Claim,
    similarity: f64,
    min_truth: f64,
    affinity_map: &std::collections::HashMap<uuid::Uuid, (f64, i64)>,
) -> Option<FindWorkflowResult> {
    if claim.truth_value.value() < min_truth {
        return None;
    }
    let (goal, steps, _prereqs, _expected) = parse_workflow_content(&claim.content);
    if goal.is_empty() && steps.is_empty() {
        return None;
    }

    let val: serde_json::Value = serde_json::from_str(&claim.content).unwrap_or_default();
    let use_count = val
        .get("use_count")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let success_count = val
        .get("success_count")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let generation = val
        .get("generation")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let parent_id = val
        .get("parent_id")
        .and_then(serde_json::Value::as_str)
        .map(String::from);

    // Look up behavioral data via lineage root (best-effort; reuse the
    // affinity_map already built from the original embedding query).
    let lineage_root = WorkflowRepository::find_lineage_root(pool, workflow_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(workflow_id = %workflow_id, "find_lineage_root failed: {e}");
            workflow_id
        });

    let (behavioral_affinity, behavioral_execution_count) = match affinity_map.get(&lineage_root) {
        Some(&(sim, count)) => (Some(sim), Some(count)),
        None => (None, None),
    };

    // Success rate is per-workflow (not per-lineage). Only report if
    // this specific workflow has executions — variants with zero
    // executions show None, not Some(0.0).
    let behavioral_success_rate = if behavioral_execution_count.is_some() {
        match BehavioralExecutionRepository::rolling_success_rate(pool, workflow_id, 20).await {
            Ok(rate) if rate > 0.0 => Some(rate),
            _ => None,
        }
    } else {
        None
    };

    // Promotion flag set by the refresh_workflow_promotion maintenance pass.
    // Advisory metadata; best-effort (a lookup failure must not drop the result).
    let promotable = ClaimRepository::promotion_flag(pool, ClaimId::from_uuid(workflow_id))
        .await
        .unwrap_or(None);

    Some(FindWorkflowResult {
        workflow_id: workflow_id.to_string(),
        goal,
        steps,
        truth_value: claim.truth_value.value(),
        similarity,
        use_count,
        success_count,
        generation,
        parent_id,
        behavioral_affinity,
        behavioral_success_rate,
        behavioral_execution_count,
        promotable,
        store: "claims",
    })
}

/// Cosine-similarity floor for the hierarchical embedding leg. 0.5 mirrors
/// `find_workflow_hierarchical` and the `behavioral_affinity_lineage` default
/// the claims leg above already uses, so both stores admit candidates on the
/// same terms.
const HIER_SIMILARITY_THRESHOLD: f64 = 0.5;

/// Search the hierarchical `workflows` table — the store `store_workflow` and
/// `ingest_workflow` write, whose step/thesis claims are never labelled
/// `workflow` and so are invisible to the claims leg of `find_workflow`.
///
/// Every repo call is best-effort: a failure warns and contributes nothing,
/// never an error. A broken hierarchical leg must degrade `find_workflow` to
/// its previous claims-only behaviour rather than blanking it.
async fn hierarchical_workflow_results(
    pool: &sqlx::PgPool,
    goal: &str,
    qvec_opt: Option<&[f32]>,
    pgvec_opt: Option<&str>,
    min_truth: f64,
    limit: i64,
) -> Vec<FindWorkflowResult> {
    // Embedding-first (tolerates paraphrase), ILIKE second — the same shape
    // `find_workflow_hierarchical` uses.
    let mut rows = match qvec_opt {
        Some(qvec) => WorkflowRepository::find_hierarchical_by_embedding(
            pool,
            qvec,
            HIER_SIMILARITY_THRESHOLD,
            min_truth,
            limit * 3,
            false,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("hierarchical embedding search failed in find_workflow: {e}");
            Vec::new()
        }),
        None => Vec::new(),
    };

    if rows.is_empty() {
        rows = WorkflowRepository::search_hierarchical_by_text(
            pool,
            goal,
            limit * 2,
            min_truth,
            false,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("hierarchical text search failed in find_workflow: {e}");
            Vec::new()
        });
    }

    if rows.is_empty() {
        return Vec::new();
    }

    // Score the rows. `search_by_goal_embedding` is the only repo fn over
    // `workflows.goal_embedding` that surfaces `similarity = 1 - cosine
    // distance`, and it takes the pgvector literal we already formatted — so
    // scoring needs no new SQL. It applies neither the similarity floor nor
    // min_truth, so a row found by the ANN pass above can be absent here; it
    // then scores 0.0 and ranks alongside the text-fallback hits, which is what
    // 0.0 already means in this function.
    let scores: std::collections::HashMap<uuid::Uuid, f64> = match pgvec_opt {
        Some(pgvec) => WorkflowRepository::search_by_goal_embedding(pool, pgvec, limit * 3)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("workflow goal-embedding scoring failed in find_workflow: {e}");
                Vec::new()
            })
            .into_iter()
            .map(|h| (h.workflow_id, h.similarity))
            .collect(),
        None => std::collections::HashMap::new(),
    };

    // Step text for every hit in 2 round-trips total, not 2 per workflow.
    let ids: Vec<uuid::Uuid> = rows.iter().map(|r| r.id).collect();
    let mut steps_by_wf = WorkflowRepository::resolve_steps_to_heads_batched(pool, &ids)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("resolve_steps_to_heads_batched failed in find_workflow: {e}");
            std::collections::HashMap::new()
        });

    rows.iter()
        .map(|row| {
            let steps = steps_by_wf
                .remove(&row.id)
                .map(|resolved| steps_from_resolved(&resolved))
                .unwrap_or_default();
            hierarchical_row_to_result(row, steps, scores.get(&row.id).copied().unwrap_or(0.0))
        })
        .collect()
}

/// Flatten resolved step lineages into the plain `Vec<String>` shape
/// `FindWorkflowResult.steps` carries.
///
/// Takes the FIRST head of each lineage, mirroring
/// `WorkflowRepository::resolve_step_claim`'s existing `heads.first()`
/// precedent for a lineage with `pending_resolution`.
///
/// A step whose lineage was pruned — or that predates step-level versioning and
/// so has no `step_lineage_id` — yields an EMPTY string IN POSITION rather than
/// being dropped. Positions are load-bearing: `report_workflow_outcome` /
/// `report_hierarchical_outcome` address steps by `step_index`, so closing a
/// gap would silently misaddress every later step. In practice
/// `store_workflow`'s steps always get a `step_lineage_id`, and
/// `latest_in_lineage` returns the claim itself when it is the lineage's only
/// member, so freshly stored workflows always resolve to real text.
fn steps_from_resolved(resolved: &[epigraph_db::ResolvedStep]) -> Vec<String> {
    resolved
        .iter()
        .map(|s| {
            s.heads
                .first()
                .map(|h| h.content.clone())
                .unwrap_or_default()
        })
        .collect()
}

/// Project a hierarchical `workflows` row into the shared `FindWorkflowResult`
/// shape. Pure — all I/O is done by the caller.
///
/// `use_count` / `success_count` come from `metadata`, which is exactly where
/// `do_report_hierarchical_outcome_via_pool` writes them.
///
/// The three `behavioral_*` fields are always `None`: the affinity map is built
/// by `BehavioralExecutionRepository::behavioral_affinity_lineage`, whose
/// `live_roots` CTE joins `claims c ON c.id = r.root_id`, and a `workflows`-table
/// id has no `claims` row — so the map can never key on a hierarchical
/// workflow. The metadata counters above carry the same use/success signal.
///
/// `promotable` is `None` for the same class of reason:
/// `ClaimRepository::promotion_flag` reads `claims.properties`, so it would be
/// `Ok(None)` for every `workflows` id. Skipping the query saves a round-trip
/// per hit for a value that cannot exist.
fn hierarchical_row_to_result(
    row: &epigraph_db::HierarchicalWorkflowRow,
    steps: Vec<String>,
    similarity: f64,
) -> FindWorkflowResult {
    let use_count = row
        .metadata
        .get("use_count")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let success_count = row
        .metadata
        .get("success_count")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);

    FindWorkflowResult {
        workflow_id: row.id.to_string(),
        goal: row.goal.clone(),
        steps,
        truth_value: row.truth_value,
        similarity,
        use_count,
        success_count,
        generation: i64::from(row.generation),
        parent_id: row.parent_id.map(|p| p.to_string()),
        behavioral_affinity: None,
        behavioral_success_rate: None,
        behavioral_execution_count: None,
        promotable: None,
        store: "workflows",
    }
}

/// Merge the two stores' hits into one ranked, deduplicated page.
///
/// Claim hits are concatenated FIRST so every tie breaks toward today's output,
/// then the whole list is STABLY sorted by descending similarity, deduplicated
/// on `workflow_id` (first occurrence wins), and truncated to `limit`.
///
/// The `.max(0.0)` clamp on the sort key matters: cosine similarity is
/// mathematically in [-1, 1], and an (vanishingly rare) negative ANN score
/// would otherwise sort BEHIND the 0.0 text-fallback hits, silently reordering
/// output that today lists ANN hits before ILIKE hits. Clamping makes them tie,
/// and the stable sort then preserves that existing order exactly — so with an
/// empty hierarchical side this function is the identity on the claims list.
fn merge_workflow_results(
    claim_hits: Vec<FindWorkflowResult>,
    hierarchical_hits: Vec<FindWorkflowResult>,
    limit: usize,
) -> Vec<FindWorkflowResult> {
    let mut merged: Vec<FindWorkflowResult> = claim_hits;
    merged.extend(hierarchical_hits);

    merged.sort_by(|a, b| b.similarity.max(0.0).total_cmp(&a.similarity.max(0.0)));

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    merged.retain(|r| seen.insert(r.workflow_id.clone()));
    merged.truncate(limit);
    merged
}

pub async fn report_workflow_outcome(
    server: &EpiGraphMcpFull,
    params: ReportWorkflowOutcomeParams,
) -> Result<CallToolResult, McpError> {
    let workflow_id = parse_uuid(&params.workflow_id)?;

    // `store_workflow` was migrated to the hierarchical ingest pipeline, so
    // workflow_ids it returns are rows in the `workflows` table — NOT claim
    // ids. Probe `workflows` first; if the id lives there, delegate to the
    // hierarchical outcome path. Falls through to the legacy claims-table
    // flat-workflow path only when the id is not a hierarchical workflow
    // (preserves backward-compat for the ~144 legacy flat-workflow claims).
    let is_hierarchical: bool =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM workflows WHERE id = $1)")
            .bind(workflow_id)
            .fetch_one(&server.pool)
            .await
            .map_err(internal_error)?;

    if is_hierarchical {
        // Map flat StepExecution → HierarchicalStepExecution (identical
        // field shape; the two structs exist only because each tool owns
        // its own JsonSchema-derived params type).
        let step_executions: Vec<crate::types::HierarchicalStepExecution> = params
            .execution_log
            .iter()
            .map(|s| crate::types::HierarchicalStepExecution {
                step_index: s.step_index,
                planned: s.planned.clone(),
                actual: s.actual.clone(),
                deviated: s.deviated,
                deviation_reason: s.deviation_reason.clone(),
            })
            .collect();
        return crate::tools::workflow_hierarchical::do_report_hierarchical_outcome_via_pool(
            &server.pool,
            workflow_id,
            params.success,
            &step_executions,
            params.quality,
            params.goal_text.as_deref(),
            None,
        )
        .await;
    }

    let claim =
        ClaimRepository::get_by_id(&server.pool, epigraph_core::ClaimId::from_uuid(workflow_id))
            .await
            .map_err(internal_error)?
            .ok_or_else(|| {
                invalid_params(format!(
                    "workflow {workflow_id} not found in `workflows` or `claims` tables"
                ))
            })?;

    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();

    let quality = params
        .quality
        .unwrap_or(if params.success { 1.0 } else { 0.0 });

    // Create evidence from execution log
    let evidence_text = serde_json::to_string_pretty(&serde_json::json!({
        "success": params.success,
        "outcome_details": params.outcome_details,
        "execution_log": params.execution_log,
        "quality": quality,
    }))
    .map_err(internal_error)?;

    let evidence_hash = ContentHasher::hash(evidence_text.as_bytes());
    let mut evidence = Evidence::new(
        agent_id_typed,
        pub_key,
        evidence_hash,
        EvidenceType::Observation {
            observed_at: chrono::Utc::now(),
            method: "workflow_execution".to_string(),
            location: None,
        },
        Some(evidence_text),
        epigraph_core::ClaimId::from_uuid(workflow_id),
    );
    evidence.signature = Some(server.signer.sign(&evidence_hash));

    EvidenceRepository::create(&server.pool, &evidence)
        .await
        .map_err(internal_error)?;

    let before = claim.truth_value.value();

    // CDST update: replace Bayesian update with calibration-weighted DS combination.
    // Evidence type "observation" (matches the EvidenceType::Observation created above).
    // quality is the confidence signal; success determines supports/refutes direction.
    let weight = load_evidence_type_weight("observation");
    let ds = ds_auto::auto_wire_ds_update(
        &server.pool,
        workflow_id,
        agent_id,
        quality,
        weight,
        params.success,
        Some("observation"),
        Some(evidence.id.as_uuid()), // unique perspective per evidence submission
    )
    .await
    .map_err(internal_error)?;

    // Derive truth_value from CDST pignistic probability
    let after = TruthValue::clamped(ds.pignistic_prob);
    ClaimRepository::update_truth_value(
        &server.pool,
        epigraph_core::ClaimId::from_uuid(workflow_id),
        after,
    )
    .await
    .map_err(internal_error)?;

    // Update use counts in workflow JSON
    let val: serde_json::Value = serde_json::from_str(&claim.content).unwrap_or_default();
    let use_count = val
        .get("use_count")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
        + 1;
    let success_count = val
        .get("success_count")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
        + i64::from(params.success);

    // ── Behavioral execution row (best-effort) ──────────────────────────
    // Derive goal text: prefer agent-supplied, fall back to workflow claim goal.
    let (parsed_goal, _, _, _) = parse_workflow_content(&claim.content);
    let behavioral_goal = params.goal_text.unwrap_or(parsed_goal);

    // Derive step-level data from execution log
    let deviation_count = params.execution_log.iter().filter(|s| s.deviated).count() as i32;
    let total_steps = params.execution_log.len() as i32;
    let tool_pattern: Vec<String> = params
        .execution_log
        .iter()
        .map(|s| s.planned.clone())
        .collect();
    let step_beliefs: serde_json::Value = params
        .execution_log
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

    // Embed the goal text for affinity matching
    let goal_embedding_pgvec = match server.embedder.generate(&behavioral_goal).await {
        Ok(vec) => Some(format_pgvector(&vec)),
        Err(e) => {
            tracing::warn!("behavioral goal embedding failed: {e}");
            None
        }
    };

    let behavioral_row = epigraph_db::BehavioralExecutionRow {
        id: uuid::Uuid::new_v4(),
        workflow_id,
        goal_text: behavioral_goal,
        success: params.success,
        step_beliefs,
        tool_pattern,
        quality: Some(quality),
        deviation_count,
        total_steps,
        created_at: chrono::Utc::now(),
        step_claim_id: None,
        run_label: None,
    };

    if let Err(e) = BehavioralExecutionRepository::create(
        &server.pool,
        behavioral_row,
        goal_embedding_pgvec.as_deref(),
    )
    .await
    {
        tracing::warn!(workflow_id = %workflow_id, "behavioral execution write failed: {e}");
    }

    success_json(&ReportWorkflowOutcomeResponse {
        workflow_id: workflow_id.to_string(),
        evidence_id: evidence.id.as_uuid().to_string(),
        truth_before: before,
        truth_after: after.value(),
        total_uses: use_count,
        success_rate: if use_count > 0 {
            success_count as f64 / use_count as f64
        } else {
            0.0
        },
    })
}

pub async fn deprecate_workflow(
    server: &EpiGraphMcpFull,
    params: DeprecateWorkflowParams,
) -> Result<CallToolResult, McpError> {
    let workflow_id = parse_uuid(&params.workflow_id)?;
    let cascade = params.cascade.unwrap_or(false);

    let mut deprecated_ids = Vec::new();

    // Deprecate the target workflow (A4: also set is_current = false).
    // ClaimRepository::deprecate_claim ALSO nulls the embedding in the same
    // statement — required by CLAUDE.md "Embedding policy → Cleanup paths"
    // so the deprecated workflow drops out of semantic recall and does not
    // inflate the `stale_present` audit count.
    ClaimRepository::deprecate_claim(&server.pool, epigraph_core::ClaimId::from_uuid(workflow_id))
        .await
        .map_err(internal_error)?;
    // Cascade onto the hierarchical `workflows` row (no-op when this
    // workflow has only a flat-claim representation). Without this,
    // `find_workflow_hierarchical` keeps returning the deprecated row.
    epigraph_db::WorkflowRepository::set_truth_value(&server.pool, workflow_id, 0.05)
        .await
        .map_err(internal_error)?;
    deprecated_ids.push(workflow_id.to_string());

    if cascade {
        // A5: Walk both 'supersedes' and 'variant_of' edges, but only
        // deprecate workflow-labeled claims to avoid corrupting regular
        // claim-version supersedes chains.
        const DESCENDANT_REL: &[&str] = &["variant_of", "supersedes"];

        let mut visited: std::collections::HashSet<uuid::Uuid> = std::collections::HashSet::new();
        visited.insert(workflow_id);
        let mut queue = vec![workflow_id];
        while let Some(current) = queue.pop() {
            let edges = EdgeRepository::get_by_target(&server.pool, current, "claim")
                .await
                .unwrap_or_default();

            for edge in edges {
                if !DESCENDANT_REL.contains(&edge.relationship.as_str()) {
                    continue;
                }
                let child_id = edge.source_id;
                // Filter to workflow-labeled claims only.
                let is_workflow: bool =
                    sqlx::query_scalar("SELECT 'workflow' = ANY(labels) FROM claims WHERE id = $1")
                        .bind(child_id)
                        .fetch_optional(&server.pool)
                        .await
                        .map_err(internal_error)?
                        .unwrap_or(false);
                if !is_workflow {
                    continue;
                }

                if !visited.insert(child_id) {
                    continue;
                }

                ClaimRepository::deprecate_claim(
                    &server.pool,
                    epigraph_core::ClaimId::from_uuid(child_id),
                )
                .await
                .map_err(internal_error)?;
                // Mirror onto the hierarchical row, if any.
                epigraph_db::WorkflowRepository::set_truth_value(&server.pool, child_id, 0.05)
                    .await
                    .map_err(internal_error)?;
                deprecated_ids.push(child_id.to_string());
                queue.push(child_id);
            }
        }
    }

    success_json(&DeprecateWorkflowResponse {
        deprecated_ids,
        reason: params.reason,
    })
}

#[doc(hidden)]
pub mod __test_only {
    use super::{find_workflow_post_embed, EpiGraphMcpFull, FindWorkflowParams, McpError};
    use rmcp::model::CallToolResult;

    /// Integration-test entry point that skips the OpenAI embedder.
    ///
    /// Tests cannot call the real embedder (no API key in CI / sandbox),
    /// so they pre-format a known pgvector literal and dispatch directly
    /// into the post-embed pipeline. This is the same code that
    /// `find_workflow` runs after `embedder.generate`.
    ///
    /// The hierarchical leg's EMBEDDING path is skipped here: this entry point
    /// carries only the pgvector literal, not the raw `Vec<f32>` that
    /// `find_hierarchical_by_embedding` needs, so it passes `None` and that leg
    /// falls back to its ILIKE search.
    pub async fn find_workflow_with_pgvec(
        server: &EpiGraphMcpFull,
        params: FindWorkflowParams,
        pgvec: Option<String>,
    ) -> Result<CallToolResult, McpError> {
        find_workflow_post_embed(server, &params, pgvec, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::{
        hierarchical_row_to_result, merge_threshold_from_env, merge_workflow_results,
        resolve_goal_identity, slugify_workflow_goal, source_identity, steps_from_resolved,
        FindWorkflowResult, GoalIdentity, DEFAULT_GOAL_MERGE_THRESHOLD,
    };
    use epigraph_db::{HierarchicalWorkflowRow, LineageHead, ResolvedStep};

    /// Row builder so a future field on `HierarchicalWorkflowRow` is a one-line
    /// fix here rather than N broken struct literals.
    fn row(canonical: &str, generation: i32, goal: &str) -> HierarchicalWorkflowRow {
        HierarchicalWorkflowRow {
            id: uuid::Uuid::nil(),
            canonical_name: canonical.to_string(),
            generation,
            goal: goal.to_string(),
            parent_id: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            truth_value: 1.0,
        }
    }

    #[test]
    fn resolve_goal_identity_mints_new_root_when_no_candidates() {
        assert_eq!(
            resolve_goal_identity("Deploy the API", "deploy-the-api", false, &[]),
            GoalIdentity::NewRoot("deploy-the-api".to_string())
        );
    }

    #[test]
    fn resolve_goal_identity_preserves_exact_slug_lineage_at_generation_zero() {
        // Identity beats semantics: an existing slug lineage short-circuits
        // BEFORE any candidate is considered, so today's behaviour is verbatim.
        let candidates = [row("deploy-api-service", 3, "Deploy API service")];
        let identity = resolve_goal_identity("Deploy the API", "deploy-the-api", true, &candidates);
        assert_eq!(
            identity,
            GoalIdentity::NewRoot("deploy-the-api".to_string())
        );
        assert_eq!(
            source_identity(identity, 7),
            ("deploy-the-api".to_string(), 0, None)
        );
    }

    #[test]
    fn resolve_goal_identity_drifts_into_closest_candidate_lineage() {
        let candidates = [row("deploy-api-service", 2, "Deploy API service")];
        assert_eq!(
            resolve_goal_identity("Deploy the API", "deploy-the-api", false, &candidates),
            GoalIdentity::DriftedInto {
                canonical_name: "deploy-api-service".to_string()
            }
        );
    }

    #[test]
    fn resolve_goal_identity_reuses_existing_generation_for_identical_goal_text() {
        // The idempotency rule: a repeated drifted goal re-attaches to the
        // generation already carrying that exact text instead of forking one
        // more generation on every call.
        let candidates = [
            row("deploy-api-service", 2, "Deploy API service"),
            row("deploy-api-service", 1, "Deploy the API"),
        ];
        assert_eq!(
            resolve_goal_identity("Deploy the API", "deploy-the-api", false, &candidates),
            GoalIdentity::Existing {
                canonical_name: "deploy-api-service".to_string(),
                generation: 1,
            }
        );
    }

    #[test]
    fn resolve_goal_identity_exact_goal_match_ignores_case_and_surrounding_whitespace() {
        let candidates = [row("deploy-api-service", 4, "  deploy THE api  ")];
        assert_eq!(
            resolve_goal_identity("Deploy the API\n", "deploy-the-api", false, &candidates),
            GoalIdentity::Existing {
                canonical_name: "deploy-api-service".to_string(),
                generation: 4,
            }
        );
    }

    #[test]
    fn resolve_goal_identity_prefers_first_candidate_when_several_clear_threshold() {
        // find_hierarchical_by_embedding returns closest-first, so index 0 is
        // the nearest lineage — the drift target.
        let candidates = [
            row("deploy-api-service", 0, "Deploy API service"),
            row("ship-the-api", 0, "Ship the API"),
        ];
        assert_eq!(
            resolve_goal_identity("Deploy the API", "deploy-the-api", false, &candidates),
            GoalIdentity::DriftedInto {
                canonical_name: "deploy-api-service".to_string()
            }
        );
    }

    #[test]
    fn resolve_goal_identity_skips_candidate_with_negative_generation() {
        // A negative generation cannot be represented in WorkflowSource (u32);
        // the exact-text rule declines it and the drift rule takes over.
        let candidates = [row("deploy-api-service", -1, "Deploy the API")];
        assert_eq!(
            resolve_goal_identity("Deploy the API", "deploy-the-api", false, &candidates),
            GoalIdentity::DriftedInto {
                canonical_name: "deploy-api-service".to_string()
            }
        );
    }

    #[test]
    fn source_identity_new_root_is_generation_zero_with_no_parent() {
        assert_eq!(
            source_identity(GoalIdentity::NewRoot("deploy-the-api".to_string()), 9),
            ("deploy-the-api".to_string(), 0, None)
        );
    }

    #[test]
    fn source_identity_existing_reuses_generation_without_parent() {
        assert_eq!(
            source_identity(
                GoalIdentity::Existing {
                    canonical_name: "deploy-api-service".to_string(),
                    generation: 2,
                },
                9
            ),
            ("deploy-api-service".to_string(), 2, None)
        );
    }

    #[test]
    fn source_identity_drift_sets_generation_above_lineage_max_and_names_parent() {
        // The executor resolves the parent as
        // find_root_by_canonical(parent, generation - 1), so generation MUST be
        // lineage_max + 1 for parent_id and the variant_of edge to resolve.
        assert_eq!(
            source_identity(
                GoalIdentity::DriftedInto {
                    canonical_name: "deploy-api-service".to_string(),
                },
                2
            ),
            (
                "deploy-api-service".to_string(),
                3,
                Some("deploy-api-service".to_string())
            )
        );
    }

    #[test]
    fn merge_threshold_from_env_defaults_when_unset_or_unparseable() {
        for raw in [None, Some(""), Some("high"), Some("NaN"), Some("inf")] {
            assert_eq!(
                merge_threshold_from_env(raw),
                DEFAULT_GOAL_MERGE_THRESHOLD,
                "raw={raw:?}"
            );
        }
    }

    #[test]
    fn merge_threshold_from_env_honours_valid_override() {
        assert!((merge_threshold_from_env(Some("0.97")) - 0.97).abs() < f64::EPSILON);
        assert!((merge_threshold_from_env(Some(" 0.5 ")) - 0.5).abs() < f64::EPSILON);
        // > 1.0 is the documented kill switch: cosine similarity never exceeds
        // 1, so nothing can clear the floor and merging is off.
        assert!(merge_threshold_from_env(Some("1.5")) > 1.0);
    }

    #[test]
    fn slugify_workflow_goal_maps_paraphrases_to_distinct_slugs() {
        // This is the bug's root cause, pinned: slug identity alone cannot see
        // that these two goals are the same workflow.
        assert_eq!(slugify_workflow_goal("Deploy the API"), "deploy-the-api");
        assert_eq!(
            slugify_workflow_goal("Deploy API service"),
            "deploy-api-service"
        );
        assert_ne!(
            slugify_workflow_goal("Deploy the API"),
            slugify_workflow_goal("Deploy API service")
        );
    }

    // ── find_workflow's two-store merge ──────────────────────────────────

    /// Result builder so a future field on `FindWorkflowResult` is a one-line
    /// fix here rather than N broken struct literals.
    fn hit(id: &str, similarity: f64, store: &'static str) -> FindWorkflowResult {
        FindWorkflowResult {
            workflow_id: id.to_string(),
            goal: format!("goal for {id}"),
            steps: Vec::new(),
            truth_value: 1.0,
            similarity,
            use_count: 0,
            success_count: 0,
            generation: 0,
            parent_id: None,
            behavioral_affinity: None,
            behavioral_success_rate: None,
            behavioral_execution_count: None,
            promotable: None,
            store,
        }
    }

    fn head(content: &str) -> LineageHead {
        LineageHead {
            id: uuid::Uuid::new_v4(),
            content: content.to_string(),
            truth_value: 1.0,
            created_at: chrono::Utc::now(),
        }
    }

    fn step(step_index: usize, heads: Vec<LineageHead>) -> ResolvedStep {
        ResolvedStep {
            step_index,
            frozen_claim_id: uuid::Uuid::new_v4(),
            step_lineage_id: Some(uuid::Uuid::new_v4()),
            heads,
            pending_resolution: false,
        }
    }

    #[test]
    fn merge_ranks_hierarchical_hit_above_lower_scored_claim_hit() {
        // The bug, pinned: before this change the hierarchical hit did not
        // exist at all, and a merge that merely appended it would still have
        // buried it beneath a weaker claim hit.
        let merged = merge_workflow_results(
            vec![hit("claim-a", 0.40, "claims")],
            vec![hit("wf-a", 0.90, "workflows")],
            5,
        );
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].workflow_id, "wf-a");
        assert_eq!(merged[0].store, "workflows");
        assert_eq!(merged[1].workflow_id, "claim-a");
    }

    #[test]
    fn merge_returns_hierarchical_hits_when_claim_side_is_empty() {
        let merged = merge_workflow_results(
            Vec::new(),
            vec![
                hit("wf-low", 0.30, "workflows"),
                hit("wf-high", 0.80, "workflows"),
            ],
            5,
        );
        assert_eq!(
            merged
                .iter()
                .map(|r| r.workflow_id.as_str())
                .collect::<Vec<_>>(),
            vec!["wf-high", "wf-low"]
        );
    }

    #[test]
    fn merge_dedups_by_workflow_id_keeping_first() {
        // Equal scores tie, and the stable sort keeps the claim-side copy
        // first because claim hits are concatenated first.
        let merged = merge_workflow_results(
            vec![hit("shared", 0.5, "claims")],
            vec![hit("shared", 0.5, "workflows")],
            5,
        );
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].store, "claims");
    }

    #[test]
    fn merge_truncates_to_limit() {
        let merged = merge_workflow_results(
            vec![
                hit("c1", 0.90, "claims"),
                hit("c2", 0.20, "claims"),
                hit("c3", 0.10, "claims"),
            ],
            vec![
                hit("w1", 0.80, "workflows"),
                hit("w2", 0.70, "workflows"),
                hit("w3", 0.05, "workflows"),
            ],
            4,
        );
        assert_eq!(
            merged
                .iter()
                .map(|r| r.workflow_id.as_str())
                .collect::<Vec<_>>(),
            vec!["c1", "w1", "w2", "c2"]
        );
    }

    #[test]
    fn merge_keeps_negative_similarity_ann_hit_ahead_of_zero_scored_text_hit() {
        // The `.max(0.0)` clamp: without it the negative ANN score would sort
        // behind the 0.0 ILIKE hit and silently reorder today's output.
        let merged = merge_workflow_results(
            vec![hit("ann", -0.10, "claims"), hit("ilike", 0.0, "claims")],
            Vec::new(),
            5,
        );
        assert_eq!(
            merged
                .iter()
                .map(|r| r.workflow_id.as_str())
                .collect::<Vec<_>>(),
            vec!["ann", "ilike"]
        );
    }

    #[test]
    fn merge_preserves_claims_only_order_when_hierarchical_empty() {
        // Guards crates/epigraph-mcp/tests/find_workflow_semantic_test.rs,
        // which asserts on arr[0] of a claims-only result set.
        let claims = vec![
            hit("c1", 0.91, "claims"),
            hit("c2", 0.55, "claims"),
            hit("c3", 0.0, "claims"),
        ];
        let expected: Vec<String> = claims.iter().map(|r| r.workflow_id.clone()).collect();
        let merged = merge_workflow_results(claims, Vec::new(), 10);
        assert_eq!(merged.len(), expected.len());
        assert_eq!(
            merged
                .iter()
                .map(|r| r.workflow_id.clone())
                .collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn hierarchical_row_to_result_maps_metadata_counters_generation_and_parent() {
        let parent = uuid::Uuid::new_v4();
        let row = HierarchicalWorkflowRow {
            id: uuid::Uuid::new_v4(),
            canonical_name: "deploy-api".to_string(),
            generation: 3,
            goal: "Deploy the API".to_string(),
            parent_id: Some(parent),
            metadata: serde_json::json!({ "use_count": 7, "success_count": 5 }),
            created_at: chrono::Utc::now(),
            truth_value: 0.82,
        };

        let result = hierarchical_row_to_result(&row, vec!["build".to_string()], 0.77);

        assert_eq!(result.workflow_id, row.id.to_string());
        assert_eq!(result.goal, "Deploy the API");
        assert_eq!(result.steps, vec!["build".to_string()]);
        assert!((result.truth_value - 0.82).abs() < f64::EPSILON);
        assert!((result.similarity - 0.77).abs() < f64::EPSILON);
        assert_eq!(result.generation, 3);
        assert_eq!(result.parent_id, Some(parent.to_string()));
        assert_eq!(result.use_count, 7);
        assert_eq!(result.success_count, 5);
        assert_eq!(result.store, "workflows");
        // A workflows-table id has no claims row, so neither the affinity map
        // nor the promotion flag can ever key on it.
        assert_eq!(result.behavioral_affinity, None);
        assert_eq!(result.behavioral_success_rate, None);
        assert_eq!(result.behavioral_execution_count, None);
        assert_eq!(result.promotable, None);
    }

    #[test]
    fn hierarchical_row_to_result_defaults_missing_metadata_counters_to_zero() {
        for metadata in [serde_json::json!({}), serde_json::json!(null)] {
            let row = HierarchicalWorkflowRow {
                id: uuid::Uuid::new_v4(),
                canonical_name: "deploy-api".to_string(),
                generation: 0,
                goal: "Deploy the API".to_string(),
                parent_id: None,
                metadata,
                created_at: chrono::Utc::now(),
                truth_value: 1.0,
            };
            let result = hierarchical_row_to_result(&row, Vec::new(), 0.0);
            assert_eq!(result.use_count, 0);
            assert_eq!(result.success_count, 0);
            assert_eq!(result.parent_id, None);
        }
    }

    #[test]
    fn steps_from_resolved_uses_first_head_content_in_plan_order() {
        let resolved = vec![
            step(0, vec![head("build image")]),
            // Two heads (an unreconciled lineage): take the first, matching
            // resolve_step_claim's existing precedent.
            step(1, vec![head("push"), head("push --force")]),
            step(2, vec![head("restart")]),
        ];
        assert_eq!(
            steps_from_resolved(&resolved),
            vec![
                "build image".to_string(),
                "push".to_string(),
                "restart".to_string()
            ]
        );
    }

    #[test]
    fn steps_from_resolved_preserves_positions_for_steps_without_heads() {
        // A pruned or legacy lineage yields "" IN POSITION. Closing the gap
        // would misaddress every later step for report_workflow_outcome, which
        // addresses steps by step_index.
        let resolved = vec![
            step(0, vec![head("a")]),
            step(1, Vec::new()),
            step(2, vec![head("c")]),
        ];
        assert_eq!(
            steps_from_resolved(&resolved),
            vec!["a".to_string(), String::new(), "c".to_string()]
        );
    }
}
