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

/// Store a new hierarchical workflow.
///
/// Input shape stays simple (`goal` + `steps[]`); internally builds a
/// `WorkflowExtraction` and runs the hierarchical ingest pipeline. Each step
/// becomes a first-class claim under a single `"Body"` phase. The workflow
/// itself is a row in the `workflows` table, identified by a deterministic
/// UUID from `(canonical_name, generation)`. Idempotent on `canonical_name`.
pub async fn store_workflow(
    server: &EpiGraphMcpFull,
    params: StoreWorkflowParams,
) -> Result<CallToolResult, McpError> {
    use epigraph_ingest::common::schema::ThesisDerivation;
    use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
    use epigraph_ingest::workflow::WorkflowExtraction;

    let canonical_name = slugify_workflow_goal(&params.goal);
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
            generation: 0,
            parent_canonical_name: None,
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
    // store_workflow; do_ingest_workflow embeds it correctly.
    if let Ok(wf_id) = uuid::Uuid::parse_str(&response.workflow_id) {
        match server.embedder.generate(&params.goal).await {
            Ok(qvec) => {
                if let Err(e) =
                    WorkflowRepository::set_goal_embedding(&server.pool, wf_id, &qvec).await
                {
                    tracing::warn!(workflow_id=%wf_id, error=?e, "set_goal_embedding failed");
                }
            }
            Err(e) => {
                tracing::warn!(workflow_id=%wf_id, error=?e, "goal embedding generation failed");
            }
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
    let pgvec_opt = match server.embedder.generate(&params.goal).await {
        Ok(v) => Some(format_pgvector(&v)),
        Err(e) => {
            tracing::warn!("embedder failed in find_workflow; relying on text fallback: {e}");
            None
        }
    };

    find_workflow_post_embed(server, &params, pgvec_opt).await
}

/// Post-embedding pipeline: shared by `find_workflow` and the
/// `__test_only::find_workflow_with_pgvec` entry point that lets integration
/// tests skip the OpenAI embedder (no API key available in CI / sandbox).
///
/// Recomputes `limit`/`min_truth` from `params` internally (rather than taking
/// them as args) so the public wrapper stays minimal and the two extraction
/// sites cannot drift, mirroring recall.rs's wrapper pattern.
async fn find_workflow_post_embed(
    server: &EpiGraphMcpFull,
    params: &FindWorkflowParams,
    pgvec_opt: Option<String>,
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

    // Fallback: workflows usually have no associated evidence with embeddings,
    // so the semantic path above frequently returns empty even when a perfectly
    // good ILIKE match exists. The 144 production workflows live as claims
    // labeled `workflow` (the legacy `workflows` table has only 3 test rows),
    // so we search claims directly. When semantic hits came in below half the
    // requested limit, augment with an ILIKE pass on workflow-labeled claims.
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

    success_json(&results)
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
    })
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
    pub async fn find_workflow_with_pgvec(
        server: &EpiGraphMcpFull,
        params: FindWorkflowParams,
        pgvec: Option<String>,
    ) -> Result<CallToolResult, McpError> {
        find_workflow_post_embed(server, &params, pgvec).await
    }
}
