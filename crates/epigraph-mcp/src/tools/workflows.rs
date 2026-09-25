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
    viewer: &epigraph_db::visibility::Viewer,
    params: EvaluateWorkflowPromotionParams,
) -> Result<CallToolResult, McpError> {
    let variant_id = parse_uuid(params.workflow_id.trim())?;
    let window = params.window.unwrap_or(50).clamp(1, 500);
    let assessment = assess_workflow_promotion(server, viewer, variant_id, window).await?;
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
    viewer: &epigraph_db::visibility::Viewer,
    variant_id: uuid::Uuid,
    window: i64,
) -> Result<PromotionAssessment, McpError> {
    use epigraph_engine::workflow_promotion::{
        evaluate_workflow_promotion as gate, WorkflowPromotionConfig, WorkflowSampleStats,
    };
    let config = WorkflowPromotionConfig::default();

    let parent_id = WorkflowRepository::immediate_variant_parent(&server.pool, viewer, variant_id)
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
    viewer: &epigraph_db::visibility::Viewer,
    params: EvaluateWorkflowPromotionParams,
) -> Result<CallToolResult, McpError> {
    let variant_id = parse_uuid(params.workflow_id.trim())?;
    let window = params.window.unwrap_or(50).clamp(1, 500);
    let assessment = assess_workflow_promotion(server, viewer, variant_id, window).await?;

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
    viewer: &epigraph_db::visibility::Viewer,
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
            server,
            viewer,
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
    viewer: &epigraph_db::visibility::Viewer,
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

    find_workflow_post_embed(server, viewer, &params, pgvec_opt).await
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
    viewer: &epigraph_db::visibility::Viewer,
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
            viewer,
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
                viewer,
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

    // Hierarchical leg (backlog 18168514). `store_workflow` writes a row in the
    // `workflows` table and labels its claims `workflow_thesis` / `workflow_step`
    // — never `workflow` — so the label-scoped passes above could NEVER return
    // anything `store_workflow` produced. Searching only the flat store made
    // that tool's output permanently invisible to the tool named to find it,
    // which is the long-standing convention in epiclaw scheduled-task prompts.
    //
    // Best-effort: a failure here degrades to the flat-only behaviour rather
    // than blanking the whole tool.
    let hierarchical_hits = if let Some(pgvec) = pgvec_opt.as_deref() {
        WorkflowRepository::search_hierarchical_by_embedding_scored(
            &server.pool,
            pgvec,
            min_truth,
            limit * 3,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("hierarchical workflow embedding search failed: {e}");
            Vec::new()
        })
    } else {
        Vec::new()
    };

    // Step texts for the hierarchical candidates, resolved in ONE query before
    // ranking. A `workflows` row carries no inline steps, and a result with an
    // empty `steps` array is precisely what caused the 2026-08-18 incident, so
    // rows whose steps cannot be resolved are dropped below rather than
    // surfaced hollow.
    let hierarchical_ids: Vec<uuid::Uuid> = hierarchical_hits.iter().map(|r| r.id).collect();
    let mut hierarchical_steps =
        WorkflowRepository::step_texts_for_hierarchical(&server.pool, viewer, &hierarchical_ids)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("hierarchical step resolution failed: {e}");
                std::collections::HashMap::new()
            });

    // Merge both stores onto ONE ranked list before truncating to `limit`.
    // Appending the hierarchical leg after the flat leg had already consumed
    // the budget would leave the measured failure untouched: the two
    // content-free flat records (305050d2, d32ee4e8) outrank everything for
    // theme-maintenance queries, so they would still fill the window. Both
    // legs score `1 - cosine_distance` from the SAME query embedding, so the
    // similarities are directly comparable.
    enum Candidate {
        Flat(epigraph_db::ClaimEmbeddingHit),
        Hierarchical(epigraph_db::ScoredHierarchicalWorkflowRow),
    }
    let mut candidates: Vec<(f64, Candidate)> =
        Vec::with_capacity(semantic_hits.len() + hierarchical_hits.len());
    for hit in semantic_hits {
        candidates.push((hit.similarity, Candidate::Flat(hit)));
    }
    for row in hierarchical_hits {
        candidates.push((row.similarity, Candidate::Hierarchical(row)));
    }
    candidates.sort_by(|a, b| b.0.total_cmp(&a.0));

    // Build results, enriching with behavioral data
    let mut results = Vec::new();
    for (_, candidate) in candidates {
        if results.len() >= limit as usize {
            break;
        }
        match candidate {
            Candidate::Flat(hit) => {
                if let Ok(Some(claim)) = ClaimRepository::get_by_id(
                    &server.pool,
                    viewer,
                    epigraph_core::ClaimId::from_uuid(hit.claim_id),
                )
                .await
                {
                    if let Some(r) = enrich_workflow_result(
                        &server.pool,
                        viewer,
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
            }
            Candidate::Hierarchical(row) => {
                let steps = hierarchical_steps.remove(&row.id).unwrap_or_default();
                if let Some(r) =
                    hierarchical_workflow_result(&server.pool, viewer, &row, steps, &affinity_map)
                        .await
                {
                    results.push(r);
                }
            }
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
            viewer,
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
                viewer,
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

    // Hierarchical half of the same fallback. Needed for more than symmetry:
    // the embedding leg above is skipped entirely when the embedder is
    // unavailable (`pgvec_opt` is None), which is also the configuration the
    // integration tests run in — without this leg the union would be
    // unreachable exactly where it is cheapest to verify.
    if results.len() < half {
        let text_rows = WorkflowRepository::search_hierarchical_by_text(
            &server.pool,
            &params.goal,
            limit * 2,
            min_truth,
            false, // frozen steps, not lineage heads — see step_texts_for_hierarchical
        )
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("search_hierarchical_by_text fallback failed: {e}");
            Vec::new()
        });

        let already_seen: std::collections::HashSet<String> =
            results.iter().map(|r| r.workflow_id.clone()).collect();
        let text_ids: Vec<uuid::Uuid> = text_rows
            .iter()
            .filter(|r| !already_seen.contains(&r.id.to_string()))
            .map(|r| r.id)
            .collect();
        let mut text_steps =
            WorkflowRepository::step_texts_for_hierarchical(&server.pool, viewer, &text_ids)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!("hierarchical step resolution failed: {e}");
                    std::collections::HashMap::new()
                });

        for row in text_rows {
            if results.len() >= limit_usize {
                break;
            }
            if already_seen.contains(&row.id.to_string()) {
                continue;
            }
            let scored = epigraph_db::ScoredHierarchicalWorkflowRow {
                id: row.id,
                canonical_name: row.canonical_name,
                generation: row.generation,
                goal: row.goal,
                parent_id: row.parent_id,
                metadata: row.metadata,
                created_at: row.created_at,
                truth_value: row.truth_value,
                similarity: 0.0, // text-fallback hit; no semantic similarity score
            };
            let steps = text_steps.remove(&scored.id).unwrap_or_default();
            if let Some(r) =
                hierarchical_workflow_result(&server.pool, viewer, &scored, steps, &affinity_map)
                    .await
            {
                results.push(r);
            }
        }
    }

    success_json(&results)
}

/// Render a hierarchical `workflows` row into the same `FindWorkflowResult`
/// shape the flat workflow claims use, so `find_workflow` can return both
/// stores in one ranked list.
///
/// Returns `None` when `steps` is empty. That guard is the whole reason this
/// function takes resolved steps rather than resolving them lazily: a
/// `workflows` row holds no inline steps, and `FindWorkflowResult.steps` is a
/// `Vec<String>` the caller is expected to execute. Emitting `[]` is exactly
/// the shape that caused the 2026-08-18 incident — an agent instructed to
/// "follow the best-matching workflow steps" got an empty array, fell back to
/// a bare `theme_cluster` with `wipe_first=true`, and destroyed 76 themes. A
/// step-less workflow is not a usable answer to "find me a workflow", so it is
/// withheld rather than surfaced hollow.
///
/// The truth floor is NOT re-applied here: both hierarchical queries already
/// filter on `truth_value >= min_truth` in SQL, which is also what drops
/// `deprecate_workflow`'s 0.05 rows.
async fn hierarchical_workflow_result(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    row: &epigraph_db::ScoredHierarchicalWorkflowRow,
    steps: Vec<String>,
    affinity_map: &std::collections::HashMap<uuid::Uuid, (f64, i64)>,
) -> Option<FindWorkflowResult> {
    if steps.is_empty() {
        tracing::debug!(
            workflow_id = %row.id,
            "find_workflow: withholding hierarchical workflow with no resolvable steps"
        );
        return None;
    }

    // Counters live in `workflows.metadata`, written by
    // `report_hierarchical_outcome`; the flat store keeps the equivalents
    // inside the claim's JSON content.
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

    let lineage_root = WorkflowRepository::find_lineage_root(pool, viewer, row.id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(workflow_id = %row.id, "find_lineage_root failed: {e}");
            row.id
        });
    let (behavioral_affinity, behavioral_execution_count) = match affinity_map.get(&lineage_root) {
        Some(&(sim, count)) => (Some(sim), Some(count)),
        None => (None, None),
    };

    let behavioral_success_rate = if use_count > 0 {
        #[allow(clippy::cast_precision_loss)]
        Some(success_count as f64 / use_count as f64)
    } else {
        None
    };

    Some(FindWorkflowResult {
        workflow_id: row.id.to_string(),
        goal: row.goal.clone(),
        steps,
        truth_value: row.truth_value,
        similarity: row.similarity,
        use_count,
        success_count,
        generation: i64::from(row.generation),
        parent_id: row.parent_id.map(|id| id.to_string()),
        behavioral_affinity,
        behavioral_success_rate,
        behavioral_execution_count,
        // `promotable` is written by `refresh_workflow_promotion` onto the FLAT
        // claim's `properties.promotion`; hierarchical rows have no equivalent
        // field, so it stays absent rather than being faked as `false`.
        promotable: None,
    })
}

/// Build a `FindWorkflowResult` from a workflow claim, applying the shared
/// filters (min_truth, non-empty goal/steps) and behavioral enrichment.
///
/// Returns `None` when the claim fails the truth-value floor or has neither
/// a goal nor steps. Used by both the semantic and text-fallback loops in
/// `find_workflow` to keep enrichment behavior identical.
async fn enrich_workflow_result(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
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
    let lineage_root = WorkflowRepository::find_lineage_root(pool, viewer, workflow_id)
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
    let promotable = ClaimRepository::promotion_flag(pool, viewer, ClaimId::from_uuid(workflow_id))
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
    viewer: &epigraph_db::visibility::Viewer,
    params: ReportWorkflowOutcomeParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let workflow_id = parse_uuid(&params.workflow_id)?;

    // `store_workflow` was migrated to the hierarchical ingest pipeline, so
    // workflow_ids it returns are rows in the `workflows` table — NOT claim
    // ids. Probe `workflows` first; if the id lives there, delegate to the
    // hierarchical outcome path. Falls through to the legacy claims-table
    // flat-workflow path only when the id is not a hierarchical workflow
    // (preserves backward-compat for the ~144 legacy flat-workflow claims).
    let is_hierarchical: bool =
        // VISIBILITY-EXEMPT: `workflows` is not in migration 062's `tier_a`
        // array and carries neither `visibility` nor `owner_group_id` (verified
        // against `information_schema.columns`), so no predicate can be written
        // here. Same category as `papers` in `recall.rs::compute_corpus_scope`.
        // What leaves the function is one boolean routing decision — which of
        // two outcome paths to take — and both paths perform their own
        // viewer-scoped reads. Owner of the residual: the PR that gives
        // `workflows` tenancy columns (plan §2.4's registration pass).
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

    let claim = ClaimRepository::get_by_id(
        &server.pool,
        viewer,
        epigraph_core::ClaimId::from_uuid(workflow_id),
    )
    .await
    .map_err(internal_error)?
    .ok_or_else(|| {
        invalid_params(format!(
            "workflow {workflow_id} not found in `workflows` or `claims` tables"
        ))
    })?;

    // Author = the request's principal (batch H-b, D1); signer = this server.
    let author = server.write_identity(auth, viewer).await?;
    let agent_id = author.agent_id();
    let signer_typed = AgentId::from_uuid(server.signer_agent_id().await?);
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
    // `Evidence::agent_id` is `evidence.signer_id`: this server signs it.
    let mut evidence = Evidence::new(
        signer_typed,
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

    // ── HISTORY: WHY THE EVIDENCE WRITE WAS ONCE LEFT UNSTAMPED ─────────
    //
    // Superseded by the D2 block below, which stamps it; kept because the
    // measurement is what D2 had to answer. Same site, same argument and the same
    // measurement as `tools::claims::update_with_evidence`, which was unstamped
    // for this reason earlier in this branch. `evidence` is tier-A under migration 077's strict
    // `WITH CHECK (owner_group_id = ANY(epigraph_writable_groups()))`, so on the
    // unstamped pool this INSERT is refused on a cleanly-migrated schema — and
    // that refusal is currently the tool's WHOLE outcome, because nothing has
    // been written before it.
    //
    // Stamping it cannot make this tool whole, and the obstruction is structural:
    // migration 046 gives `mass_functions.evidence_id` a FK to `evidence(id)`, and
    // `ds_auto::auto_wire_ds_update` below runs on a SIBLING pool connection that
    // cannot see an uncommitted row. So a stamped evidence INSERT is forced to
    // COMMIT ON ITS OWN, and the DS wiring that follows is itself unconverted —
    // it writes `claim_frames`, which carries no orphan `*_privacy` policy and is
    // therefore refused on BOTH configurations.
    //
    // MEASURED with the real binary over a unix socket as `epigraph_app`
    // (`rolbypassrls = false`), on a legacy flat workflow claim owned by the MCP
    // server agent's own group — the only ownership shape this stamp could ever
    // serve — via `scripts/e2e/probe-workflow.sh`:
    //
    //   CONFIG A, stamped:   `evidence_rows=1`, then
    //                        `assign_claim: … row-level security policy for table
    //                        "claim_frames"`.            ← committed orphan
    //   CONFIG A, unstamped: `evidence_rows=0`, and
    //                        `… policy for table "evidence"`. ← clean refusal
    //   CONFIG B, either:    `evidence_rows=1`, then the same `claim_frames`
    //                        failure.                     ← the stamp changes nothing
    //
    // So the stamp buys nothing on either configuration and, on the one this
    // programme exists to make reachable, trades a clean refusal for a committed
    // orphan. (An earlier form of this note also called it a retry amplifier,
    // on the premise that a fresh `EvidenceId` plus no `ON CONFLICT` appends a
    // row per retry. That is wrong for an IDENTICAL retry: `content_hash` is
    // `blake3(evidence_text)`, a deterministic serialization of the call's
    // arguments, and migration 001's `evidence_content_hash_claim_unique UNIQUE
    // (content_hash, claim_id)` refuses it. Only a retry with different
    // arguments adds a row. See `tools::claims::update_with_evidence`, where the
    // same correction is measured.) Re-adding the stamp belongs in D2, which has
    // to put evidence → BBA → truth_value into one unit anyway.
    //
    // ── D2 lands here too: evidence -> BBA -> truth_value, ONE STAMPED UNIT ──
    //
    // "the DS wiring that follows is itself unconverted" and "a SIBLING pool
    // connection that cannot see an uncommitted row" were both true and are both
    // now false. `ds_auto::auto_wire_ds_update` takes a connection, so it runs on
    // THIS transaction, and migration 046's FK from `mass_functions.evidence_id`
    // is checked against this transaction's own snapshot — an uncommitted evidence
    // row in the same transaction satisfies it. The stamped INSERT is therefore no
    // longer forced to commit alone, which removes the objection: nothing commits
    // unless everything does, so a failed call leaves no BBA-less evidence row
    // behind to make `evidence_content_hash_claim_unique` refuse the identical
    // retry that would land it.
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, author, "report_workflow_outcome")
            .await?;

    EvidenceRepository::create(&mut *tx, &evidence)
        .await
        .map_err(internal_error)?;

    let before = claim.truth_value.value();

    // CDST update: replace Bayesian update with calibration-weighted DS combination.
    // Evidence type "observation" (matches the EvidenceType::Observation created above).
    // quality is the confidence signal; success determines supports/refutes direction.
    let weight = load_evidence_type_weight("observation");
    let ds = ds_auto::auto_wire_ds_update(
        &mut tx,
        viewer,
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

    // Derive truth_value from CDST pignistic probability. `UPDATE claims`, and it
    // commits in the SAME stamped transaction as the evidence INSERT and the DS
    // wiring above — there is no longer an unstamped write before it, and no
    // self-committing unit of its own. It is the tool's last HARD write: what
    // follows the commit is `BehavioralExecutionRepository::create`, which is
    // warn-only and targets `behavioral_executions`: `relrowsecurity = f` with
    // zero policies, so it is refused on neither configuration. That site is
    // registered as a residual in
    // `crates/epigraph-mcp/tests/residual_unstamped_writes.rs` with that reason.
    // After the DS wiring necessarily, because the value comes from it.
    let after = TruthValue::clamped(ds.pignistic_prob);
    {
        ClaimRepository::update_truth_value_conn(
            &mut tx,
            epigraph_core::ClaimId::from_uuid(workflow_id),
            after,
        )
        .await
        .map_err(internal_error)?;
        tx.commit().await.map_err(internal_error)?;
    }

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
    viewer: &epigraph_db::visibility::Viewer,
    params: DeprecateWorkflowParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let workflow_id = parse_uuid(&params.workflow_id)?;
    let cascade = params.cascade.unwrap_or(false);

    let mut deprecated_ids = Vec::new();

    // ── THE WHOLE DEPRECATION, IN ONE AUTHOR-STAMPED TRANSACTION ────────
    //
    // `deprecate_claim` is an `UPDATE claims`, so `claims_tenancy`'s WITH CHECK
    // governs it and an unstamped session is refused with `42501`. The cascade
    // makes that worse than a single refusal: it walks a tree deprecating one
    // claim at a time, so a refusal partway through used to leave a HALF-
    // DEPRECATED hierarchy — some variants flipped, some still current, and
    // `find_workflow_hierarchical` returning the ones that were missed.
    //
    // THE STAMP IS LOAD-BEARING, AND THAT IS MEASURED RATHER THAN ARGUED.
    //
    // A review finding held that this conversion is INERT for its own target
    // population, because every workflow claim is authored by the
    // `workflow-ingest-system` agent while this tool stamps from
    // `server.agent_id()`. The authorship half is correct —
    // `epigraph_ingest_executor::execute_workflow_ingest_plan` resolves
    // `get_or_create_system_agent` and passes that id to
    // `create_with_id_if_absent` — but the population half does not survive
    // measurement. Taken as `epigraph_app` (`rolbypassrls = false`) with the real
    // binary over a unix socket, via `scripts/e2e/probe-workflow.sh`, on a
    // cleanly-migrated schema, differing only in the binary:
    //
    //   flat workflow claim owned by the server agent's OWN group
    //     stamped   -> succeeds, `is_current = false`
    //     unstamped -> `new row violates row-level security policy for table
    //                   "claims"`, `is_current = true`
    //   the same claim owned by a FOREIGN group
    //     stamped   -> refused;  unstamped -> refused
    //
    // Revert the stamp and the write fails; restore it and the write lands. On
    // CONFIG B both binaries succeed, so production sees no change.
    //
    // WHY THE FOREIGN CASE IS NOT THE ANSWER HERE. The reviewer reached it with
    // raw SQL. Through the tool it is not reachable: `store_workflow` returns a
    // `workflows` ROW id, and `find_workflow` and `find_workflow_hierarchical`
    // both return that same id (MEASURED: the id they returned was present in
    // `workflows` and absent from `claims`). No discovery tool in this surface
    // hands `deprecate_workflow` a system-agent-owned CLAIM id.
    //
    // THE RESIDUAL THAT IS REAL, stated so the green above is not over-read: for a
    // HIERARCHICAL workflow this tool deprecates nothing in `claims` at all. It is
    // handed the `workflows` row id, `deprecate_claim` matches zero rows, and the
    // thesis and step claims stay `is_current = true` while the response reports
    // that id as deprecated. MEASURED: `deprecated_ids: ["3d99ce3a-…"]` with
    // `SELECT … FROM claims WHERE id = '3d99ce3a-…'` returning no row and all four
    // seeded workflow claims still current. Fixing that means deprecating claims
    // the system agent owns, which is the author-stamping question (#493) rather
    // than a rename — it is recorded here, not silently widened.
    //
    // TWO AUTHORITIES IN ONE LOOP, deliberately. The transaction's session GUCs
    // carry the SERVER AGENT's groups (the write authority), while the traversal
    // below splices the CALLER's `viewer` (the read authority). That divergence is
    // intentional and neither half may take the other's: stamping the caller would
    // refuse the write this tool exists to perform, and reading with the server
    // agent's viewer would let a caller cascade into workflow claims it cannot
    // see. The widened USING side does mean the cascade can ENUMERATE rows the
    // caller's viewer would not reach on the unstamped pool; the `viewer.splice`
    // label oracle below is what keeps that from turning into a write, and it is
    // filtered rather than exempted for exactly this reason. On stdio the caller
    // and the server agent coincide, so this only differs on authenticated HTTP.
    //
    // The traversal reads run on the same stamped connection as the writes, which
    // is the correct direction: an unstamped read returns FEWER rows, so a
    // cascade planned on one connection and executed on another could silently
    // skip a child it was entitled to deprecate.
    let mut tx = crate::claim_helper::begin_author_stamped_tx(
        server,
        server.write_identity(auth, viewer).await?,
        "deprecate_workflow",
    )
    .await?;

    // Deprecate the target workflow (A4: also set is_current = false).
    // ClaimRepository::deprecate_claim ALSO nulls the embedding in the same
    // statement — required by CLAUDE.md "Embedding policy → Cleanup paths"
    // so the deprecated workflow drops out of semantic recall and does not
    // inflate the `stale_present` audit count.
    ClaimRepository::deprecate_claim(&mut *tx, epigraph_core::ClaimId::from_uuid(workflow_id))
        .await
        .map_err(internal_error)?;
    // Cascade onto the hierarchical `workflows` row (no-op when this
    // workflow has only a flat-claim representation). Without this,
    // `find_workflow_hierarchical` keeps returning the deprecated row.
    // `workflows` is NOT RLS-protected (measured: no policy, not in 062's
    // tier-A), so this half was never refused — it is in the transaction so the
    // two halves of one deprecation cannot land apart.
    epigraph_db::WorkflowRepository::set_truth_value(&mut *tx, workflow_id, 0.05)
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
            // PROPAGATED, not swallowed. This read was `.unwrap_or_default()`
            // before the branch, and on `&server.pool` that was harmless: the
            // target's deprecation had already autocommitted and a failed read
            // merely skipped the children. INSIDE the transaction the same swallow
            // is a poison pill, and the failure it produces is WORSE than the
            // `25P02` one might expect.
            //
            // MEASURED, by dropping `edges` inside a `#[sqlx::test]` database and
            // calling this tool with `cascade: true` on the swallowing revision:
            //
            //     {"deprecated_ids": ["dc975b42-…"], "reason": "cascade read failure"}
            //     is_error: false
            //
            // — success, with nothing written. The mechanism is PostgreSQL's, not
            // sqlx's: after an error inside a transaction block, `COMMIT` is
            // accepted and returns the `ROLLBACK` command tag rather than an error
            // (verified directly: `BEGIN; INSERT…; SELECT FROM <missing>; COMMIT;`
            // leaves zero rows and raises nothing on the COMMIT). So the swallow
            // aborts the transaction, the loop exits with an empty edge list,
            // `tx.commit()` returns `Ok`, and the tool reports a deprecation that
            // was discarded in full. A caller cannot tell, and neither can a log.
            //
            // That is the failure mode #494's SAVEPOINT discipline exists to
            // prevent (`EventRepository::publish_or_log_conn` opens one;
            // `create_or_get`'s duplicate-key re-find opens one). A SAVEPOINT would
            // work here too, but propagation is the better answer for THIS read: a
            // savepoint preserves the "skip the children" behaviour, and that
            // behaviour was only ever an accident of running outside a transaction.
            // A cascade that cannot enumerate its children has not completed.
            let edges = EdgeRepository::get_by_target(&mut *tx, viewer, current, "claim")
                .await
                .map_err(internal_error)?;

            for edge in edges {
                if !DESCENDANT_REL.contains(&edge.relationship.as_str()) {
                    continue;
                }
                let child_id = edge.source_id;
                // Filter to workflow-labeled claims only.
                let is_workflow: bool = {
                    // PR-09: a label-membership oracle over an id reached by
                    // graph traversal. Filtered rather than exempted — a child
                    // the viewer cannot read must not be cascaded into, and
                    // `unwrap_or(false)` already means "not a workflow, skip".
                    let sql = viewer.splice(
                        "SELECT 'workflow' = ANY(c.labels) FROM claims c \
                         WHERE c.id = $1 /* {VISIBILITY:c} */",
                        2,
                    );
                    let mut q = sqlx::query_scalar(&sql).bind(child_id);
                    if let Some(g) = viewer.group_bind() {
                        q = q.bind(g);
                    }
                    q.fetch_optional(&mut *tx)
                        .await
                        .map_err(internal_error)?
                        .unwrap_or(false)
                };
                if !is_workflow {
                    continue;
                }

                if !visited.insert(child_id) {
                    continue;
                }

                let child_rows = ClaimRepository::deprecate_claim(
                    &mut *tx,
                    epigraph_core::ClaimId::from_uuid(child_id),
                )
                .await
                .map_err(internal_error)?;
                // Mirror onto the hierarchical row, if any.
                epigraph_db::WorkflowRepository::set_truth_value(&mut *tx, child_id, 0.05)
                    .await
                    .map_err(internal_error)?;
                // REPORT ONLY WHAT ACTUALLY FLIPPED. `deprecate_claim` returns
                // `rows_affected`, and a cascade child can legitimately yield 0:
                // `claims_tenancy`'s USING side filters the UPDATE's target, so a
                // row this session may not write is silently not written rather
                // than refused. Pushing the id regardless made the response assert
                // a deprecation that did not happen — and unlike a `42501`, a
                // USING-filtered miss raises nothing for the caller to notice.
                // The traversal still descends: `is_workflow` above proved this is
                // a workflow claim, and a child that was skipped here may still
                // have descendants that are not.
                if child_rows > 0 {
                    deprecated_ids.push(child_id.to_string());
                }
                queue.push(child_id);
            }
        }
    }

    tx.commit().await.map_err(internal_error)?;

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
        viewer: &epigraph_db::visibility::Viewer,
        params: FindWorkflowParams,
        pgvec: Option<String>,
    ) -> Result<CallToolResult, McpError> {
        find_workflow_post_embed(server, viewer, &params, pgvec).await
    }
}
