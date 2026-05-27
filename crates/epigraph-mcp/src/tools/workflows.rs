#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::ds_auto;
use crate::types::*;

use epigraph_core::{AgentId, Claim, Evidence, EvidenceType, TruthValue};
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
    let limit = params.limit.unwrap_or(5).clamp(1, 20);
    let min_truth = params.min_truth.unwrap_or(0.3);

    // Generate embedding once — reused for both semantic search and behavioral
    // affinity. Failure here is non-fatal: we still want the ILIKE fallback to
    // run (workflows commonly lack evidence embeddings, and offline embedders
    // shouldn't blank the whole tool).
    let pgvec_opt = match server.embedder.generate(&params.goal).await {
        Ok(v) => Some(format_pgvector(&v)),
        Err(e) => {
            tracing::warn!("embedder failed in find_workflow; relying on text fallback: {e}");
            None
        }
    };

    // Semantic search via evidence embeddings (only when embedding is available).
    let semantic_hits = if let Some(pgvec) = pgvec_opt.as_deref() {
        epigraph_db::EvidenceRepository::search_by_embedding(&server.pool, pgvec, limit * 3)
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

    // Deprecate the target workflow (A4: also set is_current = false)
    sqlx::query(
        "UPDATE claims SET truth_value = 0.05, is_current = false, updated_at = NOW() WHERE id = $1",
    )
    .bind(workflow_id)
    .execute(&server.pool)
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

                sqlx::query(
                    "UPDATE claims SET truth_value = 0.05, is_current = false, updated_at = NOW() WHERE id = $1",
                )
                .bind(child_id)
                .execute(&server.pool)
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
