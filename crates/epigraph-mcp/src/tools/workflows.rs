#![allow(clippy::wildcard_imports)]

use std::fmt::Write;

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::ds_auto;
use crate::types::*;

use epigraph_core::{
    AgentId, Claim, Evidence, EvidenceType, Methodology, ReasoningTrace, TraceInput, TruthValue,
};
use epigraph_crypto::ContentHasher;
use epigraph_db::{
    BehavioralExecutionRepository, ClaimRepository, EdgeRepository, EvidenceRepository,
    ReasoningTraceRepository, WorkflowRepository,
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

fn workflow_embed_text(goal: &str, steps: &[String], prereqs: &[String]) -> String {
    let mut text = format!("Workflow: {goal}. Steps: ");
    for (i, step) in steps.iter().enumerate() {
        if i > 0 {
            text.push_str(", ");
        }
        let _ = write!(text, "{}. {}", i + 1, step);
    }
    if !prereqs.is_empty() {
        text.push_str(". Prerequisites: ");
        text.push_str(&prereqs.join(", "));
    }
    text
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

pub async fn store_workflow(
    server: &EpiGraphMcpFull,
    params: StoreWorkflowParams,
) -> Result<CallToolResult, McpError> {
    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();
    let confidence = params.confidence.unwrap_or(0.5).clamp(0.0, 1.0);
    let tags = params.tags.unwrap_or_default();
    let prereqs = params.prerequisites.unwrap_or_default();

    let content = serde_json::json!({
        "goal": params.goal,
        "steps": params.steps,
        "prerequisites": prereqs,
        "expected_outcome": params.expected_outcome,
        "tags": tags,
        "type": "workflow",
        "generation": 0,
        "use_count": 0,
        "success_count": 0,
        "failure_count": 0,
        "avg_variance": 1.0,
    });
    let content_str = serde_json::to_string(&content).map_err(internal_error)?;

    let raw_truth = (confidence * 0.5).clamp(0.01, 0.99);
    let mut claim = Claim::new(
        content_str.clone(),
        agent_id_typed,
        pub_key,
        TruthValue::clamped(raw_truth),
    );
    claim.content_hash = ContentHasher::hash(content_str.as_bytes());
    claim.signature = Some(server.signer.sign(&claim.content_hash));

    let (claim, was_created) =
        crate::claim_helper::create_claim_idempotent(&server.pool, &claim, "store_workflow")
            .await?;
    let claim_uuid = claim.id.as_uuid();

    let (final_truth, ds, embedded) = if was_created {
        let evidence_text = format!("Workflow hypothesis: {}", params.goal);
        let evidence_hash = ContentHasher::hash(evidence_text.as_bytes());
        let mut evidence = Evidence::new(
            agent_id_typed,
            pub_key,
            evidence_hash,
            EvidenceType::Testimony {
                source: "mcp-workflow".to_string(),
                testified_at: chrono::Utc::now(),
                verification: None,
            },
            Some(evidence_text),
            claim.id,
        );
        evidence.signature = Some(server.signer.sign(&evidence_hash));

        let trace = ReasoningTrace::new(
            agent_id_typed,
            pub_key,
            Methodology::Heuristic,
            vec![TraceInput::Evidence { id: evidence.id }],
            confidence,
            format!("Workflow stored: {}", params.goal),
        );

        ReasoningTraceRepository::create(&server.pool, &trace, claim.id)
            .await
            .map_err(internal_error)?;
        EvidenceRepository::create(&server.pool, &evidence)
            .await
            .map_err(internal_error)?;
        ClaimRepository::update_trace_id(&server.pool, claim.id, trace.id)
            .await
            .map_err(internal_error)?;

        let ds = match ds_auto::auto_wire_ds_for_claim(
            &server.pool,
            claim_uuid,
            agent_id,
            confidence,
            0.5,
            true,
            None,
        )
        .await
        {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!(workflow_id = %claim_uuid, "ds auto-wire workflow failed: {e}");
                None
            }
        };

        let embed_text = workflow_embed_text(&params.goal, &params.steps, &prereqs);
        let embedded = server
            .embedder
            .embed_and_store(claim_uuid, &embed_text)
            .await;

        (raw_truth, ds, embedded)
    } else {
        (claim.truth_value.value(), None, false)
    };

    success_json(&StoreWorkflowResponse {
        workflow_id: claim_uuid.to_string(),
        goal: params.goal,
        step_count: params.steps.len(),
        truth_value: final_truth,
        embedded,
        belief: ds.as_ref().map(|d| d.belief),
        plausibility: ds.as_ref().map(|d| d.plausibility),
    })
}

pub async fn find_workflow(
    server: &EpiGraphMcpFull,
    params: FindWorkflowParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(5).clamp(1, 20);
    let min_truth = params.min_truth.unwrap_or(0.3);

    // Generate embedding once — reused for both semantic search and behavioral affinity
    let query_vec = match server.embedder.generate(&params.goal).await {
        Ok(v) => v,
        Err(_) => return success_json(&Vec::<FindWorkflowResult>::new()),
    };
    let pgvec = format_pgvector(&query_vec);

    // Semantic search via evidence embeddings
    let semantic_hits =
        epigraph_db::EvidenceRepository::search_by_embedding(&server.pool, &pgvec, limit * 3)
            .await
            .map_err(internal_error)?;

    // Behavioral affinity lookup (best-effort)
    let affinity_map: std::collections::HashMap<uuid::Uuid, (f64, i64)> =
        match BehavioralExecutionRepository::behavioral_affinity_lineage(
            &server.pool,
            &pgvec,
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
            if claim.truth_value.value() < min_truth {
                continue;
            }
            let (goal, steps, _prereqs, _expected) = parse_workflow_content(&claim.content);
            if goal.is_empty() && steps.is_empty() {
                continue;
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

            // Look up behavioral data via lineage root
            let lineage_root = WorkflowRepository::find_lineage_root(&server.pool, hit.claim_id)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(workflow_id = %hit.claim_id, "find_lineage_root failed: {e}");
                    hit.claim_id
                });

            let (behavioral_affinity, behavioral_execution_count) =
                match affinity_map.get(&lineage_root) {
                    Some(&(sim, count)) => (Some(sim), Some(count)),
                    None => (None, None),
                };

            // Success rate is per-workflow (not per-lineage). Only report if
            // this specific workflow has executions — variants with zero
            // executions show None, not Some(0.0).
            let behavioral_success_rate = if behavioral_execution_count.is_some() {
                match BehavioralExecutionRepository::rolling_success_rate(
                    &server.pool,
                    hit.claim_id,
                    20,
                )
                .await
                {
                    Ok(rate) if rate > 0.0 => Some(rate),
                    _ => None,
                }
            } else {
                None
            };

            results.push(FindWorkflowResult {
                workflow_id: hit.claim_id.to_string(),
                goal,
                steps,
                truth_value: claim.truth_value.value(),
                similarity: hit.similarity,
                use_count,
                success_count,
                generation,
                parent_id,
                behavioral_affinity,
                behavioral_success_rate,
                behavioral_execution_count,
            });
        }
        if results.len() >= limit as usize {
            break;
        }
    }

    success_json(&results)
}

pub async fn report_workflow_outcome(
    server: &EpiGraphMcpFull,
    params: ReportWorkflowOutcomeParams,
) -> Result<CallToolResult, McpError> {
    let workflow_id = parse_uuid(&params.workflow_id)?;
    let claim =
        ClaimRepository::get_by_id(&server.pool, epigraph_core::ClaimId::from_uuid(workflow_id))
            .await
            .map_err(internal_error)?
            .ok_or_else(|| invalid_params(format!("workflow {workflow_id} not found")))?;

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

pub async fn improve_workflow(
    server: &EpiGraphMcpFull,
    params: ImproveWorkflowParams,
) -> Result<CallToolResult, McpError> {
    let parent_id = parse_uuid(&params.parent_workflow_id)?;
    let parent =
        ClaimRepository::get_by_id(&server.pool, epigraph_core::ClaimId::from_uuid(parent_id))
            .await
            .map_err(internal_error)?
            .ok_or_else(|| invalid_params(format!("parent workflow {parent_id} not found")))?;

    let (parent_goal, parent_steps, parent_prereqs, parent_outcome) =
        parse_workflow_content(&parent.content);
    let parent_val: serde_json::Value = serde_json::from_str(&parent.content).unwrap_or_default();
    let parent_gen = parent_val
        .get("generation")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let parent_tags: Vec<String> = parent_val
        .get("tags")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let goal = params.goal.unwrap_or(parent_goal);
    let steps = params.steps.unwrap_or(parent_steps);
    let prereqs = params.prerequisites.unwrap_or(parent_prereqs);
    let expected_outcome = params.expected_outcome.or(parent_outcome);
    let generation = parent_gen + 1;

    let mut tags = parent_tags;
    if let Some(extra) = params.tags {
        tags.extend(extra);
    }
    tags.sort();
    tags.dedup();

    let content = serde_json::json!({
        "goal": goal,
        "steps": steps,
        "prerequisites": prereqs,
        "expected_outcome": expected_outcome,
        "tags": tags,
        "type": "workflow",
        "generation": generation,
        "parent_id": parent_id.to_string(),
        "change_rationale": params.change_rationale,
        "use_count": 0,
        "success_count": 0,
        "failure_count": 0,
        "avg_variance": 1.0,
    });
    let content_str = serde_json::to_string(&content).map_err(internal_error)?;

    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();

    let mut claim = Claim::new(
        content_str.clone(),
        agent_id_typed,
        pub_key,
        TruthValue::clamped(0.5),
    );
    claim.content_hash = ContentHasher::hash(content_str.as_bytes());
    claim.signature = Some(server.signer.sign(&claim.content_hash));

    let (claim, was_created) =
        crate::claim_helper::create_claim_idempotent(&server.pool, &claim, "improve_workflow")
            .await?;
    let claim_uuid = claim.id.as_uuid();

    let embedded = if was_created {
        let evidence_text = format!(
            "Improved variant of workflow {}. Rationale: {}",
            parent_id, params.change_rationale
        );
        let evidence_hash = ContentHasher::hash(evidence_text.as_bytes());
        let mut evidence = Evidence::new(
            agent_id_typed,
            pub_key,
            evidence_hash,
            EvidenceType::Testimony {
                source: "mcp-workflow-improve".to_string(),
                testified_at: chrono::Utc::now(),
                verification: None,
            },
            Some(evidence_text),
            claim.id,
        );
        evidence.signature = Some(server.signer.sign(&evidence_hash));

        let trace = ReasoningTrace::new(
            agent_id_typed,
            pub_key,
            Methodology::Heuristic,
            vec![
                TraceInput::Evidence { id: evidence.id },
                TraceInput::Claim {
                    id: epigraph_core::ClaimId::from_uuid(parent_id),
                },
            ],
            0.5,
            format!(
                "Workflow variant of {}. {}",
                parent_id, params.change_rationale
            ),
        );

        ReasoningTraceRepository::create(&server.pool, &trace, claim.id)
            .await
            .map_err(internal_error)?;
        EvidenceRepository::create(&server.pool, &evidence)
            .await
            .map_err(internal_error)?;
        ClaimRepository::update_trace_id(&server.pool, claim.id, trace.id)
            .await
            .map_err(internal_error)?;

        // First-create only: the parent → variant relationship.
        EdgeRepository::create(
            &server.pool,
            claim_uuid,
            "claim",
            parent_id,
            "claim",
            "variant_of",
            Some(serde_json::json!({"generation": generation})),
            None,
            None,
        )
        .await
        .map_err(internal_error)?;

        let embed_text = workflow_embed_text(&goal, &steps, &prereqs);
        server
            .embedder
            .embed_and_store(claim_uuid, &embed_text)
            .await
    } else {
        // Option A + idempotent variant_of: skip everything including the
        // variant_of edge (already created on first variant insert).
        false
    };

    success_json(&ImproveWorkflowResponse {
        variant_id: claim_uuid.to_string(),
        parent_id: parent_id.to_string(),
        goal,
        step_count: steps.len(),
        generation,
        truth_value: claim.truth_value.value(),
        embedded,
    })
}

pub async fn deprecate_workflow(
    server: &EpiGraphMcpFull,
    params: DeprecateWorkflowParams,
) -> Result<CallToolResult, McpError> {
    let workflow_id = parse_uuid(&params.workflow_id)?;
    let cascade = params.cascade.unwrap_or(false);

    let mut deprecated_ids = Vec::new();

    // Deprecate the target workflow
    ClaimRepository::update_truth_value(
        &server.pool,
        epigraph_core::ClaimId::from_uuid(workflow_id),
        TruthValue::clamped(0.05),
    )
    .await
    .map_err(internal_error)?;
    deprecated_ids.push(workflow_id.to_string());

    if cascade {
        // Find all descendants via variant_of edges
        let mut queue = vec![workflow_id];
        while let Some(current) = queue.pop() {
            let edges = EdgeRepository::get_by_target(&server.pool, current, "claim")
                .await
                .unwrap_or_default();

            for edge in edges {
                if edge.relationship == "variant_of" {
                    let child_id = edge.source_id;
                    ClaimRepository::update_truth_value(
                        &server.pool,
                        epigraph_core::ClaimId::from_uuid(child_id),
                        TruthValue::clamped(0.05),
                    )
                    .await
                    .map_err(internal_error)?;
                    deprecated_ids.push(child_id.to_string());
                    queue.push(child_id);
                }
            }
        }
    }

    success_json(&DeprecateWorkflowResponse {
        deprecated_ids,
        reason: params.reason,
    })
}
