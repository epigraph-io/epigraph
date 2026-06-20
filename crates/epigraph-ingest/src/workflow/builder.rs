//! Workflow hierarchy walker. Reads a `WorkflowExtraction` and produces an
//! `IngestPlan` of claims + edges + path index. Compound nodes are scoped by
//! `canonical_name`; operation atoms use the global `ATOM_NAMESPACE` (shared
//! with documents) for cross-source convergence.

use std::collections::HashMap;

use uuid::Uuid;

use crate::common::edges::{decomposes_edge, thesis_derivation_str};
use crate::common::ids::{atom_id, compound_claim_id, content_hash, workflow_root_id};
use crate::common::paths::normalize_claim_path;
use crate::common::plan::{IngestPlan, PlannedClaim, PlannedEdge};
use crate::workflow::schema::WorkflowExtraction;

/// Walk a `WorkflowExtraction` tree and produce a flat list of operations.
///
/// The result includes a `workflow` source-node id (deterministic from
/// `canonical_name + generation`) but does NOT include the `workflow —executes→`
/// edges — those are emitted by `epigraph-mcp::tools::workflow_ingest::do_ingest_workflow`
/// once the workflow row is created. The plan returns claims + intra-claim
/// edges + path index, identical in shape to the document plan.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn build_ingest_plan(extraction: &WorkflowExtraction) -> IngestPlan {
    let mut claims = Vec::new();
    let mut edges = Vec::new();
    let mut path_index = HashMap::new();

    let canonical_name = &extraction.source.canonical_name;
    let source_type = "workflow";

    // Step 1: Thesis (level 0)
    let thesis_id = if let Some(ref thesis_text) = extraction.thesis {
        let hash = content_hash(thesis_text);
        let id = compound_claim_id(&hash, canonical_name);
        path_index.insert("thesis".to_string(), id);

        claims.push(PlannedClaim {
            id,
            content: thesis_text.clone(),
            level: 0,
            properties: serde_json::json!({
                "level": 0,
                "source_type": source_type,
                "thesis_derivation": thesis_derivation_str(&extraction.thesis_derivation),
                "kind": "workflow_thesis",
            }),
            content_hash: hash,
            confidence: 1.0,
            methodology: None,
            evidence_type: None,
            supporting_text: None,
            enrichment: serde_json::json!({}),
        });
        Some(id)
    } else {
        None
    };

    let mut phase_ids: Vec<Uuid> = Vec::new();

    for (pi, phase) in extraction.phases.iter().enumerate() {
        let phase_path = format!("phases[{pi}]");
        // BUGFIX (k1-trace-bug): `Phase.summary` carries `#[serde(default)]` in
        // schema.rs so it silently defaults to `""` when the field is omitted from
        // JSON input. Passing an empty string as `content` to
        // `ClaimRepository::create_with_id_if_absent` violates the DB constraint
        // `claims_content_not_empty` (`length(TRIM(BOTH FROM content)) > 0`).
        //
        // Root-cause line: this was `content_hash(&phase.summary)` / `content:
        // phase.summary.clone()` with no guard — any caller that omits `summary`
        // would trigger the constraint, regardless of `canonical_name`.
        // `improve_workflow_hierarchy` with `parent_canonical_name =
        // "weekly-capability-audit"` was the first observed trigger, but the bug
        // affects every code path that reaches `build_ingest_plan`.
        //
        // Fix: fall back to `phase.title` (always required, never empty) when
        // `summary` is blank. The hash is computed from whichever string ends up as
        // the claim content so the deterministic ID stays consistent with what is
        // actually persisted.
        let phase_content = if phase.summary.trim().is_empty() {
            phase.title.clone()
        } else {
            phase.summary.clone()
        };
        let phase_hash = content_hash(&phase_content);
        let phase_id = compound_claim_id(&phase_hash, canonical_name);
        phase_ids.push(phase_id);
        path_index.insert(phase_path.clone(), phase_id);

        // `kind: "workflow_step"` is intentionally shared with level-2 step claims
        // below. The label parallels this — `'workflow_step'` covers levels 1 and 2
        // so that `WHERE 'workflow_step' = ANY(labels)` returns all non-thesis,
        // non-atomic hierarchical content under a workflow as a single set. Use
        // `properties.level` (1 vs 2) to disambiguate phase from step when needed.
        claims.push(PlannedClaim {
            id: phase_id,
            content: phase_content,
            level: 1,
            properties: serde_json::json!({
                "level": 1,
                "source_type": source_type,
                "phase": phase.title,
                "kind": "workflow_step",
            }),
            content_hash: phase_hash,
            confidence: 1.0,
            methodology: None,
            evidence_type: None,
            supporting_text: None,
            enrichment: serde_json::json!({}),
        });

        if let Some(tid) = thesis_id {
            edges.push(decomposes_edge(tid, phase_id));
        }

        let mut step_ids: Vec<Uuid> = Vec::new();

        for (si, step) in phase.steps.iter().enumerate() {
            let step_path = format!("{phase_path}.steps[{si}]");
            let step_hash = content_hash(&step.compound);
            let step_id = compound_claim_id(&step_hash, canonical_name);
            step_ids.push(step_id);
            path_index.insert(step_path.clone(), step_id);

            claims.push(PlannedClaim {
                id: step_id,
                content: step.compound.clone(),
                level: 2,
                properties: serde_json::json!({
                    "level": 2,
                    "source_type": source_type,
                    "phase": phase.title,
                    "rationale": step.rationale,
                    "kind": "workflow_step",
                }),
                content_hash: step_hash,
                confidence: step.confidence,
                methodology: None,
                evidence_type: None,
                supporting_text: Some(step.rationale.clone()),
                enrichment: serde_json::json!({}),
            });

            edges.push(decomposes_edge(phase_id, step_id));

            for (oi, op_text) in step.operations.iter().enumerate() {
                let op_hash = content_hash(op_text);
                // ATOM_NAMESPACE is the SAME namespace documents use → cross-source convergence.
                let oid = atom_id(&op_hash);
                let op_path = format!("{step_path}.operations[{oi}]");
                path_index.insert(op_path, oid);

                let generality = step.generality.get(oi).copied().filter(|&g| g >= 0);

                let mut props = serde_json::json!({
                    "level": 3,
                    "source_type": source_type,
                    "phase": phase.title,
                    "kind": "workflow_atom",
                });
                if let Some(g) = generality {
                    props["generality"] = serde_json::json!(g);
                }

                claims.push(PlannedClaim {
                    id: oid,
                    content: op_text.clone(),
                    level: 3,
                    properties: props,
                    content_hash: op_hash,
                    confidence: step.confidence,
                    methodology: None,
                    evidence_type: None,
                    supporting_text: Some(step.rationale.clone()),
                    enrichment: serde_json::json!({}),
                });

                edges.push(decomposes_edge(step_id, oid));
            }
        }

        // step_follows within the phase
        for w in step_ids.windows(2) {
            edges.push(PlannedEdge {
                source_id: w[0],
                source_type: "claim".to_string(),
                target_id: w[1],
                target_type: "claim".to_string(),
                relationship: "step_follows".to_string(),
                properties: serde_json::json!({}),
            });
        }
    }

    // phase_follows between phases
    for w in phase_ids.windows(2) {
        edges.push(PlannedEdge {
            source_id: w[0],
            source_type: "claim".to_string(),
            target_id: w[1],
            target_type: "claim".to_string(),
            relationship: "phase_follows".to_string(),
            properties: serde_json::json!({}),
        });
    }

    // Cross-references from extraction.relationships
    for rel in &extraction.relationships {
        let src_path = normalize_claim_path(&rel.source_path);
        let tgt_path = normalize_claim_path(&rel.target_path);
        let source_id = match path_index.get(&src_path) {
            Some(id) => *id,
            None => continue,
        };
        let target_id = match path_index.get(&tgt_path) {
            Some(id) => *id,
            None => continue,
        };
        let mut props = serde_json::json!({});
        if let Some(ref rationale) = rel.rationale {
            props["rationale"] = serde_json::json!(rationale);
        }
        if let Some(strength) = rel.strength {
            props["strength"] = serde_json::json!(strength);
        }
        edges.push(PlannedEdge {
            source_id,
            source_type: "claim".to_string(),
            target_id,
            target_type: "claim".to_string(),
            relationship: rel.relationship.clone(),
            properties: props,
        });
    }

    // Author → claim edges (same as documents; resolved by MCP layer to real agent UUIDs)
    for (author_idx, _author) in extraction.source.authors.iter().enumerate() {
        for planned_claim in &claims {
            edges.push(PlannedEdge {
                source_id: Uuid::nil(),
                source_type: "author_placeholder".to_string(),
                target_id: planned_claim.id,
                target_type: "claim".to_string(),
                relationship: "asserts".to_string(),
                properties: serde_json::json!({
                    "author_index": author_idx,
                    "role": "author",
                    "source": "workflow_attribution",
                }),
            });
        }
    }

    IngestPlan {
        claims,
        edges,
        path_index,
    }
}

/// Compute the deterministic `workflows.id` for an extraction's source.
#[must_use]
pub fn root_workflow_id(extraction: &WorkflowExtraction) -> Uuid {
    workflow_root_id(
        &extraction.source.canonical_name,
        extraction.source.generation,
    )
}

impl crate::common::walker::Walker for WorkflowExtraction {
    fn build_ingest_plan(&self) -> IngestPlan {
        build_ingest_plan(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::schema::ThesisDerivation;
    use crate::workflow::schema::{Phase, Step, WorkflowSource};

    fn extraction_with_empty_phase_summary() -> WorkflowExtraction {
        WorkflowExtraction {
            source: WorkflowSource {
                canonical_name: "weekly-capability-audit".to_string(),
                goal: "Audit weekly capabilities".to_string(),
                generation: 1,
                parent_canonical_name: Some("weekly-capability-audit".to_string()),
                authors: vec![],
                expected_outcome: None,
                tags: vec![],
                metadata: serde_json::json!({}),
            },
            thesis: Some("Thesis text".to_string()),
            thesis_derivation: ThesisDerivation::TopDown,
            phases: vec![Phase {
                title: "Capability Review".to_string(),
                summary: "".to_string(), // empty — serde default; triggers constraint bug
                steps: vec![Step {
                    compound: "Review all capabilities".to_string(),
                    rationale: "Need to know what we have".to_string(),
                    operations: vec!["List capabilities".to_string()],
                    generality: vec![1],
                    confidence: 0.9,
                }],
            }],
            relationships: vec![],
        }
    }

    /// Regression: a Phase with `summary = ""` (the serde default when the field
    /// is omitted from JSON) must NOT produce a PlannedClaim with empty content,
    /// because the DB enforces `claims_content_not_empty` CHECK
    /// `(length(TRIM(BOTH FROM content)) > 0)`.
    ///
    /// Root cause: `Phase.summary` is `#[serde(default)]` (schema.rs:54), so it
    /// defaults to `""`. `build_ingest_plan` previously passed `phase.summary.clone()`
    /// directly as `PlannedClaim.content` for level-1 phase claims without guarding
    /// against an empty value. The fix falls back to `phase.title` when `summary`
    /// is blank, which is always present and required.
    #[test]
    fn phase_with_empty_summary_falls_back_to_title() {
        let extraction = extraction_with_empty_phase_summary();
        let plan = build_ingest_plan(&extraction);

        for claim in &plan.claims {
            assert!(
                !claim.content.trim().is_empty(),
                "PlannedClaim at level {} has empty content (would violate \
                 claims_content_not_empty); id={:?}",
                claim.level,
                claim.id,
            );
        }

        // The phase claim (level=1) must have fallen back to the title.
        let phase_claim = plan
            .claims
            .iter()
            .find(|c| c.level == 1)
            .expect("expected a level-1 phase claim");
        assert_eq!(
            phase_claim.content, "Capability Review",
            "phase claim content should be the phase title when summary is empty"
        );
    }

    /// A Phase with a non-empty summary must continue to use the summary as
    /// content (no regression).
    #[test]
    fn phase_with_nonempty_summary_uses_summary() {
        let mut extraction = extraction_with_empty_phase_summary();
        extraction.phases[0].summary = "Non-empty summary text".to_string();
        let plan = build_ingest_plan(&extraction);

        let phase_claim = plan
            .claims
            .iter()
            .find(|c| c.level == 1)
            .expect("expected a level-1 phase claim");
        assert_eq!(phase_claim.content, "Non-empty summary text");
    }
}
