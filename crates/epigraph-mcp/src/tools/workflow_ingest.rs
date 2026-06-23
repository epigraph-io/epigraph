//! Hierarchical workflow ingest tool.
//!
//! `do_ingest_workflow` walks a `WorkflowExtraction` JSON payload, persists
//! the claim hierarchy (thesis → phases → steps → operation atoms), writes
//! `workflow —executes→ claim` edges for every planned claim, resolves author
//! placeholder edges, and returns a summary. Mirrors `do_ingest_document` in
//! `ingestion.rs`.
//!
//! The persistence body lives in [`epigraph_ingest_executor::execute_workflow_ingest_plan`];
//! this module is now a thin wrapper that builds an ingest plan, invokes the
//! executor, and maps the result into the MCP response shape.

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::ds_auto;
use crate::types::{ImproveWorkflowHierarchyParams, IngestWorkflowParams};

use epigraph_ingest::workflow::WorkflowExtraction;

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

// ── Response type ──────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
pub struct IngestWorkflowResponse {
    pub workflow_id: String,
    pub canonical_name: String,
    pub generation: i32,
    pub claims_ingested: usize,
    pub claims_skipped_dedup: usize,
    pub executes_edges: usize,
    pub relationships_created: usize,
    pub already_ingested: bool,
}

// ── Pool-only inner ────────────────────────────────────────────────────────

/// Inner helper: runs the executor and builds the response, but also returns
/// the executor's `inserted` vec so MCP entry points can embed those claims
/// inline. `pub(crate)` so sibling MCP tool modules (e.g. `workflows::store_workflow`)
/// can drive the same embed loop without duplicating the executor wiring.
pub(crate) async fn execute_workflow_ingest_with_inserted(
    pool: &sqlx::PgPool,
    extraction: &WorkflowExtraction,
) -> Result<(IngestWorkflowResponse, Vec<(uuid::Uuid, String)>), McpError> {
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(extraction);
    let result = epigraph_ingest_executor::execute_workflow_ingest_plan(pool, &plan, extraction)
        .await
        .map_err(|e| internal_error(format!("workflow ingest: {e}")))?;

    // Auto-wire DS factors for newly-inserted epistemic edges. The executor
    // returns the edges so the caller can fire this without pulling
    // `epigraph-engine` into the executor's dep graph (matches the embedding
    // pattern documented in CLAUDE.md "Embedding policy").
    if let Some(agent_id) = result.system_agent_id {
        for e in &result.inserted_edges {
            ds_auto::auto_wire_edge_if_epistemic(
                pool,
                true, // executor only emits an InsertedPlanEdge when was_created=true
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
    }

    let inserted = result.inserted.clone();
    let response = IngestWorkflowResponse {
        workflow_id: result.workflow_id.to_string(),
        canonical_name: result.canonical_name,
        generation: result.generation,
        claims_ingested: result.claims_ingested,
        claims_skipped_dedup: result.claims_skipped_dedup,
        executes_edges: result.executes_edges_created,
        relationships_created: result.relationship_edges_created,
        already_ingested: result.already_ingested,
    };
    Ok((response, inserted))
}

/// Pool-only ingest logic. Callable from both the MCP entry point (which
/// supplies `server.pool`) and from integration tests (which supply a
/// `sqlx::test`-managed pool directly).
///
/// Thin wrapper over [`epigraph_ingest_executor::execute_workflow_ingest_plan`];
/// see that function for the canonical persistence semantics. Does NOT embed
/// — embedding happens in the MCP entry point [`do_ingest_workflow`], which
/// has access to `server.embedder`.
pub async fn do_ingest_workflow_via_pool(
    pool: &sqlx::PgPool,
    extraction: &WorkflowExtraction,
) -> Result<IngestWorkflowResponse, McpError> {
    let (response, _inserted) = execute_workflow_ingest_with_inserted(pool, extraction).await?;
    Ok(response)
}

// ── MCP entry point ────────────────────────────────────────────────────────

/// MCP tool: ingest a `WorkflowExtraction` JSON.
pub async fn do_ingest_workflow(
    server: &EpiGraphMcpFull,
    extraction: &WorkflowExtraction,
) -> Result<CallToolResult, McpError> {
    let (response, inserted) =
        execute_workflow_ingest_with_inserted(&server.pool, extraction).await?;

    // Embed inline, best-effort. Satisfies the is_current=true → has-embedding
    // invariant (CLAUDE.md "Embedding policy"). Failures warn and continue —
    // embedding is recoverable via backfill; the workflow ingest is not.
    // `embed_and_store` logs tracing::warn on failure internally; no outer handling needed.
    for (claim_id, content) in &inserted {
        let _ = server.embedder.embed_and_store(*claim_id, content).await;
    }

    // Also embed the workflows-table goal for semantic find_workflow_hierarchical.
    // Best-effort: workflow is still findable via ILIKE fallback if this errors.
    if let Ok(wf_id) = uuid::Uuid::parse_str(&response.workflow_id) {
        match server.embedder.generate(&extraction.source.goal).await {
            Ok(qvec) => {
                if let Err(e) =
                    epigraph_db::WorkflowRepository::set_goal_embedding(&server.pool, wf_id, &qvec)
                        .await
                {
                    tracing::warn!(workflow_id=%wf_id, error=?e, "set_goal_embedding failed");
                }
            }
            Err(e) => {
                tracing::warn!(workflow_id=%wf_id, error=?e, "goal embedding generation failed");
            }
        }
    }

    success_json(&response)
}

/// Param-driven MCP tool entry point. Thin wrapper over `do_ingest_workflow`.
pub async fn ingest_workflow(
    server: &EpiGraphMcpFull,
    params: IngestWorkflowParams,
) -> Result<CallToolResult, McpError> {
    do_ingest_workflow(server, &params.extraction).await
}

// ── improve_workflow_hierarchy ─────────────────────────────────────────────
//
// Creates a generation-incremented variant of an existing hierarchical
// workflow lineage. Idempotent on `(canonical_name, generation)` via the
// underlying executor's gate: a fully-formed variant at the resolved
// generation is detected and reported as `already_ingested`. Note that the
// resolved generation is always `max(generation) + 1` for the canonical
// lineage, so back-to-back calls each produce a fresh generation rather
// than no-oping the second call.
//
// We do NOT add the `'workflow'` label to the thesis claim. That label is
// reserved for FLAT workflow claims (the `store_workflow` / `improve_workflow`
// lineage). Hierarchical workflows live in the `workflows` table and use
// `kind: workflow_thesis` on the root claim, matching `do_ingest_workflow`'s
// behavior.

#[derive(Debug, serde::Serialize)]
pub struct ImproveWorkflowHierarchyResponse {
    pub parent_canonical_name: String,
    pub parent_generation: i32,
    pub new_generation: i32,
    pub workflow_id: String,
    pub claims_ingested: usize,
    pub already_ingested: bool,
}

/// Inner helper: same as [`improve_workflow_hierarchy_via_pool`] but also
/// returns the executor's `inserted` vec so MCP entry points can embed.
/// Called by `improve_workflow_hierarchy` (this module) — kept private since
/// no other module needs the inserted vec for this path.
async fn improve_workflow_hierarchy_with_inserted(
    pool: &sqlx::PgPool,
    parent_canonical_name: &str,
    mut extraction: WorkflowExtraction,
) -> Result<(ImproveWorkflowHierarchyResponse, Vec<(uuid::Uuid, String)>), McpError> {
    let parent_max =
        epigraph_db::WorkflowRepository::max_generation_by_canonical(pool, parent_canonical_name)
            .await
            .map_err(internal_error)?
            .ok_or_else(|| {
                invalid_params(format!(
                    "no workflow with canonical_name={parent_canonical_name}"
                ))
            })?;

    let new_generation = parent_max + 1;

    extraction.source.canonical_name = parent_canonical_name.to_string();
    extraction.source.generation = u32::try_from(new_generation)
        .map_err(|e| internal_error(format!("new_generation does not fit in u32: {e}")))?;
    extraction.source.parent_canonical_name = Some(parent_canonical_name.to_string());

    let (response, inserted) = execute_workflow_ingest_with_inserted(pool, &extraction).await?;

    let improve_response = ImproveWorkflowHierarchyResponse {
        parent_canonical_name: parent_canonical_name.to_string(),
        parent_generation: parent_max,
        new_generation,
        workflow_id: response.workflow_id,
        claims_ingested: response.claims_ingested,
        already_ingested: response.already_ingested,
    };
    Ok((improve_response, inserted))
}

/// Pool-only logic for `improve_workflow_hierarchy`. Resolves the max
/// generation for `parent_canonical_name`, overwrites the caller-supplied
/// extraction source fields with the resolved variant identity, then calls
/// the shared inner helper to perform the actual hierarchical ingest.
///
/// Caller-supplied values for `extraction.source.canonical_name`,
/// `extraction.source.generation`, and `extraction.source.parent_canonical_name`
/// are intentionally OVERWRITTEN so that the variant's identity is dictated
/// by the resolver, not the caller. Does NOT embed — embedding happens in
/// the MCP entry point [`improve_workflow_hierarchy`].
pub async fn improve_workflow_hierarchy_via_pool(
    pool: &sqlx::PgPool,
    parent_canonical_name: &str,
    extraction: WorkflowExtraction,
) -> Result<ImproveWorkflowHierarchyResponse, McpError> {
    let (response, _inserted) =
        improve_workflow_hierarchy_with_inserted(pool, parent_canonical_name, extraction).await?;
    Ok(response)
}

/// MCP tool entry point for `improve_workflow_hierarchy`.
pub async fn improve_workflow_hierarchy(
    server: &EpiGraphMcpFull,
    params: ImproveWorkflowHierarchyParams,
) -> Result<CallToolResult, McpError> {
    let (response, inserted) = improve_workflow_hierarchy_with_inserted(
        &server.pool,
        &params.parent_canonical_name,
        params.extraction,
    )
    .await?;

    // Embed inline, best-effort (see `do_ingest_workflow` for rationale).
    // `embed_and_store` logs tracing::warn on failure internally; no outer handling needed.
    for (claim_id, content) in &inserted {
        let _ = server.embedder.embed_and_store(*claim_id, content).await;
    }

    success_json(&response)
}

// ── Integration tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
    use uuid::Uuid;

    fn minimal_extraction() -> WorkflowExtraction {
        WorkflowExtraction {
            source: WorkflowSource {
                canonical_name: "test-workflow-ingest".to_string(),
                goal: "Run integration tests for ingest".to_string(),
                generation: 0,
                parent_canonical_name: None,
                authors: vec![],
                expected_outcome: None,
                tags: vec![],
                metadata: serde_json::json!({}),
            },
            thesis: Some("This workflow validates ingest idempotency".to_string()),
            thesis_derivation: epigraph_ingest::common::schema::ThesisDerivation::TopDown,
            phases: vec![Phase {
                title: "Phase 1".to_string(),
                summary: "Execute the first and only phase".to_string(),
                steps: vec![Step {
                    compound: "Run the integration test suite".to_string(),
                    rationale: "CI must pass".to_string(),
                    operations: vec!["cargo test".to_string(), "check exit code".to_string()],
                    generality: vec![2, 1],
                    confidence: 0.9,
                }],
            }],
            relationships: vec![],
        }
    }

    /// Smoke test: a fresh extraction ingests without error and returns
    /// `already_ingested: false` with at least one claim inserted.
    #[sqlx::test(migrations = "../../migrations")]
    async fn ingest_workflow_smoke(pool: sqlx::PgPool) {
        let extraction = minimal_extraction();
        let result = do_ingest_workflow_via_pool(&pool, &extraction)
            .await
            .expect("ingest must succeed");

        assert!(
            !result.already_ingested,
            "first ingest should not be skipped"
        );
        assert!(
            result.claims_ingested > 0,
            "expected at least one new claim"
        );
        assert!(result.executes_edges > 0, "expected executes edges");
    }

    /// Idempotency test: ingesting the same extraction twice returns
    /// `already_ingested: true` on the second call.
    #[sqlx::test(migrations = "../../migrations")]
    async fn ingest_workflow_idempotent(pool: sqlx::PgPool) {
        let mut extraction = minimal_extraction();
        // Use a unique canonical_name so this test doesn't collide with smoke.
        extraction.source.canonical_name = "test-workflow-idempotent".to_string();

        let r1 = do_ingest_workflow_via_pool(&pool, &extraction)
            .await
            .expect("first ingest");
        assert!(!r1.already_ingested);

        let r2 = do_ingest_workflow_via_pool(&pool, &extraction)
            .await
            .expect("second ingest");
        assert!(r2.already_ingested, "second ingest should be a no-op");

        // After re-ingest, edge count should be unchanged.
        let exec_edges_after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'executes'",
        )
        .bind(Uuid::parse_str(&r1.workflow_id).expect("valid uuid"))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            exec_edges_after, r1.executes_edges as i64,
            "re-ingest must not duplicate executes edges"
        );

        let claim_count_after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM claims WHERE id IN \
             (SELECT target_id FROM edges WHERE source_id = $1 AND relationship = 'executes')",
        )
        .bind(Uuid::parse_str(&r1.workflow_id).expect("valid uuid"))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            claim_count_after, r1.executes_edges as i64,
            "re-ingest must not duplicate claims"
        );
    }

    /// Cross-source convergence: same atom text in a document and a workflow → same claim id.
    #[sqlx::test(migrations = "../../migrations")]
    async fn ingest_workflow_atom_converges_with_document_atom(pool: sqlx::PgPool) {
        // Build the document's plan deterministically and manually persist its atom claim.
        let doc_extraction: epigraph_ingest::document::DocumentExtraction = serde_json::from_str(
            r#"{
                "source": {"title": "Test Paper", "source_type": "Paper", "authors": []},
                "thesis": "Doc thesis",
                "sections": [{
                    "title": "Body", "summary": "Body summary",
                    "paragraphs": [{
                        "compound": "P1",
                        "atoms": ["text-embedding-3-large produces 3072-dimensional vectors."],
                        "generality": [1], "confidence": 0.9
                    }]
                }],
                "relationships": []
            }"#,
        )
        .unwrap();

        let doc_plan = epigraph_ingest::document::build_ingest_plan(&doc_extraction);
        let atom_text = "text-embedding-3-large produces 3072-dimensional vectors.";
        let hash = blake3::hash(atom_text.as_bytes());
        let expected_atom_id = Uuid::new_v5(
            &epigraph_ingest::common::ids::ATOM_NAMESPACE,
            hash.as_bytes(),
        );

        // Manually insert the document atom (mirrors what do_ingest_document would do).
        let sys_agent_id = epigraph_ingest_executor::get_or_create_system_agent(&pool)
            .await
            .unwrap();
        let doc_atom = doc_plan.claims.iter().find(|c| c.level == 3).unwrap();
        assert_eq!(doc_atom.id, expected_atom_id);
        epigraph_db::ClaimRepository::create_with_id_if_absent(
            &pool,
            doc_atom.id,
            &doc_atom.content,
            &doc_atom.content_hash,
            sys_agent_id,
            epigraph_core::TruthValue::clamped(0.5),
            &["paper_atom".to_string()],
        )
        .await
        .unwrap();

        // Now ingest a workflow that uses the same atom text as one of its operations.
        let wf_extraction: epigraph_ingest::workflow::WorkflowExtraction = serde_json::from_str(
            r#"{
                "source": {"canonical_name": "embed-pipeline-convergence-test", "goal": "G", "generation": 0, "authors": []},
                "thesis": "Workflow thesis",
                "phases": [{
                    "title": "Embed", "summary": "Embed step",
                    "steps": [{
                        "compound": "Run embedding",
                        "operations": ["text-embedding-3-large produces 3072-dimensional vectors."],
                        "generality": [1], "confidence": 0.9
                    }]
                }]
            }"#,
        )
        .unwrap();
        let wf_result = do_ingest_workflow_via_pool(&pool, &wf_extraction)
            .await
            .unwrap();

        // Exactly one row in claims with this id (no duplicate from ingest).
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
            .bind(expected_atom_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "atom must converge to one claim node, not two");

        // The workflow has an `executes` edge to the same atom.
        let wf_id = Uuid::parse_str(&wf_result.workflow_id).expect("valid uuid");
        let wf_edge: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges \
             WHERE source_id = $1 AND target_id = $2 AND relationship = 'executes'",
        )
        .bind(wf_id)
        .bind(expected_atom_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(wf_edge, 1);
    }

    /// executes-edges test: the workflow row is linked to every planned claim.
    #[sqlx::test(migrations = "../../migrations")]
    async fn ingest_workflow_executes_edges_created(pool: sqlx::PgPool) {
        let mut extraction = minimal_extraction();
        extraction.source.canonical_name = "test-workflow-executes".to_string();

        let result = do_ingest_workflow_via_pool(&pool, &extraction)
            .await
            .expect("ingest must succeed");

        // Count executes edges in DB.
        let wf_id = Uuid::parse_str(&result.workflow_id).expect("valid uuid");
        let db_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM edges \
             WHERE source_id = $1 AND source_type = 'workflow' AND relationship = 'executes'",
        )
        .bind(wf_id)
        .fetch_one(&pool)
        .await
        .expect("count query");

        assert_eq!(
            db_count, result.executes_edges as i64,
            "DB edge count must match reported executes_edges"
        );
        assert!(db_count > 0, "must have at least one executes edge");
    }

    /// Regression test for k1-trace-bug: `improve_workflow_hierarchy` must not
    /// produce a `claims_content_not_empty` constraint violation when a Phase
    /// has an empty (or omitted) `summary`.
    ///
    /// `Phase.summary` is `#[serde(default)]` so it defaults to `""` when
    /// absent from JSON. Before the fix, `build_ingest_plan` used
    /// `phase.summary.clone()` as the level-1 claim content without guarding
    /// against an empty value, causing PostgreSQL to reject the INSERT with
    /// `ERROR: new row violates check constraint "claims_content_not_empty"`.
    ///
    /// The fix falls back to `phase.title` in `builder.rs` when summary is blank.
    /// This test validates the full end-to-end path through
    /// `improve_workflow_hierarchy_via_pool`.
    #[sqlx::test(migrations = "../../migrations")]
    async fn improve_workflow_hierarchy_empty_phase_summary_succeeds(pool: sqlx::PgPool) {
        // 1. Seed the base workflow (generation 0).
        let mut base = minimal_extraction();
        base.source.canonical_name = "weekly-capability-audit".to_string();
        do_ingest_workflow_via_pool(&pool, &base)
            .await
            .expect("base workflow ingest must succeed");

        // 2. Build an improved extraction where summary is explicitly empty —
        //    this is the triggering condition from the bug report.
        let improved = WorkflowExtraction {
            source: epigraph_ingest::workflow::schema::WorkflowSource {
                canonical_name: "will-be-overwritten".to_string(),
                goal: "Improved audit capabilities".to_string(),
                generation: 99, // overwritten by improve_workflow_hierarchy_via_pool
                parent_canonical_name: None, // overwritten
                authors: vec![],
                expected_outcome: None,
                tags: vec![],
                metadata: serde_json::json!({}),
            },
            thesis: Some("Improved thesis".to_string()),
            thesis_derivation: epigraph_ingest::common::schema::ThesisDerivation::TopDown,
            phases: vec![Phase {
                title: "Capability Review Phase".to_string(),
                summary: "".to_string(), // empty — the serde default; was the bug trigger
                steps: vec![Step {
                    compound: "Review all system capabilities".to_string(),
                    rationale: "Ensure completeness".to_string(),
                    operations: vec!["audit step".to_string()],
                    generality: vec![1],
                    confidence: 0.85,
                }],
            }],
            relationships: vec![],
        };

        // 3. Must succeed without a constraint violation.
        let result =
            improve_workflow_hierarchy_via_pool(&pool, "weekly-capability-audit", improved)
                .await
                .expect("improve must not violate claims_content_not_empty constraint");

        assert!(!result.already_ingested, "should be a fresh generation");
        assert!(
            result.claims_ingested > 0,
            "expected at least one new claim"
        );
        assert_eq!(result.parent_generation, 0);
        assert_eq!(result.new_generation, 1);

        // 4. Verify the phase claim actually has the title as content (not empty).
        let phase_content: String = sqlx::query_scalar(
            "SELECT content FROM claims \
             WHERE properties->>'kind' = 'workflow_step' \
               AND properties->>'level' = '1' \
             ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .expect("phase claim must exist");

        assert_eq!(
            phase_content, "Capability Review Phase",
            "phase claim content must fall back to title when summary is empty"
        );
    }
}
