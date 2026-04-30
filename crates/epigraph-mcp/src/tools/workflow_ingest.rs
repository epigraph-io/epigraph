//! Hierarchical workflow ingest tool.
//!
//! Thin MCP-side wrapper over
//! `epigraph_ingest_executor::workflow::ingest_workflow`. The pool-only
//! flow used to live here as `do_ingest_workflow_via_pool` and was
//! step-for-step duplicated by the HTTP handler in
//! `crates/epigraph-api/src/routes/workflows.rs`. Both surfaces now call
//! into the executor crate so they cannot drift.

use rmcp::model::*;

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;

use epigraph_ingest::workflow::WorkflowExtraction;
pub use epigraph_ingest_executor::workflow::IngestWorkflowResponse;

#[cfg(test)]
use uuid::Uuid;

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

// ── Pool-only entry: thin wrapper over the executor crate ─────────────────

/// Pool-only ingest. Delegates to
/// `epigraph_ingest_executor::workflow::ingest_workflow` and maps its
/// neutral `IngestError` to the MCP-side `McpError`. Kept under this name
/// so the MCP test harness, the migrate-flat-workflows binary, and any
/// out-of-tree callers don't need to update imports.
pub async fn do_ingest_workflow_via_pool(
    pool: &sqlx::PgPool,
    extraction: &WorkflowExtraction,
) -> Result<IngestWorkflowResponse, McpError> {
    epigraph_ingest_executor::workflow::ingest_workflow(pool, extraction)
        .await
        .map_err(internal_error)
}

// ── MCP entry point ────────────────────────────────────────────────────────

/// MCP tool: ingest a `WorkflowExtraction` JSON.
pub async fn do_ingest_workflow(
    server: &EpiGraphMcpFull,
    extraction: &WorkflowExtraction,
) -> Result<CallToolResult, McpError> {
    let response = do_ingest_workflow_via_pool(&server.pool, extraction).await?;
    success_json(&response)
}

// ── Integration tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};

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

    /// Smoke test: a fresh extraction ingests without error and returns
    /// `already_ingested: false` with at least one claim inserted.
    #[tokio::test]
    async fn ingest_workflow_smoke() {
        let pool = test_pool_or_skip!();
        let extraction = minimal_extraction();
        let result = do_ingest_workflow_via_pool(&pool, &extraction)
            .await
            .expect("ingest must succeed");

        assert!(!result.already_ingested, "first ingest should not be skipped");
        assert!(result.claims_ingested > 0, "expected at least one new claim");
        assert!(result.executes_edges > 0, "expected executes edges");
    }

    /// Idempotency test: ingesting the same extraction twice returns
    /// `already_ingested: true` on the second call.
    #[tokio::test]
    async fn ingest_workflow_idempotent() {
        let pool = test_pool_or_skip!();
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
            exec_edges_after,
            r1.executes_edges as i64,
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
            claim_count_after,
            r1.executes_edges as i64,
            "re-ingest must not duplicate claims"
        );
    }

    /// Cross-source convergence: same atom text in a document and a workflow → same claim id.
    #[tokio::test]
    async fn ingest_workflow_atom_converges_with_document_atom() {
        let pool = test_pool_or_skip!();

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
        let sys_agent_id = epigraph_ingest_executor::workflow::get_or_create_system_agent(&pool)
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
    #[tokio::test]
    async fn ingest_workflow_executes_edges_created() {
        let pool = test_pool_or_skip!();
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

    /// Build a `WorkflowExtraction` whose every claim text is uniquely seeded
    /// so it cannot collide with other tests on the `(content_hash, agent_id)`
    /// uniqueness constraint when the suite is run end-to-end against a shared
    /// DB. Compound IDs are seeded by `canonical_name` and atom IDs are
    /// content-addressed; both must be distinct across tests.
    fn unique_extraction(seed: &str) -> WorkflowExtraction {
        WorkflowExtraction {
            source: WorkflowSource {
                canonical_name: format!("test-wf-{seed}"),
                goal: format!("Goal for {seed}"),
                generation: 0,
                parent_canonical_name: None,
                authors: vec![],
                expected_outcome: None,
                tags: vec![],
                metadata: serde_json::json!({}),
            },
            thesis: Some(format!("Thesis for {seed}")),
            thesis_derivation: epigraph_ingest::common::schema::ThesisDerivation::TopDown,
            phases: vec![Phase {
                title: format!("Phase {seed}"),
                summary: format!("Phase summary {seed}"),
                steps: vec![Step {
                    compound: format!("Step compound {seed}"),
                    rationale: format!("Step rationale {seed}"),
                    operations: vec![format!("op-a-{seed}"), format!("op-b-{seed}")],
                    generality: vec![2, 1],
                    confidence: 0.9,
                }],
            }],
            relationships: vec![],
        }
    }

    /// variant_of edge: ingesting a gen=1 workflow with parent_canonical_name
    /// set must write a single workflow→workflow `variant_of` edge from the new
    /// generation back to the parent.
    #[tokio::test]
    async fn ingest_workflow_writes_variant_of_edge() {
        let pool = test_pool_or_skip!();
        let canonical = "variant-of";

        // gen=0
        let mut gen0 = unique_extraction("variant-of-gen0");
        gen0.source.canonical_name = format!("test-wf-{canonical}");
        let r0 = do_ingest_workflow_via_pool(&pool, &gen0)
            .await
            .expect("gen=0 ingest");
        let gen0_id = Uuid::parse_str(&r0.workflow_id).expect("valid uuid");

        // gen=1, parent_canonical_name pointing at gen=0
        let mut gen1 = unique_extraction("variant-of-gen1");
        gen1.source.canonical_name = format!("test-wf-{canonical}");
        gen1.source.generation = 1;
        gen1.source.parent_canonical_name = Some(format!("test-wf-{canonical}"));
        let r1 = do_ingest_workflow_via_pool(&pool, &gen1)
            .await
            .expect("gen=1 ingest");
        let gen1_id = Uuid::parse_str(&r1.workflow_id).expect("valid uuid");

        assert_ne!(gen0_id, gen1_id, "different generations must have distinct ids");

        // Exactly one variant_of edge from gen1 → gen0.
        let edge_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges \
             WHERE source_id = $1 AND source_type = 'workflow' \
               AND target_id = $2 AND target_type = 'workflow' \
               AND relationship = 'variant_of'",
        )
        .bind(gen1_id)
        .bind(gen0_id)
        .fetch_one(&pool)
        .await
        .expect("variant_of count");
        assert_eq!(edge_count, 1, "expected exactly one variant_of edge gen1→gen0");

        // Re-ingest gen=1 must not duplicate the variant_of edge.
        let r1b = do_ingest_workflow_via_pool(&pool, &gen1)
            .await
            .expect("gen=1 re-ingest");
        assert!(r1b.already_ingested, "second ingest should be a no-op");
        let edge_count_after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges \
             WHERE source_id = $1 AND target_id = $2 AND relationship = 'variant_of'",
        )
        .bind(gen1_id)
        .bind(gen0_id)
        .fetch_one(&pool)
        .await
        .expect("variant_of count after");
        assert_eq!(edge_count_after, 1, "re-ingest must not duplicate variant_of");
    }

    /// gen=0 (no parent) must NOT write a variant_of edge.
    #[tokio::test]
    async fn ingest_workflow_gen0_no_variant_of_edge() {
        let pool = test_pool_or_skip!();
        let extraction = unique_extraction("no-variant-of-gen0");

        let result = do_ingest_workflow_via_pool(&pool, &extraction)
            .await
            .expect("gen=0 ingest");
        let wf_id = Uuid::parse_str(&result.workflow_id).expect("valid uuid");

        let edge_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges \
             WHERE source_id = $1 AND relationship = 'variant_of'",
        )
        .bind(wf_id)
        .fetch_one(&pool)
        .await
        .expect("variant_of count");
        assert_eq!(edge_count, 0, "gen=0 must not have a variant_of edge");
    }
}
