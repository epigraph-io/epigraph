//! Hierarchical workflow ingest tool.
//!
//! `do_ingest_workflow` walks a `WorkflowExtraction` JSON payload, persists
//! the claim hierarchy (thesis → phases → steps → operation atoms), writes
//! `workflow —executes→ claim` edges for every planned claim, resolves author
//! placeholder edges, and returns a summary. Mirrors `do_ingest_document` in
//! `ingestion.rs`.

use std::collections::HashMap;

use rmcp::model::*;
use uuid::Uuid;

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;

use epigraph_core::{AgentId, TruthValue};
use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, WorkflowRepository};
use epigraph_ingest::workflow::builder::root_workflow_id;
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

/// Pool-only ingest logic. Callable from both the MCP entry point (which
/// supplies `server.pool`) and from integration tests (which supply a
/// `sqlx::test`-managed pool directly).
pub async fn do_ingest_workflow_via_pool(
    pool: &sqlx::PgPool,
    extraction: &WorkflowExtraction,
) -> Result<IngestWorkflowResponse, McpError> {
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(extraction);

    let canonical_name = &extraction.source.canonical_name;
    let generation = extraction.source.generation as i32;
    let goal = &extraction.source.goal;

    let workflow_id = root_workflow_id(extraction);

    // ── 1. Idempotency gate: skip if workflow row already processed ──────
    if let Some(existing_id) = WorkflowRepository::find_root_by_canonical(pool, canonical_name, generation)
        .await
        .map_err(internal_error)?
    {
        // Workflow row exists — check if any executes edges have been written.
        let edge_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM edges \
             WHERE source_id = $1 AND source_type = 'workflow' AND relationship = 'executes'",
        )
        .bind(existing_id)
        .fetch_one(pool)
        .await
        .map_err(internal_error)?;

        if edge_count > 0 {
            return Ok(IngestWorkflowResponse {
                workflow_id: existing_id.to_string(),
                canonical_name: canonical_name.clone(),
                generation,
                claims_ingested: 0,
                claims_skipped_dedup: 0,
                executes_edges: edge_count as usize,
                relationships_created: 0,
                already_ingested: true,
            });
        }
    }

    // ── 2. Ensure system agent ───────────────────────────────────────────
    let system_agent_id = get_or_create_system_agent(pool).await?;
    let agent_id_typed = AgentId::from_uuid(system_agent_id);

    // ── 3. Insert workflow row (idempotent) ──────────────────────────────
    let parent_id = if let Some(ref pcn) = extraction.source.parent_canonical_name {
        WorkflowRepository::find_root_by_canonical(pool, pcn, generation.saturating_sub(1))
            .await
            .map_err(internal_error)?
    } else {
        None
    };

    WorkflowRepository::insert_root(
        pool,
        workflow_id,
        canonical_name,
        generation,
        goal,
        parent_id,
        extraction.source.metadata.clone(),
    )
    .await
    .map_err(internal_error)?;

    // ── 4. Ensure author agents ──────────────────────────────────────────
    let mut author_agent_map: HashMap<usize, Uuid> = HashMap::new();
    for (idx, author) in extraction.source.authors.iter().enumerate() {
        if author.name.is_empty() {
            continue;
        }
        let (_did, pub_key_bytes) =
            epigraph_crypto::did_key::did_key_for_author(None, &author.name);
        let agent_uuid = if let Some(existing) =
            AgentRepository::get_by_public_key(pool, &pub_key_bytes)
                .await
                .map_err(internal_error)?
        {
            existing.id.into()
        } else {
            let author_agent = epigraph_core::Agent::new(pub_key_bytes, Some(author.name.clone()));
            let created = AgentRepository::create(pool, &author_agent)
                .await
                .map_err(internal_error)?;
            created.id.into()
        };
        author_agent_map.insert(idx, agent_uuid);
    }

    // ── 5. Walk planned claims: dedup-by-id ─────────────────────────────
    let mut claims_ingested = 0_usize;
    let mut claims_skipped_dedup = 0_usize;
    let mut id_map: HashMap<Uuid, Uuid> = HashMap::new();

    for planned in &plan.claims {
        let confidence = planned.confidence.clamp(0.0, 1.0);
        let raw_truth = confidence.clamp(0.01, 0.99);
        let truth = TruthValue::clamped(raw_truth);

        // Derive labels from kind property.
        let kind = planned
            .properties
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("workflow_claim");
        let labels = vec!["claim".to_string(), kind.to_string()];

        let was_new = ClaimRepository::create_with_id_if_absent(
            pool,
            planned.id,
            &planned.content,
            &planned.content_hash,
            system_agent_id,
            truth,
            &labels,
        )
        .await
        .map_err(internal_error)?;

        if was_new {
            // Set properties via raw SQL (no set_properties method on ClaimRepository).
            sqlx::query("UPDATE claims SET properties = $1 WHERE id = $2")
                .bind(&planned.properties)
                .bind(planned.id)
                .execute(pool)
                .await
                .map_err(internal_error)?;
            claims_ingested += 1;
        } else {
            claims_skipped_dedup += 1;
        }

        id_map.insert(planned.id, planned.id);
        let _ = agent_id_typed; // suppress unused warning
    }

    // ── 6. workflow —executes→ claim edges ──────────────────────────────
    let mut executes_edges = 0_usize;
    for planned in &plan.claims {
        EdgeRepository::create_if_not_exists(
            pool,
            workflow_id,
            "workflow",
            planned.id,
            "claim",
            "executes",
            Some(serde_json::json!({"level": planned.level})),
            None,
            None,
        )
        .await
        .map_err(internal_error)?;
        executes_edges += 1;
    }

    // ── 7. Intra-claim plan edges (decomposes_to / step_follows / phase_follows / cross-refs) ──
    let mut relationships_created = 0_usize;
    for edge in &plan.edges {
        let (src, src_type) = if edge.source_type == "author_placeholder" {
            let idx = edge.properties["author_index"].as_u64().unwrap_or(0) as usize;
            let Some(&agent_uuid) = author_agent_map.get(&idx) else {
                continue;
            };
            (agent_uuid, "agent".to_string())
        } else {
            let mapped = id_map
                .get(&edge.source_id)
                .copied()
                .unwrap_or(edge.source_id);
            (mapped, edge.source_type.clone())
        };
        let tgt = id_map
            .get(&edge.target_id)
            .copied()
            .unwrap_or(edge.target_id);

        EdgeRepository::create_if_not_exists(
            pool,
            src,
            &src_type,
            tgt,
            &edge.target_type,
            &edge.relationship,
            Some(edge.properties.clone()),
            None,
            None,
        )
        .await
        .map_err(internal_error)?;
        relationships_created += 1;
    }

    Ok(IngestWorkflowResponse {
        workflow_id: workflow_id.to_string(),
        canonical_name: canonical_name.clone(),
        generation,
        claims_ingested,
        claims_skipped_dedup,
        executes_edges,
        relationships_created,
        already_ingested: false,
    })
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

// ── Internal helper ────────────────────────────────────────────────────────

async fn get_or_create_system_agent(pool: &sqlx::PgPool) -> Result<Uuid, McpError> {
    let (_did, pub_key_bytes) =
        epigraph_crypto::did_key::did_key_for_author(None, "workflow-ingest-system");
    if let Some(existing) = AgentRepository::get_by_public_key(pool, &pub_key_bytes)
        .await
        .map_err(internal_error)?
    {
        Ok(existing.id.into())
    } else {
        let agent = epigraph_core::Agent::new(
            pub_key_bytes,
            Some("workflow-ingest-system".to_string()),
        );
        let created = AgentRepository::create(pool, &agent)
            .await
            .map_err(internal_error)?;
        Ok(created.id.into())
    }
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
        let sys_agent_id = get_or_create_system_agent(&pool).await.unwrap();
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
}
