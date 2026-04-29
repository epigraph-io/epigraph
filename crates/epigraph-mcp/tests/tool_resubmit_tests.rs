//! Tier-2 integration tests for the trickiest two MCP tools post-S3a.

#[macro_use]
mod common;

use common::*;
use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_mcp::types::SubmitClaimParams;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

async fn build_test_server(pool: PgPool, signer_seed: [u8; 32]) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&signer_seed).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None); // mock — no API key
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

async fn server_agent_uuid(pool: &PgPool, signer_seed: [u8; 32]) -> Uuid {
    let signer = AgentSigner::from_bytes(&signer_seed).expect("signer");
    let pub_key = signer.public_key();
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM agents WHERE public_key = $1")
        .bind(pub_key.as_slice())
        .fetch_one(pool)
        .await
        .expect("server agent must exist (set by submit_claim's agent_id())")
}

#[tokio::test]
async fn submit_claim_resubmit_creates_evidence_trace_via_edges() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;

    let signer_seed = [0x42u8; 32];
    let server = build_test_server(pool.clone(), signer_seed).await;

    let content = format!("submit-claim test {}", Uuid::new_v4());
    let params1 = SubmitClaimParams {
        content: content.clone(),
        evidence_data: "evidence-1".to_string(),
        evidence_type: "empirical".to_string(),
        methodology: "bayesian".to_string(),
        confidence: 0.8,
        source_url: None,
        reasoning: None,
    };
    let params2 = SubmitClaimParams {
        content: content.clone(),
        evidence_data: "evidence-2-different-text".to_string(),
        evidence_type: "empirical".to_string(),
        methodology: "bayesian".to_string(),
        confidence: 0.9,
        source_url: None,
        reasoning: None,
    };

    tools::claims::submit_claim(&server, params1)
        .await
        .expect("first submit_claim");
    tools::claims::submit_claim(&server, params2)
        .await
        .expect("second submit_claim");

    let agent_id = server_agent_uuid(&pool, signer_seed).await;
    let content_hash = ContentHasher::hash(content.as_bytes());

    // Exactly one canonical claims row for this (content_hash, agent_id)
    let claim_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(content_hash.as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claim_count.0, 1, "exactly one canonical claims row");

    let canonical: (Uuid, Option<Uuid>, f64) = sqlx::query_as(
        "SELECT id, trace_id, truth_value FROM claims
         WHERE content_hash = $1 AND agent_id = $2",
    )
    .bind(content_hash.as_slice())
    .bind(agent_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let (claim_id, canonical_trace_id, canonical_truth) = canonical;

    // Two evidence rows (one per call)
    let evidence_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM evidence WHERE claim_id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(evidence_count.0, 2, "two evidence rows");

    // Two reasoning_traces rows (one per call)
    let trace_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM reasoning_traces WHERE claim_id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(trace_count.0, 2, "two reasoning_traces rows");

    // Canonical claim's trace_id is the FIRST trace (immutable post-creation)
    let first_trace_id: (Uuid,) = sqlx::query_as(
        "SELECT id FROM reasoning_traces WHERE claim_id = $1 ORDER BY created_at ASC LIMIT 1",
    )
    .bind(claim_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        canonical_trace_id,
        Some(first_trace_id.0),
        "canonical trace_id unchanged"
    );

    // Two HAS_TRACE + two DERIVED_FROM edges (hoisted on every submission).
    // was_created marker partitions them 1+1: first-create + resubmit.
    let has_trace_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND relationship = 'HAS_TRACE'",
    )
    .bind(claim_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(has_trace_count.0, 2, "two HAS_TRACE edges");

    let has_trace_first: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND relationship = 'HAS_TRACE'
         AND properties->>'was_created' = 'true'",
    )
    .bind(claim_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(has_trace_first.0, 1, "one HAS_TRACE with was_created=true");

    let derived_from_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND relationship = 'DERIVED_FROM'",
    )
    .bind(claim_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(derived_from_count.0, 2, "two DERIVED_FROM edges");

    // Two AUTHORED edges (helper emits one per submission)
    let authored_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'AUTHORED'",
    )
    .bind(agent_id)
    .bind(claim_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(authored_count.0, 2, "two AUTHORED edges (per spec helper)");

    // Sanity: response.truth_value reading is asserted indirectly — if the
    // migration writes the wrong truth_value back to claims, canonical_truth
    // would diverge between calls. Just check it's finite and in range.
    assert!(canonical_truth.is_finite() && (0.0..=1.0).contains(&canonical_truth));
}

// ────────────────────────────────────────────────────────────────────────────
// Shared Option-A skip assertion — used by memorize / store_workflow /
// improve_workflow tests in this file. After two identical submissions of the
// same content, expect: one canonical claim row, one Evidence row, one
// reasoning_traces row, zero DERIVED_FROM/HAS_TRACE edges, two AUTHORED edges.
// ────────────────────────────────────────────────────────────────────────────

async fn assert_option_a_skip(pool: &PgPool, agent_id: Uuid, content_hash: &[u8]) {
    let claim_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(content_hash)
            .bind(agent_id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        claim_count.0, 1,
        "Option A: exactly one canonical claim row"
    );

    let claim_id: (Uuid,) =
        sqlx::query_as("SELECT id FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(content_hash)
            .bind(agent_id)
            .fetch_one(pool)
            .await
            .unwrap();
    let claim_id = claim_id.0;

    let evidence_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM evidence WHERE claim_id = $1")
            .bind(claim_id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        evidence_count.0, 1,
        "Option A: only the first-create's Evidence row"
    );

    let trace_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM reasoning_traces WHERE claim_id = $1")
            .bind(claim_id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        trace_count.0, 1,
        "Option A: only the first-create's reasoning_traces row"
    );

    let derived_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND relationship = 'DERIVED_FROM'",
    )
    .bind(claim_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        derived_count.0, 0,
        "Option A: no DERIVED_FROM edge on resubmit"
    );

    let has_trace_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND relationship = 'HAS_TRACE'",
    )
    .bind(claim_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        has_trace_count.0, 0,
        "Option A: no HAS_TRACE edge on resubmit"
    );

    let authored_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'AUTHORED'",
    )
    .bind(agent_id)
    .bind(claim_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        authored_count.0, 2,
        "Option A: two AUTHORED edges (one per submission)"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// memorize_resubmit_option_a_skip
// ────────────────────────────────────────────────────────────────────────────

use epigraph_mcp::types::MemorizeParams;

#[tokio::test]
async fn memorize_resubmit_option_a_skip() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;

    let signer_seed = [0x33u8; 32];
    let server = build_test_server(pool.clone(), signer_seed).await;

    let content = format!("memorize test {}", Uuid::new_v4());
    let make_params = || MemorizeParams {
        content: content.clone(),
        confidence: Some(0.7),
        tags: Some(vec!["s3a-test".to_string()]),
    };

    tools::memory::memorize(&server, make_params())
        .await
        .expect("first memorize");
    tools::memory::memorize(&server, make_params())
        .await
        .expect("second memorize");

    let agent_id = server_agent_uuid(&pool, signer_seed).await;
    let content_hash = ContentHasher::hash(content.as_bytes());

    assert_option_a_skip(&pool, agent_id, content_hash.as_slice()).await;
}

// ────────────────────────────────────────────────────────────────────────────
// store_workflow_resubmit_option_a_skip
// ────────────────────────────────────────────────────────────────────────────

use epigraph_mcp::types::StoreWorkflowParams;

#[tokio::test]
async fn store_workflow_resubmit_option_a_skip() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;

    let signer_seed = [0x44u8; 32];
    let server = build_test_server(pool.clone(), signer_seed).await;

    let goal = format!("test workflow goal {}", Uuid::new_v4());
    let make_params = || StoreWorkflowParams {
        goal: goal.clone(),
        steps: vec!["step1".to_string(), "step2".to_string()],
        prerequisites: Some(vec!["prereq1".to_string()]),
        expected_outcome: Some("outcome".to_string()),
        confidence: Some(0.5),
        tags: Some(vec!["s3a-test".to_string()]),
    };

    tools::workflows::store_workflow(&server, make_params())
        .await
        .expect("first store_workflow");
    tools::workflows::store_workflow(&server, make_params())
        .await
        .expect("second store_workflow");

    // Recompute the same canonical content_hash as the migrated tool.
    let agent_id = server_agent_uuid(&pool, signer_seed).await;
    let canonical_content = serde_json::json!({
        "goal": goal,
        "steps": vec!["step1", "step2"],
        "prerequisites": vec!["prereq1"],
        "expected_outcome": "outcome",
        "tags": vec!["s3a-test"],
        "type": "workflow",
        "generation": 0,
        "use_count": 0,
        "success_count": 0,
        "failure_count": 0,
        "avg_variance": 1.0,
    });
    let content_str = serde_json::to_string(&canonical_content).unwrap();
    let content_hash = ContentHasher::hash(content_str.as_bytes());

    assert_option_a_skip(&pool, agent_id, content_hash.as_slice()).await;
}

// ────────────────────────────────────────────────────────────────────────────
// improve_workflow_resubmit_option_a_skip
// ────────────────────────────────────────────────────────────────────────────

use epigraph_mcp::types::ImproveWorkflowParams;

#[tokio::test]
async fn improve_workflow_resubmit_option_a_skip() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;

    let signer_seed = [0x55u8; 32];
    let server = build_test_server(pool.clone(), signer_seed).await;

    // 1. Seed a parent workflow via store_workflow.
    let parent_goal = format!("parent goal {}", Uuid::new_v4());
    let parent_params = StoreWorkflowParams {
        goal: parent_goal.clone(),
        steps: vec!["s1".to_string()],
        prerequisites: None,
        expected_outcome: None,
        confidence: Some(0.5),
        tags: None,
    };
    tools::workflows::store_workflow(&server, parent_params)
        .await
        .expect("seed parent workflow");

    // Look up the parent's claim_id by content_hash.
    let parent_canonical = serde_json::json!({
        "goal": parent_goal,
        "steps": vec!["s1"],
        "prerequisites": Vec::<String>::new(),
        "expected_outcome": Option::<String>::None,
        "tags": Vec::<String>::new(),
        "type": "workflow",
        "generation": 0,
        "use_count": 0,
        "success_count": 0,
        "failure_count": 0,
        "avg_variance": 1.0,
    });
    let parent_content_str = serde_json::to_string(&parent_canonical).unwrap();
    let parent_hash = ContentHasher::hash(parent_content_str.as_bytes());
    let agent_id = server_agent_uuid(&pool, signer_seed).await;
    let parent_id: (Uuid,) =
        sqlx::query_as("SELECT id FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(parent_hash.as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let parent_id = parent_id.0;

    // 2. Submit the same improve_workflow request twice.
    let make_params = || ImproveWorkflowParams {
        parent_workflow_id: parent_id.to_string(),
        change_rationale: "test rationale".to_string(),
        goal: Some("improved goal".to_string()),
        steps: Some(vec!["s1-improved".to_string()]),
        prerequisites: Some(vec!["new-prereq".to_string()]),
        expected_outcome: Some("improved outcome".to_string()),
        tags: Some(vec!["s3a-test".to_string()]),
    };

    tools::workflows::improve_workflow(&server, make_params())
        .await
        .expect("first improve_workflow");
    tools::workflows::improve_workflow(&server, make_params())
        .await
        .expect("second improve_workflow");

    // 3. Recompute the variant's canonical content_hash.
    let variant_canonical = serde_json::json!({
        "goal": "improved goal",
        "steps": vec!["s1-improved"],
        "prerequisites": vec!["new-prereq"],
        "expected_outcome": "improved outcome",
        "tags": vec!["s3a-test"],
        "type": "workflow",
        "generation": 1,
        "parent_id": parent_id.to_string(),
        "change_rationale": "test rationale",
        "use_count": 0,
        "success_count": 0,
        "failure_count": 0,
        "avg_variance": 1.0,
    });
    let variant_content_str = serde_json::to_string(&variant_canonical).unwrap();
    let variant_hash = ContentHasher::hash(variant_content_str.as_bytes());

    assert_option_a_skip(&pool, agent_id, variant_hash.as_slice()).await;

    // Extra invariant: exactly one variant_of edge (idempotent on resubmit).
    let variant_id: (Uuid,) =
        sqlx::query_as("SELECT id FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(variant_hash.as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    let variant_of_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'variant_of'",
    )
    .bind(variant_id.0)
    .bind(parent_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        variant_of_count.0, 1,
        "variant_of edge created exactly once (Option A + idempotent variant_of)"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// ingest_paper_resubmit_creates_per_call_evidence_no_dup_claim
// ────────────────────────────────────────────────────────────────────────────

use epigraph_mcp::types::{
    ClaimRelationship, LiteratureClaim, LiteratureExtraction, LiteratureSource,
};

fn make_extraction(stmt1: &str, stmt2: &str, version: &str) -> LiteratureExtraction {
    LiteratureExtraction {
        source: LiteratureSource {
            doi: "10.1000/test-doi".to_string(),
            title: "Test Paper".to_string(),
            // Empty: ingest_paper has a pre-existing dup-key bug on author
            // re-creation (Agent::new uses hardcoded [0u8; 32] public_key).
            // Out of scope for S3a; this test focuses on claim semantics.
            authors: vec![],
            journal: None,
        },
        claims: vec![
            LiteratureClaim {
                statement: stmt1.to_string(),
                // Per-call supporting_text: evidence_content_hash_claim_unique
                // (migration 031) requires (content_hash, claim_id) be unique,
                // so resubmit must carry distinct evidence content to exercise
                // the per-call Evidence-row branch.
                supporting_text: format!("supporting text for {stmt1} ({version})"),
                confidence: 0.8,
                methodology: Some("statistical".to_string()),
                section: Some("results".to_string()),
                page: Some(3),
                evidence_type: None,
            },
            LiteratureClaim {
                statement: stmt2.to_string(),
                supporting_text: format!("supporting text for {stmt2} ({version})"),
                confidence: 0.7,
                methodology: Some("statistical".to_string()),
                section: Some("discussion".to_string()),
                page: Some(7),
                evidence_type: None,
            },
        ],
        relationships: vec![ClaimRelationship {
            source_index: 0,
            target_index: 1,
            relationship: "supports".to_string(),
            strength: Some(0.8),
        }],
    }
}

#[tokio::test]
async fn ingest_paper_resubmit_creates_per_call_evidence_no_dup_claim() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;

    let signer_seed = [0x99u8; 32];
    let server = build_test_server(pool.clone(), signer_seed).await;

    let stmt1 = format!("ingest test claim 1 {}", Uuid::new_v4());
    let stmt2 = format!("ingest test claim 2 {}", Uuid::new_v4());
    let extraction1 = make_extraction(&stmt1, &stmt2, "v1");
    let extraction2 = make_extraction(&stmt1, &stmt2, "v2");

    tools::ingestion::do_ingest(&server, &extraction1)
        .await
        .expect("first ingest");
    tools::ingestion::do_ingest(&server, &extraction2)
        .await
        .expect("second ingest");

    let agent_id = server_agent_uuid(&pool, signer_seed).await;
    let stmt1_hash = ContentHasher::hash(stmt1.as_bytes());

    // One canonical claims row per unique statement
    let claim1_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(stmt1_hash.as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claim1_count.0, 1, "stmt1 has exactly one claims row");

    let stmt2_hash = ContentHasher::hash(stmt2.as_bytes());
    let claim2_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(stmt2_hash.as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claim2_count.0, 1, "stmt2 has exactly one claims row");

    // Get canonical UUIDs to query downstream tables
    let claim1_id: (Uuid,) =
        sqlx::query_as("SELECT id FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(stmt1_hash.as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let claim1_id = claim1_id.0;

    let claim2_id: (Uuid,) =
        sqlx::query_as("SELECT id FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(stmt2_hash.as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let claim2_id = claim2_id.0;

    // Two evidence rows per canonical claim (one per ingest run)
    let evidence_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM evidence WHERE claim_id = $1")
            .bind(claim1_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(evidence_count.0, 2, "two evidence rows for stmt1 canonical");

    // Two reasoning_traces rows per canonical claim
    let trace_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM reasoning_traces WHERE claim_id = $1")
            .bind(claim1_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        trace_count.0, 2,
        "two reasoning_traces rows for stmt1 canonical"
    );

    // Hoisted verb-edges: HAS_TRACE + DERIVED_FROM emit on every submission
    // (matches submit_claim's hoist; S3a fix #1 unified the rule across
    // MCP writers). One per call × two calls = 2 of each.
    let has_trace_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND relationship = 'HAS_TRACE'",
    )
    .bind(claim1_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        has_trace_count.0, 2,
        "two HAS_TRACE edges (hoisted on every submission)"
    );

    let derived_from_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND relationship = 'DERIVED_FROM'",
    )
    .bind(claim1_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        derived_from_count.0, 2,
        "two DERIVED_FROM edges (hoisted on every submission)"
    );

    // was_created marker on hoisted edges: one true (first-create) + one
    // false (resubmit) per type. Lets downstream queries distinguish the
    // two even after migration 109 dropped triple-uniqueness.
    let has_trace_first: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND relationship = 'HAS_TRACE'
         AND properties->>'was_created' = 'true'",
    )
    .bind(claim1_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(has_trace_first.0, 1, "one HAS_TRACE with was_created=true");

    let has_trace_resubmit: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND relationship = 'HAS_TRACE'
         AND properties->>'was_created' = 'false'",
    )
    .bind(claim1_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        has_trace_resubmit.0, 1,
        "one HAS_TRACE with was_created=false"
    );

    // DS-skip: only ONE mass_function row per canonical claim, despite two
    // ingest calls (resubmit skipped DS batch entry).
    let mf_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM mass_functions WHERE claim_id = $1")
            .bind(claim1_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        mf_count.0, 1,
        "DS auto-wire fired only on first call; resubmit skipped"
    );

    // Relationship-edge multi-emit: two SUPPORTS edges (one per run).
    // Migration 109 widened 108 by dropping triple-uniqueness for all
    // relationships, so verb-edges accumulate per submission per the
    // architecture doc's "re-occurrence = new edge" rule.
    let supports_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'SUPPORTS'",
    )
    .bind(claim1_id)
    .bind(claim2_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        supports_count.0, 2,
        "relationship edge multi-emit on resubmit (architecture rule 1)"
    );

    // AUTHORED edges: two per canonical claim (one per ingest call)
    let authored_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'AUTHORED'",
    )
    .bind(agent_id)
    .bind(claim1_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        authored_count.0, 2,
        "two AUTHORED edges per canonical claim"
    );
}
