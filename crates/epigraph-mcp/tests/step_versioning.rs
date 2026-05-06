//! Integration tests for step-level versioning end-to-end.
//!
//! Covers:
//! - evolve_step with supersedes (linear chain): old → new flips head ownership
//! - evolve_step with revises (concurrent branch): produces parallel heads
//! - find_workflow_hierarchical resolve_to_latest=false: behavior unchanged
//! - find_workflow_hierarchical resolve_to_latest=true: surfaces heads + pending_resolution
//! - evolve_step rejects bad edge_type
//! - evolve_step rejects level=0/1

use epigraph_crypto::AgentSigner;
use epigraph_db::ClaimRepository;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::tools::evolve_step::{evolve_step, EvolveStepParams};
use epigraph_mcp::tools::workflow_hierarchical::find_workflow_hierarchical;
use epigraph_mcp::types::FindWorkflowHierarchicalParams;
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

/// Build a minimal MCP server for tests. Mirrors the pattern in
/// `tool_resubmit_tests.rs` (signer from a fixed seed, mock embedder).
fn build_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0xA7u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None); // mock — no API key
    EpiGraphMcpFull::new(pool, signer, embedder, /* read_only */ false)
}

/// Insert a freestanding agent for seeded parent claims. The server will
/// lazily create its OWN agent (keyed off the signer's public key) the
/// first time `evolve_step` is invoked — this seeded agent is just a
/// foreign-key target for the bootstrap parent claim.
async fn insert_seed_agent(pool: &PgPool) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO agents (id, public_key, created_at, updated_at)
           VALUES ($1, sha256($1::text::bytea), NOW(), NOW())
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("upsert agent");
    agent_id
}

/// Seed a level=2 step claim with `step_lineage_id` set. Used as the
/// `parent_id` argument to `evolve_step`.
async fn seed_versioned_step(pool: &PgPool, agent: Uuid, lineage: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0u8, 16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, step_lineage_id) \
         VALUES ($1, $2, $3, $4, 0.5, jsonb_build_object('level', 2, 'step_lineage_id', $5::text), $5)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent)
    .bind(lineage)
    .execute(pool)
    .await
    .unwrap();
    id
}

/// Pull the JSON body out of a `CallToolResult` (text content envelope).
fn parse_body(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("result has at least one text content block");
    serde_json::from_str(&text).expect("payload is valid JSON")
}

// ── evolve_step happy paths ──────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_flips_head(pool: PgPool) {
    let server = build_server(pool.clone());
    let agent = insert_seed_agent(&pool).await;
    let lineage = Uuid::new_v4();

    let v1 = seed_versioned_step(&pool, agent, lineage, "step v1 content").await;

    let params = EvolveStepParams {
        step_lineage_id: lineage.to_string(),
        parent_id: v1.to_string(),
        content: "step v2 content".to_string(),
        edge_type: "supersedes".to_string(),
        rationale: Some("clarified wording".to_string()),
        level: Some(2),
    };
    let _result = evolve_step(&server, params).await.expect("evolve_step");

    let heads = ClaimRepository::latest_in_lineage(&pool, lineage)
        .await
        .unwrap();
    assert_eq!(heads.len(), 1, "supersession produces one head");
    let head_content: Vec<&str> = heads.iter().map(|h| h.content.as_str()).collect();
    assert!(head_content.contains(&"step v2 content"));
    assert!(!head_content.contains(&"step v1 content"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_revises_produces_parallel_heads(pool: PgPool) {
    let server = build_server(pool.clone());
    let agent = insert_seed_agent(&pool).await;
    let lineage = Uuid::new_v4();

    let v1 = seed_versioned_step(&pool, agent, lineage, "v1").await;

    // Agent A revises v1.
    evolve_step(
        &server,
        EvolveStepParams {
            step_lineage_id: lineage.to_string(),
            parent_id: v1.to_string(),
            content: "v1 + agent A refinement".to_string(),
            edge_type: "revises".to_string(),
            rationale: None,
            level: Some(2),
        },
    )
    .await
    .expect("revises A");

    // Agent B revises v1 too.
    evolve_step(
        &server,
        EvolveStepParams {
            step_lineage_id: lineage.to_string(),
            parent_id: v1.to_string(),
            content: "v1 + agent B refinement".to_string(),
            edge_type: "revises".to_string(),
            rationale: None,
            level: Some(2),
        },
    )
    .await
    .expect("revises B");

    let heads = ClaimRepository::latest_in_lineage(&pool, lineage)
        .await
        .unwrap();
    // v1 (no incoming supersedes) + A's revision + B's revision = 3 heads.
    // `revises` does NOT remove head status per spec §3.1.
    assert_eq!(heads.len(), 3, "v1 + A + B all heads");
}

// ── evolve_step validation ───────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_rejects_bad_edge_type(pool: PgPool) {
    let server = build_server(pool.clone());
    let agent = insert_seed_agent(&pool).await;
    let lineage = Uuid::new_v4();
    let v1 = seed_versioned_step(&pool, agent, lineage, "v1").await;

    let result = evolve_step(
        &server,
        EvolveStepParams {
            step_lineage_id: lineage.to_string(),
            parent_id: v1.to_string(),
            content: "v2".to_string(),
            edge_type: "BOGUS".to_string(),
            rationale: None,
            level: Some(2),
        },
    )
    .await;
    assert!(result.is_err(), "BOGUS edge_type must error");
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_rejects_level_0_or_1(pool: PgPool) {
    let server = build_server(pool.clone());
    let agent = insert_seed_agent(&pool).await;
    let lineage = Uuid::new_v4();
    let v1 = seed_versioned_step(&pool, agent, lineage, "v1").await;

    for bad_level in [0u32, 1, 4] {
        let result = evolve_step(
            &server,
            EvolveStepParams {
                step_lineage_id: lineage.to_string(),
                parent_id: v1.to_string(),
                content: "v2".to_string(),
                edge_type: "supersedes".to_string(),
                rationale: None,
                level: Some(bad_level),
            },
        )
        .await;
        assert!(result.is_err(), "level={bad_level} must error");
    }
}

// ── find_workflow_hierarchical with resolve_to_latest ────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn find_workflow_hierarchical_frozen_by_default(pool: PgPool) {
    let server = build_server(pool.clone());

    let workflow_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, parent_id, metadata, created_at) \
         VALUES ($1, $2, 0, $3, NULL, '{}', NOW())",
    )
    .bind(workflow_id)
    .bind("test_wf")
    .bind("test goal — versioning probe")
    .execute(&pool)
    .await
    .unwrap();

    let result = find_workflow_hierarchical(
        &server,
        FindWorkflowHierarchicalParams {
            query: "versioning probe".to_string(),
            limit: Some(5),
            resolve_to_latest: None,
        },
    )
    .await
    .expect("find_workflow_hierarchical");

    let body = parse_body(&result);
    let workflows = body["workflows"].as_array().expect("workflows array");
    assert!(!workflows.is_empty(), "should find the seeded workflow");
    for w in workflows {
        assert!(
            w.get("resolved_steps").is_none(),
            "frozen mode must not include resolved_steps"
        );
    }
    assert_eq!(body["resolve_to_latest"], serde_json::json!(false));
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_workflow_hierarchical_resolve_walks_lineage(pool: PgPool) {
    let server = build_server(pool.clone());
    let agent = insert_seed_agent(&pool).await;

    let workflow_id = Uuid::new_v4();
    let lineage_a = Uuid::new_v4();
    let lineage_b = Uuid::new_v4();

    // Insert workflow row.
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, parent_id, metadata, created_at) \
         VALUES ($1, $2, 0, $3, NULL, '{}', NOW())",
    )
    .bind(workflow_id)
    .bind("resolve_test")
    .bind("resolve_to_latest target")
    .execute(&pool)
    .await
    .unwrap();

    // Step 0: lineage_a, evolved via supersedes (single head).
    let s0_v1 = seed_versioned_step(&pool, agent, lineage_a, "step 0 v1").await;
    evolve_step(
        &server,
        EvolveStepParams {
            step_lineage_id: lineage_a.to_string(),
            parent_id: s0_v1.to_string(),
            content: "step 0 v2 (refined)".to_string(),
            edge_type: "supersedes".to_string(),
            rationale: None,
            level: Some(2),
        },
    )
    .await
    .expect("evolve s0");
    let (s0_v2_id,): (Uuid,) =
        sqlx::query_as("SELECT id FROM claims WHERE step_lineage_id = $1 AND content = $2")
            .bind(lineage_a)
            .bind("step 0 v2 (refined)")
            .fetch_one(&pool)
            .await
            .unwrap();

    // Step 1: lineage_b, two concurrent revises (multi-head).
    let s1_v1 = seed_versioned_step(&pool, agent, lineage_b, "step 1 v1").await;
    evolve_step(
        &server,
        EvolveStepParams {
            step_lineage_id: lineage_b.to_string(),
            parent_id: s1_v1.to_string(),
            content: "step 1 v2 — agent A".to_string(),
            edge_type: "revises".to_string(),
            rationale: None,
            level: Some(2),
        },
    )
    .await
    .expect("revises s1 A");
    evolve_step(
        &server,
        EvolveStepParams {
            step_lineage_id: lineage_b.to_string(),
            parent_id: s1_v1.to_string(),
            content: "step 1 v2 — agent B".to_string(),
            edge_type: "revises".to_string(),
            rationale: None,
            level: Some(2),
        },
    )
    .await
    .expect("revises s1 B");

    // Wire executes edges: workflow → s0_v1, workflow → s1_v1
    // (frozen references at ingest time). Order-by uses (created_at, id),
    // so we offset created_at to enforce s0 before s1.
    for (step_claim, ts_offset) in [(s0_v1, 0i32), (s1_v1, 1)] {
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, created_at) \
             VALUES (gen_random_uuid(), $1, 'workflow', $2, 'claim', 'executes', NOW() + ($3 * INTERVAL '1 millisecond'))",
        )
        .bind(workflow_id)
        .bind(step_claim)
        .bind(ts_offset)
        .execute(&pool)
        .await
        .unwrap();
    }

    let result = find_workflow_hierarchical(
        &server,
        FindWorkflowHierarchicalParams {
            query: "resolve_to_latest target".to_string(),
            limit: Some(5),
            resolve_to_latest: Some(true),
        },
    )
    .await
    .expect("find_workflow_hierarchical");

    let body = parse_body(&result);
    let workflows = body["workflows"].as_array().expect("workflows array");
    let wf = workflows
        .iter()
        .find(|w| w["workflow_id"].as_str() == Some(&workflow_id.to_string()))
        .expect("seeded workflow not in results");

    let resolved = wf["resolved_steps"]
        .as_array()
        .expect("resolved_steps array");
    assert_eq!(resolved.len(), 2, "two steps under workflow");

    // Step 0: single head (supersedes chain ended at v2).
    let s0 = &resolved[0];
    assert_eq!(
        s0["frozen_claim_id"].as_str(),
        Some(s0_v1.to_string().as_str())
    );
    assert_eq!(s0["pending_resolution"], serde_json::json!(false));
    let s0_heads = s0["heads"].as_array().unwrap();
    assert_eq!(s0_heads.len(), 1, "single supersedes head");
    assert_eq!(
        s0_heads[0]["id"].as_str(),
        Some(s0_v2_id.to_string().as_str())
    );

    // Step 1: three heads (v1 + revises A + revises B). pending_resolution = true.
    let s1 = &resolved[1];
    assert_eq!(s1["pending_resolution"], serde_json::json!(true));
    let s1_heads = s1["heads"].as_array().unwrap();
    assert_eq!(
        s1_heads.len(),
        3,
        "v1 + A's revision + B's revision = 3 heads"
    );

    assert_eq!(body["resolve_to_latest"], serde_json::json!(true));
}
