//! Integration tests for step-level versioning end-to-end.
//!
//! Covers:
//! - evolve_step with supersedes (linear chain): old → new flips head ownership
//! - evolve_step with revises (concurrent branch): produces parallel heads
//! - find_workflow_hierarchical resolve_to_latest=false: behavior unchanged
//! - find_workflow_hierarchical resolve_to_latest=true: surfaces heads + pending_resolution
//! - evolve_step rejects bad edge_type
//! - evolve_step rejects level=0/1

#[path = "viewer_fixture.rs"]
mod fixture;

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
        .chain(std::iter::repeat(0u8).take(16))
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
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone());
    let agent = insert_seed_agent(&pool).await;
    let lineage = Uuid::new_v4();

    let v1 = seed_versioned_step(&pool, agent, lineage, "step v1 content").await;

    let params = EvolveStepParams {
        canonical_name: None,
        step_index: None,
        step_lineage_id: lineage.to_string(),
        parent_id: v1.to_string(),
        content: "step v2 content".to_string(),
        edge_type: "supersedes".to_string(),
        rationale: Some("clarified wording".to_string()),
        level: Some(2),
    };
    let _result = evolve_step(&server, &viewer, params, None)
        .await
        .expect("evolve_step");

    let heads = ClaimRepository::latest_in_lineage(&pool, &viewer, lineage)
        .await
        .unwrap();
    assert_eq!(heads.len(), 1, "supersession produces one head");
    let head_content: Vec<&str> = heads.iter().map(|h| h.content.as_str()).collect();
    assert!(head_content.contains(&"step v2 content"));
    assert!(!head_content.contains(&"step v1 content"));

    let (parent_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(v1)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        !parent_current,
        "supersedes must flip parent.is_current=false"
    );
}

/// Regression test for issue #352: evolve_step can address a step by
/// `(canonical_name, step_index)` — resolved server-side through the workflow's
/// `executes` edges — without threading `parent_id`/`step_lineage_id` from a
/// prior `find_workflow_hierarchical` lookup.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_addresses_by_canonical_name_and_index(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone());
    let agent = insert_seed_agent(&pool).await;

    let lin0 = Uuid::new_v4();
    let lin1 = Uuid::new_v4();
    let step0 = seed_versioned_step(&pool, agent, lin0, "step0 v1").await;
    let step1 = seed_versioned_step(&pool, agent, lin1, "step1 v1").await;

    // A workflow whose `executes` edges point at the two steps, in order.
    let wf = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, metadata) \
         VALUES ($1, 'name-mode-wf', 0, 'goal', '{}'::jsonb)",
    )
    .bind(wf)
    .execute(&pool)
    .await
    .unwrap();
    for (i, s) in [step0, step1].iter().enumerate() {
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, created_at) \
             VALUES (gen_random_uuid(), $1, 'workflow', $2, 'claim', 'executes', NOW() + make_interval(secs => $3::int))",
        )
        .bind(wf)
        .bind(*s)
        .bind(i as i32)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Address step index 1 purely by workflow name — no ids supplied.
    let params = EvolveStepParams {
        canonical_name: Some("name-mode-wf".to_string()),
        step_index: Some(1),
        step_lineage_id: String::new(),
        parent_id: String::new(),
        content: "step1 v2 via name".to_string(),
        edge_type: "supersedes".to_string(),
        rationale: None,
        level: Some(2),
    };
    evolve_step(&server, &viewer, params, None)
        .await
        .expect("name-mode evolve_step must resolve and succeed");

    // step1's head is now v2; step0 is untouched (proves the index selected the
    // right step).
    let heads1 = ClaimRepository::latest_in_lineage(&pool, &viewer, lin1)
        .await
        .unwrap();
    assert_eq!(heads1.len(), 1);
    assert_eq!(heads1[0].content, "step1 v2 via name");

    let heads0 = ClaimRepository::latest_in_lineage(&pool, &viewer, lin0)
        .await
        .unwrap();
    assert_eq!(heads0.len(), 1);
    assert_eq!(heads0[0].content, "step0 v1", "wrong step was addressed");
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_revises_produces_parallel_heads(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone());
    let agent = insert_seed_agent(&pool).await;
    let lineage = Uuid::new_v4();

    let v1 = seed_versioned_step(&pool, agent, lineage, "v1").await;

    // Agent A revises v1.
    evolve_step(
        &server,
        &viewer,
        EvolveStepParams {
            canonical_name: None,
            step_index: None,
            step_lineage_id: lineage.to_string(),
            parent_id: v1.to_string(),
            content: "v1 + agent A refinement".to_string(),
            edge_type: "revises".to_string(),
            rationale: None,
            level: Some(2),
        },
        None,
    )
    .await
    .expect("revises A");

    // Agent B revises v1 too.
    evolve_step(
        &server,
        &viewer,
        EvolveStepParams {
            canonical_name: None,
            step_index: None,
            step_lineage_id: lineage.to_string(),
            parent_id: v1.to_string(),
            content: "v1 + agent B refinement".to_string(),
            edge_type: "revises".to_string(),
            rationale: None,
            level: Some(2),
        },
        None,
    )
    .await
    .expect("revises B");

    let heads = ClaimRepository::latest_in_lineage(&pool, &viewer, lineage)
        .await
        .unwrap();
    // v1 (no incoming supersedes) + A's revision + B's revision = 3 heads.
    // `revises` does NOT remove head status per spec §3.1.
    assert_eq!(heads.len(), 3, "v1 + A + B all heads");
}

// ── evolve_step validation ───────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_rejects_bad_edge_type(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone());
    let agent = insert_seed_agent(&pool).await;
    let lineage = Uuid::new_v4();
    let v1 = seed_versioned_step(&pool, agent, lineage, "v1").await;

    let result = evolve_step(
        &server,
        &viewer,
        EvolveStepParams {
            canonical_name: None,
            step_index: None,
            step_lineage_id: lineage.to_string(),
            parent_id: v1.to_string(),
            content: "v2".to_string(),
            edge_type: "BOGUS".to_string(),
            rationale: None,
            level: Some(2),
        },
        None,
    )
    .await;
    assert!(result.is_err(), "BOGUS edge_type must error");
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_rejects_level_0_or_1(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone());
    let agent = insert_seed_agent(&pool).await;
    let lineage = Uuid::new_v4();
    let v1 = seed_versioned_step(&pool, agent, lineage, "v1").await;

    for bad_level in [0u32, 1, 4] {
        let result = evolve_step(
            &server,
            &viewer,
            EvolveStepParams {
                canonical_name: None,
                step_index: None,
                step_lineage_id: lineage.to_string(),
                parent_id: v1.to_string(),
                content: "v2".to_string(),
                edge_type: "supersedes".to_string(),
                rationale: None,
                level: Some(bad_level),
            },
            None,
        )
        .await;
        assert!(result.is_err(), "level={bad_level} must error");
    }
}

// ── find_workflow_hierarchical with resolve_to_latest ────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn find_workflow_hierarchical_frozen_by_default(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
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
        &viewer,
        FindWorkflowHierarchicalParams {
            query: "versioning probe".to_string(),
            limit: Some(5),
            resolve_to_latest: None,
            min_truth: None,
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
    let viewer = fixture::public_viewer(&pool).await;
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
        &viewer,
        EvolveStepParams {
            canonical_name: None,
            step_index: None,
            step_lineage_id: lineage_a.to_string(),
            parent_id: s0_v1.to_string(),
            content: "step 0 v2 (refined)".to_string(),
            edge_type: "supersedes".to_string(),
            rationale: None,
            level: Some(2),
        },
        None,
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
        &viewer,
        EvolveStepParams {
            canonical_name: None,
            step_index: None,
            step_lineage_id: lineage_b.to_string(),
            parent_id: s1_v1.to_string(),
            content: "step 1 v2 — agent A".to_string(),
            edge_type: "revises".to_string(),
            rationale: None,
            level: Some(2),
        },
        None,
    )
    .await
    .expect("revises s1 A");
    evolve_step(
        &server,
        &viewer,
        EvolveStepParams {
            canonical_name: None,
            step_index: None,
            step_lineage_id: lineage_b.to_string(),
            parent_id: s1_v1.to_string(),
            content: "step 1 v2 — agent B".to_string(),
            edge_type: "revises".to_string(),
            rationale: None,
            level: Some(2),
        },
        None,
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
        &viewer,
        FindWorkflowHierarchicalParams {
            query: "resolve_to_latest target".to_string(),
            limit: Some(5),
            resolve_to_latest: Some(true),
            min_truth: None,
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

// ── Bug 1 (claim a73dee60): canonical_name-with-hyphens divergence ──────
//
// Repro for the norcal-rfp-monitor failure on 2026-05-19: a query string
// containing spaces ("scan norcal rfps") only substring-matched gen-0's
// goal verbatim. Later generations (gen-4/5/6) had differentiated goals
// that no longer contained the gen-0 phrase, yet their canonical_name
// slug (`scan-norcal-rfps`) still represents the lineage. Before the
// hyphen-normalized concat, those rows were invisible to the tool even
// though they were the rows callers actually wanted.
//
// This test seeds the exact divergence shape (slug constant, goals
// diverge) and asserts both rows return. With the old `goal ILIKE $1 OR
// canonical_name ILIKE $1` form, only the gen-0 row would surface
// because spaces never match hyphens in either column.
#[sqlx::test(migrations = "../../migrations")]
async fn find_workflow_hierarchical_matches_canonical_name_across_diverged_goals(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone());

    let gen0 = Uuid::new_v4();
    let gen4 = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, parent_id, metadata, created_at) \
         VALUES \
           ($1, 'scan-norcal-architecture-rfps', 0, \
                'Scan NorCal architecture RFPs and send email notification', \
                NULL, '{}', NOW()), \
           ($2, 'scan-norcal-architecture-rfps', 4, \
                'Scan via direct query-string GETs over aggregators with form-fill', \
                NULL, '{}', NOW())",
    )
    .bind(gen0)
    .bind(gen4)
    .execute(&pool)
    .await
    .unwrap();

    // The query is the gen-0 goal phrase verbatim. Gen-4's goal does NOT
    // contain it. The slug (with hyphens) does NOT contain it either.
    // Only the hyphen-normalized `(replace(canonical_name,'-',' ') || ' '
    // || goal)` concat surfaces gen-4.
    let result = find_workflow_hierarchical(
        &server,
        &viewer,
        FindWorkflowHierarchicalParams {
            query: "scan norcal architecture rfps".to_string(),
            limit: Some(10),
            resolve_to_latest: None,
            min_truth: Some(0.0),
        },
    )
    .await
    .expect("find_workflow_hierarchical");

    let body = parse_body(&result);
    let workflows = body["workflows"].as_array().expect("workflows array");
    let found_ids: std::collections::HashSet<String> = workflows
        .iter()
        .filter_map(|w| w["workflow_id"].as_str().map(str::to_string))
        .collect();

    assert!(
        found_ids.contains(&gen0.to_string()),
        "gen-0 (verbatim goal match) must return; got ids {found_ids:?}"
    );
    assert!(
        found_ids.contains(&gen4.to_string()),
        "gen-4 (canonical_name slug match only) must return; got ids {found_ids:?}. \
         This regresses without hyphen normalization of canonical_name."
    );
}

// ── Bug 2 (claim a73dee60): deprecation must filter via min_truth ──────
//
// `deprecate_workflow` writes `truth_value = 0.05`. Before this fix, the
// `workflows` table had no truth_value column, so the deprecation was
// invisible to `find_workflow_hierarchical` (it only touched `claims`).
// Repro: gen-3 of the norcal monitor was deprecated 2026-05-19 16:48 UTC
// yet kept appearing.
//
// This test seeds two rows under the same canonical_name with different
// truth_values directly (we test the filter, not the cascade — the
// cascade has its own coverage in tests/deprecate_workflow_is_current_test.rs).
#[sqlx::test(migrations = "../../migrations")]
async fn find_workflow_hierarchical_filters_deprecated_via_min_truth(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone());

    let live_id = Uuid::new_v4();
    let dead_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, parent_id, metadata, created_at, truth_value) \
         VALUES \
           ($1, 'rfp-monitor-test', 4, 'live differentiated goal', NULL, '{}', NOW(), 1.0), \
           ($2, 'rfp-monitor-test', 3, 'deprecated older goal',    NULL, '{}', NOW(), 0.05)",
    )
    .bind(live_id)
    .bind(dead_id)
    .execute(&pool)
    .await
    .unwrap();

    // Default min_truth (0.3) → only the live row.
    let default_result = find_workflow_hierarchical(
        &server,
        &viewer,
        FindWorkflowHierarchicalParams {
            query: "rfp monitor test".to_string(),
            limit: Some(10),
            resolve_to_latest: None,
            min_truth: None,
        },
    )
    .await
    .expect("default min_truth");
    let body = parse_body(&default_result);
    let ids: std::collections::HashSet<String> = body["workflows"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w["workflow_id"].as_str().map(str::to_string))
        .collect();
    assert!(
        ids.contains(&live_id.to_string()),
        "live (truth=1.0) row must surface under default min_truth=0.3"
    );
    assert!(
        !ids.contains(&dead_id.to_string()),
        "deprecated (truth=0.05) row must NOT surface under default min_truth=0.3; got {ids:?}"
    );

    // min_truth=0.0 → both rows (caller opts into the cemetery).
    let all_result = find_workflow_hierarchical(
        &server,
        &viewer,
        FindWorkflowHierarchicalParams {
            query: "rfp monitor test".to_string(),
            limit: Some(10),
            resolve_to_latest: None,
            min_truth: Some(0.0),
        },
    )
    .await
    .expect("min_truth=0.0");
    let body = parse_body(&all_result);
    let ids: std::collections::HashSet<String> = body["workflows"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w["workflow_id"].as_str().map(str::to_string))
        .collect();
    assert!(
        ids.contains(&live_id.to_string()) && ids.contains(&dead_id.to_string()),
        "min_truth=0.0 must include both live and deprecated; got {ids:?}"
    );
}

// ── resolve_to_latest must surface the TRUE lineage head ────────────────
//
// Bridge 37d65fe0 / 00132b1d / 8e78eb29, backlog ed6a953e / 21574bd2: with
// resolve_to_latest=true the tool returned a max generation below the one
// `improve_workflow_hierarchy` resolves (`max_generation_by_canonical`, no
// filter), and different phrasings of one query surfaced disjoint generation
// subsets. Both searches filter on each row's OWN goal text / embedding before
// ordering, so a head whose goal diverged from the query never reaches the
// `ORDER BY generation DESC`. Seeded here: gens 0-2 share a goal phrase, the
// head (gen 3) was reworded, and the query is the old phrase.
async fn seed_generation(
    pool: &PgPool,
    canonical: &str,
    generation: i32,
    goal: &str,
    truth: f64,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, parent_id, metadata, created_at, truth_value) \
         VALUES ($1, $2, $3, $4, NULL, '{}', NOW(), $5)",
    )
    .bind(id)
    .bind(canonical)
    .bind(generation)
    .bind(goal)
    .bind(truth)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn search(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    query: &str,
    resolve_to_latest: Option<bool>,
    min_truth: Option<f64>,
) -> serde_json::Value {
    let result = find_workflow_hierarchical(
        server,
        viewer,
        FindWorkflowHierarchicalParams {
            query: query.to_string(),
            limit: Some(10),
            resolve_to_latest,
            min_truth,
        },
    )
    .await
    .expect("find_workflow_hierarchical");
    parse_body(&result)
}

#[sqlx::test(migrations = "../../migrations")]
async fn resolve_to_latest_returns_true_lineage_head(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone());
    let canonical = "design-or-improve-a-workflow";
    let old_phrase = "consider all available tools";
    let mut ids = Vec::new();
    for g in 0..3 {
        ids.push(seed_generation(&pool, canonical, g, old_phrase, 1.0).await);
    }
    let head = seed_generation(&pool, canonical, 3, "rewrite the plan from scratch", 1.0).await;
    let max = epigraph_db::WorkflowRepository::max_generation_by_canonical(&pool, canonical)
        .await
        .unwrap();
    assert_eq!(
        max,
        Some(3),
        "precondition: improve's head definition says 3"
    );

    let body = search(&server, &viewer, "available tools", Some(true), Some(0.0)).await;
    let workflows = body["workflows"].as_array().expect("workflows array");
    let head_entry = workflows
        .iter()
        .find(|w| w["workflow_id"].as_str() == Some(&head.to_string()))
        .unwrap_or_else(|| {
            panic!("resolve_to_latest=true must include the true lineage head (gen 3); got {body}")
        });
    assert_eq!(head_entry["generation"], serde_json::json!(3));
    assert_eq!(head_entry["is_lineage_head"], serde_json::json!(true));
    assert_eq!(
        workflows[0]["workflow_id"].as_str(),
        Some(head.to_string().as_str()),
        "the head leads its canonical group"
    );
    assert!(
        head_entry["resolved_steps"].is_array(),
        "the injected head gets step resolution like every other entry"
    );
    for w in workflows {
        assert_eq!(
            w["lineage_head_generation"],
            serde_json::json!(3),
            "every entry of the lineage names the head generation: {w}"
        );
        assert_eq!(w["lineage_head_deprecated"], serde_json::json!(false));
        if w["workflow_id"].as_str() != Some(&head.to_string()) {
            assert_eq!(
                w["is_lineage_head"],
                serde_json::json!(false),
                "only the head is flagged: {w}"
            );
        }
    }
    for id in &ids {
        assert!(
            workflows
                .iter()
                .any(|w| w["workflow_id"].as_str() == Some(&id.to_string())),
            "the matched generations are still returned"
        );
    }

    // Default (frozen) mode is unchanged: no head injection, no annotations.
    let body = search(&server, &viewer, "available tools", None, Some(0.0)).await;
    let workflows = body["workflows"].as_array().unwrap();
    assert_eq!(workflows.len(), 3, "default mode returns only matched rows");
    assert!(workflows.iter().all(|w| w.get("is_lineage_head").is_none()));
}

/// A deprecated head (truth 0.05, below the default min_truth 0.3) is still
/// the head `improve_workflow_hierarchy` builds on, so hiding it would make
/// the guard and improve disagree again. It is disclosed and flagged instead.
#[sqlx::test(migrations = "../../migrations")]
async fn resolve_to_latest_discloses_a_deprecated_head(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone());
    let canonical = "deprecated-head-probe";
    let live = seed_generation(&pool, canonical, 0, "send the weekly digest", 1.0).await;
    let dead = seed_generation(&pool, canonical, 1, "send the weekly digest v2", 0.05).await;

    let body = search(&server, &viewer, "weekly digest", Some(true), None).await;
    let workflows = body["workflows"].as_array().expect("workflows array");
    let dead_entry = workflows
        .iter()
        .find(|w| w["workflow_id"].as_str() == Some(&dead.to_string()))
        .unwrap_or_else(|| panic!("the deprecated head must be disclosed; got {body}"));
    assert_eq!(dead_entry["is_lineage_head"], serde_json::json!(true));
    let live_entry = workflows
        .iter()
        .find(|w| w["workflow_id"].as_str() == Some(&live.to_string()))
        .expect("live gen 0 still returned");
    assert_eq!(live_entry["is_lineage_head"], serde_json::json!(false));
    assert_eq!(live_entry["lineage_head_generation"], serde_json::json!(1));
    assert_eq!(
        live_entry["lineage_head_deprecated"],
        serde_json::json!(true),
        "the head's truth is below min_truth, and every entry says so"
    );
}

// ── A retired step head must be flagged, and name-mode must not hit it ──
//
// Bridge 00132b1d: `evolve_step(canonical_name, step_index, 'supersedes')`
// failed with the opaque "cannot supersede a non-current step" on a step that
// `find_workflow_hierarchical(resolve_to_latest=true)` had just reported as
// its head. A lineage head is defined structurally (no incoming `supersedes`
// edge) while the guard reads `claims.is_current`; a claim retired without a
// supersedes edge (deprecate_workflow's retirement, reused by a later
// generation with identical text; mark_duplicate) is both. Seeded directly in
// that shape: a sole lineage member with is_current=false and no edge.
async fn seed_retired_step_workflow(pool: &PgPool) -> (Uuid, Uuid, Uuid, Uuid) {
    let agent = insert_seed_agent(pool).await;
    let healthy = seed_versioned_step(pool, agent, Uuid::new_v4(), "healthy step").await;
    let retired = seed_versioned_step(pool, agent, Uuid::new_v4(), "retired step").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(retired)
        .execute(pool)
        .await
        .unwrap();
    // Step 2: a lineage whose NEWEST head is retired while an older head (a
    // concurrent branch, no supersedes edge between them) is current.
    let branch_lineage = Uuid::new_v4();
    let branch_current = seed_versioned_step(pool, agent, branch_lineage, "branch v1").await;
    let branch_retired = seed_versioned_step(pool, agent, branch_lineage, "branch v2").await;
    sqlx::query(
        "UPDATE claims SET is_current = false, created_at = NOW() + INTERVAL '1 minute' WHERE id = $1",
    )
    .bind(branch_retired)
    .execute(pool)
    .await
    .unwrap();

    let wf = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, metadata) \
         VALUES ($1, 'retired-step-wf', 0, 'retired step probe', '{}'::jsonb)",
    )
    .bind(wf)
    .execute(pool)
    .await
    .unwrap();
    for (i, s) in [healthy, retired, branch_current].iter().enumerate() {
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, created_at) \
             VALUES (gen_random_uuid(), $1, 'workflow', $2, 'claim', 'executes', NOW() + make_interval(secs => $3::int))",
        )
        .bind(wf)
        .bind(*s)
        .bind(i as i32)
        .execute(pool)
        .await
        .unwrap();
    }
    (healthy, retired, branch_current, branch_retired)
}

fn name_mode(idx: usize, content: &str) -> EvolveStepParams {
    EvolveStepParams {
        canonical_name: Some("retired-step-wf".to_string()),
        step_index: Some(idx),
        step_lineage_id: String::new(),
        parent_id: String::new(),
        content: content.to_string(),
        edge_type: "supersedes".to_string(),
        rationale: None,
        level: Some(2),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn retired_step_head_is_flagged_and_evolve_step_names_the_retirement(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone());
    let (healthy, retired, branch_current, branch_retired) =
        seed_retired_step_workflow(&pool).await;

    let body = search(&server, &viewer, "retired step probe", Some(true), None).await;
    let steps = body["workflows"][0]["resolved_steps"]
        .as_array()
        .unwrap_or_else(|| panic!("resolved_steps expected; got {body}"));
    assert_eq!(steps.len(), 3);
    assert_eq!(
        steps[0]["heads"][0]["id"].as_str(),
        Some(healthy.to_string().as_str())
    );
    assert_eq!(
        steps[0]["heads"][0]["is_current"],
        serde_json::json!(true),
        "a healthy head reports is_current=true, so the flag is not a constant"
    );
    assert_eq!(
        steps[1]["heads"][0]["id"].as_str(),
        Some(retired.to_string().as_str())
    );
    assert_eq!(
        steps[1]["heads"][0]["is_current"],
        serde_json::json!(false),
        "the retired head is still listed (a sole member must not vanish) but flagged: {body}"
    );

    // Name-mode on the retired step: refused with a message that names the
    // retired head and the retirement, as a caller error.
    let err = evolve_step(&server, &viewer, name_mode(1, "retired step v2"), None)
        .await
        .expect_err("a retired head cannot be superseded");
    let msg = err.message.to_string();
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{msg}");
    assert!(
        msg.contains(&retired.to_string())
            && msg.contains("is_current=false")
            && msg.contains("revive or re-ingest"),
        "the error must name the retired head and the retirement; got {msg}"
    );
    assert!(
        !msg.contains("cannot supersede a non-current step"),
        "the opaque guard message must not be what the caller sees; got {msg}"
    );

    // Same resolution for update_with_evidence's name mode.
    let params: epigraph_mcp::types::UpdateWithEvidenceParams =
        serde_json::from_value(serde_json::json!({
            "claim_id": "",
            "canonical_name": "retired-step-wf",
            "step_index": 1,
            "evidence_data": "observed",
            "evidence_type": "observation",
            "supports": true,
            "strength": 0.5
        }))
        .expect("params");
    let err = epigraph_mcp::tools::claims::update_with_evidence(&server, &viewer, params, None)
        .await
        .expect_err("evidence must not silently land on a retired head");
    let msg = err.message.to_string();
    assert_eq!(
        err.code,
        rmcp::model::ErrorCode::INVALID_PARAMS,
        "a retired step head is the caller's error: {msg}"
    );
    assert!(
        msg.contains(&retired.to_string())
            && msg.contains("is_current=false")
            && msg.contains("revive or re-ingest"),
        "update_with_evidence must name the retired head and the retirement; got {msg}"
    );
    assert!(
        !msg.contains("cannot supersede a non-current step"),
        "the opaque guard message must not be what the caller sees; got {msg}"
    );

    // A lineage whose newest head is retired but an older head is current:
    // name-mode branches from the CURRENT head and succeeds.
    evolve_step(&server, &viewer, name_mode(2, "branch v3"), None)
        .await
        .expect("name-mode must pick the current head of a lineage");
    let (branch_current_now,): (bool,) =
        sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
            .bind(branch_current)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !branch_current_now,
        "the current head was the one superseded"
    );
    let (retired_untouched,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM edges WHERE target_id = $1 AND relationship = 'supersedes'",
    )
    .bind(branch_retired)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(retired_untouched, 0, "the retired head was not the parent");

    // Control: the healthy step evolves normally.
    evolve_step(&server, &viewer, name_mode(0, "healthy step v2"), None)
        .await
        .expect("a healthy head evolves");
}

// ── find_workflow's evolved_steps must name the CURRENT head ────────────
//
// `find_workflow` discloses, per hierarchical result, the steps whose lineage
// head differs from the frozen claim (backlog 563165f2). That head must be
// chosen the way name-mode `evolve_step` / `update_with_evidence` choose it
// (the newest head with is_current=true), or the result names a claim those
// tools then refuse (bridge 00132b1d's mismatch on a second surface). A
// lineage whose only head is retired is disclosed with `is_current=false`
// rather than presented as current.
#[sqlx::test(migrations = "../../migrations")]
async fn find_workflow_evolved_steps_name_the_current_head_and_flag_retirement(pool: PgPool) {
    use epigraph_mcp::tools::workflows::__test_only::find_workflow_with_pgvec;
    use epigraph_mcp::types::FindWorkflowParams;

    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone());
    let (_healthy, _retired, branch_current, branch_retired) =
        seed_retired_step_workflow(&pool).await;
    let (wf,): (Uuid,) =
        sqlx::query_as("SELECT id FROM workflows WHERE canonical_name = 'retired-step-wf'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let agent = insert_seed_agent(&pool).await;

    // Step 3: evolved (supersedes), and the evolved claim then retired with no
    // further supersedes edge, so the lineage's only head is retired.
    let evolving = seed_versioned_step(&pool, agent, Uuid::new_v4(), "evolving step").await;
    // Step 4: a concurrent `revises` branch, both heads current.
    let revised = seed_versioned_step(&pool, agent, Uuid::new_v4(), "revised step").await;
    for (offset, s) in [(3_i32, evolving), (4, revised)] {
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, created_at) \
             VALUES (gen_random_uuid(), $1, 'workflow', $2, 'claim', 'executes', NOW() + make_interval(secs => $3::int))",
        )
        .bind(wf)
        .bind(s)
        .bind(offset)
        .execute(&pool)
        .await
        .unwrap();
    }
    let id_mode = |parent: Uuid, content: &str, edge_type: &str| EvolveStepParams {
        canonical_name: None,
        step_index: None,
        step_lineage_id: String::new(),
        parent_id: parent.to_string(),
        content: content.to_string(),
        edge_type: edge_type.to_string(),
        rationale: None,
        level: Some(2),
    };
    let evolved_body = parse_body(
        &evolve_step(
            &server,
            &viewer,
            id_mode(evolving, "evolving step v2", "supersedes"),
            None,
        )
        .await
        .expect("evolve step 3"),
    );
    let evolved_then_retired: Uuid = evolved_body["claim_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("claim_id expected; got {evolved_body}"));
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(evolved_then_retired)
        .execute(&pool)
        .await
        .unwrap();
    let revised_body = parse_body(
        &evolve_step(
            &server,
            &viewer,
            id_mode(revised, "revised step v2", "revises"),
            None,
        )
        .await
        .expect("revise step 4"),
    );
    let revision: Uuid = revised_body["claim_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("claim_id expected; got {revised_body}"));

    let result = find_workflow_with_pgvec(
        &server,
        &viewer,
        FindWorkflowParams {
            goal: "retired step probe".to_string(),
            min_truth: Some(0.0),
            limit: Some(5),
        },
        None,
    )
    .await
    .expect("find_workflow text leg");
    let body = parse_body(&result);
    let hit = body
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|r| r["workflow_id"].as_str() == Some(&wf.to_string()))
        })
        .unwrap_or_else(|| panic!("the seeded workflow must be returned; got {body}"));
    assert_eq!(hit["has_evolved_steps"], serde_json::json!(true), "{hit}");
    let evolved = hit["evolved_steps"]
        .as_array()
        .unwrap_or_else(|| panic!("evolved_steps expected; got {hit}"));
    let by_index = |i: usize| {
        evolved
            .iter()
            .find(|e| e["step_index"] == serde_json::json!(i))
            .unwrap_or_else(|| panic!("step {i} must be listed in evolved_steps; got {hit}"))
    };
    let indices: Vec<u64> = evolved
        .iter()
        .filter_map(|e| e["step_index"].as_u64())
        .collect();
    assert_eq!(
        indices,
        vec![2, 3, 4],
        "a never-evolved step is not listed, even when its sole head is retired \
         (step 1); the healthy step 0 is not listed either: {hit}"
    );

    // Step 2: the newest head is retired, an older head is current. The
    // current one is named, as evolve_step name-mode would pick it.
    let s2 = by_index(2);
    assert_eq!(
        s2["head_claim_id"].as_str(),
        Some(branch_current.to_string().as_str()),
        "the CURRENT head, not the newer retired {branch_retired}: {s2}"
    );
    assert_eq!(s2["is_current"], serde_json::json!(true), "{s2}");
    assert_eq!(s2["pending_resolution"], serde_json::json!(true), "{s2}");

    // Step 3: the only head is retired; disclosed, flagged, never presented
    // as current.
    let s3 = by_index(3);
    assert_eq!(
        s3["head_claim_id"].as_str(),
        Some(evolved_then_retired.to_string().as_str()),
        "{s3}"
    );
    assert_eq!(
        s3["is_current"],
        serde_json::json!(false),
        "a retired-only head must be flagged: {s3}"
    );
    assert_eq!(s3["pending_resolution"], serde_json::json!(false), "{s3}");

    // Step 4: concurrent current heads: the newest is named, pending.
    let s4 = by_index(4);
    assert_eq!(
        s4["head_claim_id"].as_str(),
        Some(revision.to_string().as_str()),
        "{s4}"
    );
    assert_eq!(s4["head_content"].as_str(), Some("revised step v2"));
    assert_eq!(s4["is_current"], serde_json::json!(true), "{s4}");
    assert_eq!(
        s4["pending_resolution"],
        serde_json::json!(true),
        "concurrent revises heads must be flagged pending: {s4}"
    );
}

/// With resolve_to_latest=true a lineage head below min_truth is returned
/// (flagged), so the min_truth contract an agent reads must state that
/// exception instead of promising deprecated rows are always hidden.
#[test]
fn min_truth_description_states_the_lineage_head_exception() {
    let tools = EpiGraphMcpFull::all_tools_json();
    let d = tools
        .as_array()
        .expect("all_tools_json returns an array")
        .iter()
        .find(|t| t["name"] == "find_workflow_hierarchical")
        .and_then(|t| t["inputSchema"]["properties"]["min_truth"]["description"].as_str())
        .expect("find_workflow_hierarchical.min_truth carries a description")
        .to_string();
    for needle in [
        "with resolve_to_latest=true the lineage head",
        "always returned",
        "lineage_head_deprecated",
    ] {
        assert!(
            d.contains(needle),
            "min_truth must say {needle:?}; got: {d}"
        );
    }
}
