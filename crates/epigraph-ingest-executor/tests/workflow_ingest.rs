//! Integration tests for [`epigraph_ingest_executor::execute_workflow_ingest_plan`].
//!
//! Migrated from the duplicate-site tests in `epigraph-mcp::tools::workflow_ingest`
//! and `epigraph-api::routes::workflows`. The executor crate owns the canonical
//! contract going forward.

use sqlx::PgPool;

use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;

fn build_minimal_workflow_extraction(canonical_name: &str) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical_name.to_string(),
            goal: "Validate the executor crate ingests workflows idempotently".to_string(),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: Some("Executor must be idempotent across repeat calls".to_string()),
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Phase 1".to_string(),
            summary: "Run the executor twice and assert no duplicates".to_string(),
            steps: vec![Step {
                compound: "Invoke executor".to_string(),
                rationale: "Idempotency contract".to_string(),
                operations: vec![
                    "Call execute_workflow_ingest_plan".to_string(),
                    "Verify counters and edge counts".to_string(),
                ],
                generality: vec![2, 1],
                confidence: 0.9,
                evidence_type: None,
            }],
        }],
        relationships: vec![],
    }
}

/// Build a hierarchical (generation 1) workflow whose `parent_canonical_name`
/// points at an already-ingested parent.
fn build_workflow_with_parent(
    canonical_name: &str,
    parent_canonical_name: &str,
) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical_name.to_string(),
            goal: "Validate variant_of edge creation for hierarchical workflows".to_string(),
            generation: 1,
            parent_canonical_name: Some(parent_canonical_name.to_string()),
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: Some("Hierarchical variants get a variant_of edge to their parent".to_string()),
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Phase 1".to_string(),
            summary: "Run the executor on a hierarchical variant".to_string(),
            steps: vec![Step {
                compound: "Invoke executor with parent_canonical_name set".to_string(),
                rationale: "variant_of edge contract".to_string(),
                operations: vec![
                    "Call execute_workflow_ingest_plan".to_string(),
                    "Verify variant_of edge exists".to_string(),
                ],
                generality: vec![2, 1],
                confidence: 0.9,
                evidence_type: None,
            }],
        }],
        relationships: vec![],
    }
}

/// Re-running the executor with the same plan must short-circuit on the
/// idempotency gate: no new claims, no duplicated edges.
#[sqlx::test(migrations = "../../migrations")]
async fn execute_is_idempotent(pool: PgPool) {
    let extraction = build_minimal_workflow_extraction("executor-idempotent-test");
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);

    let r1 = epigraph_ingest_executor::execute_workflow_ingest_plan(
        &mut pool.acquire().await.expect("acquire"),
        &plan,
        &extraction,
    )
    .await
    .expect("first call");
    assert!(
        !r1.already_ingested,
        "first ingest should not short-circuit"
    );
    assert!(r1.claims_ingested > 0, "first ingest should write claims");
    assert!(
        r1.executes_edges_created > 0,
        "first ingest should write executes edges"
    );

    let r2 = epigraph_ingest_executor::execute_workflow_ingest_plan(
        &mut pool.acquire().await.expect("acquire"),
        &plan,
        &extraction,
    )
    .await
    .expect("second call");
    assert!(
        r2.already_ingested,
        "second ingest should hit the idempotency gate"
    );
    assert_eq!(r2.workflow_id, r1.workflow_id);
    assert_eq!(r2.claims_ingested, 0);
    assert_eq!(r2.claims_skipped_dedup, 0);
    assert_eq!(r2.relationship_edges_created, 0);

    // Edge count in DB must be unchanged.
    let edge_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges \
         WHERE source_id = $1 AND source_type = 'workflow' AND relationship = 'executes'",
    )
    .bind(r1.workflow_id)
    .fetch_one(&pool)
    .await
    .expect("edge count");
    assert_eq!(
        edge_count, r1.executes_edges_created as i64,
        "re-ingest must not duplicate executes edges"
    );

    // Claim count under the workflow must be unchanged.
    let claim_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM claims WHERE id IN \
         (SELECT target_id FROM edges WHERE source_id = $1 AND relationship = 'executes')",
    )
    .bind(r1.workflow_id)
    .fetch_one(&pool)
    .await
    .expect("claim count");
    assert_eq!(claim_count, r1.executes_edges_created as i64);
}

/// First-call sanity: counters reflect what was actually written.
#[sqlx::test(migrations = "../../migrations")]
async fn execute_smoke(pool: PgPool) {
    let extraction = build_minimal_workflow_extraction("executor-smoke-test");
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);

    let r = epigraph_ingest_executor::execute_workflow_ingest_plan(
        &mut pool.acquire().await.expect("acquire"),
        &plan,
        &extraction,
    )
    .await
    .expect("ingest must succeed");

    assert!(!r.already_ingested);
    assert!(
        !r.variant_of_edge_created,
        "non-hierarchical workflow (no parent_canonical_name) must not create a variant_of edge"
    );
    assert!(r.claims_ingested > 0);
    assert!(r.executes_edges_created > 0);

    // Workflow row exists.
    let workflow_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workflows WHERE id = $1)")
            .bind(r.workflow_id)
            .fetch_one(&pool)
            .await
            .expect("workflow exists query");
    assert!(workflow_exists);

    // workflow_id is deterministic from canonical_name + generation.
    let recomputed = epigraph_ingest::workflow::builder::root_workflow_id(&extraction);
    assert_eq!(r.workflow_id, recomputed);
}

/// Hierarchical workflows (those with `parent_canonical_name` set) must get a
/// `variant_of` edge from the variant's workflow row to the parent's workflow
/// row. Closes #51.
#[sqlx::test(migrations = "../../migrations")]
async fn execute_creates_variant_of_edge_for_hierarchical_workflow(pool: PgPool) {
    // Step 1: ingest a parent workflow.
    let parent_extraction = build_minimal_workflow_extraction("parent_workflow_v1");
    let parent_plan = epigraph_ingest::workflow::builder::build_ingest_plan(&parent_extraction);
    let parent = epigraph_ingest_executor::execute_workflow_ingest_plan(
        &mut pool.acquire().await.expect("acquire"),
        &parent_plan,
        &parent_extraction,
    )
    .await
    .expect("parent ingest");

    // Step 2: ingest a variant whose parent_canonical_name points at the parent.
    let variant_extraction = build_workflow_with_parent("variant_v1", "parent_workflow_v1");
    let variant_plan = epigraph_ingest::workflow::builder::build_ingest_plan(&variant_extraction);
    let result = epigraph_ingest_executor::execute_workflow_ingest_plan(
        &mut pool.acquire().await.expect("acquire"),
        &variant_plan,
        &variant_extraction,
    )
    .await
    .expect("variant ingest");

    assert!(
        result.variant_of_edge_created,
        "variant_of_edge_created should be true for hierarchical workflows"
    );

    // Step 3: confirm the edge actually lives in the DB.
    let row_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM edges
           WHERE source_id = $1
             AND target_id = $2
             AND relationship = 'variant_of'"#,
    )
    .bind(result.workflow_id)
    .bind(parent.workflow_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row_count, 1, "expected exactly one variant_of edge");

    // Step 4: re-ingest must be idempotent — still exactly one edge.
    let _result2 = epigraph_ingest_executor::execute_workflow_ingest_plan(
        &mut pool.acquire().await.expect("acquire"),
        &variant_plan,
        &variant_extraction,
    )
    .await
    .expect("variant re-ingest");

    let row_count2: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM edges
           WHERE source_id = $1
             AND target_id = $2
             AND relationship = 'variant_of'"#,
    )
    .bind(result.workflow_id)
    .bind(parent.workflow_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row_count2, 1,
        "re-ingest must not duplicate the variant_of edge"
    );
}

/// A machine-derived `properties.kind` carrying unexpanded shell syntax must
/// cost its own label and nothing else — the workflow ingest must still
/// complete.
///
/// Since backlog f6310444, `ClaimRepository::create_with_id_if_absent` refuses
/// any label containing `$`. The executor walks a whole plan on a pool with no
/// enclosing transaction, so passing `kind` through verbatim made an extraction
/// emitting `kind = "cost_$_per_unit"` abort the ENTIRE ingest at that claim
/// (`DbError::InvalidData`), leaving the claims written before it behind as a
/// partial ingest. `labels_for_planned_kind` drops the unusable label instead.
///
/// The plan is built by the real builder and then mutated, because the builder
/// hardcodes its own `kind` values — the corruption this guards against enters
/// from LLM plan output, which reaches the executor as exactly this shape.
#[sqlx::test(migrations = "../../migrations")]
async fn a_kind_with_shell_syntax_costs_its_label_not_the_whole_ingest(pool: PgPool) {
    let extraction = build_minimal_workflow_extraction("executor-dollar-kind-test");
    let mut plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);
    let planned_count = plan.claims.len();

    // Corrupt exactly one planned claim's kind, the way an extraction would.
    let victim_id = {
        let victim = plan
            .claims
            .iter_mut()
            .find(|c| c.level == 2)
            .expect("the minimal extraction has a level-2 step claim");
        victim.properties["kind"] = serde_json::json!("cost_$_per_unit");
        victim.id
    };

    let result = epigraph_ingest_executor::execute_workflow_ingest_plan(
        &mut pool.acquire().await.expect("acquire"),
        &plan,
        &extraction,
    )
    .await
    .expect("one unusable kind label must not abort the whole workflow ingest");

    assert_eq!(
        result.claims_ingested, planned_count,
        "every planned claim must still be written"
    );

    let (labels,): (Vec<String>,) = sqlx::query_as("SELECT labels FROM claims WHERE id = $1")
        .bind(victim_id)
        .fetch_one(&pool)
        .await
        .expect("the claim whose kind was corrupted must exist");
    assert_eq!(
        labels,
        vec!["claim".to_string()],
        "the unusable kind must be dropped and `claim` kept; got {labels:?}"
    );

    // And nothing anywhere in the graph acquired a `$` label from this ingest.
    let corrupt: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims, unnest(labels) l WHERE l LIKE '%$%'")
            .fetch_one(&pool)
            .await
            .expect("count corrupt labels");
    assert_eq!(corrupt, 0, "no label may carry unexpanded shell syntax");
}

// ── U032: a new generation links to its lineage predecessor ─────────────────
//
// Before U032 the executor resolved `parent_id` ONLY from
// `parent_canonical_name` (`find_root_by_canonical(parent, generation - 1)`),
// so a generation > 0 ingested without naming a parent — or naming its own
// lineage at a generation that is missing — was stored as a parentless root
// with no `variant_of` edge, even when lower generations of the same
// `canonical_name` existed. The authority layer (`ingest_anchors`) already
// treats such an ingest as a generation of THAT lineage; the linkage did not.

async fn exec(
    pool: &PgPool,
    extraction: &WorkflowExtraction,
) -> epigraph_ingest_executor::WorkflowIngestExecutionResult {
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(extraction);
    epigraph_ingest_executor::execute_workflow_ingest_plan(
        &mut pool.acquire().await.expect("acquire"),
        &plan,
        extraction,
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "ingest of {} gen {} failed: {e}",
            extraction.source.canonical_name, extraction.source.generation
        )
    })
}

/// Generation `generation` of `canonical_name`, naming no parent, with a step
/// text distinct per generation so each generation plans its own step claim.
fn generation_of(canonical_name: &str, generation: u32) -> WorkflowExtraction {
    let mut x = build_minimal_workflow_extraction(canonical_name);
    x.source.generation = generation;
    x.source.parent_canonical_name = None;
    x.phases[0].steps[0].compound = format!("Invoke executor for generation {generation}");
    x
}

async fn parent_of(pool: &PgPool, workflow_id: uuid::Uuid) -> Option<uuid::Uuid> {
    sqlx::query_scalar("SELECT parent_id FROM workflows WHERE id = $1")
        .bind(workflow_id)
        .fetch_one(pool)
        .await
        .expect("workflow row")
}

async fn variant_of_edges(pool: &PgPool, source: uuid::Uuid, target: uuid::Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges \
         WHERE source_id = $1 AND source_type = 'workflow' \
           AND target_id = $2 AND target_type = 'workflow' \
           AND relationship = 'variant_of'",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("variant_of count")
}

/// A generation > 0 that names no parent is a generation of its own lineage
/// and must link to the generation below it, with the `variant_of` edge.
#[sqlx::test(migrations = "../../migrations")]
async fn a_new_generation_without_a_parent_name_links_to_its_predecessor(pool: PgPool) {
    let r0 = exec(&pool, &generation_of("u032-lineage", 0)).await;
    let r1 = exec(&pool, &generation_of("u032-lineage", 1)).await;

    assert_eq!(
        parent_of(&pool, r1.workflow_id).await,
        Some(r0.workflow_id),
        "generation 1 of an existing lineage must link to generation 0, not be a parentless root"
    );
    assert!(
        r1.variant_of_edge_created,
        "a resolved parent must also get its variant_of edge"
    );
    assert_eq!(
        variant_of_edges(&pool, r1.workflow_id, r0.workflow_id).await,
        1
    );
}

/// Naming its OWN lineage as the parent at a generation that does not exist
/// (a gap) falls back to the predecessor, and the predecessor is the highest
/// generation BELOW the new one — not the lineage head, which may be above it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_gap_filling_generation_links_to_the_generation_below_not_the_head(pool: PgPool) {
    let r0 = exec(&pool, &generation_of("u032-gap", 0)).await;
    let r3 = exec(&pool, &generation_of("u032-gap", 3)).await;

    // Gen 2, naming its own lineage: gen 1 does not exist.
    let mut g2 = generation_of("u032-gap", 2);
    g2.source.parent_canonical_name = Some("u032-gap".to_string());
    let r2 = exec(&pool, &g2).await;

    assert_eq!(
        parent_of(&pool, r2.workflow_id).await,
        Some(r0.workflow_id),
        "gen 2 must link to gen 0 (the generation below it), never to the head gen 3"
    );
    assert_eq!(
        variant_of_edges(&pool, r2.workflow_id, r3.workflow_id).await,
        0
    );
    assert_eq!(
        variant_of_edges(&pool, r2.workflow_id, r0.workflow_id).await,
        1
    );
    // And gen 3, ingested parentless over the gap, linked to gen 0 too.
    assert_eq!(parent_of(&pool, r3.workflow_id).await, Some(r0.workflow_id));
}

/// Over-correction guard: a lineage may legitimately START above generation 0
/// (the `improve_workflow_hierarchy_test` fixture shape), and a fork naming a
/// DIFFERENT lineage at a missing generation links nothing (it is the caller's
/// own new lineage — `a_fork_under_a_new_name_needs_authority_over_the_linked_parent`).
#[sqlx::test(migrations = "../../migrations")]
async fn a_lineage_may_start_above_generation_zero(pool: PgPool) {
    let r1 = exec(&pool, &generation_of("u032-starts-at-one", 1)).await;
    assert_eq!(parent_of(&pool, r1.workflow_id).await, None);
    assert!(!r1.variant_of_edge_created);

    exec(&pool, &generation_of("u032-other-lineage", 0)).await;
    let mut fork = generation_of("u032-fork", 5);
    fork.source.parent_canonical_name = Some("u032-other-lineage".to_string());
    let rf = exec(&pool, &fork).await;
    assert_eq!(
        parent_of(&pool, rf.workflow_id).await,
        None,
        "a cross-lineage parent at a missing generation must not fall back to anything"
    );
}
