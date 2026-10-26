//! Lineage Recursive CTE Query Tests
//!
//! These tests verify the claim lineage tracing functionality that uses
//! PostgreSQL recursive CTEs to traverse the epistemic provenance graph.
//!
//! # Test Coverage
//!
//! 1. Simple lineage (no ancestors, single parent, deep ancestry)
//! 2. Evidence and trace inclusion at each level
//! 3. Depth limiting with max_depth parameter
//! 4. Diamond dependency handling (multiple paths to same ancestor)
//! 5. Performance verification (1000+ nodes < 100ms)
//! 6. Cycle detection (defensive - shouldn't exist)
//! 7. Topological ordering of results
//!
//! # Evidence
//! - IMPLEMENTATION_PLAN.md specifies claim provenance tracking
//! - Recursive CTE pattern required for arbitrary depth traversal
//!
//! # Reasoning
//! - PostgreSQL WITH RECURSIVE provides efficient graph traversal
//! - Topological order ensures ancestors always precede descendants
//! - Diamond dependencies require proper deduplication

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "support/statement_log.rs"]
mod statement_log;

mod helpers;

use epigraph_core::domain::reasoning_trace::Methodology;
use epigraph_db::{
    AgentRepository, ClaimRepository, EdgeRepository, EvidenceRepository, LineageRepository,
    PgPool, ReasoningTraceRepository,
};
use helpers::{make_agent, make_claim, make_evidence, make_trace};
use std::time::Instant;
use uuid::Uuid;

// ============================================================================
// Internal helper: create a claim via repos, return its UUID
// ============================================================================

async fn create_test_claim(pool: &PgPool, content: &str, truth_value: f64) -> Uuid {
    let agent = make_agent(None);
    let agent = AgentRepository::create(pool, &agent).await.unwrap();
    let claim = make_claim(agent.id, content, truth_value);
    let claim = ClaimRepository::create(pool, &claim, epigraph_core::TenancyDecl::Inherited)
        .await
        .unwrap();
    claim.id.as_uuid()
}

async fn create_claim_edge(pool: &PgPool, parent_id: Uuid, child_id: Uuid, relationship: &str) {
    EdgeRepository::create(
        pool,
        parent_id,
        "claim",
        child_id,
        "claim",
        relationship,
        None,
        None,
        None,
    )
    .await
    .unwrap();
}

/// Create a linear chain of claims with specified depth; returns UUIDs
async fn create_claim_chain(pool: &PgPool, depth: usize) -> Vec<Uuid> {
    let mut claim_ids = Vec::with_capacity(depth);

    for i in 0..depth {
        let claim_id = create_test_claim(
            pool,
            &format!("Claim at depth {}", i),
            0.5 + (i as f64 * 0.05),
        )
        .await;

        if i > 0 {
            create_claim_edge(pool, claim_ids[i - 1], claim_id, "supports").await;
        }

        claim_ids.push(claim_id);
    }

    claim_ids
}

// ============================================================================
// Test Cases
// ============================================================================

/// Test 1: Lineage of claim with no ancestors returns only itself
///
/// **Evidence**: Single claim with no edges should return lineage of depth 0
/// **Reasoning**: Base case validation - every claim is part of its own lineage
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_no_ancestors_returns_only_itself(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // Setup: Create a single claim with no parents
    let claim_id = create_test_claim(&pool, "Standalone claim with no ancestors", 0.75).await;

    // Execute: Query lineage
    let lineage = LineageRepository::get_lineage(&pool, &viewer, claim_id, None, None)
        .await
        .expect("Failed to query lineage");

    // Verify: Only the claim itself should be in lineage
    assert_eq!(
        lineage.claims.len(),
        1,
        "Lineage should contain exactly one claim"
    );
    assert!(
        lineage.claims.contains_key(&claim_id),
        "Lineage should contain the queried claim"
    );

    let claim = lineage.claims.get(&claim_id).unwrap();
    assert_eq!(claim.depth, 0, "Claim should be at depth 0");
    assert!(
        claim.parent_ids.is_empty(),
        "Claim should have no parent IDs"
    );
    assert!(!lineage.cycle_detected, "No cycle should be detected");
    assert_eq!(lineage.max_depth_reached, 0, "Max depth should be 0");

    // Verify topological order contains only this claim
    assert_eq!(lineage.topological_order.len(), 1);
    assert_eq!(lineage.topological_order[0], claim_id);
}

/// Test 2: Lineage of claim with single parent returns both
///
/// **Evidence**: Parent -> Child edge should include parent in lineage
/// **Reasoning**: Simple two-node lineage validates basic traversal
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_single_parent_returns_both(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // Setup: Create parent and child claims
    let parent_id = create_test_claim(&pool, "Parent claim", 0.8).await;
    let child_id = create_test_claim(&pool, "Child claim derived from parent", 0.7).await;

    // Create edge: parent supports child
    create_claim_edge(&pool, parent_id, child_id, "supports").await;

    // Execute: Query lineage from child
    let lineage = LineageRepository::get_lineage(&pool, &viewer, child_id, None, None)
        .await
        .expect("Failed to query lineage");

    // Verify: Both claims should be in lineage
    assert_eq!(lineage.claims.len(), 2, "Lineage should contain two claims");
    assert!(lineage.claims.contains_key(&parent_id));
    assert!(lineage.claims.contains_key(&child_id));

    // Verify depths
    let child = lineage.claims.get(&child_id).unwrap();
    assert_eq!(child.depth, 0, "Child should be at depth 0");
    assert_eq!(
        child.parent_ids,
        vec![parent_id],
        "Child should reference parent"
    );

    let parent = lineage.claims.get(&parent_id).unwrap();
    assert_eq!(parent.depth, 1, "Parent should be at depth 1");
    assert!(parent.parent_ids.is_empty());

    // Verify topological order: parent (depth 1) before child (depth 0)
    assert_eq!(lineage.topological_order.len(), 2);
    assert_eq!(
        lineage.topological_order[0], parent_id,
        "Parent should come first in topological order"
    );
    assert_eq!(lineage.topological_order[1], child_id);
}

/// Test 3: Lineage of claim with deep ancestry (5+ levels) returns all
///
/// **Evidence**: Chain of 7 claims should all be returned in lineage
/// **Reasoning**: Validates recursive CTE traverses arbitrarily deep graphs
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_deep_ancestry_returns_all(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // Setup: Create chain of 7 claims (0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6)
    let chain = create_claim_chain(&pool, 7).await;

    // Execute: Query lineage from the leaf (last) claim
    let leaf_id = *chain.last().unwrap();
    let lineage = LineageRepository::get_lineage(&pool, &viewer, leaf_id, None, None)
        .await
        .expect("Failed to query lineage");

    // Verify: All 7 claims should be in lineage
    assert_eq!(
        lineage.claims.len(),
        7,
        "Lineage should contain all 7 claims in the chain"
    );

    for (i, &claim_id) in chain.iter().enumerate() {
        assert!(
            lineage.claims.contains_key(&claim_id),
            "Claim at position {} should be in lineage",
            i
        );

        let claim = lineage.claims.get(&claim_id).unwrap();
        // Depth increases from leaf (0) to root (6)
        let expected_depth = (chain.len() - 1 - i) as i32;
        assert_eq!(
            claim.depth, expected_depth,
            "Claim at position {} should have depth {}",
            i, expected_depth
        );
    }

    // Verify max depth
    assert_eq!(
        lineage.max_depth_reached, 6,
        "Max depth should be 6 (0 to 6 inclusive)"
    );

    // Verify topological order: root (depth 6) to leaf (depth 0)
    assert_eq!(lineage.topological_order.len(), 7);
    assert_eq!(
        lineage.topological_order[0], chain[0],
        "Root should be first in topological order"
    );
    assert_eq!(
        lineage.topological_order[6], chain[6],
        "Leaf should be last in topological order"
    );
}

/// Test 4: Lineage includes all evidence at each level
///
/// **Evidence**: Evidence attached to claims in lineage should be included
/// **Reasoning**: Full provenance requires evidence at all levels
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_includes_all_evidence_at_each_level(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // Setup: Create agent and 3 claims with evidence at each level
    let agent = make_agent(Some("Evidence Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    let root_claim = make_claim(agent.id, "Root claim with evidence", 0.9);
    let root_claim =
        ClaimRepository::create(&pool, &root_claim, epigraph_core::TenancyDecl::Inherited)
            .await
            .unwrap();
    let root_id = root_claim.id.as_uuid();

    let middle_claim = make_claim(agent.id, "Middle claim with evidence", 0.8);
    let middle_claim =
        ClaimRepository::create(&pool, &middle_claim, epigraph_core::TenancyDecl::Inherited)
            .await
            .unwrap();
    let middle_id = middle_claim.id.as_uuid();

    let leaf_claim = make_claim(agent.id, "Leaf claim with evidence", 0.7);
    let leaf_claim =
        ClaimRepository::create(&pool, &leaf_claim, epigraph_core::TenancyDecl::Inherited)
            .await
            .unwrap();
    let leaf_id = leaf_claim.id.as_uuid();

    // Create edges
    create_claim_edge(&pool, root_id, middle_id, "supports").await;
    create_claim_edge(&pool, middle_id, leaf_id, "supports").await;

    // Add evidence to each claim
    let ev_root_1 = make_evidence(agent.id, root_claim.id, "Root evidence 1");
    let ev_root_1 = EvidenceRepository::create(&pool, &ev_root_1).await.unwrap();
    let evidence_root_1: Uuid = ev_root_1.id.as_uuid();

    let ev_root_2 = make_evidence(agent.id, root_claim.id, "Root evidence 2");
    let ev_root_2 = EvidenceRepository::create(&pool, &ev_root_2).await.unwrap();
    let evidence_root_2: Uuid = ev_root_2.id.as_uuid();

    let ev_middle = make_evidence(agent.id, middle_claim.id, "Middle evidence");
    let ev_middle = EvidenceRepository::create(&pool, &ev_middle).await.unwrap();
    let evidence_middle: Uuid = ev_middle.id.as_uuid();

    let ev_leaf = make_evidence(agent.id, leaf_claim.id, "Leaf evidence");
    let ev_leaf = EvidenceRepository::create(&pool, &ev_leaf).await.unwrap();
    let evidence_leaf: Uuid = ev_leaf.id.as_uuid();

    // Execute: Query lineage from leaf
    let lineage = LineageRepository::get_lineage(&pool, &viewer, leaf_id, None, None)
        .await
        .expect("Failed to query lineage");

    // Verify: All 4 evidence items should be in lineage
    assert_eq!(
        lineage.evidence.len(),
        4,
        "Lineage should contain all 4 evidence items"
    );
    assert!(lineage.evidence.contains_key(&evidence_root_1));
    assert!(lineage.evidence.contains_key(&evidence_root_2));
    assert!(lineage.evidence.contains_key(&evidence_middle));
    assert!(lineage.evidence.contains_key(&evidence_leaf));

    // Verify evidence is correctly linked to claims
    let root = lineage.claims.get(&root_id).unwrap();
    assert_eq!(
        root.evidence_ids.len(),
        2,
        "Root should have 2 evidence items"
    );
    assert!(root.evidence_ids.contains(&evidence_root_1));
    assert!(root.evidence_ids.contains(&evidence_root_2));

    let middle = lineage.claims.get(&middle_id).unwrap();
    assert_eq!(
        middle.evidence_ids.len(),
        1,
        "Middle should have 1 evidence item"
    );
    assert!(middle.evidence_ids.contains(&evidence_middle));

    let leaf = lineage.claims.get(&leaf_id).unwrap();
    assert_eq!(
        leaf.evidence_ids.len(),
        1,
        "Leaf should have 1 evidence item"
    );
    assert!(leaf.evidence_ids.contains(&evidence_leaf));
}

/// Test 5: Lineage includes all reasoning traces
///
/// **Evidence**: Reasoning traces attached to claims should be included
/// **Reasoning**: Traces explain how claims were derived, essential for provenance
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_includes_all_reasoning_traces(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // Setup: Create agent and claims with reasoning traces
    let agent = make_agent(Some("Trace Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    let root_claim = make_claim(agent.id, "Root claim", 0.85);
    let root_claim =
        ClaimRepository::create(&pool, &root_claim, epigraph_core::TenancyDecl::Inherited)
            .await
            .unwrap();
    let root_id = root_claim.id.as_uuid();

    let child_claim = make_claim(agent.id, "Child claim", 0.75);
    let child_claim =
        ClaimRepository::create(&pool, &child_claim, epigraph_core::TenancyDecl::Inherited)
            .await
            .unwrap();
    let child_id = child_claim.id.as_uuid();

    // Create edge
    create_claim_edge(&pool, root_id, child_id, "supports").await;

    // Add traces
    let rt_root = make_trace(
        agent.id,
        Methodology::Deductive,
        0.9,
        "Deductive reasoning from first principles",
    );
    let rt_root = ReasoningTraceRepository::create(&pool, &rt_root, root_claim.id)
        .await
        .unwrap();
    ClaimRepository::update_trace_id(&pool, root_claim.id, rt_root.id)
        .await
        .unwrap();
    let trace_root: Uuid = rt_root.id.as_uuid();

    let rt_child = make_trace(
        agent.id,
        Methodology::Inductive,
        0.7,
        "Inductive reasoning from root claim",
    );
    let rt_child = ReasoningTraceRepository::create(&pool, &rt_child, child_claim.id)
        .await
        .unwrap();
    ClaimRepository::update_trace_id(&pool, child_claim.id, rt_child.id)
        .await
        .unwrap();
    let trace_child: Uuid = rt_child.id.as_uuid();

    // Link traces (child trace depends on root trace)
    ReasoningTraceRepository::add_parent(&pool, rt_child.id, rt_root.id)
        .await
        .unwrap();

    // Execute: Query lineage from child
    let lineage = LineageRepository::get_lineage(&pool, &viewer, child_id, None, None)
        .await
        .expect("Failed to query lineage");

    // Verify: Both traces should be in lineage
    assert_eq!(
        lineage.traces.len(),
        2,
        "Lineage should contain 2 reasoning traces"
    );
    assert!(lineage.traces.contains_key(&trace_root));
    assert!(lineage.traces.contains_key(&trace_child));

    // Verify trace metadata
    let root_trace = lineage.traces.get(&trace_root).unwrap();
    assert_eq!(root_trace.reasoning_type, "deductive");
    assert!((root_trace.confidence - 0.9).abs() < 0.001);
    assert!(root_trace.parent_trace_ids.is_empty());

    let child_trace = lineage.traces.get(&trace_child).unwrap();
    assert_eq!(child_trace.reasoning_type, "inductive");
    assert!((child_trace.confidence - 0.7).abs() < 0.001);
    assert_eq!(child_trace.parent_trace_ids, vec![trace_root]);

    // Verify claims reference their traces
    let root = lineage.claims.get(&root_id).unwrap();
    assert_eq!(root.trace_id, Some(trace_root));

    let child = lineage.claims.get(&child_id).unwrap();
    assert_eq!(child.trace_id, Some(trace_child));
}

/// Test 6: Lineage respects max_depth parameter
///
/// **Evidence**: Query with max_depth=2 should stop traversal at depth 2
/// **Reasoning**: Depth limiting enables efficient queries on large graphs
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_respects_max_depth_parameter(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // Setup: Create chain of 5 claims
    let chain = create_claim_chain(&pool, 5).await;

    // Execute: Query lineage with max_depth=2
    let leaf_id = *chain.last().unwrap();
    let lineage = LineageRepository::get_lineage(&pool, &viewer, leaf_id, Some(2), None)
        .await
        .expect("Failed to query lineage");

    // Verify: Only 3 claims should be returned (depth 0, 1, 2)
    assert_eq!(
        lineage.claims.len(),
        3,
        "Lineage should contain only 3 claims (depth 0, 1, 2)"
    );
    assert!(lineage.claims.contains_key(&chain[4])); // depth 0
    assert!(lineage.claims.contains_key(&chain[3])); // depth 1
    assert!(lineage.claims.contains_key(&chain[2])); // depth 2
    assert!(!lineage.claims.contains_key(&chain[1])); // depth 3 - excluded
    assert!(!lineage.claims.contains_key(&chain[0])); // depth 4 - excluded

    // Verify max depth is correct
    assert_eq!(lineage.max_depth_reached, 2);
}

/// Test 7: Lineage handles diamond dependencies (A->B, A->C, B->D, C->D)
///
/// **Evidence**: Diamond pattern should not duplicate claims
/// **Reasoning**: Real provenance graphs often have shared ancestors
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_handles_diamond_dependencies(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // Setup: Create diamond pattern
    //       A (common ancestor)
    //      / \
    //     B   C
    //      \ /
    //       D (leaf)

    let a_id = create_test_claim(&pool, "Claim A - common ancestor", 0.9).await;
    let b_id = create_test_claim(&pool, "Claim B - left branch", 0.8).await;
    let c_id = create_test_claim(&pool, "Claim C - right branch", 0.8).await;
    let d_id = create_test_claim(&pool, "Claim D - leaf with diamond parents", 0.7).await;

    // Create diamond edges
    create_claim_edge(&pool, a_id, b_id, "supports").await;
    create_claim_edge(&pool, a_id, c_id, "supports").await;
    create_claim_edge(&pool, b_id, d_id, "supports").await;
    create_claim_edge(&pool, c_id, d_id, "supports").await;

    // Execute: Query lineage from D
    let lineage = LineageRepository::get_lineage(&pool, &viewer, d_id, None, None)
        .await
        .expect("Failed to query lineage");

    // Verify: All 4 claims should be present, but A only once
    assert_eq!(
        lineage.claims.len(),
        4,
        "Lineage should contain exactly 4 claims (no duplicates)"
    );
    assert!(lineage.claims.contains_key(&a_id));
    assert!(lineage.claims.contains_key(&b_id));
    assert!(lineage.claims.contains_key(&c_id));
    assert!(lineage.claims.contains_key(&d_id));

    // Verify D has both B and C as parents
    let d = lineage.claims.get(&d_id).unwrap();
    assert_eq!(d.depth, 0);
    assert_eq!(d.parent_ids.len(), 2, "D should have 2 parents (B and C)");
    assert!(d.parent_ids.contains(&b_id));
    assert!(d.parent_ids.contains(&c_id));

    // Verify B and C both have A as parent
    let b = lineage.claims.get(&b_id).unwrap();
    assert_eq!(b.parent_ids, vec![a_id]);

    let c = lineage.claims.get(&c_id).unwrap();
    assert_eq!(c.parent_ids, vec![a_id]);

    // Verify A is at the deepest level
    let a = lineage.claims.get(&a_id).unwrap();
    assert_eq!(a.depth, 2, "A should be at depth 2");
    assert!(a.parent_ids.is_empty());

    // Verify topological order: A comes before B and C, which come before D
    let a_pos = lineage
        .topological_order
        .iter()
        .position(|&id| id == a_id)
        .unwrap();
    let b_pos = lineage
        .topological_order
        .iter()
        .position(|&id| id == b_id)
        .unwrap();
    let c_pos = lineage
        .topological_order
        .iter()
        .position(|&id| id == c_id)
        .unwrap();
    let d_pos = lineage
        .topological_order
        .iter()
        .position(|&id| id == d_id)
        .unwrap();

    assert!(a_pos < b_pos, "A should come before B");
    assert!(a_pos < c_pos, "A should come before C");
    assert!(b_pos < d_pos, "B should come before D");
    assert!(c_pos < d_pos, "C should come before D");
}

/// Test 8: Lineage query performance with 1000+ nodes (< 100ms)
///
/// **Evidence**: Large graph should be queried efficiently
/// **Reasoning**: Production graphs may have deep/wide provenance chains
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_performance_with_large_graph(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // Setup: Create a tree structure with 1000+ nodes
    // Root -> 10 children -> 10 grandchildren each -> 10 great-grandchildren each
    // Total: 1 + 10 + 100 + 1000 = 1111 nodes

    let root_id = create_test_claim(&pool, "Root of large tree", 0.9).await;

    let mut level1_ids = Vec::new();

    // Level 1: 10 children
    for i in 0..10 {
        let child_id = create_test_claim(&pool, &format!("Level 1 claim {}", i), 0.8).await;
        create_claim_edge(&pool, root_id, child_id, "supports").await;
        level1_ids.push(child_id);
    }

    // Level 2: 100 grandchildren (10 per level 1)
    let mut level2_ids = Vec::new();
    for (i, &parent) in level1_ids.iter().enumerate() {
        for j in 0..10 {
            let child_id =
                create_test_claim(&pool, &format!("Level 2 claim {}-{}", i, j), 0.7).await;
            create_claim_edge(&pool, parent, child_id, "supports").await;
            level2_ids.push(child_id);
        }
    }

    // Level 3: 1000 great-grandchildren (10 per level 2)
    let mut level3_ids = Vec::new();
    for (i, &parent) in level2_ids.iter().enumerate() {
        for j in 0..10 {
            let child_id =
                create_test_claim(&pool, &format!("Level 3 claim {}-{}", i, j), 0.6).await;
            create_claim_edge(&pool, parent, child_id, "supports").await;
            level3_ids.push(child_id);
        }
    }

    // Pick a leaf node to query from
    let leaf_id = level3_ids[500];

    // Execute: Query lineage and measure time
    let start = Instant::now();
    let lineage = LineageRepository::get_lineage(&pool, &viewer, leaf_id, None, None)
        .await
        .expect("Failed to query lineage");
    let elapsed = start.elapsed();

    // Verify: Performance should be under 100ms
    assert!(
        elapsed.as_millis() < 100,
        "Lineage query took {}ms, expected < 100ms",
        elapsed.as_millis()
    );

    // Verify: Lineage should include the path from leaf to root
    assert!(
        lineage.claims.len() >= 4,
        "Lineage should contain at least 4 claims (leaf to root path)"
    );
    assert!(lineage.claims.contains_key(&leaf_id));
    assert!(lineage.claims.contains_key(&root_id));

    // Verify max depth is correct (3 levels of edges)
    assert_eq!(lineage.max_depth_reached, 3);
}

/// Test 9: Lineage detects and reports cycles (defensive)
///
/// **Evidence**: If a cycle exists, it should be detected and reported
/// **Reasoning**: Cycles violate DAG invariant but system should handle gracefully
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_detects_and_reports_cycles(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // Setup: Create a cycle (A -> B -> C -> A)
    let a_id = create_test_claim(&pool, "Claim A in cycle", 0.7).await;
    let b_id = create_test_claim(&pool, "Claim B in cycle", 0.7).await;
    let c_id = create_test_claim(&pool, "Claim C in cycle", 0.7).await;

    // Create cycle edges (this violates DAG invariant!)
    create_claim_edge(&pool, a_id, b_id, "supports").await;
    create_claim_edge(&pool, b_id, c_id, "supports").await;
    create_claim_edge(&pool, c_id, a_id, "supports").await;

    // Execute: Detect cycles
    let has_cycle = LineageRepository::detect_cycles(&pool, &viewer, a_id)
        .await
        .expect("Failed to detect cycles");

    // Verify: Cycle should be detected
    assert!(has_cycle, "Cycle should be detected in A -> B -> C -> A");

    // Query lineage should still work (with cycle detection)
    let lineage = LineageRepository::get_lineage(&pool, &viewer, a_id, Some(10), None)
        .await
        .expect("Failed to query lineage");

    // The query should terminate and not loop forever
    assert!(
        lineage.claims.len() <= 3,
        "Lineage should not have duplicates despite cycle"
    );
}

/// Test 10: Lineage returns results in topological order
///
/// **Evidence**: Ancestors should always appear before their descendants
/// **Reasoning**: Topological order enables deterministic processing
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_returns_topological_order(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // Setup: Create complex DAG
    //     A
    //    /|\
    //   B C D
    //    \|/
    //     E
    //     |
    //     F

    let a_id = create_test_claim(&pool, "Claim A (root)", 0.9).await;
    let b_id = create_test_claim(&pool, "Claim B", 0.8).await;
    let c_id = create_test_claim(&pool, "Claim C", 0.8).await;
    let d_id = create_test_claim(&pool, "Claim D", 0.8).await;
    let e_id = create_test_claim(&pool, "Claim E", 0.7).await;
    let f_id = create_test_claim(&pool, "Claim F (leaf)", 0.6).await;

    // Create edges
    create_claim_edge(&pool, a_id, b_id, "supports").await;
    create_claim_edge(&pool, a_id, c_id, "supports").await;
    create_claim_edge(&pool, a_id, d_id, "supports").await;
    create_claim_edge(&pool, b_id, e_id, "supports").await;
    create_claim_edge(&pool, c_id, e_id, "supports").await;
    create_claim_edge(&pool, d_id, e_id, "supports").await;
    create_claim_edge(&pool, e_id, f_id, "supports").await;

    // Execute: Query lineage from F
    let lineage = LineageRepository::get_lineage(&pool, &viewer, f_id, None, None)
        .await
        .expect("Failed to query lineage");

    // Verify: All 6 claims present
    assert_eq!(lineage.claims.len(), 6);

    // Verify topological order invariant
    let order = &lineage.topological_order;
    let pos = |id: Uuid| order.iter().position(|&x| x == id).unwrap();

    // A must come before B, C, D
    assert!(pos(a_id) < pos(b_id), "A must come before B");
    assert!(pos(a_id) < pos(c_id), "A must come before C");
    assert!(pos(a_id) < pos(d_id), "A must come before D");

    // B, C, D must come before E
    assert!(pos(b_id) < pos(e_id), "B must come before E");
    assert!(pos(c_id) < pos(e_id), "C must come before E");
    assert!(pos(d_id) < pos(e_id), "D must come before E");

    // E must come before F
    assert!(pos(e_id) < pos(f_id), "E must come before F");

    // F must be last (leaf)
    assert_eq!(
        order[order.len() - 1],
        f_id,
        "F should be last in topological order"
    );

    // A must be first (root)
    assert_eq!(order[0], a_id, "A should be first in topological order");
}

/// Test: Lineage handles multiple roots (claims with no parents)
///
/// **Evidence**: Multiple independent ancestries should all be included
/// **Reasoning**: Claims can derive from multiple independent sources
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_handles_multiple_roots(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // Setup: Two independent roots both supporting one claim
    let root1_id = create_test_claim(&pool, "Independent root 1", 0.9).await;
    let root2_id = create_test_claim(&pool, "Independent root 2", 0.85).await;
    let leaf_id = create_test_claim(&pool, "Leaf with two roots", 0.8).await;

    create_claim_edge(&pool, root1_id, leaf_id, "supports").await;
    create_claim_edge(&pool, root2_id, leaf_id, "supports").await;

    // Execute
    let lineage = LineageRepository::get_lineage(&pool, &viewer, leaf_id, None, None)
        .await
        .expect("Failed to query lineage");

    // Verify
    assert_eq!(lineage.claims.len(), 3);
    assert!(lineage.claims.contains_key(&root1_id));
    assert!(lineage.claims.contains_key(&root2_id));
    assert!(lineage.claims.contains_key(&leaf_id));

    let leaf = lineage.claims.get(&leaf_id).unwrap();
    assert_eq!(leaf.parent_ids.len(), 2);
    assert!(leaf.parent_ids.contains(&root1_id));
    assert!(leaf.parent_ids.contains(&root2_id));

    // Both roots at same depth
    let root1 = lineage.claims.get(&root1_id).unwrap();
    let root2 = lineage.claims.get(&root2_id).unwrap();
    assert_eq!(
        root1.depth, root2.depth,
        "Both roots should be at same depth"
    );
}

/// Test: Lineage handles wide graphs (many siblings)
///
/// **Evidence**: Graph with many siblings at same level should work
/// **Reasoning**: Wide graphs are common in evidence aggregation
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_handles_wide_graph(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // Setup: Root with 50 children all supporting one grandchild
    let root_id = create_test_claim(&pool, "Root of wide graph", 0.9).await;

    let mut child_ids = Vec::new();
    for i in 0..50 {
        let child_id = create_test_claim(&pool, &format!("Child {}", i), 0.8).await;
        create_claim_edge(&pool, root_id, child_id, "supports").await;
        child_ids.push(child_id);
    }

    let leaf_id = create_test_claim(&pool, "Leaf with many parents", 0.7).await;
    for &child_id in &child_ids {
        create_claim_edge(&pool, child_id, leaf_id, "supports").await;
    }

    // Execute
    let lineage = LineageRepository::get_lineage(&pool, &viewer, leaf_id, None, None)
        .await
        .expect("Failed to query lineage");

    // Verify
    assert_eq!(
        lineage.claims.len(),
        52,
        "Should have root + 50 children + leaf"
    );

    let leaf = lineage.claims.get(&leaf_id).unwrap();
    assert_eq!(leaf.parent_ids.len(), 50, "Leaf should have 50 parents");
}

/// Test: Empty database returns empty lineage for non-existent claim
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_nonexistent_claim_returns_empty(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // Execute: Query lineage for a UUID that doesn't exist
    let nonexistent_id = Uuid::new_v4();
    let lineage = LineageRepository::get_lineage(&pool, &viewer, nonexistent_id, None, None)
        .await
        .expect("Failed to query lineage");

    // Verify: Empty result
    assert!(
        lineage.claims.is_empty(),
        "Lineage for non-existent claim should be empty"
    );
    assert!(lineage.evidence.is_empty());
    assert!(lineage.traces.is_empty());
    assert!(lineage.topological_order.is_empty());
    assert!(!lineage.cycle_detected);
    assert_eq!(lineage.max_depth_reached, 0);
}

/// Test: the ancestry walk follows derivation edges only, each in the
/// direction its relationship is written
///
/// **Evidence**: I104 / U042. `get_lineage_conn`'s recursive term joined
/// every incoming claim->claim edge with no relationship predicate, so
/// `get_provenance` reported a claim that DISPUTES the root, a cross-source
/// matcher corroboration and -- because `ClaimRepository::supersede` writes
/// `supersedes` new->old -- the NEWER claim that replaced the root as
/// "ancestors", while never reaching the predecessor the root replaced.
/// This test replaces `test_lineage_with_mixed_relationship_types`, which
/// pinned that defect ("All claims included regardless of relationship type").
/// **Reasoning**: Direction is a property of the relationship, the same table
/// `provenance_chain.rs` walks: `supports` is written ancestor->claim, so the
/// ancestor is behind an INCOMING edge; `supersedes` is written new->old, so
/// the predecessor is behind an OUTGOING edge.
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_walks_derivation_edges_only(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let root = create_test_claim(&pool, "Root claim R", 0.7).await;
    let supporter = create_test_claim(&pool, "S supports R", 0.8).await;
    let disputer = create_test_claim(&pool, "X contradicts R", 0.6).await;
    let successor = create_test_claim(&pool, "N supersedes R", 0.75).await;
    let predecessor = create_test_claim(&pool, "P, superseded by R", 0.65).await;
    let matched = create_test_claim(&pool, "M, a cross-source match of R", 0.7).await;

    create_claim_edge(&pool, supporter, root, "supports").await;
    create_claim_edge(&pool, disputer, root, "contradicts").await;
    create_claim_edge(&pool, successor, root, "supersedes").await;
    create_claim_edge(&pool, root, predecessor, "supersedes").await;
    // The spelling the matcher writes (`match_candidate.rs`).
    create_claim_edge(&pool, matched, root, "CORROBORATES").await;
    // OUTGOING non-supersedes edges from R lead to descendants / disputed
    // claims, never to ancestors: they pin the relationship filter on the
    // walk's outgoing branch (descendants reported as ancestors otherwise).
    let descendant = create_test_claim(&pool, "D, supported by R", 0.7).await;
    let disputed = create_test_claim(&pool, "Y, contradicted by R", 0.6).await;
    create_claim_edge(&pool, root, descendant, "supports").await;
    create_claim_edge(&pool, root, disputed, "contradicts").await;
    // A non-derivation edge BETWEEN two lineage members (S and P are both
    // R's ancestors; the walk from P never follows an incoming contradicts
    // edge, so membership is unchanged): pins the parent-edge query filter.
    create_claim_edge(&pool, supporter, predecessor, "contradicts").await;

    let lineage = LineageRepository::get_lineage(&pool, &viewer, root, None, None)
        .await
        .expect("Failed to query lineage");

    // Control: a derivation parent is still walked.
    assert!(
        lineage.claims.contains_key(&supporter),
        "a supporting claim is an ancestor"
    );
    assert!(
        !lineage.claims.contains_key(&disputer),
        "a contradicting claim is not an ancestor"
    );
    assert!(
        !lineage.claims.contains_key(&descendant),
        "a claim R supports is a descendant, not an ancestor"
    );
    assert!(
        !lineage.claims.contains_key(&disputed),
        "a claim R contradicts is not an ancestor"
    );
    assert!(
        !lineage.claims.contains_key(&successor),
        "the superseding (newer) claim is not an ancestor"
    );
    assert!(
        !lineage.claims.contains_key(&matched),
        "a cross-source corroboration is independent support, not ancestry"
    );
    assert!(
        lineage.claims.contains_key(&predecessor),
        "the superseded predecessor is R's ancestor"
    );

    let parents: std::collections::HashSet<Uuid> =
        lineage.claims[&root].parent_ids.iter().copied().collect();
    assert_eq!(
        parents,
        [supporter, predecessor].into_iter().collect(),
        "R's parent_ids name exactly its derivation parents"
    );
    assert!(
        lineage.claims[&predecessor].parent_ids.is_empty(),
        "a contradicts edge between two lineage members is not a parent link"
    );
    assert_eq!(lineage.claims[&predecessor].depth, 1);
    assert_eq!(lineage.claims.len(), 3, "R, S and P only");
}

/// Test: the relationship match is case-insensitive
///
/// **Evidence**: verb edges are stored upper-case in parts of the graph
/// (`decomposition_priority.rs`: "verb edges are stored upper-case"), and the
/// unfiltered walk followed an upper-case `SUPPORTS` edge.
/// **Reasoning**: Moving from "every edge" to a relationship filter must not
/// silently drop a derivation edge because of its spelling. The `SUPPORTS` /
/// `Elaborates` half is green before and after U042, a regression guard on
/// the filter. The upper-case `SUPERSEDES` half (accepted by the
/// `routes/edges.rs` allowlist as an alias of `supersedes`) pins both the
/// SQL's `lower()` on the outgoing branch and the parent map's lower-cased
/// orientation: a case-sensitive orientation would make R the parent of its
/// own predecessor.
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_relationship_match_is_case_insensitive(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let root = create_test_claim(&pool, "Root claim", 0.7).await;
    let upper = create_test_claim(&pool, "Upper-case supporter", 0.8).await;
    let grandparent = create_test_claim(&pool, "Elaborated by the supporter", 0.8).await;

    create_claim_edge(&pool, upper, root, "SUPPORTS").await;
    create_claim_edge(&pool, grandparent, upper, "Elaborates").await;
    let predecessor = create_test_claim(&pool, "Superseded by the root", 0.6).await;
    create_claim_edge(&pool, root, predecessor, "SUPERSEDES").await;

    let lineage = LineageRepository::get_lineage(&pool, &viewer, root, None, None)
        .await
        .expect("Failed to query lineage");

    assert!(
        lineage.claims.contains_key(&upper),
        "an upper-case SUPPORTS edge is still a derivation edge"
    );
    assert!(
        lineage.claims.contains_key(&grandparent),
        "a mixed-case Elaborates edge is still a derivation edge"
    );
    assert!(
        lineage.claims.contains_key(&predecessor),
        "an upper-case SUPERSEDES edge still reaches the predecessor"
    );
    let root_parents: std::collections::HashSet<Uuid> =
        lineage.claims[&root].parent_ids.iter().copied().collect();
    assert_eq!(
        root_parents,
        [upper, predecessor].into_iter().collect(),
        "an upper-case SUPERSEDES edge names its TARGET as the root's parent"
    );
    assert!(
        lineage.claims[&predecessor].parent_ids.is_empty(),
        "the root is not the parent of the predecessor it superseded"
    );
    assert_eq!(lineage.claims[&upper].parent_ids, vec![grandparent]);
}

/// Test: `max_nodes` trims to the target claim plus its nearest ancestors
///
/// **Evidence**: Chain of 5 claims queried with `max_nodes = 3` should keep
/// only the leaf (target) and its 2 nearest ancestors, dropping the 2
/// furthest ancestors.
/// **Reasoning**: `topological_order` is ancestors-first / target-last, so
/// trimming from the front would discard the very claim being queried;
/// `get_lineage` instead keeps the tail of the list.
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_max_nodes_keeps_target_and_nearest_ancestors(pool: PgPool) {
    // #397's max_nodes tests predate the tenancy Viewer; these claims are
    // seeded public, so the public viewer is the one that sees them.
    let viewer = fixture::public_viewer(&pool).await;
    // Setup: chain[0] -> chain[1] -> chain[2] -> chain[3] -> chain[4] (leaf)
    let chain = create_claim_chain(&pool, 5).await;
    let leaf_id = *chain.last().unwrap();

    // Execute: cap the result at 3 nodes
    let lineage = LineageRepository::get_lineage(&pool, &viewer, leaf_id, None, Some(3))
        .await
        .expect("Failed to query lineage");

    // Verify: only the leaf (depth 0) plus its 2 nearest ancestors remain
    assert_eq!(
        lineage.topological_order.len(),
        3,
        "topological_order should be trimmed to max_nodes entries"
    );
    assert_eq!(lineage.claims.len(), 3, "claims map should match the cap");
    assert!(lineage.claims.contains_key(&chain[4]), "leaf (target) kept");
    assert!(
        lineage.claims.contains_key(&chain[3]),
        "nearest ancestor kept"
    );
    assert!(
        lineage.claims.contains_key(&chain[2]),
        "2nd-nearest ancestor kept"
    );
    assert!(
        !lineage.claims.contains_key(&chain[1]),
        "distant ancestor dropped"
    );
    assert!(
        !lineage.claims.contains_key(&chain[0]),
        "furthest ancestor dropped"
    );

    // Verify: the target claim is last, ancestors-first order preserved
    assert_eq!(lineage.topological_order[2], leaf_id);

    // Verify: truncation is flagged
    assert!(
        lineage.truncated,
        "truncated should be true when max_nodes cuts the result"
    );
}

/// Test: a `max_nodes` cut prunes `parent_ids` to the kept claims
///
/// **Evidence**: #397 review finding (arch, HIGH) on `get_lineage_conn`:
/// `LineageClaim.parent_ids` was built from the UNTRIMMED parent map, and the
/// `max_nodes` trim only retained `claims`/`evidence`/`traces`. Every kept
/// claim whose parent fell outside the cut kept a reference to a claim that is
/// no longer in `claims`. `get_provenance` passes `Some(max_nodes)` by
/// default, so its bundles emitted `claim:` ids absent from `entities`.
/// **Reasoning**: an id in `parent_ids` must resolve to a key of `claims`;
/// otherwise a consumer building edges from it emits an edge to a node the
/// response does not contain. The untrimmed control proves the prune drops
/// only the cut references, not the real ones.
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_max_nodes_prunes_parent_ids_to_kept_claims(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // chain[0] -> chain[1] -> chain[2] -> chain[3] -> chain[4] (leaf)
    let chain = create_claim_chain(&pool, 5).await;
    let leaf_id = *chain.last().unwrap();

    // ---- Control: untrimmed, every parent link is present and resolves ----
    let full = LineageRepository::get_lineage(&pool, &viewer, leaf_id, None, None)
        .await
        .expect("Failed to query lineage");
    assert!(!full.truncated);
    for i in 1..5 {
        assert_eq!(
            full.claims[&chain[i]].parent_ids,
            vec![chain[i - 1]],
            "untrimmed lineage must keep the real parent link of chain[{i}]"
        );
    }

    // ---- Trimmed to 3 nodes: chain[2], chain[3], chain[4] are kept ----
    let lineage = LineageRepository::get_lineage(&pool, &viewer, leaf_id, None, Some(3))
        .await
        .expect("Failed to query lineage");
    assert!(lineage.truncated, "the cap must actually cut this lineage");
    assert_eq!(lineage.claims.len(), 3);

    for c in lineage.claims.values() {
        for p in &c.parent_ids {
            assert!(
                lineage.claims.contains_key(p),
                "claim {} lists parent {p}, which max_nodes dropped from `claims`: \
                 a dangling reference",
                c.id
            );
        }
    }
    // The prune must not over-reach: links between two KEPT claims survive.
    assert_eq!(lineage.claims[&chain[4]].parent_ids, vec![chain[3]]);
    assert_eq!(lineage.claims[&chain[3]].parent_ids, vec![chain[2]]);
    assert!(
        lineage.claims[&chain[2]].parent_ids.is_empty(),
        "chain[2]'s only parent (chain[1]) was cut, so it must list none"
    );
}

/// Test: `max_nodes` set to `None` never truncates and leaves `truncated` false
///
/// **Evidence**: Same 5-claim chain queried without a node cap returns all
/// claims and reports `truncated == false` (max_depth default of 100 is
/// nowhere near being hit either).
/// **Reasoning**: Omitting `max_nodes` must be behavior-preserving for
/// existing callers.
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_max_nodes_none_does_not_truncate(pool: PgPool) {
    // #397's max_nodes tests predate the tenancy Viewer; these claims are
    // seeded public, so the public viewer is the one that sees them.
    let viewer = fixture::public_viewer(&pool).await;
    let chain = create_claim_chain(&pool, 5).await;
    let leaf_id = *chain.last().unwrap();

    let lineage = LineageRepository::get_lineage(&pool, &viewer, leaf_id, None, None)
        .await
        .expect("Failed to query lineage");

    assert_eq!(lineage.claims.len(), 5);
    assert_eq!(lineage.topological_order.len(), 5);
    assert!(
        !lineage.truncated,
        "truncated should be false when nothing was cut"
    );
}

/// Test: `max_nodes` larger than the full lineage is a no-op
///
/// **Evidence**: Requesting `max_nodes` greater than the number of ancestors
/// returns the full, untruncated lineage.
/// **Reasoning**: The cap should only trim when the result actually exceeds
/// it.
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_max_nodes_larger_than_result_is_noop(pool: PgPool) {
    // #397's max_nodes tests predate the tenancy Viewer; these claims are
    // seeded public, so the public viewer is the one that sees them.
    let viewer = fixture::public_viewer(&pool).await;
    let chain = create_claim_chain(&pool, 5).await;
    let leaf_id = *chain.last().unwrap();

    let lineage = LineageRepository::get_lineage(&pool, &viewer, leaf_id, None, Some(100))
        .await
        .expect("Failed to query lineage");

    assert_eq!(lineage.claims.len(), 5);
    assert_eq!(lineage.topological_order.len(), 5);
    assert!(
        !lineage.truncated,
        "truncated should be false when max_nodes exceeds the actual result size"
    );
}

/// Test: depth-based truncation sets `truncated = true` even without `max_nodes`
///
/// **Evidence**: Reusing the existing max_depth=2 scenario over a 5-claim
/// chain, two ancestors lie beyond the requested `max_depth`, so the walk's
/// probe layer finds one and the result is cut.
/// **Reasoning**: `truncated` must reflect depth-capping, not just node
/// capping, per the spec.
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_truncated_flag_set_by_max_depth(pool: PgPool) {
    // #397's max_nodes tests predate the tenancy Viewer; these claims are
    // seeded public, so the public viewer is the one that sees them.
    let viewer = fixture::public_viewer(&pool).await;
    let chain = create_claim_chain(&pool, 5).await;
    let leaf_id = *chain.last().unwrap();

    let lineage = LineageRepository::get_lineage(&pool, &viewer, leaf_id, Some(2), None)
        .await
        .expect("Failed to query lineage");

    assert_eq!(lineage.max_depth_reached, 2);
    assert!(
        lineage.truncated,
        "truncated should be true when ancestors lie past max_depth"
    );
}

/// Test: a lineage that fits entirely within `max_depth` is not flagged truncated
///
/// **Evidence**: A 3-claim chain queried with `max_depth = 100` (default)
/// never reaches the cutoff, so `truncated` stays false.
/// **Reasoning**: Guards against a naive "any depth reached" check that
/// would incorrectly flag small, complete lineages as truncated.
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_not_truncated_when_depth_cutoff_not_reached(pool: PgPool) {
    // #397's max_nodes tests predate the tenancy Viewer; these claims are
    // seeded public, so the public viewer is the one that sees them.
    let viewer = fixture::public_viewer(&pool).await;
    let chain = create_claim_chain(&pool, 3).await;
    let leaf_id = *chain.last().unwrap();

    let lineage = LineageRepository::get_lineage(&pool, &viewer, leaf_id, None, None)
        .await
        .expect("Failed to query lineage");

    assert_eq!(lineage.max_depth_reached, 2);
    assert!(
        !lineage.truncated,
        "truncated should be false when the full chain fit within max_depth"
    );
}

// ============================================================================
// `truncated` is exact: set iff a visible claim lies beyond `max_depth`
// ============================================================================

/// The depth cap every exact-truncation test below walks with.
const CUT: i32 = 3;

/// A chain whose last ancestor sits EXACTLY at `max_depth` is complete, so it
/// must not be reported truncated, in either direction.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_ending_exactly_at_max_depth_is_not_truncated(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // CUT + 1 claims: depths 0..=CUT from either end, nothing beyond.
    let chain = create_claim_chain(&pool, CUT as usize + 1).await;

    let up =
        LineageRepository::get_lineage(&pool, &viewer, *chain.last().unwrap(), Some(CUT), None)
            .await
            .expect("ancestor walk");
    assert_eq!(
        up.claims.len(),
        CUT as usize + 1,
        "the whole chain is in range"
    );
    assert_eq!(up.max_depth_reached, CUT);
    assert!(
        !up.truncated,
        "get_lineage: an ancestry that ends exactly at max_depth is complete and must \
         not be flagged truncated"
    );

    let down = LineageRepository::get_descendants(&pool, &viewer, chain[0], Some(CUT))
        .await
        .expect("descendant walk");
    assert_eq!(
        down.claims.len(),
        CUT as usize + 1,
        "the whole chain is in range"
    );
    assert_eq!(down.max_depth_reached, CUT);
    assert!(
        !down.truncated,
        "get_descendants: a descent that ends exactly at max_depth is complete and must \
         not be flagged truncated"
    );
}

/// One claim past `max_depth` makes the result truncated, in either direction,
/// and the claim that proved it is not in the result.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_with_a_claim_past_max_depth_is_truncated_and_omits_it(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // CUT + 2 claims: one claim at depth CUT + 1 from either end.
    let chain = create_claim_chain(&pool, CUT as usize + 2).await;
    let leaf = *chain.last().unwrap();

    let up = LineageRepository::get_lineage(&pool, &viewer, leaf, Some(CUT), None)
        .await
        .expect("ancestor walk");
    assert!(up.truncated, "get_lineage: an ancestor lies past max_depth");
    assert_eq!(up.max_depth_reached, CUT);
    assert_eq!(
        up.claims.len(),
        CUT as usize + 1,
        "{:?}",
        up.topological_order
    );
    assert!(
        !up.claims.contains_key(&chain[0]),
        "get_lineage: the claim past max_depth must not be returned"
    );
    assert!(up.claims.values().all(|c| c.depth <= CUT));
    assert_eq!(up.topological_order.len(), CUT as usize + 1);

    let down = LineageRepository::get_descendants(&pool, &viewer, chain[0], Some(CUT))
        .await
        .expect("descendant walk");
    assert!(
        down.truncated,
        "get_descendants: a descendant lies past max_depth, so the result is not \
         complete and must say so"
    );
    assert_eq!(down.max_depth_reached, CUT);
    assert_eq!(
        down.claims.len(),
        CUT as usize + 1,
        "{:?}",
        down.topological_order
    );
    assert!(
        !down.claims.contains_key(&leaf),
        "get_descendants: the claim past max_depth must not be returned"
    );
    assert!(down.claims.values().all(|c| c.depth <= CUT));
    assert_eq!(down.topological_order.len(), CUT as usize + 1);
}

/// Truncation follows the viewer: a claim past `max_depth` that the viewer
/// cannot read does not make its result truncated, while a member of that
/// claim's group is told the result was cut.
///
/// The edge to the private claim is forced PUBLIC, so only the claim-level
/// visibility predicate decides whether the walk may count it.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_truncation_follows_the_viewer(pool: PgPool) {
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "trunc-owner").await;
    let world = fixture::world_group(&pool).await;
    let public = fixture::public_viewer(&pool).await;
    let member = epigraph_db::visibility::Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve member");

    // Public chain c0 -> ... -> c{CUT}: complete at depth CUT from either end.
    let chain = create_claim_chain(&pool, CUT as usize + 1).await;
    let leaf = *chain.last().unwrap();
    // One private claim beyond each end, over a public edge.
    let above =
        fixture::seed_group_claim(&pool, stranger, stranger_group, "private ancestor").await;
    fixture::seed_edge_owned_by(&pool, above, chain[0], "public", world).await;
    let below =
        fixture::seed_group_claim(&pool, stranger, stranger_group, "private descendant").await;
    fixture::seed_edge_owned_by(&pool, leaf, below, "public", world).await;

    let up_public = LineageRepository::get_lineage(&pool, &public, leaf, Some(CUT), None)
        .await
        .expect("ancestor walk, public");
    let up_member = LineageRepository::get_lineage(&pool, &member, leaf, Some(CUT), None)
        .await
        .expect("ancestor walk, member");
    assert!(
        !up_public.truncated,
        "get_lineage: the only claim past max_depth is one the viewer cannot read, so \
         for this viewer the result is complete"
    );
    assert!(
        up_member.truncated,
        "get_lineage: a member of the private ancestor's group must be told the result \
         was cut"
    );
    assert!(!up_member.claims.contains_key(&above));

    let down_public = LineageRepository::get_descendants(&pool, &public, chain[0], Some(CUT))
        .await
        .expect("descendant walk, public");
    let down_member = LineageRepository::get_descendants(&pool, &member, chain[0], Some(CUT))
        .await
        .expect("descendant walk, member");
    assert!(
        !down_public.truncated,
        "get_descendants: the only claim past max_depth is one the viewer cannot read"
    );
    assert!(
        down_member.truncated,
        "get_descendants: a member of the private descendant's group must be told the \
         result was cut"
    );
    assert!(!down_member.claims.contains_key(&below));
}

/// Truncation follows EDGE visibility too: a PUBLIC claim past `max_depth`
/// that is reachable only over an edge the viewer cannot read does not make
/// its result truncated, while a member of the edge's owning group is told the
/// result was cut.
///
/// The claims past the cut are public, so only the edge-level visibility
/// predicate decides whether the walk may count them; this is the half of
/// "the probe layer reveals nothing" that
/// `lineage_truncation_follows_the_viewer` (claim-level) does not reach.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_truncation_follows_edge_visibility(pool: PgPool) {
    let (edge_owner, edge_group) = fixture::seed_agent_with_group(&pool, "trunc-edge-owner").await;
    let public = fixture::public_viewer(&pool).await;
    let member = epigraph_db::visibility::Viewer::resolve(&pool, edge_owner)
        .await
        .expect("resolve member");

    // Public chain c0 -> ... -> c{CUT}: complete at depth CUT from either end.
    let chain = create_claim_chain(&pool, CUT as usize + 1).await;
    let leaf = *chain.last().unwrap();
    // One PUBLIC claim beyond each end, each reachable only over a
    // group-private edge.
    let above = fixture::seed_public_claim(&pool, edge_owner, "public ancestor").await;
    fixture::seed_edge_owned_by(&pool, above, chain[0], "group", edge_group).await;
    let below = fixture::seed_public_claim(&pool, edge_owner, "public descendant").await;
    fixture::seed_edge_owned_by(&pool, leaf, below, "group", edge_group).await;

    for (walk, public_result, member_result, beyond) in [
        (
            "get_lineage",
            LineageRepository::get_lineage(&pool, &public, leaf, Some(CUT), None)
                .await
                .expect("ancestor walk, public"),
            LineageRepository::get_lineage(&pool, &member, leaf, Some(CUT), None)
                .await
                .expect("ancestor walk, member"),
            above,
        ),
        (
            "get_descendants",
            LineageRepository::get_descendants(&pool, &public, chain[0], Some(CUT))
                .await
                .expect("descendant walk, public"),
            LineageRepository::get_descendants(&pool, &member, chain[0], Some(CUT))
                .await
                .expect("descendant walk, member"),
            below,
        ),
    ] {
        // Calibration: both viewers walk the whole public chain.
        assert_eq!(public_result.claims.len(), CUT as usize + 1, "{walk}");
        assert_eq!(member_result.claims.len(), CUT as usize + 1, "{walk}");
        assert!(
            !public_result.truncated,
            "{walk}: the only claim past max_depth is reachable only over an edge the \
             viewer cannot read, so for this viewer the result is complete"
        );
        assert!(
            member_result.truncated,
            "{walk}: a member of the edge's owning group must be told the result was cut"
        );
        assert!(
            !member_result.claims.contains_key(&beyond),
            "{walk}: the probe layer must not be returned"
        );
    }
}

// ============================================================================
// `max_nodes` trims BEFORE the follow-up queries
// ============================================================================

/// The `max_nodes` cap bounds what `get_lineage` FETCHES, not only what it
/// returns: claims the cap drops must never reach the edges, evidence or
/// reasoning-trace statements.
///
/// Far ancestors carry evidence and traces, the kept target carries none and
/// has no edge inside the kept set, so every follow-up statement must return
/// zero rows. The second half pins the
/// trimmed result explicitly, so moving the trim cannot change the answer.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_max_nodes_trims_before_the_follow_up_queries(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // c0 -> c1 -> c2 -> c3 -> c4; the target is c4.
    let chain = create_claim_chain(&pool, 5).await;
    let target = chain[4];
    let mut far_evidence = Vec::new();
    for &far in &chain[0..3] {
        for kind in ["document", "observation", "reference"] {
            far_evidence.push(fixture::seed_evidence(&pool, far, kind).await);
        }
        fixture::seed_reasoning_trace(&pool, far, "deductive").await;
    }

    // ---- cost: max_nodes = 1 keeps only the target ----
    let (lineage, statements) = statement_log::capture(LineageRepository::get_lineage(
        &pool,
        &viewer,
        target,
        None,
        Some(1),
    ))
    .await;
    let lineage = lineage.expect("capped lineage");
    assert_eq!(lineage.topological_order, vec![target]);
    assert!(lineage.truncated);

    let follow_ups: Vec<_> = statements
        .iter()
        .filter(|s| {
            let t = s.normalized();
            t.contains("FROM edges")
                || t.contains("FROM evidence")
                || t.contains("FROM reasoning_traces")
        })
        .collect();
    assert!(
        !follow_ups.is_empty(),
        "CALIBRATION: the capture must see the edge/evidence/trace statements:\n{}",
        statement_log::describe(&statements)
    );
    for s in &follow_ups {
        assert_eq!(
            s.rows_returned,
            0,
            "a claim dropped by max_nodes must not be fetched by a follow-up statement \
             (the far ancestors hold {} evidence rows and 3 traces):\n{}",
            far_evidence.len(),
            statement_log::describe(&statements)
        );
    }

    // ---- answer: max_nodes = 2 keeps the target and its nearest ancestor ----
    let c3_evidence = fixture::seed_evidence(&pool, chain[3], "testimony").await;
    let c3_trace = fixture::seed_reasoning_trace(&pool, chain[3], "inductive").await;
    let two = LineageRepository::get_lineage(&pool, &viewer, target, None, Some(2))
        .await
        .expect("capped lineage");
    assert!(two.truncated);
    assert_eq!(two.topological_order, vec![chain[3], target]);
    let mut kept: Vec<Uuid> = two.claims.keys().copied().collect();
    kept.sort();
    let mut expected = vec![chain[3], target];
    expected.sort();
    assert_eq!(kept, expected);
    assert_eq!(two.claims[&target].parent_ids, vec![chain[3]]);
    assert!(
        two.claims[&chain[3]].parent_ids.is_empty(),
        "the dropped c2 must not be named as a parent"
    );
    assert_eq!(
        two.evidence.keys().copied().collect::<Vec<_>>(),
        vec![c3_evidence]
    );
    assert_eq!(two.claims[&chain[3]].evidence_ids, vec![c3_evidence]);
    assert_eq!(
        two.traces.keys().copied().collect::<Vec<_>>(),
        vec![c3_trace]
    );
    assert_eq!(
        two.max_depth_reached, 4,
        "measured on the walk, before the cap"
    );
    assert!(!two.cycle_detected);
}

/// When `max_nodes` cuts INSIDE one depth layer, the kept set is pinned
/// explicitly: the target plus the nearest ancestors, and within the cut layer
/// the claims that sort LAST in the walk's `ORDER BY id` (the stable
/// descending-depth sort keeps that id order inside a layer, and the cap keeps
/// the last `n` entries).
///
/// Every other `max_nodes` fixture is a single chain, where no layer holds
/// more than one claim, so a change to tie-breaking at the cut would go
/// unnoticed there. The expected sets are computed from the seeded ids, not
/// from another call.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_max_nodes_cut_inside_a_depth_layer_is_pinned(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // Fan-in: three parents p -> root, all at depth 1.
    let root = create_test_claim(&pool, "fan-in root", 0.5).await;
    let mut parents = Vec::new();
    for i in 0..3 {
        let p = create_test_claim(&pool, &format!("fan-in parent {i}"), 0.6).await;
        create_claim_edge(&pool, p, root, "supports").await;
        parents.push(p);
    }
    parents.sort();

    // Calibration: uncapped, the whole fan is returned, ancestors first.
    let all = LineageRepository::get_lineage(&pool, &viewer, root, None, None)
        .await
        .expect("uncapped lineage");
    assert_eq!(
        all.topological_order,
        vec![parents[0], parents[1], parents[2], root]
    );
    assert!(!all.truncated);

    let sorted_keys = |l: &epigraph_db::LineageResult| {
        let mut k: Vec<Uuid> = l.claims.keys().copied().collect();
        k.sort();
        k
    };
    let sorted = |mut v: Vec<Uuid>| {
        v.sort();
        v
    };

    // max_nodes = 2 keeps the root and the highest-id parent only.
    let two = LineageRepository::get_lineage(&pool, &viewer, root, None, Some(2))
        .await
        .expect("capped lineage, 2");
    assert!(two.truncated);
    assert_eq!(two.topological_order, vec![parents[2], root]);
    assert_eq!(sorted_keys(&two), sorted(vec![parents[2], root]));
    assert_eq!(two.claims[&root].parent_ids, vec![parents[2]]);

    // max_nodes = 3 keeps the root and the two highest-id parents.
    let three = LineageRepository::get_lineage(&pool, &viewer, root, None, Some(3))
        .await
        .expect("capped lineage, 3");
    assert!(three.truncated);
    assert_eq!(three.topological_order, vec![parents[1], parents[2], root]);
    assert_eq!(
        sorted_keys(&three),
        sorted(vec![parents[1], parents[2], root])
    );
    assert_eq!(
        sorted(three.claims[&root].parent_ids.clone()),
        vec![parents[1], parents[2]],
        "the dropped lowest-id parent must not be named as a parent"
    );
}
