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
use std::collections::HashSet;
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
    let ev_root_1 =
        EvidenceRepository::create(&pool, &ev_root_1, epigraph_db::EvidenceEdge::supports(None))
            .await
            .unwrap();
    let evidence_root_1: Uuid = ev_root_1.id.as_uuid();

    let ev_root_2 = make_evidence(agent.id, root_claim.id, "Root evidence 2");
    let ev_root_2 =
        EvidenceRepository::create(&pool, &ev_root_2, epigraph_db::EvidenceEdge::supports(None))
            .await
            .unwrap();
    let evidence_root_2: Uuid = ev_root_2.id.as_uuid();

    let ev_middle = make_evidence(agent.id, middle_claim.id, "Middle evidence");
    let ev_middle =
        EvidenceRepository::create(&pool, &ev_middle, epigraph_db::EvidenceEdge::supports(None))
            .await
            .unwrap();
    let evidence_middle: Uuid = ev_middle.id.as_uuid();

    let ev_leaf = make_evidence(agent.id, leaf_claim.id, "Leaf evidence");
    let ev_leaf =
        EvidenceRepository::create(&pool, &ev_leaf, epigraph_db::EvidenceEdge::supports(None))
            .await
            .unwrap();
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
    // ...and report the cycle it walked (backlog c07884a9).
    assert_eq!(lineage.claims.len(), 3);
    assert!(
        lineage.cycle_detected,
        "A -> B -> C -> A is among the claims"
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

/// Test: `omitted_by_node_cap` names EXACTLY the claims the cap cut, and a
/// lineage that fits the cap exactly is reported complete.
///
/// **Evidence**: backlog 04007084. A REST node cap needs an exact signal, or a
/// capped response silently hides part of the lineage; `truncated` alone says
/// "something is missing" but not what or how much.
/// **Reasoning**: the walk returns every visible claim within `max_depth`
/// before the cap trims in memory, so the omitted set is the difference and is
/// exact. The boundary (cap == size) is what tells exact from "at least one".
/// A claim past `max_depth` is the depth half's business and must not be
/// counted as cut by the cap.
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_max_nodes_reports_exactly_the_omitted_claims(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // chain[0] -> chain[1] -> chain[2] -> chain[3] -> chain[4] (leaf)
    let chain = create_claim_chain(&pool, 5).await;
    let leaf = chain[4];
    let set = |v: &[Uuid]| v.iter().copied().collect::<HashSet<Uuid>>();

    for (cap, cut) in [(3usize, &chain[..2]), (4, &chain[..1]), (1, &chain[..4])] {
        let l = LineageRepository::get_lineage(&pool, &viewer, leaf, None, Some(cap))
            .await
            .expect("capped walk");
        assert_eq!(l.claims.len(), cap, "cap {cap}");
        assert_eq!(
            set(&l.omitted_by_node_cap),
            set(cut),
            "cap {cap}: the omitted ids must be exactly the furthest ancestors cut"
        );
        assert_eq!(
            l.omitted_by_node_cap.len(),
            cut.len(),
            "cap {cap}: no duplicates"
        );
        assert!(l.truncated && !l.truncated_by_depth, "cap {cap}");
    }

    // Exactly at the cap: complete, nothing omitted.
    let exact = LineageRepository::get_lineage(&pool, &viewer, leaf, None, Some(5))
        .await
        .expect("walk at exactly the cap");
    assert_eq!(exact.claims.len(), 5);
    assert!(exact.omitted_by_node_cap.is_empty());
    assert!(
        !exact.truncated,
        "a lineage exactly as large as the cap is complete and must not be flagged"
    );

    // Depth AND cap: max_depth 3 keeps chain[1..=4] in reach (chain[0] lies
    // past it); a cap of 2 then cuts chain[1] and chain[2]. chain[0] is the
    // depth bound's cut, not the cap's.
    let both = LineageRepository::get_lineage(&pool, &viewer, leaf, Some(3), Some(2))
        .await
        .expect("depth and cap");
    assert!(both.truncated_by_depth, "chain[0] lies past max_depth");
    assert_eq!(set(&both.omitted_by_node_cap), set(&chain[1..3]));
    assert!(both.truncated);
}

/// Test: the DESCENDANT walk takes a `max_nodes` cap, keeping the root and its
/// nearest descendants, and names what it cut.
///
/// **Evidence**: backlog 04007084. `get_descendants_conn` had no node cap, so
/// `GET /lineage/:id?direction=descendants` could not be bounded at all.
/// **Reasoning**: the cap keeps the claims NEAREST the root by depth; one that
/// kept the deepest would drop the root itself, and its `topological_order` is
/// root-first (the opposite of `get_lineage`'s), so the root leads it. Every
/// kept claim's `parent_ids` must resolve inside `claims`.
#[sqlx::test(migrations = "../../migrations")]
async fn test_descendants_max_nodes_keeps_root_and_nearest_descendants(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // chain[0] (root) -> chain[1] -> chain[2] -> chain[3] -> chain[4]
    let chain = create_claim_chain(&pool, 5).await;
    let root = chain[0];

    let full = LineageRepository::get_descendants(&pool, &viewer, root, None, None)
        .await
        .expect("uncapped descendant walk");
    assert_eq!(full.claims.len(), 5, "CALIBRATION: the chain is 5 claims");
    assert!(!full.truncated && full.omitted_by_node_cap.is_empty());

    let capped = LineageRepository::get_descendants(&pool, &viewer, root, None, Some(3))
        .await
        .expect("capped descendant walk");
    assert_eq!(capped.claims.len(), 3);
    for kept in &chain[..3] {
        assert!(capped.claims.contains_key(kept), "nearest kept: {kept}");
    }
    assert_eq!(capped.topological_order[0], root, "root first, and kept");
    assert_eq!(
        capped
            .omitted_by_node_cap
            .iter()
            .copied()
            .collect::<HashSet<_>>(),
        chain[3..].iter().copied().collect::<HashSet<_>>(),
        "the two furthest descendants are the ones cut"
    );
    assert!(capped.truncated && !capped.truncated_by_depth);
    for c in capped.claims.values() {
        for p in &c.parent_ids {
            assert!(
                capped.claims.contains_key(p),
                "claim {} names parent {p} outside the kept set",
                c.id
            );
        }
    }

    let exact = LineageRepository::get_descendants(&pool, &viewer, root, None, Some(5))
        .await
        .expect("descendant walk at exactly the cap");
    assert!(!exact.truncated && exact.omitted_by_node_cap.is_empty());
}

/// Test: the descendant cap runs BEFORE the edges and evidence statements, so
/// nothing a kept claim carries points at a claim the cap cut.
///
/// **Evidence**: T104 review finding 1. Every other capped fixture is a chain
/// or a one-layer fan, where a kept descendant's parents are all kept, so a
/// cap moved below the follow-up statements (with `claims` still built from
/// the kept rows) left every test green while a kept claim named a cut parent
/// and the cut claims' evidence was fetched and served.
/// **Reasoning**: a back-edge from a cut claim into a kept one is the shape
/// that tells the two orders apart. `root -> a -> c` puts `c` at depth 2;
/// `root -> k` puts `k` at depth 1; `c -> k` is the back-edge (it leaves `k`
/// at depth 1, its shortest). A cap of 3 keeps root, a and k and cuts c. `c`
/// carries evidence, which must not be served either.
#[sqlx::test(migrations = "../../migrations")]
async fn test_descendants_max_nodes_cut_claim_does_not_leak_through_a_back_edge(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = AgentRepository::create(&pool, &make_agent(None))
        .await
        .unwrap();
    let mut ids = Vec::new();
    for name in ["root", "a", "k", "c"] {
        let claim = make_claim(agent.id, &format!("back-edge fixture {name}"), 0.6);
        let claim = ClaimRepository::create(&pool, &claim, epigraph_core::TenancyDecl::Inherited)
            .await
            .unwrap();
        ids.push(claim.id);
    }
    let [root, a, k, c] = [ids[0], ids[1], ids[2], ids[3]].map(|id| id.as_uuid());
    create_claim_edge(&pool, root, a, "supports").await;
    create_claim_edge(&pool, a, c, "supports").await;
    create_claim_edge(&pool, root, k, "supports").await;
    create_claim_edge(&pool, c, k, "supports").await; // the back-edge

    let ev_k = make_evidence(agent.id, ids[2], "evidence on the kept claim k");
    let ev_k = EvidenceRepository::create(&pool, &ev_k, epigraph_db::EvidenceEdge::supports(None))
        .await
        .unwrap()
        .id
        .as_uuid();
    let ev_c = make_evidence(agent.id, ids[3], "evidence on the cut claim c");
    let ev_c = EvidenceRepository::create(&pool, &ev_c, epigraph_db::EvidenceEdge::supports(None))
        .await
        .unwrap()
        .id
        .as_uuid();

    // CALIBRATION: uncapped, c is a depth-2 descendant and k names it as a
    // parent, so the back-edge is really in the walk.
    let full = LineageRepository::get_descendants(&pool, &viewer, root, None, None)
        .await
        .expect("uncapped descendant walk");
    assert_eq!(full.claims.len(), 4);
    assert_eq!(full.claims[&c].depth, 2);
    assert_eq!(full.claims[&k].depth, 1);
    assert!(
        full.claims[&k].parent_ids.contains(&c),
        "CALIBRATION: k must name c as a parent uncapped, or the capped \
         assertions below prove nothing; got {:?}",
        full.claims[&k].parent_ids
    );
    assert!(full.evidence.contains_key(&ev_c));

    let capped = LineageRepository::get_descendants(&pool, &viewer, root, None, Some(3))
        .await
        .expect("capped descendant walk");
    assert_eq!(
        capped.claims.keys().copied().collect::<HashSet<_>>(),
        HashSet::from([root, a, k])
    );
    assert_eq!(capped.omitted_by_node_cap, vec![c]);
    assert!(capped.truncated && !capped.truncated_by_depth);
    for kept in capped.claims.values() {
        for p in &kept.parent_ids {
            assert!(
                capped.claims.contains_key(p),
                "claim {} names parent {p}, which the cap cut",
                kept.id
            );
        }
    }
    assert_eq!(capped.claims[&k].parent_ids, vec![root]);
    assert!(
        capped.evidence.contains_key(&ev_k),
        "CALIBRATION: a kept claim's evidence is served"
    );
    assert!(
        !capped.evidence.contains_key(&ev_c),
        "the cut claim's evidence must not be fetched and served"
    );
    for ev in capped.evidence.values() {
        assert!(capped.claims.contains_key(&ev.claim_id));
    }
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

    let down = LineageRepository::get_descendants(&pool, &viewer, chain[0], Some(CUT), None)
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

    let down = LineageRepository::get_descendants(&pool, &viewer, chain[0], Some(CUT), None)
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

    let down_public = LineageRepository::get_descendants(&pool, &public, chain[0], Some(CUT), None)
        .await
        .expect("descendant walk, public");
    let down_member = LineageRepository::get_descendants(&pool, &member, chain[0], Some(CUT), None)
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
            LineageRepository::get_descendants(&pool, &public, chain[0], Some(CUT), None)
                .await
                .expect("descendant walk, public"),
            LineageRepository::get_descendants(&pool, &member, chain[0], Some(CUT), None)
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

// ============================================================================
// Dense DAGs: the walks are bounded by nodes x depth, not by paths
// ============================================================================

/// A dense layered DAG ("lattice"): `top -> L_d (w claims) -> ... -> L_1 (w
/// claims) -> bottom`, every claim of a layer `supports` every claim of the
/// next one. Layer `L_j` is `j` hops above `bottom`, so `bottom` sees
/// `w^(j-1)` distinct paths to each claim of `L_j` and `w^d` to `top`, while
/// the lattice holds only `w * d + 2` claims.
///
/// Returns `(top, layers, bottom)` with `layers[j - 1]` = `L_j`.
async fn create_lattice(
    pool: &PgPool,
    tag: &str,
    width: usize,
    layers: usize,
) -> (Uuid, Vec<Vec<Uuid>>, Uuid) {
    // Content is unique per claim (the tag and both indices) so no claim of
    // one lattice can be shared with another.
    let bottom = create_test_claim(pool, &format!("{tag} bottom"), 0.5).await;
    let mut built: Vec<Vec<Uuid>> = Vec::with_capacity(layers);
    let mut below = vec![bottom];
    for j in 1..=layers {
        let mut layer = Vec::with_capacity(width);
        for i in 0..width {
            let c = create_test_claim(pool, &format!("{tag} L{j}-{i}"), 0.5).await;
            for &child in &below {
                create_claim_edge(pool, c, child, "supports").await;
            }
            layer.push(c);
        }
        below = layer.clone();
        built.push(layer);
    }
    let top = create_test_claim(pool, &format!("{tag} top"), 0.5).await;
    for &child in &below {
        create_claim_edge(pool, top, child, "supports").await;
    }
    (top, built, bottom)
}

/// A connection whose statements are cancelled after a few seconds. A walk
/// that enumerates paths cannot finish a lattice with millions of paths in
/// that time on any host; a walk bounded by nodes x depth finishes in
/// milliseconds. The bound is short on purpose: a path-enumerating walk spills
/// its rows (content plus a path array each) to temp files while it runs.
async fn time_boxed_conn(pool: &PgPool) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("SET statement_timeout = '5s'")
        .execute(&mut *conn)
        .await
        .expect("set statement_timeout");
    conn
}

/// Width and depth of the lattice the dense-DAG tests walk: 4^12 (about 16.7
/// million) paths from `bottom` to `top`, over 50 claims.
const LATTICE_WIDTH: usize = 4;
const LATTICE_LAYERS: usize = 12;

/// Backlog f889c86f: every lineage walk that reports each claim's shortest
/// depth finishes on a dense DAG, and reports exactly the claims and depths
/// the DAG has, in both directions, with `truncated` exact at the boundary.
///
/// On the path-enumerating walks (`UNION ALL` plus a path array, deduplicated
/// only by the outer `DISTINCT ON`) every call here exceeds the 5 s statement
/// timeout.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_walks_finish_on_a_dense_dag(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (top, layers, bottom) = create_lattice(&pool, "dense", LATTICE_WIDTH, LATTICE_LAYERS).await;
    let d = LATTICE_LAYERS as i32;
    let total = LATTICE_WIDTH * LATTICE_LAYERS + 2;
    let mut conn = time_boxed_conn(&pool).await;

    // ---- ancestors of `bottom` ----
    let up = LineageRepository::get_lineage_conn(&mut conn, &viewer, bottom, None, None)
        .await
        .expect("get_lineage over the lattice must finish inside the statement timeout");
    assert_eq!(up.claims.len(), total);
    assert_eq!(up.claims[&bottom].depth, 0);
    for (j, layer) in layers.iter().enumerate() {
        for c in layer {
            assert_eq!(up.claims[c].depth, j as i32 + 1, "L{} depth", j + 1);
        }
    }
    assert_eq!(up.claims[&top].depth, d + 1);
    assert_eq!(up.max_depth_reached, d + 1);
    assert!(!up.truncated);
    assert_eq!(up.topological_order.first(), Some(&top));
    assert_eq!(up.topological_order.last(), Some(&bottom));
    assert_eq!(
        up.claims[&bottom].parent_ids.len(),
        LATTICE_WIDTH,
        "bottom's parents are all of L1"
    );

    // Ending exactly at max_depth is complete; one layer short is truncated
    // and omits exactly the claim past the cut.
    let exact = LineageRepository::get_lineage_conn(&mut conn, &viewer, bottom, Some(d + 1), None)
        .await
        .expect("lineage at the exact depth");
    assert_eq!(exact.claims.len(), total);
    assert!(!exact.truncated);
    let short = LineageRepository::get_lineage_conn(&mut conn, &viewer, bottom, Some(d), None)
        .await
        .expect("lineage one layer short");
    assert!(short.truncated, "top lies past max_depth");
    assert_eq!(short.claims.len(), total - 1);
    assert!(!short.claims.contains_key(&top));
    assert_eq!(short.max_depth_reached, d);

    let ids = LineageRepository::get_ancestor_ids(&mut *conn, &viewer, bottom, None)
        .await
        .expect("get_ancestor_ids over the lattice");
    assert_eq!(ids.len(), total);
    assert_eq!(ids.first(), Some(&top), "ancestors first");
    assert_eq!(ids.last(), Some(&bottom));

    // ---- descendants of `top` ----
    let down = LineageRepository::get_descendants_conn(&mut conn, &viewer, top, None, None)
        .await
        .expect("get_descendants over the lattice must finish inside the statement timeout");
    assert_eq!(down.claims.len(), total);
    assert_eq!(down.claims[&top].depth, 0);
    for (j, layer) in layers.iter().enumerate() {
        for c in layer {
            assert_eq!(
                down.claims[c].depth,
                d - j as i32,
                "L{} depth from top",
                j + 1
            );
        }
    }
    assert_eq!(down.claims[&bottom].depth, d + 1);
    assert!(!down.truncated);
    let down_short =
        LineageRepository::get_descendants_conn(&mut conn, &viewer, top, Some(d), None)
            .await
            .expect("descendants one layer short");
    assert!(down_short.truncated, "bottom lies past max_depth");
    assert_eq!(down_short.claims.len(), total - 1);
    assert!(!down_short.claims.contains_key(&bottom));

    let dids = LineageRepository::get_descendant_ids(&mut *conn, &viewer, top, None)
        .await
        .expect("get_descendant_ids over the lattice");
    assert_eq!(dids.len(), total);
    assert_eq!(dids.first(), Some(&top), "root first");
    assert_eq!(dids.last(), Some(&bottom));

    // ---- lowest common ancestor of two L1 claims ----
    // Both are one hop below every L2 claim; nothing is closer to both.
    let lca = LineageRepository::get_lca(&mut *conn, &viewer, layers[0][0], layers[0][1], None)
        .await
        .expect("get_lca over the lattice")
        .expect("the L1 claims share ancestors");
    assert!(layers[1].contains(&lca.ancestor_id), "an L2 claim");
    assert_eq!(
        (lca.depth_from_a, lca.depth_from_b, lca.total_depth),
        (1, 1, 2)
    );
}

/// Backlog f889c86f: a claim that is reached both by a shortcut AND, past
/// `max_depth`, by a long path is reported at its SHORTEST depth and does not
/// make the result truncated. The deduplicated walk must keep the minimum
/// depth per claim, as the path-enumerating walk's `DISTINCT ON (id) ...
/// ORDER BY id, depth` did.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_shortcut_keeps_the_shortest_depth_on_a_dense_dag(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (top, layers, bottom) =
        create_lattice(&pool, "shortcut", LATTICE_WIDTH, LATTICE_LAYERS).await;
    // top -> bottom directly: top is one hop from bottom, and d + 1 hops
    // along every lattice path.
    create_claim_edge(&pool, top, bottom, "supports").await;
    let d = LATTICE_LAYERS as i32;
    let total = LATTICE_WIDTH * LATTICE_LAYERS + 2;
    let mut conn = time_boxed_conn(&pool).await;

    // max_depth = d: every claim is within d of bottom once the shortcut
    // exists (top at 1, L_j at j), so nothing lies past the cut.
    let up = LineageRepository::get_lineage_conn(&mut conn, &viewer, bottom, Some(d), None)
        .await
        .expect("lineage with a shortcut");
    assert_eq!(up.claims.len(), total);
    assert_eq!(
        up.claims[&top].depth, 1,
        "top's shortest depth is the shortcut"
    );
    assert_eq!(up.claims[&layers[d as usize - 1][0]].depth, d);
    assert!(
        !up.truncated,
        "a claim reachable within max_depth is not a truncation witness, even when a \
         longer path to it runs past the cut"
    );
    assert_eq!(up.topological_order.last(), Some(&bottom));

    let down = LineageRepository::get_descendants_conn(&mut conn, &viewer, top, Some(d), None)
        .await
        .expect("descendants with a shortcut");
    assert_eq!(down.claims.len(), total);
    assert_eq!(down.claims[&bottom].depth, 1);
    assert!(!down.truncated);

    let lca = LineageRepository::get_lca(&mut *conn, &viewer, bottom, layers[0][0], Some(d))
        .await
        .expect("lca with a shortcut")
        .expect("L1 is an ancestor of bottom");
    assert_eq!(
        lca.ancestor_id, layers[0][0],
        "L1-0 is its own ancestor at depth 0"
    );
    assert_eq!((lca.depth_from_a, lca.depth_from_b), (1, 0));

    // Unbounded (default depth), so the long paths to top ARE walked: the
    // shortest depth must still win over them.
    let lca_top = LineageRepository::get_lca(&mut *conn, &viewer, bottom, top, None)
        .await
        .expect("lca of bottom and top")
        .expect("top is an ancestor of bottom");
    assert_eq!(lca_top.ancestor_id, top);
    assert_eq!(
        (lca_top.depth_from_a, lca_top.depth_from_b),
        (1, 0),
        "top is one hop from bottom through the shortcut"
    );

    // The same pair swapped, so the shortcut lies on the SECOND walk
    // (`ancestors_b`): each side must keep its own shortest depth.
    let lca_swapped = LineageRepository::get_lca(&mut *conn, &viewer, top, bottom, None)
        .await
        .expect("lca of top and bottom")
        .expect("top is an ancestor of bottom");
    assert_eq!(lca_swapped.ancestor_id, top);
    assert_eq!(
        (lca_swapped.depth_from_a, lca_swapped.depth_from_b),
        (0, 1),
        "top is one hop from bottom through the shortcut, from the second walk too"
    );

    // Ancestors first by shortest depth: top sorts with L1 (depth 1), just
    // before bottom, not first (where its lattice depth d + 1 would put it).
    let ids = LineageRepository::get_ancestor_ids(&mut *conn, &viewer, bottom, None)
        .await
        .expect("ancestor ids with a shortcut");
    assert_eq!(ids.len(), total);
    let depth_one = &ids[total - 1 - (LATTICE_WIDTH + 1)..total - 1];
    assert!(depth_one.contains(&top), "top is at depth 1: {ids:?}");
    assert_eq!(ids.last(), Some(&bottom));

    // Root first by shortest depth: bottom sorts with L_d (depth 1).
    let dids = LineageRepository::get_descendant_ids(&mut *conn, &viewer, top, None)
        .await
        .expect("descendant ids with a shortcut");
    assert_eq!(dids.len(), total);
    assert_eq!(dids.first(), Some(&top));
    assert!(
        dids[1..=LATTICE_WIDTH + 1].contains(&bottom),
        "bottom is at depth 1: {dids:?}"
    );
}

// ============================================================================
// Cycles: the walks end when no new claim is reached, not at the depth bound
// ============================================================================

/// A hub cycle with a tail: `root -> kid_i` and `kid_i -> root` for every
/// kid (all `supports`), plus `kid_0 -> tail -> end`. Every kid lies on a
/// 2-cycle through `root`.
///
/// Returns `(root, kids, tail, end)`.
async fn create_hub_cycle(pool: &PgPool, tag: &str, kids: usize) -> (Uuid, Vec<Uuid>, Uuid, Uuid) {
    let root = create_test_claim(pool, &format!("{tag} root"), 0.5).await;
    let mut ks = Vec::with_capacity(kids);
    for i in 0..kids {
        let k = create_test_claim(pool, &format!("{tag} kid {i}"), 0.5).await;
        create_claim_edge(pool, root, k, "supports").await;
        create_claim_edge(pool, k, root, "supports").await;
        ks.push(k);
    }
    let tail = create_test_claim(pool, &format!("{tag} tail"), 0.5).await;
    create_claim_edge(pool, ks[0], tail, "supports").await;
    let end = create_test_claim(pool, &format!("{tag} end"), 0.5).await;
    create_claim_edge(pool, tail, end, "supports").await;
    (root, ks, tail, end)
}

/// Kids on the hub cycle. Large enough that a walk which re-emits the cycle
/// at every depth does millions of rows of work at [`UNBOUNDED`].
const HUB_KIDS: usize = 200;

/// A depth bound no lineage reaches. The repository accepts any bound (the
/// provenance export CLI passes its `--max-depth` through uncapped), so a
/// walk's cost must not grow with it once the reachable claims are exhausted.
const UNBOUNDED: i32 = 1_000_000;

fn assert_unique(ids: &[Uuid], what: &str) {
    let set: std::collections::HashSet<&Uuid> = ids.iter().collect();
    assert_eq!(set.len(), ids.len(), "{what}: a claim is listed twice");
}

/// Review of backlog f889c86f: on a graph with cycles every lineage walk
/// stops as soon as a layer reaches no new claim, reports each claim once at
/// its exact shortest depth, and keeps `truncated` exact.
///
/// A walk without a visited set (the per-`(id, depth)` `UNION` form) is ended
/// on a cycle only by the depth bound: it re-emits every claim of the cycle at
/// every depth, about `HUB_KIDS` x `UNBOUNDED` rows here, and every call below
/// exceeds the 5 s statement timeout.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_walks_end_on_a_cycle_at_exact_depths(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (root, kids, tail, end) = create_hub_cycle(&pool, "cycle", HUB_KIDS).await;
    let total = HUB_KIDS + 3;
    let mut conn = time_boxed_conn(&pool).await;

    // ---- ancestors of `end`: tail 1, kid_0 2, root 3, the other kids 4 ----
    let up = LineageRepository::get_lineage_conn(&mut conn, &viewer, end, Some(UNBOUNDED), None)
        .await
        .expect("get_lineage on a cycle must end inside the statement timeout");
    assert_eq!(up.claims.len(), total);
    assert_eq!(up.claims[&end].depth, 0);
    assert_eq!(up.claims[&tail].depth, 1);
    assert_eq!(up.claims[&kids[0]].depth, 2);
    assert_eq!(up.claims[&root].depth, 3);
    for k in &kids[1..] {
        assert_eq!(up.claims[k].depth, 4, "a kid behind the root");
    }
    assert_eq!(up.max_depth_reached, 4);
    assert!(!up.truncated, "the cycle is exhausted, not cut");
    assert_unique(&up.topological_order, "ancestor topological order");
    assert_eq!(up.topological_order.len(), total);
    assert_eq!(up.topological_order.last(), Some(&end));

    // One layer short: the kids behind the root are past the cut.
    let short = LineageRepository::get_lineage_conn(&mut conn, &viewer, end, Some(3), None)
        .await
        .expect("lineage one layer short");
    assert!(
        short.truncated,
        "the kids behind the root lie past max_depth"
    );
    assert_eq!(short.claims.len(), 4);
    assert_eq!(short.max_depth_reached, 3);

    // The default bound, from a claim ON the cycle: root's parents are the
    // kids (each `kid -> root`), and root itself is not re-entered.
    let at_root = LineageRepository::get_lineage_conn(&mut conn, &viewer, root, None, None)
        .await
        .expect("lineage from a claim on the cycle");
    assert_eq!(at_root.claims.len(), HUB_KIDS + 1);
    assert_eq!(at_root.claims[&root].depth, 0);
    assert!(kids.iter().all(|k| at_root.claims[k].depth == 1));
    assert!(!at_root.truncated);

    let ids = LineageRepository::get_ancestor_ids(&mut *conn, &viewer, end, Some(UNBOUNDED))
        .await
        .expect("get_ancestor_ids on a cycle");
    assert_eq!(ids.len(), total);
    assert_unique(&ids, "ancestor ids");
    assert!(kids[1..].contains(&ids[0]), "the deepest ancestors first");
    assert_eq!(ids[total - 4..], [root, kids[0], tail, end]);

    // ---- descendants of `root`: kids 1, tail 2, end 3 ----
    let down =
        LineageRepository::get_descendants_conn(&mut conn, &viewer, root, Some(UNBOUNDED), None)
            .await
            .expect("get_descendants on a cycle must end inside the statement timeout");
    assert_eq!(down.claims.len(), total);
    assert_eq!(down.claims[&root].depth, 0);
    assert!(kids.iter().all(|k| down.claims[k].depth == 1));
    assert_eq!(down.claims[&tail].depth, 2);
    assert_eq!(down.claims[&end].depth, 3);
    assert_eq!(down.max_depth_reached, 3);
    assert!(!down.truncated);
    assert_unique(&down.topological_order, "descendant topological order");

    let down_short =
        LineageRepository::get_descendants_conn(&mut conn, &viewer, root, Some(2), None)
            .await
            .expect("descendants one layer short");
    assert!(down_short.truncated, "end lies past max_depth");
    assert_eq!(down_short.claims.len(), total - 1);
    assert!(!down_short.claims.contains_key(&end));

    let dids = LineageRepository::get_descendant_ids(&mut *conn, &viewer, root, Some(UNBOUNDED))
        .await
        .expect("get_descendant_ids on a cycle");
    assert_eq!(dids.len(), total);
    assert_unique(&dids, "descendant ids");
    assert_eq!(dids.first(), Some(&root));
    assert_eq!(dids[total - 2..], [tail, end]);

    // ---- lowest common ancestor across the cycle ----
    // Both walks run through the whole cycle; `tail` is the only common
    // ancestor at total depth 1 (end -> tail, tail itself).
    let lca = LineageRepository::get_lca(&mut *conn, &viewer, end, tail, Some(UNBOUNDED))
        .await
        .expect("get_lca on a cycle must end inside the statement timeout")
        .expect("tail is an ancestor of end");
    assert_eq!(lca.ancestor_id, tail);
    assert_eq!((lca.depth_from_a, lca.depth_from_b), (1, 0));
    // And with the pair swapped, so the long walk is the second one.
    let lca = LineageRepository::get_lca(&mut *conn, &viewer, kids[1], end, Some(UNBOUNDED))
        .await
        .expect("get_lca on a cycle, swapped")
        .expect("root is an ancestor of both");
    assert_eq!(
        lca.total_depth, 4,
        "kid_1 <- root (1) and end <- tail <- kid_0 <- root (3)"
    );
}

// ============================================================================
// `get_depth` and `detect_cycles`: bounded by the claims and edges reached
// ============================================================================

/// Backlog c07884a9: `get_depth` and `detect_cycles` finish on the dense
/// lattice, and answer exactly: every path from `bottom` to `top` has
/// `LATTICE_LAYERS + 1` hops, and the lattice has no cycle.
///
/// The path-enumerating forms (`UNION ALL` plus a path array, guarded only by
/// `NOT c.id = ANY(path)`) walk all 4^12 paths, and each call here exceeds the
/// 5 s statement timeout (SQLSTATE 57014).
#[sqlx::test(migrations = "../../migrations")]
async fn depth_and_cycle_check_finish_on_a_dense_dag(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (top, layers, bottom) = create_lattice(&pool, "dense", LATTICE_WIDTH, LATTICE_LAYERS).await;
    let d = LATTICE_LAYERS as i32;
    let mut conn = time_boxed_conn(&pool).await;

    let depth = LineageRepository::get_depth(&mut *conn, &viewer, bottom)
        .await
        .expect("get_depth over the lattice must finish inside the statement timeout");
    assert_eq!(depth, d + 1, "bottom -> L1 -> ... -> L12 -> top");
    let depth = LineageRepository::get_depth(&mut *conn, &viewer, layers[0][0])
        .await
        .expect("get_depth from an L1 claim");
    assert_eq!(depth, d, "L1 -> ... -> L12 -> top");
    let depth = LineageRepository::get_depth(&mut *conn, &viewer, top)
        .await
        .expect("get_depth from the top");
    assert_eq!(depth, 0, "top has no parents");

    // Every claim of the lattice is reached many times over, so a check that
    // calls "reached an already-visited claim" a cycle answers `true` here.
    let has_cycle = LineageRepository::detect_cycles(&mut *conn, &viewer, bottom)
        .await
        .expect("detect_cycles over the lattice must finish inside the statement timeout");
    assert!(!has_cycle, "a dense DAG has no cycle");

    // The full walk over the same DAG carries the same answer.
    let up = LineageRepository::get_lineage_conn(&mut conn, &viewer, bottom, None, None)
        .await
        .expect("get_lineage over the lattice");
    assert!(!up.cycle_detected, "a dense DAG has no cycle");
    let down = LineageRepository::get_descendants_conn(&mut conn, &viewer, top, None, None)
        .await
        .expect("get_descendants over the lattice");
    assert!(!down.cycle_detected, "a dense DAG has no cycle");
}

/// Backlog c07884a9: `get_depth` is the LONGEST chain of parents, not the
/// shortest. `root`'s ancestors are the chain `root <- a <- b <- c` plus the
/// shortcut `root <- c`: `c` is one hop away by the shortcut and three by the
/// chain, so the depth is 3 (a walk that reports its deepest SHORTEST depth
/// answers 1).
#[sqlx::test(migrations = "../../migrations")]
async fn get_depth_is_the_longest_chain_past_a_shortcut(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let root = create_test_claim(&pool, "depth root", 0.5).await;
    let a = create_test_claim(&pool, "depth a", 0.5).await;
    let b = create_test_claim(&pool, "depth b", 0.5).await;
    let c = create_test_claim(&pool, "depth c", 0.5).await;
    create_claim_edge(&pool, a, root, "supports").await;
    create_claim_edge(&pool, b, a, "supports").await;
    create_claim_edge(&pool, c, b, "supports").await;
    create_claim_edge(&pool, c, root, "supports").await;
    // A second edge on the same pair must not count twice.
    create_claim_edge(&pool, c, root, "elaborates").await;

    let depth = LineageRepository::get_depth(&pool, &viewer, root)
        .await
        .expect("get_depth");
    assert_eq!(depth, 3, "root <- a <- b <- c, past the shortcut root <- c");
    assert!(!LineageRepository::detect_cycles(&pool, &viewer, root)
        .await
        .expect("detect_cycles"));

    // A claim that does not exist has no lineage.
    let depth = LineageRepository::get_depth(&pool, &viewer, Uuid::new_v4())
        .await
        .expect("get_depth of a missing claim");
    assert_eq!(depth, 0);
}

/// Backlog c07884a9: on a cycle that does NOT pass through the start,
/// `detect_cycles` answers `true` and `get_depth` counts the cycle as one
/// step. `root <- a <- {b <-> c} <- d`: the chain of parents is root, a, the
/// cycle {b, c}, d, so the depth is 3.
#[sqlx::test(migrations = "../../migrations")]
async fn cycle_behind_the_start_is_detected_and_counted_once(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let root = create_test_claim(&pool, "cyc root", 0.5).await;
    let a = create_test_claim(&pool, "cyc a", 0.5).await;
    let b = create_test_claim(&pool, "cyc b", 0.5).await;
    let c = create_test_claim(&pool, "cyc c", 0.5).await;
    let d = create_test_claim(&pool, "cyc d", 0.5).await;
    create_claim_edge(&pool, a, root, "supports").await;
    create_claim_edge(&pool, b, a, "supports").await;
    create_claim_edge(&pool, c, b, "supports").await;
    create_claim_edge(&pool, b, c, "supports").await;
    create_claim_edge(&pool, d, c, "supports").await;

    assert!(LineageRepository::detect_cycles(&pool, &viewer, root)
        .await
        .expect("detect_cycles"));
    assert_eq!(
        LineageRepository::get_depth(&pool, &viewer, root)
            .await
            .expect("get_depth"),
        3,
        "root, a, the cycle {{b, c}} as one step, d"
    );
    // From `d`, which nothing derives from, there is neither.
    assert!(!LineageRepository::detect_cycles(&pool, &viewer, d)
        .await
        .expect("detect_cycles from d"));

    let up = LineageRepository::get_lineage(&pool, &viewer, root, None, None)
        .await
        .expect("get_lineage");
    assert_eq!(up.claims.len(), 5);
    assert!(up.cycle_detected, "b <-> c lies among the returned claims");
    // Capped to the target and its nearest ancestor, the cycle is gone.
    let capped = LineageRepository::get_lineage(&pool, &viewer, root, None, Some(2))
        .await
        .expect("get_lineage, capped");
    assert!(capped.truncated);
    assert!(
        !capped.cycle_detected,
        "the flag describes the returned claims, and {{root, a}} has no cycle"
    );
}

/// Backlog c07884a9: `cycle_detected` and `detect_cycles` are real on the hub
/// cycle (every kid on a 2-cycle through the root, reached from `end`, which
/// is on no cycle), and both finish inside the statement timeout.
///
/// Before this fix `cycle_detected` was `false` by construction on every
/// walk.
#[sqlx::test(migrations = "../../migrations")]
async fn cycle_detected_is_set_on_the_hub_cycle(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (root, _kids, tail, end) = create_hub_cycle(&pool, "hub", HUB_KIDS).await;
    let mut conn = time_boxed_conn(&pool).await;

    assert!(LineageRepository::detect_cycles(&mut *conn, &viewer, end)
        .await
        .expect("detect_cycles on the hub cycle"));
    // end <- tail <- {root and every kid, kid_0 included}: the cycle is one
    // step, so the depth is 2.
    assert_eq!(
        LineageRepository::get_depth(&mut *conn, &viewer, end)
            .await
            .expect("get_depth on the hub cycle"),
        2
    );

    let up = LineageRepository::get_lineage_conn(&mut conn, &viewer, end, Some(UNBOUNDED), None)
        .await
        .expect("get_lineage on the hub cycle");
    assert!(up.cycle_detected, "every kid is on a 2-cycle through root");
    // Stopped before the root, the walk returns end, tail and kid_0 only.
    let short = LineageRepository::get_lineage_conn(&mut conn, &viewer, end, Some(2), None)
        .await
        .expect("get_lineage before the root");
    assert_eq!(short.claims.len(), 3);
    assert!(!short.cycle_detected, "no cycle among end, tail and kid_0");

    let down =
        LineageRepository::get_descendants_conn(&mut conn, &viewer, root, Some(UNBOUNDED), None)
            .await
            .expect("get_descendants on the hub cycle");
    assert!(
        down.cycle_detected,
        "every kid is on a 2-cycle through root"
    );
    let below =
        LineageRepository::get_descendants_conn(&mut conn, &viewer, tail, Some(UNBOUNDED), None)
            .await
            .expect("get_descendants below the cycle");
    assert!(!below.cycle_detected, "tail -> end is a chain");
}

/// Backlog c07884a9: an edge the viewer cannot read cannot close a cycle.
/// `a -> b` is public; the back edge `b -> a` belongs to a group, so only a
/// member sees the cycle, and for anyone else the answer reveals nothing
/// about the private edge.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cycle_closed_by_an_unreadable_edge_is_not_reported(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "cycle-edge-owner").await;
    let public = fixture::public_viewer(&pool).await;
    let member = epigraph_db::visibility::Viewer::resolve(&pool, owner)
        .await
        .expect("resolve member");
    let a = fixture::seed_public_claim(&pool, owner, "vis a").await;
    let b = fixture::seed_public_claim(&pool, owner, "vis b").await;
    create_claim_edge(&pool, a, b, "supports").await;
    fixture::seed_edge_owned_by(&pool, b, a, "group", group).await;

    assert!(LineageRepository::detect_cycles(&pool, &member, b)
        .await
        .expect("detect_cycles, member"));
    assert!(!LineageRepository::detect_cycles(&pool, &public, b)
        .await
        .expect("detect_cycles, public"));
    assert_eq!(
        LineageRepository::get_depth(&pool, &public, b)
            .await
            .expect("get_depth, public"),
        1,
        "b <- a over the public edge only"
    );
}
