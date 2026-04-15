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
    let claim = ClaimRepository::create(pool, &claim).await.unwrap();
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
    // Setup: Create a single claim with no parents
    let claim_id = create_test_claim(&pool, "Standalone claim with no ancestors", 0.75).await;

    // Execute: Query lineage
    let lineage = LineageRepository::get_lineage(&pool, claim_id, None)
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
    // Setup: Create parent and child claims
    let parent_id = create_test_claim(&pool, "Parent claim", 0.8).await;
    let child_id = create_test_claim(&pool, "Child claim derived from parent", 0.7).await;

    // Create edge: parent supports child
    create_claim_edge(&pool, parent_id, child_id, "supports").await;

    // Execute: Query lineage from child
    let lineage = LineageRepository::get_lineage(&pool, child_id, None)
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
    // Setup: Create chain of 7 claims (0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6)
    let chain = create_claim_chain(&pool, 7).await;

    // Execute: Query lineage from the leaf (last) claim
    let leaf_id = *chain.last().unwrap();
    let lineage = LineageRepository::get_lineage(&pool, leaf_id, None)
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
    // Setup: Create agent and 3 claims with evidence at each level
    let agent = make_agent(Some("Evidence Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    let root_claim = make_claim(agent.id, "Root claim with evidence", 0.9);
    let root_claim = ClaimRepository::create(&pool, &root_claim).await.unwrap();
    let root_id = root_claim.id.as_uuid();

    let middle_claim = make_claim(agent.id, "Middle claim with evidence", 0.8);
    let middle_claim = ClaimRepository::create(&pool, &middle_claim).await.unwrap();
    let middle_id = middle_claim.id.as_uuid();

    let leaf_claim = make_claim(agent.id, "Leaf claim with evidence", 0.7);
    let leaf_claim = ClaimRepository::create(&pool, &leaf_claim).await.unwrap();
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
    let lineage = LineageRepository::get_lineage(&pool, leaf_id, None)
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
    // Setup: Create agent and claims with reasoning traces
    let agent = make_agent(Some("Trace Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    let root_claim = make_claim(agent.id, "Root claim", 0.85);
    let root_claim = ClaimRepository::create(&pool, &root_claim).await.unwrap();
    let root_id = root_claim.id.as_uuid();

    let child_claim = make_claim(agent.id, "Child claim", 0.75);
    let child_claim = ClaimRepository::create(&pool, &child_claim).await.unwrap();
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
    let lineage = LineageRepository::get_lineage(&pool, child_id, None)
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
    // Setup: Create chain of 5 claims
    let chain = create_claim_chain(&pool, 5).await;

    // Execute: Query lineage with max_depth=2
    let leaf_id = *chain.last().unwrap();
    let lineage = LineageRepository::get_lineage(&pool, leaf_id, Some(2))
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
    let lineage = LineageRepository::get_lineage(&pool, d_id, None)
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
    let lineage = LineageRepository::get_lineage(&pool, leaf_id, None)
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
    // Setup: Create a cycle (A -> B -> C -> A)
    let a_id = create_test_claim(&pool, "Claim A in cycle", 0.7).await;
    let b_id = create_test_claim(&pool, "Claim B in cycle", 0.7).await;
    let c_id = create_test_claim(&pool, "Claim C in cycle", 0.7).await;

    // Create cycle edges (this violates DAG invariant!)
    create_claim_edge(&pool, a_id, b_id, "supports").await;
    create_claim_edge(&pool, b_id, c_id, "supports").await;
    create_claim_edge(&pool, c_id, a_id, "supports").await;

    // Execute: Detect cycles
    let has_cycle = LineageRepository::detect_cycles(&pool, a_id)
        .await
        .expect("Failed to detect cycles");

    // Verify: Cycle should be detected
    assert!(has_cycle, "Cycle should be detected in A -> B -> C -> A");

    // Query lineage should still work (with cycle detection)
    let lineage = LineageRepository::get_lineage(&pool, a_id, Some(10))
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
    let lineage = LineageRepository::get_lineage(&pool, f_id, None)
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
    // Setup: Two independent roots both supporting one claim
    let root1_id = create_test_claim(&pool, "Independent root 1", 0.9).await;
    let root2_id = create_test_claim(&pool, "Independent root 2", 0.85).await;
    let leaf_id = create_test_claim(&pool, "Leaf with two roots", 0.8).await;

    create_claim_edge(&pool, root1_id, leaf_id, "supports").await;
    create_claim_edge(&pool, root2_id, leaf_id, "supports").await;

    // Execute
    let lineage = LineageRepository::get_lineage(&pool, leaf_id, None)
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
    let lineage = LineageRepository::get_lineage(&pool, leaf_id, None)
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
    // Execute: Query lineage for a UUID that doesn't exist
    let nonexistent_id = Uuid::new_v4();
    let lineage = LineageRepository::get_lineage(&pool, nonexistent_id, None)
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

/// Test: Lineage with mixed relationship types
///
/// **Evidence**: Different edge relationships should all be traversed
/// **Reasoning**: Provenance includes supports, derives_from, etc.
#[sqlx::test(migrations = "../../migrations")]
async fn test_lineage_with_mixed_relationship_types(pool: PgPool) {
    // Setup: Claims with different relationship types
    let source_id = create_test_claim(&pool, "Source claim", 0.9).await;
    let derived_id = create_test_claim(&pool, "Derived claim", 0.8).await;
    let refined_id = create_test_claim(&pool, "Refined claim", 0.85).await;
    let final_id = create_test_claim(&pool, "Final claim", 0.7).await;

    // Different relationship types
    create_claim_edge(&pool, source_id, derived_id, "supports").await;
    create_claim_edge(&pool, source_id, refined_id, "refines").await;
    create_claim_edge(&pool, derived_id, final_id, "derives_from").await;
    create_claim_edge(&pool, refined_id, final_id, "supports").await;

    // Execute
    let lineage = LineageRepository::get_lineage(&pool, final_id, None)
        .await
        .expect("Failed to query lineage");

    // Verify: All claims included regardless of relationship type
    assert_eq!(lineage.claims.len(), 4);
    assert!(lineage.claims.contains_key(&source_id));
    assert!(lineage.claims.contains_key(&derived_id));
    assert!(lineage.claims.contains_key(&refined_id));
    assert!(lineage.claims.contains_key(&final_id));
}
