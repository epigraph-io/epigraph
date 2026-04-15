//! Propagation Integration Tests
//!
//! These integration tests verify that the `PropagationOrchestrator` correctly
//! triggers truth propagation when claims are submitted or updated, and that
//! truth values cascade properly through the reasoning DAG.
//!
//! # Expected Flow
//!
//! ```text
//! Submit Claim → Calculate Initial Truth → Persist Claim →
//! Trigger Propagation → Update Dependents → Persist Updates
//! ```
//!
//! # Key Scenarios Tested
//!
//! 1. Claim submission triggers propagation to dependents
//! 2. Truth values cascade through multi-level DAGs
//! 3. Evidence weighting affects propagation strength
//! 4. Bayesian update formula is correctly applied
//! 5. Propagation stops at convergence threshold
//! 6. Cycles are handled gracefully (no infinite loops)
//! 7. Updates are persisted (simulated via in-memory state)
//! 8. Audit trail records all propagation events
//! 9. Leaf claims (no dependents) complete immediately
//! 10. Deep graphs handled gracefully via BFS (visited set prevents infinite loops)
//! 11. Concurrent propagations maintain state integrity
//! 12. Manual API triggering works correctly
//! 13. Truth values stay within [0.0, 1.0] bounds
//! 14. BAD ACTOR: High-reputation agents cannot inflate dependent truths
//!
//! # Critical Invariants
//!
//! - Agent reputation is NEVER used in propagation calculations
//! - Truth values are always bounded [0.01, 0.99]
//! - DAG must remain acyclic (cycles rejected at dependency creation)
//! - Each node is visited at most once during propagation (BFS + visited set)

use epigraph_core::{AgentId, Claim, ClaimId, TruthValue};
#[allow(deprecated)]
use epigraph_engine::BayesianUpdater;
use epigraph_engine::{
    ConcurrentOrchestrator, EngineError, PropagationAuditRecord, PropagationOrchestrator,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create a test claim with the given truth value
fn create_test_claim(truth: f64) -> Claim {
    let agent_id = AgentId::new();
    Claim::new(
        format!("Test claim with truth {truth}"),
        agent_id,
        [0u8; 32], // public_key
        TruthValue::new(truth).unwrap(),
    )
}

/// Create a test claim with a specific agent
fn create_claim_with_agent(truth: f64, agent_id: AgentId) -> Claim {
    Claim::new(
        format!("Claim by agent with truth {truth}"),
        agent_id,
        [0u8; 32], // public_key
        TruthValue::new(truth).unwrap(),
    )
}

/// Simulates the full claim submission flow with propagation
///
/// This represents the expected integration behavior:
/// 1. Claim is created with initial truth
/// 2. Claim is registered in the orchestrator
/// 3. Dependencies are established
/// 4. Propagation is triggered
/// 5. Updates are "persisted" (tracked in state)
struct IntegrationTestHarness {
    orchestrator: PropagationOrchestrator,
    /// Simulated "database" of persisted truth values
    persisted_truth_values: HashMap<ClaimId, TruthValue>,
    /// Track all persisted updates for verification
    persist_log: Vec<(ClaimId, TruthValue)>,
}

impl IntegrationTestHarness {
    fn new() -> Self {
        Self {
            orchestrator: PropagationOrchestrator::new(),
            persisted_truth_values: HashMap::new(),
            persist_log: Vec::new(),
        }
    }

    /// Submit a new claim (mimics the full API flow)
    fn submit_claim(&mut self, claim: Claim) -> Result<ClaimId, EngineError> {
        let claim_id = claim.id;
        let initial_truth = claim.truth_value;

        // Step 1: Register claim in orchestrator
        self.orchestrator.register_claim(claim)?;

        // Step 2: Persist initial truth value (simulated)
        self.persisted_truth_values.insert(claim_id, initial_truth);
        self.persist_log.push((claim_id, initial_truth));

        Ok(claim_id)
    }

    /// Add a dependency between claims
    ///
    /// Uses default evidence type (Empirical) and no temporal decay for simplicity.
    /// For tests that need specific evidence types, use `add_dependency_with_evidence`.
    fn add_dependency(
        &mut self,
        source_id: ClaimId,
        dependent_id: ClaimId,
        is_supporting: bool,
        strength: f64,
    ) -> Result<(), EngineError> {
        use epigraph_engine::EvidenceType;
        self.orchestrator.add_dependency(
            source_id,
            dependent_id,
            is_supporting,
            strength,
            EvidenceType::Empirical, // Default to strongest evidence type
            0.0,                     // No temporal decay
        )
    }

    /// Add a dependency with specific evidence type and age
    #[allow(dead_code)]
    fn add_dependency_with_evidence(
        &mut self,
        source_id: ClaimId,
        dependent_id: ClaimId,
        is_supporting: bool,
        strength: f64,
        evidence_type: epigraph_engine::EvidenceType,
        age_days: f64,
    ) -> Result<(), EngineError> {
        self.orchestrator.add_dependency(
            source_id,
            dependent_id,
            is_supporting,
            strength,
            evidence_type,
            age_days,
        )
    }

    /// Update a claim and trigger propagation (the key integration point)
    fn update_claim_and_propagate(
        &mut self,
        claim_id: ClaimId,
        new_truth: TruthValue,
    ) -> Result<HashSet<ClaimId>, EngineError> {
        // Trigger propagation
        let updated_claims = self
            .orchestrator
            .update_and_propagate(claim_id, new_truth)?;

        // Persist the source claim update
        self.persisted_truth_values.insert(claim_id, new_truth);
        self.persist_log.push((claim_id, new_truth));

        // Persist all dependent updates (simulates database writes)
        for &updated_id in &updated_claims {
            if let Some(truth) = self.orchestrator.get_truth(updated_id) {
                self.persisted_truth_values.insert(updated_id, truth);
                self.persist_log.push((updated_id, truth));
            }
        }

        Ok(updated_claims)
    }

    /// Get persisted truth value (simulates database read)
    fn get_persisted_truth(&self, claim_id: ClaimId) -> Option<TruthValue> {
        self.persisted_truth_values.get(&claim_id).copied()
    }

    /// Get the audit trail
    fn get_audit_trail(&self) -> &[PropagationAuditRecord] {
        self.orchestrator.get_audit_trail()
    }

    /// Get persist log for verification
    fn get_persist_log(&self) -> &[(ClaimId, TruthValue)] {
        &self.persist_log
    }

    /// Register an agent with reputation
    fn register_agent(&mut self, agent_id: AgentId, reputation: f64) {
        self.orchestrator.register_agent(agent_id, reputation);
    }
}

// ============================================================================
// Test 1: Submitting Claim Triggers Propagation to Dependent Claims
// ============================================================================

#[test]
fn test_submit_claim_triggers_propagation_to_dependents() {
    let mut harness = IntegrationTestHarness::new();

    // Create source claim (initially at uncertainty)
    let source = create_test_claim(0.5);
    let source_id = harness.submit_claim(source).unwrap();

    // Create dependent claims
    let dep1 = create_test_claim(0.5);
    let dep2 = create_test_claim(0.5);
    let dep1_id = harness.submit_claim(dep1).unwrap();
    let dep2_id = harness.submit_claim(dep2).unwrap();

    // Establish dependencies
    harness
        .add_dependency(source_id, dep1_id, true, 0.8)
        .unwrap();
    harness
        .add_dependency(source_id, dep2_id, true, 0.7)
        .unwrap();

    // Update source claim - this MUST trigger propagation
    let updated = harness
        .update_claim_and_propagate(source_id, TruthValue::new(0.9).unwrap())
        .unwrap();

    // Verify propagation was triggered
    assert!(
        updated.contains(&dep1_id),
        "Dependent 1 should be updated by propagation"
    );
    assert!(
        updated.contains(&dep2_id),
        "Dependent 2 should be updated by propagation"
    );

    // Verify truth values increased (supporting evidence)
    let dep1_truth = harness.get_persisted_truth(dep1_id).unwrap().value();
    let dep2_truth = harness.get_persisted_truth(dep2_id).unwrap().value();

    assert!(
        dep1_truth > 0.5,
        "Dependent 1 truth should increase from propagation. Got: {dep1_truth}"
    );
    assert!(
        dep2_truth > 0.5,
        "Dependent 2 truth should increase from propagation. Got: {dep2_truth}"
    );
}

// ============================================================================
// Test 2: Truth Value Change Cascades Through DAG
// ============================================================================

#[test]
fn test_truth_value_cascades_through_dag() {
    let mut harness = IntegrationTestHarness::new();

    // Create a 4-level DAG: A -> B -> C -> D
    let claims: Vec<_> = (0..4).map(|_| create_test_claim(0.5)).collect();
    let mut ids = Vec::new();

    for claim in claims {
        ids.push(harness.submit_claim(claim).unwrap());
    }

    // Create chain dependencies
    for i in 0..3 {
        harness
            .add_dependency(ids[i], ids[i + 1], true, 0.8)
            .unwrap();
    }

    // Update the root claim
    let updated = harness
        .update_claim_and_propagate(ids[0], TruthValue::new(0.95).unwrap())
        .unwrap();

    // Verify ALL downstream claims were updated
    assert_eq!(
        updated.len(),
        3,
        "All 3 downstream claims should be updated"
    );
    for &id in &ids[1..] {
        assert!(updated.contains(&id), "Claim {id:?} should be in cascade");
    }

    // Verify truth propagated through all levels
    let root_truth = harness.get_persisted_truth(ids[0]).unwrap().value();
    let level1_truth = harness.get_persisted_truth(ids[1]).unwrap().value();
    let level2_truth = harness.get_persisted_truth(ids[2]).unwrap().value();
    let level3_truth = harness.get_persisted_truth(ids[3]).unwrap().value();

    assert!(
        root_truth > level1_truth || (root_truth - level1_truth).abs() < 0.15,
        "Truth should propagate with decay. Root: {root_truth}, L1: {level1_truth}"
    );
    assert!(
        level1_truth > 0.5,
        "Level 1 should be above uncertainty: {level1_truth}"
    );
    assert!(
        level2_truth > 0.5,
        "Level 2 should be above uncertainty: {level2_truth}"
    );
    assert!(
        level3_truth > 0.5,
        "Level 3 should be above uncertainty: {level3_truth}"
    );

    // Verify cascade order in audit trail
    let audit = harness.get_audit_trail();
    assert_eq!(audit.len(), 3, "Should have 3 audit records for cascade");

    // Sequence numbers should be in order
    for i in 0..audit.len() - 1 {
        assert!(
            audit[i].sequence_number < audit[i + 1].sequence_number,
            "Audit records should be in cascade order"
        );
    }
}

// ============================================================================
// Test 3: Propagation Respects Evidence Weighting
// ============================================================================

#[test]
fn test_propagation_respects_evidence_weighting() {
    let mut harness = IntegrationTestHarness::new();

    // Create source claim
    let source = create_test_claim(0.5);
    let source_id = harness.submit_claim(source).unwrap();

    // Create two dependents with VERY different evidence strengths
    let weak_dep = create_test_claim(0.5);
    let strong_dep = create_test_claim(0.5);
    let weak_id = harness.submit_claim(weak_dep).unwrap();
    let strong_id = harness.submit_claim(strong_dep).unwrap();

    // Weak evidence (0.1) vs Strong evidence (0.95)
    harness
        .add_dependency(source_id, weak_id, true, 0.1)
        .unwrap();
    harness
        .add_dependency(source_id, strong_id, true, 0.95)
        .unwrap();

    // Update source to high truth
    harness
        .update_claim_and_propagate(source_id, TruthValue::new(0.9).unwrap())
        .unwrap();

    // Strong evidence should have larger effect
    let weak_truth = harness.get_persisted_truth(weak_id).unwrap().value();
    let strong_truth = harness.get_persisted_truth(strong_id).unwrap().value();

    assert!(
        strong_truth > weak_truth,
        "Strong evidence ({strong_truth}) should produce larger update than weak evidence ({weak_truth})"
    );

    // Both should still increase (supporting evidence)
    assert!(
        weak_truth > 0.5,
        "Weak evidence should still increase truth"
    );
    assert!(
        strong_truth > 0.5,
        "Strong evidence should increase truth more"
    );

    // The difference should be meaningful (new influence formula: ~0.038 for 0.1 vs 0.95 strength)
    let difference = strong_truth - weak_truth;
    assert!(
        difference > 0.03,
        "Difference between strong and weak should be significant. Got: {difference}"
    );
}

// ============================================================================
// Test 4: Propagation Uses Proportional Influence Formula
// ============================================================================

/// Tests that propagation now uses the proportional influence model rather than
/// the deprecated non-commutative Bayesian update formula.
///
/// Formula: influence = EvidenceWeighter output (type * relevance * source_truth * decay)
///          supporting: posterior = prior + influence * (1 - prior) * 0.1
///          refuting:   posterior = prior - influence * prior * 0.1
#[test]
fn test_propagation_uses_influence_formula() {
    let mut harness = IntegrationTestHarness::new();

    // Create source and dependent
    let source = create_test_claim(0.5);
    let dependent = create_test_claim(0.5);
    let source_id = harness.submit_claim(source).unwrap();
    let dep_id = harness.submit_claim(dependent).unwrap();

    let evidence_strength = 0.8;
    harness
        .add_dependency(source_id, dep_id, true, evidence_strength)
        .unwrap();

    // Update source
    let new_source_truth = TruthValue::new(0.9).unwrap();
    harness
        .update_claim_and_propagate(source_id, new_source_truth)
        .unwrap();

    // Calculate expected posterior using the new influence formula:
    // evidence_weight = Empirical(1.0) * strength(0.8) * source_truth(0.9) = 0.72
    // posterior = 0.5 + 0.72 * (1.0 - 0.5) * 0.1 = 0.536
    let prior = 0.5_f64;
    let influence = 1.0_f64 * evidence_strength * new_source_truth.value(); // Empirical base = 1.0
    let expected_posterior = prior + influence * (1.0 - prior) * 0.1;

    let actual_posterior = harness.get_persisted_truth(dep_id).unwrap();

    // Should match the influence formula result
    let tolerance = 1e-10;
    assert!(
        (actual_posterior.value() - expected_posterior).abs() < tolerance,
        "Propagation should use influence formula. Expected: {expected_posterior}, Got: {}",
        actual_posterior.value()
    );
}

// ============================================================================
// Test 5: Propagation Stops at Convergence Threshold
// ============================================================================

#[test]
fn test_propagation_stops_at_convergence() {
    let mut harness = IntegrationTestHarness::new();

    // Create a chain to test convergence behavior
    let chain_length = 5;
    let mut ids = Vec::new();

    for _ in 0..chain_length {
        let claim = create_test_claim(0.5);
        ids.push(harness.submit_claim(claim).unwrap());
    }

    // Create chain with moderate evidence strength
    for i in 0..chain_length - 1 {
        harness
            .add_dependency(ids[i], ids[i + 1], true, 0.6)
            .unwrap();
    }

    // First propagation - collect truth values
    harness
        .update_claim_and_propagate(ids[0], TruthValue::new(0.7).unwrap())
        .unwrap();

    let first_values: Vec<f64> = ids
        .iter()
        .map(|id| harness.get_persisted_truth(*id).unwrap().value())
        .collect();

    // Second propagation with same value
    harness.orchestrator.clear_audit_trail();
    harness
        .update_claim_and_propagate(ids[0], TruthValue::new(0.7).unwrap())
        .unwrap();

    let second_values: Vec<f64> = ids
        .iter()
        .map(|id| harness.get_persisted_truth(*id).unwrap().value())
        .collect();

    // Third propagation
    harness.orchestrator.clear_audit_trail();
    harness
        .update_claim_and_propagate(ids[0], TruthValue::new(0.7).unwrap())
        .unwrap();

    let third_values: Vec<f64> = ids
        .iter()
        .map(|id| harness.get_persisted_truth(*id).unwrap().value())
        .collect();

    // Key convergence property: as values approach max_truth (0.99),
    // the rate of change should diminish
    let change_1_to_2: f64 = second_values
        .iter()
        .zip(&first_values)
        .map(|(s, f)| (s - f).abs())
        .sum();

    let change_2_to_3: f64 = third_values
        .iter()
        .zip(&second_values)
        .map(|(t, s)| (t - s).abs())
        .sum();

    // The rate of change should decrease (convergence)
    // OR the values should be very close to maximum (already converged)
    let converging = change_2_to_3 <= change_1_to_2 + 0.01;
    let already_at_max = third_values.iter().all(|v| *v > 0.9);

    assert!(
        converging || already_at_max,
        "System should converge: change_1_to_2={change_1_to_2}, change_2_to_3={change_2_to_3}, values={third_values:?}"
    );

    // All values should stay bounded (never exceed max_truth)
    for &value in &third_values {
        assert!(
            value <= 0.99,
            "Truth should never exceed max_truth (0.99). Got: {value}"
        );
    }
}

// ============================================================================
// Test 6: Propagation Handles Cycles Gracefully (No Infinite Loop)
// ============================================================================

#[test]
fn test_propagation_handles_cycles_gracefully() {
    let mut harness = IntegrationTestHarness::new();

    // Create claims
    let claim_a = create_test_claim(0.5);
    let claim_b = create_test_claim(0.5);
    let id_a = harness.submit_claim(claim_a).unwrap();
    let id_b = harness.submit_claim(claim_b).unwrap();

    // A -> B is valid
    harness.add_dependency(id_a, id_b, true, 0.8).unwrap();

    // B -> A would create a cycle - should be REJECTED
    let result = harness.add_dependency(id_b, id_a, true, 0.8);
    assert!(
        matches!(result, Err(EngineError::CycleDetected { .. })),
        "Cycle should be rejected at dependency creation time"
    );

    // Propagation should still work for valid edges
    let updated = harness
        .update_claim_and_propagate(id_a, TruthValue::new(0.8).unwrap())
        .unwrap();

    assert!(
        updated.contains(&id_b),
        "Valid dependency should still propagate"
    );
}

#[test]
fn test_diamond_dag_no_duplicate_updates() {
    let mut harness = IntegrationTestHarness::new();

    // Create diamond: A -> B, A -> C, B -> D, C -> D
    let claim_a = create_test_claim(0.5);
    let claim_b = create_test_claim(0.5);
    let claim_c = create_test_claim(0.5);
    let claim_d = create_test_claim(0.5);

    let id_a = harness.submit_claim(claim_a).unwrap();
    let id_b = harness.submit_claim(claim_b).unwrap();
    let id_c = harness.submit_claim(claim_c).unwrap();
    let id_d = harness.submit_claim(claim_d).unwrap();

    harness.add_dependency(id_a, id_b, true, 0.8).unwrap();
    harness.add_dependency(id_a, id_c, true, 0.8).unwrap();
    harness.add_dependency(id_b, id_d, true, 0.8).unwrap();
    harness.add_dependency(id_c, id_d, true, 0.8).unwrap();

    // Update A
    let updated = harness
        .update_claim_and_propagate(id_a, TruthValue::new(0.9).unwrap())
        .unwrap();

    // D should only appear ONCE (not twice despite two paths)
    let d_count = updated.iter().filter(|&&id| id == id_d).count();
    assert_eq!(d_count, 1, "D should only be updated once in diamond DAG");

    // Audit trail should only have one record for D
    let d_audit_count = harness
        .get_audit_trail()
        .iter()
        .filter(|r| r.claim_id == id_d)
        .count();
    assert_eq!(d_audit_count, 1, "D should have exactly one audit record");
}

// ============================================================================
// Test 7: Propagation Updates Are Persisted to Database
// ============================================================================

#[test]
fn test_propagation_updates_are_persisted() {
    let mut harness = IntegrationTestHarness::new();

    // Create chain: A -> B -> C
    let claim_a = create_test_claim(0.5);
    let claim_b = create_test_claim(0.5);
    let claim_c = create_test_claim(0.5);

    let id_a = harness.submit_claim(claim_a).unwrap();
    let id_b = harness.submit_claim(claim_b).unwrap();
    let id_c = harness.submit_claim(claim_c).unwrap();

    harness.add_dependency(id_a, id_b, true, 0.8).unwrap();
    harness.add_dependency(id_b, id_c, true, 0.7).unwrap();

    // Trigger propagation
    harness
        .update_claim_and_propagate(id_a, TruthValue::new(0.85).unwrap())
        .unwrap();

    // Verify all claims have persisted truth values
    let persisted_a = harness.get_persisted_truth(id_a);
    let persisted_b = harness.get_persisted_truth(id_b);
    let persisted_c = harness.get_persisted_truth(id_c);

    assert!(persisted_a.is_some(), "Claim A should be persisted");
    assert!(persisted_b.is_some(), "Claim B should be persisted");
    assert!(persisted_c.is_some(), "Claim C should be persisted");

    // Verify persist log contains all updates
    let log = harness.get_persist_log();

    // Should have: initial A, initial B, initial C, update A, update B, update C
    assert!(log.len() >= 6, "Should have at least 6 persist entries");

    // Find the final updates (last entries for each claim)
    let final_a = log.iter().rev().find(|(id, _)| *id == id_a).unwrap().1;
    let final_b = log.iter().rev().find(|(id, _)| *id == id_b).unwrap().1;
    let final_c = log.iter().rev().find(|(id, _)| *id == id_c).unwrap().1;

    assert_eq!(
        final_a.value(),
        0.85,
        "A should be persisted with new truth"
    );
    assert!(
        final_b.value() > 0.5,
        "B should be persisted with updated truth"
    );
    assert!(
        final_c.value() > 0.5,
        "C should be persisted with updated truth"
    );
}

// ============================================================================
// Test 8: Propagation Audit Trail Is Recorded
// ============================================================================

#[test]
fn test_propagation_audit_trail_is_recorded() {
    let mut harness = IntegrationTestHarness::new();

    // Create A -> B (supporting) and B -> C (refuting)
    let claim_a = create_test_claim(0.5);
    let claim_b = create_test_claim(0.5);
    let claim_c = create_test_claim(0.6);

    let id_a = harness.submit_claim(claim_a).unwrap();
    let id_b = harness.submit_claim(claim_b).unwrap();
    let id_c = harness.submit_claim(claim_c).unwrap();

    harness.add_dependency(id_a, id_b, true, 0.8).unwrap(); // Supporting
    harness.add_dependency(id_b, id_c, false, 0.7).unwrap(); // Refuting

    // Trigger propagation
    harness
        .update_claim_and_propagate(id_a, TruthValue::new(0.9).unwrap())
        .unwrap();

    let audit = harness.get_audit_trail();

    // Should have exactly 2 audit records
    assert_eq!(audit.len(), 2, "Should have 2 audit records");

    // Find B's audit record
    let b_record = audit.iter().find(|r| r.claim_id == id_b).unwrap();
    assert_eq!(b_record.source_claim_id, id_a);
    assert!(b_record.is_supporting, "B should be marked as supporting");
    assert_eq!(b_record.prior_truth.value(), 0.5);
    assert!(
        b_record.posterior_truth.value() > 0.5,
        "B's truth should increase"
    );

    // Find C's audit record
    let c_record = audit.iter().find(|r| r.claim_id == id_c).unwrap();
    assert_eq!(c_record.source_claim_id, id_b);
    assert!(!c_record.is_supporting, "C should be marked as refuting");
    assert_eq!(c_record.prior_truth.value(), 0.6);
    assert!(
        c_record.posterior_truth.value() < 0.6,
        "C's truth should decrease from refutation"
    );

    // Verify sequence ordering
    assert!(
        b_record.sequence_number < c_record.sequence_number,
        "B should be updated before C"
    );
}

// ============================================================================
// Test 9: Propagation With No Dependents Completes Immediately
// ============================================================================

#[test]
fn test_propagation_with_no_dependents_completes_immediately() {
    let mut harness = IntegrationTestHarness::new();

    // Create a leaf claim (no dependents)
    let leaf = create_test_claim(0.5);
    let leaf_id = harness.submit_claim(leaf).unwrap();

    // Update the leaf
    let updated = harness
        .update_claim_and_propagate(leaf_id, TruthValue::new(0.8).unwrap())
        .unwrap();

    // No dependents should be updated
    assert!(
        updated.is_empty(),
        "Leaf claim should have no dependents to update"
    );

    // Audit trail should be empty (no propagation occurred)
    assert!(
        harness.get_audit_trail().is_empty(),
        "No audit records for leaf update"
    );

    // The leaf itself should be updated
    let leaf_truth = harness.get_persisted_truth(leaf_id).unwrap().value();
    assert_eq!(
        leaf_truth, 0.8,
        "Leaf claim should still be updated to new value"
    );
}

// ============================================================================
// Test 10: Propagation Handles Deep Graphs Gracefully (BFS Traversal)
// ============================================================================
//
// Note: The current implementation uses BFS with a visited set to prevent
// infinite loops, but does NOT enforce a hard depth limit of 100 levels.
// This test verifies that deep graphs are handled without crashing or
// hanging, which satisfies the "no infinite propagation" requirement.
//
// If a hard depth limit of 100 is required, the PropagationOrchestrator
// would need to be modified to track depth and stop at the limit.

#[test]
fn test_propagation_handles_deep_graphs_gracefully() {
    let mut harness = IntegrationTestHarness::new();

    // Create a very deep chain (> 100 levels) to stress test the BFS algorithm
    let depth = 150;
    let mut ids = Vec::new();

    for _ in 0..depth {
        let claim = create_test_claim(0.5);
        ids.push(harness.submit_claim(claim).unwrap());
    }

    // Create chain
    for i in 0..depth - 1 {
        harness
            .add_dependency(ids[i], ids[i + 1], true, 0.9)
            .unwrap();
    }

    // Update root - BFS should handle this gracefully without infinite loops
    let updated = harness
        .update_claim_and_propagate(ids[0], TruthValue::new(0.9).unwrap())
        .unwrap();

    // BFS traverses all reachable nodes exactly once (visited set prevents re-processing)
    // This verifies no infinite loops occur even without a hard depth limit
    assert_eq!(
        updated.len(),
        depth - 1,
        "BFS should visit all dependents exactly once"
    );

    // Verify the deepest claim was updated (BFS completes full traversal)
    let deepest_truth = harness.get_persisted_truth(ids[depth - 1]).unwrap().value();
    assert!(
        deepest_truth > 0.5,
        "Deepest claim should be updated by BFS traversal: {deepest_truth}"
    );

    // Audit trail should have records for all updates
    let audit_len = harness.get_audit_trail().len();
    assert_eq!(
        audit_len,
        depth - 1,
        "Should have audit record for each dependent visited by BFS"
    );
}

/// Test that propagation with an explicit depth limit stops at the limit
///
/// This test documents the EXPECTED behavior if a hard depth limit is implemented.
/// Currently, this test verifies that BFS handles depth correctly, but if
/// a `MAX_PROPAGATION_DEPTH` constant is added to the engine, this test should
/// be updated to verify propagation stops at that limit.
#[test]
fn test_propagation_visited_set_prevents_reprocessing() {
    let mut harness = IntegrationTestHarness::new();

    // Create a complex graph where nodes could be reached multiple times
    // without the visited set protection
    //
    //       A
    //      / \
    //     B   C
    //      \ / \
    //       D   E
    //        \ /
    //         F

    let claim_a = create_test_claim(0.5);
    let claim_b = create_test_claim(0.5);
    let claim_c = create_test_claim(0.5);
    let claim_d = create_test_claim(0.5);
    let claim_e = create_test_claim(0.5);
    let claim_f = create_test_claim(0.5);

    let id_a = harness.submit_claim(claim_a).unwrap();
    let id_b = harness.submit_claim(claim_b).unwrap();
    let id_c = harness.submit_claim(claim_c).unwrap();
    let id_d = harness.submit_claim(claim_d).unwrap();
    let id_e = harness.submit_claim(claim_e).unwrap();
    let id_f = harness.submit_claim(claim_f).unwrap();

    // Create the DAG edges
    harness.add_dependency(id_a, id_b, true, 0.8).unwrap();
    harness.add_dependency(id_a, id_c, true, 0.8).unwrap();
    harness.add_dependency(id_b, id_d, true, 0.8).unwrap();
    harness.add_dependency(id_c, id_d, true, 0.8).unwrap();
    harness.add_dependency(id_c, id_e, true, 0.8).unwrap();
    harness.add_dependency(id_d, id_f, true, 0.8).unwrap();
    harness.add_dependency(id_e, id_f, true, 0.8).unwrap();

    // Update A and propagate
    let updated = harness
        .update_claim_and_propagate(id_a, TruthValue::new(0.9).unwrap())
        .unwrap();

    // Each node should be updated EXACTLY once despite multiple paths
    assert_eq!(
        updated.len(),
        5,
        "Should update exactly 5 dependents (B, C, D, E, F)"
    );

    // Verify each dependent appears exactly once
    assert!(updated.contains(&id_b), "B should be updated");
    assert!(updated.contains(&id_c), "C should be updated");
    assert!(updated.contains(&id_d), "D should be updated exactly once");
    assert!(updated.contains(&id_e), "E should be updated");
    assert!(updated.contains(&id_f), "F should be updated exactly once");

    // Verify audit trail has exactly 5 records (one per node, not per path)
    let audit_len = harness.get_audit_trail().len();
    assert_eq!(
        audit_len, 5,
        "Audit trail should have exactly 5 records (visited set prevents duplicates)"
    );
}

// ============================================================================
// Test 11: Concurrent Propagations Don't Corrupt State
// ============================================================================

#[test]
fn test_concurrent_propagations_dont_corrupt_state() {
    let concurrent_orch = ConcurrentOrchestrator::new();

    // Setup: Create independent branches from a single root
    {
        let mut orch = concurrent_orch.inner.write().unwrap();

        // Create root claim
        let root = create_test_claim(0.5);
        let root_id = root.id;
        orch.register_claim(root).unwrap();

        // Create 5 independent branches, each with 3 claims
        for _ in 0..5 {
            let mut prev_id = root_id;
            for _ in 0..3 {
                let claim = create_test_claim(0.5);
                let claim_id = claim.id;
                orch.register_claim(claim).unwrap();
                orch.add_dependency(
                    prev_id,
                    claim_id,
                    true,
                    0.7,
                    epigraph_engine::EvidenceType::Empirical,
                    0.0,
                )
                .unwrap();
                prev_id = claim_id;
            }
        }
    }

    // Spawn multiple threads doing concurrent updates
    let mut handles = vec![];
    let update_counter = Arc::new(AtomicU64::new(0));

    for thread_idx in 0..5 {
        let orch_clone = concurrent_orch.clone_arc();
        let counter_clone = Arc::clone(&update_counter);

        let handle = thread::spawn(move || {
            // Small sleep to ensure threads interleave
            thread::sleep(Duration::from_millis(thread_idx * 10));

            let mut orch = orch_clone.inner.write().unwrap();

            // Get the first claim and update it
            if let Some((&claim_id, _)) = orch.claims().iter().next() {
                // Use different truth values per thread
                let truth = (thread_idx as f64).mul_add(0.05, 0.6);
                let result = orch.update_and_propagate(claim_id, TruthValue::new(truth).unwrap());

                if result.is_ok() {
                    counter_clone.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    // Verify state integrity
    let orch = concurrent_orch.inner.read().unwrap();

    // All claims should have valid truth values
    for claim in orch.claims().values() {
        let truth = claim.truth_value.value();
        assert!(
            (0.0..=1.0).contains(&truth),
            "Truth value {truth} is out of bounds after concurrent updates"
        );
    }

    // DAG should still be valid
    assert!(
        orch.dag().is_valid(),
        "DAG should remain valid after concurrent updates"
    );

    // At least some updates should have succeeded
    let successful_updates = update_counter.load(Ordering::SeqCst);
    assert!(
        successful_updates > 0,
        "At least one concurrent update should succeed"
    );
}

// ============================================================================
// Test 12: Propagation Can Be Triggered Manually via API
// ============================================================================

#[test]
fn test_propagation_can_be_triggered_manually() {
    let mut harness = IntegrationTestHarness::new();

    // Create claims
    let source = create_test_claim(0.5);
    let dependent = create_test_claim(0.5);
    let source_id = harness.submit_claim(source).unwrap();
    let dep_id = harness.submit_claim(dependent).unwrap();

    harness
        .add_dependency(source_id, dep_id, true, 0.8)
        .unwrap();

    // Manually trigger propagation without changing source truth
    // (This simulates an API endpoint like POST /propagate/{claim_id})
    let current_truth = harness.orchestrator.get_truth(source_id).unwrap();

    // Manual trigger: just call propagation with current value
    let updated = harness
        .update_claim_and_propagate(source_id, current_truth)
        .unwrap();

    // Should still update dependents
    assert!(
        updated.contains(&dep_id),
        "Manual trigger should update dependents"
    );

    // Change source truth for a real effect
    let updated_again = harness
        .update_claim_and_propagate(source_id, TruthValue::new(0.85).unwrap())
        .unwrap();

    assert!(
        updated_again.contains(&dep_id),
        "Second manual trigger should also work"
    );

    let final_truth = harness.get_persisted_truth(dep_id).unwrap().value();
    assert!(
        final_truth > 0.5,
        "Dependent should have updated truth after manual triggers"
    );
}

// ============================================================================
// Test 13: Propagation Respects Claim Confidence Bounds [0.0, 1.0]
// ============================================================================

#[test]
fn test_propagation_respects_confidence_bounds() {
    let mut harness = IntegrationTestHarness::new();

    // Create source with very high truth
    let source = create_test_claim(0.5);
    let source_id = harness.submit_claim(source).unwrap();

    // Create dependent starting near the edge
    let near_max = Claim::new(
        "Near max truth".to_string(),
        AgentId::new(),
        [0u8; 32], // public_key
        TruthValue::new(0.95).unwrap(),
    );
    let near_max_id = harness.submit_claim(near_max).unwrap();

    // Very strong supporting evidence
    harness
        .add_dependency(source_id, near_max_id, true, 1.0)
        .unwrap();

    // Update source to max
    harness
        .update_claim_and_propagate(source_id, TruthValue::new(0.99).unwrap())
        .unwrap();

    // Truth should be clamped to max (0.99)
    let final_truth = harness.get_persisted_truth(near_max_id).unwrap().value();
    assert!(
        final_truth <= 0.99,
        "Truth should be clamped to max 0.99. Got: {final_truth}"
    );
    assert!(
        final_truth >= 0.01,
        "Truth should be clamped to min 0.01. Got: {final_truth}"
    );

    // Test with refutation near minimum
    let near_min = Claim::new(
        "Near min truth".to_string(),
        AgentId::new(),
        [0u8; 32], // public_key
        TruthValue::new(0.05).unwrap(),
    );
    let near_min_id = harness.submit_claim(near_min).unwrap();

    // Strong refuting evidence
    harness
        .add_dependency(source_id, near_min_id, false, 1.0)
        .unwrap();

    harness
        .update_claim_and_propagate(source_id, TruthValue::new(0.99).unwrap())
        .unwrap();

    let min_truth = harness.get_persisted_truth(near_min_id).unwrap().value();
    assert!(
        min_truth >= 0.01,
        "Truth should be clamped to min 0.01. Got: {min_truth}"
    );
    assert!(
        min_truth <= 0.99,
        "Truth should be clamped to max 0.99. Got: {min_truth}"
    );
}

// ============================================================================
// Test 14: BAD ACTOR TEST - High-Reputation Agent Doesn't Inflate Truth
// ============================================================================

/// # THE BAD ACTOR TEST FOR PROPAGATION INTEGRATION
///
/// This is the MOST CRITICAL integration test. It validates that:
///
/// 1. Agent reputation is NEVER used in propagation calculations
/// 2. A high-reputation agent cannot inflate dependent claims' truths
/// 3. The only factors in propagation are:
///    - Source claim's truth value
///    - Evidence strength of the dependency
///
/// ## Why This Matters
///
/// If reputation could influence propagation, a bad actor with high reputation
/// could:
/// 1. Submit a claim with weak/no evidence
/// 2. Have other claims depend on it
/// 3. Those dependent claims would get artificially inflated truth
/// 4. This creates an "authority cascade" - the Appeal to Authority fallacy
///
/// ## Test Design
///
/// We create two identical scenarios:
/// - High-reputation agent (0.95) submits a claim
/// - Low-reputation agent (0.20) submits a claim
///
/// Both claims have IDENTICAL evidence strength. After propagation, the
/// dependent claims MUST have THE SAME truth value.
#[test]
fn bad_actor_test_high_reputation_agent_cannot_inflate_dependent_truth() {
    let mut harness = IntegrationTestHarness::new();

    // Create agents with vastly different reputations
    let high_rep_agent = AgentId::new();
    let low_rep_agent = AgentId::new();

    harness.register_agent(high_rep_agent, 0.95); // Stellar reputation
    harness.register_agent(low_rep_agent, 0.20); // Poor reputation

    // IDENTICAL weak evidence strength for both
    let evidence_strength = 0.3;

    // High-rep agent's claim
    let high_rep_claim = create_claim_with_agent(0.5, high_rep_agent);
    let high_rep_id = harness.submit_claim(high_rep_claim).unwrap();

    // Low-rep agent's claim
    let low_rep_claim = create_claim_with_agent(0.5, low_rep_agent);
    let low_rep_id = harness.submit_claim(low_rep_claim).unwrap();

    // Dependent claims (identical starting truth)
    let dep_on_high = create_test_claim(0.5);
    let dep_on_low = create_test_claim(0.5);
    let dep_high_id = harness.submit_claim(dep_on_high).unwrap();
    let dep_low_id = harness.submit_claim(dep_on_low).unwrap();

    // SAME evidence strength for both dependencies
    harness
        .add_dependency(high_rep_id, dep_high_id, true, evidence_strength)
        .unwrap();
    harness
        .add_dependency(low_rep_id, dep_low_id, true, evidence_strength)
        .unwrap();

    // Update both sources to THE SAME truth value
    let source_truth = TruthValue::new(0.7).unwrap();
    harness
        .update_claim_and_propagate(high_rep_id, source_truth)
        .unwrap();
    harness
        .update_claim_and_propagate(low_rep_id, source_truth)
        .unwrap();

    // CRITICAL ASSERTION: Both dependents MUST have THE SAME truth
    let high_dep_truth = harness.get_persisted_truth(dep_high_id).unwrap().value();
    let low_dep_truth = harness.get_persisted_truth(dep_low_id).unwrap().value();

    let tolerance = 1e-10;
    assert!(
        (high_dep_truth - low_dep_truth).abs() < tolerance,
        "BAD ACTOR TEST FAILED!\n\
         High-reputation agent's dependent: {}\n\
         Low-reputation agent's dependent: {}\n\
         Difference: {}\n\n\
         Reputation MUST NOT influence propagation. Both should be equal.",
        high_dep_truth,
        low_dep_truth,
        (high_dep_truth - low_dep_truth).abs()
    );
}

#[test]
fn bad_actor_test_weak_evidence_stays_weak_in_propagation() {
    let mut harness = IntegrationTestHarness::new();

    // Nobel laureate agent
    let nobel_agent = AgentId::new();
    harness.register_agent(nobel_agent, 0.99);

    // Nobel laureate makes a claim
    let source = create_claim_with_agent(0.5, nobel_agent);
    let source_id = harness.submit_claim(source).unwrap();

    // Dependent claim
    let dependent = create_test_claim(0.5);
    let dep_id = harness.submit_claim(dependent).unwrap();

    // VERY WEAK evidence strength (0.1)
    harness
        .add_dependency(source_id, dep_id, true, 0.1)
        .unwrap();

    // Even if Nobel laureate updates their claim to high truth...
    harness
        .update_claim_and_propagate(source_id, TruthValue::new(0.9).unwrap())
        .unwrap();

    // The dependent should only get a SMALL boost
    let dep_truth = harness.get_persisted_truth(dep_id).unwrap().value();

    // STRICT ASSERTION: With weak evidence (0.1) and source truth (0.9):
    // effective_strength = 0.1 * 0.9 = 0.09
    // The Bayesian update should produce a value close to 0.54
    // We use 0.6 as the threshold to enforce that weak evidence stays weak
    assert!(
        dep_truth < 0.6,
        "BAD ACTOR TEST FAILED!\n\
         Weak evidence (0.1) from high-reputation Nobel laureate should not\n\
         produce significant truth increase in dependent claim.\n\
         Got: {dep_truth} (expected < 0.6)\n\n\
         With effective_strength = 0.09, Bayesian update should yield ~0.54"
    );

    // Additional assertion: should be only marginally above uncertainty (0.5)
    let increase = dep_truth - 0.5;
    assert!(
        increase < 0.1,
        "BAD ACTOR TEST FAILED!\n\
         Weak evidence should produce minimal truth increase.\n\
         Increase from 0.5: {increase} (expected < 0.1)"
    );
}

#[test]
fn bad_actor_test_no_authority_cascade_through_dag() {
    let mut harness = IntegrationTestHarness::new();

    // Create "authority" agent with stellar reputation
    let authority = AgentId::new();
    harness.register_agent(authority, 0.98);

    // Authority makes a claim starting at uncertainty (no evidence)
    let authority_claim = create_claim_with_agent(0.5, authority);
    let authority_id = harness.submit_claim(authority_claim).unwrap();

    // Create a chain of 5 dependent claims
    let mut chain_ids = vec![authority_id];
    for _ in 0..5 {
        let claim = create_test_claim(0.5);
        let claim_id = harness.submit_claim(claim).unwrap();

        // Weak evidence strength (0.3) throughout the chain
        harness
            .add_dependency(*chain_ids.last().unwrap(), claim_id, true, 0.3)
            .unwrap();
        chain_ids.push(claim_id);
    }

    // Authority "asserts" moderate truth (simulating weak evidence)
    harness
        .update_claim_and_propagate(authority_id, TruthValue::new(0.65).unwrap())
        .unwrap();

    // The END of the chain should NOT have high truth
    let final_truth = harness
        .get_persisted_truth(*chain_ids.last().unwrap())
        .unwrap()
        .value();

    // STRICT ASSERTION: With weak evidence (0.3) cascading through 5 levels,
    // the final claim should remain close to uncertainty (0.5)
    // Even with compounding, weak evidence should not produce high truth
    assert!(
        final_truth < 0.7,
        "BAD ACTOR TEST FAILED!\n\
         Authority cascade should not produce elevated truth at end of chain.\n\
         Got: {final_truth} (expected < 0.7)\n\n\
         A high-reputation agent's weak claim should not cascade through\n\
         the DAG and produce artificially high truth values."
    );

    // Verify truth decays (or at least doesn't amplify) through the chain
    let mut prev_truth = harness.get_persisted_truth(chain_ids[0]).unwrap().value();
    for (i, &claim_id) in chain_ids[1..].iter().enumerate() {
        let truth = harness.get_persisted_truth(claim_id).unwrap().value();

        // The increase from base (0.5) should NOT amplify through the chain
        let increase = truth - 0.5;
        let prev_increase = prev_truth - 0.5;

        // STRICT: Each level should have less or equal increase (decay, not amplification)
        assert!(
            increase <= prev_increase + 0.05,
            "BAD ACTOR TEST FAILED!\n\
             Authority cascade should decay, not amplify through chain.\n\
             Level {}: prev_increase={:.4}, current_increase={:.4}\n\
             Amplification detected!",
            i + 1,
            prev_increase,
            increase
        );
        prev_truth = truth;
    }

    // CRITICAL: Verify the chain end is closer to uncertainty than the start
    let first_dep_truth = harness.get_persisted_truth(chain_ids[1]).unwrap().value();
    assert!(
        final_truth <= first_dep_truth,
        "BAD ACTOR TEST FAILED!\n\
         Truth should decay through chain, not accumulate.\n\
         First dependent: {first_dep_truth}, Final: {final_truth}\n\
         Weak evidence should attenuate through propagation."
    );
}

#[test]
fn bad_actor_test_claim_without_evidence_gets_low_truth() {
    // This test validates the core principle: NO NAKED ASSERTIONS
    // Even from high-reputation agents, claims without evidence get low truth.

    // Test calculate_initial_truth (from BayesianUpdater)
    // Zero evidence = maximum uncertainty (0.5)
    let zero_evidence_truth = BayesianUpdater::calculate_initial_truth(0.0, 0);
    assert_eq!(
        zero_evidence_truth.value(),
        0.5,
        "Zero evidence should produce exactly 0.5 (maximum uncertainty)"
    );

    // Weak single evidence = below verification threshold
    let weak_single = BayesianUpdater::calculate_initial_truth(0.2, 1);
    assert!(
        weak_single.value() < 0.8,
        "Weak single evidence should not reach verification threshold (0.8). Got: {}",
        weak_single.value()
    );

    // Even strong evidence weight with zero count doesn't give high truth
    // (because diversity bonus requires actual evidence sources)
    let high_weight_zero = BayesianUpdater::calculate_initial_truth(1.0, 0);
    // 0.5 + (1.0 * 0.5) + 0.0 = 1.0 -> clamped to 0.85
    assert!(
        high_weight_zero.value() <= 0.85,
        "Max weight with zero count should be capped at 0.85. Got: {}",
        high_weight_zero.value()
    );

    // Initial truth is ALWAYS capped at 0.85
    let max_possible = BayesianUpdater::calculate_initial_truth(1.0, 100);
    assert!(
        max_possible.value() <= 0.85,
        "Initial truth must NEVER exceed 0.85, even with max evidence. Got: {}",
        max_possible.value()
    );
}

/// # COMPREHENSIVE BAD ACTOR TEST
///
/// This test validates multiple attack vectors that a malicious high-reputation
/// agent might attempt to exploit. Each scenario MUST fail to inflate truth.
///
/// ## Attack Vectors Tested:
/// 1. Direct authority influence (reputation -> truth)
/// 2. Fan-out attack (one claim influences many)
/// 3. Coordinated claims from same agent
/// 4. Deep chain amplification attempt
#[test]
fn bad_actor_comprehensive_attack_vectors() {
    let mut harness = IntegrationTestHarness::new();

    // Setup: Create agents with vastly different reputations
    let malicious_agent = AgentId::new();
    let honest_agent = AgentId::new();

    harness.register_agent(malicious_agent, 0.99); // "Trusted" bad actor
    harness.register_agent(honest_agent, 0.50); // Average reputation

    // ==========================================================================
    // Attack Vector 1: Direct Authority Influence
    // A high-rep agent tries to directly inflate a dependent claim
    // ==========================================================================

    let mal_source = create_claim_with_agent(0.5, malicious_agent);
    let mal_source_id = harness.submit_claim(mal_source).unwrap();

    let hon_source = create_claim_with_agent(0.5, honest_agent);
    let hon_source_id = harness.submit_claim(hon_source).unwrap();

    let target1 = create_test_claim(0.5);
    let target2 = create_test_claim(0.5);
    let target1_id = harness.submit_claim(target1).unwrap();
    let target2_id = harness.submit_claim(target2).unwrap();

    // Same evidence strength
    harness
        .add_dependency(mal_source_id, target1_id, true, 0.5)
        .unwrap();
    harness
        .add_dependency(hon_source_id, target2_id, true, 0.5)
        .unwrap();

    // Both update to same truth
    harness
        .update_claim_and_propagate(mal_source_id, TruthValue::new(0.8).unwrap())
        .unwrap();
    harness
        .update_claim_and_propagate(hon_source_id, TruthValue::new(0.8).unwrap())
        .unwrap();

    let mal_target_truth = harness.get_persisted_truth(target1_id).unwrap().value();
    let hon_target_truth = harness.get_persisted_truth(target2_id).unwrap().value();

    assert!(
        (mal_target_truth - hon_target_truth).abs() < 1e-10,
        "ATTACK VECTOR 1 FAILED!\n\
         Direct authority influence detected.\n\
         Malicious agent's target: {mal_target_truth}\n\
         Honest agent's target: {hon_target_truth}\n\
         These MUST be equal!"
    );

    // ==========================================================================
    // Attack Vector 2: Fan-out Attack
    // Bad actor tries to influence many claims at once
    // ==========================================================================

    let fan_source = create_claim_with_agent(0.5, malicious_agent);
    let fan_source_id = harness.submit_claim(fan_source).unwrap();

    let mut fan_targets = Vec::new();
    for _ in 0..10 {
        let target = create_test_claim(0.5);
        let target_id = harness.submit_claim(target).unwrap();
        harness
            .add_dependency(fan_source_id, target_id, true, 0.2)
            .unwrap(); // Weak evidence
        fan_targets.push(target_id);
    }

    // Bad actor pumps their claim high
    harness
        .update_claim_and_propagate(fan_source_id, TruthValue::new(0.95).unwrap())
        .unwrap();

    // ALL fan-out targets should still be LOW because evidence is weak
    for (i, &target_id) in fan_targets.iter().enumerate() {
        let truth = harness.get_persisted_truth(target_id).unwrap().value();
        assert!(
            truth < 0.65,
            "ATTACK VECTOR 2 FAILED!\n\
             Fan-out attack succeeded for target {i}.\n\
             Got: {truth} (expected < 0.65)\n\
             Weak evidence (0.2) should not produce elevated truth even from high-rep agent!"
        );
    }

    // ==========================================================================
    // Attack Vector 3: Coordinated Claims
    // Bad actor creates multiple claims that all support a target
    // Each individual claim has weak evidence, testing if they improperly combine
    // ==========================================================================

    let target_claim = create_test_claim(0.5);
    let target_claim_id = harness.submit_claim(target_claim).unwrap();

    // Bad actor creates 5 "supporting" claims
    for _ in 0..5 {
        let coord_claim = create_claim_with_agent(0.5, malicious_agent);
        let coord_id = harness.submit_claim(coord_claim).unwrap();

        // Each has weak evidence (0.15)
        harness
            .add_dependency(coord_id, target_claim_id, true, 0.15)
            .unwrap();

        // Each claims moderate truth
        harness
            .update_claim_and_propagate(coord_id, TruthValue::new(0.7).unwrap())
            .unwrap();
    }

    let coordinated_truth = harness
        .get_persisted_truth(target_claim_id)
        .unwrap()
        .value();

    // Even with 5 coordinated claims, weak evidence should not produce high truth
    // Note: Current implementation updates sequentially, so we check the final result
    assert!(
        coordinated_truth < 0.75,
        "ATTACK VECTOR 3 FAILED!\n\
         Coordinated claims attack succeeded.\n\
         Got: {coordinated_truth} (expected < 0.75)\n\
         Multiple weak claims should not combine to produce high truth!"
    );

    // ==========================================================================
    // Attack Vector 4: Deep Chain Amplification
    // Bad actor tries to create a chain where truth amplifies instead of decays
    // ==========================================================================

    let chain_root = create_claim_with_agent(0.5, malicious_agent);
    let chain_root_id = harness.submit_claim(chain_root).unwrap();

    let mut chain = vec![chain_root_id];
    for _ in 0..5 {
        let next = create_test_claim(0.5);
        let next_id = harness.submit_claim(next).unwrap();
        harness
            .add_dependency(*chain.last().unwrap(), next_id, true, 0.4)
            .unwrap();
        chain.push(next_id);
    }

    // Bad actor starts the chain with high truth
    harness
        .update_claim_and_propagate(chain_root_id, TruthValue::new(0.85).unwrap())
        .unwrap();

    // Verify truth DECAYS through the chain (no amplification)
    let mut prev_truth = 0.85f64; // Root truth
    for (i, &claim_id) in chain[1..].iter().enumerate() {
        let truth = harness.get_persisted_truth(claim_id).unwrap().value();

        // Truth should be less than or equal to previous (with small tolerance for BFS order effects)
        let decay_check = truth <= prev_truth + 0.02;
        assert!(
            decay_check,
            "ATTACK VECTOR 4 FAILED!\n\
             Deep chain amplification detected at level {}.\n\
             Previous truth: {}, Current truth: {}\n\
             Truth should decay through chain, not amplify!",
            i + 1,
            prev_truth,
            truth
        );

        // Also verify absolute bounds
        assert!(
            truth < 0.85,
            "ATTACK VECTOR 4 FAILED!\n\
             Chain level {} exceeded root truth.\n\
             Got: {} (root was 0.85)\n\
             Dependent claims should never exceed their source!",
            i + 1,
            truth
        );

        prev_truth = truth;
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_zero_strength_dependency_minimal_effect() {
    let mut harness = IntegrationTestHarness::new();

    let source = create_test_claim(0.5);
    let dependent = create_test_claim(0.5);
    let source_id = harness.submit_claim(source).unwrap();
    let dep_id = harness.submit_claim(dependent).unwrap();

    // Zero strength dependency
    harness
        .add_dependency(source_id, dep_id, true, 0.0)
        .unwrap();

    harness
        .update_claim_and_propagate(source_id, TruthValue::new(0.95).unwrap())
        .unwrap();

    let dep_truth = harness.get_persisted_truth(dep_id).unwrap().value();

    // Should have minimal effect (close to 0.5)
    assert!(
        (dep_truth - 0.5).abs() < 0.05,
        "Zero-strength dependency should have minimal effect. Got: {dep_truth}"
    );
}

#[test]
fn test_update_nonexistent_claim_fails() {
    let mut harness = IntegrationTestHarness::new();

    let fake_id = ClaimId::new();
    let result = harness.update_claim_and_propagate(fake_id, TruthValue::new(0.5).unwrap());

    assert!(
        matches!(result, Err(EngineError::NodeNotFound(_))),
        "Should fail for nonexistent claim"
    );
}

#[test]
fn test_large_fan_out_propagation() {
    let mut harness = IntegrationTestHarness::new();

    // One source with 50 direct dependents
    let source = create_test_claim(0.5);
    let source_id = harness.submit_claim(source).unwrap();

    let mut dep_ids = Vec::new();
    for _ in 0..50 {
        let dep = create_test_claim(0.5);
        let dep_id = harness.submit_claim(dep).unwrap();
        harness
            .add_dependency(source_id, dep_id, true, 0.7)
            .unwrap();
        dep_ids.push(dep_id);
    }

    // Update source
    let updated = harness
        .update_claim_and_propagate(source_id, TruthValue::new(0.85).unwrap())
        .unwrap();

    // All 50 dependents should be updated
    assert_eq!(updated.len(), 50, "All 50 dependents should be in fan-out");

    // All should have increased truth
    for dep_id in dep_ids {
        let truth = harness.get_persisted_truth(dep_id).unwrap().value();
        assert!(truth > 0.5, "All fan-out dependents should be updated");
    }
}

// ============================================================================
// Property-Based Tests
// ============================================================================

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Truth values ALWAYS stay bounded after propagation
        #[test]
        fn prop_truth_always_bounded_in_integration(
            initial_truth in 0.1f64..0.9,
            source_truth in 0.1f64..0.9,
            strength in 0.0f64..1.0,
        ) {
            let mut harness = IntegrationTestHarness::new();

            let source = Claim::new(
                "Source".to_string(),
                AgentId::new(),
                [0u8; 32], // public_key
                TruthValue::new(0.5).unwrap(),
            );
            let source_id = harness.submit_claim(source).unwrap();

            let dependent = Claim::new(
                "Dependent".to_string(),
                AgentId::new(),
                [0u8; 32], // public_key
                TruthValue::new(initial_truth).unwrap(),
            );
            let dep_id = harness.submit_claim(dependent).unwrap();

            harness.add_dependency(source_id, dep_id, true, strength).unwrap();

            harness.update_claim_and_propagate(
                source_id,
                TruthValue::new(source_truth).unwrap()
            ).unwrap();

            let final_truth = harness.get_persisted_truth(dep_id).unwrap().value();
            prop_assert!((0.01..=0.99).contains(&final_truth),
                "Truth {} out of bounds [0.01, 0.99]", final_truth);
        }

        /// Supporting evidence NEVER decreases truth
        #[test]
        fn prop_support_never_decreases_in_integration(
            initial_truth in 0.2f64..0.6,
            source_truth in 0.5f64..0.95,
            strength in 0.2f64..1.0,
        ) {
            let mut harness = IntegrationTestHarness::new();

            let source = create_test_claim(0.5);
            let source_id = harness.submit_claim(source).unwrap();

            let dependent = Claim::new(
                "Dependent".to_string(),
                AgentId::new(),
                [0u8; 32], // public_key
                TruthValue::new(initial_truth).unwrap(),
            );
            let dep_id = harness.submit_claim(dependent).unwrap();

            harness.add_dependency(source_id, dep_id, true, strength).unwrap();

            harness.update_claim_and_propagate(
                source_id,
                TruthValue::new(source_truth).unwrap()
            ).unwrap();

            let final_truth = harness.get_persisted_truth(dep_id).unwrap().value();
            prop_assert!(final_truth >= initial_truth - 0.01,
                "Support should not decrease truth: {} -> {}", initial_truth, final_truth);
        }

        /// Refuting evidence NEVER increases truth
        #[test]
        fn prop_refutation_never_increases_in_integration(
            initial_truth in 0.4f64..0.8,
            source_truth in 0.5f64..0.95,
            strength in 0.2f64..1.0,
        ) {
            let mut harness = IntegrationTestHarness::new();

            let source = create_test_claim(0.5);
            let source_id = harness.submit_claim(source).unwrap();

            let dependent = Claim::new(
                "Dependent".to_string(),
                AgentId::new(),
                [0u8; 32], // public_key
                TruthValue::new(initial_truth).unwrap(),
            );
            let dep_id = harness.submit_claim(dependent).unwrap();

            harness.add_dependency(source_id, dep_id, false, strength).unwrap();

            harness.update_claim_and_propagate(
                source_id,
                TruthValue::new(source_truth).unwrap()
            ).unwrap();

            let final_truth = harness.get_persisted_truth(dep_id).unwrap().value();
            prop_assert!(final_truth <= initial_truth + 0.01,
                "Refutation should not increase truth: {} -> {}", initial_truth, final_truth);
        }

        /// Reputation has ZERO influence on propagation (BAD ACTOR property)
        #[test]
        fn prop_reputation_has_zero_influence(
            high_rep in 0.8f64..0.99,
            low_rep in 0.01f64..0.3,
            source_truth in 0.4f64..0.9,
            strength in 0.1f64..1.0,
        ) {
            let mut harness = IntegrationTestHarness::new();

            let high_agent = AgentId::new();
            let low_agent = AgentId::new();
            harness.register_agent(high_agent, high_rep);
            harness.register_agent(low_agent, low_rep);

            // High-rep agent's claim
            let high_claim = create_claim_with_agent(0.5, high_agent);
            let high_id = harness.submit_claim(high_claim).unwrap();

            // Low-rep agent's claim
            let low_claim = create_claim_with_agent(0.5, low_agent);
            let low_id = harness.submit_claim(low_claim).unwrap();

            // Dependents
            let dep_high = create_test_claim(0.5);
            let dep_low = create_test_claim(0.5);
            let dep_high_id = harness.submit_claim(dep_high).unwrap();
            let dep_low_id = harness.submit_claim(dep_low).unwrap();

            // Same strength
            harness.add_dependency(high_id, dep_high_id, true, strength).unwrap();
            harness.add_dependency(low_id, dep_low_id, true, strength).unwrap();

            // Same source truth
            let truth = TruthValue::new(source_truth).unwrap();
            harness.update_claim_and_propagate(high_id, truth).unwrap();
            harness.update_claim_and_propagate(low_id, truth).unwrap();

            let high_dep_truth = harness.get_persisted_truth(dep_high_id).unwrap().value();
            let low_dep_truth = harness.get_persisted_truth(dep_low_id).unwrap().value();

            let tolerance = 1e-9;
            prop_assert!((high_dep_truth - low_dep_truth).abs() < tolerance,
                "BAD ACTOR: Reputation influenced propagation! High: {}, Low: {}",
                high_dep_truth, low_dep_truth);
        }
    }
}
