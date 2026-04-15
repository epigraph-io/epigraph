//! Truth Propagation Orchestrator Tests
//!
//! These tests verify the correct behavior of truth value propagation through
//! the reasoning DAG when claims are updated. Key scenarios tested:
//!
//! - Leaf nodes (no dependents) don't trigger propagation
//! - Updates propagate to all dependents correctly
//! - Deep DAGs propagate completely through all levels
//! - Evidence weighting affects propagation strength
//! - Cycles are prevented (no infinite loops)
//! - Concurrent propagations maintain state integrity
//! - Audit trails record all propagation events
//! - Conflicting evidence is handled correctly
//! - BAD ACTOR TEST: High-reputation agents can't inflate dependent truths
//!
//! # Bayesian Update Formula (Reference)
//!
//! ```text
//! P(H|E) = P(E|H) * P(H) / P(E)
//! posterior = likelihood * prior / marginal
//! ```
//!
//! Where:
//! - P(H) = prior (current truth value)
//! - P(E|H) = likelihood of evidence if hypothesis is true
//! - P(E|~H) = likelihood of evidence if hypothesis is false
//! - P(E) = P(E|H)*P(H) + P(E|~H)*P(~H)

use epigraph_core::{AgentId, Claim, ClaimId, TruthValue};
use epigraph_engine::{BayesianUpdater, DagValidator, EngineError, EvidenceWeighter};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};

// ============================================================================
// Test Infrastructure: Propagation Orchestrator
// ============================================================================

/// Represents a dependency relationship between claims
#[derive(Debug, Clone)]
struct ClaimDependency {
    /// The claim that depends on another
    dependent_id: ClaimId,
    /// Whether this is supporting (true) or refuting (false) evidence
    is_supporting: bool,
    /// Strength of the dependency relationship [0, 1]
    strength: f64,
}

/// Audit record for a single propagation event
#[derive(Debug, Clone)]
struct PropagationAuditRecord {
    /// The claim that was updated
    claim_id: ClaimId,
    /// Truth value before propagation
    prior_truth: TruthValue,
    /// Truth value after propagation
    posterior_truth: TruthValue,
    /// The source claim that triggered this update
    source_claim_id: ClaimId,
    /// Whether this was from supporting or refuting evidence
    is_supporting: bool,
    /// Timestamp of the propagation (simplified as counter for testing)
    sequence_number: u64,
}

/// The Truth Propagation Orchestrator
///
/// Coordinates Bayesian truth updates across the reasoning DAG.
/// When a claim's truth value changes, this orchestrator:
/// 1. Identifies all dependent claims
/// 2. Recalculates their truth values using Bayesian updates
/// 3. Recursively propagates to their dependents
/// 4. Records an audit trail of all updates
/// 5. Prevents cycles and infinite loops
struct PropagationOrchestrator {
    /// Bayesian updater for truth calculations
    bayesian: BayesianUpdater,
    /// DAG validator for cycle detection
    dag: DagValidator,
    /// Evidence weighter for calculating evidence strength (reserved for future use)
    #[allow(dead_code)]
    evidence_weighter: EvidenceWeighter,
    /// Map from claim ID to claim data
    claims: HashMap<ClaimId, Claim>,
    /// Map from claim ID to its dependents (claims that depend on it)
    dependents: HashMap<ClaimId, Vec<ClaimDependency>>,
    /// Audit trail of all propagation events
    audit_trail: Vec<PropagationAuditRecord>,
    /// Counter for audit sequence numbers
    sequence_counter: u64,
    /// Agent reputation scores (for Bad Actor testing)
    agent_reputations: HashMap<AgentId, f64>,
}

impl PropagationOrchestrator {
    /// Create a new propagation orchestrator
    fn new() -> Self {
        Self {
            bayesian: BayesianUpdater::new(),
            dag: DagValidator::new(),
            evidence_weighter: EvidenceWeighter::new(),
            claims: HashMap::new(),
            dependents: HashMap::new(),
            audit_trail: Vec::new(),
            sequence_counter: 0,
            agent_reputations: HashMap::new(),
        }
    }

    /// Register a claim in the orchestrator
    fn register_claim(&mut self, claim: Claim) -> Result<(), EngineError> {
        let claim_id = claim.id;
        self.dag.add_node(claim_id.as_uuid());
        self.claims.insert(claim_id, claim);
        self.dependents.entry(claim_id).or_default();
        Ok(())
    }

    /// Register an agent with a reputation score
    fn register_agent(&mut self, agent_id: AgentId, reputation: f64) {
        self.agent_reputations.insert(agent_id, reputation);
    }

    /// Add a dependency relationship: `dependent` depends on `source`
    ///
    /// When `source`'s truth value changes, `dependent`'s truth should be updated.
    fn add_dependency(
        &mut self,
        source_id: ClaimId,
        dependent_id: ClaimId,
        is_supporting: bool,
        strength: f64,
    ) -> Result<(), EngineError> {
        // Add edge to DAG (source -> dependent means dependent is affected by source)
        self.dag
            .add_edge(source_id.as_uuid(), dependent_id.as_uuid())?;

        // Record the dependency
        let dep = ClaimDependency {
            dependent_id,
            is_supporting,
            strength,
        };
        self.dependents.entry(source_id).or_default().push(dep);
        Ok(())
    }

    /// Update a claim's truth value and propagate to dependents
    ///
    /// Returns the set of claim IDs that were updated during propagation.
    fn update_and_propagate(
        &mut self,
        claim_id: ClaimId,
        new_truth: TruthValue,
    ) -> Result<HashSet<ClaimId>, EngineError> {
        // Update the source claim
        let claim = self
            .claims
            .get_mut(&claim_id)
            .ok_or(EngineError::NodeNotFound(claim_id.as_uuid()))?;
        claim.update_truth_value(new_truth);

        // Propagate to dependents using BFS to ensure correct ordering
        let mut updated_claims = HashSet::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        // Start with direct dependents
        queue.push_back(claim_id);
        visited.insert(claim_id);

        while let Some(current_id) = queue.pop_front() {
            let deps = self
                .dependents
                .get(&current_id)
                .cloned()
                .unwrap_or_default();

            for dep in deps {
                if visited.contains(&dep.dependent_id) {
                    // Already visited - skip to prevent infinite loops
                    continue;
                }
                visited.insert(dep.dependent_id);

                // Get the source claim's truth value
                let source_truth = self
                    .claims
                    .get(&current_id)
                    .map_or_else(TruthValue::uncertain, |c| c.truth_value);

                // Get the dependent claim
                if let Some(dependent_claim) = self.claims.get_mut(&dep.dependent_id) {
                    let prior = dependent_claim.truth_value;

                    // Calculate posterior using Bayesian update
                    // The strength is modulated by the source claim's truth value
                    let effective_strength = dep.strength * source_truth.value();

                    let posterior = if dep.is_supporting {
                        self.bayesian
                            .update_with_support(prior, effective_strength)?
                    } else {
                        self.bayesian
                            .update_with_refutation(prior, effective_strength)?
                    };

                    // Record audit trail
                    self.sequence_counter += 1;
                    self.audit_trail.push(PropagationAuditRecord {
                        claim_id: dep.dependent_id,
                        prior_truth: prior,
                        posterior_truth: posterior,
                        source_claim_id: current_id,
                        is_supporting: dep.is_supporting,
                        sequence_number: self.sequence_counter,
                    });

                    // Update the dependent claim
                    dependent_claim.update_truth_value(posterior);
                    updated_claims.insert(dep.dependent_id);

                    // Add to queue for further propagation
                    queue.push_back(dep.dependent_id);
                }
            }
        }

        Ok(updated_claims)
    }

    /// Get the current truth value of a claim
    fn get_truth(&self, claim_id: ClaimId) -> Option<TruthValue> {
        self.claims.get(&claim_id).map(|c| c.truth_value)
    }

    /// Get the audit trail
    fn get_audit_trail(&self) -> &[PropagationAuditRecord] {
        &self.audit_trail
    }

    /// Clear the audit trail (for testing)
    fn clear_audit_trail(&mut self) {
        self.audit_trail.clear();
        self.sequence_counter = 0;
    }

    /// Get the number of dependents for a claim
    fn dependent_count(&self, claim_id: ClaimId) -> usize {
        self.dependents.get(&claim_id).map_or(0, std::vec::Vec::len)
    }
}

/// Thread-safe wrapper for concurrent testing
struct ConcurrentOrchestrator {
    inner: Arc<RwLock<PropagationOrchestrator>>,
}

impl ConcurrentOrchestrator {
    fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(PropagationOrchestrator::new())),
        }
    }

    fn clone_arc(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a test claim with given truth value
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

// ============================================================================
// Test 1: Single Claim Update (Leaf Node) - No Propagation
// ============================================================================

#[test]
fn test_single_claim_update_no_propagation() {
    // A leaf node (claim with no dependents) should not trigger any propagation
    // when its truth value is updated.

    let mut orchestrator = PropagationOrchestrator::new();

    // Create and register a single claim
    let claim = create_test_claim(0.5);
    let claim_id = claim.id;
    orchestrator.register_claim(claim).unwrap();

    // Verify no dependents
    assert_eq!(
        orchestrator.dependent_count(claim_id),
        0,
        "Leaf node should have no dependents"
    );

    // Update the claim's truth value
    let updated = orchestrator
        .update_and_propagate(claim_id, TruthValue::new(0.8).unwrap())
        .unwrap();

    // Verify no propagation occurred (only the source was updated, not counted)
    assert!(
        updated.is_empty(),
        "Leaf node update should not propagate to any other claims"
    );

    // Verify the audit trail is empty (no dependent updates)
    assert!(
        orchestrator.get_audit_trail().is_empty(),
        "No audit records should exist for leaf node update"
    );

    // Verify the claim itself was updated
    assert_eq!(
        orchestrator.get_truth(claim_id).unwrap().value(),
        0.8,
        "The leaf claim's truth value should be updated"
    );
}

// ============================================================================
// Test 2: Claim with One Dependent Propagates Correctly
// ============================================================================

#[test]
fn test_single_dependent_propagation() {
    // When claim A (source) changes, claim B (dependent) should be updated
    // via Bayesian update.

    let mut orchestrator = PropagationOrchestrator::new();

    // Create source claim (A) with initial truth 0.5
    let claim_a = create_test_claim(0.5);
    let claim_a_id = claim_a.id;
    orchestrator.register_claim(claim_a).unwrap();

    // Create dependent claim (B) with initial truth 0.5
    let claim_b = create_test_claim(0.5);
    let claim_b_id = claim_b.id;
    orchestrator.register_claim(claim_b).unwrap();

    // B depends on A (A supports B with strength 0.8)
    orchestrator
        .add_dependency(claim_a_id, claim_b_id, true, 0.8)
        .unwrap();

    // Update A to high truth value
    let updated = orchestrator
        .update_and_propagate(claim_a_id, TruthValue::new(0.9).unwrap())
        .unwrap();

    // Verify B was updated
    assert!(
        updated.contains(&claim_b_id),
        "Dependent claim B should be updated"
    );
    assert_eq!(updated.len(), 1, "Only one claim should be updated");

    // Verify B's truth increased (supporting evidence)
    let b_truth = orchestrator.get_truth(claim_b_id).unwrap();
    assert!(
        b_truth.value() > 0.5,
        "Supporting evidence should increase truth. Got: {}",
        b_truth.value()
    );

    // Verify audit trail
    let audit = orchestrator.get_audit_trail();
    assert_eq!(audit.len(), 1, "One audit record should exist");
    assert_eq!(audit[0].claim_id, claim_b_id);
    assert_eq!(audit[0].source_claim_id, claim_a_id);
    assert!(audit[0].is_supporting);
    assert!(audit[0].posterior_truth.value() > audit[0].prior_truth.value());
}

// ============================================================================
// Test 3: Claim with Multiple Dependents Propagates to All
// ============================================================================

#[test]
fn test_multiple_dependents_propagation() {
    // When claim A changes, all of its dependents (B, C, D) should be updated.

    let mut orchestrator = PropagationOrchestrator::new();

    // Create source claim A
    let claim_a = create_test_claim(0.5);
    let claim_a_id = claim_a.id;
    orchestrator.register_claim(claim_a).unwrap();

    // Create multiple dependent claims
    let mut dependent_ids = Vec::new();
    for i in 0..5 {
        let claim = create_test_claim(0.5);
        let claim_id = claim.id;
        orchestrator.register_claim(claim).unwrap();

        // Each dependent has different strength
        let strength = f64::from(i).mul_add(0.1, 0.5);
        orchestrator
            .add_dependency(claim_a_id, claim_id, true, strength)
            .unwrap();
        dependent_ids.push(claim_id);
    }

    // Update A
    let updated = orchestrator
        .update_and_propagate(claim_a_id, TruthValue::new(0.85).unwrap())
        .unwrap();

    // Verify all dependents were updated
    assert_eq!(updated.len(), 5, "All 5 dependents should be updated");
    for dep_id in &dependent_ids {
        assert!(
            updated.contains(dep_id),
            "Dependent {dep_id:?} should be updated"
        );
    }

    // Verify all dependents have increased truth (supporting evidence)
    for dep_id in &dependent_ids {
        let truth = orchestrator.get_truth(*dep_id).unwrap();
        assert!(
            truth.value() > 0.5,
            "All dependents should have increased truth"
        );
    }

    // Verify audit trail has records for all dependents
    let audit = orchestrator.get_audit_trail();
    assert_eq!(audit.len(), 5, "Should have 5 audit records");
}

// ============================================================================
// Test 4: Deep DAG (5+ Levels) Propagates Completely
// ============================================================================

#[test]
fn test_deep_dag_propagation() {
    // Create a chain: A -> B -> C -> D -> E -> F (6 levels)
    // Update A, verify propagation reaches F.

    let mut orchestrator = PropagationOrchestrator::new();

    // Create 6 claims in a chain
    let mut claim_ids = Vec::new();
    for _ in 0..6 {
        let claim = create_test_claim(0.5);
        claim_ids.push(claim.id);
        orchestrator.register_claim(claim).unwrap();
    }

    // Create chain: each claim depends on the previous
    for i in 0..5 {
        orchestrator
            .add_dependency(claim_ids[i], claim_ids[i + 1], true, 0.8)
            .unwrap();
    }

    // Update the root claim (A)
    let updated = orchestrator
        .update_and_propagate(claim_ids[0], TruthValue::new(0.9).unwrap())
        .unwrap();

    // Verify all 5 dependents were updated (B, C, D, E, F)
    assert_eq!(updated.len(), 5, "All 5 dependent claims should be updated");
    for claim_id in &claim_ids[1..] {
        assert!(
            updated.contains(claim_id),
            "Claim at level should be updated"
        );
    }

    // Verify truth values propagated (with decay through the chain)
    for claim_id in &claim_ids[1..] {
        let truth = orchestrator.get_truth(*claim_id).unwrap().value();
        // Each level should be updated (truth increases from prior 0.5)
        assert!(
            truth > 0.5,
            "Deep claim should have increased truth. Got: {truth}"
        );
    }

    // Verify audit trail shows correct propagation order
    let audit = orchestrator.get_audit_trail();
    assert_eq!(
        audit.len(),
        5,
        "Should have 5 audit records for chain propagation"
    );

    // Verify sequence numbers are in order
    for i in 0..audit.len() - 1 {
        assert!(
            audit[i].sequence_number < audit[i + 1].sequence_number,
            "Audit records should be in sequence order"
        );
    }
}

// ============================================================================
// Test 5: Propagation Respects Evidence Weighting
// ============================================================================

#[test]
fn test_propagation_respects_evidence_weighting() {
    // Claims with higher evidence strength should receive larger truth updates.

    let mut orchestrator = PropagationOrchestrator::new();

    // Create source claim
    let source = create_test_claim(0.5);
    let source_id = source.id;
    orchestrator.register_claim(source).unwrap();

    // Create two dependent claims with different evidence strengths
    let weak_dep = create_test_claim(0.5);
    let weak_dep_id = weak_dep.id;
    orchestrator.register_claim(weak_dep).unwrap();

    let strong_dep = create_test_claim(0.5);
    let strong_dep_id = strong_dep.id;
    orchestrator.register_claim(strong_dep).unwrap();

    // Add dependencies with different strengths
    orchestrator
        .add_dependency(source_id, weak_dep_id, true, 0.2) // Weak evidence
        .unwrap();
    orchestrator
        .add_dependency(source_id, strong_dep_id, true, 0.9) // Strong evidence
        .unwrap();

    // Update source to high truth
    orchestrator
        .update_and_propagate(source_id, TruthValue::new(0.9).unwrap())
        .unwrap();

    // Verify strong evidence produced larger update
    let weak_truth = orchestrator.get_truth(weak_dep_id).unwrap().value();
    let strong_truth = orchestrator.get_truth(strong_dep_id).unwrap().value();

    assert!(
        strong_truth > weak_truth,
        "Strong evidence ({strong_truth}) should produce larger truth update than weak evidence ({weak_truth})"
    );

    // Both should increase from 0.5 (supporting evidence)
    assert!(
        weak_truth > 0.5,
        "Weak evidence should still increase truth"
    );
    assert!(strong_truth > 0.5, "Strong evidence should increase truth");
}

// ============================================================================
// Test 6: Propagation Stops at Already-Visited Nodes (No Infinite Loops)
// ============================================================================

#[test]
fn test_no_infinite_loops_diamond_dag() {
    // Diamond DAG: A -> B, A -> C, B -> D, C -> D
    // D should only be updated once, not twice.

    let mut orchestrator = PropagationOrchestrator::new();

    // Create claims
    let claim_a = create_test_claim(0.5);
    let claim_b = create_test_claim(0.5);
    let claim_c = create_test_claim(0.5);
    let claim_d = create_test_claim(0.5);

    let id_a = claim_a.id;
    let id_b = claim_b.id;
    let id_c = claim_c.id;
    let id_d = claim_d.id;

    orchestrator.register_claim(claim_a).unwrap();
    orchestrator.register_claim(claim_b).unwrap();
    orchestrator.register_claim(claim_c).unwrap();
    orchestrator.register_claim(claim_d).unwrap();

    // Create diamond: A -> B, A -> C, B -> D, C -> D
    orchestrator.add_dependency(id_a, id_b, true, 0.8).unwrap();
    orchestrator.add_dependency(id_a, id_c, true, 0.8).unwrap();
    orchestrator.add_dependency(id_b, id_d, true, 0.8).unwrap();
    orchestrator.add_dependency(id_c, id_d, true, 0.8).unwrap();

    // Update A
    let updated = orchestrator
        .update_and_propagate(id_a, TruthValue::new(0.9).unwrap())
        .unwrap();

    // D should only appear once in the updated set
    assert_eq!(
        updated.iter().filter(|&&id| id == id_d).count(),
        1,
        "D should only be updated once despite two paths"
    );

    // Count audit records for D - should only be 1
    let d_audit_count = orchestrator
        .get_audit_trail()
        .iter()
        .filter(|r| r.claim_id == id_d)
        .count();
    assert_eq!(
        d_audit_count, 1,
        "D should only have one audit record (visited once)"
    );
}

#[test]
fn test_cycle_prevention_via_dag_validator() {
    // Attempting to create a cycle should be rejected by the DAG validator.

    let mut orchestrator = PropagationOrchestrator::new();

    let claim_a = create_test_claim(0.5);
    let claim_b = create_test_claim(0.5);

    let id_a = claim_a.id;
    let id_b = claim_b.id;

    orchestrator.register_claim(claim_a).unwrap();
    orchestrator.register_claim(claim_b).unwrap();

    // A -> B is valid
    orchestrator.add_dependency(id_a, id_b, true, 0.8).unwrap();

    // B -> A would create a cycle - should fail
    let result = orchestrator.add_dependency(id_b, id_a, true, 0.8);
    assert!(
        matches!(result, Err(EngineError::CycleDetected { .. })),
        "Cycle should be rejected"
    );
}

// ============================================================================
// Test 7: Concurrent Propagations Don't Corrupt State
// ============================================================================

#[test]
fn test_concurrent_propagations_thread_safety() {
    // Multiple threads updating different parts of the DAG should not corrupt state.

    use std::thread;

    let orchestrator = ConcurrentOrchestrator::new();

    // Setup: Create a star topology (center with multiple independent branches)
    {
        let mut orch = orchestrator.inner.write().unwrap();

        // Center claim
        let center = create_test_claim(0.5);
        let center_id = center.id;
        orch.register_claim(center).unwrap();

        // Create 10 branches, each with 3 claims
        for _branch in 0..10 {
            let mut prev_id = center_id;
            for _depth in 0..3 {
                let claim = create_test_claim(0.5);
                let claim_id = claim.id;
                orch.register_claim(claim).unwrap();
                orch.add_dependency(prev_id, claim_id, true, 0.7).unwrap();
                prev_id = claim_id;
            }
        }
    }

    // Concurrent updates from multiple threads
    let mut handles = vec![];

    for _ in 0..5 {
        let orch_clone = orchestrator.clone_arc();
        let handle = thread::spawn(move || {
            let mut orch = orch_clone.inner.write().unwrap();
            // Get the first claim (center) and update it
            if let Some((&claim_id, _)) = orch.claims.iter().next() {
                let _ = orch
                    .update_and_propagate(claim_id, TruthValue::new(0.7 + rand_float()).unwrap());
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should complete without panic");
    }

    // Verify the orchestrator is still in a consistent state
    let orch = orchestrator.inner.read().unwrap();

    // All claims should have valid truth values
    for claim in orch.claims.values() {
        let truth = claim.truth_value.value();
        assert!(
            (0.0..=1.0).contains(&truth),
            "Truth value should be valid after concurrent updates"
        );
    }

    // DAG should still be valid
    assert!(
        orch.dag.is_valid(),
        "DAG should remain valid after concurrent updates"
    );
}

/// Simple pseudo-random float for testing (deterministic)
fn rand_float() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    f64::from(nanos % 100) / 500.0 // 0.0 to 0.198
}

// ============================================================================
// Test 8: Propagation Audit Trail is Recorded
// ============================================================================

#[test]
fn test_audit_trail_completeness() {
    // Every propagation event should be recorded in the audit trail with
    // complete information.

    let mut orchestrator = PropagationOrchestrator::new();

    // Create a simple chain: A -> B -> C
    let claim_a = create_test_claim(0.4);
    let claim_b = create_test_claim(0.5);
    let claim_c = create_test_claim(0.6);

    let id_a = claim_a.id;
    let id_b = claim_b.id;
    let id_c = claim_c.id;

    orchestrator.register_claim(claim_a).unwrap();
    orchestrator.register_claim(claim_b).unwrap();
    orchestrator.register_claim(claim_c).unwrap();

    // A -> B (supporting), B -> C (refuting)
    orchestrator.add_dependency(id_a, id_b, true, 0.8).unwrap();
    orchestrator.add_dependency(id_b, id_c, false, 0.7).unwrap();

    // Update A
    orchestrator
        .update_and_propagate(id_a, TruthValue::new(0.9).unwrap())
        .unwrap();

    let audit = orchestrator.get_audit_trail();

    // Should have 2 records (B and C were updated)
    assert_eq!(audit.len(), 2, "Should have 2 audit records");

    // First record: B was updated from A (supporting)
    let b_record = audit.iter().find(|r| r.claim_id == id_b).unwrap();
    assert_eq!(b_record.source_claim_id, id_a);
    assert!(b_record.is_supporting);
    assert_eq!(b_record.prior_truth.value(), 0.5);
    assert!(b_record.posterior_truth.value() > 0.5); // Increased from support

    // Second record: C was updated from B (refuting)
    let c_record = audit.iter().find(|r| r.claim_id == id_c).unwrap();
    assert_eq!(c_record.source_claim_id, id_b);
    assert!(!c_record.is_supporting);
    assert_eq!(c_record.prior_truth.value(), 0.6);
    // C should decrease from refutation
    assert!(c_record.posterior_truth.value() < 0.6);

    // Verify sequence ordering
    assert!(
        b_record.sequence_number < c_record.sequence_number,
        "B should be updated before C in sequence"
    );
}

#[test]
fn test_audit_trail_can_be_cleared() {
    let mut orchestrator = PropagationOrchestrator::new();

    let claim_a = create_test_claim(0.5);
    let claim_b = create_test_claim(0.5);
    let id_a = claim_a.id;
    let id_b = claim_b.id;

    orchestrator.register_claim(claim_a).unwrap();
    orchestrator.register_claim(claim_b).unwrap();
    orchestrator.add_dependency(id_a, id_b, true, 0.8).unwrap();

    // First propagation
    orchestrator
        .update_and_propagate(id_a, TruthValue::new(0.7).unwrap())
        .unwrap();
    assert_eq!(orchestrator.get_audit_trail().len(), 1);

    // Clear audit trail
    orchestrator.clear_audit_trail();
    assert!(orchestrator.get_audit_trail().is_empty());

    // Second propagation should start fresh
    orchestrator
        .update_and_propagate(id_a, TruthValue::new(0.8).unwrap())
        .unwrap();
    assert_eq!(orchestrator.get_audit_trail().len(), 1);
    assert_eq!(orchestrator.get_audit_trail()[0].sequence_number, 1);
}

// ============================================================================
// Test 9: Propagation with Conflicting Evidence
// ============================================================================

#[test]
fn test_conflicting_evidence_balanced() {
    // Claim B has two sources: A supports it, C refutes it.
    // The net effect should depend on the relative strengths.

    let mut orchestrator = PropagationOrchestrator::new();

    // Source claims
    let claim_a = create_test_claim(0.8); // Strong support source
    let claim_c = create_test_claim(0.8); // Strong refutation source
    let claim_b = create_test_claim(0.5); // Target claim

    let id_a = claim_a.id;
    let id_c = claim_c.id;
    let id_b = claim_b.id;

    orchestrator.register_claim(claim_a).unwrap();
    orchestrator.register_claim(claim_c).unwrap();
    orchestrator.register_claim(claim_b).unwrap();

    // A supports B, C refutes B (equal strength)
    orchestrator.add_dependency(id_a, id_b, true, 0.8).unwrap();
    orchestrator.add_dependency(id_c, id_b, false, 0.8).unwrap();

    // Update A (supporting) to high truth
    orchestrator
        .update_and_propagate(id_a, TruthValue::new(0.9).unwrap())
        .unwrap();

    let b_truth_after_support = orchestrator.get_truth(id_b).unwrap().value();
    assert!(
        b_truth_after_support > 0.5,
        "After support, B should increase. Got: {b_truth_after_support}"
    );

    // Now update C (refuting) to high truth
    orchestrator.clear_audit_trail();
    orchestrator
        .update_and_propagate(id_c, TruthValue::new(0.9).unwrap())
        .unwrap();

    let b_truth_after_refutation = orchestrator.get_truth(id_b).unwrap().value();

    // B should decrease from the refutation
    assert!(
        b_truth_after_refutation < b_truth_after_support,
        "After refutation, B should decrease. Was: {b_truth_after_support}, Now: {b_truth_after_refutation}"
    );
}

#[test]
fn test_conflicting_evidence_stronger_wins() {
    // When one piece of evidence is stronger, it should dominate.

    let mut orchestrator = PropagationOrchestrator::new();

    let support_source = create_test_claim(0.5);
    let refute_source = create_test_claim(0.5);
    let target = create_test_claim(0.5);

    let support_id = support_source.id;
    let refute_id = refute_source.id;
    let target_id = target.id;

    orchestrator.register_claim(support_source).unwrap();
    orchestrator.register_claim(refute_source).unwrap();
    orchestrator.register_claim(target).unwrap();

    // Weak support, strong refutation
    orchestrator
        .add_dependency(support_id, target_id, true, 0.3)
        .unwrap();
    orchestrator
        .add_dependency(refute_id, target_id, false, 0.9)
        .unwrap();

    // Update both sources to same truth
    orchestrator
        .update_and_propagate(support_id, TruthValue::new(0.8).unwrap())
        .unwrap();
    orchestrator
        .update_and_propagate(refute_id, TruthValue::new(0.8).unwrap())
        .unwrap();

    // Strong refutation should win - target truth should decrease below 0.5
    let target_truth = orchestrator.get_truth(target_id).unwrap().value();
    assert!(
        target_truth < 0.5,
        "Stronger refutation should pull truth down. Got: {target_truth}"
    );
}

// ============================================================================
// Test 10: BAD ACTOR TEST - Reputation NEVER Inflates Dependents
// ============================================================================

/// # THE BAD ACTOR TEST FOR PROPAGATION
///
/// This is the CRITICAL test that validates the core epistemic principle:
/// Agent reputation MUST NOT influence truth propagation.
///
/// ## Scenario
/// 1. High-reputation agent makes Claim A with weak evidence
/// 2. Claim B depends on Claim A
/// 3. When A's truth propagates to B, only the EVIDENCE strength matters
/// 4. The agent's reputation MUST NOT inflate B's truth
///
/// ## Why This Matters
/// If reputation could inflate propagated truths, a high-reputation agent could:
/// 1. Make a weakly-supported claim
/// 2. Have other claims depend on it
/// 3. Those dependent claims would get inflated truth
/// 4. This creates an "authority cascade" - the Appeal to Authority fallacy
///
/// The propagation system MUST use only:
/// - The source claim's truth value
/// - The evidence strength of the dependency
///
/// It MUST NOT use:
/// - Agent reputation scores
/// - Historical trust metrics
/// - Any authority-based weighting
#[test]
fn bad_actor_test_reputation_never_inflates_propagation() {
    let mut orchestrator = PropagationOrchestrator::new();

    // Create two agents: one with high reputation, one with low
    let high_rep_agent = AgentId::new();
    let low_rep_agent = AgentId::new();

    orchestrator.register_agent(high_rep_agent, 0.95); // Stellar reputation
    orchestrator.register_agent(low_rep_agent, 0.20); // Poor reputation

    // Both agents make claims with IDENTICAL weak evidence
    let weak_evidence_strength = 0.3;

    // High-rep agent's claim
    let high_rep_claim = create_claim_with_agent(0.5, high_rep_agent);
    let high_rep_id = high_rep_claim.id;
    orchestrator.register_claim(high_rep_claim).unwrap();

    // Low-rep agent's claim
    let low_rep_claim = create_claim_with_agent(0.5, low_rep_agent);
    let low_rep_id = low_rep_claim.id;
    orchestrator.register_claim(low_rep_claim).unwrap();

    // Dependent claims (identical setup)
    let dep_on_high = create_test_claim(0.5);
    let dep_on_low = create_test_claim(0.5);
    let dep_high_id = dep_on_high.id;
    let dep_low_id = dep_on_low.id;

    orchestrator.register_claim(dep_on_high).unwrap();
    orchestrator.register_claim(dep_on_low).unwrap();

    // Same evidence strength for both dependencies
    orchestrator
        .add_dependency(high_rep_id, dep_high_id, true, weak_evidence_strength)
        .unwrap();
    orchestrator
        .add_dependency(low_rep_id, dep_low_id, true, weak_evidence_strength)
        .unwrap();

    // Update both source claims to the same truth value
    let source_truth = TruthValue::new(0.7).unwrap();
    orchestrator
        .update_and_propagate(high_rep_id, source_truth)
        .unwrap();
    orchestrator
        .update_and_propagate(low_rep_id, source_truth)
        .unwrap();

    // CRITICAL ASSERTION: Both dependents should have THE SAME truth value
    let high_dep_truth = orchestrator.get_truth(dep_high_id).unwrap().value();
    let low_dep_truth = orchestrator.get_truth(dep_low_id).unwrap().value();

    // Allow tiny floating point tolerance
    let tolerance = 1e-10;
    assert!(
        (high_dep_truth - low_dep_truth).abs() < tolerance,
        "BAD ACTOR TEST FAILED: High-reputation agent's dependent has truth {high_dep_truth} \
         but low-reputation agent's dependent has truth {low_dep_truth}. \
         Reputation MUST NOT influence propagation!"
    );
}

#[test]
fn bad_actor_test_weak_evidence_stays_weak_regardless_of_source() {
    // Even if a claim comes from a high-reputation agent,
    // weak evidence should produce weak truth updates in dependents.

    let mut orchestrator = PropagationOrchestrator::new();

    // Nobel laureate agent with stellar reputation
    let nobel_agent = AgentId::new();
    orchestrator.register_agent(nobel_agent, 0.99);

    // Nobel laureate makes a claim (starts with weak truth - weak evidence)
    let source = create_claim_with_agent(0.3, nobel_agent); // Low initial truth = weak evidence
    let source_id = source.id;
    orchestrator.register_claim(source).unwrap();

    // Dependent claim
    let dependent = create_test_claim(0.5);
    let dep_id = dependent.id;
    orchestrator.register_claim(dependent).unwrap();

    // Very weak evidence strength
    orchestrator
        .add_dependency(source_id, dep_id, true, 0.2)
        .unwrap();

    // Even updating the source to moderate truth...
    orchestrator
        .update_and_propagate(source_id, TruthValue::new(0.6).unwrap())
        .unwrap();

    // The dependent should only get a small boost
    let dep_truth = orchestrator.get_truth(dep_id).unwrap().value();

    assert!(
        dep_truth < 0.7,
        "BAD ACTOR TEST: Weak evidence (0.2 strength) from high-rep agent \
         should not produce high truth in dependent. Got: {dep_truth}"
    );
}

#[test]
fn bad_actor_test_no_authority_cascade() {
    // Test that a high-reputation agent cannot create an "authority cascade"
    // where their claims artificially inflate a chain of dependent claims.

    let mut orchestrator = PropagationOrchestrator::new();

    // Create the "authority" agent
    let authority_agent = AgentId::new();
    orchestrator.register_agent(authority_agent, 0.98);

    // Authority makes a claim with NO real evidence (starts at uncertainty)
    let authority_claim = create_claim_with_agent(0.5, authority_agent);
    let authority_id = authority_claim.id;
    orchestrator.register_claim(authority_claim).unwrap();

    // Create a chain of 5 dependent claims
    let mut chain_ids = vec![authority_id];
    for _ in 0..5 {
        let claim = create_test_claim(0.5);
        let claim_id = claim.id;
        orchestrator.register_claim(claim).unwrap();

        // Weak evidence strength throughout
        orchestrator
            .add_dependency(*chain_ids.last().unwrap(), claim_id, true, 0.3)
            .unwrap();
        chain_ids.push(claim_id);
    }

    // Authority "asserts" their claim is true (but with no evidence, starts at 0.5)
    // Even if they update to moderate truth...
    orchestrator
        .update_and_propagate(authority_id, TruthValue::new(0.65).unwrap())
        .unwrap();

    // The END of the chain should NOT have high truth
    let final_truth = orchestrator
        .get_truth(*chain_ids.last().unwrap())
        .unwrap()
        .value();

    assert!(
        final_truth < 0.75,
        "BAD ACTOR TEST: Authority cascade should not produce high truth \
         at end of chain. Got: {final_truth} (expected < 0.75)"
    );

    // Also verify: each step in the chain should show decay, not amplification
    let mut prev_truth = orchestrator.get_truth(chain_ids[0]).unwrap().value();
    for &claim_id in &chain_ids[1..] {
        let truth = orchestrator.get_truth(claim_id).unwrap().value();
        // Truth increase should be bounded by weak evidence
        let increase = truth - 0.5; // How much above uncertainty
        assert!(
            increase < prev_truth - 0.5 + 0.2, // Should not amplify much
            "Chain should not amplify authority's influence"
        );
        prev_truth = truth;
    }
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

#[test]
fn test_update_nonexistent_claim_fails() {
    let mut orchestrator = PropagationOrchestrator::new();

    let fake_id = ClaimId::new();
    let result = orchestrator.update_and_propagate(fake_id, TruthValue::new(0.5).unwrap());

    assert!(
        matches!(result, Err(EngineError::NodeNotFound(_))),
        "Updating nonexistent claim should fail"
    );
}

#[test]
fn test_truth_clamping_during_propagation() {
    // Ensure truth values stay in [0.01, 0.99] during propagation
    // (no certainty lock-in)

    let mut orchestrator = PropagationOrchestrator::new();

    let source = create_test_claim(0.5);
    let source_id = source.id;
    orchestrator.register_claim(source).unwrap();

    // Create dependent starting near the edge
    let agent_id = AgentId::new();
    let edge_claim = Claim::new(
        "Near edge".to_string(),
        agent_id,
        [0u8; 32],                      // public_key
        TruthValue::new(0.95).unwrap(), // Near maximum
    );
    let edge_id = edge_claim.id;
    orchestrator.register_claim(edge_claim).unwrap();

    // Very strong supporting evidence
    orchestrator
        .add_dependency(source_id, edge_id, true, 1.0)
        .unwrap();

    // Update source to max
    orchestrator
        .update_and_propagate(source_id, TruthValue::new(0.99).unwrap())
        .unwrap();

    // Edge claim should be clamped to max_truth (0.99)
    let edge_truth = orchestrator.get_truth(edge_id).unwrap().value();
    assert!(
        edge_truth <= 0.99,
        "Truth should be clamped to max 0.99. Got: {edge_truth}"
    );
}

#[test]
fn test_zero_strength_dependency_no_effect() {
    // A dependency with zero strength should have no effect.

    let mut orchestrator = PropagationOrchestrator::new();

    let source = create_test_claim(0.5);
    let dependent = create_test_claim(0.5);
    let source_id = source.id;
    let dep_id = dependent.id;

    orchestrator.register_claim(source).unwrap();
    orchestrator.register_claim(dependent).unwrap();
    orchestrator
        .add_dependency(source_id, dep_id, true, 0.0)
        .unwrap();

    orchestrator
        .update_and_propagate(source_id, TruthValue::new(0.9).unwrap())
        .unwrap();

    // Dependent should stay at 0.5 (or very close due to floating point)
    let dep_truth = orchestrator.get_truth(dep_id).unwrap().value();
    assert!(
        (dep_truth - 0.5).abs() < 0.05,
        "Zero-strength dependency should have minimal effect. Got: {dep_truth}"
    );
}

#[test]
fn test_large_dag_performance() {
    // Test with a larger DAG to ensure reasonable performance.
    // This is more of a smoke test than a strict performance test.

    let mut orchestrator = PropagationOrchestrator::new();

    // Create 100 claims in a wide tree structure
    let root = create_test_claim(0.5);
    let root_id = root.id;
    orchestrator.register_claim(root).unwrap();

    // Level 1: 10 direct children
    let mut level1_ids = Vec::new();
    for _ in 0..10 {
        let claim = create_test_claim(0.5);
        let id = claim.id;
        orchestrator.register_claim(claim).unwrap();
        orchestrator.add_dependency(root_id, id, true, 0.7).unwrap();
        level1_ids.push(id);
    }

    // Level 2: Each level-1 has 5 children (50 total)
    for &parent_id in &level1_ids {
        for _ in 0..5 {
            let claim = create_test_claim(0.5);
            let id = claim.id;
            orchestrator.register_claim(claim).unwrap();
            orchestrator
                .add_dependency(parent_id, id, true, 0.6)
                .unwrap();
        }
    }

    // Update root and verify propagation completes
    let updated = orchestrator
        .update_and_propagate(root_id, TruthValue::new(0.8).unwrap())
        .unwrap();

    // Should have updated 10 + 50 = 60 claims
    assert_eq!(updated.len(), 60, "Should propagate to all 60 descendants");

    // Verify all updated claims have valid truth values
    for claim_id in updated {
        let truth = orchestrator.get_truth(claim_id).unwrap().value();
        assert!(truth > 0.5, "All descendants should have increased truth");
    }
}

// ============================================================================
// Property-Based Tests (using proptest)
// ============================================================================

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Truth values always stay bounded after propagation
        #[test]
        fn prop_truth_always_bounded(
            initial_truth in 0.01f64..0.99,
            source_truth in 0.01f64..0.99,
            strength in 0.0f64..1.0,
        ) {
            let mut orchestrator = PropagationOrchestrator::new();

            let source = create_test_claim(0.5);
            let source_id = source.id;
            orchestrator.register_claim(source).unwrap();

            let agent_id = AgentId::new();
            let dependent = Claim::new(
                "Prop test".to_string(),
                agent_id,
                [0u8; 32], // public_key
                TruthValue::new(initial_truth).unwrap(),
            );
            let dep_id = dependent.id;
            orchestrator.register_claim(dependent).unwrap();
            orchestrator.add_dependency(source_id, dep_id, true, strength).unwrap();

            orchestrator
                .update_and_propagate(source_id, TruthValue::new(source_truth).unwrap())
                .unwrap();

            let final_truth = orchestrator.get_truth(dep_id).unwrap().value();
            prop_assert!((0.01..=0.99).contains(&final_truth),
                "Truth {} out of bounds", final_truth);
        }

        /// Supporting evidence never decreases truth (for positive source truth)
        #[test]
        fn prop_support_never_decreases(
            initial_truth in 0.3f64..0.7,
            source_truth in 0.5f64..0.99,
            strength in 0.1f64..1.0,
        ) {
            let mut orchestrator = PropagationOrchestrator::new();

            let source = create_test_claim(0.5);
            let source_id = source.id;
            orchestrator.register_claim(source).unwrap();

            let agent_id = AgentId::new();
            let dependent = Claim::new(
                "Prop test".to_string(),
                agent_id,
                [0u8; 32], // public_key
                TruthValue::new(initial_truth).unwrap(),
            );
            let dep_id = dependent.id;
            orchestrator.register_claim(dependent).unwrap();
            orchestrator.add_dependency(source_id, dep_id, true, strength).unwrap();

            orchestrator
                .update_and_propagate(source_id, TruthValue::new(source_truth).unwrap())
                .unwrap();

            let final_truth = orchestrator.get_truth(dep_id).unwrap().value();
            prop_assert!(final_truth >= initial_truth - 0.01,
                "Support should not decrease truth: {} -> {}", initial_truth, final_truth);
        }

        /// Refuting evidence never increases truth (for positive source truth)
        #[test]
        fn prop_refutation_never_increases(
            initial_truth in 0.3f64..0.7,
            source_truth in 0.5f64..0.99,
            strength in 0.1f64..1.0,
        ) {
            let mut orchestrator = PropagationOrchestrator::new();

            let source = create_test_claim(0.5);
            let source_id = source.id;
            orchestrator.register_claim(source).unwrap();

            let agent_id = AgentId::new();
            let dependent = Claim::new(
                "Prop test".to_string(),
                agent_id,
                [0u8; 32], // public_key
                TruthValue::new(initial_truth).unwrap(),
            );
            let dep_id = dependent.id;
            orchestrator.register_claim(dependent).unwrap();
            orchestrator.add_dependency(source_id, dep_id, false, strength).unwrap();

            orchestrator
                .update_and_propagate(source_id, TruthValue::new(source_truth).unwrap())
                .unwrap();

            let final_truth = orchestrator.get_truth(dep_id).unwrap().value();
            prop_assert!(final_truth <= initial_truth + 0.01,
                "Refutation should not increase truth: {} -> {}", initial_truth, final_truth);
        }
    }
}
