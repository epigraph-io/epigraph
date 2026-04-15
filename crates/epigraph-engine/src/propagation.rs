//! Truth Propagation Orchestrator
//!
//! Propagates truth value changes across the reasoning DAG using a simple
//! proportional influence model (stopgap replacing non-commutative Bayesian updates).
//! When a claim's truth value changes, this orchestrator:
//!
//! 1. Identifies all dependent claims
//! 2. Recalculates their truth values using a proportional influence nudge
//! 3. Recursively propagates to their dependents
//! 4. Records an audit trail of all updates
//! 5. Prevents cycles and infinite loops
//!
//! # Key Algorithm
//!
//! ```text
//! 1. Get claim and its dependents from DAG
//! 2. For each dependent:
//!    a. influence = source_truth * dep.strength
//!    b. supporting: posterior = current + influence * (1 - current) * 0.1
//!    c. refuting:   posterior = current - influence * current * 0.1
//!    d. Mark node as visited
//!    e. Recursively propagate to dependents
//! 3. Record audit trail
//! ```
//!
//! # Note
//!
//! Full CDST-based transitive propagation is deferred to a separate spec.
//! `BayesianUpdater` has been removed from this module; it is deprecated.
//!
//! # Core Principle
//!
//! Agent reputation NEVER influences truth propagation. Only the source claim's
//! truth value and evidence strength determine updates. This prevents the
//! "Appeal to Authority" fallacy.

use crate::{DagValidator, EngineError, EvidenceType, EvidenceWeighter};
use epigraph_core::{AgentId, Claim, ClaimId, TruthValue};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};

/// Maximum number of audit entries to retain in the audit trail.
/// Implements circular buffer behavior: oldest entries are evicted when limit is exceeded.
/// Prevents unbounded memory growth from long-running propagation operations.
const MAX_AUDIT_ENTRIES: usize = 100_000;

/// Represents a dependency relationship between claims
///
/// When the source claim's truth value changes, the dependent claim
/// should be updated according to this relationship.
#[derive(Debug, Clone)]
pub struct ClaimDependency {
    /// The claim that depends on another
    pub dependent_id: ClaimId,
    /// Whether this is supporting (true) or refuting (false) evidence
    pub is_supporting: bool,
    /// Base strength of the dependency relationship [0, 1]
    pub strength: f64,
    /// Type of evidence (affects weight calculation)
    pub evidence_type: EvidenceType,
    /// Age of the evidence in days (for temporal decay)
    pub age_days: f64,
}

/// Audit record for a single propagation event
///
/// Provides complete traceability for truth value changes
/// during propagation, enabling forensic analysis of how
/// beliefs evolved through the reasoning graph.
#[derive(Debug, Clone)]
pub struct PropagationAuditRecord {
    /// The claim that was updated
    pub claim_id: ClaimId,
    /// Truth value before propagation
    pub prior_truth: TruthValue,
    /// Truth value after propagation
    pub posterior_truth: TruthValue,
    /// The source claim that triggered this update
    pub source_claim_id: ClaimId,
    /// Whether this was from supporting or refuting evidence
    pub is_supporting: bool,
    /// Type of evidence used for this update
    pub evidence_type: EvidenceType,
    /// The calculated evidence weight applied
    pub evidence_weight: f64,
    /// Timestamp of the propagation (simplified as counter)
    pub sequence_number: u64,
}

/// The Truth Propagation Orchestrator
///
/// Propagates truth value changes across the reasoning DAG using a proportional
/// influence model. When a claim's truth value changes, this orchestrator:
///
/// 1. Identifies all dependent claims
/// 2. Recalculates their truth values using a proportional nudge
/// 3. Recursively propagates to their dependents
/// 4. Records an audit trail of all updates
/// 5. Prevents cycles and infinite loops
///
/// # Core Invariant
///
/// Agent reputation is NEVER used in propagation calculations.
/// Only the source claim's truth value and evidence strength
/// determine the update magnitude. This architectural choice
/// prevents "authority cascades" where high-reputation agents
/// could artificially inflate truth values through the graph.
pub struct PropagationOrchestrator {
    /// DAG validator for cycle detection
    dag: DagValidator,
    /// Evidence weighter for calculating evidence strength
    ///
    /// Weights depend on evidence type:
    /// - Empirical (1.0): Direct observation/measurement
    /// - Statistical (0.9): Reproducible data
    /// - Logical (0.85): Valid reasoning derivation
    /// - Testimonial (0.6): Expert opinion/testimony
    /// - Circumstantial (0.4): Indirect evidence
    evidence_weighter: EvidenceWeighter,
    /// Map from claim ID to claim data
    claims: HashMap<ClaimId, Claim>,
    /// Map from claim ID to its dependents (claims that depend on it)
    dependents: HashMap<ClaimId, Vec<ClaimDependency>>,
    /// Audit trail of all propagation events
    audit_trail: Vec<PropagationAuditRecord>,
    /// Counter for audit sequence numbers
    sequence_counter: u64,
    /// Agent reputation scores (stored but NEVER used in propagation).
    ///
    /// # Why store if not used?
    ///
    /// Reputations are stored for other purposes (display, filtering, etc.)
    /// but explicitly excluded from propagation calculations. This design
    /// makes the "no reputation influence" principle explicit and auditable.
    ///
    /// # TODO
    ///
    /// Reserved for future reputation-weighted propagation feature where
    /// agent credibility adjusts the *prior* on submitted evidence, not the
    /// propagation calculation itself (to preserve the no-authority-cascade
    /// invariant). Until that feature lands this field is write-only.
    #[allow(dead_code)]
    agent_reputations: HashMap<AgentId, f64>,
}

impl PropagationOrchestrator {
    /// Create a new propagation orchestrator
    #[must_use]
    pub fn new() -> Self {
        Self {
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
    ///
    /// # Errors
    ///
    /// Returns an error if the claim cannot be added to the DAG.
    pub fn register_claim(&mut self, claim: Claim) -> Result<(), EngineError> {
        let claim_id = claim.id;
        self.dag.add_node(claim_id.as_uuid());
        self.claims.insert(claim_id, claim);
        self.dependents.entry(claim_id).or_default();
        Ok(())
    }

    /// Register an agent with a reputation score
    ///
    /// # Note
    ///
    /// Reputation is stored for reference but NEVER used in propagation
    /// calculations. This is an intentional architectural decision to
    /// prevent the "Appeal to Authority" fallacy.
    pub fn register_agent(&mut self, agent_id: AgentId, reputation: f64) {
        self.agent_reputations.insert(agent_id, reputation);
    }

    /// Add a dependency relationship: `dependent` depends on `source`
    ///
    /// When `source`'s truth value changes, `dependent`'s truth should be updated.
    ///
    /// # Arguments
    ///
    /// * `source_id` - The claim that provides evidence
    /// * `dependent_id` - The claim that depends on the source
    /// * `is_supporting` - Whether this is supporting (true) or refuting (false) evidence
    /// * `strength` - Base strength of the dependency relationship [0, 1]
    /// * `evidence_type` - Type of evidence (affects weight calculation)
    /// * `age_days` - Age of evidence in days (for temporal decay)
    ///
    /// # Errors
    ///
    /// Returns an error if adding this dependency would create a cycle in the DAG.
    pub fn add_dependency(
        &mut self,
        source_id: ClaimId,
        dependent_id: ClaimId,
        is_supporting: bool,
        strength: f64,
        evidence_type: EvidenceType,
        age_days: f64,
    ) -> Result<(), EngineError> {
        // Add edge to DAG (source -> dependent means dependent is affected by source)
        self.dag
            .add_edge(source_id.as_uuid(), dependent_id.as_uuid())?;

        // Record the dependency
        let dep = ClaimDependency {
            dependent_id,
            is_supporting,
            strength,
            evidence_type,
            age_days,
        };
        self.dependents.entry(source_id).or_default().push(dep);
        Ok(())
    }

    /// Update a claim's truth value and propagate to dependents
    ///
    /// This is the core propagation algorithm. It uses BFS to ensure correct
    /// ordering (closer dependents are updated before further ones) and tracks
    /// visited nodes to prevent infinite loops in diamond-shaped DAGs.
    ///
    /// # Algorithm
    ///
    /// 1. Update the source claim's truth value
    /// 2. Initialize BFS queue with source claim
    /// 3. For each claim in queue:
    ///    a. Get its dependents
    ///    b. For each unvisited dependent:
    ///       - Calculate effective evidence strength (dependency strength * source truth)
    ///       - Apply proportional influence nudge (support or refutation)
    ///       - Record audit trail
    ///       - Update dependent's truth value
    ///       - Add dependent to queue for further propagation
    ///
    /// # Arguments
    ///
    /// * `claim_id` - The claim whose truth value is changing
    /// * `new_truth` - The new truth value for the claim
    ///
    /// # Returns
    ///
    /// The set of claim IDs that were updated during propagation (not including source).
    ///
    /// # Errors
    ///
    /// Returns an error if the claim is not found.
    pub fn update_and_propagate(
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

                    // Calculate evidence weight based on:
                    // - Evidence type (Empirical=1.0, Statistical=0.9, Logical=0.85, etc.)
                    // - Source claim's truth value (evidence from uncertain sources weighs less)
                    // - Temporal decay (older evidence weighs less)
                    // - Base strength (relevance of the dependency)
                    //
                    // CRITICAL: Note that we use ONLY:
                    // - dep.evidence_type (evidence classification)
                    // - dep.strength (dependency relevance)
                    // - dep.age_days (temporal decay factor)
                    // - source_truth (source claim's truth value)
                    //
                    // We do NOT use:
                    // - Agent reputation
                    // - Historical trust metrics
                    // - Any authority-based weighting
                    let evidence_weight = self
                        .evidence_weighter
                        .calculate_weight(
                            dep.evidence_type,
                            Some(source_truth),
                            dep.strength, // Use strength as relevance
                            dep.age_days,
                        )
                        .unwrap_or_else(|_| dep.strength * source_truth.value()); // Fallback to simple calculation

                    // Use source truth as a scaling factor on dependency strength
                    // instead of running a Bayesian update.
                    // evidence_weight already encodes evidence type, temporal decay, and
                    // dep.strength via EvidenceWeighter, so we use it as the influence scalar.
                    // Full CDST-based transitive propagation is deferred to a separate spec.
                    let influence = evidence_weight;
                    let posterior = if dep.is_supporting {
                        // Nudge toward 1.0 proportional to influence
                        let current = prior.value();
                        TruthValue::clamped(current + influence * (1.0 - current) * 0.1)
                    } else {
                        // Nudge toward 0.0 proportional to influence
                        let current = prior.value();
                        TruthValue::clamped(current - influence * current * 0.1)
                    };

                    // Record audit trail with bounded size (DoS prevention)
                    // Evict oldest entries when at capacity to prevent unbounded memory growth
                    if self.audit_trail.len() >= MAX_AUDIT_ENTRIES {
                        // Remove oldest entry (circular buffer behavior)
                        // Consider using VecDeque for O(1) removal if this becomes a hotspot
                        self.audit_trail.remove(0);
                    }
                    self.sequence_counter += 1;
                    self.audit_trail.push(PropagationAuditRecord {
                        claim_id: dep.dependent_id,
                        prior_truth: prior,
                        posterior_truth: posterior,
                        source_claim_id: current_id,
                        is_supporting: dep.is_supporting,
                        evidence_type: dep.evidence_type,
                        evidence_weight,
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
    #[must_use]
    pub fn get_truth(&self, claim_id: ClaimId) -> Option<TruthValue> {
        self.claims.get(&claim_id).map(|c| c.truth_value)
    }

    /// Get the audit trail of all propagation events
    #[must_use]
    pub fn get_audit_trail(&self) -> &[PropagationAuditRecord] {
        &self.audit_trail
    }

    /// Clear the audit trail
    ///
    /// Resets both the trail and the sequence counter.
    pub fn clear_audit_trail(&mut self) {
        self.audit_trail.clear();
        self.sequence_counter = 0;
    }

    /// Get the number of dependents for a claim
    #[must_use]
    pub fn dependent_count(&self, claim_id: ClaimId) -> usize {
        self.dependents.get(&claim_id).map_or(0, Vec::len)
    }

    /// Get a reference to the underlying DAG validator
    ///
    /// Useful for checking DAG validity or getting topological order.
    #[must_use]
    pub const fn dag(&self) -> &DagValidator {
        &self.dag
    }

    /// Get a reference to the claims map
    #[must_use]
    pub const fn claims(&self) -> &HashMap<ClaimId, Claim> {
        &self.claims
    }

    /// Get a mutable reference to a claim
    pub fn get_claim_mut(&mut self, claim_id: ClaimId) -> Option<&mut Claim> {
        self.claims.get_mut(&claim_id)
    }
}

impl Default for PropagationOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper for concurrent propagation operations
///
/// Wraps `PropagationOrchestrator` in `Arc<RwLock<>>` for safe
/// concurrent access from multiple threads.
///
/// # Usage
///
/// ```ignore
/// let orchestrator = ConcurrentOrchestrator::new();
///
/// // Clone for use in another thread
/// let orch_clone = orchestrator.clone_arc();
///
/// thread::spawn(move || {
///     let mut orch = orch_clone.inner.write().unwrap();
///     // ... perform operations
/// });
/// ```
pub struct ConcurrentOrchestrator {
    /// The inner orchestrator wrapped in thread-safe containers
    pub inner: Arc<RwLock<PropagationOrchestrator>>,
}

impl ConcurrentOrchestrator {
    /// Create a new concurrent orchestrator
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(PropagationOrchestrator::new())),
        }
    }

    /// Clone the Arc for sharing with another thread
    #[must_use]
    pub fn clone_arc(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Default for ConcurrentOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// DATABASE-AWARE PROPAGATION
// =============================================================================

/// Result of a database propagation operation
///
/// Contains information about what was updated during propagation
/// for logging, auditing, and response construction.
#[derive(Debug, Clone)]
pub struct PropagationResult {
    /// The claim that triggered propagation
    pub source_claim_id: ClaimId,
    /// Claims that were updated during propagation
    pub updated_claims: HashSet<ClaimId>,
    /// Number of propagation levels traversed
    pub depth_reached: usize,
    /// Whether propagation stopped due to depth limit
    pub depth_limited: bool,
    /// Whether propagation stopped due to convergence
    pub converged: bool,
    /// Audit records generated during this propagation
    pub audit_records: Vec<PropagationAuditRecord>,
}

/// Configuration for propagation behavior
#[derive(Debug, Clone)]
pub struct PropagationConfig {
    /// Maximum depth to propagate (prevents infinite chains)
    pub max_depth: usize,
    /// Convergence threshold - stop if change is below this
    pub convergence_threshold: f64,
    /// Whether to run propagation synchronously or spawn background task
    pub run_async: bool,
}

impl Default for PropagationConfig {
    fn default() -> Self {
        Self {
            max_depth: 100,
            convergence_threshold: 0.001,
            run_async: false,
        }
    }
}

/// Database-aware propagation orchestrator
///
/// This struct provides the interface for triggering propagation after
/// database operations. It coordinates between the in-memory propagation
/// logic and the database persistence layer.
///
/// # Usage Pattern
///
/// ```ignore
/// // After claim is persisted to database
/// let propagator = DatabasePropagator::new(pool.clone(), config);
/// let result = propagator.propagate_from(claim_id).await?;
///
/// // Log the propagation result
/// tracing::info!(
///     claim_id = %claim_id,
///     updated_count = result.updated_claims.len(),
///     "Propagation completed"
/// );
/// ```
///
/// # Core Invariant
///
/// Agent reputation is NEVER used in propagation calculations. Only the
/// source claim's truth value and evidence strength determine updates.
#[derive(Clone)]
pub struct DatabasePropagator {
    /// Configuration for propagation behavior
    config: PropagationConfig,
}

impl DatabasePropagator {
    /// Create a new database propagator with the given configuration
    #[must_use]
    pub const fn new(config: PropagationConfig) -> Self {
        Self { config }
    }

    /// Create a new database propagator with default configuration
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(PropagationConfig::default())
    }

    /// Propagate truth value changes from a source claim
    ///
    /// This method:
    /// 1. Loads claim dependencies from the provided orchestrator
    /// 2. Runs BFS-based propagation with depth limiting
    /// 3. Tracks all updates for persistence
    /// 4. Returns a result containing all changes
    ///
    /// # Arguments
    ///
    /// * `orchestrator` - The in-memory orchestrator containing the claim graph
    /// * `source_claim_id` - The claim whose truth value changed
    /// * `new_truth` - The new truth value (if updating), or None to use current value
    ///
    /// # Returns
    ///
    /// A `PropagationResult` containing information about what was updated.
    ///
    /// # Errors
    ///
    /// Returns `EngineError` if propagation fails (e.g., claim not found).
    #[allow(clippy::too_many_lines)]
    pub fn propagate_from(
        &self,
        orchestrator: &mut PropagationOrchestrator,
        source_claim_id: ClaimId,
        new_truth: Option<TruthValue>,
    ) -> Result<PropagationResult, EngineError> {
        // Clear any existing audit trail for clean tracking
        let initial_audit_len = orchestrator.audit_trail.len();

        // Get or update the source claim's truth value
        let _source_truth = if let Some(truth) = new_truth {
            let claim = orchestrator
                .claims
                .get_mut(&source_claim_id)
                .ok_or(EngineError::NodeNotFound(source_claim_id.as_uuid()))?;
            claim.update_truth_value(truth);
            truth
        } else {
            orchestrator
                .get_truth(source_claim_id)
                .ok_or(EngineError::NodeNotFound(source_claim_id.as_uuid()))?
        };

        // Run propagation with depth tracking
        let mut updated_claims = HashSet::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut depth_map: HashMap<ClaimId, usize> = HashMap::new();

        // Initialize with source claim at depth 0
        queue.push_back(source_claim_id);
        visited.insert(source_claim_id);
        depth_map.insert(source_claim_id, 0);

        let mut max_depth_reached = 0;
        let mut depth_limited = false;
        let mut converged = false;

        while let Some(current_id) = queue.pop_front() {
            let current_depth = depth_map.get(&current_id).copied().unwrap_or(0);

            // Check depth limit
            if current_depth >= self.config.max_depth {
                depth_limited = true;
                continue;
            }

            let deps = orchestrator
                .dependents
                .get(&current_id)
                .cloned()
                .unwrap_or_default();

            for dep in deps {
                if visited.contains(&dep.dependent_id) {
                    continue;
                }
                visited.insert(dep.dependent_id);

                // Get source claim's current truth value
                let source_truth = orchestrator
                    .claims
                    .get(&current_id)
                    .map_or_else(TruthValue::uncertain, |c| c.truth_value);

                // Get the dependent claim
                if let Some(dependent_claim) = orchestrator.claims.get_mut(&dep.dependent_id) {
                    let prior = dependent_claim.truth_value;

                    // Calculate evidence weight using evidence type and other factors
                    // (NEVER uses agent reputation)
                    let evidence_weight = orchestrator
                        .evidence_weighter
                        .calculate_weight(
                            dep.evidence_type,
                            Some(source_truth),
                            dep.strength,
                            dep.age_days,
                        )
                        .unwrap_or_else(|_| dep.strength * source_truth.value());

                    // Use source truth as a scaling factor on dependency strength
                    // instead of running a Bayesian update.
                    // evidence_weight already encodes evidence type, temporal decay, and
                    // dep.strength via EvidenceWeighter, so we use it as the influence scalar.
                    // Full CDST-based transitive propagation is deferred to a separate spec.
                    let influence = evidence_weight;
                    let posterior = if dep.is_supporting {
                        // Nudge toward 1.0 proportional to influence
                        let current = prior.value();
                        TruthValue::clamped(current + influence * (1.0 - current) * 0.1)
                    } else {
                        // Nudge toward 0.0 proportional to influence
                        let current = prior.value();
                        TruthValue::clamped(current - influence * current * 0.1)
                    };

                    // Check for convergence
                    let change = (posterior.value() - prior.value()).abs();
                    if change < self.config.convergence_threshold {
                        converged = true;
                        // Still record the update but don't propagate further
                    }

                    // Record audit trail (with bounded size)
                    if orchestrator.audit_trail.len() >= MAX_AUDIT_ENTRIES {
                        orchestrator.audit_trail.remove(0);
                    }
                    orchestrator.sequence_counter += 1;
                    orchestrator.audit_trail.push(PropagationAuditRecord {
                        claim_id: dep.dependent_id,
                        prior_truth: prior,
                        posterior_truth: posterior,
                        source_claim_id: current_id,
                        is_supporting: dep.is_supporting,
                        evidence_type: dep.evidence_type,
                        evidence_weight,
                        sequence_number: orchestrator.sequence_counter,
                    });

                    // Update the dependent claim
                    dependent_claim.update_truth_value(posterior);
                    updated_claims.insert(dep.dependent_id);

                    // Track depth
                    let new_depth = current_depth + 1;
                    depth_map.insert(dep.dependent_id, new_depth);
                    max_depth_reached = max_depth_reached.max(new_depth);

                    // Add to queue for further propagation (unless converged)
                    if !converged || change >= self.config.convergence_threshold {
                        queue.push_back(dep.dependent_id);
                    }
                }
            }
        }

        // Collect audit records generated during this propagation
        let new_audit_records = orchestrator.audit_trail[initial_audit_len..].to_vec();

        Ok(PropagationResult {
            source_claim_id,
            updated_claims,
            depth_reached: max_depth_reached,
            depth_limited,
            converged,
            audit_records: new_audit_records,
        })
    }

    /// Get the configuration
    #[must_use]
    pub const fn config(&self) -> &PropagationConfig {
        &self.config
    }
}

impl Default for DatabasePropagator {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Helper to create a test claim with given truth value
    fn create_test_claim(truth: f64) -> Claim {
        let agent_id = AgentId::new();
        Claim::new(
            format!("Test claim with truth {truth}"),
            agent_id,
            [0u8; 32], // public_key
            TruthValue::new(truth).unwrap(),
        )
    }

    /// Helper to create a claim with a specific agent
    fn create_claim_with_agent(truth: f64, agent_id: AgentId) -> Claim {
        Claim::new(
            format!("Claim by agent with truth {truth}"),
            agent_id,
            [0u8; 32], // public_key
            TruthValue::new(truth).unwrap(),
        )
    }

    #[test]
    fn test_new_orchestrator_is_empty() {
        let orch = PropagationOrchestrator::new();
        assert!(orch.claims.is_empty());
        assert!(orch.audit_trail.is_empty());
        assert_eq!(orch.sequence_counter, 0);
    }

    #[test]
    fn test_register_claim() {
        let mut orch = PropagationOrchestrator::new();
        let claim = create_test_claim(0.5);
        let claim_id = claim.id;

        orch.register_claim(claim).unwrap();

        assert!(orch.claims.contains_key(&claim_id));
        assert_eq!(orch.dependent_count(claim_id), 0);
    }

    #[test]
    fn test_add_dependency() {
        let mut orch = PropagationOrchestrator::new();

        let source = create_test_claim(0.5);
        let dependent = create_test_claim(0.5);
        let source_id = source.id;
        let dep_id = dependent.id;

        orch.register_claim(source).unwrap();
        orch.register_claim(dependent).unwrap();
        orch.add_dependency(source_id, dep_id, true, 0.8, EvidenceType::Empirical, 0.0)
            .unwrap();

        assert_eq!(orch.dependent_count(source_id), 1);
    }

    #[test]
    fn test_cycle_detection() {
        let mut orch = PropagationOrchestrator::new();

        let claim_a = create_test_claim(0.5);
        let claim_b = create_test_claim(0.5);
        let id_a = claim_a.id;
        let id_b = claim_b.id;

        orch.register_claim(claim_a).unwrap();
        orch.register_claim(claim_b).unwrap();

        // A -> B is valid
        orch.add_dependency(id_a, id_b, true, 0.8, EvidenceType::Empirical, 0.0)
            .unwrap();

        // B -> A would create a cycle - should fail
        let result = orch.add_dependency(id_b, id_a, true, 0.8, EvidenceType::Empirical, 0.0);
        assert!(matches!(result, Err(EngineError::CycleDetected { .. })));
    }

    #[test]
    fn test_propagation_updates_dependent() {
        let mut orch = PropagationOrchestrator::new();

        let source = create_test_claim(0.5);
        let dependent = create_test_claim(0.5);
        let source_id = source.id;
        let dep_id = dependent.id;

        orch.register_claim(source).unwrap();
        orch.register_claim(dependent).unwrap();
        orch.add_dependency(source_id, dep_id, true, 0.8, EvidenceType::Empirical, 0.0)
            .unwrap();

        let updated = orch
            .update_and_propagate(source_id, TruthValue::new(0.9).unwrap())
            .unwrap();

        assert!(updated.contains(&dep_id));
        assert!(orch.get_truth(dep_id).unwrap().value() > 0.5);
    }

    #[test]
    fn test_audit_trail_recorded() {
        let mut orch = PropagationOrchestrator::new();

        let source = create_test_claim(0.5);
        let dependent = create_test_claim(0.5);
        let source_id = source.id;
        let dep_id = dependent.id;

        orch.register_claim(source).unwrap();
        orch.register_claim(dependent).unwrap();
        orch.add_dependency(source_id, dep_id, true, 0.8, EvidenceType::Statistical, 0.0)
            .unwrap();

        orch.update_and_propagate(source_id, TruthValue::new(0.9).unwrap())
            .unwrap();

        let audit = orch.get_audit_trail();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].claim_id, dep_id);
        assert_eq!(audit[0].source_claim_id, source_id);
        assert_eq!(audit[0].evidence_type, EvidenceType::Statistical);
        assert!(audit[0].evidence_weight > 0.0);
    }

    /// # THE BAD ACTOR TEST
    ///
    /// Validates that agent reputation NEVER influences propagation.
    #[test]
    fn bad_actor_test_reputation_isolated_from_propagation() {
        let mut orch = PropagationOrchestrator::new();

        // Create two agents with vastly different reputations
        let high_rep_agent = AgentId::new();
        let low_rep_agent = AgentId::new();

        orch.register_agent(high_rep_agent, 0.95); // Stellar reputation
        orch.register_agent(low_rep_agent, 0.20); // Poor reputation

        // Identical evidence strength
        let evidence_strength = 0.3;

        // High-rep agent's claim
        let high_rep_claim = create_claim_with_agent(0.5, high_rep_agent);
        let high_rep_id = high_rep_claim.id;
        orch.register_claim(high_rep_claim).unwrap();

        // Low-rep agent's claim
        let low_rep_claim = create_claim_with_agent(0.5, low_rep_agent);
        let low_rep_id = low_rep_claim.id;
        orch.register_claim(low_rep_claim).unwrap();

        // Dependent claims
        let dep_on_high = create_test_claim(0.5);
        let dep_on_low = create_test_claim(0.5);
        let dep_high_id = dep_on_high.id;
        let dep_low_id = dep_on_low.id;

        orch.register_claim(dep_on_high).unwrap();
        orch.register_claim(dep_on_low).unwrap();

        // Same evidence strength and type for both
        orch.add_dependency(
            high_rep_id,
            dep_high_id,
            true,
            evidence_strength,
            EvidenceType::Empirical,
            0.0,
        )
        .unwrap();
        orch.add_dependency(
            low_rep_id,
            dep_low_id,
            true,
            evidence_strength,
            EvidenceType::Empirical,
            0.0,
        )
        .unwrap();

        // Update both sources to same truth
        let source_truth = TruthValue::new(0.7).unwrap();
        orch.update_and_propagate(high_rep_id, source_truth)
            .unwrap();
        orch.update_and_propagate(low_rep_id, source_truth).unwrap();

        // CRITICAL: Both dependents must have THE SAME truth value
        let high_dep_truth = orch.get_truth(dep_high_id).unwrap().value();
        let low_dep_truth = orch.get_truth(dep_low_id).unwrap().value();

        let tolerance = 1e-10;
        assert!(
            (high_dep_truth - low_dep_truth).abs() < tolerance,
            "BAD ACTOR TEST FAILED: Reputation influenced propagation! \
             High-rep dependent: {high_dep_truth}, Low-rep dependent: {low_dep_truth}"
        );
    }

    // =========================================================================
    // EVIDENCE WEIGHTING INTEGRATION TESTS
    // =========================================================================

    /// Test: Empirical evidence has more impact than Testimonial evidence
    ///
    /// Evidence type weights:
    /// - Empirical: 1.0 (direct observation)
    /// - Testimonial: 0.6 (expert opinion)
    ///
    /// Given identical source claims and strengths, empirical evidence should
    /// produce a larger truth change than testimonial evidence.
    #[test]
    fn test_empirical_evidence_has_more_impact_than_testimonial() {
        let mut orch = PropagationOrchestrator::new();

        // Create source claim
        let source = create_test_claim(0.8); // High-truth source
        let source_id = source.id;
        orch.register_claim(source).unwrap();

        // Create two identical dependent claims
        let dep_empirical = create_test_claim(0.5);
        let dep_testimonial = create_test_claim(0.5);
        let dep_emp_id = dep_empirical.id;
        let dep_test_id = dep_testimonial.id;

        orch.register_claim(dep_empirical).unwrap();
        orch.register_claim(dep_testimonial).unwrap();

        // Same strength, different evidence types
        let strength = 0.8;
        orch.add_dependency(
            source_id,
            dep_emp_id,
            true,
            strength,
            EvidenceType::Empirical,
            0.0,
        )
        .unwrap();

        // Need a separate source for testimonial to avoid already-visited
        let source2 = create_test_claim(0.8);
        let source2_id = source2.id;
        orch.register_claim(source2).unwrap();
        orch.add_dependency(
            source2_id,
            dep_test_id,
            true,
            strength,
            EvidenceType::Testimonial,
            0.0,
        )
        .unwrap();

        // Propagate from both sources
        orch.update_and_propagate(source_id, TruthValue::new(0.9).unwrap())
            .unwrap();
        orch.update_and_propagate(source2_id, TruthValue::new(0.9).unwrap())
            .unwrap();

        let empirical_truth = orch.get_truth(dep_emp_id).unwrap().value();
        let testimonial_truth = orch.get_truth(dep_test_id).unwrap().value();

        assert!(
            empirical_truth > testimonial_truth,
            "Empirical evidence (type weight 1.0) should produce higher truth than \
             Testimonial (type weight 0.6). Got: Empirical={empirical_truth}, Testimonial={testimonial_truth}"
        );
    }

    /// Test: Circumstantial evidence has least impact
    ///
    /// Circumstantial evidence weight is 0.4 (weakest).
    #[test]
    fn test_circumstantial_evidence_has_least_impact() {
        let mut orch = PropagationOrchestrator::new();

        // Create source claims with same truth
        let source1 = create_test_claim(0.8);
        let source2 = create_test_claim(0.8);
        let source1_id = source1.id;
        let source2_id = source2.id;
        orch.register_claim(source1).unwrap();
        orch.register_claim(source2).unwrap();

        // Create dependent claims starting at same truth
        let dep_statistical = create_test_claim(0.5);
        let dep_circumstantial = create_test_claim(0.5);
        let dep_stat_id = dep_statistical.id;
        let dep_circ_id = dep_circumstantial.id;

        orch.register_claim(dep_statistical).unwrap();
        orch.register_claim(dep_circumstantial).unwrap();

        let strength = 0.8;
        orch.add_dependency(
            source1_id,
            dep_stat_id,
            true,
            strength,
            EvidenceType::Statistical, // 0.9 weight
            0.0,
        )
        .unwrap();
        orch.add_dependency(
            source2_id,
            dep_circ_id,
            true,
            strength,
            EvidenceType::Circumstantial, // 0.4 weight
            0.0,
        )
        .unwrap();

        // Propagate
        orch.update_and_propagate(source1_id, TruthValue::new(0.9).unwrap())
            .unwrap();
        orch.update_and_propagate(source2_id, TruthValue::new(0.9).unwrap())
            .unwrap();

        let statistical_truth = orch.get_truth(dep_stat_id).unwrap().value();
        let circumstantial_truth = orch.get_truth(dep_circ_id).unwrap().value();

        assert!(
            statistical_truth > circumstantial_truth,
            "Statistical evidence (weight 0.9) should produce higher truth than \
             Circumstantial (weight 0.4). Got: Statistical={statistical_truth}, Circumstantial={circumstantial_truth}"
        );
    }

    /// Test: Temporal decay reduces evidence weight over time
    ///
    /// Older evidence should have less impact than fresh evidence.
    /// Default decay is 0.99 per day (1% decay per day).
    #[test]
    fn test_temporal_decay_reduces_evidence_impact() {
        let mut orch = PropagationOrchestrator::new();

        // Create source claims
        let source_fresh = create_test_claim(0.8);
        let source_old = create_test_claim(0.8);
        let fresh_id = source_fresh.id;
        let old_id = source_old.id;
        orch.register_claim(source_fresh).unwrap();
        orch.register_claim(source_old).unwrap();

        // Create dependent claims
        let dep_fresh = create_test_claim(0.5);
        let dep_old = create_test_claim(0.5);
        let dep_fresh_id = dep_fresh.id;
        let dep_old_id = dep_old.id;

        orch.register_claim(dep_fresh).unwrap();
        orch.register_claim(dep_old).unwrap();

        let strength = 0.8;
        // Fresh evidence: 0 days old
        orch.add_dependency(
            fresh_id,
            dep_fresh_id,
            true,
            strength,
            EvidenceType::Empirical,
            0.0,
        )
        .unwrap();
        // Old evidence: 30 days old (significant decay)
        orch.add_dependency(
            old_id,
            dep_old_id,
            true,
            strength,
            EvidenceType::Empirical,
            30.0,
        )
        .unwrap();

        // Propagate
        orch.update_and_propagate(fresh_id, TruthValue::new(0.9).unwrap())
            .unwrap();
        orch.update_and_propagate(old_id, TruthValue::new(0.9).unwrap())
            .unwrap();

        let fresh_truth = orch.get_truth(dep_fresh_id).unwrap().value();
        let old_truth = orch.get_truth(dep_old_id).unwrap().value();

        assert!(
            fresh_truth > old_truth,
            "Fresh evidence (0 days) should have more impact than old evidence (30 days). \
             Got: Fresh={fresh_truth}, Old={old_truth}"
        );
    }

    /// Test: Evidence weight is recorded in audit trail
    #[test]
    fn test_evidence_weight_recorded_in_audit() {
        let mut orch = PropagationOrchestrator::new();

        let source = create_test_claim(0.8);
        let dependent = create_test_claim(0.5);
        let source_id = source.id;
        let dep_id = dependent.id;

        orch.register_claim(source).unwrap();
        orch.register_claim(dependent).unwrap();
        orch.add_dependency(source_id, dep_id, true, 0.9, EvidenceType::Logical, 0.0)
            .unwrap();

        orch.update_and_propagate(source_id, TruthValue::new(0.9).unwrap())
            .unwrap();

        let audit = orch.get_audit_trail();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].evidence_type, EvidenceType::Logical);

        // Evidence weight should be: type_multiplier * relevance * source_truth
        // Logical = 0.85, relevance = 0.9, source_truth = 0.9
        // Expected weight = 0.85 * 0.9 * 0.9 = 0.6885
        let expected_weight = 0.85 * 0.9 * 0.9;
        let tolerance = 0.01;
        assert!(
            (audit[0].evidence_weight - expected_weight).abs() < tolerance,
            "Evidence weight should be approximately {}, got {}",
            expected_weight,
            audit[0].evidence_weight
        );
    }

    /// Test: Evidence type multipliers match expected values
    #[test]
    fn test_evidence_type_multiplier_ordering() {
        // Verify the ordering of evidence types by their multipliers
        assert!(
            EvidenceType::Empirical.base_multiplier() > EvidenceType::Statistical.base_multiplier()
        );
        assert!(
            EvidenceType::Statistical.base_multiplier() > EvidenceType::Logical.base_multiplier()
        );
        assert!(
            EvidenceType::Logical.base_multiplier() > EvidenceType::Testimonial.base_multiplier()
        );
        assert!(
            EvidenceType::Testimonial.base_multiplier()
                > EvidenceType::Circumstantial.base_multiplier()
        );

        // Verify exact values
        assert!((EvidenceType::Empirical.base_multiplier() - 1.0).abs() < f64::EPSILON);
        assert!((EvidenceType::Statistical.base_multiplier() - 0.9).abs() < f64::EPSILON);
        assert!((EvidenceType::Logical.base_multiplier() - 0.85).abs() < f64::EPSILON);
        assert!((EvidenceType::Testimonial.base_multiplier() - 0.6).abs() < f64::EPSILON);
        assert!((EvidenceType::Circumstantial.base_multiplier() - 0.4).abs() < f64::EPSILON);
    }

    /// Test: Combined evidence weighting with all factors
    ///
    /// This test verifies that evidence weight is properly calculated
    /// combining: type, source truth, relevance, and temporal decay.
    #[test]
    fn test_combined_evidence_weighting() {
        let mut orch = PropagationOrchestrator::new();

        // High-confidence source
        let source = create_test_claim(0.9);
        let source_id = source.id;
        orch.register_claim(source).unwrap();

        // Dependent starting at uncertainty
        let dependent = create_test_claim(0.5);
        let dep_id = dependent.id;
        orch.register_claim(dependent).unwrap();

        // Add dependency with:
        // - Statistical evidence (0.9 multiplier)
        // - High relevance (0.95)
        // - Some age (10 days, ~0.904 decay factor with 0.99/day)
        orch.add_dependency(
            source_id,
            dep_id,
            true,
            0.95,                      // relevance
            EvidenceType::Statistical, // 0.9 multiplier
            10.0,                      // 10 days old
        )
        .unwrap();

        // Update source to high truth
        orch.update_and_propagate(source_id, TruthValue::new(0.95).unwrap())
            .unwrap();

        let final_truth = orch.get_truth(dep_id).unwrap().value();

        // Should be higher than initial 0.5 (supporting evidence)
        assert!(
            final_truth > 0.5,
            "Supporting evidence should increase truth above 0.5, got {final_truth}"
        );

        // Verify audit shows proper calculation
        let audit = orch.get_audit_trail();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].evidence_type, EvidenceType::Statistical);

        // Weight should incorporate all factors
        assert!(audit[0].evidence_weight > 0.0);
        assert!(audit[0].evidence_weight <= 1.0);
    }

    /// Test: Refuting evidence with evidence weighting
    #[test]
    fn test_refuting_evidence_with_weighting() {
        let mut orch = PropagationOrchestrator::new();

        // Source with high truth
        let source = create_test_claim(0.9);
        let source_id = source.id;
        orch.register_claim(source).unwrap();

        // Dependent starting at high truth
        let dependent = create_test_claim(0.8);
        let dep_id = dependent.id;
        orch.register_claim(dependent).unwrap();

        // Add REFUTING dependency with strong empirical evidence
        orch.add_dependency(
            source_id,
            dep_id,
            false, // refuting
            0.9,
            EvidenceType::Empirical,
            0.0,
        )
        .unwrap();

        orch.update_and_propagate(source_id, TruthValue::new(0.9).unwrap())
            .unwrap();

        let final_truth = orch.get_truth(dep_id).unwrap().value();

        // Refuting evidence should decrease truth
        assert!(
            final_truth < 0.8,
            "Refuting evidence should decrease truth below 0.8, got {final_truth}"
        );

        // Audit should show is_supporting = false
        let audit = orch.get_audit_trail();
        assert!(!audit[0].is_supporting);
    }

    /// Bad Actor Test: Evidence type cannot inflate truth beyond what evidence warrants
    ///
    /// Even with "Empirical" evidence type (highest weight), the truth update
    /// should be bounded by the actual evidence strength and source truth.
    #[test]
    fn bad_actor_test_evidence_type_cannot_create_false_certainty() {
        let mut orch = PropagationOrchestrator::new();

        // Weak source (low truth)
        let weak_source = create_test_claim(0.3);
        let weak_id = weak_source.id;
        orch.register_claim(weak_source).unwrap();

        // Dependent at uncertainty
        let dependent = create_test_claim(0.5);
        let dep_id = dependent.id;
        orch.register_claim(dependent).unwrap();

        // Even with Empirical evidence type, weak source limits impact
        orch.add_dependency(weak_id, dep_id, true, 1.0, EvidenceType::Empirical, 0.0)
            .unwrap();

        orch.update_and_propagate(weak_id, TruthValue::new(0.3).unwrap())
            .unwrap();

        let final_truth = orch.get_truth(dep_id).unwrap().value();

        // Truth should not increase dramatically from weak evidence
        assert!(
            final_truth < 0.7,
            "Weak source should not produce high truth regardless of evidence type. Got: {final_truth}"
        );
    }
}
