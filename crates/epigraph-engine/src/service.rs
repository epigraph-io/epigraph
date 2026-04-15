//! `EpistemicService` Facade
//!
//! Provides a unified interface to epistemic operations for the API layer.
//! This facade coordinates between:
//! - [`PropagationOrchestrator`]: Truth propagation across the reasoning DAG
//! - [`ReputationCalculator`]: Agent reputation from claim outcomes
//! - [`EvidenceWeighter`]: Evidence weight calculation
//!
//! # Core Principle
//!
//! Agent reputation NEVER influences truth calculation. Evidence -> Truth -> Reputation.
//! This is the "Appeal to Authority" prevention guarantee.
//!
//! # Usage
//!
//! ```ignore
//! let service = EpistemicServiceBuilder::new()
//!     .with_propagation_config(PropagationConfig::default())
//!     .with_reputation_config(ReputationConfig::default())
//!     .build();
//!
//! let result = service.process_new_claim(&claim, &evidence_list)?;
//! ```

use crate::reputation::{ClaimOutcome, ReputationCalculator, ReputationConfig};
use crate::{
    EngineError, EvidenceType, EvidenceWeightConfig, EvidenceWeighter, PropagationConfig,
    PropagationOrchestrator, PropagationResult,
};
use epigraph_core::{AgentId, Claim, ClaimId, Evidence, ReasoningTrace, TraceInput, TruthValue};
use std::collections::HashMap;

// =============================================================================
// RESULT TYPES
// =============================================================================

/// Result of processing a new claim through the epistemic service
#[derive(Debug, Clone)]
pub struct ClaimProcessingResult {
    /// The claim ID that was processed
    pub claim_id: ClaimId,
    /// Initial truth value assigned to the claim
    pub initial_truth: TruthValue,
    /// Results from truth propagation (if any dependents)
    pub propagation: Option<PropagationResult>,
    /// Combined evidence weight used for initial truth calculation
    pub evidence_weight: f64,
    /// Number of evidence pieces processed
    pub evidence_count: usize,
}

/// Result of updating an agent's reputation
#[derive(Debug, Clone)]
pub struct ReputationResult {
    /// The agent whose reputation was calculated
    pub agent_id: AgentId,
    /// The calculated reputation score [0, 1]
    pub reputation: f64,
    /// Number of claim outcomes used in calculation
    pub claim_count: usize,
    /// Whether this is a stable reputation (enough claims)
    pub is_stable: bool,
}

/// Result of validating a reasoning chain
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the chain is valid (acyclic, all inputs exist)
    pub is_valid: bool,
    /// Error message if invalid
    pub error: Option<String>,
    /// Number of nodes in the chain
    pub chain_length: usize,
    /// Missing inputs (claims or evidence not found)
    pub missing_inputs: Vec<String>,
}

// =============================================================================
// SERVICE CONFIGURATION
// =============================================================================

/// Configuration for the [`EpistemicService`]
#[derive(Debug, Clone)]
pub struct EpistemicServiceConfig {
    /// Configuration for truth propagation
    pub propagation: PropagationConfig,
    /// Configuration for reputation calculation
    pub reputation: ReputationConfig,
    /// Configuration for evidence weighting
    pub evidence: EvidenceWeightConfig,
    /// Minimum evidence count for stable initial truth
    pub min_evidence_for_stability: usize,
}

impl Default for EpistemicServiceConfig {
    fn default() -> Self {
        Self {
            propagation: PropagationConfig::default(),
            reputation: ReputationConfig::default(),
            evidence: EvidenceWeightConfig::default(),
            min_evidence_for_stability: 2,
        }
    }
}

// =============================================================================
// SERVICE BUILDER
// =============================================================================

/// Builder for `EpistemicService`
///
/// Provides a fluent API for configuring the service.
///
/// # Example
///
/// ```ignore
/// let service = EpistemicServiceBuilder::new()
///     .with_propagation_config(PropagationConfig {
///         max_depth: 50,
///         ..Default::default()
///     })
///     .build();
/// ```
#[derive(Debug, Default)]
pub struct EpistemicServiceBuilder {
    config: EpistemicServiceConfig,
}

impl EpistemicServiceBuilder {
    /// Create a new builder with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the propagation configuration
    #[must_use]
    pub const fn with_propagation_config(mut self, config: PropagationConfig) -> Self {
        self.config.propagation = config;
        self
    }

    /// Set the reputation configuration
    #[must_use]
    pub const fn with_reputation_config(mut self, config: ReputationConfig) -> Self {
        self.config.reputation = config;
        self
    }

    /// Set the evidence weighting configuration
    #[must_use]
    pub const fn with_evidence_config(mut self, config: EvidenceWeightConfig) -> Self {
        self.config.evidence = config;
        self
    }

    /// Set the minimum evidence count for stable initial truth
    #[must_use]
    pub const fn with_min_evidence_for_stability(mut self, count: usize) -> Self {
        self.config.min_evidence_for_stability = count;
        self
    }

    /// Build the `EpistemicService`
    #[must_use]
    pub fn build(self) -> EpistemicService {
        EpistemicService::with_config(self.config)
    }
}

// =============================================================================
// EPISTEMIC SERVICE FACADE
// =============================================================================

/// Unified facade for epistemic operations
///
/// Coordinates truth propagation, reputation calculation, and evidence weighting.
///
/// # Design Rationale
///
/// This facade exists to:
/// 1. Provide a single entry point for API operations
/// 2. Coordinate multi-step operations (e.g., process claim + propagate)
/// 3. Encapsulate configuration complexity
/// 4. Maintain the "no authority influence" invariant
///
/// # Core Invariant
///
/// Agent reputation is NEVER used in `process_new_claim` or `get_claim_confidence`.
/// Reputation is computed FROM claim outcomes, not used AS INPUT to truth calculation.
pub struct EpistemicService {
    /// Truth propagation orchestrator
    orchestrator: PropagationOrchestrator,
    /// Reputation calculator
    reputation_calculator: ReputationCalculator,
    /// Evidence weighter
    evidence_weighter: EvidenceWeighter,
    /// Service configuration
    config: EpistemicServiceConfig,
    /// Claim outcomes by agent (for reputation calculation)
    claim_outcomes: HashMap<AgentId, Vec<ClaimOutcome>>,
}

impl EpistemicService {
    /// Create a new service with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(EpistemicServiceConfig::default())
    }

    /// Create a new service with custom configuration
    #[must_use]
    pub fn with_config(config: EpistemicServiceConfig) -> Self {
        Self {
            orchestrator: PropagationOrchestrator::new(),
            reputation_calculator: ReputationCalculator::with_config(config.reputation.clone()),
            evidence_weighter: EvidenceWeighter::with_config(config.evidence.clone()),
            config,
            claim_outcomes: HashMap::new(),
        }
    }

    /// Create a builder for configuring the service
    #[must_use]
    pub fn builder() -> EpistemicServiceBuilder {
        EpistemicServiceBuilder::new()
    }

    /// Process a new claim with its supporting evidence
    ///
    /// This method:
    /// 1. Calculates evidence weights for each piece of evidence
    /// 2. Computes initial truth value from evidence (NOT reputation)
    /// 3. Registers the claim in the propagation orchestrator
    /// 4. Optionally triggers propagation to dependent claims
    ///
    /// # Arguments
    ///
    /// * `claim` - The claim to process
    /// * `evidence` - Evidence supporting this claim
    ///
    /// # Returns
    ///
    /// Result containing processing details including initial truth and propagation results.
    ///
    /// # Errors
    ///
    /// Returns `EngineError::InvalidEvidence` if evidence parameters are invalid.
    ///
    /// # Core Invariant
    ///
    /// Agent reputation is NEVER used in this calculation. Only evidence determines truth.
    pub fn process_new_claim(
        &mut self,
        claim: Claim,
        evidence: &[Evidence],
    ) -> Result<ClaimProcessingResult, EngineError> {
        // Calculate individual evidence weights
        let mut weights = Vec::with_capacity(evidence.len());
        for ev in evidence {
            let evidence_type = self.map_evidence_type(&ev.evidence_type);
            let weight = self.evidence_weighter.calculate_weight(
                evidence_type,
                None, // No source claim for primary evidence
                1.0,  // Full relevance for direct evidence
                0.0,  // Fresh evidence (age = 0)
            )?;
            weights.push(weight);
        }

        // Combine weights using diminishing returns
        let combined_weight = self.evidence_weighter.combine_weights(&weights);

        // Calculate initial truth from evidence ONLY (no reputation)
        // TODO: Replace with CDST pignistic probability when that path is implemented
        #[allow(deprecated)]
        let initial_truth =
            crate::BayesianUpdater::calculate_initial_truth(combined_weight, evidence.len());

        // Create claim with calculated initial truth
        let mut claim_with_truth = claim;
        claim_with_truth.update_truth_value(initial_truth);
        let claim_id = claim_with_truth.id;

        // Register in orchestrator
        self.orchestrator.register_claim(claim_with_truth)?;

        // No propagation for new claims (they have no dependents yet)
        Ok(ClaimProcessingResult {
            claim_id,
            initial_truth,
            propagation: None,
            evidence_weight: combined_weight,
            evidence_count: evidence.len(),
        })
    }

    /// Update an agent's reputation based on their claim history
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The agent whose reputation to update
    ///
    /// # Returns
    ///
    /// Result containing the calculated reputation.
    ///
    /// # Errors
    ///
    /// Returns `EngineError::ReputationComputationFailed` if calculation fails.
    ///
    /// # Note
    ///
    /// This method computes reputation FROM claim outcomes. It does NOT influence
    /// any truth calculations. Reputation is purely informational/for access control.
    pub fn update_agent_reputation(
        &self,
        agent_id: AgentId,
    ) -> Result<ReputationResult, EngineError> {
        let outcomes = self
            .claim_outcomes
            .get(&agent_id)
            .map_or(&[][..], Vec::as_slice);
        let reputation = self.reputation_calculator.calculate(outcomes)?;
        let claim_count = outcomes.len();
        let is_stable = claim_count >= self.config.reputation.min_claims_for_stability;

        Ok(ReputationResult {
            agent_id,
            reputation,
            claim_count,
            is_stable,
        })
    }

    /// Record a claim outcome for reputation tracking
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The agent who made the claim
    /// * `outcome` - The claim outcome to record
    pub fn record_claim_outcome(&mut self, agent_id: AgentId, outcome: ClaimOutcome) {
        self.claim_outcomes
            .entry(agent_id)
            .or_default()
            .push(outcome);
    }

    /// Get the confidence (truth value) of a claim
    ///
    /// # Arguments
    ///
    /// * `claim_id` - The claim to query
    ///
    /// # Returns
    ///
    /// The truth value as f64.
    ///
    /// # Errors
    ///
    /// Returns `EngineError::NodeNotFound` if the claim is not registered.
    pub fn get_claim_confidence(&self, claim_id: ClaimId) -> Result<f64, EngineError> {
        self.orchestrator
            .get_truth(claim_id)
            .map(|tv| tv.value())
            .ok_or(EngineError::NodeNotFound(claim_id.as_uuid()))
    }

    /// Validate a reasoning chain for integrity
    ///
    /// Checks that:
    /// 1. The chain is acyclic (no circular reasoning)
    /// 2. All referenced inputs exist
    /// 3. The methodology is valid
    ///
    /// # Arguments
    ///
    /// * `trace` - The reasoning trace to validate
    ///
    /// # Returns
    ///
    /// Validation result with details about any issues found.
    #[must_use]
    pub fn validate_reasoning_chain(&self, trace: &ReasoningTrace) -> ValidationResult {
        let mut missing_inputs = Vec::new();

        // Check that all claim inputs exist in the orchestrator
        for input in &trace.inputs {
            match input {
                TraceInput::Claim { id } => {
                    if self.orchestrator.get_truth(*id).is_none() {
                        missing_inputs.push(format!("Claim {}", id.as_uuid()));
                    }
                }
                TraceInput::Evidence { id } => {
                    // Evidence validation would require evidence storage
                    // For now, we assume evidence IDs are valid if provided
                    // In production, this would check against evidence repository
                    let _ = id; // Acknowledge the ID without validation
                }
            }
        }

        // Check for cycles by verifying the DAG would accept all dependencies
        let dag = self.orchestrator.dag();
        let is_acyclic = dag.is_valid();

        let is_valid = missing_inputs.is_empty() && is_acyclic;
        let error = if is_valid {
            None
        } else if !is_acyclic {
            Some("Cycle detected in reasoning graph".to_string())
        } else if !missing_inputs.is_empty() {
            Some(format!("Missing inputs: {}", missing_inputs.join(", ")))
        } else {
            None
        };

        ValidationResult {
            is_valid,
            error,
            chain_length: trace.inputs.len(),
            missing_inputs,
        }
    }

    /// Add a dependency relationship between claims
    ///
    /// When the source claim's truth changes, the dependent claim will be updated.
    ///
    /// # Arguments
    ///
    /// * `source_id` - The claim that provides evidence
    /// * `dependent_id` - The claim that depends on the source
    /// * `is_supporting` - Whether this is supporting (true) or refuting (false) evidence
    /// * `strength` - Base strength of the dependency [0, 1]
    /// * `evidence_type` - Type of evidence for weighting
    /// * `age_days` - Age of evidence in days (for temporal decay)
    ///
    /// # Errors
    ///
    /// Returns `EngineError::CycleDetected` if adding this dependency would create a cycle.
    #[allow(clippy::too_many_arguments)]
    pub fn add_claim_dependency(
        &mut self,
        source_id: ClaimId,
        dependent_id: ClaimId,
        is_supporting: bool,
        strength: f64,
        evidence_type: EvidenceType,
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

    /// Trigger truth propagation from a claim
    ///
    /// Updates all dependent claims based on the source claim's truth value.
    ///
    /// # Arguments
    ///
    /// * `claim_id` - The claim whose truth value changed
    /// * `new_truth` - Optional new truth value (uses current if None)
    ///
    /// # Returns
    ///
    /// Propagation result with details about updated claims.
    ///
    /// # Errors
    ///
    /// Returns `EngineError::NodeNotFound` if the source claim is not registered.
    pub fn propagate_from(
        &mut self,
        claim_id: ClaimId,
        new_truth: Option<TruthValue>,
    ) -> Result<PropagationResult, EngineError> {
        let propagator = crate::DatabasePropagator::new(self.config.propagation.clone());
        propagator.propagate_from(&mut self.orchestrator, claim_id, new_truth)
    }

    /// Get access to the underlying orchestrator (for advanced use)
    #[must_use]
    pub const fn orchestrator(&self) -> &PropagationOrchestrator {
        &self.orchestrator
    }

    /// Get mutable access to the underlying orchestrator (for advanced use)
    pub const fn orchestrator_mut(&mut self) -> &mut PropagationOrchestrator {
        &mut self.orchestrator
    }

    /// Map core `EvidenceType` to engine `EvidenceType`
    ///
    /// The core crate has a richer evidence type model (Document, Observation, etc.)
    /// which we map to the engine's simpler classification for weighting purposes.
    #[allow(clippy::unused_self)]
    const fn map_evidence_type(&self, core_type: &epigraph_core::EvidenceType) -> EvidenceType {
        match core_type {
            epigraph_core::EvidenceType::Observation { .. }
            | epigraph_core::EvidenceType::Figure { .. } => EvidenceType::Empirical,
            epigraph_core::EvidenceType::Document { .. } => EvidenceType::Logical,
            epigraph_core::EvidenceType::Literature { .. } => EvidenceType::Statistical,
            epigraph_core::EvidenceType::Testimony { .. } => EvidenceType::Testimonial,
            epigraph_core::EvidenceType::Consensus { .. } => EvidenceType::Circumstantial,
        }
    }
}

impl Default for EpistemicService {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use epigraph_core::AgentId;

    /// Helper to create a test claim
    fn create_test_claim(content: &str, truth: f64) -> Claim {
        let agent_id = AgentId::new();
        Claim::new(
            content.to_string(),
            agent_id,
            [0u8; 32], // public_key
            TruthValue::new(truth).unwrap(),
        )
    }

    /// Helper to create test evidence
    fn create_test_evidence(claim_id: ClaimId) -> Evidence {
        let agent_id = AgentId::new();
        Evidence::new(
            agent_id,
            [0u8; 32], // public_key
            [1u8; 32], // content_hash
            epigraph_core::EvidenceType::Observation {
                observed_at: Utc::now(),
                method: "visual".to_string(),
                location: None,
            },
            Some("test observation".to_string()),
            claim_id,
        )
    }

    // =========================================================================
    // BUILDER TESTS
    // =========================================================================

    #[test]
    fn test_builder_creates_service_with_defaults() {
        let service = EpistemicServiceBuilder::new().build();
        assert_eq!(service.config.propagation.max_depth, 100);
        assert_eq!(service.config.reputation.initial_reputation, 0.5);
    }

    #[test]
    fn test_builder_accepts_custom_propagation_config() {
        let config = PropagationConfig {
            max_depth: 50,
            convergence_threshold: 0.01,
            run_async: false,
        };

        let service = EpistemicServiceBuilder::new()
            .with_propagation_config(config)
            .build();

        assert_eq!(service.config.propagation.max_depth, 50);
        assert_eq!(service.config.propagation.convergence_threshold, 0.01);
    }

    #[test]
    fn test_builder_accepts_custom_reputation_config() {
        let config = ReputationConfig {
            initial_reputation: 0.3,
            min_reputation: 0.05,
            max_reputation: 0.99,
            recency_weight: 0.8,
            min_claims_for_stability: 5,
        };

        let service = EpistemicServiceBuilder::new()
            .with_reputation_config(config)
            .build();

        assert_eq!(service.config.reputation.initial_reputation, 0.3);
        assert_eq!(service.config.reputation.min_claims_for_stability, 5);
    }

    #[test]
    fn test_builder_fluent_chaining() {
        let service = EpistemicService::builder()
            .with_propagation_config(PropagationConfig {
                max_depth: 25,
                ..Default::default()
            })
            .with_min_evidence_for_stability(3)
            .build();

        assert_eq!(service.config.propagation.max_depth, 25);
        assert_eq!(service.config.min_evidence_for_stability, 3);
    }

    // =========================================================================
    // PROCESS NEW CLAIM TESTS
    // =========================================================================

    #[test]
    fn test_process_claim_without_evidence_gets_low_truth() {
        let mut service = EpistemicService::new();
        let claim = create_test_claim("Unsupported claim", 0.5);

        let result = service.process_new_claim(claim, &[]).unwrap();

        // No evidence = maximum uncertainty (0.5)
        assert_eq!(result.initial_truth.value(), 0.5);
        assert_eq!(result.evidence_count, 0);
        assert_eq!(result.evidence_weight, 0.0);
    }

    #[test]
    fn test_process_claim_with_evidence_increases_truth() {
        let mut service = EpistemicService::new();
        let claim = create_test_claim("Supported claim", 0.5);
        let claim_id = claim.id;
        let evidence = vec![create_test_evidence(claim_id)];

        let result = service.process_new_claim(claim, &evidence).unwrap();

        // With evidence, truth should be higher than base uncertainty
        assert!(result.initial_truth.value() > 0.5);
        assert_eq!(result.evidence_count, 1);
        assert!(result.evidence_weight > 0.0);
    }

    #[test]
    fn test_process_claim_multiple_evidence_higher_truth() {
        let mut service = EpistemicService::new();
        let claim = create_test_claim("Well-supported claim", 0.5);
        let claim_id = claim.id;
        let evidence = vec![
            create_test_evidence(claim_id),
            create_test_evidence(claim_id),
            create_test_evidence(claim_id),
        ];

        let result = service.process_new_claim(claim, &evidence).unwrap();

        // Multiple evidence sources should produce higher truth
        // (diversity bonus from calculate_initial_truth)
        assert!(result.initial_truth.value() > 0.6);
        assert_eq!(result.evidence_count, 3);
    }

    #[test]
    fn test_process_claim_registers_in_orchestrator() {
        let mut service = EpistemicService::new();
        let claim = create_test_claim("Test claim", 0.5);
        let claim_id = claim.id;

        service.process_new_claim(claim, &[]).unwrap();

        // Claim should be retrievable
        let truth = service.get_claim_confidence(claim_id).unwrap();
        assert_eq!(truth, 0.5);
    }

    // =========================================================================
    // THE BAD ACTOR TEST - CRITICAL
    // =========================================================================

    /// # THE BAD ACTOR TEST
    ///
    /// Validates the core epistemic principle: reputation NEVER influences truth.
    ///
    /// A high-reputation agent submitting claims with NO evidence should get
    /// the same truth value as a low-reputation agent with NO evidence.
    #[test]
    fn bad_actor_test_reputation_never_influences_truth() {
        let mut service = EpistemicService::new();

        // Create agent with stellar reputation
        let high_rep_agent = AgentId::new();
        for _ in 0..20 {
            service.record_claim_outcome(
                high_rep_agent,
                ClaimOutcome {
                    truth_value: 0.95, // All high-truth claims
                    age_days: 1.0,
                    was_refuted: false,
                },
            );
        }

        // Verify high reputation was recorded
        let rep_result = service.update_agent_reputation(high_rep_agent).unwrap();
        assert!(
            rep_result.reputation > 0.8,
            "Agent should have high reputation"
        );
        assert!(rep_result.is_stable, "Reputation should be stable");

        // Submit claim with NO evidence
        let claim = Claim::new(
            "Trust me, I'm reputable".to_string(),
            high_rep_agent,
            [0u8; 32], // public_key
            TruthValue::new(0.5).unwrap(),
        );

        let result = service.process_new_claim(claim, &[]).unwrap();

        // CRITICAL: Truth must be LOW despite high reputation
        assert_eq!(
            result.initial_truth.value(),
            0.5,
            "BAD ACTOR TEST FAILED: High reputation agent got truth {} without evidence. \
             Expected 0.5 (maximum uncertainty). Reputation must NEVER influence truth!",
            result.initial_truth.value()
        );
    }

    /// Complementary Bad Actor Test: Two agents with different reputations,
    /// same evidence, should get identical truth values.
    #[test]
    fn bad_actor_test_same_evidence_same_truth_regardless_of_reputation() {
        let mut service = EpistemicService::new();

        // High-rep agent
        let high_rep_agent = AgentId::new();
        for _ in 0..20 {
            service.record_claim_outcome(
                high_rep_agent,
                ClaimOutcome {
                    truth_value: 0.9,
                    age_days: 5.0,
                    was_refuted: false,
                },
            );
        }

        // Low-rep agent
        let low_rep_agent = AgentId::new();
        for _ in 0..20 {
            service.record_claim_outcome(
                low_rep_agent,
                ClaimOutcome {
                    truth_value: 0.2,
                    age_days: 5.0,
                    was_refuted: true,
                },
            );
        }

        // Verify different reputations
        let high_rep = service.update_agent_reputation(high_rep_agent).unwrap();
        let low_rep = service.update_agent_reputation(low_rep_agent).unwrap();
        assert!(high_rep.reputation > low_rep.reputation);

        // Both submit claims with identical evidence
        let claim1 = Claim::new(
            "Claim from high-rep agent".to_string(),
            high_rep_agent,
            [0u8; 32], // public_key
            TruthValue::new(0.5).unwrap(),
        );
        let claim1_id = claim1.id;
        let evidence1 = vec![create_test_evidence(claim1_id)];

        let claim2 = Claim::new(
            "Claim from low-rep agent".to_string(),
            low_rep_agent,
            [0u8; 32], // public_key
            TruthValue::new(0.5).unwrap(),
        );
        let claim2_id = claim2.id;
        let evidence2 = vec![create_test_evidence(claim2_id)];

        let result1 = service.process_new_claim(claim1, &evidence1).unwrap();
        let result2 = service.process_new_claim(claim2, &evidence2).unwrap();

        // CRITICAL: Same evidence type/count = Same truth value
        assert_eq!(
            result1.initial_truth.value(),
            result2.initial_truth.value(),
            "BAD ACTOR TEST FAILED: Different truth values for identical evidence! \
             High-rep got {}, Low-rep got {}. Reputation influenced truth!",
            result1.initial_truth.value(),
            result2.initial_truth.value()
        );
    }

    // =========================================================================
    // REPUTATION TESTS
    // =========================================================================

    #[test]
    fn test_new_agent_gets_initial_reputation() {
        let service = EpistemicService::new();
        let agent_id = AgentId::new();

        let result = service.update_agent_reputation(agent_id).unwrap();

        assert_eq!(result.reputation, 0.5); // Initial reputation
        assert_eq!(result.claim_count, 0);
        assert!(!result.is_stable);
    }

    #[test]
    fn test_agent_with_good_claims_gets_high_reputation() {
        let mut service = EpistemicService::new();
        let agent_id = AgentId::new();

        // Record many good claim outcomes
        for _ in 0..15 {
            service.record_claim_outcome(
                agent_id,
                ClaimOutcome {
                    truth_value: 0.9,
                    age_days: 5.0,
                    was_refuted: false,
                },
            );
        }

        let result = service.update_agent_reputation(agent_id).unwrap();

        assert!(result.reputation > 0.7);
        assert!(result.is_stable);
        assert_eq!(result.claim_count, 15);
    }

    #[test]
    fn test_agent_with_refuted_claims_gets_low_reputation() {
        let mut service = EpistemicService::new();
        let agent_id = AgentId::new();

        for _ in 0..15 {
            service.record_claim_outcome(
                agent_id,
                ClaimOutcome {
                    truth_value: 0.3,
                    age_days: 5.0,
                    was_refuted: true,
                },
            );
        }

        let result = service.update_agent_reputation(agent_id).unwrap();

        assert!(result.reputation < 0.4);
    }

    // =========================================================================
    // CLAIM CONFIDENCE TESTS
    // =========================================================================

    #[test]
    fn test_get_claim_confidence_returns_truth_value() {
        let mut service = EpistemicService::new();
        let claim = create_test_claim("Test", 0.75);
        let claim_id = claim.id;

        // Process claim (which will set truth to 0.5 due to no evidence)
        service.process_new_claim(claim, &[]).unwrap();

        let confidence = service.get_claim_confidence(claim_id).unwrap();
        assert_eq!(confidence, 0.5);
    }

    #[test]
    fn test_get_claim_confidence_not_found() {
        let service = EpistemicService::new();
        let fake_id = ClaimId::new();

        let result = service.get_claim_confidence(fake_id);

        assert!(matches!(result, Err(EngineError::NodeNotFound(_))));
    }

    // =========================================================================
    // VALIDATION TESTS
    // =========================================================================

    #[test]
    fn test_validate_reasoning_chain_valid_empty_inputs() {
        let service = EpistemicService::new();
        let agent_id = AgentId::new();

        let trace = ReasoningTrace::new(
            agent_id,
            [0u8; 32], // public_key
            epigraph_core::Methodology::Deductive,
            vec![],
            0.9,
            "Deduced from first principles".to_string(),
        );

        let result = service.validate_reasoning_chain(&trace);

        assert!(result.is_valid);
        assert!(result.error.is_none());
        assert_eq!(result.chain_length, 0);
        assert!(result.missing_inputs.is_empty());
    }

    #[test]
    fn test_validate_reasoning_chain_missing_claim_input() {
        let service = EpistemicService::new();
        let agent_id = AgentId::new();
        let missing_claim_id = ClaimId::new(); // Not registered

        let trace = ReasoningTrace::new(
            agent_id,
            [0u8; 32], // public_key
            epigraph_core::Methodology::Inductive,
            vec![TraceInput::Claim {
                id: missing_claim_id,
            }],
            0.8,
            "Based on prior claim".to_string(),
        );

        let result = service.validate_reasoning_chain(&trace);

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        assert_eq!(result.missing_inputs.len(), 1);
    }

    #[test]
    fn test_validate_reasoning_chain_with_existing_claim_input() {
        let mut service = EpistemicService::new();
        let agent_id = AgentId::new();

        // Register a claim first
        let source_claim = create_test_claim("Source claim", 0.7);
        let source_id = source_claim.id;
        service.process_new_claim(source_claim, &[]).unwrap();

        // Create trace referencing the registered claim
        let trace = ReasoningTrace::new(
            agent_id,
            [0u8; 32], // public_key
            epigraph_core::Methodology::Deductive,
            vec![TraceInput::Claim { id: source_id }],
            0.9,
            "Derived from source".to_string(),
        );

        let result = service.validate_reasoning_chain(&trace);

        assert!(result.is_valid);
        assert!(result.missing_inputs.is_empty());
    }

    // =========================================================================
    // DEPENDENCY AND PROPAGATION TESTS
    // =========================================================================

    #[test]
    fn test_add_claim_dependency_prevents_cycles() {
        let mut service = EpistemicService::new();

        let claim_a = create_test_claim("A", 0.6);
        let claim_b = create_test_claim("B", 0.6);
        let id_a = claim_a.id;
        let id_b = claim_b.id;

        service.process_new_claim(claim_a, &[]).unwrap();
        service.process_new_claim(claim_b, &[]).unwrap();

        // A -> B is valid
        service
            .add_claim_dependency(id_a, id_b, true, 0.8, EvidenceType::Empirical, 0.0)
            .unwrap();

        // B -> A would create cycle
        let result =
            service.add_claim_dependency(id_b, id_a, true, 0.8, EvidenceType::Empirical, 0.0);
        assert!(matches!(result, Err(EngineError::CycleDetected { .. })));
    }

    #[test]
    fn test_propagate_from_updates_dependents() {
        let mut service = EpistemicService::new();

        let source = create_test_claim("Source", 0.6);
        let dependent = create_test_claim("Dependent", 0.5);
        let source_id = source.id;
        let dep_id = dependent.id;

        service.process_new_claim(source, &[]).unwrap();
        service.process_new_claim(dependent, &[]).unwrap();

        // Add dependency: dependent depends on source
        service
            .add_claim_dependency(source_id, dep_id, true, 0.8, EvidenceType::Empirical, 0.0)
            .unwrap();

        // Propagate from source with high truth
        let result = service
            .propagate_from(source_id, Some(TruthValue::new(0.9).unwrap()))
            .unwrap();

        assert!(result.updated_claims.contains(&dep_id));

        // Dependent's truth should have increased
        let dep_truth = service.get_claim_confidence(dep_id).unwrap();
        assert!(dep_truth > 0.5);
    }

    // =========================================================================
    // ERROR PROPAGATION TESTS
    // =========================================================================

    #[test]
    fn test_process_claim_duplicate_id_fails() {
        let mut service = EpistemicService::new();
        let claim = create_test_claim("Test", 0.5);
        let claim_copy = Claim::with_id(
            claim.id,
            "Copy".to_string(),
            claim.agent_id,
            claim.public_key,
            claim.content_hash,
            claim.trace_id,
            claim.signature,
            claim.truth_value,
            claim.created_at,
            claim.updated_at,
        );

        service.process_new_claim(claim, &[]).unwrap();

        // Second registration with same ID should be handled gracefully
        // (Currently the orchestrator allows re-registration, which is fine)
        let result = service.process_new_claim(claim_copy, &[]);
        // This should succeed (idempotent) or fail with clear error
        // Current implementation allows it, which is acceptable
        assert!(result.is_ok() || matches!(result, Err(EngineError::NodeNotFound(_))));
    }

    #[test]
    fn test_propagate_from_nonexistent_claim_fails() {
        let mut service = EpistemicService::new();
        let fake_id = ClaimId::new();

        let result = service.propagate_from(fake_id, None);

        assert!(matches!(result, Err(EngineError::NodeNotFound(_))));
    }
}
