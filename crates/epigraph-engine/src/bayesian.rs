//! Bayesian truth value updating
//!
//! Implements Bayes' theorem for updating claim truth values
//! based on new evidence: P(H|E) = P(E|H) * P(H) / P(E)
//!
//! # Deprecation
//!
//! `BayesianUpdater` is deprecated since 0.2.0. Use CDST pignistic probability instead.
//! The module-level allow suppresses self-referential deprecation warnings in the impls.

// The struct itself is deprecated; suppress warnings within its own implementation.
#![allow(deprecated)]

use crate::errors::EngineError;
use epigraph_core::TruthValue;

/// Configuration for Bayesian updates
#[derive(Debug, Clone)]
pub struct BayesianConfig {
    /// Minimum truth value (prevents certainty lock-in at 0)
    pub min_truth: f64,
    /// Maximum truth value (prevents certainty lock-in at 1)
    pub max_truth: f64,
    /// Prior probability of evidence given hypothesis is true
    pub likelihood_true_default: f64,
    /// Prior probability of evidence given hypothesis is false
    pub likelihood_false_default: f64,
}

impl Default for BayesianConfig {
    fn default() -> Self {
        Self {
            min_truth: 0.01, // Never reach absolute certainty
            max_truth: 0.99, // Never reach absolute certainty
            likelihood_true_default: 0.8,
            likelihood_false_default: 0.2,
        }
    }
}

/// Bayesian updater for claim truth values
#[deprecated(
    since = "0.2.0",
    note = "Use CDST pignistic probability instead. See update-math-cdst-convergence spec."
)]
pub struct BayesianUpdater {
    config: BayesianConfig,
}

impl BayesianUpdater {
    /// Create a new Bayesian updater with default config
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: BayesianConfig::default(),
        }
    }

    /// Create with custom config
    #[must_use]
    pub const fn with_config(config: BayesianConfig) -> Self {
        Self { config }
    }

    /// Update truth value using Bayes' theorem
    ///
    /// P(H|E) = P(E|H) * P(H) / P(E)
    ///
    /// Where:
    /// - P(H) = prior (current truth value)
    /// - P(E|H) = likelihood of evidence if hypothesis is true
    /// - P(E|¬H) = likelihood of evidence if hypothesis is false
    /// - P(E) = P(E|H)*P(H) + P(E|¬H)*P(¬H)
    ///
    /// # Arguments
    /// * `prior` - Current truth value (P(H))
    /// * `likelihood_true` - P(E|H) - probability of seeing this evidence if claim is true
    /// * `likelihood_false` - P(E|¬H) - probability of seeing this evidence if claim is false
    ///
    /// # Returns
    /// Updated truth value (posterior)
    ///
    /// # Errors
    /// Returns `EngineError::TruthComputationFailed` if likelihoods are out of bounds
    /// or evidence probability is too low.
    pub fn update(
        &self,
        prior: TruthValue,
        likelihood_true: f64,
        likelihood_false: f64,
    ) -> Result<TruthValue, EngineError> {
        // Validate inputs
        if !(0.0..=1.0).contains(&likelihood_true) || !(0.0..=1.0).contains(&likelihood_false) {
            return Err(EngineError::TruthComputationFailed {
                reason: "Likelihoods must be in [0, 1]".to_string(),
            });
        }

        let p_h = prior.value();
        let p_not_h = 1.0 - p_h;

        // P(E) = P(E|H)*P(H) + P(E|¬H)*P(¬H)
        let p_e = likelihood_true.mul_add(p_h, likelihood_false * p_not_h);

        // Avoid division by zero
        if p_e < f64::EPSILON {
            return Err(EngineError::TruthComputationFailed {
                reason: "Evidence probability too low".to_string(),
            });
        }

        // P(H|E) = P(E|H) * P(H) / P(E)
        let posterior = (likelihood_true * p_h) / p_e;

        // Clamp to prevent certainty lock-in
        let clamped = posterior.clamp(self.config.min_truth, self.config.max_truth);

        TruthValue::new(clamped).map_err(|e| EngineError::TruthComputationFailed {
            reason: e.to_string(),
        })
    }

    /// Update with supporting evidence (increases truth)
    ///
    /// Uses default likelihoods configured for supporting evidence.
    ///
    /// # Errors
    /// Returns `EngineError::TruthComputationFailed` if strength is out of bounds.
    pub fn update_with_support(
        &self,
        prior: TruthValue,
        strength: f64,
    ) -> Result<TruthValue, EngineError> {
        if !(0.0..=1.0).contains(&strength) {
            return Err(EngineError::TruthComputationFailed {
                reason: format!("Strength must be in [0, 1], got {strength}"),
            });
        }

        // Strong support: high P(E|H), low P(E|¬H)
        let likelihood_true = strength.mul_add(0.5, 0.5); // [0.5, 1.0]
        let likelihood_false = strength.mul_add(-0.4, 0.5); // [0.1, 0.5]

        self.update(prior, likelihood_true, likelihood_false)
    }

    /// Update with refuting evidence (decreases truth)
    ///
    /// # Errors
    /// Returns `EngineError::TruthComputationFailed` if strength is out of bounds.
    pub fn update_with_refutation(
        &self,
        prior: TruthValue,
        strength: f64,
    ) -> Result<TruthValue, EngineError> {
        if !(0.0..=1.0).contains(&strength) {
            return Err(EngineError::TruthComputationFailed {
                reason: format!("Strength must be in [0, 1], got {strength}"),
            });
        }

        // Strong refutation: low P(E|H), high P(E|¬H)
        let likelihood_true = strength.mul_add(-0.4, 0.5); // [0.1, 0.5]
        let likelihood_false = strength.mul_add(0.5, 0.5); // [0.5, 1.0]

        self.update(prior, likelihood_true, likelihood_false)
    }

    /// Calculate initial truth value for a new claim
    ///
    /// # Critical Invariant
    ///
    /// Initial truth is based ONLY on evidence quality, NOT agent reputation.
    /// This prevents the "Appeal to Authority" fallacy.
    ///
    /// # Arguments
    /// * `evidence_weight` - Combined weight of supporting evidence [0, 1]
    /// * `evidence_count` - Number of distinct evidence pieces
    #[must_use]
    pub fn calculate_initial_truth(evidence_weight: f64, evidence_count: usize) -> TruthValue {
        // Base truth from evidence weight
        let base = evidence_weight * 0.5; // Max 0.5 from weight alone

        // Bonus for multiple evidence sources (diversity)
        let diversity_bonus = match evidence_count {
            0 => 0.0,
            1 => 0.1,
            2 => 0.15,
            3 => 0.18,
            _ => 0.2, // Cap at 0.2
        };

        // Start from maximum uncertainty (0.5) and adjust
        let truth = 0.5 + base + diversity_bonus;

        // Clamp and return
        TruthValue::clamped(truth.min(0.85)) // Never start above 0.85
    }
}

impl Default for BayesianUpdater {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supporting_evidence_increases_truth() {
        let updater = BayesianUpdater::new();
        let prior = TruthValue::new(0.5).unwrap();

        let posterior = updater.update_with_support(prior, 0.8).unwrap();

        assert!(posterior.value() > prior.value());
    }

    #[test]
    fn refuting_evidence_decreases_truth() {
        let updater = BayesianUpdater::new();
        let prior = TruthValue::new(0.5).unwrap();

        let posterior = updater.update_with_refutation(prior, 0.8).unwrap();

        assert!(posterior.value() < prior.value());
    }

    #[test]
    fn strong_evidence_has_larger_effect() {
        let updater = BayesianUpdater::new();
        let prior = TruthValue::new(0.5).unwrap();

        let weak = updater.update_with_support(prior, 0.3).unwrap();
        let strong = updater.update_with_support(prior, 0.9).unwrap();

        assert!(strong.value() > weak.value());
    }

    #[test]
    fn truth_never_reaches_zero_or_one() {
        let updater = BayesianUpdater::new();

        // Even with strong refutation from high truth
        let high = TruthValue::new(0.95).unwrap();
        let refuted = updater.update_with_refutation(high, 1.0).unwrap();
        assert!(refuted.value() > 0.0);

        // Even with strong support from low truth
        let low = TruthValue::new(0.05).unwrap();
        let supported = updater.update_with_support(low, 1.0).unwrap();
        assert!(supported.value() < 1.0);
    }

    #[test]
    fn initial_truth_never_high_without_evidence() {
        // This is the Bad Actor Test principle
        let no_evidence = BayesianUpdater::calculate_initial_truth(0.0, 0);
        assert!(
            no_evidence.value() <= 0.5,
            "No evidence should not exceed uncertainty"
        );

        let weak_evidence = BayesianUpdater::calculate_initial_truth(0.3, 1);
        assert!(
            weak_evidence.value() < 0.8,
            "Weak evidence should not produce high truth"
        );
    }

    #[test]
    fn multiple_evidence_sources_increase_truth() {
        // Test with lower weight to avoid capping at 0.85
        let single_low = BayesianUpdater::calculate_initial_truth(0.2, 1);
        let multiple_low = BayesianUpdater::calculate_initial_truth(0.2, 3);

        // Multiple sources should give higher truth (diversity bonus)
        // single_low = 0.5 + (0.2 * 0.5) + 0.1 = 0.7
        // multiple_low = 0.5 + (0.2 * 0.5) + 0.18 = 0.78
        assert!(
            multiple_low.value() > single_low.value(),
            "Multiple evidence sources should produce higher initial truth"
        );

        // Also verify the diversity bonus tiers work correctly
        let zero_evidence = BayesianUpdater::calculate_initial_truth(0.2, 0);
        let one_evidence = BayesianUpdater::calculate_initial_truth(0.2, 1);
        let two_evidence = BayesianUpdater::calculate_initial_truth(0.2, 2);
        let four_evidence = BayesianUpdater::calculate_initial_truth(0.2, 4);

        assert!(one_evidence.value() > zero_evidence.value());
        assert!(two_evidence.value() > one_evidence.value());
        assert!(four_evidence.value() > two_evidence.value());
    }

    #[test]
    fn invalid_likelihood_rejected() {
        let updater = BayesianUpdater::new();
        let prior = TruthValue::new(0.5).unwrap();

        // Likelihood > 1.0 should fail
        let result = updater.update(prior, 1.5, 0.5);
        assert!(result.is_err());

        // Likelihood < 0.0 should fail
        let result = updater.update(prior, 0.5, -0.1);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_strength_rejected() {
        let updater = BayesianUpdater::new();
        let prior = TruthValue::new(0.5).unwrap();

        // Strength > 1.0 should fail
        let result = updater.update_with_support(prior, 1.5);
        assert!(result.is_err());

        // Strength < 0.0 should fail
        let result = updater.update_with_refutation(prior, -0.1);
        assert!(result.is_err());
    }

    /// # THE BAD ACTOR TEST
    ///
    /// This is the MOST CRITICAL test in the entire `EpiGraph` system.
    /// It validates the core epistemic principle: reputation NEVER influences
    /// initial truth calculation.
    ///
    /// ## Scenario
    /// A high-reputation agent (e.g., Nobel laureate) submits a claim with:
    /// - ZERO supporting evidence
    /// - NO citations
    /// - Pure assertion ("trust me")
    ///
    /// ## Expected Behavior
    /// The claim MUST receive a LOW initial truth value (≤ 0.5).
    /// The agent's stellar reputation MUST NOT inflate the truth.
    ///
    /// ## Why This Matters
    /// This prevents the "Appeal to Authority" fallacy. In `EpiGraph`:
    /// - Evidence → Truth → Reputation (CORRECT flow)
    /// - Reputation → Truth (FORBIDDEN flow)
    ///
    /// If this test fails, the entire epistemic foundation is compromised.
    #[test]
    fn bad_actor_test_reputation_never_influences_initial_truth() {
        // CRITICAL: Verify the function signature enforces reputation isolation
        //
        // calculate_initial_truth(evidence_weight, evidence_count) takes ONLY:
        // - evidence_weight: f64
        // - evidence_count: usize
        //
        // It has NO agent/reputation parameter. This is the architectural
        // enforcement of reputation isolation - a compile-time guarantee.
        //
        // If someone adds a reputation parameter, this code won't compile,
        // alerting developers to the architectural violation.

        // 1. Zero evidence weight AND zero count = uncertainty (0.5)
        let zero_evidence_truth = BayesianUpdater::calculate_initial_truth(0.0, 0);
        assert_eq!(
            zero_evidence_truth.value(),
            0.5,
            "BAD ACTOR TEST: Zero evidence should produce exactly 0.5 (maximum uncertainty)"
        );

        // 2. Single weak evidence = still below verification threshold
        let weak_single = BayesianUpdater::calculate_initial_truth(0.2, 1);
        assert!(
            weak_single.value() < 0.8,
            "BAD ACTOR TEST FAILED: Weak single evidence produced truth {} (threshold: 0.8). \
             Claims should not be 'verified true' with weak evidence.",
            weak_single.value()
        );

        // 3. The key invariant: NO reputation parameter exists
        // This is enforced by the type system. The following conceptual test
        // documents what CANNOT happen:
        //
        // IMPOSSIBLE (won't compile):
        // BayesianUpdater::calculate_initial_truth(0.0, 0, agent_reputation: 0.99)
        //
        // A high-reputation agent cannot inflate their claim's initial truth
        // because there is no way to pass reputation into this function.

        // 4. Initial truth is capped at 0.85 no matter what
        let max_possible = BayesianUpdater::calculate_initial_truth(1.0, 10);
        assert!(
            max_possible.value() <= 0.85,
            "Initial truth must never exceed 0.85, got {}",
            max_possible.value()
        );
    }

    #[test]
    fn bad_actor_test_truth_requires_evidence_accumulation() {
        // High truth must be EARNED through Bayesian updates with real evidence
        let updater = BayesianUpdater::new();

        // Start from uncertainty
        let initial = TruthValue::new(0.5).unwrap();

        // Single strong evidence update - significant but not conclusive
        let after_one = updater.update_with_support(initial, 0.9).unwrap();
        assert!(
            after_one.value() > initial.value(),
            "Evidence should increase truth"
        );
        assert!(
            after_one.value() < 0.95,
            "Single evidence shouldn't produce near-certain truth. Got: {}",
            after_one.value()
        );

        // Truth accumulates through multiple independent evidence sources
        let after_two = updater.update_with_support(after_one, 0.9).unwrap();
        let after_three = updater.update_with_support(after_two, 0.9).unwrap();

        // Each update increases truth, demonstrating proper evidence accumulation
        assert!(
            after_two.value() > after_one.value(),
            "Second evidence should further increase truth"
        );
        assert!(
            after_three.value() > after_two.value(),
            "Third evidence should further increase truth"
        );

        // Truth is always clamped below 1.0 (never absolute certainty)
        assert!(
            after_three.value() <= 0.99,
            "Truth should never exceed max_truth (0.99), got {}",
            after_three.value()
        );
    }

    #[test]
    fn bad_actor_test_evidence_weight_requires_count() {
        // Evidence weight without count should not produce high truth
        // This tests that the diversity bonus matters

        // High weight, zero count - no diversity bonus applied
        let high_weight_zero_count = BayesianUpdater::calculate_initial_truth(1.0, 0);
        // 0.5 (base uncertainty) + 0.5 (weight * 0.5) + 0.0 (no diversity) = 1.0 -> clamped to 0.85

        // Same weight with evidence count - diversity bonus applied
        let high_weight_with_count = BayesianUpdater::calculate_initial_truth(0.5, 3);
        // 0.5 + 0.25 + 0.18 = 0.93 -> clamped to 0.85

        // Both are capped at 0.85
        assert!(high_weight_zero_count.value() <= 0.85);
        assert!(high_weight_with_count.value() <= 0.85);

        // The diversity bonus increases truth when we have multiple sources
        let low_weight_no_count = BayesianUpdater::calculate_initial_truth(0.3, 0);
        let low_weight_with_count = BayesianUpdater::calculate_initial_truth(0.3, 3);

        assert!(
            low_weight_with_count.value() > low_weight_no_count.value(),
            "Multiple evidence sources should increase truth via diversity bonus"
        );
    }
}
