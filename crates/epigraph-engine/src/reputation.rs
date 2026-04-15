//! Agent reputation calculation
//!
//! # Critical Design Principle
//!
//! Reputation is computed FROM claim outcomes, NOT used AS INPUT to truth calculation.
//! This prevents the "Appeal to Authority" fallacy where high-reputation agents
//! could make unsupported claims that are automatically believed.
//!
//! ```text
//! CORRECT:  Evidence → Truth → Reputation
//! WRONG:    Reputation → Truth
//! ```

use crate::errors::EngineError;

/// Configuration for reputation calculation
#[derive(Debug, Clone)]
pub struct ReputationConfig {
    /// Initial reputation for new agents
    pub initial_reputation: f64,
    /// Minimum reputation (floor)
    pub min_reputation: f64,
    /// Maximum reputation (ceiling)
    pub max_reputation: f64,
    /// How much recent claims are weighted vs historical
    pub recency_weight: f64,
    /// Minimum claims needed for stable reputation
    pub min_claims_for_stability: usize,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            initial_reputation: 0.5,
            min_reputation: 0.1,
            max_reputation: 0.95,
            recency_weight: 0.7, // 70% recent, 30% historical
            min_claims_for_stability: 10,
        }
    }
}

/// A record of a claim's outcome for reputation calculation
#[derive(Debug, Clone)]
pub struct ClaimOutcome {
    /// Final truth value of the claim
    pub truth_value: f64,
    /// Age of the claim in days
    pub age_days: f64,
    /// Whether the claim was later refuted by strong evidence
    pub was_refuted: bool,
}

/// Calculator for agent reputation
///
/// # Isolation Principle
///
/// This calculator ONLY outputs reputation scores. It should NEVER be called
/// during truth calculation for a claim. Reputation is derived FROM truth,
/// not the other way around.
pub struct ReputationCalculator {
    config: ReputationConfig,
}

impl ReputationCalculator {
    /// Create a new reputation calculator with default config
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ReputationConfig::default(),
        }
    }

    /// Create with custom config
    #[must_use]
    pub const fn with_config(config: ReputationConfig) -> Self {
        Self { config }
    }

    /// Calculate reputation from an agent's claim history
    ///
    /// # Arguments
    /// * `outcomes` - Historical claim outcomes for this agent
    ///
    /// # Returns
    /// Reputation score in `[min_reputation, max_reputation]`
    /// # Errors
    /// Returns `EngineError` if reputation computation fails.
    pub fn calculate(&self, outcomes: &[ClaimOutcome]) -> Result<f64, EngineError> {
        if outcomes.is_empty() {
            return Ok(self.config.initial_reputation);
        }

        // Separate recent vs historical
        let mut recent: Vec<&ClaimOutcome> = vec![];
        let mut historical: Vec<&ClaimOutcome> = vec![];

        for outcome in outcomes {
            if outcome.age_days <= 30.0 {
                recent.push(outcome);
            } else {
                historical.push(outcome);
            }
        }

        // Calculate scores for each group
        let recent_score = self.calculate_group_score(&recent);
        let historical_score = self.calculate_group_score(&historical);

        // Weighted combination
        let combined = if historical.is_empty() {
            recent_score
        } else if recent.is_empty() {
            historical_score
        } else {
            recent_score.mul_add(
                self.config.recency_weight,
                historical_score * (1.0 - self.config.recency_weight),
            )
        };

        // Apply stability penalty if too few claims
        let stability_factor = if outcomes.len() < self.config.min_claims_for_stability {
            // Regress toward mean for new agents
            #[allow(clippy::cast_precision_loss)]
            let progress = outcomes.len() as f64 / self.config.min_claims_for_stability as f64;
            progress.mul_add(combined, (1.0 - progress) * self.config.initial_reputation)
        } else {
            combined
        };

        // Clamp to bounds
        Ok(stability_factor.clamp(self.config.min_reputation, self.config.max_reputation))
    }

    /// Calculate score for a group of claim outcomes
    fn calculate_group_score(&self, outcomes: &[&ClaimOutcome]) -> f64 {
        if outcomes.is_empty() {
            return self.config.initial_reputation;
        }

        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        for outcome in outcomes {
            // Refuted claims hurt reputation more
            let claim_score = if outcome.was_refuted {
                outcome.truth_value * 0.5 // Penalty for being refuted
            } else {
                outcome.truth_value
            };

            // More recent claims weighted higher (within group)
            let recency_factor = 1.0 / (1.0 + outcome.age_days / 30.0);

            total_score += claim_score * recency_factor;
            total_weight += recency_factor;
        }

        if total_weight > 0.0 {
            total_score / total_weight
        } else {
            self.config.initial_reputation
        }
    }

    /// Check if an agent's reputation allows certain actions
    ///
    /// Note: This is for access control, NOT truth calculation.
    #[must_use]
    pub fn can_perform_action(&self, reputation: f64, required_reputation: f64) -> bool {
        reputation >= required_reputation
    }
}

impl Default for ReputationCalculator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_agent_gets_initial_reputation() {
        let calc = ReputationCalculator::new();
        let reputation = calc.calculate(&[]).unwrap();

        assert!((reputation - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn high_truth_claims_increase_reputation() {
        let calc = ReputationCalculator::new();

        let outcomes: Vec<ClaimOutcome> = (0..10)
            .map(|_| ClaimOutcome {
                truth_value: 0.9,
                age_days: 5.0,
                was_refuted: false,
            })
            .collect();

        let reputation = calc.calculate(&outcomes).unwrap();

        assert!(reputation > 0.5);
    }

    #[test]
    fn low_truth_claims_decrease_reputation() {
        let calc = ReputationCalculator::new();

        let outcomes: Vec<ClaimOutcome> = (0..10)
            .map(|_| ClaimOutcome {
                truth_value: 0.2,
                age_days: 5.0,
                was_refuted: false,
            })
            .collect();

        let reputation = calc.calculate(&outcomes).unwrap();

        assert!(reputation < 0.5);
    }

    #[test]
    fn refuted_claims_hurt_reputation() {
        let calc = ReputationCalculator::new();

        let not_refuted: Vec<ClaimOutcome> = (0..10)
            .map(|_| ClaimOutcome {
                truth_value: 0.7,
                age_days: 5.0,
                was_refuted: false,
            })
            .collect();

        let refuted: Vec<ClaimOutcome> = (0..10)
            .map(|_| ClaimOutcome {
                truth_value: 0.7,
                age_days: 5.0,
                was_refuted: true,
            })
            .collect();

        let rep_not_refuted = calc.calculate(&not_refuted).unwrap();
        let rep_refuted = calc.calculate(&refuted).unwrap();

        assert!(rep_not_refuted > rep_refuted);
    }

    #[test]
    fn recent_claims_weighted_more() {
        let calc = ReputationCalculator::new();

        // Agent with good recent history, bad old history
        let outcomes: Vec<ClaimOutcome> = vec![
            ClaimOutcome {
                truth_value: 0.9,
                age_days: 1.0,
                was_refuted: false,
            },
            ClaimOutcome {
                truth_value: 0.9,
                age_days: 2.0,
                was_refuted: false,
            },
            ClaimOutcome {
                truth_value: 0.2,
                age_days: 60.0,
                was_refuted: false,
            },
            ClaimOutcome {
                truth_value: 0.2,
                age_days: 90.0,
                was_refuted: false,
            },
        ];

        let reputation = calc.calculate(&outcomes).unwrap();

        // Should be closer to recent (0.9) than historical (0.2)
        assert!(reputation > 0.5);
    }

    #[test]
    fn reputation_bounded() {
        let calc = ReputationCalculator::new();

        // All perfect claims
        let outcomes: Vec<ClaimOutcome> = (0..100)
            .map(|_| ClaimOutcome {
                truth_value: 1.0,
                age_days: 1.0,
                was_refuted: false,
            })
            .collect();

        let reputation = calc.calculate(&outcomes).unwrap();

        assert!(reputation <= 0.95); // max_reputation
    }

    #[test]
    fn reputation_bounded_minimum() {
        let calc = ReputationCalculator::new();

        // All terrible claims
        let outcomes: Vec<ClaimOutcome> = (0..100)
            .map(|_| ClaimOutcome {
                truth_value: 0.0,
                age_days: 1.0,
                was_refuted: true,
            })
            .collect();

        let reputation = calc.calculate(&outcomes).unwrap();

        assert!(reputation >= 0.1); // min_reputation
    }

    #[test]
    fn few_claims_regress_to_mean() {
        let calc = ReputationCalculator::new();

        // Only 2 perfect claims
        let outcomes = vec![
            ClaimOutcome {
                truth_value: 1.0,
                age_days: 1.0,
                was_refuted: false,
            },
            ClaimOutcome {
                truth_value: 1.0,
                age_days: 2.0,
                was_refuted: false,
            },
        ];

        let reputation = calc.calculate(&outcomes).unwrap();

        // Should be pulled toward initial 0.5 due to low claim count
        assert!(reputation < 0.9);
    }

    #[test]
    fn can_perform_action_sufficient_reputation() {
        let calc = ReputationCalculator::new();

        assert!(calc.can_perform_action(0.8, 0.5));
        assert!(calc.can_perform_action(0.5, 0.5));
    }

    #[test]
    fn can_perform_action_insufficient_reputation() {
        let calc = ReputationCalculator::new();

        assert!(!calc.can_perform_action(0.4, 0.5));
        assert!(!calc.can_perform_action(0.0, 0.5));
    }

    #[test]
    fn custom_config() {
        let config = ReputationConfig {
            initial_reputation: 0.3,
            min_reputation: 0.05,
            max_reputation: 0.99,
            recency_weight: 0.8,
            min_claims_for_stability: 5,
        };

        let calc = ReputationCalculator::with_config(config);

        // New agent should get custom initial reputation
        let reputation = calc.calculate(&[]).unwrap();
        assert!((reputation - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn only_historical_claims() {
        let calc = ReputationCalculator::new();

        // All claims are older than 30 days
        let outcomes: Vec<ClaimOutcome> = (0..10)
            .map(|i| ClaimOutcome {
                truth_value: 0.8,
                age_days: 60.0 + f64::from(i),
                was_refuted: false,
            })
            .collect();

        let reputation = calc.calculate(&outcomes).unwrap();

        // Should still compute a valid reputation
        assert!(reputation > 0.5);
    }
}
