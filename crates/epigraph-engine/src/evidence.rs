//! Evidence weighting for claim truth calculation
//!
//! Evidence weight determines how strongly a piece of evidence
//! supports (positive weight) or refutes (negative weight) a claim.

use crate::errors::EngineError;
use epigraph_core::TruthValue;

/// Configuration for evidence weight calculation
#[derive(Debug, Clone)]
pub struct EvidenceWeightConfig {
    /// Maximum weight a single piece of evidence can contribute
    pub max_weight: f64,
    /// Minimum weight (for very weak evidence)
    pub min_weight: f64,
    /// Decay factor for older evidence (per day)
    pub temporal_decay: f64,
    /// Whether to apply temporal decay
    pub apply_temporal_decay: bool,
}

impl Default for EvidenceWeightConfig {
    fn default() -> Self {
        Self {
            max_weight: 1.0,
            min_weight: 0.01,
            temporal_decay: 0.99, // 1% decay per day
            apply_temporal_decay: true,
        }
    }
}

/// Evidence type classification for weighting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceType {
    /// Direct observation or measurement
    Empirical,
    /// Logical derivation from other claims
    Logical,
    /// Expert opinion or testimony
    Testimonial,
    /// Statistical or probabilistic evidence
    Statistical,
    /// Circumstantial or indirect evidence
    Circumstantial,
}

impl EvidenceType {
    /// Base weight multiplier for this evidence type
    #[must_use]
    pub const fn base_multiplier(self) -> f64 {
        match self {
            Self::Empirical => 1.0,      // Strongest: direct observation
            Self::Statistical => 0.9,    // Strong: reproducible data
            Self::Logical => 0.85,       // Strong: valid reasoning
            Self::Testimonial => 0.6,    // Moderate: depends on source
            Self::Circumstantial => 0.4, // Weak: indirect
        }
    }
}

/// Calculator for evidence weights
pub struct EvidenceWeighter {
    config: EvidenceWeightConfig,
}

impl EvidenceWeighter {
    /// Create a new evidence weighter with default config
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: EvidenceWeightConfig::default(),
        }
    }

    /// Create with custom config
    #[must_use]
    pub const fn with_config(config: EvidenceWeightConfig) -> Self {
        Self { config }
    }

    /// Calculate the weight of evidence for a claim
    ///
    /// # Arguments
    /// * `evidence_type` - Classification of the evidence
    /// * `source_truth` - Truth value of the source claim (if derived)
    /// * `relevance` - How directly relevant the evidence is [0, 1]
    /// * `age_days` - Age of the evidence in days (for temporal decay)
    ///
    /// # Returns
    /// Weight in range `[min_weight, max_weight]`
    ///
    /// # Errors
    /// Returns `EngineError::InvalidEvidence` if relevance is out of bounds.
    pub fn calculate_weight(
        &self,
        evidence_type: EvidenceType,
        source_truth: Option<TruthValue>,
        relevance: f64,
        age_days: f64,
    ) -> Result<f64, EngineError> {
        if !(0.0..=1.0).contains(&relevance) {
            return Err(EngineError::InvalidEvidence {
                reason: format!("Relevance must be in [0, 1], got {relevance}"),
            });
        }

        // Start with type-based multiplier
        let mut weight = evidence_type.base_multiplier();

        // Apply relevance factor
        weight *= relevance;

        // If derived from another claim, factor in source truth
        if let Some(truth) = source_truth {
            // Evidence from uncertain sources carries less weight
            weight *= truth.value();
        }

        // Apply temporal decay if enabled
        if self.config.apply_temporal_decay && age_days > 0.0 {
            weight *= self.config.temporal_decay.powf(age_days);
        }

        // Clamp to configured bounds
        let final_weight = weight.clamp(self.config.min_weight, self.config.max_weight);

        Ok(final_weight)
    }

    /// Calculate combined weight from multiple pieces of evidence
    ///
    /// Uses diminishing returns: each additional piece of evidence
    /// contributes less than the previous one (prevents evidence stacking).
    #[must_use]
    pub fn combine_weights(&self, weights: &[f64]) -> f64 {
        if weights.is_empty() {
            return 0.0;
        }

        // Sort weights descending (strongest evidence first)
        let mut sorted: Vec<f64> = weights.to_vec();
        sorted.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

        // Diminishing returns formula: w1 + w2*0.5 + w3*0.25 + ...
        let mut combined = 0.0;
        let mut factor = 1.0;
        for w in sorted {
            combined += w * factor;
            factor *= 0.5; // Each subsequent piece contributes half as much
        }

        // Normalize to [0, 1] range (max possible is 2.0 with infinite evidence)
        (combined / 2.0).min(1.0)
    }
}

impl Default for EvidenceWeighter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_type_multipliers() {
        assert!(
            EvidenceType::Empirical.base_multiplier() > EvidenceType::Testimonial.base_multiplier()
        );
        assert!(
            EvidenceType::Statistical.base_multiplier()
                > EvidenceType::Circumstantial.base_multiplier()
        );
    }

    #[test]
    fn weight_respects_relevance() {
        let weighter = EvidenceWeighter::new();

        let high_relevance = weighter
            .calculate_weight(EvidenceType::Empirical, None, 1.0, 0.0)
            .unwrap();
        let low_relevance = weighter
            .calculate_weight(EvidenceType::Empirical, None, 0.5, 0.0)
            .unwrap();

        assert!(high_relevance > low_relevance);
    }

    #[test]
    fn weight_respects_source_truth() {
        let weighter = EvidenceWeighter::new();

        let certain_source = weighter
            .calculate_weight(
                EvidenceType::Logical,
                Some(TruthValue::new(0.9).unwrap()),
                1.0,
                0.0,
            )
            .unwrap();
        let uncertain_source = weighter
            .calculate_weight(
                EvidenceType::Logical,
                Some(TruthValue::new(0.5).unwrap()),
                1.0,
                0.0,
            )
            .unwrap();

        assert!(certain_source > uncertain_source);
    }

    #[test]
    fn temporal_decay_reduces_weight() {
        let weighter = EvidenceWeighter::new();

        let fresh = weighter
            .calculate_weight(EvidenceType::Empirical, None, 1.0, 0.0)
            .unwrap();
        let old = weighter
            .calculate_weight(EvidenceType::Empirical, None, 1.0, 30.0)
            .unwrap();

        assert!(fresh > old);
    }

    #[test]
    fn combine_weights_diminishing_returns() {
        let weighter = EvidenceWeighter::new();

        let single = weighter.combine_weights(&[1.0]);
        let double = weighter.combine_weights(&[1.0, 1.0]);
        let triple = weighter.combine_weights(&[1.0, 1.0, 1.0]);

        // Each additional evidence should add less
        assert!(double > single);
        assert!(triple > double);
        assert!(triple - double < double - single);
    }

    #[test]
    fn invalid_relevance_rejected() {
        let weighter = EvidenceWeighter::new();

        assert!(weighter
            .calculate_weight(EvidenceType::Empirical, None, 1.5, 0.0)
            .is_err());
        assert!(weighter
            .calculate_weight(EvidenceType::Empirical, None, -0.1, 0.0)
            .is_err());
    }
}
