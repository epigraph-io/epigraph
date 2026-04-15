//! Wilson score confidence intervals for truth values

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TruthWithConfidence {
    pub value: f64,
    pub ci_lower: f64,
    pub ci_upper: f64,
    pub evidence_count: u32,
}

impl TruthWithConfidence {
    pub fn with_wilson_interval(truth: f64, evidence_count: u32) -> Self {
        if evidence_count == 0 {
            return Self {
                value: truth,
                ci_lower: 0.0,
                ci_upper: 1.0,
                evidence_count: 0,
            };
        }
        let n = evidence_count as f64;
        let p = truth.clamp(0.0, 1.0);
        let z = 1.96;
        let z2 = z * z;
        let denominator = 1.0 + z2 / n;
        let center = (p + z2 / (2.0 * n)) / denominator;
        let margin = z * ((p * (1.0 - p) + z2 / (4.0 * n)) / n).sqrt() / denominator;
        Self {
            value: truth,
            ci_lower: (center - margin).max(0.0),
            ci_upper: (center + margin).min(1.0),
            evidence_count,
        }
    }

    pub fn is_significant(&self) -> bool {
        self.ci_upper < 0.5 || self.ci_lower > 0.5
    }

    pub fn interval_width(&self) -> f64 {
        self.ci_upper - self.ci_lower
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wilson_high_evidence() {
        let ci = TruthWithConfidence::with_wilson_interval(0.8, 100);
        assert!((ci.value - 0.8).abs() < f64::EPSILON);
        assert!(ci.ci_lower > 0.7);
        assert!(ci.ci_upper < 0.9);
    }

    #[test]
    fn test_wilson_low_evidence() {
        let ci = TruthWithConfidence::with_wilson_interval(0.8, 3);
        assert!(ci.ci_upper - ci.ci_lower > 0.3);
    }

    #[test]
    fn test_bounds_clamped() {
        let ci = TruthWithConfidence::with_wilson_interval(0.99, 5);
        assert!(ci.ci_upper <= 1.0);
        assert!(ci.ci_lower >= 0.0);
    }

    #[test]
    fn test_significant_high_truth() {
        let ci = TruthWithConfidence::with_wilson_interval(0.9, 50);
        assert!(ci.is_significant());
    }

    #[test]
    fn test_not_significant_uncertain() {
        let ci = TruthWithConfidence::with_wilson_interval(0.5, 3);
        assert!(!ci.is_significant());
    }

    #[test]
    fn test_zero_evidence() {
        let ci = TruthWithConfidence::with_wilson_interval(0.5, 0);
        assert_eq!(ci.ci_lower, 0.0);
        assert_eq!(ci.ci_upper, 1.0);
    }

    #[test]
    fn test_interval_width() {
        let ci = TruthWithConfidence::with_wilson_interval(0.7, 30);
        assert!((ci.interval_width() - (ci.ci_upper - ci.ci_lower)).abs() < f64::EPSILON);
    }
}
