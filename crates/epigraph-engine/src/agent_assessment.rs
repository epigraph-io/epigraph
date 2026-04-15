//! Agent assessment metrics for performance tracking

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAssessment {
    pub claims_submitted: u64,
    pub claims_verified_true: u64,
    pub claims_verified_false: u64,
    pub claims_uncertain: u64,
    pub accuracy: f64,
    pub average_truth: f64,
}

impl AgentAssessment {
    pub fn from_counts(
        verified_true: u64,
        verified_false: u64,
        uncertain: u64,
        average_truth: f64,
    ) -> Self {
        let total_verified = verified_true + verified_false;
        let accuracy = if total_verified > 0 {
            verified_true as f64 / total_verified as f64
        } else {
            0.0
        };
        Self {
            claims_submitted: verified_true + verified_false + uncertain,
            claims_verified_true: verified_true,
            claims_verified_false: verified_false,
            claims_uncertain: uncertain,
            accuracy,
            average_truth,
        }
    }

    pub fn is_reliable(&self) -> bool {
        let total_verified = self.claims_verified_true + self.claims_verified_false;
        total_verified >= 10 && self.accuracy > 0.7
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perfect_agent() {
        let a = AgentAssessment::from_counts(50, 0, 0, 0.9);
        assert!((a.accuracy - 1.0).abs() < f64::EPSILON);
        assert!(a.is_reliable());
    }

    #[test]
    fn test_terrible_agent() {
        let a = AgentAssessment::from_counts(0, 50, 0, 0.1);
        assert!((a.accuracy - 0.0).abs() < f64::EPSILON);
        assert!(!a.is_reliable());
    }

    #[test]
    fn test_mixed_agent() {
        let a = AgentAssessment::from_counts(30, 10, 10, 0.7);
        assert!((a.accuracy - 0.75).abs() < f64::EPSILON);
        assert!(a.is_reliable());
    }

    #[test]
    fn test_no_verified() {
        let a = AgentAssessment::from_counts(0, 0, 50, 0.5);
        assert!((a.accuracy - 0.0).abs() < f64::EPSILON);
        assert!(!a.is_reliable());
    }

    #[test]
    fn test_few_verified_not_reliable() {
        let a = AgentAssessment::from_counts(5, 1, 0, 0.8);
        assert!(!a.is_reliable());
    }
}
