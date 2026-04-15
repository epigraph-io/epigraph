//! Silence Alarm — detects suspiciously low conflict density.
//!
//! A healthy knowledge graph with diverse sources should contain *some*
//! contradictions.  When the CONTRADICTS edge rate drops below a
//! configurable floor, it may indicate that the ingestion pipeline is
//! silently dropping dissent, that sources are too homogeneous, or that
//! contradiction detection is broken.
//!
//! This module exposes a **pure function** (`check_conflict_density`)
//! that takes pre-computed counts and returns a diagnostic result.
//! No database access is performed here — callers are responsible for
//! providing the counts.

/// Configuration for the silence alarm.
#[derive(Debug, Clone)]
pub struct SilenceAlarmConfig {
    /// Minimum number of claims before the alarm can fire (default: 20).
    pub min_claims_threshold: usize,
    /// Expected minimum conflict rate (default: 0.02 = 2%).
    pub min_conflict_rate: f64,
}

impl Default for SilenceAlarmConfig {
    fn default() -> Self {
        Self {
            min_claims_threshold: 20,
            min_conflict_rate: 0.02,
        }
    }
}

/// Result of a silence alarm check.
#[derive(Debug, Clone)]
pub struct SilenceCheckResult {
    /// Total claims considered.
    pub total_claims: usize,
    /// Number of CONTRADICTS edges found.
    pub contradicts_edges: usize,
    /// Computed conflict rate (`contradicts_edges / total_claims`).
    pub conflict_rate: f64,
    /// Whether the conflict density is suspiciously low.
    pub is_suspicious: bool,
    /// Human-readable explanation when the alarm fires or when the
    /// check is skipped due to insufficient data.
    pub reason: Option<String>,
}

/// Check conflict density given claim and contradiction counts.
///
/// Pure function — no DB access.  The caller provides the counts.
///
/// # Logic
///
/// 1. If `total_claims < config.min_claims_threshold`, return *not*
///    suspicious with a reason explaining the threshold was not met.
/// 2. Compute `rate = contradicts_count / total_claims`.
/// 3. `is_suspicious = rate < config.min_conflict_rate`.
/// 4. If suspicious, attach a reason describing the shortfall.
#[must_use]
pub fn check_conflict_density(
    total_claims: usize,
    contradicts_count: usize,
    config: &SilenceAlarmConfig,
) -> SilenceCheckResult {
    // Below the minimum claim threshold — not enough data to judge.
    if total_claims < config.min_claims_threshold {
        return SilenceCheckResult {
            total_claims,
            contradicts_edges: contradicts_count,
            conflict_rate: 0.0,
            is_suspicious: false,
            reason: Some(format!(
                "Below threshold ({} < {})",
                total_claims, config.min_claims_threshold
            )),
        };
    }

    #[allow(clippy::cast_precision_loss)] // counts will never exceed 2^52
    let rate = contradicts_count as f64 / total_claims as f64;
    let is_suspicious = rate < config.min_conflict_rate;

    let reason = if is_suspicious {
        Some(format!(
            "Conflict rate {:.4} < minimum {:.4} with {} claims",
            rate, config.min_conflict_rate, total_claims
        ))
    } else {
        None
    };

    SilenceCheckResult {
        total_claims,
        contradicts_edges: contradicts_count,
        conflict_rate: rate,
        is_suspicious,
        reason,
    }
}

/// A sample in a belief trajectory: (belief_value, evidence_count_at_time).
#[derive(Debug, Clone)]
pub struct BeliefSample {
    pub belief: f64,
    pub evidence_count: usize,
}

/// Result of checking for monotonic belief increase.
#[derive(Debug, Clone)]
pub struct VelocityCheckResult {
    pub is_suspicious: bool,
    pub monotonic_streak: usize,
    pub total_samples: usize,
    pub reason: Option<String>,
}

/// Check if belief has increased monotonically for too many consecutive
/// evidence submissions. A healthy process shows fluctuation as
/// conflicting evidence arrives. Monotonic increase is a sycophancy signature.
///
/// Pure function — caller provides the trajectory.
#[must_use]
pub fn check_confidence_velocity(
    samples: &[BeliefSample],
    max_monotonic_streak: usize,
) -> VelocityCheckResult {
    if samples.len() < 3 {
        return VelocityCheckResult {
            is_suspicious: false,
            monotonic_streak: 0,
            total_samples: samples.len(),
            reason: Some("Too few samples".into()),
        };
    }

    let mut streak = 0usize;
    let mut max_streak = 0usize;
    for window in samples.windows(2) {
        if window[1].belief > window[0].belief + f64::EPSILON {
            streak += 1;
            max_streak = max_streak.max(streak);
        } else {
            streak = 0;
        }
    }

    let suspicious = max_streak >= max_monotonic_streak;
    VelocityCheckResult {
        is_suspicious: suspicious,
        monotonic_streak: max_streak,
        total_samples: samples.len(),
        reason: if suspicious {
            Some(format!(
                "Belief increased monotonically for {} consecutive submissions (max: {})",
                max_streak, max_monotonic_streak
            ))
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fires_on_zero_conflicts() {
        let config = SilenceAlarmConfig::default();
        let result = check_conflict_density(30, 0, &config);

        assert!(result.is_suspicious);
        assert_eq!(result.total_claims, 30);
        assert_eq!(result.contradicts_edges, 0);
        assert!((result.conflict_rate - 0.0).abs() < f64::EPSILON);
        assert!(result.reason.is_some());
        assert!(result.reason.unwrap().contains("Conflict rate"));
    }

    #[test]
    fn test_quiet_on_healthy() {
        let config = SilenceAlarmConfig::default();
        // 3 / 30 = 10%, well above the 2% floor.
        let result = check_conflict_density(30, 3, &config);

        assert!(!result.is_suspicious);
        assert_eq!(result.contradicts_edges, 3);
        assert!((result.conflict_rate - 0.1).abs() < f64::EPSILON);
        assert!(result.reason.is_none());
    }

    #[test]
    fn test_quiet_below_threshold() {
        let config = SilenceAlarmConfig::default();
        // Only 5 claims — below the default threshold of 20.
        let result = check_conflict_density(5, 0, &config);

        assert!(!result.is_suspicious);
        assert!(result.reason.is_some());
        assert!(result.reason.unwrap().contains("Below threshold"));
    }

    #[test]
    fn test_custom_config() {
        let config = SilenceAlarmConfig {
            min_claims_threshold: 10,
            min_conflict_rate: 0.05,
        };

        // 10 claims, 0 contradicts → rate 0% < 5% → suspicious
        let suspicious = check_conflict_density(10, 0, &config);
        assert!(suspicious.is_suspicious);

        // 10 claims, 1 contradict → rate 10% >= 5% → not suspicious
        let healthy = check_conflict_density(10, 1, &config);
        assert!(!healthy.is_suspicious);
    }

    // =========================================================================
    // R7: Confidence velocity tests
    // =========================================================================

    #[test]
    fn test_velocity_fires_on_monotonic() {
        // 6 monotonically increasing samples → streak of 5
        let samples: Vec<BeliefSample> = (0..6)
            .map(|i| BeliefSample {
                belief: 0.5 + i as f64 * 0.05,
                evidence_count: i,
            })
            .collect();

        let result = check_confidence_velocity(&samples, 5);
        assert!(
            result.is_suspicious,
            "Expected suspicious for 5-step monotonic increase"
        );
        assert_eq!(result.monotonic_streak, 5);
        assert!(result.reason.is_some());
        assert!(result.reason.unwrap().contains("monotonically"));
    }

    #[test]
    fn test_velocity_quiet_on_fluctuation() {
        // Alternating up/down pattern → max streak = 1
        let samples = vec![
            BeliefSample {
                belief: 0.5,
                evidence_count: 0,
            },
            BeliefSample {
                belief: 0.6,
                evidence_count: 1,
            },
            BeliefSample {
                belief: 0.55,
                evidence_count: 2,
            },
            BeliefSample {
                belief: 0.65,
                evidence_count: 3,
            },
            BeliefSample {
                belief: 0.58,
                evidence_count: 4,
            },
            BeliefSample {
                belief: 0.62,
                evidence_count: 5,
            },
        ];

        let result = check_confidence_velocity(&samples, 5);
        assert!(
            !result.is_suspicious,
            "Fluctuating pattern should not be suspicious"
        );
        assert!(result.monotonic_streak <= 1);
        assert!(result.reason.is_none());
    }

    #[test]
    fn test_velocity_too_few_samples() {
        let samples = vec![
            BeliefSample {
                belief: 0.5,
                evidence_count: 0,
            },
            BeliefSample {
                belief: 0.6,
                evidence_count: 1,
            },
        ];

        let result = check_confidence_velocity(&samples, 5);
        assert!(
            !result.is_suspicious,
            "Too few samples should not be suspicious"
        );
        assert_eq!(result.total_samples, 2);
        assert!(result.reason.unwrap().contains("Too few"));
    }
}
