//! Workflow-variant promotion gate (GEPA).
//!
//! Decides whether a proposed workflow *variant* is statistically good enough
//! to be preferred over its lineage *parent*, based purely on behavioral
//! execution outcomes (NOT claim `truth_value` — the hierarchical
//! workflow-outcome path never updates it; the signal lives in
//! `behavioral_executions`).
//!
//! A variant is promotable only when BOTH hold:
//!  1. **Minimum sample** — it has at least `min_executions` of its OWN
//!     executions (default 10). Below that, its success rate is noise.
//!  2. **Beats the parent with confidence** — the Wilson score-interval LOWER
//!     bound of the variant's success rate exceeds the parent's observed
//!     success rate. Using the variant's lower bound (not its point estimate)
//!     means we promote only when we're statistically confident the variant is
//!     genuinely better, not lucky on a small sample.
//!
//! This is the autonomous statistical gate: a maintenance pass evaluates it and
//! sets a `promotable` flag, keeping `find_workflow` read-only and cheap.

use serde::Serialize;

/// Tunables for the promotion gate.
#[derive(Debug, Clone)]
pub struct WorkflowPromotionConfig {
    /// Minimum number of the variant's own executions before it is eligible.
    pub min_executions: i64,
    /// Wilson interval z-score (1.96 ≈ 95% one-sided-ish confidence).
    pub z: f64,
}

impl Default for WorkflowPromotionConfig {
    fn default() -> Self {
        Self {
            min_executions: 10,
            z: 1.96,
        }
    }
}

/// Success counts for one workflow over a window of executions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkflowSampleStats {
    pub successes: i64,
    pub total: i64,
}

impl WorkflowSampleStats {
    /// Observed success rate, or 0.0 when there are no executions.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total <= 0 {
            0.0
        } else {
            self.successes as f64 / self.total as f64
        }
    }
}

/// The gate's decision plus the figures behind it (for logging / the tool).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WorkflowPromotionVerdict {
    pub promotable: bool,
    pub variant_lower_bound: f64,
    pub parent_rate: f64,
    pub variant_total: i64,
    pub reason: String,
}

/// Wilson score-interval lower bound for `successes` of `total` Bernoulli
/// trials at z-score `z`. Returns 0.0 for an empty sample. Clamped to `[0, 1]`.
#[must_use]
pub fn wilson_lower_bound(successes: i64, total: i64, z: f64) -> f64 {
    if total <= 0 {
        return 0.0;
    }
    let n = total as f64;
    let p = (successes as f64 / n).clamp(0.0, 1.0);
    let z2 = z * z;
    let denom = 1.0 + z2 / n;
    let center = p + z2 / (2.0 * n);
    let margin = z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt();
    ((center - margin) / denom).clamp(0.0, 1.0)
}

/// Evaluate whether `variant` should be promoted over a parent whose observed
/// success rate is `parent_rate`.
#[must_use]
pub fn evaluate_workflow_promotion(
    variant: &WorkflowSampleStats,
    parent_rate: f64,
    config: &WorkflowPromotionConfig,
) -> WorkflowPromotionVerdict {
    let variant_lower_bound = wilson_lower_bound(variant.successes, variant.total, config.z);

    let (promotable, reason) = if variant.total < config.min_executions {
        (
            false,
            format!(
                "insufficient sample: {} executions < min {}",
                variant.total, config.min_executions
            ),
        )
    } else if variant_lower_bound > parent_rate {
        (
            true,
            format!(
                "variant Wilson lower bound {variant_lower_bound:.3} exceeds parent rate \
                 {parent_rate:.3} over {} executions",
                variant.total
            ),
        )
    } else {
        (
            false,
            format!(
                "variant Wilson lower bound {variant_lower_bound:.3} does not exceed parent rate \
                 {parent_rate:.3}"
            ),
        )
    };

    WorkflowPromotionVerdict {
        promotable,
        variant_lower_bound,
        parent_rate,
        variant_total: variant.total,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 0.005, "expected ~{b}, got {a}");
    }

    #[test]
    fn wilson_lower_bound_known_values() {
        // 10/10 at z=1.96 → ~0.7225 (the classic "10 for 10" lower bound).
        approx(wilson_lower_bound(10, 10, 1.96), 0.7225);
        // 50/100 → ~0.4038.
        approx(wilson_lower_bound(50, 100, 1.96), 0.4038);
        // empty sample → 0.0.
        approx(wilson_lower_bound(0, 0, 1.96), 0.0);
        // lower bound is always below the point estimate for a finite sample.
        assert!(wilson_lower_bound(60, 100, 1.96) < 0.6);
    }

    fn cfg() -> WorkflowPromotionConfig {
        WorkflowPromotionConfig::default()
    }

    #[test]
    fn rejects_below_min_sample_even_at_100pct() {
        // 9/9 is a perfect record but below the min-10 sample → not promotable.
        let v = WorkflowSampleStats {
            successes: 9,
            total: 9,
        };
        let verdict = evaluate_workflow_promotion(&v, 0.0, &cfg());
        assert!(
            !verdict.promotable,
            "9 executions < min 10 must not promote"
        );
        assert!(verdict.reason.contains("sample") || verdict.reason.contains("executions"));
    }

    #[test]
    fn promotes_when_lower_bound_beats_weak_parent() {
        // 10/10 → lower bound ~0.72, beats a 0.5 parent.
        let v = WorkflowSampleStats {
            successes: 10,
            total: 10,
        };
        let verdict = evaluate_workflow_promotion(&v, 0.5, &cfg());
        assert!(
            verdict.promotable,
            "0.72 lower bound should beat a 0.5 parent"
        );
        approx(verdict.variant_lower_bound, 0.7225);
    }

    #[test]
    fn does_not_promote_against_strong_parent() {
        // Same 10/10 variant, but the parent already wins 0.8 of the time:
        // 0.72 lower bound does NOT exceed 0.8 → stay conservative.
        let v = WorkflowSampleStats {
            successes: 10,
            total: 10,
        };
        let verdict = evaluate_workflow_promotion(&v, 0.8, &cfg());
        assert!(
            !verdict.promotable,
            "must not promote when lower bound < parent rate"
        );
    }

    #[test]
    fn marginal_case_60_of_100_barely_beats_half() {
        // 60/100 lower bound ~0.502 just clears a 0.5 parent.
        let v = WorkflowSampleStats {
            successes: 60,
            total: 100,
        };
        assert!(evaluate_workflow_promotion(&v, 0.5, &cfg()).promotable);
        // 55/100 lower bound ~0.452 does NOT clear 0.5.
        let v2 = WorkflowSampleStats {
            successes: 55,
            total: 100,
        };
        assert!(!evaluate_workflow_promotion(&v2, 0.5, &cfg()).promotable);
    }

    #[test]
    fn min_executions_boundary_is_inclusive() {
        // Exactly min_executions is eligible (>=, not >).
        let v = WorkflowSampleStats {
            successes: 10,
            total: 10,
        };
        assert!(evaluate_workflow_promotion(&v, 0.0, &cfg()).promotable);
    }
}
