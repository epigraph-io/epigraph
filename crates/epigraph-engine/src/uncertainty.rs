//! Parse uncertainty / error bars from scientific text.
//!
//! Returns a normalised `f64` in `[0.01, 0.99]` where lower = more precise,
//! or `None` when no parseable uncertainty is found.

use std::sync::LazyLock;

use regex::Regex;

// ---------------------------------------------------------------------------
// Compiled patterns, checked in priority order
// ---------------------------------------------------------------------------

/// 1. `+-X%` or `+- X%` (percentage directly)
static RE_PM_PCT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"±\s*(\d+(?:\.\d+)?)\s*%").expect("RE_PM_PCT"));

/// 5. Parenthetical: `(value +- error)` — checked before generic +- so parens
///    are not consumed by pattern 2.
static RE_PAREN_PM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\(\s*(\d+(?:\.\d+)?)\s*±\s*(\d+(?:\.\d+)?)\s*\)").expect("RE_PAREN_PM")
});

/// 2. `value +- error` (absolute, generic — checked after parenthetical)
static RE_PM_ABS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d+(?:\.\d+)?)\s*±\s*(\d+(?:\.\d+)?)").expect("RE_PM_ABS"));

/// 3. `95% CI [lower, upper]`
static RE_CI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:\d+%?\s*)?CI\s*\[\s*(\d+(?:\.\d+)?)\s*,\s*(\d+(?:\.\d+)?)\s*\]")
        .expect("RE_CI")
});

/// 4. `p < 0.001`, `p = 0.05`, `p=.01`, etc.
static RE_PVAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)p\s*[<>=≤≥]+\s*(\d*\.?\d+)").expect("RE_PVAL"));

// ---------------------------------------------------------------------------
// p-value tier map
// ---------------------------------------------------------------------------

const P_TIERS: [(f64, f64); 3] = [(0.001, 0.05), (0.01, 0.10), (0.05, 0.20)];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn clamp(v: f64) -> f64 {
    v.clamp(0.01, 0.99)
}

fn relative_error(value: f64, error: f64) -> Option<f64> {
    if value == 0.0 {
        return None;
    }
    Some(clamp((error / value).abs()))
}

fn p_to_uncertainty(p: f64) -> f64 {
    for &(threshold, mapped) in &P_TIERS {
        if p <= threshold {
            return clamp(mapped);
        }
    }
    clamp(0.4 + p)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Extract the first recognisable uncertainty from `text`.
///
/// Priority order:
///   1. `+-X%`
///   2. `(value +- error)` parenthetical
///   3. `value +- error` absolute
///   4. `95% CI [lo, hi]`
///   5. p-value
///
/// Returns a float in `[0.01, 0.99]` or `None`.
#[must_use]
pub fn parse_uncertainty(text: &str) -> Option<f64> {
    if text.is_empty() {
        return None;
    }

    // 1 — percentage
    if let Some(m) = RE_PM_PCT.captures(text) {
        let pct: f64 = m[1].parse().ok()?;
        return Some(clamp(pct / 100.0));
    }

    // 2 — parenthetical (check before generic +- so parens are not consumed)
    if let Some(m) = RE_PAREN_PM.captures(text) {
        let val: f64 = m[1].parse().ok()?;
        let err: f64 = m[2].parse().ok()?;
        return relative_error(val, err);
    }

    // 3 — absolute +-
    if let Some(m) = RE_PM_ABS.captures(text) {
        let val: f64 = m[1].parse().ok()?;
        let err: f64 = m[2].parse().ok()?;
        return relative_error(val, err);
    }

    // 4 — confidence interval
    if let Some(m) = RE_CI.captures(text) {
        let lo: f64 = m[1].parse().ok()?;
        let hi: f64 = m[2].parse().ok()?;
        let mid = (lo + hi) / 2.0;
        if mid == 0.0 {
            return None;
        }
        let width = hi - lo;
        return Some(clamp((width / mid).abs()));
    }

    // 5 — p-value
    if let Some(m) = RE_PVAL.captures(text) {
        let p: f64 = m[1].parse().ok()?;
        return Some(p_to_uncertainty(p));
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to assert approximate equality.
    fn assert_approx(actual: Option<f64>, expected: f64, tol: f64) {
        let v = actual.expect("expected Some, got None");
        assert!((v - expected).abs() < tol, "expected ~{expected}, got {v}");
    }

    // ---- Pattern 1: +-X% ----

    #[test]
    fn pct_integer() {
        assert_approx(parse_uncertainty("±5%"), 0.05, 1e-9);
    }

    #[test]
    fn pct_decimal() {
        assert_approx(parse_uncertainty("±2.5%"), 0.025, 1e-9);
    }

    #[test]
    fn pct_with_space() {
        assert_approx(parse_uncertainty("± 10%"), 0.10, 1e-9);
    }

    #[test]
    fn pct_in_sentence() {
        assert_approx(
            parse_uncertainty("The measurement was ±3% of baseline"),
            0.03,
            1e-9,
        );
    }

    #[test]
    fn pct_clamp_high() {
        // ±150% should clamp to 0.99
        assert_approx(parse_uncertainty("±150%"), 0.99, 1e-9);
    }

    #[test]
    fn pct_clamp_low() {
        // ±0.001% = 0.00001, clamp to 0.01
        assert_approx(parse_uncertainty("±0.001%"), 0.01, 1e-9);
    }

    // ---- Pattern 2: (value +- error) parenthetical ----

    #[test]
    fn paren_basic() {
        // (50 +- 5) => 5/50 = 0.1
        assert_approx(parse_uncertainty("result was (50 ± 5)"), 0.10, 1e-9);
    }

    #[test]
    fn paren_decimal() {
        // (3.14 +- 0.02) => 0.02/3.14 ~= 0.00637 -> clamp to 0.01
        assert_approx(parse_uncertainty("(3.14 ± 0.02)"), 0.01, 1e-3);
    }

    #[test]
    fn paren_zero_value() {
        // (0 +- 5) => division by zero => None
        assert!(parse_uncertainty("(0 ± 5)").is_none());
    }

    // ---- Pattern 3: value +- error (absolute) ----

    #[test]
    fn abs_basic() {
        // 100 +- 10 => 10/100 = 0.1
        assert_approx(parse_uncertainty("100 ± 10"), 0.10, 1e-9);
    }

    #[test]
    fn abs_decimal() {
        // 2.5 +- 0.5 => 0.5/2.5 = 0.2
        assert_approx(parse_uncertainty("2.5 ± 0.5"), 0.20, 1e-9);
    }

    #[test]
    fn abs_zero_value() {
        assert!(parse_uncertainty("0 ± 5").is_none());
    }

    // ---- Pattern 4: CI ----

    #[test]
    fn ci_basic() {
        // 95% CI [10, 20] => width=10, mid=15 => 10/15 ~= 0.667
        assert_approx(parse_uncertainty("95% CI [10, 20]"), 10.0 / 15.0, 1e-3);
    }

    #[test]
    fn ci_no_prefix() {
        // CI [4, 6] => width=2, mid=5 => 0.4
        assert_approx(parse_uncertainty("CI [4, 6]"), 0.4, 1e-9);
    }

    #[test]
    fn ci_case_insensitive() {
        assert_approx(parse_uncertainty("95% ci [10, 20]"), 10.0 / 15.0, 1e-3);
    }

    #[test]
    fn ci_zero_midpoint() {
        // CI [0, 0] => mid=0 => None
        assert!(parse_uncertainty("CI [0, 0]").is_none());
    }

    // ---- Pattern 5: p-value ----

    #[test]
    fn p_very_small() {
        // p < 0.001 => tier 0.05
        assert_approx(parse_uncertainty("p < 0.001"), 0.05, 1e-9);
    }

    #[test]
    fn p_small() {
        // p < 0.01 => tier 0.10
        assert_approx(parse_uncertainty("p < 0.01"), 0.10, 1e-9);
    }

    #[test]
    fn p_moderate() {
        // p = 0.05 => tier 0.20
        assert_approx(parse_uncertainty("p = 0.05"), 0.20, 1e-9);
    }

    #[test]
    fn p_large() {
        // p = 0.1 => 0.4 + 0.1 = 0.5
        assert_approx(parse_uncertainty("p = 0.1"), 0.50, 1e-9);
    }

    #[test]
    fn p_very_large() {
        // p = 0.8 => 0.4 + 0.8 = 1.2 => clamp to 0.99
        assert_approx(parse_uncertainty("p = 0.8"), 0.99, 1e-9);
    }

    #[test]
    fn p_equality_boundary() {
        // p <= 0.001 exactly => maps to 0.05
        assert_approx(parse_uncertainty("p≤0.001"), 0.05, 1e-9);
    }

    // ---- Edge cases ----

    #[test]
    fn empty_string() {
        assert!(parse_uncertainty("").is_none());
    }

    #[test]
    fn no_match() {
        assert!(parse_uncertainty("The sky is blue.").is_none());
    }

    #[test]
    fn priority_pct_over_abs() {
        // "±5%" matches pattern 1 (percentage), not pattern 3 (absolute).
        // Should return 0.05, not a relative error.
        assert_approx(parse_uncertainty("100 ±5%"), 0.05, 1e-9);
    }

    #[test]
    fn priority_paren_over_abs() {
        // "(50 +- 5) and also 100 +- 20" — parenthetical should win.
        assert_approx(
            parse_uncertainty("reported (50 ± 5) with 100 ± 20"),
            0.10,
            1e-9,
        );
    }

    #[test]
    fn multiple_patterns_first_priority_wins() {
        // Has both CI and p-value; CI (pattern 4) has higher priority.
        let text = "95% CI [10, 20], p < 0.01";
        assert_approx(parse_uncertainty(text), 10.0 / 15.0, 1e-3);
    }

    #[test]
    fn all_results_clamped_low() {
        // Extremely precise: (1000000 +- 1) => 1e-6 => clamp to 0.01
        assert_approx(parse_uncertainty("(1000000 ± 1)"), 0.01, 1e-9);
    }

    #[test]
    fn all_results_clamped_high() {
        // Very imprecise: (1 +- 100) => 100 => clamp to 0.99
        assert_approx(parse_uncertainty("(1 ± 100)"), 0.99, 1e-9);
    }
}
