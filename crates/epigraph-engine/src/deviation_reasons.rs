//! Normalisation and recurrence ranking for free-text step deviation reasons.
//!
//! `behavioral_executions.step_beliefs.deviation_reason` is agent-written prose:
//! the same underlying failure arrives as `"Tool timed out"`, `"tool  timed
//! out"`, and `"TOOL TIMED OUT."` on three different runs. Counting the raw
//! strings therefore reports three singletons instead of one recurring problem,
//! which is exactly the signal a step-evolution decision needs.
//!
//! This module is pure: no database, no async, no I/O. Normalisation must
//! happen *before* counting, so the grouping lives here (unit-testable without
//! Postgres) rather than in a SQL `GROUP BY`. The DB layer stays a bounded raw
//! fetch; see `epigraph_db::BehavioralExecutionRepository::step_deviation_reasons`.

use std::cmp::Reverse;
use std::collections::BTreeMap;

/// Maximum length, in `char`s, of a canonical reason. Longer inputs are
/// truncated on a char boundary so a runaway stack trace pasted into
/// `deviation_reason` cannot dominate the grouping key.
pub const MAX_REASON_CHARS: usize = 200;

/// One canonical deviation reason together with how often it recurred.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RecurringReason {
    /// The canonical (normalised) form used as the grouping key.
    pub reason: String,
    /// The most common raw form observed for this canonical reason — what an
    /// agent actually wrote, kept so the reader sees real prose rather than
    /// only the lowercased key.
    pub representative: String,
    /// Number of observations that mapped to this canonical reason.
    pub count: usize,
    /// Of those, how many came from a run that reported `success = false`.
    pub failure_count: usize,
    /// `count` as a fraction of all observations that normalised successfully
    /// (unnormalisable observations are excluded from the denominator).
    pub share: f64,
}

/// Canonicalise one raw deviation reason, or `None` if it carries no signal.
///
/// The rules, in order: trim; strip a matched pair of wrapping quotes;
/// lowercase; collapse every whitespace run to a single space; drop trailing
/// sentence punctuation; truncate to [`MAX_REASON_CHARS`] on a char boundary.
/// Blank and punctuation-only inputs yield `None` — they must not be counted,
/// because "the agent wrote nothing useful" is not a recurring reason.
#[must_use]
pub fn normalize_reason(raw: &str) -> Option<String> {
    let trimmed = raw.trim();

    // Strip one matched pair of wrapping quotes ("…" or '…'). An unmatched
    // leading quote is left alone — it may be meaningful prose.
    let unquoted = {
        let mut chars = trimmed.chars();
        match (chars.next(), chars.next_back()) {
            (Some(first), Some(last))
                if first == last
                    && (first == '"' || first == '\'')
                    && trimmed.chars().count() >= 2 =>
            {
                chars.as_str().trim()
            }
            _ => trimmed,
        }
    };

    let lowered = unquoted.to_lowercase();
    let collapsed = lowered.split_whitespace().collect::<Vec<_>>().join(" ");
    let depunctuated = collapsed.trim_end_matches(|c| ".,;:!?".contains(c)).trim();

    if depunctuated.is_empty() {
        return None;
    }

    // Truncate by chars, never by byte index: reasons routinely contain
    // multibyte characters and slicing mid-codepoint would panic.
    let result = if depunctuated.chars().count() > MAX_REASON_CHARS {
        let truncated: String = depunctuated.chars().take(MAX_REASON_CHARS).collect();
        truncated.trim_end().to_string()
    } else {
        depunctuated.to_string()
    };

    if result.is_empty() {
        return None;
    }

    Some(result)
}

/// Accumulator for one canonical reason while scanning observations.
struct Acc {
    count: usize,
    failure_count: usize,
    /// Trimmed *raw* forms → how often each was written, so the reported
    /// `representative` is the phrasing agents actually used most.
    raw_forms: BTreeMap<String, usize>,
}

/// Group `observations` by canonical reason and rank them by recurrence.
///
/// Each observation is `(raw_reason, success)`; `success` is the enclosing
/// run's outcome, so `failure_count` separates "this deviation recurs" from
/// "this deviation recurs *and* the run fails".
///
/// Observations whose reason does not normalise are dropped entirely — they do
/// not count toward any reason and are not in the `share` denominator.
/// Reasons seen fewer than `min_count` times (floored at 1) are filtered out
/// *after* grouping, and `limit` truncates *after* ranking, so the highest-count
/// reasons always survive. Ordering is fully deterministic: count desc, then
/// failure count desc, then canonical reason ascending.
#[must_use]
pub fn rank_recurring_reasons<'a>(
    observations: impl IntoIterator<Item = (&'a str, bool)>,
    min_count: usize,
    limit: usize,
) -> Vec<RecurringReason> {
    let mut groups: BTreeMap<String, Acc> = BTreeMap::new();
    let mut normalized_total = 0usize;

    for (raw, success) in observations {
        let Some(canonical) = normalize_reason(raw) else {
            continue;
        };
        normalized_total += 1;

        let acc = groups.entry(canonical).or_insert_with(|| Acc {
            count: 0,
            failure_count: 0,
            raw_forms: BTreeMap::new(),
        });
        acc.count += 1;
        if !success {
            acc.failure_count += 1;
        }
        *acc.raw_forms.entry(raw.trim().to_string()).or_insert(0) += 1;
    }

    if normalized_total == 0 {
        return Vec::new();
    }

    let floor = min_count.max(1);
    let total = normalized_total as f64;

    let mut ranked: Vec<RecurringReason> = groups
        .into_iter()
        .filter(|(_, acc)| acc.count >= floor)
        .map(|(reason, acc)| {
            // Strict `>` over the lexicographically sorted map: ties keep the
            // first (smallest) raw form, so the pick is deterministic.
            let mut representative = String::new();
            let mut best = 0usize;
            for (form, n) in &acc.raw_forms {
                if *n > best {
                    best = *n;
                    representative = form.clone();
                }
            }
            RecurringReason {
                share: acc.count as f64 / total,
                reason,
                representative,
                count: acc.count,
                failure_count: acc.failure_count,
            }
        })
        .collect();

    // Stable sort over a reason-ascending Vec: full ties stay alphabetical.
    ranked.sort_by(|a, b| {
        (Reverse(a.count), Reverse(a.failure_count))
            .cmp(&(Reverse(b.count), Reverse(b.failure_count)))
    });
    ranked.truncate(limit);
    ranked
}

#[cfg(test)]
mod tests {
    use super::{normalize_reason, rank_recurring_reasons, MAX_REASON_CHARS};

    #[test]
    fn normalize_reason_lowercases_trims_and_collapses_whitespace() {
        assert_eq!(
            normalize_reason("  Tool   TIMED\tOut ").as_deref(),
            Some("tool timed out")
        );
        assert_eq!(
            normalize_reason("tool timed out").as_deref(),
            Some("tool timed out")
        );
    }

    #[test]
    fn normalize_reason_returns_none_for_blank_or_punctuation_only() {
        for raw in ["", "   ", "\n\t", "...", "!!"] {
            assert_eq!(normalize_reason(raw), None, "expected None for {raw:?}");
        }
    }

    #[test]
    fn normalize_reason_strips_wrapping_quotes_and_trailing_punctuation() {
        assert_eq!(
            normalize_reason("\"Tool timed out.\"").as_deref(),
            Some("tool timed out")
        );
        assert_eq!(
            normalize_reason("'tool timed out!'").as_deref(),
            Some("tool timed out")
        );
        // Unmatched leading quote is prose, not a wrapper: it is preserved.
        assert_eq!(
            normalize_reason("\"tool timed out").as_deref(),
            Some("\"tool timed out")
        );
    }

    #[test]
    fn normalize_reason_truncates_long_input_on_char_boundary() {
        let long: String = "é".repeat(400);
        let out = normalize_reason(&long).expect("400 chars normalise");
        assert_eq!(out.chars().count(), MAX_REASON_CHARS);
    }

    #[test]
    fn rank_recurring_reasons_groups_case_and_whitespace_variants() {
        let ranked = rank_recurring_reasons(
            [
                ("Tool timed out", false),
                ("tool  timed out", false),
                ("TOOL TIMED OUT.", false),
            ],
            1,
            5,
        );
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].reason, "tool timed out");
        assert_eq!(ranked[0].count, 3);
    }

    #[test]
    fn rank_recurring_reasons_counts_failures_separately_from_total() {
        let ranked = rank_recurring_reasons(
            [
                ("tool timed out", true),
                ("tool timed out", false),
                ("tool timed out", false),
                ("tool timed out", true),
            ],
            1,
            5,
        );
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].count, 4);
        assert_eq!(ranked[0].failure_count, 2);
    }

    #[test]
    fn rank_recurring_reasons_applies_min_count_floor() {
        let obs = [
            ("tool timed out", false),
            ("tool timed out", false),
            ("schema drift", false),
        ];

        let at_two = rank_recurring_reasons(obs, 2, 5);
        assert_eq!(at_two.len(), 1);
        assert_eq!(at_two[0].reason, "tool timed out");

        let at_one = rank_recurring_reasons(obs, 1, 5);
        assert_eq!(at_one.len(), 2);

        // min_count = 0 must behave as 1, never as "keep nothing" or a divide.
        let at_zero = rank_recurring_reasons(obs, 0, 5);
        assert_eq!(at_zero, at_one);
    }

    #[test]
    fn rank_recurring_reasons_applies_limit_after_ranking() {
        // Five qualifying reasons with strictly decreasing counts, fed in
        // ascending-count order so a truncate-before-sort bug is visible.
        let mut obs: Vec<(&str, bool)> = Vec::new();
        for (reason, n) in [("aaa", 1), ("bbb", 2), ("ccc", 3), ("ddd", 4), ("eee", 5)] {
            for _ in 0..n {
                obs.push((reason, false));
            }
        }
        let ranked = rank_recurring_reasons(obs, 1, 2);
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].reason, "eee");
        assert_eq!(ranked[0].count, 5);
        assert_eq!(ranked[1].reason, "ddd");
        assert_eq!(ranked[1].count, 4);
    }

    #[test]
    fn rank_recurring_reasons_orders_by_count_then_failures_then_reason() {
        let ranked = rank_recurring_reasons(
            [
                // count 2, 0 failures
                ("zebra stalled", true),
                ("zebra stalled", true),
                // count 2, 2 failures — outranks zebra on failure_count
                ("alpha stalled", false),
                ("alpha stalled", false),
                // count 2, 0 failures — fully tied with zebra, sorts first
                ("mid stalled", true),
                ("mid stalled", true),
            ],
            1,
            10,
        );
        let order: Vec<&str> = ranked.iter().map(|r| r.reason.as_str()).collect();
        assert_eq!(order, vec!["alpha stalled", "mid stalled", "zebra stalled"]);
    }

    #[test]
    fn rank_recurring_reasons_representative_is_most_common_raw_form() {
        let ranked = rank_recurring_reasons(
            [
                ("Tool timed out", false),
                ("Tool timed out", false),
                ("TOOL TIMED OUT", false),
            ],
            1,
            5,
        );
        assert_eq!(ranked[0].representative, "Tool timed out");

        // 1-1 tie resolves to the lexicographically smaller raw form.
        let tied =
            rank_recurring_reasons([("Tool timed out", false), ("TOOL TIMED OUT", false)], 1, 5);
        assert_eq!(tied[0].representative, "TOOL TIMED OUT");
    }

    #[test]
    fn rank_recurring_reasons_share_is_fraction_of_normalized_observations() {
        let ranked = rank_recurring_reasons(
            [
                ("tool timed out", false),
                ("tool timed out", false),
                ("tool timed out", false),
                ("schema drift", false),
                // Unnormalisable: excluded from the denominator entirely.
                ("...", false),
            ],
            1,
            5,
        );
        let top = &ranked[0];
        assert_eq!(top.reason, "tool timed out");
        assert!(
            (top.share - 0.75).abs() < f64::EPSILON,
            "share was {}",
            top.share
        );
    }

    #[test]
    fn rank_recurring_reasons_empty_input_is_empty() {
        let empty: Vec<(&str, bool)> = Vec::new();
        assert!(rank_recurring_reasons(empty, 1, 5).is_empty());
        assert!(
            rank_recurring_reasons([("", false), ("   ", true), ("!!", false)], 1, 5).is_empty()
        );
    }
}
