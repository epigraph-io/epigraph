//! The bypass ratchet (plan §4.13).
//!
//! `SystemReason` is the closed set of legitimate reasons to hold an
//! unrestricted `Viewer`. Every variant is one code path that reads the corpus
//! with no visibility predicate at all, so the count is the honest measure of
//! how much of the system is exempt from tenancy.
//!
//! **This file is the canonical count.** `no_anonymous_viewer.rs` keeps the
//! compile-time exhaustive `match` (adding a variant without handling it there
//! fails to *build*, which is a stronger check than any assertion) and the
//! source lint on `visibility.rs`. What used to live there as
//! `assert_eq!(SystemReason::ALL.len(), 10)` lives here instead, as a
//! **monotone-decreasing** bound — an equality assertion and a ratchet cannot
//! both survive the first removal of a bypass reason, and one of them would then
//! have to be edited to keep the other green.

use epigraph_db::SystemReason;

/// The count at PR-04, when this ratchet was created.
///
/// PR-04 (`feat(db): add tenancy columns, the world and seed groups, the
/// ScopedPool, and the resolvable Viewer`) is the baseline. The number is
/// expected to go **down** as PR-06 through PR-22 replace bypasses with scoped
/// reads. It is not expected to go up, ever.
const PR04_BASELINE: usize = 10;

#[test]
fn bypass_count_is_monotone_decreasing_from_the_pr04_baseline() {
    let n = SystemReason::ALL.len();
    assert!(
        n <= PR04_BASELINE,
        "SystemReason::ALL has grown to {n}, above the PR-04 baseline of {PR04_BASELINE}.\n\
         \n\
         This is the bypass ratchet. Each variant is a code path that reads the \
         corpus with NO visibility predicate. The fix is to DELETE a bypass, not \
         to raise this number. If a new job genuinely cannot be scoped, say in \
         the commit body which job it is, on which pool it runs, and why the \
         scoped form is wrong — and expect that to be the subject of the review, \
         not a footnote in it.\n\
         \n\
         When a bypass is legitimately REMOVED, lower PR04_BASELINE to match, so \
         the ratchet keeps its teeth."
    );
}

/// The exhaustive match, repeated here so this file fails to COMPILE (not merely
/// to assert) when a variant is added.
///
/// `SystemReason` is `#[non_exhaustive]`, so an out-of-crate match needs a
/// wildcard arm; the wildcard panics rather than returning a placeholder, which
/// is what turns a compile-time convenience back into a ratchet.
#[test]
fn every_reason_is_accounted_for_by_name() {
    for reason in SystemReason::ALL {
        let expected: &'static str = match reason {
            SystemReason::EmbeddingBackfill => "embedding_backfill",
            SystemReason::BeliefRecomputation => "belief_recomputation",
            SystemReason::DedupSweep => "dedup_sweep",
            SystemReason::ThemeClustering => "theme_clustering",
            SystemReason::TenancyBackfill => "tenancy_backfill",
            SystemReason::PrivatizationSelection => "privatization_selection",
            SystemReason::PrivatizationApply => "privatization_apply",
            SystemReason::PrivatizationReseal => "privatization_reseal",
            SystemReason::SchemaContractTest => "schema_contract_test",
            SystemReason::RlsCanaryProbe => "rls_canary_probe",
            other => panic!(
                "SystemReason::{other:?} is not accounted for in viewer_ratchet.rs. \
                 Adding a bypass reason is a security-relevant change: extend this \
                 match, extend SystemReason::ALL, extend the twin match in \
                 no_anonymous_viewer.rs, and say in the commit body which job needs \
                 it and on which pool it runs."
            ),
        };
        assert_eq!(
            reason.as_str(),
            expected,
            "the label for {reason:?} changed. Labels are the metric dimension for \
             `visibility.bypass{{reason}}`; renaming one silently splits a series."
        );
    }
}

/// The labels are the dimension values of the bypass metric, so they must be
/// unique — two reasons sharing a label would merge two independent series into
/// one and make the ratchet unobservable in production.
#[test]
fn bypass_count_by_reason_is_documented() {
    let mut seen = std::collections::HashSet::new();
    for reason in SystemReason::ALL {
        assert!(
            seen.insert(reason.as_str()),
            "duplicate metric label {:?} on {reason:?}",
            reason.as_str()
        );
    }
    assert_eq!(
        seen.len(),
        SystemReason::ALL.len(),
        "every reason must carry its own label"
    );

    // Labels are lowercase snake_case: they are emitted verbatim as a Prometheus
    // label value and read back in dashboards.
    for reason in SystemReason::ALL {
        let l = reason.as_str();
        assert!(
            !l.is_empty()
                && l.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "metric label {l:?} for {reason:?} is not lowercase snake_case"
        );
    }
}

/// `ALL` must actually be all of them, with no duplicates. The `match` above
/// proves every *listed* reason is known; this proves the list itself is not
/// padded.
#[test]
fn all_has_no_duplicates() {
    let mut seen = std::collections::HashSet::new();
    for reason in SystemReason::ALL {
        assert!(seen.insert(*reason), "duplicate entry in ALL: {reason:?}");
    }
}
