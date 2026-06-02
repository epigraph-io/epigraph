use epigraph_engine::calibration::{ConformalConfig, ConformalQuantiles};
use epigraph_engine::classifier::{classify_conformal, CdstClassification};

/// Build a config with explicit per-class quantiles for deterministic tests.
fn cfg(sup: f64, con: f64, nei: f64) -> ConformalConfig {
    ConformalConfig {
        alpha: 0.1,
        quantiles: ConformalQuantiles {
            supported: sup,
            contradicted: con,
            not_enough_info: nei,
        },
    }
}

/// A claim with high betp_sup (low score_supported) and tight per-class
/// quantiles must yield the singleton {Supported} — the conformal set must
/// EXCLUDE contradicted and NEI, not return everything.
#[test]
fn high_support_yields_singleton_supported() {
    // betp_sup=0.9 -> score_sup=0.10; betp_unsup=0.05 -> score_con=0.95;
    // theta=0.05 -> score_nei=0.95. Quantiles admit only sup.
    let set = classify_conformal(0.9, 0.05, 0.05, &cfg(0.20, 0.43, 0.12));
    assert_eq!(set, vec![CdstClassification::Supported]);
}

/// A genuinely ambiguous claim (moderate betp on two axes) yields a
/// MULTI-label set, demonstrating the set is genuinely set-valued, not a
/// disguised point classifier.
#[test]
fn ambiguous_claim_yields_multilabel_set() {
    // betp_sup=0.62 -> score_sup=0.38 (<=0.40); betp_unsup=0.60 ->
    // score_con=0.40 (<=0.43); theta=0.90 -> score_nei=0.10 (>... no).
    let set = classify_conformal(0.62, 0.60, 0.10, &cfg(0.40, 0.43, 0.12));
    assert!(set.contains(&CdstClassification::Supported));
    assert!(set.contains(&CdstClassification::Contradicted));
    assert!(!set.contains(&CdstClassification::NotEnoughInfo));
    assert_eq!(set.len(), 2);
}

/// High theta (high ignorance) -> low score_nei -> NEI included; a claim that
/// is informative on neither hypothesis must surface NEI.
#[test]
fn high_ignorance_includes_nei() {
    // theta=0.95 -> score_nei=0.05 <= 0.12. betp_sup=betp_unsup=0.025 ->
    // score_sup=score_con=0.975 -> excluded by 0.20/0.43.
    let set = classify_conformal(0.025, 0.025, 0.95, &cfg(0.20, 0.43, 0.12));
    assert_eq!(set, vec![CdstClassification::NotEnoughInfo]);
}

/// An out-of-distribution claim whose scores all exceed their quantiles
/// yields the EMPTY set — a legitimate abstention signal, not a panic.
#[test]
fn all_scores_above_quantile_yields_empty_set() {
    // Every betp/theta moderate so every score ~0.5 > tight quantiles 0.05.
    let set = classify_conformal(0.5, 0.5, 0.5, &cfg(0.05, 0.05, 0.05));
    assert!(
        set.is_empty(),
        "expected abstention (empty set), got {set:?}"
    );
}

/// The default ConformalConfig (quantiles all 1.0 = include-always) is the
/// safe degenerate behavior when calibration.toml has no [conformal] section:
/// every class is admitted (coverage-1 trivial set). This guards the
/// #[serde(default)] contract.
#[test]
fn default_config_includes_all_classes() {
    let set = classify_conformal(0.9, 0.05, 0.05, &ConformalConfig::default());
    assert_eq!(set.len(), 3, "default quantiles=1.0 must admit every class");
}

/// Boundary: score exactly equal to the quantile is INCLUDED (<= not <).
/// 1 - betp_sup == q.supported must keep Supported in the set.
#[test]
fn score_equal_to_quantile_is_inclusive() {
    // score_sup = 1.0 - 0.7; set q.supported to that SAME expression so both
    // sides are bit-identical and the reflexive `<=` holds. A `0.30` literal
    // would NOT equal 1.0-0.7 in IEEE-754 (1.0-0.7 = 0.30000000000000004) and
    // would spuriously fail this inclusive-boundary test. Crucially, `score <
    // q` would be FALSE here, so this still discriminates `<=` from `<`: a
    // future weakening of the impl to strict `<` re-breaks this test.
    let set = classify_conformal(0.7, 0.05, 0.05, &cfg(1.0 - 0.7, 0.01, 0.01));
    assert!(set.contains(&CdstClassification::Supported));
}
