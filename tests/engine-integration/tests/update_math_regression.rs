//! Regression tests for C1-C4 CDST convergence bugs
//!
//! These tests exercise the discount → combine → pignistic path at the DS
//! library level. No database required — pure math validation.
//!
//! Bug descriptions:
//! - C1: evidence_type weight must produce different BBA masses
//! - C2: 8 weak discounted BBAs must NOT reach "verified" (BetP < 0.7)
//! - C3: 5 weak contradictions must NOT overwhelm 1 strong support
//! - C4: Dempster combination is commutative (order-independent)

use epigraph_ds::{
    combination::{combine_multiple, discount},
    measures, FrameOfDiscernment, MassFunction,
};
use std::collections::BTreeSet;

/// Build the standard binary truth frame used in all tests.
fn binary_frame() -> FrameOfDiscernment {
    FrameOfDiscernment::new(
        "binary_truth",
        vec!["TRUE".to_string(), "FALSE".to_string()],
    )
    .unwrap()
}

/// Build a BBA with mass on {TRUE} (hypothesis index 0).
///
/// `mass` = confidence * type_weight (pre-multiplied by caller to simulate bba.rs behaviour)
fn support_bba(frame: FrameOfDiscernment, mass: f64) -> MassFunction {
    MassFunction::simple(frame, BTreeSet::from([0usize]), mass).unwrap()
}

/// Build a BBA with mass on {FALSE} (hypothesis index 1).
fn contradiction_bba(frame: FrameOfDiscernment, mass: f64) -> MassFunction {
    MassFunction::simple(frame, BTreeSet::from([1usize]), mass).unwrap()
}

// ---------------------------------------------------------------------------
// C1: evidence_type weighting
// ---------------------------------------------------------------------------

/// C1 regression: evidence_type must produce different BBA masses.
///
/// Empirical evidence (type_weight = 1.0) should produce a more informative
/// BBA than circumstantial evidence (type_weight = 0.4) at the same raw
/// confidence level.
///
/// This test validates that the mass computation `confidence * type_weight`
/// in bba.rs produces meaningfully different BBAs and that the difference
/// propagates through to pignistic probability.
#[tokio::test]
async fn test_c1_evidence_type_produces_different_weights() {
    let frame = binary_frame();
    let confidence = 0.7_f64;

    // Empirical: type_weight = 1.0
    let empirical_mass = confidence * 1.0;
    let empirical_bba = support_bba(frame.clone(), empirical_mass);

    // Circumstantial: type_weight = 0.4
    let circumstantial_mass = confidence * 0.4;
    let circumstantial_bba = support_bba(frame.clone(), circumstantial_mass);

    // Both discounted by same reliability (source is equally reliable)
    let reliability = 0.8_f64;
    let empirical_disc = discount(&empirical_bba, reliability).unwrap();
    let circumstantial_disc = discount(&circumstantial_bba, reliability).unwrap();

    let betp_empirical = measures::pignistic_probability(&empirical_disc, 0);
    let betp_circumstantial = measures::pignistic_probability(&circumstantial_disc, 0);

    println!(
        "C1: BetP(TRUE) empirical={betp_empirical:.4}, circumstantial={betp_circumstantial:.4}"
    );

    // Empirical evidence should produce higher BetP(TRUE)
    assert!(
        betp_empirical > betp_circumstantial,
        "C1 FAILED: empirical BBA ({betp_empirical:.4}) should dominate circumstantial ({betp_circumstantial:.4})"
    );

    // The gap should be substantial — empirical is 2.5× more informative
    let gap = betp_empirical - betp_circumstantial;
    assert!(
        gap > 0.05,
        "C1 FAILED: gap between empirical and circumstantial too small ({gap:.4}), expected > 0.05"
    );

    // Empirical BBA should push BetP well above 0.5
    assert!(
        betp_empirical > 0.55,
        "C1 FAILED: empirical BBA should push BetP(TRUE) > 0.55, got {betp_empirical:.4}"
    );
}

// ---------------------------------------------------------------------------
// C2: runaway confirmation resistance
// ---------------------------------------------------------------------------

/// C2 regression: 8 weak updates must NOT reach "verified" status.
///
/// Scenario: 8 weak pieces of circumstantial evidence (strength=0.3,
/// type_weight=0.4), each discounted by low source reliability (r=0.3).
///
/// Expected: pignistic BetP(TRUE) < 0.7 even after combining all 8.
/// Also validates that 1 strong empirical source beats 8 weak ones.
#[tokio::test]
async fn test_c2_runaway_confirmation_resistance() {
    let frame = binary_frame();

    // 8 weak BBAs: circumstantial evidence, low reliability source
    let strength = 0.3_f64;
    let type_weight = 0.4_f64; // circumstantial
    let reliability = 0.3_f64;
    let weak_mass = strength * type_weight; // = 0.12

    let weak_discounted: Vec<MassFunction> = (0..8)
        .map(|_| {
            let bba = support_bba(frame.clone(), weak_mass);
            discount(&bba, reliability).unwrap()
        })
        .collect();

    let (combined_weak, _reports) = combine_multiple(&weak_discounted, 0.5).unwrap();
    let betp_weak = measures::pignistic_probability(&combined_weak, 0);

    println!("C2: BetP(TRUE) for 8 weak combined = {betp_weak:.4}");

    // The 8 weak sources must NOT push past the "verified" threshold
    assert!(
        betp_weak < 0.65,
        "C2 FAILED: 8 weak discounted BBAs reached {betp_weak:.4}, must be < 0.65"
    );

    // Single strong BBA: empirical, high confidence, high reliability
    let strong_mass = 0.9_f64 * 1.0_f64; // empirical: type_weight = 1.0
    let strong_reliability = 0.9_f64;
    let strong_bba = support_bba(frame.clone(), strong_mass);
    let strong_disc = discount(&strong_bba, strong_reliability).unwrap();
    let betp_strong = measures::pignistic_probability(&strong_disc, 0);

    println!("C2: BetP(TRUE) for 1 strong = {betp_strong:.4}");

    // One strong source should dominate 8 weak
    assert!(
        betp_strong > betp_weak,
        "C2 FAILED: 1 strong ({betp_strong:.4}) should exceed 8 weak combined ({betp_weak:.4})"
    );
}

// ---------------------------------------------------------------------------
// C3: dilution resistance
// ---------------------------------------------------------------------------

/// C3 regression: 5 weak contradictions must NOT overwhelm 1 strong support.
///
/// Scenario:
/// - 1 support BBA: mass on TRUE = 0.9 * 1.0 = 0.9, discounted by r=0.9
/// - 5 contradiction BBAs: mass on FALSE = 0.2 * 0.4 = 0.08, each r=0.2
///
/// The strong support should still dominate after combining all 6 BBAs.
#[tokio::test]
async fn test_c3_dilution_resistance() {
    let frame = binary_frame();

    // 1 strong support BBA
    let support_mass = 0.9_f64 * 1.0_f64; // empirical type_weight=1.0
    let support_reliability = 0.9_f64;
    let support = support_bba(frame.clone(), support_mass);
    let support_disc = discount(&support, support_reliability).unwrap();

    // 5 weak contradiction BBAs
    let contra_mass = 0.2_f64 * 0.4_f64; // circumstantial type_weight=0.4
    let contra_reliability = 0.2_f64;
    let contradictions: Vec<MassFunction> = (0..5)
        .map(|_| {
            let bba = contradiction_bba(frame.clone(), contra_mass);
            discount(&bba, contra_reliability).unwrap()
        })
        .collect();

    // Combine all 6: [support_disc] + [5 × contra_disc]
    let mut all_bbas = vec![support_disc];
    all_bbas.extend(contradictions);

    let (combined, _reports) = combine_multiple(&all_bbas, 0.5).unwrap();
    let betp_true = measures::pignistic_probability(&combined, 0);
    let betp_false = measures::pignistic_probability(&combined, 1);

    println!("C3: BetP(TRUE)={betp_true:.4}, BetP(FALSE)={betp_false:.4}");

    // Strong support should still dominate — BetP(TRUE) > 0.5
    assert!(
        betp_true > 0.5,
        "C3 FAILED: 5 weak contradictions overwhelmed 1 strong support; BetP(TRUE)={betp_true:.4}, must be > 0.50"
    );

    // The support's advantage should be clear, not marginal
    assert!(
        betp_true > betp_false,
        "C3 FAILED: BetP(TRUE)={betp_true:.4} should exceed BetP(FALSE)={betp_false:.4}"
    );
}

// ---------------------------------------------------------------------------
// C4: commutativity
// ---------------------------------------------------------------------------

/// C4 regression: evidence applied in different orders must produce identical results.
///
/// Dempster's rule satisfies commutativity (m1 ⊕ m2 = m2 ⊕ m1).
/// This test verifies the property holds through the discount → combine pipeline.
#[tokio::test]
async fn test_c4_commutativity() {
    let frame = binary_frame();

    // BBA A: empirical, high mass on TRUE
    let mass_a = 0.8_f64 * 1.0_f64; // empirical
    let reliability_a = 0.85_f64;
    let bba_a = support_bba(frame.clone(), mass_a);
    let disc_a = discount(&bba_a, reliability_a).unwrap();

    // BBA B: testimonial, lower mass on TRUE
    let mass_b = 0.6_f64 * 0.7_f64; // testimonial type_weight ≈ 0.7
    let reliability_b = 0.65_f64;
    let bba_b = support_bba(frame.clone(), mass_b);
    let disc_b = discount(&bba_b, reliability_b).unwrap();

    // Order 1: A then B
    let (combined_ab, _) = combine_multiple(&[disc_a.clone(), disc_b.clone()], 0.5).unwrap();
    let betp_ab = measures::pignistic_probability(&combined_ab, 0);

    // Order 2: B then A
    let (combined_ba, _) = combine_multiple(&[disc_b.clone(), disc_a.clone()], 0.5).unwrap();
    let betp_ba = measures::pignistic_probability(&combined_ba, 0);

    println!("C4: BetP(TRUE) A⊕B={betp_ab:.6}, B⊕A={betp_ba:.6}");

    let epsilon = 1e-9_f64;
    assert!(
        (betp_ab - betp_ba).abs() < epsilon,
        "C4 FAILED: combination is not commutative; A⊕B={betp_ab:.10}, B⊕A={betp_ba:.10}, diff={:.2e}",
        (betp_ab - betp_ba).abs()
    );
}
