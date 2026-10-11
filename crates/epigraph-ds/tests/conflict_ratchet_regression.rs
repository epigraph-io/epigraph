//! Regression guard for the open-world **conflict ratchet** in
//! [`combination::combine_multiple`] — diagnosed from backlog item C2
//! ("belief propagation stalled on claim f8cf28d0"), fixed by drain unit U025
//! (backlog 9d4821c1).
//!
//! These tests were first written (commit 8a92402c) as a characterization that
//! pinned the defective behaviour; U025 inverted every assertion. They now pin
//! the FIX: `combine_multiple` folds with Dempster's rule at every step, so it
//! can neither manufacture nor ratchet open-world mass.
//!
//! # The mechanism that used to run (two steps)
//!
//! 1. **Seeding.** `select_combination_rule` routed "high conflict + *closed*
//!    world" (`K >= 0.5`, `open_world_fraction <= 0.03`) to
//!    `CombinationRule::Inagaki`, which redistributed `gamma * K` onto the
//!    focal element `(Omega, true)` — an *open-world* element meaning "the
//!    truth lies outside the frame". So the closed-world arm manufactured the
//!    very open-world mass whose absence selected it.
//!
//! 2. **Ratchet.** Once `open_world_fraction > 0.03`, every subsequent
//!    high-conflict step took the `YagerOpen` arm, i.e. `inagaki_combine(..,
//!    gamma = 1.0)`, which sent *all* conflict to `(Omega, true)`. And
//!    `cdst_intersect((Omega, true), (A, false)) = positive(empty)` for **every**
//!    positive `A` (including Theta), so the accumulated missing mass `mu`
//!    contributed `mu * 1.0` to the next step's conflict `K`, which `gamma =
//!    1.0` then deposited straight back onto `(Omega, true)`. Therefore
//!    `mu_next >= mu`.
//!
//! The consequence was a hard, monotonically shrinking ceiling on belief:
//! `Bel(A) <= 1 - mu`, and supporting evidence could not lift it back.
//!
//! On the canonical `binary_truth` frame `(Omega, true)` asserts the claim is
//! neither TRUE nor FALSE, which is semantically impossible.

use std::collections::{BTreeMap, BTreeSet};

use epigraph_ds::{combination, measures, FocalElement, FrameOfDiscernment, MassFunction};

fn binary_frame() -> FrameOfDiscernment {
    FrameOfDiscernment::new(
        "binary_truth".to_string(),
        vec!["TRUE".to_string(), "FALSE".to_string()],
    )
    .expect("binary frame")
}

/// Simple closed-world BBA: `m({idx}) = s`, `m(Theta) = 1 - s`.
fn leaning(frame: &FrameOfDiscernment, idx: usize, s: f64) -> MassFunction {
    let mut m: BTreeMap<FocalElement, f64> = BTreeMap::new();
    m.insert(FocalElement::positive(BTreeSet::from([idx])), s);
    m.insert(
        FocalElement::positive(BTreeSet::from([0_usize, 1])),
        1.0 - s,
    );
    MassFunction::from_raw(frame.clone(), m)
}

fn bel_true(m: &MassFunction) -> f64 {
    measures::belief(m, &FocalElement::positive(BTreeSet::from([0_usize])))
}

/// Seeding is gone: two closed-world BBAs in the regime that used to select
/// the closed-world Inagaki arm (`K >= 0.5`, `open_world_fraction == 0`) now
/// combine to a closed-world result. Nothing lands on `(Omega, true)`.
#[test]
fn closed_world_high_conflict_combination_stays_closed_world() {
    let frame = binary_frame();
    let pro = leaning(&frame, 0, 0.8);
    let con = leaning(&frame, 1, 0.8);

    assert_eq!(
        pro.open_world_fraction(),
        0.0,
        "input BBAs must be closed-world for this test to mean anything"
    );
    assert_eq!(con.open_world_fraction(), 0.0);

    let k = combination::conflict_coefficient(&pro, &con).expect("same frame");
    assert!(
        k >= 0.5,
        "test needs the old high-conflict branch, got K={k}"
    );
    assert_eq!(
        combination::select_combination_rule(k, 0.0),
        combination::CombinationRule::Inagaki,
        "these inputs are exactly the ones the old selector sent to Inagaki"
    );

    let (combined, reports) = combination::combine_multiple(&[pro, con], 0.9).expect("combine");

    assert_eq!(
        combined.open_world_fraction(),
        0.0,
        "closed-world inputs must combine to a closed-world result (U025)"
    );
    assert_eq!(combined.mass_of_missing(), 0.0);
    assert_eq!(
        reports[0].method_used,
        combination::CombinationMethod::Dempster
    );
    assert!(
        (reports[0].conflict_k - k).abs() < 1e-12,
        "conflict is still reported"
    );
}

/// The ratchet is gone, replayed on the exact BBAs prod holds for claim
/// `f8cf28d0-877c-4678-b47f-5f14c0a0f20a` on the `binary_truth` frame.
///
/// Masses and per-row reliability discounts are the values
/// `epigraph_engine::edge_factor::effective_source_strength` derives from
/// `mass_functions.{evidence_type, locality_tag}` for those rows
/// (`logical` 0.85, `statistical` 0.9, `empirical` 1.0; `locality_tag` is
/// `unknown`, so the locality factor is 1.0).
///
/// Before U025 the per-step missing mass ran
/// `0, 0, 0.2634, 0.5497, 0.6631, 0.7158, 0.7436, 0.7573`. Now it is zero at
/// every step, and the fold still reports the conflict it normalised away.
#[test]
fn missing_mass_is_zero_at_every_step_of_the_fold() {
    let frame = binary_frame();
    let rows = f8cf28d0_binary_bbas(&frame);

    let (combined, reports) = combination::combine_multiple(&rows, 0.9).expect("combine");
    assert_eq!(reports.len(), rows.len() - 1);

    for (i, report) in reports.iter().enumerate() {
        assert_eq!(
            report.mass_on_missing, 0.0,
            "step {i}: {} on (Omega, true) — the ratchet's seeding is back",
            report.mass_on_missing
        );
    }
    assert_eq!(combined.mass_of_missing(), 0.0);

    // The evidence genuinely conflicts (3 TRUE-leaning vs 6 FALSE-leaning rows);
    // that is visible in the aggregate, not hidden in an open-world element.
    let k_total = combination::aggregate_conflict(&reports);
    assert!(
        k_total > 0.5,
        "f8cf28d0's rows conflict heavily; aggregate K={k_total}"
    );
}

/// The stall is gone: supporting evidence moves belief again.
///
/// Three strongly supporting BBAs (`m(TRUE) = 0.8`, undiscounted) are appended
/// to the f8cf28d0 set. Before U025 they moved `Bel(TRUE)` from 0.0174 to
/// 0.0234 and *raised* missing mass (0.757 -> 0.975). Under the Dempster fold
/// they lift `Bel(TRUE)` by more than 0.5 (Python-port estimate 0.0715 ->
/// 0.918), and missing mass stays zero.
#[test]
fn supporting_evidence_lifts_belief_on_the_f8cf28d0_set() {
    let frame = binary_frame();
    let baseline = f8cf28d0_binary_bbas(&frame);

    let (before, _) = combination::combine_multiple(&baseline, 0.9).expect("combine");
    let bel_before = bel_true(&before);

    let mut enriched = baseline;
    for _ in 0..3 {
        enriched.push(leaning(&frame, 0, 0.8));
    }
    let (after, _) = combination::combine_multiple(&enriched, 0.9).expect("combine");
    let bel_after = bel_true(&after);

    // Control: the same three BBAs on their own are near-conclusive.
    let alone: Vec<MassFunction> = (0..3).map(|_| leaning(&frame, 0, 0.8)).collect();
    let (alone_combined, _) = combination::combine_multiple(&alone, 0.9).expect("combine");
    assert!(
        bel_true(&alone_combined) > 0.99,
        "control: the appended evidence really is strongly supporting"
    );

    assert!(
        bel_before < 0.2,
        "the f8cf28d0 set leans FALSE; baseline Bel(TRUE)={bel_before}"
    );
    assert!(
        bel_after > bel_before + 0.5,
        "three strong supports moved Bel(TRUE) only {bel_before} -> {bel_after}; \
         the ratchet's 1 - mu ceiling is back"
    );
    assert_eq!(after.mass_of_missing(), 0.0);
}

/// Open-world semantics under the Dempster fold (the U028-coupled part of
/// U025, operator question Q3).
///
/// Before U025, inputs that reserve `(Omega, true)` mass took the YagerOpen arm
/// at `K >= 0.5` and parked the conflict on `(Omega, true)`. Now reserved
/// missing mass is conflict against every positive element (including Theta)
/// and is normalised away; it survives only as `missing ∩ missing`. Closed-world
/// inputs keep none. The same numbers are re-checked in the `#[ignore]`d
/// `epigraph-engine/tests/perspectival_loader.rs::load_and_validate_open_world`
/// harness, which needs a seeded dev DB; this copy runs in every gate.
#[test]
fn reserved_open_world_mass_survives_only_as_missing_intersect_missing() {
    let frame = FrameOfDiscernment::new("ow_proof", vec!["a".into(), "b".into()]).unwrap();
    let mk = |idx: usize, ow: f64| {
        let mut m = BTreeMap::new();
        m.insert(FocalElement::positive(BTreeSet::from([idx])), 0.80);
        if ow > 0.0 {
            m.insert(FocalElement::missing(&frame), ow);
        }
        m.insert(FocalElement::theta(&frame), 0.20 - ow);
        MassFunction::new(frame.clone(), m).unwrap()
    };

    let (ow_combined, rep_ow) =
        combination::combine_multiple(&[mk(0, 0.08), mk(1, 0.08)], 0.1).unwrap();
    let (cl_combined, rep_cl) =
        combination::combine_multiple(&[mk(0, 0.0), mk(1, 0.0)], 0.1).unwrap();

    assert_eq!(
        rep_ow[0].method_used,
        combination::CombinationMethod::Dempster
    );
    assert_eq!(
        rep_cl[0].method_used,
        combination::CombinationMethod::Dempster
    );

    // K = a∩b 0.64 + missing∩positive 2*(0.08*0.80 + 0.08*0.12) = 0.7872:
    // missing mass against positive evidence counts as conflict.
    assert!(
        (rep_ow[0].conflict_k - 0.7872).abs() < 1e-12,
        "open-world K: {}",
        rep_ow[0].conflict_k
    );
    assert!((rep_cl[0].conflict_k - 0.64).abs() < 1e-12);

    // Only missing ∩ missing (0.08 * 0.08) survives, renormalised by 1 - K.
    let expected = 0.0064 / 0.2128;
    assert!(
        (rep_ow[0].mass_on_missing - expected).abs() < 1e-12,
        "open-world reservation must survive only as missing ∩ missing: {}",
        rep_ow[0].mass_on_missing
    );
    assert!((ow_combined.mass_of_missing() - expected).abs() < 1e-12);
    assert_eq!(rep_cl[0].mass_on_missing, 0.0);
    assert_eq!(cl_combined.mass_of_missing(), 0.0);
}

/// The nine `mass_functions` rows prod holds for claim f8cf28d0 on
/// `binary_truth`, each already Shafer-discounted by its effective reliability.
fn f8cf28d0_binary_bbas(frame: &FrameOfDiscernment) -> Vec<MassFunction> {
    // (raw masses JSON as stored, effective reliability discount)
    const ROWS: &[(&str, f64)] = &[
        (r#"{"0":0.595,"0,1":0.405}"#, 0.85),
        (r#"{"1":0.5599999999999999,"0,1":0.44000000000000006}"#, 0.9),
        (r#"{"1":0.5599999999999999,"0,1":0.44000000000000006}"#, 1.0),
        (r#"{"1":0.5249999999999999,"0,1":0.4750000000000001}"#, 0.9),
        (r#"{"1":0.48999999999999994,"0,1":0.51}"#, 0.9),
        (r#"{"0":0.504,"0,1":0.496}"#, 1.0),
        (r#"{"1":0.616,"0,1":0.384}"#, 1.0),
        (r#"{"0":0.45499999999999996,"0,1":0.545}"#, 0.9),
        (r#"{"1":0.5249999999999999,"0,1":0.4750000000000001}"#, 0.9),
    ];

    ROWS.iter()
        .map(|(json, reliability)| {
            let value: serde_json::Value = serde_json::from_str(json).expect("BBA JSON");
            let mass = MassFunction::from_json_masses(frame.clone(), &value).expect("parse BBA");
            combination::discount(&mass, *reliability).expect("discount")
        })
        .collect()
}
