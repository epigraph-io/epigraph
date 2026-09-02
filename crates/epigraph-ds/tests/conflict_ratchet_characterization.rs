//! Characterization of the open-world **conflict ratchet** in
//! [`combination::combine_multiple`] — diagnosed from backlog item C2
//! ("belief propagation stalled on claim f8cf28d0").
//!
//! These tests pin CURRENT behaviour, which is believed to be wrong. They exist
//! so that the mechanism is executable and so that any future change to the
//! adaptive combination semantics is a *deliberate* decision rather than an
//! accident: if you change [`combination::select_combination_rule`] or the
//! `inagaki_combine` redistribution target, these tests will fail — read this
//! comment, then update them on purpose.
//!
//! # The mechanism (two steps)
//!
//! 1. **Seeding.** `select_combination_rule` routes "high conflict + *closed*
//!    world" (`K >= 0.5`, `open_world_fraction <= 0.03`) to
//!    `CombinationRule::Inagaki`, which redistributes `gamma * K` onto the
//!    focal element `(Omega, true)` — an *open-world* element meaning "the
//!    truth lies outside the frame". So the closed-world arm manufactures the
//!    very open-world mass whose absence selected it.
//!
//! 2. **Ratchet.** Once `open_world_fraction > 0.03`, every subsequent
//!    high-conflict step takes the `YagerOpen` arm, i.e. `inagaki_combine(..,
//!    gamma = 1.0)`, which sends *all* conflict to `(Omega, true)`. And
//!    `cdst_intersect((Omega, true), (A, false)) = positive(empty)` for **every**
//!    positive `A` (including Theta), so the accumulated missing mass `mu`
//!    contributes `mu * 1.0` to the next step's conflict `K`, which `gamma =
//!    1.0` then deposits straight back onto `(Omega, true)`. Therefore
//!    `mu_next >= mu`, strictly greater whenever the two BBAs disagree at all.
//!
//! The consequence is a hard, monotonically shrinking ceiling on belief:
//! `Bel(A) <= 1 - mu` for every `A`, and `mu` never decreases. Supporting
//! evidence cannot lift it back — the "convergence to a low-belief fixed point"
//! the C2 report hypothesised.
//!
//! On the canonical `binary_truth` frame this is also semantically impossible:
//! `(Omega, true)` asserts the claim is neither TRUE nor FALSE.

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

/// Step 1 of the mechanism: the arm `select_combination_rule` picks *because*
/// the world is closed is the arm that opens it.
///
/// Two closed-world BBAs (`open_world_fraction == 0`) in high conflict select
/// `CombinationRule::Inagaki` — documented as the "closed world" branch — and
/// the combination it performs puts mass on `(Omega, true)`. After one such
/// step the accumulated `open_world_fraction` is over the 0.03 threshold, so
/// the *same* conflict level now selects `YagerOpen` instead. The selector has
/// been flipped, irreversibly, by the closed-world arm's own output.
#[test]
fn closed_world_inagaki_arm_manufactures_open_world_mass() {
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
    assert!(k >= 0.5, "test needs the high-conflict branch, got K={k}");
    assert_eq!(
        combination::select_combination_rule(k, 0.0),
        combination::CombinationRule::Inagaki,
        "closed-world high-conflict inputs must select the closed-world arm"
    );

    let (combined, _) = combination::combine_multiple(&[pro, con], 0.9).expect("combine");

    let owf = combined.open_world_fraction();
    assert!(
        owf > 0.03,
        "closed-world arm produced open_world_fraction={owf}, expected > 0.03 \
         (this is the defect being characterized)"
    );
    assert_eq!(
        combination::select_combination_rule(k, owf),
        combination::CombinationRule::YagerOpen,
        "one closed-world step has flipped the selector to the open-world arm"
    );
}

/// Step 2 of the mechanism, replayed on the exact BBAs prod holds for claim
/// `f8cf28d0-877c-4678-b47f-5f14c0a0f20a` on the `binary_truth` frame.
///
/// Masses and per-row reliability discounts are the values
/// `epigraph_engine::edge_factor::effective_source_strength` derives from
/// `mass_functions.{evidence_type, locality_tag}` for those rows
/// (`logical` 0.85, `statistical` 0.9, `empirical` 1.0; `locality_tag` is
/// `unknown`, so the locality factor is 1.0).
///
/// Asserted: missing mass never decreases across the fold, and nine ordinary
/// evidence rows on a **closed** binary frame end with the overwhelming
/// majority of mass on "the truth is outside {TRUE, FALSE}".
#[test]
fn missing_mass_never_decreases_across_the_fold() {
    let frame = binary_frame();
    let rows = f8cf28d0_binary_bbas(&frame);

    let (combined, reports) = combination::combine_multiple(&rows, 0.9).expect("combine");

    let mut previous = 0.0_f64;
    for (i, report) in reports.iter().enumerate() {
        assert!(
            report.mass_on_missing >= previous - 1e-12,
            "step {i}: missing mass fell from {previous} to {} — the ratchet is \
             gone, which means the combination semantics changed; see the module \
             comment before updating this test",
            report.mass_on_missing
        );
        previous = report.mass_on_missing;
    }

    let mu = combined.mass_of_missing();
    assert!(
        mu > 0.75,
        "nine real evidence rows on the closed binary frame put only {mu} on \
         (Omega, true); expected the ratchet to have driven it above 0.75"
    );
    assert!(
        bel_true(&combined) <= 1.0 - mu,
        "Bel is bounded above by the surviving positive mass"
    );
}

/// The stall itself: once the ratchet has run, supporting evidence cannot move
/// belief, because `Bel <= 1 - mu` and `mu` only grows.
///
/// Three strongly supporting BBAs (`m(TRUE) = 0.8`, undiscounted) are appended
/// to the f8cf28d0 set. In isolation those three combine to `Bel(TRUE) > 0.99`.
/// Appended here they move `Bel(TRUE)` by less than 0.01 — and they *raise*
/// missing mass, tightening the ceiling that is suppressing them.
#[test]
fn supporting_evidence_cannot_lift_belief_after_the_ratchet() {
    let frame = binary_frame();
    let baseline = f8cf28d0_binary_bbas(&frame);

    let (before, _) = combination::combine_multiple(&baseline, 0.9).expect("combine");
    let bel_before = bel_true(&before);
    let mu_before = before.mass_of_missing();

    let mut enriched = baseline;
    for _ in 0..3 {
        enriched.push(leaning(&frame, 0, 0.8));
    }
    let (after, _) = combination::combine_multiple(&enriched, 0.9).expect("combine");
    let bel_after = bel_true(&after);
    let mu_after = after.mass_of_missing();

    // Control: the same three BBAs on their own are near-conclusive.
    let alone: Vec<MassFunction> = (0..3).map(|_| leaning(&frame, 0, 0.8)).collect();
    let (alone_combined, _) = combination::combine_multiple(&alone, 0.9).expect("combine");
    assert!(
        bel_true(&alone_combined) > 0.99,
        "control: the appended evidence really is strongly supporting"
    );

    assert!(
        (bel_after - bel_before).abs() < 0.01,
        "Bel(TRUE) moved from {bel_before} to {bel_after} — more than the \
         stalled behaviour this test pins"
    );
    assert!(
        mu_after > mu_before,
        "supporting evidence should have *raised* missing mass under the \
         ratchet ({mu_before} -> {mu_after})"
    );
    assert!(
        bel_after < 0.05,
        "belief is pinned near zero by the 1 - mu ceiling, got {bel_after}"
    );
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
