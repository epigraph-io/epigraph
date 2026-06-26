//! Validates the perspectival-demo seed beliefs against the REAL engine DS math.
//!
//! Reproduces what `belief_query::recompute_framed_belief` does — discount each
//! BBA by its per-perspective alpha, then `combine_multiple`, then
//! `pignistic_probability` — using the actual `epigraph_ds` functions (not the
//! Python reimplementation in the demo's scripts/verify_beliefs.py). Asserts the
//! engine reproduces that script's numbers on the discriminating cases:
//! the K>0 safety-divergence and efficacy-conflict cases, plus a consensus control.
//!
//! Throwaway cross-check harness (not a permanent epigraph test); safe to delete.

use epigraph_ds::{combination, measures, FrameOfDiscernment, MassFunction};
use serde_json::{json, Value};

/// Discount each (masses, alpha) BBA, combine via the engine's adaptive rule,
/// return pignistic BetP for `target`.
fn betp(frame: &FrameOfDiscernment, bbas: &[(Value, f64)], target: usize) -> f64 {
    let discounted: Vec<MassFunction> = bbas
        .iter()
        .map(|(m, a)| {
            let mf = MassFunction::from_json_masses(frame.clone(), m).expect("parse masses");
            combination::discount(&mf, *a).expect("discount")
        })
        .collect();
    let (combined, _reports) = combination::combine_multiple(&discounted, 0.1).expect("combine");
    measures::pignistic_probability(&combined, target)
}

#[test]
fn perspectival_seed_matches_python_model() {
    // Binary frames; index 0 is the target ("positive") hypothesis. theta key = "0,1".
    let eff = FrameOfDiscernment::new(
        "treatment_efficacy",
        vec!["efficacious".into(), "no_effect".into()],
    )
    .unwrap();
    let saf =
        FrameOfDiscernment::new("treatment_safety", vec!["safe".into(), "harmful".into()]).unwrap();

    // --- treatment-c SAFETY {safe(0), harmful(1)} : clinical harmful vs tradition safe (K>0) ---
    let tc_saf = |a_clin: f64, a_trad: f64, a_prac: f64| {
        betp(
            &saf,
            &[
                (json!({"1": 0.70, "0,1": 0.30}), a_clin), // source_clinical: harmful
                (json!({"0": 0.50, "0,1": 0.50}), a_trad), // source_tradition: safe
                (json!({"0": 0.45, "0,1": 0.55}), a_prac), // source_practitioner: safe
            ],
            0,
        )
    };
    let saf_clin = tc_saf(0.95, 0.15, 0.10);
    let saf_trad = tc_saf(0.60, 0.90, 0.85);

    // --- treatment-e EFFICACY {efficacious(0), no_effect(1)} : tradition efficacious vs clinical no_effect (K>0) ---
    let te_eff = |a_trad: f64, a_prac: f64, a_clin: f64| {
        betp(
            &eff,
            &[
                (json!({"0": 0.55, "0,1": 0.45}), a_trad), // source_tradition: efficacious
                (json!({"0": 0.45, "0,1": 0.55}), a_prac), // source_practitioner: efficacious
                (json!({"1": 0.60, "0,1": 0.40}), a_clin), // source_clinical: no_effect
            ],
            0,
        )
    };
    let te_clin = te_eff(0.15, 0.10, 0.95);
    let te_trad = te_eff(0.90, 0.85, 0.60);

    // --- treatment-a EFFICACY (consensus control, K=0), clinical lens ---
    let ta_clin = betp(
        &eff,
        &[
            (json!({"0": 0.75, "0,1": 0.25}), 0.95), // source_clinical
            (json!({"0": 0.55, "0,1": 0.45}), 0.15), // source_tradition
            (json!({"0": 0.40, "0,1": 0.60}), 0.10), // source_practitioner
        ],
        0,
    );

    eprintln!("REAL ENGINE vs Python model (verify_beliefs.py):");
    eprintln!("  treatment-c safety  clinical = {saf_clin:.3}  (python 0.203)");
    eprintln!("  treatment-c safety  tradition = {saf_trad:.3}  (python 0.666)");
    eprintln!("  treatment-e eff     clinical = {te_clin:.3}  (python 0.260)");
    eprintln!("  treatment-e eff     tradition = {te_trad:.3}  (python 0.718)");
    eprintln!("  treatment-a eff     clinical = {ta_clin:.3}  (python 0.873)");

    let approx = |a: f64, b: f64| (a - b).abs() < 0.005;
    assert!(
        approx(saf_clin, 0.203),
        "treatment-c safety clinical = {saf_clin}, expected 0.203"
    );
    assert!(
        approx(saf_trad, 0.666),
        "treatment-c safety tradition = {saf_trad}, expected 0.666"
    );
    assert!(
        approx(te_clin, 0.260),
        "treatment-e eff clinical = {te_clin}, expected 0.260"
    );
    assert!(
        approx(te_trad, 0.718),
        "treatment-e eff tradition = {te_trad}, expected 0.718"
    );
    assert!(
        approx(ta_clin, 0.873),
        "treatment-a eff clinical = {ta_clin}, expected 0.873"
    );
}
