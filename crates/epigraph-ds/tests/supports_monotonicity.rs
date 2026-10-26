//! Supports-monotonicity of [`combination::combine_multiple`] (backlog
//! `9d4821c1`, drain unit U025).
//!
//! Property: appending one BBA that supports TRUE (`m({TRUE}) = s`,
//! `m(Theta) = 1 - s`) to ANY pool of BBAs must never lower BetP(TRUE) of the
//! combined result. Under Dempster's rule this is a theorem: the new BBA only
//! adds mass to focal elements containing TRUE, and the normaliser `1 - K`
//! only shrinks the denominator of the surviving TRUE-supporting mass.
//!
//! The adaptive per-step rule selector (`select_combination_rule`) breaks it:
//! `combine_multiple` re-sorts the whole input set and re-picks
//! Dempster / CdstConjunctive / Inagaki for every step, so appending one BBA
//! can re-route *earlier* steps onto a different rule. The only guard against
//! this was a write-time cache clamp in `ds_auto::auto_wire_ds_update`, which
//! every recompute and every framed `get_belief` read bypasses.
//!
//! Pure math: production `combine_multiple` + `measures::pignistic_probability`,
//! no DB, no mocks.

use std::collections::BTreeSet;

use epigraph_ds::{combination, measures, FrameOfDiscernment, MassFunction};

fn binary_frame() -> FrameOfDiscernment {
    FrameOfDiscernment::new(
        "binary_truth".to_string(),
        vec!["TRUE".to_string(), "FALSE".to_string()],
    )
    .expect("binary frame")
}

/// `m({idx}) = s`, `m(Theta) = 1 - s` (closed-world, undiscounted).
fn simple(f: &FrameOfDiscernment, idx: usize, s: f64) -> MassFunction {
    MassFunction::simple(f.clone(), BTreeSet::from([idx]), s).expect("simple BBA")
}

fn betp_true(ms: &[MassFunction]) -> f64 {
    let (c, _) = combination::combine_multiple(ms, 0.9).expect("combine");
    measures::pignistic_probability(&c, 0)
}

/// Counterexample A: on the adaptive selector the prior pool folds via the
/// CdstConjunctive arm (K = 0.48), but after appending a weak TRUE support the
/// canonical re-sort puts the weak support first, the first step becomes
/// Dempster, and the second step crosses K >= 0.5 into Inagaki(gamma = 0.5),
/// which parks conflict on `(Omega, true)` and drags BetP(TRUE) down
/// (port estimate: 0.6923 -> 0.5703).
#[test]
fn appending_a_supporting_bba_never_lowers_betp_counterexample_a() {
    let f = binary_frame();
    let prior = vec![simple(&f, 0, 0.8), simple(&f, 1, 0.6)];
    let mut after = prior.clone();
    after.push(simple(&f, 0, 0.3));

    let before = betp_true(&prior);
    let after_v = betp_true(&after);
    assert!(
        after_v >= before - 1e-9,
        "supporting BBA m(TRUE)=0.3 LOWERED BetP(TRUE): {before} -> {after_v}"
    );
}

/// Counterexample B discriminates the recommended fix (one associative rule
/// per step) from the tempting minimal one (redirect `inagaki_combine`'s
/// conflict share to Theta instead of `(Omega, true)`): it holds on the
/// adaptive selector and under Dempster, but the Theta-redirect variant drops
/// BetP(TRUE) here (port estimate: 0.1977 -> 0.1073).
#[test]
fn appending_a_supporting_bba_never_lowers_betp_counterexample_b() {
    let f = binary_frame();
    let prior = vec![simple(&f, 0, 0.6), simple(&f, 1, 0.8), simple(&f, 1, 0.8)];
    let mut after = prior.clone();
    after.push(simple(&f, 0, 0.3));

    let before = betp_true(&prior);
    let after_v = betp_true(&after);
    assert!(
        after_v >= before - 1e-9,
        "supporting BBA m(TRUE)=0.3 LOWERED BetP(TRUE): {before} -> {after_v}"
    );
}

/// Exhaustive grid: every prior pool of 2..=3 simple BBAs over
/// idx in {TRUE, FALSE} and s in GRID (as a multiset), plus every new
/// TRUE-support s' in GRID. Every violation is collected so a failure shows
/// the size of the defect, not just its first instance.
#[test]
fn appending_a_supporting_bba_never_lowers_betp_exhaustive_grid() {
    const GRID: &[f64] = &[0.3, 0.5, 0.6, 0.7, 0.8, 0.9];
    let f = binary_frame();

    // All (idx, s) atoms; pools are non-decreasing index sequences over them
    // (multisets), since combine_multiple canonically sorts its input.
    let atoms: Vec<(usize, f64)> = [0_usize, 1]
        .iter()
        .flat_map(|&i| GRID.iter().map(move |&s| (i, s)))
        .collect();

    let mut pools: Vec<Vec<(usize, f64)>> = Vec::new();
    for a in 0..atoms.len() {
        for b in a..atoms.len() {
            pools.push(vec![atoms[a], atoms[b]]);
            for c in b..atoms.len() {
                pools.push(vec![atoms[a], atoms[b], atoms[c]]);
            }
        }
    }

    let mut checked = 0_usize;
    let mut violations: Vec<String> = Vec::new();
    for pool in &pools {
        let prior: Vec<MassFunction> = pool.iter().map(|&(i, s)| simple(&f, i, s)).collect();
        let before = betp_true(&prior);
        for &s_new in GRID {
            let mut after = prior.clone();
            after.push(simple(&f, 0, s_new));
            let after_v = betp_true(&after);
            checked += 1;
            if after_v < before - 1e-9 {
                violations.push(format!(
                    "{pool:?} + (0,{s_new}): {before:.4} -> {after_v:.4}"
                ));
            }
        }
    }

    assert!(checked > 1000, "grid too small to mean anything: {checked}");
    assert!(
        violations.is_empty(),
        "{} of {checked} supporting appends LOWERED BetP(TRUE); first 10:\n{}",
        violations.len(),
        violations
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The same property on the BBA SHAPES production stores, not only closed-world
/// simple supports (council finding on U025; the scope's Monte Carlo had this
/// second arm, with 10.6% drops on main):
///
/// - edge-factor BBAs carrying open-world `(Omega, true)` mass
///   (`epistemic_interval::to_mass_function`, here a 0.6/1.0/ow 0.2 interval
///   discounted by 0.9: `{x: 0.54, Theta: 0.28, missing: 0.18}`);
/// - assess BBAs carrying open-world vacuous `(empty, true)` mass at the 0.05
///   default (`bba.rs`);
/// - complement (negative) elements, which push `open_world_fraction` above
///   the old selector's 0.03 YagerOpen threshold;
/// - discounted simple supports.
///
/// Every multiset pool of 1..=3 such atoms, plus a closed-world TRUE support.
#[test]
fn appending_a_supporting_bba_never_lowers_betp_on_open_world_shapes() {
    use epigraph_ds::FocalElement;
    use std::collections::BTreeMap;

    let f = binary_frame();
    let build = |pairs: Vec<(FocalElement, f64)>| -> MassFunction {
        let m: BTreeMap<FocalElement, f64> = pairs.into_iter().collect();
        MassFunction::new(f.clone(), m).expect("valid BBA")
    };
    let pos = |i: usize| FocalElement::positive(BTreeSet::from([i]));

    let mut atoms: Vec<(String, MassFunction)> = Vec::new();
    for idx in [0_usize, 1] {
        for s in [0.3, 0.6, 0.9] {
            atoms.push((format!("simple({idx},{s})"), simple(&f, idx, s)));
            let d = combination::discount(&simple(&f, idx, s), 0.7).expect("discount");
            atoms.push((format!("simple({idx},{s})@0.7"), d));
        }
        atoms.push((
            format!("edge({idx})"),
            build(vec![
                (pos(idx), 0.54),
                (FocalElement::theta(&f), 0.28),
                (FocalElement::missing(&f), 0.18),
            ]),
        ));
        atoms.push((
            format!("assess({idx})"),
            build(vec![
                (pos(idx), 0.6),
                (FocalElement::theta(&f), 0.35),
                (FocalElement::vacuous(), 0.05),
            ]),
        ));
        atoms.push((
            format!("not({idx})"),
            build(vec![
                (FocalElement::negative(BTreeSet::from([idx])), 0.3),
                (FocalElement::theta(&f), 0.7),
            ]),
        ));
    }
    assert!(
        atoms.iter().any(|(_, m)| m.open_world_fraction() > 0.03),
        "the arm must include inputs the old selector treated as open-world"
    );

    let mut pools: Vec<Vec<usize>> = Vec::new();
    for a in 0..atoms.len() {
        pools.push(vec![a]);
        for b in a..atoms.len() {
            pools.push(vec![a, b]);
            for c in b..atoms.len() {
                pools.push(vec![a, b, c]);
            }
        }
    }

    let mut checked = 0_usize;
    let mut violations: Vec<String> = Vec::new();
    for pool in &pools {
        let prior: Vec<MassFunction> = pool.iter().map(|&i| atoms[i].1.clone()).collect();
        let before = betp_true(&prior);
        for s_new in [0.3, 0.6, 0.9] {
            let mut after = prior.clone();
            after.push(simple(&f, 0, s_new));
            let after_v = betp_true(&after);
            checked += 1;
            if after_v < before - 1e-9 {
                let names: Vec<&str> = pool.iter().map(|&i| atoms[i].0.as_str()).collect();
                violations.push(format!(
                    "{names:?} + simple(0,{s_new}): {before:.4} -> {after_v:.4}"
                ));
            }
        }
    }

    assert!(checked > 3000, "grid too small to mean anything: {checked}");
    assert!(
        violations.is_empty(),
        "{} of {checked} supporting appends LOWERED BetP(TRUE); first 10:\n{}",
        violations.len(),
        violations
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
