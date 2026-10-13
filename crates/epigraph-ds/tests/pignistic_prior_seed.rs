//! [`MassFunction::from_pignistic_prior`]: the seed BBA `ds_auto` writes from a
//! claim's scalar `truth_value` before its first evidence update (backlog
//! fc55465b, drain unit U026).
//!
//! The seed must not move belief by itself, so its pignistic probability must
//! be exactly the scalar it encodes. Among all binary BBAs with BetP(idx) = t,
//! it must be the LEAST committed (Smets): the maximum ignorance any of them
//! can carry is m(Θ) = 2·min(t, 1-t), since m(idx) + m(Θ)/2 = t and
//! m(other) + m(Θ)/2 = 1-t with both singleton masses non-negative. The
//! simple-support shape m({idx}) = t, which an earlier corpus-migration plan
//! (#472) uses, has BetP (1+t)/2 instead, and is pinned here as NOT what the
//! helper builds.
//!
//! Pure math: production constructor + `measures::pignistic_probability`.

use epigraph_ds::{measures, DsError, FocalElement, FrameOfDiscernment, MassFunction};
use std::collections::BTreeSet;

fn binary() -> FrameOfDiscernment {
    FrameOfDiscernment::new("binary_truth", vec!["TRUE".into(), "FALSE".into()]).unwrap()
}

fn theta_mass(m: &MassFunction) -> f64 {
    m.mass_of(&FocalElement::theta(&binary()))
}

fn singleton(idx: usize) -> FocalElement {
    FocalElement::positive(BTreeSet::from([idx]))
}

const TS: [f64; 8] = [0.0, 0.05, 0.3, 0.49, 0.51, 0.75, 0.85, 1.0];

#[test]
fn betp_of_the_seed_is_exactly_t_for_either_index() {
    for idx in [0_usize, 1] {
        for t in TS {
            let m = MassFunction::from_pignistic_prior(binary(), idx, t)
                .expect("valid input")
                .expect("t != 0.5 seeds something");
            let betp = measures::pignistic_probability(&m, idx);
            assert!(
                (betp - t).abs() < 1e-12,
                "idx {idx}, t {t}: BetP {betp} must equal t"
            );
            let other = measures::pignistic_probability(&m, 1 - idx);
            assert!(
                (other - (1.0 - t)).abs() < 1e-12,
                "idx {idx}, t {t}: BetP(other) {other} must be 1-t"
            );
            let sum: f64 = m.focal_elements().map(|(_, v)| *v).sum();
            assert!((sum - 1.0).abs() < 1e-12, "masses sum to 1, got {sum}");
        }
    }
}

#[test]
fn the_seed_is_the_least_committed_bba_with_that_betp() {
    for t in TS {
        let m = MassFunction::from_pignistic_prior(binary(), 0, t)
            .unwrap()
            .unwrap();
        let max_ignorance = 2.0 * t.min(1.0 - t);
        assert!(
            (theta_mass(&m) - max_ignorance).abs() < 1e-12,
            "t {t}: m(Θ) {} must be the maximum 2·min(t,1-t) = {max_ignorance}",
            theta_mass(&m)
        );
        // Mass sits on at most ONE singleton: the side t leans to.
        let (lean, away) = if t > 0.5 { (0, 1) } else { (1, 0) };
        assert!(
            (m.mass_of(&singleton(lean)) - (2.0 * t - 1.0).abs()).abs() < 1e-12,
            "t {t}: m({{{lean}}}) must be |2t-1|"
        );
        assert_eq!(m.mass_of(&singleton(away)), 0.0, "t {t}: nothing on {away}");
    }
}

#[test]
fn the_seed_is_not_the_simple_support_shape() {
    // m({TRUE}) = t has BetP (1+t)/2: at t = 0.75 that is 0.875, so the first
    // evidence update would RAISE belief by 0.125 with no evidence at all.
    let t = 0.75;
    let simple = MassFunction::simple(binary(), BTreeSet::from([0]), t).unwrap();
    assert!((measures::pignistic_probability(&simple, 0) - 0.875).abs() < 1e-12);
    let seed = MassFunction::from_pignistic_prior(binary(), 0, t)
        .unwrap()
        .unwrap();
    assert!((seed.mass_of(&singleton(0)) - 0.5).abs() < 1e-12);
    assert!((theta_mass(&seed) - 0.5).abs() < 1e-12);
}

#[test]
fn an_indifferent_prior_seeds_nothing() {
    for idx in [0_usize, 1] {
        assert!(
            MassFunction::from_pignistic_prior(binary(), idx, 0.5)
                .unwrap()
                .is_none(),
            "t = 0.5 is the vacuous BBA: there is nothing to store"
        );
    }
}

#[test]
fn invalid_probabilities_are_refused() {
    for t in [f64::NAN, -0.01, 1.01, f64::INFINITY] {
        let err = MassFunction::from_pignistic_prior(binary(), 0, t).unwrap_err();
        assert!(
            matches!(err, DsError::InvalidProbability { .. }),
            "t {t}: expected InvalidProbability, got {err:?}"
        );
    }
}

#[test]
fn only_a_two_hypothesis_frame_is_accepted() {
    let tri = FrameOfDiscernment::new("tri", vec!["a".into(), "b".into(), "c".into()]).unwrap();
    let err = MassFunction::from_pignistic_prior(tri, 0, 0.75).unwrap_err();
    assert!(
        matches!(err, DsError::NotBinaryFrame { n: 3 }),
        "a ternary frame has no single complement singleton; got {err:?}"
    );
    let err = MassFunction::from_pignistic_prior(binary(), 2, 0.75).unwrap_err();
    assert!(
        matches!(err, DsError::ElementOutsideFrame { .. }),
        "index 2 is outside a binary frame; got {err:?}"
    );
}
