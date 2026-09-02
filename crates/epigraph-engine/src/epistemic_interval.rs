//! EpistemicInterval: belief interval with decomposed open-world ignorance.
//!
//! Extends the [Bel, Pl] interval with an explicit open_world mass component
//! representing frame incompleteness (CDST complement focal elements).

use epigraph_ds::errors::DsError;
use epigraph_ds::frame::FrameOfDiscernment;
use epigraph_ds::mass::{FocalElement, MassFunction};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Belief interval with decomposed ignorance source.
///
/// `open_world` is the sum of masses on focal elements where
/// `FocalElement.complement == true` in the CDST mass function.
/// It represents "the frame may be incomplete" — distinct from
/// closed-world ignorance ("I don't know which hypothesis").
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EpistemicInterval {
    pub bel: f64,
    pub pl: f64,
    pub open_world: f64,
}

impl EpistemicInterval {
    /// Full ignorance: no evidence, frame status unknown.
    pub const VACUOUS: Self = Self {
        bel: 0.0,
        pl: 1.0,
        open_world: 0.5, // honest default: half of width attributed to OW
    };

    pub fn new(bel: f64, pl: f64, open_world: f64) -> Self {
        debug_assert!(bel <= pl + 1e-9, "bel ({bel}) > pl ({pl})");
        Self {
            bel: bel.clamp(0.0, 1.0),
            pl: pl.clamp(0.0, 1.0),
            open_world: open_world.clamp(0.0, (pl - bel).max(0.0)),
        }
    }

    /// Certain: bel == pl, zero ignorance, zero open-world.
    pub fn certain(p: f64) -> Self {
        let p = p.clamp(0.0, 1.0);
        Self {
            bel: p,
            pl: p,
            open_world: 0.0,
        }
    }

    /// From scalar BetP only (no mass function data).
    /// Conservatively attributes half of ignorance to open-world.
    pub fn from_scalar(_betp: f64, belief: f64, plausibility: f64) -> Self {
        let width = (plausibility - belief).max(0.0);
        Self::new(belief, plausibility, width * 0.5)
    }

    /// Extract from a CDST mass function.
    /// `open_world` = sum of masses on complement focal elements.
    /// Requires access to the mass function's focal elements.
    pub fn from_mass_components(bel: f64, pl: f64, complement_mass_sum: f64) -> Self {
        Self::new(bel, pl, complement_mass_sum)
    }

    /// Total ignorance width.
    pub fn width(&self) -> f64 {
        (self.pl - self.bel).max(0.0)
    }

    /// Closed-world ignorance: ignorance within the frame.
    pub fn closed_world(&self) -> f64 {
        (self.width() - self.open_world).max(0.0)
    }

    /// Pignistic midpoint.
    pub fn betp(&self) -> f64 {
        ((self.bel + self.pl) / 2.0).clamp(0.0, 1.0)
    }

    /// Hausdorff distance between two intervals.
    pub fn hausdorff_distance(&self, other: &Self) -> f64 {
        (self.bel - other.bel).abs().max((self.pl - other.pl).abs())
    }

    /// Is this interval narrow enough to be considered "certain"?
    pub fn is_narrow(&self, threshold: f64) -> bool {
        self.width() < threshold
    }

    /// Materialize this interval as a CDST `MassFunction` on a binary frame.
    ///
    /// For frame `{0, 1}`:
    /// - `m({0}) = bel` — support for hypothesis 0
    /// - `m({1}) = 1 − pl` — support for hypothesis 1
    /// - `m({0,1}, positive) = (pl − bel) − open_world` — closed-world ignorance
    /// - `m(Ω, complement) = open_world` — frame may be incomplete
    ///
    /// Round-trip identity holds for inputs constructed via
    /// `EpistemicInterval::new` (which clamps `open_world ≤ pl − bel`).
    pub fn to_mass_function(&self, frame: &FrameOfDiscernment) -> Result<MassFunction, DsError> {
        debug_assert_eq!(
            frame.hypothesis_count(),
            2,
            "to_mass_function expects a binary frame"
        );

        let bel = self.bel.clamp(0.0, 1.0);
        let pl = self.pl.clamp(0.0, 1.0);
        let width = (pl - bel).max(0.0);
        let ow = self.open_world.clamp(0.0, width);
        let closed = (width - ow).max(0.0);
        let m_false = (1.0 - pl).max(0.0);

        let mut masses: BTreeMap<FocalElement, f64> = BTreeMap::new();
        if bel > 0.0 {
            masses.insert(FocalElement::positive(BTreeSet::from([0_usize])), bel);
        }
        if m_false > 0.0 {
            masses.insert(FocalElement::positive(BTreeSet::from([1_usize])), m_false);
        }
        if closed > 0.0 {
            masses.insert(FocalElement::theta(frame), closed);
        }
        if ow > 0.0 {
            masses.insert(FocalElement::missing(frame), ow);
        }

        if masses.is_empty() {
            return Ok(MassFunction::vacuous(frame.clone()));
        }
        MassFunction::new(frame.clone(), masses)
    }
}

impl std::fmt::Display for EpistemicInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:.4}, {:.4}] ow={:.4}",
            self.bel, self.pl, self.open_world
        )
    }
}

// ── Restriction Maps ──

/// Positive restriction (supports/corroborates): the source's opinion about
/// the target, Shafer-discounted by the edge's transmission `factor`.
///
/// Every mass component — including the CDST `missing` (complement) focal that
/// carries `open_world` — is attenuated by `factor`, with the freed mass
/// `1 − factor` going to closed-world ignorance `m(Θ)`. That is exactly
/// [`epigraph_ds::combination::discount`] applied to
/// [`EpistemicInterval::to_mass_function`], so the two agree focal-for-focal:
///
/// ```text
/// restrict_epistemic_positive(iv, f).to_mass_function(frame)
///     == discount(iv.to_mass_function(frame), f)
/// ```
///
/// Consequences of discounting `open_world` along with the rest: the map
/// converges to the combination-neutral BBA `m(Θ) = 1` as `factor → 0` (a
/// zero-strength edge cannot move the target), and a frame-incomplete source
/// no longer transplants its *full* frame doubt onto the target through a
/// belief-strengthening edge.
pub fn restrict_epistemic_positive(source: &EpistemicInterval, factor: f64) -> EpistemicInterval {
    EpistemicInterval {
        bel: source.bel * factor,
        pl: (1.0 - source.pl).mul_add(-factor, 1.0),
        open_world: source.open_world * factor,
    }
}

/// Negative restriction (contradicts/refutes): the polarity-flipped source
/// opinion, Shafer-discounted by the edge's transmission `factor`.
///
/// Same discount law as [`restrict_epistemic_positive`] (see its doc comment):
/// `open_world` is attenuated by `factor` so the map is `discount` composed
/// with the `TRUE`/`FALSE` swap, and reduces to the neutral BBA at `factor = 0`.
pub fn restrict_epistemic_negative(source: &EpistemicInterval, factor: f64) -> EpistemicInterval {
    EpistemicInterval {
        bel: (1.0 - source.pl) * factor,
        pl: source.bel.mul_add(-factor, 1.0),
        open_world: source.open_world * factor,
    }
}

/// Frame evidence restriction: Bel/Pl pass through unchanged.
/// Open-world mass reduced proportional to neighbor's truth × factor.
pub fn restrict_epistemic_frame_evidence(
    source: &EpistemicInterval,
    neighbor_betp: f64,
    factor: f64,
) -> EpistemicInterval {
    let reduction = neighbor_betp * factor;
    EpistemicInterval {
        bel: source.bel,
        pl: source.pl,
        open_world: (source.open_world * (1.0 - reduction).max(0.0)).max(0.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vacuous_interval() {
        let v = EpistemicInterval::VACUOUS;
        assert!((v.bel - 0.0).abs() < 1e-10);
        assert!((v.pl - 1.0).abs() < 1e-10);
        assert!((v.width() - 1.0).abs() < 1e-10);
        assert!((v.open_world - 0.5).abs() < 1e-10);
        assert!((v.closed_world() - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_certain_interval() {
        let c = EpistemicInterval::certain(0.8);
        assert!((c.width() - 0.0).abs() < 1e-10);
        assert!((c.open_world - 0.0).abs() < 1e-10);
        assert!((c.betp() - 0.8).abs() < 1e-10);
    }

    #[test]
    fn test_from_scalar_conservative_default() {
        let ei = EpistemicInterval::from_scalar(0.5, 0.3, 0.7);
        assert!((ei.bel - 0.3).abs() < 1e-10);
        assert!((ei.pl - 0.7).abs() < 1e-10);
        // Half of width=0.4 → open_world=0.2
        assert!((ei.open_world - 0.2).abs() < 1e-10);
        assert!((ei.closed_world() - 0.2).abs() < 1e-10);
    }

    #[test]
    fn test_open_world_clamped_to_width() {
        // open_world can't exceed width
        let ei = EpistemicInterval::new(0.4, 0.6, 0.9);
        assert!(ei.open_world <= ei.width() + 1e-10);
    }

    #[test]
    fn test_hausdorff_distance() {
        let a = EpistemicInterval::new(0.3, 0.8, 0.1);
        let b = EpistemicInterval::new(0.5, 0.9, 0.1);
        // max(|0.3-0.5|, |0.8-0.9|) = max(0.2, 0.1) = 0.2
        assert!((a.hausdorff_distance(&b) - 0.2).abs() < 1e-10);
    }

    #[test]
    fn test_restrict_positive_attenuates_open_world() {
        let src = EpistemicInterval::new(0.6, 0.9, 0.15);
        let restricted = restrict_epistemic_positive(&src, 0.8);
        // bel = 0.6 * 0.8 = 0.48
        assert!((restricted.bel - 0.48).abs() < 1e-10);
        // pl = 1 - (1-0.9)*0.8 = 1 - 0.08 = 0.92
        assert!((restricted.pl - 0.92).abs() < 1e-10);
        // open_world is discounted by the transmission factor too: 0.15 * 0.8
        assert!((restricted.open_world - 0.12).abs() < 1e-10);
    }

    #[test]
    fn test_restrict_negative_flips_and_attenuates_ow() {
        let src = EpistemicInterval::new(0.7, 0.9, 0.1);
        let restricted = restrict_epistemic_negative(&src, 0.8);
        // bel = (1-0.9)*0.8 = 0.08
        assert!((restricted.bel - 0.08).abs() < 1e-10);
        // pl = 1 - 0.7*0.8 = 0.44
        assert!((restricted.pl - 0.44).abs() < 1e-10);
        // open_world discounted: 0.1 * 0.8
        assert!((restricted.open_world - 0.08).abs() < 1e-10);
    }

    /// The load-bearing invariant behind discounting `open_world`:
    /// `restrict_epistemic_positive` must BE the Shafer reliability discount.
    ///
    /// `bel' = bel·f` and `pl' = 1 − (1−pl)·f` were already derived from
    /// `combination::discount`; leaving `open_world` undiscounted made the
    /// map disagree with `discount` on exactly the `Θ` / `missing` split.
    /// Comparing focal-for-focal against the independent `epigraph-ds`
    /// implementation is what pins that down.
    #[test]
    fn restrict_positive_equals_shafer_discount_focal_for_focal() {
        let frame = binary_frame();
        for &(bel, pl, ow) in &[
            (0.20, 0.95, 0.60),
            (0.60, 0.90, 0.30),
            (0.10, 0.40, 0.20),
            (0.00, 1.00, 0.50),
            (0.85, 0.85, 0.00),
        ] {
            for &f in &[0.0, 0.1, 0.5, 0.8, 0.95, 1.0] {
                let iv = EpistemicInterval::new(bel, pl, ow);
                let via_restrict = restrict_epistemic_positive(&iv, f)
                    .to_mass_function(&frame)
                    .expect("restricted mass");
                let via_discount = epigraph_ds::combination::discount(
                    &iv.to_mass_function(&frame).expect("source mass"),
                    f,
                )
                .expect("discount");

                for focal in [
                    FocalElement::positive(BTreeSet::from([0_usize])),
                    FocalElement::positive(BTreeSet::from([1_usize])),
                    FocalElement::theta(&frame),
                    FocalElement::missing(&frame),
                ] {
                    let a = via_restrict.mass_of(&focal);
                    let b = via_discount.mass_of(&focal);
                    assert!(
                        (a - b).abs() < 1e-9,
                        "iv={iv} f={f} focal={focal:?}: restrict={a} discount={b}"
                    );
                }
            }
        }
    }

    /// A zero-strength edge must be a no-op: the restricted BBA has to be the
    /// neutral element of conjunctive combination, `m(Θ) = 1`.
    ///
    /// Before the discount fix this produced `m(Θ) = 1 − ow`, `m(~Ω) = ow`,
    /// and `missing` conflicts with every positive focal under
    /// `cdst_intersect`, so an `f = 0` edge still contracted the target's Bel.
    #[test]
    fn restrict_at_zero_factor_is_the_combination_neutral() {
        let frame = binary_frame();
        let src = EpistemicInterval::new(0.20, 0.95, 0.60);
        for restricted in [
            restrict_epistemic_positive(&src, 0.0),
            restrict_epistemic_negative(&src, 0.0),
        ] {
            assert!((restricted.open_world - 0.0).abs() < 1e-12);
            let mf = restricted.to_mass_function(&frame).expect("mass");
            assert!(
                (mf.mass_of(&FocalElement::theta(&frame)) - 1.0).abs() < 1e-12,
                "f=0 must give m(Theta)=1, got {:?}",
                mf.masses()
            );
            assert!((mf.mass_of(&FocalElement::missing(&frame)) - 0.0).abs() < 1e-12);
        }
    }

    #[test]
    fn test_frame_evidence_restriction_reduces_ow() {
        let src = EpistemicInterval::new(0.3, 0.8, 0.3);
        // neighbor_betp=0.9, factor=0.8 → reduction = 0.72
        let restricted = restrict_epistemic_frame_evidence(&src, 0.9, 0.8);
        // bel, pl unchanged
        assert!((restricted.bel - 0.3).abs() < 1e-10);
        assert!((restricted.pl - 0.8).abs() < 1e-10);
        // open_world = 0.3 * (1 - 0.72) = 0.3 * 0.28 = 0.084
        assert!((restricted.open_world - 0.084).abs() < 1e-10);
    }

    #[test]
    fn test_frame_evidence_does_not_go_negative() {
        let src = EpistemicInterval::new(0.3, 0.8, 0.1);
        // Very strong frame evidence: reduction > 1.0
        let restricted = restrict_epistemic_frame_evidence(&src, 1.0, 1.0);
        assert!(restricted.open_world >= 0.0);
    }

    #[test]
    fn test_is_narrow() {
        let narrow = EpistemicInterval::new(0.78, 0.82, 0.01);
        let wide = EpistemicInterval::new(0.2, 0.8, 0.3);
        assert!(narrow.is_narrow(0.2));
        assert!(!wide.is_narrow(0.2));
    }

    fn binary_frame() -> FrameOfDiscernment {
        FrameOfDiscernment::new("binary_truth", vec!["TRUE".into(), "FALSE".into()])
            .expect("binary frame")
    }

    #[test]
    fn to_mass_function_typical() {
        let frame = binary_frame();
        let iv = EpistemicInterval::new(0.5, 0.9, 0.3);
        let mf = iv.to_mass_function(&frame).expect("mass");
        let sum: f64 = mf.masses().values().sum();
        assert!((sum - 1.0).abs() < 1e-10, "masses sum to 1 (got {sum})");

        let bel =
            epigraph_ds::measures::belief(&mf, &FocalElement::positive(BTreeSet::from([0_usize])));
        let pl_minus_ow = epigraph_ds::measures::plausibility(
            &mf,
            &FocalElement::positive(BTreeSet::from([0_usize])),
        );
        assert!((bel - iv.bel).abs() < 1e-10, "bel round-trip");
        // Standard Pl ignores complement masses, so Pl({0}) = bel + closed_world.
        let expected_pl_minus_ow = iv.pl - iv.open_world;
        assert!(
            (pl_minus_ow - expected_pl_minus_ow).abs() < 1e-10,
            "Pl({{0}}) on positive focals equals pl − open_world"
        );
    }

    #[test]
    fn to_mass_function_vacuous() {
        let frame = binary_frame();
        let mf = EpistemicInterval::VACUOUS
            .to_mass_function(&frame)
            .expect("mass");
        // VACUOUS = (bel=0, pl=1, ow=0.5) → m({0,1})=0.5, m(~{0,1})=0.5
        let theta = mf
            .masses()
            .get(&FocalElement::theta(&frame))
            .copied()
            .unwrap_or(0.0);
        let missing = mf
            .masses()
            .get(&FocalElement::missing(&frame))
            .copied()
            .unwrap_or(0.0);
        assert!((theta - 0.5).abs() < 1e-10);
        assert!((missing - 0.5).abs() < 1e-10);
    }

    #[test]
    fn to_mass_function_certain() {
        let frame = binary_frame();
        let mf = EpistemicInterval::certain(0.8)
            .to_mass_function(&frame)
            .expect("mass");
        let m_true = mf
            .masses()
            .get(&FocalElement::positive(BTreeSet::from([0_usize])))
            .copied()
            .unwrap_or(0.0);
        let m_false = mf
            .masses()
            .get(&FocalElement::positive(BTreeSet::from([1_usize])))
            .copied()
            .unwrap_or(0.0);
        assert!((m_true - 0.8).abs() < 1e-10);
        assert!((m_false - 0.2).abs() < 1e-10);
    }

    #[test]
    fn to_mass_function_clamps_overflowing_open_world() {
        let frame = binary_frame();
        // Construct via new() so open_world is clamped to width=0.2
        let iv = EpistemicInterval::new(0.4, 0.6, 0.9);
        assert!(iv.open_world <= iv.width() + 1e-10);
        let mf = iv.to_mass_function(&frame).expect("mass");
        let sum: f64 = mf.masses().values().sum();
        assert!((sum - 1.0).abs() < 1e-10);
    }

    #[test]
    fn to_mass_function_round_trip_via_from_mass_components() {
        let frame = binary_frame();
        let iv = EpistemicInterval::new(0.45, 0.85, 0.2);
        let mf = iv.to_mass_function(&frame).expect("mass");

        let bel =
            epigraph_ds::measures::belief(&mf, &FocalElement::positive(BTreeSet::from([0_usize])));
        let pl_pos = epigraph_ds::measures::plausibility(
            &mf,
            &FocalElement::positive(BTreeSet::from([0_usize])),
        );
        let complement_sum: f64 = mf
            .masses()
            .iter()
            .filter(|(fe, _)| fe.complement)
            .map(|(_, m)| *m)
            .sum();
        // from_mass_components takes (bel, pl_with_ow_added_back, complement_sum)
        let iv2 =
            EpistemicInterval::from_mass_components(bel, pl_pos + complement_sum, complement_sum);
        assert!((iv2.bel - iv.bel).abs() < 1e-10);
        assert!((iv2.pl - iv.pl).abs() < 1e-10);
        assert!((iv2.open_world - iv.open_world).abs() < 1e-10);
    }

    #[test]
    fn to_mass_function_zero_belief() {
        let frame = binary_frame();
        // Pure refutation: bel=0, pl=0.2, ow=0
        let iv = EpistemicInterval::new(0.0, 0.2, 0.0);
        let mf = iv.to_mass_function(&frame).expect("mass");
        let m_false = mf
            .masses()
            .get(&FocalElement::positive(BTreeSet::from([1_usize])))
            .copied()
            .unwrap_or(0.0);
        assert!((m_false - 0.8).abs() < 1e-10);
        // No mass on {0}
        assert!(!mf
            .masses()
            .contains_key(&FocalElement::positive(BTreeSet::from([0_usize]))));
    }
}
