//! EpistemicInterval: belief interval with decomposed open-world ignorance.
//!
//! Extends the [Bel, Pl] interval with an explicit open_world mass component
//! representing frame incompleteness (CDST complement focal elements).

use serde::{Deserialize, Serialize};

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

/// Positive restriction (supports/corroborates): Bel/Pl transform,
/// open-world mass propagates at full strength.
pub fn restrict_epistemic_positive(source: &EpistemicInterval, factor: f64) -> EpistemicInterval {
    EpistemicInterval {
        bel: source.bel * factor,
        pl: (1.0 - source.pl).mul_add(-factor, 1.0),
        open_world: source.open_world,
    }
}

/// Negative restriction (contradicts/refutes): flip interval,
/// open-world mass propagates unchanged.
pub fn restrict_epistemic_negative(source: &EpistemicInterval, factor: f64) -> EpistemicInterval {
    EpistemicInterval {
        bel: (1.0 - source.pl) * factor,
        pl: source.bel.mul_add(-factor, 1.0),
        open_world: source.open_world,
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
    fn test_restrict_positive_propagates_open_world() {
        let src = EpistemicInterval::new(0.6, 0.9, 0.15);
        let restricted = restrict_epistemic_positive(&src, 0.8);
        // bel = 0.6 * 0.8 = 0.48
        assert!((restricted.bel - 0.48).abs() < 1e-10);
        // pl = 1 - (1-0.9)*0.8 = 1 - 0.08 = 0.92
        assert!((restricted.pl - 0.92).abs() < 1e-10);
        // open_world passes through unchanged
        assert!((restricted.open_world - 0.15).abs() < 1e-10);
    }

    #[test]
    fn test_restrict_negative_flips_and_propagates_ow() {
        let src = EpistemicInterval::new(0.7, 0.9, 0.1);
        let restricted = restrict_epistemic_negative(&src, 0.8);
        // bel = (1-0.9)*0.8 = 0.08
        assert!((restricted.bel - 0.08).abs() < 1e-10);
        // pl = 1 - 0.7*0.8 = 0.44
        assert!((restricted.pl - 0.44).abs() < 1e-10);
        // open_world unchanged
        assert!((restricted.open_world - 0.1).abs() < 1e-10);
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
}
