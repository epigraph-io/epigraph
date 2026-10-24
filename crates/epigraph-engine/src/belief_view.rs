//! The one read shape of a claim's belief: [`BeliefView`], with a [`Basis`]
//! marker that says where the numbers come from (atom-level belief program,
//! SPEC §3.5, §7.1).
//!
//! An atom's belief is the fold of its own evidence
//! ([`crate::atom_items::atom_fold`], an
//! [`EvidencedInterval`](crate::atom_items::EvidencedInterval)). A compound's
//! belief is a QUERY over its visible leaves
//! ([`crate::compound_belief::derive_compound_belief_batch`]): a
//! [`DerivedBelief`]. The two are different types on purpose. Every fold, the
//! edge-factor source read and every other piece of belief machinery takes an
//! `EvidencedInterval`, so a derived compound value can never be fed back in
//! as evidence (that would count the leaves' evidence twice):
//!
//! ```compile_fail,E0308
//! use epigraph_engine::atom_items::EvidencedInterval;
//! use epigraph_engine::belief_view::DerivedBelief;
//!
//! fn machinery(_input: &EvidencedInterval) {}
//! #[allow(unused_variables)]
//! fn feed_back(derived: &DerivedBelief, folded: &EvidencedInterval) {
//!     machinery(derived);
//! }
//! ```
//!
//! The twin below is the same text with the other argument, and it compiles:
//! both types and both import paths resolve, so the failure above is the
//! type split and nothing else. (Rustdoc checks the `E0308` code only on
//! nightly; on stable this twin is what rules out any other compile error.)
//!
//! ```
//! use epigraph_engine::atom_items::EvidencedInterval;
//! use epigraph_engine::belief_view::DerivedBelief;
//!
//! fn machinery(_input: &EvidencedInterval) {}
//! #[allow(unused_variables)]
//! fn feed_back(derived: &DerivedBelief, folded: &EvidencedInterval) {
//!     machinery(folded);
//! }
//! ```
//!
//! # Wire shape
//!
//! [`BeliefView`] serializes with `basis` in lower case, and for a compound a
//! `derived` object (or a `profile` for a spine node). Leaf counts
//! (`leaves_used`, `evidenced`, `legacy_leaves`) count the leaves the viewer
//! can see; no field carries a total, a hidden count or a "partial" flag
//! (SPEC §8 T1).
//!
//! # `EPIGRAPH_COMPOUND_BELIEF`
//!
//! [`CompoundBeliefMode`] is read once per process. `legacy` (the default)
//! serves today's values and computes nothing new; `shadow` serves today's
//! values and adds a `shadow` view beside them on `get_belief`. The
//! `progressive` and `strict` modes, which change served values, are not
//! recognised here: until they are wired, either spelling falls back to
//! `legacy` (and is logged), so no setting can move a served value.

use serde::Serialize;
use uuid::Uuid;

/// Where a [`BeliefView`]'s numbers come from (SPEC §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Basis {
    /// An atom's fold of its own visible evidence (AEF).
    Axiom,
    /// An atom with no AEF input and no kept cache: Bel 0, Pl 1, `BetP` .5.
    /// Distinct from "believed at .5".
    Unproven,
    /// An atom with no AEF input whose old cache is kept and served as it is.
    Legacy,
    /// A compound: the conjunction (R-DEP) of its visible leaves.
    Derived,
    /// A spine compound (or one over the leaf cap): a profile of its visible
    /// leaves, never a conjunction.
    Profile,
    /// Reserved for the inference layer.
    Inferred,
    /// Reserved for the inference layer.
    Combined,
}

/// A leaf's state for the readiness predicates (SPEC §7.1), as one viewer
/// sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LeafState {
    /// P1: the viewer can see at least one AEF input row of the atom.
    Axiom,
    /// Not P1, and the atom's cache is kept (non-NULL): served `Legacy`.
    Legacy,
    /// Not P1 and no cache.
    Unproven,
}

impl LeafState {
    /// P1 (atom evidenced): an AEF input row the viewer can see exists.
    #[must_use]
    pub const fn is_evidenced(self) -> bool {
        matches!(self, Self::Axiom)
    }
}

/// P2 (compound ready for a viewer): no visible leaf is served `Legacy`.
///
/// Unevidenced (`Unproven`) leaves do not block readiness: R-DEP with the NR
/// gate already treats them soundly. The argument is the viewer's visible
/// leaves only, so the answer discloses nothing about hidden ones (SPEC §8
/// T4). A compound with no visible leaf is ready.
pub fn compound_ready<I: IntoIterator<Item = LeafState>>(visible_leaves: I) -> bool {
    visible_leaves
        .into_iter()
        .all(|s| !matches!(s, LeafState::Legacy))
}

/// An envelope that holds whatever the dependence between leaves: Fréchet
/// bounds on Bel and Pl, and the upper bound on NR.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Envelope {
    /// Lower bound on Bel.
    pub lo: f64,
    /// Upper bound on Pl.
    pub hi: f64,
    /// Upper bound on NR.
    pub hi_nr: f64,
}

impl From<epigraph_ds::conjunction::Frechet> for Envelope {
    fn from(f: epigraph_ds::conjunction::Frechet) -> Self {
        Self {
            lo: f.lo,
            hi: f.hi,
            hi_nr: f.hi_nr,
        }
    }
}

/// The `not_all` valuation of a compound (SPEC §3.6): refutation of the
/// compound as a whole, from its own rows and from refuting edges into it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct NotAll {
    /// The combined mass on ¬(∧ leaves), 1 − Π(1 − mᵢ) across sources.
    pub m: f64,
    /// How many sources contributed (row keys plus edges).
    pub sources: usize,
    /// Refuting edges into the compound that were skipped because their
    /// source shares a visible leaf with it.
    pub shared_leaf_skipped: usize,
    /// Refuting edges into the compound that were skipped because the same
    /// source's refuting edge into one of its visible leaves already carries
    /// a frozen BBA the conjunction reads (a parent edge retargeted onto its
    /// atoms): that refutation is counted once, on the leaf.
    pub leaf_edge_skipped: usize,
}

impl NotAll {
    /// No refutation of the whole.
    pub const NONE: Self = Self {
        m: 0.0,
        sources: 0,
        shared_leaf_skipped: 0,
        leaf_edge_skipped: 0,
    };
}

/// A compound's derived belief: the conjunction of its visible leaves.
///
/// Computed, never evidence. It cannot be passed where an
/// [`EvidencedInterval`](crate::atom_items::EvidencedInterval) is required
/// (see the module doc).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DerivedBelief {
    /// The rule (`dep_v1`).
    pub rule: &'static str,
    /// What the view's `betp` is: `product_frame` (½ per free leaf).
    pub betp_kind: &'static str,
    /// The Fréchet envelope.
    pub frechet: Envelope,
    /// Conflict K seen by the conjunction.
    pub conflict: f64,
    /// `false` over the exact cap, under the R-FRE fallback, or when a closed
    /// form met open-world mass.
    pub exact: bool,
    /// Visible leaves the conjunction ran over.
    pub leaves_used: usize,
    /// Visible leaves with AEF input (P1).
    pub evidenced: usize,
    /// Visible leaves read as a `legacy:<atom>` pseudo-item from their cache.
    pub legacy_leaves: usize,
    /// Two or more negative edges between visible leaves: the value is the
    /// R-FRE envelope, not a conjunction.
    pub internally_contested: bool,
    /// The compound's `not_all` valuation.
    pub not_all: NotAll,
}

/// Minimum, median and maximum of a per-leaf statistic.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Summary3 {
    /// Smallest value.
    pub min: f64,
    /// Median.
    pub median: f64,
    /// Largest value.
    pub max: f64,
}

impl From<epigraph_ds::conjunction::Summary> for Summary3 {
    fn from(s: epigraph_ds::conjunction::Summary) -> Self {
        Self {
            min: s.min,
            median: s.median,
            max: s.max,
        }
    }
}

/// A profile of a spine compound's visible leaves (SPEC §2.2), served instead
/// of a conjunction.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LeafProfile {
    /// The rule (`profile_v1`).
    pub rule: &'static str,
    /// Visible leaves.
    pub n: usize,
    /// Visible leaves with AEF input (P1).
    pub evidenced: usize,
    /// Visible leaves read from their cache.
    pub legacy_leaves: usize,
    /// Per-leaf Bel.
    pub bel: Summary3,
    /// Per-leaf `BetP`.
    pub betp: Summary3,
    /// Visible leaves with Pl < .5.
    pub contested: usize,
    /// Fréchet envelope of the leaves.
    pub frechet: Envelope,
}

/// What went into a view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct InputSummary {
    /// Evidence items read (pseudo-items of `Legacy` leaves included).
    pub items: usize,
    /// Items that carry a frozen edge-factor row whose edge source is a
    /// compound (a labelled fidelity cost of stage 1, SPEC §6.3).
    pub legacy_compound_edge_items: usize,
}

/// The rule version of an atom's own fold.
pub const AEF_RULE: &str = "aef_v1";
/// The rule version of a value served from a kept cache.
pub const LEGACY_RULE: &str = "legacy";
/// The rule version of a compound's conjunction.
pub const DEP_RULE: &str = "dep_v1";
/// The rule version of a spine compound's profile.
pub const PROFILE_RULE: &str = epigraph_ds::conjunction::PROFILE_RULE;
/// [`DerivedBelief::betp_kind`].
pub const PRODUCT_FRAME_BETP: &str = "product_frame";

/// One claim's belief as one viewer may read it (SPEC §3.5).
///
/// `bel`, `pl` and `betp` are the served numbers: for an atom its fold or its
/// kept cache, for a compound the derived conjunction (`betp` product-frame),
/// for a spine node the envelope (`bel` = lo, `pl` = hi, `betp` their
/// midpoint). `nr` = 1 − Dis is the gate statistic ("not refuted").
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BeliefView {
    /// The claim.
    pub claim_id: Uuid,
    /// Where the numbers come from.
    pub basis: Basis,
    /// Bel(claim).
    pub bel: f64,
    /// Pl(claim).
    pub pl: f64,
    /// `BetP`(claim).
    pub betp: f64,
    /// NR = 1 − Dis: not refuted.
    pub nr: f64,
    /// A compound's derivation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived: Option<DerivedBelief>,
    /// A spine compound's profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<LeafProfile>,
    /// `aef_v1`, `legacy`, `dep_v1` or `profile_v1`.
    pub rule_version: &'static str,
    /// What went into it.
    pub inputs: InputSummary,
}

/// `EPIGRAPH_COMPOUND_BELIEF` (SPEC §7.1, §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CompoundBeliefMode {
    /// Today's values, nothing new computed (the default).
    #[default]
    Legacy,
    /// Today's values, plus a `shadow` view on `get_belief`.
    Shadow,
}

impl CompoundBeliefMode {
    /// The environment variable this switch is read from.
    pub const ENV: &'static str = "EPIGRAPH_COMPOUND_BELIEF";

    /// Parse one value: trimmed, case-insensitive; `None` when it is neither
    /// `legacy` nor `shadow`.
    #[must_use]
    pub fn parse_value(raw: &str) -> Option<Self> {
        let v = raw.trim();
        if v.eq_ignore_ascii_case("legacy") {
            Some(Self::Legacy)
        } else if v.eq_ignore_ascii_case("shadow") {
            Some(Self::Shadow)
        } else {
            None
        }
    }

    /// This process's setting: [`Self::ENV`], read once. Unset, blank or an
    /// unrecognised value (including the not-yet-wired `progressive` and
    /// `strict`) is the default, [`Self::Legacy`]; an unrecognised one is
    /// logged.
    #[must_use]
    pub fn current() -> Self {
        static CELL: std::sync::OnceLock<CompoundBeliefMode> = std::sync::OnceLock::new();
        *CELL.get_or_init(|| crate::atom_items::read_flag(Self::ENV, Self::parse_value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_legacy_and_shadow_are_recognised_and_legacy_is_the_default() {
        assert_eq!(CompoundBeliefMode::default(), CompoundBeliefMode::Legacy);
        assert_eq!(
            CompoundBeliefMode::parse_value(" Shadow "),
            Some(CompoundBeliefMode::Shadow)
        );
        assert_eq!(
            CompoundBeliefMode::parse_value("LEGACY"),
            Some(CompoundBeliefMode::Legacy)
        );
        // The modes that change served values are not wired here, so no
        // spelling of them (or a typo) can select anything but the default.
        for raw in ["progressive", "strict", "shadows", "on", ""] {
            assert_eq!(CompoundBeliefMode::parse_value(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn readiness_is_blocked_by_a_legacy_leaf_only() {
        use LeafState::{Axiom, Legacy, Unproven};
        assert!(compound_ready([Axiom, Unproven, Unproven]));
        assert!(compound_ready([]));
        assert!(!compound_ready([Axiom, Legacy]));
    }

    #[test]
    fn the_wire_shape_names_the_basis_in_lower_case_and_omits_absent_parts() {
        let v = BeliefView {
            claim_id: Uuid::nil(),
            basis: Basis::Unproven,
            bel: 0.0,
            pl: 1.0,
            betp: 0.5,
            nr: 1.0,
            derived: None,
            profile: None,
            rule_version: AEF_RULE,
            inputs: InputSummary::default(),
        };
        let j = serde_json::to_value(&v).expect("serialize");
        assert_eq!(j["basis"], "unproven");
        assert!(j.get("derived").is_none() && j.get("profile").is_none());
    }
}
