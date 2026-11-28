//! Belief over the scratch graph, slice 1 (DESIGN §4.4).
//!
//! * Each stored seed BBA becomes a `MassFunctionRow` on BP's binary frame
//!   and is seeded through [`cdst_bp::seed_mass`] under
//!   [`BeliefProfile::builtin`], the same seeding the served CDST BP uses.
//! * An atom's seeds (its own and every corroboration) are combined with
//!   epigraph-ds's Dempster rule, so a restatement raises Bel.
//! * Bel, Pl and BetP are read off the combined mass for `{supported}`.
//! * An atom is CONTESTED while a `contradicts` or `refutes` edge joins it to
//!   another current atom.
//!
//! Slice 2 (E3) adds CDST BP over the edges; nothing here propagates.
//!
//! # The speaker reliability is applied once (critic finding X6)
//!
//! `seed_mass` discounts the stored masses by
//! `edge_factor::effective_source_strength_profiled(row, profile)`. The row
//! built here stores the undiscounted `m({supported}) = confidence` and sets
//! `source_strength = reliability`, `evidence_type = None`,
//! `locality_tag = "intra"`. With no evidence type, the profile's chain
//! returns the stored source strength verbatim (its legacy-cohort step), so
//! the one discount is exactly the reliability and the seed is
//! `m({supported}) = confidence × reliability` (DESIGN §3.4).
//!
//! `evidence_type` must stay `None`. A profile that calibrates an evidence
//! type multiplies an `intra` row of that type by the intra locality factor
//! (0.3 in `BeliefProfile::builtin()`), which the reliability table does not
//! describe. The builtin profile calibrates no type and has no perspective
//! lens, so today only the untyped path is reachable either way; leaving the
//! type unset keeps it so if either changes. A perspective lens with an
//! `intra` locality entry would still discount; belief never passes one.
//! `tests/scratch_belief.rs` pins these facts with exact values.
//!
//! # Derived, never stored
//!
//! Belief is a pure function of the stored graph and is recomputed on read.
//! Nothing derived is written to the snapshot, so a snapshot stays a function
//! of the acknowledged writes alone, and a change of profile or rule never
//! leaves a stale number on disk.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use epigraph_db::MassFunctionRow;
use epigraph_ds::combination::dempster_combine;
use epigraph_ds::measures::{belief, pignistic_probability, plausibility};
use epigraph_ds::{FocalElement, MassFunction};
use epigraph_engine::belief_profile::BeliefProfile;
use epigraph_engine::cdst_bp;
use serde::Serialize;
use uuid::Uuid;

use super::store::{Relationship, ScratchAtom, ScratchStore, SeedBba};

/// The locality every seed row carries: all evidence is from this one chat.
pub const SEED_LOCALITY_TAG: &str = "intra";

/// Index of `supported` on BP's binary frame.
const H_SUPPORTED: usize = 0;

/// Relationships that make both endpoints CONTESTED while both are current.
pub const CONTESTING: [Relationship; 2] = [Relationship::Contradicts, Relationship::Refutes];

/// Why belief could not be computed for an atom. Text-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeliefError {
    pub atom: Uuid,
    pub stage: &'static str,
}

impl std::fmt::Display for BeliefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "belief failed at {} for atom {}", self.stage, self.atom)
    }
}

impl std::error::Error for BeliefError {}

/// One atom's belief.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AtomBelief {
    /// Bel({supported}).
    pub bel: f64,
    /// Pl({supported}).
    pub pl: f64,
    /// Pignistic probability of `supported`; the ranking key.
    pub betp: f64,
    /// A live `contradicts`/`refutes` edge joins this atom to another current
    /// atom. Always false for a superseded atom.
    pub contested: bool,
    /// The current atoms on the other end of those edges, in id order.
    pub contested_with: Vec<Uuid>,
}

/// The binary frame `cdst_bp` parses seed rows on.
fn binary_frame() -> epigraph_ds::FrameOfDiscernment {
    cdst_bp::vacuous().frame().clone()
}

/// The `MassFunctionRow` a stored seed BBA is seeded from: undiscounted
/// `{supported: confidence}`, with the reliability as the source strength.
///
/// # Errors
/// The confidence is not a valid simple-support mass (the store validates
/// it, so only a hand-built `SeedBba` reaches this).
pub fn seed_row(atom: Uuid, bba: &SeedBba) -> Result<MassFunctionRow, BeliefError> {
    let mass = MassFunction::simple(
        binary_frame(),
        BTreeSet::from([H_SUPPORTED]),
        bba.confidence,
    )
    .map_err(|_| BeliefError {
        atom,
        stage: "seed mass",
    })?;
    Ok(MassFunctionRow {
        id: bba.source,
        claim_id: atom,
        frame_id: Uuid::nil(),
        source_agent_id: None,
        perspective_id: None,
        slot_kind: None,
        slot_id: None,
        masses: mass.masses_to_json(),
        conflict_k: None,
        combination_method: None,
        source_strength: Some(bba.reliability),
        evidence_type: None,
        locality_tag: SEED_LOCALITY_TAG.to_string(),
        evidence_id: None,
        // A constant: belief reads no clock (the row's time plays no part in
        // seeding).
        created_at: DateTime::<Utc>::UNIX_EPOCH,
    })
}

/// An atom's combined mass: every seed through `seed_mass`, then Dempster's
/// rule in stored order (the rule is commutative; the order only fixes
/// rounding).
///
/// Dempster's rule and not an adaptive or cautious rule: a cautious rule is
/// idempotent, so a restatement would never raise Bel.
///
/// # Errors
/// A seed fails to parse or discount, or two seeds conflict totally (not
/// reachable in slice 1, where every seed supports `{supported}`).
pub fn combined_mass(
    atom: &ScratchAtom,
    profile: &BeliefProfile,
) -> Result<MassFunction, BeliefError> {
    let mut combined: Option<MassFunction> = None;
    for bba in &atom.bbas {
        let row = seed_row(atom.id, bba)?;
        let seeded = cdst_bp::seed_mass(&row, profile).map_err(|_| BeliefError {
            atom: atom.id,
            stage: "seed_mass",
        })?;
        combined = Some(match combined {
            None => seeded,
            Some(acc) => dempster_combine(&acc, &seeded).map_err(|_| BeliefError {
                atom: atom.id,
                stage: "combine",
            })?,
        });
    }
    Ok(combined.unwrap_or_else(cdst_bp::vacuous))
}

/// Bel, Pl and BetP of `supported` under `m`.
pub fn measures(m: &MassFunction) -> (f64, f64, f64) {
    let supported = FocalElement::positive(BTreeSet::from([H_SUPPORTED]));
    (
        belief(m, &supported),
        plausibility(m, &supported),
        pignistic_probability(m, H_SUPPORTED),
    )
}

/// For each current atom, the current atoms a contesting edge joins it to.
fn contested_partners(store: &ScratchStore) -> BTreeMap<Uuid, BTreeSet<Uuid>> {
    let current = |id: &Uuid| store.atom(id).is_some_and(|a| a.is_current);
    let mut out: BTreeMap<Uuid, BTreeSet<Uuid>> = BTreeMap::new();
    for edge in store.edges() {
        if !CONTESTING.contains(&edge.relationship) {
            continue;
        }
        if current(&edge.source) && current(&edge.target) {
            out.entry(edge.source).or_default().insert(edge.target);
            out.entry(edge.target).or_default().insert(edge.source);
        }
    }
    out
}

/// Belief for every atom in the graph, current or not, keyed by id.
#[derive(Debug, Clone, PartialEq)]
pub struct BeliefView {
    beliefs: BTreeMap<Uuid, AtomBelief>,
}

impl BeliefView {
    /// Compute belief for the whole graph under `BeliefProfile::builtin()`.
    ///
    /// # Errors
    /// The first atom whose belief cannot be computed.
    pub fn compute(store: &ScratchStore) -> Result<Self, BeliefError> {
        Self::compute_with(store, &BeliefProfile::builtin())
    }

    /// As [`Self::compute`], under `profile`.
    ///
    /// # Errors
    /// The first atom whose belief cannot be computed.
    pub fn compute_with(
        store: &ScratchStore,
        profile: &BeliefProfile,
    ) -> Result<Self, BeliefError> {
        let mut partners = contested_partners(store);
        let mut beliefs = BTreeMap::new();
        for atom in store.atoms() {
            let (bel, pl, betp) = measures(&combined_mass(atom, profile)?);
            let contested_with: Vec<Uuid> = partners
                .remove(&atom.id)
                .map(|s| s.into_iter().collect())
                .unwrap_or_default();
            beliefs.insert(
                atom.id,
                AtomBelief {
                    bel,
                    pl,
                    betp,
                    contested: !contested_with.is_empty(),
                    contested_with,
                },
            );
        }
        Ok(Self { beliefs })
    }

    pub fn get(&self, id: &Uuid) -> Option<&AtomBelief> {
        self.beliefs.get(id)
    }

    /// Every atom's belief, in id order.
    pub fn iter(&self) -> impl Iterator<Item = (&Uuid, &AtomBelief)> {
        self.beliefs.iter()
    }

    /// Counts for `update_belief`: current atoms, how many are CONTESTED, and
    /// the seed BBAs combined for them.
    pub fn summary(&self, store: &ScratchStore) -> BeliefSummary {
        let mut s = BeliefSummary::default();
        for atom in store.atoms().filter(|a| a.is_current) {
            s.current_atoms += 1;
            s.seeds += atom.bbas.len();
            if self.beliefs.get(&atom.id).is_some_and(|b| b.contested) {
                s.contested += 1;
            }
        }
        s
    }
}

/// What `update_belief` reports. Counts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct BeliefSummary {
    pub current_atoms: usize,
    pub contested: usize,
    pub seeds: usize,
}
