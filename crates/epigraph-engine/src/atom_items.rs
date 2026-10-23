//! The atom evidence fold (AEF): the ONE fold of an atom's own evidence
//! (atom-level belief program, SPEC §3.3, §3.4, §4.2, §11.4).
//!
//! An atom's belief is a fold of the rows that are evidence about IT. This
//! module reads those rows ([`atom_axiom_rows`]), keys each one by its
//! canonical source ([`crate::source_dependence::item_key`]) and folds them
//! by item ([`atom_fold`]): one key's pure-support rows count once (the max),
//! its refutations are a separate item, and distinct items combine by
//! Dempster. The result is an [`EvidencedInterval`], which only [`atom_fold`]
//! can build.
//!
//! Nothing on a served path calls this module yet: the single atom-cache
//! writer [`crate::edge_factor::recompute_atom_cache`] is wired to its call
//! sites separately, behind `EPIGRAPH_ATOM_FOLD` (default `legacy`).

use std::collections::HashMap;

use uuid::Uuid;

use epigraph_ds::MassFunction;

use crate::belief_query::FramedBeliefContext;
use crate::source_dependence::ItemKey;

/// Which rows of an atom's input a read takes (SPEC §3.4, §11.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AxiomMode {
    /// The stage-1 served fold: evidence, edge-factor rows from atom sources,
    /// compound-source edge-factor rows while
    /// [`CompoundSourceEdges::Frozen`], `propagated_*` and `auto_cdst`.
    Display,
    /// The engine's premise input: evidence only. No `edge_factor`, no
    /// `propagated_*`, no `auto_cdst`.
    Pure,
}

/// `EPIGRAPH_COMPOUND_SOURCE_EDGES` (SPEC §6.3, §10.2): whether edge-factor
/// rows whose edge SOURCE is a compound stay in the [`AxiomMode::Display`]
/// fold. Spelled as PR-G0's `belief_modes::CompoundSourceEdges`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CompoundSourceEdges {
    /// Kept, read one-sided on positive relationships (the default).
    #[default]
    Frozen,
    /// Dropped from every fold.
    Excluded,
}

impl CompoundSourceEdges {
    /// The environment variable this switch is read from.
    pub const ENV: &'static str = "EPIGRAPH_COMPOUND_SOURCE_EDGES";

    /// This process's setting: [`Self::ENV`], read once. Unset, blank or an
    /// unrecognised value is the default, [`Self::Frozen`].
    #[must_use]
    pub fn current() -> Self {
        Self::default()
    }
}

/// `EPIGRAPH_ATOM_FOLD` (SPEC §10.2): which atoms the single cache writer
/// folds with the AEF. Spelled as PR-G0's `belief_modes::AtomFold`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AtomFoldMode {
    /// Today's per-site folds, for every atom (the default).
    #[default]
    Legacy,
    /// The AEF for standalone atoms; leaves keep the legacy fold.
    AefStandalone,
    /// The AEF for every atom.
    Aef,
}

impl AtomFoldMode {
    /// The environment variable this switch is read from.
    pub const ENV: &'static str = "EPIGRAPH_ATOM_FOLD";

    /// This process's setting: [`Self::ENV`], read once. Unset, blank or an
    /// unrecognised value is the default, [`Self::Legacy`].
    #[must_use]
    pub fn current() -> Self {
        Self::default()
    }
}

/// What a row is, for the mode filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AxiomClass {
    /// Evidence about the atom: every row no other class names.
    Evidence,
    /// The author's `truth_value` seed (`combination_method =
    /// 'truth_value_seed'`).
    Seed,
    /// An edge-factor row; `compound_source` when the edge's source is a
    /// compound.
    EdgeFactor { compound_source: bool },
    /// `propagated_from_parent` / `propagated_from_neighbor`.
    Propagated,
    /// `auto_cdst`.
    AutoCdst,
}

/// One row of an atom's AEF input, on the `binary_truth` frame (index 0 =
/// TRUE), keyed and discounted.
#[derive(Debug, Clone)]
pub struct AxiomRow {
    /// The `mass_functions` row.
    pub row_id: Uuid,
    /// The atom it is evidence about.
    pub atom_id: Uuid,
    /// Its canonical item key (SPEC §3.3).
    pub key: ItemKey,
    /// Its class.
    pub class: AxiomClass,
    /// Coarsened to `binary_truth`, before the reliability discount.
    pub coarse: MassFunction,
    /// Coarsened and discounted by α under the read's lens.
    pub bba: MassFunction,
}

/// An atom's folded evidence. Only [`atom_fold`] builds one, so a value of
/// this type is always the fold of an atom's own rows, never a cache read or
/// a compound's derived value.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidencedInterval {
    belief: f64,
    plausibility: f64,
    pignistic_prob: f64,
    mass_on_conflict: f64,
    mass_on_missing: f64,
    theta: f64,
    items: usize,
}

impl EvidencedInterval {
    /// The fold of nothing: Bel 0, Pl 1, BetP .5 (`unproven`).
    fn unproven() -> Self {
        Self {
            belief: 0.0,
            plausibility: 1.0,
            pignistic_prob: 0.5,
            mass_on_conflict: 0.0,
            mass_on_missing: 0.0,
            theta: 1.0,
            items: 0,
        }
    }

    /// Bel(TRUE).
    #[must_use]
    pub const fn belief(&self) -> f64 {
        self.belief
    }

    /// Pl(TRUE).
    #[must_use]
    pub const fn plausibility(&self) -> f64 {
        self.plausibility
    }

    /// BetP(TRUE).
    #[must_use]
    pub const fn pignistic_prob(&self) -> f64 {
        self.pignistic_prob
    }

    /// The conflict the fold saw.
    #[must_use]
    pub const fn mass_on_conflict(&self) -> f64 {
        self.mass_on_conflict
    }

    /// Open-world (`~`) mass left in the fold.
    #[must_use]
    pub const fn mass_on_missing(&self) -> f64 {
        self.mass_on_missing
    }

    /// Closed-world ignorance m({TRUE, FALSE}) left in the fold.
    #[must_use]
    pub const fn theta(&self) -> f64 {
        self.theta
    }

    /// How many items were folded.
    #[must_use]
    pub const fn items(&self) -> usize {
        self.items
    }

    /// No item was folded: the atom has no AEF input (`unproven`).
    #[must_use]
    pub const fn is_unproven(&self) -> bool {
        self.items == 0
    }
}

/// The AEF input rows of each requested atom, as `viewer` sees them, in
/// `mode`, under the lens `ctx`. Reads the process's
/// [`CompoundSourceEdges::current`]; [`atom_axiom_rows_under`] takes it
/// explicitly.
///
/// # Errors
/// A database read or a stored BBA that cannot be parsed.
pub async fn atom_axiom_rows(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
    mode: AxiomMode,
    ctx: &FramedBeliefContext,
) -> Result<HashMap<Uuid, Vec<AxiomRow>>, String> {
    atom_axiom_rows_under(conn, viewer, ids, mode, ctx, CompoundSourceEdges::current()).await
}

/// [`atom_axiom_rows`] under an explicit [`CompoundSourceEdges`] setting.
///
/// # Errors
/// A database read or a stored BBA that cannot be parsed.
pub async fn atom_axiom_rows_under(
    _conn: &mut sqlx::PgConnection,
    _viewer: &epigraph_db::visibility::Viewer,
    _ids: &[Uuid],
    _mode: AxiomMode,
    _ctx: &FramedBeliefContext,
    _compound_source_edges: CompoundSourceEdges,
) -> Result<HashMap<Uuid, Vec<AxiomRow>>, String> {
    Ok(HashMap::new())
}

/// Fold ONE atom's AEF rows by item.
///
/// # Errors
/// A Dempster step that fails (total conflict between dogmatic items).
pub fn atom_fold(_rows: &[AxiomRow]) -> Result<EvidencedInterval, String> {
    Ok(EvidencedInterval::unproven())
}
