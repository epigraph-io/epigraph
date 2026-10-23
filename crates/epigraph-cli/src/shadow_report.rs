//! The belief shadow report (atom-level belief program, SPEC §1.3, §3.2,
//! §7.1, §10.4): what every claim serves today beside what it would serve
//! under the atom fold and the per-viewer compound derivation, and the
//! corpus statistics the cutover is reviewed on. It writes nothing to the
//! database.
//!
//! Skeleton: the types the report emits. The computation lands in the
//! following commits.

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use epigraph_db::visibility::Viewer;
use epigraph_engine::atom_items::AtomFoldMode;
use epigraph_engine::belief_view::BeliefView;

/// The `confirmed` partition's threshold (SPEC §3.2).
pub const CONFIRMED_SCORE: f64 = 0.75;
/// A recall event's gate when its params carry no `min_truth`.
pub const DEFAULT_MIN_TRUTH: f64 = 0.3;
/// The tolerance of the served-versus-fold comparison (SPEC §1.3).
pub const MISMATCH_TOLERANCE: f64 = 1e-9;

/// Which claims the report covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Every current claim the report viewer can read.
    All,
    /// These claims (those the report viewer can read).
    Ids(Vec<Uuid>),
}

/// How a report run is set up.
#[derive(Debug, Clone)]
pub struct ReportOptions {
    /// The claims covered.
    pub scope: Scope,
    /// Recall events created at or after this instant are replayed and
    /// counted as exposure.
    pub since: DateTime<Utc>,
    /// The atom fold the candidate is read under: an atom whose role it does
    /// not cover keeps today's value.
    pub target_fold: AtomFoldMode,
    /// Claims per page.
    pub page_size: usize,
    /// How many top movers to list.
    pub top: usize,
    /// A compound moving more than this many places in the corpus ordering
    /// counts as a rank move.
    pub rank_threshold: usize,
    /// The conflict scan's threshold on K.
    pub conflict_min_k: f64,
    /// The sheaf cohomology's consistency threshold.
    pub sheaf_threshold: f64,
    /// Compute the owner-rule recompute stage of the drift decomposition
    /// (several reads per atom).
    pub owner_preview: bool,
    /// A snapshot's `pignistic_prob` per claim: the decomposition's start.
    pub s0: Option<HashMap<Uuid, f64>>,
    /// Graph-view exposure per claim, measured outside this report.
    pub graph_view_exposure: Option<HashMap<Uuid, u64>>,
}

impl ReportOptions {
    /// The defaults for `scope` and `since`.
    #[must_use]
    pub fn new(scope: Scope, since: DateTime<Utc>) -> Self {
        Self {
            scope,
            since,
            target_fold: AtomFoldMode::Aef,
            page_size: 500,
            top: 100,
            rank_threshold: 100,
            conflict_min_k: 0.3,
            sheaf_threshold: 0.05,
            owner_preview: false,
            s0: None,
            graph_view_exposure: None,
        }
    }
}

/// A belief interval.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize)]
pub struct Interval {
    pub bel: f64,
    pub pl: f64,
    pub betp: f64,
    pub open_world: f64,
}

/// What a claim serves today.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct Served {
    pub bel: Option<f64>,
    pub pl: Option<f64>,
    pub betp: Option<f64>,
    pub mass_on_missing: Option<f64>,
    pub frame_id: Option<Uuid>,
    /// The gate score (the cache, else `truth_value`).
    pub score: f64,
    pub confirmed: bool,
    pub contested: bool,
}

/// An atom's fold of its own visible evidence.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize)]
pub struct AefValue {
    pub bel: f64,
    pub pl: f64,
    pub betp: f64,
    pub nr: f64,
    pub conflict: f64,
    pub open_world: f64,
    pub items: usize,
}

/// A claim under one candidate mode.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct Candidate {
    /// `axiom`, `legacy`, `unproven`, `derived`, `profile` or `served`.
    pub basis: &'static str,
    /// The statistic the recall gate compares with `min_truth`.
    pub gate: f64,
    /// The ordering key.
    pub rank: f64,
    pub confirmed: bool,
    pub contested: bool,
    pub interval: Interval,
}

/// An atom's drift decomposition (SPEC §10.4).
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct Drift {
    pub start: f64,
    pub stages: BTreeMap<&'static str, Option<f64>>,
    pub components: BTreeMap<&'static str, Option<f64>>,
    #[serde(rename = "final")]
    pub final_value: f64,
    pub total: f64,
}

/// One claim's line of the report.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct ClaimLine {
    pub claim_id: Uuid,
    pub role: &'static str,
    pub spine: bool,
    pub served: Served,
    pub aef: Option<AefValue>,
    pub drift: Option<Drift>,
    pub derived: Option<BeliefView>,
    pub ready: Option<bool>,
    pub progressive: Candidate,
    pub strict: Candidate,
    pub recall_exposure: u64,
    pub graph_view_exposure: Option<u64>,
    pub served_vs_fold: Option<f64>,
}

/// One recall event, replayed.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct EventReplay {
    pub event_id: Uuid,
    pub min_truth: f64,
    pub returned: usize,
    pub resolved: usize,
    pub unresolved: usize,
    pub lost: usize,
    pub lost_in_first_10: usize,
    pub already_failing: usize,
}

/// Flips of a two-way status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Flips {
    pub to: u64,
    pub from: u64,
}

/// The recall replay under one mode (SPEC §10.4, extended).
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct ReplaySummary {
    pub events: usize,
    pub returned: usize,
    pub resolved: usize,
    pub unresolved: usize,
    pub lost: usize,
    pub already_failing: usize,
    pub mean_share_lost: f64,
    pub max_share_lost: f64,
    pub max_lost_in_first_10: usize,
    pub events_losing_more_than_one_in_first_10: usize,
    pub confirmed: Flips,
    pub contested: Flips,
    #[serde(skip)]
    pub per_event: Vec<EventReplay>,
}

/// One value per candidate mode.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct ByMode<T> {
    pub progressive: T,
    pub strict: T,
}

/// A compound's move in the corpus ordering.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct RankMove {
    pub claim_id: Uuid,
    pub from: usize,
    pub to: usize,
    pub moved: usize,
    pub recall_exposure: u64,
}

/// What strict mode changes for compounds (SPEC §10.4 strict-entry replay).
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct StrictEntry {
    pub compounds: usize,
    pub confirmed: Flips,
    pub confirmed_recall_weighted: Flips,
    pub confirmed_graph_view_weighted: Option<Flips>,
    pub rank_threshold: usize,
    pub rank_moves_over_threshold: usize,
    pub rank_moves_recall_weighted: u64,
    pub rank_moves_graph_view_weighted: Option<u64>,
    pub rank_move_quantiles: Quantiles,
    pub top_rank_moves: Vec<RankMove>,
}

/// Quantiles of a distribution.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize)]
pub struct Quantiles {
    pub n: usize,
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub max: f64,
}

/// The served value against the atom's own fold (SPEC §1.3).
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize)]
pub struct FoldMismatch {
    /// Atoms with AEF input the viewer can see.
    pub p1_atoms: usize,
    /// Of those, the ones whose served Bel, Pl or `BetP` differs from the
    /// fold by more than [`MISMATCH_TOLERANCE`].
    pub mismatched: usize,
    pub share: f64,
}

/// Sheaf cohomology under one set of intervals.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize)]
pub struct SheafStats {
    pub edge_count: usize,
    pub coverage: f64,
    pub h1: f64,
    pub h1_normalized: f64,
    pub conflict_h1: f64,
    pub ignorance_h1: f64,
    pub open_world_h1: f64,
    pub obstructed: usize,
}

/// The sheaf shadow.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct SheafShadow {
    pub served: SheafStats,
    pub shadow: SheafStats,
    pub strict: SheafStats,
    pub vanished_obstructions: usize,
    pub new_obstructions: usize,
    pub pairs_outside_scope: usize,
}

/// The conflict set.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct ConflictShadow {
    pub min_k: f64,
    pub served: usize,
    pub shadow: usize,
    pub atoms_added: usize,
    pub atoms_removed: usize,
    pub compounds_dropped: usize,
    pub compounds_dropped_with_leaf_conflict: usize,
    pub compounds_dropped_unexplained: usize,
}

/// A mover, weighted by its recall exposure.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct Mover {
    pub claim_id: Uuid,
    pub role: &'static str,
    pub delta: f64,
    pub recall_exposure: u64,
    pub weight: f64,
}

/// The report's summary.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct Summary {
    pub claims: usize,
    pub by_role: BTreeMap<&'static str, usize>,
    pub abs_delta: BTreeMap<&'static str, Quantiles>,
    pub vacate: usize,
    pub residue: usize,
    pub fold_mismatch: FoldMismatch,
    pub compound_confirmed_set: ByMode<usize>,
    pub replay: ByMode<ReplaySummary>,
    pub strict_entry: StrictEntry,
    pub sheaf: SheafShadow,
    pub conflicts: ConflictShadow,
    pub top_movers: Vec<Mover>,
}

/// Run the report: every claim in scope as `report_viewer` reads it, recall
/// events as `events_viewer` reads them. Each claim's line goes to `sink`.
///
/// # Errors
/// A database read, or a fold that fails.
pub async fn run_report<F>(
    _pool: &PgPool,
    _report_viewer: &Viewer,
    _events_viewer: &Viewer,
    _opts: &ReportOptions,
    _sink: F,
) -> Result<Summary, String>
where
    F: FnMut(&ClaimLine) -> Result<(), String>,
{
    Ok(Summary::default())
}
