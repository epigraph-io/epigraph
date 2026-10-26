//! The belief shadow report (atom-level belief program, SPEC §1.3, §3.2,
//! §7.1, §8, §10.4): what every claim serves today beside what it would
//! serve under the atom fold (AEF) and the per-viewer compound derivation,
//! and the corpus statistics the cutover is reviewed on.
//!
//! # It writes nothing
//!
//! Every read runs on ONE connection whose session is set
//! `default_transaction_read_only`, so a write anywhere on the report's call
//! graph is refused by the database rather than trusted to be absent. The
//! binary runs on its maintenance session's own connection (the one its
//! bypass viewer was issued with) and sets the session back when the run
//! ends; [`run_report`] closes the connection it acquired instead.
//!
//! # Two viewers
//!
//! Claim values are computed as the report viewer: the maintenance viewer
//! for corpus statistics, or the anonymous viewer for the public floor (SPEC
//! §8 T2). Recall events are always read as the events viewer (maintenance):
//! `recall_events` is keyed on the querying agent, so an anonymous read would
//! return almost none of them and the replay would pass vacuously. A returned
//! id the report viewer cannot read is counted `unresolved`, never as a loss.
//!
//! # Today and the candidate (SPEC §3.2, §7.1)
//!
//! * Today: the gate score is the served cache (else `truth_value`),
//!   `contested` is a live refuting edge, `confirmed` is uncontested and a
//!   score of at least [`confirmed_score`].
//! * An atom with AEF input the viewer can see (P1), whose role the target
//!   fold covers, gates and ranks on its fold's `BetP`; any other atom keeps
//!   today's value (a kept cache is served `Legacy`).
//! * A compound gates on its derived NR, ranks on its derived Bel, is
//!   `confirmed` on Bel .75 (a compound with one visible leaf takes that
//!   leaf's partition) and is contested when a visible leaf is, when NR is
//!   under .5, when its `not_all` valuation is at least .5, or on a live
//!   refuting edge of its own. Strict serves the derivation (a profile for a
//!   spine); progressive serves it only when the compound is ready (no
//!   visible leaf served `Legacy`) and today's value otherwise.
//! * A spine compound's profile Bel is a Fréchet floor, not a conjunction
//!   (SPEC §2.2), so every compound tally (role counts and |Δ| quantiles,
//!   vacates, the `confirmed` set, the strict-entry replay, top movers)
//!   keeps spines (`compound_spine`) apart from conjunctions.
//!
//! # Where the SQL lives
//!
//! The few reads written here (a page of claim ids, the cache columns, the
//! per-claim conflict K, the `attributed_v1` row ids) are the report's own and
//! feed nothing else. The cache read dispatches on role in the same function
//! (it reads `claim_role::roles_batch`), so the role-blind belief-read
//! ratchet (SPEC §7.3) classifies it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use epigraph_db::repos::claim_role::{self, ClaimRole};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, MassFunctionRepository};
use epigraph_engine::atom_items::{
    atom_axiom_rows, atom_fold_under, AtomFoldMode, AxiomMode, AxiomRow, CompoundSourceEdges,
};
use epigraph_engine::belief_query::FramedBeliefContext;
use epigraph_engine::belief_view::{Basis, BeliefView};
use epigraph_engine::compound_belief::{
    derive_compound_belief_batch, derive_compound_conjunction_batch,
};
use epigraph_engine::source_dependence::ATTRIBUTED_METHOD;

/// The `confirmed` partition's threshold (SPEC §3.2): the served belief
/// profile's `gates.confirmed_score` (built-in default 0.75), the same
/// parameter recall's `confirmed` partition reads, so the report's `today`
/// replay and recall cannot disagree on what "confirmed" means.
#[must_use]
pub fn confirmed_score() -> f64 {
    epigraph_engine::belief_profile::BeliefProfile::served()
        .gates
        .confirmed_score
}
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

/// A compound's product-frame `BetP` beside today's gate score: its own line
/// of the decomposition, never a stage (SPEC §10.4).
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize)]
pub struct BetpLine {
    pub today: f64,
    pub derived: f64,
    pub delta: f64,
}

/// A claim's drift decomposition (SPEC §10.4): an atom's in `BetP` from S0
/// (or today) to its AEF fold, a compound's in Bel from today's own-fold to
/// its derivation (see `compound_drift`).
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct Drift {
    /// What the stages are measured in: `betp` for an atom (its fold's
    /// `BetP`), `bel` for a compound (its rank key). The two never sum.
    pub unit: &'static str,
    pub start: f64,
    pub stages: BTreeMap<&'static str, Option<f64>>,
    pub components: BTreeMap<&'static str, Option<f64>>,
    #[serde(rename = "final")]
    pub final_value: f64,
    pub total: f64,
    /// A compound's product-frame `BetP` line; `None` for an atom.
    pub product_frame_betp: Option<BetpLine>,
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
    /// The strict candidate's `BetP` less today's gate score.
    pub delta: f64,
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

/// The served value against the atom's own fold (SPEC §1.3), over the atoms
/// whose fold this run serves: an atom with AEF input the viewer can see,
/// whose role the target fold covers. (A leaf under `aef_standalone` keeps
/// today's value; its line still shows its gap, but it is no mismatch of the
/// run's.)
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize)]
pub struct FoldMismatch {
    /// Atoms with AEF input the viewer can see, whose fold the run serves.
    pub p1_atoms: usize,
    /// Of those, the ones whose served Bel, Pl or `BetP` differs from the
    /// fold by more than [`MISMATCH_TOLERANCE`].
    pub mismatched: usize,
    pub share: f64,
    /// Whether this run is the one the one-atom-value-on-prod criterion
    /// reads (SPEC §1.3): the anonymous viewer under the `aef` target fold.
    pub measures_floor: bool,
}

/// Sheaf cohomology under one set of intervals.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize)]
pub struct SheafStats {
    pub edge_count: usize,
    /// The share of the coverage denominator (SPEC §1.3) this set covers.
    pub coverage: f64,
    pub h1: f64,
    pub h1_normalized: f64,
    pub conflict_h1: f64,
    pub ignorance_h1: f64,
    pub open_world_h1: f64,
    pub obstructed: usize,
}

/// How the obstructions of one candidate mode differ from today's, each
/// mapped to a cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct ObstructionChanges {
    /// Evaluated both ways; the candidate's values resolve it.
    pub vanished_on_value: usize,
    /// A compound-ended edge the mode drops because atom edges replaced it.
    pub vanished_edge_replaced: usize,
    /// A compound-ended edge the mode drops with no replacement.
    pub vanished_edge_dropped: usize,
    /// An endpoint has no value under the candidate.
    pub vanished_endpoint_without_value: usize,
    /// Evaluated both ways; the candidate's values raise it.
    pub new_on_value: usize,
    /// Not evaluated today (an endpoint had no served value) and obstructed
    /// under the candidate.
    pub new_endpoint_gained_value: usize,
}

/// The sheaf shadow (see `sheaf_shadow`).
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct SheafShadow {
    /// Today's cohomology computed exactly as the sheaf tool computes it
    /// (coverage not computed: 1).
    pub served_as_tool: SheafStats,
    /// Today's cohomology like for like with the candidate (`mass_on_missing`
    /// as the open-world mass).
    pub served: SheafStats,
    pub progressive: SheafStats,
    pub strict: SheafStats,
    pub pairs_outside_scope: usize,
    /// The coverage denominator (SPEC §1.3).
    pub coverage_denominator: usize,
    /// Atom-to-atom edges today's cohomology evaluates.
    pub atom_atom_edges: usize,
    /// Edges with a compound end.
    pub compound_ended_edges: usize,
    /// Of those, the ones atom edges replaced (SPEC §7.1 P4).
    pub compound_ended_replaced: usize,
    pub progressive_changes: ObstructionChanges,
    pub strict_changes: ObstructionChanges,
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

/// Claims whose served value becomes vacuous (Bel under .01, Pl over .99)
/// where it was not (SPEC §10.4 vacate count).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Vacate {
    pub atoms: usize,
    /// Conjunction compounds.
    pub compounds: usize,
    /// Spine compounds (served a profile).
    pub spines: usize,
}

/// What a report ran under, so two reports (before and after a wave) can be
/// compared. `compound_source_edges` is this process's
/// `EPIGRAPH_COMPOUND_SOURCE_EDGES`, which the atom reader applies.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct RunSettings {
    pub target_fold: &'static str,
    pub compound_source_edges: &'static str,
    pub since: Option<DateTime<Utc>>,
    /// `all` or `ids`.
    pub scope: &'static str,
    /// How many ids an `ids` scope listed.
    pub scope_ids: Option<usize>,
    pub page_size: usize,
    pub top: usize,
    pub rank_threshold: usize,
    pub conflict_min_k: f64,
    pub sheaf_threshold: f64,
    pub owner_preview: bool,
    pub s0_given: bool,
    pub graph_view_exposure_given: bool,
    pub confirmed_score: f64,
    pub default_min_truth: f64,
}

impl RunSettings {
    fn of(opts: &ReportOptions) -> Self {
        let (scope, scope_ids) = match &opts.scope {
            Scope::All => ("all", None),
            Scope::Ids(ids) => ("ids", Some(ids.len())),
        };
        Self {
            target_fold: match opts.target_fold {
                AtomFoldMode::Legacy => "legacy",
                AtomFoldMode::AefStandalone => "aef_standalone",
                AtomFoldMode::Aef => "aef",
            },
            compound_source_edges: match CompoundSourceEdges::current() {
                CompoundSourceEdges::Frozen => "frozen",
                CompoundSourceEdges::Excluded => "excluded",
            },
            since: Some(opts.since),
            scope,
            scope_ids,
            page_size: opts.page_size,
            top: opts.top,
            rank_threshold: opts.rank_threshold,
            conflict_min_k: opts.conflict_min_k,
            sheaf_threshold: opts.sheaf_threshold,
            owner_preview: opts.owner_preview,
            s0_given: opts.s0.is_some(),
            graph_view_exposure_given: opts.graph_view_exposure.is_some(),
            confirmed_score: confirmed_score(),
            default_min_truth: DEFAULT_MIN_TRUTH,
        }
    }
}

/// The report's summary.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct Summary {
    pub settings: RunSettings,
    pub claims: usize,
    pub by_role: BTreeMap<&'static str, usize>,
    pub abs_delta: BTreeMap<&'static str, Quantiles>,
    pub vacate: Vacate,
    pub residue: usize,
    pub fold_mismatch: FoldMismatch,
    /// Conjunction compounds in the `confirmed` set.
    pub compound_confirmed_set: ByMode<usize>,
    /// Spine compounds in the `confirmed` set (on their profile's floor).
    pub spine_confirmed_set: ByMode<usize>,
    /// Whether the compound statistics read the leaf values the candidate
    /// serves: only under the `aef` target fold. Under another fold every
    /// compound number (lines, the confirmed sets, vacates, the replay's
    /// compound flips, the strict-entry replay) reads leaf folds the run does
    /// not serve, and belongs to a later wave than the one being reviewed.
    pub compound_statistics_valid: bool,
    pub replay: ByMode<ReplaySummary>,
    /// The strict-entry replay over conjunction compounds.
    pub strict_entry: StrictEntry,
    /// The same over spine compounds.
    pub strict_entry_spine: StrictEntry,
    pub sheaf: SheafShadow,
    pub conflicts: ConflictShadow,
    pub top_movers: Vec<Mover>,
}

// ── per-claim evaluation ────────────────────────────────────────────────────

/// A claim's cache columns as served.
#[derive(Debug, Clone, Copy, Default)]
struct Cache {
    bel: Option<f64>,
    pl: Option<f64>,
    betp: Option<f64>,
    missing: Option<f64>,
    frame: Option<Uuid>,
}

/// What the report reads for one claim before evaluating it.
#[derive(Debug, Clone, Copy)]
struct Base {
    role: ClaimRole,
    cache: Cache,
    /// Today's gate score.
    score: f64,
    /// A live refuting edge into it, as the viewer sees it.
    contested: bool,
}

/// One candidate value, kept per claim for the corpus passes.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
struct Cand {
    basis: &'static str,
    gate: f64,
    rank: f64,
    confirmed: bool,
    contested: bool,
    iv: Interval,
    /// The claim has a value the sheaf can read: a computed candidate, or a
    /// cached `BetP` today (the served cohomology's own requirement).
    valued: bool,
}

impl Cand {
    /// Today's value of a claim.
    fn today(b: &Base) -> Self {
        let s = b.score;
        Self {
            basis: "served",
            gate: s,
            rank: s,
            confirmed: !b.contested && s >= confirmed_score(),
            contested: b.contested,
            iv: Interval {
                bel: b.cache.bel.unwrap_or(s),
                pl: b.cache.pl.unwrap_or(s),
                betp: b.cache.betp.unwrap_or(s),
                open_world: b.cache.missing.unwrap_or(0.0),
            },
            valued: b.cache.betp.is_some(),
        }
    }

    /// Whether the value is one this report computed (not today's, kept).
    fn computed(&self) -> bool {
        matches!(self.basis, "axiom" | "derived" | "profile")
    }

    fn public(&self) -> Candidate {
        Candidate {
            basis: self.basis,
            gate: self.gate,
            rank: self.rank,
            confirmed: self.confirmed,
            contested: self.contested,
            interval: self.iv,
        }
    }
}

/// An evaluated claim: its line's parts and the compact record the corpus
/// passes keep.
#[derive(Debug, Clone)]
struct Eval {
    aef: Option<AefValue>,
    drift: Option<Drift>,
    view: Option<BeliefView>,
    ready: Option<bool>,
    progressive: Cand,
    strict: Cand,
    served_vs_fold: Option<f64>,
    /// The fold is what this run serves (P1, and the target fold covers the
    /// role): the atom counts in the fold mismatch.
    fold_served: bool,
    /// An atom with no AEF input whose cache is kept.
    residue: bool,
}

/// The ids of a page, every claim the viewer can read, after `after`.
async fn next_page(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    after: Option<Uuid>,
    limit: usize,
) -> Result<Vec<Uuid>, String> {
    let sql = viewer.splice(
        "SELECT c.id FROM claims c \
          WHERE COALESCE(c.is_current, true) \
            AND ($1::uuid IS NULL OR c.id > $1) /* {VISIBILITY:c} */ \
          ORDER BY c.id LIMIT $2",
        3,
    );
    let mut q = sqlx::query_scalar::<_, Uuid>(&sql)
        .bind(after)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX));
    if let Some(g) = viewer.group_bind() {
        q = q.bind(g);
    }
    q.fetch_all(&mut *conn)
        .await
        .map_err(|e| format!("claim page: {e}"))
}

/// Role, served cache, gate score and contested flag of each id the viewer
/// can read. The cache read dispatches on role in this function.
async fn read_bases(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, Base>, String> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let roles = claim_role::roles_batch(&mut *conn, viewer, ids)
        .await
        .map_err(|e| format!("roles_batch: {e}"))?;
    let visible: Vec<Uuid> = ids
        .iter()
        .filter(|id| roles.contains_key(id))
        .copied()
        .collect();
    let sql = viewer.splice(
        "SELECT c.id, c.belief, c.plausibility, c.pignistic_prob, c.mass_on_missing, \
                c.belief_frame_id \
           FROM claims c WHERE c.id = ANY($1) /* {VISIBILITY:c} */",
        2,
    );
    type Row = (
        Uuid,
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<Uuid>,
    );
    let mut q = sqlx::query_as::<_, Row>(&sql).bind(&visible);
    if let Some(g) = viewer.group_bind() {
        q = q.bind(g);
    }
    let caches: HashMap<Uuid, Cache> = q
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| format!("cache columns: {e}"))?
        .into_iter()
        .map(|(id, bel, pl, betp, missing, frame)| {
            (
                id,
                Cache {
                    bel,
                    pl,
                    betp,
                    missing,
                    frame,
                },
            )
        })
        .collect();
    let scores = ClaimRepository::effective_belief_batch(&mut *conn, viewer, &visible)
        .await
        .map_err(|e| format!("effective_belief_batch: {e}"))?;
    let disputes = ClaimRepository::dispute_batch(&mut *conn, viewer, &visible)
        .await
        .map_err(|e| format!("dispute_batch: {e}"))?;
    Ok(visible
        .into_iter()
        .filter_map(|id| {
            // A claim deleted between the reads is skipped.
            let score = *scores.get(&id)?;
            Some((
                id,
                Base {
                    role: roles[&id],
                    cache: caches.get(&id).copied().unwrap_or_default(),
                    score,
                    contested: disputes.get(&id).is_some_and(|d| d.dispute_count > 0),
                },
            ))
        })
        .collect())
}

/// Whether the target fold folds an atom of this role with the AEF.
const fn covers(fold: AtomFoldMode, role: ClaimRole) -> bool {
    match role {
        ClaimRole::Standalone => matches!(fold, AtomFoldMode::AefStandalone | AtomFoldMode::Aef),
        ClaimRole::Atom => matches!(fold, AtomFoldMode::Aef),
        _ => false,
    }
}

/// The largest gap between the served Bel, Pl and `BetP` and the fold's. A
/// column the cache does not hold counts as the full gap, 1.
fn served_vs_fold(c: &Cache, f: &epigraph_engine::atom_items::EvidencedInterval) -> f64 {
    let gap = |served: Option<f64>, fold: f64| served.map_or(1.0, |s| (s - fold).abs());
    gap(c.bel, f.belief())
        .max(gap(c.pl, f.plausibility()))
        .max(gap(c.betp, f.pignistic_prob()))
}

/// The `attributed_v1` rows among `rows`, as the viewer sees them.
async fn attributed_rows(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    rows: &[Uuid],
) -> Result<HashSet<Uuid>, String> {
    if rows.is_empty() {
        return Ok(HashSet::new());
    }
    let sql = viewer.splice(
        "SELECT mf.id FROM mass_functions mf \
          WHERE mf.id = ANY($1) AND mf.combination_method = $2 /* {VISIBILITY:mf} */",
        3,
    );
    let mut q = sqlx::query_scalar::<_, Uuid>(&sql)
        .bind(rows)
        .bind(ATTRIBUTED_METHOD);
    if let Some(g) = viewer.group_bind() {
        q = q.bind(g);
    }
    Ok(q.fetch_all(&mut *conn)
        .await
        .map_err(|e| format!("attributed rows: {e}"))?
        .into_iter()
        .collect())
}

/// The drift decomposition's stages, in telescoping order (SPEC §10.4). The
/// ones this report cannot separate are `null`, and the next separable
/// stage absorbs them; `recompute_betp --dry-run` gives the full one. Every
/// stage is present, so a reader can tell "not separated here" (null) from
/// "not a stage" (absent): (0c), the part of the served value a monotonicity
/// clamp holds up, is null and folded into the next separable stage.
const DRIFT_STAGES: [&str; 11] = ["0", "0b", "0c", "1", "1'", "2", "3", "3a", "3b", "3c", "4"];

/// Each stage after the first, less the last separable stage before it
/// (from `start`); a null stage is null and carries nothing, so the next
/// separable stage absorbs it and the components sum to the last stage less
/// `start`.
fn telescope(
    stages: &BTreeMap<&'static str, Option<f64>>,
    order: &[&'static str],
    start: f64,
) -> BTreeMap<&'static str, Option<f64>> {
    let mut prev = start;
    order
        .iter()
        .skip(1)
        .map(|key| {
            let c = stages[key].map(|v| {
                let d = v - prev;
                prev = v;
                d
            });
            (*key, c)
        })
        .collect()
}

/// A compound's drift stages, in Bel (SPEC §10.4): (a) the legacy own-fold,
/// (b) R-DEP without attribution, (c) R-DEP with attribution, (d) (c) met by
/// the `not_all` valuation.
const COMPOUND_DRIFT_STAGES: [&str; 4] = ["a", "b", "c", "d"];

/// One compound's drift decomposition, in Bel (its rank key):
///
/// * (a) today's own-fold: the cache's Bel (else today's gate score, for a
///   compound with no cache);
/// * (b) R-DEP over its leaves without `attributed_v1` rows: null, the
///   derivation reads the leaves' rows as they are, so (c) absorbs it;
/// * (c) R-DEP over its leaves as they are, before `not_all`
///   (`conjunction`, read only for a compound with a `not_all` mass; with
///   none, (c) is (d));
/// * (d) the served derivation: (c) met by `not_all` (a spine's profile
///   floor).
///
/// The product-frame `BetP` against today's gate score is its own line,
/// never a stage: it is not in Bel. A snapshot (S0) holds `BetP`, so it does
/// not start a compound's decomposition.
fn compound_drift(base: &Base, view: &BeliefView, conjunction: Option<&BeliefView>) -> Drift {
    let start = base.cache.bel.unwrap_or(base.score);
    let stages: BTreeMap<&'static str, Option<f64>> = [
        ("a", Some(start)),
        ("b", None),
        ("c", Some(conjunction.map_or(view.bel, |c| c.bel))),
        ("d", Some(view.bel)),
    ]
    .into_iter()
    .collect();
    let components = telescope(&stages, &COMPOUND_DRIFT_STAGES, start);
    Drift {
        unit: "bel",
        start,
        stages,
        components,
        final_value: view.bel,
        total: view.bel - start,
        product_frame_betp: Some(BetpLine {
            today: base.score,
            derived: view.betp,
            delta: view.betp - base.score,
        }),
    }
}

/// One atom's drift decomposition, in `BetP` (see [`Drift`]):
///
/// * (0) the snapshot's value, when one was given;
/// * (0b) today's gate score;
/// * (0c) the clamp residue: null (not separable here);
/// * (1) the owner-rule recompute (what the held apply would write; today's
///   value where it would write nothing), only with `owner_preview`;
/// * (3c) the AEF over the current rows without `attributed_v1` (paper-key
///   grouping, compound-source rows as the process reads them); today's
///   value when no other row is left (the writer keeps the cache);
/// * (4) the AEF over every row.
#[allow(clippy::too_many_arguments)]
async fn drift(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    ctx: &FramedBeliefContext,
    opts: &ReportOptions,
    id: Uuid,
    base: &Base,
    rows: &[AxiomRow],
    attributed: &HashSet<Uuid>,
    fold_betp: f64,
) -> Result<Drift, String> {
    let mut stages: BTreeMap<&'static str, Option<f64>> =
        DRIFT_STAGES.iter().map(|k| (*k, None)).collect();
    let s0 = opts.s0.as_ref().and_then(|m| m.get(&id).copied());
    stages.insert("0", s0);
    stages.insert("0b", Some(base.score));
    if opts.owner_preview {
        let owner = MassFunctionRepository::cache_owner_frame_for_claim(&mut *conn, viewer, id)
            .await
            .map_err(|e| format!("cache_owner_frame_for_claim: {e}"))?;
        let v = match owner {
            Some(frame) => epigraph_engine::edge_factor::preview_claim_belief_on_frame(
                &mut *conn, viewer, id, frame,
            )
            .await?
            .map_or(base.score, |p| p.pignistic_prob),
            None => base.score,
        };
        stages.insert("1", Some(v));
    }
    let without: Vec<AxiomRow> = rows
        .iter()
        .filter(|r| !attributed.contains(&r.row_id()))
        .cloned()
        .collect();
    let v3c = if without.is_empty() {
        base.score
    } else {
        atom_fold_under(&without, ctx.profile())?.pignistic_prob()
    };
    stages.insert("3c", Some(v3c));
    stages.insert("4", Some(fold_betp));

    let start = s0.unwrap_or(base.score);
    let components = telescope(&stages, &DRIFT_STAGES, start);
    Ok(Drift {
        unit: "betp",
        start,
        stages,
        components,
        final_value: fold_betp,
        total: fold_betp - start,
        product_frame_betp: None,
    })
}

/// Evaluate atoms and standalones (SPEC §3.2 atom column, §7.1 P1).
async fn eval_atoms(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    ctx: &FramedBeliefContext,
    opts: &ReportOptions,
    atoms: &[(Uuid, Base)],
    with_drift: bool,
) -> Result<HashMap<Uuid, Eval>, String> {
    let ids: Vec<Uuid> = atoms.iter().map(|(id, _)| *id).collect();
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = atom_axiom_rows(&mut *conn, viewer, &ids, AxiomMode::Display, ctx).await?;
    let attributed = if with_drift {
        let all: Vec<Uuid> = rows.values().flatten().map(AxiomRow::row_id).collect();
        attributed_rows(conn, viewer, &all).await?
    } else {
        HashSet::new()
    };
    let mut out = HashMap::with_capacity(atoms.len());
    for (id, base) in atoms {
        let today = Cand::today(base);
        let eval = match rows.get(id).filter(|r| !r.is_empty()) {
            Some(rs) => {
                let f = atom_fold_under(rs, ctx.profile())?;
                let aef = AefValue {
                    bel: f.belief(),
                    pl: f.plausibility(),
                    betp: f.pignistic_prob(),
                    nr: (f.plausibility() + f.mass_on_missing()).min(1.0),
                    conflict: f.mass_on_conflict(),
                    open_world: f.mass_on_missing(),
                    items: f.items(),
                };
                let covered = covers(opts.target_fold, base.role);
                let cand = if covered {
                    Cand {
                        basis: "axiom",
                        gate: aef.betp,
                        rank: aef.betp,
                        confirmed: !base.contested && aef.betp >= confirmed_score(),
                        contested: base.contested,
                        iv: Interval {
                            bel: aef.bel,
                            pl: aef.pl,
                            betp: aef.betp,
                            open_world: aef.open_world,
                        },
                        valued: true,
                    }
                } else {
                    today
                };
                let drift = if covered && with_drift {
                    Some(
                        drift(
                            conn,
                            viewer,
                            ctx,
                            opts,
                            *id,
                            base,
                            rs,
                            &attributed,
                            aef.betp,
                        )
                        .await?,
                    )
                } else {
                    None
                };
                Eval {
                    aef: Some(aef),
                    drift,
                    view: None,
                    ready: None,
                    progressive: cand,
                    strict: cand,
                    served_vs_fold: Some(served_vs_fold(&base.cache, &f)),
                    fold_served: covered,
                    residue: false,
                }
            }
            None => {
                let kept = base.cache.bel.is_some() && base.cache.pl.is_some();
                let cand = Cand {
                    basis: if kept { "legacy" } else { "unproven" },
                    ..today
                };
                Eval {
                    aef: None,
                    drift: None,
                    view: None,
                    ready: None,
                    progressive: cand,
                    strict: cand,
                    served_vs_fold: None,
                    fold_served: false,
                    residue: kept,
                }
            }
        };
        out.insert(*id, eval);
    }
    Ok(out)
}

/// Evaluate compounds (SPEC §3.2 compound column, §3.6, §7.1 P2).
async fn eval_compounds(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    ctx: &FramedBeliefContext,
    opts: &ReportOptions,
    compounds: &[(Uuid, Base)],
) -> Result<(HashMap<Uuid, Eval>, HashMap<Uuid, Vec<Uuid>>), String> {
    let ids: Vec<Uuid> = compounds.iter().map(|(id, _)| *id).collect();
    if ids.is_empty() {
        return Ok((HashMap::new(), HashMap::new()));
    }
    let views = derive_compound_belief_batch(&mut *conn, viewer, &ids, ctx).await?;
    // Drift stage (c), the conjunction before `not_all`, for the compounds
    // that carry a `not_all` mass (for the rest it is the served value).
    let refuted: Vec<Uuid> = views
        .iter()
        .filter(|(_, v)| v.derived.as_ref().is_some_and(|d| d.not_all.m > 0.0))
        .map(|(id, _)| *id)
        .collect();
    let conjunctions = if refuted.is_empty() {
        HashMap::new()
    } else {
        derive_compound_conjunction_batch(&mut *conn, viewer, &refuted, ctx).await?
    };
    let closures = claim_role::leaf_closure_batch(&mut *conn, viewer, &ids)
        .await
        .map_err(|e| format!("leaf_closure_batch: {e}"))?;
    let leaves: Vec<Uuid> = closures
        .values()
        .flatten()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let leaf_disputes = ClaimRepository::dispute_batch(&mut *conn, viewer, &leaves)
        .await
        .map_err(|e| format!("dispute_batch: {e}"))?;

    // A compound with one visible leaf takes that leaf's partition.
    let singles: Vec<Uuid> = closures
        .values()
        .filter(|l| l.len() == 1)
        .map(|l| l[0])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let single_bases = read_bases(conn, viewer, &singles).await?;
    let single_atoms: Vec<(Uuid, Base)> = single_bases
        .into_iter()
        .filter(|(_, b)| matches!(b.role, ClaimRole::Atom | ClaimRole::Standalone))
        .collect();
    let single_evals = eval_atoms(conn, viewer, ctx, opts, &single_atoms, false).await?;

    let mut out = HashMap::with_capacity(compounds.len());
    for (id, base) in compounds {
        let today = Cand::today(base);
        let Some(view) = views.get(id) else {
            out.insert(
                *id,
                Eval {
                    aef: None,
                    drift: None,
                    view: None,
                    ready: None,
                    progressive: today,
                    strict: today,
                    served_vs_fold: None,
                    fold_served: false,
                    residue: false,
                },
            );
            continue;
        };
        let leaves = closures.get(id).map(Vec::as_slice).unwrap_or_default();
        let not_all = view.derived.as_ref().map_or(0.0, |d| d.not_all.m);
        let legacy_leaves = view
            .derived
            .as_ref()
            .map(|d| d.legacy_leaves)
            .or_else(|| view.profile.as_ref().map(|p| p.legacy_leaves))
            .unwrap_or(0);
        let contested = base.contested
            || leaves
                .iter()
                .any(|l| leaf_disputes.get(l).is_some_and(|d| d.dispute_count > 0))
            || view.nr < 0.5
            || not_all >= 0.5;
        let proven = match leaves {
            [only] => single_evals
                .get(only)
                .map_or(view.bel >= confirmed_score(), |e| e.strict.confirmed),
            _ => view.bel >= confirmed_score(),
        };
        let strict = Cand {
            basis: if view.basis == Basis::Profile {
                "profile"
            } else {
                "derived"
            },
            gate: view.nr,
            rank: view.bel,
            confirmed: !contested && proven,
            contested,
            iv: Interval {
                bel: view.bel,
                pl: view.pl,
                betp: view.betp,
                open_world: (view.nr - view.pl).max(0.0),
            },
            valued: true,
        };
        let ready = legacy_leaves == 0;
        let progressive = if ready {
            strict
        } else {
            Cand {
                basis: "legacy",
                ..today
            }
        };
        out.insert(
            *id,
            Eval {
                aef: None,
                drift: Some(compound_drift(base, view, conjunctions.get(id))),
                view: Some(view.clone()),
                ready: Some(ready),
                progressive,
                strict,
                served_vs_fold: None,
                fold_served: false,
                residue: false,
            },
        );
    }
    Ok((out, closures))
}

// ── the corpus passes ───────────────────────────────────────────────────────

/// Quantiles by nearest rank.
fn quantiles(mut v: Vec<f64>) -> Quantiles {
    v.sort_by(f64::total_cmp);
    let n = v.len();
    if n == 0 {
        return Quantiles::default();
    }
    let at = |q: f64| {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let rank = (q * n as f64).ceil() as usize;
        v[rank.clamp(1, n) - 1]
    };
    Quantiles {
        n,
        p50: at(0.5),
        p90: at(0.9),
        p99: at(0.99),
        max: v[n - 1],
    }
}

/// The key a claim is tallied under: its role, with spine compounds (served
/// a profile, SPEC §2.2) apart from conjunctions.
const fn role_key(role: ClaimRole) -> &'static str {
    match role {
        ClaimRole::Compound { spine: true } => "compound_spine",
        r => r.as_sql(),
    }
}

/// What the corpus passes keep per claim.
#[derive(Debug, Clone, Copy)]
struct Rec {
    compound: bool,
    /// A spine compound.
    spine: bool,
    today: Cand,
    progressive: Cand,
    strict: Cand,
    recall_exposure: u64,
    graph_view_exposure: Option<u64>,
    /// In the conflict set today (a stored row's K at least the threshold).
    conflict_served: bool,
    /// In the conflict set under strict.
    conflict_shadow: bool,
}

/// One recall event, as the replay reads it.
#[derive(Debug, Clone)]
struct Event {
    id: Uuid,
    min_truth: f64,
    /// In the order the recall returned them.
    returned: Vec<Uuid>,
}

/// Every recall event created in `[since, until]`, as `viewer` reads them
/// (the same visibility rule `RecallEventRepository::list` applies).
/// `until` is fixed at the run's start, so events logged during the run do
/// not shift the pages. Pages are a keyset on `(created_at, id)`, newest
/// first: events logged in one statement share `created_at`, and an OFFSET
/// over a sort key with ties may skip one across a page boundary.
async fn read_events(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<Vec<Event>, String> {
    const PAGE: i64 = 500;
    let sql = viewer.splice(
        "SELECT r.id, r.params, r.returned_claim_ids, r.created_at \
           FROM recall_events r \
          WHERE r.created_at >= $1 AND r.created_at <= $2 \
            AND ($3::timestamptz IS NULL OR (r.created_at, r.id) < ($3, $4::uuid)) \
            /* {VISIBILITY:r} */ \
          ORDER BY r.created_at DESC, r.id DESC \
          LIMIT $5",
        6,
    );
    type Row = (Uuid, serde_json::Value, Vec<Uuid>, DateTime<Utc>);
    let mut out = Vec::new();
    let mut after: Option<(DateTime<Utc>, Uuid)> = None;
    loop {
        let mut q = sqlx::query_as::<_, Row>(&sql)
            .bind(since)
            .bind(until)
            .bind(after.map(|(t, _)| t))
            .bind(after.map(|(_, id)| id))
            .bind(PAGE);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| format!("recall_events: {e}"))?;
        let n = rows.len();
        for (id, params, returned, created_at) in rows {
            after = Some((created_at, id));
            let min_truth = params
                .get("min_truth")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(DEFAULT_MIN_TRUTH);
            out.push(Event {
                id,
                min_truth,
                returned,
            });
        }
        if i64::try_from(n).unwrap_or(0) < PAGE {
            break;
        }
    }
    Ok(out)
}

/// How many events returned each claim (once per event).
fn recall_exposure(events: &[Event]) -> HashMap<Uuid, u64> {
    let mut out: HashMap<Uuid, u64> = HashMap::new();
    for e in events {
        for id in e.returned.iter().collect::<HashSet<_>>() {
            *out.entry(*id).or_default() += 1;
        }
    }
    out
}

/// Count a two-way status change from `before` to `after`.
fn flip(f: &mut Flips, before: bool, after: bool, weight: u64) {
    match (before, after) {
        (false, true) => f.to += weight,
        (true, false) => f.from += weight,
        _ => {}
    }
}

/// The recall replay under one candidate mode (SPEC §10.4, extended): per
/// event, a returned claim is **lost** when it passes the event's
/// `min_truth` today and fails it under the candidate; one that fails today
/// is `already_failing` (no loss of the cutover's). `confirmed` and
/// `contested` flips are counted per returned occurrence. A returned id with
/// no record (hidden from the report viewer, deleted, or outside the run's
/// scope) is `unresolved`. The share lost is over resolved ids, and the mean
/// is over events that resolved any.
fn replay(events: &[Event], recs: &HashMap<Uuid, Rec>, pick: fn(&Rec) -> &Cand) -> ReplaySummary {
    let mut s = ReplaySummary {
        events: events.len(),
        ..ReplaySummary::default()
    };
    let mut shares = Vec::new();
    for e in events {
        let mut ev = EventReplay {
            event_id: e.id,
            min_truth: e.min_truth,
            returned: e.returned.len(),
            ..EventReplay::default()
        };
        for (pos, id) in e.returned.iter().enumerate() {
            let Some(r) = recs.get(id) else {
                ev.unresolved += 1;
                continue;
            };
            ev.resolved += 1;
            let cand = pick(r);
            if r.today.gate < e.min_truth {
                ev.already_failing += 1;
            } else if cand.gate < e.min_truth {
                ev.lost += 1;
                if pos < 10 {
                    ev.lost_in_first_10 += 1;
                }
            }
            flip(&mut s.confirmed, r.today.confirmed, cand.confirmed, 1);
            flip(&mut s.contested, r.today.contested, cand.contested, 1);
        }
        s.returned += ev.returned;
        s.resolved += ev.resolved;
        s.unresolved += ev.unresolved;
        s.lost += ev.lost;
        s.already_failing += ev.already_failing;
        s.max_lost_in_first_10 = s.max_lost_in_first_10.max(ev.lost_in_first_10);
        if ev.lost_in_first_10 > 1 {
            s.events_losing_more_than_one_in_first_10 += 1;
        }
        if ev.resolved > 0 {
            #[allow(clippy::cast_precision_loss)]
            shares.push(ev.lost as f64 / ev.resolved as f64);
        }
        s.per_event.push(ev);
    }
    if !shares.is_empty() {
        #[allow(clippy::cast_precision_loss)]
        let mean = shares.iter().sum::<f64>() / shares.len() as f64;
        s.mean_share_lost = mean;
        s.max_share_lost = shares.iter().copied().fold(0.0, f64::max);
    }
    s
}

/// Each claim's 1-based place in the corpus ordered by `key`, highest
/// first (ties by id, so the order is total).
fn places(recs: &HashMap<Uuid, Rec>, key: fn(&Rec) -> f64) -> HashMap<Uuid, usize> {
    let mut v: Vec<(&Uuid, f64)> = recs.iter().map(|(id, r)| (id, key(r))).collect();
    v.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(b.0)));
    v.into_iter()
        .enumerate()
        .map(|(i, (id, _))| (*id, i + 1))
        .collect()
}

/// What strict mode changes for the conjunction compounds, or (`spine`) the
/// spine compounds (SPEC §10.4, strict-entry replay): `confirmed` flips and
/// moves of more than `threshold` places in the corpus ordering (`today`:
/// today's gate score; `strict`: strict's rank key, Bel for a compound and
/// the fold's `BetP` for an atom, the ordering SPEC §3.2 serves), each also
/// weighted by recall exposure and, when it was measured, by graph-view
/// exposure.
fn strict_entry(
    recs: &HashMap<Uuid, Rec>,
    (today, strict): (&HashMap<Uuid, usize>, &HashMap<Uuid, usize>),
    spine: bool,
    threshold: usize,
    top: usize,
    graph_view: bool,
) -> StrictEntry {
    let mut se = StrictEntry {
        rank_threshold: threshold,
        confirmed_graph_view_weighted: graph_view.then(Flips::default),
        rank_moves_graph_view_weighted: graph_view.then_some(0),
        ..StrictEntry::default()
    };
    let mut moves = Vec::new();
    for (id, r) in recs.iter().filter(|(_, r)| r.compound && r.spine == spine) {
        se.compounds += 1;
        let (before, after) = (r.today.confirmed, r.strict.confirmed);
        flip(&mut se.confirmed, before, after, 1);
        flip(
            &mut se.confirmed_recall_weighted,
            before,
            after,
            r.recall_exposure,
        );
        if let (Some(f), Some(g)) = (
            se.confirmed_graph_view_weighted.as_mut(),
            r.graph_view_exposure,
        ) {
            flip(f, before, after, g);
        }
        let (from, to) = (today[id], strict[id]);
        let moved = from.abs_diff(to);
        if moved > threshold {
            se.rank_moves_over_threshold += 1;
            se.rank_moves_recall_weighted += r.recall_exposure;
            if let (Some(w), Some(g)) = (
                se.rank_moves_graph_view_weighted.as_mut(),
                r.graph_view_exposure,
            ) {
                *w += g;
            }
        }
        moves.push(RankMove {
            claim_id: *id,
            from,
            to,
            moved,
            recall_exposure: r.recall_exposure,
        });
    }
    #[allow(clippy::cast_precision_loss)]
    let dist = moves.iter().map(|m| m.moved as f64).collect();
    se.rank_move_quantiles = quantiles(dist);
    moves.sort_by(|a, b| {
        b.moved
            .cmp(&a.moved)
            .then(b.recall_exposure.cmp(&a.recall_exposure))
            .then(a.claim_id.cmp(&b.claim_id))
    });
    moves.truncate(top);
    se.top_rank_moves = moves;
    se
}

/// An interval as the sheaf reads it.
fn sheaf_interval(iv: &Interval) -> epigraph_engine::EpistemicInterval {
    let pl = iv.pl.max(iv.bel);
    epigraph_engine::EpistemicInterval::new(iv.bel, pl, iv.open_world)
}

fn sheaf_stats(
    obstructions: Vec<epigraph_engine::CdstSheafObstruction>,
    threshold: f64,
    coverage: f64,
) -> SheafStats {
    let c = epigraph_engine::compute_cdst_cohomology(obstructions, threshold);
    SheafStats {
        edge_count: c.edge_count,
        coverage,
        h1: c.h1,
        h1_normalized: c.h1_normalized,
        conflict_h1: c.conflict_h1,
        ignorance_h1: c.ignorance_h1,
        open_world_h1: c.open_world_h1,
        obstructed: c.obstructions.len(),
    }
}

/// The relationships the sheaf cohomology reads, as
/// `SheafRepository::get_epistemic_edge_pairs` lists them.
const SHEAF_RELATIONSHIPS: &str = "'supports', 'refutes', 'contradicts', 'corroborates', \
     'elaborates', 'specializes', 'generalizes', 'frame_validates'";

/// One live epistemic edge between two claims the viewer can read.
struct SheafEdge {
    id: Uuid,
    source_id: Uuid,
    target_id: Uuid,
    relationship: String,
    /// Replaced by atom edges (SPEC §7.1 P4: `retargeted_to` present and
    /// `retarget_unwired` empty).
    replaced: bool,
    /// The atom edges that replaced it.
    retargeted_to: Vec<Uuid>,
}

/// Every live epistemic edge the viewer can see, WITHOUT the served
/// cohomology's prefilter (both endpoints holding a cached `BetP`): an edge
/// whose endpoint gains a value only under the candidate must be read too.
/// Whether each mode can evaluate an edge is decided from the endpoints'
/// values, per mode.
async fn sheaf_edges(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
) -> Result<Vec<SheafEdge>, String> {
    let sql = viewer.splice(
        &format!(
            "SELECT e.id, e.source_id, e.target_id, e.relationship, \
                    COALESCE(e.properties ? 'retargeted_to' \
                             AND e.properties -> 'retarget_unwired' = '[]'::jsonb, false), \
                    e.properties -> 'retargeted_to' \
               FROM edges e \
               JOIN claims src ON src.id = e.source_id \
               JOIN claims tgt ON tgt.id = e.target_id \
              WHERE e.source_type = 'claim' AND e.target_type = 'claim' \
                AND e.relationship IN ({SHEAF_RELATIONSHIPS}) \
                AND (e.valid_to IS NULL OR e.valid_to > now()) \
                /* {{EDGE_VISIBILITY:e}} */ /* {{VISIBILITY:src}} */ /* {{VISIBILITY:tgt}} */"
        ),
        1,
    );
    type Row = (Uuid, Uuid, Uuid, String, bool, Option<serde_json::Value>);
    let mut q = sqlx::query_as::<_, Row>(&sql);
    if let Some(g) = viewer.group_bind() {
        q = q.bind(g);
    }
    Ok(q.fetch_all(&mut *conn)
        .await
        .map_err(|e| format!("sheaf edges: {e}"))?
        .into_iter()
        .map(
            |(id, source_id, target_id, relationship, replaced, retargeted)| SheafEdge {
                id,
                source_id,
                target_id,
                relationship,
                replaced,
                retargeted_to: retargeted
                    .as_ref()
                    .and_then(serde_json::Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                            .collect()
                    })
                    .unwrap_or_default(),
            },
        )
        .collect())
}

/// One edge's obstruction exactly as the sheaf cohomology tool computes it
/// today: each endpoint's interval from its cached `BetP`, Bel and Pl (`BetP`
/// standing in for a missing one) and its `open_world_mass` column.
fn tool_obstruction(
    ep: &epigraph_db::EpistemicEdgePairRow,
    profile: &epigraph_engine::sheaf::RestrictionProfile,
) -> Option<epigraph_engine::CdstSheafObstruction> {
    let iv = |betp: f64, bel: Option<f64>, pl: Option<f64>, ow: Option<f64>| {
        let s = epigraph_engine::EpistemicInterval::from_scalar(
            betp,
            bel.unwrap_or(betp),
            pl.unwrap_or(betp),
        );
        epigraph_engine::EpistemicInterval::new(s.bel, s.pl, ow.unwrap_or(s.open_world))
    };
    let source = iv(
        ep.source_betp?,
        ep.source_belief,
        ep.source_plausibility,
        ep.source_open_world,
    );
    let target = iv(
        ep.target_betp?,
        ep.target_belief,
        ep.target_plausibility,
        ep.target_open_world,
    );
    Some(epigraph_engine::compute_cdst_edge_inconsistency(
        ep.source_id,
        ep.target_id,
        source,
        target,
        &ep.relationship,
        profile,
    ))
}

/// Why a mode does not evaluate an edge it was evaluated on today.
#[derive(Clone, Copy)]
enum Unevaluated {
    /// A compound-ended edge the mode drops because atom edges replaced it.
    Replaced,
    /// A compound-ended edge the mode drops with no replacement.
    Dropped,
    /// An endpoint has no value under the candidate.
    NoValue,
}

/// Count how one edge's obstruction changed from today to a mode.
/// `served` / `mode` are the edge's inconsistency where it is evaluated;
/// `dropped` is the mode's reason for not evaluating a compound-ended edge.
fn count_change(
    c: &mut ObstructionChanges,
    served: Option<f64>,
    mode: Option<f64>,
    dropped: Option<Unevaluated>,
    threshold: f64,
) {
    let was = served.is_some_and(|x| x > threshold);
    let is = mode.is_some_and(|x| x > threshold);
    if was && !is {
        match (mode, dropped.unwrap_or(Unevaluated::NoValue)) {
            (Some(_), _) => c.vanished_on_value += 1,
            (None, Unevaluated::Replaced) => c.vanished_edge_replaced += 1,
            (None, Unevaluated::Dropped) => c.vanished_edge_dropped += 1,
            (None, Unevaluated::NoValue) => c.vanished_endpoint_without_value += 1,
        }
    } else if !was && is {
        if served.is_some() {
            c.new_on_value += 1;
        } else {
            c.new_endpoint_gained_value += 1;
        }
    }
}

/// The sheaf shadow (SPEC §1.3, §7.2 sheaf row, §10.4).
///
/// * `served_as_tool`: today's cohomology exactly as the sheaf tool computes
///   it (every edge `get_epistemic_edge_pairs` returns, intervals from the
///   cache with `open_world_mass`); restricted to edges with both ends in
///   scope when the run's scope is a list of ids.
/// * `served`: today's cohomology like for like with the candidate: each
///   endpoint's cached Bel and Pl with `mass_on_missing` (the column the
///   single writer fills from the fold's open-world mass, which the
///   candidate interval carries). An edge is evaluated when both endpoints
///   hold a cached `BetP`, as the tool requires.
/// * `progressive`: the candidate's intervals; a compound-ended edge atom
///   edges replaced (P4) is dropped, any other is kept.
/// * `strict`: the candidate's intervals; every compound-ended edge is
///   dropped.
///
/// A candidate interval the report did not compute (a kept cache) is
/// today's, so the comparison isolates value change; a mode evaluates an
/// edge whose endpoints both have a value under it (an atom with AEF input
/// and no cache gains one).
///
/// Coverage (SPEC §1.3) is over a fixed denominator: the atom-atom edges
/// today's cohomology evaluates plus the compound-ended edges atom edges
/// replaced. A mode covers an atom-atom edge it evaluates, and a replaced
/// edge when it evaluates every edge in its `retargeted_to`. A compound-ended
/// edge nothing replaced is outside the denominator: strict's drop of it is
/// an accepted, reported loss (`strict_changes.vanished_edge_dropped`).
///
/// Every obstruction that vanishes or appears under a mode is counted under
/// its cause in `progressive_changes` / `strict_changes`. An edge with an
/// endpoint outside the run's scope is skipped and counted.
async fn sheaf_shadow(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    recs: &HashMap<Uuid, Rec>,
    threshold: f64,
    scoped: bool,
) -> Result<SheafShadow, String> {
    let profile = epigraph_engine::sheaf::RestrictionProfile::scientific();
    let mut out = SheafShadow::default();

    let pairs = epigraph_db::SheafRepository::get_epistemic_edge_pairs(&mut *conn, viewer, None)
        .await
        .map_err(|e| format!("get_epistemic_edge_pairs: {e}"))?;
    let as_tool: Vec<_> = pairs
        .iter()
        .filter(|p| !scoped || (recs.contains_key(&p.source_id) && recs.contains_key(&p.target_id)))
        .filter_map(|p| tool_obstruction(p, &profile))
        .collect();

    // Per edge in scope: (edge, compound-ended, today's / progressive's /
    // strict's inconsistency where the mode evaluates it).
    let mut evaluated: Vec<(
        &SheafEdge,
        bool,
        [Option<epigraph_engine::CdstSheafObstruction>; 3],
    )> = Vec::new();
    let edges = sheaf_edges(conn, viewer).await?;
    for e in &edges {
        let (Some(rs), Some(rt)) = (recs.get(&e.source_id), recs.get(&e.target_id)) else {
            out.pairs_outside_scope += 1;
            continue;
        };
        let compound_end = rs.compound || rt.compound;
        let edge = |s: &Cand, t: &Cand| {
            (s.valued && t.valued).then(|| {
                epigraph_engine::compute_cdst_edge_inconsistency(
                    e.source_id,
                    e.target_id,
                    sheaf_interval(&s.iv),
                    sheaf_interval(&t.iv),
                    &e.relationship,
                    &profile,
                )
            })
        };
        let served = edge(&rs.today, &rt.today);
        let progressive = if compound_end && e.replaced {
            None
        } else {
            edge(&rs.progressive, &rt.progressive)
        };
        let strict = if compound_end {
            None
        } else {
            edge(&rs.strict, &rt.strict)
        };
        if compound_end {
            out.compound_ended_edges += 1;
            out.compound_ended_replaced += usize::from(e.replaced);
        } else if served.is_some() {
            out.atom_atom_edges += 1;
        }
        evaluated.push((e, compound_end, [served, progressive, strict]));
    }

    // Which edges each mode evaluates, for a replaced edge's coverage.
    let mut by_mode: [HashSet<Uuid>; 3] = Default::default();
    for (e, _, obs) in &evaluated {
        for (set, o) in by_mode.iter_mut().zip(obs) {
            if o.is_some() {
                set.insert(e.id);
            }
        }
    }
    out.coverage_denominator = out.atom_atom_edges + out.compound_ended_replaced;
    let mut covered = [0usize; 3];
    for (e, compound_end, obs) in &evaluated {
        for (m, n) in covered.iter_mut().enumerate() {
            let counts = if *compound_end {
                e.replaced
                    && !e.retargeted_to.is_empty()
                    && e.retargeted_to.iter().all(|r| by_mode[m].contains(r))
            } else {
                obs[0].is_some() && obs[m].is_some()
            };
            *n += usize::from(counts);
        }
    }
    #[allow(clippy::cast_precision_loss)]
    let coverage = |n: usize| {
        if out.coverage_denominator == 0 {
            1.0
        } else {
            n as f64 / out.coverage_denominator as f64
        }
    };

    let mut lists: [Vec<epigraph_engine::CdstSheafObstruction>; 3] = Default::default();
    for (e, compound_end, obs) in evaluated {
        let x = |o: &Option<epigraph_engine::CdstSheafObstruction>| {
            o.as_ref().map(|o| o.interval_inconsistency)
        };
        let replaced = (compound_end && e.replaced).then_some(Unevaluated::Replaced);
        count_change(
            &mut out.progressive_changes,
            x(&obs[0]),
            x(&obs[1]),
            replaced,
            threshold,
        );
        count_change(
            &mut out.strict_changes,
            x(&obs[0]),
            x(&obs[2]),
            replaced.or(compound_end.then_some(Unevaluated::Dropped)),
            threshold,
        );
        for (list, o) in lists.iter_mut().zip(obs) {
            list.extend(o);
        }
    }
    let [served, progressive, strict] = lists;
    out.served_as_tool = sheaf_stats(as_tool, threshold, 1.0);
    out.served = sheaf_stats(served, threshold, coverage(covered[0]));
    out.progressive = sheaf_stats(progressive, threshold, coverage(covered[1]));
    out.strict = sheaf_stats(strict, threshold, coverage(covered[2]));
    Ok(out)
}

/// The largest stored `conflict_k` over each claim's rows the viewer can
/// see: the predicate of the conflict scan route (per claim, not per frame),
/// spliced for the viewer.
async fn stored_conflict(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, f64>, String> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let sql = viewer.splice(
        "SELECT mf.claim_id, MAX(mf.conflict_k)::float8 FROM mass_functions mf \
          WHERE mf.claim_id = ANY($1) AND mf.conflict_k IS NOT NULL /* {VISIBILITY:mf} */ \
          GROUP BY mf.claim_id",
        2,
    );
    let mut q = sqlx::query_as::<_, (Uuid, f64)>(&sql).bind(ids);
    if let Some(g) = viewer.group_bind() {
        q = q.bind(g);
    }
    Ok(q.fetch_all(&mut *conn)
        .await
        .map_err(|e| format!("stored conflict: {e}"))?
        .into_iter()
        .collect())
}

/// The conflict set (SPEC §7.2 conflicts row; §10.4): today, claims with a
/// stored K at least `min_k`; under strict, an atom the report folded is in
/// it by its fold's K, any other atom keeps today's membership, and every
/// compound is out. A dropped compound is explained when one of its visible
/// leaves is in the strict set (its K now shows on an atom), and reported
/// otherwise.
fn conflict_shadow(
    recs: &HashMap<Uuid, Rec>,
    dropped: &[(Uuid, Vec<Uuid>)],
    min_k: f64,
) -> ConflictShadow {
    let mut c = ConflictShadow {
        min_k,
        ..ConflictShadow::default()
    };
    for r in recs.values() {
        c.served += usize::from(r.conflict_served);
        c.shadow += usize::from(r.conflict_shadow);
        if !r.compound {
            c.atoms_added += usize::from(!r.conflict_served && r.conflict_shadow);
            c.atoms_removed += usize::from(r.conflict_served && !r.conflict_shadow);
        }
    }
    for (_, leaves) in dropped {
        c.compounds_dropped += 1;
        if leaves
            .iter()
            .any(|l| recs.get(l).is_some_and(|r| r.conflict_shadow))
        {
            c.compounds_dropped_with_leaf_conflict += 1;
        } else {
            c.compounds_dropped_unexplained += 1;
        }
    }
    c
}

/// The running totals of the per-claim pass.
#[derive(Default)]
struct Totals {
    summary: Summary,
    deltas: BTreeMap<&'static str, Vec<f64>>,
    movers: Vec<Mover>,
    recs: HashMap<Uuid, Rec>,
    /// Compounds in today's conflict set, with their visible leaves.
    conflicted_compounds: Vec<(Uuid, Vec<Uuid>)>,
}

impl Totals {
    fn add(
        &mut self,
        id: Uuid,
        base: &Base,
        e: &Eval,
        recall_exposure: u64,
        graph_view_exposure: Option<u64>,
        conflict: (bool, bool),
    ) {
        let role = role_key(base.role);
        let s = &mut self.summary;
        s.claims += 1;
        *s.by_role.entry(role).or_default() += 1;
        let delta = e.strict.iv.betp - base.score;
        self.deltas.entry(role).or_default().push(delta.abs());
        let vacuous = |bel: f64, pl: f64| bel < 0.01 && pl > 0.99;
        let served_vacuous =
            matches!((base.cache.bel, base.cache.pl), (Some(b), Some(p)) if vacuous(b, p));
        let compound = matches!(base.role, ClaimRole::Compound { .. });
        let spine = matches!(base.role, ClaimRole::Compound { spine: true });
        if e.strict.computed() && vacuous(e.strict.iv.bel, e.strict.iv.pl) && !served_vacuous {
            if spine {
                s.vacate.spines += 1;
            } else if compound {
                s.vacate.compounds += 1;
            } else {
                s.vacate.atoms += 1;
            }
        }
        if e.residue {
            s.residue += 1;
        }
        if let Some(gap) = e.served_vs_fold.filter(|_| e.fold_served) {
            s.fold_mismatch.p1_atoms += 1;
            if gap > MISMATCH_TOLERANCE {
                s.fold_mismatch.mismatched += 1;
            }
        }
        if compound {
            let set = if spine {
                &mut s.spine_confirmed_set
            } else {
                &mut s.compound_confirmed_set
            };
            set.progressive += usize::from(e.progressive.confirmed);
            set.strict += usize::from(e.strict.confirmed);
        }
        #[allow(clippy::cast_precision_loss)]
        let weight = delta.abs() * (1.0 + recall_exposure as f64);
        if delta.abs() > MISMATCH_TOLERANCE {
            self.movers.push(Mover {
                claim_id: id,
                role,
                delta,
                recall_exposure,
                weight,
            });
        }
        self.recs.insert(
            id,
            Rec {
                compound,
                spine,
                today: Cand::today(base),
                progressive: e.progressive,
                strict: e.strict,
                recall_exposure,
                graph_view_exposure,
                conflict_served: conflict.0,
                conflict_shadow: conflict.1,
            },
        );
    }

    fn finish_claims(&mut self, top: usize) {
        let s = &mut self.summary;
        #[allow(clippy::cast_precision_loss)]
        if s.fold_mismatch.p1_atoms > 0 {
            s.fold_mismatch.share =
                s.fold_mismatch.mismatched as f64 / s.fold_mismatch.p1_atoms as f64;
        }
        s.abs_delta = std::mem::take(&mut self.deltas)
            .into_iter()
            .map(|(role, v)| (role, quantiles(v)))
            .collect();
        let mut movers = std::mem::take(&mut self.movers);
        movers.sort_by(|a, b| {
            b.weight
                .total_cmp(&a.weight)
                .then(b.delta.abs().total_cmp(&a.delta.abs()))
                .then(a.claim_id.cmp(&b.claim_id))
        });
        movers.truncate(top);
        s.top_movers = movers;
    }
}

/// Run the report on a connection acquired from `pool`: every claim in scope
/// as `report_viewer` reads it, recall events as `events_viewer` reads them.
/// Each claim's line goes to `sink`. The connection is closed afterwards,
/// not returned to the pool.
///
/// A bypass viewer must be spent on the connection it was issued with; use
/// [`run_report_on`] with a maintenance session's own connection for that.
///
/// # Errors
/// A database read, or a fold that fails.
pub async fn run_report<F>(
    pool: &PgPool,
    report_viewer: &Viewer,
    events_viewer: &Viewer,
    opts: &ReportOptions,
    sink: F,
) -> Result<Summary, String>
where
    F: FnMut(&ClaimLine) -> Result<(), String>,
{
    let mut conn = pool.acquire().await.map_err(|e| format!("acquire: {e}"))?;
    let out = run_report_on(&mut conn, report_viewer, events_viewer, opts, sink).await;
    // Close the session rather than hand it back to the pool.
    drop(conn.detach());
    out
}

/// [`run_report`] on `conn` (a maintenance session's own connection, so its
/// bypass viewer is spent where it was issued). The session is set
/// `default_transaction_read_only` for the run and set back afterwards,
/// whether the run succeeded or not.
///
/// # Errors
/// A database read, or a fold that fails.
pub async fn run_report_on<F>(
    conn: &mut sqlx::PgConnection,
    report_viewer: &Viewer,
    events_viewer: &Viewer,
    opts: &ReportOptions,
    sink: F,
) -> Result<Summary, String>
where
    F: FnMut(&ClaimLine) -> Result<(), String>,
{
    sqlx::query("SET SESSION default_transaction_read_only = on")
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("read-only session: {e}"))?;
    let out = run_on(conn, report_viewer, events_viewer, opts, sink).await;
    let reset = sqlx::query("SET SESSION default_transaction_read_only = off")
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("reset read-only session: {e}"));
    let summary = out?;
    reset?;
    Ok(summary)
}

async fn run_on<F>(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    events_viewer: &Viewer,
    opts: &ReportOptions,
    mut sink: F,
) -> Result<Summary, String>
where
    F: FnMut(&ClaimLine) -> Result<(), String>,
{
    let ctx = FramedBeliefContext::global();
    // The window's end is the database's clock, the one `created_at` is
    // stamped by: a client clock behind it would drop events logged just
    // before the run.
    let until: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| format!("database clock: {e}"))?;
    let events = read_events(conn, events_viewer, opts.since, until).await?;
    let exposure = recall_exposure(&events);
    let page_size = opts.page_size.max(1);
    let mut totals = Totals::default();
    totals.summary.settings = RunSettings::of(opts);
    // The one-atom-value-on-prod measure (SPEC §1.3) is the public floor
    // viewer's (a scoped viewer in no group) under the `aef` fold.
    totals.summary.fold_mismatch.measures_floor = matches!(opts.target_fold, AtomFoldMode::Aef)
        && viewer.group_bind().is_some_and(<[Uuid]>::is_empty);
    // The compound derivation reads every evidenced leaf through its AEF
    // fold, whatever the target fold; only under `aef` is that the leaf
    // value the run serves.
    totals.summary.compound_statistics_valid = matches!(opts.target_fold, AtomFoldMode::Aef);

    let mut after: Option<Uuid> = None;
    let mut listed = match &opts.scope {
        Scope::All => None,
        Scope::Ids(ids) => Some(
            ids.iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>(),
        ),
    };
    loop {
        let page: Vec<Uuid> = match listed.as_mut() {
            Some(rest) => {
                let n = rest.len().min(page_size);
                rest.drain(..n).collect()
            }
            None => next_page(conn, viewer, after, page_size).await?,
        };
        if page.is_empty() {
            break;
        }
        after = page.last().copied();

        let bases = read_bases(conn, viewer, &page).await?;
        let mut atoms = Vec::new();
        let mut compounds = Vec::new();
        for id in &page {
            let Some(b) = bases.get(id) else { continue };
            match b.role {
                ClaimRole::Atom | ClaimRole::Standalone => atoms.push((*id, *b)),
                ClaimRole::Compound { .. } => compounds.push((*id, *b)),
                ClaimRole::Procedural | ClaimRole::Rule => {}
            }
        }
        let mut evals = eval_atoms(conn, viewer, &ctx, opts, &atoms, true).await?;
        let (compound_evals, mut closures) =
            eval_compounds(conn, viewer, &ctx, opts, &compounds).await?;
        evals.extend(compound_evals);
        let visible: Vec<Uuid> = bases.keys().copied().collect();
        let stored_k = stored_conflict(conn, viewer, &visible).await?;

        for id in &page {
            let Some(base) = bases.get(id) else { continue };
            let eval = evals.remove(id).unwrap_or_else(|| {
                let today = Cand::today(base);
                Eval {
                    aef: None,
                    drift: None,
                    view: None,
                    ready: None,
                    progressive: today,
                    strict: today,
                    served_vs_fold: None,
                    fold_served: false,
                    residue: false,
                }
            });
            let recall_exposure = exposure.get(id).copied().unwrap_or(0);
            let today = Cand::today(base);
            let line = ClaimLine {
                claim_id: *id,
                role: base.role.as_sql(),
                spine: matches!(base.role, ClaimRole::Compound { spine: true }),
                served: Served {
                    bel: base.cache.bel,
                    pl: base.cache.pl,
                    betp: base.cache.betp,
                    mass_on_missing: base.cache.missing,
                    frame_id: base.cache.frame,
                    score: base.score,
                    confirmed: today.confirmed,
                    contested: today.contested,
                },
                aef: eval.aef,
                drift: eval.drift.clone(),
                derived: eval.view.clone(),
                ready: eval.ready,
                progressive: eval.progressive.public(),
                strict: eval.strict.public(),
                delta: eval.strict.iv.betp - base.score,
                recall_exposure,
                graph_view_exposure: opts
                    .graph_view_exposure
                    .as_ref()
                    .map(|m| m.get(id).copied().unwrap_or(0)),
                served_vs_fold: eval.served_vs_fold,
            };
            sink(&line)?;
            let conflict_served = stored_k.get(id).is_some_and(|k| *k >= opts.conflict_min_k);
            let compound = matches!(base.role, ClaimRole::Compound { .. });
            let conflict_shadow = match (&eval.aef, eval.strict.basis) {
                _ if compound => false,
                (Some(aef), "axiom") => aef.conflict >= opts.conflict_min_k,
                _ => conflict_served,
            };
            if compound && conflict_served {
                totals
                    .conflicted_compounds
                    .push((*id, closures.remove(id).unwrap_or_default()));
            }
            totals.add(
                *id,
                base,
                &eval,
                recall_exposure,
                line.graph_view_exposure,
                (conflict_served, conflict_shadow),
            );
        }
    }
    totals.finish_claims(opts.top);
    totals.summary.replay = ByMode {
        progressive: replay(&events, &totals.recs, |r| &r.progressive),
        strict: replay(&events, &totals.recs, |r| &r.strict),
    };
    totals.summary.conflicts = conflict_shadow(
        &totals.recs,
        &totals.conflicted_compounds,
        opts.conflict_min_k,
    );
    totals.summary.sheaf = sheaf_shadow(
        conn,
        viewer,
        &totals.recs,
        opts.sheaf_threshold,
        matches!(opts.scope, Scope::Ids(_)),
    )
    .await?;
    let today_places = places(&totals.recs, |r| r.today.rank);
    let strict_places = places(&totals.recs, |r| r.strict.rank);
    for (spine, slot) in [
        (false, &mut totals.summary.strict_entry),
        (true, &mut totals.summary.strict_entry_spine),
    ] {
        *slot = strict_entry(
            &totals.recs,
            (&today_places, &strict_places),
            spine,
            opts.rank_threshold,
            opts.top,
            opts.graph_view_exposure.is_some(),
        );
    }
    Ok(totals.summary)
}
