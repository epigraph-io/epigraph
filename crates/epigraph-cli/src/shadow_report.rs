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
//! connection is closed, not returned to the pool, when the run ends.
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
//!   score of at least [`CONFIRMED_SCORE`].
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
use epigraph_engine::atom_items::{atom_axiom_rows, atom_fold, AtomFoldMode, AxiomMode, AxiomRow};
use epigraph_engine::belief_query::FramedBeliefContext;
use epigraph_engine::belief_view::{Basis, BeliefView};
use epigraph_engine::compound_belief::derive_compound_belief_batch;
use epigraph_engine::source_dependence::ATTRIBUTED_METHOD;

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
    pub progressive: SheafStats,
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
}

impl Cand {
    /// Today's value of a claim.
    fn today(b: &Base) -> Self {
        let s = b.score;
        Self {
            basis: "served",
            gate: s,
            rank: s,
            confirmed: !b.contested && s >= CONFIRMED_SCORE,
            contested: b.contested,
            iv: Interval {
                bel: b.cache.bel.unwrap_or(s),
                pl: b.cache.pl.unwrap_or(s),
                betp: b.cache.betp.unwrap_or(s),
                open_world: b.cache.missing.unwrap_or(0.0),
            },
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
/// stage absorbs them; `recompute_betp --dry-run` gives the full one.
const DRIFT_STAGES: [&str; 10] = ["0", "0b", "1", "1'", "2", "3", "3a", "3b", "3c", "4"];

/// One atom's drift decomposition, in `BetP` (see [`Drift`]):
///
/// * (0) the snapshot's value, when one was given;
/// * (0b) today's gate score;
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
        atom_fold(&without)?.pignistic_prob()
    };
    stages.insert("3c", Some(v3c));
    stages.insert("4", Some(fold_betp));

    let start = s0.unwrap_or(base.score);
    let mut prev = start;
    let mut components = BTreeMap::new();
    for key in DRIFT_STAGES.iter().skip(1) {
        let c = stages[key].map(|v| {
            let d = v - prev;
            prev = v;
            d
        });
        components.insert(*key, c);
    }
    Ok(Drift {
        start,
        stages,
        components,
        final_value: fold_betp,
        total: fold_betp - start,
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
                let f = atom_fold(rs)?;
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
                        confirmed: !base.contested && aef.betp >= CONFIRMED_SCORE,
                        contested: base.contested,
                        iv: Interval {
                            bel: aef.bel,
                            pl: aef.pl,
                            betp: aef.betp,
                            open_world: aef.open_world,
                        },
                    }
                } else {
                    today
                };
                let drift = if covered && with_drift {
                    Some(drift(conn, viewer, opts, *id, base, rs, &attributed, aef.betp).await?)
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
                .map_or(view.bel >= CONFIRMED_SCORE, |e| e.strict.confirmed),
            _ => view.bel >= CONFIRMED_SCORE,
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
                drift: None,
                view: Some(view.clone()),
                ready: Some(ready),
                progressive,
                strict,
                served_vs_fold: None,
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

/// The running totals of the per-claim pass.
#[derive(Default)]
struct Totals {
    summary: Summary,
    deltas: BTreeMap<&'static str, Vec<f64>>,
    movers: Vec<Mover>,
}

impl Totals {
    fn add(&mut self, id: Uuid, base: &Base, e: &Eval, recall_exposure: u64) {
        let role = base.role.as_sql();
        let s = &mut self.summary;
        s.claims += 1;
        *s.by_role.entry(role).or_default() += 1;
        let delta = e.strict.iv.betp - base.score;
        self.deltas.entry(role).or_default().push(delta.abs());
        let vacuous = |bel: f64, pl: f64| bel < 0.01 && pl > 0.99;
        let served_vacuous =
            matches!((base.cache.bel, base.cache.pl), (Some(b), Some(p)) if vacuous(b, p));
        if e.strict.computed() && vacuous(e.strict.iv.bel, e.strict.iv.pl) && !served_vacuous {
            s.vacate += 1;
        }
        if e.residue {
            s.residue += 1;
        }
        if let Some(gap) = e.served_vs_fold {
            s.fold_mismatch.p1_atoms += 1;
            if gap > MISMATCH_TOLERANCE {
                s.fold_mismatch.mismatched += 1;
            }
        }
        let compound = matches!(base.role, ClaimRole::Compound { .. });
        if compound {
            s.compound_confirmed_set.progressive += usize::from(e.progressive.confirmed);
            s.compound_confirmed_set.strict += usize::from(e.strict.confirmed);
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

/// Run the report: every claim in scope as `report_viewer` reads it, recall
/// events as `events_viewer` reads them. Each claim's line goes to `sink`.
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
    sqlx::query("SET SESSION default_transaction_read_only = on")
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("read-only session: {e}"))?;
    let out = run_on(&mut conn, report_viewer, events_viewer, opts, sink).await;
    // Close the read-only session rather than hand it back to the pool.
    drop(conn.detach());
    out
}

async fn run_on<F>(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    _events_viewer: &Viewer,
    opts: &ReportOptions,
    mut sink: F,
) -> Result<Summary, String>
where
    F: FnMut(&ClaimLine) -> Result<(), String>,
{
    let ctx = FramedBeliefContext::global();
    let exposure: HashMap<Uuid, u64> = HashMap::new();
    let page_size = opts.page_size.max(1);
    let mut totals = Totals::default();

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
        let (compound_evals, _closures) =
            eval_compounds(conn, viewer, &ctx, opts, &compounds).await?;
        evals.extend(compound_evals);

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
            totals.add(*id, base, &eval, recall_exposure);
        }
    }
    totals.finish_claims(opts.top);
    Ok(totals.summary)
}
