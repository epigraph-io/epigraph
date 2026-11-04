//! The targeted edge-factor rewire (R-176(2), R-177(4): class E of the
//! calibration recompute): passes to a fixed point, the snapshot files a
//! rollback restores from, the compare-and-swap restore of the edge rows, and
//! the predicting dry run.
//!
//! A wave (the R-176(1) calibration recompute, `recompute_claim_belief
//! --snapshot`) moved some claims' caches. Every edge-factor row sourced at a
//! moved claim froze the claim's OLD interval when it was wired. This module
//! re-wires exactly those rows, through the guarded per-edge rewire in
//! [`crate::backfill_factors::rewire_edge_targeted`], and then the rows
//! sourced at the targets that moved, pass after pass, until a pass moves
//! nothing.
//!
//! * **Pass 1** takes the edges sourced at the wave's moved claims; **pass
//!   k+1** the edges sourced at targets pass k moved (bel or pl by more than
//!   `epsilon`). The run stops when a pass moves nothing, or at
//!   `max_passes`, when the edges it did not reach are reported
//!   ([`TargetedRunReport::unconverged_edges`]) and left alone.
//! * **Baseline.** A claim's stored edge rows were wired from the interval it
//!   held before it first moved: the wave's `before` for a wave claim, the
//!   first rewrite's `before` for a target. Row class `r173` is decided
//!   against it, or, for an edge this run already rewrote, against the row
//!   it wrote.
//! * **Snapshots.** Before each rewrite commits it appends a
//!   [`WaveRecord`] for the target (wave `<prefix>-pass-<k>`, `at` = the
//!   database clock before the run's first write, as the calibration wave
//!   stamps it) and an [`EdgeRowRecord`] for the row.
//! * **Rollback** is LIFO: [`restore_edge_rows`] puts the rows back by
//!   compare-and-swap, then `restore_belief_cache --from <the E wave file>`
//!   the target caches.
//! * **Predict** ([`predict_targeted_rewire`]): the same passes, the same
//!   per-edge decision ([`crate::backfill_factors::decide_targeted`]) and
//!   the same pure row builder, in ONE `REPEATABLE READ, READ ONLY`
//!   transaction, with an in-memory overlay standing in for each write. Both
//!   loops visit edges in the same order (Gauss-Seidel), so on an unchanged
//!   database the predict's fixed point is the apply's.
//!
//! The SQL lives here rather than in `epigraph-db/src/repos/` for the same
//! reason as `belief_cache`'s: an operator binary's maintenance statements on
//! the maintenance connection, with no request path.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, Write};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::backfill_factors::{
    cache_of_fold, decide_targeted, rewire_edge_targeted, select_targeted_edges, selected_edge_row,
    HeldBucket, RewireCapture, RewireEdge, RewireOverlay, StoredEdgeRow, TargetedGuards,
    TargetedOutcome, TargetedVerdict,
};
use crate::belief_cache::{plan_restore, write_wave_record, CacheColumns, WaveRecord};

/// Default pass cap.
pub const DEFAULT_MAX_PASSES: usize = 10;

/// Default move threshold on belief and plausibility.
pub const DEFAULT_EPSILON: f64 = 1e-9;

/// Rows per restore transaction.
pub const EDGE_ROW_RESTORE_BATCH: usize = 1000;

/// What the wave files say: per wave claim, the cache before its first
/// recorded write and after its last (chained as `belief_cache::plan_restore`
/// chains them).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WaveSeed {
    /// `(belief, plausibility)` before the claim first moved.
    pub baseline: HashMap<Uuid, (f64, f64)>,
    /// The claims whose cache moved: pass 1's sources.
    pub moved: BTreeSet<Uuid>,
    pub before: HashMap<Uuid, CacheColumns>,
    pub written: HashMap<Uuid, CacheColumns>,
}

/// Whether `a` and `b` differ by more than `eps` on belief or plausibility
/// (a NULL against a value always differs).
#[must_use]
pub fn cache_moved(a: &CacheColumns, b: &CacheColumns, eps: f64) -> bool {
    let diff = |x: Option<f64>, y: Option<f64>| match (x, y) {
        (Some(x), Some(y)) => (x - y).abs() > eps,
        (None, None) => false,
        _ => true,
    };
    diff(a.belief, b.belief) || diff(a.plausibility, b.plausibility)
}

/// Read the wave records into a [`WaveSeed`].
#[must_use]
pub fn seed_from_waves(records: &[WaveRecord], epsilon: f64) -> WaveSeed {
    let plan = plan_restore(records, None);
    let mut seed = WaveSeed::default();
    for e in plan.entries {
        if let (Some(b), Some(p)) = (e.before.belief, e.before.plausibility) {
            seed.baseline.insert(e.claim_id, (b, p));
        }
        if cache_moved(&e.before, &e.written, epsilon) {
            seed.moved.insert(e.claim_id);
        }
        seed.before.insert(e.claim_id, e.before);
        seed.written.insert(e.claim_id, e.written);
    }
    seed
}

/// The switches of a targeted run (apply or predict).
#[derive(Debug, Clone)]
pub struct TargetedRunOptions {
    /// The accepted edge list: an edge outside it is never rewired, and is
    /// counted `chain_boundary_held` when a pass reaches it.
    pub edges: Option<BTreeSet<Uuid>>,
    pub max_passes: usize,
    pub epsilon: f64,
    pub only_changed: bool,
    /// Wave name prefix; pass k's records are `<prefix>-pass-<k>`.
    pub wave_prefix: String,
}

impl Default for TargetedRunOptions {
    fn default() -> Self {
        Self {
            edges: None,
            max_passes: DEFAULT_MAX_PASSES,
            epsilon: DEFAULT_EPSILON,
            only_changed: false,
            wave_prefix: "r176e".to_string(),
        }
    }
}

/// One pass's counts.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PassSummary {
    pub pass: usize,
    /// Edges the pass's selection returned.
    pub selected: usize,
    pub rewired: usize,
    pub unchanged: usize,
    pub skipped_stale: usize,
    pub failed: usize,
    /// Selected, but not on the accepted list.
    pub chain_boundary_held: usize,
    /// Held, by [`HeldBucket::name`].
    pub held: BTreeMap<String, usize>,
    /// Targets whose cache moved: the next pass's sources.
    pub moved_targets: usize,
}

impl PassSummary {
    fn hold(&mut self, bucket: HeldBucket) {
        *self.held.entry(bucket.name().to_string()).or_default() += 1;
    }
}

/// What a targeted run did.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TargetedRunReport {
    pub passes: Vec<PassSummary>,
    /// A pass moved nothing before `max_passes`.
    pub converged: bool,
    /// When not converged: the edges the next pass would have taken, left
    /// alone (`cycle_unconverged` / `chain_boundary_held` at the pass cap).
    pub unconverged_edges: Vec<Uuid>,
}

impl TargetedRunReport {
    /// Rows rewritten over all passes.
    #[must_use]
    pub fn rewired(&self) -> usize {
        self.passes.iter().map(|p| p.rewired).sum()
    }

    /// Edges held under `bucket` over all passes.
    #[must_use]
    pub fn held(&self, bucket: HeldBucket) -> usize {
        self.passes
            .iter()
            .map(|p| p.held.get(bucket.name()).copied().unwrap_or(0))
            .sum()
    }

    /// Edges outside the accepted list a pass reached.
    #[must_use]
    pub fn chain_boundary_held(&self) -> usize {
        self.passes.iter().map(|p| p.chain_boundary_held).sum()
    }

    /// Per-edge failures over all passes.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.passes.iter().map(|p| p.failed).sum()
    }
}

/// One line of an edge-rows file: a rewritten row's stored columns before and
/// after one targeted rewrite.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgeRowRecord {
    pub mf_id: Uuid,
    pub edge_id: Uuid,
    pub target_id: Uuid,
    pub frame_id: Uuid,
    pub agent_id: Uuid,
    pub before: StoredEdgeRow,
    pub written: StoredEdgeRow,
    pub wave: String,
    pub at: DateTime<Utc>,
}

/// Append one edge-row record as a JSON line.
///
/// # Errors
/// Serialization or I/O failure.
pub fn write_edge_row_record<W: Write>(out: &mut W, rec: &EdgeRowRecord) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *out, rec)?;
    out.write_all(b"\n")?;
    Ok(())
}

/// Parse an edge-rows file.
///
/// # Errors
/// I/O failure or a malformed line.
pub fn read_edge_row_records<R: BufRead>(input: R) -> anyhow::Result<Vec<EdgeRowRecord>> {
    let mut out = Vec::new();
    for (i, line) in input.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line).map_err(|e| anyhow::anyhow!("line {}: {e}", i + 1))?);
    }
    Ok(out)
}

/// Read the database clock (the run's `at`, before its first write).
async fn db_now(pool: &PgPool) -> anyhow::Result<DateTime<Utc>> {
    Ok(sqlx::query_scalar("SELECT now()").fetch_one(pool).await?)
}

/// Apply the targeted rewire: passes to a fixed point from `seed`'s moved
/// claims (see the module doc). Every rewrite appends its target's
/// [`WaveRecord`] to `wave_out` and its row's [`EdgeRowRecord`] to
/// `rows_out` before it commits.
///
/// # Errors
/// A selection or the clock read fails. Per-edge failures roll that edge back
/// and are counted.
pub async fn run_targeted_rewire(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    seed: &WaveSeed,
    opts: &TargetedRunOptions,
    wave_out: &mut (dyn Write + Send),
    rows_out: &mut (dyn Write + Send),
) -> anyhow::Result<TargetedRunReport> {
    let at = db_now(pool).await?;
    let mut baseline = seed.baseline.clone();
    let mut own_rows: HashMap<Uuid, StoredEdgeRow> = HashMap::new();
    let mut sources: BTreeSet<Uuid> = seed.moved.clone();
    let mut report = TargetedRunReport::default();
    let accepted: Option<Vec<Uuid>> = opts.edges.as_ref().map(|e| e.iter().copied().collect());

    for pass in 1..=opts.max_passes.max(1) {
        if sources.is_empty() {
            report.converged = true;
            break;
        }
        let src: Vec<Uuid> = sources.iter().copied().collect();
        let edges = {
            let mut conn = pool.acquire().await?;
            select_targeted_edges(&mut conn, &src, None).await?
        };
        let mut summary = PassSummary {
            pass,
            selected: edges.len(),
            ..PassSummary::default()
        };
        let mut next: BTreeSet<Uuid> = BTreeSet::new();
        let wave = format!("{}-pass-{pass}", opts.wave_prefix);
        for edge in &edges {
            if accepted
                .as_ref()
                .is_some_and(|a| a.binary_search(&edge.edge_id).is_err())
            {
                summary.chain_boundary_held += 1;
                continue;
            }
            let guards = TargetedGuards {
                baseline: &baseline,
                own_rows: &own_rows,
                only_changed: opts.only_changed,
            };
            let mut on_capture = |c: &RewireCapture| -> Result<(), String> {
                let mut w: &mut (dyn Write + Send) = &mut *wave_out;
                write_wave_record(
                    &mut w,
                    &WaveRecord {
                        claim_id: c.target_id,
                        before: c.target_before.clone(),
                        written: c.target_after.clone(),
                        wave: wave.clone(),
                        at,
                    },
                )
                .and_then(|()| Ok(w.flush()?))
                .map_err(|e| format!("wave record: {e}"))?;
                let mut r: &mut (dyn Write + Send) = &mut *rows_out;
                write_edge_row_record(
                    &mut r,
                    &EdgeRowRecord {
                        mf_id: c.row_after.mf_id,
                        edge_id: c.edge_id,
                        target_id: c.target_id,
                        frame_id: c.frame_id,
                        agent_id: c.agent_id,
                        before: c.row_before.clone(),
                        written: c.row_after.clone(),
                        wave: wave.clone(),
                        at,
                    },
                )
                .and_then(|()| Ok(r.flush()?))
                .map_err(|e| format!("edge-row record: {e}"))
            };
            match rewire_edge_targeted(pool, viewer, edge, &guards, &mut on_capture).await {
                Ok(TargetedOutcome::Rewired(c)) => {
                    summary.rewired += 1;
                    if cache_moved(&c.target_before, &c.target_after, opts.epsilon) {
                        next.insert(c.target_id);
                        if let (Some(b), Some(p)) =
                            (c.target_before.belief, c.target_before.plausibility)
                        {
                            baseline.entry(c.target_id).or_insert((b, p));
                        }
                    }
                    own_rows.insert(c.edge_id, c.row_after.clone());
                }
                Ok(TargetedOutcome::Unchanged) => summary.unchanged += 1,
                Ok(TargetedOutcome::Held(b)) => summary.hold(b),
                Ok(TargetedOutcome::SkippedStale) => summary.skipped_stale += 1,
                Err(e) => {
                    tracing::warn!(edge = %edge.edge_id, target = %edge.target_id,
                        "targeted rewire failed: {e}");
                    summary.failed += 1;
                }
            }
        }
        summary.moved_targets = next.len();
        report.passes.push(summary);
        sources = next;
    }
    if sources.is_empty() {
        report.converged = true;
    } else {
        let src: Vec<Uuid> = sources.iter().copied().collect();
        let mut conn = pool.acquire().await?;
        report.unconverged_edges = select_targeted_edges(&mut conn, &src, accepted.as_deref())
            .await?
            .into_iter()
            .map(|e| e.edge_id)
            .collect();
    }
    Ok(report)
}

// ── Restore ────────────────────────────────────────────────────────────────

/// Per-row outcome of [`restore_edge_rows`]. Each row is in exactly one.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EdgeRowRestoreReport {
    pub restored: Vec<Uuid>,
    pub already_restored: Vec<Uuid>,
    /// Written since the rewire (no longer what the rewire wrote): left alone.
    pub superseded_since_rewire: Vec<Uuid>,
    /// Retracted since the rewire: left alone (migration 184 audit row).
    pub retracted_since_rewire: Vec<Uuid>,
    pub missing: Vec<Uuid>,
}

/// One row a restore puts back: chained like `belief_cache::plan_restore`
/// (the earliest `before` of the run of records at the end whose each
/// `before` is the previous `written`), compared against the last `written`.
#[derive(Debug, Clone, PartialEq)]
struct EdgeRowRestore {
    mf_id: Uuid,
    before: StoredEdgeRow,
    written: StoredEdgeRow,
}

fn plan_edge_rows(records: &[EdgeRowRecord]) -> Vec<EdgeRowRestore> {
    let mut order: Vec<Uuid> = Vec::new();
    let mut groups: HashMap<Uuid, Vec<&EdgeRowRecord>> = HashMap::new();
    for r in records {
        groups
            .entry(r.mf_id)
            .or_insert_with(|| {
                order.push(r.mf_id);
                Vec::new()
            })
            .push(r);
    }
    // LIFO: the row whose last rewrite came last is restored first.
    let last_index = |id: &Uuid| records.iter().rposition(|r| r.mf_id == *id).unwrap_or(0);
    order.sort_by_key(|id| std::cmp::Reverse(last_index(id)));
    order
        .into_iter()
        .map(|id| {
            let group = &groups[&id];
            let mut start = group.len() - 1;
            while start > 0 && group[start - 1].written == group[start].before {
                start -= 1;
            }
            EdgeRowRestore {
                mf_id: id,
                before: group[start].before.clone(),
                written: group[group.len() - 1].written.clone(),
            }
        })
        .collect()
}

/// Put every rewritten edge-factor row back, compare-and-swap: a row is
/// written only where it is live (`retracted_at IS NULL`, so migration 184's
/// retracted-row guard is never reached) and still holds EXACTLY what the
/// rewire wrote (`masses`, `source_strength`, `evidence_type`,
/// `locality_tag` and `created_at`); `created_at` is restored too, since the
/// rewire's upsert stamped it. Anything else is reported and left alone. The
/// target caches are restored separately from the E wave file
/// (`restore_belief_cache --from`). `dry_run` runs the same statements and
/// rolls each batch back.
///
/// # Errors
/// Any database error; batches already committed stay committed.
pub async fn restore_edge_rows(
    pool: &PgPool,
    records: &[EdgeRowRecord],
    dry_run: bool,
) -> anyhow::Result<EdgeRowRestoreReport> {
    let plan = plan_edge_rows(records);
    let mut report = EdgeRowRestoreReport::default();
    for chunk in plan.chunks(EDGE_ROW_RESTORE_BATCH) {
        let mut tx = pool.begin().await?;
        for e in chunk {
            let restored: Option<Uuid> = sqlx::query_scalar(
                "UPDATE mass_functions \
                    SET masses = $2::jsonb, source_strength = $3, evidence_type = $4, \
                        locality_tag = $5, created_at = $6 \
                  WHERE id = $1 AND retracted_at IS NULL \
                    AND masses = $7::jsonb AND source_strength IS NOT DISTINCT FROM $8 \
                    AND evidence_type IS NOT DISTINCT FROM $9 AND locality_tag = $10 \
                    AND created_at = $11 \
                  RETURNING id",
            )
            .bind(e.mf_id)
            .bind(&e.before.masses)
            .bind(e.before.source_strength)
            .bind(&e.before.evidence_type)
            .bind(&e.before.locality_tag)
            .bind(e.before.created_at)
            .bind(&e.written.masses)
            .bind(e.written.source_strength)
            .bind(&e.written.evidence_type)
            .bind(&e.written.locality_tag)
            .bind(e.written.created_at)
            .fetch_optional(&mut *tx)
            .await?;
            if restored.is_some() {
                report.restored.push(e.mf_id);
                continue;
            }
            let state: Option<(bool, bool)> = sqlx::query_as(
                "SELECT retracted_at IS NOT NULL, \
                        masses = $2::jsonb AND source_strength IS NOT DISTINCT FROM $3 \
                        AND evidence_type IS NOT DISTINCT FROM $4 AND locality_tag = $5 \
                        AND created_at = $6 \
                   FROM mass_functions WHERE id = $1",
            )
            .bind(e.mf_id)
            .bind(&e.before.masses)
            .bind(e.before.source_strength)
            .bind(&e.before.evidence_type)
            .bind(&e.before.locality_tag)
            .bind(e.before.created_at)
            .fetch_optional(&mut *tx)
            .await?;
            match state {
                None => report.missing.push(e.mf_id),
                Some((true, _)) => report.retracted_since_rewire.push(e.mf_id),
                Some((false, true)) => report.already_restored.push(e.mf_id),
                Some((false, false)) => report.superseded_since_rewire.push(e.mf_id),
            }
        }
        if dry_run {
            tx.rollback().await?;
        } else {
            tx.commit().await?;
        }
    }
    Ok(report)
}

// ── Predict ────────────────────────────────────────────────────────────────

/// One edge the predict decided.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PredictedEdge {
    pub edge_id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub relationship: String,
    pub pass: usize,
    /// `rewire`, `unchanged`, `skipped_stale`, `chain_boundary_held`, or a
    /// [`HeldBucket::name`].
    pub outcome: String,
    /// The stored row's `masses` (database text).
    pub stored_masses: Option<String>,
    /// A wire from the source's baseline (pre-move) interval.
    pub p0_masses: Option<serde_json::Value>,
    /// A wire from the source's current (or predicted) interval.
    pub p1_masses: Option<serde_json::Value>,
    pub p1_source_strength: Option<f64>,
    pub p1_evidence_type: Option<String>,
    pub p1_locality_tag: Option<String>,
    /// The new row's locality differs from the stored row's (E-e).
    pub locality_changed: bool,
    /// The new row's evidence-type spelling differs from the stored one (E-f).
    pub respelled: bool,
}

/// One target the predict touched, binary frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PredictedTarget {
    /// The stored cache when the predict first reached the target.
    pub s: CacheColumns,
    /// BetP of the fold of its current rows then (no rewire).
    pub r_betp: Option<f64>,
    /// The predicted cache after the last rewire into it (`None`: none).
    pub w: Option<CacheColumns>,
    /// R − S on BetP: the target's own staleness.
    pub d_stale: Option<f64>,
    /// W − R on BetP: what the rewire moves it by.
    pub d_edge: Option<f64>,
    pub fresh: bool,
    /// Thresholds crossed S → W on BetP: `up_0.50`, `down_0.75`, ...
    pub crossings: Vec<String>,
}

/// Totals over a predict.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PredictTotals {
    pub would_rewrite: usize,
    pub unchanged: usize,
    pub held: BTreeMap<String, usize>,
    pub chain_boundary_held: usize,
    pub would_remove: usize,
    pub would_vacate: usize,
    pub cycle_unconverged: usize,
    /// |d_edge| on BetP, K0 bins.
    pub d_edge_histogram: BTreeMap<String, usize>,
    pub max_abs_d_edge: f64,
    pub d_edge_over_0_10: usize,
    pub d_edge_over_0_20: usize,
    /// Crossings by name, summed over targets.
    pub crossings: BTreeMap<String, usize>,
}

/// The options and inputs a predict ran with. Predict-equals-apply holds only
/// for an apply with the SAME options (an `epsilon` decides which targets
/// count as moved), so acceptance compares the apply's flags with these.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PredictRun {
    pub epsilon: f64,
    pub max_passes: usize,
    pub only_changed: bool,
    /// Size of the accepted edge list, when one was given.
    pub accepted_edges: Option<usize>,
    /// Wave claims in the seed, and how many of them moved (pass 1's sources).
    pub wave_claims: usize,
    pub moved_sources: usize,
    /// The wave files the seed came from (filled in by the binary).
    pub wave_files: Vec<String>,
}

/// What a predict writes to `--predict-json`. Deterministic: no timestamp,
/// ordered maps, edges in visit order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PredictReport {
    pub calibration_source: String,
    pub profile_hash: String,
    pub run: PredictRun,
    /// `db` (the database holds the wave's written values) or `seeded` (some
    /// wave claims still hold their `before`: the overlay was seeded with
    /// the wave's `written`, a restored pre-wave copy).
    pub seed_mode: String,
    pub passes: Vec<PassSummary>,
    pub converged: bool,
    pub unconverged_edges: Vec<Uuid>,
    pub edges: Vec<PredictedEdge>,
    pub targets: BTreeMap<Uuid, PredictedTarget>,
    pub totals: PredictTotals,
}

impl PredictReport {
    /// Edges the predict would rewrite.
    #[must_use]
    pub fn would_rewrite(&self) -> Vec<Uuid> {
        self.edges
            .iter()
            .filter(|e| e.outcome == "rewire")
            .map(|e| e.edge_id)
            .collect()
    }
}

/// Open the predict's transaction: `REPEATABLE READ, READ ONLY`, set as its
/// first statement, so every read sees one snapshot and any write fails
/// (SQLSTATE 25006).
///
/// # Errors
/// The begin or the `SET TRANSACTION` fails.
pub async fn begin_predict_tx(
    pool: &PgPool,
) -> anyhow::Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

const CROSSING_THRESHOLDS: [(f64, &str); 3] = [(0.30, "0.30"), (0.50, "0.50"), (0.75, "0.75")];

fn crossings(s: Option<f64>, w: Option<f64>) -> Vec<String> {
    let (Some(s), Some(w)) = (s, w) else {
        return Vec::new();
    };
    CROSSING_THRESHOLDS
        .iter()
        .filter_map(|&(t, name)| {
            if s < t && w >= t {
                Some(format!("up_{name}"))
            } else if s >= t && w < t {
                Some(format!("down_{name}"))
            } else {
                None
            }
        })
        .collect()
}

fn d_edge_bin(d: f64) -> &'static str {
    let d = d.abs();
    if d < 0.01 {
        "lt_0.01"
    } else if d < 0.05 {
        "lt_0.05"
    } else if d < 0.10 {
        "lt_0.10"
    } else if d < 0.20 {
        "lt_0.20"
    } else if d < 0.50 {
        "lt_0.50"
    } else {
        "ge_0.50"
    }
}

/// Predict the targeted rewire without writing: the passes, decisions and
/// rows [`run_targeted_rewire`] would produce on this snapshot (module doc).
///
/// Refuses when a wave claim's cache equals neither its wave `before` nor
/// its `written` (`l1_state_unknown`: someone wrote it since the wave).
///
/// The fixed-point VERIFY after an apply (design §1.5 (b)) must be handed the
/// L1 wave files AND the apply's `--snapshot` file: an L1 claim the rewire
/// refolded as a target now holds the rewire's value, which is neither its L1
/// `before` nor its L1 `written`, and the E records chain onto the L1 ones
/// (each E `before` is the previous `written`), so together they read as the
/// current state.
///
/// # Errors
/// A read fails, the binary frame is missing, or the state check refuses.
#[allow(clippy::too_many_lines)]
pub async fn predict_targeted_rewire(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    seed: &WaveSeed,
    opts: &TargetedRunOptions,
) -> anyhow::Result<PredictReport> {
    let mut tx = begin_predict_tx(pool).await?;
    let binary = epigraph_db::FrameRepository::get_by_name(&mut *tx, viewer, "binary_truth")
        .await?
        .ok_or_else(|| anyhow::anyhow!("binary_truth frame not found"))?
        .id;

    // Seed the overlay: a wave claim still at its `before` (a restored
    // pre-wave copy) is read at its `written`.
    let mut overlay = RewireOverlay::default();
    let ids: Vec<Uuid> = seed.written.keys().copied().collect();
    let stored = crate::belief_cache::read_cache_columns(&mut *tx, &ids).await?;
    let mut unknown: Vec<Uuid> = Vec::new();
    for id in &ids {
        let (Some(now), Some(written)) = (stored.get(id), seed.written.get(id)) else {
            unknown.push(*id);
            continue;
        };
        if now == written {
            continue;
        }
        if seed.before.get(id) == Some(now) {
            overlay.cache.insert(*id, written.clone());
        } else {
            unknown.push(*id);
        }
    }
    if !unknown.is_empty() {
        unknown.sort_unstable();
        anyhow::bail!(
            "l1_state_unknown: {} wave claim(s) hold neither the wave's before nor its written \
             value (written since the wave), first {:?}",
            unknown.len(),
            unknown.iter().take(5).collect::<Vec<_>>()
        );
    }
    let seed_mode = if overlay.cache.is_empty() {
        "db"
    } else {
        "seeded"
    };

    let mut baseline = seed.baseline.clone();
    let own_rows: HashMap<Uuid, StoredEdgeRow> = HashMap::new();
    let mut sources: BTreeSet<Uuid> = seed.moved.clone();
    let accepted: Option<Vec<Uuid>> = opts.edges.as_ref().map(|e| e.iter().copied().collect());
    let mut passes: Vec<PassSummary> = Vec::new();
    let mut edges_out: Vec<PredictedEdge> = Vec::new();
    let mut targets: BTreeMap<Uuid, PredictedTarget> = BTreeMap::new();
    let mut converged = false;

    for pass in 1..=opts.max_passes.max(1) {
        if sources.is_empty() {
            converged = true;
            break;
        }
        let src: Vec<Uuid> = sources.iter().copied().collect();
        let edges: Vec<RewireEdge> = select_targeted_edges(&mut tx, &src, None).await?;
        let mut summary = PassSummary {
            pass,
            selected: edges.len(),
            ..PassSummary::default()
        };
        let mut next: BTreeSet<Uuid> = BTreeSet::new();
        for edge in &edges {
            let mut out = PredictedEdge {
                edge_id: edge.edge_id,
                source_id: edge.source_id,
                target_id: edge.target_id,
                relationship: edge.relationship.clone(),
                pass,
                outcome: String::new(),
                stored_masses: None,
                p0_masses: None,
                p1_masses: None,
                p1_source_strength: None,
                p1_evidence_type: None,
                p1_locality_tag: None,
                locality_changed: false,
                respelled: false,
            };
            if accepted
                .as_ref()
                .is_some_and(|a| a.binary_search(&edge.edge_id).is_err())
            {
                summary.chain_boundary_held += 1;
                out.outcome = "chain_boundary_held".into();
                edges_out.push(out);
                continue;
            }
            if matches!(
                epigraph_engine::sheaf::restriction_kind_with_profile(
                    &edge.relationship,
                    &epigraph_engine::sheaf::RestrictionProfile::scientific()
                ),
                epigraph_engine::sheaf::RestrictionKind::Neutral
            ) {
                summary.hold(HeldBucket::NonEpistemic);
                out.outcome = HeldBucket::NonEpistemic.name().into();
                edges_out.push(out);
                continue;
            }
            let Some(selected_id) = selected_edge_row(&mut tx, edge)
                .await
                .map_err(anyhow::Error::msg)?
            else {
                summary.skipped_stale += 1;
                out.outcome = "skipped_stale".into();
                edges_out.push(out);
                continue;
            };
            let guards = TargetedGuards {
                baseline: &baseline,
                own_rows: &own_rows,
                only_changed: opts.only_changed,
            };
            let d = decide_targeted(
                &mut tx,
                viewer,
                edge,
                binary,
                selected_id,
                &guards,
                Some(&overlay),
            )
            .await
            .map_err(anyhow::Error::msg)?;
            out.stored_masses = d.stored.as_ref().map(|r| r.masses.clone());
            out.p0_masses = d.p0.as_ref().map(|b| b.masses_json.clone());
            if let Some(p1) = &d.p1 {
                out.p1_masses = Some(p1.masses_json.clone());
                out.p1_source_strength = Some(p1.source_strength);
                out.p1_evidence_type = Some(p1.evidence_type.clone());
                out.p1_locality_tag = Some(p1.locality_tag.to_string());
                if let Some(st) = &d.stored {
                    out.locality_changed = st.locality_tag != p1.locality_tag;
                    out.respelled = st.evidence_type.as_deref() != Some(p1.evidence_type.as_str());
                }
            }
            if let Some(s) = &d.s {
                targets
                    .entry(edge.target_id)
                    .or_insert_with(|| PredictedTarget {
                        s: s.clone(),
                        r_betp: d.r.as_ref().map(|r| r.pignistic_prob),
                        w: None,
                        d_stale: match (s.pignistic_prob, d.r.as_ref()) {
                            (Some(s), Some(r)) => Some(r.pignistic_prob - s),
                            _ => None,
                        },
                        d_edge: None,
                        // The S-vs-R comparison itself, not the verdict: a
                        // held `would_vacate` target has no fold to be fresh to.
                        fresh: d.r.as_ref().is_some_and(|r| {
                            crate::backfill_factors::cache_matches_fold(
                                s,
                                r,
                                binary,
                                crate::backfill_factors::FRESH_EPSILON,
                            )
                        }),
                        crossings: Vec::new(),
                    });
            }
            match d.verdict {
                TargetedVerdict::Hold(b) => {
                    summary.hold(b);
                    out.outcome = b.name().into();
                }
                TargetedVerdict::Unchanged => {
                    summary.unchanged += 1;
                    out.outcome = "unchanged".into();
                }
                TargetedVerdict::Proceed => {
                    let (Some(p1), Some(w), Some(s)) = (d.p1, d.w, d.s) else {
                        anyhow::bail!("predict: edge {} proceeded without its fold", edge.edge_id);
                    };
                    summary.rewired += 1;
                    out.outcome = "rewire".into();
                    overlay.rows.insert(selected_id, p1);
                    let new_cache = cache_of_fold(&w, binary, Some(&s));
                    if crate::edge_rewire::cache_moved(&s, &new_cache, opts.epsilon) {
                        next.insert(edge.target_id);
                        if let (Some(b), Some(p)) = (s.belief, s.plausibility) {
                            baseline.entry(edge.target_id).or_insert((b, p));
                        }
                    }
                    if let Some(t) = targets.get_mut(&edge.target_id) {
                        t.w = Some(new_cache.clone());
                    }
                    overlay.cache.insert(edge.target_id, new_cache);
                }
            }
            edges_out.push(out);
        }
        summary.moved_targets = next.len();
        passes.push(summary);
        sources = next;
    }
    let mut unconverged_edges = Vec::new();
    if sources.is_empty() {
        converged = true;
    } else {
        let src: Vec<Uuid> = sources.iter().copied().collect();
        unconverged_edges = select_targeted_edges(&mut tx, &src, accepted.as_deref())
            .await?
            .into_iter()
            .map(|e| e.edge_id)
            .collect();
    }
    // Nothing above writes; roll back regardless.
    tx.rollback().await?;

    let mut totals = PredictTotals {
        cycle_unconverged: unconverged_edges.len(),
        ..PredictTotals::default()
    };
    for p in &passes {
        totals.would_rewrite += p.rewired;
        totals.unchanged += p.unchanged;
        totals.chain_boundary_held += p.chain_boundary_held;
        for (k, v) in &p.held {
            *totals.held.entry(k.clone()).or_default() += v;
        }
    }
    totals.would_remove = totals
        .held
        .get(HeldBucket::WouldRemove.name())
        .copied()
        .unwrap_or(0);
    totals.would_vacate = totals
        .held
        .get(HeldBucket::WouldVacate.name())
        .copied()
        .unwrap_or(0);
    for t in targets.values_mut() {
        let Some(w) = &t.w else { continue };
        t.d_edge = match (w.pignistic_prob, t.r_betp) {
            (Some(w), Some(r)) => Some(w - r),
            _ => None,
        };
        t.crossings = crossings(t.s.pignistic_prob, w.pignistic_prob);
        if let Some(d) = t.d_edge {
            *totals
                .d_edge_histogram
                .entry(d_edge_bin(d).to_string())
                .or_default() += 1;
            totals.max_abs_d_edge = totals.max_abs_d_edge.max(d.abs());
            if d.abs() > 0.10 {
                totals.d_edge_over_0_10 += 1;
            }
            if d.abs() > 0.20 {
                totals.d_edge_over_0_20 += 1;
            }
        }
        for c in &t.crossings {
            *totals.crossings.entry(c.clone()).or_default() += 1;
        }
    }

    Ok(PredictReport {
        calibration_source: epigraph_engine::calibration::CalibrationConfig::cached_source()
            .to_string(),
        profile_hash: epigraph_engine::belief_profile::BeliefProfile::served().profile_hash(),
        run: PredictRun {
            epsilon: opts.epsilon,
            max_passes: opts.max_passes,
            only_changed: opts.only_changed,
            accepted_edges: opts.edges.as_ref().map(BTreeSet::len),
            wave_claims: seed.written.len(),
            moved_sources: seed.moved.len(),
            wave_files: Vec::new(),
        },
        seed_mode: seed_mode.to_string(),
        passes,
        converged,
        unconverged_edges,
        edges: edges_out,
        targets,
        totals,
    })
}
