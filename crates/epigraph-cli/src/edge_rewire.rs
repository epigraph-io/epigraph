//! The targeted edge-factor rewire (R-176(2), R-177(4): class E of the
//! calibration recompute): passes to a fixed point, the snapshot files a
//! rollback restores from, and the compare-and-swap restore of the edge rows.
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
    rewire_edge_targeted, select_targeted_edges, HeldBucket, RewireCapture, StoredEdgeRow,
    TargetedGuards, TargetedOutcome,
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

/// The switches of a targeted run.
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
