//! The retroactive K10(3) sweep's apply and undo (supersede SPEC §11 K10(3),
//! operator decision OD-10; rulings R-178(2), R-179), behind the operator
//! binary `sweep_retired_source_bbas`.
//!
//! # What it removes
//!
//! The live edge-keyed BBAs that claims retired BEFORE the supersede
//! cascade's K10(2) arm existed still hold on current claims: exactly the
//! rows the read-only dry-run delta measures as `k10_retro`
//! (`supersede_belief_delta --items k10-retro`). The plan IS that
//! measurement: [`plan`] calls
//! [`epigraph_engine::supersede_delta::measure_k10_retro`], whose report is
//! the delta's `k10_retro` block, so the rows the apply deletes are the rows
//! the delta counted, and nothing else. Retracted rows are never selected
//! and never deleted (rulings R-79, R-103; migration 194 refuses it anyway).
//!
//! # How
//!
//! [`apply`] runs in ONE `REPEATABLE READ` transaction on the maintenance
//! connection:
//!
//! 1. plan (the measurement) and compare it with the accepted measurement
//!    (`--expect`, a `supersede_belief_delta` report): every count, every
//!    holder, every outcome and every served value (floats within
//!    [`FLOAT_TOLERANCE`]) must match, or nothing is written;
//! 2. refuse a holder the measurement could not predict
//!    ([`DeltaOutcome::VacatePossible`]);
//! 3. read the holders' caches, then run the K10(2) arm over the planned rows
//!    ([`epigraph_engine::retraction_cascade::sweep_retired_source_bbas`]:
//!    per edge, delete exactly the planned rows, probe each holder's repair;
//!    then one recompute pass, nothing re-wired from the retired source);
//! 4. check, before committing: the deleted ids are the planned ids, the
//!    repair reported no error, every holder's cache is what the measurement
//!    predicted, and the selection now returns nothing;
//! 5. append one audit row and hand the snapshot ([`SweepSnapshot`]) to the
//!    caller, which writes and syncs it; then COMMIT.
//!
//! Any failure rolls the whole transaction back.
//!
//! # Undo
//!
//! [`restore_rows`] re-inserts each deleted row from its stored image
//! (`to_jsonb(row)::text`, every column exact) where neither its id nor its
//! upsert key is taken; the binary then restores the holders' caches by
//! compare-and-set from the snapshot's wave records
//! (`belief_cache::restore_wave`), only for holders whose every row came
//! back. Last in, first out: rows before caches. Nothing is re-derived.
//!
//! The SQL lives here rather than in `epigraph-db/src/repos/` for the same
//! reason as `belief_cache`'s: an operator binary's maintenance statements on
//! the maintenance connection, with no request path.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Acquire;
use uuid::Uuid;

use epigraph_engine::retraction_cascade::{
    sweep_retired_source_bbas, CascadeReport, DeletedEdgeBba,
};
use epigraph_engine::supersede_delta::{
    binary_frame_id, measure_k10_retro, retired_source_edge_bbas, DeltaOutcome, EdgeKeyedBba,
    K10RetroReport,
};

use crate::belief_cache::{read_cache_columns, CacheColumns, WaveRecord};

/// The binary's name, in refusals and in the audit rows.
pub const BIN: &str = "sweep_retired_source_bbas";

/// The snapshot file's format version.
pub const SNAPSHOT_FORMAT: u32 = 1;

/// The wave name the snapshot's cache records carry.
pub const WAVE: &str = "k10-retro";

/// `security_events.event_type` of an applied sweep. Not a `cascade.*` type:
/// the cascade replay reads those rows by cause and would count one it cannot
/// rebuild as unreadable.
pub const EVENT_APPLIED: &str = "k10_retro.sweep_applied";

/// `security_events.event_type` of an undo that wrote.
pub const EVENT_UNDONE: &str = "k10_retro.sweep_undone";

/// How close a float must be to the accepted measurement's. The report is
/// read through `serde_json`'s default float parse, which can be one ulp off
/// a 17-digit value; the apply runbook compares at the same tolerance.
pub const FLOAT_TOLERANCE: f64 = 1e-12;

/// The default `top` of the plan's report, the delta binary's default, so a
/// plan and a default measurement list the same top movers.
pub const DEFAULT_TOP: usize = 200;

/// One planned row (an [`EdgeKeyedBba`], which is serialize-only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedRow {
    pub mass_function_id: Uuid,
    pub holder_id: Uuid,
    pub edge_id: Uuid,
    pub source_id: Uuid,
    pub relationship: String,
    pub edge_in_force: bool,
}

impl From<&EdgeKeyedBba> for PlannedRow {
    fn from(r: &EdgeKeyedBba) -> Self {
        Self {
            mass_function_id: r.mass_function_id,
            holder_id: r.holder_id,
            edge_id: r.edge_id,
            source_id: r.source_id,
            relationship: r.relationship.clone(),
            edge_in_force: r.edge_in_force,
        }
    }
}

/// The measured plan: the rows and the `k10_retro` report.
#[derive(Debug, Clone)]
pub struct Plan {
    pub rows: Vec<EdgeKeyedBba>,
    pub report: K10RetroReport,
}

impl Plan {
    /// The plan as the JSON a dry run prints.
    #[must_use]
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "rows": self.rows.iter().map(PlannedRow::from).collect::<Vec<_>>(),
            "k10_retro": self.report,
        })
    }
}

/// The undo file an apply writes before it commits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepSnapshot {
    /// [`BIN`].
    pub tool: String,
    /// [`SNAPSHOT_FORMAT`].
    pub format: u32,
    pub acting_agent: Uuid,
    pub reason: String,
    /// The database clock at the start of the apply's transaction, before its
    /// first write (the wave records' `at`).
    pub at: DateTime<Utc>,
    /// The `k10_retro` block the apply planned from (and matched against the
    /// accepted measurement).
    pub plan: Value,
    pub planned_rows: Vec<PlannedRow>,
    /// Every row deleted, as stored.
    pub deleted: Vec<DeletedEdgeBba>,
    /// Per holder, the cache before and after (`belief_cache::WaveRecord`,
    /// bit-exact floats): the input of the cache half of the undo.
    pub caches: Vec<WaveRecord>,
    /// The repair, as the cascade reports one.
    pub cascade: CascadeReport,
    /// The audit row of the apply; `None` when there was nothing to sweep.
    pub audit_event_id: Option<Uuid>,
}

/// Read a snapshot file's contents.
///
/// # Errors
/// Malformed JSON, or a file another tool or format wrote.
pub fn read_snapshot(text: &str) -> anyhow::Result<SweepSnapshot> {
    let snap: SweepSnapshot = serde_json::from_str(text)?;
    if snap.tool != BIN || snap.format != SNAPSHOT_FORMAT {
        anyhow::bail!(
            "not a {BIN} snapshot of format {SNAPSHOT_FORMAT} (tool `{}`, format {})",
            snap.tool,
            snap.format
        );
    }
    Ok(snap)
}

/// The `k10_retro` block of an accepted measurement: a whole
/// `supersede_belief_delta` report (its `k10_retro` key) or the block itself.
///
/// # Errors
/// Neither shape, or a report measured without `k10-retro`.
pub fn expected_block(v: &Value) -> Result<&Value, String> {
    match v.get("k10_retro") {
        Some(Value::Null) => Err(
            "the expected report was measured without the k10-retro item (`k10_retro` is null)"
                .to_string(),
        ),
        Some(block) => Ok(block),
        None if v.get("live_rows").is_some() && v.get("delta").is_some() => Ok(v),
        None => Err(
            "the expected file is neither a supersede_belief_delta report nor its k10_retro block"
                .to_string(),
        ),
    }
}

/// Every difference between the plan's report and the accepted measurement's
/// `k10_retro` block (see [`expected_block`]); empty when they match.
///
/// Compared field by field over the whole block: integers, strings, ids and
/// the order of the claims exactly, floats within [`FLOAT_TOLERANCE`], `null`
/// only with `null`. `delta.totals.top_movers` is left out: it is the first
/// `top` of a list both sides compute from the claims compared here, and its
/// length depends on the `--top` each run was given.
#[must_use]
pub fn compare_to_measurement(plan: &K10RetroReport, expected: &Value) -> Vec<String> {
    let ours = match serde_json::to_value(plan) {
        Ok(v) => v,
        Err(e) => return vec![format!("serialize the plan: {e}")],
    };
    let mut diffs = Vec::new();
    compare_json("k10_retro", &ours, expected, &mut diffs);
    diffs
}

fn compare_json(path: &str, ours: &Value, theirs: &Value, diffs: &mut Vec<String>) {
    match (ours, theirs) {
        (Value::Object(a), Value::Object(b)) => {
            let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
            for k in keys {
                if path == "k10_retro.delta.totals" && k == "top_movers" {
                    continue;
                }
                let p = format!("{path}.{k}");
                match (a.get(k), b.get(k)) {
                    (Some(x), Some(y)) => compare_json(&p, x, y, diffs),
                    (Some(x), None) => diffs.push(format!("{p}: plan {x}, measurement has none")),
                    (None, Some(y)) => diffs.push(format!("{p}: measurement {y}, plan has none")),
                    (None, None) => {}
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                diffs.push(format!(
                    "{path}: plan has {} entries, measurement {}",
                    a.len(),
                    b.len()
                ));
                return;
            }
            for (i, (x, y)) in a.iter().zip(b).enumerate() {
                compare_json(&format!("{path}[{i}]"), x, y, diffs);
            }
        }
        (Value::Number(a), Value::Number(b)) => {
            let exact = (a.as_i64().is_some() || a.as_u64().is_some())
                && (b.as_i64().is_some() || b.as_u64().is_some());
            let same = if exact {
                a.as_i64() == b.as_i64() && a.as_u64() == b.as_u64()
            } else {
                match (a.as_f64(), b.as_f64()) {
                    (Some(x), Some(y)) => (x - y).abs() <= FLOAT_TOLERANCE,
                    _ => false,
                }
            };
            if !same {
                diffs.push(format!("{path}: plan {a}, measurement {b}"));
            }
        }
        (a, b) => {
            if a != b {
                diffs.push(format!("{path}: plan {a}, measurement {b}"));
            }
        }
    }
}

/// The holders whose outcome the measurement does not predict (a real run
/// may VACATE the cache, ruling R-80): an apply refuses while any exists.
#[must_use]
pub fn unpredicted(plan: &K10RetroReport) -> Vec<Uuid> {
    plan.delta
        .claims
        .iter()
        .filter(|c| c.outcome == DeltaOutcome::VacatePossible)
        .map(|c| c.id)
        .collect()
}

fn close(a: Option<f64>, b: Option<f64>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => (x - y).abs() <= FLOAT_TOLERANCE,
        (None, None) => true,
        _ => false,
    }
}

/// Every holder whose cache after the sweep is not what the measurement
/// predicted, with why; empty when every one is.
///
/// * `recomputed`: Bel, Pl and BetP are the predicted fold's;
/// * `unbacked`: Bel, Pl and BetP are NULL (the cache was cleared);
/// * `kept_other_frame`, `no_cache`: the cache is exactly what it was.
#[must_use]
pub fn check_predictions(
    plan: &K10RetroReport,
    before: &HashMap<Uuid, CacheColumns>,
    after: &HashMap<Uuid, CacheColumns>,
) -> Vec<String> {
    let mut bad = Vec::new();
    for c in &plan.delta.claims {
        let Some(got) = after.get(&c.id) else {
            bad.push(format!(
                "{}: the holder cannot be read after the sweep",
                c.id
            ));
            continue;
        };
        let ok = match c.outcome {
            DeltaOutcome::Recomputed => c.new.is_some_and(|n| {
                close(got.belief, n.belief)
                    && close(got.plausibility, n.plausibility)
                    && close(got.pignistic_prob, n.betp)
            }),
            DeltaOutcome::Unbacked => {
                got.belief.is_none() && got.plausibility.is_none() && got.pignistic_prob.is_none()
            }
            DeltaOutcome::KeptOtherFrame | DeltaOutcome::NoCache => before.get(&c.id) == Some(got),
            DeltaOutcome::VacatePossible => false,
        };
        if !ok {
            bad.push(format!(
                "{}: predicted {:?} {:?}, the sweep left (Bel {:?}, Pl {:?}, BetP {:?})",
                c.id, c.outcome, c.new, got.belief, got.plausibility, got.pignistic_prob
            ));
        }
    }
    bad
}

/// The plan, in whatever transaction `conn` is in: the measurement itself.
///
/// # Errors
/// Any read's error.
pub async fn plan(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    top: usize,
) -> Result<Plan, String> {
    let frame = binary_frame_id(&mut *conn, viewer).await?;
    let (rows, report) = measure_k10_retro(&mut *conn, viewer, frame, top).await?;
    Ok(Plan { rows, report })
}

/// The dry run: [`plan`] in one `REPEATABLE READ READ ONLY` transaction,
/// rolled back. Writes nothing.
///
/// # Errors
/// Any read's error.
pub async fn dry_run(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    top: usize,
) -> Result<Plan, String> {
    let mut tx = epigraph_engine::supersede_delta::begin_read_only(&mut *conn)
        .await
        .map_err(|e| format!("begin the read-only transaction: {e}"))?;
    let planned = plan(&mut tx, viewer, top).await;
    tx.rollback()
        .await
        .map_err(|e| format!("end the read-only transaction: {e}"))?;
    planned
}

/// Who runs an apply or an undo, and why: recorded in the audit row and the
/// snapshot.
#[derive(Debug, Clone)]
pub struct Operator {
    pub acting_agent: Uuid,
    pub reason: String,
}

async fn audit(
    conn: &mut sqlx::PgConnection,
    event_type: &str,
    details: Value,
) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    // Agent-less (readable by privileged and admin sessions only): the row
    // names other writers' rows; the operator is in `details`.
    epigraph_db::SecurityEventRepository::log_conn(
        &mut *conn,
        &epigraph_db::SecurityEventRow {
            id,
            event_type: event_type.to_string(),
            agent_id: None,
            success: Some(true),
            details,
            ip_address: None,
            user_agent: None,
            correlation_id: None,
            created_at: Utc::now(),
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("write the audit row: {e}"))?;
    Ok(id)
}

/// The apply (see the module doc), on the maintenance connection `conn` and
/// its bypass `viewer`. `expected` is the accepted measurement (a whole
/// report or its `k10_retro` block). `persist` receives the snapshot before
/// the COMMIT and must make it durable; its failure rolls everything back.
/// Once it has succeeded the caller must keep the file whatever this returns:
/// a failed COMMIT may still have landed.
///
/// With nothing to sweep (the plan, matching the measurement, selects no
/// row), nothing is written to the database and the snapshot lists nothing.
///
/// # Errors
/// A mismatch with the measurement, an unpredicted holder, any repair error,
/// any failed post-check, `persist`'s error, or a database error. Every one
/// rolls the transaction back.
pub async fn apply<F>(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    operator: &Operator,
    expected: &Value,
    top: usize,
    persist: F,
) -> anyhow::Result<SweepSnapshot>
where
    F: FnOnce(&SweepSnapshot) -> anyhow::Result<()>,
{
    let expected = expected_block(expected).map_err(|e| anyhow::anyhow!(e))?;
    let mut tx = sqlx::Connection::begin_with(
        &mut *conn,
        "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ",
    )
    .await?;
    let result = apply_in(&mut tx, viewer, operator, expected, top).await;
    let snapshot = match result {
        Ok(s) => s,
        Err(e) => {
            let _ = tx.rollback().await;
            return Err(e);
        }
    };
    if let Err(e) = persist(&snapshot) {
        let _ = tx.rollback().await;
        return Err(e.context("the snapshot was not written; nothing was committed"));
    }
    tx.commit().await.map_err(|e| {
        anyhow::anyhow!(
            "COMMIT failed ({e}): its outcome is unknown, and the snapshot was kept. Run \
             --undo <snapshot> --dry-run to see which rows are gone"
        )
    })?;
    Ok(snapshot)
}

async fn apply_in(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    operator: &Operator,
    expected: &Value,
    top: usize,
) -> anyhow::Result<SweepSnapshot> {
    let planned = plan(&mut *conn, viewer, top)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let diffs = compare_to_measurement(&planned.report, expected);
    if !diffs.is_empty() {
        anyhow::bail!(
            "the plan differs from the accepted measurement in {} place(s); nothing was \
             written. Re-measure (supersede_belief_delta --items k10-retro) and re-accept:\n  {}",
            diffs.len(),
            diffs.join("\n  ")
        );
    }
    let vacate = unpredicted(&planned.report);
    if !vacate.is_empty() {
        anyhow::bail!(
            "the measurement does not predict {} holder(s) (outcome vacate_possible): {vacate:?}; \
             nothing was written. Their outcome needs a ruling first",
            vacate.len()
        );
    }
    let at: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&mut *conn)
        .await?;
    let planned_rows: Vec<PlannedRow> = planned.rows.iter().map(PlannedRow::from).collect();
    let plan_json = serde_json::to_value(&planned.report)?;
    if planned.rows.is_empty() {
        return Ok(SweepSnapshot {
            tool: BIN.to_string(),
            format: SNAPSHOT_FORMAT,
            acting_agent: operator.acting_agent,
            reason: operator.reason.clone(),
            at,
            plan: plan_json,
            planned_rows,
            deleted: Vec::new(),
            caches: Vec::new(),
            cascade: CascadeReport::default(),
            audit_event_id: None,
        });
    }

    let holders: Vec<Uuid> = planned
        .rows
        .iter()
        .map(|r| r.holder_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let before = read_cache_columns(&mut *conn, &holders).await?;

    let sweep = sweep_retired_source_bbas(&mut *conn, viewer, &planned.rows).await;
    if !sweep.report.errors.is_empty() {
        anyhow::bail!(
            "the sweep's repair reported {} error(s); nothing was committed:\n  {}",
            sweep.report.errors.len(),
            sweep.report.errors.join("\n  ")
        );
    }
    let want: BTreeSet<Uuid> = planned.rows.iter().map(|r| r.mass_function_id).collect();
    let got: BTreeSet<Uuid> = sweep.deleted.iter().map(|d| d.id).collect();
    if want != got || sweep.deleted.len() != want.len() {
        anyhow::bail!(
            "the sweep deleted {} row(s), the plan named {}; not deleted: {:?}, not planned: \
             {:?}; nothing was committed",
            sweep.deleted.len(),
            want.len(),
            want.difference(&got).collect::<Vec<_>>(),
            got.difference(&want).collect::<Vec<_>>()
        );
    }
    let after = read_cache_columns(&mut *conn, &holders).await?;
    let bad = check_predictions(&planned.report, &before, &after);
    if !bad.is_empty() {
        anyhow::bail!(
            "{} holder(s) are not what the measurement predicted; nothing was committed:\n  {}",
            bad.len(),
            bad.join("\n  ")
        );
    }
    let left = retired_source_edge_bbas(&mut *conn, None).await?;
    if !left.is_empty() {
        anyhow::bail!(
            "{} live row(s) from retired sources remain after the sweep; nothing was committed",
            left.len()
        );
    }

    let mut caches = Vec::with_capacity(holders.len());
    for id in &holders {
        let (Some(b), Some(w)) = (before.get(id), after.get(id)) else {
            anyhow::bail!("holder {id} cannot be read; nothing was committed");
        };
        caches.push(WaveRecord {
            claim_id: *id,
            before: b.clone(),
            written: w.clone(),
            wave: WAVE.to_string(),
            at,
        });
    }
    let mut by_relationship: BTreeMap<String, usize> = BTreeMap::new();
    for r in &planned.rows {
        *by_relationship.entry(r.relationship.clone()).or_insert(0) += 1;
    }
    let audit_id = audit(
        &mut *conn,
        EVENT_APPLIED,
        serde_json::json!({
            "tool": BIN,
            "acting_agent": operator.acting_agent,
            "reason": operator.reason,
            "rows_deleted": sweep.deleted.len(),
            "holders": holders,
            "recomputed": sweep.report.recomputed,
            "unbacked": sweep.report.unbacked,
            "by_relationship": by_relationship,
            "mass_function_ids": want,
            "edges": planned.rows.iter().map(|r| r.edge_id).collect::<BTreeSet<_>>(),
            "retired_sources": planned.rows.iter().map(|r| r.source_id).collect::<BTreeSet<_>>(),
        }),
    )
    .await?;
    Ok(SweepSnapshot {
        tool: BIN.to_string(),
        format: SNAPSHOT_FORMAT,
        acting_agent: operator.acting_agent,
        reason: operator.reason.clone(),
        at,
        plan: plan_json,
        planned_rows,
        deleted: sweep.deleted,
        caches,
        cascade: sweep.report,
        audit_event_id: Some(audit_id),
    })
}

/// Per-row outcome of [`restore_rows`]. Each row is in exactly one bucket.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RowRestoreReport {
    /// Re-inserted from the stored image.
    pub restored: Vec<Uuid>,
    /// A row with this id already holds exactly the stored image.
    pub already_restored: Vec<Uuid>,
    /// Its id holds a different row, or its upsert key
    /// `(claim, frame, agent, perspective)` is taken by another row (written
    /// since the sweep): left alone.
    pub superseded_since_sweep: Vec<Uuid>,
    /// Its holder claim no longer exists.
    pub missing: Vec<Uuid>,
    /// The insert failed (a referenced row gone, a guard): left alone, with
    /// the error.
    pub failed: Vec<(Uuid, String)>,
}

impl RowRestoreReport {
    /// The holders every one of whose rows is back (restored now or already):
    /// the only holders whose caches the undo may restore.
    #[must_use]
    pub fn holders_whole(&self, deleted: &[DeletedEdgeBba]) -> HashSet<Uuid> {
        let back: HashSet<Uuid> = self
            .restored
            .iter()
            .chain(&self.already_restored)
            .copied()
            .collect();
        let mut whole: HashSet<Uuid> = deleted.iter().map(|d| d.holder_id).collect();
        for d in deleted {
            if !back.contains(&d.id) {
                whole.remove(&d.holder_id);
            }
        }
        whole
    }
}

/// Re-insert the row from its image where neither its id nor its upsert key
/// is taken and its holder exists. `INSERT ... SELECT` from the image, so
/// every column is the stored one (the AFTER INSERT tenancy inheritance then
/// stamps it from the claim, as on any insert).
const RESTORE_ROW_SQL: &str = r#"-- VISIBILITY-EXEMPT: the K10(3) sweep's undo runs on the privileged maintenance connection only.
INSERT INTO mass_functions
SELECT r.* FROM jsonb_populate_record(NULL::mass_functions, $1::jsonb) r
 WHERE NOT EXISTS (SELECT 1 FROM mass_functions m WHERE m.id = r.id)
   AND NOT EXISTS (SELECT 1 FROM mass_functions m
                    WHERE m.claim_id = r.claim_id AND m.frame_id = r.frame_id
                      AND m.source_agent_id IS NOT DISTINCT FROM r.source_agent_id
                      AND m.perspective_id IS NOT DISTINCT FROM r.perspective_id)
   AND EXISTS (SELECT 1 FROM claims c WHERE c.id = r.claim_id)
RETURNING id"#;

/// Why a row was not re-inserted: (a row with its id holds exactly the
/// image, its id is taken, its key is taken, its holder exists).
const RESTORE_PROBE_SQL: &str = r#"-- VISIBILITY-EXEMPT: the K10(3) sweep's undo runs on the privileged maintenance connection only.
SELECT EXISTS (SELECT 1 FROM mass_functions m WHERE m.id = r.id AND to_jsonb(m.*) = $1::jsonb),
       EXISTS (SELECT 1 FROM mass_functions m WHERE m.id = r.id),
       EXISTS (SELECT 1 FROM mass_functions m
                WHERE m.claim_id = r.claim_id AND m.frame_id = r.frame_id
                  AND m.source_agent_id IS NOT DISTINCT FROM r.source_agent_id
                  AND m.perspective_id IS NOT DISTINCT FROM r.perspective_id),
       EXISTS (SELECT 1 FROM claims c WHERE c.id = r.claim_id)
  FROM jsonb_populate_record(NULL::mass_functions, $1::jsonb) r"#;

/// The row half of the undo: re-insert every deleted row (last deleted
/// first) from its image, in ONE transaction on `conn`, each in its own
/// savepoint so one failure is reported alone. With `dry_run` the whole
/// transaction is rolled back. A non-dry run that restored anything appends
/// one audit row in the same transaction.
///
/// # Errors
/// A database error outside a row's savepoint (the transaction, the probe,
/// the audit row); nothing of this call is then committed.
pub async fn restore_rows(
    conn: &mut sqlx::PgConnection,
    deleted: &[DeletedEdgeBba],
    operator: &Operator,
    snapshot_audit: Option<Uuid>,
    dry_run: bool,
) -> anyhow::Result<RowRestoreReport> {
    let mut report = RowRestoreReport::default();
    let mut tx = conn.begin().await?;
    for d in deleted.iter().rev() {
        let mut sp = Acquire::begin(&mut *tx).await?;
        match sqlx::query_scalar::<_, Uuid>(RESTORE_ROW_SQL)
            .bind(&d.row)
            .fetch_optional(&mut *sp)
            .await
        {
            Ok(Some(_)) => {
                sp.commit().await?;
                report.restored.push(d.id);
                continue;
            }
            Ok(None) => {
                sp.rollback().await?;
            }
            Err(e) => {
                sp.rollback().await?;
                report.failed.push((d.id, e.to_string()));
                continue;
            }
        }
        let (same, id_taken, key_taken, holder): (bool, bool, bool, bool) =
            sqlx::query_as(RESTORE_PROBE_SQL)
                .bind(&d.row)
                .fetch_one(&mut *tx)
                .await?;
        if same {
            report.already_restored.push(d.id);
        } else if id_taken || key_taken {
            report.superseded_since_sweep.push(d.id);
        } else if !holder {
            report.missing.push(d.id);
        } else {
            report.failed.push((
                d.id,
                "not re-inserted, for no reason the probe names".into(),
            ));
        }
    }
    if dry_run {
        tx.rollback().await?;
        return Ok(report);
    }
    if !report.restored.is_empty() {
        audit(
            &mut tx,
            EVENT_UNDONE,
            serde_json::json!({
                "tool": BIN,
                "acting_agent": operator.acting_agent,
                "reason": operator.reason,
                "undoes": snapshot_audit,
                "rows_restored": report.restored,
                "rows_already_restored": report.already_restored,
                "rows_superseded_since_sweep": report.superseded_since_sweep,
                "rows_missing": report.missing,
                "rows_failed": report.failed.iter().map(|(id, _)| id).collect::<Vec<_>>(),
            }),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_engine::supersede_delta::{ClaimDelta, DeltaBlock, DeltaTotals, Served};

    fn served(b: f64, pl: f64, p: f64) -> Served {
        Served {
            belief: Some(b),
            plausibility: Some(pl),
            betp: Some(p),
        }
    }

    fn report(claims: Vec<ClaimDelta>) -> K10RetroReport {
        K10RetroReport {
            live_rows: claims.len(),
            edges: claims.len(),
            edges_not_in_force: 0,
            retired_sources: 1,
            retracted_key_kept: 0,
            by_relationship: BTreeMap::from([("refutes".to_string(), claims.len())]),
            delta: DeltaBlock {
                rows: claims.len(),
                totals: DeltaTotals {
                    claims: claims.len(),
                    ..DeltaTotals::default()
                },
                claims,
            },
        }
    }

    fn unbacked(id: Uuid) -> ClaimDelta {
        ClaimDelta {
            id,
            old: served(0.0, 0.64, 0.32),
            new: Some(Served {
                belief: None,
                plausibility: None,
                betp: None,
            }),
            delta: None,
            outcome: DeltaOutcome::Unbacked,
            causes: vec!["k10_retro"],
            rows_removed: 1,
            crosses_half: true,
        }
    }

    fn cache(b: Option<f64>, pl: Option<f64>, p: Option<f64>) -> CacheColumns {
        CacheColumns {
            belief: b,
            plausibility: pl,
            pignistic_prob: p,
            mass_on_empty: Some(0.0),
            mass_on_missing: Some(0.0),
            belief_frame_id: None,
            classification: None,
        }
    }

    #[test]
    fn a_measurement_equal_to_the_plan_has_no_difference_in_either_shape() {
        let id = Uuid::new_v4();
        let plan = report(vec![unbacked(id)]);
        let whole = serde_json::json!({ "items": {}, "k10_retro": plan });
        let block = expected_block(&whole).expect("the report shape");
        assert!(compare_to_measurement(&plan, block).is_empty());
        let bare = serde_json::to_value(&plan).unwrap();
        let block = expected_block(&bare).expect("the bare block shape");
        assert!(compare_to_measurement(&plan, block).is_empty());
    }

    #[test]
    fn a_report_without_the_item_or_of_another_shape_is_refused() {
        assert!(expected_block(&serde_json::json!({ "k10_retro": null })).is_err());
        assert!(expected_block(&serde_json::json!({ "r131": {} })).is_err());
    }

    #[test]
    fn every_kind_of_drift_from_the_measurement_is_named() {
        let id = Uuid::new_v4();
        let plan = report(vec![unbacked(id)]);
        let base = serde_json::to_value(&plan).unwrap();

        // A count.
        let mut m = base.clone();
        m["live_rows"] = serde_json::json!(2);
        let d = compare_to_measurement(&plan, &m);
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(d[0].starts_with("k10_retro.live_rows"), "{d:?}");

        // Another holder.
        let mut m = base.clone();
        m["delta"]["claims"][0]["id"] = serde_json::json!(Uuid::new_v4());
        let d = compare_to_measurement(&plan, &m);
        assert!(d.iter().any(|s| s.contains("claims[0].id")), "{d:?}");

        // An extra holder.
        let mut m = base.clone();
        let extra = serde_json::to_value(unbacked(Uuid::new_v4())).unwrap();
        m["delta"]["claims"].as_array_mut().unwrap().push(extra);
        let d = compare_to_measurement(&plan, &m);
        assert!(
            d.iter().any(|s| s.contains("1 entries, measurement 2")),
            "{d:?}"
        );

        // A served value that drifted past the tolerance, and one within it.
        let mut m = base.clone();
        m["delta"]["claims"][0]["old"]["betp"] = serde_json::json!(0.32 + 1e-9);
        let d = compare_to_measurement(&plan, &m);
        assert!(d.iter().any(|s| s.contains("old.betp")), "{d:?}");
        let mut m = base.clone();
        m["delta"]["claims"][0]["old"]["betp"] = serde_json::json!(0.32 + 1e-15);
        assert!(compare_to_measurement(&plan, &m).is_empty());

        // An outcome, and a null where the plan has a value.
        let mut m = base.clone();
        m["delta"]["claims"][0]["outcome"] = serde_json::json!("recomputed");
        let d = compare_to_measurement(&plan, &m);
        assert!(d.iter().any(|s| s.contains("outcome")), "{d:?}");
        let mut m = base.clone();
        m["delta"]["claims"][0]["old"]["belief"] = Value::Null;
        let d = compare_to_measurement(&plan, &m);
        assert!(d.iter().any(|s| s.contains("old.belief")), "{d:?}");

        // A relationship.
        let mut m = base.clone();
        m["by_relationship"] = serde_json::json!({ "contradicts": 1 });
        let d = compare_to_measurement(&plan, &m);
        assert_eq!(d.len(), 2, "{d:?}");

        // top_movers is not compared (its length is the run's --top).
        let mut m = base;
        m["delta"]["totals"]["top_movers"] = serde_json::json!([Uuid::new_v4()]);
        assert!(compare_to_measurement(&plan, &m).is_empty());
    }

    #[test]
    fn a_holder_the_measurement_cannot_predict_is_named() {
        let id = Uuid::new_v4();
        let mut c = unbacked(id);
        c.outcome = DeltaOutcome::VacatePossible;
        c.new = None;
        assert_eq!(unpredicted(&report(vec![c])), vec![id]);
        assert!(unpredicted(&report(vec![unbacked(id)])).is_empty());
    }

    #[test]
    fn a_cache_is_checked_against_each_outcome() {
        let gone = Uuid::new_v4();
        let folded = Uuid::new_v4();
        let kept = Uuid::new_v4();
        let mut rec = unbacked(folded);
        rec.outcome = DeltaOutcome::Recomputed;
        rec.new = Some(served(0.2, 0.6, 0.4));
        let mut keep = unbacked(kept);
        keep.outcome = DeltaOutcome::KeptOtherFrame;
        let plan = report(vec![unbacked(gone), rec, keep]);
        let before = HashMap::from([
            (gone, cache(Some(0.0), Some(0.64), Some(0.32))),
            (folded, cache(Some(0.1), Some(0.7), Some(0.4))),
            (kept, cache(Some(0.3), Some(0.8), Some(0.55))),
        ]);
        let good = HashMap::from([
            (gone, cache(None, None, None)),
            (folded, cache(Some(0.2), Some(0.6), Some(0.4))),
            (kept, cache(Some(0.3), Some(0.8), Some(0.55))),
        ]);
        assert!(check_predictions(&plan, &before, &good).is_empty());

        // Each wrong: a cleared claim that kept a value, a fold off the
        // prediction, a kept cache that moved, a holder that vanished.
        let mut bad = good.clone();
        bad.insert(gone, cache(Some(0.0), Some(0.64), Some(0.32)));
        bad.insert(folded, cache(Some(0.2), Some(0.6), Some(0.41)));
        bad.insert(kept, cache(Some(0.3), Some(0.8), Some(0.56)));
        assert_eq!(check_predictions(&plan, &before, &bad).len(), 3);
        let mut lost = good;
        lost.remove(&gone);
        let d = check_predictions(&plan, &before, &lost);
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(d[0].contains("cannot be read"), "{d:?}");
    }

    #[test]
    fn a_holder_is_whole_only_when_every_row_it_lost_came_back() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let row = |holder: Uuid| DeletedEdgeBba {
            id: Uuid::new_v4(),
            holder_id: holder,
            edge_id: Uuid::new_v4(),
            row: "{}".into(),
        };
        let deleted = vec![row(a), row(a), row(b)];
        let report = RowRestoreReport {
            restored: vec![deleted[0].id, deleted[2].id],
            superseded_since_sweep: vec![deleted[1].id],
            ..RowRestoreReport::default()
        };
        assert_eq!(report.holders_whole(&deleted), HashSet::from([b]));
        let report = RowRestoreReport {
            restored: vec![deleted[0].id],
            already_restored: vec![deleted[1].id, deleted[2].id],
            ..RowRestoreReport::default()
        };
        assert_eq!(report.holders_whole(&deleted), HashSet::from([a, b]));
    }

    #[test]
    fn a_snapshot_of_another_tool_or_format_is_refused() {
        let snap = SweepSnapshot {
            tool: BIN.into(),
            format: SNAPSHOT_FORMAT,
            acting_agent: Uuid::new_v4(),
            reason: "r".into(),
            at: Utc::now(),
            plan: Value::Null,
            planned_rows: Vec::new(),
            deleted: Vec::new(),
            caches: Vec::new(),
            cascade: CascadeReport::default(),
            audit_event_id: None,
        };
        let text = serde_json::to_string(&snap).unwrap();
        let back = read_snapshot(&text).expect("its own snapshot reads back");
        assert_eq!(back.acting_agent, snap.acting_agent);
        assert_eq!(back.at, snap.at);
        let other = text.replace(BIN, "refresh_truth_mirrors");
        assert!(read_snapshot(&other).is_err());
        let mut v: Value = serde_json::from_str(&text).unwrap();
        v["format"] = serde_json::json!(2);
        assert!(read_snapshot(&v.to_string()).is_err());
    }
}
