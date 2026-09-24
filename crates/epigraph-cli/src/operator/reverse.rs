//! `reown-reverse`: restore every row a manifest names to its recorded owner.
//!
//! # Order inside a batch
//!
//! 1. Lock the batch's claims `FOR UPDATE`, and the cascade tables with no key
//!    to `claims` (`tables::lock_unkeyed_tables`), as the re-own does.
//! 2. Put each claim back on its recorded owner. The tenancy trigger then
//!    copies that owner onto EVERY row derived from the claim.
//! 3. Put every recorded row back on ITS OWN recorded tenancy. This is the
//!    step that makes reversal exact: a derived row whose owner differed from
//!    its claim's before the re-own (a `keep-writer` row, or one that simply
//!    disagreed) gets its own owner back, never the claim's re-propagated one.
//!
//! A row the manifest does not name (a derived row written after the re-own)
//! is left where the trigger puts it, which is where it would have been had
//! the claim never moved. Its visibility is still checked.
//!
//! # Refusals
//!
//! A claim whose owner is now NEITHER the manifest's target group NOR its
//! recorded prior owner has been moved by something else since; it is HELD
//! with its rows, not overwritten. A claim whose visibility changed since is
//! held too.
//!
//! # Idempotent
//!
//! A claim already on its recorded owner is not updated, and a row already in
//! its recorded state is not written, so a second run changes nothing and its
//! counter census is all zeros.

use super::manifest::{self, Record};
use super::reown::{counter_delta, counter_violations, BatchError};
use super::tables::{
    self, app_readable, fetch_attached, fetch_claims, refetch_tenancy, write_tenancy,
    xact_counters, Kind, RowKey, TableSpec, Tenancy,
};
use anyhow::{anyhow, bail, Context};
use serde_json::json;
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use uuid::Uuid;

/// Everything `reown-reverse` was told.
#[derive(Clone, Debug)]
pub struct Options {
    pub manifest: PathBuf,
    pub apply: bool,
    pub batch_size: usize,
    pub lock_timeout: String,
}

/// A manifest resolved against the live table specs.
pub struct Resolved {
    pub target: Uuid,
    /// Claim id → its record, in manifest order.
    pub claims: Vec<(Uuid, Record)>,
    /// Every non-claim record by row key.
    pub rows: BTreeMap<RowKey, Record>,
}

/// # Errors
/// The header lacks a target group, or a record names a table the live
/// cascade does not know.
pub fn resolve(m: &manifest::Manifest, specs: &[TableSpec]) -> anyhow::Result<Resolved> {
    let target = m
        .header
        .get("target_group_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("manifest header has no target_group_id"))
        .and_then(|s| Uuid::parse_str(s).context("target_group_id"))?;
    let mut claims = Vec::new();
    let mut rows = BTreeMap::new();
    for r in &m.records {
        let spec = tables::spec(specs, &r.table).ok_or_else(|| {
            anyhow!(
                "manifest names table {}, which the live epigraph_propagate_tenancy does not \
                 cascade to; refusing",
                r.table
            )
        })?;
        let pk = spec.pk_from_json(&r.id)?;
        if spec.kind == Kind::Claims {
            let id = Uuid::parse_str(&pk).context("claim id")?;
            claims.push((id, r.clone()));
        } else {
            rows.insert((r.table.clone(), pk), r.clone());
        }
    }
    Ok(Resolved {
        target,
        claims,
        rows,
    })
}

fn recorded_tenancy(r: &Record, current: &Tenancy) -> Tenancy {
    Tenancy {
        owner: r.owner_group_id,
        visibility: r.visibility.clone(),
        co_owner: match r.co_owner_group_id {
            Some(co) => co,
            None => current.co_owner,
        },
    }
}

/// What one reversal batch did.
#[derive(Default, Debug)]
pub struct Outcome {
    pub claims_restored: usize,
    pub rows_restored: BTreeMap<String, usize>,
    pub held: Vec<(Uuid, String)>,
    pub missing_rows: usize,
}

/// Run one reversal batch inside the caller's transaction. Does NOT commit.
///
/// # Errors
/// [`BatchError`], as for the re-own.
pub async fn run_batch(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    unkeyed: &[String],
    res: &Resolved,
    batch: &[(Uuid, Record)],
    lock_timeout: &str,
) -> Result<Outcome, BatchError> {
    let mut out = Outcome::default();
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(lock_timeout)
        .execute(&mut *conn)
        .await?;
    let ids: Vec<Uuid> = batch.iter().map(|(id, _)| *id).collect();
    let locked = fetch_claims(conn, &ids, true).await?;
    tables::lock_unkeyed_tables(conn, unkeyed).await?;
    let now: BTreeMap<Uuid, _> = locked.iter().map(|c| (c.id, c)).collect();
    let mut work: Vec<(Uuid, &Record)> = Vec::new();
    for (id, rec) in batch {
        let Some(c) = now.get(id) else {
            out.held.push((*id, "claim no longer exists".into()));
            continue;
        };
        if c.visibility != rec.visibility {
            out.held.push((
                *id,
                format!(
                    "visibility is {} now, {} when recorded; not reversing",
                    c.visibility, rec.visibility
                ),
            ));
            continue;
        }
        if c.owner != res.target && c.owner != rec.owner_group_id {
            out.held.push((
                *id,
                format!(
                    "owned by {} now, which is neither the re-own target {} nor the recorded \
                     owner {}; something else moved it, not reversing",
                    c.owner, res.target, rec.owner_group_id
                ),
            ));
            continue;
        }
        work.push((*id, rec));
    }
    if work.is_empty() {
        return Ok(out);
    }
    let claim_ids: Vec<Uuid> = work.iter().map(|(id, _)| *id).collect();
    let s0 = fetch_attached(conn, specs, &claim_ids).await?;
    let keys: BTreeSet<RowKey> = s0.keys().cloned().collect();
    let readable_before = app_readable(conn, specs, &claim_ids, &keys).await?;
    let counters_before = xact_counters(conn).await?;

    let payload: Vec<serde_json::Value> = work
        .iter()
        .map(|(id, r)| json!({"id": id, "o": r.owner_group_id}))
        .collect();
    let claims_updated = sqlx::query(
        "UPDATE claims c SET owner_group_id = m.o \
           FROM jsonb_to_recordset($1::jsonb) AS m(id uuid, o uuid) \
          WHERE c.id = m.id AND c.owner_group_id = $2 AND c.owner_group_id <> m.o",
    )
    .bind(serde_json::Value::Array(payload))
    .bind(res.target)
    .execute(&mut *conn)
    .await
    .context("UPDATE claims")?
    .rows_affected();

    let s1 = refetch_tenancy(conn, specs, &claim_ids, &keys).await?;
    let mut trigger_changed: BTreeMap<String, i64> = BTreeMap::new();
    for (k, a) in &s0 {
        if s1.get(k) != Some(&a.tenancy) {
            *trigger_changed.entry(k.0.clone()).or_default() += 1;
        }
    }
    let mut to_write: BTreeMap<String, Vec<(String, Tenancy)>> = BTreeMap::new();
    for k in &keys {
        if let (Some(rec), Some(cur)) = (res.rows.get(k), s1.get(k)) {
            let want = recorded_tenancy(rec, cur);
            if *cur != want {
                to_write
                    .entry(k.0.clone())
                    .or_default()
                    .push((k.1.clone(), want));
            }
        }
    }
    let mut restored: BTreeMap<String, i64> = BTreeMap::new();
    for (t, rows) in &to_write {
        let spec = tables::spec(specs, t).expect("keys come from specs");
        let n = write_tenancy(conn, spec, &claim_ids, rows).await?;
        restored.insert(t.clone(), i64::try_from(n).unwrap_or(i64::MAX));
    }
    let s2 = refetch_tenancy(conn, specs, &claim_ids, &keys).await?;
    let after = fetch_claims(conn, &claim_ids, false).await?;
    let counters_after = xact_counters(conn).await?;
    let readable_after = app_readable(conn, specs, &claim_ids, &keys).await?;

    // ---- invariants ----
    let mut v = Vec::new();
    let recs: BTreeMap<Uuid, &Record> = work.iter().map(|(id, r)| (*id, *r)).collect();
    for c in &after {
        let r = recs[&c.id];
        if c.owner != r.owner_group_id {
            v.push(format!(
                "claim {} is owned by {}, the manifest records {}",
                c.id, c.owner, r.owner_group_id
            ));
        }
        if c.visibility != r.visibility {
            v.push(format!("claim {} visibility changed", c.id));
        }
    }
    for (k, a) in &s0 {
        let Some(got) = s2.get(k) else {
            v.push(format!("{} {} vanished during the batch", k.0, k.1));
            continue;
        };
        if got.visibility != a.tenancy.visibility {
            v.push(format!(
                "{} {} visibility changed {} -> {}",
                k.0, k.1, a.tenancy.visibility, got.visibility
            ));
        }
        if let Some(rec) = res.rows.get(k) {
            let want = recorded_tenancy(rec, got);
            if *got != want {
                v.push(format!(
                    "{} {} ended as {got:?}, the manifest records {want:?}",
                    k.0, k.1
                ));
            }
        }
    }
    let mut expect_counts: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    if claims_updated > 0 {
        expect_counts.insert(
            "claims".into(),
            (0, i64::try_from(claims_updated).unwrap_or(i64::MAX), 0),
        );
    }
    for (t, n) in trigger_changed.iter().chain(restored.iter()) {
        expect_counts.entry(t.clone()).or_default().1 += n;
    }
    expect_counts.retain(|_, d| *d != (0, 0, 0));
    v.extend(counter_violations(
        &counter_delta(&counters_before, &counters_after),
        &expect_counts,
    ));
    if readable_before != readable_after {
        v.push(format!(
            "the rows an unstamped epigraph_app session can read changed: lost {:?}, gained {:?}",
            readable_before
                .difference(&readable_after)
                .collect::<Vec<_>>(),
            readable_after
                .difference(&readable_before)
                .collect::<Vec<_>>()
        ));
    }
    if !v.is_empty() {
        return Err(BatchError::Invariant(v));
    }
    let claim_set: BTreeSet<Uuid> = claim_ids.iter().copied().collect();
    out.missing_rows = res
        .rows
        .iter()
        .filter(|(k, r)| claim_set.contains(&r.claim_id) && !keys.contains(*k))
        .count();
    out.claims_restored = usize::try_from(claims_updated).unwrap_or(usize::MAX);
    for (t, n) in restored {
        out.rows_restored
            .insert(t, usize::try_from(n).unwrap_or(usize::MAX));
    }
    Ok(out)
}

/// Totals for the caller.
#[derive(Default, Debug)]
pub struct Report {
    pub claims_restored: usize,
    pub rows_restored: BTreeMap<String, usize>,
    pub held: Vec<(Uuid, String)>,
    pub missing_rows: usize,
    pub batch_failures: Vec<(usize, String)>,
}

fn tally(
    report: &mut Report,
    out: &mut dyn std::io::Write,
    n: usize,
    total: usize,
    result: Result<Outcome, BatchError>,
    apply: bool,
) -> anyhow::Result<bool> {
    match result {
        Ok(o) => {
            writeln!(
                out,
                "BATCH {n}/{total}\tOK\t{} claim(s) restored",
                o.claims_restored
            )?;
            report.claims_restored += o.claims_restored;
            for (t, k) in o.rows_restored {
                *report.rows_restored.entry(t).or_default() += k;
            }
            report.held.extend(o.held);
            report.missing_rows += o.missing_rows;
            Ok(true)
        }
        Err(e) => {
            writeln!(out, "BATCH {n}/{total}\tROLLED BACK\t{e}")?;
            report.batch_failures.push((n, e.to_string()));
            if apply {
                writeln!(out, "STOPPED: no further batch was attempted")?;
                return Ok(false);
            }
            Ok(true)
        }
    }
}

/// Read the manifest and restore it, batch by batch.
///
/// # Errors
/// A failure outside a batch.
pub async fn run(
    conn: &mut PgConnection,
    opts: &Options,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<Report> {
    if opts.batch_size == 0 {
        bail!("--batch-size must be at least 1");
    }
    let m = manifest::read(&opts.manifest)?;
    let specs = tables::propagated_tables(conn).await?;
    let unkeyed = tables::unkeyed_tables(conn, &specs).await?;
    tables::probe_session_switch(conn).await?;
    let res = resolve(&m, &specs)?;
    writeln!(
        out,
        "reown-reverse: manifest={} target_group={} claims={} rows={} mode={}",
        opts.manifest.display(),
        res.target,
        res.claims.len(),
        res.rows.len(),
        if opts.apply { "APPLY" } else { "DRY-RUN" }
    )?;
    let mut report = Report::default();
    let batches: Vec<&[(Uuid, Record)]> = res.claims.chunks(opts.batch_size).collect();
    let total = batches.len();
    if opts.apply {
        for (i, batch) in batches.iter().enumerate() {
            let mut tx = sqlx::Connection::begin(&mut *conn).await?;
            let r = run_batch(&mut tx, &specs, &unkeyed, &res, batch, &opts.lock_timeout).await;
            if r.is_ok() {
                tx.commit().await?;
            } else {
                tx.rollback().await?;
            }
            if !tally(&mut report, out, i + 1, total, r, true)? {
                break;
            }
        }
    } else {
        let mut tx = sqlx::Connection::begin(&mut *conn).await?;
        for (i, batch) in batches.iter().enumerate() {
            sqlx::query("SAVEPOINT reverse_batch")
                .execute(&mut *tx)
                .await?;
            let r = run_batch(&mut tx, &specs, &unkeyed, &res, batch, &opts.lock_timeout).await;
            let sp = if r.is_ok() {
                "RELEASE SAVEPOINT reverse_batch"
            } else {
                "ROLLBACK TO SAVEPOINT reverse_batch"
            };
            sqlx::query(sp).execute(&mut *tx).await?;
            tally(&mut report, out, i + 1, total, r, false)?;
        }
        tx.rollback().await?;
    }
    for (id, why) in &report.held {
        writeln!(out, "HELD\t{id}\t{why}")?;
    }
    writeln!(out, "RESULT")?;
    writeln!(out, "  claims restored: {}", report.claims_restored)?;
    for (t, n) in &report.rows_restored {
        writeln!(out, "  {t}: rows restored to their own recorded owner: {n}")?;
    }
    if report.missing_rows > 0 {
        writeln!(
            out,
            "  {} recorded row(s) no longer exist and were skipped",
            report.missing_rows
        )?;
    }
    writeln!(
        out,
        "  invariants: {}",
        if report.batch_failures.is_empty() {
            "all held in every batch".to_string()
        } else {
            format!(
                "{} batch(es) violated and were rolled back",
                report.batch_failures.len()
            )
        }
    )?;
    if !opts.apply {
        writeln!(
            out,
            "DRY RUN: everything above ran in one transaction and was rolled back."
        )?;
    }
    Ok(report)
}
