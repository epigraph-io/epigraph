//! `reown-reverse`: restore every row a manifest's run moved to its recorded
//! prior owner.
//!
//! # A per-row compare-and-swap
//!
//! A manifest (version 2) carries each row's PRIOR record and, for every claim
//! a committed batch moved and every row that batch checked, a POST record: the
//! state that run left it in (see `manifest`). Reversal restores a row only
//! while it is in one of those two states:
//!
//! * a claim with NO post record was planned but never moved by this run (held
//!   under the lock, or never reached after a stopped run): it is NOT touched;
//! * a claim already at its prior state is already restored: skipped;
//! * a claim at its post state is reversed — unless one of its recorded rows is
//!   in neither its post nor its prior state, or a NEIGHBOUR claim sharing one
//!   of its recorded rows is no longer in the state recorded for it; then the
//!   claim is HELD;
//! * a claim in any other state is HELD.
//!
//! The neighbour test is the one that catches a NEWER re-own run that shared
//! rows with this one (a fragment, an edge between their claims). Review
//! measured the failure it prevents: two manifests M1, M2 whose runs shared
//! rows, reversed oldest-first, left those rows on neither their original
//! owner nor anything the operator chose, and every run printed "invariants:
//! all held". The rows alone cannot show it — a public–public edge is `(world,
//! public)` after either run, and the shared fragment was already on the
//! target before M2 ran — but M2 moved a claim M1 recorded as a neighbour. So
//! M1 reversed on its own HOLDS and names the cause, and reversing M2 then M1
//! restores every row. Pass every manifest to ONE invocation and it applies
//! them newest-first by header `created_at` (a tie is refused), so the order
//! is the tool's, not the operator's memory.
//!
//! Two consequences, both deliberate. A neighbour with NO record (fragment
//! provenance added after the run) is not compared. And a claim that shares
//! rows with a claim a newer, unreversed run moved can never be reversed on
//! its own: undoing M1 while keeping M2 applied is not offered, because the
//! shared rows have one state and no correct value serves both.
//!
//! # Order inside a batch
//!
//! 1. Lock the batch's claims `FOR UPDATE`, and the cascade tables with no key
//!    to `claims` (`tables::lock_unkeyed_tables`), as the re-own does.
//! 2. Classify each claim and its attached rows against the CAS above.
//! 3. Put each remaining claim back on its recorded owner. The tenancy trigger
//!    then copies that owner onto EVERY row derived from the claim.
//! 4. Put every recorded row back on ITS OWN recorded tenancy. This is the step
//!    that makes reversal exact: a derived row whose owner differed from its
//!    claim's before the re-own (a `keep-writer` row, or one that simply
//!    disagreed) gets its own owner back, never the claim's re-propagated one.
//!
//! A row the manifest does not name (a derived row written after the re-own)
//! is left where the trigger puts it, which is where it would have been had
//! the claim never moved — when it is public. A NON-public one, or an edge
//! with a non-public endpoint, would change visibility under the cascade, so
//! its claim is HELD in step 2 rather than failing the whole batch.
//!
//! # Idempotent
//!
//! A claim already on its recorded prior state is not updated, and a row
//! already in its recorded state is not written, so a second run changes
//! nothing and its counter census is all zeros.

use super::manifest::{self, Record};
use super::reown::{counter_delta, counter_violations, BatchError};
use super::tables::{
    self, app_readable, fetch_attached, fetch_claims, refetch_tenancy, write_tenancy,
    xact_counters, Kind, RowKey, Snapshot, TableSpec, Tenancy,
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
    /// One or more manifests; applied newest-first by header `created_at`.
    pub manifests: Vec<PathBuf>,
    pub apply: bool,
    pub batch_size: usize,
    pub lock_timeout: String,
}

/// A manifest resolved against the live table specs.
pub struct Resolved {
    pub target: Uuid,
    /// Claim id → its PRIOR record, in manifest order.
    pub claims: Vec<(Uuid, Record)>,
    /// Claim id → its POST record (the last one).
    pub claim_posts: BTreeMap<Uuid, Record>,
    /// Every non-claim PRIOR record by row key.
    pub rows: BTreeMap<RowKey, Record>,
    /// Every non-claim POST record by row key (the last one).
    pub row_posts: BTreeMap<RowKey, Record>,
    /// NEIGHBOUR claim id → its recorded state (the last one).
    pub neighbours: BTreeMap<Uuid, Record>,
}

/// # Errors
/// The header lacks a target group or is not version 2, or a record names a
/// table the live cascade does not know.
pub fn resolve(m: &manifest::Manifest, specs: &[TableSpec]) -> anyhow::Result<Resolved> {
    let version = m.header.get("version").and_then(serde_json::Value::as_i64);
    if version != Some(manifest::VERSION) {
        bail!(
            "manifest version is {version:?}; this build reverses version {} only, whose post-state \
             records make reversal a compare-and-swap. A manifest without them cannot tell a row \
             this run moved from one a later run moved, so it is refused rather than guessed at",
            manifest::VERSION
        );
    }
    let target = m
        .header
        .get("target_group_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("manifest header has no target_group_id"))
        .and_then(|s| Uuid::parse_str(s).context("target_group_id"))?;
    let mut claims = Vec::new();
    let mut claim_posts = BTreeMap::new();
    let mut rows = BTreeMap::new();
    let mut row_posts = BTreeMap::new();
    let mut neighbours = BTreeMap::new();
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
            if r.after && r.neighbour {
                neighbours.insert(id, r.clone());
            } else if r.after {
                claim_posts.insert(id, r.clone());
            } else {
                claims.push((id, r.clone()));
            }
        } else if r.after {
            row_posts.insert((r.table.clone(), pk), r.clone());
        } else {
            rows.entry((r.table.clone(), pk))
                .or_insert_with(|| r.clone());
        }
    }
    Ok(Resolved {
        target,
        claims,
        claim_posts,
        rows,
        row_posts,
        neighbours,
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

fn show(t: &Tenancy) -> String {
    match t.co_owner {
        Some(co) => format!("({}, {}, co-owner {co})", t.owner, t.visibility),
        None => format!("({}, {})", t.owner, t.visibility),
    }
}

/// What one reversal batch did.
#[derive(Default, Debug)]
pub struct Outcome {
    pub claims_restored: usize,
    pub rows_restored: BTreeMap<String, usize>,
    pub held: Vec<(Uuid, String)>,
    /// Claims this manifest's run never moved (no post record): untouched.
    pub never_moved: usize,
    /// Claims already on their recorded prior state: untouched.
    pub already: usize,
    pub missing_rows: usize,
}

const NEWER_FIRST: &str =
    "if a NEWER re-own run moved it, reverse that manifest first (pass every \
                           manifest to one reown-reverse and it orders them newest-first)";

/// Run one reversal batch inside the caller's transaction. Does NOT commit.
///
/// # Errors
/// [`BatchError`], as for the re-own.
#[allow(clippy::too_many_lines)]
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

    // ---- claims: the CAS ----
    let mut candidates: Vec<(Uuid, &Record)> = Vec::new();
    for (id, rec) in batch {
        let Some(post) = res.claim_posts.get(id) else {
            out.never_moved += 1;
            continue;
        };
        let Some(c) = now.get(id) else {
            out.held.push((*id, "claim no longer exists".into()));
            continue;
        };
        if c.owner == rec.owner_group_id && c.visibility == rec.visibility {
            out.already += 1;
            continue;
        }
        if c.owner != post.owner_group_id || c.visibility != post.visibility {
            out.held.push((
                *id,
                format!(
                    "claim is ({}, {}) now; this manifest's run left it ({}, {}) and recorded \
                     ({}, {}) before; something moved it since, not reversing; {NEWER_FIRST}",
                    c.owner,
                    c.visibility,
                    post.owner_group_id,
                    post.visibility,
                    rec.owner_group_id,
                    rec.visibility
                ),
            ));
            continue;
        }
        candidates.push((*id, rec));
    }
    if candidates.is_empty() {
        return Ok(out);
    }

    // ---- rows: the CAS, holding every claim a drifted row hangs off ----
    let cand_ids: BTreeSet<Uuid> = candidates.iter().map(|(id, _)| *id).collect();
    let cand_vec: Vec<Uuid> = cand_ids.iter().copied().collect();
    let attached = fetch_attached(conn, specs, &cand_vec).await?;
    let mut drift: BTreeMap<Uuid, String> = BTreeMap::new();
    for (k, a) in &attached {
        let Some(prior) = res.rows.get(k) else {
            continue;
        };
        let prior_t = recorded_tenancy(prior, &a.tenancy);
        let post_t = res
            .row_posts
            .get(k)
            .map(|p| recorded_tenancy(p, &a.tenancy));
        let ok = a.tenancy == prior_t || post_t.as_ref() == Some(&a.tenancy);
        if !ok {
            let why = format!(
                "{} {} is {} now; this manifest's run left it {} and recorded {} before; not \
                 reversing; {NEWER_FIRST}",
                k.0,
                k.1,
                show(&a.tenancy),
                post_t
                    .as_ref()
                    .map_or_else(|| "unchanged".to_string(), show),
                show(&prior_t)
            );
            for cl in a.claims.intersection(&cand_ids) {
                drift.entry(*cl).or_insert_with(|| why.clone());
            }
        }
    }
    // ---- neighbours: a claim sharing a recorded row that has MOVED since ----
    // A neighbour this manifest itself moved is governed by its own records,
    // and one with no record (e.g. provenance added after the run) is not
    // compared.
    let watched: BTreeSet<Uuid> = attached
        .iter()
        .filter(|(k, _)| res.rows.contains_key(*k))
        .flat_map(|(_, a)| a.neighbours.iter().copied())
        .filter(|n| !res.claim_posts.contains_key(n) && res.neighbours.contains_key(n))
        .collect();
    if !watched.is_empty() {
        let ids: Vec<Uuid> = watched.iter().copied().collect();
        let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
            "SELECT id, owner_group_id, visibility::text FROM claims \
              WHERE id = ANY($1) ORDER BY id FOR SHARE",
        )
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await?;
        let now_n: BTreeMap<Uuid, (Uuid, String)> =
            rows.into_iter().map(|(i, o, v)| (i, (o, v))).collect();
        let mut moved_n: BTreeMap<Uuid, String> = BTreeMap::new();
        for n in &watched {
            let rec = &res.neighbours[n];
            let cur = now_n.get(n);
            if cur != Some(&(rec.owner_group_id, rec.visibility.clone())) {
                moved_n.insert(
                    *n,
                    format!(
                        "claim {n}, which shares a recorded row with it, is {} now and was ({}, \
                         {}) when this run moved it; not reversing; {NEWER_FIRST}",
                        cur.map_or_else(|| "gone".to_string(), |(o, v)| format!("({o}, {v})")),
                        rec.owner_group_id,
                        rec.visibility
                    ),
                );
            }
        }
        for (k, a) in &attached {
            if !res.rows.contains_key(k) {
                continue;
            }
            for n in &a.neighbours {
                if let Some(why) = moved_n.get(n) {
                    for cl in a.claims.intersection(&cand_ids) {
                        drift.entry(*cl).or_insert_with(|| why.clone());
                    }
                }
            }
        }
    }
    // ---- rows the cascade would widen: hold, don't fail the batch ----
    // Restoring a claim makes `epigraph_propagate_tenancy` copy the claim's
    // (owner, visibility) onto EVERY derived row, recorded or not, and
    // recompute every touching edge's meet. A row written AFTER the re-own
    // that is not public, or an edge with a non-public endpoint, would change
    // visibility; the batch's invariant would then roll the WHOLE batch back
    // and stop the run (review finding), so every other claim in the manifest
    // would stay moved. Holding the one claim is the per-claim answer.
    for (k, a) in &attached {
        let why = if !res.rows.contains_key(k) && a.tenancy.visibility != "public" {
            Some(format!(
                "{} {} is {} and was written after the re-own; restoring the claim would copy \
                 the claim's public visibility onto it, so not reversing",
                k.0, k.1, a.tenancy.visibility
            ))
        } else if a.endpoints_public == Some(false) {
            Some(format!(
                "edge {} has a non-public endpoint now, so the trigger's meet would change its \
                 visibility; not reversing",
                k.1
            ))
        } else {
            None
        };
        if let Some(why) = why {
            for cl in a.claims.intersection(&cand_ids) {
                drift.entry(*cl).or_insert_with(|| why.clone());
            }
        }
    }
    let work: Vec<(Uuid, &Record)> = candidates
        .into_iter()
        .filter(|(id, _)| !drift.contains_key(id))
        .collect();
    for (id, why) in drift {
        out.held.push((id, why));
    }
    if work.is_empty() {
        return Ok(out);
    }
    let claim_ids: Vec<Uuid> = work.iter().map(|(id, _)| *id).collect();
    let work_ids: BTreeSet<Uuid> = claim_ids.iter().copied().collect();
    let s0: Snapshot = attached
        .into_iter()
        .filter(|(_, a)| a.claims.iter().any(|c| work_ids.contains(c)))
        .collect();
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
    out.missing_rows = res
        .rows
        .iter()
        .filter(|(k, r)| work_ids.contains(&r.claim_id) && !keys.contains(*k))
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
    pub never_moved: usize,
    pub already: usize,
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
            report.never_moved += o.never_moved;
            report.already += o.already;
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

/// Read every manifest and order them newest-first by header `created_at`.
///
/// # Errors
/// A manifest cannot be read, lacks `created_at`, or two share one.
pub fn read_ordered(paths: &[PathBuf]) -> anyhow::Result<Vec<(PathBuf, manifest::Manifest)>> {
    if paths.is_empty() {
        bail!("at least one --manifest is required");
    }
    let mut ms = Vec::with_capacity(paths.len());
    for p in paths {
        let m = manifest::read(p)?;
        let at = m
            .header
            .get("created_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("{}: header has no created_at", p.display()))
            .and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .with_context(|| format!("{}: created_at {s:?}", p.display()))
            })?;
        ms.push((at, p.clone(), m));
    }
    ms.sort_by_key(|x| std::cmp::Reverse(x.0));
    for w in ms.windows(2) {
        if w[0].0 == w[1].0 {
            bail!(
                "{} and {} carry the same created_at; refusing to guess which is newer",
                w[0].1.display(),
                w[1].1.display()
            );
        }
    }
    Ok(ms.into_iter().map(|(_, p, m)| (p, m)).collect())
}

/// Read the manifests and restore them, newest first, batch by batch.
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
    let ordered = read_ordered(&opts.manifests)?;
    let specs = tables::propagated_tables(conn).await?;
    let unkeyed = tables::unkeyed_tables(conn, &specs).await?;
    tables::probe_session_switch(conn).await?;
    let mut resolved = Vec::with_capacity(ordered.len());
    for (p, m) in &ordered {
        resolved.push((p, resolve(m, &specs)?));
    }
    writeln!(
        out,
        "reown-reverse: {} manifest(s), newest first; mode={}",
        resolved.len(),
        if opts.apply { "APPLY" } else { "DRY-RUN" }
    )?;
    let mut report = Report::default();
    'manifests: for (path, res) in &resolved {
        writeln!(
            out,
            "MANIFEST\t{}\ttarget_group={}\tclaims={}\tmoved={}\trows={}",
            path.display(),
            res.target,
            res.claims.len(),
            res.claim_posts.len(),
            res.rows.len()
        )?;
        let batches: Vec<&[(Uuid, Record)]> = res.claims.chunks(opts.batch_size).collect();
        let total = batches.len();
        for (i, batch) in batches.iter().enumerate() {
            let mut tx = sqlx::Connection::begin(&mut *conn).await?;
            let r = run_batch(&mut tx, &specs, &unkeyed, res, batch, &opts.lock_timeout).await;
            if opts.apply && r.is_ok() {
                tx.commit().await?;
            } else {
                // A dry run rolls every batch back at once, so it holds a
                // batch's locks for that batch only (see `reown::run`).
                tx.rollback().await?;
            }
            if !tally(&mut report, out, i + 1, total, r, opts.apply)? {
                break 'manifests;
            }
        }
    }
    for (id, why) in &report.held {
        writeln!(out, "HELD\t{id}\t{why}")?;
    }
    writeln!(out, "RESULT")?;
    writeln!(out, "  claims restored: {}", report.claims_restored)?;
    writeln!(
        out,
        "  claims already on their recorded owner: {}",
        report.already
    )?;
    writeln!(
        out,
        "  claims planned but never moved by their run (untouched): {}",
        report.never_moved
    )?;
    writeln!(out, "  claims HELD: {}", report.held.len())?;
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
            "DRY RUN: each batch above ran in its own transaction and was rolled back, so no \
             lock outlived its batch; a batch does not see an earlier batch's effects, so a row \
             shared across batches is checked against its current state."
        )?;
        if resolved.len() > 1 {
            writeln!(
                out,
                "DRY RUN with several manifests: a newer manifest's reversal was rolled back \
                 before the older one was checked, so an older manifest's claim that shares rows \
                 with a newer run shows as HELD here; --apply reverses the newer one first."
            )?;
        }
    }
    Ok(report)
}
