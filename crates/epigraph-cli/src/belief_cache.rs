//! Belief-cache snapshot and compare-and-swap (CAS) restore (SPEC §10.8).
//!
//! Three files, all JSON lines, all bit-exact for the cache floats:
//!
//! * **snapshot** ([`SnapshotRow`], written by [`write_snapshot`], the
//!   `belief_snapshot` binary): every current claim's cache columns at one
//!   point in time. Snapshot S0 is the baseline each wave's drift report is
//!   measured from.
//! * **wave file** ([`WaveRecord`], appended by a writing run with
//!   [`write_wave_record`]): per claim, the cache the run found (`before`),
//!   what it wrote (`written`), the wave's name and when (`at`). A writer
//!   should stamp `at` from the DATABASE clock after its write, because
//!   [`downstream_edges`] compares it with `edges.created_at`.
//! * **restore outputs** (the `restore_belief_cache` binary): per-claim
//!   outcomes, and the downstream edges to re-wire.
//!
//! The restore puts `before` back only where the row still holds exactly
//! `written` ([`restore_wave`]); everything else is reported, never
//! overwritten. It restores `claims.*` only: per-frame `ds_combined_beliefs`
//! rows, edge-factor BBAs and anything downstream are the follow-up re-wire's
//! (SPEC §10.8, "only with the follow-up re-wire").
//!
//! The SQL lives here rather than in `epigraph-db/src/repos/` for the same
//! reason as `recompute_betp`'s: it is an operator binary's corpus-wide
//! maintenance statement on the maintenance connection, with no request path
//! and no viewer.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Bit-exact JSON for the cache floats.
///
/// A restore's compare-and-swap matches a claim only when its stored value
/// equals the wave file's `written` value exactly, so the file must give back
/// the bits it was given. Writing is serde_json's shortest round-trip form;
/// READING is the problem: serde_json's default number parse multiplies a
/// 64-bit significand by a power of ten, which double-rounds 17-digit values
/// (measured: 2516 of 4000 random records lost a bit). Each value is therefore
/// taken as its raw JSON text and parsed with `str::parse::<f64>`, which is
/// correctly rounded. A non-finite value has no JSON number and serde_json
/// would write it as `null`, which a restore would then write back as NULL, so
/// it is refused instead.
mod exact_f64 {
    use serde::de::Error as _;
    use serde::ser::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_json::value::RawValue;

    pub fn serialize<S: Serializer>(v: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            None => s.serialize_none(),
            Some(x) if x.is_finite() => s.serialize_some(x),
            Some(x) => Err(S::Error::custom(format!(
                "non-finite cache value {x} has no exact JSON form"
            ))),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<f64>, D::Error> {
        let raw: Option<Box<RawValue>> = Option::deserialize(d)?;
        raw.map(|r| {
            r.get()
                .parse::<f64>()
                .map_err(|e| D::Error::custom(format!("cache value {}: {e}", r.get())))
        })
        .transpose()
    }
}

/// Claims per restore transaction (SPEC §10.8: one transaction per 1k claims).
pub const DEFAULT_RESTORE_BATCH: usize = 1000;

/// Rows per snapshot page.
pub const DEFAULT_SNAPSHOT_PAGE: i64 = 5000;

/// The belief-cache columns of one `claims` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheColumns {
    #[serde(with = "exact_f64")]
    pub belief: Option<f64>,
    #[serde(with = "exact_f64")]
    pub plausibility: Option<f64>,
    #[serde(with = "exact_f64")]
    pub pignistic_prob: Option<f64>,
    #[serde(with = "exact_f64")]
    pub mass_on_empty: Option<f64>,
    #[serde(with = "exact_f64")]
    pub mass_on_missing: Option<f64>,
    pub belief_frame_id: Option<Uuid>,
    pub classification: Option<String>,
}

/// One line of a `belief_snapshot` file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotRow {
    pub claim_id: Uuid,
    #[serde(with = "exact_f64")]
    pub belief: Option<f64>,
    #[serde(with = "exact_f64")]
    pub plausibility: Option<f64>,
    #[serde(with = "exact_f64")]
    pub pignistic_prob: Option<f64>,
    #[serde(with = "exact_f64")]
    pub mass_on_empty: Option<f64>,
    #[serde(with = "exact_f64")]
    pub mass_on_missing: Option<f64>,
    pub belief_frame_id: Option<Uuid>,
    pub classification: Option<String>,
    pub updated_at: DateTime<Utc>,
}

impl SnapshotRow {
    /// The cache columns this row recorded.
    #[must_use]
    pub fn cache(&self) -> CacheColumns {
        CacheColumns {
            belief: self.belief,
            plausibility: self.plausibility,
            pignistic_prob: self.pignistic_prob,
            mass_on_empty: self.mass_on_empty,
            mass_on_missing: self.mass_on_missing,
            belief_frame_id: self.belief_frame_id,
            classification: self.classification.clone(),
        }
    }
}

/// One line of a wave file: what a writing run found and what it wrote.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WaveRecord {
    pub claim_id: Uuid,
    pub before: CacheColumns,
    pub written: CacheColumns,
    pub wave: String,
    pub at: DateTime<Utc>,
}

/// One claim a restore will try to put back.
#[derive(Debug, Clone, PartialEq)]
pub struct RestoreEntry {
    pub claim_id: Uuid,
    pub before: CacheColumns,
    pub written: CacheColumns,
    pub at: DateTime<Utc>,
}

/// What a wave file asks a restore to do, after the `--claims` filter.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RestorePlan {
    pub entries: Vec<RestoreEntry>,
    pub broken_chain: Vec<Uuid>,
    pub not_in_wave: Vec<Uuid>,
}

#[derive(Debug, Clone)]
pub struct RestoreOptions {
    pub batch_size: usize,
    pub dry_run: bool,
}

impl Default for RestoreOptions {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_RESTORE_BATCH,
            dry_run: false,
        }
    }
}

/// Per-claim outcome of a restore.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RestoreReport {
    pub restored: Vec<Uuid>,
    pub already_restored: Vec<Uuid>,
    pub superseded_since_wave: Vec<Uuid>,
    pub missing: Vec<Uuid>,
    pub frame_gone: Vec<Uuid>,
    pub not_in_wave: Vec<Uuid>,
}

/// An edge whose source is a wave claim and which was created after that
/// claim's wave write.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
pub struct DownstreamEdge {
    pub edge_id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub target_type: String,
    pub relationship: String,
    pub created_at: DateTime<Utc>,
    pub valid_to: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct SnapshotOptions {
    pub page_size: i64,
    pub include_superseded: bool,
}

impl Default for SnapshotOptions {
    fn default() -> Self {
        Self {
            page_size: DEFAULT_SNAPSHOT_PAGE,
            include_superseded: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotSummary {
    pub rows: u64,
    pub snapshot_at: DateTime<Utc>,
}

/// `(id, belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing,
/// belief_frame_id, classification)`.
type CacheTuple = (
    Uuid,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<Uuid>,
    Option<String>,
);

/// Read the cache columns of `ids`. Absent claims are absent from the map.
///
/// # Errors
/// Any database error.
pub async fn read_cache_columns<'e, E: sqlx::PgExecutor<'e>>(
    exec: E,
    ids: &[Uuid],
) -> anyhow::Result<HashMap<Uuid, CacheColumns>> {
    let rows: Vec<CacheTuple> = sqlx::query_as(
        "SELECT id, belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing, \
                belief_frame_id, classification \
           FROM claims WHERE id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(exec)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, b, p, bp, me, mm, f, c)| {
            (
                id,
                CacheColumns {
                    belief: b,
                    plausibility: p,
                    pignistic_prob: bp,
                    mass_on_empty: me,
                    mass_on_missing: mm,
                    belief_frame_id: f,
                    classification: c,
                },
            )
        })
        .collect())
}

/// Append one wave record as a JSON line.
///
/// # Errors
/// Serialization or I/O failure.
pub fn write_wave_record<W: Write>(out: &mut W, rec: &WaveRecord) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *out, rec)?;
    out.write_all(b"\n")?;
    Ok(())
}

/// Parse a wave file.
///
/// # Errors
/// I/O failure or a malformed line.
pub fn read_wave<R: BufRead>(input: R) -> anyhow::Result<Vec<WaveRecord>> {
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

/// Parse a snapshot file.
///
/// # Errors
/// I/O failure or a malformed line.
pub fn read_snapshot<R: BufRead>(input: R) -> anyhow::Result<Vec<SnapshotRow>> {
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

/// Parse a `--claims` file: one claim id per line; blank lines and lines
/// starting with `#` are ignored.
///
/// # Errors
/// I/O failure, or a line that is not a UUID (with its line number).
pub fn read_claim_ids<R: BufRead>(input: R) -> anyhow::Result<HashSet<Uuid>> {
    let mut out = HashSet::new();
    for (i, line) in input.lines().enumerate() {
        let line = line?;
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let id = Uuid::parse_str(t)
            .map_err(|e| anyhow::anyhow!("--claims line {}: not a claim id: {e}", i + 1))?;
        out.insert(id);
    }
    Ok(out)
}

/// Turn wave records into a restore plan.
///
/// `only` is the `--claims` filter: records for other claims are skipped, and
/// a requested id the wave never wrote is listed in `not_in_wave` rather than
/// silently ignored.
///
/// # A claim recorded more than once
///
/// A wave re-run against the same file appends a second record for a claim.
/// The records CHAIN when each one's `before` is the previous one's `written`:
/// nothing else wrote the claim between them, so the plan restores the FIRST
/// `before` and compares against the LAST `written`, and `at` is the earliest
/// record's (the downstream list must cover every edge that could have frozen
/// any of the wave's values). When they do not chain, another writer landed
/// between two wave writes; restoring the first `before` would erase it, so
/// the claim goes to `broken_chain` and is reported `superseded_since_wave`
/// without a write.
#[must_use]
pub fn plan_restore(records: &[WaveRecord], only: Option<&HashSet<Uuid>>) -> RestorePlan {
    let mut order: Vec<Uuid> = Vec::new();
    let mut groups: HashMap<Uuid, Vec<&WaveRecord>> = HashMap::new();
    for r in records {
        if only.is_some_and(|o| !o.contains(&r.claim_id)) {
            continue;
        }
        groups
            .entry(r.claim_id)
            .or_insert_with(|| {
                order.push(r.claim_id);
                Vec::new()
            })
            .push(r);
    }

    let mut plan = RestorePlan::default();
    for id in order {
        let group = &groups[&id];
        let chains = group.windows(2).all(|w| w[0].written == w[1].before);
        match (chains, group.first(), group.last()) {
            (true, Some(first), Some(last)) => plan.entries.push(RestoreEntry {
                claim_id: id,
                before: first.before.clone(),
                written: last.written.clone(),
                at: group.iter().map(|r| r.at).min().unwrap_or(first.at),
            }),
            _ => plan.broken_chain.push(id),
        }
    }
    if let Some(only) = only {
        let mut absent: Vec<Uuid> = only
            .iter()
            .filter(|id| !groups.contains_key(id))
            .copied()
            .collect();
        absent.sort_unstable();
        plan.not_in_wave = absent;
    }
    plan
}

/// The cache columns, in the order every statement below names them.
const CACHE_COLUMN_NAMES: [&str; 7] = [
    "belief",
    "plausibility",
    "pignistic_prob",
    "mass_on_empty",
    "mass_on_missing",
    "belief_frame_id",
    "classification",
];

/// `w`: one row per planned claim, `b_*` = the wave's `before`, `w_*` = what
/// it wrote. Binds `$1` (ids) and `$2..$15` (see [`bind_wave_rows`]).
const WAVE_ROWS_CTE: &str = "WITH w AS ( \
    SELECT * FROM unnest($1::uuid[], \
        $2::float8[], $3::float8[], $4::float8[], $5::float8[], $6::float8[], $7::uuid[], $8::text[], \
        $9::float8[], $10::float8[], $11::float8[], $12::float8[], $13::float8[], $14::uuid[], $15::text[]) \
      AS w(id, b_belief, b_plausibility, b_pignistic_prob, b_mass_on_empty, b_mass_on_missing, \
              b_belief_frame_id, b_classification, \
              w_belief, w_plausibility, w_pignistic_prob, w_mass_on_empty, w_mass_on_missing, \
              w_belief_frame_id, w_classification) \
)";

/// `c`'s cache equals the `w` row's `prefix` values in EVERY column, NULL
/// equal to NULL (`IS NOT DISTINCT FROM`; `=` would never match a column the
/// wave left NULL).
fn cache_equals(prefix: &str) -> String {
    CACHE_COLUMN_NAMES
        .iter()
        .map(|c| format!("c.{c} IS NOT DISTINCT FROM w.{prefix}_{c}"))
        .collect::<Vec<_>>()
        .join(" AND ")
}

fn bind_wave_rows<'q>(
    q: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    chunk: &[RestoreEntry],
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    fn floats(
        chunk: &[RestoreEntry],
        f: impl Fn(&RestoreEntry) -> Option<f64>,
    ) -> Vec<Option<f64>> {
        chunk.iter().map(f).collect()
    }
    let mut q = q.bind(chunk.iter().map(|e| e.claim_id).collect::<Vec<_>>());
    fn before(e: &RestoreEntry) -> &CacheColumns {
        &e.before
    }
    fn written(e: &RestoreEntry) -> &CacheColumns {
        &e.written
    }
    let sides: [fn(&RestoreEntry) -> &CacheColumns; 2] = [before, written];
    for side in sides {
        q = q
            .bind(floats(chunk, |e| side(e).belief))
            .bind(floats(chunk, |e| side(e).plausibility))
            .bind(floats(chunk, |e| side(e).pignistic_prob))
            .bind(floats(chunk, |e| side(e).mass_on_empty))
            .bind(floats(chunk, |e| side(e).mass_on_missing))
            .bind(
                chunk
                    .iter()
                    .map(|e| side(e).belief_frame_id)
                    .collect::<Vec<_>>(),
            )
            .bind(
                chunk
                    .iter()
                    .map(|e| side(e).classification.clone())
                    .collect::<Vec<_>>(),
            );
    }
    q
}

/// Put every planned claim back to its `before` value, compare-and-swap.
///
/// Per batch of `opts.batch_size` claims, in one transaction:
///
/// * one `UPDATE` writes `before` only where the row still holds EXACTLY what
///   the wave wrote, in all seven cache columns. A row that differs in any of
///   them took a later write, which a rollback must not erase; it is left
///   alone and reported `superseded_since_wave`.
/// * a row that already holds `before` is not written at all (so a second run
///   creates no new tuple version and bumps no `updated_at`) and is reported
///   `already_restored`. That is what makes the restore idempotent rather than
///   a second run reporting every claim as superseded.
/// * a `before` whose `belief_frame_id` names a frame deleted since the wave
///   would abort the whole batch on the foreign key, so that row is skipped
///   and reported `frame_gone`.
///
/// The `UPDATE` re-checks its `WHERE` against a row a concurrent writer
/// changed (READ COMMITTED), so a write that commits during the restore is
/// still never overwritten. `dry_run` runs the same statements and rolls each
/// batch back.
///
/// # Errors
/// Any database error; batches already committed stay committed.
pub async fn restore_wave(
    pool: &PgPool,
    plan: &RestorePlan,
    opts: &RestoreOptions,
) -> anyhow::Result<RestoreReport> {
    let restore_sql = format!(
        "{WAVE_ROWS_CTE} \
         UPDATE claims c \
            SET belief = w.b_belief, plausibility = w.b_plausibility, \
                pignistic_prob = w.b_pignistic_prob, mass_on_empty = w.b_mass_on_empty, \
                mass_on_missing = w.b_mass_on_missing, belief_frame_id = w.b_belief_frame_id, \
                classification = w.b_classification \
           FROM w \
          WHERE c.id = w.id \
            AND {written} \
            AND NOT ({before}) \
            AND (w.b_belief_frame_id IS NULL \
                 OR EXISTS (SELECT 1 FROM frames f WHERE f.id = w.b_belief_frame_id)) \
         RETURNING c.id",
        written = cache_equals("w"),
        before = cache_equals("b"),
    );
    let classify_sql = format!(
        "{WAVE_ROWS_CTE} \
         SELECT w.id, c.id IS NOT NULL, COALESCE({before}, false), COALESCE({written}, false) \
           FROM w LEFT JOIN claims c ON c.id = w.id",
        written = cache_equals("w"),
        before = cache_equals("b"),
    );

    let mut report = RestoreReport {
        superseded_since_wave: plan.broken_chain.clone(),
        not_in_wave: plan.not_in_wave.clone(),
        ..RestoreReport::default()
    };
    for chunk in plan.entries.chunks(opts.batch_size.max(1)) {
        let mut tx = pool.begin().await?;
        let restored: HashSet<Uuid> = bind_wave_rows(sqlx::query(&restore_sql), chunk)
            .fetch_all(&mut *tx)
            .await?
            .iter()
            .map(|row| sqlx::Row::get::<Uuid, _>(row, 0))
            .collect();
        let states: HashMap<Uuid, (bool, bool, bool)> =
            bind_wave_rows(sqlx::query(&classify_sql), chunk)
                .fetch_all(&mut *tx)
                .await?
                .iter()
                .map(|row| {
                    (
                        sqlx::Row::get::<Uuid, _>(row, 0),
                        (
                            sqlx::Row::get::<bool, _>(row, 1),
                            sqlx::Row::get::<bool, _>(row, 2),
                            sqlx::Row::get::<bool, _>(row, 3),
                        ),
                    )
                })
                .collect();
        for e in chunk {
            let id = e.claim_id;
            let bucket = if restored.contains(&id) {
                &mut report.restored
            } else {
                match states.get(&id) {
                    None | Some((false, _, _)) => &mut report.missing,
                    Some((true, true, _)) => &mut report.already_restored,
                    Some((true, false, true)) => &mut report.frame_gone,
                    Some((true, false, false)) => &mut report.superseded_since_wave,
                }
            };
            bucket.push(id);
        }
        if opts.dry_run {
            tx.rollback().await?;
        } else {
            tx.commit().await?;
        }
    }
    Ok(report)
}

/// Edges created after the wave whose source is a planned claim.
///
/// SPEC §10.8: an edge a wave claim sourced after the wave wrote an
/// edge-factor BBA from the wave's value, and a cache restore does not undo
/// that BBA. These are the targets of the follow-up targeted re-wire.
///
/// "After" is per claim: `created_at > at` of THAT claim's record, so an edge
/// created after the wave started but before its source was written (which
/// froze the pre-wave value) is not listed. Only edges whose SOURCE is the
/// wave claim: the BBA lands on the target. Closed edges (`valid_to` set) are
/// listed too, with `valid_to`, because their BBA may outlive the close.
///
/// # Errors
/// Any database error.
pub async fn downstream_edges(
    pool: &PgPool,
    plan: &RestorePlan,
) -> anyhow::Result<Vec<DownstreamEdge>> {
    let mut out = Vec::new();
    for chunk in plan.entries.chunks(DEFAULT_RESTORE_BATCH) {
        let ids: Vec<Uuid> = chunk.iter().map(|e| e.claim_id).collect();
        let ats: Vec<DateTime<Utc>> = chunk.iter().map(|e| e.at).collect();
        let mut rows: Vec<DownstreamEdge> = sqlx::query_as(
            "SELECT e.id AS edge_id, e.source_id, e.target_id, \
                    e.target_type::text AS target_type, e.relationship::text AS relationship, \
                    e.created_at, e.valid_to \
               FROM unnest($1::uuid[], $2::timestamptz[]) AS w(id, at) \
               JOIN edges e ON e.source_id = w.id AND e.source_type = 'claim' \
                           AND e.created_at > w.at \
              ORDER BY e.created_at, e.id",
        )
        .bind(&ids)
        .bind(&ats)
        .fetch_all(pool)
        .await?;
        out.append(&mut rows);
    }
    Ok(out)
}

type SnapshotTuple = (
    Uuid,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<Uuid>,
    Option<String>,
    DateTime<Utc>,
);

/// Write every current claim's cache columns as JSON lines (SPEC §10.8; the
/// baseline snapshot S0 that every wave's drift report is measured from).
///
/// The whole export is ONE `REPEATABLE READ, READ ONLY` transaction, paged by
/// keyset on `id` (`opts.page_size` rows per round trip, so memory stays
/// bounded): every page sees the same database state, so a claim written
/// while the export runs is recorded either entirely before or not at all,
/// and no claim is skipped or repeated at a page boundary. `snapshot_at` is
/// that state's transaction time. Superseded claims are included only with
/// `include_superseded`.
///
/// # Errors
/// Any database or I/O error. Rows already written to `out` stay written; the
/// binary writes to a temporary path and renames only on success.
pub async fn write_snapshot<W: Write>(
    pool: &PgPool,
    out: &mut W,
    opts: &SnapshotOptions,
) -> anyhow::Result<SnapshotSummary> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let snapshot_at: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&mut *tx)
        .await?;

    let page = opts.page_size.max(1);
    let mut after: Option<Uuid> = None;
    let mut n = 0u64;
    loop {
        let rows: Vec<SnapshotTuple> = sqlx::query_as(
            "SELECT id, belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing, \
                    belief_frame_id, classification, updated_at \
               FROM claims \
              WHERE ($1::uuid IS NULL OR id > $1) AND ($2 OR is_current) \
              ORDER BY id \
              LIMIT $3",
        )
        .bind(after)
        .bind(opts.include_superseded)
        .bind(page)
        .fetch_all(&mut *tx)
        .await?;
        let Some(last) = rows.last() else { break };
        after = Some(last.0);
        let full_page = rows.len() as i64 == page;
        for (claim_id, b, p, bp, me, mm, f, c, updated_at) in rows {
            let row = SnapshotRow {
                claim_id,
                belief: b,
                plausibility: p,
                pignistic_prob: bp,
                mass_on_empty: me,
                mass_on_missing: mm,
                belief_frame_id: f,
                classification: c,
                updated_at,
            };
            serde_json::to_writer(&mut *out, &row)?;
            out.write_all(b"\n")?;
            n += 1;
        }
        if !full_page {
            break;
        }
    }
    tx.rollback().await?;
    Ok(SnapshotSummary {
        rows: n,
        snapshot_at,
    })
}
