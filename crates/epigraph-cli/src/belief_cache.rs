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
//!   what it wrote (`written`), the wave's name and when the run started
//!   (`at`). See [`WaveRecord::at`] for how a writer must stamp it.
//! * **restore outputs** (the `restore_belief_cache` binary): per-claim
//!   outcomes, and the downstream edges to re-wire.
//!
//! The restore puts `before` back only where the row still holds exactly
//! `written` ([`restore_wave`]); everything else is reported, never
//! overwritten. It restores the seven `claims` cache columns and nothing
//! else:
//!
//! * edge-factor BBAs on the targets of a wave claim's edges, and what they
//!   feed, are the follow-up targeted re-wire's ([`downstream_edges`] lists
//!   them; SPEC §10.8, "only with the follow-up re-wire");
//! * a wave claim's OWN per-frame `ds_combined_beliefs` rows are covered by
//!   NOTHING here or in that re-wire: the re-wire rewrites edge-factor BBAs
//!   and the target's `claims` cache, never `ds_combined_beliefs`, and a wave
//!   claim is a source, not a target. A wave that rewrites those rows must
//!   record their `before` and `written` values itself and have them restored
//!   the same way; a [`WaveRecord`] does not carry them.
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

/// How far before the wave's start [`downstream_edges`] reaches: a
/// transaction that began this long before the stamp and read a wave value
/// after it is still listed. Over-listing costs one idempotent re-wire of an
/// edge whose source is back on its pre-wave value, so the margin is wide.
pub const DOWNSTREAM_SLACK_SECS: i64 = 3600;

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
    /// When the RUN started (SPEC §10.8 `wave_at`): one value for every record
    /// of a run, taken from the DATABASE clock (`SELECT now()` in its own
    /// statement) BEFORE the run's first write.
    ///
    /// [`downstream_edges`] lists the edges whose edge-factor BBA may have
    /// frozen a wave value by comparing this with `edges.created_at` and
    /// `mass_functions.created_at`. Both are `DEFAULT now()`, the writing
    /// transaction's START time, so a transaction that began before a claim's
    /// write can still read the written value. A stamp taken after the write
    /// would therefore exclude edges that froze it; a stamp from before the
    /// run cannot, short of a transaction open across it, which
    /// [`DOWNSTREAM_SLACK_SECS`] covers.
    pub at: DateTime<Utc>,
}

/// One claim a restore will try to put back.
#[derive(Debug, Clone, PartialEq)]
pub struct RestoreEntry {
    pub claim_id: Uuid,
    pub before: CacheColumns,
    pub written: CacheColumns,
    /// The claim's records do not chain all the way back: another writer
    /// landed between two wave writes, and `before` is that write's value
    /// rather than the cache the first run found (see [`plan_restore`]).
    pub partial: bool,
}

/// What a wave file asks a restore to do, after the `--claims` filter.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RestorePlan {
    pub entries: Vec<RestoreEntry>,
    /// Claims whose records do not chain all the way back; each is also in
    /// `entries`, with `partial` set.
    pub broken_chain: Vec<Uuid>,
    pub not_in_wave: Vec<Uuid>,
    /// Every in-scope wave claim, restorable or held back: the sources
    /// [`downstream_edges`] lists edges for.
    pub sources: Vec<Uuid>,
    /// The earliest `at` over the in-scope records: when the (earliest) wave
    /// run started. `None` when nothing is in scope.
    pub wave_at: Option<DateTime<Utc>>,
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
    /// Restored to the newest value the wave did not write, which is a write
    /// that landed between two of its runs, not to what the first run found.
    pub restored_partial: Vec<Uuid>,
    pub already_restored: Vec<Uuid>,
    pub superseded_since_wave: Vec<Uuid>,
    pub missing: Vec<Uuid>,
    pub frame_gone: Vec<Uuid>,
    pub not_in_wave: Vec<Uuid>,
}

impl RestoreReport {
    /// Every outcome bucket with its name, in report order. Each claim the
    /// restore considered is in exactly one.
    #[must_use]
    pub fn buckets(&self) -> [(&'static str, &Vec<Uuid>); 7] {
        [
            ("restored", &self.restored),
            ("restored_partial", &self.restored_partial),
            ("already_restored", &self.already_restored),
            ("superseded_since_wave", &self.superseded_since_wave),
            ("missing", &self.missing),
            ("frame_gone", &self.frame_gone),
            ("not_in_wave", &self.not_in_wave),
        ]
    }

    /// Add `other`'s outcomes to this report's.
    pub fn append(&mut self, other: RestoreReport) {
        // Destructured, so a new bucket cannot be forgotten here.
        let RestoreReport {
            restored,
            restored_partial,
            already_restored,
            superseded_since_wave,
            missing,
            frame_gone,
            not_in_wave,
        } = other;
        self.restored.extend(restored);
        self.restored_partial.extend(restored_partial);
        self.already_restored.extend(already_restored);
        self.superseded_since_wave.extend(superseded_since_wave);
        self.missing.extend(missing);
        self.frame_gone.extend(frame_gone);
        self.not_in_wave.extend(not_in_wave);
    }
}

/// An edge whose source is a wave claim and which was created, or had its
/// edge-factor BBA written, after the wave started (see [`downstream_edges`]).
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
/// The records are taken in `at` order (file order among equal times), so a
/// file whose runs were concatenated out of order reads the same. They CHAIN
/// when each one's `before` is the previous one's `written`: nothing else
/// wrote the claim between them, so the plan restores the FIRST `before` and
/// compares against the LAST `written`.
///
/// When they do not chain, another writer landed between two wave writes.
/// Restoring the first `before` would erase that write, and doing nothing
/// would keep the wave's last value. The plan takes the longest run of
/// chained records at the END, restores ITS first `before` (the newest value
/// the wave did not write) and compares against the last `written`; the
/// entry is marked `partial` and the claim listed in `broken_chain`.
///
/// `wave_at` is the earliest in-scope record's `at`, so the downstream list
/// covers every edge that could have frozen any of the wave's values.
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

    let mut plan = RestorePlan {
        wave_at: groups.values().flatten().map(|r| r.at).min(),
        ..RestorePlan::default()
    };
    for id in order {
        let mut group = groups[&id].clone();
        // Stable: records with equal `at` keep their file order.
        group.sort_by_key(|r| r.at);
        plan.sources.push(id);
        let mut start = group.len() - 1;
        while start > 0 && group[start - 1].written == group[start].before {
            start -= 1;
        }
        if start > 0 {
            plan.broken_chain.push(id);
        }
        plan.entries.push(RestoreEntry {
            claim_id: id,
            before: group[start].before.clone(),
            written: group[group.len() - 1].written.clone(),
            partial: start > 0,
        });
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
///   alone and reported `superseded_since_wave`. A restored `partial` entry
///   (a broken chain, see [`plan_restore`]) is reported `restored_partial`.
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
/// Any database error; batches already committed stay committed, and their
/// outcomes are lost to the caller. Use [`restore_wave_with`] to record each
/// batch as it commits.
pub async fn restore_wave(
    pool: &PgPool,
    plan: &RestorePlan,
    opts: &RestoreOptions,
) -> anyhow::Result<RestoreReport> {
    let mut report = RestoreReport {
        not_in_wave: plan.not_in_wave.clone(),
        ..RestoreReport::default()
    };
    restore_wave_with(pool, plan, opts, |batch| {
        report.append(batch.clone());
        Ok(())
    })
    .await?;
    Ok(report)
}

/// [`restore_wave`], handing each batch's outcomes to `on_batch` right after
/// that batch commits (or, with `dry_run`, rolls back), so a later batch's
/// failure cannot lose the record of what earlier batches did. The batch
/// reports cover `plan.entries` only; `plan.not_in_wave` is the caller's.
///
/// # Errors
/// Any database error, or `on_batch`'s; batches already committed stay
/// committed and have been handed to `on_batch`, except the one whose
/// `on_batch` failed.
pub async fn restore_wave_with<F>(
    pool: &PgPool,
    plan: &RestorePlan,
    opts: &RestoreOptions,
    mut on_batch: F,
) -> anyhow::Result<()>
where
    F: FnMut(&RestoreReport) -> anyhow::Result<()>,
{
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

    for chunk in plan.entries.chunks(opts.batch_size.max(1)) {
        let mut report = RestoreReport::default();
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
                if e.partial {
                    &mut report.restored_partial
                } else {
                    &mut report.restored
                }
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
        on_batch(&report)?;
    }
    Ok(())
}

/// The edges a wave claim in scope sourced whose edge-factor BBA may have
/// frozen a wave value: the targets of the follow-up targeted re-wire.
///
/// SPEC §10.8: an edge-factor BBA is computed from its source's cached value
/// when it is wired, and a cache restore does not undo it. The BBA lands on the
/// TARGET, so only edges whose SOURCE is a wave claim are listed, every
/// in-scope one ([`RestorePlan::sources`]), including a claim held back from
/// the restore: the wave still wrote its value.
///
/// An edge is listed when, after `cutoff` = [`RestorePlan::wave_at`] less
/// [`DOWNSTREAM_SLACK_SECS`]:
///
/// * it was created (`edges.created_at`), or
/// * an edge-factor BBA keyed on it (`mass_functions.perspective_id = edge`,
///   `claim_id = target`) was written (`mass_functions.created_at`, which the
///   upsert resets on every re-store). An edge created while its source was
///   factorless is wired later (a dedup re-hit, `backfill_factors`), so its
///   `created_at` alone can predate the wave while its BBA does not.
///
/// One cutoff for the whole wave, not one per claim: an edge created after
/// the wave began but before its own source's write is wired after the edge
/// transaction commits, by which time the wave may have written the source.
/// Over-listing costs one idempotent re-wire. Closed edges (`valid_to` set)
/// are listed too, with `valid_to`, because their BBA may outlive the close.
///
/// # Errors
/// Any database error.
pub async fn downstream_edges(
    pool: &PgPool,
    plan: &RestorePlan,
) -> anyhow::Result<Vec<DownstreamEdge>> {
    let Some(wave_at) = plan.wave_at else {
        return Ok(Vec::new());
    };
    let cutoff = wave_at - chrono::Duration::seconds(DOWNSTREAM_SLACK_SECS);
    let mut out = Vec::new();
    for ids in plan.sources.chunks(DEFAULT_RESTORE_BATCH) {
        let mut rows: Vec<DownstreamEdge> = sqlx::query_as(
            "SELECT e.id AS edge_id, e.source_id, e.target_id, \
                    e.target_type::text AS target_type, e.relationship::text AS relationship, \
                    e.created_at, e.valid_to \
               FROM edges e \
              WHERE e.source_type = 'claim' AND e.source_id = ANY($1) \
                AND (e.created_at > $2 \
                     OR EXISTS (SELECT 1 FROM mass_functions mf \
                                 WHERE mf.perspective_id = e.id \
                                   AND mf.claim_id = e.target_id \
                                   AND mf.created_at > $2)) \
              ORDER BY e.created_at, e.id",
        )
        .bind(ids)
        .bind(cutoff)
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

// ── per-scope rows a wave rewrites (SPEC §7.2) ─────────────────────────────
//
// A cohort-v2 wave resyncs a wave atom's own `ds_combined_beliefs` rows from
// the atom fold. Nothing in the claim-cache restore above covers those rows,
// so the wave records each row's `before` and `written` in a SIDECAR next to
// its wave file ([`scoped_sidecar_path`]) and [`restore_scoped`] puts them
// back the same way: only where the row still holds exactly `written`.

/// The value columns of one `ds_combined_beliefs` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopedColumns {
    #[serde(with = "exact_f64")]
    pub belief: Option<f64>,
    #[serde(with = "exact_f64")]
    pub plausibility: Option<f64>,
    #[serde(with = "exact_f64")]
    pub mass_on_empty: Option<f64>,
    #[serde(with = "exact_f64")]
    pub mass_on_missing: Option<f64>,
    #[serde(with = "exact_f64")]
    pub conflict_k: Option<f64>,
    pub strategy_used: Option<String>,
    #[serde(with = "exact_f64")]
    pub pignistic_prob: Option<f64>,
}

/// One line of a wave's scoped sidecar: what the wave found in one
/// `ds_combined_beliefs` row and what it wrote there.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopedWaveRecord {
    /// `ds_combined_beliefs.id`.
    pub row_id: Uuid,
    pub claim_id: Uuid,
    pub frame_id: Uuid,
    pub scope_type: String,
    pub scope_id: Option<Uuid>,
    pub before: ScopedColumns,
    pub written: ScopedColumns,
    pub wave: String,
    /// The run's `wave_at`, as [`WaveRecord::at`].
    pub at: DateTime<Utc>,
}

/// Where a wave file's scoped sidecar lives: `<wave file>.scoped.jsonl`.
#[must_use]
pub fn scoped_sidecar_path(wave_file: &std::path::Path) -> std::path::PathBuf {
    let mut p = wave_file.as_os_str().to_owned();
    p.push(".scoped.jsonl");
    std::path::PathBuf::from(p)
}

/// Append one scoped record as a JSON line.
///
/// # Errors
/// Serialization or I/O failure.
pub fn write_scoped_record<W: Write>(out: &mut W, rec: &ScopedWaveRecord) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *out, rec)?;
    out.write_all(b"\n")?;
    Ok(())
}

/// Parse a scoped sidecar.
///
/// # Errors
/// I/O failure or a malformed line.
pub fn read_scoped_wave<R: BufRead>(input: R) -> anyhow::Result<Vec<ScopedWaveRecord>> {
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

/// Per-row outcome of [`restore_scoped`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopedRestoreReport {
    /// Put back to the wave's `before`.
    pub restored: Vec<Uuid>,
    /// Already holds `before`.
    pub already_restored: Vec<Uuid>,
    /// Holds neither: a later write landed; left alone.
    pub superseded_since_wave: Vec<Uuid>,
    /// The row no longer exists.
    pub missing: Vec<Uuid>,
}

/// One row's restore: the `before` of the trailing CHAINED run of its
/// records, compared against the last `written` (as [`plan_restore`] does
/// for a claim recorded more than once).
fn scoped_restore_entries(
    records: &[ScopedWaveRecord],
) -> Vec<(Uuid, ScopedColumns, ScopedColumns)> {
    let mut by_row: HashMap<Uuid, Vec<&ScopedWaveRecord>> = HashMap::new();
    let mut order: Vec<Uuid> = Vec::new();
    for r in records {
        let e = by_row.entry(r.row_id).or_default();
        if e.is_empty() {
            order.push(r.row_id);
        }
        e.push(r);
    }
    order
        .into_iter()
        .filter_map(|id| {
            let mut recs = by_row.remove(&id)?;
            recs.sort_by_key(|r| r.at);
            let last = recs.last()?;
            let mut first = recs.len() - 1;
            while first > 0 && recs[first - 1].written == recs[first].before {
                first -= 1;
            }
            Some((id, recs[first].before.clone(), last.written.clone()))
        })
        .collect()
}

/// Compare-and-swap restore of a wave's scoped rows: each row goes back to
/// its `before` only where it still holds exactly `written`. One transaction
/// per `opts.batch_size` rows; `opts.dry_run` rolls every batch back.
///
/// # Errors
/// Any database error; batches already committed stay committed.
pub async fn restore_scoped(
    pool: &PgPool,
    records: &[ScopedWaveRecord],
    opts: &RestoreOptions,
) -> anyhow::Result<ScopedRestoreReport> {
    const SAME: &str = "belief IS NOT DISTINCT FROM $2 AND plausibility IS NOT DISTINCT FROM $3 \
         AND mass_on_empty IS NOT DISTINCT FROM $4 AND mass_on_missing IS NOT DISTINCT FROM $5 \
         AND conflict_k IS NOT DISTINCT FROM $6 AND strategy_used IS NOT DISTINCT FROM $7 \
         AND pignistic_prob IS NOT DISTINCT FROM $8";
    let restore_sql = format!(
        "UPDATE ds_combined_beliefs SET belief = $9, plausibility = $10, mass_on_empty = $11, \
                mass_on_missing = $12, conflict_k = $13, strategy_used = $14, \
                pignistic_prob = $15 \
          WHERE id = $1 AND {SAME} RETURNING id"
    );
    let probe_sql = format!("SELECT ({SAME}) FROM ds_combined_beliefs WHERE id = $1");
    fn bind<'q>(
        sql: &'q str,
        id: Uuid,
        c: &ScopedColumns,
    ) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
        sqlx::query(sql)
            .bind(id)
            .bind(c.belief)
            .bind(c.plausibility)
            .bind(c.mass_on_empty)
            .bind(c.mass_on_missing)
            .bind(c.conflict_k)
            .bind(c.strategy_used.clone())
            .bind(c.pignistic_prob)
    }
    let entries = scoped_restore_entries(records);
    let mut report = ScopedRestoreReport::default();
    for chunk in entries.chunks(opts.batch_size.max(1)) {
        let mut tx = pool.begin().await?;
        for (id, before, written) in chunk {
            let hit = bind(&restore_sql, *id, written)
                .bind(before.belief)
                .bind(before.plausibility)
                .bind(before.mass_on_empty)
                .bind(before.mass_on_missing)
                .bind(before.conflict_k)
                .bind(before.strategy_used.clone())
                .bind(before.pignistic_prob)
                .fetch_optional(&mut *tx)
                .await?;
            if hit.is_some() {
                report.restored.push(*id);
                continue;
            }
            let holds_before: Option<Option<bool>> = {
                use sqlx::Row as _;
                bind(&probe_sql, *id, before)
                    .fetch_optional(&mut *tx)
                    .await?
                    .map(|r| r.get::<Option<bool>, _>(0))
            };
            match holds_before {
                None => report.missing.push(*id),
                Some(Some(true)) => report.already_restored.push(*id),
                Some(_) => report.superseded_since_wave.push(*id),
            }
        }
        if opts.dry_run {
            tx.rollback().await?;
        } else {
            tx.commit().await?;
        }
    }
    Ok(report)
}
