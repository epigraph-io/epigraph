//! Belief-cache snapshot and compare-and-swap (CAS) restore (SPEC §10.8).
//!
//! SKELETON: the types and signatures the red tests pin. The bodies are the
//! naive versions (plain serde floats, one snapshot page, an unconditional
//! overwrite, no downstream list); the implementation commits replace them.

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

/// Read the cache columns of `ids`. Absent claims are absent from the map.
///
/// # Errors
/// Any database error.
pub async fn read_cache_columns<'e, E: sqlx::PgExecutor<'e>>(
    exec: E,
    ids: &[Uuid],
) -> anyhow::Result<HashMap<Uuid, CacheColumns>> {
    let rows: Vec<(
        Uuid,
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<Uuid>,
        Option<String>,
    )> = sqlx::query_as(
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
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line)?);
    }
    Ok(out)
}

/// Parse a snapshot file.
///
/// # Errors
/// I/O failure or a malformed line.
pub fn read_snapshot<R: BufRead>(input: R) -> anyhow::Result<Vec<SnapshotRow>> {
    let mut out = Vec::new();
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line)?);
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

/// Put every planned claim back to its `before` value.
///
/// # Errors
/// Any database error.
pub async fn restore_wave(
    pool: &PgPool,
    plan: &RestorePlan,
    opts: &RestoreOptions,
) -> anyhow::Result<RestoreReport> {
    let _ = opts;
    let mut report = RestoreReport::default();
    for e in &plan.entries {
        sqlx::query(
            "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4, \
                    mass_on_empty = $5, mass_on_missing = $6, belief_frame_id = $7, \
                    classification = $8 \
              WHERE id = $1",
        )
        .bind(e.claim_id)
        .bind(e.before.belief)
        .bind(e.before.plausibility)
        .bind(e.before.pignistic_prob)
        .bind(e.before.mass_on_empty)
        .bind(e.before.mass_on_missing)
        .bind(e.before.belief_frame_id)
        .bind(e.before.classification.as_deref())
        .execute(pool)
        .await?;
        report.restored.push(e.claim_id);
    }
    Ok(report)
}

/// Edges created after the wave whose source is a planned claim.
///
/// # Errors
/// Any database error.
pub async fn downstream_edges(
    pool: &PgPool,
    plan: &RestorePlan,
) -> anyhow::Result<Vec<DownstreamEdge>> {
    let _ = (pool, plan);
    Ok(Vec::new())
}

/// Write every claim's cache columns as JSON lines.
///
/// # Errors
/// Any database or I/O error.
pub async fn write_snapshot<W: Write>(
    pool: &PgPool,
    out: &mut W,
    opts: &SnapshotOptions,
) -> anyhow::Result<SnapshotSummary> {
    let snapshot_at: DateTime<Utc> = sqlx::query_scalar("SELECT now()").fetch_one(pool).await?;
    let rows: Vec<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, updated_at FROM claims WHERE ($1 OR is_current) ORDER BY id LIMIT $2",
    )
    .bind(opts.include_superseded)
    .bind(opts.page_size)
    .fetch_all(pool)
    .await?;
    let ids: Vec<Uuid> = rows.iter().map(|r| r.0).collect();
    let caches = read_cache_columns(pool, &ids).await?;
    let mut n = 0u64;
    for (id, updated_at) in rows {
        let c = &caches[&id];
        let row = SnapshotRow {
            claim_id: id,
            belief: c.belief,
            plausibility: c.plausibility,
            pignistic_prob: c.pignistic_prob,
            mass_on_empty: c.mass_on_empty,
            mass_on_missing: c.mass_on_missing,
            belief_frame_id: c.belief_frame_id,
            classification: c.classification.clone(),
            updated_at,
        };
        serde_json::to_writer(&mut *out, &row)?;
        out.write_all(b"\n")?;
        n += 1;
    }
    Ok(SnapshotSummary {
        rows: n,
        snapshot_at,
    })
}
