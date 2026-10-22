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

/// Claims per restore transaction (SPEC §10.8: one transaction per 1k claims).
pub const DEFAULT_RESTORE_BATCH: usize = 1000;

/// Rows per snapshot page.
pub const DEFAULT_SNAPSHOT_PAGE: i64 = 5000;

/// The belief-cache columns of one `claims` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
pub struct CacheColumns {
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub pignistic_prob: Option<f64>,
    pub mass_on_empty: Option<f64>,
    pub mass_on_missing: Option<f64>,
    pub belief_frame_id: Option<Uuid>,
    pub classification: Option<String>,
}

/// One line of a `belief_snapshot` file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotRow {
    pub claim_id: Uuid,
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub pignistic_prob: Option<f64>,
    pub mass_on_empty: Option<f64>,
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
#[must_use]
pub fn plan_restore(records: &[WaveRecord], only: Option<&HashSet<Uuid>>) -> RestorePlan {
    let _ = only;
    RestorePlan {
        entries: records
            .iter()
            .map(|r| RestoreEntry {
                claim_id: r.claim_id,
                before: r.before.clone(),
                written: r.written.clone(),
                at: r.at,
            })
            .collect(),
        ..RestorePlan::default()
    }
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
