//! Compare-and-set refresh of `claims.truth_value` copies of an old belief
//! cache (operator rulings R-176(2) and R-177(5), class D), and its reverse.
//!
//! # The problem
//!
//! Several writers persist `truth_value = clamped(pignistic_prob)` when they
//! fold evidence (`update_with_evidence`, `submit_claim`): the scalar is a
//! MIRROR of the cache at write time. A cache recompute (`recompute_claim_belief`,
//! a factor re-wire) rewrites the cache and never touches `truth_value`, so a
//! mirror keeps the old number. Readers that compare or order on `truth_value`
//! directly, and every reader that falls back to it when the cache is NULLed
//! later, then serve the old value.
//!
//! # What this module does
//!
//! It works only from the wave files the recomputes wrote
//! ([`crate::belief_cache::WaveRecord`]): per claim, the chained records give
//! the OLD cache (`first.before.pignistic_prob`) and the NEW one
//! (`last.written.pignistic_prob`). A claim's `truth_value` is set to the new
//! cache only when EVERY rule below holds; otherwise it is left untouched and
//! reported in the named bucket ([`Bucket`]), the first rule that fails:
//!
//! | rule | bucket when false |
//! |---|---|
//! | the claim's wave records chain (as `belief_cache::plan_restore`) | `broken_chain` |
//! | the claim exists | `missing` |
//! | `is_current` | `not_current` |
//! | its role is neither compound nor procedural (`claim_role::roles_batch`) | `compound` / `procedural` |
//! | not a workflow or step claim: id not in `workflows`, `step_lineage_id IS NULL`, no `executes` in-edge, no `workflow` label (R-177 OD-D2) | `workflow_or_step` |
//! | the cache is unmoved since the wave: all seven cache columns equal the last `written` exactly | `superseded_since_wave` |
//! | `truth_value` equals the OLD cache exactly | `not_a_mirror` |
//! | neither `truth_value` nor the new value is within 1e-9 of the 0.05 deprecation sentinel (no flag admits it) | `sentinel_005` |
//! | `truth_value` is not round (a multiple of 0.001), unless `include_round` (R-177 OD-D3) | `round_value` |
//! | at least one live (not retracted) `auto_wire` row, the mirroring writers' combination method | `no_mirror_writer` |
//! | the new value is a probability | `no_new_value` |
//! | the new value differs from the old | `noop` |
//!
//! Exact equality is the mirror test because the mirroring writers persist
//! the same in-range `f64` in both columns (both are `double precision`). A
//! round value is where an authored scalar matches a cache by accident (0.5,
//! 0.75), hence the hold. The cache test is stricter than "the BetP is
//! unmoved": any later write to any cache column means the wave's value is no
//! longer what is served, so the refresh would mirror a stale number.
//!
//! # Writes
//!
//! [`apply`] runs one transaction per batch: it locks the claims
//! (`FOR UPDATE`, in id order), re-evaluates every rule on the locked values,
//! and writes each eligible claim with [`cas_refresh`]: an `UPDATE` that
//! matches only while `truth_value` and `pignistic_prob` still hold the exact
//! values just read, the claim is current, and its role is still neither
//! compound nor procedural. A write that matches no row is `raced`. Each
//! write's [`TruthRecord`] is handed to the caller BEFORE the batch commits,
//! so every committed write has a record. It writes `claims.truth_value` and
//! nothing else: no cache column, no `mass_functions` row, no `workflows` row
//! (the BEFORE UPDATE trigger bumps `updated_at`).
//!
//! [`dry_run`] evaluates the same rules in ONE `REPEATABLE READ, READ ONLY`
//! transaction and writes nothing. [`restore`] is the reverse compare-and-set
//! over a record file: `truth_before` goes back only where `truth_value` still
//! holds exactly `truth_written`.
//!
//! The SQL lives here rather than in `epigraph-db/src/repos/` for the same
//! reason as `belief_cache`'s: an operator binary's maintenance statement on
//! the maintenance connection, with no request path and no viewer to serve.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, Write};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use epigraph_db::repos::claim_role::{self, ClaimRole};

use crate::belief_cache::{plan_restore, CacheColumns, WaveRecord};

/// The deprecation sentinel (`claim.rs::deprecate_claim`: `SET truth_value =
/// 0.05`). A claim whose truth or new value is at it is never written.
pub const SENTINEL_005: f64 = 0.05;
/// How close to [`SENTINEL_005`] counts as the sentinel.
pub const SENTINEL_TOLERANCE: f64 = 1e-9;
/// How close to a multiple of 0.001 counts as round.
pub const ROUND_TOLERANCE: f64 = 1e-6;
/// Claims per transaction.
pub const DEFAULT_BATCH: usize = 1000;
/// The thresholds a refresh's crossings are counted at.
pub const CROSSINGS: [f64; 3] = [0.30, 0.50, 0.75];
/// The combination method of the writers that persist `truth_value` from the
/// fold they just cached (`ds_auto::auto_wire_ds_update`).
pub const MIRROR_WRITER_METHOD: &str = "auto_wire";

/// Bit-exact JSON for a required float (see `belief_cache`'s `exact_f64`: the
/// value is read from its raw JSON text with the correctly rounded
/// `str::parse::<f64>`, because serde_json's default parse can be off by one
/// ULP, and a restore compares exactly).
mod exact_f64_req {
    use serde::de::Error as _;
    use serde::ser::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_json::value::RawValue;

    pub fn serialize<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
        if v.is_finite() {
            s.serialize_f64(*v)
        } else {
            Err(S::Error::custom(format!(
                "non-finite value {v} has no exact JSON form"
            )))
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
        let raw: Box<RawValue> = Box::deserialize(d)?;
        raw.get()
            .parse::<f64>()
            .map_err(|e| D::Error::custom(format!("value {}: {e}", raw.get())))
    }
}

/// Why a claim was, or was not, refreshed. Each claim is in exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bucket {
    /// Every rule holds: refreshed (apply) or would be (dry run).
    Refresh,
    BrokenChain,
    Missing,
    NotCurrent,
    Compound,
    Procedural,
    WorkflowOrStep,
    SupersededSinceWave,
    NotAMirror,
    Sentinel005,
    RoundValue,
    NoMirrorWriter,
    NoNewValue,
    Noop,
    /// Eligible on the locked read, but the compare-and-set matched no row.
    Raced,
}

impl Bucket {
    /// Every bucket, in report order.
    pub const ALL: [Self; 15] = [
        Self::Refresh,
        Self::BrokenChain,
        Self::Missing,
        Self::NotCurrent,
        Self::Compound,
        Self::Procedural,
        Self::WorkflowOrStep,
        Self::SupersededSinceWave,
        Self::NotAMirror,
        Self::Sentinel005,
        Self::RoundValue,
        Self::NoMirrorWriter,
        Self::NoNewValue,
        Self::Noop,
        Self::Raced,
    ];

    /// The bucket's name in reports and on stdout.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Refresh => "refresh",
            Self::BrokenChain => "broken_chain",
            Self::Missing => "missing",
            Self::NotCurrent => "not_current",
            Self::Compound => "compound",
            Self::Procedural => "procedural",
            Self::WorkflowOrStep => "workflow_or_step",
            Self::SupersededSinceWave => "superseded_since_wave",
            Self::NotAMirror => "not_a_mirror",
            Self::Sentinel005 => "sentinel_005",
            Self::RoundValue => "round_value",
            Self::NoMirrorWriter => "no_mirror_writer",
            Self::NoNewValue => "no_new_value",
            Self::Noop => "noop",
            Self::Raced => "raced",
        }
    }
}

/// One claim the wave files name, with what they say about its cache.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub claim_id: Uuid,
    /// The cache the first wave found (`first.before.pignistic_prob`).
    pub old: Option<f64>,
    /// The cache the last wave wrote (`last.written.pignistic_prob`).
    pub new: Option<f64>,
    /// Every cache column the last wave wrote: the claim must still hold it.
    pub written: CacheColumns,
    /// The records do not chain: another writer landed between two waves.
    pub broken_chain: bool,
    /// The names of the waves that wrote it, sorted.
    pub waves: Vec<String>,
}

/// Turn the records of every wave file (L1 slices, then re-wire passes, in
/// any order: records are chained by `at`, as `belief_cache::plan_restore`
/// does) into one candidate per claim, in first-seen order.
#[must_use]
pub fn plan_candidates(records: &[WaveRecord]) -> Vec<Candidate> {
    let mut waves: HashMap<Uuid, BTreeSet<String>> = HashMap::new();
    for r in records {
        waves.entry(r.claim_id).or_default().insert(r.wave.clone());
    }
    plan_restore(records, None)
        .entries
        .into_iter()
        .map(|e| Candidate {
            claim_id: e.claim_id,
            old: e.before.pignistic_prob,
            new: e.written.pignistic_prob,
            written: e.written,
            broken_chain: e.partial,
            waves: waves
                .remove(&e.claim_id)
                .map(|s| s.into_iter().collect())
                .unwrap_or_default(),
        })
        .collect()
}

/// What the database holds for one candidate, as one statement read it.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimState {
    pub truth_value: f64,
    pub cache: CacheColumns,
    /// `NULL` reads as not current.
    pub is_current: bool,
    /// `None` when the role read did not return the claim.
    pub role: Option<ClaimRole>,
    pub workflow_or_step: bool,
    pub mirror_writer: bool,
}

fn near(a: f64, b: f64, tol: f64) -> bool {
    (a - b).abs() <= tol
}

/// `v` is a multiple of 0.001 (to [`ROUND_TOLERANCE`]).
#[must_use]
pub fn is_round(v: f64) -> bool {
    let k = 1000.0 * v;
    (k - k.round()).abs() <= ROUND_TOLERANCE
}

/// The rules of the module doc, in order; the first that fails names the
/// bucket. Pure.
#[must_use]
pub fn classify(c: &Candidate, state: Option<&ClaimState>, include_round: bool) -> Bucket {
    if c.broken_chain {
        return Bucket::BrokenChain;
    }
    let Some(s) = state else {
        return Bucket::Missing;
    };
    if !s.is_current {
        return Bucket::NotCurrent;
    }
    match s.role {
        None => return Bucket::Missing,
        Some(ClaimRole::Compound { .. }) => return Bucket::Compound,
        Some(ClaimRole::Procedural) => return Bucket::Procedural,
        Some(ClaimRole::Atom | ClaimRole::Standalone | ClaimRole::Rule) => {}
    }
    if s.workflow_or_step {
        return Bucket::WorkflowOrStep;
    }
    if s.cache != c.written {
        return Bucket::SupersededSinceWave;
    }
    // Exact: a mirror holds the very f64 the cache held.
    if c.old != Some(s.truth_value) {
        return Bucket::NotAMirror;
    }
    if near(s.truth_value, SENTINEL_005, SENTINEL_TOLERANCE)
        || c.new
            .is_some_and(|n| near(n, SENTINEL_005, SENTINEL_TOLERANCE))
    {
        return Bucket::Sentinel005;
    }
    if !include_round && is_round(s.truth_value) {
        return Bucket::RoundValue;
    }
    if !s.mirror_writer {
        return Bucket::NoMirrorWriter;
    }
    let Some(new) = c.new.filter(|n| n.is_finite() && (0.0..=1.0).contains(n)) else {
        return Bucket::NoNewValue;
    };
    if c.old == Some(new) {
        return Bucket::Noop;
    }
    Bucket::Refresh
}

/// `(id, truth_value, belief, plausibility, pignistic_prob, mass_on_empty,
/// mass_on_missing, belief_frame_id, classification, is_current,
/// workflow_or_step, mirror_writer)`.
type StateTuple = (
    Uuid,
    f64,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<Uuid>,
    Option<String>,
    Option<bool>,
    bool,
    bool,
);

/// Read the state every rule needs for `ids`, row-locked when `lock`. The
/// role is `claim_role::roles_batch`'s, read on the same connection; a claim
/// absent from the result does not exist.
///
/// # Errors
/// Any database error.
pub async fn read_states(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
    lock: bool,
) -> anyhow::Result<HashMap<Uuid, ClaimState>> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let sql = format!(
        "SELECT c.id, c.truth_value, c.belief, c.plausibility, c.pignistic_prob, \
                c.mass_on_empty, c.mass_on_missing, c.belief_frame_id, c.classification, \
                c.is_current, \
                (EXISTS (SELECT 1 FROM workflows w WHERE w.id = c.id) \
                 OR c.step_lineage_id IS NOT NULL \
                 OR EXISTS (SELECT 1 FROM edges e \
                             WHERE e.target_id = c.id AND e.relationship = 'executes') \
                 OR COALESCE('workflow' = ANY (c.labels), false)) AS workflow_or_step, \
                EXISTS (SELECT 1 FROM mass_functions mf \
                         WHERE mf.claim_id = c.id AND mf.retracted_at IS NULL \
                           AND mf.combination_method = $2) AS mirror_writer \
           FROM claims c \
          WHERE c.id = ANY($1) \
          ORDER BY c.id{}",
        if lock { " FOR UPDATE OF c" } else { "" }
    );
    let rows: Vec<StateTuple> = sqlx::query_as(&sql)
        .bind(ids)
        .bind(MIRROR_WRITER_METHOD)
        .fetch_all(&mut *conn)
        .await?;
    let roles = claim_role::roles_batch(&mut *conn, viewer, ids).await?;
    Ok(rows
        .into_iter()
        .map(|(id, t, b, p, bp, me, mm, f, cl, cur, wf, mw)| {
            (
                id,
                ClaimState {
                    truth_value: t,
                    cache: CacheColumns {
                        belief: b,
                        plausibility: p,
                        pignistic_prob: bp,
                        mass_on_empty: me,
                        mass_on_missing: mm,
                        belief_frame_id: f,
                        classification: cl,
                    },
                    is_current: cur == Some(true),
                    role: roles.get(&id).copied(),
                    workflow_or_step: wf,
                    mirror_writer: mw,
                },
            )
        })
        .collect())
}

/// The one write: set `truth_value` to `new` only while the row still holds
/// `read_truth` and `read_cache` exactly, is current, and its role is still
/// neither compound nor procedural. Returns whether a row matched.
///
/// # Errors
/// Any database error.
pub async fn cas_refresh(
    conn: &mut sqlx::PgConnection,
    claim_id: Uuid,
    read_truth: f64,
    read_cache: f64,
    new: f64,
) -> anyhow::Result<bool> {
    let sql = format!(
        "UPDATE claims c SET truth_value = $4 \
          WHERE c.id = $1 AND c.is_current \
            AND c.truth_value = $2 AND c.pignistic_prob = $3 \
            AND {role} NOT IN ('compound', 'procedural') \
         RETURNING c.id",
        role = claim_role::claim_role_sql("c"),
    );
    let hit: Option<Uuid> = sqlx::query_scalar(&sql)
        .bind(claim_id)
        .bind(read_truth)
        .bind(read_cache)
        .bind(new)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(hit.is_some())
}

/// One claim's outcome.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Outcome {
    pub claim_id: Uuid,
    pub bucket: Bucket,
    /// `truth_value` as read; `None` for a missing claim.
    pub truth_before: Option<f64>,
    pub old: Option<f64>,
    pub new: Option<f64>,
}

/// One refresh write, as the record file stores it (JSON lines, bit-exact).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TruthRecord {
    pub claim_id: Uuid,
    #[serde(with = "exact_f64_req")]
    pub truth_before: f64,
    #[serde(with = "exact_f64_req")]
    pub truth_written: f64,
    #[serde(with = "exact_f64_req")]
    pub cache_old: f64,
    #[serde(with = "exact_f64_req")]
    pub cache_new: f64,
    pub waves: Vec<String>,
    /// The run's start, from the database clock, before its first write.
    pub at: DateTime<Utc>,
}

/// Append one record as a JSON line.
///
/// # Errors
/// Serialization or I/O failure.
pub fn write_truth_record<W: Write>(out: &mut W, rec: &TruthRecord) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *out, rec)?;
    out.write_all(b"\n")?;
    Ok(())
}

/// Parse a record file.
///
/// # Errors
/// I/O failure or a malformed line.
pub fn read_truth_records<R: BufRead>(input: R) -> anyhow::Result<Vec<TruthRecord>> {
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

#[derive(Debug, Clone)]
pub struct RefreshOptions {
    pub batch_size: usize,
    pub include_round: bool,
}

impl Default for RefreshOptions {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH,
            include_round: false,
        }
    }
}

/// Every claim's outcome of one run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MirrorReport {
    pub outcomes: Vec<Outcome>,
}

impl MirrorReport {
    /// The claims in `bucket`, in run order.
    #[must_use]
    pub fn ids(&self, bucket: Bucket) -> Vec<Uuid> {
        self.outcomes
            .iter()
            .filter(|o| o.bucket == bucket)
            .map(|o| o.claim_id)
            .collect()
    }

    /// The bucket `claim_id` landed in.
    #[must_use]
    pub fn bucket_of(&self, claim_id: Uuid) -> Option<Bucket> {
        self.outcomes
            .iter()
            .find(|o| o.claim_id == claim_id)
            .map(|o| o.bucket)
    }

    /// Per-bucket counts, every bucket listed.
    #[must_use]
    pub fn counts(&self) -> Vec<(Bucket, usize)> {
        Bucket::ALL
            .iter()
            .map(|&b| (b, self.outcomes.iter().filter(|o| o.bucket == b).count()))
            .collect()
    }

    /// The report file's JSON: counts and ids per bucket, the refresh set with
    /// its values, the distribution of `new − old` over it, and its crossings
    /// of [`CROSSINGS`].
    #[must_use]
    pub fn to_json(
        &self,
        dry_run: bool,
        include_round: bool,
        wave_records: usize,
    ) -> serde_json::Value {
        let mut buckets = serde_json::Map::new();
        for b in Bucket::ALL {
            let ids = self.ids(b);
            buckets.insert(
                b.as_str().to_string(),
                serde_json::json!({ "count": ids.len(), "ids": ids }),
            );
        }
        let refresh: Vec<&Outcome> = self
            .outcomes
            .iter()
            .filter(|o| o.bucket == Bucket::Refresh)
            .collect();
        let deltas: Vec<(f64, f64)> = refresh
            .iter()
            .filter_map(|o| Some((o.old?, o.new?)))
            .collect();
        // Signed bins of `new − old`.
        const EDGES: [f64; 9] = [-0.2, -0.1, -0.05, -0.01, 0.0, 0.01, 0.05, 0.1, 0.2];
        let mut bins: BTreeMap<String, usize> = BTreeMap::new();
        for &(old, new) in &deltas {
            let d = new - old;
            let i = EDGES.iter().take_while(|&&e| d >= e).count();
            let lo = if i == 0 {
                "-inf".to_string()
            } else {
                format!("{:+.2}", EDGES[i - 1])
            };
            let hi = if i == EDGES.len() {
                "+inf".to_string()
            } else {
                format!("{:+.2}", EDGES[i])
            };
            *bins.entry(format!("[{lo}, {hi})")).or_default() += 1;
        }
        let mut crossings = serde_json::Map::new();
        for t in CROSSINGS {
            let up = deltas.iter().filter(|&&(o, n)| o < t && n >= t).count();
            let down = deltas.iter().filter(|&&(o, n)| n < t && o >= t).count();
            crossings.insert(
                format!("{t:.2}"),
                serde_json::json!({ "up": up, "down": down }),
            );
        }
        serde_json::json!({
            "dry_run": dry_run,
            "include_round": include_round,
            "wave_records": wave_records,
            "claims": self.outcomes.len(),
            "buckets": buckets,
            "refresh": refresh.iter().map(|o| serde_json::json!({
                "claim_id": o.claim_id,
                "truth_before": o.truth_before,
                "truth_new": o.new,
                "delta": match (o.old, o.new) { (Some(a), Some(b)) => Some(b - a), _ => None },
            })).collect::<Vec<_>>(),
            "delta_bins": bins,
            "crossings": crossings,
        })
    }
}

fn outcome(c: &Candidate, s: Option<&ClaimState>, bucket: Bucket) -> Outcome {
    Outcome {
        claim_id: c.claim_id,
        bucket,
        truth_before: s.map(|s| s.truth_value),
        old: c.old,
        new: c.new,
    }
}

/// Evaluate every rule for `candidates` and write nothing: one
/// `REPEATABLE READ, READ ONLY` transaction (a write inside it fails),
/// rolled back.
///
/// # Errors
/// Any database error.
pub async fn dry_run(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    candidates: &[Candidate],
    opts: &RefreshOptions,
) -> anyhow::Result<MirrorReport> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let mut report = MirrorReport::default();
    for chunk in candidates.chunks(opts.batch_size.max(1)) {
        let ids: Vec<Uuid> = chunk.iter().map(|c| c.claim_id).collect();
        let states = read_states(&mut tx, viewer, &ids, false).await?;
        for c in chunk {
            let s = states.get(&c.claim_id);
            report
                .outcomes
                .push(outcome(c, s, classify(c, s, opts.include_round)));
        }
    }
    tx.rollback().await?;
    Ok(report)
}

/// Refresh every eligible candidate, compare-and-set (see the module doc).
///
/// `on_record` receives each write's record before its batch commits; an
/// error from it rolls the batch back and stops the run, so no committed
/// write lacks a record. A record whose commit then fails names a write that
/// never landed, which [`restore`] reports `already_restored`.
///
/// # Errors
/// Any database error, or `on_record`'s; batches already committed stay
/// committed and their records were already handed out.
pub async fn apply<F>(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    candidates: &[Candidate],
    opts: &RefreshOptions,
    mut on_record: F,
) -> anyhow::Result<MirrorReport>
where
    F: FnMut(&TruthRecord) -> anyhow::Result<()>,
{
    // The run's stamp, from the database clock, in its own statement, before
    // the first write.
    let at: DateTime<Utc> = sqlx::query_scalar("SELECT now()").fetch_one(pool).await?;
    let mut report = MirrorReport::default();
    for chunk in candidates.chunks(opts.batch_size.max(1)) {
        let ids: Vec<Uuid> = chunk.iter().map(|c| c.claim_id).collect();
        let mut tx = pool.begin().await?;
        let states = read_states(&mut tx, viewer, &ids, true).await?;
        let mut batch = Vec::with_capacity(chunk.len());
        for c in chunk {
            let s = states.get(&c.claim_id);
            let mut bucket = classify(c, s, opts.include_round);
            if bucket == Bucket::Refresh {
                // `classify` returned Refresh, so all three are present.
                let (Some(s), Some(read_cache), Some(new)) =
                    (s, s.and_then(|s| s.cache.pignistic_prob), c.new)
                else {
                    anyhow::bail!(
                        "claim {}: classified refresh without a state, a cache or a new value",
                        c.claim_id
                    );
                };
                if cas_refresh(&mut tx, c.claim_id, s.truth_value, read_cache, new).await? {
                    on_record(&TruthRecord {
                        claim_id: c.claim_id,
                        truth_before: s.truth_value,
                        truth_written: new,
                        // Equal to `truth_before`: the mirror rule held.
                        cache_old: s.truth_value,
                        cache_new: new,
                        waves: c.waves.clone(),
                        at,
                    })?;
                } else {
                    bucket = Bucket::Raced;
                }
            }
            batch.push(outcome(c, s, bucket));
        }
        tx.commit().await?;
        report.outcomes.extend(batch);
    }
    Ok(report)
}

/// Per-claim outcome of a [`restore`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TruthRestoreReport {
    pub restored: Vec<Uuid>,
    /// Already holds `truth_before` (a second restore, or a refresh whose
    /// commit never landed).
    pub already_restored: Vec<Uuid>,
    /// Holds neither: a later write landed; left alone.
    pub superseded_since_refresh: Vec<Uuid>,
    pub missing: Vec<Uuid>,
}

impl TruthRestoreReport {
    /// Every outcome bucket with its name, in report order.
    #[must_use]
    pub fn buckets(&self) -> [(&'static str, &Vec<Uuid>); 4] {
        [
            ("restored", &self.restored),
            ("already_restored", &self.already_restored),
            ("superseded_since_refresh", &self.superseded_since_refresh),
            ("missing", &self.missing),
        ]
    }
}

/// Undo a refresh: per record, last record first (so chained refreshes of
/// one claim unwind in reverse), set `truth_before` back only where
/// `truth_value` still holds exactly `truth_written`. One transaction per
/// `batch_size` records; `dry_run` rolls each back.
///
/// # Errors
/// Any database error; batches already committed stay committed.
pub async fn restore(
    pool: &PgPool,
    records: &[TruthRecord],
    batch_size: usize,
    dry_run: bool,
) -> anyhow::Result<TruthRestoreReport> {
    let mut report = TruthRestoreReport::default();
    let reversed: Vec<&TruthRecord> = records.iter().rev().collect();
    for chunk in reversed.chunks(batch_size.max(1)) {
        let mut tx = pool.begin().await?;
        for r in chunk {
            let hit: Option<Uuid> = sqlx::query_scalar(
                "UPDATE claims SET truth_value = $2 \
                  WHERE id = $1 AND truth_value = $3 RETURNING id",
            )
            .bind(r.claim_id)
            .bind(r.truth_before)
            .bind(r.truth_written)
            .fetch_optional(&mut *tx)
            .await?;
            if hit.is_some() {
                report.restored.push(r.claim_id);
                continue;
            }
            let now: Option<f64> =
                sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
                    .bind(r.claim_id)
                    .fetch_optional(&mut *tx)
                    .await?;
            match now {
                None => report.missing.push(r.claim_id),
                Some(t) if t == r.truth_before => report.already_restored.push(r.claim_id),
                Some(_) => report.superseded_since_refresh.push(r.claim_id),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(p: f64) -> CacheColumns {
        CacheColumns {
            belief: Some(p - 0.1),
            plausibility: Some(p + 0.1),
            pignistic_prob: Some(p),
            mass_on_empty: Some(0.0),
            mass_on_missing: Some(0.0),
            belief_frame_id: None,
            classification: None,
        }
    }

    fn cand(old: f64, new: f64) -> Candidate {
        Candidate {
            claim_id: Uuid::new_v4(),
            old: Some(old),
            new: Some(new),
            written: cache(new),
            broken_chain: false,
            waves: vec!["w".into()],
        }
    }

    fn state(truth: f64, c: &Candidate) -> ClaimState {
        ClaimState {
            truth_value: truth,
            cache: c.written.clone(),
            is_current: true,
            role: Some(ClaimRole::Standalone),
            workflow_or_step: false,
            mirror_writer: true,
        }
    }

    #[test]
    fn a_mirror_of_the_old_cache_is_refreshed_and_an_offset_one_is_not() {
        let c = cand(0.612_345_678_9, 0.701_234_567_8);
        assert_eq!(
            classify(&c, Some(&state(0.612_345_678_9, &c)), false),
            Bucket::Refresh
        );
        assert_eq!(
            classify(&c, Some(&state(0.612_345_678_9 + 1e-15, &c)), false),
            Bucket::NotAMirror,
            "exact equality, not a tolerance"
        );
    }

    #[test]
    fn the_sentinel_is_refused_on_either_side_even_with_include_round() {
        let c = cand(0.05, 0.613_7);
        assert_eq!(
            classify(&c, Some(&state(0.05, &c)), true),
            Bucket::Sentinel005
        );
        let c = cand(0.613_789_1, 0.05);
        assert_eq!(
            classify(&c, Some(&state(0.613_789_1, &c)), true),
            Bucket::Sentinel005
        );
    }

    #[test]
    fn a_round_mirror_is_held_unless_included() {
        let c = cand(0.75, 0.812_345_6);
        assert_eq!(
            classify(&c, Some(&state(0.75, &c)), false),
            Bucket::RoundValue
        );
        assert_eq!(classify(&c, Some(&state(0.75, &c)), true), Bucket::Refresh);
    }

    #[test]
    fn exact_float_records_round_trip_bit_for_bit() {
        let rec = TruthRecord {
            claim_id: Uuid::new_v4(),
            truth_before: 0.1 + 0.2,
            truth_written: 0.712_345_678_901_234_5,
            cache_old: 0.1 + 0.2,
            cache_new: 0.712_345_678_901_234_5,
            waves: vec!["L1".into()],
            at: Utc::now(),
        };
        let mut buf = Vec::new();
        write_truth_record(&mut buf, &rec).unwrap();
        let back = read_truth_records(buf.as_slice()).unwrap();
        assert_eq!(back[0].truth_before.to_bits(), rec.truth_before.to_bits());
        assert_eq!(back[0].truth_written.to_bits(), rec.truth_written.to_bits());
    }
}
