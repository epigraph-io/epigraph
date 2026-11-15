//! Beta-track replay backfill (follow-up to backlog f50344c0).
//!
//! # What it is for
//!
//! Every DS evidence write is meant to keep the claim's parallel
//! Beta-Bernoulli track (`claims.beta_alpha` / `beta_beta`) beside the BBA it
//! stores. Until f50344c0 only `POST /frames/:id/evidence` did; the MCP DS
//! tools (`submit_ds_evidence`, `update_with_evidence`) and the other DS
//! writers stored BBAs and left the claim on the `Beta(1, 1)` prior. Those
//! tools now keep the track going forward, but a claim whose evidence is all
//! older still holds `Beta(1, 1)`: its next divergence row compares a BetP
//! built from its whole history with a posterior built from one BBA, and such
//! claims crowd `GET /divergence/top`.
//!
//! This module rebuilds the parameters of those claims by replaying their
//! stored BBAs, oldest first, through the live arithmetic
//! (`epigraph_engine::ds_divergence::replay_beta_params`, which folds
//! `beta_increments` exactly as successive live writes add them).
//!
//! # Which claims
//!
//! A current claim whose parameters are still the prior (both `1.0`, or
//! `NULL`, which the column default and the live update read as `1.0`) and
//! which has at least one live (not retracted), non-cached BBA. A claim whose
//! parameters moved (any Beta-keeping write landed on it) is never touched:
//! its track already counts some evidence, and replaying on top of it would
//! count that evidence twice.
//!
//! # Which BBAs are counted
//!
//! The claim's DS fold inputs, on every frame it has BBAs on: the rows the
//! combine-input readers fold (not retracted, not a cached combination, by the
//! same predicates, `mass_function::not_retracted_predicate` and
//! `cached_combination_predicate`). Each counts for the claim's hypothesis on
//! that frame (`claim_frames.hypothesis_index`, as the REST handler and
//! `submit_ds_evidence` count it); a frame with no index counts nothing, as
//! live.
//!
//! Left out by default, and counted by label in the report:
//!
//! * `truth_value_seed` rows (`epigraph_mcp::tools::ds_auto::TRUTH_VALUE_SEED_METHOD`):
//!   the claim's authored `truth_value` restated as a BBA. It is a prior, not
//!   evidence; the Beta track has its own prior, and `update_with_evidence`,
//!   which writes the seed, does not count it live;
//! * `prior` rows: a vacuous hypothesis prior. The live arithmetic counts a
//!   vacuous BBA's whole mass against the hypothesis, so counting one would
//!   move the claim toward false on no evidence.
//!
//! `--exclude-method` leaves out more writers by their `combination_method`
//! label. The dry run lists the counted rows by label, so the operator sees
//! which writers the replay would count before applying it.
//!
//! # What the replay is and is not
//!
//! It is the track the live update would hold had every currently stored BBA
//! been counted once when stored. It is not a reconstruction of past live
//! writes: a BBA replaced in its slot (a resubmission with different masses)
//! is counted once, as its current masses; a retracted BBA is not counted; and
//! each BBA counts for the claim's CURRENT hypothesis index on its frame. The
//! masses come from their stored JSON, so a replayed parameter can differ from
//! an in-memory live sum in the last bit.
//!
//! # What it writes
//!
//! Only `claims.beta_alpha` and `beta_beta`, and only on claims that still hold
//! the prior under the row lock of the batch's transaction (`FOR UPDATE`), so a
//! live write racing the backfill is never lost: one that committed first moves
//! the claim off the prior and it is skipped (counted as `moved_since_scan`);
//! one that commits after adds its increment to the replayed value, and its BBA
//! was not yet visible to the replay. The `claims_updated_at` trigger stamps
//! `updated_at`, as the live update does.
//!
//! It writes NO `ds_bayesian_divergence` row. A divergence row is a record of
//! one evidence write (the BetP after it against the posterior after it); the
//! history has no such moments to record, and inventing them would put rows
//! dated now into `GET /divergence/top`. The next live evidence write on a
//! replayed claim records its divergence against the replayed track.
//!
//! # Dry run, manifest and reversal
//!
//! Without `apply` nothing is written: the report gives the counts and a
//! sample. With `apply`, each batch's manifest records ([`ManifestRecord`]:
//! the parameters found and the parameters written, bit-exact) are written and
//! flushed BEFORE the batch commits (the binary's writer syncs the file on
//! flush), so every committed write is in the manifest; a record whose batch then failed restores nothing (its claim
//! does not hold `written`). [`reverse`] puts `before` back only where the
//! claim still holds exactly `written`, and reports the rest: a claim a live
//! write has moved since is not reset, because that would drop the live
//! increment.
//!
//! The SQL lives here rather than in `epigraph-db/src/repos/` for the reason
//! `belief_cache`'s and `recompute_betp`'s does: an operator binary's
//! corpus-wide maintenance statement on the maintenance connection, with no
//! request path and no viewer.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, Write};

use chrono::{DateTime, Utc};
use epigraph_db::repos::mass_function::{cached_combination_predicate, not_retracted_predicate};
use epigraph_db::DbError;
use epigraph_ds::{FrameOfDiscernment, MassFunction};
use serde::{Deserialize, Serialize};
use sqlx::Acquire as _;
use uuid::Uuid;

use crate::belief_cache::exact_f64;

/// The `combination_method` labels left out unless the operator says
/// otherwise. See the module documentation for why each one is not evidence.
pub const DEFAULT_EXCLUDED_METHODS: [&str; 2] = [
    epigraph_mcp::tools::ds_auto::TRUTH_VALUE_SEED_METHOD,
    "prior",
];

/// Claims per batch transaction by default.
pub const DEFAULT_BATCH: i64 = 500;

/// How a row's `combination_method` is reported when it is NULL.
const NULL_METHOD: &str = "<null>";

/// How to run.
#[derive(Debug, Clone)]
pub struct Options {
    /// Write the replayed parameters. Without it nothing is written.
    pub apply: bool,
    /// Claims per batch.
    pub batch: i64,
    /// Resume after this claim id (a previous run's `last_id`).
    pub after: Option<Uuid>,
    /// Stop after this many batches.
    pub max_batches: Option<u64>,
    /// How many claims the report samples.
    pub sample: usize,
    /// `combination_method` labels whose rows are not counted.
    pub excluded_methods: BTreeSet<String>,
}

impl Options {
    /// A dry run over everything, with the default exclusions.
    #[must_use]
    pub fn dry_run() -> Self {
        Self {
            apply: false,
            batch: DEFAULT_BATCH,
            after: None,
            max_batches: None,
            sample: 10,
            excluded_methods: DEFAULT_EXCLUDED_METHODS
                .iter()
                .map(|m| (*m).to_string())
                .collect(),
        }
    }
}

/// One replayed claim in the report's sample.
#[derive(Debug, Clone, Serialize)]
pub struct Sample {
    pub claim_id: Uuid,
    pub bbas_counted: u64,
    pub before: (Option<f64>, Option<f64>),
    pub replayed: (f64, f64),
    /// `alpha / (alpha + beta)` after the replay.
    pub replayed_posterior: f64,
}

/// What a run did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub applied: bool,
    pub batches: u64,
    /// Candidate claims scanned.
    pub scanned: u64,
    /// Claims whose replay moves the parameters (in a dry run: would move).
    pub replayed: u64,
    /// Claims actually written (always 0 in a dry run).
    pub written: u64,
    /// Candidates whose counted BBAs move nothing (none counted, or none on an
    /// indexed hypothesis); left on the prior.
    pub unchanged: u64,
    /// Candidates that moved off the prior between the scan and the row lock
    /// (a live write landed); not touched.
    pub moved_since_scan: u64,
    /// Candidates left untouched because a counted BBA's masses or frame did
    /// not parse. Their ids are in `unparsable_claims` (first 100).
    pub unparsable: u64,
    pub unparsable_claims: Vec<Uuid>,
    pub bbas_counted: u64,
    /// Counted BBAs on a frame where the claim has no hypothesis index: they
    /// count nothing, as live.
    pub bbas_without_hypothesis_index: u64,
    /// Counted BBAs by `combination_method`.
    pub counted_by_method: BTreeMap<String, u64>,
    /// BBAs left out by `combination_method` (the exclusion list).
    pub excluded_by_method: BTreeMap<String, u64>,
    /// Always 0: the replay records no divergence history (module docs).
    pub divergence_rows_written: u64,
    /// The last claim id scanned: pass it as `--after` to resume.
    pub last_id: Option<Uuid>,
    /// FALSE when the run stopped at `max_batches` with claims left to scan.
    pub complete: bool,
    pub sample: Vec<Sample>,
}

/// One line of the manifest an applying run writes: what it found and what it
/// wrote, bit-exact, for [`reverse`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestRecord {
    pub claim_id: Uuid,
    #[serde(with = "exact_f64")]
    pub before_alpha: Option<f64>,
    #[serde(with = "exact_f64")]
    pub before_beta: Option<f64>,
    #[serde(with = "exact_f64")]
    pub written_alpha: Option<f64>,
    #[serde(with = "exact_f64")]
    pub written_beta: Option<f64>,
    pub bbas_counted: u64,
    /// When the run that wrote this record started.
    pub run_started_at: DateTime<Utc>,
}

/// One stored BBA as the replay reads it.
struct BbaRow {
    claim_id: Uuid,
    combination_method: Option<String>,
    masses: serde_json::Value,
    frame_name: String,
    hypotheses: Vec<String>,
    hypothesis_index: Option<i32>,
}

/// [`BbaRow`] as the query returns it.
type BbaTuple = (
    Uuid,
    Option<String>,
    serde_json::Value,
    String,
    Vec<String>,
    Option<i32>,
);

/// A locked candidate: id, `beta_alpha`, `beta_beta`.
type LockedClaim = (Uuid, Option<f64>, Option<f64>);

/// The replay of one claim, before it is written.
enum Replay {
    /// The parameters move to these values.
    Moves { params: (f64, f64), counted: u64 },
    /// Nothing counted moves them.
    Unchanged,
    /// A counted row did not parse; the claim is left alone.
    Unparsable,
}

/// The prior test both the scan and the lock carry, on alias `c`.
const STILL_ON_PRIOR: &str = "c.is_current \
     AND COALESCE(c.beta_alpha, 1.0) = 1.0 AND COALESCE(c.beta_beta, 1.0) = 1.0";

/// One page of candidate claim ids after `after`, in id order.
async fn candidate_page(
    conn: &mut sqlx::PgConnection,
    after: Option<Uuid>,
    limit: i64,
) -> Result<Vec<Uuid>, DbError> {
    let not_retracted = not_retracted_predicate("mf.");
    let cached = cached_combination_predicate("mf.");
    let sql = format!(
        "SELECT c.id FROM claims c \
          WHERE {STILL_ON_PRIOR} \
            AND ($1::uuid IS NULL OR c.id > $1) \
            AND EXISTS (SELECT 1 FROM mass_functions mf \
                         WHERE mf.claim_id = c.id AND {not_retracted} AND NOT {cached}) \
          ORDER BY c.id LIMIT $2"
    );
    Ok(sqlx::query_scalar(&sql)
        .bind(after)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?)
}

/// The fold inputs of `claims`, per claim oldest first.
async fn fold_inputs(
    conn: &mut sqlx::PgConnection,
    claims: &[Uuid],
) -> Result<Vec<BbaRow>, DbError> {
    let not_retracted = not_retracted_predicate("mf.");
    let cached = cached_combination_predicate("mf.");
    let sql = format!(
        "SELECT mf.claim_id, mf.combination_method, mf.masses, f.name, f.hypotheses, \
                cf.hypothesis_index \
           FROM mass_functions mf \
           JOIN frames f ON f.id = mf.frame_id \
           LEFT JOIN claim_frames cf ON cf.claim_id = mf.claim_id AND cf.frame_id = mf.frame_id \
          WHERE mf.claim_id = ANY($1) AND {not_retracted} AND NOT {cached} \
          ORDER BY mf.claim_id, mf.created_at, mf.id"
    );
    let rows: Vec<BbaTuple> = sqlx::query_as(&sql)
        .bind(claims)
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows
        .into_iter()
        .map(
            |(claim_id, combination_method, masses, frame_name, hypotheses, hypothesis_index)| {
                BbaRow {
                    claim_id,
                    combination_method,
                    masses,
                    frame_name,
                    hypotheses,
                    hypothesis_index,
                }
            },
        )
        .collect())
}

/// Replay one claim's rows (already oldest first), counting into `report`.
fn replay_claim(rows: &[&BbaRow], opts: &Options, report: &mut Report) -> Replay {
    let mut parsed: Vec<(MassFunction, Option<i32>)> = Vec::new();
    let mut by_method: BTreeMap<String, u64> = BTreeMap::new();
    let mut excluded: BTreeMap<String, u64> = BTreeMap::new();
    let mut without_index = 0u64;
    for row in rows {
        let method = row
            .combination_method
            .clone()
            .unwrap_or_else(|| NULL_METHOD.to_string());
        if opts.excluded_methods.contains(&method) {
            *excluded.entry(method).or_default() += 1;
            continue;
        }
        let Ok(frame) = FrameOfDiscernment::new(row.frame_name.clone(), row.hypotheses.clone())
        else {
            return Replay::Unparsable;
        };
        let Ok(bba) = MassFunction::from_json_masses(frame, &row.masses) else {
            return Replay::Unparsable;
        };
        if row.hypothesis_index.is_none() {
            without_index += 1;
        }
        *by_method.entry(method).or_default() += 1;
        parsed.push((bba, row.hypothesis_index));
    }
    // Counted only once the claim is known to replay, so an unparsable claim
    // contributes nothing to the totals but its own count.
    for (m, n) in excluded {
        *report.excluded_by_method.entry(m).or_default() += n;
    }
    let counted = parsed.len() as u64;
    report.bbas_counted += counted;
    report.bbas_without_hypothesis_index += without_index;
    for (m, n) in by_method {
        *report.counted_by_method.entry(m).or_default() += n;
    }
    let params = epigraph_engine::ds_divergence::replay_beta_params(
        (1.0, 1.0),
        parsed.iter().map(|(bba, idx)| (bba, *idx)),
    );
    if params == (1.0, 1.0) {
        Replay::Unchanged
    } else {
        Replay::Moves { params, counted }
    }
}

/// Scan every candidate claim after `opts.after` in id order, `opts.batch` at
/// a time, replay each, and (with `opts.apply`) write each batch in its own
/// transaction, after appending its records to `manifest`. `conn` must be the
/// maintenance connection.
///
/// # Errors
/// A database error, or a manifest write that fails (the batch is then rolled
/// back). Batches already committed stay written, and their records are in
/// the manifest; `--after` resumes from the last good batch.
///
/// # Panics
/// Never on input: `apply` without a manifest is refused as an error.
pub async fn run(
    conn: &mut sqlx::PgConnection,
    opts: &Options,
    mut manifest: Option<&mut dyn Write>,
) -> Result<Report, Box<dyn std::error::Error + Send + Sync>> {
    if opts.apply && manifest.is_none() {
        return Err("an applying run needs a manifest to reverse it by".into());
    }
    let run_started_at = Utc::now();
    let batch = opts.batch.max(1);
    let mut report = Report {
        applied: opts.apply,
        last_id: opts.after,
        ..Report::default()
    };
    let mut after = opts.after;
    loop {
        if opts.max_batches.is_some_and(|m| report.batches >= m) {
            report.complete = false;
            return Ok(report);
        }
        let page = candidate_page(&mut *conn, after, batch).await?;
        let Some(&last) = page.last() else {
            report.complete = true;
            return Ok(report);
        };
        after = Some(last);
        report.batches += 1;
        report.scanned += page.len() as u64;

        let mut tx = conn.begin().await?;
        // Under the lock when applying, so no live write lands between the
        // read below and the write (module docs).
        let lock = if opts.apply { " FOR UPDATE" } else { "" };
        let locked: Vec<LockedClaim> = sqlx::query_as(&format!(
            "SELECT c.id, c.beta_alpha, c.beta_beta FROM claims c \
              WHERE c.id = ANY($1) AND {STILL_ON_PRIOR} ORDER BY c.id{lock}"
        ))
        .bind(&page)
        .fetch_all(&mut *tx)
        .await?;
        report.moved_since_scan += (page.len() - locked.len()) as u64;
        let ids: Vec<Uuid> = locked.iter().map(|r| r.0).collect();
        let inputs = fold_inputs(&mut tx, &ids).await?;
        let mut per_claim: HashMap<Uuid, Vec<&BbaRow>> = HashMap::new();
        for row in &inputs {
            per_claim.entry(row.claim_id).or_default().push(row);
        }

        let mut records = Vec::new();
        for (claim_id, before_alpha, before_beta) in &locked {
            let rows = per_claim.get(claim_id).map_or(&[][..], Vec::as_slice);
            match replay_claim(rows, opts, &mut report) {
                Replay::Unchanged => report.unchanged += 1,
                Replay::Unparsable => {
                    report.unparsable += 1;
                    if report.unparsable_claims.len() < 100 {
                        report.unparsable_claims.push(*claim_id);
                    }
                }
                Replay::Moves { params, counted } => {
                    report.replayed += 1;
                    if report.sample.len() < opts.sample {
                        report.sample.push(Sample {
                            claim_id: *claim_id,
                            bbas_counted: counted,
                            before: (*before_alpha, *before_beta),
                            replayed: params,
                            replayed_posterior: params.0 / (params.0 + params.1),
                        });
                    }
                    records.push(ManifestRecord {
                        claim_id: *claim_id,
                        before_alpha: *before_alpha,
                        before_beta: *before_beta,
                        written_alpha: Some(params.0),
                        written_beta: Some(params.1),
                        bbas_counted: counted,
                        run_started_at,
                    });
                }
            }
        }

        if opts.apply && !records.is_empty() {
            if let Some(out) = manifest.as_deref_mut() {
                for r in &records {
                    serde_json::to_writer(&mut *out, r)?;
                    out.write_all(b"\n")?;
                }
                out.flush()?;
            }
            let ids: Vec<Uuid> = records.iter().map(|r| r.claim_id).collect();
            let alphas: Vec<Option<f64>> = records.iter().map(|r| r.written_alpha).collect();
            let betas: Vec<Option<f64>> = records.iter().map(|r| r.written_beta).collect();
            let written = sqlx::query(&format!(
                "UPDATE claims AS c SET beta_alpha = v.a, beta_beta = v.b \
                   FROM unnest($1::uuid[], $2::float8[], $3::float8[]) AS v(id, a, b) \
                  WHERE c.id = v.id AND {STILL_ON_PRIOR}"
            ))
            .bind(&ids)
            .bind(&alphas)
            .bind(&betas)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            report.written += written;
        }
        tx.commit().await?;
        report.last_id = after;
        tracing::info!(
            batch = report.batches,
            last_id = ?after,
            scanned = report.scanned,
            replayed = report.replayed,
            written = report.written,
            "replay_beta_track batch done"
        );
        if i64::try_from(page.len()).unwrap_or(i64::MAX) < batch {
            report.complete = true;
            return Ok(report);
        }
    }
}

/// What a reversal did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ReverseReport {
    pub applied: bool,
    pub records: u64,
    /// Claims put back to `before` (in a dry run: that would be).
    pub restored: u64,
    /// Claims that no longer hold `written` (a live write moved them, or the
    /// record's batch never committed) and were left alone. First 100 ids in
    /// `not_at_written_claims`.
    pub not_at_written: u64,
    pub not_at_written_claims: Vec<Uuid>,
}

/// Put each manifest record's `before` back where the claim still holds
/// exactly its `written` parameters, `batch` records per transaction. Without
/// `apply`, only count. `conn` must be the maintenance connection.
///
/// # Errors
/// A manifest line that does not parse (nothing after it is applied), or a
/// database error (batches already committed stay restored).
pub async fn reverse(
    conn: &mut sqlx::PgConnection,
    manifest: impl BufRead,
    batch: usize,
    apply: bool,
) -> Result<ReverseReport, Box<dyn std::error::Error + Send + Sync>> {
    let mut records = Vec::new();
    for (n, line) in manifest.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let r: ManifestRecord =
            serde_json::from_str(&line).map_err(|e| format!("manifest line {}: {e}", n + 1))?;
        records.push(r);
    }
    let mut report = ReverseReport {
        applied: apply,
        records: records.len() as u64,
        ..ReverseReport::default()
    };
    for chunk in records.chunks(batch.max(1)) {
        let ids: Vec<Uuid> = chunk.iter().map(|r| r.claim_id).collect();
        let before_a: Vec<Option<f64>> = chunk.iter().map(|r| r.before_alpha).collect();
        let before_b: Vec<Option<f64>> = chunk.iter().map(|r| r.before_beta).collect();
        let written_a: Vec<Option<f64>> = chunk.iter().map(|r| r.written_alpha).collect();
        let written_b: Vec<Option<f64>> = chunk.iter().map(|r| r.written_beta).collect();
        // Only a claim that still holds exactly what the run wrote.
        let src = "unnest($1::uuid[], $2::float8[], $3::float8[], $4::float8[], $5::float8[]) \
                   AS v(id, ba, bb, wa, wb)";
        let cas = "c.id = v.id \
                   AND c.beta_alpha IS NOT DISTINCT FROM v.wa \
                   AND c.beta_beta IS NOT DISTINCT FROM v.wb";
        let sql = if apply {
            format!(
                "UPDATE claims AS c SET beta_alpha = v.ba, beta_beta = v.bb \
                   FROM {src} WHERE {cas} RETURNING c.id"
            )
        } else {
            format!("SELECT c.id FROM claims AS c, {src} WHERE {cas}")
        };
        let mut tx = conn.begin().await?;
        let hit: Vec<Uuid> = sqlx::query_scalar(&sql)
            .bind(&ids)
            .bind(&before_a)
            .bind(&before_b)
            .bind(&written_a)
            .bind(&written_b)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        let hit: BTreeSet<Uuid> = hit.into_iter().collect();
        report.restored += hit.len() as u64;
        for id in ids.iter().filter(|id| !hit.contains(id)) {
            report.not_at_written += 1;
            if report.not_at_written_claims.len() < 100 {
                report.not_at_written_claims.push(*id);
            }
        }
    }
    Ok(report)
}
