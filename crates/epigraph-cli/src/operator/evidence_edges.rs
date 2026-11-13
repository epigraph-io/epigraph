//! `backfill-evidence-edges`: write the stored `evidence -> claim` edge every
//! older evidence row lacks; and `reverse-evidence-edges`, its exact reversal
//! from the run's manifest (backlog 2d60f619).
//!
//! # Why
//!
//! The Atlas leaf view draws stored `evidence -> claim` edges only; there is no
//! derived edge (operator ruling). Since this backlog item every evidence write
//! stores its edge in its own transaction
//! (`EvidenceRepository::link_to_claims_signed_conn`), but the rows written
//! before it mostly have none. This writes them, through that same helper.
//!
//! # What is missing
//!
//! An evidence row is MISSING its edge when no `edges` row of ANY relationship
//! and in ANY state runs `evidence(id) -> claim(evidence.claim_id)`. So a row
//! with a legacy `SUPPORTS`, a `supports`, a `refutes` or only a RETRACTED edge
//! is left alone: a retracted edge is its owner's decision and is never
//! re-written (the census counts those rows on their own).
//!
//! A row whose claim is SEALED (`claim_encryption`) or which is sealed itself
//! (`evidence_encryption`) is never touched: it is counted and skipped.
//!
//! # Direction
//!
//! The `evidence` row records none. Its BBAs do: every non-retracted
//! `mass_functions` row with `evidence_id` = the row and `claim_id` = its
//! claim, on a frame where the claim's own hypothesis index `h` is known
//! (`claim_frames.hypothesis_index`, or 0 on a two-hypothesis frame with no
//! assignment, the binary frame's TRUE). Mass on `{h}` argues FOR the claim;
//! mass on a non-empty set without `h` argues AGAINST it. More against than
//! for writes `refutes`; otherwise `supports`. A row with no such BBA, or a
//! tie, gets `supports` (the census counts which rule decided each row).
//!
//! # Tenancy and signing
//!
//! The edge's tenancy is stamped by the edges trigger from its two endpoints
//! (the meet), as for every edge. This runs on the maintenance DSN, which
//! holds no entity key, so the edges are unsigned (the signing ratchet
//! registers the call `Unsigned`). The apply report counts the edges it wrote
//! by their stored tenancy.
//!
//! # Run shape
//!
//! Maintenance DSN only (`operator::connect`). A dry run is READ-ONLY: the
//! census, nothing written. `--apply` needs `--confirm-count` (the dry run's
//! `to_write`, repeated back), `--manifest-out` (a new file) and `--reason`.
//! It writes batches of `--batch-size` rows in evidence-id order, each in its
//! own transaction under `lock_timeout`. Each batch's edge lines are appended
//! to the manifest and `fsync`ed BEFORE its COMMIT, and a `committed_batch`
//! line follows AFTER it. One `security_events` row per applied run, in its
//! first batch. `--max-batches` stops early; a re-run (a new manifest) picks
//! up the rest, since the selection is "missing". An applied run (and an
//! applied reversal) holds the session advisory lock [`LOCK_NAME`] from
//! before its census to its end, and refuses to start while another holds
//! it: `edges` has no unique key on its triple, so two interleaved applies
//! could otherwise both write one row's edge.
//!
//! # Reversal
//!
//! `reverse-evidence-edges --manifest <file>` deletes exactly the edges the
//! manifest names, and only while each still runs from the recorded evidence
//! to the recorded claim with the recorded relationship. Every edge line is
//! reversed, committed batch or not: a batch whose COMMIT landed before the
//! process died has no `committed_batch` line, and a line whose batch rolled
//! back names an edge that does not exist and deletes nothing. A dry run
//! rolls each batch back. A second reversal deletes nothing.

use anyhow::{anyhow, bail, Context};
use epigraph_db::{EvidenceDirection, EvidenceRepository};
use serde_json::{json, Value};
use sqlx::{Connection, PgConnection, Row};
use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// The manifest's `manifest` key.
pub const OPERATION: &str = "backfill-evidence-edges";
/// The manifest format version this build writes and reads.
pub const VERSION: i64 = 1;
/// `security_events.event_type` of an applied run.
pub const EVENT_APPLY: &str = "evidence_claim_edge.backfill";
/// `security_events.event_type` of an applied reversal.
pub const EVENT_REVERSE: &str = "evidence_claim_edge.backfill_reverse";
/// The largest batch a run takes.
pub const MAX_BATCH: usize = 10_000;
/// The session advisory lock (`pg_try_advisory_lock(hashtextextended(name, 0))`)
/// an applied backfill or reversal holds for its whole run, so two never
/// interleave: the "is it missing?" check before each edge INSERT takes no
/// row lock and `edges` has no unique key on its triple, so two concurrent
/// applies could each write an edge for the same row.
pub const LOCK_NAME: &str = "epigraph-operator:backfill-evidence-edges";

/// Take [`LOCK_NAME`] on `conn`, or refuse.
async fn try_lock(conn: &mut PgConnection) -> anyhow::Result<()> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1, 0))")
        .bind(LOCK_NAME)
        .fetch_one(&mut *conn)
        .await?;
    if !locked {
        bail!(
            "refusing: another applied backfill-evidence-edges or reverse-evidence-edges holds \
             the advisory lock `{LOCK_NAME}`; nothing was written"
        );
    }
    Ok(())
}

/// Release [`LOCK_NAME`] (best effort: the session's end releases it too).
async fn unlock(conn: &mut PgConnection) {
    let _ = sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
        .bind(LOCK_NAME)
        .execute(&mut *conn)
        .await;
}


/// The run's options.
#[derive(Debug, Clone)]
pub struct Options {
    pub apply: bool,
    pub confirm_count: Option<u64>,
    pub manifest_out: Option<PathBuf>,
    pub reason: String,
    pub batch_size: usize,
    pub max_batches: Option<usize>,
    pub lock_timeout: String,
    pub statement_timeout: String,
}

/// Refuse a bad option set before any connection.
///
/// # Errors
/// `--batch-size` out of range; under `--apply`, a missing `--confirm-count`,
/// `--manifest-out` or `--reason`, or a manifest path that exists.
pub fn validate(o: &Options) -> anyhow::Result<()> {
    if o.batch_size == 0 || o.batch_size > MAX_BATCH {
        bail!("--batch-size must be 1..={MAX_BATCH}");
    }
    if o.apply {
        if o.confirm_count.is_none() {
            bail!("--apply needs --confirm-count <the dry run's to_write>");
        }
        let Some(path) = &o.manifest_out else {
            bail!("--apply needs --manifest-out <a new file>");
        };
        if path.exists() {
            bail!(
                "--manifest-out {} exists; a manifest is never overwritten, so a resumed run \
                 needs a new path",
                path.display()
            );
        }
        if o.reason.trim().is_empty() {
            bail!("--apply needs --reason <text>");
        }
    }
    Ok(())
}

/// How a row's direction was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    /// Its BBAs put more mass for the claim than against it.
    BbaFor,
    /// Its BBAs put more mass against the claim than for it.
    BbaAgainst,
    /// Its BBAs put equal mass both ways: `supports`.
    Tie,
    /// No directed BBA: `supports`.
    NoBba,
}

impl Rule {
    #[must_use]
    pub const fn direction(self) -> EvidenceDirection {
        match self {
            Self::BbaAgainst => EvidenceDirection::Refutes,
            _ => EvidenceDirection::Supports,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BbaFor => "bba_for",
            Self::BbaAgainst => "bba_against",
            Self::Tie => "bba_tie_default_supports",
            Self::NoBba => "no_bba_default_supports",
        }
    }
}

/// The mass a BBA puts for and against hypothesis `h` of an `n`-hypothesis
/// frame. `masses` is the stored JSON object: keys are comma-separated
/// hypothesis indices, `~`-prefixed for a complement, `""` for conflict.
#[must_use]
pub fn mass_for_against(masses: &Value, n: usize, h: usize) -> (f64, f64) {
    let Some(obj) = masses.as_object() else {
        return (0.0, 0.0);
    };
    let (mut for_m, mut against_m) = (0.0, 0.0);
    for (key, m) in obj {
        let Some(m) = m.as_f64() else { continue };
        if key.is_empty() || m <= 0.0 {
            continue;
        }
        let (complement, body) = key
            .strip_prefix('~')
            .map_or((false, key.as_str()), |b| (true, b));
        let Ok(listed) = body
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::parse::<usize>)
            .collect::<Result<Vec<_>, _>>()
        else {
            continue;
        };
        if listed.iter().any(|&i| i >= n) {
            continue;
        }
        let set: Vec<usize> = if complement {
            (0..n).filter(|i| !listed.contains(i)).collect()
        } else {
            listed
        };
        if set.is_empty() {
            continue;
        }
        if set == [h] {
            for_m += m;
        } else if !set.contains(&h) {
            against_m += m;
        }
    }
    (for_m, against_m)
}

/// The rule that decides a row from its BBAs' summed (for, against) mass.
#[must_use]
pub fn decide(for_m: f64, against_m: f64) -> Rule {
    const EPS: f64 = 1e-12;
    if for_m <= EPS && against_m <= EPS {
        Rule::NoBba
    } else if (for_m - against_m).abs() <= EPS {
        Rule::Tie
    } else if against_m > for_m {
        Rule::BbaAgainst
    } else {
        Rule::BbaFor
    }
}

/// One missing row, with what the census reports of it.
#[derive(Debug, Clone)]
struct Missing {
    evidence: Uuid,
    claim: Uuid,
    /// `"<visibility>/<owner group kind>"` of the evidence row and of its claim.
    evidence_tenancy: String,
    claim_tenancy: String,
    /// A derivation row or a memorize stamp: its edge does not ground the
    /// claim (`ClaimRepository::has_grounded_evidence`).
    provenance_only: bool,
}

const MISSING_PREDICATE: &str = "\
    NOT EXISTS (SELECT 1 FROM public.edges x \
                 WHERE x.source_type = 'evidence' AND x.source_id = ev.id \
                   AND x.target_type = 'claim' AND x.target_id = ev.claim_id)";

const UNSEALED_PREDICATE: &str = "\
    NOT EXISTS (SELECT 1 FROM public.claim_encryption ce WHERE ce.claim_id = ev.claim_id) \
    AND NOT EXISTS (SELECT 1 FROM public.evidence_encryption ee WHERE ee.evidence_id = ev.id)";

/// The next page of missing, unsealed rows after `after`, in id order.
async fn missing_page(
    conn: &mut PgConnection,
    after: Uuid,
    limit: usize,
) -> anyhow::Result<Vec<Missing>> {
    let sql = format!(
        "SELECT ev.id, ev.claim_id, \
                ev.visibility::text || '/' || COALESCE(ge.kind::text, 'none'), \
                c.visibility::text || '/' || COALESCE(gc.kind::text, 'none'), \
                COALESCE(ev.properties ? 'derived_from_claim' \
                         OR ev.properties->>'source' = 'mcp-memorize', false) \
           FROM public.evidence ev \
           JOIN public.claims c ON c.id = ev.claim_id \
           LEFT JOIN public.groups ge ON ge.id = ev.owner_group_id \
           LEFT JOIN public.groups gc ON gc.id = c.owner_group_id \
          WHERE ev.id > $1 AND {MISSING_PREDICATE} AND {UNSEALED_PREDICATE} \
          ORDER BY ev.id \
          LIMIT $2"
    );
    let rows = sqlx::query(&sql)
        .bind(after)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| Missing {
            evidence: r.get(0),
            claim: r.get(1),
            evidence_tenancy: r.get(2),
            claim_tenancy: r.get(3),
            provenance_only: r.get(4),
        })
        .collect())
}

/// Each evidence row's direction rule, from its non-retracted BBAs on its
/// own claim.
async fn rules_for(
    conn: &mut PgConnection,
    evidence: &[Uuid],
) -> anyhow::Result<HashMap<Uuid, Rule>> {
    let rows = sqlx::query(
        "SELECT mf.evidence_id, mf.masses, cardinality(f.hypotheses), cf.hypothesis_index \
           FROM public.mass_functions mf \
           JOIN public.evidence ev ON ev.id = mf.evidence_id AND ev.claim_id = mf.claim_id \
           JOIN public.frames f ON f.id = mf.frame_id \
           LEFT JOIN public.claim_frames cf \
                  ON cf.claim_id = mf.claim_id AND cf.frame_id = mf.frame_id \
          WHERE mf.evidence_id = ANY($1) AND mf.retracted_at IS NULL",
    )
    .bind(evidence)
    .fetch_all(&mut *conn)
    .await?;
    let mut sums: HashMap<Uuid, (f64, f64)> = HashMap::new();
    for r in rows {
        let ev: Uuid = r.get(0);
        let masses: Value = r.get(1);
        let n: i32 = r.get::<Option<i32>, _>(2).unwrap_or(0);
        let index: Option<i32> = r.get(3);
        let Ok(n) = usize::try_from(n) else { continue };
        // The claim's own hypothesis: its assignment, else TRUE (index 0) on a
        // two-hypothesis frame. Unknown on a wider frame: no vote.
        let h = match index {
            Some(i) => match usize::try_from(i) {
                Ok(i) if i < n => i,
                _ => continue,
            },
            None if n == 2 => 0,
            None => continue,
        };
        let (f, a) = mass_for_against(&masses, n, h);
        let s = sums.entry(ev).or_insert((0.0, 0.0));
        s.0 += f;
        s.1 += a;
    }
    Ok(evidence
        .iter()
        .map(|e| {
            let (f, a) = sums.get(e).copied().unwrap_or((0.0, 0.0));
            (*e, decide(f, a))
        })
        .collect())
}

/// The read-only census.
#[derive(Debug, Default, Clone)]
pub struct Census {
    pub evidence_rows: i64,
    /// Rows with at least one in-force edge to their claim, by that edge's
    /// relationship as stored (a row with two spellings counts under each).
    pub present_by_relationship: BTreeMap<String, i64>,
    /// Rows whose only edges to their claim are retracted (never re-written).
    pub retracted_only: i64,
    /// Missing rows skipped because they are sealed either way: each row
    /// once, whatever [`Self::sealed_claim`] and [`Self::sealed_evidence`]
    /// say (a row sealed both ways is in both of those).
    pub sealed_total: i64,
    /// Missing rows whose claim is sealed.
    pub sealed_claim: i64,
    /// Missing rows that are themselves sealed.
    pub sealed_evidence: i64,
    /// Missing, unsealed rows: what `--apply` writes.
    pub to_write: u64,
    /// Of [`Self::to_write`], derivation rows and memorize stamps: their
    /// edges are written but do not ground the claim.
    pub provenance_only: u64,
    pub by_relationship: BTreeMap<&'static str, u64>,
    pub by_rule: BTreeMap<&'static str, u64>,
    /// `(evidence tenancy, claim tenancy)` -> rows.
    pub by_tenancy: BTreeMap<(String, String), u64>,
}

/// The census, on a read-only snapshot.
///
/// # Errors
/// A statement fails (including `statement_timeout`).
pub async fn census(conn: &mut PgConnection, o: &Options) -> anyhow::Result<Census> {
    let mut tx = conn.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(&o.statement_timeout)
        .execute(&mut *tx)
        .await?;
    let mut c = Census {
        evidence_rows: sqlx::query_scalar("SELECT count(*) FROM public.evidence")
            .fetch_one(&mut *tx)
            .await?,
        ..Census::default()
    };
    let present = sqlx::query(
        "SELECT x.relationship::text, count(DISTINCT ev.id) \
           FROM public.evidence ev \
           JOIN public.edges x ON x.source_type = 'evidence' AND x.source_id = ev.id \
                              AND x.target_type = 'claim' AND x.target_id = ev.claim_id \
          WHERE x.valid_to IS NULL OR x.valid_to > now() \
          GROUP BY 1 ORDER BY 1",
    )
    .fetch_all(&mut *tx)
    .await?;
    for r in present {
        c.present_by_relationship.insert(r.get(0), r.get(1));
    }
    c.retracted_only = sqlx::query_scalar(
        "SELECT count(*) FROM public.evidence ev \
          WHERE EXISTS (SELECT 1 FROM public.edges x \
                         WHERE x.source_type = 'evidence' AND x.source_id = ev.id \
                           AND x.target_type = 'claim' AND x.target_id = ev.claim_id) \
            AND NOT EXISTS (SELECT 1 FROM public.edges x \
                             WHERE x.source_type = 'evidence' AND x.source_id = ev.id \
                               AND x.target_type = 'claim' AND x.target_id = ev.claim_id \
                               AND (x.valid_to IS NULL OR x.valid_to > now()))",
    )
    .fetch_one(&mut *tx)
    .await?;
    let sealed_sql = format!(
        "SELECT count(*) FILTER (WHERE NOT ({UNSEALED_PREDICATE})), \
                count(*) FILTER (WHERE EXISTS (SELECT 1 FROM public.claim_encryption ce \
                                                WHERE ce.claim_id = ev.claim_id)), \
                count(*) FILTER (WHERE EXISTS (SELECT 1 FROM public.evidence_encryption ee \
                                                WHERE ee.evidence_id = ev.id)) \
           FROM public.evidence ev WHERE {MISSING_PREDICATE}"
    );
    let (st, sc, se): (i64, i64, i64) = sqlx::query_as(&sealed_sql).fetch_one(&mut *tx).await?;
    c.sealed_total = st;
    c.sealed_claim = sc;
    c.sealed_evidence = se;

    let mut after = Uuid::nil();
    loop {
        let page = missing_page(&mut tx, after, MAX_BATCH).await?;
        let Some(last) = page.last() else { break };
        after = last.evidence;
        let ids: Vec<Uuid> = page.iter().map(|m| m.evidence).collect();
        let rules = rules_for(&mut tx, &ids).await?;
        for m in &page {
            let rule = rules.get(&m.evidence).copied().unwrap_or(Rule::NoBba);
            c.to_write += 1;
            c.provenance_only += u64::from(m.provenance_only);
            *c.by_relationship
                .entry(rule.direction().relationship())
                .or_default() += 1;
            *c.by_rule.entry(rule.label()).or_default() += 1;
            *c.by_tenancy
                .entry((m.evidence_tenancy.clone(), m.claim_tenancy.clone()))
                .or_default() += 1;
        }
    }
    tx.rollback().await?;
    Ok(c)
}

/// The census as printed lines.
#[must_use]
pub fn describe(c: &Census) -> Vec<String> {
    let mut out = vec![
        format!("evidence rows: {}", c.evidence_rows),
        "rows with an in-force edge to their claim, by relationship as stored:".to_string(),
    ];
    if c.present_by_relationship.is_empty() {
        out.push("  (none)".to_string());
    }
    for (rel, n) in &c.present_by_relationship {
        out.push(format!("  {rel}: {n}"));
    }
    out.push(format!(
        "rows whose only edges to their claim are retracted (left alone): {}",
        c.retracted_only
    ));
    out.push(format!(
        "SKIPPED, sealed: {} missing row(s) ({} on a sealed claim, {} sealed evidence; a row \
         sealed both ways is in each)",
        c.sealed_total, c.sealed_claim, c.sealed_evidence
    ));
    out.push(format!("to_write: {}", c.to_write));
    out.push(format!(
        "  of which provenance only (derivation rows, memorize stamps; the edge does not \
         ground the claim): {}",
        c.provenance_only
    ));
    out.push("  by relationship:".to_string());
    for (rel, n) in &c.by_relationship {
        out.push(format!("    {rel}: {n}"));
    }
    out.push("  by direction rule:".to_string());
    for (rule, n) in &c.by_rule {
        out.push(format!("    {rule}: {n}"));
    }
    out.push(
        "  by tenancy (evidence visibility/owner kind -> claim visibility/owner kind; the \
         edge takes their meet):"
            .to_string(),
    );
    for ((e, cl), n) in &c.by_tenancy {
        out.push(format!("    {e} -> {cl}: {n}"));
    }
    out
}

/// What an applied (or dry) run did.
#[derive(Debug, Default, Clone)]
pub struct Report {
    pub census: Census,
    pub batches_committed: usize,
    pub edges_written: u64,
    /// Written edges by stored `(relationship, visibility, owner group kind)`.
    pub written_by_tenancy: BTreeMap<(String, String, String), u64>,
    /// A batch that failed (the run stops there; earlier batches stand).
    pub batch_failure: Option<String>,
}

struct ManifestWriter {
    file: File,
    path: PathBuf,
}

impl ManifestWriter {
    fn create_new(path: &Path, header: &Value) -> anyhow::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| {
                format!(
                    "creating manifest {} (it must not exist: a manifest is never overwritten)",
                    path.display()
                )
            })?;
        let mut w = Self {
            file,
            path: path.to_path_buf(),
        };
        w.append(std::slice::from_ref(header))?;
        if let Some(dir) = path.parent() {
            let dir = if dir.as_os_str().is_empty() {
                Path::new(".")
            } else {
                dir
            };
            File::open(dir)
                .and_then(|d| d.sync_all())
                .with_context(|| format!("fsync of {}", dir.display()))?;
        }
        Ok(w)
    }

    fn append(&mut self, lines: &[Value]) -> anyhow::Result<()> {
        for v in lines {
            let mut line = serde_json::to_string(v)?;
            line.push('\n');
            self.file.write_all(line.as_bytes())?;
        }
        self.file.flush()?;
        self.file
            .sync_all()
            .with_context(|| format!("fsync of {}", self.path.display()))
    }
}

/// The census, then (under `--apply`) the batches.
///
/// Under `--apply` the whole run, census included, holds [`LOCK_NAME`], so
/// the confirmed count and the writes see no concurrent applied run.
///
/// # Errors
/// The census fails; under `--apply`, the lock is held by another run,
/// `--confirm-count` differs from the census, or the manifest cannot be
/// written. A failed BATCH is not an error: it is reported in
/// [`Report::batch_failure`] and stops the run.
pub async fn run(
    conn: &mut PgConnection,
    o: &Options,
    session_user: &str,
    out: &mut impl Write,
) -> anyhow::Result<Report> {
    if !o.apply {
        return run_locked(conn, o, session_user, out).await;
    }
    try_lock(conn).await?;
    let result = run_locked(conn, o, session_user, out).await;
    unlock(conn).await;
    result
}

async fn run_locked(
    conn: &mut PgConnection,
    o: &Options,
    session_user: &str,
    out: &mut impl Write,
) -> anyhow::Result<Report> {
    let c = census(conn, o).await?;
    for line in describe(&c) {
        writeln!(out, "{line}")?;
    }
    let mut report = Report {
        census: c.clone(),
        ..Report::default()
    };
    if !o.apply {
        writeln!(
            out,
            "DRY RUN: read-only; nothing was written. --apply --confirm-count {} \
             --manifest-out <new file> --reason <text> writes the edges above.",
            c.to_write
        )?;
        return Ok(report);
    }
    let confirm = o.confirm_count.ok_or_else(|| anyhow!("validated"))?;
    if confirm != c.to_write {
        bail!(
            "refusing --apply: --confirm-count {confirm} is not the census's to_write {}; \
             re-run the dry run and repeat its count. Nothing was written",
            c.to_write
        );
    }
    let path = o
        .manifest_out
        .as_ref()
        .ok_or_else(|| anyhow!("validated"))?;
    let mut manifest = ManifestWriter::create_new(
        path,
        &json!({
            "manifest": OPERATION,
            "version": VERSION,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "session_user": session_user,
            "reason": o.reason,
            "census_to_write": c.to_write,
        }),
    )?;

    let mut after = Uuid::nil();
    let mut audited = false;
    let mut batch = 0usize;
    loop {
        if o.max_batches.is_some_and(|m| batch >= m) {
            break;
        }
        batch += 1;
        let outcome = apply_batch(conn, o, batch, after, !audited, session_user).await;
        match outcome {
            Ok(None) => break,
            Ok(Some(b)) => {
                let PendingBatch {
                    tx,
                    lines,
                    tenancy,
                    last,
                    audited: wrote_audit,
                } = b;
                // The batch's edge lines are durable BEFORE its commit.
                manifest.append(&lines)?;
                tx.commit().await?;
                manifest.append(&[json!({ "committed_batch": batch })])?;
                audited |= wrote_audit;
                after = last;
                report.batches_committed += 1;
                report.edges_written += lines.len() as u64;
                for k in tenancy {
                    *report.written_by_tenancy.entry(k).or_default() += 1;
                }
            }
            Err(e) => {
                report.batch_failure = Some(format!("batch {batch}: {e:#}"));
                break;
            }
        }
    }
    writeln!(
        out,
        "APPLIED: {} edge(s) in {} committed batch(es); manifest {}",
        report.edges_written,
        report.batches_committed,
        path.display()
    )?;
    for ((rel, vis, kind), n) in &report.written_by_tenancy {
        writeln!(out, "  written {rel} as {vis}/{kind}: {n}")?;
    }
    if let Some(f) = &report.batch_failure {
        writeln!(
            out,
            "STOPPED on a failed batch (rolled back; earlier batches stand): {f}"
        )?;
    }
    Ok(report)
}

/// A batch written and not yet committed.
struct PendingBatch<'c> {
    tx: sqlx::Transaction<'c, sqlx::Postgres>,
    lines: Vec<Value>,
    tenancy: Vec<(String, String, String)>,
    last: Uuid,
    audited: bool,
}

async fn apply_batch<'c>(
    conn: &'c mut PgConnection,
    o: &Options,
    batch: usize,
    after: Uuid,
    audit: bool,
    session_user: &str,
) -> anyhow::Result<Option<PendingBatch<'c>>> {
    let mut tx = conn.begin().await?;
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(&o.lock_timeout)
        .execute(&mut *tx)
        .await?;
    let page = missing_page(&mut tx, after, o.batch_size).await?;
    let Some(last) = page.last().map(|m| m.evidence) else {
        tx.rollback().await?;
        return Ok(None);
    };
    let ids: Vec<Uuid> = page.iter().map(|m| m.evidence).collect();
    let rules = rules_for(&mut tx, &ids).await?;
    if audit {
        sqlx::query(
            "INSERT INTO public.security_events (event_type, agent_id, success, details) \
             VALUES ($1, NULL, true, $2)",
        )
        .bind(EVENT_APPLY)
        .bind(json!({
            "reason": o.reason,
            "session_user": session_user,
            "confirm_count": o.confirm_count,
            "manifest": o.manifest_out.as_ref().map(|p| p.display().to_string()),
        }))
        .execute(&mut *tx)
        .await?;
    }
    let mut lines = Vec::with_capacity(page.len());
    let mut created = Vec::with_capacity(page.len());
    for m in &page {
        let rule = rules.get(&m.evidence).copied().unwrap_or(Rule::NoBba);
        let direction = rule.direction();
        let links = EvidenceRepository::link_to_claims_signed_conn(
            &mut tx,
            None,
            m.evidence,
            &[m.claim],
            direction,
        )
        .await
        .with_context(|| format!("evidence {} -> claim {}", m.evidence, m.claim))?;
        for l in links.into_iter().filter(|l| l.created) {
            created.push(l.edge_id);
            lines.push(json!({
                "batch": batch,
                "edge_id": l.edge_id,
                "evidence_id": m.evidence,
                "claim_id": l.claim_id,
                "relationship": direction.relationship(),
                "rule": rule.label(),
            }));
        }
    }
    let tenancy: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT x.relationship::text, x.visibility::text, COALESCE(g.kind::text, 'none') \
           FROM public.edges x LEFT JOIN public.groups g ON g.id = x.owner_group_id \
          WHERE x.id = ANY($1)",
    )
    .bind(&created)
    .fetch_all(&mut *tx)
    .await?;
    Ok(Some(PendingBatch {
        tx,
        lines,
        tenancy,
        last,
        audited: audit,
    }))
}

/// One manifest edge line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EdgeLine {
    edge: Uuid,
    evidence: Uuid,
    claim: Uuid,
    relationship: String,
}

fn read_manifest(path: &Path) -> anyhow::Result<Vec<EdgeLine>> {
    let file = File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut lines = BufReader::new(file).lines();
    let header: Value = serde_json::from_str(
        &lines
            .next()
            .ok_or_else(|| anyhow!("{} is empty", path.display()))??,
    )?;
    if header.get("manifest").and_then(Value::as_str) != Some(OPERATION) {
        bail!(
            "{} is not a {OPERATION} manifest; nothing was done",
            path.display()
        );
    }
    if header.get("version").and_then(Value::as_i64) != Some(VERSION) {
        bail!(
            "{} is not a version {VERSION} manifest; nothing was done",
            path.display()
        );
    }
    let mut out = Vec::new();
    for line in lines {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(&line)?;
        if v.get("committed_batch").is_some() {
            continue;
        }
        let id = |k: &str| -> anyhow::Result<Uuid> {
            v.get(k)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("manifest line without {k}: {line}"))?
                .parse()
                .with_context(|| format!("{k} in {line}"))
        };
        out.push(EdgeLine {
            edge: id("edge_id")?,
            evidence: id("evidence_id")?,
            claim: id("claim_id")?,
            relationship: v
                .get("relationship")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("manifest line without relationship: {line}"))?
                .to_string(),
        });
    }
    Ok(out)
}

/// What a reversal did.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReverseReport {
    pub recorded: u64,
    pub deleted: u64,
    /// Recorded edges already gone, or no longer between the recorded
    /// endpoints with the recorded relationship: left alone.
    pub not_matched: u64,
}

/// Delete exactly the edges a run's manifest names (see the module doc).
///
/// An applied reversal holds [`LOCK_NAME`] for its whole run.
///
/// # Errors
/// The manifest cannot be read or is not this operation's; the lock is held
/// by another run; a statement fails.
pub async fn reverse(
    conn: &mut PgConnection,
    manifest: &Path,
    apply: bool,
    lock_timeout: &str,
    session_user: &str,
    out: &mut impl Write,
) -> anyhow::Result<ReverseReport> {
    if !apply {
        return reverse_locked(conn, manifest, apply, lock_timeout, session_user, out).await;
    }
    try_lock(conn).await?;
    let result = reverse_locked(conn, manifest, apply, lock_timeout, session_user, out).await;
    unlock(conn).await;
    result
}

async fn reverse_locked(
    conn: &mut PgConnection,
    manifest: &Path,
    apply: bool,
    lock_timeout: &str,
    session_user: &str,
    out: &mut impl Write,
) -> anyhow::Result<ReverseReport> {
    let lines = read_manifest(manifest)?;
    let mut r = ReverseReport {
        recorded: lines.len() as u64,
        ..ReverseReport::default()
    };
    let mut audited = false;
    for chunk in lines.chunks(1000) {
        let mut tx = conn.begin().await?;
        sqlx::query("SELECT set_config('lock_timeout', $1, true)")
            .bind(lock_timeout)
            .execute(&mut *tx)
            .await?;
        let ids: Vec<Uuid> = chunk.iter().map(|l| l.edge).collect();
        let src: Vec<Uuid> = chunk.iter().map(|l| l.evidence).collect();
        let tgt: Vec<Uuid> = chunk.iter().map(|l| l.claim).collect();
        let rel: Vec<String> = chunk.iter().map(|l| l.relationship.clone()).collect();
        let deleted = sqlx::query(
            "DELETE FROM public.edges e \
              USING unnest($1::uuid[], $2::uuid[], $3::uuid[], $4::text[]) AS m(id, src, tgt, rel) \
              WHERE e.id = m.id \
                AND e.source_type = 'evidence' AND e.source_id = m.src \
                AND e.target_type = 'claim' AND e.target_id = m.tgt \
                AND e.relationship = m.rel",
        )
        .bind(&ids)
        .bind(&src)
        .bind(&tgt)
        .bind(&rel)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        r.deleted += deleted;
        r.not_matched += chunk.len() as u64 - deleted;
        if apply {
            if !audited && deleted > 0 {
                sqlx::query(
                    "INSERT INTO public.security_events (event_type, agent_id, success, details) \
                     VALUES ($1, NULL, true, $2)",
                )
                .bind(EVENT_REVERSE)
                .bind(json!({
                    "manifest": manifest.display().to_string(),
                    "session_user": session_user,
                }))
                .execute(&mut *tx)
                .await?;
                audited = true;
            }
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
    }
    writeln!(
        out,
        "{}: {} recorded edge(s); {} deleted; {} already gone or changed (left alone)",
        if apply {
            "REVERSED"
        } else {
            "DRY RUN (rolled back)"
        },
        r.recorded,
        r.deleted,
        r.not_matched
    )?;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_supports_and_refutes_masses_decide_the_direction() {
        // ds_auto's binary BBA: m({0}) for supports, m({1}) against, rest on Θ.
        let supports = json!({"0": 0.7, "0,1": 0.3});
        let refutes = json!({"1": 0.7, "0,1": 0.3});
        assert_eq!(
            decide_from(&supports, 2, 0),
            Rule::BbaFor,
            "mass on the claim's hypothesis"
        );
        assert_eq!(decide_from(&refutes, 2, 0), Rule::BbaAgainst);
        // The complement spelling of the same sets.
        assert_eq!(decide_from(&json!({"~1": 0.6}), 2, 0), Rule::BbaFor);
        assert_eq!(decide_from(&json!({"~0": 0.6}), 2, 0), Rule::BbaAgainst);
        // Only Θ, or only conflict: no direction.
        assert_eq!(decide_from(&json!({"0,1": 1.0}), 2, 0), Rule::NoBba);
        assert_eq!(decide_from(&json!({"": 1.0}), 2, 0), Rule::NoBba);
        assert_eq!(
            decide_from(&json!({"0": 0.4, "1": 0.4, "0,1": 0.2}), 2, 0),
            Rule::Tie
        );
        // The claim's hypothesis is index 2 of a three-hypothesis frame: mass
        // on {0,1} argues against it, mass on {2} for it.
        assert_eq!(
            decide_from(&json!({"0,1": 0.5, "2": 0.2}), 3, 2),
            Rule::BbaAgainst
        );
        // An out-of-range index is ignored, not guessed.
        assert_eq!(decide_from(&json!({"5": 0.9}), 2, 0), Rule::NoBba);
        assert_eq!(Rule::BbaAgainst.direction().relationship(), "refutes");
        assert_eq!(Rule::NoBba.direction().relationship(), "supports");
    }

    fn decide_from(m: &Value, n: usize, h: usize) -> Rule {
        let (f, a) = mass_for_against(m, n, h);
        decide(f, a)
    }

    #[test]
    fn apply_needs_its_count_manifest_and_reason() {
        let base = Options {
            apply: true,
            confirm_count: Some(1),
            manifest_out: Some(PathBuf::from("/nonexistent-dir-for-test/m.jsonl")),
            reason: "r".into(),
            batch_size: 10,
            max_batches: None,
            lock_timeout: "5s".into(),
            statement_timeout: "10min".into(),
        };
        assert!(validate(&base).is_ok());
        for broken in [
            Options {
                confirm_count: None,
                ..base.clone()
            },
            Options {
                manifest_out: None,
                ..base.clone()
            },
            Options {
                reason: " ".into(),
                ..base.clone()
            },
            Options {
                batch_size: 0,
                ..base.clone()
            },
        ] {
            assert!(validate(&broken).is_err(), "{broken:?}");
        }
        assert!(validate(&Options {
            apply: false,
            confirm_count: None,
            manifest_out: None,
            reason: String::new(),
            ..base
        })
        .is_ok());
    }
}
