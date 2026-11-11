//! `backfill-ingest-markers`: stamp the document ingest's marker onto the
//! ingest-shaped edges written before the marker existed, so every provenance
//! reader (the agent card's counts, `query_paper`, a claim's `authored_by`
//! and `ingesters`, the walk's own dedup probe) reads each legacy paper as ONE
//! ingest; and `reverse-ingest-markers`, its exact reversal from the run's
//! manifest.
//!
//! # What is stamped
//!
//! Every LEGACY edge (no `properties.ingest_written`, written before the
//! run's `--written-before` cutoff) not stamped yet, in force or retracted,
//! of these shapes:
//!
//! * `agent -authored-> paper` (a document's authors);
//! * `paper -asserts-> claim` (the claims a document states);
//! * `agent -asserts-> claim` only where it closes a legacy CHAIN: the same
//!   agent has a legacy `authored` edge onto a paper whose legacy `asserts`
//!   edge points at the same claim. The agent card credits a claim to an
//!   author only through that chain (authored, paper asserts, agent asserts,
//!   all marked by one principal), so the third edge is needed; an agent
//!   `asserts` edge with no such paper is some other writer's and stays
//!   unmarked. The workflow executor's attributions
//!   (`properties.source = 'workflow_attribution'`) are never stamped.
//!
//! Both legs of a chain must be legacy too (before the cutoff): an agent's
//! own post-deploy `asserts` edge, or one closing a chain through a
//! post-deploy edge, is never stamped. The cutoff is the moment the marked
//! writers took over (the maintenance window's start, with ingest stopped);
//! `--apply` requires it, and records it in the manifest and the audit row.
//!
//! # Who `by` names: one principal per PAPER
//!
//! A paper's principal is decided from its legacy `authored` and paper
//! `asserts` edges (whatever their labels, so it never moves while a run
//! stamps them): when every one of them signed by a classified
//! `--ingest-signer` names ONE signer, the paper's principal is that signer;
//! otherwise (no real signer, or two or more) it is the one registered
//! `legacy-ingest` system principal. Every stamped edge of the paper takes
//! it: the unsigned and attestation-signed ones too, so a paper never reads
//! as two ingests. An `agent -asserts-> claim` edge takes the principal of
//! the paper whose chain it closes, never its own signer's; when it closes
//! chains through papers of different principals, it takes the principal of
//! its oldest IN-FORCE chain (authorship and paper assertion both in force;
//! the agent card credits only through those), else of its oldest chain
//! (the oldest paper assertion), and the dry run counts those. So only the
//! signers of `authored` and paper `asserts` edges are classified
//! (`--ingest-signer` / `--attestation-signer`; `--apply` refuses while any
//! is in neither list); an `agent -asserts-> claim` signer is reported for
//! information only.
//!
//! # Where the marker goes: labels, not `properties`
//!
//! The edge attestation (a signed edge's `content_hash` / `signature`) covers
//! `properties`, so adding the marker there would make every signed legacy
//! edge read "changed since it was signed". It does not cover `labels`. So a
//! backfilled edge gets two reserved labels, `epigraph:ingest_written` and
//! `epigraph:ingest_written_by:<by>` (migration 208), which every reader's
//! marker predicate reads beside the property. Migration 208's guard refuses
//! any `epigraph:` label to a transaction that has not declared
//! `epigraph.ingest_written_edge`; this tool declares it inside each batch
//! only, around its one UPDATE, and clears it again.
//!
//! # Ingest records
//!
//! `get_claim`'s `ingesters` read `paper -ingested_claim-> claim` records,
//! `query_paper` the stamped assertions themselves; the two must agree. So
//! every paper assertion a run stamps gets a record of its principal (unless
//! that principal already has one), written in the SAME transaction as the
//! stamp: a committed batch always carries its records, and there is no
//! separate record phase a stopped run could miss.
//!
//! * a CREATION record (`created_claim: true`) only where the paper's ingest
//!   PROVABLY created the claim, from the data:
//!   * the paper's `asserts` edge onto it is legacy, in force, and signed by
//!     a classified ingest signer S, and S is the PAPER's principal (never
//!     `legacy-ingest`: the reader requires the record's ingester to be the
//!     claim's filer);
//!   * S filed the claim (`claims.agent_id = S`);
//!   * the claim's OWN reasoning trace (`claims.trace_id`, on that claim) is
//!     the document ingest's extraction trace of THIS paper ("Extracted from
//!     ... (DOI: <the paper's doi>)"), written within [`CREATION_WINDOW`] of
//!     the claim itself: the walk hangs that trace only on a claim it
//!     creates, in the same transaction;
//!   * the claim carries no workflow stamp (`step_lineage_id`), has no
//!     creation record yet, and the paper has a legacy in-force authorship
//!     signed by S.
//!
//!   When two provable assertions target one claim, the first batch to
//!   stamp one (batches run in edge-id order) writes its creation record; in
//!   one batch, the older assertion's.
//!
//!   Its authors (the claim's primary authors) are the paper's in-force
//!   authorships stamped with S, in position order: the authors
//!   `query_paper(ingested_by = S)` lists.
//! * a NON-CREATION record (`created_claim: false`) for every other stamped
//!   assertion, naming the edge's principal (`legacy-ingest` or a signer).
//!
//! The residue the creation proof cannot exclude: S filed the claim itself
//! (no trace), and an early walk of S's own document converged on it within
//! the window and hung its trace on it. Both acts are S's own.
//!
//! # Run shape (as `restrict-claims`)
//!
//! Maintenance DSN only. A dry run is READ-ONLY: it prints the census (no
//! UPDATE, no WAL). `--apply` needs `--written-before`, `--confirm-count`
//! (the dry run's edge total under the same cutoff), `--ruling`, `--reason`
//! and `--manifest-out`; it refuses unless migration 208's guard is installed
//! and `legacy-ingest` is registered. Batches of `--batch-size` edges, each
//! in its own transaction under `lock_timeout`, the kinds in order, each to
//! exhaustion (every authorship is stamped before any paper assertion); a
//! paper-assertion batch writes its stamps' ingest records in that same
//! transaction. The manifest records each batch's edge lines (tagged with the
//! batch number) and is `fsync`ed BEFORE that batch's UPDATE, then its record
//! lines (same batch number) BEFORE its COMMIT, then gets a `committed_batch`
//! line AFTER its commit. One `security_events` row per run, written in the
//! first batch that changes anything.
//!
//! So every batch a run committed carries its records however the run stops
//! after it: `--max-batches`, a failed batch, or the process killed, crashed
//! or disconnected with no summary printed. After any of those, and after
//! reversing the runs' manifests newest first (the reversal refuses an older
//! one while a newer run's stamp rests on its records, see Reversal),
//! `query_paper` and `get_claim`'s `ingesters` agree, and the backfill is
//! resumed as it stands: a fresh dry
//! run's total, a NEW manifest, the same `--written-before` and the same
//! `--ingest-signer` / `--attestation-signer` lists as the first run (they
//! decide every paper's principal). Every step of a batch (BEGIN, the locked
//! candidate SELECT, where `lock_timeout` fires against a concurrent writer,
//! the manifest writes, the UPDATE, an ingest record, COMMIT) fails into
//! `BATCH-FAILED` (exit 2), which rolls that batch back whole and stops the run
//! without leaving it, so the summary still prints. A run with a
//! `BATCH-FAILED` ends with `NEXT` lines: resume (or undo with the reversal),
//! and for a lock timeout, stop the concurrent writer or raise
//! `--lock-timeout`. A batch that committed but whose `committed_batch` line
//! failed to write gets a `NEXT first:` line naming the line to append to the
//! manifest before anything else. A run that died between a COMMIT and its
//! line (no summary) leaves that batch's lines uncommitted in the manifest;
//! the reversal reports it as `UNCOMMITTED-BATCH`, and its edges are checked
//! by hand (the stamps and records of that batch are all there or none are).
//! If one of that batch's stamps rests on a record of an earlier batch of
//! the run, the reversal refuses until the line is appended (see Reversal).
//!
//! # Reversal
//!
//! `reverse-ingest-markers --manifest <file>`: acts only on the batches the
//! manifest records as COMMITTED (a batch whose lines were written but whose
//! commit failed is reported, never reversed). Each committed batch is
//! reversed in ONE transaction, newest first: it deletes each record the
//! batch wrote while it is still the run's and removes exactly the two labels
//! each of its edges was given, only while it still carries them (a
//! compare-and-swap). A reversal stopped anywhere therefore leaves no stamp
//! without its record, and re-running it finishes the rest. One audit row.
//!
//! The record writer keeps one record per paper, claim and principal, so
//! when two legacy copies of one `paper -asserts-> claim` pair are stamped by
//! different runs (a paced or resumed backfill), the later run writes no
//! record and its stamp rests on the earlier run's. So before any write,
//! dry run or `--apply`, the reversal refuses (nothing written) while any
//! stamped paper assertion OUTSIDE its manifest's COMMITTED batches matches
//! (paper, claim, `by`) a record those batches wrote, naming those edges. An
//! edge listed only in an uncommitted batch counts as outside: a batch's
//! lines are written before its UPDATE, so a rolled-back batch lists edges a
//! newer run may since have stamped. For an edge not in the manifest at all
//! the refusal says to reverse the newer manifest first. For one in an
//! uncommitted batch it names the batch and both remedies, since the
//! manifest cannot tell them apart: reverse the newer manifest first if one
//! lists it; if none does, that batch committed before its line was written,
//! so check its edges are all stamped and append its `committed_batch` line.
//!
//! A version 2 manifest (written before a batch's records shared its
//! stamps' transaction) is still reversed, with a `LEGACY-MANIFEST` line: its
//! records are in their own batches, so a reversal of it stopped part way may
//! leave stamps without their records until it is re-run to finish.

use anyhow::{anyhow, bail, Context};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Acquire, PgConnection};
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use epigraph_db::ingest_written::{
    INGEST_WRITTEN_BY_LABEL_PREFIX, INGEST_WRITTEN_LABEL, INGEST_WRITTEN_PROPERTY,
    INGEST_WRITTEN_SETTING,
};
use epigraph_db::{ingest_written_by_sql, INGESTED_BY_PROPERTY, INGEST_RECORD_RELATIONSHIP};

/// The manifest header's `operation`.
pub const OPERATION: &str = "backfill-ingest-markers";
/// `security_events.event_type` of an applied run.
pub const EVENT_APPLY: &str = "ingest_marker.backfill";
/// `security_events.event_type` of an applied reversal.
pub const EVENT_REVERSE: &str = "ingest_marker.backfill_reverse";
/// The `tool` / `pipeline` of the ingest records this writes.
pub const TOOL: &str = "backfill-ingest-markers";
pub const PIPELINE: &str = "legacy-backfill";
/// How long after a claim its extraction trace may be written and still
/// prove the claim was created by that extraction (the walk writes both in
/// one transaction; a document's planning and persistence fit well inside).
pub const CREATION_WINDOW: &str = "10 minutes";
/// The manifest format version: every line carries its batch, each
/// committed batch has a `committed_batch` line, and a batch's record lines
/// carry its stamps' batch number (one transaction).
pub const VERSION: i64 = 3;
/// The older format the reversal still reads: its record lines were written
/// in record-only batches numbered after every edge batch, so reversing it
/// is not batch-atomic (it deletes the records before it removes the stamps).
pub const LEGACY_VERSION: i64 = 2;
/// Most conflicting papers the dry run lists by id.
pub const CONFLICTS_LISTED: i64 = 20;

/// Parse `--written-before` (RFC 3339, e.g. `2026-11-10T06:00:00Z`).
///
/// # Errors
/// Not an RFC 3339 timestamp with an offset.
pub fn parse_written_before(s: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| format!("--written-before must be RFC 3339 with an offset: {e}"))
}

/// The cutoff as it is printed, recorded and compared (microseconds, UTC).
#[must_use]
pub fn cutoff_text(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// The three stamped shapes, in the order a run stamps them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Authored,
    PaperAsserts,
    AgentAsserts,
}

fn authored(x: &str) -> String {
    format!(
        "{x}.source_type = 'agent' AND {x}.relationship = 'authored' \
         AND {x}.target_type = 'paper'"
    )
}

/// `x` is an `agent -asserts-> claim` edge other than a workflow
/// executor's attribution (never stamped).
fn agent_asserts(x: &str) -> String {
    format!(
        "{x}.source_type = 'agent' AND {x}.relationship = 'asserts' \
         AND {x}.target_type = 'claim' \
         AND COALESCE({x}.properties ->> 'source', '') <> 'workflow_attribution'"
    )
}

fn paper_asserts(x: &str) -> String {
    format!(
        "{x}.source_type = 'paper' AND {x}.relationship = 'asserts' \
         AND {x}.target_type = 'claim'"
    )
}

/// The SQL fragments of one run: everything depends on its cutoff.
#[derive(Clone, Debug)]
pub struct Frame {
    /// A `timestamptz` literal (from a parsed timestamp, or `infinity`).
    cut: String,
}

impl Frame {
    #[must_use]
    pub fn new(written_before: Option<&DateTime<Utc>>) -> Self {
        Self {
            cut: written_before.map_or_else(
                || "'infinity'::timestamptz".to_string(),
                |t| format!("'{}'::timestamptz", cutoff_text(t)),
            ),
        }
    }

    /// Edge `x` is LEGACY: no marker property (labels may be the backfill's
    /// own), written before the cutoff.
    fn legacy(&self, x: &str) -> String {
        format!(
            "NOT ({x}.properties ? '{INGEST_WRITTEN_PROPERTY}') AND {x}.created_at < {}",
            self.cut
        )
    }

    /// `FROM ... WHERE ...` of the legacy chains (`ea` the agent's
    /// authorship, `pa` the paper's assertion) agent asserts edge `e` closes.
    fn chain_from(&self, e: &str) -> String {
        format!(
            "FROM edges ea JOIN edges pa ON pa.source_id = ea.target_id \
              WHERE ea.source_id = {e}.source_id AND {au} AND {lea} \
                AND {pas} AND {lpa} AND pa.target_id = {e}.target_id",
            au = authored("ea"),
            lea = self.legacy("ea"),
            pas = paper_asserts("pa"),
            lpa = self.legacy("pa"),
        )
    }

    /// SQL: edge `e` is a candidate of `kind` (legacy, not yet stamped; any
    /// state).
    #[must_use]
    pub fn candidate(&self, kind: Kind, e: &str) -> String {
        let shape = match kind {
            Kind::Authored => authored(e),
            Kind::PaperAsserts => paper_asserts(e),
            Kind::AgentAsserts => format!(
                "{} AND EXISTS (SELECT 1 {})",
                agent_asserts(e),
                self.chain_from(e)
            ),
        };
        format!(
            "({shape} AND {} \
              AND NOT ({e}.labels @> ARRAY['{INGEST_WRITTEN_LABEL}']::text[]))",
            self.legacy(e)
        )
    }

    /// SQL: edge `e` is an `agent -asserts-> claim` candidate WITHOUT the
    /// chain test: joined to the chains it closes (`ea`, `pa` as in
    /// [`Self::chain_from`]), each joined row is a chain, so the join itself
    /// is the test and the [`Self::candidate`] EXISTS would only repeat it.
    fn agent_asserts_unchained(&self, e: &str) -> String {
        format!(
            "({} AND {} \
              AND NOT ({e}.labels @> ARRAY['{INGEST_WRITTEN_LABEL}']::text[]))",
            agent_asserts(e),
            self.legacy(e)
        )
    }

    /// SQL: the paper whose principal edge `e` of `kind` takes: its own
    /// paper, or (an agent assertion) the paper of its chosen chain
    /// ([`CHAIN_ORDER`]: oldest in-force, else oldest).
    fn paper_of(&self, kind: Kind, e: &str) -> String {
        match kind {
            Kind::Authored => format!("{e}.target_id"),
            Kind::PaperAsserts => format!("{e}.source_id"),
            Kind::AgentAsserts => format!(
                "(SELECT ea.target_id {} ORDER BY {CHAIN_ORDER} LIMIT 1)",
                self.chain_from(e)
            ),
        }
    }

    /// CTE `pp(paper, n, sids)`: per paper, its distinct classified ingest
    /// signers (`ing`, a `uuid[]` placeholder) over its legacy `authored`
    /// and paper `asserts` edges; only papers with at least one. `within`,
    /// when given, is a set expression restricting the papers.
    fn pp_cte(&self, ing: &str, within: Option<&str>) -> String {
        let (r1, r2) = within.map_or_else(
            || (String::new(), String::new()),
            |w| {
                (
                    format!("AND s.source_id IN {w}"),
                    format!("AND s.target_id IN {w}"),
                )
            },
        );
        format!(
            "pp AS (SELECT x.paper, count(DISTINCT x.sid) AS n, \
                           array_agg(DISTINCT x.sid ORDER BY x.sid) AS sids \
                      FROM (SELECT s.source_id AS paper, s.signer_id AS sid FROM edges s \
                             WHERE {pas} AND {ls} AND s.signer_id = ANY({ing}) {r1} \
                            UNION ALL \
                            SELECT s.target_id, s.signer_id FROM edges s \
                             WHERE {au} AND {ls} AND s.signer_id = ANY({ing}) {r2}) x \
                     GROUP BY x.paper)",
            pas = paper_asserts("s"),
            au = authored("s"),
            ls = self.legacy("s"),
        )
    }
}

impl Frame {
    /// The classified-signer rows of [`Self::pp_cte`] as a row stream for a
    /// per-paper window: `SELECT <nulls> paper, sid` over the legacy paper
    /// `asserts` and `authored` edges signed by one of `ing` (a `uuid[]`
    /// placeholder), `sid` as text. `nulls` is the NULL padding of the
    /// stream's leading columns; `within`, when given, restricts the papers.
    fn signer_rows(&self, ing: &str, nulls: &str, within: Option<&str>) -> String {
        let (r1, r2) = within.map_or_else(
            || (String::new(), String::new()),
            |w| {
                (
                    format!("AND s.source_id IN {w}"),
                    format!("AND s.target_id IN {w}"),
                )
            },
        );
        format!(
            "SELECT {nulls} s.source_id, s.signer_id::text FROM edges s \
              WHERE {pas} AND {ls} AND s.signer_id = ANY({ing}) {r1} \
             UNION ALL \
             SELECT {nulls} s.target_id, s.signer_id::text FROM edges s \
              WHERE {au} AND {ls} AND s.signer_id = ANY({ing}) {r2}",
            pas = paper_asserts("s"),
            au = authored("s"),
            ls = self.legacy("s"),
        )
    }
}

/// SQL: the principal of the paper of a row of stream `x` (columns `paper`
/// and `sid`, the classified-signer rows [`Frame::signer_rows`] among
/// them), over `WINDOW w AS (PARTITION BY x.paper)`: the paper's signer rows
/// name one signer exactly when their least and greatest agree (as `pp.n =
/// 1`, `pp.sids[1]`); else, or with none, `l` (the legacy principal). The
/// same value as [`principal`] over the paper's `pp` row, with no join to
/// `pp`: a join the planner sizes at one row is planned as a nested loop
/// that re-runs `pp`'s aggregate for every row.
fn principal_window(x: &str, l: &str) -> String {
    format!(
        "COALESCE(CASE WHEN min({x}.sid) OVER w = max({x}.sid) OVER w \
                       THEN (min({x}.sid) OVER w)::uuid END, {l})"
    )
}

/// The order that picks an agent assertion's chain: its IN-FORCE chains
/// (authorship and paper assertion both in force) first, then the oldest
/// paper assertion. The agent card credits a claim only through in-force
/// legs, so a retracted chain must not name the principal while a live one
/// exists.
const CHAIN_ORDER: &str = "((ea.valid_to IS NULL OR ea.valid_to > now()) \
                            AND (pa.valid_to IS NULL OR pa.valid_to > now())) DESC, \
                           pa.created_at, pa.id, ea.created_at, ea.id";

/// SQL: the principal from a `pp` row aliased `pp` (LEFT JOINed; NULL when
/// the paper has no classified ingest signer), `l` the legacy principal.
fn principal(pp: &str, l: &str) -> String {
    format!("COALESCE(CASE WHEN {pp}.n = 1 THEN {pp}.sids[1] END, {l})")
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Authored, Kind::PaperAsserts, Kind::AgentAsserts];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Authored => "agent-authored-paper",
            Kind::PaperAsserts => "paper-asserts-claim",
            Kind::AgentAsserts => "agent-asserts-claim",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// Everything the verb was told.
#[derive(Clone, Debug)]
pub struct Options {
    pub apply: bool,
    pub confirm_count: Option<u64>,
    pub written_before: Option<DateTime<Utc>>,
    pub ruling: String,
    pub reason: String,
    pub manifest_out: Option<PathBuf>,
    pub attestation_signers: Vec<Uuid>,
    pub ingest_signers: Vec<Uuid>,
    pub batch_size: usize,
    pub max_batches: Option<usize>,
    pub lock_timeout: String,
    pub statement_timeout: String,
    pub creation_records: bool,
}

impl Options {
    #[must_use]
    pub fn frame(&self) -> Frame {
        Frame::new(self.written_before.as_ref())
    }
}

/// Refuse options that cannot describe a valid run, before any connection.
///
/// # Errors
/// As described per field.
pub fn validate(o: &Options) -> anyhow::Result<()> {
    if o.batch_size == 0 {
        bail!("--batch-size must be at least 1");
    }
    if let Some(dup) = o
        .attestation_signers
        .iter()
        .find(|a| o.ingest_signers.contains(a))
    {
        bail!("{dup} is listed both as --attestation-signer and --ingest-signer");
    }
    if o.apply {
        if o.written_before.is_none() {
            bail!(
                "--apply needs --written-before <timestamptz>: the moment the marked writers \
                 took over (the maintenance window's start). Only edges written before it are \
                 stamped; it is recorded in the manifest and the audit row"
            );
        }
        if o.ruling.trim().is_empty() || o.reason.trim().is_empty() {
            bail!(
                "--apply needs --ruling and --reason (recorded in the manifest and the audit row)"
            );
        }
        if o.confirm_count.is_none() {
            bail!("--apply needs --confirm-count <N>: the dry run's edge total, repeated back");
        }
        if o.manifest_out.is_none() {
            bail!("--apply needs --manifest-out <file> (it must not exist)");
        }
    }
    Ok(())
}

/// One distinct signer of the candidate edges.
#[derive(Clone, Debug)]
pub struct Signer {
    pub id: Uuid,
    pub display_name: Option<String>,
    pub agent_type: Option<String>,
    pub key_kind: Option<String>,
    pub system_role: Option<String>,
    /// Its candidate edges per kind.
    pub authored: i64,
    pub paper_asserts: i64,
    pub agent_asserts: i64,
    /// Of its candidate `paper -asserts-> claim` edges, how many target a
    /// claim this same signer filed. A server key that signed for many
    /// ingesting callers files few of the claims it signed assertions of; an
    /// agent that ingested as itself files most of them. Evidence for the
    /// operator's classification, nothing more.
    pub paper_asserts_self_filed: i64,
}

impl Signer {
    /// It signs a candidate whose principal it can decide (an `authored` or
    /// paper `asserts` edge), so it must be classified.
    #[must_use]
    pub fn needs_class(&self) -> bool {
        self.authored > 0 || self.paper_asserts > 0
    }
}

/// What the database holds before a run.
#[derive(Clone, Debug, Default)]
pub struct Census {
    /// Migration 208's guard body is installed (labels are guarded).
    pub guard_installed: bool,
    /// The registered `legacy-ingest` principal, if any.
    pub legacy_principal: Option<Uuid>,
    /// Edges already carrying a reserved `epigraph:` label.
    pub reserved_labels_present: i64,
    /// Per kind: (candidates, in force, unsigned, attestation, ingest-signed,
    /// other signer).
    pub per_kind: BTreeMap<Kind, [i64; 6]>,
    pub signers: Vec<Signer>,
    /// Papers with a candidate `authored` or paper `asserts` edge, by the
    /// principal they take.
    pub papers: i64,
    pub papers_by_signer: Vec<(Uuid, i64)>,
    pub papers_no_real_signer: i64,
    pub papers_conflicting: i64,
    /// Up to [`CONFLICTS_LISTED`] conflicting papers with their signers.
    pub conflicts: Vec<(Uuid, Vec<Uuid>)>,
    /// Every (agent assertion, its authorship, the paper's assertion) chain
    /// a candidate agent assertion closes, each pair counted.
    pub chains: i64,
    /// Chains through a paper whose principal is not the one the agent
    /// assertion takes (it closes another, older chain of another principal).
    pub chains_on_another_principal: i64,
    /// Candidate agent assertions closing chains of two or more principals.
    pub agent_asserts_multi_principal: i64,
    /// Claims whose creation record is provable (module doc).
    pub provable_records: i64,
    /// Non-creation records the run would write.
    pub planned_non_creation: i64,
}

impl Census {
    /// The edges a run stamps.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.per_kind
            .values()
            .map(|v| u64::try_from(v[0]).unwrap_or(0))
            .sum()
    }

    /// Signers of `authored` / paper `asserts` candidates in neither list.
    #[must_use]
    pub fn unclassified(&self, o: &Options) -> Vec<Uuid> {
        self.signers
            .iter()
            .filter(|s| s.needs_class())
            .map(|s| s.id)
            .filter(|id| !o.attestation_signers.contains(id) && !o.ingest_signers.contains(id))
            .collect()
    }
}

async fn guard_installed(conn: &mut PgConnection) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT COALESCE((SELECT p.prosrc LIKE '%IWE02%' FROM pg_catalog.pg_proc p \
                           WHERE p.oid = to_regprocedure( \
                               'public.epigraph_edges_ingest_written_guard()')), false)",
    )
    .fetch_one(&mut *conn)
    .await?)
}

async fn legacy_principal(conn: &mut PgConnection) -> anyhow::Result<Option<Uuid>> {
    let present: bool =
        sqlx::query_scalar("SELECT to_regclass('public.system_agents') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?;
    if !present {
        return Ok(None);
    }
    Ok(sqlx::query_scalar(
        "SELECT s.agent_id FROM public.system_agents s WHERE s.role = 'legacy-ingest'",
    )
    .fetch_optional(&mut *conn)
    .await?)
}

/// SQL: the provable creation records (module doc), over `pa` (a legacy
/// paper assertion), `c`, `p`, `t` and the `pp` CTE LEFT JOINed on the
/// paper. `$1` = ingest signers.
fn provable_sql(f: &Frame) -> String {
    format!(
        "{pas} AND {lpa} \
         AND (pa.valid_to IS NULL OR pa.valid_to > now()) \
         AND pa.signer_id = ANY($1::uuid[]) \
         AND pp.n = 1 AND pp.sids[1] = pa.signer_id \
         AND c.agent_id = pa.signer_id \
         AND c.step_lineage_id IS NULL \
         AND t.claim_id = c.id \
         AND t.explanation LIKE 'Extracted from %' \
         AND strpos(t.explanation, '(DOI: ' || p.doi || ')') > 0 \
         AND t.created_at >= c.created_at \
         AND t.created_at <= c.created_at + interval '{CREATION_WINDOW}' \
         AND NOT EXISTS (SELECT 1 FROM edges r \
                          WHERE r.target_id = c.id AND r.target_type = 'claim' \
                            AND r.relationship = '{INGEST_RECORD_RELATIONSHIP}' \
                            AND (r.properties ->> 'created_claim') = 'true') \
         AND EXISTS (SELECT 1 FROM edges ea \
                      WHERE ea.target_id = pa.source_id AND {au} AND {lea} \
                        AND ea.signer_id = pa.signer_id \
                        AND (ea.valid_to IS NULL OR ea.valid_to > now()))",
        pas = paper_asserts("pa"),
        lpa = f.legacy("pa"),
        au = authored("ea"),
        lea = f.legacy("ea"),
    )
}

/// [`provable_sql`] as a query over `pa`, further restricted by `scope` (a
/// predicate on `pa`, `$2` onward); `within`, when given, restricts the `pp`
/// CTE to those papers (a set expression covering every `pa` in scope).
fn provable_from(f: &Frame, within: Option<&str>, scope: &str) -> String {
    format!(
        "WITH {} SELECT {{cols}} FROM edges pa \
           JOIN claims c ON c.id = pa.target_id \
           JOIN papers p ON p.id = pa.source_id \
           JOIN reasoning_traces t ON t.id = c.trace_id \
           LEFT JOIN pp ON pp.paper = pa.source_id \
          WHERE {} {scope}",
        f.pp_cte("$1::uuid[]", within),
        provable_sql(f)
    )
}

/// A signer row: id, display name, agent type, key kind, per-kind counts,
/// self-filed paper assertions.
type SignerRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    i64,
    i64,
    i64,
);

/// A census statement's bind parameter, in `$n` order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bind {
    /// The `legacy-ingest` principal (`uuid`; the nil uuid when unregistered).
    Legacy,
    /// The `--ingest-signer` list (`uuid[]`).
    Ingest,
    /// The `--attestation-signer` list (`uuid[]`).
    Attestation,
    /// A batch's keyset cursor: the last edge id of the previous batch
    /// (`uuid`; the nil uuid first).
    After,
    /// The batch size (`bigint`).
    Limit,
}

/// One statement of the read-only census, exactly as [`census`] runs it.
#[derive(Clone, Debug)]
pub struct Statement {
    pub name: String,
    pub sql: String,
    /// Its parameters, `$1` first.
    pub binds: &'static [Bind],
}

impl Statement {
    fn new(name: impl Into<String>, sql: String, binds: &'static [Bind]) -> Self {
        Self {
            name: name.into(),
            sql,
            binds,
        }
    }
}

/// The census's statements over the corpus (the schema probes aside), in
/// the order [`census`] runs them.
#[must_use]
pub fn census_statements(f: &Frame) -> Vec<Statement> {
    let mut v: Vec<Statement> = Kind::ALL.into_iter().map(|k| kind_counts(f, k)).collect();
    v.extend([
        signers_statement(f),
        paper_classes(f),
        paper_conflicts(f),
        chains_statement(f),
        provable_count(f),
        planned_records(f),
    ]);
    v
}

/// Per kind: candidates, in force, unsigned, attestation, ingest-signed,
/// other signer.
fn kind_counts(f: &Frame, kind: Kind) -> Statement {
    Statement::new(
        format!("kind:{}", kind.as_str()),
        format!(
            "SELECT count(*), \
                    count(*) FILTER (WHERE e.valid_to IS NULL OR e.valid_to > now()), \
                    count(*) FILTER (WHERE e.signer_id IS NULL), \
                    count(*) FILTER (WHERE e.signer_id = ANY($1)), \
                    count(*) FILTER (WHERE e.signer_id = ANY($2)), \
                    count(*) FILTER (WHERE e.signer_id IS NOT NULL \
                                       AND NOT (e.signer_id = ANY($1)) \
                                       AND NOT (e.signer_id = ANY($2))) \
               FROM edges e WHERE {}",
            f.candidate(kind, "e")
        ),
        &[Bind::Attestation, Bind::Ingest],
    )
}

/// The distinct signers of the candidates ([`SignerRow`]).
fn signers_statement(f: &Frame) -> Statement {
    Statement::new(
        "signers",
        format!(
            "SELECT e.signer_id, a.display_name, a.agent_type::text, a.key_kind::text, \
                    count(*) FILTER (WHERE {au}), \
                    count(*) FILTER (WHERE {pas}), \
                    count(*) FILTER (WHERE e.source_type = 'agent' AND e.relationship = 'asserts'), \
                    count(*) FILTER (WHERE {pas} AND EXISTS ( \
                        SELECT 1 FROM claims c WHERE c.id = e.target_id \
                                                 AND c.agent_id = e.signer_id)) \
               FROM edges e LEFT JOIN agents a ON a.id = e.signer_id \
              WHERE e.signer_id IS NOT NULL AND (({c0}) OR ({c1}) OR ({c2})) \
              GROUP BY 1, 2, 3, 4 ORDER BY count(*) DESC, 1",
            au = authored("e"),
            pas = paper_asserts("e"),
            c0 = f.candidate(Kind::Authored, "e"),
            c1 = f.candidate(Kind::PaperAsserts, "e"),
            c2 = f.candidate(Kind::AgentAsserts, "e"),
        ),
        &[],
    )
}

/// `WITH pp, papers`: the papers with a candidate `authored` or paper
/// `asserts` edge. `$1` = ingest signers.
fn papers_cte(f: &Frame) -> String {
    format!(
        "WITH {pp}, papers AS (SELECT e.source_id AS paper FROM edges e WHERE {c1} \
                               UNION SELECT e.target_id FROM edges e WHERE {c0})",
        pp = f.pp_cte("$1::uuid[]", None),
        c0 = f.candidate(Kind::Authored, "e"),
        c1 = f.candidate(Kind::PaperAsserts, "e"),
    )
}

/// The candidate papers by the principal they take: a signer's id,
/// `conflict` or `legacy`.
fn paper_classes(f: &Frame) -> Statement {
    Statement::new(
        "paper-classes",
        format!(
            "{} \
             SELECT CASE WHEN pp.n = 1 THEN pp.sids[1]::text \
                         WHEN pp.n > 1 THEN 'conflict' ELSE 'legacy' END, count(*) \
               FROM papers LEFT JOIN pp USING (paper) GROUP BY 1 ORDER BY 2 DESC, 1",
            papers_cte(f)
        ),
        &[Bind::Ingest],
    )
}

/// Up to [`CONFLICTS_LISTED`] conflicting papers with their signers.
fn paper_conflicts(f: &Frame) -> Statement {
    Statement::new(
        "paper-conflicts",
        format!(
            "{} \
             SELECT papers.paper, pp.sids FROM papers JOIN pp USING (paper) \
              WHERE pp.n > 1 ORDER BY 1 LIMIT {CONFLICTS_LISTED}",
            papers_cte(f)
        ),
        &[Bind::Ingest],
    )
}

/// Chains: every (agent assertion, authorship, paper assertion), each pair
/// counted; the chain an agent assertion's principal comes from is the
/// first by [`CHAIN_ORDER`] (oldest in-force), as the apply picks it. One
/// row: (chains, chains on another principal, multi-principal agent
/// assertions).
///
/// Linear whatever the planner estimates: ONE stream of rows (every chain,
/// and every classified-signer row of a legacy `authored` / paper `asserts`
/// edge, as [`Frame::pp_cte`] reads them) and windows over it, with no join
/// but the chain join itself (index lookups from the authorships).
///
/// * a paper's principal is a window over the paper's rows: its signer rows
///   name one signer exactly when their least and greatest agree (as
///   `pp.n = 1`, `pp.sids[1]`), else none and it takes the legacy principal;
/// * the chosen chain's principal is a window over the agent assertion's
///   chains (`first_value` by the chain's [`CHAIN_ORDER`] rank, a total
///   order: it ends in the two edge ids);
/// * a chain is on another principal when the two differ, and an agent
///   assertion is multi-principal exactly when it has such a chain (the
///   chosen principal is one of its own).
///
/// The planner cannot size the chains (on a production corpus it estimates
/// the legacy authorships at a few rows, so the chains at one). A version
/// that joined a chain CTE with itself was planned as a nested loop over two
/// CTE scans, O(chains^2); one that joined the chains to `pp` was planned as
/// a nested loop re-running `pp`'s aggregate for every chain. Neither
/// finished on ~10^5 chains.
fn chains_statement(f: &Frame) -> Statement {
    Statement::new(
        "chains",
        format!(
            "WITH x AS (SELECT e.id AS e, \
                               row_number() OVER (PARTITION BY e.id \
                                                  ORDER BY {CHAIN_ORDER}) AS k, \
                               ea.target_id AS paper, NULL::text AS sid \
                          FROM edges e JOIN edges ea ON ea.source_id = e.source_id \
                          JOIN edges pa ON pa.source_id = ea.target_id \
                                       AND pa.target_id = e.target_id \
                         WHERE {open} AND {au} AND {lea} AND {pas} AND {lpa} \
                        UNION ALL {signers}), \
                  p AS (SELECT x.e, x.k, {prin} AS principal \
                          FROM x WINDOW w AS (PARTITION BY x.paper)), \
                  c AS (SELECT p.e, p.principal, \
                               first_value(p.principal) OVER (PARTITION BY p.e \
                                                              ORDER BY p.k) AS chosen \
                          FROM p WHERE p.e IS NOT NULL) \
             SELECT count(*), \
                    count(*) FILTER (WHERE c.principal <> c.chosen), \
                    count(DISTINCT c.e) FILTER (WHERE c.principal <> c.chosen) \
               FROM c",
            open = f.agent_asserts_unchained("e"),
            au = authored("ea"),
            lea = f.legacy("ea"),
            pas = paper_asserts("pa"),
            lpa = f.legacy("pa"),
            signers = f.signer_rows("$2::uuid[]", "NULL, NULL,", None),
            prin = principal_window("x", "$1::uuid"),
        ),
        &[Bind::Legacy, Bind::Ingest],
    )
}

/// The claims whose creation record a run would write: provable, over the
/// candidates only (a run writes the records of the assertions IT stamps).
fn provable_count(f: &Frame) -> Statement {
    Statement::new(
        "provable-records",
        provable_from(
            f,
            None,
            &format!("AND NOT (pa.labels @> ARRAY['{INGEST_WRITTEN_LABEL}']::text[])"),
        )
        .replace("{cols}", "count(DISTINCT c.id)"),
        &[Bind::Ingest],
    )
}

/// Every candidate paper assertion's (paper, claim, principal) with no
/// record of that principal: the records a run writes (the provable ones a
/// creation record, the rest a non-creation record).
fn planned_records(f: &Frame) -> Statement {
    Statement::new(
        "planned-records",
        format!(
            "WITH {pp}, \
             x AS (SELECT DISTINCT e.source_id AS paper, e.target_id AS claim, \
                          ({prin})::text AS by \
                     FROM edges e LEFT JOIN pp ON pp.paper = e.source_id \
                    WHERE {cand}) \
             SELECT count(*) FROM x \
              WHERE NOT EXISTS (SELECT 1 FROM edges r \
                                 WHERE r.source_id = x.paper AND r.target_id = x.claim \
                                   AND r.relationship = '{INGEST_RECORD_RELATIONSHIP}' \
                                   AND r.properties ->> '{INGESTED_BY_PROPERTY}' = x.by \
                                   AND {by_r} = x.by)",
            pp = f.pp_cte("$2::uuid[]", None),
            by_r = ingest_written_by_sql("r"),
            prin = principal("pp", "$1::uuid"),
            cand = f.candidate(Kind::PaperAsserts, "e"),
        ),
        &[Bind::Legacy, Bind::Ingest],
    )
}

/// One apply batch's locking SELECT of `kind`: the next `$4` candidates
/// after the cursor `$3` in id order, locked, each with the principal of
/// its paper (`legacy` `$1`, ingest signers `$2`).
///
/// Linear whatever the planner estimates (a production corpus is sized at a
/// few rows here):
///
/// * an agent assertion's chain test is `paper_of(e) IS NOT NULL` (the
///   paper of its chosen chain exists exactly when a chain does, the same
///   predicate as [`Frame::candidate`]'s EXISTS), a per-row lookup. As an
///   EXISTS the planner turned it into a join from EVERY chain, so each
///   batch computed and sorted every candidate (seconds per batch, ~10^2
///   batches);
/// * the principal is [`principal_window`] over the batch's rows and the
///   classified-signer rows of the batch's papers, never a join of the
///   batch with `pp` (sized at one row, that join re-ran `pp`'s aggregate
///   for every row of the batch).
#[must_use]
pub fn batch_statement(f: &Frame, kind: Kind) -> Statement {
    let paper = f.paper_of(kind, "e");
    let cand = match kind {
        Kind::AgentAsserts => format!(
            "{} AND ({paper}) IS NOT NULL",
            f.agent_asserts_unchained("e")
        ),
        Kind::Authored | Kind::PaperAsserts => f.candidate(kind, "e"),
    };
    Statement::new(
        format!("batch:{}", kind.as_str()),
        format!(
            "WITH b AS (SELECT e.id, {paper} AS paper FROM edges e \
                         WHERE {cand} AND e.id > $3 ORDER BY e.id LIMIT $4 \
                           FOR UPDATE OF e), \
                  x AS (SELECT b.id, b.paper, NULL::text AS sid FROM b \
                        UNION ALL {signers}), \
                  p AS (SELECT x.id, {prin} AS principal \
                          FROM x WINDOW w AS (PARTITION BY x.paper)) \
             SELECT p.id, p.principal FROM p WHERE p.id IS NOT NULL ORDER BY p.id",
            signers = f.signer_rows("$2::uuid[]", "NULL,", Some("(SELECT b.paper FROM b)")),
            prin = principal_window("x", "$1::uuid"),
        ),
        &[Bind::Legacy, Bind::Ingest, Bind::After, Bind::Limit],
    )
}

/// The values of a statement's [`Bind`]s.
struct Binds<'a> {
    legacy: Uuid,
    ingest: &'a [Uuid],
    attestation: &'a [Uuid],
    after: Uuid,
    limit: i64,
}

impl<'a> Binds<'a> {
    fn on<'q, O>(
        &self,
        st: &'q Statement,
    ) -> sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>
    where
        'a: 'q,
        O: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>,
    {
        let mut q = sqlx::query_as(&st.sql);
        for b in st.binds {
            q = match b {
                Bind::Legacy => q.bind(self.legacy),
                Bind::Ingest => q.bind(self.ingest),
                Bind::Attestation => q.bind(self.attestation),
                Bind::After => q.bind(self.after),
                Bind::Limit => q.bind(self.limit),
            };
        }
        q
    }
}

/// The read-only census.
///
/// # Errors
/// A statement failed (including `statement_timeout`).
#[allow(clippy::too_many_lines)]
pub async fn census(conn: &mut PgConnection, o: &Options) -> anyhow::Result<Census> {
    let f = o.frame();
    let mut tx = conn.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(&o.statement_timeout)
        .execute(&mut *tx)
        .await?;
    let mut c = Census {
        guard_installed: guard_installed(&mut tx).await?,
        legacy_principal: legacy_principal(&mut tx).await?,
        ..Census::default()
    };
    let b = Binds {
        legacy: c.legacy_principal.unwrap_or(Uuid::nil()),
        ingest: &o.ingest_signers,
        attestation: &o.attestation_signers,
        after: Uuid::nil(),
        limit: 0,
    };
    c.reserved_labels_present = sqlx::query_scalar(
        "SELECT count(*) FROM edges e \
          WHERE EXISTS (SELECT 1 FROM unnest(e.labels) l WHERE l LIKE 'epigraph:%')",
    )
    .fetch_one(&mut *tx)
    .await?;
    for kind in Kind::ALL {
        let st = kind_counts(&f, kind);
        let row: (i64, i64, i64, i64, i64, i64) = b
            .on(&st)
            .fetch_one(&mut *tx)
            .await
            .with_context(|| format!("census {}", st.name))?;
        c.per_kind
            .insert(kind, [row.0, row.1, row.2, row.3, row.4, row.5]);
    }
    let st = signers_statement(&f);
    let rows: Vec<SignerRow> = b
        .on(&st)
        .fetch_all(&mut *tx)
        .await
        .with_context(|| format!("census {}", st.name))?;
    let roles: Vec<(Uuid, String)> =
        if sqlx::query_scalar::<_, bool>("SELECT to_regclass('public.system_agents') IS NOT NULL")
            .fetch_one(&mut *tx)
            .await?
        {
            sqlx::query_as("SELECT agent_id, role FROM public.system_agents")
                .fetch_all(&mut *tx)
                .await?
        } else {
            Vec::new()
        };
    c.signers = rows
        .into_iter()
        .map(
            |(id, display_name, agent_type, key_kind, au, pa, ag, pa_self)| Signer {
                id,
                display_name,
                agent_type,
                key_kind,
                system_role: roles.iter().find(|(a, _)| *a == id).map(|(_, r)| r.clone()),
                authored: au,
                paper_asserts: pa,
                agent_asserts: ag,
                paper_asserts_self_filed: pa_self,
            },
        )
        .collect();

    // Papers, by the principal they take.
    let st = paper_classes(&f);
    let classes: Vec<(String, i64)> = b
        .on(&st)
        .fetch_all(&mut *tx)
        .await
        .with_context(|| format!("census {}", st.name))?;
    for (class, n) in classes {
        c.papers += n;
        match class.as_str() {
            "legacy" => c.papers_no_real_signer = n,
            "conflict" => c.papers_conflicting = n,
            id => c
                .papers_by_signer
                .push((Uuid::parse_str(id).context("paper principal")?, n)),
        }
    }
    let st = paper_conflicts(&f);
    c.conflicts = b
        .on(&st)
        .fetch_all(&mut *tx)
        .await
        .with_context(|| format!("census {}", st.name))?;

    let st = chains_statement(&f);
    let (chains, other, multi): (i64, i64, i64) = b
        .on(&st)
        .fetch_one(&mut *tx)
        .await
        .with_context(|| format!("census {}", st.name))?;
    c.chains = chains;
    c.chains_on_another_principal = other;
    c.agent_asserts_multi_principal = multi;

    let st = provable_count(&f);
    (c.provable_records,) = b
        .on(&st)
        .fetch_one(&mut *tx)
        .await
        .with_context(|| format!("census {}", st.name))?;

    let st = planned_records(&f);
    let (pairs,): (i64,) = b
        .on(&st)
        .fetch_one(&mut *tx)
        .await
        .with_context(|| format!("census {}", st.name))?;
    c.planned_non_creation = pairs
        - if o.creation_records {
            c.provable_records
        } else {
            0
        };
    tx.rollback().await?;
    Ok(c)
}

/// The census as report lines (ids included: an operator's terminal, never a
/// public document).
#[must_use]
pub fn describe(c: &Census, o: &Options) -> Vec<String> {
    let mut out = vec![
        format!(
            "SCHEMA\tguard_208={}\tlegacy_ingest={}\treserved_labels_present={}",
            if c.guard_installed {
                "installed"
            } else {
                "MISSING"
            },
            c.legacy_principal
                .map_or_else(|| "NOT-REGISTERED".to_string(), |u| u.to_string()),
            c.reserved_labels_present
        ),
        match &o.written_before {
            Some(t) => format!("CUTOFF\twritten_before={}", cutoff_text(t)),
            None => "CUTOFF\twritten_before=none (every unmarked edge counts, whenever it was \
                     written; --apply requires --written-before)"
                .to_string(),
        },
    ];
    for (k, v) in &c.per_kind {
        out.push(format!(
            "KIND\t{}\tcandidates={}\tin_force={}\tunsigned={}\tattestation={}\tingest_signed={}\tother_signer={}",
            k.as_str(),
            v[0],
            v[1],
            v[2],
            v[3],
            v[4],
            v[5]
        ));
    }
    for s in &c.signers {
        let class = if o.attestation_signers.contains(&s.id) {
            "attestation"
        } else if o.ingest_signers.contains(&s.id) {
            "ingest"
        } else if s.needs_class() {
            "UNCLASSIFIED"
        } else {
            "agent-asserts-only:info (its edges take their paper's principal)"
        };
        out.push(format!(
            "SIGNER\t{}\tname={}\tagent_type={}\tkey_kind={}\tsystem_role={}\t\
             authored={}\tpaper_asserts={}\tagent_asserts={}\t\
             paper_asserts_onto_claims_it_filed={}/{}\t{class}",
            s.id,
            s.display_name.as_deref().unwrap_or(""),
            s.agent_type.as_deref().unwrap_or(""),
            s.key_kind.as_deref().unwrap_or(""),
            s.system_role.as_deref().unwrap_or(""),
            s.authored,
            s.paper_asserts,
            s.agent_asserts,
            s.paper_asserts_self_filed,
            s.paper_asserts
        ));
    }
    out.push(format!(
        "PAPERS\tpapers={}\tby_one_ingest_signer={}\tlegacy_ingest_no_real_signer={}\t\
         legacy_ingest_conflicting_signers={}",
        c.papers,
        c.papers_by_signer.iter().map(|(_, n)| n).sum::<i64>(),
        c.papers_no_real_signer,
        c.papers_conflicting
    ));
    for (id, n) in &c.papers_by_signer {
        out.push(format!("PAPER-PRINCIPAL\t{id}\tpapers={n}"));
    }
    for (paper, signers) in &c.conflicts {
        out.push(format!(
            "CONFLICT\tpaper={paper}\tsigners={}\t(-> legacy-ingest)",
            signers
                .iter()
                .map(Uuid::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    out.push(format!(
        "CHAINS\tchains={}\tchains_on_another_principal={}\tagent_asserts_multi_principal={}\t\
         (an agent assertion closing chains through papers of different principals takes its \
         oldest in-force chain's, else its oldest chain's; the claim is credited through that \
         chain)",
        c.chains, c.chains_on_another_principal, c.agent_asserts_multi_principal
    ));
    out.push(format!(
        "CREATION-RECORDS\tprovable={}{}",
        c.provable_records,
        if o.creation_records {
            ""
        } else {
            "\t(skipped: --no-creation-records; they get non-creation records)"
        }
    ));
    out.push(format!(
        "NON-CREATION-RECORDS\tplanned={}",
        c.planned_non_creation
    ));
    out.push(format!("TOTAL\tedges_to_stamp={}", c.total()));
    out
}

/// What a run did.
#[derive(Debug, Default)]
pub struct Report {
    pub stamped: BTreeMap<Kind, u64>,
    pub records: u64,
    pub non_creation_records: u64,
    pub batches: usize,
    pub batch_failures: Vec<String>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

struct ManifestOut {
    file: File,
    path: PathBuf,
}

impl ManifestOut {
    fn create(path: &Path, header: &Value) -> anyhow::Result<Self> {
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
        let mut m = Self {
            file,
            path: path.to_path_buf(),
        };
        m.append(std::slice::from_ref(header))?;
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
        Ok(m)
    }

    fn append(&mut self, lines: &[Value]) -> anyhow::Result<()> {
        for v in lines {
            let mut s = serde_json::to_string(v)?;
            s.push('\n');
            self.file.write_all(s.as_bytes())?;
        }
        self.file.flush()?;
        self.file
            .sync_all()
            .with_context(|| format!("fsync of {}", self.path.display()))
    }

    /// After a batch's commit: only now may a reversal act on it.
    fn committed(&mut self, batch: usize) -> anyhow::Result<()> {
        self.append(&[json!({ "committed_batch": batch })])
    }
}

async fn declare(conn: &mut PgConnection, on: bool) -> anyhow::Result<()> {
    sqlx::query("SELECT pg_catalog.set_config($1, $2, true)")
        .bind(INGEST_WRITTEN_SETTING)
        .bind(if on { "on" } else { "" })
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn audit(conn: &mut PgConnection, event: &str, details: &Value) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO public.security_events (event_type, agent_id, success, details) \
         VALUES ($1, NULL, true, $2)",
    )
    .bind(event)
    .bind(details)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// What every write of one applied run shares.
struct Act {
    frame: Frame,
    audit: Value,
    audited: bool,
}

impl Act {
    async fn audit_once(&mut self, tx: &mut PgConnection) -> anyhow::Result<()> {
        if !self.audited {
            audit(tx, EVENT_APPLY, &self.audit).await?;
        }
        Ok(())
    }
}

/// Run the backfill (dry run: the census only).
///
/// # Errors
/// A refusal before any write, or a statement / manifest failure.
#[allow(clippy::too_many_lines)]
pub async fn run(
    conn: &mut PgConnection,
    o: &Options,
    session_user: &str,
    out: &mut impl Write,
) -> anyhow::Result<Report> {
    let c = census(conn, o).await?;
    for line in describe(&c, o) {
        writeln!(out, "{line}")?;
    }
    let mut report = Report::default();
    if !o.apply {
        writeln!(
            out,
            "DRY RUN: read-only; nothing was written. --apply --written-before <same cutoff> \
             --confirm-count {} --manifest-out <file> --ruling <text> --reason <text> stamps \
             the edges above.",
            c.total()
        )?;
        return Ok(report);
    }
    if !c.guard_installed {
        bail!(
            "refusing --apply: migration 208's guard is not installed, so the backfill labels \
             would be written with no database guard; apply migration 208 first. Nothing was \
             written"
        );
    }
    let Some(legacy) = c.legacy_principal else {
        bail!(
            "refusing --apply: no 'legacy-ingest' system principal is registered. Run \
             `epigraph-operator register-system-agent --role legacy-ingest --create-agent \
             --reason <text> --apply` first. Nothing was written"
        );
    };
    let unclassified = c.unclassified(o);
    if !unclassified.is_empty() {
        bail!(
            "refusing --apply: {} signer(s) of candidate authored / paper asserts edges are \
             not classified as --ingest-signer or --attestation-signer: {}. Nothing was written",
            unclassified.len(),
            unclassified
                .iter()
                .map(Uuid::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if o.confirm_count != Some(c.total()) {
        bail!(
            "refusing --apply: --confirm-count {:?} does not match the {} edges this run would \
             stamp now. Nothing was written",
            o.confirm_count,
            c.total()
        );
    }
    let cutoff = cutoff_text(o.written_before.as_ref().expect("validated"));
    let path = o.manifest_out.as_ref().expect("validated");
    let header = json!({
        "manifest": OPERATION,
        "version": VERSION,
        "created_at": Utc::now().to_rfc3339(),
        "session_user": session_user,
        "legacy_principal": legacy,
        "written_before": cutoff,
        "attestation_signers": o.attestation_signers,
        "ingest_signers": o.ingest_signers,
        "ruling": o.ruling,
        "reason": o.reason,
        "plan": {
            "edges": c.total(),
            "papers": c.papers,
            "papers_conflicting": c.papers_conflicting,
            "chains": c.chains,
            "agent_asserts_multi_principal": c.agent_asserts_multi_principal,
            "provable_records": c.provable_records,
            "planned_non_creation": c.planned_non_creation,
        },
    });
    let header_sha = sha256_hex(serde_json::to_string(&header)?.as_bytes());
    let mut manifest = ManifestOut::create(path, &header)?;
    let mut act = Act {
        frame: o.frame(),
        audit: json!({
            "operation": OPERATION,
            "manifest_header_sha256": header_sha,
            "legacy_principal": legacy,
            "written_before": cutoff,
            "plan_edges": c.total(),
            "ruling": o.ruling,
            "reason": o.reason,
            "session_user": session_user,
        }),
        audited: false,
    };
    let mut lock_timed_out = false;
    // A batch that COMMITTED but whose `committed_batch` line was not written.
    let mut committed_line_missing: Option<usize> = None;
    'kinds: for kind in Kind::ALL {
        let mut last = Uuid::nil();
        loop {
            if o.max_batches.is_some_and(|m| report.batches >= m) {
                break 'kinds;
            }
            // Every step of a batch, BEGIN through COMMIT, runs inside this
            // one caught block: whatever fails (the locked candidate SELECT
            // timing out on a concurrent writer's lock, the manifest write,
            // the UPDATE, an ingest record, the COMMIT) rolls the whole batch
            // back and stops the run without leaving `run`, so the summary
            // below always prints. A paper-assertion batch writes its stamps'
            // ingest records in the SAME transaction: a committed batch
            // always carries its records, however the run stops after it
            // (killed included), and there is no separate record phase to
            // miss.
            let mut numbered: Option<usize> = None;
            let step: anyhow::Result<Option<Done>> = async {
                let mut tx = conn.begin().await.context("BEGIN")?;
                let body: anyhow::Result<Option<Done>> = async {
                    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
                        .bind(&o.lock_timeout)
                        .execute(&mut *tx)
                        .await?;
                    // The batch, locked, then the principal of each edge's
                    // paper, decided once per paper of the batch.
                    let st = batch_statement(&act.frame, kind);
                    let rows: Vec<(Uuid, Uuid)> = Binds {
                        legacy,
                        ingest: &o.ingest_signers,
                        attestation: &o.attestation_signers,
                        after: last,
                        limit: i64::try_from(o.batch_size).unwrap_or(i64::MAX),
                    }
                    .on(&st)
                    .fetch_all(&mut *tx)
                    .await
                    .context("locking the batch's candidate edges")?;
                    let Some((max_id, _)) = rows.last().copied() else {
                        return Ok(None);
                    };
                    report.batches += 1;
                    let batch = report.batches;
                    numbered = Some(batch);
                    manifest.append(
                        &rows
                            .iter()
                            .map(|(id, by)| {
                                json!({"edge": id, "by": by, "kind": kind.as_str(), "batch": batch})
                            })
                            .collect::<Vec<_>>(),
                    )?;
                    let ids: Vec<Uuid> = rows.iter().map(|r| r.0).collect();
                    let bys: Vec<Uuid> = rows.iter().map(|r| r.1).collect();
                    declare(&mut tx, true).await?;
                    let n = sqlx::query(&format!(
                        "UPDATE edges e \
                            SET labels = e.labels || ARRAY['{INGEST_WRITTEN_LABEL}', \
                                                           '{INGEST_WRITTEN_BY_LABEL_PREFIX}' || v.by::text] \
                           FROM unnest($1::uuid[], $2::uuid[]) AS v(id, by) \
                          WHERE e.id = v.id"
                    ))
                    .bind(&ids)
                    .bind(&bys)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
                    declare(&mut tx, false).await?;
                    if n != ids.len() as u64 {
                        bail!("batch stamped {n} of {} locked edges", ids.len());
                    }
                    let (mut created, mut other) = (0, 0);
                    if kind == Kind::PaperAsserts {
                        let (lines, c, x) =
                            batch_records(&mut tx, &act.frame, o, &ids, batch).await?;
                        // The record lines, fsynced before the commit that
                        // writes them, under this batch's number.
                        manifest.append(&lines)?;
                        (created, other) = (c, x);
                    }
                    act.audit_once(&mut tx).await?;
                    Ok(Some(Done {
                        max_id,
                        batch,
                        stamped: n,
                        created,
                        other,
                    }))
                }
                .await;
                match body {
                    Ok(Some(done)) => {
                        tx.commit().await.context(
                            "COMMIT (the manifest holds this batch's lines with no commit \
                             line, so the reversal reports it as UNCOMMITTED-BATCH)",
                        )?;
                        crash_point(done.batch, "commit");
                        Ok(Some(done))
                    }
                    Ok(None) => {
                        tx.rollback().await.context("ROLLBACK")?;
                        Ok(None)
                    }
                    Err(e) => {
                        tx.rollback().await.ok();
                        Err(e)
                    }
                }
            }
            .await;
            match step {
                Ok(None) => break,
                Ok(Some(done)) => {
                    let batch = done.batch;
                    act.audited = true;
                    *report.stamped.entry(kind).or_default() += done.stamped;
                    report.records += done.created;
                    report.non_creation_records += done.other;
                    if let Err(e) = manifest.committed(batch) {
                        committed_line_missing = Some(batch);
                        report.batch_failures.push(format!(
                            "{} batch {batch} COMMITTED, but its committed_batch line was not \
                             written ({e:#}): append the line {{\"committed_batch\": {batch}}} \
                             to the manifest by hand; until then the reversal reports this \
                             batch as UNCOMMITTED-BATCH and leaves its stamps and records",
                            kind.as_str()
                        ));
                        break 'kinds;
                    }
                    crash_point(batch, "line");
                    last = done.max_id;
                }
                Err(e) => {
                    lock_timed_out |= is_lock_timeout(&e);
                    let which = numbered.map_or_else(String::new, |b| format!(" {b}"));
                    report.batch_failures.push(format!(
                        "{} batch{which} after {last}: {e:#}",
                        kind.as_str()
                    ));
                    break 'kinds;
                }
            }
        }
    }
    for (k, n) in &report.stamped {
        writeln!(out, "STAMPED\t{}\t{n}", k.as_str())?;
    }
    writeln!(out, "CREATION-RECORDS-WRITTEN\t{}", report.records)?;
    writeln!(
        out,
        "NON-CREATION-RECORDS-WRITTEN\t{}",
        report.non_creation_records
    )?;
    for f in &report.batch_failures {
        writeln!(out, "BATCH-FAILED\t{f}")?;
    }
    writeln!(
        out,
        "MANIFEST\t{}\t(reverse with: epigraph-operator reverse-ingest-markers --manifest {} --apply)",
        path.display(),
        path.display()
    )?;
    for line in next_steps(&report, committed_line_missing, lock_timed_out, path) {
        writeln!(out, "NEXT\t{line}")?;
    }
    Ok(report)
}

/// What the operator does after a run that reported a `BATCH-FAILED`: the
/// `NEXT` lines. Nothing after a clean run. Every batch a run committed
/// carries its ingest records, so the run can always be resumed as it is or
/// undone; a batch that committed without its `committed_batch` line must get
/// that line FIRST, or the reversal leaves it in place.
fn next_steps(
    report: &Report,
    committed_line_missing: Option<usize>,
    lock_timed_out: bool,
    manifest: &Path,
) -> Vec<String> {
    if report.batch_failures.is_empty() {
        return Vec::new();
    }
    let reverse = format!(
        "epigraph-operator reverse-ingest-markers --manifest {} --apply",
        manifest.display()
    );
    let resume = "re-run the dry run with the same --written-before and the same \
                  --ingest-signer / --attestation-signer lists, then --apply with its TOTAL \
                  as --confirm-count and a NEW --manifest-out";
    let mut next = Vec::new();
    if let Some(batch) = committed_line_missing {
        next.push(format!(
            "first: append the line {{\"committed_batch\": {batch}}} to {} (batch {batch} \
             committed; without that line the reversal below leaves its stamps and records)",
            manifest.display()
        ));
    }
    next.push(format!(
        "resume: every batch this run committed carries its ingest records, so query_paper and \
         get_claim's ingesters agree; {resume}. Or undo this run: {reverse}"
    ));
    if lock_timed_out {
        next.push(
            "a lock timeout means another transaction held a candidate edge: stop \
             that writer (ingest jobs) first, or resume with a longer --lock-timeout"
                .to_string(),
        );
    }
    next
}

/// The environment variable of the test-only crash hook ([`crash_point`]).
pub const TEST_CRASH_ENV: &str = "EPIGRAPH_OPERATOR_TEST_CRASH_AT";

/// A test-only crash hook, compiled into debug builds only: when
/// [`TEST_CRASH_ENV`] is `<batch>:commit` (right after that batch's COMMIT,
/// before its `committed_batch` line), `<batch>:line` (after that line,
/// before the next batch) or `<n>:reverse` (right after a reversal's n-th
/// committed transaction), the process aborts there, as a kill would stop
/// it: no unwinding, no summary.
#[cfg(debug_assertions)]
fn crash_point(batch: usize, at: &str) {
    if std::env::var(TEST_CRASH_ENV).is_ok_and(|v| v == format!("{batch}:{at}")) {
        std::process::abort();
    }
}

#[cfg(not(debug_assertions))]
fn crash_point(_batch: usize, _at: &str) {}

/// Whether a batch failed on `lock_timeout` (SQLSTATE 55P03).
fn is_lock_timeout(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<sqlx::Error>()
            .and_then(sqlx::Error::as_database_error)
            .and_then(|d| d.code())
            .is_some_and(|code| code == "55P03")
    })
}

/// One record to write: paper, claim, principal, created.
type RecordPlan = (Uuid, Uuid, Uuid, bool);

/// What one committed batch did.
struct Done {
    max_id: Uuid,
    batch: usize,
    stamped: u64,
    created: u64,
    other: u64,
}

/// The ingest records of one paper-assertion batch's stamps (`ids`, module
/// doc), inside that batch's transaction: the provable creation records
/// first, then a non-creation record for every stamped assertion its
/// principal has no record of. Returns the manifest lines (tagged `batch`)
/// and the creation and non-creation counts.
async fn batch_records(
    tx: &mut PgConnection,
    f: &Frame,
    o: &Options,
    ids: &[Uuid],
    batch: usize,
) -> anyhow::Result<(Vec<Value>, u64, u64)> {
    let mut plan: Vec<RecordPlan> = Vec::new();
    if o.creation_records {
        // Only over this batch's stamps (the principal decided over their
        // papers only), and only where the stamp names the signer the proof
        // names (the record's ingester is the edge's `by`).
        let sql = format!(
            "{} ORDER BY c.id, pa.created_at, pa.id",
            provable_from(
                f,
                Some("(SELECT x.source_id FROM edges x WHERE x.id = ANY($2::uuid[]))"),
                &format!(
                    "AND pa.id = ANY($2::uuid[]) AND ({by_pa}) = pa.signer_id::text",
                    by_pa = ingest_written_by_sql("pa")
                )
            )
            .replace(
                "{cols}",
                "DISTINCT ON (c.id) pa.source_id, c.id, c.agent_id"
            )
        );
        let created: Vec<(Uuid, Uuid, Uuid)> = sqlx::query_as(&sql)
            .bind(&o.ingest_signers)
            .bind(ids)
            .fetch_all(&mut *tx)
            .await
            .context("the batch's provable creation records")?;
        plan.extend(created.into_iter().map(|(p, c, by)| (p, c, by, true)));
    }
    // The batch's stamped paper assertions, by the principal their label
    // names. A pair a creation record above covers is skipped by the record
    // writer's own dedup (one record per paper, claim and ingester).
    let stamped: Vec<(Uuid, Uuid, Uuid)> = sqlx::query_as(&format!(
        "SELECT DISTINCT e.source_id, e.target_id, ({by_e})::uuid FROM edges e \
          WHERE e.id = ANY($1::uuid[]) AND {pas} \
            AND e.labels @> ARRAY['{INGEST_WRITTEN_LABEL}']::text[] \
          ORDER BY 1, 2, 3",
        by_e = ingest_written_by_sql("e"),
        pas = paper_asserts("e"),
    ))
    .bind(ids)
    .fetch_all(&mut *tx)
    .await
    .context("the batch's stamped paper assertions")?;
    let creations: BTreeSet<(Uuid, Uuid, Uuid)> =
        plan.iter().map(|(p, c, by, _)| (*p, *c, *by)).collect();
    plan.extend(
        stamped
            .into_iter()
            .filter(|k| !creations.contains(k))
            .map(|(p, c, by)| (p, c, by, false)),
    );
    let mut authors_of: HashMap<(Uuid, Uuid), Vec<Uuid>> = HashMap::new();
    let mut lines = Vec::new();
    let (mut created_n, mut other_n) = (0u64, 0u64);
    for (paper, claim, by, created) in &plan {
        if let Entry::Vacant(slot) = authors_of.entry((*paper, *by)) {
            // The authorships this principal's ingest of the paper holds (the
            // authors query_paper(ingested_by = by) lists), in position order.
            // Every authorship is stamped before any paper assertion: a run
            // stamps the kinds in order, each to exhaustion.
            let authors: Vec<Uuid> = sqlx::query_scalar(&format!(
                "SELECT ea.source_id FROM edges ea \
                  WHERE ea.target_id = $1 AND {au} \
                    AND (ea.valid_to IS NULL OR ea.valid_to > now()) \
                    AND {by_ea} = $2::text \
                  ORDER BY CASE WHEN ea.properties ->> 'position' ~ '^[0-9]{{1,9}}$' \
                                THEN (ea.properties ->> 'position')::bigint END NULLS LAST, \
                           ea.created_at, ea.id",
                au = authored("ea"),
                by_ea = ingest_written_by_sql("ea"),
            ))
            .bind(paper)
            .bind(by.to_string())
            .fetch_all(&mut *tx)
            .await?;
            slot.insert(authors);
        }
        let authors = &authors_of[&(*paper, *by)];
        let wrote = epigraph_db::ClaimIngestRepository::record_signed_conn(
            &mut *tx, None, *paper, *claim, *by, *created, authors, TOOL, PIPELINE,
        )
        .await
        .map_err(|e| anyhow!("ingest record for claim {claim}: {e}"))?;
        if !wrote {
            continue;
        }
        let id: Uuid = sqlx::query_scalar(&format!(
            "SELECT e.id FROM edges e \
              WHERE e.source_id = $1 AND e.target_id = $2 \
                AND e.relationship = '{INGEST_RECORD_RELATIONSHIP}' \
                AND e.properties -> '{INGEST_WRITTEN_PROPERTY}' ->> 'tool' = $3 \
                AND e.properties ->> '{INGESTED_BY_PROPERTY}' = $4"
        ))
        .bind(paper)
        .bind(claim)
        .bind(TOOL)
        .bind(by.to_string())
        .fetch_one(&mut *tx)
        .await?;
        if *created {
            created_n += 1;
        } else {
            other_n += 1;
        }
        lines.push(json!({
            "record": id, "paper": paper, "claim": claim, "by": by,
            "created": created, "batch": batch,
        }));
    }
    Ok((lines, created_n, other_n))
}

/// The reversal's refusal while `total` stamped paper assertions outside
/// the manifest's committed batches rest on records those batches wrote.
/// `outside` are not in the manifest at all (a newer run stamped them);
/// `in_uncommitted` are listed in one of its uncommitted batches, keyed by
/// batch: either a newer run stamped them after that batch rolled back, or
/// the batch committed and the run died before its `committed_batch` line.
/// The manifest cannot tell those apart, so it names both remedies.
fn leaning_refusal(
    manifest: &Path,
    total: usize,
    outside: &[String],
    in_uncommitted: &BTreeMap<i64, Vec<String>>,
) -> String {
    let m = manifest.display();
    let mut msg = format!(
        "{m} cannot be reversed yet: {total} stamped paper assertion(s) outside its committed \
         batches rest on the ingest records those batches wrote (one record per paper, claim \
         and principal). Nothing was done."
    );
    if !outside.is_empty() {
        msg.push_str(&format!(
            " {} not in this manifest: {}. A newer run stamped them: reverse the newer \
             manifest that stamped them first, then this one.",
            outside.len(),
            outside.join("; ")
        ));
    }
    for (b, named) in in_uncommitted {
        msg.push_str(&format!(
            " {} in this manifest's uncommitted batch {b} (lines but no committed_batch \
             line): {}. If a newer manifest lists them, reverse that newer manifest first, \
             then this one. If none does, batch {b} committed before the run wrote its line \
             (the run was killed after that COMMIT): check that batch {b}'s edges are all \
             stamped, append the line {{\"committed_batch\": {b}}} to {m}, then reverse \
             this manifest again.",
            named.len(),
            named.join("; ")
        ));
    }
    msg
}

/// One committed batch to reverse: its records, and its edges with the
/// `by` each was stamped with.
type BatchUndo = (Vec<Uuid>, Vec<(Uuid, Uuid)>);

/// What a reversal did.
#[derive(Debug, Default)]
pub struct ReverseReport {
    pub restored: u64,
    pub held: u64,
    pub records_deleted: u64,
    pub records_held: u64,
    /// Batches with lines but no commit line: `(batch, edges, records)`.
    pub uncommitted: Vec<(i64, usize, usize)>,
}

/// Reverse a backfill run from its manifest (dry run: rolled back).
///
/// # Errors
/// The manifest is not a backfill manifest of version [`VERSION`] or
/// [`LEGACY_VERSION`]; a currently stamped paper assertion outside this
/// manifest's COMMITTED batches rests on a record those batches wrote (a
/// newer run's stamp: reverse that run first; or, listed in one of its
/// uncommitted batches with no newer run, that batch committed without its
/// line: append it; nothing is written, see [`leaning_refusal`]); or a
/// statement failed.
#[allow(clippy::too_many_lines)]
pub async fn reverse(
    conn: &mut PgConnection,
    manifest: &Path,
    apply: bool,
    lock_timeout: &str,
    out: &mut impl Write,
) -> anyhow::Result<ReverseReport> {
    let bytes = std::fs::read(manifest)
        .with_context(|| format!("reading manifest {}", manifest.display()))?;
    let file_sha = sha256_hex(&bytes);
    let reader = BufReader::new(&bytes[..]);
    let mut lines = reader.lines();
    let header: Value =
        serde_json::from_str(&lines.next().ok_or_else(|| anyhow!("empty manifest"))??)?;
    if header.get("manifest").and_then(Value::as_str) != Some(OPERATION) {
        bail!(
            "{} is not a {OPERATION} manifest; nothing was done",
            manifest.display()
        );
    }
    let version = header.get("version").and_then(Value::as_i64);
    if version != Some(VERSION) && version != Some(LEGACY_VERSION) {
        bail!(
            "{} is a version {} manifest; this binary reverses versions {VERSION} and \
             {LEGACY_VERSION} only. Nothing was done",
            manifest.display(),
            header.get("version").unwrap_or(&Value::Null)
        );
    }
    let mut edges: Vec<(i64, Uuid, Uuid)> = Vec::new();
    // (batch, record, paper, claim, by)
    let mut records: Vec<(i64, Uuid, Uuid, Uuid, Uuid)> = Vec::new();
    let mut committed: BTreeSet<i64> = BTreeSet::new();
    for line in lines {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(&line)?;
        if let Some(b) = v.get("committed_batch") {
            committed.insert(
                b.as_i64()
                    .ok_or_else(|| anyhow!("committed_batch is not a number: {line}"))?,
            );
            continue;
        }
        let uuid = |k: &str| -> anyhow::Result<Uuid> {
            Uuid::parse_str(
                v.get(k)
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("manifest line lacks {k}: {line}"))?,
            )
            .with_context(|| format!("{k} is not a uuid"))
        };
        let batch = v
            .get("batch")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("manifest line lacks its batch: {line}"))?;
        if v.get("edge").is_some() {
            if let Some(k) = v.get("kind").and_then(Value::as_str) {
                Kind::parse(k).ok_or_else(|| anyhow!("unknown kind {k}"))?;
            }
            edges.push((batch, uuid("edge")?, uuid("by")?));
        } else if v.get("record").is_some() {
            records.push((
                batch,
                uuid("record")?,
                uuid("paper")?,
                uuid("claim")?,
                uuid("by")?,
            ));
        } else {
            bail!("unrecognised manifest line: {line}");
        }
    }
    let mut r = ReverseReport::default();
    let mut pending: BTreeMap<i64, (usize, usize)> = BTreeMap::new();
    for (b, ..) in edges.iter().filter(|(b, ..)| !committed.contains(b)) {
        pending.entry(*b).or_default().0 += 1;
    }
    for (b, ..) in records.iter().filter(|(b, ..)| !committed.contains(b)) {
        pending.entry(*b).or_default().1 += 1;
    }
    r.uncommitted = pending.into_iter().map(|(b, (e, n))| (b, e, n)).collect();
    // Before any write, dry run or not: the record writer keeps ONE record
    // per paper, claim and principal, so a later run that stamped another
    // copy of a pair this run's records cover wrote no record of its own and
    // rests on this run's. Deleting it would leave that stamp without one,
    // so refuse until the newer run is reversed (then this one is exact).
    // Only this manifest's COMMITTED edges are excluded: an uncommitted
    // batch's lines are written before its UPDATE, so a rolled-back batch
    // lists edges a newer run may since have stamped.
    let mine: Vec<Uuid> = edges
        .iter()
        .filter(|(b, ..)| committed.contains(b))
        .map(|(_, e, _)| *e)
        .collect();
    let uncommitted_edge: BTreeMap<Uuid, i64> = edges
        .iter()
        .filter(|(b, ..)| !committed.contains(b))
        .map(|(b, e, _)| (*e, *b))
        .collect();
    let (mut rp, mut rc, mut rb) = (Vec::new(), Vec::new(), Vec::new());
    for (b, _, p, c, by) in &records {
        if committed.contains(b) {
            rp.push(*p);
            rc.push(*c);
            rb.push(*by);
        }
    }
    if !rp.is_empty() {
        let leaning: Vec<(Uuid, Uuid, Uuid, String)> = sqlx::query_as(&format!(
            "SELECT DISTINCT e.id, e.source_id, e.target_id, ({by_e}) FROM edges e \
               JOIN unnest($1::uuid[], $2::uuid[], $3::uuid[]) AS r(paper, claim, by) \
                 ON e.source_id = r.paper AND e.target_id = r.claim \
                AND ({by_e}) = r.by::text \
              WHERE {pas} AND e.labels @> ARRAY['{INGEST_WRITTEN_LABEL}']::text[] \
                AND NOT (e.id = ANY($4::uuid[])) \
              ORDER BY e.id",
            by_e = ingest_written_by_sql("e"),
            pas = paper_asserts("e"),
        ))
        .bind(&rp)
        .bind(&rc)
        .bind(&rb)
        .bind(&mine)
        .fetch_all(&mut *conn)
        .await
        .context("the stamps outside this manifest that rest on its records")?;
        if !leaning.is_empty() {
            let mut outside = Vec::new();
            let mut in_uncommitted: BTreeMap<i64, Vec<String>> = BTreeMap::new();
            for (e, p, c, by) in &leaning {
                let named = format!("edge {e} (paper {p} asserts claim {c}, by {by})");
                match uncommitted_edge.get(e) {
                    Some(b) => in_uncommitted.entry(*b).or_default().push(named),
                    None => outside.push(named),
                }
            }
            bail!(
                "{}",
                leaning_refusal(manifest, leaning.len(), &outside, &in_uncommitted)
            );
        }
    }
    if version == Some(LEGACY_VERSION) {
        writeln!(
            out,
            "LEGACY-MANIFEST\tversion {LEGACY_VERSION}: its records are in their own batches, \
             not their stamps', so this reversal is not batch-atomic: if it stops part way, \
             stamps may be left without their records until it is re-run to finish"
        )?;
    }
    // Only what the run committed, per batch: each committed batch is
    // reversed in ONE transaction (its records and its labels together), so
    // a reversal stopped anywhere, killed included, never leaves a stamp
    // without its record; newest batch first, the order the run wrote them
    // in reversed. Every statement is a compare-and-swap, so a re-run, or a
    // run after a partial one, restores only what is still the run's.
    let mut by_batch: BTreeMap<i64, BatchUndo> = BTreeMap::new();
    let (mut n_edges, mut n_records) = (0usize, 0usize);
    for (b, e, by) in edges.into_iter().filter(|(b, ..)| committed.contains(b)) {
        by_batch.entry(b).or_default().1.push((e, by));
        n_edges += 1;
    }
    for (b, id, ..) in records.into_iter().filter(|(b, ..)| committed.contains(b)) {
        by_batch.entry(b).or_default().0.push(id);
        n_records += 1;
    }
    let mut audited = false;
    let mut steps: Vec<BatchUndo> = by_batch.into_values().rev().collect();
    if steps.is_empty() {
        // Nothing committed: still one (audited) transaction.
        steps.push((Vec::new(), Vec::new()));
    }
    for (step, (recs, chunk)) in steps.into_iter().enumerate() {
        let mut tx = conn.begin().await?;
        sqlx::query("SELECT set_config('lock_timeout', $1, true)")
            .bind(lock_timeout)
            .execute(&mut *tx)
            .await?;
        declare(&mut tx, true).await?;
        if !recs.is_empty() {
            let n = sqlx::query(&format!(
                "DELETE FROM edges e WHERE e.id = ANY($1) \
                   AND e.relationship = '{INGEST_RECORD_RELATIONSHIP}' \
                   AND e.properties -> '{INGEST_WRITTEN_PROPERTY}' ->> 'tool' = $2"
            ))
            .bind(&recs)
            .bind(TOOL)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            r.records_deleted += n;
            r.records_held += recs.len() as u64 - n;
        }
        if !chunk.is_empty() {
            let ids: Vec<Uuid> = chunk.iter().map(|c| c.0).collect();
            let bys: Vec<Uuid> = chunk.iter().map(|c| c.1).collect();
            let n = sqlx::query(&format!(
                "UPDATE edges e \
                    SET labels = ARRAY(SELECT x.l \
                                         FROM unnest(e.labels) WITH ORDINALITY AS x(l, n) \
                                        WHERE x.l <> '{INGEST_WRITTEN_LABEL}' \
                                          AND x.l <> '{INGEST_WRITTEN_BY_LABEL_PREFIX}' || v.by::text \
                                        ORDER BY x.n) \
                   FROM unnest($1::uuid[], $2::uuid[]) AS v(id, by) \
                  WHERE e.id = v.id \
                    AND e.labels @> ARRAY['{INGEST_WRITTEN_LABEL}', \
                                          '{INGEST_WRITTEN_BY_LABEL_PREFIX}' || v.by::text]"
            ))
            .bind(&ids)
            .bind(&bys)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            r.restored += n;
            r.held += chunk.len() as u64 - n;
        }
        declare(&mut tx, false).await?;
        if apply {
            if !audited {
                audit(
                    &mut tx,
                    EVENT_REVERSE,
                    &json!({
                        "operation": OPERATION,
                        "manifest_sha256": file_sha,
                        "written_before": header.get("written_before"),
                        "edges": n_edges,
                        "records": n_records,
                        "uncommitted_batches": r.uncommitted.len(),
                    }),
                )
                .await?;
                audited = true;
            }
            tx.commit().await?;
            crash_point(step + 1, "reverse");
        } else {
            tx.rollback().await?;
        }
    }
    for (b, e, n) in &r.uncommitted {
        writeln!(
            out,
            "UNCOMMITTED-BATCH\t{b}\tedges={e}\trecords={n}\t(no commit line: not reversed. \
             Its transaction rolled back, unless the run died between that commit and the \
             manifest write; check those edges' labels by hand)"
        )?;
    }
    writeln!(
        out,
        "{}REVERSED\tedges_restored={}\tedges_held={}\trecords_deleted={}\trecords_held={}",
        if apply { "" } else { "WOULD BE " },
        r.restored,
        r.held,
        r.records_deleted,
        r.records_held
    )?;
    if !apply {
        writeln!(out, "DRY RUN: the reversal was rolled back.")?;
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed() -> Report {
        Report {
            batch_failures: vec!["paper-asserts-claim batch 7 COMMITTED, but ...".into()],
            ..Report::default()
        }
    }

    /// A batch that committed without its `committed_batch` line: the FIRST
    /// `NEXT` line names the line to append to this manifest, before the
    /// resume / reverse line (whose reversal would otherwise leave that
    /// batch's stamps and records in place).
    #[test]
    fn a_missing_commit_line_is_the_first_next_step() {
        let m = Path::new("/tmp/run-1.jsonl");
        let next = next_steps(&failed(), Some(7), false, m);
        assert_eq!(
            next.first().map(String::as_str),
            Some(
                "first: append the line {\"committed_batch\": 7} to /tmp/run-1.jsonl (batch 7 \
                 committed; without that line the reversal below leaves its stamps and records)"
            ),
            "{next:#?}"
        );
        assert!(next[1].starts_with("resume: "), "{next:#?}");
        assert!(
            next[1].ends_with(
                "Or undo this run: epigraph-operator reverse-ingest-markers --manifest \
                 /tmp/run-1.jsonl --apply"
            ),
            "{next:#?}"
        );
        assert_eq!(next.len(), 2, "{next:#?}");
    }

    /// The reversal's refusal names where each leaning stamp sits: not in
    /// the manifest at all, reverse the newer manifest first; in one of its
    /// uncommitted batches, that batch and both remedies (a newer manifest
    /// first, or the batch's `committed_batch` line when no newer run
    /// stamped it). Each group's advice appears only with that group.
    #[test]
    fn the_refusal_gives_each_leaning_stamp_its_remedy() {
        let m = Path::new("/tmp/run-1.jsonl");
        let head = "/tmp/run-1.jsonl cannot be reversed yet: 1 stamped paper assertion(s) \
                    outside its committed batches rest on the ingest records those batches \
                    wrote (one record per paper, claim and principal). Nothing was done.";
        let newer = " 1 not in this manifest: edge A. A newer run stamped them: reverse the \
                     newer manifest that stamped them first, then this one.";
        let own = " 1 in this manifest's uncommitted batch 7 (lines but no committed_batch \
                   line): edge B. If a newer manifest lists them, reverse that newer manifest \
                   first, then this one. If none does, batch 7 committed before the run wrote \
                   its line (the run was killed after that COMMIT): check that batch 7's edges \
                   are all stamped, append the line {\"committed_batch\": 7} to \
                   /tmp/run-1.jsonl, then reverse this manifest again.";
        let outside = vec!["edge A".to_string()];
        let in_7 = BTreeMap::from([(7, vec!["edge B".to_string()])]);
        assert_eq!(
            leaning_refusal(m, 1, &outside, &BTreeMap::new()),
            format!("{head}{newer}")
        );
        assert_eq!(leaning_refusal(m, 1, &[], &in_7), format!("{head}{own}"));
        let both = leaning_refusal(m, 2, &outside, &in_7);
        assert_eq!(
            both,
            format!("{}{newer}{own}", head.replace(": 1 stamped", ": 2 stamped"))
        );
    }

    /// Without a missing line there is no `first:` step, and a clean run has
    /// no `NEXT` line at all.
    #[test]
    fn no_first_step_without_a_missing_commit_line() {
        let m = Path::new("/tmp/run-1.jsonl");
        let next = next_steps(&failed(), None, true, m);
        assert!(next[0].starts_with("resume: "), "{next:#?}");
        assert!(next.iter().all(|l| !l.starts_with("first:")), "{next:#?}");
        assert!(next[1].contains("--lock-timeout"), "{next:#?}");
        assert!(next_steps(&Report::default(), Some(7), false, m).is_empty());
    }
}
