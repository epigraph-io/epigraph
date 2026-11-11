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
//! every paper assertion a run stamps gets a record of its principal, written
//! by that same run (unless that principal already has one):
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
//! and `legacy-ingest` is registered. Batches of `--batch-size` edges (then
//! records), each in its own transaction under `lock_timeout`; the manifest
//! records each batch's lines (tagged with the batch number) and is `fsync`ed
//! BEFORE that batch's write, then gets a `committed_batch` line AFTER its
//! commit. One `security_events` row per run, written in the first batch that
//! changes anything.
//!
//! A run writes the records of exactly the paper assertions IT stamped and
//! committed, after its edge batches, whatever stopped them: `--max-batches`
//! bounds the edge batches only, and a failed edge batch still leaves the
//! committed ones their records. So after every run, and after reversing any
//! one run's manifest, `query_paper` and `get_claim`'s `ingesters` agree. A
//! failed record batch is reported as `BATCH-FAILED` (exit 2) as a failed edge
//! batch is, and the summary still prints; that run's stamps then lack
//! records, and no later run adopts them, so reverse that run before resuming.
//! A resumed run (a new manifest) must use the same `--written-before` and the
//! same `--ingest-signer` / `--attestation-signer` lists as the first: they
//! decide every paper's principal.
//!
//! # Reversal
//!
//! `reverse-ingest-markers --manifest <file>`: acts only on the batches the
//! manifest records as COMMITTED (a batch whose lines were written but whose
//! commit failed is reported, never reversed). Removes exactly the two labels
//! each recorded edge was given, only while it still carries them (a
//! compare-and-swap), and deletes each record the run wrote while it is
//! still the run's. One audit row.

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
/// The manifest format version: every line carries its batch, and each
/// committed batch has a `committed_batch` line.
pub const VERSION: i64 = 2;
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
                "{e}.source_type = 'agent' AND {e}.relationship = 'asserts' \
                 AND {e}.target_type = 'claim' \
                 AND COALESCE({e}.properties ->> 'source', '') <> 'workflow_attribution' \
                 AND EXISTS (SELECT 1 {})",
                self.chain_from(e)
            ),
        };
        format!(
            "({shape} AND {} \
              AND NOT ({e}.labels @> ARRAY['{INGEST_WRITTEN_LABEL}']::text[]))",
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
/// predicate on `pa`, `$2` onward).
fn provable_from(f: &Frame, scope: &str) -> String {
    format!(
        "WITH {} SELECT {{cols}} FROM edges pa \
           JOIN claims c ON c.id = pa.target_id \
           JOIN papers p ON p.id = pa.source_id \
           JOIN reasoning_traces t ON t.id = c.trace_id \
           LEFT JOIN pp ON pp.paper = pa.source_id \
          WHERE {} {scope}",
        f.pp_cte("$1::uuid[]", None),
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
    let legacy = c.legacy_principal.unwrap_or(Uuid::nil());
    c.reserved_labels_present = sqlx::query_scalar(
        "SELECT count(*) FROM edges e \
          WHERE EXISTS (SELECT 1 FROM unnest(e.labels) l WHERE l LIKE 'epigraph:%')",
    )
    .fetch_one(&mut *tx)
    .await?;
    for kind in Kind::ALL {
        let row: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(&format!(
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
        ))
        .bind(&o.attestation_signers)
        .bind(&o.ingest_signers)
        .fetch_one(&mut *tx)
        .await?;
        c.per_kind
            .insert(kind, [row.0, row.1, row.2, row.3, row.4, row.5]);
    }
    let rows: Vec<SignerRow> = sqlx::query_as(&format!(
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
    ))
    .fetch_all(&mut *tx)
    .await?;
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
    let papers_cte = format!(
        "WITH {pp}, papers AS (SELECT e.source_id AS paper FROM edges e WHERE {c1} \
                               UNION SELECT e.target_id FROM edges e WHERE {c0})",
        pp = f.pp_cte("$1::uuid[]", None),
        c0 = f.candidate(Kind::Authored, "e"),
        c1 = f.candidate(Kind::PaperAsserts, "e"),
    );
    let classes: Vec<(String, i64)> = sqlx::query_as(&format!(
        "{papers_cte} \
         SELECT CASE WHEN pp.n = 1 THEN pp.sids[1]::text \
                     WHEN pp.n > 1 THEN 'conflict' ELSE 'legacy' END, count(*) \
           FROM papers LEFT JOIN pp USING (paper) GROUP BY 1 ORDER BY 2 DESC, 1"
    ))
    .bind(&o.ingest_signers)
    .fetch_all(&mut *tx)
    .await?;
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
    c.conflicts = sqlx::query_as(&format!(
        "{papers_cte} \
         SELECT papers.paper, pp.sids FROM papers JOIN pp USING (paper) \
          WHERE pp.n > 1 ORDER BY 1 LIMIT {CONFLICTS_LISTED}"
    ))
    .bind(&o.ingest_signers)
    .fetch_all(&mut *tx)
    .await?;

    // Chains: every (agent assertion, authorship, paper assertion), each pair
    // counted; the chain an agent assertion's principal comes from is the
    // first by CHAIN_ORDER (oldest in-force), as the apply picks it.
    let (chains, other, multi): (i64, i64, i64) = sqlx::query_as(&format!(
        "WITH {pp}, \
         tri AS (SELECT e.id AS e, ea.target_id AS paper, \
                        row_number() OVER (PARTITION BY e.id ORDER BY {CHAIN_ORDER}) AS k \
                   FROM edges e JOIN edges ea ON ea.source_id = e.source_id \
                   JOIN edges pa ON pa.source_id = ea.target_id AND pa.target_id = e.target_id \
                  WHERE {cand} AND {au} AND {lea} AND {pas} AND {lpa}), \
         pr AS (SELECT tri.e, tri.k, {prin} AS principal FROM tri \
                  LEFT JOIN pp ON pp.paper = tri.paper), \
         ch AS (SELECT pr.e, pr.principal FROM pr WHERE pr.k = 1) \
         SELECT (SELECT count(*) FROM pr), \
                (SELECT count(*) FROM pr JOIN ch ON ch.e = pr.e \
                  WHERE pr.principal <> ch.principal), \
                (SELECT count(*) FROM (SELECT pr.e FROM pr GROUP BY pr.e \
                                        HAVING count(DISTINCT pr.principal) > 1) m)",
        pp = f.pp_cte("$2::uuid[]", None),
        cand = f.candidate(Kind::AgentAsserts, "e"),
        au = authored("ea"),
        lea = f.legacy("ea"),
        pas = paper_asserts("pa"),
        lpa = f.legacy("pa"),
        prin = principal("pp", "$1::uuid"),
    ))
    .bind(legacy)
    .bind(&o.ingest_signers)
    .fetch_one(&mut *tx)
    .await?;
    c.chains = chains;
    c.chains_on_another_principal = other;
    c.agent_asserts_multi_principal = multi;

    // A run writes the records of the assertions IT stamps, so the plan
    // counts the candidates only.
    c.provable_records = sqlx::query_scalar(
        &provable_from(
            &f,
            &format!("AND NOT (pa.labels @> ARRAY['{INGEST_WRITTEN_LABEL}']::text[])"),
        )
        .replace("{cols}", "count(DISTINCT c.id)"),
    )
    .bind(&o.ingest_signers)
    .fetch_one(&mut *tx)
    .await?;

    // Every candidate paper assertion with no record of its principal gets
    // one; the provable ones get a creation record instead.
    let pairs: i64 = sqlx::query_scalar(&format!(
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
    ))
    .bind(legacy)
    .bind(&o.ingest_signers)
    .fetch_one(&mut *tx)
    .await?;
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
struct Act<'a> {
    o: &'a Options,
    frame: Frame,
    audit: Value,
    audited: bool,
}

impl Act<'_> {
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
        o,
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
    // The paper assertions this run stamped and committed: the run writes
    // their ingest records, and only theirs.
    let mut run_pa: Vec<Uuid> = Vec::new();
    'kinds: for kind in Kind::ALL {
        let mut last = Uuid::nil();
        loop {
            if o.max_batches.is_some_and(|m| report.batches >= m) {
                break 'kinds;
            }
            let mut tx = conn.begin().await?;
            sqlx::query("SELECT set_config('lock_timeout', $1, true)")
                .bind(&o.lock_timeout)
                .execute(&mut *tx)
                .await?;
            // The batch, locked, then the principal of each edge's paper,
            // decided once per paper of the batch.
            let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(&format!(
                "WITH b AS (SELECT e.id, {paper} AS paper FROM edges e \
                             WHERE {cand} AND e.id > $3 ORDER BY e.id LIMIT $4 \
                               FOR UPDATE OF e), \
                      {pp} \
                 SELECT b.id, {prin} FROM b LEFT JOIN pp ON pp.paper = b.paper ORDER BY b.id",
                paper = act.frame.paper_of(kind, "e"),
                cand = act.frame.candidate(kind, "e"),
                pp = act
                    .frame
                    .pp_cte("$2::uuid[]", Some("(SELECT b.paper FROM b)")),
                prin = principal("pp", "$1::uuid"),
            ))
            .bind(legacy)
            .bind(&o.ingest_signers)
            .bind(last)
            .bind(i64::try_from(o.batch_size).unwrap_or(i64::MAX))
            .fetch_all(&mut *tx)
            .await?;
            let Some((max_id, _)) = rows.last().copied() else {
                tx.rollback().await?;
                break;
            };
            report.batches += 1;
            let batch = report.batches;
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
            let result: anyhow::Result<u64> = async {
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
                act.audit_once(&mut tx).await?;
                Ok(n)
            }
            .await;
            match result {
                Ok(n) => {
                    tx.commit().await?;
                    act.audited = true;
                    manifest.committed(batch)?;
                    *report.stamped.entry(kind).or_default() += n;
                    if kind == Kind::PaperAsserts {
                        run_pa.extend_from_slice(&ids);
                    }
                }
                Err(e) => {
                    tx.rollback().await.ok();
                    report
                        .batch_failures
                        .push(format!("{} batch after {last}: {e}", kind.as_str()));
                    break 'kinds;
                }
            }
            last = max_id;
        }
    }
    // The records of exactly what this run committed, whatever stopped its
    // edge phase (a failed batch, --max-batches): every run leaves
    // query_paper and get_claim's ingesters agreeing on its own stamps, and
    // its manifest reverses exactly those. A record-phase failure is reported
    // as an edge batch's is, and the summary still prints. A run that
    // stamped no paper assertion selects nothing here (never another run's).
    if let Err(e) = write_records(conn, &mut act, &mut manifest, &mut report, &run_pa).await {
        report.batch_failures.push(format!("ingest records: {e:#}"));
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
    Ok(report)
}

/// One record to write: paper, claim, principal, created.
type RecordPlan = (Uuid, Uuid, Uuid, bool);

/// The ingest records of the paper assertions THIS run stamped (`run_pa`,
/// module doc): the provable creation records first, then a non-creation
/// record for every one of them its principal has no record of.
async fn write_records(
    conn: &mut PgConnection,
    act: &mut Act<'_>,
    manifest: &mut ManifestOut,
    report: &mut Report,
    run_pa: &[Uuid],
) -> anyhow::Result<()> {
    let o = act.o;
    let mut plan: Vec<RecordPlan> = Vec::new();
    if o.creation_records {
        // Only over this run's stamps, and only where the stamp names the
        // signer the proof names (the record's ingester is the edge's `by`).
        let sql = format!(
            "{} ORDER BY c.id, pa.created_at, pa.id",
            provable_from(
                &act.frame,
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
            .bind(run_pa)
            .fetch_all(&mut *conn)
            .await?;
        plan.extend(created.into_iter().map(|(p, c, by)| (p, c, by, true)));
    }
    // This run's stamped paper assertions, by the principal their label
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
    .bind(run_pa)
    .fetch_all(&mut *conn)
    .await?;
    let creations: BTreeSet<(Uuid, Uuid, Uuid)> =
        plan.iter().map(|(p, c, by, _)| (*p, *c, *by)).collect();
    plan.extend(
        stamped
            .into_iter()
            .filter(|k| !creations.contains(k))
            .map(|(p, c, by)| (p, c, by, false)),
    );
    let mut authors_of: HashMap<(Uuid, Uuid), Vec<Uuid>> = HashMap::new();
    // Not bounded by --max-batches: a run always writes the records of what
    // it stamped.
    for chunk in plan.chunks(o.batch_size.max(1)) {
        report.batches += 1;
        let batch = report.batches;
        let mut tx = conn.begin().await?;
        let result: anyhow::Result<(Vec<Value>, u64, u64)> = async {
            sqlx::query("SELECT set_config('lock_timeout', $1, true)")
                .bind(&o.lock_timeout)
                .execute(&mut *tx)
                .await?;
            let mut lines = Vec::new();
            let (mut created_n, mut other_n) = (0u64, 0u64);
            for (paper, claim, by, created) in chunk {
                if let Entry::Vacant(slot) = authors_of.entry((*paper, *by)) {
                    // The authorships this principal's ingest of the paper holds
                    // (the authors query_paper(ingested_by = by) lists), in
                    // position order.
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
                    &mut tx, None, *paper, *claim, *by, *created, authors, TOOL, PIPELINE,
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
            if !lines.is_empty() {
                act.audit_once(&mut tx).await?;
            }
            Ok((lines, created_n, other_n))
        }
        .await;
        let (lines, created_n, other_n) = match result {
            Ok(r) => r,
            Err(e) => {
                tx.rollback().await.ok();
                bail!("records batch {batch}: {e:#}");
            }
        };
        // The record lines, fsynced before the commit they describe; the
        // commit line after it.
        manifest.append(&lines)?;
        tx.commit().await?;
        if !lines.is_empty() {
            act.audited = true;
        }
        manifest.committed(batch)?;
        report.records += created_n;
        report.non_creation_records += other_n;
    }
    Ok(())
}

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
/// The manifest is not a backfill manifest of this version, or a statement
/// failed.
#[allow(clippy::too_many_lines)]
pub async fn reverse(
    conn: &mut PgConnection,
    manifest: &Path,
    apply: bool,
    batch_size: usize,
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
    if header.get("version").and_then(Value::as_i64) != Some(VERSION) {
        bail!(
            "{} is a version {} manifest; this binary reverses version {VERSION} only. Nothing \
             was done",
            manifest.display(),
            header.get("version").unwrap_or(&Value::Null)
        );
    }
    let mut edges: Vec<(i64, Uuid, Uuid)> = Vec::new();
    let mut records: Vec<(i64, Uuid)> = Vec::new();
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
            records.push((batch, uuid("record")?));
        } else {
            bail!("unrecognised manifest line: {line}");
        }
    }
    let mut r = ReverseReport::default();
    let mut pending: BTreeMap<i64, (usize, usize)> = BTreeMap::new();
    for (b, ..) in edges.iter().filter(|(b, ..)| !committed.contains(b)) {
        pending.entry(*b).or_default().0 += 1;
    }
    for (b, _) in records.iter().filter(|(b, _)| !committed.contains(b)) {
        pending.entry(*b).or_default().1 += 1;
    }
    r.uncommitted = pending.into_iter().map(|(b, (e, n))| (b, e, n)).collect();
    // Only what the run committed.
    let edges: Vec<(Uuid, Uuid)> = edges
        .into_iter()
        .filter(|(b, ..)| committed.contains(b))
        .map(|(_, e, by)| (e, by))
        .collect();
    let records: Vec<Uuid> = records
        .into_iter()
        .filter(|(b, _)| committed.contains(b))
        .map(|(_, id)| id)
        .collect();
    let mut audited = false;
    // Records first (each names a claim the run's stamped assertion vouches
    // for), then the labels; each chunk in its own transaction, committed
    // under --apply. Every statement is a compare-and-swap, so a re-run, or a
    // run after a partial one, restores only what is still the run's.
    let record_chunks: Vec<&[Uuid]> = records.chunks(batch_size.max(1)).collect();
    let edge_chunks: Vec<&[(Uuid, Uuid)]> = edges.chunks(batch_size.max(1)).collect();
    let total = record_chunks.len() + edge_chunks.len();
    for step in 0..total.max(1) {
        let mut tx = conn.begin().await?;
        sqlx::query("SELECT set_config('lock_timeout', $1, true)")
            .bind(lock_timeout)
            .execute(&mut *tx)
            .await?;
        declare(&mut tx, true).await?;
        if step < record_chunks.len() {
            let chunk = record_chunks[step];
            let n = sqlx::query(&format!(
                "DELETE FROM edges e WHERE e.id = ANY($1) \
                   AND e.relationship = '{INGEST_RECORD_RELATIONSHIP}' \
                   AND e.properties -> '{INGEST_WRITTEN_PROPERTY}' ->> 'tool' = $2"
            ))
            .bind(chunk)
            .bind(TOOL)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            r.records_deleted += n;
            r.records_held += chunk.len() as u64 - n;
        } else if let Some(chunk) = edge_chunks.get(step - record_chunks.len()) {
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
                        "edges": edges.len(),
                        "records": records.len(),
                        "uncommitted_batches": r.uncommitted.len(),
                    }),
                )
                .await?;
                audited = true;
            }
            tx.commit().await?;
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
