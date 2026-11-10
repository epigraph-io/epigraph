//! `backfill-ingest-markers`: stamp the document ingest's marker onto the
//! ingest-shaped edges written before the marker existed, so every provenance
//! reader (the agent card's counts, `query_paper`, a claim's `authored_by`,
//! the walk's own dedup probe) reads them again; and `reverse-ingest-markers`,
//! its exact reversal from the run's manifest.
//!
//! # What is stamped
//!
//! Every PRE-MARKER edge (no `properties.ingest_written`, no backfill label
//! yet), in force or retracted, of these shapes:
//!
//! * `agent -authored-> paper` (a document's authors);
//! * `paper -asserts-> claim` (the claims a document states);
//! * `agent -asserts-> claim` only where it closes a legacy TRIANGLE: the same
//!   agent has a pre-marker `authored` edge onto a paper whose pre-marker
//!   `asserts` edge points at the same claim. The agent card credits a claim
//!   to an author only through that chain (authored, paper asserts, agent
//!   asserts, all marked by one principal), so the third edge is needed; an
//!   agent `asserts` edge with no such paper is some other writer's and stays
//!   unmarked. The workflow executor's attributions
//!   (`properties.source = 'workflow_attribution'`) are never stamped.
//!
//! # Who `by` names
//!
//! Each edge's own SIGNER, when a real ingesting agent signed it. Every other
//! pre-marker edge (unsigned, or signed by a bulk attestation identity) names
//! the ONE registered `legacy-ingest` system principal, so all of them read as
//! one ingest. Signers are classified explicitly: every distinct signer of a
//! candidate edge must be listed as `--ingest-signer` or
//! `--attestation-signer`, and `--apply` refuses while any is not. The dry run
//! lists each signer with its name, type and count.
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
//! # Creation records
//!
//! A claim reads as LITERATURE (its document's authors are its authors) only
//! through a `paper -ingested_claim-> claim` record with `created_claim: true`
//! whose ingester is the claim's filer and whose own paper assertion is
//! marked by the same principal. A legacy claim gets one only where the
//! paper's ingest PROVABLY created it, from the data:
//!
//! * the paper's `asserts` edge onto it is in force and signed by a real
//!   ingesting agent S (never `legacy-ingest`: the reader requires the
//!   record's ingester to be the claim's filer);
//! * S filed the claim (`claims.agent_id = S`);
//! * the claim's OWN reasoning trace (`claims.trace_id`, on that claim) is the
//!   document ingest's extraction trace of THIS paper ("Extracted from ...
//!   (DOI: <the paper's doi>)"), written within [`CREATION_WINDOW`] of the
//!   claim itself: the walk hangs that trace only on a claim it creates, in
//!   the same transaction;
//! * the claim carries no workflow stamp (`step_lineage_id`), has no creation
//!   record yet, and the paper has an in-force authorship signed by S (the
//!   record's primary authors are S's authorship rows, in position order).
//!
//! Everything else gets no record and keeps reading as filed by its agent.
//! The residue this cannot exclude: S filed the claim itself (no trace),
//! and an early walk of S's own document converged on it within the window
//! and hung its trace on it. Both acts are S's own.
//!
//! # Run shape (as `restrict-claims`)
//!
//! Maintenance DSN only. A dry run is READ-ONLY: it prints the census (no
//! UPDATE, no WAL). `--apply` needs `--confirm-count` (the dry run's edge
//! total), `--ruling`, `--reason` and `--manifest-out`; it refuses unless
//! migration 208's guard is installed and `legacy-ingest` is registered.
//! Batches of `--batch-size` edges, each in its own transaction under
//! `lock_timeout`; the manifest records each batch's edges (and `by`) and is
//! `fsync`ed BEFORE that batch's UPDATE. One `security_events` row per run,
//! written in the first batch that changes anything.
//!
//! # Reversal
//!
//! `reverse-ingest-markers --manifest <file>`: removes exactly the two labels
//! each recorded edge was given, only while it still carries them (a
//! compare-and-swap), and deletes each creation record the run wrote while it
//! is still the run's. One audit row.

use anyhow::{anyhow, bail, Context};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Acquire, PgConnection};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use epigraph_db::ingest_written::{
    INGEST_WRITTEN_BY_LABEL_PREFIX, INGEST_WRITTEN_LABEL, INGEST_WRITTEN_PROPERTY,
    INGEST_WRITTEN_SETTING,
};

/// The manifest header's `operation`.
pub const OPERATION: &str = "backfill-ingest-markers";
/// `security_events.event_type` of an applied run.
pub const EVENT_APPLY: &str = "ingest_marker.backfill";
/// `security_events.event_type` of an applied reversal.
pub const EVENT_REVERSE: &str = "ingest_marker.backfill_reverse";
/// The `tool` / `pipeline` of the creation records this writes.
pub const TOOL: &str = "backfill-ingest-markers";
pub const PIPELINE: &str = "legacy-backfill";
/// How long after a claim its extraction trace may be written and still
/// prove the claim was created by that extraction (the walk writes both in
/// one transaction; a document's planning and persistence fit well inside).
pub const CREATION_WINDOW: &str = "10 minutes";
/// The manifest format version.
pub const VERSION: i64 = 1;

/// The three stamped shapes, in the order a run stamps them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Authored,
    PaperAsserts,
    AgentAsserts,
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

    /// SQL: edge `e` is a candidate of this shape (pre-marker, not yet
    /// stamped; any state).
    #[must_use]
    pub fn candidate_sql(self) -> String {
        let shape = match self {
            Kind::Authored => "e.source_type = 'agent' AND e.relationship = 'authored' \
                 AND e.target_type = 'paper'"
                .to_string(),
            Kind::PaperAsserts => "e.source_type = 'paper' AND e.relationship = 'asserts' \
                 AND e.target_type = 'claim'"
                .to_string(),
            Kind::AgentAsserts => format!(
                "e.source_type = 'agent' AND e.relationship = 'asserts' \
                 AND e.target_type = 'claim' \
                 AND COALESCE(e.properties ->> 'source', '') <> 'workflow_attribution' \
                 AND EXISTS (SELECT 1 FROM edges ea \
                               JOIN edges pa ON pa.source_id = ea.target_id \
                              WHERE ea.source_id = e.source_id AND ea.source_type = 'agent' \
                                AND ea.relationship = 'authored' AND ea.target_type = 'paper' \
                                AND NOT (ea.properties ? '{INGEST_WRITTEN_PROPERTY}') \
                                AND pa.source_type = 'paper' AND pa.relationship = 'asserts' \
                                AND pa.target_type = 'claim' AND pa.target_id = e.target_id \
                                AND NOT (pa.properties ? '{INGEST_WRITTEN_PROPERTY}'))"
            ),
        };
        format!(
            "({shape} AND NOT (e.properties ? '{INGEST_WRITTEN_PROPERTY}') \
              AND NOT (e.labels @> ARRAY['{INGEST_WRITTEN_LABEL}']::text[]))"
        )
    }
}

/// SQL: the `by` edge `e` is stamped with. `$L` is the legacy principal,
/// `$A` the attestation signers.
fn by_sql(l: &str, a: &str) -> String {
    format!(
        "(CASE WHEN e.signer_id IS NULL OR e.signer_id = ANY({a}) THEN {l} \
               ELSE e.signer_id END)"
    )
}

/// Everything the verb was told.
#[derive(Clone, Debug)]
pub struct Options {
    pub apply: bool,
    pub confirm_count: Option<u64>,
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
    pub count: i64,
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
    /// unclassified-signer).
    pub per_kind: BTreeMap<Kind, [i64; 6]>,
    pub signers: Vec<Signer>,
    /// Legacy triangles (agent authored P, P asserts C, agent asserts C).
    pub triangles: i64,
    /// Triangles whose three edges would name different principals.
    pub split_triangles: i64,
    /// Claims whose creation record is provable (module doc).
    pub provable_records: i64,
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

    #[must_use]
    pub fn unclassified(&self, o: &Options) -> Vec<Uuid> {
        self.signers
            .iter()
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

/// SQL: claim records provable for edge alias `pa` (a paper `asserts`
/// candidate). `$A` = attestation signers.
fn provable_record_sql(a: &str) -> String {
    format!(
        "pa.source_type = 'paper' AND pa.relationship = 'asserts' AND pa.target_type = 'claim' \
         AND NOT (pa.properties ? '{INGEST_WRITTEN_PROPERTY}') \
         AND (pa.valid_to IS NULL OR pa.valid_to > now()) \
         AND pa.signer_id IS NOT NULL AND NOT (pa.signer_id = ANY({a})) \
         AND c.agent_id = pa.signer_id \
         AND c.step_lineage_id IS NULL \
         AND t.claim_id = c.id \
         AND t.explanation LIKE 'Extracted from %' \
         AND strpos(t.explanation, '(DOI: ' || p.doi || ')') > 0 \
         AND t.created_at >= c.created_at \
         AND t.created_at <= c.created_at + interval '{CREATION_WINDOW}' \
         AND NOT EXISTS (SELECT 1 FROM edges r \
                          WHERE r.target_id = c.id AND r.target_type = 'claim' \
                            AND r.relationship = 'ingested_claim' \
                            AND (r.properties ->> 'created_claim') = 'true') \
         AND EXISTS (SELECT 1 FROM edges ea \
                      WHERE ea.target_id = pa.source_id AND ea.target_type = 'paper' \
                        AND ea.source_type = 'agent' AND ea.relationship = 'authored' \
                        AND NOT (ea.properties ? '{INGEST_WRITTEN_PROPERTY}') \
                        AND ea.signer_id = pa.signer_id \
                        AND (ea.valid_to IS NULL OR ea.valid_to > now()))"
    )
}

const PROVABLE_FROM: &str = "FROM edges pa \
      JOIN claims c ON c.id = pa.target_id \
      JOIN papers p ON p.id = pa.source_id \
      JOIN reasoning_traces t ON t.id = c.trace_id";

/// The read-only census.
///
/// # Errors
/// A statement failed (including `statement_timeout`).
pub async fn census(conn: &mut PgConnection, o: &Options) -> anyhow::Result<Census> {
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
            kind.candidate_sql()
        ))
        .bind(&o.attestation_signers)
        .bind(&o.ingest_signers)
        .fetch_one(&mut *tx)
        .await?;
        c.per_kind
            .insert(kind, [row.0, row.1, row.2, row.3, row.4, row.5]);
    }
    let preds: Vec<String> = Kind::ALL.iter().map(|k| k.candidate_sql()).collect();
    let rows: Vec<(Uuid, Option<String>, Option<String>, Option<String>, i64)> =
        sqlx::query_as(&format!(
            "SELECT e.signer_id, a.display_name, a.agent_type::text, a.key_kind::text, count(*) \
               FROM edges e LEFT JOIN agents a ON a.id = e.signer_id \
              WHERE e.signer_id IS NOT NULL AND (({}) OR ({}) OR ({})) \
              GROUP BY 1, 2, 3, 4 ORDER BY count(*) DESC, 1",
            preds[0], preds[1], preds[2]
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
        .map(|(id, display_name, agent_type, key_kind, count)| Signer {
            id,
            display_name,
            agent_type,
            key_kind,
            system_role: roles.iter().find(|(a, _)| *a == id).map(|(_, r)| r.clone()),
            count,
        })
        .collect();
    let legacy = c.legacy_principal.unwrap_or(Uuid::nil());
    let by_e = by_sql("$1", "$2");
    let (triangles, split): (i64, i64) = sqlx::query_as(&format!(
        "SELECT count(*), count(*) FILTER (WHERE NOT (b_e = b_ea AND b_e = b_pa)) FROM ( \
            SELECT {by_e} AS b_e, \
                   (SELECT {by_ea} FROM edges ea2 WHERE ea2.id = x.ea) AS b_ea, \
                   (SELECT {by_pa} FROM edges pa2 WHERE pa2.id = x.pa) AS b_pa \
              FROM edges e \
              CROSS JOIN LATERAL ( \
                    SELECT ea.id AS ea, pa.id AS pa FROM edges ea \
                      JOIN edges pa ON pa.source_id = ea.target_id \
                     WHERE ea.source_id = e.source_id AND ea.source_type = 'agent' \
                       AND ea.relationship = 'authored' AND ea.target_type = 'paper' \
                       AND NOT (ea.properties ? '{INGEST_WRITTEN_PROPERTY}') \
                       AND pa.source_type = 'paper' AND pa.relationship = 'asserts' \
                       AND pa.target_type = 'claim' AND pa.target_id = e.target_id \
                       AND NOT (pa.properties ? '{INGEST_WRITTEN_PROPERTY}') \
                     ORDER BY ea.created_at, pa.created_at LIMIT 1) x \
             WHERE {cand}) t",
        by_ea = by_sql("$1", "$2").replace("e.signer_id", "ea2.signer_id"),
        by_pa = by_sql("$1", "$2").replace("e.signer_id", "pa2.signer_id"),
        cand = Kind::AgentAsserts.candidate_sql(),
    ))
    .bind(legacy)
    .bind(&o.attestation_signers)
    .fetch_one(&mut *tx)
    .await?;
    c.triangles = triangles;
    c.split_triangles = split;
    c.provable_records = sqlx::query_scalar(&format!(
        "SELECT count(DISTINCT c.id) {PROVABLE_FROM} WHERE {}",
        provable_record_sql("$1")
    ))
    .bind(&o.attestation_signers)
    .fetch_one(&mut *tx)
    .await?;
    tx.rollback().await?;
    Ok(c)
}

/// The census as report lines (ids included: an operator's terminal, never a
/// public document).
#[must_use]
pub fn describe(c: &Census, o: &Options) -> Vec<String> {
    let mut out = vec![format!(
        "SCHEMA\tguard_208={}\tlegacy_ingest={}\treserved_labels_present={}",
        if c.guard_installed {
            "installed"
        } else {
            "MISSING"
        },
        c.legacy_principal
            .map_or_else(|| "NOT-REGISTERED".to_string(), |u| u.to_string()),
        c.reserved_labels_present
    )];
    for (k, v) in &c.per_kind {
        out.push(format!(
            "KIND\t{}\tcandidates={}\tin_force={}\tunsigned={}\tattestation={}\tingest_signed={}\tunclassified={}",
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
            "attestation->legacy-ingest"
        } else if o.ingest_signers.contains(&s.id) {
            "ingest->self"
        } else {
            "UNCLASSIFIED"
        };
        out.push(format!(
            "SIGNER\t{}\tname={}\tagent_type={}\tkey_kind={}\tsystem_role={}\tedges={}\t{class}",
            s.id,
            s.display_name.as_deref().unwrap_or(""),
            s.agent_type.as_deref().unwrap_or(""),
            s.key_kind.as_deref().unwrap_or(""),
            s.system_role.as_deref().unwrap_or(""),
            s.count
        ));
    }
    out.push(format!(
        "TRIANGLES\tlegacy={}\tsplit_by_principal={} (these still read 0 on the card: their \
         three edges name different principals)",
        c.triangles, c.split_triangles
    ));
    out.push(format!(
        "CREATION-RECORDS\tprovable={}{}",
        c.provable_records,
        if o.creation_records {
            ""
        } else {
            "\t(skipped: --no-creation-records)"
        }
    ));
    out.push(format!("TOTAL\tedges_to_stamp={}", c.total()));
    out
}

/// What a run did.
#[derive(Debug, Default)]
pub struct Report {
    pub stamped: BTreeMap<Kind, u64>,
    pub records: u64,
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

/// Run the backfill (dry run: the census only).
///
/// # Errors
/// A refusal before any write, or a statement / manifest failure.
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
            "DRY RUN: read-only; nothing was written. --apply --confirm-count {} \
             --manifest-out <file> --ruling <text> --reason <text> stamps the edges above.",
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
            "refusing --apply: {} signer(s) of candidate edges are not classified as \
             --ingest-signer or --attestation-signer: {}. Nothing was written",
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
    let path = o.manifest_out.as_ref().expect("validated");
    let header = json!({
        "manifest": OPERATION,
        "version": VERSION,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "session_user": session_user,
        "legacy_principal": legacy,
        "attestation_signers": o.attestation_signers,
        "ingest_signers": o.ingest_signers,
        "ruling": o.ruling,
        "reason": o.reason,
        "plan": {
            "edges": c.total(),
            "triangles": c.triangles,
            "split_triangles": c.split_triangles,
            "provable_records": c.provable_records,
        },
    });
    let header_sha = sha256_hex(serde_json::to_string(&header)?.as_bytes());
    let mut manifest = ManifestOut::create(path, &header)?;
    let mut audited = false;
    let by_e = by_sql("$1", "$2");
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
            let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(&format!(
                "SELECT e.id, {by_e} FROM edges e \
                  WHERE {} AND e.id > $3 ORDER BY e.id LIMIT $4 FOR UPDATE OF e",
                kind.candidate_sql()
            ))
            .bind(legacy)
            .bind(&o.attestation_signers)
            .bind(last)
            .bind(i64::try_from(o.batch_size).unwrap_or(i64::MAX))
            .fetch_all(&mut *tx)
            .await?;
            let Some((max_id, _)) = rows.last().copied() else {
                tx.rollback().await?;
                break;
            };
            report.batches += 1;
            manifest.append(
                &rows
                    .iter()
                    .map(|(id, by)| json!({"edge": id, "by": by, "kind": kind.as_str()}))
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
                if !audited {
                    audit(
                        &mut tx,
                        EVENT_APPLY,
                        &json!({
                            "operation": OPERATION,
                            "manifest_header_sha256": header_sha,
                            "legacy_principal": legacy,
                            "plan_edges": c.total(),
                            "ruling": o.ruling,
                            "reason": o.reason,
                            "session_user": session_user,
                        }),
                    )
                    .await?;
                }
                Ok(n)
            }
            .await;
            match result {
                Ok(n) => {
                    tx.commit().await?;
                    audited = true;
                    *report.stamped.entry(kind).or_default() += n;
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
    if report.batch_failures.is_empty() && o.creation_records {
        write_records(
            conn,
            o,
            &mut manifest,
            &mut report,
            audited,
            &header_sha,
            legacy,
        )
        .await?;
    }
    for (k, n) in &report.stamped {
        writeln!(out, "STAMPED\t{}\t{n}", k.as_str())?;
    }
    writeln!(out, "CREATION-RECORDS-WRITTEN\t{}", report.records)?;
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

async fn write_records(
    conn: &mut PgConnection,
    o: &Options,
    manifest: &mut ManifestOut,
    report: &mut Report,
    mut audited: bool,
    header_sha: &str,
    legacy: Uuid,
) -> anyhow::Result<()> {
    let candidates: Vec<(Uuid, Uuid, Uuid)> = sqlx::query_as(&format!(
        "SELECT DISTINCT ON (c.id) pa.source_id, c.id, c.agent_id {PROVABLE_FROM} \
          WHERE {} ORDER BY c.id, pa.created_at, pa.id",
        provable_record_sql("$1")
    ))
    .bind(&o.attestation_signers)
    .fetch_all(&mut *conn)
    .await?;
    for chunk in candidates.chunks(o.batch_size.max(1)) {
        if o.max_batches.is_some_and(|m| report.batches >= m) {
            break;
        }
        report.batches += 1;
        let mut tx = conn.begin().await?;
        sqlx::query("SELECT set_config('lock_timeout', $1, true)")
            .bind(&o.lock_timeout)
            .execute(&mut *tx)
            .await?;
        let mut lines = Vec::new();
        for (paper, claim, by) in chunk {
            let authors: Vec<Uuid> = sqlx::query_scalar(
                "SELECT ea.source_id FROM edges ea \
                  WHERE ea.target_id = $1 AND ea.target_type = 'paper' \
                    AND ea.source_type = 'agent' AND ea.relationship = 'authored' \
                    AND ea.signer_id = $2 AND (ea.valid_to IS NULL OR ea.valid_to > now()) \
                  ORDER BY CASE WHEN ea.properties ->> 'position' ~ '^[0-9]{1,9}$' \
                                THEN (ea.properties ->> 'position')::bigint END NULLS LAST, \
                           ea.created_at, ea.id",
            )
            .bind(paper)
            .bind(by)
            .fetch_all(&mut *tx)
            .await?;
            let wrote = epigraph_db::ClaimIngestRepository::record_signed_conn(
                &mut tx, None, *paper, *claim, *by, true, &authors, TOOL, PIPELINE,
            )
            .await
            .map_err(|e| anyhow!("creation record for claim {claim}: {e}"))?;
            if !wrote {
                continue;
            }
            let id: Uuid = sqlx::query_scalar(&format!(
                "SELECT e.id FROM edges e \
                  WHERE e.source_id = $1 AND e.target_id = $2 \
                    AND e.relationship = 'ingested_claim' \
                    AND e.properties -> '{INGEST_WRITTEN_PROPERTY}' ->> 'tool' = $3 \
                    AND e.properties ->> 'ingested_by' = $4"
            ))
            .bind(paper)
            .bind(claim)
            .bind(TOOL)
            .bind(by.to_string())
            .fetch_one(&mut *tx)
            .await?;
            lines.push(json!({"record": id, "paper": paper, "claim": claim, "by": by}));
        }
        if !audited && !lines.is_empty() {
            audit(
                &mut tx,
                EVENT_APPLY,
                &json!({
                    "operation": OPERATION,
                    "manifest_header_sha256": header_sha,
                    "legacy_principal": legacy,
                    "ruling": o.ruling,
                    "reason": o.reason,
                }),
            )
            .await?;
            audited = true;
        }
        // Post records: fsynced before the commit they describe. A failed
        // commit leaves ids that do not exist, which reversal skips.
        manifest.append(&lines)?;
        tx.commit().await?;
        report.records += lines.len() as u64;
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
}

/// Reverse a backfill run from its manifest (dry run: rolled back).
///
/// # Errors
/// The manifest is not a backfill manifest, or a statement failed.
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
    let mut edges: Vec<(Uuid, Uuid)> = Vec::new();
    let mut records: Vec<Uuid> = Vec::new();
    for line in lines {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(&line)?;
        let uuid = |k: &str| -> anyhow::Result<Uuid> {
            Uuid::parse_str(
                v.get(k)
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("manifest line lacks {k}: {line}"))?,
            )
            .with_context(|| format!("{k} is not a uuid"))
        };
        if v.get("edge").is_some() {
            if let Some(k) = v.get("kind").and_then(Value::as_str) {
                Kind::parse(k).ok_or_else(|| anyhow!("unknown kind {k}"))?;
            }
            edges.push((uuid("edge")?, uuid("by")?));
        } else if v.get("record").is_some() {
            records.push(uuid("record")?);
        } else {
            bail!("unrecognised manifest line: {line}");
        }
    }
    let mut r = ReverseReport::default();
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
                   AND e.relationship = 'ingested_claim' \
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
                        "edges": edges.len(),
                        "records": records.len(),
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
