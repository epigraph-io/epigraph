//! `set-workflow-submitter`: set or correct the recorded SUBMITTER of listed
//! `workflows` rows, as an audited maintenance act, and the exact reversal of
//! such a run (`set-workflow-submitter --reverse <manifest>`). Backlog
//! 47ebd69a.
//!
//! # What it writes
//!
//! A workflow records its submitter in `metadata.epigraph_submitted_by`
//! (`WorkflowRepository::SUBMITTER_KEY`, batch H-b), written once by
//! `WorkflowRepository::record_submitter` on ingest. Rows written before that
//! batch record none, and nothing else can set or correct one. This verb sets
//! the key to `--submitter` on the selected rows, with
//! `record_submitter`'s exact shape: a `metadata` that is not a JSON object
//! (an extraction can store a JSON `null`) becomes `{}` first.
//!
//! # Selection (exactly one)
//!
//! * `--ids-file F`: workflow ids, one per line;
//! * `--canonical-names-file F`: every generation of each lineage named;
//! * `--without-submitter`: every row that records no submitter.
//!
//! Each selected row is classified under a row lock:
//!
//! * no submitter recorded: WRITE;
//! * already `--submitter`: ALREADY (nothing written);
//! * another submitter (or a value that is not one): HELD, unless
//!   `--force-reassign`, which REASSIGNS it.
//!
//! # The run
//!
//! A dry run by default: it prints the classification and writes nothing.
//! `--apply` needs `--confirm-count` (the dry run's `ELIGIBLE-WORKFLOW-ROWS`),
//! `--ruling`, `--reason` and `--manifest-out`. The whole act is ONE
//! transaction: the rows are locked, the manifest (opened `create_new`) gets
//! its header and every row's PRIOR state and POST value, `fsync`ed, BEFORE
//! the UPDATE; then the UPDATE, then one `security_events` row
//! ([`EVENT_APPLY`]) naming the operator, the ruling, the reason and the
//! counts; then the commit. A failure anywhere rolls everything back, and the
//! manifest then describes a write that never happened, which the reversal
//! treats as nothing to undo.
//!
//! # Reversal
//!
//! A compare-and-swap per recorded row, in one transaction with one
//! [`EVENT_REVERSE`] row: a row still carrying the recorded POST value is put
//! back on its recorded PRIOR state exactly (the prior value of the key, the
//! key removed, or, for a prior `metadata` that was not an object, that whole
//! prior value); a row already at its prior state is counted and left; a row
//! in any other state (another writer changed it since) is HELD and left.
//! `reown-reverse` refuses this manifest and names this verb.

use super::client_scope::Operator;
use super::manifest::Writer;
use anyhow::{anyhow, bail, Context};
use chrono::Utc;
use epigraph_db::{SecurityEventRepository, SecurityEventRow, WorkflowRepository};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Acquire, PgConnection};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// The `operation` this verb's manifest header carries.
pub const OPERATION: &str = "set-workflow-submitter";
/// The record format this build writes and reverses.
pub const RECORD_FORMAT: &str = "set-workflow-submitter/1";
/// `security_events.event_type` of an applied run.
pub const EVENT_APPLY: &str = "operator.workflow_submitter_set";
/// `security_events.event_type` of an applied reversal.
pub const EVENT_REVERSE: &str = "operator.workflow_submitter_reversed";

/// Which rows a run selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    Ids(Vec<Uuid>),
    CanonicalNames(Vec<String>),
    WithoutSubmitter,
}

impl Selection {
    fn describe(&self) -> Value {
        match self {
            Self::Ids(v) => json!({ "kind": "ids", "count": v.len() }),
            Self::CanonicalNames(v) => json!({ "kind": "canonical_names", "names": v }),
            Self::WithoutSubmitter => json!({ "kind": "without_submitter" }),
        }
    }
}

/// A forward run's options.
#[derive(Debug, Clone)]
pub struct Options {
    pub selection: Selection,
    pub submitter: Uuid,
    pub operator: Uuid,
    pub force_reassign: bool,
    pub apply: bool,
    pub confirm_count: Option<usize>,
    pub ruling: String,
    pub reason: String,
    pub manifest_out: Option<PathBuf>,
}

/// Refuse options that cannot describe a valid run, before connecting.
///
/// # Errors
/// An empty selection; under `--apply`, a blank ruling or reason, or no
/// `--confirm-count` or `--manifest-out`.
pub fn validate(opts: &Options) -> anyhow::Result<()> {
    match &opts.selection {
        Selection::Ids(v) if v.is_empty() => bail!("the --ids-file names no workflow"),
        Selection::CanonicalNames(v) if v.is_empty() => {
            bail!("the --canonical-names-file names no lineage")
        }
        _ => {}
    }
    if opts.apply {
        if opts.ruling.trim().is_empty() {
            bail!("--apply requires a non-empty --ruling (recorded in the audit row)");
        }
        if opts.reason.trim().is_empty() {
            bail!("--apply requires a non-empty --reason (recorded in the audit row)");
        }
        if opts.confirm_count.is_none() {
            bail!(
                "--apply requires --confirm-count <N>: the dry run's ELIGIBLE-WORKFLOW-ROWS, \
                 repeated back"
            );
        }
        if opts.manifest_out.is_none() {
            bail!("--apply requires --manifest-out <path> (the undo record, written first)");
        }
    }
    Ok(())
}

/// Workflow ids, one per line; blank lines and `#` comments ignored;
/// duplicates dropped with order kept.
///
/// # Errors
/// The file cannot be read, or a line is not a uuid.
pub fn read_ids_file(path: &Path) -> anyhow::Result<Vec<Uuid>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let id = Uuid::parse_str(t)
            .with_context(|| format!("{}:{}: not a uuid: {t:?}", path.display(), n + 1))?;
        if seen.insert(id) {
            out.push(id);
        }
    }
    Ok(out)
}

/// One selected row as locked.
#[derive(Debug, Clone)]
struct Row {
    id: Uuid,
    canonical_name: String,
    generation: i32,
    metadata: Value,
}

impl Row {
    /// The recorded submitter's raw JSON value, if `metadata` is an object
    /// carrying the key.
    fn submitter_value(&self) -> Option<&Value> {
        self.metadata
            .as_object()
            .and_then(|m| m.get(WorkflowRepository::SUBMITTER_KEY))
    }
}

/// How a selected row is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Write,
    Reassign,
    Already,
    Held,
}

fn classify(row: &Row, submitter: Uuid, force: bool) -> Class {
    match row.submitter_value() {
        None => Class::Write,
        Some(Value::String(s)) if Uuid::parse_str(s).ok() == Some(submitter) => Class::Already,
        Some(_) if force => Class::Reassign,
        Some(_) => Class::Held,
    }
}

/// The prior state of one row, as the manifest records it.
fn prior_json(row: &Row) -> Value {
    match row.metadata.as_object() {
        Some(_) => match row.submitter_value() {
            Some(v) => json!({ "metadata_type": "object", "has_key": true, "value": v }),
            None => json!({ "metadata_type": "object", "has_key": false }),
        },
        // Not an object: the write replaces the whole value, so the whole
        // prior value is the record (it is a scalar, an array or null).
        None => json!({ "metadata_type": "other", "metadata": row.metadata }),
    }
}

async fn lock_rows(conn: &mut PgConnection, sel: &Selection) -> anyhow::Result<Vec<Row>> {
    let base = "SELECT id, canonical_name, generation, metadata FROM workflows WHERE ";
    let order = " ORDER BY canonical_name, generation, id FOR UPDATE";
    let rows: Vec<(Uuid, String, i32, Value)> = match sel {
        Selection::Ids(ids) => sqlx::query_as(&format!("{base}id = ANY($1){order}"))
            .bind(ids)
            .fetch_all(&mut *conn)
            .await
            .context("locking the listed workflows")?,
        Selection::CanonicalNames(names) => {
            sqlx::query_as(&format!("{base}canonical_name = ANY($1){order}"))
                .bind(names)
                .fetch_all(&mut *conn)
                .await
                .context("locking the listed lineages")?
        }
        Selection::WithoutSubmitter => sqlx::query_as(&format!(
            "{base}NOT (jsonb_typeof(metadata) = 'object' AND metadata ? $1){order}"
        ))
        .bind(WorkflowRepository::SUBMITTER_KEY)
        .fetch_all(&mut *conn)
        .await
        .context("locking the workflows with no recorded submitter")?,
    };
    Ok(rows
        .into_iter()
        .map(|(id, canonical_name, generation, metadata)| Row {
            id,
            canonical_name,
            generation,
            metadata,
        })
        .collect())
}

async fn audit(
    conn: &mut PgConnection,
    event_type: &str,
    operator: Uuid,
    details: Value,
) -> anyhow::Result<Uuid> {
    let (client_addr, _) = SecurityEventRepository::connection_origin_conn(conn).await?;
    let id = Uuid::new_v4();
    let row = SecurityEventRow {
        id,
        event_type: event_type.to_string(),
        agent_id: Some(operator),
        success: Some(true),
        details,
        ip_address: client_addr,
        user_agent: None,
        correlation_id: None,
        created_at: Utc::now(),
    };
    SecurityEventRepository::log_conn(conn, &row)
        .await
        .context("writing the audit row")?;
    Ok(id)
}

fn operator_facts(who: &Operator, operator: Uuid) -> Value {
    json!({
        "agent_id": operator,
        "session_user": who.session_user,
        "os_user": who.os_user,
        "os_user_source": "environment (SUDO_USER, USER, LOGNAME): advisory, settable by \
                           the caller",
        "process_uid": who.process_uid,
        "process_user": who.process_user,
        "login_uid": who.login_uid,
        "login_user": who.login_user,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// What a forward run found and did.
#[derive(Debug, Default)]
pub struct Report {
    pub eligible: usize,
    pub reassigned: usize,
    pub already: usize,
    pub held: usize,
    pub not_found: usize,
    pub written: u64,
    pub audit_event_id: Option<Uuid>,
}

/// Exit code of a forward run: 3 when an `--apply` left a selected row
/// unwritten (held, or a listed id or lineage not found), else 0.
#[must_use]
pub fn exit_code(r: &Report, opts: &Options) -> i32 {
    if opts.apply && (r.held > 0 || r.not_found > 0) {
        3
    } else {
        0
    }
}

/// Run the forward act.
///
/// # Errors
/// The submitter is not an agent; the operator is not a live registered
/// human operator; under `--apply`, a count other than `--confirm-count`, an
/// existing manifest path, or a failed statement. Nothing is committed then.
pub async fn run(
    conn: &mut PgConnection,
    opts: &Options,
    who: &Operator,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<Report> {
    validate(opts)?;
    let submitter_known: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM agents WHERE id = $1)")
            .bind(opts.submitter)
            .fetch_one(&mut *conn)
            .await?;
    if !submitter_known {
        bail!(
            "--submitter {} is not an agent; refusing. Nothing was written.",
            opts.submitter
        );
    }
    let operator_live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM human_operators \
                         WHERE agent_id = $1 AND revoked_at IS NULL)",
    )
    .bind(opts.operator)
    .fetch_one(&mut *conn)
    .await?;
    if !operator_live {
        bail!(
            "--operator {} is not a live registered human operator; refusing. Nothing was \
             written.",
            opts.operator
        );
    }

    let mut tx = conn.begin().await.context("beginning the transaction")?;
    let rows = lock_rows(&mut tx, &opts.selection).await?;
    let mut report = Report::default();
    match &opts.selection {
        Selection::Ids(ids) => {
            let found: BTreeSet<Uuid> = rows.iter().map(|r| r.id).collect();
            for id in ids.iter().filter(|i| !found.contains(i)) {
                writeln!(out, "NOT-FOUND\tworkflow={id}")?;
                report.not_found += 1;
            }
        }
        Selection::CanonicalNames(names) => {
            let found: BTreeSet<&str> = rows.iter().map(|r| r.canonical_name.as_str()).collect();
            for n in names.iter().filter(|n| !found.contains(n.as_str())) {
                writeln!(out, "NOT-FOUND\tcanonical_name={n}")?;
                report.not_found += 1;
            }
        }
        Selection::WithoutSubmitter => {}
    }
    let mut to_write: Vec<&Row> = Vec::new();
    for r in &rows {
        let class = classify(r, opts.submitter, opts.force_reassign);
        let prior = r
            .submitter_value()
            .map_or_else(|| "none".to_string(), Value::to_string);
        let tag = match class {
            Class::Write => "WRITE",
            Class::Reassign => "REASSIGN",
            Class::Already => "ALREADY",
            Class::Held => "HELD",
        };
        writeln!(
            out,
            "{tag}\tworkflow={}\tcanonical_name={}\tgeneration={}\tsubmitter={prior}{}",
            r.id,
            r.canonical_name,
            r.generation,
            if class == Class::Held {
                "\t(another submitter is recorded; --force-reassign replaces it)"
            } else {
                ""
            }
        )?;
        match class {
            Class::Write => to_write.push(r),
            Class::Reassign => {
                report.reassigned += 1;
                to_write.push(r);
            }
            Class::Already => report.already += 1,
            Class::Held => report.held += 1,
        }
    }
    report.eligible = to_write.len();
    writeln!(
        out,
        "ELIGIBLE-WORKFLOW-ROWS\t{}\nREASSIGN-COUNT\t{}\nALREADY-COUNT\t{}\nHELD-COUNT\t{}\n\
         NOT-FOUND-COUNT\t{}",
        report.eligible, report.reassigned, report.already, report.held, report.not_found
    )?;
    if !opts.apply {
        tx.rollback().await?;
        writeln!(out, "DRY RUN: nothing was written.")?;
        return Ok(report);
    }
    let confirm = opts.confirm_count.expect("validated");
    if confirm != report.eligible {
        tx.rollback().await?;
        bail!(
            "--confirm-count {confirm} is not this run's ELIGIBLE-WORKFLOW-ROWS {}; refusing. \
             Nothing was written.",
            report.eligible
        );
    }
    if to_write.is_empty() {
        tx.rollback().await?;
        writeln!(
            out,
            "NOTHING TO DO: no selected row needs a write; no manifest or audit row."
        )?;
        return Ok(report);
    }

    let path = opts.manifest_out.as_ref().expect("validated");
    let header = json!({
        "manifest": OPERATION,
        "operation": OPERATION,
        "record_format": RECORD_FORMAT,
        "created_at": Utc::now().to_rfc3339(),
        "submitter": opts.submitter,
        "operator": opts.operator,
        "selection": opts.selection.describe(),
        "force_reassign": opts.force_reassign,
        "ruling": opts.ruling.trim(),
        "reason": opts.reason.trim(),
    });
    let mut w = Writer::create_new(path, &header)?;
    let post = opts.submitter.to_string();
    let records: Vec<Value> = to_write
        .iter()
        .map(|r| json!({ "workflow_id": r.id, "prior": prior_json(r), "post": post }))
        .collect();
    w.append_values(&records)?;

    let ids: Vec<Uuid> = to_write.iter().map(|r| r.id).collect();
    let written = sqlx::query(
        // `record_submitter`'s shape, without its write-once guard.
        "UPDATE workflows \
            SET metadata = jsonb_set( \
                    CASE WHEN jsonb_typeof(metadata) = 'object' THEN metadata \
                         ELSE '{}'::jsonb END, \
                    ARRAY[$2], to_jsonb($3::text)) \
          WHERE id = ANY($1)",
    )
    .bind(&ids)
    .bind(WorkflowRepository::SUBMITTER_KEY)
    .bind(&post)
    .execute(&mut *tx)
    .await
    .context("UPDATE workflows")?
    .rows_affected();
    if usize::try_from(written).ok() != Some(ids.len()) {
        bail!(
            "UPDATE workflows wrote {written} row(s), {} were locked for it; rolled back",
            ids.len()
        );
    }
    report.written = written;
    let header_line = serde_json::to_string(&header)?;
    report.audit_event_id = Some(
        audit(
            &mut tx,
            EVENT_APPLY,
            opts.operator,
            json!({
                "tool": "epigraph-operator",
                "command": OPERATION,
                "operator": operator_facts(who, opts.operator),
                "ruling": opts.ruling.trim(),
                "reason": opts.reason.trim(),
                "submitter": opts.submitter,
                "selection": opts.selection.describe(),
                "force_reassign": opts.force_reassign,
                "counts": {
                    "written": written,
                    "reassigned": report.reassigned,
                    "already": report.already,
                    "held": report.held,
                    "not_found": report.not_found,
                },
                "manifest_path": path.display().to_string(),
                "manifest_header_sha256": sha256_hex(header_line.as_bytes()),
            }),
        )
        .await?,
    );
    tx.commit().await.context("committing")?;
    writeln!(
        out,
        "APPLIED\twritten={written}\tmanifest={}\taudit_row={}",
        path.display(),
        report.audit_event_id.expect("set above")
    )?;
    Ok(report)
}

/// A manifest of this verb, read back strictly.
pub struct SubmitterManifest {
    pub header: Value,
    /// `(workflow id, prior, post)`, in file order.
    pub records: Vec<(Uuid, Value, String)>,
}

/// Whether the file at `path` is a `set-workflow-submitter` manifest (its
/// first line's `operation`). `false` for anything unreadable.
#[must_use]
pub fn is_manifest_file(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| t.lines().next().map(str::to_string))
        .and_then(|l| serde_json::from_str::<Value>(&l).ok())
        .is_some_and(|v| v.get("operation").and_then(Value::as_str) == Some(OPERATION))
}

/// # Errors
/// The file cannot be read, a line is malformed, or it is not a current
/// `set-workflow-submitter` manifest.
pub fn read_manifest(path: &Path) -> anyhow::Result<SubmitterManifest> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut header: Option<Value> = None;
    let mut records = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)
            .with_context(|| format!("{}:{}: not JSON", path.display(), n + 1))?;
        if v.get("manifest").is_some() {
            if header.is_some() {
                bail!("{}:{}: a second header", path.display(), n + 1);
            }
            header = Some(v);
            continue;
        }
        let at = || format!("{}:{}", path.display(), n + 1);
        let id = v
            .get("workflow_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| anyhow!("{}: no workflow_id", at()))?;
        let prior = v
            .get("prior")
            .cloned()
            .ok_or_else(|| anyhow!("{}: no prior", at()))?;
        let post = v
            .get("post")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("{}: no post", at()))?
            .to_string();
        records.push((id, prior, post));
    }
    let header = header.ok_or_else(|| anyhow!("{} has no header line", path.display()))?;
    if header.get("operation").and_then(Value::as_str) != Some(OPERATION)
        || header.get("record_format").and_then(Value::as_str) != Some(RECORD_FORMAT)
    {
        bail!(
            "{} is not a {RECORD_FORMAT} manifest; refusing",
            path.display()
        );
    }
    Ok(SubmitterManifest { header, records })
}

/// What `metadata` must be for a row to be in its recorded PRIOR state,
/// given its current value (an object prior keeps every other key as it is
/// now).
fn prior_metadata(prior: &Value, current: &Value) -> anyhow::Result<Value> {
    let key = WorkflowRepository::SUBMITTER_KEY;
    match prior.get("metadata_type").and_then(Value::as_str) {
        Some("object") => {
            let mut m = current.as_object().cloned().unwrap_or_default();
            if prior.get("has_key").and_then(Value::as_bool) == Some(true) {
                let v = prior
                    .get("value")
                    .cloned()
                    .ok_or_else(|| anyhow!("an object prior with has_key lacks its value"))?;
                m.insert(key.to_string(), v);
            } else {
                m.remove(key);
            }
            Ok(Value::Object(m))
        }
        Some("other") => prior
            .get("metadata")
            .cloned()
            .ok_or_else(|| anyhow!("a non-object prior lacks its metadata")),
        other => bail!("unknown prior metadata_type {other:?}"),
    }
}

/// Whether `current` is the POST state a forward run left for `prior`.
fn at_post(prior: &Value, post: &str, current: &Value) -> bool {
    let key = WorkflowRepository::SUBMITTER_KEY;
    let carries = current
        .as_object()
        .and_then(|m| m.get(key))
        .and_then(Value::as_str)
        == Some(post);
    match prior.get("metadata_type").and_then(Value::as_str) {
        // The forward write replaced the whole value with {key: post}.
        Some("other") => carries && current.as_object().is_some_and(|m| m.len() == 1),
        _ => carries,
    }
}

/// What a reversal found and did.
#[derive(Debug, Default)]
pub struct ReverseReport {
    pub restored: usize,
    pub already: usize,
    pub held: usize,
    pub missing: usize,
    pub audit_event_id: Option<Uuid>,
}

/// Reverse one manifest (dry run unless `apply`).
///
/// # Errors
/// The manifest is not a current one, a statement fails, or (under
/// `--apply`) the reason is blank. Nothing is committed then.
pub async fn reverse(
    conn: &mut PgConnection,
    path: &Path,
    apply: bool,
    reason: &str,
    who: &Operator,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<ReverseReport> {
    if apply && reason.trim().is_empty() {
        bail!("--reverse --apply requires a non-empty --reason (recorded in the audit row)");
    }
    let m = read_manifest(path)?;
    let operator = m
        .header
        .get("operator")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| anyhow!("{}: header has no operator", path.display()))?;
    let ids: Vec<Uuid> = m.records.iter().map(|r| r.0).collect();
    let mut tx = conn.begin().await.context("beginning the transaction")?;
    let current: BTreeMap<Uuid, Value> = sqlx::query_as::<_, (Uuid, Value)>(
        "SELECT id, metadata FROM workflows WHERE id = ANY($1) ORDER BY id FOR UPDATE",
    )
    .bind(&ids)
    .fetch_all(&mut *tx)
    .await
    .context("locking the recorded workflows")?
    .into_iter()
    .collect();
    let mut report = ReverseReport::default();
    let mut writes: Vec<(Uuid, Value)> = Vec::new();
    for (id, prior, post) in &m.records {
        let Some(cur) = current.get(id) else {
            writeln!(out, "MISSING\tworkflow={id}")?;
            report.missing += 1;
            continue;
        };
        let want = prior_metadata(prior, cur)
            .with_context(|| format!("{}: workflow {id}", path.display()))?;
        if at_post(prior, post, cur) {
            writeln!(out, "RESTORE\tworkflow={id}")?;
            writes.push((*id, want));
            report.restored += 1;
        } else if *cur == want {
            writeln!(out, "ALREADY\tworkflow={id}\t(at its recorded prior state)")?;
            report.already += 1;
        } else {
            writeln!(
                out,
                "HELD\tworkflow={id}\t(changed since the run: neither its recorded post nor its \
                 prior state)"
            )?;
            report.held += 1;
        }
    }
    for (id, md) in &writes {
        let n = sqlx::query("UPDATE workflows SET metadata = $2 WHERE id = $1")
            .bind(id)
            .bind(md)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("restoring workflow {id}"))?
            .rows_affected();
        if n != 1 {
            bail!("restoring workflow {id} wrote {n} rows; rolled back");
        }
    }
    writeln!(
        out,
        "RESTORE-COUNT\t{}\nALREADY-COUNT\t{}\nHELD-COUNT\t{}\nMISSING-COUNT\t{}",
        report.restored, report.already, report.held, report.missing
    )?;
    if !apply {
        tx.rollback().await?;
        writeln!(out, "DRY RUN: nothing was written.")?;
        return Ok(report);
    }
    if writes.is_empty() {
        tx.rollback().await?;
        writeln!(out, "NOTHING TO DO: no recorded row is at its post state.")?;
        return Ok(report);
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    report.audit_event_id = Some(
        audit(
            &mut tx,
            EVENT_REVERSE,
            operator,
            json!({
                "tool": "epigraph-operator",
                "command": "set-workflow-submitter --reverse",
                "operator": operator_facts(who, operator),
                "reason": reason.trim(),
                "manifest_path": path.display().to_string(),
                "manifest_sha256": sha256_hex(&bytes),
                "counts": {
                    "restored": report.restored,
                    "already": report.already,
                    "held": report.held,
                    "missing": report.missing,
                },
            }),
        )
        .await?,
    );
    tx.commit().await.context("committing")?;
    writeln!(
        out,
        "APPLIED\trestored={}\taudit_row={}",
        report.restored,
        report.audit_event_id.expect("set above")
    )?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(md: Value) -> Row {
        Row {
            id: Uuid::nil(),
            canonical_name: "c".into(),
            generation: 0,
            metadata: md,
        }
    }

    #[test]
    fn a_row_is_written_held_or_already_by_its_recorded_submitter() {
        let s = Uuid::new_v4();
        let other = Uuid::new_v4().to_string();
        let key = WorkflowRepository::SUBMITTER_KEY;
        assert_eq!(classify(&row(json!({})), s, false), Class::Write);
        assert_eq!(classify(&row(Value::Null), s, false), Class::Write);
        assert_eq!(
            classify(&row(json!({ key: s.to_string() })), s, false),
            Class::Already
        );
        assert_eq!(classify(&row(json!({ key: other })), s, false), Class::Held);
        assert_eq!(
            classify(&row(json!({ key: other })), s, true),
            Class::Reassign
        );
        assert_eq!(classify(&row(json!({ key: 7 })), s, false), Class::Held);
    }

    #[test]
    fn every_prior_shape_is_restored_exactly() {
        let key = WorkflowRepository::SUBMITTER_KEY;
        let post = Uuid::new_v4().to_string();
        for prior_md in [
            json!({"a": 1}),
            json!({"a": 1, key: "old"}),
            Value::Null,
            json!([1, 2]),
            json!("text"),
        ] {
            let r = row(prior_md.clone());
            let prior = prior_json(&r);
            let mut after = prior_md.as_object().cloned().unwrap_or_default();
            after.insert(key.to_string(), json!(post));
            let after = Value::Object(after);
            assert!(at_post(&prior, &post, &after), "{prior_md}");
            assert_eq!(prior_metadata(&prior, &after).unwrap(), prior_md);
            assert!(!at_post(&prior, &post, &prior_md), "{prior_md}");
        }
    }
}
