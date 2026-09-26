//! `strip-label` and `strip-label-reverse`: remove one corrupted label value
//! from every claim that carries it, under a manifest, and put it back
//! (backlog f6310444).
//!
//! # What it is for, and the one label shape it accepts
//!
//! A script interpolated a shell variable it never expanded, and claims were
//! written with the literal label `group:$EPICLAW_GROUP_ID`. The write path now
//! refuses such a value (`epigraph_db::reject_unexpanded_labels`, commit
//! 465f1a68); the claims written before that still carry it. This tool removes
//! it.
//!
//! It removes ONLY a label the write-path validator itself rejects: `--label`
//! must fail `reject_unexpanded_labels`, or the tool refuses before reading
//! anything. It is a repair for values the system already declares corrupt,
//! not a general label editor — `update_labels` is that, and it runs through
//! the ownership gate.
//!
//! # Exact, and reversible byte for byte
//!
//! `array_remove` removes every occurrence of the value and leaves every other
//! element where it was. `ClaimRepository::update_labels_conn` would also
//! de-duplicate and SORT the whole array, which is a second, unrequested change
//! to every claim and would make an exact reversal impossible.
//!
//! One transaction: the matching claims are locked `FOR UPDATE`; under
//! `--apply` each one's labels BEFORE the write are recorded in the manifest
//! and fsynced first; the one `UPDATE` runs; then, before commit:
//!
//! * every locked claim was written, and each one's labels now equal its
//!   recorded labels with the value removed, in order;
//! * `pg_stat_xact_user_tables` shows this transaction updated exactly that
//!   many `claims` rows and wrote NOTHING in any other table (the statement
//!   trigger `claims_propagate_tenancy` fires on the UPDATE; it must change no
//!   derived row, because tenancy did not change).
//!
//! Any violation rolls the whole run back. The post-state (each claim's labels
//! after) is appended and fsynced before the commit.
//!
//! `strip-label-reverse` restores each claim to its recorded labels as a
//! compare-and-swap on the WHOLE array: a claim whose labels are exactly the
//! recorded post-state is restored; one already at its prior state is skipped;
//! one in any other state (a later label write) is HELD and not touched.
//!
//! `claims.updated_at` is stamped by `claims_updated_at` on the strip and on
//! its reversal; it is the one column neither can put back (as for
//! `reown-claims`).

use super::reown::{counter_delta, counter_violations};
use super::tables::xact_counters;
use anyhow::{anyhow, bail, Context};
use epigraph_db::reject_unexpanded_labels;
use epigraph_db::repos::OperatorRepairRepository;
use serde_json::{json, Value};
use sqlx::PgConnection;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// The header `manifest` value this module writes and the only one it reverses.
pub const MANIFEST_KIND: &str = "epigraph-operator strip-label";
/// The format version. Deliberately not `manifest::VERSION` (2): `reown-reverse`
/// refuses anything but its own version, so a label manifest handed to it is
/// refused rather than misread as a re-own.
pub const VERSION: i64 = 1;
/// The value backlog f6310444 measured.
pub const DEFAULT_LABEL: &str = "group:$EPICLAW_GROUP_ID";

/// Everything `strip-label` was told.
#[derive(Clone, Debug)]
pub struct Options {
    pub label: String,
    pub manifest_out: PathBuf,
    pub apply: bool,
    pub lock_timeout: String,
}

/// Everything `strip-label-reverse` was told.
#[derive(Clone, Debug)]
pub struct ReverseOptions {
    pub manifest: PathBuf,
    pub apply: bool,
    pub lock_timeout: String,
}

/// What `strip-label` did (or, in a dry run, would do).
#[derive(Default, Debug)]
pub struct Report {
    pub matched: usize,
    pub matched_current: usize,
    pub stripped: usize,
}

/// What `strip-label-reverse` did.
#[derive(Default, Debug)]
pub struct ReverseReport {
    pub restored: usize,
    pub already: usize,
    pub never_written: usize,
    pub held: Vec<(Uuid, String)>,
}

/// Refuse a label the write-path validator accepts.
///
/// # Errors
/// The label is one the write path would accept.
pub fn refuse_valid_label(label: &str) -> anyhow::Result<()> {
    if reject_unexpanded_labels(&[label.to_string()]).is_ok() {
        bail!(
            "refusing: {label:?} is a label the write path accepts. strip-label removes only \
             values the validator rejects (unexpanded shell syntax); use update_labels for \
             anything else"
        );
    }
    Ok(())
}

/// `labels` with every occurrence of `label` removed, order kept: what
/// `array_remove` must produce.
#[must_use]
pub fn without(labels: &[String], label: &str) -> Vec<String> {
    labels.iter().filter(|l| *l != label).cloned().collect()
}

/// A `create_new` JSONL file, fsynced on every append.
struct LabelManifest {
    file: File,
    path: PathBuf,
}

impl LabelManifest {
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

async fn set_lock_timeout(conn: &mut PgConnection, t: &str) -> anyhow::Result<()> {
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(t)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Strip `opts.label` from every claim carrying it. One transaction on
/// `conn`: committed under `--apply`, rolled back otherwise.
///
/// # Errors
/// The label is refused, the manifest cannot be written, a statement fails,
/// or an invariant fails (the transaction is rolled back).
#[allow(clippy::too_many_lines)]
pub async fn run(
    conn: &mut PgConnection,
    opts: &Options,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<Report> {
    refuse_valid_label(&opts.label)?;
    let mut report = Report::default();
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    set_lock_timeout(&mut tx, &opts.lock_timeout).await?;
    let locked = OperatorRepairRepository::claims_with_label_conn(&mut tx, &opts.label, true)
        .await
        .context("locking the claims that carry the label")?;
    report.matched = locked.len();
    report.matched_current = locked.iter().filter(|c| c.is_current).count();
    writeln!(
        out,
        "strip-label: label={:?} mode={}",
        opts.label,
        if opts.apply { "APPLY" } else { "DRY-RUN" }
    )?;
    writeln!(
        out,
        "PLAN: {} claim(s) carry it ({} current, {} not current)",
        report.matched,
        report.matched_current,
        report.matched - report.matched_current
    )?;
    for c in &locked {
        writeln!(
            out,
            "CLAIM\t{}\t{}\t{}",
            c.id,
            if c.is_current {
                "current"
            } else {
                "not-current"
            },
            json!(c.labels)
        )?;
    }
    if locked.is_empty() {
        tx.rollback().await?;
        writeln!(out, "RESULT\n  nothing to do")?;
        return Ok(report);
    }

    let mut manifest = if opts.apply {
        let header = json!({
            "manifest": MANIFEST_KIND,
            "version": VERSION,
            "label": opts.label,
            "created_at": chrono::Utc::now().to_rfc3339(),
        });
        let mut m = LabelManifest::create_new(&opts.manifest_out, &header)?;
        let prior: Vec<Value> = locked
            .iter()
            .map(|c| json!({"claim_id": c.id, "before": c.labels}))
            .collect();
        m.append(&prior)?;
        Some(m)
    } else {
        None
    };

    let ids: Vec<Uuid> = locked.iter().map(|c| c.id).collect();
    let counters_before = xact_counters(&mut tx).await?;
    let written = OperatorRepairRepository::strip_label_conn(&mut tx, &ids, &opts.label).await?;
    let counters_after = xact_counters(&mut tx).await?;

    // ---- invariants ----
    let mut v = Vec::new();
    let after: BTreeMap<Uuid, Vec<String>> = written.into_iter().collect();
    for c in &locked {
        match after.get(&c.id) {
            None => v.push(format!("claim {} was locked but not written", c.id)),
            Some(a) => {
                let want = without(&c.labels, &opts.label);
                if *a != want {
                    v.push(format!(
                        "claim {} labels are {} after the strip, expected {}",
                        c.id,
                        json!(a),
                        json!(want)
                    ));
                }
            }
        }
    }
    if after.len() != locked.len() {
        v.push(format!(
            "the UPDATE wrote {} row(s), {} were locked",
            after.len(),
            locked.len()
        ));
    }
    let mut expect: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    expect.insert(
        "claims".into(),
        (0, i64::try_from(locked.len()).unwrap_or(i64::MAX), 0),
    );
    v.extend(counter_violations(
        &counter_delta(&counters_before, &counters_after),
        &expect,
    ));
    if !v.is_empty() {
        tx.rollback().await?;
        writeln!(out, "ROLLED BACK: {} invariant violation(s):", v.len())?;
        for x in &v {
            writeln!(out, "    - {x}")?;
        }
        bail!("strip-label: invariants failed; nothing was written");
    }
    report.stripped = after.len();

    if let Some(m) = manifest.as_mut() {
        let post: Vec<Value> = after
            .iter()
            .map(|(id, a)| json!({"claim_id": id, "after": a}))
            .collect();
        m.append(&post)?;
        tx.commit().await?;
        writeln!(
            out,
            "MANIFEST\t{}\tprior and post labels of {} claim(s), fsynced before the commit",
            opts.manifest_out.display(),
            after.len()
        )?;
    } else {
        tx.rollback().await?;
    }
    writeln!(out, "RESULT")?;
    writeln!(out, "  claims stripped: {}", report.stripped)?;
    writeln!(
        out,
        "  invariants: all held (only claims.labels changed, one element each; no other table \
         written)"
    )?;
    if opts.apply {
        writeln!(
            out,
            "UNDO: epigraph-operator strip-label-reverse --manifest {} --apply",
            opts.manifest_out.display()
        )?;
    } else {
        writeln!(
            out,
            "DRY RUN: the strip above ran in a transaction that was rolled back; no manifest was \
             written."
        )?;
    }
    Ok(report)
}

/// A strip-label manifest read back: claim → (before, after if written).
struct Read {
    label: String,
    claims: BTreeMap<Uuid, (Vec<String>, Option<Vec<String>>)>,
}

fn string_array(v: &Value, key: &str) -> anyhow::Result<Vec<String>> {
    v.get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("record lacks array {key}: {v}"))?
        .iter()
        .map(|x| {
            x.as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow!("{key} holds a non-string: {v}"))
        })
        .collect()
}

fn read_manifest(path: &Path) -> anyhow::Result<Read> {
    let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut header: Option<Value> = None;
    let mut claims: BTreeMap<Uuid, (Vec<String>, Option<Vec<String>>)> = BTreeMap::new();
    for (n, line) in BufReader::new(f).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(&line)
            .with_context(|| format!("{}:{}: not JSON", path.display(), n + 1))?;
        if v.get("manifest").is_some() {
            if header.is_some() {
                bail!("{}:{}: a second header", path.display(), n + 1);
            }
            header = Some(v);
            continue;
        }
        let id = v
            .get("claim_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("{}:{}: no claim_id", path.display(), n + 1))
            .and_then(|s| Uuid::parse_str(s).context("claim_id"))?;
        if v.get("before").is_some() {
            let before = string_array(&v, "before")?;
            claims.entry(id).or_insert((before, None));
        } else if v.get("after").is_some() {
            let after = string_array(&v, "after")?;
            let e = claims
                .get_mut(&id)
                .ok_or_else(|| anyhow!("{}:{}: post record before prior", path.display(), n + 1))?;
            e.1 = Some(after);
        } else {
            bail!("{}:{}: neither before nor after", path.display(), n + 1);
        }
    }
    let header = header.ok_or_else(|| anyhow!("{} has no header line", path.display()))?;
    if header.get("manifest").and_then(Value::as_str) != Some(MANIFEST_KIND)
        || header.get("version").and_then(Value::as_i64) != Some(VERSION)
    {
        bail!(
            "{} is not a {MANIFEST_KIND} version {VERSION} manifest (header: {header}); refusing",
            path.display()
        );
    }
    let label = header
        .get("label")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{}: header has no label", path.display()))?
        .to_string();
    check_is_a_strip_of(&label, &claims)
        .with_context(|| format!("{}: refusing the whole manifest", path.display()))?;
    Ok(Read { label, claims })
}

/// A manifest is only reversible if it records a strip of its OWN header
/// label: the label is one the write-path validator rejects (the only kind
/// `run` strips), every `before` carries it, and every written `after` is
/// exactly `before` without it. `reverse` writes `before` back verbatim, so
/// without this an edited `before` would let it write any label array at all,
/// including labels whose writes are gated elsewhere, under a tool whose
/// contract is to restore one rejected value. Checked for every record before
/// the transaction opens, so a manifest that fails is refused whole.
fn check_is_a_strip_of(
    label: &str,
    claims: &BTreeMap<Uuid, (Vec<String>, Option<Vec<String>>)>,
) -> anyhow::Result<()> {
    refuse_valid_label(label)?;
    for (id, (before, after)) in claims {
        if !before.iter().any(|l| l == label) {
            bail!(
                "claim {id}: recorded labels {} do not carry {label:?}, so they are not the \
                 prior state of a strip of that label",
                json!(before)
            );
        }
        if let Some(after) = after {
            let want = without(before, label);
            if *after != want {
                bail!(
                    "claim {id}: recorded post-strip labels {} are not {} (the recorded prior \
                     labels without {label:?})",
                    json!(after),
                    json!(want)
                );
            }
        }
    }
    Ok(())
}

/// Restore every claim a strip-label manifest wrote to its recorded labels.
/// One transaction: committed under `--apply`, rolled back otherwise.
///
/// # Errors
/// The manifest is malformed, a statement fails, or an invariant fails.
pub async fn reverse(
    conn: &mut PgConnection,
    opts: &ReverseOptions,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<ReverseReport> {
    let m = read_manifest(&opts.manifest)?;
    let mut report = ReverseReport::default();
    writeln!(
        out,
        "strip-label-reverse: manifest={} label={:?} claims={} mode={}",
        opts.manifest.display(),
        m.label,
        m.claims.len(),
        if opts.apply { "APPLY" } else { "DRY-RUN" }
    )?;
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    set_lock_timeout(&mut tx, &opts.lock_timeout).await?;
    let ids: Vec<Uuid> = m.claims.keys().copied().collect();
    let now: BTreeMap<Uuid, Vec<String>> =
        OperatorRepairRepository::labels_for_update_conn(&mut tx, &ids)
            .await?
            .into_iter()
            .map(|c| (c.id, c.labels))
            .collect();
    let mut work: Vec<(Uuid, &Vec<String>, &Vec<String>)> = Vec::new();
    for (id, (before, after)) in &m.claims {
        let Some(after) = after else {
            report.never_written += 1;
            continue;
        };
        match now.get(id) {
            None => report.held.push((*id, "claim no longer exists".into())),
            Some(cur) if cur == before => report.already += 1,
            Some(cur) if cur == after => work.push((*id, after, before)),
            Some(cur) => report.held.push((
                *id,
                format!(
                    "labels are {} now; the strip left {} and recorded {} before; a later write \
                     changed them, not reversing",
                    json!(cur),
                    json!(after),
                    json!(before)
                ),
            )),
        }
    }
    let counters_before = xact_counters(&mut tx).await?;
    let mut v = Vec::new();
    for (id, after, before) in &work {
        if OperatorRepairRepository::restore_labels_conn(&mut tx, *id, after, before).await? {
            report.restored += 1;
        } else {
            v.push(format!(
                "claim {id} was not restored although it was locked in its post state"
            ));
        }
    }
    let counters_after = xact_counters(&mut tx).await?;
    let mut expect: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    if report.restored > 0 {
        expect.insert(
            "claims".into(),
            (0, i64::try_from(report.restored).unwrap_or(i64::MAX), 0),
        );
    }
    v.extend(counter_violations(
        &counter_delta(&counters_before, &counters_after),
        &expect,
    ));
    if !v.is_empty() {
        tx.rollback().await?;
        writeln!(out, "ROLLED BACK: {} invariant violation(s):", v.len())?;
        for x in &v {
            writeln!(out, "    - {x}")?;
        }
        bail!("strip-label-reverse: invariants failed; nothing was written");
    }
    if opts.apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    for (id, why) in &report.held {
        writeln!(out, "HELD\t{id}\t{why}")?;
    }
    writeln!(out, "RESULT")?;
    writeln!(out, "  claims restored: {}", report.restored)?;
    writeln!(
        out,
        "  claims already on their recorded labels: {}",
        report.already
    )?;
    writeln!(
        out,
        "  claims recorded but never written by the strip: {}",
        report.never_written
    )?;
    writeln!(out, "  claims HELD: {}", report.held.len())?;
    if !opts.apply {
        writeln!(
            out,
            "DRY RUN: the restore above ran in a transaction that was rolled back."
        )?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_label_the_validator_rejects_is_accepted() {
        assert!(refuse_valid_label(DEFAULT_LABEL).is_ok());
        assert!(refuse_valid_label("group:1234").is_err());
        assert!(refuse_valid_label("backlog").is_err());
    }

    #[test]
    fn without_keeps_every_other_element_in_place() {
        let l = |xs: &[&str]| xs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        assert_eq!(
            without(
                &l(&["z", DEFAULT_LABEL, "a", DEFAULT_LABEL, "m"]),
                DEFAULT_LABEL
            ),
            l(&["z", "a", "m"])
        );
        assert_eq!(without(&l(&["b", "a"]), DEFAULT_LABEL), l(&["b", "a"]));
    }
}
