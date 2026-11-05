//! Operator binary: the retroactive K10(3) sweep (supersede SPEC §11 K10(3),
//! operator decision OD-10; rulings R-178(2), R-179), its dry run and its
//! undo.
//!
//! The supersede cascade's K10(2) arm removes the BBAs a newly retired
//! claim's outgoing edges froze onto current claims. Claims retired before
//! that arm existed still hold such rows. This binary removes exactly the
//! rows the read-only dry-run delta measures as `k10_retro`
//! (`supersede_belief_delta --items k10-retro`) and re-derives each holder
//! the way the K10(2) arm does, nothing re-wired from the retired source
//! (`epigraph_cli::k10_retro`). Retracted rows are kept.
//!
//! Usage:
//!     sweep_retired_source_bbas [--dry-run] [--expect <report.json>] [--top N]
//!     sweep_retired_source_bbas --apply --expect <report.json> --snapshot <path>
//!         --acting-agent <uuid> --reason <text> [--top N]
//!     sweep_retired_source_bbas --undo <snapshot> [--dry-run] --acting-agent <uuid>
//!         --reason <text> [--report <path>]
//!
//! * DRY RUN BY DEFAULT: the plan (every row it would delete, and what that
//!   does to each holder, the measurement's own `k10_retro` block) in one
//!   READ ONLY transaction, printed as JSON. With `--expect`, also whether it
//!   equals that accepted measurement (exit 1 when it does not).
//! * `--apply` requires `--expect`, the `supersede_belief_delta` report the
//!   operator accepted (or its `k10_retro` block), and refuses unless the plan
//!   equals it. It writes `--snapshot` (created new, before the database is
//!   touched; written and synced before the COMMIT) and one
//!   `k10_retro.sweep_applied` audit row. One transaction: any refusal or
//!   failure writes nothing.
//! * `--undo <snapshot>` re-inserts each deleted row from its stored image
//!   where its id and key are still free, then restores the caches of the
//!   holders whose every row came back by compare-and-set (a cache written
//!   since the sweep is reported and left alone). `--dry-run` runs every
//!   statement and rolls back. The outcomes go to `--report` (default
//!   `<snapshot>.undo-<UTC stamp>[-dry-run].json`, created new).
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET (the fallback to `DATABASE_URL` is
//! refused) and its login must bypass row security: the selection reads, and
//! the sweep deletes, every group's rows. `--acting-agent` must name an
//! existing agent (recorded in the audit row and the snapshot) and `--reason`
//! must be non-empty. A writing run (`--apply`, an undo without `--dry-run`)
//! takes the cascade replay's lock and refuses while another run holds it,
//! and first checks that its belief modes match the API's
//! (`belief_mode_check`, exit 3 on a refusal), as every wave bin does.
//!
//! The JSON names claim and row ids: keep it in the operator's private
//! results directory, never in a repository.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use clap::Parser;
use uuid::Uuid;

use epigraph_cli::belief_cache::{plan_restore, restore_wave, RestoreOptions};
use epigraph_cli::belief_mode_check::{enforce_build_fold_or_exit, enforce_or_exit, RunIntent};
use epigraph_cli::k10_retro::{
    apply, compare_to_measurement, dry_run, expected_block, read_snapshot, restore_rows, Operator,
    BIN, DEFAULT_TOP,
};

#[derive(Parser, Debug)]
#[command(
    name = "sweep_retired_source_bbas",
    about = "The retroactive K10(3) sweep: remove the live edge-keyed BBAs retired claims froze \
             onto current claims, exactly as measured; dry run by default"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the work runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Write nothing (the default for a sweep, spelled out; with --undo, run
    /// every statement and roll back).
    #[arg(long, conflicts_with = "apply")]
    dry_run: bool,

    /// Apply the sweep. Requires --expect, --snapshot, --acting-agent and
    /// --reason.
    #[arg(long, conflicts_with = "undo", requires_all = ["expect", "snapshot"])]
    apply: bool,

    /// The accepted measurement: a `supersede_belief_delta` report measured
    /// with the k10-retro item, or its `k10_retro` block.
    #[arg(long, value_name = "FILE", conflicts_with = "undo")]
    expect: Option<PathBuf>,

    /// The undo file an --apply writes (refused if it exists).
    #[arg(long, value_name = "FILE", requires = "apply")]
    snapshot: Option<PathBuf>,

    /// Undo the sweep a snapshot file records.
    #[arg(long, value_name = "SNAPSHOT")]
    undo: Option<PathBuf>,

    /// The undo's outcome file (refused if it exists).
    #[arg(long, value_name = "FILE", requires = "undo")]
    report: Option<PathBuf>,

    /// The operator a writing run is attributed to.
    #[arg(long, value_name = "AGENT_ID")]
    acting_agent: Option<Uuid>,

    /// Why a writing run runs; recorded in the audit row and the snapshot.
    #[arg(long)]
    reason: Option<String>,

    /// How many top movers the plan's report lists (the delta binary's
    /// default, so a plan and a default measurement compare equal).
    #[arg(long, default_value_t = DEFAULT_TOP, conflicts_with = "undo")]
    top: usize,

    /// Proceed with a writing run although this process's belief modes differ
    /// from the API's `/health` report (or cannot be read). For tests and a
    /// deliberate, recorded override only.
    #[arg(long, hide = true)]
    allow_mode_skew: bool,
}

fn create_new(path: &Path) -> anyhow::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| anyhow!("{}: {e}", path.display()))
}

fn write_synced(file: File, v: &impl serde::Serialize) -> anyhow::Result<()> {
    let mut out = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut out, v)?;
    out.write_all(b"\n")?;
    out.flush()?;
    out.get_ref().sync_all()?;
    Ok(())
}

fn read_json(path: &Path) -> anyhow::Result<serde_json::Value> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| anyhow!("{}: {e}", path.display()))
}

fn operator(cli: &Cli) -> anyhow::Result<Operator> {
    let acting_agent = cli.acting_agent.ok_or_else(|| {
        anyhow!("a writing run needs --acting-agent <uuid>: the audit row names the operator")
    })?;
    let reason = cli
        .reason
        .clone()
        .filter(|r| !r.trim().is_empty())
        .ok_or_else(|| anyhow!("a writing run needs a non-empty --reason"))?;
    Ok(Operator {
        acting_agent,
        reason,
    })
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let writes = cli.apply || (cli.undo.is_some() && !cli.dry_run);
    let intent = if writes {
        RunIntent::Writes
    } else {
        RunIntent::WritesNothing
    };
    // Before the database: a writing run must show its belief modes match the
    // API's, and that this build writes the fold in force (the repair folds
    // each holder). A dry run is exempt.
    enforce_or_exit(BIN, intent, cli.allow_mode_skew).await;
    enforce_build_fold_or_exit(BIN, intent);
    let mut created = Vec::new();
    if let Err(e) = run(cli, writes, &mut created).await {
        // Nothing this run created holds a committed write (an apply's
        // snapshot is kept once its COMMIT succeeded, and nothing fails
        // after it): remove them, so a re-run is not refused over an
        // empty file.
        for path in created {
            let _ = std::fs::remove_file(path);
        }
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli, writes: bool, created: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    // Every input is read, and every output created, before the database is
    // touched: a bad file or an existing output stops the run first.
    let operator = if writes { Some(operator(&cli)?) } else { None };
    let expected = cli.expect.as_deref().map(read_json).transpose()?;
    if let Some(v) = &expected {
        expected_block(v).map_err(|e| anyhow!("--expect: {e}"))?;
    }
    let snapshot = match &cli.undo {
        Some(path) => Some(
            read_snapshot(
                &std::fs::read_to_string(path).map_err(|e| anyhow!("{}: {e}", path.display()))?,
            )
            .with_context(|| format!("--undo {}", path.display()))?,
        ),
        None => None,
    };
    let snapshot_out = match &cli.snapshot {
        Some(path) => {
            let f = create_new(path)?;
            created.push(path.clone());
            Some(f)
        }
        None => None,
    };
    let undo_report = match &cli.undo {
        Some(path) => {
            let out = cli.report.clone().unwrap_or_else(|| {
                let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
                let dry = if cli.dry_run { "-dry-run" } else { "" };
                let mut p = path.as_os_str().to_owned();
                p.push(format!(".undo-{stamp}{dry}.json"));
                PathBuf::from(p)
            });
            let f = create_new(&out)?;
            created.push(out.clone());
            Some((out, f))
        }
        None => None,
    };

    let maint = epigraph_cli::MaintenancePool::connect_to(&cli.database_url, BIN)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(
            "{BIN} reads and deletes rows across every owner, so it runs only on an explicitly \
             configured MAINTENANCE_DATABASE_URL; it is unset, and the application DSN is never \
             used for this"
        );
    }
    let mut session = maint
        .viewer(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .context("acquire the maintenance session")?;
    session
        .assert_privileged()
        .await
        .context("the maintenance connection cannot bypass row security")?;
    let (conn, viewer) = session.split();

    if let Some(op) = &operator {
        let agent = epigraph_db::AgentRepository::get_by_id(
            &mut *conn,
            epigraph_core::AgentId::from_uuid(op.acting_agent),
        )
        .await
        .context("look up --acting-agent")?;
        if agent.is_none() {
            bail!(
                "--acting-agent {} is not an agent; a writing run is attributed to it in its \
                 audit row, so it must exist; nothing was written",
                op.acting_agent
            );
        }
        use epigraph_db::repos::maintenance_lock;
        if !maintenance_lock::try_take(&mut *conn, maintenance_lock::REPLAY_LOCK_KEY)
            .await
            .context("take the cascade replay's lock")?
        {
            bail!(
                "a cascade replay (replay_deferred_cascades) or another maintenance run holds \
                 its lock; nothing was written. Run again once it has finished"
            );
        }
    }

    if let Some(snap) = snapshot {
        let (out_path, out) = undo_report.ok_or_else(|| anyhow!("no undo report file"))?;
        let op = operator.unwrap_or(Operator {
            acting_agent: snap.acting_agent,
            reason: String::new(),
        });
        let rows = restore_rows(
            &mut *conn,
            &snap.deleted,
            &op,
            snap.audit_event_id,
            cli.dry_run,
        )
        .await
        .context("restore the deleted rows")?;
        let whole = rows.holders_whole(&snap.deleted);
        let held_back: Vec<Uuid> = snap
            .caches
            .iter()
            .map(|r| r.claim_id)
            .filter(|id| !whole.contains(id))
            .collect();
        let plan = plan_restore(&snap.caches, Some(&whole));
        let caches = restore_wave(
            maint.pool(),
            &plan,
            &RestoreOptions {
                dry_run: cli.dry_run,
                ..RestoreOptions::default()
            },
        )
        .await
        .context("restore the holders' caches")?;
        let mut cache_buckets = serde_json::Map::new();
        for (name, ids) in caches.buckets() {
            cache_buckets.insert(name.to_string(), serde_json::json!(ids));
        }
        let failed = rows.failed.len();
        write_synced(
            out,
            &serde_json::json!({
                "undo": true,
                "dry_run": cli.dry_run,
                "rows": rows,
                "caches": cache_buckets,
                "caches_held_back": held_back,
            }),
        )?;
        if cli.dry_run {
            println!("DRY RUN: every statement rolled back");
        }
        println!(
            "rows: restored={} already_restored={} superseded_since_sweep={} missing={} \
             failed={}",
            rows.restored.len(),
            rows.already_restored.len(),
            rows.superseded_since_sweep.len(),
            rows.missing.len(),
            failed
        );
        for (name, ids) in caches.buckets() {
            println!("caches {name}: {}", ids.len());
        }
        println!("caches held back (a row not back): {}", held_back.len());
        println!("report: {}", out_path.display());
        if failed > 0 {
            bail!("{failed} row(s) could not be re-inserted; see the report");
        }
        return Ok(());
    }

    if let (Some(op), Some(out)) = (&operator, snapshot_out) {
        let expected = expected.ok_or_else(|| anyhow!("--apply requires --expect"))?;
        let path = cli.snapshot.clone().unwrap_or_default();
        let snap = apply(conn, viewer, op, &expected, cli.top, |s| {
            write_synced(out, s).with_context(|| format!("write {}", path.display()))?;
            // Written and synced: from here the COMMIT may land even if its
            // answer is lost, so the snapshot is the undo and is never removed.
            // A snapshot of an apply that rolled back is harmless (an undo
            // finds every row and cache already as recorded).
            created.clear();
            Ok(())
        })
        .await?;
        println!(
            "applied: {} row(s) deleted on {} holder(s); recomputed {}, unbacked {}; audit {}",
            snap.deleted.len(),
            snap.caches.len(),
            snap.cascade.recomputed.len(),
            snap.cascade.unbacked.len(),
            snap.audit_event_id.map_or_else(
                || "none (nothing to sweep)".to_string(),
                |id| id.to_string()
            )
        );
        println!("snapshot: {}", path.display());
        return Ok(());
    }

    let planned = dry_run(conn, viewer, cli.top)
        .await
        .map_err(|e| anyhow!(e))?;
    let mut out = planned.to_json();
    out["dry_run"] = serde_json::json!(true);
    let mut mismatched = false;
    if let Some(v) = &expected {
        let block = expected_block(v).map_err(|e| anyhow!(e))?;
        let diffs = compare_to_measurement(&planned.report, block);
        mismatched = !diffs.is_empty();
        out["matches_expect"] = serde_json::json!(diffs.is_empty());
        out["differences"] = serde_json::json!(diffs);
    }
    println!("{}", serde_json::to_string_pretty(&out)?);
    eprintln!(
        "DRY RUN: nothing written; {} row(s) on {} edge(s) from {} retired source(s), {} \
         holder(s) ({} would be unbacked)",
        planned.report.live_rows,
        planned.report.edges,
        planned.report.retired_sources,
        planned.report.delta.totals.claims,
        planned.report.delta.totals.unbacked
    );
    if mismatched {
        bail!("the plan differs from --expect (see `differences`)");
    }
    Ok(())
}
