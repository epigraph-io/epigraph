//! Operator binary: refresh `claims.truth_value` copies of an old belief
//! cache by compare-and-set, from the wave files of the recomputes that moved
//! the cache (operator rulings R-176(2), R-177(5): class D), and undo it.
//!
//! Usage:
//!     refresh_truth_mirrors --waves <wave file>... --report <path>
//!         [--dry-run (default) | --apply --record <path>] [--include-round]
//!         [--batch N]
//!     refresh_truth_mirrors --restore <record file> [--dry-run] [--report <path>]
//!         [--batch N]
//!
//! (`--batch` is also spelled `--batch-size`. A restore's report defaults to
//! `<record file>.restore-<UTC time>[-dry-run].report.json`.)
//!
//! Without `--apply` the run is a DRY RUN (the default): it evaluates every
//! rule in one read-only transaction, writes nothing, prints the bucket counts
//! and the would-change set (`<claim> <truth_value> -> <new>`), and writes the
//! report. With `--apply --record`, each eligible claim's `truth_value` is set
//! to the cache the last wave wrote, only where `truth_value` still equals the
//! cache the first wave found EXACTLY and every other rule holds (see
//! `epigraph_cli::truth_mirror` for the rules and their buckets); every write
//! is appended, flushed and synced to the record file before its batch
//! commits. Never written: a non-current claim, a compound or procedural one,
//! a workflow or step claim, a value at the 0.05 sentinel, a round value
//! (unless `--include-round`), a claim whose cache moved since the wave.
//!
//! `--restore <record file>` puts each recorded `truth_before` back, last
//! record first, only where `truth_value` still holds exactly what the
//! refresh wrote; anything else is reported `superseded_since_refresh` and
//! left alone. With `--dry-run` it runs the same statements and rolls back.
//!
//! Output files are never overwritten (they are created new, before the
//! database is touched). A writing run (`--apply`, or `--restore` without
//! `--dry-run`) first checks that its belief modes match the API's
//! (`belief_mode_check`), as every wave bin does. It runs on the maintenance
//! connection.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use clap::Parser;

use epigraph_cli::belief_cache::read_wave;
use epigraph_cli::belief_mode_check::{enforce_or_exit, RunIntent};
use epigraph_cli::truth_mirror::{
    apply, dry_run, plan_candidates, read_truth_records, restore, write_truth_record, Bucket,
    MirrorReport, RefreshOptions, DEFAULT_BATCH,
};

#[derive(Parser, Debug)]
#[command(
    name = "refresh_truth_mirrors",
    about = "Compare-and-set refresh of truth_value copies of an old belief cache"
)]
struct Cli {
    /// Wave files (`belief_cache::WaveRecord` JSON lines) of the recomputes
    /// that moved the cache, in any order.
    #[arg(long, num_args = 1.., required_unless_present = "restore", conflicts_with = "restore")]
    waves: Vec<PathBuf>,
    /// Write the refresh. Without it the run is a dry run.
    #[arg(long, requires = "record", conflicts_with = "restore")]
    apply: bool,
    /// Record file for `--apply`: one line per write, the input of `--restore`.
    #[arg(long, requires = "apply")]
    record: Option<PathBuf>,
    /// Admit round-valued mirrors (multiples of 0.001), held by default.
    #[arg(long, conflicts_with = "restore")]
    include_round: bool,
    /// Undo the writes of a record file.
    #[arg(long)]
    restore: Option<PathBuf>,
    /// Write nothing. For a refresh this is the default, spelled out; with
    /// `--restore`, run every statement and roll each batch back.
    #[arg(long, conflicts_with = "apply")]
    dry_run: bool,
    /// Report file (JSON). Required for a refresh; a restore defaults it next
    /// to the record file.
    #[arg(long, required_unless_present = "restore")]
    report: Option<PathBuf>,
    /// Claims per transaction.
    #[arg(long, alias = "batch", default_value_t = DEFAULT_BATCH)]
    batch_size: usize,
    /// Proceed with a writing run although this process's belief modes differ
    /// from the API's `/health` report (or cannot be read). For tests and a
    /// deliberate, recorded override only.
    #[arg(long, hide = true)]
    allow_mode_skew: bool,
}

const BIN: &str = "refresh_truth_mirrors";

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();
    let writes = cli.apply || (cli.restore.is_some() && !cli.dry_run);
    let intent = if writes {
        RunIntent::Writes
    } else {
        RunIntent::WritesNothing
    };
    // Before the database: a writing run must show its belief modes match the
    // API's (SPEC §10.2). A dry run writes nothing and is exempt.
    enforce_or_exit(BIN, intent, cli.allow_mode_skew).await;
    if let Err(e) = run(cli).await {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn create_new(path: &Path) -> anyhow::Result<BufWriter<File>> {
    let f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    Ok(BufWriter::new(f))
}

fn write_json(mut out: BufWriter<File>, v: &serde_json::Value) -> anyhow::Result<()> {
    serde_json::to_writer_pretty(&mut out, v)?;
    out.write_all(b"\n")?;
    out.flush()?;
    out.get_ref().sync_all()?;
    Ok(())
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    if let Some(record_path) = &cli.restore {
        return run_restore(&cli, record_path).await;
    }

    // Every input is read, and every output created, before the database is
    // touched: a bad file or an existing output stops the run first.
    let mut records = Vec::new();
    for path in &cli.waves {
        let f = File::open(path).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        records.extend(
            read_wave(BufReader::new(f)).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?,
        );
    }
    let candidates = plan_candidates(&records);
    let report_path = cli
        .report
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--report is required"))?;
    let report_w = create_new(&report_path)?;
    let mut record_w = match &cli.record {
        Some(p) => Some(create_new(p)?),
        None => None,
    };

    let maint = epigraph_cli::MaintenancePool::connect(BIN)
        .await
        .map_err(|e| anyhow::anyhow!("maintenance pool: {e}"))?;
    // The bypass viewer is spent on `claim_role::roles_batch` only, on the
    // maintenance connection, for as long as the run lasts.
    let session = maint
        .viewer(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .map_err(|e| anyhow::anyhow!("maintenance viewer: {e}"))?;
    let viewer = session.viewer();
    let opts = RefreshOptions {
        batch_size: cli.batch_size,
        include_round: cli.include_round,
    };

    let result = if let Some(w) = record_w.as_mut() {
        apply(maint.pool(), viewer, &candidates, &opts, |rec| {
            write_truth_record(w, rec)?;
            w.flush()?;
            w.get_ref().sync_data()?;
            Ok(())
        })
        .await
    } else {
        dry_run(maint.pool(), viewer, &candidates, &opts).await
    };
    let report: MirrorReport = result
        .map_err(|e| e.context("refresh stopped; the record file lists every committed write"))?;

    let dry = !cli.apply;
    write_json(
        report_w,
        &report.to_json(dry, cli.include_round, records.len()),
    )?;
    if dry {
        println!("DRY RUN: nothing written");
    }
    println!("wave records: {}", records.len());
    println!("claims: {}", candidates.len());
    for (bucket, n) in report.counts() {
        println!("{}: {n}", bucket.as_str());
    }
    if dry {
        println!("would_change:");
        for o in report
            .outcomes
            .iter()
            .filter(|o| o.bucket == Bucket::Refresh)
        {
            if let (Some(t), Some(n)) = (o.truth_before, o.new) {
                println!("  {} {t} -> {n}", o.claim_id);
            }
        }
    }
    println!("report: {}", report_path.display());
    if let Some(p) = &cli.record {
        println!("record: {}", p.display());
    }
    Ok(())
}

async fn run_restore(cli: &Cli, record_path: &Path) -> anyhow::Result<()> {
    let f =
        File::open(record_path).map_err(|e| anyhow::anyhow!("{}: {e}", record_path.display()))?;
    let records = read_truth_records(BufReader::new(f))
        .map_err(|e| anyhow::anyhow!("{}: {e}", record_path.display()))?;
    let report_path = cli.report.clone().unwrap_or_else(|| {
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
        let dry = if cli.dry_run { "-dry-run" } else { "" };
        let mut p = record_path.as_os_str().to_owned();
        p.push(format!(".restore-{stamp}{dry}.report.json"));
        PathBuf::from(p)
    });
    let report_w = create_new(&report_path)?;
    let maint = epigraph_cli::MaintenancePool::connect(BIN)
        .await
        .map_err(|e| anyhow::anyhow!("maintenance pool: {e}"))?;
    let report = restore(maint.pool(), &records, cli.batch_size, cli.dry_run).await?;

    let mut buckets = serde_json::Map::new();
    for (name, ids) in report.buckets() {
        buckets.insert(
            name.to_string(),
            serde_json::json!({ "count": ids.len(), "ids": ids }),
        );
    }
    write_json(
        report_w,
        &serde_json::json!({
            "restore": true,
            "dry_run": cli.dry_run,
            "records": records.len(),
            "buckets": buckets,
        }),
    )?;
    if cli.dry_run {
        println!("DRY RUN: every batch rolled back");
    }
    println!("records: {}", records.len());
    for (name, ids) in report.buckets() {
        println!("{name}: {}", ids.len());
    }
    println!("report: {}", report_path.display());
    Ok(())
}
