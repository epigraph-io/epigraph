//! Operator binary: undo a wave's belief-cache writes by compare-and-swap
//! (SPEC §10.8 rollback).
//!
//! Usage:
//!     restore_belief_cache --from <wave file> [--claims <ids file>] [--dry-run]
//!         [--batch-size N] [--outcomes-out <path>] [--downstream-out <path>]
//!
//! For each claim in the wave file (or in `--claims`, one id per line), the
//! claim's cache is put back to what the wave found, but only where it still
//! holds exactly what the wave wrote; see
//! `epigraph_cli::belief_cache::restore_wave` for the outcomes
//! (`restored`, `already_restored`, `superseded_since_wave`, `missing`,
//! `frame_gone`, `not_in_wave`). A second run is a no-op that reports
//! `already_restored`.
//!
//! Two files are written (never overwritten; by default next to the wave
//! file, named with the run's UTC time):
//!
//! * outcomes: `{claim_id, outcome}` for every claim considered;
//! * downstream: the edges a wave claim sourced after its wave write. Their
//!   edge-factor BBAs still carry the wave's value; re-wire exactly those
//!   targets afterwards (SPEC §10.8), then run the floor job.
//!
//! Only counts are printed; ids stay in the files. `--dry-run` runs the same
//! statements and rolls every batch back.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use serde::Serialize;
use uuid::Uuid;

use epigraph_cli::belief_cache::{
    downstream_edges, plan_restore, read_claim_ids, read_wave, restore_wave, RestoreOptions,
    DEFAULT_RESTORE_BATCH,
};

#[derive(Parser, Debug)]
#[command(
    name = "restore_belief_cache",
    about = "Undo a wave's belief-cache writes by compare-and-swap"
)]
struct Cli {
    /// Wave file (JSON lines `{claim_id, before, written, wave, at}`).
    #[arg(long)]
    from: PathBuf,
    /// Restore only these claims: one claim id per line; blank lines and
    /// lines starting with `#` are ignored.
    #[arg(long)]
    claims: Option<PathBuf>,
    /// Claims per transaction.
    #[arg(long, default_value_t = DEFAULT_RESTORE_BATCH)]
    batch_size: usize,
    /// Run every statement and roll each batch back.
    #[arg(long)]
    dry_run: bool,
    /// Per-claim outcomes file. Default: next to the wave file.
    #[arg(long)]
    outcomes_out: Option<PathBuf>,
    /// Downstream edges file. Default: next to the wave file.
    #[arg(long)]
    downstream_out: Option<PathBuf>,
}

#[derive(Serialize)]
struct Outcome<'a> {
    claim_id: Uuid,
    outcome: &'a str,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn default_out(from: &Path, run: &str, kind: &str) -> PathBuf {
    let mut p = from.as_os_str().to_owned();
    p.push(format!(".restore-{run}.{kind}.jsonl"));
    PathBuf::from(p)
}

fn create_new(path: &Path) -> anyhow::Result<BufWriter<File>> {
    let f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    Ok(BufWriter::new(f))
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let records = read_wave(BufReader::new(
        File::open(&cli.from).map_err(|e| anyhow::anyhow!("{}: {e}", cli.from.display()))?,
    ))
    .map_err(|e| anyhow::anyhow!("{}: {e}", cli.from.display()))?;
    let only = match &cli.claims {
        Some(p) => Some(read_claim_ids(BufReader::new(
            File::open(p).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?,
        ))?),
        None => None,
    };
    let plan = plan_restore(&records, only.as_ref());

    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let run_name = if cli.dry_run {
        format!("{stamp}-dry-run")
    } else {
        stamp
    };
    let outcomes_path = cli
        .outcomes_out
        .clone()
        .unwrap_or_else(|| default_out(&cli.from, &run_name, "outcomes"));
    let downstream_path = cli
        .downstream_out
        .clone()
        .unwrap_or_else(|| default_out(&cli.from, &run_name, "downstream"));
    // Opened before any write, so an unwritable or existing output path stops
    // the run before the database is touched.
    let mut outcomes_w = create_new(&outcomes_path)?;
    let mut downstream_w = create_new(&downstream_path)?;

    let maint = epigraph_cli::MaintenancePool::connect("restore_belief_cache")
        .await
        .map_err(|e| anyhow::anyhow!("maintenance pool: {e}"))?;
    let report = restore_wave(
        maint.pool(),
        &plan,
        &RestoreOptions {
            batch_size: cli.batch_size,
            dry_run: cli.dry_run,
        },
    )
    .await?;
    let downstream = downstream_edges(maint.pool(), &plan).await?;

    let buckets: [(&str, &Vec<Uuid>); 6] = [
        ("restored", &report.restored),
        ("already_restored", &report.already_restored),
        ("superseded_since_wave", &report.superseded_since_wave),
        ("missing", &report.missing),
        ("frame_gone", &report.frame_gone),
        ("not_in_wave", &report.not_in_wave),
    ];
    for (outcome, ids) in buckets {
        for &claim_id in ids {
            serde_json::to_writer(&mut outcomes_w, &Outcome { claim_id, outcome })?;
            outcomes_w.write_all(b"\n")?;
        }
    }
    outcomes_w.flush()?;
    for e in &downstream {
        serde_json::to_writer(&mut downstream_w, e)?;
        downstream_w.write_all(b"\n")?;
    }
    downstream_w.flush()?;

    if cli.dry_run {
        println!("DRY RUN: every batch rolled back");
    }
    println!("wave records: {}", records.len());
    for (outcome, ids) in buckets {
        println!("{outcome}: {}", ids.len());
    }
    println!("downstream_edges: {}", downstream.len());
    println!("outcomes: {}", outcomes_path.display());
    println!("downstream: {}", downstream_path.display());
    Ok(())
}
