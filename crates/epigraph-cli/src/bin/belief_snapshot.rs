//! Operator binary: snapshot every current claim's belief-cache columns to a
//! JSON-lines file (SPEC §10.8 snapshot tooling; the baseline snapshot S0).
//!
//! Usage:
//!     belief_snapshot --out <path> [--page-size N] [--include-superseded]
//!
//! One line per claim: `{claim_id, belief, plausibility, pignistic_prob,
//! mass_on_empty, mass_on_missing, belief_frame_id, classification,
//! updated_at}`. The export is one consistent read (see
//! `epigraph_cli::belief_cache::write_snapshot`), on the maintenance
//! connection. Read-only: it writes nothing to the database.
//!
//! `--out` is never overwritten: a snapshot is the baseline later drift
//! reports are measured from, and a second run must not silently replace it.
//! The rows go to `<out>.partial` first and are linked to `<out>` only when
//! the export completes, so a failed run never leaves a truncated file under
//! the real name. Only the row count and the snapshot time are printed; the
//! ids stay in the file.

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use clap::Parser;

use epigraph_cli::belief_cache::{write_snapshot, SnapshotOptions, DEFAULT_SNAPSHOT_PAGE};

#[derive(Parser, Debug)]
#[command(
    name = "belief_snapshot",
    about = "Snapshot every current claim's belief-cache columns to a JSON-lines file"
)]
struct Cli {
    /// Output path (JSON lines). Refused if it, or `<out>.partial`, exists.
    #[arg(long)]
    out: PathBuf,
    /// Rows fetched per round trip.
    #[arg(long, default_value_t = DEFAULT_SNAPSHOT_PAGE)]
    page_size: i64,
    /// Include superseded (non-current) claims.
    #[arg(long)]
    include_superseded: bool,
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

async fn run(cli: Cli) -> anyhow::Result<()> {
    let mut partial = cli.out.clone().into_os_string();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    // Checked BEFORE connecting, so a refused run costs nothing.
    for p in [&cli.out, &partial] {
        if p.exists() {
            anyhow::bail!(
                "{} already exists; a snapshot is never overwritten",
                p.display()
            );
        }
    }

    let maint = epigraph_cli::MaintenancePool::connect("belief_snapshot")
        .await
        .map_err(|e| anyhow::anyhow!("maintenance pool: {e}"))?;

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)?;
    let mut w = BufWriter::new(file);
    let summary = write_snapshot(
        maint.pool(),
        &mut w,
        &SnapshotOptions {
            page_size: cli.page_size,
            include_superseded: cli.include_superseded,
        },
    )
    .await?;
    w.flush()?;
    w.get_ref().sync_all()?;
    drop(w);
    // A hard link refuses an existing target, unlike `rename`.
    std::fs::hard_link(&partial, &cli.out)?;
    std::fs::remove_file(&partial)?;

    println!("rows: {}", summary.rows);
    println!("snapshot_at: {}", summary.snapshot_at.to_rfc3339());
    Ok(())
}
