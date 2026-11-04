//! Undo a targeted edge-factor rewire's row writes by compare-and-swap
//! (R-176(2) class E rollback, step 1 of 2).
//!
//! Reads the `--edge-rows` file a real `backfill_factors --phase rewire-edges
//! --sources-from-waves ...` run wrote and puts each rewritten
//! `mass_functions` row back to what the rewire found, but only where the
//! row is live and still holds exactly what the rewire wrote
//! (`epigraph_cli::edge_rewire::restore_edge_rows`). Rows written or
//! retracted since are reported and left alone; a retracted row is never
//! matched, so migration 184's retracted-row guard is never reached.
//!
//! Step 2 restores the target caches from the same run's `--snapshot` file:
//! `restore_belief_cache --from <snapshot>`. Run this first: LIFO, the rows
//! the caches were folded from come back before the caches do.
//!
//! The outcomes go to `--outcomes-out` (default `<edge-rows>.restore-<UTC
//! stamp>.outcomes.json`), which must not exist.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;

use clap::Parser;

use epigraph_cli::edge_rewire::{read_edge_row_records, restore_edge_rows};

#[derive(Parser, Debug)]
#[command(
    name = "restore_edge_factors",
    about = "Undo a targeted edge-factor rewire's row writes by compare-and-swap"
)]
struct Cli {
    /// The `--edge-rows` file of the rewire run to undo.
    #[arg(long)]
    edge_rows: PathBuf,
    /// Run the statements and roll every batch back.
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    outcomes_out: Option<PathBuf>,
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
    let records = read_edge_row_records(BufReader::new(
        File::open(&cli.edge_rows)
            .map_err(|e| anyhow::anyhow!("{}: {e}", cli.edge_rows.display()))?,
    ))
    .map_err(|e| anyhow::anyhow!("{}: {e}", cli.edge_rows.display()))?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let out_path = cli.outcomes_out.clone().unwrap_or_else(|| {
        let mut p = cli.edge_rows.as_os_str().to_owned();
        let suffix = if cli.dry_run { "-dry-run" } else { "" };
        p.push(format!(".restore-{stamp}{suffix}.outcomes.json"));
        PathBuf::from(p)
    });
    let mut out = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&out_path)
            .map_err(|e| anyhow::anyhow!("{}: {e}", out_path.display()))?,
    );

    let maint = epigraph_cli::MaintenancePool::connect("restore_edge_factors")
        .await
        .map_err(|e| anyhow::anyhow!("maintenance pool: {e}"))?;
    let report = restore_edge_rows(maint.pool(), &records, cli.dry_run).await?;
    serde_json::to_writer_pretty(&mut out, &report)?;
    out.write_all(b"\n")?;
    out.flush()?;
    println!(
        "restore_edge_factors{}: restored={} already_restored={} superseded_since_rewire={} \
         retracted_since_rewire={} missing={} (outcomes: {})",
        if cli.dry_run { " (dry run)" } else { "" },
        report.restored.len(),
        report.already_restored.len(),
        report.superseded_since_rewire.len(),
        report.retracted_since_rewire.len(),
        report.missing.len(),
        out_path.display()
    );
    Ok(())
}
