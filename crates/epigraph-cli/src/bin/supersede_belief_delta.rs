//! `supersede_belief_delta`: the read-only dry-run belief delta of the
//! supersede belief fixes (supersede SPEC §11 K0, X-3).
//!
//! It measures, on EXISTING rows, what each of these would change, without
//! changing anything:
//!
//! * `r131`: the factor backfill of ruling R-131 (factorless claim-to-claim
//!   `corroborates` / `refutes` edges between current claims), the
//!   retroactive face of K3: edges, slots a mint would fill, endpoints;
//! * `k10-retro`: the retroactive sweep K10(3) (operator decision OD-10):
//!   the live edge-keyed BBAs that already-retired claims' edges froze onto
//!   current claims, the retracted rows an invalidation would keep, and
//!   what removing the live ones does to each holder's served value;
//! * `k12b`: the live BBAs keyed on `supersedes` edges and what removing
//!   them would do (no deployed path removes them: a separate decision).
//!   The sheaf half moves no served obstruction: the sheaf readers never
//!   select `supersedes`.
//!
//! Every read runs in ONE `REPEATABLE READ READ ONLY` transaction on the
//! maintenance connection (`epigraph_engine::supersede_delta::run_read_only`);
//! any write inside it would fail with SQLSTATE 25006. It calls no recompute,
//! cascade or apply path. The selections are the ones the fixes use, from the
//! same module.
//!
//! The report names claim ids and values: write it to the operator's private
//! results directory, never into a repository. The file must not exist yet.
//! The JSON carries no timestamp, so two runs on one snapshot are
//! byte-identical.
//!
//! Usage:
//!     supersede_belief_delta --json <out.json> [--items r131,k10-retro,k12b] [--top 200]
//!
//! Connection: `DATABASE_URL`, with `MAINTENANCE_DATABASE_URL` taking
//! precedence (`epigraph_cli::MaintenancePool`).

use std::io::Write;
use std::path::PathBuf;

use clap::Parser;

use epigraph_db::visibility::SystemReason;
use epigraph_engine::supersede_delta::{run_read_only, DeltaItems, DeltaOptions};

#[derive(Parser, Debug)]
#[command(
    name = "supersede_belief_delta",
    about = "Read-only dry-run belief delta of the supersede belief fixes; writes nothing to the database"
)]
struct Cli {
    /// Where to write the JSON report (refused if the file exists).
    #[arg(long)]
    json: PathBuf,
    /// Comma-separated: r131, k10-retro, k12b.
    #[arg(long, default_value = "r131,k10-retro,k12b")]
    items: String,
    /// How many top movers each block lists.
    #[arg(long, default_value_t = 200)]
    top: usize,
}

async fn run(cli: Cli) -> Result<(), String> {
    let items = DeltaItems::parse(&cli.items)?;
    let opts = DeltaOptions {
        items,
        top: cli.top,
    };
    // Refuse an existing file before connecting: a report is never overwritten.
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&cli.json)
        .map_err(|e| format!("{}: {e}", cli.json.display()))?;

    let maint = epigraph_cli::MaintenancePool::connect("supersede_belief_delta")
        .await
        .map_err(|e| e.to_string())?;
    let mut session = maint
        .viewer(SystemReason::BeliefRecomputation)
        .await
        .map_err(|e| e.to_string())?;
    let (conn, viewer) = session.split();
    let report = run_read_only(conn, viewer, &opts).await?;

    let body = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    out.write_all(&body)
        .and_then(|()| out.write_all(b"\n"))
        .map_err(|e| format!("{}: {e}", cli.json.display()))?;

    println!(
        "transaction: read_only={}, isolation={}",
        report.transaction_read_only, report.transaction_isolation
    );
    if let Some(r) = &report.r131 {
        println!(
            "r131: {} factorless edges, {} slots a mint would fill, {} on held slots",
            r.edges, r.slots_minted, r.edges_on_held_slots
        );
    }
    if let Some(k) = &report.k10_retro {
        println!(
            "k10-retro: {} live rows on {} edges from {} retired sources; {} retracted kept; \
             {} claims affected ({} unbacked, {} moved > 0.10)",
            k.live_rows,
            k.edges,
            k.retired_sources,
            k.retracted_key_kept,
            k.delta.totals.claims,
            k.delta.totals.unbacked,
            k.delta.totals.moved_over_0_10
        );
    }
    if let Some(k) = &report.k12b {
        println!(
            "k12b: {} live rows keyed on supersedes edges; {} claims affected (counterfactual)",
            k.ds_rows, k.ds_delta.totals.claims
        );
    }
    println!("report written to {}", cli.json.display());
    Ok(())
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
