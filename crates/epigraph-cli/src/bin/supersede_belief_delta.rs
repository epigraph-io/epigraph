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
//! * `r173` (opt-in): the calibration delta of ruling R-173, for every claim
//!   holding a live typed BBA: its owner frame folded under the empty
//!   calibration vocabulary (E) and the shipped one (F), what a recompute
//!   would write (A), the stored cache (S), the components, the regime that
//!   wrote the cache and the apply lists L1 / L2 / L3
//!   (`epigraph_engine::supersede_delta::r173`). It refuses to run when the
//!   served calibration reports a startup problem, and records the
//!   calibration's source and both profiles' hashes. Run it with
//!   `CALIBRATION_PATH` unset so F is the calibration this binary was built
//!   with.
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
//!     supersede_belief_delta --json <out.json> [--items r131,k10-retro,k12b,r173] [--top 200]
//!         [--thresholds 0.3,0.5,0.75] [--chunk N] [--canary <claim id>]
//!         [--only <file of claim ids>] [--statement-timeout-ms N]
//!
//! `--chunk N` runs `r173` in one read-only transaction for its candidate
//! list and one per N claims (each snapshot is recorded; chunks see
//! different snapshots); without it every item shares one transaction.
//! `--only` restricts `r173` to the listed ids (one per line), e.g. to
//! re-measure an apply list after it was applied.
//!
//! Connection: `DATABASE_URL`, with `MAINTENANCE_DATABASE_URL` taking
//! precedence (`epigraph_cli::MaintenancePool`).

use std::io::Write;
use std::path::PathBuf;

use clap::Parser;

use epigraph_db::visibility::SystemReason;
use epigraph_engine::supersede_delta::r173::{calibration_identity, R173Options};
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
    /// Comma-separated: r131, k10-retro, k12b, r173.
    #[arg(long, default_value = "r131,k10-retro,k12b")]
    items: String,
    /// How many top movers each block lists.
    #[arg(long, default_value_t = 200)]
    top: usize,
    /// r173: comma-separated BetP thresholds whose crossings are counted.
    #[arg(long, default_value = "0.3,0.5,0.75")]
    thresholds: String,
    /// r173: claims per read-only transaction (default: one transaction).
    #[arg(long)]
    chunk: Option<usize>,
    /// r173: a claim reported in full whatever its outcome (check C2).
    #[arg(long)]
    canary: Option<uuid::Uuid>,
    /// r173: measure only the claim ids in this file (one per line).
    #[arg(long)]
    only: Option<PathBuf>,
    /// `SET LOCAL statement_timeout` in every transaction, in milliseconds.
    #[arg(long)]
    statement_timeout_ms: Option<u64>,
}

fn parse_thresholds(list: &str) -> Result<Vec<f64>, String> {
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<f64>()
                .ok()
                .filter(|t| (0.0..=1.0).contains(t))
                .ok_or_else(|| format!("threshold `{s}` is not a number in [0, 1]"))
        })
        .collect()
}

fn read_ids(path: &std::path::Path) -> Result<Vec<uuid::Uuid>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            l.parse()
                .map_err(|e| format!("{}: `{l}` is not a claim id: {e}", path.display()))
        })
        .collect()
}

async fn run(cli: Cli) -> Result<(), String> {
    let items = DeltaItems::parse(&cli.items)?;
    let r173 = R173Options {
        thresholds: parse_thresholds(&cli.thresholds)?,
        chunk: cli.chunk,
        canary: cli.canary,
        only: cli.only.as_deref().map(read_ids).transpose()?,
    };
    if items.r173 {
        // Refuse before creating the report file or connecting.
        calibration_identity()?;
    }
    let opts = DeltaOptions {
        items,
        top: cli.top,
        statement_timeout_ms: cli.statement_timeout_ms,
        r173,
    };
    // Refuse an existing file before connecting: a report is never overwritten.
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&cli.json)
        .map_err(|e| format!("{}: {e}", cli.json.display()))?;
    // This run created the file: if it fails, remove it again, so a re-run is
    // not refused over an empty report.
    let result = measure_into(&cli, &opts, &mut out).await;
    if result.is_err() {
        drop(out);
        let _ = std::fs::remove_file(&cli.json);
    }
    result
}

async fn measure_into(
    cli: &Cli,
    opts: &DeltaOptions,
    out: &mut std::fs::File,
) -> Result<(), String> {
    let maint = epigraph_cli::MaintenancePool::connect("supersede_belief_delta")
        .await
        .map_err(|e| e.to_string())?;
    let mut session = maint
        .viewer(SystemReason::BeliefRecomputation)
        .await
        .map_err(|e| e.to_string())?;
    let (conn, viewer) = session.split();
    let report = run_read_only(conn, viewer, opts).await?;

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
    if let Some(r) = &report.r173 {
        println!("r173: calibration {}", r.calibration.source);
        println!(
            "r173: {} candidates, {} entered ({} current), {} unchanged, {} compound, \
             {} template-only; {} read-only transactions",
            r.counts.candidates,
            r.counts.entered,
            r.counts.entered_current,
            r.counts.unchanged,
            r.counts.skipped_compound,
            r.counts.skipped_template_only,
            r.snapshots.len()
        );
        println!(
            "r173: L1 {} (+{} not current), L2 {}, L3 {}, vacate {}",
            r.lists.l1.len(),
            r.lists.l1_not_current.len(),
            r.lists.l2.len(),
            r.lists.l3.len(),
            r.lists.vacate.len()
        );
        let c = &r.checks;
        println!(
            "r173 checks: C3 {} checked, {} violations (max {:.3e}); C5 {} (max raw fold \
             excursion {:.3e}); C7 {} checked, {} violations; A=F violations {}",
            c.c3_checked,
            c.c3_violations.len(),
            c.c3_max_abs_diff,
            c.c5_violations.len(),
            c.c5_max_raw_excursion,
            c.c7_checked,
            c.c7_violations.len(),
            c.a_matches_f_violations.len()
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
