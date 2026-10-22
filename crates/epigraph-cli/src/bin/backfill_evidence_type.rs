//! Operator binary: type the legacy `mass_functions` rows whose stored
//! provenance determines their evidence type (backlog bc06ec6f).
//!
//! The rules, and every reason a row is left NULL, are in
//! `epigraph_cli::evidence_type_backfill`. In short: a type is derived through
//! `CalibrationConfig::canonical_evidence_type` exactly as #573's writers derive
//! it, cached combination rows are never typed, and an ambiguous row stays NULL
//! and is counted.
//!
//! DRY RUN BY DEFAULT: without `--apply` it prints the per-writer counts of
//! what it would type and what it would leave NULL, and writes nothing.
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET (the fallback to `DATABASE_URL` is
//! refused) and its login must bypass row security: the work is corpus-wide,
//! and on an application session RLS would hide most rows and the run would
//! report a fraction of the corpus as if it were all of it.
//!
//! # Calibration
//!
//! `--calibration` is REQUIRED and must load. The typed rows' weight comes
//! from that file, and a missing file would otherwise fall back to empty maps:
//! every row would stay NULL and the run would exit 0 as a clean no-op. The
//! path is printed in the report so a dry run and its apply can be compared.
//!
//! # Batches and resuming
//!
//! Keyset pages of `--batch` rows in `id` order, each written in its own
//! transaction, and only to rows still untyped, so a re-run is a no-op on rows
//! already typed. `--max-batches` bounds a run; pass its `last_id` as
//! `--after` to continue.
//!
//! Exit 0: the run finished (or stopped at `--max-batches`). Exit 1: a refusal
//! or a database error (batches already written stay written).

use anyhow::{anyhow, bail, Context};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "backfill_evidence_type",
    about = "Type legacy untyped BBAs whose stored provenance determines their evidence type \
             (dry run unless --apply), on the maintenance connection"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the work runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// The calibration.toml the API and MCP servers use. Required.
    #[arg(long, value_name = "PATH")]
    calibration: std::path::PathBuf,

    /// Write the types. Without it, nothing is written.
    #[arg(long, conflicts_with = "dry_run")]
    apply: bool,

    /// Explicit dry run (the default).
    #[arg(long)]
    dry_run: bool,

    /// Rows per batch (default 1000, at most 10000).
    #[arg(long, default_value_t = 1000)]
    batch: i64,

    /// Resume after this mass_functions id (a previous run's `last_id`).
    #[arg(long, value_name = "ID")]
    after: Option<uuid::Uuid>,

    /// Stop after this many batches.
    #[arg(long)]
    max_batches: Option<u64>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    if !(1..=10_000).contains(&cli.batch) {
        bail!("--batch must be between 1 and 10000");
    }
    let calibration = epigraph_engine::calibration::CalibrationConfig::load(&cli.calibration)
        .map_err(|e| anyhow!("--calibration {}: {e}", cli.calibration.display()))?;
    if calibration.evidence_type_weights.is_empty() {
        bail!(
            "--calibration {} has no [evidence_type_weights]; nothing could be typed",
            cli.calibration.display()
        );
    }

    let maint =
        epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "backfill_evidence_type")
            .await
            .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(
            "backfill_evidence_type rewrites rows across every owner, so it runs only on an \
             explicitly configured MAINTENANCE_DATABASE_URL; it is unset, and the application \
             DSN is never used for this"
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
    let (conn, _) = session.split();

    let opts = epigraph_cli::evidence_type_backfill::Options {
        apply: cli.apply,
        batch: cli.batch,
        after: cli.after,
        max_batches: cli.max_batches,
    };
    let report = epigraph_cli::evidence_type_backfill::run(conn, &calibration, &opts)
        .await
        .context("the backfill failed; batches already written stay written")?;
    let mut out = serde_json::to_value(&report).context("serialize the report")?;
    out["calibration"] = serde_json::Value::String(cli.calibration.display().to_string());
    println!(
        "{}",
        serde_json::to_string_pretty(&out).context("serialize the report")?
    );
    Ok(())
}
