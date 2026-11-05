//! Operator binary: build the shared Atlas theme layout (migration 197) from
//! PUBLIC current claims and public in-force edges, and write it as one
//! layout run.
//!
//! What it does, in ONE REPEATABLE READ transaction:
//!
//! 1. reads the visibility epoch, each theme's public-only centroid and the
//!    public link counts between themes
//!    (`AtlasLayoutRepository::read_public_inputs`);
//! 2. groups the themes with an embedded public member into regions (Ward
//!    clustering, the region count chosen by silhouette over 8..=15, or
//!    `--regions`), and places regions and themes in 2-D (deterministic PCA,
//!    each theme inside its region);
//! 3. with `--apply`, writes the run and keeps the newest `--keep` runs.
//!
//! DRY RUN BY DEFAULT: without `--apply` it prints the report and writes
//! nothing. The report is JSON on stdout (and in `--json PATH` when given):
//! params, counts, the region count and its scores, per-region labels and
//! public counts, link totals per relationship and the epoch. It names theme
//! labels and public counts, never claim text.
//!
//! The run is served only while no public claim or edge has been narrowed
//! since its snapshot (migration 197's epoch). Rerun this after every
//! restrict or privatize.
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET (the fallback to `DATABASE_URL` is
//! refused) and its login must bypass row security. A session advisory lock
//! keeps two runs from overlapping.
//!
//! Exit 0: the run finished (a dry run included). Exit 1: a refusal or a
//! database error (nothing is written: the run is one transaction). Exit 2:
//! an argument error.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context};
use clap::Parser;
use epigraph_cli::atlas_layout::build::{build_layout, BuildOptions};
use epigraph_db::repos::maintenance_lock::{self, ATLAS_LAYOUT_LOCK_KEY};
use epigraph_db::{AtlasLayoutRepository, Viewer};
use sqlx::{Connection, PgConnection};

#[derive(Parser, Debug)]
#[command(
    name = "atlas_layout",
    about = "Build the shared Atlas theme layout from public claims and edges (dry run unless \
             --apply), on the maintenance connection"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the work runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Write the run. Without it, nothing is written.
    #[arg(long, conflicts_with = "dry_run")]
    apply: bool,

    /// Explicit dry run (the default).
    #[arg(long)]
    dry_run: bool,

    /// Use this many regions instead of choosing by silhouette (clamped to
    /// 1..=min(placed themes, 200)).
    #[arg(long)]
    regions: Option<usize>,

    /// Themes with fewer embedded public members than this get no position.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(i64).range(1..))]
    min_public_members: i64,

    /// Runs to keep after --apply (the newest), at least 1.
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(i64).range(1..))]
    keep: i64,

    /// Also write the report to this file.
    #[arg(long)]
    json: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();

    let maint = epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "atlas_layout")
        .await
        .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(
            "atlas_layout writes the shared layout from every public row, so it runs only on an \
             explicitly configured MAINTENANCE_DATABASE_URL; it is unset, and the application \
             DSN is never used for this"
        );
    }
    // ThemeClustering is reused rather than adding a reason (viewer_ratchet.rs
    // holds the set). The bypass splices to nothing; what keeps the read
    // public-only is the literal `visibility = 'public'` in each statement.
    let mut session = maint
        .viewer(epigraph_db::visibility::SystemReason::ThemeClustering)
        .await
        .context("acquire the maintenance session")?;
    session
        .assert_privileged()
        .await
        .context("the maintenance connection cannot bypass row security")?;
    let (conn, viewer) = session.split();

    if !maintenance_lock::try_take(conn, ATLAS_LAYOUT_LOCK_KEY)
        .await
        .context("take the atlas_layout lock")?
    {
        bail!("another atlas_layout run holds the lock; nothing was written");
    }
    let outcome = run(conn, viewer, &cli).await;
    let _ = maintenance_lock::release(conn, ATLAS_LAYOUT_LOCK_KEY).await;
    let report = outcome?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).context("serialize the report")?
    );
    Ok(())
}

async fn run(
    conn: &mut PgConnection,
    viewer: &Viewer,
    cli: &Cli,
) -> anyhow::Result<serde_json::Value> {
    let mut tx = conn.begin().await.context("begin the build transaction")?;
    let inputs = AtlasLayoutRepository::read_public_inputs(&mut tx, viewer)
        .await
        .context("read the public layout inputs; nothing was written")?;
    let built = build_layout(
        &inputs,
        &BuildOptions {
            regions: cli.regions,
            min_public_members: cli.min_public_members,
        },
    )?;
    let mut report = built.report;
    report["applied"] = serde_json::Value::Bool(cli.apply);
    if cli.apply {
        let run_id = AtlasLayoutRepository::write_run(&mut tx, &built.build)
            .await
            .context("write the layout run; nothing was written")?;
        let pruned = AtlasLayoutRepository::prune_runs(&mut tx, cli.keep)
            .await
            .context("prune old layout runs; nothing was written")?;
        report["run_id"] = serde_json::json!(run_id);
        report["pruned_runs"] = serde_json::json!(pruned);
    }
    if let Some(path) = &cli.json {
        let text = serde_json::to_string_pretty(&report).context("serialize the report")?;
        std::fs::write(path, text).with_context(|| {
            format!(
                "write the report to {}; nothing was written",
                path.display()
            )
        })?;
    }
    if cli.apply {
        tx.commit().await.context("commit the layout run")?;
    } else {
        tx.rollback().await.context("roll back the dry run")?;
    }
    Ok(report)
}
