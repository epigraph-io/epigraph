//! Operator binary: replay the administrative cascades that were deferred (or
//! failed) after a caller's supersede, dedup, consolidation or match-candidate
//! retirement (migration 117, batch W10).
//!
//! # Why this exists
//!
//! The cascade that follows each of those acts re-points and invalidates rows
//! OTHER writers own, so it runs only on a privileged maintenance connection.
//! A server without one -- a stdio agent container, which must never hold an
//! RLS-bypassing credential, or any server whose `MAINTENANCE_DATABASE_URL` is
//! unset -- still commits the caller's act and records the cascade as a
//! `cascade.deferred` `security_events` row in the act's own transaction. This
//! binary finds every deferred or failed cascade with no later
//! `cascade.admin_applied` row for the same cause and subject and runs the same
//! repair the request path would have (`epigraph_engine::admin_cascade::
//! replay_deferred`). Each repair re-verifies the committed act and is
//! idempotent, so a replay of an already-repaired or undone act changes nothing
//! it should not; every applied replay writes its own audit row naming the
//! original caller, the deferral it replays and `--replayed-by`.
//!
//! # Authority
//!
//! This is the direct entry point that cascades across owners, so it demands
//! the administrative credential explicitly: `MAINTENANCE_DATABASE_URL` must be
//! SET (the documented fallback to `DATABASE_URL` is refused, so the
//! application DSN never derives this act) and its login must bypass row
//! security. Schedule it (systemd timer) on the host that holds that DSN; see
//! the deploy runbook.

use anyhow::{anyhow, bail, Context};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "replay_deferred_cascades",
    about = "Replay deferred or failed administrative cascades (migration 117) on the \
             maintenance connection"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the work runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Maximum deferral rows to consider this run.
    #[arg(long, default_value_t = 200)]
    limit: i64,

    /// Who is running the replay; recorded in every applied row's `replay_of`.
    #[arg(long, default_value = "replay_deferred_cascades")]
    replayed_by: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();

    let maint =
        epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "replay_deferred_cascades")
            .await
            .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(
            "replay_deferred_cascades re-points and invalidates rows across every owner, so it \
             runs only on an explicitly configured MAINTENANCE_DATABASE_URL; it is unset, and \
             the application DSN is never used for this"
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
    let report =
        epigraph_engine::admin_cascade::replay_deferred(conn, viewer, &cli.replayed_by, cli.limit)
            .await
            .context("list the pending deferrals")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).context("serialize the replay report")?
    );
    if report.failed > 0 || report.unreadable > 0 {
        bail!(
            "{} replay(s) failed and {} deferral row(s) were unreadable; they stay pending",
            report.failed,
            report.unreadable
        );
    }
    Ok(())
}
