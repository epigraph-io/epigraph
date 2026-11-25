//! Operator binary: rebuild the Beta-Bernoulli track (`claims.beta_alpha` /
//! `beta_beta`) of every claim `publicize_claims` or `share_claims_with_team`
//! moved before the act rebuilt the track itself (backlog 6e4ff46e).
//!
//! Such a claim still carries the track its OLD audience's evidence built,
//! including evidence that stayed behind, and serves it (and the divergence
//! rows later evidence writes recorded from it) to the new audience. This
//! runs the act's own rebuild on each of them and deletes their divergence
//! rows, as the act does: `epigraph_engine::visibility_act::rebuild_moved_beta_tracks`
//! states which claims, which evidence, and what is written.
//!
//! DRY RUN unless `--apply`: every claim's transaction is rolled back, and the
//! report lists each claim's track before and after and the divergence rows
//! that would go. Pass `--moved-before` the deploy time of the act's rebuild,
//! so claims moved since (already rebuilt by their act) are left alone.
//!
//! The report's `before` values are the record an operator needs to undo an
//! applying run (`UPDATE claims SET beta_alpha, beta_beta` per claim); the
//! deleted divergence rows are not restorable, as the act's own are not.
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET (the fallback to `DATABASE_URL` is
//! refused) and its login must bypass row security: the audit rows, claims and
//! evidence span every owner.
//!
//! Exit 0: the run finished (failed claims are listed in the report). Exit 1:
//! a refusal or an error outside one claim.

use anyhow::{anyhow, bail, Context};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "rebuild_moved_beta_tracks",
    about = "Rebuild beta_alpha/beta_beta of claims a share or publicize moved before the act \
             rebuilt them, from the evidence their current audience may read, on the \
             maintenance connection; dry run unless --apply"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the work runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Commit the rebuilt tracks and the divergence-row deletes. Without it,
    /// nothing is written.
    #[arg(long)]
    apply: bool,

    /// Only claims named by acts recorded before this time (RFC 3339): the
    /// deploy time of the act's own rebuild.
    #[arg(long, value_name = "RFC3339")]
    moved_before: Option<chrono::DateTime<chrono::Utc>>,
}

/// The refusal when MAINTENANCE_DATABASE_URL is unset.
const UNSET_MAINTENANCE_DSN: &str = "rebuild_moved_beta_tracks rewrites claims across every \
     owner, so it runs only on an explicitly configured MAINTENANCE_DATABASE_URL; it is unset, \
     and the application DSN is never used for this";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let (_, dsn_source) =
        epigraph_db::maintenance_database_url(&cli.database_url).map_err(|e| anyhow!("{e}"))?;
    if dsn_source != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(UNSET_MAINTENANCE_DSN);
    }
    let maint =
        epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "rebuild_moved_beta_tracks")
            .await
            .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(UNSET_MAINTENANCE_DSN);
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
    let report = epigraph_engine::visibility_act::rebuild_moved_beta_tracks(
        conn,
        viewer,
        cli.moved_before,
        cli.apply,
    )
    .await
    .map_err(|e| anyhow!("the rebuild failed; claims already committed stay so: {e}"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).context("serialize the report")?
    );
    Ok(())
}
