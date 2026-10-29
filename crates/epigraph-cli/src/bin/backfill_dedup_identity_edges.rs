//! Operator binary: write the missing `same_as` identity edge of every
//! duplicate the legacy raw-SQL `fuzzy_dedup_claims` marked (backlog d5781a48).
//!
//! Before 2026-10 `scripts/fuzzy_dedup_claims.py` retired duplicates with its
//! own `UPDATE claims` and recorded no identity edge, so the dedup index view
//! does not list them under their canonical. The selection rule and what the
//! edge carries are on
//! `ClaimRepository::backfill_legacy_dedup_identity_edges_conn`.
//!
//! DRY RUN BY DEFAULT: without `--apply` it prints the duplicates it would
//! give an edge and writes nothing. A re-run after `--apply` selects nothing.
//!
//! Once a mark has its edge it is an ordinary dedup record (operator ruling
//! R-7): `unmark_duplicate` makes the duplicate current again and retracts the
//! edge. The legacy script kept no repair record, so there is nothing to put
//! back; the un-mark says so (`legacy_mark`). A legacy mark this binary cannot
//! reach is refused by the un-mark with the reason.
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET (the fallback to `DATABASE_URL` is
//! refused) and its login must bypass row security: the selection is
//! corpus-wide, and on an application session RLS would hide most rows.
//!
//! Exit 0: the run finished. Exit 1: a refusal or a database error (nothing
//! is written: the run is one transaction).

use anyhow::{anyhow, bail, Context};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "backfill_dedup_identity_edges",
    about = "Write the missing dedup identity edge of each legacy fuzzy_dedup_claims duplicate \
             (dry run unless --apply), on the maintenance connection"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the work runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Write the edges. Without it, nothing is written.
    #[arg(long, conflicts_with = "dry_run")]
    apply: bool,

    /// Explicit dry run (the default).
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();

    let maint = epigraph_cli::MaintenancePool::connect_to(
        &cli.database_url,
        "backfill_dedup_identity_edges",
    )
    .await
    .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(
            "backfill_dedup_identity_edges writes edges across every owner, so it runs only on \
             an explicitly configured MAINTENANCE_DATABASE_URL; it is unset, and the \
             application DSN is never used for this"
        );
    }
    let mut session = maint
        .viewer(epigraph_db::visibility::SystemReason::DedupSweep)
        .await
        .context("acquire the maintenance session")?;
    session
        .assert_privileged()
        .await
        .context("the maintenance connection cannot bypass row security")?;
    let (conn, _) = session.split();

    let report =
        epigraph_db::ClaimRepository::backfill_legacy_dedup_identity_edges_conn(conn, cli.apply)
            .await
            .context("the backfill failed; nothing was written")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).context("serialize the report")?
    );
    Ok(())
}
