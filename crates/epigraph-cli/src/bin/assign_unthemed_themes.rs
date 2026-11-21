//! Assign every unthemed, embedded claim to its nearest theme, on the
//! maintenance connection (backlog d5f9829a).
//!
//! ```text
//! assign_unthemed_themes [--apply] [--max-batches N] [--batch-size N]
//! ```
//!
//! `POST /api/v1/themes/assign-unthemed` runs the same statement
//! (`ClaimThemeRepository::assign_unthemed_batch`) on the CALLER's
//! connection, so under row security a batch holding a claim the caller
//! cannot write is refused as a whole, and no token can place another team's
//! claims. Corpus-wide assignment is maintenance work, run here the way
//! `atlas_nightly` runs its theme step: on `MAINTENANCE_DATABASE_URL`, with a
//! bypass viewer (`SystemReason::ThemeClustering`).
//!
//! DRY RUN BY DEFAULT: without `--apply` nothing is written. The summary gives
//! the unthemed embedded count and, per theme, how many of those claims the
//! assignment would place there (`would_assign`, computed read-only by
//! `ClaimThemeRepository::preview_unthemed_assignment` with the writer's own
//! nearest-centroid ordering; centroids are not recomputed between batches, so
//! an `--apply` places claims exactly so). With `--max-batches N` the preview
//! covers the first `N * --batch-size` claims the scan meets: a sample, since
//! the writer's batches take whichever rows the scan meets first.
//!
//! `--apply` assigns in batches of `--batch-size` (1 to 1000), each committed
//! on its own, until a batch assigns nothing or `--max-batches` batches have
//! run. Run one small batch first (`--apply --max-batches 1`), then the rest.
//!
//! stdout is one JSON object:
//! `{"applied", "unthemed_before", "assigned", "unthemed_after", "batches",
//!   "batch_size", "max_batches", "would_assign"}`
//! (`batches` counts the batches that assigned at least one claim).
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET and its login must bypass row
//! security: the claims of every team are assigned, which no application
//! login can write. Exit 0: done (a dry run included). Exit 1: a refusal or a
//! database error (batches committed before it stay committed). Exit 2: an
//! argument error.

use anyhow::{anyhow, bail, Context};
use clap::Parser;
use epigraph_db::{AtlasMeaningRepository, ClaimThemeRepository};
use serde_json::json;

/// The same bound the nightly's theme step puts on its loop.
const LOOP_GUARD: u64 = 100_000;

#[derive(Parser, Debug)]
#[command(
    name = "assign_unthemed_themes",
    about = "Assign unthemed embedded claims to their nearest theme (dry run unless --apply), \
             on the maintenance connection"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the work runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Assign. Without it nothing is written and the summary says what would be.
    #[arg(long)]
    apply: bool,

    /// Stop after this many batches (at least 1). All of them by default.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    max_batches: Option<u64>,

    /// Claims per batch, 1 to 1000.
    #[arg(long, default_value_t = 500, value_parser = clap::value_parser!(i64).range(1..=1000))]
    batch_size: i64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();

    let maint =
        epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "assign_unthemed_themes")
            .await
            .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(
            "assign_unthemed_themes writes every team's claims, so it runs only on an explicitly \
             configured MAINTENANCE_DATABASE_URL; it is unset, and the application DSN is never \
             used for this"
        );
    }
    let mut session = maint
        .viewer(epigraph_db::visibility::SystemReason::ThemeClustering)
        .await
        .context("acquire the maintenance session")?;
    session
        .assert_privileged()
        .await
        .context("the maintenance connection cannot bypass row security")?;
    let (conn, viewer) = session.split();

    let unthemed_before = AtlasMeaningRepository::unthemed_embedded_count(conn, viewer).await?;
    let mut assigned = 0_i64;
    let mut batches = 0_u64;
    let mut would_assign = None;
    if cli.apply {
        for _ in 0..LOOP_GUARD {
            if cli.max_batches.is_some_and(|max| batches >= max) {
                break;
            }
            let n = ClaimThemeRepository::assign_unthemed_batch(&mut *conn, viewer, cli.batch_size)
                .await
                .with_context(|| {
                    format!("batch {} ({assigned} assigned before it)", batches + 1)
                })?;
            if n == 0 {
                break;
            }
            assigned += n;
            batches += 1;
            tracing::info!(
                batch = batches,
                assigned = n,
                total = assigned,
                "batch committed"
            );
        }
    } else {
        let limit = cli.max_batches.map(|max| {
            i64::try_from(max)
                .unwrap_or(i64::MAX)
                .saturating_mul(cli.batch_size)
        });
        would_assign = Some(
            ClaimThemeRepository::preview_unthemed_assignment(&mut *conn, viewer, limit).await?,
        );
    }
    let unthemed_after = AtlasMeaningRepository::unthemed_embedded_count(conn, viewer).await?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "applied": cli.apply,
            "unthemed_before": unthemed_before,
            "assigned": assigned,
            "unthemed_after": unthemed_after,
            "batches": batches,
            "batch_size": cli.batch_size,
            "max_batches": cli.max_batches,
            "would_assign": would_assign,
        }))
        .context("serialize the summary")?
    );
    Ok(())
}
