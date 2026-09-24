//! Prune the recall audit log past its retention window (backlog 8cbffa0e).
//!
//! Prunes two tables, both on the same retention window:
//!
//! - `recall_events` (backlog 8cbffa0e). MEASURED in prod 2026-07-28: recall
//!   runs ~30x/day, so 90-day retention stabilises this around half a
//!   megabyte. Housekeeping, not a disk control — the original
//!   "recall volume greatly exceeds claim volume" note was inherited from the
//!   design doc and never verified; it is wrong.
//! - `events` rows of TELEMETRY types only. This is the table that actually
//!   grows unbounded: 73,236 rows accumulated since 2026-03-06 with nothing
//!   pruning them.
//!
//! Runs from `prune-recall-events.timer` at 04:10 — after the 03:30
//! cross-source sweep and clear of the 01:00/02:00 pgBackRest windows, so a
//! large DELETE never overlaps a backup.

use anyhow::Context;
use clap::Parser;
use epigraph_db::RecallEventRepository;

#[derive(Parser, Debug)]
#[command(
    name = "prune_recall_events",
    about = "Delete recall_events rows older than the retention window"
)]
struct Cli {
    /// PostgreSQL connection URL.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Retention window in days. Defaults to RECALL_EVENTS_RETENTION_DAYS,
    /// then to 90.
    #[arg(long, env = "RECALL_EVENTS_RETENTION_DAYS")]
    retention_days: Option<i32>,

    /// Report how many rows WOULD be deleted without deleting them.
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();

    // Retention pruning is corpus-wide and is a DELETE. On an application
    // connection under FORCE the DELETE matches zero rows, the job exits 0,
    // and the retention window silently stops being enforced.
    // See `epigraph_cli::MaintenancePool`.
    let maint = epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "prune_recall_events")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("connect to database")?;
    let pool = maint.pool().clone();

    let days = cli
        .retention_days
        .filter(|d| *d > 0)
        .unwrap_or_else(RecallEventRepository::retention_days_from_env);

    if cli.dry_run {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM recall_events WHERE created_at < NOW() - make_interval(days => $1)",
        )
        .bind(days)
        .fetch_one(&pool)
        .await
        .context("count expired recall_events")?;
        let ev = RecallEventRepository::count_prunable_events(&pool, days)
            .await
            .context("count expired telemetry events")?;
        tracing::info!(
            retention_days = days,
            would_delete_recall_events = n,
            would_delete_telemetry_events = ev,
            "dry run; nothing deleted"
        );
        println!("dry-run ({days}d): {n} recall_events + {ev} telemetry events would be deleted");
        return Ok(());
    }

    let deleted = RecallEventRepository::prune_older_than(&pool, days)
        .await
        .context("prune recall_events")?;

    // Telemetry events are pruned in the same pass, on the same window. Only
    // types in PRUNABLE_EVENT_TYPES are touched — provenance events
    // (claim.created, edge.added, ...) are never deleted.
    let events_deleted = RecallEventRepository::prune_telemetry_events(&pool, days)
        .await
        .context("prune telemetry events")?;

    tracing::info!(
        retention_days = days,
        recall_events_deleted = deleted,
        telemetry_events_deleted = events_deleted,
        "retention pass complete"
    );
    println!(
        "deleted {deleted} recall_events + {events_deleted} telemetry events older than {days} days"
    );
    Ok(())
}
