//! Prune the recall audit log past its retention window (backlog 8cbffa0e).
//!
//! Recall volume greatly exceeds claim volume, so `recall_events` grows
//! without bound if nothing removes old rows — a real disk-exhaustion risk on
//! a host that has already hit disk pressure. Driven by the daily reconciler
//! cron, alongside `cross_source_sweep`.

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

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&cli.database_url)
        .await
        .context("connect to database")?;

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
        tracing::info!(
            retention_days = days,
            would_delete = n,
            "dry run; nothing deleted"
        );
        println!("dry-run: {n} recall_events older than {days} days would be deleted");
        return Ok(());
    }

    let deleted = RecallEventRepository::prune_older_than(&pool, days)
        .await
        .context("prune recall_events")?;
    tracing::info!(retention_days = days, deleted, "pruned recall_events");
    println!("deleted {deleted} recall_events older than {days} days");
    Ok(())
}
