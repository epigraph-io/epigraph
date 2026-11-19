//! Operator binary: enqueue one `EpiGraphJob` for the `drain_jobs` timer to
//! run, on the maintenance DSN (backlog batch B99).
//!
//! No route or CLI enqueued a job before this, so a scheduled job (the nightly
//! `ClusterGraph`, before `label_themes_llm --neighborhoods`) needed a
//! hand-written `INSERT INTO jobs`. This binary writes the row through the
//! queue code the drain reads from instead:
//!
//! ```text
//! enqueue_job --job '{"ClusterGraph":{"resolution":1.0,"retain_runs":3}}' --unique
//! echo '{"ClusterGraph":{"resolution":1.0,"retain_runs":3}}' | enqueue_job --dry-run
//! ```
//!
//! 1. The job is read from `--job` or, without it, from stdin, and validated
//!    by `epigraph_cli::enqueue_job::parse_job`: it must deserialize into an
//!    `EpiGraphJob` (an unknown or retired kind such as `ThemeClusterRebuild`
//!    is refused), carry no key its kind lacks, and not be a privatization
//!    kind (those are enqueued only by their HTTP dispatch).
//! 2. `--dry-run` prints the row it would write and exits without connecting.
//! 3. Otherwise `MAINTENANCE_DATABASE_URL` must be SET (the fallback to
//!    `DATABASE_URL` is refused, as the drain refuses it) and its login must
//!    satisfy `epigraph_bypass()`: since migration 119 an application session
//!    cannot enqueue at all.
//! 4. The row is `EpiGraphJob::into_job`, written by
//!    `PostgresJobQueue::enqueue`, or with `--unique` by
//!    `PostgresJobQueue::enqueue_unique_pending`, which writes nothing when a
//!    job of the same type is already pending (so a timer whose last job has
//!    not been drained yet does not stack a second one).
//!
//! The report is one JSON line on stdout: `job_id`, `job_type`, `payload`
//! and `outcome` (`enqueued`, `already_pending` or `dry_run`).
//!
//! Exit 0: enqueued, already pending, or a dry run. Exit 1: a refusal or an
//! error, with nothing written.
//!
//! `drain_jobs` runs only the job types it registers a handler for; a pending
//! job of any other type makes every drain exit 4 until
//! `drain_jobs --cancel-pending <TYPE>`. Enqueue only a type the drain runs.

use std::io::Read as _;

use anyhow::{anyhow, bail, Context};
use clap::Parser;
use epigraph_jobs::{JobQueue as _, PostgresJobQueue};

#[derive(Parser, Debug)]
#[command(
    name = "enqueue_job",
    about = "Validate a job as an EpiGraphJob and enqueue it for drain_jobs, on the \
             maintenance connection (--dry-run validates only)"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the enqueue runs on MAINTENANCE_DATABASE_URL, which must be
    /// set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,

    /// The job as JSON, e.g. '{"ClusterGraph":{"resolution":1.0,"retain_runs":3}}'.
    /// Read from stdin when absent.
    #[arg(long, value_name = "JSON")]
    job: Option<String>,

    /// Enqueue only if no job of the same type is pending.
    #[arg(long)]
    unique: bool,

    /// Validate and print the row; connect to nothing and write nothing.
    #[arg(long)]
    dry_run: bool,
}

/// The refusal when MAINTENANCE_DATABASE_URL is unset.
const UNSET_MAINTENANCE_DSN: &str = "enqueue_job writes the job queue, which drain_jobs runs \
     with maintenance authority, so it runs only on an explicitly configured \
     MAINTENANCE_DATABASE_URL; it is unset, and the application DSN is never used for this";

fn report(job: &epigraph_jobs::Job, outcome: &str, id: Option<uuid::Uuid>) -> String {
    serde_json::json!({
        "job_id": id,
        "job_type": job.job_type,
        "payload": job.payload,
        "outcome": outcome,
    })
    .to_string()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();

    let text = match cli.job {
        Some(text) => text,
        None => {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .context("read the job from stdin")?;
            text
        }
    };
    let job = epigraph_cli::enqueue_job::parse_job(&text).map_err(|e| anyhow!("refused: {e}"))?;
    let row = epigraph_cli::enqueue_job::job_row(job).map_err(|e| anyhow!("refused: {e}"))?;

    if cli.dry_run {
        println!("{}", report(&row, "dry_run", None));
        return Ok(());
    }

    let database_url = cli.database_url.context(
        "DATABASE_URL is not set (it names the database the maintenance DSN must match)",
    )?;
    // Refused before connecting, so an unset MAINTENANCE_DATABASE_URL never
    // opens a connection on the application DSN (checked again below on the
    // pool's own answer).
    let (_, dsn_source) =
        epigraph_db::maintenance_database_url(&database_url).map_err(|e| anyhow!("{e}"))?;
    if dsn_source != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(UNSET_MAINTENANCE_DSN);
    }
    let maint = epigraph_cli::MaintenancePool::connect_to(&database_url, "enqueue_job")
        .await
        .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(UNSET_MAINTENANCE_DSN);
    }
    // The session only proves the login bypasses row security: the queue's
    // pending-job guard must see every pending row, and 119 refuses an
    // enqueue from anything less. No reason fits a job enqueue exactly;
    // ThemeClustering names the scheduled job this binary was written for,
    // and adding a reason would raise the bypass-reason ratchet.
    let mut session = maint
        .viewer(epigraph_db::visibility::SystemReason::ThemeClustering)
        .await
        .context("acquire the maintenance session")?;
    session
        .assert_privileged()
        .await
        .context("the maintenance connection cannot bypass row security")?;
    drop(session);

    let queue = PostgresJobQueue::new(maint.pool().clone());
    let line = if cli.unique {
        match queue
            .enqueue_unique_pending(row.clone())
            .await
            .map_err(|e| anyhow!("{e}"))?
        {
            Some(id) => report(&row, "enqueued", Some(id.as_uuid())),
            None => report(&row, "already_pending", None),
        }
    } else {
        let id = queue
            .enqueue(row.clone())
            .await
            .map_err(|e| anyhow!("{e}"))?;
        report(&row, "enqueued", Some(id.as_uuid()))
    };
    println!("{line}");
    Ok(())
}
