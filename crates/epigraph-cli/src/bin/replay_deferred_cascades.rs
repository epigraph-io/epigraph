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
//! `cascade.admin_applied` (or `cascade.retired`) row for the same cause and
//! subject and runs the same repair the request path would have
//! (`epigraph_engine::admin_cascade::replay_deferred`), fewest failed attempts
//! first, then oldest. Each repair re-verifies the committed act and is
//! idempotent, so a replay of an already-repaired or undone act changes nothing
//! it should not; every applied replay writes its own audit row naming the
//! original caller, the deferral it replays and `--replayed-by`.
//!
//! A deferred match-candidate retirement is different: its act, the flip to
//! `stale`, is administrative too (migration 118 refuses it on a
//! non-privileged session), so the deferral is the whole REQUEST and the
//! candidate was left as it was. The replay carries the request out (flip,
//! retraction and derived-row deletes in one transaction) only while the
//! candidate still has the status the deferral recorded; one decided again in
//! between fails loudly and stays pending until retired below. Read the
//! pending `match_retire` requests before a run if they need review.
//!
//! # Stuck cascades
//!
//! A cascade whose repair has failed `--max-failures` times (its act was
//! undone, say, so it can never verify) leaves the window and is listed under
//! `stuck` in the report; the run then exits non-zero (status 2) until an
//! operator reads why and retires it: `--retire <event id> --reason <text>`
//! writes a `cascade.retired` row, which answers that cascade's pending rows,
//! and runs no replay.
//!
//! # Authority
//!
//! This is the direct entry point that cascades across owners, so it demands
//! the administrative credential explicitly: `MAINTENANCE_DATABASE_URL` must be
//! SET (the documented fallback to `DATABASE_URL` is refused, so the
//! application DSN never derives this act) and its login must bypass row
//! security. Schedule it (systemd timer) on the host that holds that DSN; see
//! the deploy runbook.
//!
//! # Under operator decision D9 (batch W12a)
//!
//! No request-serving process holds the maintenance DSN, so EVERY cascade is
//! deferred and this binary, on `epigraph-cascade-replay.timer` (every 90 s,
//! `--max-failures 20`), is what applies them. A run takes the replay's own
//! session advisory lock first; a run that finds it held prints
//! `{"locked": true}` and exits 0 without touching anything.
//! `--report-only` prints `{"pending", "stuck", "oldest_age_s"}` from the same
//! pending set in a READ ONLY transaction and takes no lock, so the staleness
//! check can run beside a replay.

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

    /// Maximum cascades to replay this run.
    #[arg(long, default_value_t = 200)]
    limit: i64,

    /// A cascade whose repair has failed this many times is held out of the
    /// window and reported as stuck.
    #[arg(long, default_value_t = epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES)]
    max_failures: i64,

    /// Retire the pending cascade this deferred (or failed) row belongs to
    /// instead of replaying anything (repeatable). Requires --reason.
    #[arg(long = "retire", value_name = "EVENT_ID")]
    retire: Vec<uuid::Uuid>,

    /// Why the cascades named by --retire are retired; recorded in each row.
    #[arg(long, requires = "retire")]
    reason: Option<String>,

    /// Who is running the replay; recorded in every applied row's `replay_of`.
    #[arg(long, default_value = "replay_deferred_cascades")]
    replayed_by: String,

    /// Print the backlog as JSON `{"pending", "stuck", "oldest_age_s"}` and
    /// exit, in a READ ONLY transaction: nothing is replayed, retired or
    /// written. Takes no lock, so the staleness check can run beside a replay.
    #[arg(long, conflicts_with = "retire")]
    report_only: bool,
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

    if cli.report_only {
        use sqlx::Acquire;
        let mut tx = conn.begin().await.context("begin the report transaction")?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await
            .context("make the report transaction read-only")?;
        let summary =
            epigraph_db::repos::admin_cascade::pending_summary(&mut *tx, cli.max_failures)
                .await
                .context("read the replay backlog")?;
        tx.rollback().await.context("end the report transaction")?;
        println!(
            "{}",
            serde_json::to_string(&summary).context("serialize the backlog summary")?
        );
        return Ok(());
    }

    // Operator decision D9 (batch W12a): this runs on a timer every 90 s, and an
    // operator may run it by hand; the replay's own advisory lock keeps two runs
    // from racing over the same cascades. A run that finds it held does nothing.
    if !epigraph_db::repos::maintenance_lock::try_take(
        &mut *conn,
        epigraph_db::repos::maintenance_lock::REPLAY_LOCK_KEY,
    )
    .await
    .context("take the replay lock")?
    {
        println!("{}", serde_json::json!({ "locked": true }));
        return Ok(());
    }

    if !cli.retire.is_empty() {
        let reason = cli
            .reason
            .as_deref()
            .filter(|r| !r.trim().is_empty())
            .ok_or_else(|| anyhow!("--retire needs a non-empty --reason"))?;
        let mut retired = Vec::new();
        for event_id in &cli.retire {
            let id = epigraph_db::repos::admin_cascade::retire_pending(
                &mut *conn,
                *event_id,
                &cli.replayed_by,
                reason,
            )
            .await
            .with_context(|| format!("retire the pending cascade of row {event_id}"))?;
            retired.push(serde_json::json!({"retired_event_id": event_id, "audit_event_id": id}));
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "retired": retired }))
                .context("serialize the retire report")?
        );
        return Ok(());
    }

    let report = epigraph_engine::admin_cascade::replay_deferred(
        conn,
        viewer,
        &cli.replayed_by,
        cli.limit,
        cli.max_failures,
    )
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
    if !report.stuck.is_empty() {
        eprintln!(
            "{} cascade(s) failed {} times or more and are held out of the replay; read why and \
             retire each with --retire <deferred_event_id> --reason <text>",
            report.stuck.len(),
            cli.max_failures
        );
        std::process::exit(2);
    }
    Ok(())
}
