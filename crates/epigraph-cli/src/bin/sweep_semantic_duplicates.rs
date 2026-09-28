//! Operator binary: sweep one page of the corpus for semantic near-duplicates
//! and (with `--apply`) collapse the exact restatements, on the maintenance
//! connection (operator decision D9, batch W12a).
//!
//! # Why a CLI
//!
//! The sweep pairs claims across every tenant and retires one of each pair
//! across every writer's rows, which is an administrative act (D1) on a
//! privileged maintenance connection. D9 removes that connection from every
//! request-serving process, so the MCP tool of the same name answers MOVED and
//! names this binary.
//!
//! # What it does
//!
//! `epigraph_mcp::tools::dedup_sweep::sweep`: enumerate a page, cluster near
//! neighbours, and (only with `--apply`) collapse each exact-restatement pair
//! through the act (`ClaimRepository::mark_duplicate_act_conn`) and the
//! administrative cascade (`admin_cascade::apply_after_dedup`). Every collapsed
//! pair gets ONE `cascade.admin_applied` row naming `--acting-agent` as the
//! trigger, with cause `dedup`, so each collapse is audited as D1 requires.
//! The act's own transaction also records the pair's pending cascade
//! (`cascade.deferred`), which that applied row answers: a run killed between
//! the act and its cascade leaves the pair for `replay_deferred_cascades`
//! instead of unaudited. While a replay run holds the replay's lock, the pair
//! is left to it (`left_to_replay` in the report; not a failure).
//! Clusters whose wording differs are only reported, never collapsed.
//!
//! DRY RUN BY DEFAULT: without `--apply` it lists the clusters and writes
//! nothing.
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET (the fallback to `DATABASE_URL` is
//! refused) and its login must bypass row security. `--acting-agent` is
//! REQUIRED and must name an existing agent: it is the operator the audit rows
//! attribute each collapse to. A second concurrent run finds the sweep's
//! advisory lock held, prints `{"locked": true}` and exits 0.
//!
//! Exit 0: the page was swept (or locked). Exit 1: a refusal, a read failure,
//! or any per-pair failure (listed in `failures`).

use anyhow::{anyhow, bail, Context};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "sweep_semantic_duplicates",
    about = "Sweep one page for semantic near-duplicates and (with --apply) collapse exact \
             restatements, audited, on the maintenance connection"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the work runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// The operator agent every collapse is attributed to in its audit row.
    /// Required.
    #[arg(long, value_name = "AGENT_ID")]
    acting_agent: uuid::Uuid,

    /// Collapse the exact-restatement pairs. Without it, nothing is written.
    #[arg(long)]
    apply: bool,

    /// Cosine distance below which two claims pair (default 0.10).
    #[arg(long)]
    similarity_threshold: Option<f64>,

    /// Page size (default 500, at most 2000).
    #[arg(long)]
    limit: Option<i64>,

    /// Page offset; pass the previous run's `next_offset` to continue.
    #[arg(long)]
    offset: Option<i64>,

    /// Restrict to claims by these agents (repeatable).
    #[arg(long = "agent-scope", value_name = "AGENT_ID")]
    agent_scope: Vec<uuid::Uuid>,

    /// Restrict to claims carrying these labels (repeatable).
    #[arg(long = "label", value_name = "LABEL")]
    labels: Vec<String>,
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
        epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "sweep_semantic_duplicates")
            .await
            .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(
            "sweep_semantic_duplicates retires claims across every writer, so it runs only on an \
             explicitly configured MAINTENANCE_DATABASE_URL; it is unset, and the application \
             DSN is never used for this"
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

    {
        let (conn, _) = session.split();
        let locked = !epigraph_db::repos::maintenance_lock::try_take(
            &mut *conn,
            epigraph_db::repos::maintenance_lock::SWEEP_LOCK_KEY,
        )
        .await
        .context("take the sweep lock")?;
        if locked {
            println!("{}", serde_json::json!({ "locked": true }));
            return Ok(());
        }
        let agent = epigraph_db::AgentRepository::get_by_id(
            &mut *conn,
            epigraph_core::AgentId::from_uuid(cli.acting_agent),
        )
        .await
        .context("look up --acting-agent")?;
        if agent.is_none() {
            bail!(
                "--acting-agent {} is not an agent; every collapse is attributed to it in its \
                 audit row, so it must exist",
                cli.acting_agent
            );
        }
    }

    let params = epigraph_mcp::types::SweepSemanticDuplicatesParams {
        similarity_threshold: cli.similarity_threshold,
        agent_scope: (!cli.agent_scope.is_empty())
            .then(|| cli.agent_scope.iter().map(ToString::to_string).collect()),
        labels_scope: (!cli.labels.is_empty()).then(|| cli.labels.clone()),
        dry_run: Some(!cli.apply),
        limit: cli.limit,
        offset: cli.offset,
    };
    let report = epigraph_mcp::tools::dedup_sweep::sweep(&mut session, &params, cli.acting_agent)
        .await
        .context("the sweep's reads failed; nothing was collapsed after the failure")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).context("serialize the sweep report")?
    );
    if !report.failures.is_empty() {
        bail!("{} pair(s) failed; see `failures`", report.failures.len());
    }
    Ok(())
}
