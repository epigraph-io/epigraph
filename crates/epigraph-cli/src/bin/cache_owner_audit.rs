//! `cache_owner_audit`: the read-only measurement for the cache-owner repair
//! (backlog d33a5c9f). See `epigraph_cli::cache_owner_audit` for the
//! categories and what each one means.
//!
//! Every read runs in ONE `REPEATABLE READ READ ONLY` transaction on the
//! maintenance connection, which is rolled back at the end: any write inside
//! it would fail with SQLSTATE 25006. It calls no recompute and repairs
//! nothing.
//!
//! Output: the summary (JSON) on stdout, and one JSON line per finding in
//! `--out`, which must not exist yet (it is removed again when the run
//! fails). Category (1) feeds the existing recompute:
//!
//! ```text
//! jq -r 'select(.category == "repointed_cache") | .claim_id' <out> \
//!     | recompute_claim_belief --stdin
//! ```
//!
//! Category (2) (`compound_cached`) is report-only: `recompute_claim_belief`
//! skips a compound, which has no cache owner. Category (3)
//! (`edge_without_bba`) and (4) (`edge_bba_off_endpoint`, an edge whose BBA a
//! supersede left on the retired target) are report-only too.
//!
//! The file names claim and edge ids: write it to the operator's private
//! results directory, never into a repository.
//!
//! Usage:
//!     cache_owner_audit --out <findings.jsonl> [--limit N] [--sample N]
//!         [--page-size N] [--statement-timeout-ms N] [--api-signer <agent id>]...
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET (the fallback to `DATABASE_URL` is
//! refused) and its login must bypass row security: on an application
//! session row security would hide most claims and the counts would be low
//! without saying so.

use anyhow::{anyhow, bail, Context};
use clap::Parser;
use std::path::PathBuf;

use epigraph_cli::cache_owner_audit::{run_read_only, Options, DEFAULT_PAGE, MAX_PAGE};

#[derive(Parser, Debug)]
#[command(
    name = "cache_owner_audit",
    about = "Read-only audit of belief caches against the cache-owner rule (re-pointed caches, \
             cached compounds, epistemic edges with no edge-keyed BBA); writes nothing to the \
             database"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the audit runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Where to write one JSON line per finding (refused if the file exists).
    #[arg(long, value_name = "PATH")]
    out: PathBuf,

    /// Stop each pass (claims, then edges) after this many rows; the summary
    /// says whether each pass finished.
    #[arg(long)]
    limit: Option<u64>,

    /// How many ids each category lists in the summary.
    #[arg(long, default_value_t = 10)]
    sample: usize,

    /// Rows per keyset page.
    #[arg(long, default_value_t = DEFAULT_PAGE)]
    page_size: i64,

    /// `SET LOCAL statement_timeout` in the audit's transaction, in milliseconds.
    #[arg(long)]
    statement_timeout_ms: Option<u64>,

    /// An agent whose edge signatures mark an edge as created over HTTP, besides
    /// the API's own signer agent (found by its display name). Repeatable. When
    /// several agents carry that display name, the run is refused unless this
    /// is given, and then only these agents count.
    #[arg(long, value_name = "AGENT_ID")]
    api_signer: Vec<uuid::Uuid>,
}

/// The refusal when MAINTENANCE_DATABASE_URL is unset.
const UNSET_MAINTENANCE_DSN: &str = "cache_owner_audit reads claims across every owner, so it \
     runs only on an explicitly configured MAINTENANCE_DATABASE_URL; it is unset, and the \
     application DSN is never used for this";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    if !(1..=MAX_PAGE).contains(&cli.page_size) {
        bail!("--page-size must be between 1 and {MAX_PAGE}");
    }
    // Refused before the file is created or a connection is opened.
    let (_, dsn_source) =
        epigraph_db::maintenance_database_url(&cli.database_url).map_err(|e| anyhow!("{e}"))?;
    if dsn_source != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(UNSET_MAINTENANCE_DSN);
    }

    // Created before connecting, so an existing file refuses the run before it
    // touches the database; removed again if the run fails, so a re-run is not
    // refused over a partial file.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&cli.out)
        .with_context(|| format!("create {}", cli.out.display()))?;
    let result = audit(&cli, file).await;
    if result.is_err() {
        let _ = std::fs::remove_file(&cli.out);
    }
    let report = result?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).context("serialize the report")?
    );
    eprintln!(
        "findings: {} (feed category 1 to recompute_claim_belief: jq -r 'select(.category == \
         \"repointed_cache\") | .claim_id' <out> | recompute_claim_belief --stdin)",
        cli.out.display()
    );
    Ok(())
}

async fn audit(
    cli: &Cli,
    file: std::fs::File,
) -> anyhow::Result<epigraph_cli::cache_owner_audit::Report> {
    let maint = epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "cache_owner_audit")
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
    let opts = Options {
        page_size: cli.page_size,
        limit: cli.limit,
        sample: cli.sample,
        statement_timeout_ms: cli.statement_timeout_ms,
        api_signers: cli.api_signer.clone(),
    };
    let mut sink = std::io::BufWriter::new(file);
    let report = run_read_only(conn, viewer, &opts, &mut sink)
        .await
        .map_err(|e| anyhow!("the audit failed: {e}"))?;
    let file = sink
        .into_inner()
        .map_err(|e| anyhow!("flush {}: {e}", cli.out.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", cli.out.display()))?;
    if !report.transaction_read_only {
        bail!("the audit's transaction was not READ ONLY; its findings are not trusted");
    }
    Ok(report)
}
