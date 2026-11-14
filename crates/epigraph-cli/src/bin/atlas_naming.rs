//! Operator binary: LLM names for one Atlas map's groups (Atlas W8, backlog
//! a71816e1), for `--map public` or `--map team:<group uuid>`.
//!
//! ```text
//! atlas_naming name --map M [--max-calls N] [--model M] [--claude-bin PATH] [--apply]
//! ```
//!
//! `name` reads the map's latest finished run (both hierarchies), names every
//! group and leaf whose naming input changed since the last named run (the
//! others copy their earlier name with no model call), and with `--apply`
//! stores the result as a NEW finished run of the map: the same levels with
//! their names, the source run's params plus `naming`, and the source run's
//! epochs. DRY RUN BY DEFAULT: without `--apply` it calls no model and writes
//! nothing; the report says how many levels it would name (`deferred`).
//!
//! Names are made only from text every viewer of the map can read: member
//! text is read through the map-scoped read (public claims, plus the team's
//! own on a team map). The model is the Claude CLI on this box (`claude -p`,
//! with `ANTHROPIC_API_KEY` removed from its environment: never an API key).
//! Claim text leaves the box only to the model, through that CLI.
//!
//! `--max-calls` bounds one run; groups past it stay flagged and are named by
//! the next run. Undo: delete the `atlas_map_runs` row the report prints
//! (`run_id`) as the maintenance login; its levels go with it and the source
//! run is served again.
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET and its login must bypass row
//! security (a team map is built from that team's private rows).
//!
//! Exit 0: done (a dry run included). Exit 1: a refusal or an error (nothing
//! is written). Exit 2: an argument error.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use clap::{Parser, Subcommand};
use epigraph_cli::atlas_meaning::tree::parse_map_key;
use epigraph_cli::atlas_naming::backend::{ClaudeCliBackend, DEFAULT_MODEL};
use epigraph_cli::atlas_naming::build::{name_map, NameMapOptions};

#[derive(Parser, Debug)]
#[command(
    name = "atlas_naming",
    about = "Name an Atlas map's groups with the Claude CLI from text the map's viewers can \
             read, and store them as a new run (dry run unless --apply), on the maintenance \
             connection"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the work runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Name the map's latest finished run; with --apply, store it as a new run.
    Name {
        /// `public` or `team:<group uuid>`.
        #[arg(long)]
        map: String,
        /// At most this many model calls in this run (at least 1).
        #[arg(long)]
        max_calls: Option<usize>,
        /// The model the CLI is asked for.
        #[arg(long, default_value = DEFAULT_MODEL)]
        model: String,
        /// The Claude CLI program.
        #[arg(long, default_value = "claude")]
        claude_bin: PathBuf,
        /// Seconds one call may take before it is killed and counted failed.
        #[arg(long, default_value_t = 120)]
        timeout_secs: u64,
        /// Call the model and write the run. Without it, neither happens.
        #[arg(long)]
        apply: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let Cmd::Name {
        map,
        max_calls,
        model,
        claude_bin,
        timeout_secs,
        apply,
    } = cli.cmd;
    // Check the arguments before connecting.
    let map = parse_map_key(&map)?;
    if max_calls == Some(0) {
        bail!("--max-calls must be at least 1 (a dry run is the default)");
    }
    if timeout_secs == 0 {
        bail!("--timeout-secs must be at least 1");
    }

    let maint = epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "atlas_naming")
        .await
        .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(
            "atlas_naming reads a team's private rows, so it runs only on an explicitly \
             configured MAINTENANCE_DATABASE_URL; it is unset, and the application DSN is never \
             used for this"
        );
    }
    // The bypass splices to nothing; what keeps a map's names to its own
    // readers' text is the map predicate of the member-text read.
    let mut session = maint
        .viewer(epigraph_db::visibility::SystemReason::ThemeClustering)
        .await
        .context("acquire the maintenance session")?;
    session
        .assert_privileged()
        .await
        .context("the maintenance connection cannot bypass row security")?;
    let (conn, viewer) = session.split();

    let backend = ClaudeCliBackend::new(claude_bin, model, Duration::from_secs(timeout_secs))
        .context("prepare the Claude CLI's working directory")?;
    let report = name_map(
        conn,
        viewer,
        &backend,
        NameMapOptions {
            map,
            write: apply,
            max_calls,
        },
    )
    .await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).context("serialize the report")?
    );
    Ok(())
}
