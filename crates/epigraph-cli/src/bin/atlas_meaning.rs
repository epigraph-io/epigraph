//! Operator binary: the box-side halves of the Atlas "by meaning" hierarchy
//! (Atlas W4, backlog f9fc052c), for one map (`--map public` or
//! `--map team:<group uuid>`).
//!
//! ```text
//! atlas_meaning export --map M --out DIR [--theme-id T]... [--cap 100] [--seed 42]
//! python3 scripts/atlas_meaning_core.py compute --from DIR --out result.json   # anywhere
//! atlas_meaning apply  --map M --from result.json [--from result2.json]... [--cap 100] [--apply]
//! ```
//!
//! A run is the WHOLE map: `apply` refuses a result that lacks any theme the
//! map draws with an embedded member (the latest finished run is what is
//! served, so a partial run would hide the other themes). To keep exports
//! small, export in `--theme-id` batches into separate directories, compute
//! each, and apply all the results at once with repeated `--from`; they must
//! share map, cap, seed and library versions.
//!
//! * `export` writes, per theme the map draws, its current embedded members'
//!   ids and embeddings and each member's agents and evidence (after W3's
//!   per-claim cap) as per-theme integers. No text, no agent or evidence id.
//!   It writes nothing to the database. The report (stdout) gives counts per
//!   theme, including the current members left out for having no embedding.
//! * `apply` re-reads everything in one snapshot, refuses a result whose
//!   leaves are not exactly each theme's members now or whose ids are not the
//!   minted ones, re-counts every leaf with W3 and splits one over the cap,
//!   and (with `--apply`) writes one finished run of the map. DRY RUN BY
//!   DEFAULT: without `--apply` it builds every document and writes nothing.
//!
//! The run holds the meaning hierarchy only; as the map's latest finished run
//! it hides any earlier run's links levels (the nightly writes both into one
//! run instead).
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET (the fallback to `DATABASE_URL` is
//! refused) and its login must bypass row security: a team map is built from
//! that team's private rows, which no application session reads whole.
//!
//! Exit 0: done (a dry run included). Exit 1: a refusal or an error (nothing
//! is written: each step is one transaction). Exit 2: an argument error.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context};
use clap::{Parser, Subcommand};
use epigraph_cli::atlas_meaning::build::{apply_result, export_map, ExportOptions};
use epigraph_cli::atlas_meaning::files::{merge_results, prepare_export_dir, read_result};
use epigraph_cli::atlas_meaning::tree::parse_map_key;
use epigraph_db::repos::atlas_leaf::ATLAS_LEAF_NODE_CAP;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(
    name = "atlas_meaning",
    about = "Export a map's themes for the off-box \"by meaning\" clustering, or apply its \
             result as one Atlas run (dry run unless --apply), on the maintenance connection"
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
    /// Write the map's themes (ids, embeddings, attachment integers) to DIR.
    Export {
        /// `public` or `team:<group uuid>`.
        #[arg(long)]
        map: String,
        /// A new path (created 0700), or an existing empty directory with
        /// no group or other permission bits. Every file is created 0600.
        #[arg(long)]
        out: PathBuf,
        /// Only this theme (repeatable); every theme the map draws otherwise.
        #[arg(long = "theme-id")]
        theme_ids: Vec<Uuid>,
        /// The leaf node cap the clustering must meet (at most 100).
        #[arg(long, default_value_t = ATLAS_LEAF_NODE_CAP)]
        cap: usize,
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
    /// Check a result against the map and, with --apply, write it as one run.
    Apply {
        #[arg(long)]
        map: String,
        /// The result file `atlas_meaning_core.py compute` wrote. Repeat it
        /// to apply the results of a batched export together: the run must
        /// hold every theme the map draws.
        #[arg(long = "from", required = true)]
        from: Vec<PathBuf>,
        /// The leaf node cap every leaf must fit (at most 100).
        #[arg(long, default_value_t = ATLAS_LEAF_NODE_CAP)]
        cap: usize,
        /// Write the run. Without it, nothing is written.
        #[arg(long)]
        apply: bool,
    },
}

fn check_cap(cap: usize) -> anyhow::Result<()> {
    if cap == 0 || cap > ATLAS_LEAF_NODE_CAP {
        bail!("--cap must be 1 to {ATLAS_LEAF_NODE_CAP}, not {cap}");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    // Check the arguments before connecting.
    match &cli.cmd {
        Cmd::Export { map, out, cap, .. } => {
            parse_map_key(map)?;
            check_cap(*cap)?;
            prepare_export_dir(out)?;
        }
        Cmd::Apply { map, cap, .. } => {
            parse_map_key(map)?;
            check_cap(*cap)?;
        }
    }

    let maint = epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "atlas_meaning")
        .await
        .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(
            "atlas_meaning reads a team's private rows, so it runs only on an explicitly \
             configured MAINTENANCE_DATABASE_URL; it is unset, and the application DSN is never \
             used for this"
        );
    }
    // The bypass splices to nothing; what keeps a map to its own rows is the
    // map predicate in every statement (AtlasMeaningRepository, W3's read).
    let mut session = maint
        .viewer(epigraph_db::visibility::SystemReason::ThemeClustering)
        .await
        .context("acquire the maintenance session")?;
    session
        .assert_privileged()
        .await
        .context("the maintenance connection cannot bypass row security")?;
    let (conn, viewer) = session.split();

    let report = match cli.cmd {
        Cmd::Export {
            map,
            out,
            theme_ids,
            cap,
            seed,
        } => {
            let opts = ExportOptions {
                map: parse_map_key(&map)?,
                themes: (!theme_ids.is_empty()).then_some(theme_ids),
                cap,
                seed,
            };
            export_map(conn, viewer, &opts, &out).await?
        }
        Cmd::Apply {
            map,
            from,
            cap,
            apply,
        } => {
            let result = merge_results(
                from.iter()
                    .map(|p| read_result(p))
                    .collect::<anyhow::Result<Vec<_>>>()?,
            )?;
            apply_result(conn, viewer, parse_map_key(&map)?, &result, cap, apply).await?
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).context("serialize the report")?
    );
    Ok(())
}
