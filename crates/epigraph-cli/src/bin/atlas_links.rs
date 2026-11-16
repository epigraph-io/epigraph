//! Operator binary: the box-side halves of the Atlas "by links" hierarchy
//! (Atlas W5, backlog 4e02c23f, with W5b febb2a77), for one map
//! (`--map public` or `--map team:<group uuid>`).
//!
//! ```text
//! atlas_meaning export --map M --out MDIR                      # W4
//! python3 scripts/atlas_meaning_core.py compute --from MDIR --out meaning.json
//! atlas_links export --map M --meaning-from meaning.json --out LDIR [--theme-id T]...
//! python3 scripts/atlas_links_core.py compute --from LDIR --out links.json   # anywhere
//! atlas_links apply  --map M --meaning-from meaning.json --from links.json [--apply]
//! ```
//!
//! * `export` resolves the meaning result in the export's snapshot (W4's
//!   checks and W3 re-count, so the unlinked claims follow the meaning leaves
//!   the apply will write), and writes per theme: claim ids, attachment
//!   integers, the counted links as index pairs (only edges the map may
//!   draw: public, or the team's own with no co-owner), each claim's meaning
//!   leaf as an integer, and the LINKED claims' embeddings. No text, no agent,
//!   evidence or edge id. It writes nothing to the database.
//! * `apply` checks the meaning result (W4) and the links result against the
//!   rows in one snapshot, and (with `--apply`) writes ONE finished run of
//!   the map holding BOTH hierarchies: the serving read takes the latest
//!   finished run, and every level's switch names a level of the other
//!   hierarchy, so a links-only run would hide the meaning levels. DRY RUN BY
//!   DEFAULT. Repeat `--meaning-from` / `--from` to apply batched results.
//!
//! Undo: an `apply --apply` writes one `atlas_map_runs` row and its levels and
//! nothing else. Deleting that row by the `run_id` the report prints, as the
//! maintenance login, removes its levels too (`ON DELETE CASCADE`) and the
//! previous finished run is served again.
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
use epigraph_cli::atlas_links::build::{apply_hierarchies, export_links, LinksExportOptions};
use epigraph_cli::atlas_links::files::{merge_links_results, read_links_result, LinksResultDoc};
use epigraph_cli::atlas_meaning::files::{
    merge_results, prepare_export_dir, read_result, ResultDoc,
};
use epigraph_cli::atlas_meaning::tree::parse_map_key;
use epigraph_db::repos::atlas_leaf::ATLAS_LEAF_NODE_CAP;
use epigraph_db::repos::atlas_map::AtlasMap;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(
    name = "atlas_links",
    about = "Export a map's themes for the off-box \"by links\" grouping, or apply it with the \
             \"by meaning\" result as one Atlas run (dry run unless --apply), on the maintenance \
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
    /// Write the map's themes (ids, links, integers, linked embeddings) to DIR.
    Export {
        /// `public` or `team:<group uuid>`.
        #[arg(long)]
        map: String,
        /// The meaning result(s) `atlas_meaning_core.py compute` wrote.
        #[arg(long = "meaning-from", required = true)]
        meaning_from: Vec<PathBuf>,
        /// A new path (created 0700), or an existing empty directory with
        /// no group or other permission bits. Every file is created 0600.
        #[arg(long)]
        out: PathBuf,
        /// Only this theme (repeatable); every theme the map draws otherwise.
        #[arg(long = "theme-id")]
        theme_ids: Vec<Uuid>,
        /// The leaf node cap the grouping must meet (at most 100).
        #[arg(long, default_value_t = ATLAS_LEAF_NODE_CAP)]
        cap: usize,
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
    /// Check both results against the map and, with --apply, write one run.
    Apply {
        #[arg(long)]
        map: String,
        /// The meaning result(s); the run holds every theme the map draws.
        #[arg(long = "meaning-from", required = true)]
        meaning_from: Vec<PathBuf>,
        /// The links result(s) `atlas_links_core.py compute` wrote.
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

/// What the binary will do, with every file read and argument checked.
enum Work {
    Export {
        opts: LinksExportOptions,
        meaning: ResultDoc,
        out: PathBuf,
    },
    Apply {
        map: AtlasMap,
        meaning: ResultDoc,
        links: LinksResultDoc,
        cap: usize,
        apply: bool,
    },
}

fn check_cap(cap: usize) -> anyhow::Result<()> {
    if cap == 0 || cap > ATLAS_LEAF_NODE_CAP {
        bail!("--cap must be 1 to {ATLAS_LEAF_NODE_CAP}, not {cap}");
    }
    Ok(())
}

fn read_meaning(paths: &[PathBuf]) -> anyhow::Result<ResultDoc> {
    merge_results(
        paths
            .iter()
            .map(|p| read_result(p))
            .collect::<anyhow::Result<Vec<_>>>()?,
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    // Check the arguments and read the result files before connecting.
    let work = match cli.cmd {
        Cmd::Export {
            map,
            meaning_from,
            out,
            theme_ids,
            cap,
            seed,
        } => {
            let map = parse_map_key(&map)?;
            check_cap(cap)?;
            prepare_export_dir(&out)?;
            Work::Export {
                opts: LinksExportOptions {
                    map,
                    themes: (!theme_ids.is_empty()).then_some(theme_ids),
                    cap,
                    seed,
                },
                meaning: read_meaning(&meaning_from)?,
                out,
            }
        }
        Cmd::Apply {
            map,
            meaning_from,
            from,
            cap,
            apply,
        } => {
            let map = parse_map_key(&map)?;
            check_cap(cap)?;
            Work::Apply {
                map,
                meaning: read_meaning(&meaning_from)?,
                links: merge_links_results(
                    from.iter()
                        .map(|p| read_links_result(p))
                        .collect::<anyhow::Result<Vec<_>>>()?,
                )?,
                cap,
                apply,
            }
        }
    };

    let maint = epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "atlas_links")
        .await
        .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(
            "atlas_links reads a team's private rows, so it runs only on an explicitly \
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

    let report = match work {
        Work::Export { opts, meaning, out } => {
            export_links(conn, viewer, &opts, &meaning, &out).await?
        }
        Work::Apply {
            map,
            meaning,
            links,
            cap,
            apply,
        } => apply_hierarchies(conn, viewer, map, &meaning, &links, cap, apply).await?,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).context("serialize the report")?
    );
    Ok(())
}
