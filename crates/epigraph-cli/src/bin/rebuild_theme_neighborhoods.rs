//! Operator binary: rebuild the graph neighbourhoods of themes whose
//! membership changed after the newest clustering run, in that run (backlog
//! 30633061).
//!
//! The neighbourhood readers serve the newest Louvain run
//! (`ClusterRunRepository::latest`). `scripts/theme_cap_split.py apply` moves
//! claims from a parent theme to new parts after that run was built, so the
//! run still files the moved claims under the parent and has no rows for the
//! parts (and `reverse` leaves the parent without the claims it gets back).
//! Run this after every split apply and every reverse:
//!
//! ```text
//! rebuild_theme_neighborhoods --manifest theme-cap-manifest-<UTC>.json          # dry run
//! rebuild_theme_neighborhoods --manifest theme-cap-manifest-<UTC>.json --apply
//! rebuild_theme_neighborhoods --theme-id <uuid> [--theme-id <uuid> ...] --apply
//! ```
//!
//! 1. The themes are the manifest's (`touched_theme_ids`, every parent and
//!    every new part) plus each `--theme-id`, and every theme whose
//!    neighbourhoods in the run still hold a claim now in one of them
//!    (`neighborhood::themes_to_rebuild`).
//! 2. DRY RUN BY DEFAULT: prints the run and the themes it would rebuild,
//!    and writes nothing.
//! 3. `--apply` holds the clustering job's lock (`CLUSTER_GRAPH_LOCK_KEY`),
//!    deletes those themes' neighbourhood rows in the run and rebuilds them,
//!    in ONE transaction (`neighborhood::rebuild_theme_neighborhoods_latest`).
//!    The new rows carry placeholder labels: run
//!    `scripts/label_themes_llm.py --neighborhoods` after it.
//!
//! `MAINTENANCE_DATABASE_URL` must be SET (the fallback to `DATABASE_URL` is
//! refused) and its login must bypass row security: the pass reads every
//! member of a theme, as the clustering job does.
//!
//! The report is one JSON object on stdout. Exit 0: rebuilt, nothing to do
//! (no run yet), or a dry run. Exit 1: a refusal or an error, with nothing
//! written. Exit 2: an argument error. Exit 75: a clustering run or another
//! rebuild holds the lock; nothing ran (`{"locked": true}`), retry once it
//! has finished.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context};
use clap::Parser;
use epigraph_cli::theme_neighborhoods::{merge_theme_ids, theme_ids_from_manifest};
use epigraph_jobs::cluster_graph::neighborhood::{self as nbr, LatestRebuild};
use uuid::Uuid;

const EXIT_LOCKED: i32 = 75;

#[derive(Parser, Debug)]
#[command(
    name = "rebuild_theme_neighborhoods",
    about = "Rebuild the graph neighbourhoods of split or reversed themes in the newest \
             clustering run (dry run unless --apply), on the maintenance connection"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the work runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// A `scripts/theme_cap_split.py` manifest: rebuild every theme it touched.
    #[arg(long, value_name = "PATH")]
    manifest: Option<PathBuf>,

    /// A theme to rebuild (repeatable).
    #[arg(long = "theme-id", value_name = "UUID")]
    theme_ids: Vec<Uuid>,

    /// Write. Without it, nothing is written.
    #[arg(long)]
    apply: bool,
}

const UNSET_MAINTENANCE_DSN: &str = "rebuild_theme_neighborhoods reads every member of a theme \
     and rewrites the shared neighbourhood rows, so it runs only on an explicitly configured \
     MAINTENANCE_DATABASE_URL; it is unset, and the application DSN is never used for this";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();

    let from_manifest = match &cli.manifest {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read the manifest {}", path.display()))?;
            let doc: serde_json::Value =
                serde_json::from_str(&text).context("the manifest is not JSON")?;
            theme_ids_from_manifest(&doc).map_err(|e| anyhow!("refused: {e}"))?
        }
        None => Vec::new(),
    };
    let requested = merge_theme_ids(&from_manifest, &cli.theme_ids);
    if requested.is_empty() {
        bail!("name the themes: --manifest PATH and/or --theme-id UUID");
    }

    let (_, dsn_source) =
        epigraph_db::maintenance_database_url(&cli.database_url).map_err(|e| anyhow!("{e}"))?;
    if dsn_source != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(UNSET_MAINTENANCE_DSN);
    }
    let maint =
        epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "rebuild_theme_neighborhoods")
            .await
            .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(UNSET_MAINTENANCE_DSN);
    }
    // ThemeClustering: the neighbourhood pass is part of the clustering job
    // and reads, as it does, every member of a theme. Reused rather than
    // adding a reason (viewer_ratchet.rs holds the set).
    let mut session = maint
        .viewer(epigraph_db::visibility::SystemReason::ThemeClustering)
        .await
        .context("acquire the maintenance session")?;
    session
        .assert_privileged()
        .await
        .context("the maintenance connection cannot bypass row security")?;
    drop(session);
    let pool = maint.pool();

    if !cli.apply {
        let report = dry_run(pool, &requested).await?;
        println!("{report}");
        return Ok(());
    }

    let outcome =
        nbr::rebuild_theme_neighborhoods_latest(pool, &nbr::Config::default(), &requested)
            .await
            .map_err(|e| anyhow!("{e}; nothing was written"))?;
    let report = match outcome {
        LatestRebuild::Locked => {
            println!("{}", serde_json::json!({ "locked": true }));
            eprintln!(
                "a clustering run or another rebuild holds the lock; nothing ran. Retry once it \
                 has finished."
            );
            std::process::exit(EXIT_LOCKED);
        }
        LatestRebuild::NoRun => serde_json::json!({
            "status": "no_run",
            "requested": requested,
            "note": "no clustering run exists yet; the first ClusterGraph run builds every theme",
        }),
        LatestRebuild::Rebuilt(r) => serde_json::json!({
            "status": "rebuilt",
            "requested": requested,
            "run_id": r.run_id,
            "rebuilt": r.rebuilt,
            "missing": r.missing,
            "next": "scripts/label_themes_llm.py --neighborhoods (the new rows carry placeholder labels)",
        }),
    };
    println!("{report}");
    Ok(())
}

async fn dry_run(pool: &sqlx::PgPool, requested: &[Uuid]) -> anyhow::Result<serde_json::Value> {
    let Some(run) = epigraph_db::ClusterRunRepository::latest(pool)
        .await
        .context("read the newest clustering run")?
    else {
        return Ok(serde_json::json!({
            "status": "dry_run",
            "requested": requested,
            "run_id": null,
            "would_rebuild": [],
            "note": "no clustering run exists yet",
        }));
    };
    let mut conn = pool.acquire().await.context("acquire a connection")?;
    let set = nbr::themes_to_rebuild(&mut conn, run.run_id, requested)
        .await
        .context("compute the themes to rebuild")?;
    Ok(serde_json::json!({
        "status": "dry_run",
        "requested": requested,
        "run_id": run.run_id,
        "would_rebuild": set,
    }))
}
