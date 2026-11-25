//! The nightly Atlas refresh (Atlas W9, backlog 1da9ed16), run by
//! `epigraph-atlas-nightly.timer` (`deploy/systemd/`).
//!
//! ```text
//! atlas_nightly [--map M]... [--apply] [--max-calls N] [--keep-runs K]
//!               [--cap N] [--theme-cap N] [--model M] [--claude-bin PATH]
//!               [--offbox-command PROG --offbox-dir DIR [--offbox-timeout-secs N]
//!                [--theme-cap-split scripts/theme_cap_split.py [--python PY]]]
//! ```
//!
//! One night: assign unthemed embedded claims to their nearest theme, report
//! the themes over W1's member cap, then for every map with a finished run
//! (or each `--map`): update both hierarchies incrementally, build real
//! leaves, lay out the changed levels, name the changed groups, and write ONE
//! new run of the map (nothing when every level and the epochs are
//! unchanged), then prune the map's old runs. A theme whose update fails is
//! carried from the previous run or dropped, and reported; it does not fail
//! the night.
//!
//! No UMAP runs on this box. With the off-box hook (`--offbox-command`, see
//! `epigraph_cli::atlas_nightly::offbox`) and `--apply`, the clustering it
//! needs goes through that command on ids and embeddings only: the themes
//! over the cap are split by W1's `theme_cap_split.py offbox` (when
//! `--theme-cap-split` names the script), and a theme new to a map that does
//! not fit one leaf gets its meaning tree computed off the box and is built
//! the same night. Without the hook both are reported, as before.
//!
//! DRY RUN BY DEFAULT: without `--apply` nothing is assigned or written and
//! no model is called; the summary says what would change. Undo a written
//! run: delete its `atlas_map_runs` row (`run_id` in the summary) as the
//! maintenance login; its levels go with it and the previous run is served
//! again (`docs/runbooks/atlas-nightly.md`).
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET and its login must bypass row
//! security (a team map is built from that team's private rows). A second
//! copy beside a running one does nothing: it prints `{"locked": true}`, says
//! so on stderr and exits [`EXIT_LOCKED`] (75), so an operator's manual run
//! cannot be mistaken for one that ran; the timer's unit counts 75 a success
//! (`SuccessExitStatus=75`), so a timer firing beside a manual run alerts
//! no one.
//!
//! Exit 0: every map built, unchanged or skipped (a dry run included).
//! Exit 1: a map failed, a configured off-box call failed (`themes.split`
//! or a map's `offbox` says `failed`; the night still built what it could),
//! or a refusal before any map ran (the timer's `OnFailure=` alert fires). Exit 2: an argument error. Exit 75: another
//! copy holds the lock; nothing ran (retry once it has finished).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use clap::Parser;
use epigraph_cli::atlas_meaning::tree::parse_map_key;
use epigraph_cli::atlas_naming::backend::{
    BackendError, ClaudeCliBackend, NameBackend, RecordingBackend, DEFAULT_MODEL,
};
use epigraph_cli::atlas_nightly::build::{run_night, NightOptions};
use epigraph_cli::atlas_nightly::offbox::{check_work_dir, OffBox, ThemeCapSplit};
use epigraph_db::repos::maintenance_lock::{try_take, ATLAS_NIGHTLY_LOCK_KEY};

/// The exit status of a copy that found another holding the lock
/// (`EX_TEMPFAIL`): nothing ran.
const EXIT_LOCKED: i32 = 75;

#[derive(Parser, Debug)]
#[command(
    name = "atlas_nightly",
    about = "Refresh every Atlas map incrementally and write one new run per changed map \
             (dry run unless --apply), on the maintenance connection"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the work runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Only this map (`public` or `team:<group uuid>`); repeatable. Every map
    /// with a finished run by default.
    #[arg(long = "map")]
    maps: Vec<String>,

    /// Assign themes, call the model and write the runs. Without it, none
    /// of these happens.
    #[arg(long)]
    apply: bool,

    /// At most this many model calls per map this night (at least 1); the
    /// rest stay flagged and are named on a later night.
    #[arg(long)]
    max_calls: Option<usize>,

    /// Finished runs kept per map (at least 1).
    #[arg(long, default_value_t = 3)]
    keep_runs: usize,

    /// The leaf node cap (W3's).
    #[arg(long, default_value_t = 100)]
    cap: usize,

    /// The theme member cap (W1's): themes over it are reported, and split
    /// through the off-box hook when --theme-cap-split is given.
    #[arg(long, default_value_t = 2_000)]
    theme_cap: i64,

    /// The off-box command: run as `PROG theme-cap|atlas-meaning EXPORT_DIR
    /// RESULT_FILE` with a cleared environment (PATH, HOME, LANG only), on
    /// ids and embeddings. Never run without --apply.
    #[arg(long)]
    offbox_command: Option<PathBuf>,

    /// An owner-only directory for the off-box exports (deleted after each
    /// call), results and the theme split's manifests (kept: `reverse`
    /// restores from them). Required with --offbox-command.
    #[arg(long)]
    offbox_dir: Option<PathBuf>,

    /// Seconds one off-box call may take before its process group is killed.
    #[arg(long, default_value_t = 3_600)]
    offbox_timeout_secs: u64,

    /// `scripts/theme_cap_split.py`: with --offbox-command, the themes over
    /// --theme-cap are split through its `offbox` command before the maps
    /// are built.
    #[arg(long)]
    theme_cap_split: Option<PathBuf>,

    /// The Python interpreter for --theme-cap-split.
    #[arg(long, default_value = "python3")]
    python: PathBuf,

    /// The model the CLI is asked for.
    #[arg(long, default_value = DEFAULT_MODEL)]
    model: String,

    /// The Claude CLI program.
    #[arg(long, default_value = "claude")]
    claude_bin: PathBuf,

    /// Seconds one naming call may take before it is killed and counted failed.
    #[arg(long, default_value_t = 120)]
    timeout_secs: u64,
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
    let maps = if cli.maps.is_empty() {
        None
    } else {
        Some(
            cli.maps
                .iter()
                .map(|m| parse_map_key(m))
                .collect::<anyhow::Result<Vec<_>>>()?,
        )
    };
    if cli.max_calls == Some(0) {
        bail!("--max-calls must be at least 1 (a dry run is the default)");
    }
    if cli.keep_runs == 0 {
        bail!("--keep-runs must be at least 1 (the served run)");
    }
    if cli.cap == 0 || cli.cap > epigraph_atlas_contract::MAX_LEAF_NODES {
        bail!(
            "--cap must be 1 to {} (the contract's leaf size)",
            epigraph_atlas_contract::MAX_LEAF_NODES
        );
    }
    if cli.theme_cap < 1 || cli.timeout_secs == 0 || cli.offbox_timeout_secs == 0 {
        bail!("--theme-cap, --timeout-secs and --offbox-timeout-secs must be at least 1");
    }
    let offbox = match (cli.offbox_command, cli.offbox_dir) {
        (Some(command), Some(work_dir)) => {
            check_work_dir(&work_dir)?;
            Some(OffBox {
                command,
                work_dir,
                timeout: Duration::from_secs(cli.offbox_timeout_secs),
                theme_cap_split: cli.theme_cap_split.map(|script| ThemeCapSplit {
                    python: cli.python,
                    script,
                }),
            })
        }
        (None, None) if cli.theme_cap_split.is_none() => None,
        (None, None) => bail!("--theme-cap-split needs --offbox-command and --offbox-dir"),
        _ => bail!("--offbox-command and --offbox-dir go together"),
    };

    let maint = epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "atlas_nightly")
        .await
        .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(
            "atlas_nightly reads every team's private rows, so it runs only on an explicitly \
             configured MAINTENANCE_DATABASE_URL; it is unset, and the application DSN is never \
             used for this"
        );
    }
    let mut session = maint
        .viewer(epigraph_db::visibility::SystemReason::ThemeClustering)
        .await
        .context("acquire the maintenance session")?;
    session
        .assert_privileged()
        .await
        .context("the maintenance connection cannot bypass row security")?;
    let (conn, viewer) = session.split();
    if !try_take(conn, ATLAS_NIGHTLY_LOCK_KEY).await? {
        println!("{}", serde_json::json!({"locked": true}));
        eprintln!(
            "atlas_nightly: another copy holds the nightly lock; nothing ran. Retry once it has \
             finished (journalctl -u epigraph-atlas-nightly)."
        );
        std::process::exit(EXIT_LOCKED);
    }

    let cli_backend;
    let dry_backend;
    let backend: &dyn NameBackend = if cli.apply {
        cli_backend = ClaudeCliBackend::new(
            cli.claude_bin,
            cli.model,
            Duration::from_secs(cli.timeout_secs),
        )
        .context("prepare the Claude CLI's working directory")?;
        &cli_backend
    } else {
        // A dry run never calls the model.
        dry_backend = RecordingBackend::new(|_| Err(BackendError("dry run".into())));
        &dry_backend
    };
    let opts = NightOptions {
        maps,
        apply: cli.apply,
        cap: cli.cap,
        theme_cap: cli.theme_cap,
        keep_runs: cli.keep_runs,
        max_calls: cli.max_calls,
        offbox,
        ..NightOptions::default()
    };
    let (summary, ok) = run_night(conn, viewer, backend, &opts).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).context("serialize the summary")?
    );
    if !ok {
        bail!(
            "at least one map or configured off-box call failed; see \"maps\" and \
             \"themes.split\" in the summary"
        );
    }
    Ok(())
}
