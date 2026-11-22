//! `decomposes_to_factor_sweep`: export and delete the BP factors of
//! `decomposes_to` edges, keyed and legacy (atom-level belief SPEC §6.2, D3;
//! backlog 444b1f4a). Migration 262 stops the edge trigger minting new ones;
//! this removes the rows minted before it, and re-run later it sweeps any
//! row minted since. The rules are on `epigraph_cli::decomposes_to_factor_sweep`.
//!
//!     decomposes_to_factor_sweep --manifest-out <manifest.jsonl>
//!         DRY RUN (the default): writes the exact set an apply would delete
//!         (the whole rows) to <manifest.jsonl> and prints the counts. Writes
//!         nothing to the database (one READ ONLY transaction).
//!
//!     decomposes_to_factor_sweep --manifest-out <apply.jsonl> --apply --expect <manifest.jsonl>
//!         In one transaction, under an advisory lock: selects the set and
//!         refuses unless it equals the reviewed dry run's (<manifest.jsonl>,
//!         which must be a dry run's manifest)
//!         exactly; writes and syncs <apply.jsonl>, deletes exactly those
//!         rows, re-measures (no such row may remain), commits. <apply.jsonl>
//!         is the restore record.
//!
//!     decomposes_to_factor_sweep --remaining
//!         Prints the number of such rows left (the DONE measurement: 0).
//!
//!     decomposes_to_factor_sweep --restore <apply.jsonl> [--apply]
//!         Re-inserts the rows an apply deleted (only an apply's manifest is
//!         taken), ON CONFLICT DO NOTHING. Without `--apply` it inserts and
//!         rolls back. A restore re-opens the residual the sweep closed (a
//!         caller who cannot see a decomposition reads its legacy factor
//!         again) until the next sweep.
//!
//! The sweep for rows minted later is the same dry run and apply again.
//!
//! Output files are created new, owner-only (0600): an existing file is
//! refused before any connection. Manifests name claim ids: keep them in the
//! operator's private directory, never in a repository.
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET (the fallback to `DATABASE_URL` is
//! refused, in every mode) and its login must bypass row security: the legacy
//! arm matches a factor to its decomposition by reading `edges`, and a
//! filtered session would miss the decompositions it cannot see, which are
//! exactly the rows this tool exists to remove.
//!
//! Exit 0: done. Exit 1: refused or failed; nothing was written. Exit 3: the
//! COMMIT failed, so whether the delete (or restore) landed is unknown; the
//! manifest is kept, and `--remaining` / a fresh dry run says what is left.

use std::fs::{File, OpenOptions};
use std::io::BufReader;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use clap::Parser;

use epigraph_cli::decomposes_to_factor_sweep::{self as sweep, SweepError};
use epigraph_db::visibility::SystemReason;

#[derive(Parser, Debug)]
#[command(
    name = "decomposes_to_factor_sweep",
    about = "Export and delete the BP factors of decomposes_to edges (dry run unless --apply), \
             with a manifest restore"
)]
struct Cli {
    /// Write the manifest (the exact set selected) here. Must not exist.
    #[arg(long, conflicts_with_all = ["restore", "remaining"])]
    manifest_out: Option<PathBuf>,
    /// Commit: delete the selected rows (with --expect), or (with --restore)
    /// re-insert them.
    #[arg(long, conflicts_with = "remaining")]
    apply: bool,
    /// The reviewed dry run's manifest: an apply refuses unless the live
    /// selection is exactly its rows.
    #[arg(long, requires = "apply", conflicts_with_all = ["restore", "remaining"])]
    expect: Option<PathBuf>,
    /// Re-insert the rows of this apply's manifest. This re-opens the
    /// residual the sweep closed until the next sweep.
    #[arg(long, conflicts_with = "remaining")]
    restore: Option<PathBuf>,
    /// Print how many decomposes_to factors remain, and exit.
    #[arg(long)]
    remaining: bool,
    /// `SET LOCAL statement_timeout` in the export's and `--remaining`'s
    /// transaction, in milliseconds.
    #[arg(long)]
    statement_timeout_ms: Option<u64>,
}

enum Mode {
    Export {
        out: PathBuf,
        expect: Option<PathBuf>,
    },
    Restore {
        manifest: PathBuf,
        apply: bool,
    },
    Remaining,
}

fn mode(cli: &Cli) -> Result<Mode, String> {
    if cli.remaining {
        return Ok(Mode::Remaining);
    }
    if let Some(manifest) = &cli.restore {
        return Ok(Mode::Restore {
            manifest: manifest.clone(),
            apply: cli.apply,
        });
    }
    if cli.apply && cli.expect.is_none() {
        return Err(
            "--apply deletes only a reviewed dry run: give --expect <dry-run manifest> \
                    (and --manifest-out <new file> for this run's record)"
                .into(),
        );
    }
    cli.manifest_out
        .clone()
        .map(|out| Mode::Export {
            out,
            expect: cli.expect.clone(),
        })
        .ok_or_else(|| {
            "give --manifest-out <new file> (dry run unless --apply), --restore <manifest>, \
             or --remaining"
                .into()
        })
}

struct Failure(i32, String);

impl From<String> for Failure {
    fn from(s: String) -> Self {
        Self(1, s)
    }
}

fn failure(e: &SweepError) -> Failure {
    let code = if matches!(e, SweepError::CommitUnknown(_)) {
        3
    } else {
        1
    };
    Failure(code, e.to_string())
}

/// Create an output manifest: new (an existing file is refused) and owner-only
/// (0600, whatever the umask), since every row names private claim and edge ids.
fn create_new(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Read a manifest and require the run that wrote it: `--expect` takes a dry
/// run's (the set the operator reviewed), `--restore` an apply's (the rows
/// that run deleted). Checked before any file is created or any connection.
fn read_manifest_of_mode(
    path: &Path,
    want: &str,
    flag: &str,
) -> Result<Vec<sweep::ManifestRow>, String> {
    let (header, rows) = sweep::read_manifest(BufReader::new(
        File::open(path).map_err(|e| format!("{}: {e}", path.display()))?,
    ))
    .map_err(|e| format!("{}: {e}", path.display()))?;
    if header.mode != want {
        return Err(format!(
            "{}: {flag} needs a manifest with mode `{want}`, this one has mode `{}`",
            path.display(),
            header.mode
        ));
    }
    Ok(rows)
}

async fn connect() -> Result<epigraph_cli::MaintenancePool, String> {
    let maint = epigraph_cli::MaintenancePool::connect("decomposes_to_factor_sweep")
        .await
        .map_err(|e| e.to_string())?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        return Err(
            "decomposes_to_factor_sweep reads edges and deletes factors across every owner, so \
             it runs only on an explicitly configured MAINTENANCE_DATABASE_URL; it is unset, and \
             the application DSN is never used for this"
                .into(),
        );
    }
    Ok(maint)
}

async fn session<'a>(
    maint: &'a epigraph_cli::MaintenancePool,
) -> Result<epigraph_db::MaintenanceSession<'a>, String> {
    let mut session = maint
        .viewer(SystemReason::BeliefRecomputation)
        .await
        .map_err(|e| format!("acquire the maintenance session: {e}"))?;
    session
        .assert_privileged()
        .await
        .map_err(|e| format!("the maintenance connection cannot bypass row security: {e}"))?;
    Ok(session)
}

async fn export(cli: &Cli, out: &Path, expect: Option<&Path>) -> Result<(), Failure> {
    let expected: Option<Vec<uuid::Uuid>> = match expect {
        None => None,
        Some(path) => {
            let rows = read_manifest_of_mode(path, "dry_run", "--expect")?;
            Some(rows.into_iter().map(|r| r.id).collect())
        }
    };
    let apply = expected.is_some();
    let mut file = create_new(out)?;
    let result = async {
        let maint = connect().await?;
        let mut session = session(&maint).await?;
        let (conn, _) = session.split();
        sweep::run(
            conn,
            &mut file,
            expected.as_deref(),
            cli.statement_timeout_ms,
        )
        .await
        .map_err(|e| failure(&e))
    }
    .await;
    match result {
        Ok(report) => {
            let h = &report.header;
            if apply {
                println!("APPLY: deleted {} decomposes_to factors", h.rows);
            } else {
                println!("DRY RUN: nothing written to the database");
            }
            println!(
                "decomposes_to factors: {} ({} keyed, {} legacy); bp_messages {}; \
                 parallel unfactored edges {}",
                h.rows, h.keyed, h.legacy, h.bp_messages, h.parallel_unfactored_edges
            );
            println!("manifest written to {}", out.display());
            Ok(())
        }
        Err(f) => {
            // Exit 1: nothing was written, so the manifest records nothing.
            // Exit 3 keeps it: it is the only record of what may have landed.
            if f.0 == 1 {
                drop(file);
                let _ = std::fs::remove_file(out);
            }
            Err(f)
        }
    }
}

async fn restore(manifest: &Path, apply: bool) -> Result<(), Failure> {
    let rows = read_manifest_of_mode(manifest, "apply", "--restore")?;
    let maint = connect().await?;
    let mut session = session(&maint).await?;
    let (conn, _) = session.split();
    let report = sweep::restore(conn, &rows, !apply)
        .await
        .map_err(|e| failure(&e))?;
    println!(
        "restore{}: restored={} skipped={}",
        if apply { "" } else { " (dry run: rolled back)" },
        report.restored.len(),
        report.skipped.len()
    );
    for id in &report.skipped {
        println!("skipped {id}");
    }
    Ok(())
}

async fn remaining(cli: &Cli) -> Result<(), Failure> {
    let maint = connect().await?;
    let mut session = session(&maint).await?;
    let (conn, _) = session.split();
    let n = sweep::remaining(conn, cli.statement_timeout_ms)
        .await
        .map_err(|e| failure(&e))?;
    println!("decomposes_to factors remaining: {n}");
    Ok(())
}

async fn run(cli: Cli) -> Result<(), Failure> {
    match mode(&cli)? {
        Mode::Export { out, expect } => export(&cli, &out, expect.as_deref()).await,
        Mode::Restore { manifest, apply } => restore(&manifest, apply).await,
        Mode::Remaining => remaining(&cli).await,
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    if let Err(Failure(code, msg)) = run(Cli::parse()).await {
        eprintln!("decomposes_to_factor_sweep: {msg}");
        std::process::exit(code);
    }
}
