//! `r131_factor_mint`: the apply tool of ruling R-131 (backlog 5094766c):
//! mint the BP factor of every empty `(type, pair)` slot that a factorless
//! claim-to-claim `corroborates` / `refutes` edge between current claims
//! would fill, exactly the set `supersede_belief_delta --items r131` measures
//! (its "slots a mint would fill"), and never a slot it reports as held.
//! BP factors only: no mass function, no claim cache and no served value is
//! written. The rules are on `epigraph_cli::r131_factor_mint`.
//!
//! Three modes, each one transaction:
//!
//!     r131_factor_mint --plan-out <plan.json> [--dry-run]
//!         DRY RUN (the default): writes the exact set an apply would write
//!         (every slot, the edge whose factor it gets, every edge on it, and
//!         the held edges it leaves alone) to <plan.json> and prints the
//!         counts in `supersede_belief_delta`'s words. Writes nothing to the
//!         database (one REPEATABLE READ READ ONLY transaction).
//!
//!     r131_factor_mint --apply --plan <plan.json> --record <undo.jsonl>
//!         Re-reads the selection and refuses unless it equals <plan.json>
//!         exactly; mints each slot; re-measures (no slot left to fill);
//!         writes and syncs the undo record; commits. Re-running the dry run
//!         afterwards plans nothing, so a second apply mints nothing.
//!
//!     r131_factor_mint --undo <undo.jsonl> [--apply]
//!         Deletes each recorded factor only where the row still equals what
//!         the mint wrote (compare-and-set); reports deleted / absent /
//!         changed_since and the `bp_messages` rows removed with them. Without
//!         `--apply` it runs the deletes and rolls back.
//!
//! Output files are created new: an existing file is refused before any
//! connection. They name claim and edge ids: keep them in the operator's
//! private directory, never in a repository.
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET (the fallback to `DATABASE_URL` is
//! refused, in every mode) and its login must bypass row security: the
//! selection is corpus-wide, and an application session would see only the
//! rows its groups can read, so its plan would silently miss the rest.
//!
//! Exit 0: done. Exit 1: refused or failed; nothing was written. Exit 3: the
//! apply's COMMIT failed, so whether it landed is unknown; the undo record is
//! kept, and `--undo` on it deletes exactly what landed.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};

use clap::Parser;

use epigraph_cli::r131_factor_mint::{self, MintError, MintPlan, PLAN_KIND};
use epigraph_db::visibility::SystemReason;

#[derive(Parser, Debug)]
#[command(
    name = "r131_factor_mint",
    about = "Mint the BP factors of the R-131 factorless corroborates/refutes edges' empty \
             slots (dry run unless --apply), with a compare-and-set undo"
)]
struct Cli {
    /// Dry run: write the plan (the exact set an apply writes) here.
    #[arg(long, conflicts_with_all = ["plan", "record", "undo"])]
    plan_out: Option<PathBuf>,
    /// Commit: with --plan and --record, mint; with --undo, delete.
    #[arg(long, conflicts_with = "dry_run")]
    apply: bool,
    /// Explicit dry run (the default).
    #[arg(long)]
    dry_run: bool,
    /// The dry run's plan to apply (refused unless the live set equals it).
    #[arg(long, requires = "apply")]
    plan: Option<PathBuf>,
    /// Where the apply writes its undo record (must not exist).
    #[arg(long, requires = "apply")]
    record: Option<PathBuf>,
    /// Undo the mint recorded in this file.
    #[arg(long, conflicts_with_all = ["plan", "record"])]
    undo: Option<PathBuf>,
    /// `SET LOCAL statement_timeout` in the dry run's and the apply's
    /// transaction, in milliseconds.
    #[arg(long)]
    statement_timeout_ms: Option<u64>,
}

enum Mode {
    DryRun(PathBuf),
    Apply { plan: PathBuf, record: PathBuf },
    Undo { record: PathBuf, commit: bool },
}

fn mode(cli: &Cli) -> Result<Mode, String> {
    if let Some(record) = &cli.undo {
        return Ok(Mode::Undo {
            record: record.clone(),
            commit: cli.apply,
        });
    }
    if cli.apply {
        return match (&cli.plan, &cli.record) {
            (Some(plan), Some(record)) => Ok(Mode::Apply {
                plan: plan.clone(),
                record: record.clone(),
            }),
            _ => Err(
                "--apply mints only a reviewed plan: give --plan <dry-run plan> and \
                      --record <new undo file>"
                    .into(),
            ),
        };
    }
    cli.plan_out
        .clone()
        .map(Mode::DryRun)
        .ok_or_else(|| "a dry run writes its plan to --plan-out <file>".into())
}

fn create_new(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn counts_line(prefix: &str, edges: usize, slots: usize, held: usize) -> String {
    format!(
        "{prefix}: {edges} factorless edges, {slots} slots a mint would fill, {held} on held slots"
    )
}

/// Exit 3 when the outcome is unknown, else 1.
struct Failure(i32, String);

impl From<String> for Failure {
    fn from(s: String) -> Self {
        Self(1, s)
    }
}

async fn connect() -> Result<epigraph_cli::MaintenancePool, String> {
    let maint = epigraph_cli::MaintenancePool::connect("r131_factor_mint")
        .await
        .map_err(|e| e.to_string())?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        return Err(
            "r131_factor_mint reads and writes factors across every owner, so it runs only on \
             an explicitly configured MAINTENANCE_DATABASE_URL; it is unset, and the \
             application DSN is never used for this"
                .into(),
        );
    }
    Ok(maint)
}

async fn run(cli: Cli) -> Result<(), Failure> {
    let mode = mode(&cli)?;
    // Refuse existing outputs and unreadable inputs before connecting.
    match &mode {
        Mode::DryRun(out) => {
            let mut file = create_new(out)?;
            let result = dry_run(&cli, out, &mut file).await;
            if result.is_err() {
                drop(file);
                let _ = std::fs::remove_file(out);
            }
            result
        }
        Mode::Apply { plan, record } => {
            let text =
                std::fs::read_to_string(plan).map_err(|e| format!("{}: {e}", plan.display()))?;
            let expected: MintPlan = serde_json::from_str(&text)
                .map_err(|e| format!("{}: not a plan: {e}", plan.display()))?;
            if expected.kind != PLAN_KIND {
                return Err(format!("{}: not an r131_factor_mint plan", plan.display()).into());
            }
            let mut file = create_new(record)?;
            let result = apply(&cli, &expected, record, &mut file).await;
            if matches!(&result, Err(Failure(1, _))) {
                drop(file);
                let _ = std::fs::remove_file(record);
            }
            result
        }
        Mode::Undo { record, commit } => {
            let parsed = r131_factor_mint::read_record(BufReader::new(
                File::open(record).map_err(|e| format!("{}: {e}", record.display()))?,
            ))
            .map_err(|e| format!("{}: {e}", record.display()))?;
            undo(&parsed, *commit).await
        }
    }
}

async fn session_conn<'a>(
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

async fn dry_run(cli: &Cli, out: &Path, file: &mut File) -> Result<(), Failure> {
    let maint = connect().await?;
    let mut session = session_conn(&maint).await?;
    let (conn, _) = session.split();
    let plan = r131_factor_mint::dry_run(conn, cli.statement_timeout_ms)
        .await
        .map_err(|e| e.to_string())?;
    let body = serde_json::to_vec_pretty(&plan).map_err(|e| e.to_string())?;
    file.write_all(&body)
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|e| format!("{}: {e}", out.display()))?;
    println!("DRY RUN: nothing written to the database");
    println!(
        "{}",
        counts_line(
            "r131",
            plan.edges,
            plan.slots_minted,
            plan.edges_on_held_slots
        )
    );
    println!(
        "plan written to {} (sha256 {})",
        out.display(),
        plan.sha256()
    );
    Ok(())
}

async fn apply(
    cli: &Cli,
    expected: &MintPlan,
    record: &Path,
    file: &mut File,
) -> Result<(), Failure> {
    let maint = connect().await?;
    let mut session = session_conn(&maint).await?;
    let (conn, _) = session.split();
    let report = r131_factor_mint::apply(conn, expected, file, cli.statement_timeout_ms)
        .await
        .map_err(|e| match e {
            e @ MintError::CommitUnknown(_) => Failure(3, e.to_string()),
            e => Failure(1, e.to_string()),
        })?;
    println!(
        "r131 apply: minted {} factors (plan sha256 {}; undo record {})",
        report.minted,
        expected.sha256(),
        record.display()
    );
    println!(
        "{}",
        counts_line(
            "r131 after",
            report.after.edges,
            report.after.slots_minted,
            report.after.edges_on_held_slots
        )
    );
    Ok(())
}

async fn undo(record: &r131_factor_mint::MintRecord, commit: bool) -> Result<(), Failure> {
    let maint = connect().await?;
    let mut session = session_conn(&maint).await?;
    let (conn, _) = session.split();
    let report = r131_factor_mint::undo(conn, record, !commit)
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "r131 undo{}: deleted={} absent={} changed_since={} bp_messages_removed={}",
        if commit {
            ""
        } else {
            " (dry run: rolled back)"
        },
        report.deleted.len(),
        report.absent.len(),
        report.changed_since.len(),
        report.bp_messages_removed
    );
    for id in &report.changed_since {
        println!("changed_since {id}");
    }
    for id in &report.absent {
        println!("absent {id}");
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    if let Err(Failure(code, e)) = run(cli).await {
        eprintln!("Error: {e}");
        std::process::exit(code);
    }
}
