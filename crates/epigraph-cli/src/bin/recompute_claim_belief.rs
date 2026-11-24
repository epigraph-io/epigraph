//! One-shot operator binary: recompute cached `claims.{belief, plausibility,
//! pignistic_prob, conflict_k, missing_mass}` from current
//! `mass_functions` state for a list of claim_ids.
//!
//! Use case: after a script directly mutates `mass_functions.source_strength`
//! (e.g. the locality-aware backfill in
//! `scripts/backfill_intra_source_evidence_discount.py`), the BBA data is
//! correct but the cached BetP on `claims` is stale because the write
//! bypassed `edge_factor::wire_evidential_edge_factor` (the production
//! path that calls `recompute_claim_belief_binary`).
//!
//! The HTTP API exposes `/api/v1/sheaf/reconcile`, but that's a GLOBAL
//! obstruction-resolver — only touches the most-inconsistent clusters,
//! leaving the bulk of an affected backfill population stale. This binary
//! invokes the canonical per-claim, per-frame recompute directly.
//!
//! Frame handling: `claims.{belief, pl, pignistic_prob, ...}` is ONE shared
//! cache, so for each input claim `edge_factor::recompute_claim_cached_belief`
//! recomputes it from the claim's single owner frame (a frame with a
//! cache-admissible input first; then `binary_truth`, else `claim_validity`,
//! else the frame the cache already records, else the frame
//! holding the claim's earliest input; see
//! `MassFunctionRepository::cache_owner_frame_for_claim`). No other frame name
//! plays a part, so two runs against the same population converge to
//! the same cached value.
//!
//! Reads claim_ids from a file (one UUID per line) or `--stdin`.
//!
//! Usage (a writing run names its disk gate; see "Disk gate" below):
//!     epigraph-recompute-belief --input /tmp/claim_ids.txt --dry-run
//!     epigraph-recompute-belief --input /tmp/claim_ids.txt \
//!         --disk-path <db data volume> (--disk-check-cmd <cmd> | --no-backup-check)
//!     epigraph-recompute-belief --stdin <GATE FLAGS> < /tmp/claim_ids.txt
//!     epigraph-recompute-belief --input /tmp/claim_ids.txt <GATE FLAGS> \
//!         --snapshot /path/wave-1.jsonl [--wave <name>]
//!
//! Rollback (`--snapshot <wave file>`): each claim is recomputed in ONE
//! transaction that locks its row, reads its cache, recomputes, reads the
//! cache back and, when it changed, appends and syncs a
//! `belief_cache::WaveRecord` (`before` = the cache found, `written` = the
//! cache left, `wave` = `--wave`, `at` = the run's start on the database
//! clock) BEFORE it commits. So every committed write has a record, and
//! `restore_belief_cache --from <wave file>` undoes exactly this run by
//! compare-and-swap: a claim goes back to `before` only where it still holds
//! exactly `written`, and a claim another writer changed since is reported
//! `superseded_since_wave` and left alone. The wave file must be absent or
//! empty (one file holds one run), and an empty `<wave file>.scoped.jsonl`
//! sidecar is created next to it (this binary writes no scoped rows). A file
//! that cannot be opened stops the run before any write; a record that cannot
//! be written rolls its claim back and stops the run (exit 3), so no write
//! lands unrecorded. Unchanged claims are not recorded; `claims.updated_at` is
//! not part of the record. See `epigraph_cli::recompute_claim_belief`.
//! Before the first write the run also writes `<wave file>.run.json`: this
//! process's belief modes, whether `--allow-mode-skew` overrode the mode
//! check, and the disk gate (including a `--no-backup-check` opt-out), so the
//! wave file carries how it was made.
//!
//! Mode check (backlog a7ab715d, 1ea4f6bf): before a WRITING run, and before
//! it opens the database, the run reads the API's `/health` → `belief_modes`
//! (`EPIGRAPH_API`, else `EPIGRAPH_API_URL`) and refuses (exit 3) when any mode
//! differs from this process's, or when they cannot be read
//! (`epigraph_cli::belief_mode_check`, as `recompute_betp` and
//! `backfill_factors` do). It also refuses (exit 3) a writing run under any
//! `EPIGRAPH_ATOM_FOLD` other than `legacy`, whatever the server says: the
//! owner-frame recompute this binary calls implements only the legacy fold.
//! `--dry-run` writes nothing and is exempt. Exit 3 is also the wave-file STOP
//! below; the two are told apart by stderr (a mode refusal names
//! `belief_modes` or `atom_fold` and writes nothing).
//!
//! Disk gate (backlog 1ea4f6bf, `recompute_betp::DiskGate`): a writing run
//! needs `--disk-path <path on the database's data volume>` and
//! `--disk-check-cmd <backup and archive health check>` (or an explicit
//! `--no-backup-check`). The claim list is worked in batches of `--batch-size`
//! (default 1000), and before EACH batch the free space on that volume, less
//! the batch's projected write volume (`--projected-bytes-per-claim`, WAL and
//! archive, plus the wave file's records when it is on that volume), must stay
//! at or above `--min-free-gb` (default 20), and the check command must exit
//! 0. A failure stops the run before that batch writes (exit 4); every
//! committed write before it is recorded, so the wave file still restores
//! the run. The wave file's own volume is not gated separately: a record that
//! does not fit already rolls its claim back and stops the run (exit 3).
//!
//! Concurrency is `--concurrency` (default 8). Each task is one DB round-trip
//! to fetch BBAs + one round-trip to write the recomputed belief. On a local
//! Postgres ~10–20 claims/sec per worker is typical. 15 000 claims at 8
//! workers ≈ 2–3 minutes.

use clap::Parser;
use futures::StreamExt as _;
use std::io::BufRead;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

use epigraph_cli::belief_mode_check::{enforce_build_fold_or_exit, enforce_or_exit, RunIntent};
use epigraph_cli::recompute_betp::DiskGate;
use epigraph_cli::recompute_claim_belief::{recompute_claim_recorded, ClaimRecomputeError};

#[derive(Parser, Debug)]
#[command(
    name = "recompute_claim_belief",
    about = "Per-claim CDST recompute from current mass_functions state"
)]
struct Cli {
    /// File with one claim UUID per line. Lines starting with `#` and blank
    /// lines are ignored.
    #[arg(long)]
    input: Option<PathBuf>,
    /// Read claim UUIDs from stdin instead of a file (one per line).
    #[arg(long, conflicts_with = "input")]
    stdin: bool,
    /// Concurrency for the recompute fan-out. Default 8.
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    /// Print what would be recomputed without writing.
    #[arg(long)]
    dry_run: bool,
    /// Print a progress line every N completions. Default 100.
    #[arg(long, default_value_t = 100)]
    progress_every: usize,
    /// Wave file: record every cache write as a `belief_cache::WaveRecord`
    /// (`{claim_id, before, written, wave, at}`) so `restore_belief_cache
    /// --from <wave file>` can undo exactly this run by compare-and-swap. Must
    /// be absent or empty (one wave file holds one run); a claim whose record
    /// cannot be written is not written, and the run stops. Refused with
    /// `--dry-run`, which writes nothing and so opens no wave file.
    #[arg(long, conflicts_with = "dry_run")]
    snapshot: Option<PathBuf>,
    /// The wave name every record carries. Default `recompute_claim_belief`.
    #[arg(long, requires = "snapshot")]
    wave: Option<String>,
    /// A path on the database's data volume, for the disk gate checked before
    /// every batch (mandatory for a writing run).
    #[arg(long, required_unless_present = "dry_run")]
    disk_path: Option<PathBuf>,
    /// Free space (GB) that must remain on `--disk-path`'s volume after each
    /// batch's projected writes.
    #[arg(long, default_value_t = 20.0)]
    min_free_gb: f64,
    /// Projected write volume per claim, in bytes: WAL and archive, plus the
    /// wave file's records when it is on the measured volume.
    #[arg(long, default_value_t = 65_536)]
    projected_bytes_per_claim: u64,
    /// The backup and archive health check the disk gate runs before each
    /// batch (exit 0 = pass). A writing run needs this or `--no-backup-check`.
    #[arg(
        long,
        conflicts_with = "no_backup_check",
        required_unless_present_any = ["dry_run", "no_backup_check"]
    )]
    disk_check_cmd: Option<String>,
    /// Run the disk gate on free space alone, with no backup check. A
    /// deliberate opt-out, printed at the start of the run.
    #[arg(long)]
    no_backup_check: bool,
    /// Claims per batch (the disk gate runs before each).
    #[arg(long, default_value_t = 1000)]
    batch_size: usize,
    /// Proceed with a writing run although this process's belief modes differ
    /// from the API's `/health` report (or cannot be read). For tests and a
    /// deliberate, recorded override only.
    #[arg(long, hide = true)]
    allow_mode_skew: bool,
}

/// The wave name a `--snapshot` run records when `--wave` is not given.
const DEFAULT_WAVE: &str = "recompute_claim_belief";

/// Exit code of a run stopped because a wave-file record could not be
/// written (claims after it were not attempted). The same number as
/// `belief_mode_check::MODE_CHECK_REFUSED_EXIT`; stderr tells them apart.
const EXIT_SNAPSHOT_FAILED: i32 = 3;

/// Exit code of a run the disk gate stopped before a batch (claims from that
/// batch on were not attempted).
const EXIT_DISK_GATE: i32 = 4;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();

    // Before the database: a writing run must show its belief modes match the
    // API's (SPEC §10.2), and, since the owner-frame recompute folds only the
    // legacy way, must run under the legacy atom fold. A dry run writes
    // nothing and is exempt.
    let intent = if cli.dry_run {
        RunIntent::WritesNothing
    } else {
        RunIntent::Writes
    };
    enforce_or_exit("recompute_claim_belief", intent, cli.allow_mode_skew).await;
    enforce_build_fold_or_exit("recompute_claim_belief", intent);

    // CLI maintenance bin: the operator is the authority and the work is
    // corpus-wide. See `epigraph_cli::MaintenancePool` for why that earns a
    // bypass and a request handler does not.
    //
    // Built AFTER clap has parsed: an argv error must be reported as an argv
    // error, not as a connection failure. And `_maint_conn` is held for the
    // whole run — the lease attests to THAT connection, and the pre-PR-15
    // template dropped it while the viewer lived on.
    let maint = epigraph_cli::MaintenancePool::connect("recompute_claim_belief")
        .await
        .expect("maintenance pool");
    let session = maint
        .viewer(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance viewer");
    let viewer = session.viewer();
    if let Err(e) = run(cli, maint.pool().clone(), viewer).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run(
    cli: Cli,
    pool: sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read the claim list first — fail fast if the file is missing /
    // unparseable, before touching the DB.
    let claim_ids = read_claim_ids(&cli)?;
    println!("loaded {} claim ids", claim_ids.len());
    if claim_ids.is_empty() {
        println!("nothing to do");
        return Ok(());
    }

    if cli.dry_run {
        println!(
            "DRY-RUN — would recompute belief on {} claims",
            claim_ids.len()
        );
        return Ok(());
    }

    // The disk gate (backlog 1ea4f6bf), checked before every batch. clap
    // requires `--disk-path` and a backup check (or `--no-backup-check`) for a
    // writing run, which is all that reaches here.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let gate = DiskGate {
        path: cli
            .disk_path
            .clone()
            .ok_or("a writing run needs --disk-path")?,
        min_free_bytes: (cli.min_free_gb.max(0.0) * 1e9) as u64,
        projected_bytes_per_claim: cli.projected_bytes_per_claim,
        check_cmd: cli.disk_check_cmd.clone(),
    };
    println!(
        "disk gate: {} keeps {} bytes free after {} projected bytes per claim, before every \
         batch of {}; backup check: {}",
        gate.path.display(),
        gate.min_free_bytes,
        gate.projected_bytes_per_claim,
        cli.batch_size.max(1),
        gate.check_cmd
            .as_deref()
            .unwrap_or("NONE (--no-backup-check)"),
    );

    // The wave file is opened BEFORE the first write, and `wave_at` is taken
    // from the database clock in its own statement before it
    // (`belief_cache::WaveRecord::at`). A file that cannot be opened, or that
    // already holds a run's records, stops the run here with nothing written.
    let log = match &cli.snapshot {
        Some(path) => {
            let at: chrono::DateTime<chrono::Utc> =
                sqlx::query_scalar("SELECT now()").fetch_one(&pool).await?;
            let wave = cli.wave.as_deref().unwrap_or(DEFAULT_WAVE);
            let log = epigraph_cli::recompute_betp::WaveLog::open(path, wave, at)
                .map_err(|e| format!("--snapshot: {e}"))?;
            // The run's own record beside its wave file, before the first
            // write: this process's belief modes, whether the mode check was
            // overridden, and the disk gate, including a backup-check
            // opt-out, so the wave file shows how it was made (as
            // `recompute_betp` records its runs).
            let backup_check = match &gate.check_cmd {
                Some(cmd) => serde_json::json!({ "command": cmd }),
                None => serde_json::json!({ "command": null, "no_backup_check": true }),
            };
            epigraph_cli::recompute_betp::write_run_record(
                path,
                &serde_json::json!({
                    "bin": "recompute_claim_belief",
                    "wave": wave,
                    "wave_at": at,
                    "belief_modes": epigraph_engine::belief_modes::current(),
                    "allow_mode_skew": cli.allow_mode_skew,
                    "disk_gate": {
                        "path": gate.path,
                        "min_free_bytes": gate.min_free_bytes,
                        "projected_bytes_per_claim": gate.projected_bytes_per_claim,
                        "batch_size": cli.batch_size.max(1),
                        "backup_check": backup_check,
                    },
                }),
            )
            .map_err(|e| format!("--snapshot: run record: {e}"))?;
            println!(
                "wave file: {} (wave {wave}, wave_at {}); run record: {}.run.json",
                path.display(),
                at.to_rfc3339(),
                path.display()
            );
            Some(log)
        }
        None => None,
    };
    let log = log.as_ref();

    let total = claim_ids.len();
    let done = Arc::new(AtomicUsize::new(0));
    let claims_with_work = Arc::new(AtomicUsize::new(0));
    let claims_empty = Arc::new(AtomicUsize::new(0));
    let frame_writes = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    let recorded = Arc::new(AtomicUsize::new(0));
    let not_attempted = Arc::new(AtomicUsize::new(0));
    let stopped = Arc::new(AtomicBool::new(false));

    // Bounded concurrent fan-out. Each claim may issue multiple per-frame
    // recomputes — bounding at the claim level keeps the pool ceiling
    // predictable, and `buffer_unordered(n)` holds exactly the ceiling the
    // previous `tokio::spawn` + `Semaphore` shape did.
    //
    // What changed, and why: `tokio::spawn` requires `'static`, so every task
    // needed its OWN `Viewer`, and the bypass viewer this binary spends is one
    // half of a pair whose other half is the maintenance connection held in
    // `main`. `epigraph_db::Viewer` is no longer `Clone`, precisely so that
    // pair cannot come apart; these futures are not `'static` and simply BORROW
    // the viewer out of the session for as long as the fan-out runs.
    //
    // The cost, stated rather than implied: `concurrency` concurrent futures on
    // ONE task rather than `concurrency` tasks on the multi-threaded runtime.
    // Database round trips interleave exactly as before; a CPU-bound stretch of
    // the DS math now serialises against its peers. No test covers this —
    // `run` lives inside this binary and Cargo integration tests cannot reach
    // it. See the sibling `recompute_betp.rs`, whose shape this mirrors.
    //
    // Second cost, and the less obvious one: a PANIC in one claim now stops the
    // run, where the old `let _ = h.await;` discarded the `JoinError` and left
    // that claim silently missing from the totals. Ordinary per-claim failures
    // are unaffected — still counted into `errors` and printed. Deliberate. AND
    // IT STOPS MORE THAN THE ONE CLAIM: the panic unwinds through the
    // combinator, so the up to `concurrency - 1` siblings still in the buffer
    // are dropped at their await points and one mid-write simply stops, leaving
    // a handful of claims beyond the panicking one partially recomputed, where
    // the old independent tasks ran to completion. This binary is idempotent,
    // so the remedy is a re-run. Written out for an operator in
    // `docs/deploy.md`.
    let progress_every = cli.progress_every;
    let batch_size = cli.batch_size.max(1);
    let batches = claim_ids.len().div_ceil(batch_size);
    let mut gate_stop: Option<String> = None;
    for (i, batch) in claim_ids.chunks(batch_size).enumerate() {
        // A wave-file STOP or a gate failure leaves every later batch
        // unattempted, and counted as such.
        if gate_stop.is_some() || stopped.load(Ordering::SeqCst) {
            not_attempted.fetch_add(batch.len(), Ordering::Relaxed);
            continue;
        }
        if let Err(why) = gate.check(batch.len()) {
            gate_stop = Some(format!("before batch {} of {batches}: {why}", i + 1));
            not_attempted.fetch_add(batch.len(), Ordering::Relaxed);
            continue;
        }
        futures::stream::iter(batch.iter().copied())
            .map(|claim_id| {
                let pool = pool.clone();
                let done = done.clone();
                let claims_with_work = claims_with_work.clone();
                let claims_empty = claims_empty.clone();
                let frame_writes = frame_writes.clone();
                let errors = errors.clone();
                let recorded = recorded.clone();
                let not_attempted = not_attempted.clone();
                let stopped = stopped.clone();
                async move {
                    if stopped.load(Ordering::SeqCst) {
                        not_attempted.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    // Backlog 696d3a1c: the cache is ONE shared value, written from
                    // the claim's single owner frame, independent of frame names.
                    // An operator one-shot on the DSN the operator supplies (in
                    // practice a superuser, where a tenancy stamp is inert); each
                    // claim is one transaction on one connection.
                    match recompute_claim_recorded(&pool, viewer, claim_id, log).await {
                        Ok(outcome) => {
                            if outcome.recomputed {
                                claims_with_work.fetch_add(1, Ordering::Relaxed);
                                frame_writes.fetch_add(1, Ordering::Relaxed);
                            } else {
                                claims_empty.fetch_add(1, Ordering::Relaxed);
                            }
                            if outcome.changed && log.is_some() {
                                recorded.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(e) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                            if matches!(e, ClaimRecomputeError::Record(_)) {
                                stopped.store(true, Ordering::SeqCst);
                            }
                            eprintln!("  {claim_id}: {e}");
                        }
                    }
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if progress_every > 0 && n.is_multiple_of(progress_every) {
                        println!(
                            "  [{n}/{total}] claims_recomputed={} frame_writes={} empty={} errors={}",
                            claims_with_work.load(Ordering::Relaxed),
                            frame_writes.load(Ordering::Relaxed),
                            claims_empty.load(Ordering::Relaxed),
                            errors.load(Ordering::Relaxed),
                        );
                    }
                }
            })
            .buffer_unordered(cli.concurrency.max(1))
            .for_each(|()| async {})
            .await;
    }

    println!(
        "done: {} claims recomputed across {} (claim, frame) writes, {} had no recomputable input \
         (no BBA, only ingest templates, or a compound; cache left as it was), {} errors (of {total})",
        claims_with_work.load(Ordering::Relaxed),
        frame_writes.load(Ordering::Relaxed),
        claims_empty.load(Ordering::Relaxed),
        errors.load(Ordering::Relaxed),
    );
    if log.is_some() {
        println!("recorded: {}", recorded.load(Ordering::Relaxed));
    }
    if let Some(why) = gate_stop {
        let rest = if log.is_some() {
            "Every committed write is recorded; restore with `restore_belief_cache --from \
             <wave file>`, or free space and re-run the rest against a NEW wave file."
        } else {
            "Free space and re-run the rest; the run is idempotent."
        };
        eprintln!(
            "STOPPED by the disk gate {why}. {} claims were not attempted. {rest}",
            not_attempted.load(Ordering::Relaxed),
        );
        std::process::exit(EXIT_DISK_GATE);
    }
    if stopped.load(Ordering::SeqCst) {
        eprintln!(
            "STOPPED: a wave file record could not be written; that claim was rolled back and \
             {} claims were not attempted. Every committed write is recorded; restore with \
             `restore_belief_cache --from <wave file>`, or fix the wave file's volume and re-run \
             the rest against a NEW wave file.",
            not_attempted.load(Ordering::Relaxed),
        );
        std::process::exit(EXIT_SNAPSHOT_FAILED);
    }
    if errors.load(Ordering::Relaxed) > 0 {
        std::process::exit(2);
    }
    Ok(())
}

fn read_claim_ids(cli: &Cli) -> Result<Vec<Uuid>, Box<dyn std::error::Error>> {
    let reader: Box<dyn BufRead> = if cli.stdin {
        Box::new(std::io::BufReader::new(std::io::stdin()))
    } else if let Some(path) = &cli.input {
        Box::new(std::io::BufReader::new(std::fs::File::open(path)?))
    } else {
        return Err("must pass --input <file> or --stdin".into());
    };

    let mut ids = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        ids.push(Uuid::parse_str(trimmed).map_err(|e| format!("bad uuid {trimmed:?}: {e}"))?);
    }
    Ok(ids)
}
