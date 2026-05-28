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
//! Frame handling: for each input claim, looks up every distinct
//! `frame_id` in `mass_functions` and recomputes per-frame via
//! `edge_factor::recompute_claim_belief_on_frame`. `claims.{belief, pl,
//! pignistic_prob, ...}` are frame-agnostic scalars — last writer wins.
//! Per-claim frames are processed in lexicographic frame-name order so
//! two runs against the same population converge to the same cached value.
//!
//! Reads claim_ids from a file (one UUID per line) or `--stdin`.
//!
//! Usage:
//!     epigraph-recompute-belief --input /tmp/claim_ids.txt
//!     epigraph-recompute-belief --stdin < /tmp/claim_ids.txt
//!     epigraph-recompute-belief --input /tmp/claim_ids.txt --dry-run
//!
//! Concurrency is `--concurrency` (default 8). Each task is one DB round-trip
//! to fetch BBAs + one round-trip to write the recomputed belief. On a local
//! Postgres ~10–20 claims/sec per worker is typical. 15 000 claims at 8
//! workers ≈ 2–3 minutes.

use clap::Parser;
use std::io::BufRead;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

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
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
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

    let pool = epigraph_cli::db_connect().await?;
    let total = claim_ids.len();
    let done = Arc::new(AtomicUsize::new(0));
    let claims_with_work = Arc::new(AtomicUsize::new(0));
    let claims_empty = Arc::new(AtomicUsize::new(0));
    let frame_writes = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));

    // Bounded concurrent fan-out via tokio Semaphore. Each task may issue
    // multiple per-frame recomputes for one claim — bounding at the
    // claim level keeps the pool ceiling predictable.
    let sem = Arc::new(tokio::sync::Semaphore::new(cli.concurrency.max(1)));
    let mut handles = Vec::with_capacity(claim_ids.len());
    for claim_id in claim_ids {
        let permit = sem.clone().acquire_owned().await?;
        let pool = pool.clone();
        let done = done.clone();
        let claims_with_work = claims_with_work.clone();
        let claims_empty = claims_empty.clone();
        let frame_writes = frame_writes.clone();
        let errors = errors.clone();
        let progress_every = cli.progress_every;
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            match recompute_one_claim_all_frames(&pool, claim_id).await {
                Ok(written) => {
                    if written > 0 {
                        claims_with_work.fetch_add(1, Ordering::Relaxed);
                        frame_writes.fetch_add(written, Ordering::Relaxed);
                    } else {
                        claims_empty.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    errors.fetch_add(1, Ordering::Relaxed);
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
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    println!(
        "done: {} claims recomputed across {} (claim, frame) writes, {} had no BBAs, {} errors (of {total})",
        claims_with_work.load(Ordering::Relaxed),
        frame_writes.load(Ordering::Relaxed),
        claims_empty.load(Ordering::Relaxed),
        errors.load(Ordering::Relaxed),
    );
    if errors.load(Ordering::Relaxed) > 0 {
        std::process::exit(2);
    }
    Ok(())
}

/// Discover every distinct `frame_id` this claim has BBAs on, ordered by
/// the frame's name, and recompute each. Frame-name ordering gives a
/// deterministic last-writer for the cached `claims.{belief, pl, betp, ...}`
/// scalars so that two runs against the same population converge.
///
/// Returns the number of (claim, frame) pairs that produced a recompute.
async fn recompute_one_claim_all_frames(
    pool: &sqlx::PgPool,
    claim_id: Uuid,
) -> Result<usize, String> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT DISTINCT mf.frame_id, f.name \
           FROM mass_functions mf \
           JOIN frames f ON f.id = mf.frame_id \
          WHERE mf.claim_id = $1 \
          ORDER BY f.name",
    )
    .bind(claim_id)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("list frames for claim: {e}"))?;
    let mut written = 0usize;
    for (frame_id, _frame_name) in rows {
        let did =
            epigraph_engine::edge_factor::recompute_claim_belief_on_frame(pool, claim_id, frame_id)
                .await?;
        if did {
            written += 1;
        }
    }
    Ok(written)
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
