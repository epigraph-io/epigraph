//! One-shot operator binary: backfill stale cached `claims.pignistic_prob`
//! (and `belief`, `plausibility`, `conflict_k`, `mass_on_missing`) on the
//! cohort of claims whose combined belief was last written under the
//! superseded raw-`source_strength` model.
//!
//! Backlog claim f2521c53-86bb-4b3b-96b4-a5cc963f8015: the claim originally
//! cited `auto_wire_ds_update`'s `ds_auto.rs:289-326` combine+discount+
//! pignistic pattern (raw stored `source_strength`) as the reference to
//! mirror. That reference is stale — every touch path (including
//! `auto_wire_ds_update`, now at `ds_auto.rs:302`) has since moved to
//! `effective_source_strength`'s dynamic reliability derivation
//! (evidence_type + locality + per-frame factor + calibration; issue #197
//! Phase 2/4). This binary re-derives the cached BetP under the CURRENT
//! model — the opposite of pinning the superseded one — for the cohort of
//! claims most likely to be stale under it:
//!
//!   (a) claims with more than one BBA on the same binary (2-hypothesis)
//!       frame ("hub" claims needing a fresh Dempster combination across
//!       sources), and
//!   (b) single-BBA claims on a binary frame whose stored `masses` JSONB
//!       has a non-simple focal-element key (`"1"` or `"~"`).
//!
//! See `crates/epigraph-cli/src/recompute_betp.rs` for the cohort query and
//! per-claim orchestration, both of which call straight through to
//! `epigraph_engine::edge_factor`'s canonical recompute entry points — this
//! binary does not re-derive any DS combine/discount/pignistic logic itself
//! (see `crates/epigraph-cli/src/bin/recompute_claim_belief.rs`, the sibling
//! operator binary this one's frame-handling mirrors).
//!
//! Usage:
//!     recompute_betp --dry-run
//!     recompute_betp
//!
//! `--dry-run` prints, per cohort claim, the cached `pignistic_prob` before
//! the run alongside what the current combine pipeline would recompute it
//! to (and the delta), without writing anything. Without `--dry-run`, the
//! same cohort is recomputed for real via the same transaction-safe engine
//! write path `recompute_claim_belief.rs` uses.

use clap::Parser;
use futures::StreamExt as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

use epigraph_cli::recompute_betp::{preview_claim, run_claim, select_cohort};

#[derive(Parser, Debug)]
#[command(
    name = "recompute_betp",
    about = "Backfill stale cached BetP on the multi-BBA-hub / non-simple-shape claim cohort"
)]
struct Cli {
    /// Print what would be recomputed (cached-before vs. recomputed-after,
    /// with delta) without writing.
    #[arg(long)]
    dry_run: bool,
    /// Concurrency for the recompute fan-out. Default 8.
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
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

    // CLI maintenance bin: the operator is the authority and the work is
    // corpus-wide. See `epigraph_cli::MaintenancePool` for why that earns a
    // bypass and a request handler does not.
    //
    // Built AFTER clap has parsed: an argv error must be reported as an argv
    // error, not as a connection failure. And `_maint_conn` is held for the
    // whole run — the lease attests to THAT connection, and the pre-PR-15
    // template dropped it while the viewer lived on.
    let maint = epigraph_cli::MaintenancePool::connect("recompute_betp")
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
    let cohort = select_cohort(&pool).await?;
    println!("cohort: {} claims", cohort.len());
    if cohort.is_empty() {
        println!("nothing to do");
        return Ok(());
    }

    if cli.dry_run {
        run_dry(&pool, viewer, &cohort).await?;
        return Ok(());
    }

    run_for_real(&pool, viewer, cohort, cli.concurrency, cli.progress_every).await
}

/// Dry-run path: sequential (no concurrency needed — read-only, and the
/// point is a readable before/after/delta report, not throughput) preview
/// of every cohort claim. Prints claim_id, cached_before, recomputed_after,
/// delta. Writes nothing.
async fn run_dry(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    cohort: &[Uuid],
) -> Result<(), Box<dyn std::error::Error>> {
    println!("DRY-RUN — no writes");
    println!(
        "{:<38} {:>14} {:>16} {:>10}",
        "claim_id", "cached_before", "recomputed_after", "delta"
    );
    let mut previewed = 0usize;
    let mut unchanged = 0usize;
    for &claim_id in cohort {
        let cached_before: Option<f64> =
            sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
                .bind(claim_id)
                .fetch_optional(pool)
                .await?
                .flatten();

        let previews = preview_claim(pool, viewer, claim_id).await?;
        // claims.pignistic_prob is frame-agnostic — last writer wins across
        // a claim's frames, same ordering `run_claim` writes in. Report the
        // last preview's value as "what a real run would leave cached".
        let Some((_, last)) = previews.last() else {
            continue;
        };
        let recomputed_after = last.pignistic_prob;
        let delta = match cached_before {
            Some(before) => recomputed_after - before,
            None => f64::NAN,
        };
        println!(
            "{:<38} {:>14} {:>16.6} {:>10}",
            claim_id,
            cached_before
                .map(|v| format!("{v:.6}"))
                .unwrap_or_else(|| "NULL".to_string()),
            recomputed_after,
            if delta.is_nan() {
                "n/a".to_string()
            } else {
                format!("{delta:+.6}")
            },
        );
        previewed += 1;
        if let Some(before) = cached_before {
            if (recomputed_after - before).abs() < 1e-9 {
                unchanged += 1;
            }
        }
    }
    println!(
        "dry-run summary: {previewed} claims previewed, {unchanged} unchanged (of {} cohort claims)",
        cohort.len()
    );
    Ok(())
}

/// Real-write path: bounded concurrent fan-out over the cohort, mirroring
/// `recompute_claim_belief.rs`'s fan-out shape.
async fn run_for_real(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    cohort: Vec<Uuid>,
    concurrency: usize,
    progress_every: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let total = cohort.len();
    let done = Arc::new(AtomicUsize::new(0));
    let claims_with_work = Arc::new(AtomicUsize::new(0));
    let claims_empty = Arc::new(AtomicUsize::new(0));
    let frame_writes = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));

    // Bounded concurrent fan-out, at the SAME ceiling the previous
    // `tokio::spawn` + `Semaphore` shape held: `buffer_unordered(n)` polls at
    // most `n` of these futures at a time, so the number of claims in flight —
    // and therefore the peak connection demand on `pool` — is unchanged.
    //
    // What changed, and why: `tokio::spawn` requires `'static`, so every task
    // needed its OWN `Viewer`, and the bypass viewer this binary spends is one
    // half of a pair whose other half is the maintenance connection held in
    // `main`. `epigraph_db::Viewer` is no longer `Clone`, precisely so that
    // pair cannot come apart; these futures are not `'static` and simply BORROW
    // the viewer out of the session for as long as the fan-out runs, which is
    // the coupling stated as a lifetime instead of as a comment.
    //
    // The cost, stated rather than implied: the work now runs as `concurrency`
    // concurrent futures on ONE task rather than `concurrency` tasks on the
    // multi-threaded runtime. The per-claim work is dominated by database
    // round trips, which interleave here exactly as they did before; any
    // CPU-bound stretch of the DS math now serialises against its peers where
    // it could previously occupy several worker threads. Wall-clock on a
    // cohort is expected to be comparable and is not asserted by any test —
    // `run_for_real` lives inside this binary and Cargo integration tests
    // cannot reach it.
    //
    // Second cost, and the less obvious one: a PANIC in one claim now stops the
    // run. The old shape joined with `let _ = h.await;`, which DISCARDED the
    // `JoinError` a panicking task produced — the process carried on and that
    // claim was silently missing from the totals. Ordinary per-claim failures
    // are unaffected: they were counted into `errors` and printed before, and
    // still are. Taken deliberately, because a maintenance binary that
    // under-counts without saying so is worse than one that stops, and the old
    // behaviour was an artefact of the join rather than a decision. AND IT
    // STOPS MORE THAN THE ONE CLAIM: the panic unwinds through the combinator,
    // so the up to `concurrency - 1` sibling futures still in the buffer are
    // dropped at their await points and one mid-write simply stops, leaving a
    // handful of claims beyond the panicking one partially recomputed. Under
    // the old shape the siblings were independent tasks and ran to completion.
    // This binary is idempotent, so the remedy is a re-run. Written out for an
    // operator in `docs/deploy.md` alongside the fan-out note.
    futures::stream::iter(cohort)
        .map(|claim_id| {
            let pool = pool.clone();
            let done = done.clone();
            let claims_with_work = claims_with_work.clone();
            let claims_empty = claims_empty.clone();
            let frame_writes = frame_writes.clone();
            let errors = errors.clone();
            async move {
                match run_claim(&pool, viewer, claim_id).await {
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
            }
        })
        .buffer_unordered(concurrency.max(1))
        .for_each(|()| async {})
        .await;

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
