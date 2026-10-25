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
//!     recompute_betp --dry-run [--target-fold legacy|aef_standalone|aef]
//!     recompute_betp
//!
//! A writing run (no `--dry-run`) first reads the API's `/health` →
//! `belief_modes` (`EPIGRAPH_API`, else `EPIGRAPH_API_URL`) and refuses, exit
//! 3, when this process's belief modes differ or cannot be compared (SPEC
//! §10.2; `epigraph_cli::belief_mode_check`). A dry run writes
//! nothing and is exempt, so `--dry-run --target-fold <fold>` can run while
//! the server is still on another fold. This build previews only the legacy
//! fold; an AEF target reports the cohort and previews nothing. For the same
//! reason a writing run also refuses, exit 3, when its own
//! `EPIGRAPH_ATOM_FOLD` is not `legacy`, even if the API agrees: this build
//! writes only the legacy fold.
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

use epigraph_cli::belief_mode_check::{enforce_build_fold_or_exit, enforce_or_exit, RunIntent};
use epigraph_cli::recompute_betp::{predict_cached_after, run_claim, select_cohort};
use epigraph_engine::belief_modes::AtomFold;

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
    /// With --dry-run: the atom fold the preview is for (`legacy`,
    /// `aef_standalone`, `aef`), whatever the server's `EPIGRAPH_ATOM_FOLD`
    /// is, so a wave can be reviewed before its flag flips (SPEC §10.3).
    /// A dry run writes nothing, so it is exempt from the mode check.
    #[arg(long, requires = "dry_run", value_parser = parse_target_fold)]
    target_fold: Option<AtomFold>,
    /// Proceed with a writing run although this process's belief modes differ
    /// from the API's `/health` report (or cannot be read). For tests and a
    /// deliberate, recorded override only.
    #[arg(long, hide = true)]
    allow_mode_skew: bool,
}

fn parse_target_fold(raw: &str) -> Result<AtomFold, String> {
    AtomFold::parse_value(raw).ok_or_else(|| {
        let all: Vec<&str> = AtomFold::ALL.iter().map(|f| f.as_str()).collect();
        format!("unknown fold {raw:?}; one of {}", all.join(", "))
    })
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();

    // Before the database: a writing run must show its belief modes match the
    // API's (SPEC §10.2). A dry run writes nothing and is exempt.
    let intent = if cli.dry_run {
        RunIntent::WritesNothing
    } else {
        RunIntent::Writes
    };
    enforce_or_exit("recompute_betp", intent, cli.allow_mode_skew).await;
    // Agreement on the flag is not enough: this build's cache writers fold only
    // the legacy way, so a writing run under another fold refuses.
    enforce_build_fold_or_exit("recompute_betp", intent);

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
        match cli.target_fold {
            None | Some(AtomFold::Legacy) => run_dry(&pool, viewer, &cohort).await?,
            Some(fold) => {
                // This build has no AEF fold to preview under; printing the
                // legacy fold's numbers under an AEF label would mislead a
                // wave review. The change that adds the fold to this bin fills it in.
                println!("DRY-RUN — no writes");
                println!(
                    "target fold {fold}: this build cannot compute the {fold} fold; \
                     no values previewed for {} cohort claims",
                    cohort.len()
                );
            }
        }
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
    let mut skipped = 0usize;
    for &claim_id in cohort {
        let cached_before: Option<f64> =
            sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
                .bind(claim_id)
                .fetch_optional(pool)
                .await?
                .flatten();

        // A real run caches only the owner frame's value (`run_claim` ->
        // `recompute_claim_cached_belief`); report that as "what a real run
        // would leave cached".
        //
        // No owner: a real run writes nothing for this claim (no BBA, only
        // ingest templates, or a compound). Counted, so the report tells a
        // guarded claim from an absent one.
        let Some((_, owned)) = predict_cached_after(pool, viewer, claim_id).await? else {
            skipped += 1;
            continue;
        };
        let recomputed_after = owned.pignistic_prob;
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
        "dry-run summary: {previewed} claims previewed, {unchanged} unchanged, {skipped} with no \
         recomputable input (no BBA, only ingest templates, or a compound; a real run leaves \
         their cache as it is) (of {} cohort claims)",
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
        "done: {} claims recomputed across {} (claim, frame) writes, {} had no recomputable input \
         (no BBA, only ingest templates, or a compound; cache left as it was), {} errors (of {total})",
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
