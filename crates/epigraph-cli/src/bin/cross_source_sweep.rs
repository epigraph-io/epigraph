//! Batch driver for the cross-source matcher (spec §Tasks 18).
//!
//! Picks a window of recently-touched claims that haven't been scanned in 7+
//! days, runs the matching pipeline against them, optionally applies the
//! promotions, and stamps `claims.last_match_scan_at` so the next sweep
//! advances. Output is a single JSON line on stdout, easy to feed into
//! scheduled-job logs.

use async_trait::async_trait;
use clap::Parser;
use epigraph_cli::matching_client::RerankBridgesClient;
use epigraph_engine::matching::calibration::MatcherConfig;
use epigraph_engine::matching::pipeline::{run_pipeline, RunInputs};
use epigraph_engine::matching::verifier::{Verdict, VerifierClient};
use uuid::Uuid;

/// Stub verifier for `--count-only`: **no answer** for every pair, so the band
/// distribution can be measured without spending LLM tokens and without the
/// stub's silence being mistaken for a finding.
///
/// It used to return `relationship: "derives_from", strength: 0.0`, which
/// `map_relationship` sends to `MatchVerdict::Distinct` → `PolicyAction::Reject`
/// → `Policy::patch_verdict("distinct")` — i.e. the *same* fabrication this
/// binary's real verifier was fixed for, reached by the same mechanism, from a
/// path where no model was asked anything at all. That wrote 12,006
/// `status='rejected'` rows carrying the rationale `"count-only run; verifier
/// skipped"` in prod (MEASURED, read-only, all from one 2026-05-23 run).
///
/// Returning `None` loses **no** band-distribution information: `run_pipeline`
/// increments `mid_band` *before* it inspects the slot, so every pair routed
/// here is still counted; the ones that used to be labelled `rejected` are now
/// reported honestly as `skipped_no_verdict`, and `rejected` narrows to the
/// low-band pairs that really were rejected on score. The only thing dropped is
/// the `match_candidates` write — and that write is the harm, on a run that
/// already forces `--dry-run` and already skips the `last_match_scan_at` stamp
/// because it is an analysis run, not a real sweep.
struct CountOnlyVerifier;

#[async_trait]
impl VerifierClient for CountOnlyVerifier {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Option<Verdict>>> {
        // One slot per input pair (the trait's alignment contract), every one
        // `None`. Nothing was asked, so there is nothing to report.
        Ok(pairs.iter().map(|_| None).collect())
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "cross_source_sweep",
    about = "Sweep claims for cross-source matches and (optionally) promote them"
)]
struct Args {
    /// Maximum number of seed claims to scan in this sweep.
    #[arg(long, default_value_t = 200)]
    limit: i64,

    /// Run the pipeline without writing CORROBORATES edges. Match-candidate
    /// rows are still written so admins can review.
    #[arg(long)]
    dry_run: bool,

    /// Write CORROBORATES edges for high-band and verifier-approved mid-band
    /// candidates.
    #[arg(long)]
    apply: bool,

    /// Path to calibration.toml; defaults to the workspace root.
    #[arg(long, env = "EPIGRAPH_CALIBRATION_PATH")]
    calibration: Option<std::path::PathBuf>,

    /// Skip the LLM verifier — every mid-band pair is reported as "no answer"
    /// and skipped (counted in `skipped_no_verdict`, no candidate row written).
    /// Lets you measure band distribution against the calibration without
    /// burning LLM tokens. Forces --dry-run.
    #[arg(long)]
    count_only: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // --count-only forces dry-run (no edges written) and a stub verifier.
    let dry_run = args.dry_run || args.count_only;
    let apply = args.apply && !args.count_only;
    match (dry_run, apply) {
        (true, false) | (false, true) => {}
        (true, true) => anyhow::bail!("--dry-run and --apply are mutually exclusive"),
        (false, false) => anyhow::bail!("must pass one of --dry-run or --apply"),
    }
    let auto_promote = apply;

    // Corpus-wide by construction: a cross-SOURCE match that only sees one
    // tenant's rows is the one match this sweep exists to find and would
    // silently not find. It also writes match_candidates.
    // See `epigraph_cli::MaintenancePool`.
    //
    // Constructed after the argv validation above, so `--dry-run`/`--apply`
    // misuse is still reported as misuse rather than as a connection error
    // (pinned by `tests/cross_source_sweep_smoke.rs`).
    let maint = epigraph_cli::MaintenancePool::connect("cross_source_sweep")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let pool = maint.pool().clone();

    let cfg = match args.calibration {
        Some(p) => MatcherConfig::load_from(&p)?,
        None => MatcherConfig::load_default()?,
    };

    // Pick seeds: claims never scanned, or scanned more than 7 days ago.
    // Bias toward recent claims so newly-ingested material gets attention
    // first — the older-and-unscanned tail can wait for a backfill pass.
    let seeds: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM claims
         WHERE COALESCE(is_current, true) = true
           AND (last_match_scan_at IS NULL
                OR last_match_scan_at < now() - INTERVAL '7 days')
         ORDER BY created_at DESC
         LIMIT $1",
    )
    .bind(args.limit)
    .fetch_all(&pool)
    .await?;

    let seed_count = seeds.len();
    let verifier: Box<dyn VerifierClient> = if args.count_only {
        Box::new(CountOnlyVerifier)
    } else {
        Box::new(RerankBridgesClient::new(pool.clone()))
    };
    let report = run_pipeline(
        &pool,
        RunInputs {
            seeds: seeds.clone(),
            cfg,
            verifier,
            auto_promote,
        },
    )
    .await?;

    // Stamp the seed window so the next sweep moves forward, regardless of
    // whether we applied. Skipping this on --dry-run would put the sweep in
    // a loop re-scanning the same seeds.
    // EXCEPT for --count-only: that's an analysis run, not a real sweep, and
    // stamping would skip the picked claims from the next legitimate sweep
    // for 7 days.
    if !seeds.is_empty() && !args.count_only {
        sqlx::query("UPDATE claims SET last_match_scan_at = now() WHERE id = ANY($1)")
            .bind(&seeds)
            .execute(&pool)
            .await?;
    }

    println!(
        "{}",
        serde_json::json!({
            "run_id":        report.run_id,
            "seeds":         seed_count,
            "scanned_pairs": report.scanned_pairs,
            "promoted":      report.promoted,
            "mid_band":      report.mid_band,
            "rejected":      report.rejected,
            // Nonzero = the verifier re-scored pairs a human already decided
            // and the gate refused the rewrite. The nightly wrapper journals
            // this JSON, so a spike is visible with no extra plumbing.
            "verdict_writes_suppressed": report.verdict_writes_suppressed,
            // Pairs the verifier had no answer for and the pipeline skipped
            // without touching stored state. NOT an outage alarm: the
            // reranker's pre-LLM query drops pairs that already carry an edge
            // while the pipeline does not, so a re-run over an already-linked
            // corpus lands a large routine baseline here. A total verifier
            // outage is a hard error instead (see matching_client's
            // `is_total_verifier_outage`): `run_pipeline` propagates it, so the
            // run exits nonzero and never reaches the `last_match_scan_at`
            // stamp above.
            "skipped_no_verdict": report.skipped_no_verdict,
            "apply":         auto_promote,
            "count_only":    args.count_only,
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Link 1 of 2 for "`--count-only` writes no `match_candidates` row":
    /// the stub answers **nothing** for every pair it is handed.
    ///
    /// Link 2 is `epigraph-engine`'s
    /// `pipeline_end_to_end::verifier_no_answer_writes_nothing_and_is_counted_separately`,
    /// which asserts on persisted state that a `None` slot produces zero
    /// `match_candidates` rows and zero edges, and lands in `skipped_no_verdict`
    /// rather than `rejected`. Composed, the two pin the whole path without a
    /// live-DB run of the binary.
    ///
    /// The regression this guards: returning
    /// `Verdict { relationship: "derives_from", strength: 0.0 }` here mapped to
    /// `MatchVerdict::Distinct` → `Reject` → `patch_verdict("distinct")`, so an
    /// analysis run that asked no model anything wrote 12,006 `rejected` rows.
    #[tokio::test]
    async fn count_only_verifier_answers_nothing_for_every_pair() {
        let pairs: Vec<(Uuid, Uuid)> = (0..3).map(|_| (Uuid::new_v4(), Uuid::new_v4())).collect();
        let out = CountOnlyVerifier.verify(&pairs).await.expect("verify");

        assert_eq!(
            out.len(),
            pairs.len(),
            "one slot per input pair — the pipeline bails if alignment breaks"
        );
        assert!(
            out.iter().all(|slot| slot.is_none()),
            "a run that asks no model anything has no verdict to report; \
             any Some(..) here is a fabricated finding, got {out:?}"
        );
    }
}
