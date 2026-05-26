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
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// Stub verifier that returns `derives_from` for every pair — maps to
/// MatchVerdict::Distinct upstream so all mid-band pairs land as rejected.
/// Lets `--count-only` report band distribution without spending LLM tokens.
struct CountOnlyVerifier;

#[async_trait]
impl VerifierClient for CountOnlyVerifier {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Verdict>> {
        Ok(pairs
            .iter()
            .map(|(a, b)| Verdict {
                source_id: *a,
                target_id: *b,
                relationship: "derives_from".to_string(),
                strength: 0.0,
                rationale: "count-only run; verifier skipped".to_string(),
            })
            .collect())
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

    /// Skip the LLM verifier — every mid-band pair gets a `derives_from`
    /// placeholder verdict (mapped to MatchVerdict::Distinct → Reject).
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

    let db_url =
        std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL must be set"))?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;

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
            "apply":         auto_promote,
            "count_only":    args.count_only,
        })
    );
    Ok(())
}
