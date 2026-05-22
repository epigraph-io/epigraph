//! Batch driver for the cross-source matcher (spec §Tasks 18).
//!
//! Picks a window of recently-touched claims that haven't been scanned in 7+
//! days, runs the matching pipeline against them, optionally applies the
//! promotions, and stamps `claims.last_match_scan_at` so the next sweep
//! advances. Output is a single JSON line on stdout, easy to feed into
//! scheduled-job logs.

use clap::Parser;
use epigraph_cli::matching_client::RerankBridgesClient;
use epigraph_engine::matching::calibration::MatcherConfig;
use epigraph_engine::matching::pipeline::{run_pipeline, RunInputs};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Exactly one of --dry-run / --apply. Default behavior — neither flag —
    // is rejected to force operators to declare intent. (Spec §Failure Modes
    // calls out silent edge writes as a hazard.)
    match (args.dry_run, args.apply) {
        (true, false) | (false, true) => {}
        (true, true) => anyhow::bail!("--dry-run and --apply are mutually exclusive"),
        (false, false) => anyhow::bail!("must pass one of --dry-run or --apply"),
    }
    let auto_promote = args.apply;

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
    let verifier = Box::new(RerankBridgesClient::new(pool.clone()));
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
    if !seeds.is_empty() {
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
        })
    );
    Ok(())
}
