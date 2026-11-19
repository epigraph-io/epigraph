//! Operator binary: rebuild the Beta-Bernoulli track (`claims.beta_alpha` /
//! `beta_beta`) of claims still on the `Beta(1, 1)` prior by replaying their
//! stored BBAs, oldest first, through the live Beta update (follow-up to
//! backlog f50344c0).
//!
//! Which claims, which BBAs, and what is left out are in
//! `epigraph_cli::beta_replay`. In short: current claims still on the prior,
//! their live non-cached BBAs, with the priors and placeholders left out by
//! default (`truth_value_seed`, `auto_wire:creation`, `prior`,
//! `ingest_template`; `--exclude-method` leaves out more).
//!
//! DRY RUN ONLY: it prints the counts (counted BBAs by writer label, excluded
//! rows, claims that would move) and a sample, and writes nothing.
//!
//! # Not to be applied
//!
//! A replay `--apply` is REFUSED (backlog candidate 913-cold-start-divergence).
//! The replay counts every stored BBA, including those of writers that never
//! move the live track (assess discounts, unlabelled rows, the seed and edge
//! wires), and the Beta arithmetic counts their uncommitted mass against the
//! hypothesis. On a production-sized corpus its dry run put the replayed
//! posteriors well below the claims' BetP, so applying it would have pushed
//! thousands of claims INTO the top-divergent list rather than out of it. The
//! problem it was meant to fix, a claim's first live update registering a
//! large divergence against an empty track, is handled where the row is
//! written instead: a cold-start update records no divergence row
//! (`epigraph_engine::ds_divergence`). The replay arithmetic and the dry run
//! stay, as the measurement; `--reverse` stays, to undo a run applied before
//! this refusal.
//!
//! # Apply (refused) and reverse
//!
//! An applying run (before the refusal) required `--manifest <PATH>`, a file
//! that must not exist yet.
//! Each batch's records (the parameters found and written, bit-exact) are
//! written and synced to disk before the batch commits. `--reverse <PATH>` reads such a
//! manifest and, with `--apply`, puts the found parameters back on every claim
//! that still holds exactly what was written; claims a live write has moved
//! since are reported and left alone. Without `--apply` it only counts.
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET (the fallback to `DATABASE_URL` is
//! refused) and its login must bypass row security: the work is corpus-wide,
//! and on an application session RLS would hide most claims.
//!
//! # Batches and resuming
//!
//! Keyset pages of `--batch` claims in id order, each in its own transaction,
//! and only claims still on the prior, so a re-run skips claims already
//! replayed. `--max-batches` bounds a run; pass its `last_id` as `--after` to
//! continue.
//!
//! Exit 0: the run finished (or stopped at `--max-batches`). Exit 1: a refusal
//! or an error (a reversal's batches already committed stay restored).

use anyhow::{anyhow, bail, Context};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "replay_beta_track",
    about = "Measure (dry run only) rebuilding beta_alpha/beta_beta of claims still on the \
             Beta(1,1) prior from their stored BBAs, on the maintenance connection; a replay \
             --apply is refused, --reverse --apply undoes an earlier run"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the work runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// With --reverse: write the reversal. A replay --apply is refused: see
    /// the binary's docs. Without it, nothing is written.
    #[arg(long, conflicts_with = "dry_run")]
    apply: bool,

    /// Explicit dry run (the default).
    #[arg(long)]
    dry_run: bool,

    /// Retired with a replay --apply (the manifest an applying run wrote).
    /// Still accepted, so an old invocation reaches the refusal.
    #[arg(long, value_name = "PATH", conflicts_with = "reverse")]
    manifest: Option<PathBuf>,

    /// Reverse the run that wrote this manifest instead of replaying.
    #[arg(long, value_name = "PATH")]
    reverse: Option<PathBuf>,

    /// Claims per batch (default 500, at most 10000).
    #[arg(long, default_value_t = epigraph_cli::beta_replay::DEFAULT_BATCH)]
    batch: i64,

    /// Resume after this claim id (a previous run's `last_id`).
    #[arg(long, value_name = "ID", conflicts_with = "reverse")]
    after: Option<uuid::Uuid>,

    /// Stop after this many batches.
    #[arg(long, conflicts_with = "reverse")]
    max_batches: Option<u64>,

    /// How many replayed claims the report samples.
    #[arg(long, default_value_t = 10)]
    sample: usize,

    /// Also leave out BBAs with this replay label (repeatable): a
    /// `combination_method`, `<null>` for an unlabelled row, or
    /// `auto_wire:workflow_outcome`. `auto_wire` names only the remaining
    /// auto_wire evidence rows. `truth_value_seed`, `auto_wire:creation`,
    /// `prior` and `ingest_template` are always left out.
    #[arg(long, value_name = "LABEL")]
    exclude_method: Vec<String>,
}

/// The refusal of a replay `--apply`.
const APPLY_RETIRED: &str = "replay_beta_track --apply is retired and will not write: \
     replaying every stored BBA builds a Beta track the live writers never would have, and \
     pushes claims INTO the top-divergent list instead of out of it. A claim's cold-start \
     update records no divergence row instead (epigraph_engine::ds_divergence). Run without \
     --apply to measure; --reverse <MANIFEST> --apply still undoes an earlier run";

/// The refusal when MAINTENANCE_DATABASE_URL is unset.
const UNSET_MAINTENANCE_DSN: &str = "replay_beta_track rewrites claims across every owner, so it \
     runs only on an explicitly configured MAINTENANCE_DATABASE_URL; it is unset, and the \
     application DSN is never used for this";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    // First, before any other check, file or connection.
    if cli.apply && cli.reverse.is_none() {
        bail!(APPLY_RETIRED);
    }
    if !(1..=10_000).contains(&cli.batch) {
        bail!("--batch must be between 1 and 10000");
    }
    // Refused before anything else, so an unset MAINTENANCE_DATABASE_URL
    // never creates a manifest or opens a connection on the application DSN
    // (checked again below on the pool's own answer).
    let (_, dsn_source) =
        epigraph_db::maintenance_database_url(&cli.database_url).map_err(|e| anyhow!("{e}"))?;
    if dsn_source != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(UNSET_MAINTENANCE_DSN);
    }

    let maint = epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "replay_beta_track")
        .await
        .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(UNSET_MAINTENANCE_DSN);
    }
    let mut session = maint
        .viewer(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .context("acquire the maintenance session")?;
    session
        .assert_privileged()
        .await
        .context("the maintenance connection cannot bypass row security")?;
    let (conn, _) = session.split();

    let out = if let Some(path) = &cli.reverse {
        let file = std::fs::File::open(path)
            .with_context(|| format!("open the manifest {}", path.display()))?;
        let batch = usize::try_from(cli.batch).unwrap_or(1);
        let report = epigraph_cli::beta_replay::reverse(
            conn,
            std::io::BufReader::new(file),
            batch,
            cli.apply,
        )
        .await
        .map_err(|e| anyhow!("the reversal failed; batches already restored stay so: {e}"))?;
        let mut out = serde_json::to_value(&report).context("serialize the report")?;
        out["manifest"] = serde_json::Value::String(path.display().to_string());
        out
    } else {
        // Always a dry run: a replay --apply was refused above.
        let mut opts = epigraph_cli::beta_replay::Options::dry_run();
        opts.batch = cli.batch;
        opts.after = cli.after;
        opts.max_batches = cli.max_batches;
        opts.sample = cli.sample;
        opts.excluded_methods
            .extend(cli.exclude_method.iter().cloned());
        let report = epigraph_cli::beta_replay::run(conn, &opts, None)
            .await
            .map_err(|e| anyhow!("the dry run failed: {e}"))?;
        let mut out = serde_json::to_value(&report).context("serialize the report")?;
        out["excluded_methods"] = serde_json::to_value(&opts.excluded_methods)?;
        out
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&out).context("serialize the report")?
    );
    Ok(())
}
