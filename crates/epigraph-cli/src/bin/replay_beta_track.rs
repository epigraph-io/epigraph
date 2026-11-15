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
//! DRY RUN BY DEFAULT: without `--apply` it prints the counts (counted BBAs by
//! writer label, excluded rows, claims that would move) and a sample, and
//! writes nothing.
//!
//! It writes NO `ds_bayesian_divergence` row for the history: the next live
//! evidence write on a replayed claim records its divergence.
//!
//! # Apply and reverse
//!
//! `--apply` requires `--manifest <PATH>`, a file that must not exist yet.
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
//! continue (with a new `--manifest`).
//!
//! Exit 0: the run finished (or stopped at `--max-batches`). Exit 1: a refusal
//! or an error (batches already committed stay written, and are in the
//! manifest).

use anyhow::{anyhow, bail, Context};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "replay_beta_track",
    about = "Rebuild beta_alpha/beta_beta of claims still on the Beta(1,1) prior from their \
             stored BBAs (dry run unless --apply), on the maintenance connection"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the work runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Write. Without it, nothing is written.
    #[arg(long, conflicts_with = "dry_run")]
    apply: bool,

    /// Explicit dry run (the default).
    #[arg(long)]
    dry_run: bool,

    /// With --apply: the manifest to write (must not exist). Required.
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

/// The manifest file. `flush`, which the replay calls once per batch before
/// it commits, also syncs the file to disk, so a host crash after a commit
/// cannot lose that batch's records.
struct SyncedManifest(std::io::BufWriter<std::fs::File>);

impl std::io::Write for SyncedManifest {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.0, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.0)?;
        self.0.get_ref().sync_data()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    if !(1..=10_000).contains(&cli.batch) {
        bail!("--batch must be between 1 and 10000");
    }
    if cli.apply && cli.reverse.is_none() && cli.manifest.is_none() {
        bail!("--apply needs --manifest <PATH>: the record a --reverse undoes the run by");
    }
    // Opened before connecting, so an existing file refuses the run before it
    // touches the database, and a later write cannot clobber an older run's
    // manifest.
    let mut manifest_file = match (&cli.manifest, cli.apply) {
        (Some(path), true) => Some(SyncedManifest(std::io::BufWriter::new(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .with_context(|| format!("create the manifest {}", path.display()))?,
        ))),
        _ => None,
    };

    let maint = epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "replay_beta_track")
        .await
        .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(
            "replay_beta_track rewrites claims across every owner, so it runs only on an \
             explicitly configured MAINTENANCE_DATABASE_URL; it is unset, and the application \
             DSN is never used for this"
        );
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
        let mut opts = epigraph_cli::beta_replay::Options::dry_run();
        opts.apply = cli.apply;
        opts.batch = cli.batch;
        opts.after = cli.after;
        opts.max_batches = cli.max_batches;
        opts.sample = cli.sample;
        opts.excluded_methods
            .extend(cli.exclude_method.iter().cloned());
        let report = epigraph_cli::beta_replay::run(
            conn,
            &opts,
            manifest_file.as_mut().map(|w| w as &mut dyn std::io::Write),
        )
        .await
        .map_err(|e| anyhow!("the replay failed; batches already committed stay written: {e}"))?;
        let mut out = serde_json::to_value(&report).context("serialize the report")?;
        out["excluded_methods"] = serde_json::to_value(&opts.excluded_methods)?;
        if let Some(path) = &cli.manifest {
            out["manifest"] = serde_json::Value::String(path.display().to_string());
        }
        out
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&out).context("serialize the report")?
    );
    Ok(())
}
