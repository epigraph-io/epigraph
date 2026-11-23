//! Post-sweep contamination split (`tests/cross_source/prompts_v1.md` §2
//! step 3; backlog ea6eb305). See [`epigraph_cli::contamination_split`].
//!
//! ```sh
//! # file mode: never touches a database
//! contamination_split --ledger <archive>/contamination_ledger.json \
//!     --pairs <archive>/run_pairs.json --out-dir <archive>/split
//! # run mode: reads the run's match_candidates rows (read-only) first
//! contamination_split --ledger <archive>/contamination_ledger.json \
//!     --run-id <run_id from the sweep's JSON line> --out-dir <archive>/split
//! ```

use clap::Parser;
use epigraph_cli::contamination_split::{
    ensure_absent, read_ledger, read_pairs, split, write_split, CLEAN_FILE, CONTAMINATED_FILE,
    COUNTS_FILE, RUN_PAIRS_FILE,
};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(
    name = "contamination_split",
    about = "Split a cross-source sweep's pairs into clean and contaminated sets \
             against a pre-sweep contamination ledger snapshot",
    long_about = "Split a cross-source sweep's candidate pairs into clean and contaminated \
                  sets against the contamination ledger snapshot taken BEFORE the sweep \
                  (tests/cross_source/prompts_v1.md section 2 step 3). Writes clean_pairs.json, \
                  contaminated_pairs.json and split_counts.json under --out-dir (refusing to \
                  overwrite; all files or none) and prints the counts as one JSON line, \
                  including the ledger's sha256 and generated_at, the pairs' sha256 and the \
                  run id. A --run-id that matches no row is refused. Writes nothing to the \
                  database.\n\nEvery input and output file lists claim ids from every \
                  tenant: archive them privately and never commit them to the public \
                  repository."
)]
struct Args {
    /// Ledger snapshot written by `calibrate_matcher --contamination-ledger`
    /// before the sweep ran.
    #[arg(long)]
    ledger: PathBuf,

    /// The sweep's pairs as a JSON array of objects with `claim_a` and
    /// `claim_b` (other fields are carried through). Never connects to a
    /// database.
    #[arg(long, conflicts_with = "run_id", required_unless_present = "run_id")]
    pairs: Option<PathBuf>,

    /// Read the pairs from the `match_candidates` rows stamped with this
    /// `matcher_run_id` (read-only, through the maintenance connection) and
    /// archive them as run_pairs.json next to the split. A later sweep
    /// re-stamps rows it touches, so run this before the next sweep.
    #[arg(long)]
    run_id: Option<Uuid>,

    /// Directory for the output files.
    #[arg(long)]
    out_dir: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // Read the ledger first so a bad snapshot fails before any database work.
    let ledger = read_ledger(&args.ledger)?;
    let (pairs, run_pairs_bytes) = match (&args.pairs, args.run_id) {
        (Some(path), _) => (read_pairs(path)?, None),
        (None, Some(run_id)) => {
            // Every output name is checked before the fetch, so a run into a
            // directory holding an earlier split refuses without database
            // work. `write_split` checks again and writes all four files as
            // one batch, so a failure never leaves run_pairs.json behind.
            ensure_absent(
                &args.out_dir,
                &[RUN_PAIRS_FILE, CLEAN_FILE, CONTAMINATED_FILE, COUNTS_FILE],
            )?;
            let maint = epigraph_cli::MaintenancePool::connect("contamination_split")
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let (pairs, bytes) = epigraph_cli::contamination_split::fetch_run_pairs_nonempty(
                maint.pool(),
                run_id,
            )
            .await?;
            (pairs, Some(bytes))
        }
        (None, None) => anyhow::bail!("pass --pairs or --run-id"),
    };
    let (clean, contaminated, counts) = split(pairs, &ledger);
    write_split(
        &args.out_dir,
        run_pairs_bytes,
        &clean,
        &contaminated,
        &counts,
    )?;
    println!("{}", serde_json::to_string(&counts)?);
    Ok(())
}
