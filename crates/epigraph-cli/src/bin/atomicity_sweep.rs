//! `atomicity_sweep`: label the current atoms that still assert several
//! independent things `compound-atom`, and take the label off claims that no
//! longer qualify (backlog `72850d43`). See `epigraph_cli::atomicity_sweep`
//! for the rule.
//!
//! DRY RUN by default: prints what would change and writes nothing.
//! `--apply` writes the labels. Runs on the maintenance connection
//! (`MAINTENANCE_DATABASE_URL`, falling back to `DATABASE_URL` only when it
//! is privileged), because the sweep must see every group's atoms.
//!
//! The labelled claims are the input of `decompose_claims --redecompose
//! --ids-file`; `query_claims_by_label(["compound-atom"])` lists them, and the
//! MCP `query_compound_claims` tool finds the same set live without the label.
//!
//! Usage:
//!     atomicity_sweep                       # dry run: counts and ids
//!     atomicity_sweep --apply               # write the labels
//!     atomicity_sweep --max-scan 100000     # bound the atom walk

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "atomicity_sweep",
    about = "Label current compound atoms `compound-atom` and unlabel claims that no longer qualify (dry run unless --apply)"
)]
struct Args {
    /// Write the labels. Without it nothing is written.
    #[arg(long)]
    apply: bool,

    /// Most atoms to read. A capped walk labels what it read and unlabels
    /// nothing, since it cannot tell a stale label from one past the cap.
    #[arg(long, default_value_t = 5_000_000)]
    max_scan: usize,

    /// Print every changed id, not only the counts.
    #[arg(long)]
    list: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let args = Args::parse();
    let maint = epigraph_cli::MaintenancePool::connect("atomicity_sweep").await?;
    let session = maint
        .viewer(epigraph_db::visibility::SystemReason::DedupSweep)
        .await?;
    let report = epigraph_cli::atomicity_sweep::sweep(
        maint.pool(),
        session.viewer(),
        args.apply,
        args.max_scan,
    )
    .await?;
    println!(
        "atomicity_sweep: applied={} atoms_scanned={} compound_atoms={} labelled={} \
         unlabelled={} scan_capped={}",
        report.applied,
        report.atoms_scanned,
        report.compound_atoms,
        report.labelled.len(),
        report.unlabelled.len(),
        report.scan_capped
    );
    if args.list {
        for id in &report.labelled {
            println!("label {id}");
        }
        for id in &report.unlabelled {
            println!("unlabel {id}");
        }
    }
    if !args.apply {
        println!("dry run: nothing was written (pass --apply)");
    }
    Ok(())
}
