//! Table-graph extraction and ingestion driver.

mod discover;
mod dossier;
mod extract;
mod ingest;
mod llm;
mod types;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "table_graph")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Discover tables and crates; print a JSON listing.
    Discover,
    /// Build dossiers + run LLM extraction; write staging files.
    Extract {
        #[arg(long)]
        only: Option<String>,
    },
    /// Ingest staged narratives via extract-claims + ingest_document.
    Ingest {
        #[arg(long)]
        dry_run: bool,
        /// Filter to a single table name (matches all repos that contain it).
        #[arg(long)]
        only: Option<String>,
    },
    /// Verification queries.
    Verify,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Discover => discover::run(),
        Cmd::Extract { only } => extract::run(only.as_deref()),
        Cmd::Ingest { dry_run, only } => ingest::run(dry_run, only.as_deref()),
        Cmd::Verify => ingest::verify(),
    }
}
