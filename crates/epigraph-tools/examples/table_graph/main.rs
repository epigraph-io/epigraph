//! Table-graph extraction and ingestion driver.

mod discover;
mod dossier;
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
    Extract { #[arg(long)] only: Option<String> },
    /// Ingest staged narratives via extract-claims + ingest_document.
    Ingest { #[arg(long)] dry_run: bool },
    /// Verification queries.
    Verify,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Discover => discover::run(),
        Cmd::Extract { only } => dossier::run(only.as_deref()),
        Cmd::Ingest { dry_run } => ingest::run(dry_run),
        Cmd::Verify => ingest::verify(),
    }
}
