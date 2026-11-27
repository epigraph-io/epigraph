//! Table-graph extraction and ingestion driver.
//!
//! ```text
//! cargo run -p epigraph-cli --example table_graph -- discover \
//!     --epigraph-root <epigraph checkout> --episcience-root <episcience checkout>
//! cargo run -p epigraph-cli --example table_graph -- extract \
//!     --epigraph-root <epigraph checkout> --episcience-root <episcience checkout> [--only <table>]
//! ```

mod cli;
mod discover;
mod dossier;
mod extract;
mod ingest;
mod llm;
mod types;

use clap::Parser;
use cli::{Cli, Cmd};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Discover { roots } => discover::run(&roots),
        Cmd::Extract { roots, only } => extract::run(&roots, only.as_deref()),
        Cmd::Ingest { dry_run, only } => ingest::run(dry_run, only.as_deref()),
        Cmd::Verify => ingest::verify(),
    }
}
