//! Operator CLI: export a claim's provenance graph as PROV-O JSON-LD.
//!
//! Wraps `epigraph_engine::export::prov::export_provenance_prov_o`, which
//! walks claim-to-claim ancestry via `LineageRepository` and maps internal
//! `edges.relationship` values (`derived_from`, `supersedes`, ...) onto
//! `http://www.w3.org/ns/prov#` predicates **at serialization time only** —
//! this binary never writes to the database.
//!
//! Usage:
//!     epigraph-export-provenance --claim-id <uuid> --format prov-o
//!     epigraph-export-provenance --claim-id <uuid> --max-depth 10 --output /tmp/prov.json
//!
//! `--format` currently only accepts `prov-o`. RO-Crate (an
//! `ro-crate-metadata.json` manifest) was considered and rejected for this
//! first pass — this schema's provenance shape is claims/edges/agents, not
//! packaged research-object files, so PROV-O is the more natural fit. See
//! `crates/epigraph-engine/src/export/prov.rs` module docs for the full
//! reasoning; RO-Crate support (if a file-artifact use case emerges) is a
//! documented follow-up, not implemented here.

use clap::Parser;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(
    name = "export_provenance",
    about = "Export a claim's provenance graph as PROV-O JSON-LD (read-only)"
)]
struct Cli {
    /// Root claim to export provenance for.
    #[arg(long)]
    claim_id: Uuid,

    /// Output vocabulary. Only `prov-o` is implemented today.
    #[arg(long, default_value = "prov-o")]
    format: String,

    /// Maximum ancestor traversal depth (defaults to the repository default
    /// of 100 when omitted).
    #[arg(long)]
    max_depth: Option<i32>,

    /// Write the JSON-LD document to this file instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    if cli.format != "prov-o" {
        return Err(format!(
            "unsupported --format '{}': only 'prov-o' is implemented",
            cli.format
        )
        .into());
    }

    let pool = epigraph_cli::db_connect().await?;
    let document =
        epigraph_engine::export::prov::export_provenance_prov_o(&pool, cli.claim_id, cli.max_depth)
            .await?;
    let pretty = serde_json::to_string_pretty(&document)?;

    match cli.output {
        Some(path) => {
            std::fs::write(&path, &pretty)?;
            eprintln!("wrote PROV-O export to {}", path.display());
        }
        None => println!("{pretty}"),
    }

    Ok(())
}
