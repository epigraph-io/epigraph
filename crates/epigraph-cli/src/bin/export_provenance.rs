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

    // CLI maintenance bin: the operator is the authority and the work is
    // corpus-wide. See `epigraph_cli::MaintenancePool` for why that earns a
    // bypass and a request handler does not.
    //
    // Built AFTER clap has parsed: an argv error must be reported as an argv
    // error, not as a connection failure. And `_maint_conn` is held for the
    // whole run — the lease attests to THAT connection, and the pre-PR-15
    // template dropped it while the viewer lived on.
    let maint = epigraph_cli::MaintenancePool::connect("export_provenance")
        .await
        .expect("maintenance pool");
    let (_maint_conn, viewer) = maint
        .viewer(epigraph_db::visibility::SystemReason::SchemaContractTest)
        .await
        .expect("maintenance viewer");
    if let Err(e) = run(cli, maint.pool().clone(), &viewer).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run(
    cli: Cli,
    pool: sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<(), Box<dyn std::error::Error>> {
    if cli.format != "prov-o" {
        return Err(format!(
            "unsupported --format '{}': only 'prov-o' is implemented",
            cli.format
        )
        .into());
    }

    let document = epigraph_engine::export::prov::export_provenance_prov_o(
        &pool,
        viewer,
        cli.claim_id,
        cli.max_depth,
    )
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
