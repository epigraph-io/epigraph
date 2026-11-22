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
//!     epigraph-export-provenance --claim-id <uuid> --max-nodes 2000
//!     epigraph-export-provenance --claim-id <uuid> --unbounded
//!
//! # Bounded by default
//!
//! The export has no row cap of its own: every kept claim costs about two
//! statements in one read transaction (plus its content), so a hub claim's
//! whole lineage is thousands of statements. By default at most
//! `DEFAULT_MAX_NODES` (500) claims are kept, nearest-first, each with at most
//! `DEFAULT_MAX_CONTENT_CHARS` (4000) characters of content; the document's
//! `truncated` says when a bound cut it. `--unbounded` exports the whole
//! lineage, as this binary did before (backlog 4caad789).
//!
//! `--format` currently only accepts `prov-o`. RO-Crate (an
//! `ro-crate-metadata.json` manifest) was considered and rejected for this
//! first pass — this schema's provenance shape is claims/edges/agents, not
//! packaged research-object files, so PROV-O is the more natural fit. See
//! `crates/epigraph-engine/src/export/prov.rs` module docs for the full
//! reasoning; RO-Crate support (if a file-artifact use case emerges) is a
//! documented follow-up, not implemented here.

use clap::Parser;
use epigraph_engine::export::prov::ProvExportLimits;
use std::path::PathBuf;
use uuid::Uuid;

/// Default node cap: `MAX_CHAIN_NODES`, the
/// provenance-chain walk's own cap.
const DEFAULT_MAX_NODES: usize = 500;
/// Default per-claim content budget: the MCP tool's ceiling.
const DEFAULT_MAX_CONTENT_CHARS: usize = 4_000;

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

    /// Most claims kept as entities, nearest-first (default 500).
    #[arg(long, conflicts_with = "unbounded")]
    max_nodes: Option<usize>,

    /// Most characters of each entity's content (default 4000).
    #[arg(long, conflicts_with = "unbounded")]
    max_content_chars: Option<usize>,

    /// Export the whole lineage with no node cap and no content clip.
    #[arg(long)]
    unbounded: bool,

    /// Write the JSON-LD document to this file instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

/// The limits this run passes: finite unless `--unbounded`.
fn limits(cli: &Cli) -> ProvExportLimits {
    if cli.unbounded {
        return ProvExportLimits::default();
    }
    ProvExportLimits {
        max_nodes: Some(cli.max_nodes.unwrap_or(DEFAULT_MAX_NODES)),
        max_content_chars: Some(cli.max_content_chars.unwrap_or(DEFAULT_MAX_CONTENT_CHARS)),
    }
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
    let session = maint
        .viewer(epigraph_db::visibility::SystemReason::SchemaContractTest)
        .await
        .expect("maintenance viewer");
    let viewer = session.viewer();
    if let Err(e) = run(cli, maint.pool().clone(), viewer).await {
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

    let limits = limits(&cli);
    let mut conn = pool.acquire().await?;
    let document = epigraph_engine::export::prov::export_provenance_prov_o(
        &mut conn,
        viewer,
        cli.claim_id,
        cli.max_depth,
        limits,
    )
    .await?;
    if document["truncated"] == true {
        eprintln!(
            "the export is incomplete (truncated: max_nodes {:?}, depth_truncated {}); \
             raise --max-nodes / --max-depth or pass --unbounded",
            limits.max_nodes, document["depth_truncated"]
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        let mut argv = vec![
            "export_provenance",
            "--claim-id",
            "00000000-0000-0000-0000-000000000001",
        ];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv)
    }

    #[test]
    fn the_export_is_bounded_by_default() {
        let l = limits(&parse(&[]).expect("parse"));
        assert_eq!(
            (l.max_nodes, l.max_content_chars),
            (Some(DEFAULT_MAX_NODES), Some(DEFAULT_MAX_CONTENT_CHARS))
        );
    }

    #[test]
    fn explicit_limits_override_the_defaults() {
        let l = limits(&parse(&["--max-nodes", "7", "--max-content-chars", "90"]).expect("parse"));
        assert_eq!((l.max_nodes, l.max_content_chars), (Some(7), Some(90)));
    }

    #[test]
    fn unbounded_is_an_explicit_opt_in_and_excludes_limits() {
        let l = limits(&parse(&["--unbounded"]).expect("parse"));
        assert_eq!(l, ProvExportLimits::default());
        assert!(parse(&["--unbounded", "--max-nodes", "7"]).is_err());
        assert!(parse(&["--unbounded", "--max-content-chars", "90"]).is_err());
    }
}
