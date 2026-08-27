//! Operator CLI: export a claim's provenance graph as PROV-O JSON-LD, anchored
//! by a signed Merkle manifest.
//!
//! Wraps `epigraph_engine::export::prov::export_provenance_prov_o`, which
//! walks claim-to-claim ancestry via `LineageRepository` and maps internal
//! `edges.relationship` values (`derived_from`, `supersedes`, ...) onto
//! `http://www.w3.org/ns/prov#` predicates **at serialization time only**.
//!
//! # This binary WRITES to the database
//!
//! It did not, until manifests landed (backlog 6e2364b8). Every run now anchors
//! a signed commitment over exactly the claim ids and edge ids it emitted —
//! one `manifests` row plus one `manifest_entries` row per committed row — and
//! splices the self-verifying bundle into the document under `manifest`. There
//! is deliberately no `--no-manifest` escape hatch: an export whose recipient
//! must simply trust that nothing was dropped is the failure this feature
//! exists to remove. Scripting this binary in a loop grows the manifest tables.
//!
//! # Signing identity
//!
//! With no configuration at all the exporter signs as
//! `keypair_from_service("epigraph-export-provenance")` — a deterministic key
//! in the `service:` namespace — and resolves (or creates) the matching
//! `agents` row exactly the way the MCP server does on boot. So the first run
//! in a fresh environment adds one `agents` row, and every run thereafter, on
//! any host, lands on that same row. Pass `--agent-key` (or set
//! `EPIGRAPH_AGENT_KEY`) to sign as a specific identity instead.
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
use epigraph_crypto::{keypair_from_service, AgentSigner, ContentHasher};
use epigraph_db::{AgentRepository, PgPool};
use std::path::PathBuf;
use uuid::Uuid;

/// Service identity used when no `--agent-key` is supplied. Stable across
/// hosts and processes, so every unconfigured run signs as the same agent.
const SERVICE_ID: &str = "epigraph-export-provenance";

#[derive(Parser, Debug)]
#[command(
    name = "export_provenance",
    about = "Export a claim's provenance graph as PROV-O JSON-LD, anchored by a signed manifest"
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

    /// Ed25519 secret key as 64 lowercase hex chars, used to sign the manifest.
    /// Defaults to the deterministic `service:epigraph-export-provenance` key.
    #[arg(long, env = "EPIGRAPH_AGENT_KEY")]
    agent_key: Option<String>,
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

/// Build the signer: an explicit key if one was supplied, else the service key.
fn resolve_signer(agent_key: Option<&str>) -> Result<AgentSigner, Box<dyn std::error::Error>> {
    let Some(hex) = agent_key.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(keypair_from_service(SERVICE_ID));
    };
    let bytes = ContentHasher::from_hex(hex).map_err(|e| {
        format!("--agent-key must be 64 lowercase hex chars (32-byte Ed25519 secret key): {e}")
    })?;
    Ok(AgentSigner::from_bytes(&bytes)?)
}

/// Resolve (or create) the `agents` row for this signer's public key.
///
/// Identical to `EpiGraphMcpFull::agent_id()`'s find-or-create: the identity is
/// the public key, so a repeat run reuses the row rather than accumulating one
/// per invocation.
async fn resolve_agent_id(
    pool: &PgPool,
    signer: &AgentSigner,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let public_key = signer.public_key();
    if let Some(existing) = AgentRepository::get_by_public_key(pool, &public_key).await? {
        return Ok(existing.id.as_uuid());
    }
    let agent = epigraph_core::Agent::new(public_key, Some(SERVICE_ID.to_string()));
    let created = AgentRepository::create(pool, &agent).await?;
    Ok(created.id.as_uuid())
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
    let signer = resolve_signer(cli.agent_key.as_deref())?;
    let signer_agent_id = resolve_agent_id(&pool, &signer).await?;

    let export = epigraph_engine::export::prov::export_provenance_prov_o(
        &pool,
        cli.claim_id,
        cli.max_depth,
        &signer,
        signer_agent_id,
    )
    .await?;
    let pretty = serde_json::to_string_pretty(&export.document)?;

    // To stderr, so `--output`-less runs can still be piped into a JSON tool.
    eprintln!(
        "anchored manifest {} over {} claims + {} edges; root {}",
        export.document["manifest"]["manifest_id"]
            .as_str()
            .unwrap_or("<unknown>"),
        export.claim_ids.len(),
        export.edge_ids.len(),
        export.document["manifest"]["root"]
            .as_str()
            .unwrap_or("<unknown>"),
    );

    match cli.output {
        Some(path) => {
            std::fs::write(&path, &pretty)?;
            eprintln!("wrote PROV-O export to {}", path.display());
        }
        None => println!("{pretty}"),
    }

    Ok(())
}
