//! Operator CLI for the canonical hierarchical `ingest_document` pipeline.
//!
//! This is intentionally a thin wrapper around
//! `epigraph_mcp::tools::ingestion::do_ingest_document`: it gives operators a
//! per-invocation database target without forking the ingestion logic away from
//! the MCP tool.

use std::path::PathBuf;

use anyhow::{anyhow, Context};
use clap::Parser;
use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::tools::ingestion::do_ingest_document;
use epigraph_mcp::EpiGraphMcpFull;

#[derive(Parser, Debug)]
#[command(
    name = "ingest-document",
    about = "Ingest a DocumentExtraction JSON into a target EpiGraph database"
)]
struct Cli {
    /// PostgreSQL connection URL for the target graph.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Path to a hierarchical DocumentExtraction JSON file.
    #[arg(long)]
    file: PathBuf,

    /// Ed25519 secret key as 64 hex chars. If omitted, uses a deterministic
    /// document-ingest-cli signer so repeated operator runs share attribution.
    #[arg(long)]
    agent_key: Option<String>,

    /// OpenAI API key for embedding generation. If omitted, embeddings use the
    /// MCP embedder's mock/no-provider behavior.
    #[arg(long, env = "OPENAI_API_KEY", hide_env_values = true)]
    openai_api_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "epigraph_cli=info,epigraph_mcp=info".parse().unwrap()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    run(cli).await
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let data = tokio::fs::read_to_string(&cli.file)
        .await
        .with_context(|| format!("cannot read {}", cli.file.display()))?;
    let extraction: DocumentExtraction =
        serde_json::from_str(&data).context("invalid DocumentExtraction JSON")?;

    let pool = epigraph_db::create_pool(&cli.database_url)
        .await
        .context("connect target database")?;
    let signer = signer_from_cli(cli.agent_key.as_deref())?;
    let embedder = McpEmbedder::new(pool.clone(), cli.openai_api_key);
    let server = EpiGraphMcpFull::new(pool, signer, embedder, false);

    let result = do_ingest_document(&server, &extraction)
        .await
        .map_err(|e| anyhow!("ingest_document failed: {}", e.message))?;
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .ok_or_else(|| anyhow!("ingest_document returned no text content"))?;

    println!("{text}");
    Ok(())
}

fn signer_from_cli(agent_key: Option<&str>) -> anyhow::Result<AgentSigner> {
    if let Some(key_hex) = agent_key {
        let bytes = (0..key_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&key_hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .context("invalid --agent-key hex")?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("--agent-key must be exactly 32 bytes / 64 hex chars"))?;
        return AgentSigner::from_bytes(&key).context("invalid --agent-key");
    }

    Ok(epigraph_crypto::did_key::keypair_from_name(
        "document-ingest-cli",
    ))
}
