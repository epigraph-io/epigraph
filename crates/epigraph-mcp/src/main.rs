#![allow(clippy::doc_markdown)]

//! EpiGraph Full-Framework MCP Server — exposes all workspace crates as MCP tools.
//!
//! Connects to the EpiGraph PostgreSQL backend and provides 40 MCP tools including
//! full CDST support (6 combination methods), scoped beliefs, and DS-vs-Bayesian divergence.
//!
//! ## Usage
//!
//! ```bash
//! # Stdio transport (default — for Claude Code / .mcp.json integration)
//! epigraph-mcp-full --database-url postgres://user:pass@host/db
//!
//! # HTTP transport (for curl / remote agents)
//! epigraph-mcp-full --database-url postgres://user:pass@host/db --listen 127.0.0.1:8080
//! ```

use std::fmt::Write;
use std::sync::Arc;

use clap::Parser;
use rmcp::ServiceExt;

use epigraph_crypto::AgentSigner;
use epigraph_db::create_pool;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::EpiGraphMcpFull;

#[derive(Parser)]
#[command(
    name = "epigraph-mcp-full",
    about = "EpiGraph full-framework MCP server — 27 epistemic tools"
)]
struct Cli {
    /// PostgreSQL connection URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// Ed25519 secret key (64 hex chars). If omitted, generates a new keypair.
    #[arg(long)]
    agent_key: Option<String>,

    /// OpenAI API key for embedding generation. If omitted, uses mock embeddings.
    #[arg(long, env = "OPENAI_API_KEY")]
    openai_api_key: Option<String>,

    /// Listen on HTTP address (e.g., 127.0.0.1:8080). If omitted, uses stdio transport.
    #[arg(long)]
    listen: Option<String>,

    /// Start in read-only mode (query tools only, write operations return errors)
    #[arg(long)]
    read_only: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Logging to stderr (stdout reserved for MCP JSON-RPC in stdio mode)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "epigraph_mcp=info".parse().unwrap()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // Connect to database
    tracing::info!("Connecting to database...");
    let pool = create_pool(&cli.database_url).await?;
    tracing::info!("Database connected");

    // Create or restore agent signer
    let signer = if let Some(key_hex) = &cli.agent_key {
        let bytes = (0..key_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&key_hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| format!("invalid agent-key hex: {e}"))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "agent-key must be exactly 32 bytes (64 hex chars)")?;
        AgentSigner::from_bytes(&key)?
    } else {
        let signer = AgentSigner::generate();
        eprintln!("Generated new agent keypair");
        let secret = signer.secret_key();
        let hex_str = secret.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        eprintln!("  Public key: {}", hex::encode(signer.public_key()));
        eprintln!("  Secret key (save this!): {hex_str}");
        signer
    };

    tracing::info!(public_key = %hex::encode(signer.public_key()), "Agent identity ready");

    // Create embedder
    let embedder = McpEmbedder::new(pool.clone(), cli.openai_api_key);

    let mode = if cli.read_only {
        "read-only (23 tools)"
    } else {
        "full (40 tools)"
    };
    tracing::info!("EpiGraph MCP server running in {mode} mode");

    if let Some(addr) = &cli.listen {
        // ── HTTP transport ──────────────────────────────────────────────
        use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
        use rmcp::transport::streamable_http_server::{
            StreamableHttpServerConfig, StreamableHttpService,
        };

        let signer = Arc::new(signer);
        let embedder = Arc::new(embedder);
        let read_only = cli.read_only;

        let service = StreamableHttpService::new(
            move || {
                Ok(EpiGraphMcpFull::new_shared(
                    pool.clone(),
                    signer.clone(),
                    embedder.clone(),
                    read_only,
                ))
            },
            Arc::new(LocalSessionManager::default()),
            StreamableHttpServerConfig::default(),
        );

        let router = axum::Router::new().nest_service("/mcp", service);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("EpiGraph MCP server listening on http://{addr}/mcp ({mode})");
        axum::serve(listener, router).await?;
    } else {
        // ── Stdio transport (default) ───────────────────────────────────
        let server = EpiGraphMcpFull::new(pool, signer, embedder, cli.read_only);
        let service = server.serve(rmcp::transport::stdio()).await.map_err(|e| {
            tracing::error!("MCP serve error: {e}");
            e
        })?;

        tracing::info!("EpiGraph MCP full-framework server running on stdio ({mode})");
        service.waiting().await?;
    }

    Ok(())
}
