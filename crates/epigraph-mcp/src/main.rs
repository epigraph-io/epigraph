#![allow(clippy::doc_markdown)]

//! EpiGraph Full-Framework MCP Server — exposes all workspace crates as MCP tools.
//!
//! Connects to the EpiGraph PostgreSQL backend and provides 58 MCP tools including
//! full CDST support (6 combination methods), scoped beliefs, and DS-vs-Bayesian divergence.
//!
//! ## Usage
//!
//! ```bash
//! # Stdio transport (default — for Claude Code / .mcp.json integration)
//! epigraph-mcp-full --database-url postgres://user:pass@host/db
//!
//! # HTTP transport with Bearer auth (production)
//! epigraph-mcp-full --database-url postgres://... --listen 127.0.0.1:8080 \
//!   --jwt-secret "<HMAC secret matching epigraph-api's JWT_SECRET>"
//!
//! # Unauthenticated HTTP (unix socket behind filesystem perms, or local dev)
//! epigraph-mcp-full --database-url postgres://... --listen unix:/run/mcp.sock \
//!   --allow-unauthenticated-http
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
    about = "EpiGraph full-framework MCP server — 58 epistemic tools"
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

    /// Listen on HTTP. Accepts either `host:port` (TCP) or `unix:/abs/path` (Unix socket).
    /// Unix sockets close the localhost-bypass surface: only processes with filesystem
    /// access can connect. If omitted, uses stdio transport.
    ///
    /// Requires either `--jwt-secret` (Bearer auth, recommended for production) or
    /// `--allow-unauthenticated-http` (for unix-socket listeners behind filesystem
    /// permissions, or local dev).
    #[arg(long)]
    listen: Option<String>,

    /// HMAC-SHA256 secret used to validate Bearer tokens on the HTTP transport.
    ///
    /// Required when `--listen` is used unless `--allow-unauthenticated-http` is
    /// set. Must be at least 32 bytes. The same secret signs and verifies tokens
    /// across both `epigraph-api` and `epigraph-mcp` — when rotating, restart
    /// both processes with the new value.
    #[arg(long, env = "EPIGRAPH_JWT_SECRET")]
    jwt_secret: Option<String>,

    /// Acknowledge that HTTP transport exposes all MCP tools without authentication.
    ///
    /// One of two accepted modes when `--listen` is used. Use this for unix-socket
    /// listeners behind filesystem permissions, or for local dev. For network-exposed
    /// HTTP, use `--jwt-secret` instead. Mutually exclusive with `--jwt-secret`.
    ///
    /// See: https://github.com/epigraph-io/epigraph/issues/122
    #[arg(long)]
    allow_unauthenticated_http: bool,

    /// Start in read-only mode (query tools only, write operations return errors)
    #[arg(long)]
    read_only: bool,

    /// Absolute URL of the protected-resource metadata document, advertised in 401
    /// WWW-Authenticate challenges so MCP clients can discover the auth server.
    #[arg(long, env = "EPIGRAPH_RESOURCE_METADATA_URL")]
    resource_metadata_url: Option<String>,
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

    // Safety gate for the HTTP transport. The stdio process boundary is the
    // default trust gate; HTTP removes it. To start with --listen, the operator
    // must either supply a JWT secret (Bearer auth) or explicitly opt out of
    // auth (e.g., a unix-socket listener behind filesystem permissions).
    if cli.listen.is_some() {
        match (cli.jwt_secret.as_deref(), cli.allow_unauthenticated_http) {
            (Some(secret), false) => {
                if let Err(reason) = epigraph_auth::assert_production_secret(secret.as_bytes()) {
                    eprintln!("ERROR: --jwt-secret rejected: {reason}");
                    std::process::exit(1);
                }
                // authenticated path
            }
            (None, true) => {} // operator-acknowledged unauthenticated path
            (Some(_), true) => {
                eprintln!(
                    "ERROR: --jwt-secret and --allow-unauthenticated-http are mutually exclusive."
                );
                std::process::exit(1);
            }
            (None, false) => {
                eprintln!(
                    "ERROR: --listen requires either --jwt-secret <SECRET> (Bearer auth) or\n\
                     --allow-unauthenticated-http (e.g., for a unix-socket listener behind\n\
                     filesystem permissions). See https://github.com/epigraph-io/epigraph/issues/122."
                );
                std::process::exit(1);
            }
        }
    }

    // Fail fast on a malformed --resource-metadata-url. The value is interpolated
    // into the 401 WWW-Authenticate challenge (an HTTP header), which rejects
    // control chars / non-ASCII. Validating here surfaces an operator typo at boot
    // instead of letting it fail to attach the header on every 401.
    if let Some(url) = cli.resource_metadata_url.as_deref() {
        if let Err(reason) = epigraph_mcp::auth::validate_resource_metadata_url(url) {
            eprintln!("ERROR: {reason}");
            std::process::exit(1);
        }
    }

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

    // ── Federation gateway ──────────────────────────────────────────────
    // Parse EPIGRAPH_MCP_EXTENSIONS and mount each downstream extension MCP.
    // Built ONCE here and cloned (via the Arc) into every per-session server on
    // both transport paths, so the discovery-cached tool list is shared. Absent
    // env -> empty registry -> the gateway behaves exactly as pre-federation.
    // A malformed EPIGRAPH_MCP_EXTENSIONS is a hard boot error (fail fast rather
    // than silently drop an extension); a tool-name COLLISION between two
    // extensions is likewise fatal (ambiguous routing). An individual extension
    // being unreachable at startup is NOT fatal — it is logged and mounted
    // unhealthy inside `build`.
    let ext_env = std::env::var("EPIGRAPH_MCP_EXTENSIONS").ok();
    let ext_configs = epigraph_mcp::federation::config::parse_extensions(ext_env.as_deref())
        .map_err(|e| format!("EPIGRAPH_MCP_EXTENSIONS: {e}"))?;
    // Discovery uses a gateway SERVICE token (never a caller token): the
    // persistent discovery session is authenticated with it to drive
    // list_all_tools. Per-call INVOCATION uses the caller's raw bearer instead.
    let discovery_token = std::env::var("EPIGRAPH_MCP_DISCOVERY_TOKEN")
        .or_else(|_| std::env::var("EPIGRAPH_SERVICE_TOKEN"))
        .unwrap_or_default();
    if !ext_configs.is_empty() && discovery_token.is_empty() {
        tracing::warn!(
            "EPIGRAPH_MCP_EXTENSIONS is set but no EPIGRAPH_MCP_DISCOVERY_TOKEN / \
             EPIGRAPH_SERVICE_TOKEN — federated discovery will send an empty bearer \
             and likely fail; extensions will mount unhealthy"
        );
    }
    let federation = Arc::new(
        epigraph_mcp::federation::FederationRegistry::build(ext_configs, &discovery_token)
            .await
            .map_err(|e| format!("federation gateway build failed: {e}"))?,
    );
    let federated_tool_count = federation.list_federated_tools().len();
    if federation.is_empty() {
        tracing::info!(
            "Federation gateway: no extensions configured (EPIGRAPH_MCP_EXTENSIONS unset)"
        );
    } else {
        tracing::info!(
            federated_tools = federated_tool_count,
            "Federation gateway: mounted {} federated tool(s) across configured extension(s)",
            federated_tool_count
        );
    }

    let tool_count = EpiGraphMcpFull::all_tools_json()
        .as_array()
        .map_or(0, Vec::len);
    let mode = if cli.read_only { "read-only" } else { "full" };
    tracing::info!(
        "EpiGraph MCP server running in {mode} ({tool_count} kernel + {federated_tool_count} federated tools) mode"
    );

    if let Some(addr) = &cli.listen {
        // ── HTTP transport (TCP or Unix socket) ────────────────────────
        // (auth gate already enforced above at startup; --allow-unauthenticated-http was checked)
        use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
        use rmcp::transport::streamable_http_server::{
            StreamableHttpServerConfig, StreamableHttpService,
        };

        let signer = Arc::new(signer);
        let embedder = Arc::new(embedder);
        let read_only = cli.read_only;
        let federation = federation.clone();

        let service = StreamableHttpService::new(
            move || {
                Ok(EpiGraphMcpFull::new_shared_with_federation(
                    pool.clone(),
                    signer.clone(),
                    embedder.clone(),
                    read_only,
                    federation.clone(),
                ))
            },
            Arc::new(LocalSessionManager::default()),
            StreamableHttpServerConfig::default(),
        );

        let router = axum::Router::new().nest_service("/mcp", service);

        let router = if let Some(secret) = cli.jwt_secret.as_deref() {
            use epigraph_auth::JwtConfig;
            use epigraph_mcp::auth::{bearer_auth_middleware, McpAuthState};

            let state = McpAuthState {
                jwt_config: Arc::new(JwtConfig::from_secret(secret.as_bytes())),
                resource_metadata_url: cli.resource_metadata_url.clone(),
            };
            router.layer(axum::middleware::from_fn_with_state(
                state,
                bearer_auth_middleware,
            ))
        } else if cli.allow_unauthenticated_http {
            // Operator opted out of Bearer auth (e.g. unix-socket listener
            // behind filesystem perms). Inject a permissive AuthContext so the
            // per-tool scope gate passes — without it every tool 403s on a
            // missing auth context, making the flag misleading (bug be2a3391).
            router.layer(axum::middleware::from_fn(
                epigraph_mcp::auth::inject_unauthenticated_context,
            ))
        } else {
            router
        };

        tracing::info!("Starting EpiGraph MCP server in {mode} mode on {addr}");
        epigraph_mcp::serve_with_listener(addr, router).await?;
    } else {
        // ── Stdio transport (default) ───────────────────────────────────
        // Inject the same federation registry so stdio's `list_tools` surfaces
        // federated tools too (discovery ran at build time with the service
        // token, independent of transport). Note: over stdio there is no caller
        // Bearer, so a federated `tools/call` will fail closed in
        // `enforce_federated_scope` (no AuthContext) — listing works, invoking
        // does not, which is the intended v1 behavior.
        let server =
            EpiGraphMcpFull::new_with_federation(pool, signer, embedder, cli.read_only, federation);
        let service = server.serve(rmcp::transport::stdio()).await.map_err(|e| {
            tracing::error!("MCP serve error: {e}");
            e
        })?;

        tracing::info!("EpiGraph MCP full-framework server running on stdio ({mode})");
        service.waiting().await?;
    }

    Ok(())
}
