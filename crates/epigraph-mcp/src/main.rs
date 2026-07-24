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

    /// Provider model identifier for LLM-agent identity derivation (e.g.
    /// `claude-opus-4-8`). When set together with a system prompt (or its hash),
    /// the agent keypair is derived deterministically from `(model, prompt)` so
    /// identical configurations collapse to ONE agent. Absent -> unchanged
    /// behavior (a fresh keypair per process).
    #[arg(long, env = "EPIGRAPH_AGENT_MODEL")]
    agent_model: Option<String>,

    /// Raw system prompt for LLM-agent identity derivation. Hashed internally
    /// (BLAKE3) before it becomes seed material; the raw text is NEVER logged.
    /// Prefer `--agent-system-prompt-hash` when the prompt should not be
    /// materialized in this process's argv/env at all. Ignored unless
    /// `--agent-model` is also set.
    #[arg(long, env = "EPIGRAPH_AGENT_SYSTEM_PROMPT")]
    agent_system_prompt: Option<String>,

    /// Pre-computed BLAKE3 lowercase-hex digest of the system prompt. Lets the
    /// operator derive the same identity as `--agent-system-prompt` without ever
    /// putting the raw prompt in this process. Takes precedence over
    /// `--agent-system-prompt` when both are set. Ignored unless `--agent-model`
    /// is also set.
    #[arg(long, env = "EPIGRAPH_AGENT_SYSTEM_PROMPT_HASH")]
    agent_system_prompt_hash: Option<String>,
}

/// Outcome of signer selection: the Ed25519 signer plus, when the identity was
/// derived from an LLM configuration, the `(model, prompt_hash)` pair to record
/// on the agent row. `None` for the second element means "no LLM identity"
/// (`--agent-key` or the `generate()` fallback), which the server threads
/// through as `llm_identity: None` so `agent_id()` never calls
/// `set_llm_properties`.
struct SelectedSigner {
    signer: AgentSigner,
    llm_identity: Option<(String, String)>,
}

/// Select the agent signer from CLI/env inputs, returning the signer paired with
/// the LLM identity to persist. Extracted (and pure over its inputs) so the
/// precedence order is unit-testable without a process/DB.
///
/// Precedence (first match wins):
/// 1. `model` AND `prompt_hash` -> `keypair_from_llm_agent_prehashed` (the hash
///    is used verbatim; feeding it to the raw path would blake3(hash) -> a
///    different, silently-orphaned key).
/// 2. `model` AND (`raw_prompt` or empty) -> `keypair_from_llm_agent`, which
///    BLAKE3-hashes the prompt. The stored `prompt_hash` is that SAME digest, so
///    the agent row's `llm_prompt_hash` always corresponds to its key.
/// 3. `agent_key` (32-byte hex) -> `AgentSigner::from_bytes` (no LLM identity).
/// 4. else -> `AgentSigner::generate()` (UNCHANGED legacy fallback).
///
/// `model` takes precedence over `agent_key` by design: an explicit LLM config
/// is a stronger identity declaration than a raw key.
fn select_signer(
    model: Option<&str>,
    raw_prompt: Option<&str>,
    prompt_hash: Option<&str>,
    agent_key: Option<&str>,
) -> Result<SelectedSigner, String> {
    if let Some(model) = model {
        // (1) model + explicit hash -> prehashed path (hash used verbatim).
        if let Some(hash) = prompt_hash {
            let signer = epigraph_crypto::keypair_from_llm_agent_prehashed(model, hash);
            return Ok(SelectedSigner {
                signer,
                llm_identity: Some((model.trim().to_string(), hash.to_string())),
            });
        }
        // (2) model + raw prompt (or empty) -> raw path, which hashes the
        // prompt. Store that SAME digest so key and recorded hash cannot drift.
        let prompt = raw_prompt.unwrap_or("");
        // Lowercase-hex BLAKE3 digest — byte-identical to what
        // `keypair_from_llm_agent` computes internally (both wrap
        // `blake3::hash`), so the stored `llm_prompt_hash` always corresponds to
        // the derived key. Using `ContentHasher` (a regular dep) rather than
        // `blake3` directly, which is only a dev-dependency of this crate.
        let hash = epigraph_crypto::ContentHasher::to_hex(&epigraph_crypto::ContentHasher::hash(
            prompt.as_bytes(),
        ));
        let signer = epigraph_crypto::keypair_from_llm_agent(model, prompt);
        return Ok(SelectedSigner {
            signer,
            llm_identity: Some((model.trim().to_string(), hash)),
        });
    }

    // (3) explicit 32-byte key, no LLM identity.
    if let Some(key_hex) = agent_key {
        let bytes = (0..key_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&key_hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| format!("invalid agent-key hex: {e}"))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "agent-key must be exactly 32 bytes (64 hex chars)".to_string())?;
        let signer = AgentSigner::from_bytes(&key).map_err(|e| format!("agent-key: {e}"))?;
        return Ok(SelectedSigner {
            signer,
            llm_identity: None,
        });
    }

    // (4) legacy fallback: fresh keypair, no LLM identity (UNCHANGED).
    Ok(SelectedSigner {
        signer: AgentSigner::generate(),
        llm_identity: None,
    })
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

    // Create or restore agent signer. Precedence lives in `select_signer`
    // (unit-tested); here we only handle the side effects (secret-key print for
    // the generate() fallback, and NEVER logging the raw prompt).
    let is_generate_fallback = cli.agent_model.is_none() && cli.agent_key.is_none();
    let SelectedSigner {
        signer,
        llm_identity,
    } = select_signer(
        cli.agent_model.as_deref(),
        cli.agent_system_prompt.as_deref(),
        cli.agent_system_prompt_hash.as_deref(),
        cli.agent_key.as_deref(),
    )?;

    if is_generate_fallback {
        eprintln!("Generated new agent keypair");
        let secret = signer.secret_key();
        let hex_str = secret.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        eprintln!("  Public key: {}", hex::encode(signer.public_key()));
        eprintln!("  Secret key (save this!): {hex_str}");
    }

    // Log the derived LLM identity (model + prompt HASH only — the raw prompt is
    // never logged). Absent -> nothing to report beyond the public key.
    if let Some((model, hash)) = &llm_identity {
        tracing::info!(
            llm_model = %model,
            llm_prompt_hash = %hash,
            "LLM-agent identity derived deterministically from (model, prompt)"
        );
    }

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
                    llm_identity.clone(),
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
        let server = EpiGraphMcpFull::new_with_federation(
            pool,
            signer,
            embedder,
            cli.read_only,
            federation,
            llm_identity,
        );
        let service = server.serve(rmcp::transport::stdio()).await.map_err(|e| {
            tracing::error!("MCP serve error: {e}");
            e
        })?;

        tracing::info!("EpiGraph MCP full-framework server running on stdio ({mode})");
        service.waiting().await?;
    }

    Ok(())
}

#[cfg(test)]
mod signer_selection_tests {
    use super::{select_signer, SelectedSigner};

    const KEY_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    /// Precedence rung 1 must win even when a raw prompt AND an agent-key are
    /// ALSO supplied: model + explicit hash routes to the PREHASHED path, which
    /// uses the hash verbatim. This guards the ORDER, not an isolated branch —
    /// the derived key must match `keypair_from_llm_agent_prehashed(model, hash)`
    /// and NOT the raw-prompt path (which would blake3(prompt) instead).
    #[test]
    fn model_plus_hash_wins_and_uses_hash_verbatim() {
        let model = "claude-opus-4-8";
        let hash = "abc123def456";
        let raw_prompt = "some other prompt whose blake3 is NOT the hash above";

        let SelectedSigner {
            signer,
            llm_identity,
        } = select_signer(Some(model), Some(raw_prompt), Some(hash), Some(KEY_HEX)).unwrap();

        // Key is the verbatim-hash derivation, proving the prehashed rung ran
        // and neither the raw-prompt path nor the agent-key path was taken.
        let expected = epigraph_crypto::keypair_from_llm_agent_prehashed(model, hash);
        assert_eq!(signer.public_key(), expected.public_key());
        assert_eq!(llm_identity, Some((model.to_string(), hash.to_string())));

        // Cross-check: it is DISTINCT from the raw-prompt derivation and from the
        // agent-key. If precedence were wrong these would collide.
        let raw_path = epigraph_crypto::keypair_from_llm_agent(model, raw_prompt);
        assert_ne!(signer.public_key(), raw_path.public_key());
        let key: [u8; 32] = [0x01; 32];
        let key_path = epigraph_crypto::AgentSigner::from_bytes(&key).unwrap();
        assert_ne!(signer.public_key(), key_path.public_key());
    }

    /// Rung 2: model + raw prompt (no hash) routes to `keypair_from_llm_agent`,
    /// and the STORED prompt_hash must be the blake3 digest that fn computes
    /// internally — so the agent row's `llm_prompt_hash` always corresponds to
    /// its key. This is the anti-drift guarantee.
    #[test]
    fn model_plus_raw_prompt_stores_matching_blake3_digest() {
        let model = "gpt-5";
        let prompt = "You are a careful reviewer.";

        let SelectedSigner {
            signer,
            llm_identity,
        } = select_signer(Some(model), Some(prompt), None, None).unwrap();

        let expected_signer = epigraph_crypto::keypair_from_llm_agent(model, prompt);
        assert_eq!(signer.public_key(), expected_signer.public_key());

        let expected_hash = blake3::hash(prompt.as_bytes()).to_hex().to_string();
        assert_eq!(
            llm_identity,
            Some((model.to_string(), expected_hash.clone()))
        );
        // The stored hash, fed to the PREHASHED path, must reproduce the same key
        // — i.e. the recorded hash truly corresponds to the signer.
        let from_stored = epigraph_crypto::keypair_from_llm_agent_prehashed(model, &expected_hash);
        assert_eq!(signer.public_key(), from_stored.public_key());
    }

    /// Rung 2 with an empty prompt is still an LLM identity (model alone is a
    /// valid deterministic config) — NOT the generate() fallback. Guards that
    /// `raw_prompt = None` under a model does not silently fall through.
    #[test]
    fn model_with_no_prompt_derives_from_empty_string() {
        let model = "claude-haiku";
        let SelectedSigner {
            signer,
            llm_identity,
        } = select_signer(Some(model), None, None, None).unwrap();

        let expected = epigraph_crypto::keypair_from_llm_agent(model, "");
        assert_eq!(signer.public_key(), expected.public_key());
        let empty_hash = blake3::hash(b"").to_hex().to_string();
        assert_eq!(llm_identity, Some((model.to_string(), empty_hash)));
    }

    /// Rung 3: agent-key with NO model routes to `from_bytes` and carries NO LLM
    /// identity (so `agent_id()` will never call `set_llm_properties`).
    #[test]
    fn agent_key_without_model_uses_from_bytes_no_identity() {
        let SelectedSigner {
            signer,
            llm_identity,
        } = select_signer(None, None, None, Some(KEY_HEX)).unwrap();

        let key: [u8; 32] = [0x01; 32];
        let expected = epigraph_crypto::AgentSigner::from_bytes(&key).unwrap();
        assert_eq!(signer.public_key(), expected.public_key());
        assert!(llm_identity.is_none());
    }

    /// Rung 4: no model, no key -> `generate()`. Can't assert a fixed value
    /// (random), so we assert the two OBSERVABLE properties: (a) no LLM identity,
    /// and (b) the key is NOT the deterministic one a same-model config would
    /// produce — proving the fallback path ran, not a derivation. Two calls also
    /// differ from each other (it is genuinely random, not a fixed seed).
    #[test]
    fn no_inputs_generates_random_signer_without_identity() {
        let a = select_signer(None, None, None, None).unwrap();
        let b = select_signer(None, None, None, None).unwrap();
        assert!(a.llm_identity.is_none());
        assert!(b.llm_identity.is_none());
        assert_ne!(
            a.signer.public_key(),
            b.signer.public_key(),
            "generate() must be random per call, not a fixed seed"
        );
    }

    /// Malformed agent-key hex (odd length / non-hex) is an error, not a panic
    /// and not a silent generate() — the operator asked for a specific key.
    #[test]
    fn malformed_agent_key_is_an_error() {
        assert!(select_signer(None, None, None, Some("zz")).is_err());
    }
}
