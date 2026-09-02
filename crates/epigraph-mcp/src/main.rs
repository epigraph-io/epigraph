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
//! # HTTP transport with Bearer auth (the only supported TCP mode)
//! epigraph-mcp-full --database-url postgres://... --listen 127.0.0.1:8080 \
//!   --jwt-secret "<HMAC secret matching epigraph-api's JWT_SECRET>" \
//!   --allowed-host mcp.example.com          # add the name a reverse proxy forwards
//!
//! # Unauthenticated HTTP — unix socket ONLY (behind filesystem perms).
//! # The same flag on a TCP --listen is refused at startup.
//! epigraph-mcp-full --database-url postgres://... --listen unix:/run/mcp.sock \
//!   --allow-unauthenticated-http
//! ```
//!
//! Every TCP listener enforces a `Host`/`Origin` allowlist (`localhost`,
//! `127.0.0.1`, `::1`, the `--listen` authority, plus `--allowed-host`) as the
//! DNS-rebinding defense rmcp 0.15 does not provide. A reverse-proxied
//! deployment MUST add the public name, since Caddy forwards the client's Host.

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
    /// A TCP address requires `--jwt-secret` (Bearer auth); a unix path may use
    /// either `--jwt-secret` or `--allow-unauthenticated-http`. TCP listeners also
    /// enforce a `Host`/`Origin` allowlist — see `--allowed-host`.
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
    /// Accepted ONLY for a unix-socket listener (`--listen unix:/abs/path`), whose
    /// filesystem permissions are the trust gate. Rejected for a TCP `--listen`
    /// address: a TCP listener is reachable by every local process AND by a browser
    /// whose DNS rebinds to it, so combining it with this flag exposes the full write
    /// surface with no credential. For a TCP listener use `--jwt-secret`.
    /// Mutually exclusive with `--jwt-secret`.
    ///
    /// See: https://github.com/epigraph-io/epigraph/issues/122
    #[arg(long)]
    allow_unauthenticated_http: bool,

    /// Additional `Host` / `Origin` authority to accept on the HTTP listener
    /// (repeatable; comma-separated in the env var).
    ///
    /// The listener rejects any request whose `Host` — or, when present, `Origin`
    /// — is outside its allowlist, which is the DNS-rebinding defense rmcp 0.15
    /// does not provide. The allowlist always contains `localhost`, `127.0.0.1`,
    /// `::1` and the `--listen` authority; a reverse-proxied deployment must add
    /// the public name the proxy forwards (e.g. `5-78-124-36.nip.io`), because
    /// Caddy's `reverse_proxy` preserves the client's original `Host`.
    /// Ports are ignored in the comparison.
    #[arg(
        long = "allowed-host",
        env = "EPIGRAPH_MCP_ALLOWED_HOSTS",
        value_delimiter = ','
    )]
    allowed_host: Vec<String>,

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
    /// `true` when the operator DECLARED this identity (`--agent-model` or
    /// `--agent-key`, rungs 1-3); `false` for the rung-4 `generate()` fallback.
    ///
    /// Distinct from `llm_identity.is_some()`, which is `None` for BOTH rung 3
    /// and rung 4. The distinction matters to
    /// `epigraph_mcp::tools::claims::require_owner_or_admin`: its no-`AuthContext`
    /// fallback compares a claim's author against this server's signer agent,
    /// which is only a policy when the identity is stable across process
    /// restarts. Under rung 4 the signer is a fresh random keypair per process,
    /// so that comparison can never match a pre-existing claim — see
    /// [`EpiGraphMcpFull::with_generated_signer_identity`].
    identity_declared: bool,
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
                identity_declared: true,
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
            identity_declared: true,
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
            identity_declared: true,
        });
    }

    // (4) legacy fallback: fresh keypair, no LLM identity (UNCHANGED).
    Ok(SelectedSigner {
        signer: AgentSigner::generate(),
        llm_identity: None,
        identity_declared: false,
    })
}

/// Validate the `(--listen, --jwt-secret, --allow-unauthenticated-http)`
/// combination, returning the operator-facing rejection reason on failure.
///
/// The stdio process boundary is the default trust gate; `--listen` removes it,
/// so serving requires either Bearer auth or an explicit, *narrowly scoped*
/// opt-out. The opt-out is scoped to unix sockets: that is the case its own
/// documentation cites ("behind filesystem permissions"), and it is the only
/// listener kind a browser cannot reach — so it is the only one where running
/// with no credential is not a remote-code-execution-by-rebinding surface.
///
/// Extracted (and pure over its inputs) so every arm is unit-testable without a
/// process or a database, mirroring `select_signer`. This is not merely stylistic:
/// `create_pool` connects EAGERLY, so a subprocess test of an *accepting* arm
/// would sail past the gate and then hang/fail on the DB, proving nothing about
/// the gate. `tests/jwt_secret_gate_test.rs` still covers the rejecting arms
/// end-to-end, which is what proves `main` actually calls this.
fn check_listen_auth_mode(
    listen: &str,
    jwt_secret: Option<&str>,
    allow_unauthenticated_http: bool,
) -> Result<(), String> {
    match (jwt_secret, allow_unauthenticated_http) {
        (Some(secret), false) => epigraph_auth::assert_production_secret(secret.as_bytes())
            .map_err(|reason| format!("--jwt-secret rejected: {reason}")),
        (None, true) => {
            if epigraph_mcp::is_unix_listener(listen) {
                Ok(())
            } else {
                Err(format!(
                    "--allow-unauthenticated-http is permitted only for a unix-socket listener\n\
                     (--listen unix:/abs/path), whose filesystem permissions are the trust gate.\n\
                     --listen {listen} is a TCP address: it is reachable by any local process and\n\
                     by a browser whose DNS rebinds to it, which would drive every write tool with\n\
                     no credential. Use --jwt-secret <SECRET>, or move the listener to a unix socket.\n\
                     See https://github.com/epigraph-io/epigraph/issues/122."
                ))
            }
        }
        (Some(_), true) => {
            Err("--jwt-secret and --allow-unauthenticated-http are mutually exclusive.".to_string())
        }
        (None, false) => Err(
            "--listen requires either --jwt-secret <SECRET> (Bearer auth) or\n\
             --allow-unauthenticated-http (unix-socket listeners only, behind filesystem\n\
             permissions). See https://github.com/epigraph-io/epigraph/issues/122."
                .to_string(),
        ),
    }
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

    // Safety gate for the HTTP transport (see `check_listen_auth_mode`). Runs
    // before the DB connect so a misconfiguration surfaces immediately rather
    // than after a connection timeout.
    if let Some(listen) = cli.listen.as_deref() {
        if let Err(reason) = check_listen_auth_mode(
            listen,
            cli.jwt_secret.as_deref(),
            cli.allow_unauthenticated_http,
        ) {
            eprintln!("ERROR: {reason}");
            std::process::exit(1);
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
    let SelectedSigner {
        signer,
        llm_identity,
        identity_declared,
    } = select_signer(
        cli.agent_model.as_deref(),
        cli.agent_system_prompt.as_deref(),
        cli.agent_system_prompt_hash.as_deref(),
        cli.agent_key.as_deref(),
    )?;
    // Read the rung off `select_signer`'s own return value rather than
    // re-deriving `agent_model.is_none() && agent_key.is_none()` here: the
    // precedence table is documented as living in one place, and a second copy
    // of the rung-4 predicate is free to drift from it.
    let is_generate_fallback = !identity_declared;

    if is_generate_fallback {
        eprintln!("Generated new agent keypair");
        let secret = signer.secret_key();
        let hex_str = secret.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        eprintln!("  Public key: {}", hex::encode(signer.public_key()));
        eprintln!("  Secret key (save this!): {hex_str}");
        // Surfaced at boot, not only at the first refused call: with a random
        // per-process signer the owner-equality fallback in
        // `require_owner_or_admin` has nothing stable to compare against, so
        // ownership-gated tools stop enforcing ownership on transports that
        // carry no AuthContext.
        tracing::warn!(
            "No declared signer identity (--agent-key / --agent-model absent): a fresh keypair \
             was generated for this process. Ownership-gated tools (supersede_claim, \
             mark_duplicate, resolve_backlog_item) will therefore NOT enforce owner-equality on \
             transports without an AuthContext (stdio). Pass --agent-key for strict enforcement."
        );
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
    let federation = epigraph_mcp::federation::SharedFederation::new(
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
        // An extension that lost the boot race (dialled before it had bound its
        // port) mounts unhealthy and, without this timer, stays unroutable for
        // the whole process lifetime — only a gateway restart would pick it up.
        // Systemd ordering cannot close that window: `After=` orders *start*,
        // not readiness, and a `Type=simple` extension counts as started the
        // instant it execs, before it listens. So the gateway re-dials instead.
        let reconnect_interval = std::env::var("EPIGRAPH_MCP_RECONNECT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| *s > 0)
            .map_or(
                epigraph_mcp::federation::DEFAULT_RECONNECT_INTERVAL,
                std::time::Duration::from_secs,
            );
        tracing::info!(
            reconnect_interval_secs = reconnect_interval.as_secs(),
            "Federation gateway: reconnect timer started for unhealthy extensions"
        );
        federation.spawn_reconnect_loop(reconnect_interval);
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
                let srv = EpiGraphMcpFull::new_shared_with_federation(
                    pool.clone(),
                    signer.clone(),
                    embedder.clone(),
                    read_only,
                    federation.clone(),
                    llm_identity.clone(),
                );
                Ok(if identity_declared {
                    srv
                } else {
                    srv.with_generated_signer_identity()
                })
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

        // ── DNS-rebinding guard (CVE-2026-42559 class) ──────────────────
        // rmcp 0.15's StreamableHttpServerConfig has no allowed_hosts /
        // allowed_origins knob and the crate validates neither header, so a
        // browser pointed at a page whose DNS rebinds to this listener could
        // otherwise drive every tool. Applied LAST, i.e. OUTERMOST, so it runs
        // BEFORE the auth layer: a rebound request is refused on its headers
        // alone. TCP only — a unix socket is unreachable from a browser, so the
        // guard would add no security there while risking a 403 on the one
        // listener kind allowed to run unauthenticated.
        let router = if epigraph_mcp::is_unix_listener(addr) {
            tracing::info!(
                "Unix-socket listener: Host/Origin allowlist not applied (a unix socket has no \
                 DNS-rebinding surface); filesystem permissions are the trust gate"
            );
            router
        } else {
            let allowlist =
                epigraph_mcp::host_guard::HostAllowlist::for_tcp_listener(addr, &cli.allowed_host);
            tracing::info!(
                allowed_hosts = %allowlist.describe(),
                "Host/Origin allowlist active on the MCP HTTP listener (DNS-rebinding guard); \
                 extend it with --allowed-host / EPIGRAPH_MCP_ALLOWED_HOSTS"
            );
            router.layer(axum::middleware::from_fn_with_state(
                allowlist,
                epigraph_mcp::host_guard::host_guard_middleware,
            ))
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
        // Rung-4 signer: the owner-equality fallback in
        // `require_owner_or_admin` has no stable identity to compare against.
        // See `EpiGraphMcpFull::with_generated_signer_identity`.
        let server = if identity_declared {
            server
        } else {
            server.with_generated_signer_identity()
        };
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
mod listen_auth_gate_tests {
    use super::check_listen_auth_mode;

    const TCP: &str = "127.0.0.1:3100";
    const UNIX: &str = "unix:/run/epigraph-mcp.sock";
    const GOOD_SECRET: &str = "a-real-production-secret-of-at-least-32-bytes";

    /// The escalating case this gate was tightened for: a TCP listener served
    /// with NO credential. `epigraph-mcp-http.service` ran exactly this
    /// (`--listen 127.0.0.1:3100 --allow-unauthenticated-http`), and the
    /// unauthenticated path injects a permissive AuthContext, so every write
    /// tool was callable by anything that could open a loopback socket —
    /// including a browser whose DNS rebound to it. It must not start.
    #[test]
    fn tcp_listener_with_no_credential_is_refused() {
        for listen in [TCP, "0.0.0.0:3100", "[::1]:3100", "localhost:3100"] {
            let err = check_listen_auth_mode(listen, None, true)
                .expect_err("unauthenticated TCP listener must be refused");
            assert!(
                err.contains("unix-socket"),
                "rejection must point the operator at the unix-socket alternative; got: {err}"
            );
        }
    }

    /// The case the flag's own documentation cites — a unix socket behind
    /// filesystem permissions — must STILL be accepted. Without this the change
    /// would be a blanket removal of the flag rather than a narrowing, and the
    /// socket deployment would break.
    #[test]
    fn unix_listener_with_no_credential_is_still_accepted() {
        assert!(check_listen_auth_mode(UNIX, None, true).is_ok());
    }

    /// A TCP listener WITH a real Bearer secret is the supported production
    /// shape and must remain accepted — the narrowing keys on the missing
    /// credential, not on the transport being TCP.
    #[test]
    fn tcp_listener_with_a_real_jwt_secret_is_accepted() {
        assert!(check_listen_auth_mode(TCP, Some(GOOD_SECRET), false).is_ok());
    }

    /// Pre-existing guards must survive the extraction: the committed dev
    /// literal is still refused, and the two modes are still mutually exclusive
    /// (so a stray `--allow-unauthenticated-http` cannot quietly disable a
    /// supplied secret).
    #[test]
    fn preexisting_secret_guards_survive_the_extraction() {
        let dev = check_listen_auth_mode(
            TCP,
            Some("epigraph-dev-secret-change-in-production!!"),
            false,
        )
        .expect_err("dev literal must be refused");
        assert!(dev.contains("--jwt-secret rejected"), "got: {dev}");

        let short = check_listen_auth_mode(TCP, Some("too-short"), false)
            .expect_err("a sub-32-byte secret must be refused");
        assert!(short.contains("--jwt-secret rejected"), "got: {short}");

        let both = check_listen_auth_mode(TCP, Some(GOOD_SECRET), true)
            .expect_err("both modes at once must be refused");
        assert!(both.contains("mutually exclusive"), "got: {both}");

        // ...including on a unix listener, where the unauth path is otherwise legal.
        assert!(check_listen_auth_mode(UNIX, Some(GOOD_SECRET), true).is_err());
    }

    /// `--listen` with neither mode selected is still refused on both transports
    /// (this arm never depended on the TCP/unix distinction).
    #[test]
    fn listen_with_no_mode_selected_is_refused() {
        for listen in [TCP, UNIX] {
            let err = check_listen_auth_mode(listen, None, false)
                .expect_err("--listen with no auth mode must be refused");
            assert!(err.contains("--jwt-secret"), "got: {err}");
        }
    }
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
            ..
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
            ..
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
            ..
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
            ..
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

    /// `identity_declared` must track the RUNG, not `llm_identity`. Rungs 1-3
    /// are declarations by the operator; only rung 4 is not. Rung 3 is the
    /// discriminating case: it reports `llm_identity: None` exactly like rung
    /// 4, so a consumer that tried to infer declaredness from `llm_identity`
    /// would classify an explicit `--agent-key` as undeclared and silently
    /// disable owner-equality enforcement for it.
    #[test]
    fn identity_declared_tracks_the_rung_not_the_llm_identity() {
        // Rung 1: model + hash.
        assert!(
            select_signer(Some("m"), None, Some("abc123"), None)
                .unwrap()
                .identity_declared
        );
        // Rung 2: model + raw prompt.
        assert!(
            select_signer(Some("m"), Some("prompt"), None, None)
                .unwrap()
                .identity_declared
        );
        // Rung 3: agent-key alone — `llm_identity` is None, yet DECLARED.
        let rung3 = select_signer(None, None, None, Some(KEY_HEX)).unwrap();
        assert!(rung3.llm_identity.is_none());
        assert!(
            rung3.identity_declared,
            "--agent-key is an explicit identity declaration even though it carries no \
             llm_identity; conflating the two would disable ownership enforcement for it"
        );
        // Rung 4: nothing supplied.
        assert!(
            !select_signer(None, None, None, None)
                .unwrap()
                .identity_declared
        );
    }

    /// Malformed agent-key hex (odd length / non-hex) is an error, not a panic
    /// and not a silent generate() — the operator asked for a specific key.
    #[test]
    fn malformed_agent_key_is_an_error() {
        assert!(select_signer(None, None, None, Some("zz")).is_err());
    }
}
