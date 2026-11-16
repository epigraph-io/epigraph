//! The federation gateway as a CALLER sees it: the manifest `EpiGraphMcpFull`
//! lists, and what a federated `tools/call` answers, against a controllable
//! stub downstream (`support/federation_stub.rs`).
//!
//! No database: the server runs on a lazy pool that points at a port nothing
//! listens on, as in `http_auth_test.rs`. Nothing asserted here reads it;
//! `emit_tool_invoked` is best-effort and only logs when it cannot publish.

#[path = "support/federation_stub.rs"]
mod stub;

use std::collections::HashSet;
use std::sync::Arc;

use epigraph_mcp::federation::config::ExtensionConfig;
use epigraph_mcp::federation::{FederationRegistry, SharedFederation};
use epigraph_mcp::EpiGraphMcpFull;

fn cfg(name: &str, addr: &str) -> ExtensionConfig {
    epigraph_mcp::federation::config::parse_extensions(Some(&format!(
        "{name}=tcp:{addr};scope={name}:tools"
    )))
    .expect("a well-formed test entry")
    .remove(0)
}

fn dead_pool() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(100))
        .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/invalid")
        .expect("connect_lazy never errors")
}

fn server_with(federation: SharedFederation) -> EpiGraphMcpFull {
    let pool = dead_pool();
    let signer = Arc::new(epigraph_crypto::AgentSigner::generate());
    let embedder = Arc::new(epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None));
    EpiGraphMcpFull::new_shared_with_federation(pool, signer, embedder, false, federation, None)
}

/// An `AuthContext` as the bearer middleware builds it from a real token: a
/// client id and a token id, so not principal-less.
fn bearer_context() -> epigraph_auth::AuthContext {
    epigraph_auth::AuthContext {
        client_id: uuid::Uuid::new_v4(),
        agent_id: Some(uuid::Uuid::new_v4()),
        owner_id: None,
        client_type: epigraph_auth::ClientType::Service,
        scopes: vec!["ext:tools".to_string()],
        jti: uuid::Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Armed,
        delegated_by: None,
    }
}

async fn mounted_server(tool: &str) -> EpiGraphMcpFull {
    let (addr, _control) = stub::spawn_controlled_stub(&[tool]).await;
    let registry = FederationRegistry::build(vec![cfg("ext", &addr)], "discovery-tok")
        .await
        .expect("build against a reachable stub");
    server_with(SharedFederation::new(registry))
}

fn names(tools: &[rmcp::model::Tool]) -> HashSet<String> {
    tools.iter().map(|t| t.name.to_string()).collect()
}

// ── Backlog b6559e75: a federated tool is listed only where it can be called ──

/// Over stdio there is no bearer to forward, so `call_tool` refuses every
/// federated call. The manifest must not list one.
///
/// Mutation: make `manifest_for` extend with the federated tools
/// unconditionally (the pre-fix code) -> `federated_probe` is listed and this
/// fails.
#[tokio::test]
async fn the_stdio_manifest_lists_no_federated_tool() {
    let server = mounted_server("federated_probe").await;
    let stdio = names(&server.manifest_for(false, None).await);
    assert!(
        !stdio.contains("federated_probe"),
        "a stdio caller cannot call a federated tool, so it must not be listed one"
    );
    assert!(
        stdio.contains("submit_claim"),
        "CALIBRATION: the kernel tools are still listed over stdio"
    );
}

/// The positive control: a bearer caller over HTTP is listed the federated
/// tool. Without it, the stdio assertion above would also pass if the registry
/// had mounted nothing.
#[tokio::test]
async fn the_http_manifest_of_a_bearer_caller_lists_the_federated_tool() {
    let server = mounted_server("federated_probe").await;
    let auth = bearer_context();
    let http = names(&server.manifest_for(true, Some(&auth)).await);
    assert!(
        http.contains("federated_probe"),
        "a bearer caller over HTTP can call the federated tool and is listed it"
    );
}

/// The unauthenticated listener injects a principal-less context and carries
/// no token, so its callers can call no federated tool either.
///
/// Mutation: reduce `lists_federated_tools` to `http` -> listed, fails.
#[tokio::test]
async fn the_unauthenticated_listener_lists_no_federated_tool() {
    let server = mounted_server("federated_probe").await;
    let principal_less = epigraph_mcp::auth::unauthenticated_context(
        Some(uuid::Uuid::new_v4()),
        epigraph_mcp::auth::UnauthenticatedWrites::Refused,
    );
    let listed = names(&server.manifest_for(true, Some(&principal_less)).await);
    assert!(
        !listed.contains("federated_probe"),
        "a principal-less caller has no bearer to forward and must not be listed \
         a federated tool"
    );
}
