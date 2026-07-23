//! rmcp streamable-HTTP client wrappers for the federation gateway.
//!
//! Two distinct session shapes, driven by rmcp 0.15's transport model where
//! `auth_header` is **per-transport** (cloned into every request) — there is no
//! per-call token slot:
//!
//! - **Discovery** ([`discovery_session`]): one long-lived client session per
//!   extension, authenticated with a gateway *service* token. It drives
//!   `list_all_tools` for the routing cache and is periodically health-checked /
//!   reconnected. Persisting it avoids a fresh TCP + `initialize` handshake on
//!   every list.
//! - **Invocation** ([`invoke_once`]): a fresh, ephemeral session per federated
//!   `tools/call`, authenticated with the *caller's* raw bearer so the
//!   downstream sees the real principal (not the gateway). The session is
//!   dropped immediately after the call; rmcp's transport worker issues
//!   `delete_session` on drop, so downstream sessions do not leak.
//!
//! ## Timeouts
//!
//! The `initialize` handshake ([`serve_client`]) is wrapped in a bounded
//! [`tokio::time::timeout`]. A downstream that accepts the TCP connection but
//! never completes `initialize` would otherwise hang the gateway's `build()`
//! (discovery) or a caller's `tools/call` (invocation) indefinitely. On timeout
//! we surface a [`FederationError::Timeout`] so the registry can log-and-skip a
//! wedged extension rather than wedge the whole gateway.

use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{CallToolRequestParams, CallToolResult, Tool};
use rmcp::serve_client;
use rmcp::service::RunningService;
use rmcp::transport::streamable_http_client::{
    StreamableHttpClientTransport, StreamableHttpClientTransportConfig,
};
use rmcp::RoleClient;

/// How long to wait for the `initialize` handshake before giving up on a
/// downstream extension. Deliberately short: a healthy loopback extension
/// completes `initialize` in milliseconds; anything slower is either a wedged
/// process or a mis-routed port, and we would rather log-and-skip than block
/// gateway startup or a caller's request.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// A live rmcp client session to one downstream extension. The `()` service
/// handler is the no-op client handler (`impl ClientHandler for ()`), which is
/// all we need: the gateway is a pure client of the downstream — it issues
/// requests and never serves the downstream's server-initiated calls.
pub type ExtensionClient = RunningService<RoleClient, ()>;

/// Errors talking to a downstream extension over the federation transport.
#[derive(Debug, thiserror::Error)]
pub enum FederationError {
    /// The `initialize` handshake did not complete within [`HANDSHAKE_TIMEOUT`].
    /// Distinguished from [`Connect`](FederationError::Connect) so the registry
    /// can report a wedged (vs unreachable) downstream.
    #[error("timed out after {0:?} connecting to extension at {1}")]
    Timeout(Duration, String),

    /// The `serve_client` handshake failed (connection refused, TCP reset,
    /// protocol error at `initialize`, …). Carries the target URI and the
    /// underlying error string.
    #[error("failed to connect to extension at {uri}: {cause}")]
    Connect {
        /// The `http://host:port/mcp` URI we dialed.
        uri: String,
        /// Stringified underlying rmcp / transport error. (Named `cause`, not
        /// `source`, so thiserror does not treat it as a `#[source]` field —
        /// it is a `String`, which is not `std::error::Error`.)
        cause: String,
    },

    /// A request on an established session failed (`list_tools`,
    /// `call_tool`, …).
    #[error("request to extension failed: {0}")]
    Request(String),
}

/// Build the `http://{addr}/mcp` URI the gateway dials for an extension whose
/// parsed `addr` is a bare `host:port` (v1 loopback TCP only; see
/// [`super::config`]).
#[must_use]
pub fn extension_uri(addr: &str) -> String {
    format!("http://{addr}/mcp")
}

/// Open a persistent **discovery** session to the extension at `addr`,
/// authenticated with `discovery_token` (the gateway service token, sent as a
/// bearer). The returned session is meant to be kept alive and reused for
/// `list_all_tools` and health checks.
///
/// # Errors
/// [`FederationError::Timeout`] if `initialize` does not complete within
/// [`HANDSHAKE_TIMEOUT`]; [`FederationError::Connect`] on any other handshake
/// failure.
pub async fn discovery_session(
    addr: &str,
    discovery_token: &str,
) -> Result<ExtensionClient, FederationError> {
    connect(addr, Some(discovery_token)).await
}

/// List every tool the extension advertises over its discovery session,
/// following pagination to completion.
///
/// # Errors
/// [`FederationError::Request`] if the downstream `tools/list` fails.
pub async fn list_all_tools(client: &ExtensionClient) -> Result<Vec<Tool>, FederationError> {
    client
        .peer()
        .list_all_tools()
        .await
        .map_err(|e| FederationError::Request(e.to_string()))
}

/// Proxy a single `tools/call` to the extension at `addr` on a **fresh**
/// ephemeral session authenticated with `caller_token` (the caller's raw
/// bearer, forwarded verbatim so the downstream sees the real principal).
///
/// The session is dropped when this function returns; rmcp's transport worker
/// issues `delete_session` on drop, so the downstream session is released and
/// does not leak.
///
/// # Errors
/// [`FederationError::Timeout`] / [`FederationError::Connect`] on handshake
/// failure; [`FederationError::Request`] if the downstream `tools/call` fails.
pub async fn invoke_once(
    addr: &str,
    caller_token: &str,
    name: &str,
    arguments: Option<rmcp::model::JsonObject>,
) -> Result<CallToolResult, FederationError> {
    let client = connect(addr, Some(caller_token)).await?;
    let result = client
        .peer()
        .call_tool(CallToolRequestParams {
            meta: None,
            name: std::borrow::Cow::Owned(name.to_string()),
            arguments,
            task: None,
        })
        .await
        .map_err(|e| FederationError::Request(e.to_string()));
    // Explicit drop: releasing the session (and its downstream `delete_session`)
    // is the whole point of the ephemeral-per-call model. Dropping after we have
    // the result keeps the RAII contract obvious to future readers.
    drop(client);
    result
}

/// Core connect path shared by discovery and invocation: build a reqwest
/// streamable-HTTP transport with the given bearer (if any) and run the
/// `serve_client` `initialize` handshake under [`HANDSHAKE_TIMEOUT`].
async fn connect(addr: &str, token: Option<&str>) -> Result<ExtensionClient, FederationError> {
    let uri = extension_uri(addr);
    let mut config = StreamableHttpClientTransportConfig::with_uri(Arc::<str>::from(uri.as_str()));
    if let Some(token) = token {
        // `auth_header` is the raw bearer WITHOUT the `Bearer ` prefix; rmcp's
        // reqwest client calls `.bearer_auth(token)` which prepends it, so the
        // downstream receives `Authorization: Bearer <token>`.
        config.auth_header = Some(token.to_string());
    }
    let transport = StreamableHttpClientTransport::<reqwest::Client>::from_config(config);

    match tokio::time::timeout(HANDSHAKE_TIMEOUT, serve_client((), transport)).await {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(e)) => Err(FederationError::Connect {
            uri,
            cause: e.to_string(),
        }),
        Err(_elapsed) => Err(FederationError::Timeout(HANDSHAKE_TIMEOUT, uri)),
    }
}
