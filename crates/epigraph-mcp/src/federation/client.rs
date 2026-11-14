//! rmcp streamable-HTTP client wrappers for the federation gateway.
//!
//! Two distinct session shapes, driven by rmcp's transport model where
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
//! The proxied `tools/call` is bounded by the extension's `call_timeout_secs=`
//! ([`super::config::DEFAULT_CALL_TIMEOUT`] when unset), and surfaces
//! [`FederationError::CallTimeout`].
//!
//! The `initialize` handshake ([`serve_client`]) is wrapped in a bounded
//! [`tokio::time::timeout`]. A downstream that accepts the TCP connection but
//! never completes `initialize` would otherwise hang the gateway's `build()`
//! (discovery) or a caller's `tools/call` (invocation) indefinitely. On timeout
//! we surface a [`FederationError::Timeout`] so the registry can log-and-skip a
//! wedged extension rather than wedge the whole gateway.

use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{CallToolRequestParams, CallToolResult, ErrorData, Tool};
use rmcp::serve_client;
use rmcp::service::{RunningService, ServiceError};
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

/// The largest single response event the gateway accepts from a downstream
/// extension: 16 MiB, rmcp 3.9's default, set explicitly in [`connect`].
///
/// rmcp 2.2's streamable-HTTP client buffered a downstream response of any
/// size (RUSTSEC-2026-0462), so one oversized or never-ending reply could
/// exhaust the gateway's memory. rmcp 3.9 bounds each SSE event at
/// `StreamableHttpClientTransportConfig::max_sse_event_size`, and a larger one
/// fails the call instead of being buffered. Pinned by
/// `tests/federation_gateway_test.rs`
/// (`a_downstream_reply_over_16_mib_fails_the_call_and_one_under_is_proxied`).
pub const MAX_RESPONSE_EVENT_BYTES: usize = 16 * 1024 * 1024;

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

    /// The downstream ANSWERED the request, with an MCP error. Carried whole
    /// (code, message, data) so the gateway hands the caller the downstream's
    /// own answer unchanged rather than a redacted "internal error" (backlog
    /// 7ea4bd74): it is the extension's reply to the caller's own request,
    /// made under the caller's own token.
    #[error("extension answered with an MCP error: {0}")]
    Downstream(ErrorData),

    /// A request on an established session failed without an MCP answer
    /// (the transport broke, the session closed, the reply was refused as
    /// oversized, …). Carries the stringified rmcp error, which can name the
    /// dialed URI, so it is for the server log only.
    #[error("request to extension failed: {0}")]
    Request(String),

    /// The downstream accepted the `tools/call` and gave no answer within the
    /// extension's `call_timeout_secs=` (backlog 7ea4bd74). The gateway stopped
    /// waiting and dropped the session; the call may still complete there.
    #[error("extension gave no answer within {0:?}")]
    CallTimeout(Duration),

    /// No mounted extension routes this effective tool name (any more): the
    /// route was looked up and was gone, e.g. the extension was demoted
    /// between the caller's lookup and the call.
    #[error("no federated route for tool `{0}`")]
    NoRoute(String),
}

impl FederationError {
    /// Classify an rmcp request failure: an MCP error answer is
    /// [`Downstream`](Self::Downstream), anything else
    /// [`Request`](Self::Request).
    fn from_service(e: ServiceError) -> Self {
        match e {
            ServiceError::McpError(data) => Self::Downstream(data),
            other => Self::Request(other.to_string()),
        }
    }
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
/// [`FederationError::Downstream`] or [`FederationError::Request`] if the
/// downstream `tools/list` fails.
pub async fn list_all_tools(client: &ExtensionClient) -> Result<Vec<Tool>, FederationError> {
    client
        .peer()
        .list_all_tools()
        .await
        .map_err(FederationError::from_service)
}

/// Proxy a single `tools/call` to the extension at `addr` on a **fresh**
/// ephemeral session authenticated with `caller_token` (the caller's raw
/// bearer, forwarded verbatim so the downstream sees the real principal),
/// waiting at most `call_timeout` for the answer.
///
/// The session is dropped when this function returns; rmcp's transport worker
/// issues `delete_session` on drop, so the downstream session is released and
/// does not leak.
///
/// # Errors
/// [`FederationError::Timeout`] / [`FederationError::Connect`] on handshake
/// failure; [`FederationError::Downstream`] if the downstream answers the
/// `tools/call` with an MCP error; [`FederationError::Request`] if the call
/// fails without one; [`FederationError::CallTimeout`] if it gives no answer
/// within `call_timeout`.
pub async fn invoke_once(
    addr: &str,
    caller_token: &str,
    name: &str,
    arguments: Option<rmcp::model::JsonObject>,
    call_timeout: Duration,
) -> Result<CallToolResult, FederationError> {
    let client = connect(addr, Some(caller_token)).await?;
    let mut params = CallToolRequestParams::new(name.to_string());
    params.arguments = arguments;
    let result = match tokio::time::timeout(call_timeout, client.peer().call_tool(params)).await {
        Ok(answer) => answer.map_err(FederationError::from_service),
        Err(_elapsed) => Err(FederationError::CallTimeout(call_timeout)),
    };
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
    // Explicit rather than inherited, so a later rmcp default cannot move it.
    config.max_sse_event_size = MAX_RESPONSE_EVENT_BYTES;
    // rmcp implements its client transport for the reqwest it links (0.13),
    // not this crate's reqwest; leaving the type parameter to inference keeps
    // that version choice inside rmcp instead of adding a second direct
    // reqwest dependency here.
    let transport = StreamableHttpClientTransport::from_config(config);

    match tokio::time::timeout(HANDSHAKE_TIMEOUT, serve_client((), transport)).await {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(e)) => Err(FederationError::Connect {
            uri,
            cause: e.to_string(),
        }),
        Err(_elapsed) => Err(FederationError::Timeout(HANDSHAKE_TIMEOUT, uri)),
    }
}
