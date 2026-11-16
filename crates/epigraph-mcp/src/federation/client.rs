//! rmcp streamable-HTTP client wrappers for the federation gateway.
//!
//! Two distinct session shapes, driven by rmcp's transport model where
//! `auth_header` is **per-transport** (cloned into every request) — there is no
//! per-call token slot:
//!
//! - **Discovery** ([`discovery_session`]): one long-lived client session per
//!   extension, authenticated with a gateway *service* token. It drives
//!   `list_all_tools` for the routing cache, and the gateway's health timer
//!   ([`super::SharedFederation::reconnect_tick`]) re-lists over it on every
//!   tick and re-dials it when that fails. Persisting it avoids a fresh TCP +
//!   `initialize` handshake on every list.
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
//!
//! The two requests made on an established session are bounded too: a
//! `tools/list` by [`LIST_TIMEOUT`] (it runs on the health timer, which a hung
//! downstream would otherwise stop for every extension), and the proxied
//! `tools/call` by the gateway's configured call timeout
//! ([`DEFAULT_CALL_TIMEOUT`] unless overridden), so a downstream that accepts
//! a call and never answers cannot hold the caller's request open forever.

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

/// How long a `tools/list` on an established session may take. A healthy
/// loopback extension answers in milliseconds; this only has to be long enough
/// never to demote a busy one.
pub const LIST_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a proxied `tools/call` may take when the gateway is given no
/// other value (`EPIGRAPH_MCP_EXTENSION_CALL_TIMEOUT_SECS`). Deliberately
/// generous: federated tools include LLM-backed syntheses that run for
/// minutes. The bound exists to end a call that will never answer, not to
/// police a slow one.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(300);

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

    /// A request on an established session failed (`list_tools`,
    /// `call_tool`, …) for a reason that is not the downstream's own answer:
    /// the transport closed, the reply was not a tool result, and so on.
    #[error("request to extension failed: {0}")]
    Request(String),

    /// The downstream ANSWERED the call with a JSON-RPC error (its own
    /// invalid-params refusal, an unknown tool, …). Kept as the downstream's
    /// `ErrorData`, code and message, so the gateway can hand it to the caller
    /// as the tool error it is instead of redacting it to an internal error.
    #[error("extension returned an error: {}", .0.message)]
    Downstream(rmcp::ErrorData),

    /// The downstream accepted `tool` and did not answer within `timeout`.
    /// The call was abandoned; it may still have run downstream.
    #[error("extension did not answer `{tool}` within {timeout:?}")]
    CallTimeout {
        /// The bound that elapsed.
        timeout: Duration,
        /// The downstream (un-prefixed) tool name.
        tool: String,
    },
}

impl FederationError {
    /// Whether this failure means the extension could not be REACHED (as
    /// opposed to reached and unhappy): the handshake was refused or timed
    /// out. The registry demotes an extension on one of these.
    #[must_use]
    pub fn is_unreachable(&self) -> bool {
        matches!(self, Self::Timeout(..) | Self::Connect { .. })
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
/// [`FederationError::Request`] if the downstream `tools/list` fails or does
/// not complete within [`LIST_TIMEOUT`].
pub async fn list_all_tools(client: &ExtensionClient) -> Result<Vec<Tool>, FederationError> {
    list_all_tools_on(client.peer()).await
}

/// [`list_all_tools`] on a cloned peer handle, so the health timer can list
/// over an extension's persistent session without holding the registry lock
/// (the session itself stays in the registry).
///
/// # Errors
/// As [`list_all_tools`].
pub async fn list_all_tools_on(
    peer: &rmcp::service::Peer<RoleClient>,
) -> Result<Vec<Tool>, FederationError> {
    match tokio::time::timeout(LIST_TIMEOUT, peer.list_all_tools()).await {
        Ok(Ok(tools)) => Ok(tools),
        Ok(Err(e)) => Err(FederationError::Request(e.to_string())),
        Err(_elapsed) => Err(FederationError::Request(format!(
            "tools/list did not complete within {LIST_TIMEOUT:?}"
        ))),
    }
}

/// Proxy a single `tools/call` to the extension at `addr` on a **fresh**
/// ephemeral session authenticated with `caller_token` (the caller's raw
/// bearer, forwarded verbatim so the downstream sees the real principal).
///
/// The session is dropped when this function returns; rmcp's transport worker
/// issues `delete_session` on drop, so the downstream session is released and
/// does not leak.
///
/// The round trip is bounded by `call_timeout`: dropping the session when it
/// elapses cancels the request and releases the downstream session.
///
/// # Errors
/// [`FederationError::Timeout`] / [`FederationError::Connect`] on handshake
/// failure; [`FederationError::Downstream`] when the downstream answers with a
/// JSON-RPC error; [`FederationError::CallTimeout`] when it does not answer in
/// time; [`FederationError::Request`] for any other failure of the call.
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
        Ok(Ok(result)) => Ok(result),
        Ok(Err(rmcp::ServiceError::McpError(e))) => Err(FederationError::Downstream(e)),
        Ok(Err(e)) => Err(FederationError::Request(e.to_string())),
        Err(_elapsed) => Err(FederationError::CallTimeout {
            timeout: call_timeout,
            tool: name.to_string(),
        }),
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
