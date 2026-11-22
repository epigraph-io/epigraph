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
//!   `tools/call`, authenticated with a token EXCHANGED for the caller's
//!   ([`TokenExchange`], RFC 8693 at the kernel's `/oauth/token`): the same
//!   principal, `aud` = the extension, at most five minutes, scopes no wider
//!   than the caller's. The downstream sees the real principal (not the
//!   gateway) but never holds a token the kernel would admit, so it cannot
//!   replay the caller at the kernel (backlog c9b82fae: the caller's raw
//!   bearer used to be forwarded verbatim). The session is dropped
//!   immediately after the call; rmcp's transport worker issues
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

use rmcp::model::{CallToolRequestParams, CallToolResult, ResultType, Tool};
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

/// How long the gateway waits for the kernel's token endpoint to answer an
/// exchange. Loopback in every supported deployment; the bound only keeps a
/// wedged endpoint from holding a caller's request.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// The gateway's client of the kernel's RFC 8693 token-exchange grant
/// (`epigraph-api` `oauth::token_exchange`). One per gateway process, set on
/// the registry with
/// [`FederationRegistry::with_token_exchange`](super::FederationRegistry::with_token_exchange).
/// A registry without one REFUSES every federated call: there is no fallback
/// to forwarding the caller's own bearer.
#[derive(Clone, Debug)]
pub struct TokenExchange {
    endpoint: String,
    http: reqwest::Client,
}

impl TokenExchange {
    /// A client for the token endpoint at `endpoint` (the kernel's absolute
    /// `/oauth/token` URL). The caller's bearer is sent there on every
    /// federated call, so the URL must be `https`, or `http` to a loopback
    /// host (`127.0.0.0/8`, `[::1]`, `localhost`). An `http` URL naming
    /// `localhost` is dialled at `127.0.0.1`, never by resolving the name
    /// (backlog b0d05192); an `https` one keeps its name, which the
    /// certificate check needs.
    ///
    /// # Errors
    /// A description of why `endpoint` is refused.
    pub fn new(endpoint: &str) -> Result<Self, String> {
        let mut url = reqwest::Url::parse(endpoint)
            .map_err(|e| format!("token exchange URL `{endpoint}` does not parse: {e}"))?;
        let host = url.host_str().unwrap_or_default();
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let localhost = super::config::is_localhost_name(host);
        let loopback = localhost
            || bare
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        match url.scheme() {
            "https" => {}
            "http" if loopback => {}
            other => {
                return Err(format!(
                    "token exchange URL must be https, or http to a loopback host (it carries \
                     every caller's bearer); got scheme `{other}` on host `{}`",
                    url.host_str().unwrap_or_default()
                ))
            }
        }
        if localhost && url.scheme() == "http" {
            url.set_host(Some(super::config::LOCALHOST_LITERAL))
                .map_err(|e| format!("token exchange URL `{endpoint}`: {e}"))?;
        }
        let http = reqwest::Client::builder()
            .timeout(EXCHANGE_TIMEOUT)
            .build()
            .map_err(|e| format!("token exchange HTTP client: {e}"))?;
        Ok(Self {
            endpoint: url.to_string(),
            http,
        })
    }

    /// Exchange `caller_token` for a token whose audience is `audience` (the
    /// extension's configured name). Returns the new access token.
    ///
    /// # Errors
    /// [`FederationError::Exchange`] when the endpoint cannot be reached,
    /// refuses (carrying its RFC `error` code, never the caller's token), or
    /// answers with something that is not an access token.
    pub async fn exchange(
        &self,
        caller_token: &str,
        audience: &str,
    ) -> Result<String, FederationError> {
        let form = [
            ("grant_type", epigraph_auth::TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", caller_token),
            ("subject_token_type", epigraph_auth::ACCESS_TOKEN_TYPE),
            ("requested_token_type", epigraph_auth::ACCESS_TOKEN_TYPE),
            ("audience", audience),
        ];
        let resp = self
            .http
            .post(&self.endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| {
                FederationError::Exchange(format!(
                    "token endpoint unreachable: {}",
                    e.without_url()
                ))
            })?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.map_err(|e| {
            FederationError::Exchange(format!(
                "token endpoint answered {status} with a non-JSON body: {}",
                e.without_url()
            ))
        })?;
        if !status.is_success() {
            let error = body
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            return Err(FederationError::Exchange(format!(
                "token exchange refused ({status}, {error})"
            )));
        }
        if let Some(issued) = body
            .get("issued_token_type")
            .and_then(serde_json::Value::as_str)
        {
            if issued != epigraph_auth::ACCESS_TOKEN_TYPE {
                return Err(FederationError::Exchange(format!(
                    "token endpoint issued `{issued}`, not an access token"
                )));
            }
        }
        match body.get("access_token").and_then(serde_json::Value::as_str) {
            Some(token) if !token.is_empty() && token != caller_token => Ok(token.to_string()),
            Some(_) => Err(FederationError::Exchange(
                "token endpoint returned the caller's own token; refusing to forward it"
                    .to_string(),
            )),
            None => Err(FederationError::Exchange(
                "token endpoint answered without an access_token".to_string(),
            )),
        }
    }
}

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

    /// The gateway could not obtain an extension-audience token for the
    /// caller ([`TokenExchange`]): no exchange is configured, the kernel's
    /// token endpoint refused or could not be reached. The downstream was
    /// never dialled. Never carries the caller's token.
    #[error("token exchange failed: {0}")]
    Exchange(String),

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
/// ephemeral session authenticated with a token `exchange` mints from
/// `caller_token` for `audience` (the extension's name). The caller's own
/// bearer goes ONLY to the kernel's token endpoint, never to the downstream.
///
/// The session is dropped when this function returns; rmcp's transport worker
/// issues `delete_session` on drop, so the downstream session is released and
/// does not leak.
///
/// The round trip is bounded by `call_timeout`: dropping the session when it
/// elapses cancels the request and releases the downstream session.
///
/// # Errors
/// [`FederationError::Exchange`] when no extension token can be obtained (the
/// downstream is not dialled); [`FederationError::Timeout`] /
/// [`FederationError::Connect`] on handshake failure;
/// [`FederationError::Downstream`] when the downstream answers with a
/// JSON-RPC error; [`FederationError::CallTimeout`] when it does not answer in
/// time; [`FederationError::Request`] for any other failure of the call.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct input of one proxied call; a struct would only rename them"
)]
pub async fn invoke_once(
    addr: &str,
    exchange: &TokenExchange,
    audience: &str,
    caller_token: &str,
    name: &str,
    arguments: Option<rmcp::model::JsonObject>,
    call_timeout: Duration,
) -> Result<CallToolResult, FederationError> {
    let forwarded = exchange.exchange(caller_token, audience).await?;
    let client = connect(addr, Some(&forwarded)).await?;
    let mut params = CallToolRequestParams::new(name.to_string());
    params.arguments = arguments;
    let result = match tokio::time::timeout(call_timeout, client.peer().call_tool(params)).await {
        Ok(Ok(result)) => Ok(as_complete_result(result)),
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

/// Give a downstream's `tools/call` result the SEP-2322 `resultType` it lacks
/// when the downstream negotiated a revision older than `2026-07-28`.
///
/// Such a downstream (episcience-mcp speaks `2025-03-26`) omits the field, and
/// rmcp deserializes the absence as `result_type: None`. Relayed as-is, the
/// gateway answers a `2026-07-28` caller WITHOUT `resultType`, which that
/// revision requires of every server result: claude.ai rejected exactly that
/// (backlog e3614de6, "missing required resultType"). Kernel tools never hit
/// this because every rmcp constructor (`CallToolResult::success`, ...) sets
/// `Some(ResultType::COMPLETE)`.
///
/// `"complete"` is what an absent field means in the older revision (rmcp's
/// `ResultType` doc: "clients MUST treat an absent field as `complete`"), and
/// rmcp's `CallToolResult` deserializer rejects any other value, so `None` is
/// the only case to fill. Filling it unconditionally still answers each
/// caller in ITS revision: rmcp's server handler
/// (`Service<RoleServer>::handle_request`) calls
/// `ServerResult::strip_result_type_for_legacy_peer` for callers older than
/// `2026-07-28`, removing `"complete"` again, exactly as it does for kernel
/// results; only `2026-07-28`+ callers (the `fill_missing_cache_hints`
/// branch) keep it.
fn as_complete_result(mut result: CallToolResult) -> CallToolResult {
    result.result_type.get_or_insert(ResultType::COMPLETE);
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

#[cfg(test)]
mod tests {
    use super::TokenExchange;

    /// The exchange URL carries every caller's bearer, so cleartext is
    /// accepted only to a loopback host. Mutation: drop the loopback check
    /// -> the remote `http` URLs are accepted and this fails.
    #[test]
    fn the_exchange_url_is_https_or_loopback_http() {
        for ok in [
            "https://kernel.example/oauth/token",
            "http://127.0.0.1:8080/oauth/token",
            "http://127.9.9.9/oauth/token",
            "http://[::1]:8080/oauth/token",
            "http://LOCALHOST:8080/oauth/token",
        ] {
            assert!(TokenExchange::new(ok).is_ok(), "{ok} must be accepted");
        }
        for refused in [
            "http://kernel.example/oauth/token",
            "http://10.0.0.5:8080/oauth/token",
            "http://localhost.evil.example/oauth/token",
            "ftp://127.0.0.1/oauth/token",
            "not a url",
        ] {
            assert!(
                TokenExchange::new(refused).is_err(),
                "{refused} must be refused"
            );
        }
    }

    /// Cleartext to `localhost` is accepted as loopback, but the name is
    /// never what the exchange dials: the stored endpoint is the `127.0.0.1`
    /// literal, so where every caller's bearer is sent does not depend on how
    /// this host resolves `localhost` (backlog b0d05192). `https` keeps its
    /// name, which its certificate check needs, and protects the bearer
    /// whatever the name resolves to.
    ///
    /// Mutation: store the URL as given -> the `localhost` endpoints are kept
    /// and this fails.
    #[test]
    fn a_cleartext_localhost_exchange_url_is_dialled_as_the_loopback_literal() {
        for (given, dialled) in [
            (
                "http://localhost:8080/oauth/token",
                "http://127.0.0.1:8080/oauth/token",
            ),
            (
                "http://LOCALHOST:8080/oauth/token",
                "http://127.0.0.1:8080/oauth/token",
            ),
            (
                "http://localhost/oauth/token",
                "http://127.0.0.1/oauth/token",
            ),
            (
                "https://localhost:8443/oauth/token",
                "https://localhost:8443/oauth/token",
            ),
            (
                "http://127.0.0.1:8080/oauth/token",
                "http://127.0.0.1:8080/oauth/token",
            ),
        ] {
            let exchange = TokenExchange::new(given).unwrap_or_else(|e| panic!("{given}: {e}"));
            assert_eq!(exchange.endpoint, dialled, "{given}");
        }
    }
}
