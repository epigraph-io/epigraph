//! DNS-rebinding mitigation for the MCP Streamable-HTTP listener.
//!
//! ## Why this exists
//!
//! The workspace pins `rmcp = "0.15"` (Cargo.lock resolves 0.15.0). That
//! version's [`StreamableHttpServerConfig`] has exactly four fields
//! (`sse_keep_alive`, `sse_retry`, `stateful_mode`, `cancellation_token`) — no
//! `allowed_hosts` / `allowed_origins` knob — and the crate source contains no
//! Host- or Origin-validation code anywhere. rmcp added that guard internally
//! in 1.4.0 (CVE-2026-42559 class); until this workspace takes that major bump
//! the transport ships with **no** rebinding defense.
//!
//! Without it, a browser on the same host as the listener can be pointed at a
//! hostile page whose DNS rebinds to `127.0.0.1:<mcp port>`. The browser then
//! issues same-origin-looking requests to the MCP endpoint from the victim's
//! machine, driving every tool the listener exposes.
//!
//! ## What it does
//!
//! Rejects (403) any request whose `Host` is not in an allowlist, and — when an
//! `Origin` header is present — any request whose Origin authority is not in the
//! same allowlist. This is the same defense rmcp >= 1.4.0 applies internally, so
//! it stays correct across the later bump rather than being obsoleted by it.
//!
//! ## TCP only
//!
//! `main.rs` attaches this layer only for TCP listeners. DNS rebinding requires
//! a browser opening a TCP connection to an IP address; a `unix:/abs/path`
//! listener is unreachable from a browser at all, so the guard would buy zero
//! security there while adding a way to break the one transport that is
//! legitimately allowed to run unauthenticated (behind filesystem permissions).
//!
//! ## Comparison semantics
//!
//! Hostname only — the port is stripped before comparison. An attacker does not
//! choose which port they reached the server on, and keeping the port out of the
//! comparison is what lets a reverse proxy forward the client's original `Host`
//! (Caddy's `reverse_proxy` preserves it by default) without a port mismatch
//! turning into a 403.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{
    header::{HOST, ORIGIN},
    StatusCode,
};

/// Authorities always permitted, regardless of `--listen` / `--allowed-host`.
///
/// These are the loopback spellings a legitimate local client uses. They are
/// safe to allow because a rebinding attack cannot *produce* them: the browser
/// sends the attacker's own hostname (`evil.example`) in `Host`, which is the
/// signal this guard keys on — the victim's DNS resolving that name to
/// 127.0.0.1 does not change the header.
pub const DEFAULT_ALLOWED_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// The set of `Host` / `Origin` authorities this listener will serve.
///
/// Cheap to clone (the set lives behind an `Arc`), which is what
/// `axum::middleware::from_fn_with_state` requires.
#[derive(Clone, Debug)]
pub struct HostAllowlist {
    allowed: Arc<BTreeSet<String>>,
}

/// Reduce a raw `Host`-header / listen-spec authority to its comparable
/// hostname: port stripped, IPv6 brackets removed, one trailing DNS dot
/// removed, ASCII-lowercased.
///
/// Returns `None` when nothing usable remains (empty input, or an authority
/// that is only a port such as `:3100`) so callers fail closed.
///
/// The trailing-dot strip matters: `localhost.` and `evil.example.` are valid
/// fully-qualified DNS names that resolve identically to their dotless forms,
/// and are a standard way to slip past a naive string allowlist. Normalizing
/// both sides means the dotted form neither bypasses a deny nor breaks an allow.
#[must_use]
pub fn normalize_host(raw: &str) -> Option<String> {
    let raw = raw.trim();
    // `[::1]:3100` / `[::1]` — the bracketed literal is everything up to `]`.
    // A bare `::1` (more than one `:`, unbracketed) can only be an IPv6 literal:
    // a port suffix would be unparseable there, and RFC 3986 requires brackets
    // whenever a port follows. Take it whole rather than truncating at the first
    // `:`, which would yield the empty string. Everything else: the first `:`
    // starts the port, since neither a DNS hostname nor an IPv4 literal may
    // contain one.
    let host = if let Some(rest) = raw.strip_prefix('[') {
        rest.split(']').next()?
    } else if raw.matches(':').count() > 1 {
        raw
    } else {
        raw.split(':').next()?
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

impl HostAllowlist {
    /// Build the allowlist for a TCP listener: [`DEFAULT_ALLOWED_HOSTS`], plus
    /// the authority of the `--listen` value, plus every operator-supplied
    /// `--allowed-host` / `EPIGRAPH_MCP_ALLOWED_HOSTS` entry.
    ///
    /// Entries that normalize to nothing (e.g. a stray empty string from a
    /// trailing comma in the env var) are dropped rather than inserted as an
    /// empty key that could never match anyway.
    #[must_use]
    pub fn for_tcp_listener(listen: &str, extra: &[String]) -> Self {
        let mut allowed: BTreeSet<String> = DEFAULT_ALLOWED_HOSTS
            .iter()
            .map(|h| (*h).to_string())
            .collect();
        if let Some(host) = normalize_host(listen) {
            allowed.insert(host);
        }
        for entry in extra {
            if let Some(host) = normalize_host(entry) {
                allowed.insert(host);
            }
        }
        Self {
            allowed: Arc::new(allowed),
        }
    }

    /// Is this raw `Host` header value served by this listener?
    #[must_use]
    pub fn allows_host(&self, raw_host: &str) -> bool {
        normalize_host(raw_host).is_some_and(|h| self.allowed.contains(&h))
    }

    /// Is this raw `Origin` header value served by this listener?
    ///
    /// An Origin is `scheme://host[:port]`. Anything without a `://` authority
    /// — notably the literal `null` a sandboxed/opaque origin sends — is
    /// rejected: we cannot attribute it to an allowlisted site, and an
    /// unattributable cross-origin request is precisely the thing being
    /// defended against.
    #[must_use]
    pub fn allows_origin(&self, raw_origin: &str) -> bool {
        raw_origin
            .split_once("://")
            // Origins carry no path, but truncate at `/` defensively so a
            // malformed value cannot smuggle an allowlisted prefix.
            .and_then(|(_, rest)| rest.split('/').next())
            .is_some_and(|authority| self.allows_host(authority))
    }

    /// Comma-separated rendering for the startup log, so an operator debugging
    /// a 403 can see what the process actually accepts.
    #[must_use]
    pub fn describe(&self) -> String {
        self.allowed
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// 403 for a request whose `Host`/`Origin` this listener does not serve.
fn forbidden(reason: &'static str) -> Response {
    (StatusCode::FORBIDDEN, format!("Forbidden: {reason}")).into_response()
}

/// Axum middleware enforcing the [`HostAllowlist`].
///
/// Attach it as the **outermost** layer (applied last in `main.rs`) so it runs
/// *before* Bearer validation: a rebound request is refused on the header alone,
/// without the auth layer first deciding whether to hand it a session.
///
/// Falls back to the URI authority when no `Host` header is present, which is
/// how an HTTP/2 `:authority` pseudo-header surfaces. A request with neither is
/// rejected — HTTP/1.1 makes `Host` mandatory, so its absence is already
/// anomalous, and there is nothing left to check it against.
pub async fn host_guard_middleware(
    State(allowlist): State<HostAllowlist>,
    req: Request,
    next: Next,
) -> Response {
    let host = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_owned()));

    let Some(host) = host else {
        tracing::warn!(
            allowlist = %allowlist.describe(),
            "MCP request rejected: no Host header and no URI authority"
        );
        return forbidden("missing Host header");
    };

    if !allowlist.allows_host(&host) {
        tracing::warn!(
            rejected_host = %host,
            allowlist = %allowlist.describe(),
            "MCP request rejected: Host not in allowlist (DNS-rebinding guard). \
             Add it with --allowed-host / EPIGRAPH_MCP_ALLOWED_HOSTS if legitimate."
        );
        return forbidden("Host not allowed");
    }

    if let Some(origin) = req.headers().get(ORIGIN).and_then(|v| v.to_str().ok()) {
        if !allowlist.allows_origin(origin) {
            tracing::warn!(
                rejected_origin = %origin,
                allowlist = %allowlist.describe(),
                "MCP request rejected: Origin not in allowlist (DNS-rebinding guard)"
            );
            return forbidden("Origin not allowed");
        }
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::{normalize_host, HostAllowlist};

    fn prod_like() -> HostAllowlist {
        // Mirrors the production shape: a loopback TCP listener plus the
        // proxy-facing name the operator adds.
        HostAllowlist::for_tcp_listener("127.0.0.1:3100", &["5-78-124-36.nip.io".to_string()])
    }

    /// The attack itself: the browser sends the ATTACKER's hostname in `Host`
    /// even though DNS has rebound it to 127.0.0.1. That is the whole signal,
    /// and it must not be served — including the fully-qualified `evil.example.`
    /// spelling, which resolves identically and is the standard allowlist bypass.
    #[test]
    fn rebound_attacker_host_is_refused_in_every_spelling() {
        let a = prod_like();
        for host in [
            "evil.example",
            "evil.example.",
            "EVIL.EXAMPLE",
            "evil.example:3100",
            "attacker.localhost.evil.example",
            "localhost.evil.example",
        ] {
            assert!(!a.allows_host(host), "must refuse rebound Host {host:?}");
        }
    }

    /// Legitimate local clients reach the listener under a loopback spelling,
    /// with or without a port, in any case, bracketed for IPv6, and with a
    /// trailing DNS dot. All must be served or the guard breaks real traffic.
    #[test]
    fn loopback_and_listen_authority_are_served_in_every_spelling() {
        let a = prod_like();
        for host in [
            "localhost",
            "localhost:3100",
            "LocalHost",
            "localhost.",
            "127.0.0.1",
            "127.0.0.1:3100",
            "[::1]",
            "[::1]:3100",
            "::1",
        ] {
            assert!(a.allows_host(host), "must serve legitimate Host {host:?}");
        }
    }

    /// The operator-supplied entry is what keeps a reverse-proxied deployment
    /// working; without it the proxy's forwarded `Host` would 403. Cross-check
    /// that a *near-miss* of that name is still refused, so the entry is an
    /// exact-host allow and not a substring match.
    #[test]
    fn operator_allowed_host_is_served_but_lookalikes_are_not() {
        let a = prod_like();
        assert!(a.allows_host("5-78-124-36.nip.io"));
        assert!(a.allows_host("5-78-124-36.nip.io:443"));
        assert!(!a.allows_host("5-78-124-36.nip.io.evil.example"));
        assert!(!a.allows_host("evil-5-78-124-36.nip.io"));
    }

    /// A hostile page that reaches the listener carries its own `Origin`. Even
    /// if the `Host` check were somehow satisfied, the Origin must be refused —
    /// and `null` (opaque/sandboxed origin) is unattributable, so it fails
    /// closed rather than being treated as "no origin".
    #[test]
    fn cross_origin_and_opaque_origins_are_refused() {
        let a = prod_like();
        assert!(!a.allows_origin("http://evil.example"));
        assert!(!a.allows_origin("https://evil.example:8443"));
        assert!(!a.allows_origin("null"));
        assert!(!a.allows_origin(""));
        // No `://` authority at all — must not be read as an allowlisted host.
        assert!(!a.allows_origin("localhost"));
        // A path-bearing malformation must not smuggle an allowlisted prefix.
        assert!(!a.allows_origin("http://evil.example/localhost"));
    }

    /// The origins a legitimate local browser client (e.g. a dev UI on :5173)
    /// sends must pass, or the guard breaks the localhost use case it is meant
    /// to protect.
    #[test]
    fn loopback_origins_are_served() {
        let a = prod_like();
        assert!(a.allows_origin("http://localhost:5173"));
        assert!(a.allows_origin("http://127.0.0.1:3100"));
        assert!(a.allows_origin("https://5-78-124-36.nip.io"));
    }

    /// Degenerate authorities must normalize to `None` (fail closed) rather
    /// than to an empty string that could be inserted into, and then matched
    /// against, the allowlist.
    #[test]
    fn degenerate_authorities_normalize_to_none() {
        assert_eq!(normalize_host(":3100"), None);
        assert_eq!(normalize_host(""), None);
        assert_eq!(normalize_host("   "), None);
        assert_eq!(normalize_host("."), None);
        // And an empty `--allowed-host` entry must not become a matchable key.
        let a = HostAllowlist::for_tcp_listener("127.0.0.1:3100", &[String::new()]);
        assert!(!a.allows_host(""));
        assert!(!a.allows_host(":443"));
    }

    /// A wildcard bind must not implicitly widen the allowlist: `--listen
    /// 0.0.0.0:3100` contributes only the literal `0.0.0.0`, which no real
    /// client sends as `Host`. Arbitrary external names still need an explicit
    /// `--allowed-host`.
    #[test]
    fn wildcard_bind_does_not_allow_arbitrary_hosts() {
        let a = HostAllowlist::for_tcp_listener("0.0.0.0:3100", &[]);
        assert!(!a.allows_host("5-78-124-36.nip.io"));
        assert!(!a.allows_host("evil.example"));
        assert!(a.allows_host("localhost"));
    }
}
