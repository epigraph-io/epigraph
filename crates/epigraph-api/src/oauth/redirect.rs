//! Which OAuth redirect URIs EpiGraph's authorization server accepts, and how an
//! authorization request's `redirect_uri` is matched against a registered one.
//!
//! Two classes are acceptable:
//! - **Hosted**: the fixed HTTPS callbacks of hosted MCP clients (claude.ai,
//!   claude.com). Matched exactly.
//! - **Loopback** (RFC 8252 §7.3): a native client's local listener, e.g. OpenAI
//!   Codex's MCP login, `http://127.0.0.1:<port>/callback/<id>`. Only an IP-literal
//!   loopback host (`127.0.0.1` or `[::1]`) over plain `http`, with no userinfo and
//!   no fragment. `localhost` is not accepted: RFC 8252 §8.3 recommends the IP
//!   literal, and a name can be resolved elsewhere. Matched exactly EXCEPT for the
//!   port, which RFC 8252 §7.3 requires the authorization server to accept at any
//!   value at request time (a native client gets an ephemeral port per login).
//!
//! Every authorization request also requires PKCE S256 (authorize.rs), which is
//! what keeps an intercepted loopback code useless (RFC 8252 §8.1).

use std::net::{Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

/// Callback prefixes of hosted MCP clients.
const HOSTED_PREFIXES: &[&str] = &["https://claude.ai/", "https://claude.com/"];

/// The kind of an acceptable redirect URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectClass {
    /// A hosted MCP client's fixed HTTPS callback (claude.ai, claude.com).
    Hosted,
    /// A native client's loopback listener (RFC 8252 §7.3), e.g. OpenAI Codex.
    Loopback,
}

/// The class of `uri`, or `None` when EpiGraph does not accept it as a redirect.
pub fn classify(uri: &str) -> Option<RedirectClass> {
    if HOSTED_PREFIXES.iter().any(|p| uri.starts_with(p)) {
        return Some(RedirectClass::Hosted);
    }
    loopback(uri).map(|_| RedirectClass::Loopback)
}

/// Whether `requested` (an authorization request's `redirect_uri`) matches the
/// registered `registered`: identical, or both loopback and identical once the
/// port is ignored.
pub fn matches_registered(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    match (loopback(registered), loopback(requested)) {
        (Some(mut registered), Some(mut requested)) => {
            // `set_port` only fails for URLs that cannot carry a port, which a
            // parsed http loopback URL always can.
            let _ = registered.set_port(None);
            let _ = requested.set_port(None);
            registered == requested
        }
        _ => false,
    }
}

/// `uri` parsed, when it is an RFC 8252 loopback redirect.
fn loopback(uri: &str) -> Option<Url> {
    let url = Url::parse(uri).ok()?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    match url.host()? {
        Host::Ipv4(ip) if ip == Ipv4Addr::LOCALHOST => Some(url),
        Host::Ipv6(ip) if ip == Ipv6Addr::LOCALHOST => Some(url),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_callbacks_are_loopback() {
        for uri in [
            "http://127.0.0.1:53682/callback/Xq3vT0aBk9Lm",
            "http://127.0.0.1/callback/Xq3vT0aBk9Lm",
            "http://[::1]:53682/callback",
        ] {
            assert_eq!(classify(uri), Some(RedirectClass::Loopback), "{uri}");
        }
        assert_eq!(
            classify("https://claude.ai/api/mcp/auth_callback"),
            Some(RedirectClass::Hosted)
        );
    }

    #[test]
    fn lookalikes_are_not_acceptable() {
        for uri in [
            "http://localhost:53682/callback",
            "http://127.0.0.2/callback",
            "https://127.0.0.1/callback",
            "http://127.0.0.1.evil.example/callback",
            "http://127.0.0.1:80@evil.example/callback",
            "http://user@127.0.0.1/callback",
            "http://127.0.0.1/callback#frag",
            "https://claude.ai.evil.example/api/mcp/auth_callback",
            "not a url",
        ] {
            assert_eq!(classify(uri), None, "{uri}");
        }
    }

    #[test]
    fn only_the_loopback_port_is_relaxed() {
        let reg = "http://127.0.0.1/callback/abc";
        assert!(matches_registered(
            reg,
            "http://127.0.0.1:54321/callback/abc"
        ));
        assert!(matches_registered(
            "http://127.0.0.1:1111/callback/abc",
            "http://127.0.0.1:2222/callback/abc"
        ));
        assert!(!matches_registered(
            reg,
            "http://127.0.0.1:54321/callback/other"
        ));
        assert!(!matches_registered(
            reg,
            "http://127.0.0.1:54321/callback/abc?x=1"
        ));
        assert!(!matches_registered(
            reg,
            "http://localhost:54321/callback/abc"
        ));
        assert!(!matches_registered(reg, "http://[::1]:54321/callback/abc"));
        let hosted = "https://claude.ai/api/mcp/auth_callback";
        assert!(matches_registered(hosted, hosted));
        assert!(!matches_registered(
            hosted,
            "https://claude.ai:8443/api/mcp/auth_callback"
        ));
    }
}
