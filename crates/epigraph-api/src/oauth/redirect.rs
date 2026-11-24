//! Which OAuth redirect URIs EpiGraph's authorization server accepts, and how an
//! authorization request's `redirect_uri` is matched against a registered one.
//!
//! Three classes are acceptable:
//! - **Hosted**: the fixed HTTPS callbacks of hosted MCP clients (claude.ai,
//!   claude.com). Matched exactly.
//! - **Configured**: a redirect on an HTTPS origin the operator listed in
//!   [`REDIRECT_ORIGINS_ENV`] (e.g. a first-party web client on its own
//!   origin). The origin (scheme, host, port) must equal a listed one exactly;
//!   any path is allowed under it. Matched exactly at `/authorize`.
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
use url::{Host, Origin, Url};

/// Callback prefixes of hosted MCP clients.
const HOSTED_PREFIXES: &[&str] = &["https://claude.ai/", "https://claude.com/"];

/// The environment variable listing extra redirect origins, read once at boot
/// (`bin/server.rs`): comma- or whitespace-separated HTTPS origins, e.g.
/// `https://explorer.example.org,https://partner.example.com:8443`.
pub const REDIRECT_ORIGINS_ENV: &str = "EPIGRAPH_OAUTH_REDIRECT_ORIGINS";

/// The kind of an acceptable redirect URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectClass {
    /// A hosted MCP client's fixed HTTPS callback (claude.ai, claude.com).
    Hosted,
    /// A redirect on an origin listed in [`REDIRECT_ORIGINS_ENV`].
    Configured,
    /// A native client's loopback listener (RFC 8252 §7.3), e.g. OpenAI Codex.
    Loopback,
}

/// The operator's extra redirect origins ([`REDIRECT_ORIGINS_ENV`]). EMPTY in
/// every `AppState` constructor and when the variable is unset or blank, which
/// keeps the built-in classes only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedirectOrigins(Vec<Origin>);

impl RedirectOrigins {
    /// Parse a comma- or whitespace-separated list of origins. Each entry must
    /// be exactly an origin: `https`, a host, an optional port, and nothing
    /// else (no path other than `/`, no query, fragment or userinfo, no `*`).
    /// A default port is normalised away, so `https://a.example:443` and
    /// `https://a.example` are one origin. Repeats are dropped.
    ///
    /// # Errors
    /// The first entry that is not such an origin, named, with the reason. A
    /// boot that gets this error must refuse to start rather than drop the
    /// entry, so a typo never silently narrows or widens the allowlist.
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        let mut out: Vec<Origin> = Vec::new();
        for entry in raw
            .unwrap_or_default()
            .split(|c: char| c == ',' || c.is_whitespace())
            .map(str::trim)
            .filter(|e| !e.is_empty())
        {
            let origin = parse_origin(entry)
                .map_err(|why| format!("{REDIRECT_ORIGINS_ENV}: {entry:?} {why}"))?;
            if !out.contains(&origin) {
                out.push(origin);
            }
        }
        Ok(Self(out))
    }

    /// [`Self::parse`] of [`REDIRECT_ORIGINS_ENV`]. For a binary's boot only.
    ///
    /// # Errors
    /// As [`Self::parse`].
    pub fn from_env() -> Result<Self, String> {
        Self::parse(std::env::var(REDIRECT_ORIGINS_ENV).ok().as_deref())
    }

    /// The configured origins, serialised (`https://host[:port]`), in order.
    #[must_use]
    pub fn to_strings(&self) -> Vec<String> {
        self.0.iter().map(Origin::ascii_serialization).collect()
    }

    /// Whether `uri` is an `https` URL on one of the configured origins, with
    /// no userinfo and no fragment.
    #[must_use]
    pub fn admits(&self, uri: &str) -> bool {
        if self.0.is_empty() {
            return false;
        }
        let Ok(url) = Url::parse(uri) else {
            return false;
        };
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && self.0.contains(&url.origin())
    }
}

/// One configured entry as an origin, or why it is not one.
fn parse_origin(entry: &str) -> Result<Origin, &'static str> {
    if entry.contains('*') {
        return Err("is a wildcard; list each origin exactly");
    }
    let url = Url::parse(entry).map_err(|_| "is not a URL")?;
    if url.scheme() != "https" {
        return Err("is not https (loopback redirects are built in; nothing else may be http)");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("carries userinfo");
    }
    if url.host().is_none() {
        return Err("has no host");
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err("is not an origin (no path, query or fragment: scheme://host[:port])");
    }
    Ok(url.origin())
}

/// The class of `uri`, or `None` when EpiGraph does not accept it as a
/// redirect. `extra` is the operator's [`RedirectOrigins`].
pub fn classify(uri: &str, extra: &RedirectOrigins) -> Option<RedirectClass> {
    if HOSTED_PREFIXES.iter().any(|p| uri.starts_with(p)) {
        return Some(RedirectClass::Hosted);
    }
    if extra.admits(uri) {
        return Some(RedirectClass::Configured);
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

    fn none() -> RedirectOrigins {
        RedirectOrigins::default()
    }

    fn partner() -> RedirectOrigins {
        RedirectOrigins::parse(Some(
            "https://partner.example.test, https://app.example.test:8443",
        ))
        .expect("valid origins")
    }

    /// An operator-listed origin admits any https callback path on exactly
    /// that origin (scheme, host, port); the defaults are unchanged beside it.
    #[test]
    fn a_configured_origin_is_accepted() {
        let extra = partner();
        for uri in [
            "https://partner.example.test/oauth/callback",
            "https://partner.example.test:443/cb?x=1",
            "https://PARTNER.example.test/cb",
            "https://app.example.test:8443/auth/callback",
        ] {
            assert_eq!(
                classify(uri, &extra),
                Some(RedirectClass::Configured),
                "{uri}"
            );
        }
        assert_eq!(
            classify("https://claude.ai/api/mcp/auth_callback", &extra),
            Some(RedirectClass::Hosted)
        );
        assert_eq!(
            classify("http://127.0.0.1:5000/cb", &extra),
            Some(RedirectClass::Loopback)
        );
        // Not configured, not accepted.
        assert_eq!(
            classify("https://partner.example.test/oauth/callback", &none()),
            None
        );
    }

    /// Only the exact origin: no suffix or prefix host, no userinfo trick, no
    /// other scheme or port, no subdomain, no fragment.
    #[test]
    fn configured_origin_lookalikes_are_refused() {
        let extra = partner();
        for uri in [
            "https://partner.example.test.evil.test/cb",
            "https://evilpartner.example.test/cb",
            "https://sub.partner.example.test/cb",
            "https://partner.example.test@evil.test/cb",
            "https://user@partner.example.test/cb",
            "http://partner.example.test/cb",
            "https://partner.example.test:8443/cb",
            "https://app.example.test/cb",
            "https://partner.example.test/cb#frag",
            "https://other.example.test/cb",
            "partner.example.test/cb",
        ] {
            assert_eq!(classify(uri, &extra), None, "{uri}");
        }
    }

    /// A configured entry is exactly an https origin; anything else is an
    /// error naming the entry (the boot refuses to start on it).
    #[test]
    fn a_configured_entry_must_be_an_https_origin() {
        for bad in [
            "https://*.example.test",
            "*",
            "http://partner.example.test",
            "https://partner.example.test/cb",
            "https://partner.example.test/?q=1",
            "https://partner.example.test/#f",
            "https://user:pw@partner.example.test",
            "partner.example.test",
            "ftp://partner.example.test",
        ] {
            let err = RedirectOrigins::parse(Some(bad)).expect_err(bad);
            assert!(err.contains(REDIRECT_ORIGINS_ENV), "{bad}: {err}");
        }
        assert_eq!(RedirectOrigins::parse(None), Ok(none()));
        assert_eq!(RedirectOrigins::parse(Some(" , ")), Ok(none()));
        let parsed = RedirectOrigins::parse(Some(
            "https://a.example.test:443/ https://a.example.test https://b.example.test:8443",
        ))
        .expect("valid");
        assert_eq!(
            parsed.to_strings(),
            vec![
                "https://a.example.test".to_string(),
                "https://b.example.test:8443".to_string()
            ]
        );
    }

    #[test]
    fn codex_callbacks_are_loopback() {
        for uri in [
            "http://127.0.0.1:53682/callback/Xq3vT0aBk9Lm",
            "http://127.0.0.1/callback/Xq3vT0aBk9Lm",
            "http://[::1]:53682/callback",
        ] {
            assert_eq!(
                classify(uri, &none()),
                Some(RedirectClass::Loopback),
                "{uri}"
            );
        }
        assert_eq!(
            classify("https://claude.ai/api/mcp/auth_callback", &none()),
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
            assert_eq!(classify(uri, &none()), None, "{uri}");
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
