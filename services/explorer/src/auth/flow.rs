//! Short-lived sign-in state (plan §3.3): pending logins, embed handoff
//! codes, the pre-auth cookie that binds a login to its browser, and the
//! `return_to` check that keeps every post-login redirect on this site.

use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderValue};
use cookie::{Cookie, SameSite};
use url::Url;

use super::session::{read_cookie, SessionId};
use crate::config::Config;
use crate::links::Links;
use crate::ttl::TtlMap;

/// Upstream's authorize session lives 10 minutes; ours need not outlive it.
pub const PENDING_LOGIN_TTL: Duration = Duration::from_secs(10 * 60);
/// Embed handoff codes are single-use and live 60 s.
pub const HANDOFF_TTL: Duration = Duration::from_secs(60);
/// Pending logins held at once. Each is a few hundred bytes and anyone can
/// start one, so the map is capped rather than left to grow for 10 minutes.
pub const MAX_PENDING_LOGINS: usize = 10_000;

/// Binds a pending login to the browser that started it, so a callback URL
/// replayed into another browser (login CSRF) is refused. `Path={base}/auth`,
/// `SameSite=Lax` (the callback is a top-level GET navigation back from the
/// API origin, which Lax allows), 10-minute max-age.
pub const PRE_AUTH_COOKIE: &str = "epx_login";
/// Longest `return_to` accepted.
const MAX_RETURN_TO: usize = 2048;

/// Between `/auth/login` and `/auth/callback`, keyed by OAuth `state`.
#[derive(Clone, Debug)]
pub struct PendingLogin {
    pub pkce_verifier: String,
    /// Browser-visible local path to land on after sign-in (already passed
    /// through [`safe_return_to`]).
    pub return_to: String,
    /// `mode=popup` (embed sign-in): the callback posts a handoff code to
    /// `window.opener` instead of setting a first-party cookie.
    pub popup: bool,
    /// Value of the [`PRE_AUTH_COOKIE`] the login was started with.
    pub binding: String,
    pub created_at: Instant,
}

/// A popup-issued code the iframe redeems at `POST /auth/redeem`.
#[derive(Clone, Debug)]
pub struct Handoff {
    pub session_id: SessionId,
}

#[derive(Clone, Default)]
pub struct FlowState {
    /// OAuth `state` → pending login. Use `take` (single use).
    pub pending: TtlMap<String, PendingLogin>,
    /// Handoff code → session. Use `take` (single use).
    pub handoffs: TtlMap<String, Handoff>,
}

impl FlowState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop expired pending logins and handoff codes (run by the
    /// housekeeping task in `app.rs`).
    pub fn purge_expired(&self) -> usize {
        self.pending.purge_expired() + self.handoffs.purge_expired()
    }
}

/// A value shaped like [`crate::auth::random_token`]`(32)`: 43 base64url
/// characters. OAuth `state`, the pre-auth binding and handoff codes are all
/// this shape, so anything else is refused before it reaches a map.
pub fn is_token_shaped(raw: &str) -> bool {
    raw.len() == 43
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `Set-Cookie` for the pre-auth binding.
pub fn pre_auth_cookie(config: &Config, binding: &str) -> HeaderValue {
    let mut c = Cookie::new(PRE_AUTH_COOKIE, binding.to_string());
    c.set_path(format!("{}/auth", config.base_path));
    c.set_http_only(true);
    c.set_same_site(SameSite::Lax);
    c.set_secure(config.cookie_secure());
    c.set_max_age(cookie::time::Duration::seconds(
        PENDING_LOGIN_TTL.as_secs() as i64
    ));
    HeaderValue::from_str(&c.to_string()).expect("cookie built from validated parts")
}

/// The pre-auth binding from the request, if well-formed.
pub fn read_pre_auth_cookie(headers: &HeaderMap) -> Option<String> {
    read_cookie(headers, PRE_AUTH_COOKIE).filter(|v| is_token_shaped(v))
}

/// `raw` if it is a safe post-login destination, else the home page.
pub fn safe_return_to(links: &Links, raw: Option<&str>) -> String {
    match raw.map(str::trim).filter(|r| !r.is_empty()) {
        Some(r) => validate_return_to(links, r).unwrap_or_else(|| {
            tracing::debug!(return_to = %r, "unsafe return_to replaced with home");
            links.home()
        }),
        None => links.home(),
    }
}

/// Accept only a browser-visible path (+ query) on this site, under the
/// base path, outside `/auth/`. The result goes into a `Location` header
/// and a `data-` attribute, so the check is deliberately narrow:
///
/// - printable ASCII only (no whitespace, control characters or CR/LF);
/// - a single leading `/` (`//host` and `/\host` are scheme-relative to
///   browsers) and no `\` anywhere;
/// - after percent-decoding the path once, still no `\`, control
///   characters, leading `//`, or `.`/`..` segments (`/explorer/%2e%2e/x`);
/// - both the raw and the decoded path under the base path;
/// - and, belt and braces, resolving it against the public origin must not
///   change the origin.
pub fn validate_return_to(links: &Links, raw: &str) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_RETURN_TO {
        return None;
    }
    if !raw.bytes().all(|b| (0x21..=0x7e).contains(&b)) || raw.contains('\\') {
        return None;
    }
    let bytes = raw.as_bytes();
    if bytes[0] != b'/' || bytes.get(1) == Some(&b'/') {
        return None;
    }

    let raw_path = raw.split(['?', '#']).next().unwrap_or("");
    let decoded = percent_decode(raw_path)?;
    if decoded.starts_with("//")
        || decoded
            .bytes()
            .any(|b| b == b'\\' || b.is_ascii_control() || b == b' ')
        || decoded.split('/').any(|seg| seg == "." || seg == "..")
    {
        return None;
    }

    let base = links.base_path();
    for p in [raw_path, decoded.as_str()] {
        let rest = if base.is_empty() {
            p
        } else {
            match p.strip_prefix(base) {
                Some(rest) if rest.is_empty() || rest.starts_with('/') => rest,
                _ => return None,
            }
        };
        if rest == "/auth" || rest.starts_with("/auth/") {
            return None;
        }
    }

    let origin = links.absolute("");
    let resolved = Url::parse(&origin).ok()?.join(raw).ok()?;
    if resolved.origin().ascii_serialization() != origin {
        return None;
    }
    Some(raw.to_string())
}

/// Decode `%XX` escapes once. `None` on a malformed escape or when the
/// result is not UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ENV_INSECURE_COOKIES, ENV_PUBLIC_BASE_URL};
    use std::collections::HashMap;

    fn links() -> Links {
        Links::new("https://explorer.example.com", "/explorer")
    }

    #[test]
    fn local_paths_under_the_base_are_kept() {
        let l = links();
        for ok in [
            "/explorer",
            "/explorer/",
            "/explorer/claim/0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10",
            "/explorer/search?q=a%20b&mode=label",
            "/explorer/claim/x?return=%2F%2Fnot-a-path-in-the-query",
            "/explorer/claim/x#section",
            "/explorer/authors",
        ] {
            assert_eq!(validate_return_to(&l, ok).as_deref(), Some(ok), "{ok}");
        }
    }

    #[test]
    fn open_redirects_and_tricks_are_refused() {
        let l = links();
        for bad in [
            "https://evil.example.net/",
            "http://explorer.example.com.evil.example.net/explorer/",
            "//evil.example.net/explorer/",
            "///evil.example.net",
            "/\\evil.example.net",
            "\\\\evil.example.net",
            "/explorer\\..\\evil",
            "javascript:alert(1)",
            "data:text/html,x",
            "explorer/claim/x",
            "/%2F%2Fevil.example.net",
            "/%2f%2fevil.example.net",
            "/%5Cevil.example.net",
            "/explorer/%5C%5Cevil",
            "/explorer/%2e%2e/evil",
            "/explorer/../evil",
            "/explorer/./claim",
            "/explorer/%0d%0aSet-Cookie:%20x=y",
            "/explorer/\r\nSet-Cookie: x=y",
            "/explorer/claim x",
            "/explorer/cl\u{e9}im",
            "/explorer/%ff",
            "/explorer/%zz",
            "/explorer/%2",
            "/explorers",
            "/explorer@evil.example.net",
            "/",
            "/claim/x",
            "/%65xplorer/claim",
            "/explorer/auth/login?return_to=/explorer/",
            "/explorer/auth",
            "/explorer/%61uth/callback",
            "",
        ] {
            assert_eq!(validate_return_to(&l, bad), None, "{bad:?} must be refused");
        }
        let long = format!("/explorer/{}", "a".repeat(MAX_RETURN_TO));
        assert_eq!(validate_return_to(&l, &long), None);
    }

    #[test]
    fn unsafe_values_fall_back_to_home() {
        let l = links();
        assert_eq!(safe_return_to(&l, None), "/explorer/");
        assert_eq!(safe_return_to(&l, Some("   ")), "/explorer/");
        assert_eq!(safe_return_to(&l, Some("//evil.example.net")), "/explorer/");
        assert_eq!(
            safe_return_to(&l, Some("/explorer/claim/x")),
            "/explorer/claim/x"
        );
    }

    #[test]
    fn root_base_path_accepts_any_local_path() {
        let l = Links::new("http://localhost:8096", "");
        assert_eq!(validate_return_to(&l, "/").as_deref(), Some("/"));
        assert_eq!(
            validate_return_to(&l, "/claim/x?y=1").as_deref(),
            Some("/claim/x?y=1")
        );
        for bad in ["//evil.example.net", "/auth/login", "/auth", "/\\x"] {
            assert_eq!(validate_return_to(&l, bad), None, "{bad}");
        }
    }

    #[test]
    fn pre_auth_cookie_attributes() {
        let map: HashMap<String, String> = [(
            ENV_PUBLIC_BASE_URL.to_string(),
            "https://explorer.example.com/explorer".to_string(),
        )]
        .into();
        let c = Config::from_lookup(|k| map.get(k).cloned()).unwrap();
        let binding = crate::auth::random_token(32);
        let v = pre_auth_cookie(&c, &binding).to_str().unwrap().to_string();
        assert!(v.starts_with(&format!("epx_login={binding}")), "{v}");
        for attr in [
            "HttpOnly",
            "SameSite=Lax",
            "Secure",
            "Path=/explorer/auth",
            "Max-Age=600",
        ] {
            assert!(v.contains(attr), "{attr} missing from {v}");
        }

        let map: HashMap<String, String> = [
            (
                ENV_PUBLIC_BASE_URL.to_string(),
                "http://localhost:8096".to_string(),
            ),
            (ENV_INSECURE_COOKIES.to_string(), "true".to_string()),
        ]
        .into();
        let c = Config::from_lookup(|k| map.get(k).cloned()).unwrap();
        let v = pre_auth_cookie(&c, &binding).to_str().unwrap().to_string();
        assert!(v.contains("Path=/auth") && !v.contains("Secure"), "{v}");
    }

    #[test]
    fn token_shape_is_strict() {
        assert!(is_token_shaped(&crate::auth::random_token(32)));
        assert!(!is_token_shaped("short"));
        assert!(!is_token_shaped(&"=".repeat(43)));
        assert!(!is_token_shaped(&"a".repeat(44)));
    }
}
