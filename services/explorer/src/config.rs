//! Environment configuration (plan §3.2).
//!
//! Every knob is read once at startup by [`Config::from_env`]. Parsing goes
//! through [`Config::from_lookup`] so tests can feed a map instead of mutating
//! the process environment.

use std::time::Duration;

use thiserror::Error;
use url::Url;

pub const ENV_API_URL: &str = "EPIGRAPH_API_URL";
pub const ENV_PORT: &str = "EPIGRAPH_EXPLORER_PORT";
pub const ENV_PUBLIC_BASE_URL: &str = "EPIGRAPH_EXPLORER_PUBLIC_BASE_URL";
pub const ENV_OAUTH_BASE_URL: &str = "EPIGRAPH_OAUTH_BASE_URL";
pub const ENV_CLIENT_ID: &str = "EPIGRAPH_EXPLORER_CLIENT_ID";
pub const ENV_PUBLIC_UNFURL: &str = "EPIGRAPH_EXPLORER_PUBLIC_UNFURL";
pub const ENV_FRAME_ANCESTORS: &str = "EPIGRAPH_EXPLORER_FRAME_ANCESTORS";
pub const ENV_UPSTREAM_CONCURRENCY: &str = "EPIGRAPH_EXPLORER_UPSTREAM_CONCURRENCY";
pub const ENV_UPSTREAM_TIMEOUT_MS: &str = "EPIGRAPH_EXPLORER_UPSTREAM_TIMEOUT_MS";
pub const ENV_INSECURE_COOKIES: &str = "EPIGRAPH_EXPLORER_INSECURE_COOKIES";
pub const ENV_DEV_BEARER: &str = "EPIGRAPH_EXPLORER_DEV_BEARER";

pub const DEFAULT_API_URL: &str = "http://127.0.0.1:8080";
pub const DEFAULT_PORT: u16 = 8096;
pub const DEFAULT_FRAME_ANCESTORS: &str =
    "https://www.notion.so https://*.notion.so https://*.notion.site";
pub const DEFAULT_UPSTREAM_CONCURRENCY: usize = 6;
pub const DEFAULT_UPSTREAM_TIMEOUT_MS: u64 = 8000;

/// Clamp range for the upstream semaphore. The API's pool is 10 connections
/// shared with every other client, so the ceiling stays well under it.
pub const UPSTREAM_CONCURRENCY_RANGE: (usize, usize) = (1, 8);
/// Clamp range for the per-call upstream timeout, in milliseconds.
pub const UPSTREAM_TIMEOUT_MS_RANGE: (u64, u64) = (250, 60_000);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{0} is required")]
    Missing(&'static str),
    #[error("{var} is invalid: {reason}")]
    Invalid { var: &'static str, reason: String },
}

fn invalid(var: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        var,
        reason: reason.into(),
    }
}

/// Validated runtime configuration. Cheap to share behind an `Arc`.
#[derive(Clone)]
pub struct Config {
    /// epigraph-api origin the BFF calls server-to-server.
    pub api_url: Url,
    /// Loopback port to bind (`127.0.0.1:<port>`).
    pub port: u16,
    /// The full public URL, e.g. `https://explorer.example.com/explorer`.
    pub public_base_url: Url,
    /// Scheme + host (+ non-default port) of `public_base_url`, no trailing slash.
    pub public_origin: String,
    /// Path component of `public_base_url` without a trailing slash: `""` or
    /// `"/explorer"`. Every generated link, redirect and cookie `Path` uses it.
    pub base_path: String,
    /// Browser-facing OAuth authorization server origin.
    pub oauth_base_url: Url,
    /// Pre-registered OAuth client id; `None` disables sign-in.
    pub client_id: Option<String>,
    /// Render OG text for anonymous `/claim/:id` from an anonymous upstream read.
    pub public_unfurl: bool,
    /// CSP `frame-ancestors` source list.
    pub frame_ancestors: String,
    /// Global upstream semaphore size.
    pub upstream_concurrency: usize,
    /// Per-call upstream timeout.
    pub upstream_timeout: Duration,
    /// Drop `Secure` from the session cookie (plain-http local dev only).
    pub insecure_cookies: bool,
    /// Dev-only bearer used for every anonymous request (localhost only).
    pub dev_bearer: Option<String>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("api_url", &self.api_url.as_str())
            .field("port", &self.port)
            .field("public_base_url", &self.public_base_url.as_str())
            .field("base_path", &self.base_path)
            .field("oauth_base_url", &self.oauth_base_url.as_str())
            .field("client_id", &self.client_id)
            .field("public_unfurl", &self.public_unfurl)
            .field("frame_ancestors", &self.frame_ancestors)
            .field("upstream_concurrency", &self.upstream_concurrency)
            .field("upstream_timeout", &self.upstream_timeout)
            .field("insecure_cookies", &self.insecure_cookies)
            .field("dev_bearer", &self.dev_bearer.as_ref().map(|_| "<set>"))
            .finish()
    }
}

impl Config {
    /// Read and validate the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Read and validate configuration from an arbitrary lookup. Empty and
    /// whitespace-only values count as unset.
    pub fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let get = |k: &str| {
            lookup(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        let api_url = match get(ENV_API_URL) {
            Some(v) => parse_http_url(ENV_API_URL, &v)?,
            None => Url::parse(DEFAULT_API_URL).expect("default API URL parses"),
        };

        let port = match get(ENV_PORT) {
            Some(v) => match v.parse::<u16>() {
                Ok(0) | Err(_) => return Err(invalid(ENV_PORT, "expected a port in 1..=65535")),
                Ok(p) => p,
            },
            None => DEFAULT_PORT,
        };

        let raw_public =
            get(ENV_PUBLIC_BASE_URL).ok_or(ConfigError::Missing(ENV_PUBLIC_BASE_URL))?;
        let public_base_url = parse_http_url(ENV_PUBLIC_BASE_URL, &raw_public)?;
        if public_base_url.query().is_some() || public_base_url.fragment().is_some() {
            return Err(invalid(
                ENV_PUBLIC_BASE_URL,
                "must not carry a query string or fragment",
            ));
        }
        let base_path = normalize_base_path(public_base_url.path())
            .map_err(|reason| invalid(ENV_PUBLIC_BASE_URL, reason))?;
        reject_reserved_base_path(&base_path)?;
        let public_origin = public_base_url.origin().ascii_serialization();

        let oauth_base_url = match get(ENV_OAUTH_BASE_URL) {
            Some(v) => parse_http_url(ENV_OAUTH_BASE_URL, &v)?,
            None => api_url.clone(),
        };

        let client_id = match get(ENV_CLIENT_ID) {
            Some(v) if v.chars().any(|c| c.is_whitespace() || c.is_control()) => {
                return Err(invalid(ENV_CLIENT_ID, "must not contain whitespace"))
            }
            other => other,
        };

        let public_unfurl = parse_bool(ENV_PUBLIC_UNFURL, get(ENV_PUBLIC_UNFURL), false)?;
        let insecure_cookies = parse_bool(ENV_INSECURE_COOKIES, get(ENV_INSECURE_COOKIES), false)?;

        let frame_ancestors = match lookup(ENV_FRAME_ANCESTORS) {
            // Explicitly empty means "no framing at all".
            Some(v) if v.trim().is_empty() => "'none'".to_string(),
            Some(v) => validate_frame_ancestors(v.trim())?,
            None => DEFAULT_FRAME_ANCESTORS.to_string(),
        };

        let upstream_concurrency = match get(ENV_UPSTREAM_CONCURRENCY) {
            Some(v) => {
                let n = v.parse::<usize>().map_err(|_| {
                    invalid(ENV_UPSTREAM_CONCURRENCY, "expected a positive integer")
                })?;
                clamp_logged(ENV_UPSTREAM_CONCURRENCY, n, UPSTREAM_CONCURRENCY_RANGE)
            }
            None => DEFAULT_UPSTREAM_CONCURRENCY,
        };

        let timeout_ms = match get(ENV_UPSTREAM_TIMEOUT_MS) {
            Some(v) => {
                let n = v.parse::<u64>().map_err(|_| {
                    invalid(
                        ENV_UPSTREAM_TIMEOUT_MS,
                        "expected milliseconds as an integer",
                    )
                })?;
                clamp_logged(ENV_UPSTREAM_TIMEOUT_MS, n, UPSTREAM_TIMEOUT_MS_RANGE)
            }
            None => DEFAULT_UPSTREAM_TIMEOUT_MS,
        };

        let dev_bearer = get(ENV_DEV_BEARER);
        if dev_bearer.is_some() && !is_loopback_host(&public_base_url) {
            return Err(invalid(
                ENV_DEV_BEARER,
                "refused: only allowed when the public base URL host is localhost or 127.0.0.1",
            ));
        }

        Ok(Config {
            api_url,
            port,
            public_base_url,
            public_origin,
            base_path,
            oauth_base_url,
            client_id,
            public_unfurl,
            frame_ancestors,
            upstream_concurrency,
            upstream_timeout: Duration::from_millis(timeout_ms),
            insecure_cookies,
            dev_bearer,
        })
    }

    /// Cookie `Path` attribute: the base path, or `/` at the root.
    pub fn cookie_path(&self) -> &str {
        if self.base_path.is_empty() {
            "/"
        } else {
            &self.base_path
        }
    }

    /// Whether the session cookie carries `Secure`.
    pub fn cookie_secure(&self) -> bool {
        !self.insecure_cookies
    }

    /// The exact OAuth `redirect_uri` registered upstream.
    pub fn redirect_uri(&self) -> String {
        format!("{}{}/auth/callback", self.public_origin, self.base_path)
    }
}

fn parse_http_url(var: &'static str, raw: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(raw).map_err(|e| invalid(var, e.to_string()))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(invalid(var, "scheme must be http or https"));
    }
    if url.host_str().is_none() {
        return Err(invalid(var, "must include a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(var, "must not embed credentials"));
    }
    Ok(url)
}

/// `"/"` → `""`, `"/explorer/"` → `"/explorer"`. Segments are restricted to
/// RFC 3986 unreserved characters so the path is safe verbatim in routes,
/// links and the cookie `Path` attribute.
fn normalize_base_path(path: &str) -> Result<String, String> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    for segment in trimmed.split('/').skip(1) {
        if segment.is_empty() {
            return Err("base path must not contain empty segments".into());
        }
        if segment == "." || segment == ".." {
            return Err("base path must not contain dot segments".into());
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
        {
            return Err(format!(
                "base path segment {segment:?} may only use letters, digits, '-', '_', '.', '~'"
            ));
        }
    }
    Ok(trimmed.to_string())
}

/// Refuse a base path whose first segment is also a top-level route name.
///
/// `app::build_app_with` mounts the routes nested under the base path *and*
/// at the root, so `/search` as a base path makes both claim `GET /search`
/// and axum panics while building the router. A panic exits 101, which the
/// systemd unit's `RestartPreventExitStatus=2` cannot distinguish from a
/// crash, so it restart-loops on what is really a config typo. Catching it
/// here turns it into an ordinary `ConfigError::Invalid` → exit 2 with a
/// message naming the offending segment.
fn reject_reserved_base_path(base_path: &str) -> Result<(), ConfigError> {
    let Some(first) = base_path.split('/').nth(1) else {
        return Ok(()); // root base path: nothing to collide with
    };
    if crate::app::RESERVED_BASE_PATH_SEGMENTS.contains(&first) {
        return Err(invalid(
            ENV_PUBLIC_BASE_URL,
            format!(
                "base path may not start with {first:?}: it is one of the Explorer's own \
                 top-level routes ({}). Pick another prefix, e.g. /explorer",
                crate::app::RESERVED_BASE_PATH_SEGMENTS.join(", ")
            ),
        ));
    }
    Ok(())
}

fn parse_bool(var: &'static str, raw: Option<String>, default: bool) -> Result<bool, ConfigError> {
    match raw.as_deref().map(str::to_ascii_lowercase).as_deref() {
        None => Ok(default),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(_) => Err(invalid(var, "expected true or false")),
    }
}

/// Source expressions go verbatim into a response header, so reject anything
/// that could terminate the directive or the header.
fn validate_frame_ancestors(raw: &str) -> Result<String, ConfigError> {
    if raw
        .chars()
        .any(|c| c == ';' || c == ',' || c.is_control() || !c.is_ascii())
    {
        return Err(invalid(
            ENV_FRAME_ANCESTORS,
            "must be a space-separated CSP source list without ';' or ','",
        ));
    }
    Ok(raw.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn clamp_logged<T: Ord + Copy + std::fmt::Display>(var: &str, value: T, (lo, hi): (T, T)) -> T {
    let clamped = value.clamp(lo, hi);
    if clamped != value {
        tracing::warn!(%var, requested = %value, used = %clamped, "config value clamped");
    }
    clamped
}

fn is_loopback_host(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost") | Some("127.0.0.1"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|k| map.get(k).cloned())
    }

    const BASE: (&str, &str) = (ENV_PUBLIC_BASE_URL, "https://explorer.example.com/explorer");

    #[test]
    fn public_base_url_is_required() {
        assert_eq!(
            cfg(&[]).unwrap_err(),
            ConfigError::Missing(ENV_PUBLIC_BASE_URL)
        );
        assert_eq!(
            cfg(&[(ENV_PUBLIC_BASE_URL, "   ")]).unwrap_err(),
            ConfigError::Missing(ENV_PUBLIC_BASE_URL)
        );
    }

    #[test]
    fn defaults_apply() {
        let c = cfg(&[BASE]).unwrap();
        assert_eq!(c.api_url.as_str(), "http://127.0.0.1:8080/");
        assert_eq!(c.port, 8096);
        assert_eq!(c.oauth_base_url, c.api_url);
        assert_eq!(c.client_id, None);
        assert!(!c.public_unfurl);
        assert_eq!(c.frame_ancestors, DEFAULT_FRAME_ANCESTORS);
        assert_eq!(c.upstream_concurrency, 6);
        assert_eq!(c.upstream_timeout, Duration::from_millis(8000));
        assert!(!c.insecure_cookies);
        assert!(c.cookie_secure());
        assert_eq!(c.dev_bearer, None);
    }

    #[test]
    fn base_url_splits_into_origin_and_path() {
        let c = cfg(&[BASE]).unwrap();
        assert_eq!(c.public_origin, "https://explorer.example.com");
        assert_eq!(c.base_path, "/explorer");
        assert_eq!(c.cookie_path(), "/explorer");
        assert_eq!(
            c.redirect_uri(),
            "https://explorer.example.com/explorer/auth/callback"
        );

        let c = cfg(&[(ENV_PUBLIC_BASE_URL, "https://explorer.example.com/a/b/")]).unwrap();
        assert_eq!(c.base_path, "/a/b");

        let c = cfg(&[(ENV_PUBLIC_BASE_URL, "http://localhost:8096")]).unwrap();
        assert_eq!(c.public_origin, "http://localhost:8096");
        assert_eq!(c.base_path, "");
        assert_eq!(c.cookie_path(), "/");
        assert_eq!(c.redirect_uri(), "http://localhost:8096/auth/callback");
    }

    #[test]
    fn bad_public_base_urls_are_rejected() {
        for bad in [
            "explorer.example.com/explorer",
            "ftp://explorer.example.com/",
            "https://explorer.example.com/explorer?x=1",
            "https://explorer.example.com/explorer#top",
            "https://user:pw@explorer.example.com/",
            "https://explorer.example.com/ex%20plorer",
            "https://explorer.example.com//explorer",
        ] {
            let err = cfg(&[(ENV_PUBLIC_BASE_URL, bad)]).unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::Invalid {
                        var: ENV_PUBLIC_BASE_URL,
                        ..
                    }
                ),
                "{bad} gave {err:?}"
            );
        }
    }

    /// A base path that collides with a top-level route used to panic inside
    /// `build_app` (exit 101), which `RestartPreventExitStatus=2` cannot tell
    /// from a crash. It must be a config error instead.
    #[test]
    fn base_path_may_not_shadow_a_top_level_route() {
        for seg in crate::app::RESERVED_BASE_PATH_SEGMENTS {
            let url = format!("https://explorer.example.com/{seg}");
            let err = match cfg(&[(ENV_PUBLIC_BASE_URL, &url)]) {
                Err(e) => e,
                Ok(_) => panic!("{url} must be refused, not accepted"),
            };
            match &err {
                ConfigError::Invalid { var, reason } => {
                    assert_eq!(*var, ENV_PUBLIC_BASE_URL);
                    assert!(reason.contains(seg), "{reason}");
                }
                other => panic!("{url} gave {other:?}"),
            }
            // Only the FIRST segment can collide.
            let nested = format!("https://explorer.example.com/explorer/{seg}");
            assert_eq!(
                cfg(&[(ENV_PUBLIC_BASE_URL, &nested)]).unwrap().base_path,
                format!("/explorer/{seg}")
            );
        }
        // The ordinary prefixes still work.
        for ok in [
            "https://explorer.example.com/explorer",
            "http://localhost:8096",
        ] {
            assert!(cfg(&[(ENV_PUBLIC_BASE_URL, ok)]).is_ok(), "{ok}");
        }
    }

    #[test]
    fn dev_bearer_requires_loopback_host() {
        let err = cfg(&[BASE, (ENV_DEV_BEARER, "tok")]).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: ENV_DEV_BEARER,
                ..
            }
        ));

        for ok in ["http://localhost:8096", "http://127.0.0.1:8096/explorer"] {
            let c = cfg(&[(ENV_PUBLIC_BASE_URL, ok), (ENV_DEV_BEARER, "tok")]).unwrap();
            assert_eq!(c.dev_bearer.as_deref(), Some("tok"));
        }
        // A look-alike host is not loopback.
        let err = cfg(&[
            (ENV_PUBLIC_BASE_URL, "http://localhost.example.com"),
            (ENV_DEV_BEARER, "tok"),
        ])
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: ENV_DEV_BEARER,
                ..
            }
        ));
    }

    #[test]
    fn numeric_knobs_are_clamped() {
        let c = cfg(&[
            BASE,
            (ENV_UPSTREAM_CONCURRENCY, "500"),
            (ENV_UPSTREAM_TIMEOUT_MS, "1"),
        ])
        .unwrap();
        assert_eq!(c.upstream_concurrency, UPSTREAM_CONCURRENCY_RANGE.1);
        assert_eq!(
            c.upstream_timeout,
            Duration::from_millis(UPSTREAM_TIMEOUT_MS_RANGE.0)
        );

        let c = cfg(&[BASE, (ENV_UPSTREAM_CONCURRENCY, "0")]).unwrap();
        assert_eq!(c.upstream_concurrency, 1);

        let c = cfg(&[BASE, (ENV_UPSTREAM_TIMEOUT_MS, "999999")]).unwrap();
        assert_eq!(
            c.upstream_timeout,
            Duration::from_millis(UPSTREAM_TIMEOUT_MS_RANGE.1)
        );
    }

    #[test]
    fn malformed_numbers_and_bools_are_errors() {
        for (var, val) in [
            (ENV_UPSTREAM_CONCURRENCY, "six"),
            (ENV_UPSTREAM_TIMEOUT_MS, "-5"),
            (ENV_PORT, "0"),
            (ENV_PORT, "70000"),
            (ENV_PUBLIC_UNFURL, "maybe"),
            (ENV_INSECURE_COOKIES, "2"),
        ] {
            let err = cfg(&[BASE, (var, val)]).unwrap_err();
            assert!(
                matches!(&err, ConfigError::Invalid { var: v, .. } if *v == var),
                "{var}={val} gave {err:?}"
            );
        }
    }

    #[test]
    fn bools_parse() {
        let c = cfg(&[
            BASE,
            (ENV_PUBLIC_UNFURL, "TRUE"),
            (ENV_INSECURE_COOKIES, "1"),
        ])
        .unwrap();
        assert!(c.public_unfurl);
        assert!(c.insecure_cookies);
        assert!(!c.cookie_secure());
    }

    #[test]
    fn frame_ancestors_validated() {
        let c = cfg(&[
            BASE,
            (ENV_FRAME_ANCESTORS, "  'self'   https://a.example.com "),
        ])
        .unwrap();
        assert_eq!(c.frame_ancestors, "'self' https://a.example.com");

        let c = cfg(&[BASE, (ENV_FRAME_ANCESTORS, "")]).unwrap();
        assert_eq!(c.frame_ancestors, "'none'");

        for bad in ["'self'; script-src *", "a\r\nX-Evil: 1", "a, b"] {
            let err = cfg(&[BASE, (ENV_FRAME_ANCESTORS, bad)]).unwrap_err();
            assert!(matches!(
                err,
                ConfigError::Invalid {
                    var: ENV_FRAME_ANCESTORS,
                    ..
                }
            ));
        }
    }

    #[test]
    fn urls_and_client_id_validated() {
        let c = cfg(&[
            BASE,
            (ENV_API_URL, "http://api.example.com:9000"),
            (ENV_OAUTH_BASE_URL, "https://api.example.com"),
            (ENV_CLIENT_ID, "epigraph_explorer_abc"),
        ])
        .unwrap();
        assert_eq!(c.api_url.as_str(), "http://api.example.com:9000/");
        assert_eq!(c.oauth_base_url.as_str(), "https://api.example.com/");
        assert_eq!(c.client_id.as_deref(), Some("epigraph_explorer_abc"));

        assert!(cfg(&[BASE, (ENV_API_URL, "not a url")]).is_err());
        assert!(cfg(&[BASE, (ENV_CLIENT_ID, "a b")]).is_err());
    }

    #[test]
    fn debug_hides_dev_bearer() {
        let c = cfg(&[
            (ENV_PUBLIC_BASE_URL, "http://localhost:8096"),
            (ENV_DEV_BEARER, "super-secret-token"),
        ])
        .unwrap();
        let shown = format!("{c:?}");
        assert!(!shown.contains("super-secret-token"));
        assert!(shown.contains("<set>"));
    }
}
