//! Parser for the `EPIGRAPH_MCP_EXTENSIONS` environment variable.
//!
//! The gateway mounts zero or more downstream extension MCP servers. Each is
//! described by one comma-separated entry; fields within an entry are
//! semicolon-separated:
//!
//! ```text
//! EPIGRAPH_MCP_EXTENSIONS="episcience=tcp:127.0.0.1:8093;scope=episcience:tools;prefix=episcience__"
//! ```
//!
//! Entry grammar (fields after the first are order-independent `key=value`):
//!
//! - **`name=tcp:host:port`** — REQUIRED, MUST be the first field. `name` is the
//!   extension's logical identifier; the value is a transport spec. v1 supports
//!   only the `tcp:` scheme (loopback TCP); the parsed `addr` is the bare
//!   `host:port` with the scheme stripped.
//! - **`scope=<oauth-scope>`** — REQUIRED. The OAuth scope a caller must hold for
//!   the gateway to forward any tool owned by this extension. Federated tools are
//!   deliberately NOT in the static `SCOPE_MAP` (whose coverage is compile-time),
//!   so this is the sole scope gate for them.
//! - **`prefix=<str>`** — OPTIONAL. Prepended to each federated tool name to
//!   avoid collisions with kernel tools or other extensions.
//!
//! Absent or empty env → [`Vec::new`] → empty registry → the gateway behaves
//! exactly as it does today (backward compatible). A malformed entry is a hard
//! error at parse time (fail fast at boot rather than silently drop an
//! extension).

use std::fmt;

/// The transport scheme prefix for the v1 loopback-TCP transport. UDS is a
/// documented fast-follow and is intentionally rejected here.
const TCP_SCHEME: &str = "tcp:";

/// Parsed configuration for one mounted downstream extension MCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionConfig {
    /// Logical name of the extension (e.g. `"episcience"`). Used in logs and,
    /// with the default prefix, to disambiguate tools.
    pub name: String,
    /// Bare `host:port` the extension serves streamable-HTTP on (scheme
    /// stripped). v1 is always loopback TCP; the gateway dials
    /// `http://{addr}/mcp`.
    pub addr: String,
    /// OAuth scope a caller must hold for the gateway to forward this
    /// extension's tools.
    pub scope: String,
    /// Optional tool-name prefix to avoid collisions.
    pub prefix: Option<String>,
}

/// Failure while parsing `EPIGRAPH_MCP_EXTENSIONS`. Carries the offending entry
/// so the boot log points the operator straight at the typo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// The raw entry (or field) that failed to parse.
    pub entry: String,
    /// Human-readable reason.
    pub reason: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid EPIGRAPH_MCP_EXTENSIONS entry `{}`: {}",
            self.entry, self.reason
        )
    }
}

impl std::error::Error for ConfigError {}

/// Parse the value of `EPIGRAPH_MCP_EXTENSIONS`.
///
/// `None` (env unset) and `Some("")` / whitespace-only both yield an empty
/// vector. Otherwise every comma-separated entry is parsed; the first malformed
/// entry aborts with a [`ConfigError`].
///
/// # Errors
/// Returns [`ConfigError`] on the first malformed entry (unknown scheme,
/// missing required field, duplicate field, empty value, unknown key).
pub fn parse_extensions(raw: Option<&str>) -> Result<Vec<ExtensionConfig>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }

    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(parse_entry)
        .collect()
}

/// Parse a single comma-delimited entry into an [`ExtensionConfig`].
fn parse_entry(entry: &str) -> Result<ExtensionConfig, ConfigError> {
    let err = |reason: &str| ConfigError {
        entry: entry.to_string(),
        reason: reason.to_string(),
    };

    let mut fields = entry.split(';').map(str::trim).filter(|f| !f.is_empty());

    // First field MUST be `name=tcp:host:port`.
    let first = fields
        .next()
        .ok_or_else(|| err("entry is empty (expected `name=tcp:host:port`)"))?;
    let (name, transport) = first
        .split_once('=')
        .ok_or_else(|| err("first field must be `name=tcp:host:port`"))?;
    let name = name.trim();
    let transport = transport.trim();
    if name.is_empty() {
        return Err(err("extension name is empty"));
    }
    let addr = transport.strip_prefix(TCP_SCHEME).ok_or_else(|| {
        err("transport must use the `tcp:` scheme (v1 supports loopback TCP only)")
    })?;
    let addr = addr.trim();
    if addr.is_empty() {
        return Err(err("transport address (host:port) is empty"));
    }
    // Require an explicit `:port`. rmcp dials `http://{addr}/mcp`; without a
    // port the request would silently target port 80 (or fail), so reject at
    // boot rather than let a portless address slip through to the dial. The
    // check is deliberately syntactic (last segment after ':' is all digits) —
    // full socket-addr validation belongs to the Stage-2 dialer.
    match addr.rsplit_once(':') {
        Some((host, port))
            if !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
        }
        _ => {
            return Err(err(
                "transport address must be `host:port` with a numeric port (e.g. 127.0.0.1:8093)",
            ))
        }
    }

    // Remaining fields are order-independent `key=value` pairs.
    let mut scope: Option<String> = None;
    let mut prefix: Option<String> = None;
    for field in fields {
        let (key, value) = field
            .split_once('=')
            .ok_or_else(|| err(&format!("field `{field}` must be `key=value`")))?;
        let key = key.trim();
        let value = value.trim();
        if value.is_empty() {
            return Err(err(&format!("field `{key}` has an empty value")));
        }
        match key {
            "scope" => {
                if scope.is_some() {
                    return Err(err("duplicate `scope` field"));
                }
                scope = Some(value.to_string());
            }
            "prefix" => {
                if prefix.is_some() {
                    return Err(err("duplicate `prefix` field"));
                }
                prefix = Some(value.to_string());
            }
            other => {
                return Err(err(&format!(
                    "unknown field `{other}` (expected `scope` or `prefix`)"
                )));
            }
        }
    }

    let scope = scope.ok_or_else(|| err("missing required `scope` field"))?;

    Ok(ExtensionConfig {
        name: name.to_string(),
        addr: addr.to_string(),
        scope,
        prefix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_env_yields_empty() {
        assert_eq!(parse_extensions(None).unwrap(), Vec::new());
    }

    #[test]
    fn empty_and_whitespace_env_yields_empty() {
        assert_eq!(parse_extensions(Some("")).unwrap(), Vec::new());
        assert_eq!(parse_extensions(Some("   ")).unwrap(), Vec::new());
    }

    #[test]
    fn parses_single_extension_without_prefix() {
        let cfgs =
            parse_extensions(Some("episcience=tcp:127.0.0.1:8093;scope=episcience:tools")).unwrap();
        assert_eq!(
            cfgs,
            vec![ExtensionConfig {
                name: "episcience".into(),
                addr: "127.0.0.1:8093".into(),
                scope: "episcience:tools".into(),
                prefix: None,
            }]
        );
    }

    #[test]
    fn parses_single_extension_with_prefix() {
        let cfgs = parse_extensions(Some(
            "episcience=tcp:127.0.0.1:8093;scope=episcience:tools;prefix=episcience__",
        ))
        .unwrap();
        assert_eq!(
            cfgs,
            vec![ExtensionConfig {
                name: "episcience".into(),
                addr: "127.0.0.1:8093".into(),
                scope: "episcience:tools".into(),
                prefix: Some("episcience__".into()),
            }]
        );
    }

    #[test]
    fn parses_two_extensions_comma_separated() {
        let cfgs = parse_extensions(Some(
            "episcience=tcp:127.0.0.1:8093;scope=episcience:tools;prefix=episcience__,\
             foundry=tcp:127.0.0.1:8094;scope=foundry:tools",
        ))
        .unwrap();
        assert_eq!(cfgs.len(), 2);
        assert_eq!(cfgs[0].name, "episcience");
        assert_eq!(cfgs[0].prefix.as_deref(), Some("episcience__"));
        assert_eq!(cfgs[1].name, "foundry");
        assert_eq!(cfgs[1].addr, "127.0.0.1:8094");
        assert_eq!(cfgs[1].scope, "foundry:tools");
        assert_eq!(cfgs[1].prefix, None);
    }

    #[test]
    fn field_order_is_independent() {
        let cfgs = parse_extensions(Some(
            "episcience=tcp:127.0.0.1:8093;prefix=e__;scope=episcience:tools",
        ))
        .unwrap();
        assert_eq!(cfgs[0].scope, "episcience:tools");
        assert_eq!(cfgs[0].prefix.as_deref(), Some("e__"));
    }

    #[test]
    fn trailing_comma_and_extra_whitespace_tolerated() {
        let cfgs = parse_extensions(Some(
            "  episcience=tcp:127.0.0.1:8093 ; scope=episcience:tools ,",
        ))
        .unwrap();
        assert_eq!(cfgs.len(), 1);
        assert_eq!(cfgs[0].addr, "127.0.0.1:8093");
        assert_eq!(cfgs[0].scope, "episcience:tools");
    }

    #[test]
    fn missing_scope_is_error() {
        let err = parse_extensions(Some("episcience=tcp:127.0.0.1:8093")).unwrap_err();
        assert!(err.reason.contains("scope"), "got: {}", err.reason);
    }

    #[test]
    fn non_tcp_scheme_is_error() {
        let err = parse_extensions(Some("episcience=unix:/run/e.sock;scope=episcience:tools"))
            .unwrap_err();
        assert!(err.reason.contains("tcp:"), "got: {}", err.reason);
    }

    #[test]
    fn missing_transport_scheme_is_error() {
        let err =
            parse_extensions(Some("episcience=127.0.0.1:8093;scope=episcience:tools")).unwrap_err();
        assert!(err.reason.contains("tcp:"), "got: {}", err.reason);
    }

    #[test]
    fn empty_name_is_error() {
        let err = parse_extensions(Some("=tcp:127.0.0.1:8093;scope=x")).unwrap_err();
        assert!(err.reason.contains("name"), "got: {}", err.reason);
    }

    #[test]
    fn empty_addr_is_error() {
        let err = parse_extensions(Some("episcience=tcp:;scope=x")).unwrap_err();
        assert!(err.reason.contains("address"), "got: {}", err.reason);
    }

    #[test]
    fn addr_without_port_is_error() {
        let err = parse_extensions(Some("episcience=tcp:127.0.0.1;scope=x")).unwrap_err();
        assert!(err.reason.contains("numeric port"), "got: {}", err.reason);
    }

    #[test]
    fn addr_with_non_numeric_port_is_error() {
        let err = parse_extensions(Some("episcience=tcp:127.0.0.1:http;scope=x")).unwrap_err();
        assert!(err.reason.contains("numeric port"), "got: {}", err.reason);
    }

    #[test]
    fn unknown_field_is_error() {
        let err =
            parse_extensions(Some("episcience=tcp:127.0.0.1:8093;scope=x;bogus=1")).unwrap_err();
        assert!(err.reason.contains("bogus"), "got: {}", err.reason);
    }

    #[test]
    fn duplicate_scope_is_error() {
        let err =
            parse_extensions(Some("episcience=tcp:127.0.0.1:8093;scope=a;scope=b")).unwrap_err();
        assert!(err.reason.contains("duplicate"), "got: {}", err.reason);
    }

    #[test]
    fn empty_field_value_is_error() {
        let err = parse_extensions(Some("episcience=tcp:127.0.0.1:8093;scope=")).unwrap_err();
        assert!(err.reason.contains("empty"), "got: {}", err.reason);
    }

    #[test]
    fn field_without_equals_is_error() {
        let err =
            parse_extensions(Some("episcience=tcp:127.0.0.1:8093;scope=x;justakey")).unwrap_err();
        assert!(err.reason.contains("key=value"), "got: {}", err.reason);
    }

    #[test]
    fn display_includes_entry_and_reason() {
        let err = parse_extensions(Some("episcience=tcp:127.0.0.1:8093")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("EPIGRAPH_MCP_EXTENSIONS"), "got: {msg}");
        assert!(msg.contains("episcience=tcp:127.0.0.1:8093"), "got: {msg}");
    }
}
