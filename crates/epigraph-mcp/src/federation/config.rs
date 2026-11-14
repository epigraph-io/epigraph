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
//!   only the `tcp:` scheme (loopback TCP, see `insecure_remote` below); the
//!   parsed `addr` is the bare `host:port` with the scheme stripped. An IPv6
//!   host is bracketed (`tcp:[::1]:8093`).
//! - **`scope=<oauth-scope>`** — REQUIRED. The OAuth scope a caller must hold for
//!   the gateway to forward any tool owned by this extension. Federated tools are
//!   deliberately NOT in the static `SCOPE_MAP` (whose coverage is compile-time),
//!   so this is the sole scope gate for them.
//! - **`prefix=<str>`** — OPTIONAL. Prepended to each federated tool name to
//!   avoid collisions with kernel tools or other extensions.
//! - **`insecure_remote=1`** — OPTIONAL, and the only accepted value is `1`.
//!   Without it the host MUST be loopback: an IPv4 address in `127.0.0.0/8`,
//!   `[::1]`, or `localhost` (any case). The gateway dials `http://{addr}/mcp`
//!   in cleartext and forwards the CALLER's own bearer token on every call, so
//!   a non-loopback host would carry every caller's token across the network
//!   unencrypted (backlog bcff7c2b). The field is the operator saying they
//!   accept that, and the gateway logs a warning at boot when it is set.
//!
//! Extension names are unique: a second entry with a name already used is an
//! error, not a silent second mount under the same name.
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
    /// stripped). Loopback unless the entry set `insecure_remote=1`; the
    /// gateway dials `http://{addr}/mcp`.
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
/// non-loopback host without `insecure_remote=1`, missing required field,
/// duplicate field, empty value, unknown key) or on a duplicate extension name.
pub fn parse_extensions(raw: Option<&str>) -> Result<Vec<ExtensionConfig>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut configs: Vec<ExtensionConfig> = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let config = parse_entry(entry)?;
        if configs.iter().any(|c| c.name == config.name) {
            return Err(ConfigError {
                entry: entry.to_string(),
                reason: format!(
                    "duplicate extension name `{}` (each extension is mounted once, under \
                     its own name)",
                    config.name
                ),
            });
        }
        configs.push(config);
    }
    Ok(configs)
}

/// Whether `host` (the part of `host:port` before the port, IPv6 still in
/// brackets) names this machine's loopback interface.
///
/// Accepted: an IPv4 literal in `127.0.0.0/8`, the IPv6 literal `[::1]`, and
/// the name `localhost` in any case. Nothing else: not `0.0.0.0` or `[::]`
/// (which a listener binds but a dialer reaches as "any"), not an
/// IPv4-mapped `[::ffff:127.0.0.1]`, and not any other name, since resolving a
/// name at parse time would prove nothing about where a later dial goes.
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip.is_loopback());
    }
    host.parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| ip.is_loopback())
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
    let host = match addr.rsplit_once(':') {
        Some((host, port))
            if !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            host
        }
        _ => {
            return Err(err(
                "transport address must be `host:port` with a numeric port (e.g. 127.0.0.1:8093)",
            ))
        }
    };

    // Remaining fields are order-independent `key=value` pairs.
    let mut scope: Option<String> = None;
    let mut prefix: Option<String> = None;
    let mut insecure_remote = false;
    let mut insecure_remote_seen = false;
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
            "insecure_remote" => {
                if insecure_remote_seen {
                    return Err(err("duplicate `insecure_remote` field"));
                }
                insecure_remote_seen = true;
                if value != "1" {
                    return Err(err(
                        "`insecure_remote` takes only the value `1` (omit the field to require \
                         a loopback host)",
                    ));
                }
                insecure_remote = true;
            }
            other => {
                return Err(err(&format!(
                    "unknown field `{other}` (expected `scope`, `prefix` or `insecure_remote`)"
                )));
            }
        }
    }

    let scope = scope.ok_or_else(|| err("missing required `scope` field"))?;

    // Loopback is ENFORCED, not just advertised (backlog bcff7c2b): the dial
    // is cleartext http and carries the caller's own bearer.
    if !is_loopback_host(host) {
        if !insecure_remote {
            return Err(err(&format!(
                "host `{host}` is not loopback; v1 supports loopback TCP only \
                 (127.0.0.0/8, [::1] or localhost), because the gateway forwards each \
                 caller's bearer token over cleartext http. Add `insecure_remote=1` to \
                 accept that for this extension"
            )));
        }
        tracing::warn!(
            extension = name,
            host,
            "federation extension dials a NON-LOOPBACK host over cleartext http \
             (insecure_remote=1): every caller's bearer token for this extension's \
             tools crosses the network unencrypted"
        );
    }

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

    // ── Loopback is enforced, not just advertised (backlog bcff7c2b) ──
    //
    // The gateway dials `http://{addr}/mcp` in cleartext and forwards the
    // caller's own bearer, so an `addr` off this host sends every caller's
    // token across the network. These pin that the parser refuses one.

    #[test]
    fn non_loopback_ip_is_error() {
        for addr in [
            "10.0.0.5:8093",
            "0.0.0.0:8093",
            "192.168.1.2:8093",
            "[::]:8093",
        ] {
            let err = parse_extensions(Some(&format!("ext=tcp:{addr};scope=x")))
                .expect_err(&format!("{addr} is not loopback"));
            assert!(err.reason.contains("loopback"), "{addr}: {}", err.reason);
        }
    }

    #[test]
    fn non_localhost_hostname_is_error() {
        for host in [
            "episcience.internal",
            "example.com",
            "localhost.example.com",
        ] {
            let err = parse_extensions(Some(&format!("ext=tcp:{host}:8093;scope=x")))
                .expect_err(&format!("{host} is a hostname, not loopback"));
            assert!(err.reason.contains("loopback"), "{host}: {}", err.reason);
        }
    }

    #[test]
    fn loopback_forms_are_accepted() {
        for addr in [
            "127.0.0.1:8093",
            "127.0.0.53:8093",
            "127.255.255.254:8093",
            "localhost:8093",
            "LOCALHOST:8093",
            "[::1]:8093",
        ] {
            let cfgs = parse_extensions(Some(&format!("ext=tcp:{addr};scope=x")))
                .unwrap_or_else(|e| panic!("{addr} is loopback: {e}"));
            assert_eq!(cfgs[0].addr, addr);
        }
    }

    #[test]
    fn an_unbracketed_ipv6_host_is_error() {
        // `::1:8093` is ambiguous (is `8093` the port or the last group?);
        // `http://::1:8093/mcp` is not a valid URL either. Require brackets.
        let err = parse_extensions(Some("ext=tcp:::1:8093;scope=x")).unwrap_err();
        assert!(err.reason.contains("loopback"), "got: {}", err.reason);
    }

    #[test]
    fn insecure_remote_opts_a_non_loopback_host_in() {
        let cfgs =
            parse_extensions(Some("ext=tcp:10.0.0.5:8093;scope=x;insecure_remote=1")).unwrap();
        assert_eq!(cfgs[0].addr, "10.0.0.5:8093");
        assert_eq!(cfgs[0].scope, "x");
    }

    #[test]
    fn insecure_remote_takes_only_the_value_1() {
        for v in ["0", "true", "yes"] {
            let err = parse_extensions(Some(&format!(
                "ext=tcp:10.0.0.5:8093;scope=x;insecure_remote={v}"
            )))
            .expect_err(&format!("insecure_remote={v} is not the opt-in"));
            assert!(
                err.reason.contains("insecure_remote"),
                "{v}: {}",
                err.reason
            );
        }
    }

    #[test]
    fn duplicate_insecure_remote_is_error() {
        let err = parse_extensions(Some(
            "ext=tcp:10.0.0.5:8093;scope=x;insecure_remote=1;insecure_remote=1",
        ))
        .unwrap_err();
        assert!(err.reason.contains("duplicate"), "got: {}", err.reason);
    }

    // ── Extension names are unique (backlog bcff7c2b) ──

    #[test]
    fn duplicate_extension_name_is_error() {
        let err = parse_extensions(Some(
            "episcience=tcp:127.0.0.1:8093;scope=a,episcience=tcp:127.0.0.1:8094;scope=b",
        ))
        .unwrap_err();
        assert!(err.reason.contains("duplicate"), "got: {}", err.reason);
        assert!(err.reason.contains("episcience"), "got: {}", err.reason);
        assert!(
            err.entry.contains("8094"),
            "the error names the SECOND entry: {}",
            err.entry
        );
    }

    #[test]
    fn display_includes_entry_and_reason() {
        let err = parse_extensions(Some("episcience=tcp:127.0.0.1:8093")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("EPIGRAPH_MCP_EXTENSIONS"), "got: {msg}");
        assert!(msg.contains("episcience=tcp:127.0.0.1:8093"), "got: {msg}");
    }
}
