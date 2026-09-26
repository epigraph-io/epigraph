//! Outbound-webhook egress guard (SSRF protection).
//!
//! Every outbound webhook path in the workspace — `epigraph-api`'s
//! registration gate and delivery dispatcher, and this crate's
//! [`crate::ConfigurableWebhookHandler`] — decides "may this address be dialled?"
//! here, and only here. Two classifiers are two definitions of "internal" that
//! can drift, and the one that drifts open is the one nobody notices.
//!
//! # The address table
//!
//! [`internal_category`] is the single table. An address is refused when it is
//! not globally reachable according to the IANA IPv4 and IPv6 Special-Purpose
//! Address Registries, plus the multicast blocks. Addresses that *carry* an IPv4
//! address inside IPv6 (IPv4-mapped `::ffff:a.b.c.d`, NAT64 `64:ff9b::a.b.c.d`,
//! 6to4 `2002:aabb:ccdd::`) are judged by the IPv4 address they carry, through
//! the SAME IPv4 table — an inline copy of the IPv4 list in the IPv6 arm is how
//! the previous table drifted.
//!
//! # Parsing
//!
//! A URL is judged only after [`url::Url`] has parsed it, so what is classified
//! is the WHATWG-normalised authority the HTTP client will dial — not a
//! substring of the raw input. That is what makes `http://example.com@127.0.0.1/`
//! (userinfo), `http://[::1]:8080/`, `http://127.1/` and `http://2130706433/`
//! (alternate loopback spellings) all land on the loopback address they name.
//!
//! # Resolution, and why the answer must be pinned
//!
//! A name is only as safe as what it resolves to: a public name can have a
//! static record pointing at loopback or at the metadata address, and no
//! string check on the name can see that. [`EgressGuard::vet`] therefore
//! resolves the name ONCE and refuses it if ANY answer is internal.
//!
//! Vetting alone is not enough. If the HTTP client then resolves the name
//! again, a hostile DNS server can answer the guard with a public address and
//! the client, moments later, with an internal one (DNS rebinding). So `vet`
//! returns a [`VettedTarget`] carrying the vetted socket addresses, and every
//! caller must connect to those and nothing else — keeping the URL (and so the
//! `Host` header and TLS SNI) unchanged. Redirects must not be followed: a hop
//! is a new, unvetted destination.
//!
//! # Tests never use real DNS
//!
//! The resolver is injectable ([`EgressResolver`]); [`StubResolver`] answers
//! from a table. A stub cannot weaken the guard — whatever it returns is still
//! judged by the table. The one way to reach a loopback listener in a test is
//! [`EgressGuard::exempt_socket_for_tests`], which exists only under the
//! `test-support` feature (enabled from `[dev-dependencies]` only).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Schemes a webhook may be delivered over.
pub const ALLOWED_SCHEMES: &[&str] = &["http", "https"];

/// Why a webhook target was refused.
///
/// # `Display` is for LOGS; [`Self::public_message`] is for callers
///
/// The `Display` text is the full diagnosis. For a NAME it can include what
/// the server's resolver answered (the internal address, its range) or the
/// resolver's own error text, and none of that was supplied by the caller.
/// Returning it to a registering client would tell that client what the
/// server's resolver maps a name to: an internal-DNS enumeration oracle.
///
/// Anything returned across a trust boundary must use
/// [`Self::public_message`], which repeats back only what the caller supplied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EgressDenied {
    /// The string is not an absolute URL.
    #[error("Webhook URL is not a valid absolute URL: {0}")]
    Unparseable(String),
    /// The scheme is not in [`ALLOWED_SCHEMES`].
    #[error("Webhook URL scheme must be one of [\"http\", \"https\"], got {0:?}")]
    Scheme(String),
    /// The URL names no host.
    #[error("Webhook URL must name a host")]
    NoHost,
    /// The host is an IP literal in a refused range.
    #[error("Webhook URL must not target an internal address ({category}): {addr}")]
    InternalAddress {
        /// The literal address.
        addr: IpAddr,
        /// The table row it matched.
        category: &'static str,
    },
    /// The host is a name RFC 6761 reserves to loopback.
    #[error(
        "Webhook URL must not target an internal address (loopback name reserved by RFC 6761): {0}"
    )]
    ReservedName(String),
    /// The host is a name that resolved to at least one refused address.
    ///
    /// ANY internal answer refuses the whole name: a resolver may return the
    /// addresses in any order and the client may try any of them.
    #[error("Webhook URL host {host} resolves to an internal address ({category}): {addr}")]
    ResolvesInternal {
        /// The name as the URL spelled it (normalised).
        host: String,
        /// The first refused address in the answer.
        addr: IpAddr,
        /// The table row it matched.
        category: &'static str,
    },
    /// The host is a name that could not be resolved (no answer, an empty
    /// answer, a resolver error, or a timeout). Nothing can be vetted, so
    /// nothing is dialled.
    #[error("Webhook URL host {host} could not be resolved: {reason}")]
    Unresolvable {
        /// The name as the URL spelled it (normalised).
        host: String,
        /// What the resolver said.
        reason: String,
    },
}

impl EgressDenied {
    /// The refusal as it may be shown to the caller who supplied the URL.
    ///
    /// Variants judged from the URL alone ([`Self::Unparseable`],
    /// [`Self::Scheme`], [`Self::NoHost`], [`Self::InternalAddress`],
    /// [`Self::ReservedName`]) only echo caller input, so they keep their
    /// `Display` text.
    ///
    /// [`Self::ResolvesInternal`] and [`Self::Unresolvable`] are verdicts about
    /// the SERVER's resolver, so they share ONE message naming only the host.
    /// It must be the same message for both, and it avoids the word "resolve":
    /// if "is internal" and "does not exist" read differently, a caller can
    /// still tell whether an internal-only name exists, even without an
    /// address in the text. What remains observable is 201 versus 400 and the
    /// time a lookup takes; those cannot be removed without dropping the
    /// registration-time check, and are accepted.
    #[must_use]
    pub fn public_message(&self) -> String {
        match self {
            Self::ResolvesInternal { host, .. } | Self::Unresolvable { host, .. } => {
                format!("Webhook URL host {host} is not an acceptable public destination")
            }
            Self::Unparseable(_)
            | Self::Scheme(_)
            | Self::NoHost
            | Self::InternalAddress { .. }
            | Self::ReservedName(_) => self.to_string(),
        }
    }

    /// The refused destination, for logs and `JobError::SsrfBlocked`, or `None`
    /// when the refusal is not about an internal destination (a bad shape, or
    /// a name that did not resolve).
    #[must_use]
    pub fn blocked_destination(&self) -> Option<String> {
        match self {
            Self::InternalAddress { addr, .. } => Some(addr.to_string()),
            Self::ReservedName(name) => Some(name.clone()),
            Self::ResolvesInternal { host, addr, .. } => Some(format!("{host} ({addr})")),
            Self::Unparseable(_) | Self::Scheme(_) | Self::NoHost | Self::Unresolvable { .. } => {
                None
            }
        }
    }

    /// May the same URL be vetted successfully later? Only a resolution
    /// failure can change without the URL changing.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Unresolvable { .. })
    }
}

/// The host of a URL that passed [`parse_and_classify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckedHost {
    /// An IP literal, already judged external.
    Ip(IpAddr),
    /// A name. NOT yet judged: a name is only as safe as what it resolves to.
    Domain(String),
}

/// A URL that parsed, has an allowed scheme, and whose host is not refused on
/// its face. For a [`CheckedHost::Domain`] that is a necessary condition, not a
/// sufficient one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedUrl {
    url: url::Url,
    host: CheckedHost,
    port: u16,
}

impl CheckedUrl {
    /// The parsed URL — the one to dial, so the judged value and the dialled
    /// value are the same object.
    #[must_use]
    pub fn url(&self) -> &url::Url {
        &self.url
    }

    /// The parsed host.
    #[must_use]
    pub fn host(&self) -> &CheckedHost {
        &self.host
    }

    /// The explicit port, or the scheme's default.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Is `name` one of the names RFC 6761 reserves to loopback?
///
/// `localhost` and any label under `.localhost`, compared case-insensitively
/// with a single trailing root dot stripped. These are loopback *by
/// definition*, so they are refused without consulting a resolver.
#[must_use]
pub fn is_reserved_loopback_name(name: &str) -> bool {
    let n = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    n == "localhost" || n.ends_with(".localhost")
}

/// Parse `raw` and apply every check that needs no DNS: absolute URL, `http`
/// or `https`, a host, an IP literal outside the refused ranges, a name
/// outside the reserved-to-loopback set.
///
/// Surrounding whitespace is trimmed first, so a padded target is judged as
/// the value it will be dialled as.
///
/// # Errors
///
/// [`EgressDenied`] naming the rule the URL tripped.
pub fn parse_and_classify(raw: &str) -> Result<CheckedUrl, EgressDenied> {
    let url = url::Url::parse(raw.trim()).map_err(|e| EgressDenied::Unparseable(e.to_string()))?;

    if !ALLOWED_SCHEMES.contains(&url.scheme()) {
        return Err(EgressDenied::Scheme(url.scheme().to_string()));
    }

    let host = match url.host() {
        None => return Err(EgressDenied::NoHost),
        Some(url::Host::Ipv4(v4)) => CheckedHost::Ip(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => CheckedHost::Ip(IpAddr::V6(v6)),
        Some(url::Host::Domain(name)) => {
            if is_reserved_loopback_name(name) {
                return Err(EgressDenied::ReservedName(name.to_string()));
            }
            CheckedHost::Domain(name.to_string())
        }
    };

    if let CheckedHost::Ip(addr) = host {
        if let Some(category) = internal_category(addr) {
            return Err(EgressDenied::InternalAddress { addr, category });
        }
    }

    // Both allowed schemes are special, so a known default always exists.
    let port = url.port_or_known_default().unwrap_or(80);
    Ok(CheckedUrl { url, host, port })
}

// =============================================================================
// RESOLUTION
// =============================================================================

/// Name resolution as the guard sees it.
///
/// Injectable so tests never touch real DNS ([`StubResolver`]). A resolver
/// cannot weaken the guard: whatever it returns is judged by the address
/// table, and the returned addresses are the only ones the caller may dial.
#[async_trait::async_trait]
pub trait EgressResolver: Send + Sync {
    /// Resolve `host` (as the URL spells it, normalised by the `url` crate)
    /// to the addresses a client would try.
    ///
    /// # Errors
    ///
    /// Any resolution failure; the guard reports it as
    /// [`EgressDenied::Unresolvable`].
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>>;
}

/// The operating system's resolver (`getaddrinfo`, via `tokio::net::lookup_host`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

#[async_trait::async_trait]
impl EgressResolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>> {
        Ok(tokio::net::lookup_host((host, port))
            .await?
            .map(|sa| sa.ip())
            .collect())
    }
}

/// A fixed-answer resolver for tests. No network access.
///
/// Each name maps to a SEQUENCE of answers: the n-th lookup of a name returns
/// the n-th answer and the last answer repeats, which is how a test models a
/// DNS-rebinding server (public on the first lookup, internal afterwards).
/// Names are matched case-insensitively with a trailing root dot ignored. A
/// name with no entry falls back to [`Self::with_fallback`]'s answer, or fails
/// like NXDOMAIN.
#[derive(Debug, Default)]
pub struct StubResolver {
    answers: std::collections::HashMap<String, Vec<Vec<IpAddr>>>,
    fallback: Option<Vec<IpAddr>>,
    calls: std::sync::Mutex<std::collections::HashMap<String, usize>>,
}

impl StubResolver {
    /// An empty stub: every lookup fails.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn key(host: &str) -> String {
        host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
    }

    /// Answer `host` with `addrs` on every lookup.
    #[must_use]
    pub fn with(self, host: &str, addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        self.with_sequence(host, vec![addrs.into_iter().collect()])
    }

    /// Answer the n-th lookup of `host` with `answers[n]`; the last repeats.
    #[must_use]
    pub fn with_sequence(mut self, host: &str, answers: Vec<Vec<IpAddr>>) -> Self {
        self.answers.insert(Self::key(host), answers);
        self
    }

    /// Answer every name that has no entry with `addrs`.
    #[must_use]
    pub fn with_fallback(mut self, addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        self.fallback = Some(addrs.into_iter().collect());
        self
    }

    /// How many times `host` has been looked up.
    #[must_use]
    pub fn calls(&self, host: &str) -> usize {
        self.calls
            .lock()
            .map(|c| c.get(&Self::key(host)).copied().unwrap_or(0))
            .unwrap_or(0)
    }
}

#[async_trait::async_trait]
impl EgressResolver for StubResolver {
    async fn resolve(&self, host: &str, _port: u16) -> std::io::Result<Vec<IpAddr>> {
        let key = Self::key(host);
        let n = {
            let mut calls = self
                .calls
                .lock()
                .map_err(|_| std::io::Error::other("stub resolver lock poisoned"))?;
            let entry = calls.entry(key.clone()).or_insert(0);
            *entry += 1;
            *entry - 1
        };
        if let Some(seq) = self.answers.get(&key) {
            if let Some(answer) = seq.get(n).or_else(|| seq.last()) {
                return Ok(answer.clone());
            }
        }
        self.fallback.clone().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("stub resolver has no answer for {host}"),
            )
        })
    }
}

// =============================================================================
// THE GUARD
// =============================================================================

/// A URL that passed every check, with the ONLY socket addresses it may be
/// dialled on.
///
/// For a name, `addrs` is the single vetted resolution. Dialling anything
/// else — in particular, letting the HTTP client resolve the name again —
/// reopens DNS rebinding: a hostile server can answer the guard with a public
/// address and the client with an internal one. See [`EgressGuard::vet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VettedTarget {
    checked: CheckedUrl,
    addrs: Vec<std::net::SocketAddr>,
}

impl VettedTarget {
    /// The URL to send to. Unchanged from what was judged, so the `Host`
    /// header and TLS SNI/certificate name are the registered host's.
    #[must_use]
    pub fn url(&self) -> &url::Url {
        self.checked.url()
    }

    /// The name to pin, or `None` for an IP-literal URL (which the client
    /// dials directly, without resolving).
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        match self.checked.host() {
            CheckedHost::Domain(name) => Some(name),
            CheckedHost::Ip(_) => None,
        }
    }

    /// The port every address is dialled on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.checked.port()
    }

    /// The vetted socket addresses — the only ones a client may connect to.
    /// Never empty.
    #[must_use]
    pub fn addrs(&self) -> &[std::net::SocketAddr] {
        &self.addrs
    }
}

/// Default bound on a single resolution, so a slow resolver cannot hold a
/// registration request or a delivery open indefinitely.
pub const DEFAULT_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The egress guard: parse, classify, resolve once, refuse if any answer is
/// internal, and hand back the vetted addresses to pin.
#[derive(Clone)]
pub struct EgressGuard {
    resolver: std::sync::Arc<dyn EgressResolver>,
    resolve_timeout: std::time::Duration,
    #[cfg(feature = "test-support")]
    exempt: std::sync::Arc<std::collections::HashSet<std::net::SocketAddr>>,
}

impl std::fmt::Debug for EgressGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("EgressGuard");
        d.field("resolve_timeout", &self.resolve_timeout);
        #[cfg(feature = "test-support")]
        d.field("exempt", &self.exempt);
        d.finish_non_exhaustive()
    }
}

impl Default for EgressGuard {
    fn default() -> Self {
        Self::system()
    }
}

impl EgressGuard {
    /// The production guard: the operating system's resolver.
    #[must_use]
    pub fn system() -> Self {
        Self::with_resolver(std::sync::Arc::new(SystemResolver))
    }

    /// A guard over a caller-supplied resolver (tests: [`StubResolver`]).
    #[must_use]
    pub fn with_resolver(resolver: std::sync::Arc<dyn EgressResolver>) -> Self {
        Self {
            resolver,
            resolve_timeout: DEFAULT_RESOLVE_TIMEOUT,
            #[cfg(feature = "test-support")]
            exempt: std::sync::Arc::default(),
        }
    }

    /// Bound each resolution by `timeout`.
    #[must_use]
    pub fn resolve_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.resolve_timeout = timeout;
        self
    }

    /// TEST SUPPORT ONLY: treat exactly `addr` (IP *and* port) as external
    /// when a NAME resolves to it, so a test can deliver to a local listener.
    ///
    /// Compiled only with the `test-support` feature, which only
    /// `[dev-dependencies]` enable, so a release build of any binary does not
    /// contain it. Keyed on the full socket address so a test guard still
    /// refuses every other loopback port — a redirect hop, a second listener.
    /// IP-literal URLs are never exempted.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn exempt_socket_for_tests(mut self, addr: std::net::SocketAddr) -> Self {
        std::sync::Arc::make_mut(&mut self.exempt).insert(addr);
        self
    }

    #[cfg(feature = "test-support")]
    fn is_exempt(&self, addr: std::net::SocketAddr) -> bool {
        self.exempt.contains(&addr)
    }

    #[cfg(not(feature = "test-support"))]
    #[allow(clippy::unused_self)]
    fn is_exempt(&self, _addr: std::net::SocketAddr) -> bool {
        false
    }

    /// Vet `raw` as a webhook destination.
    ///
    /// 1. [`parse_and_classify`] — shape, scheme, IP literal, reserved names.
    /// 2. For a name: resolve it ONCE (bounded by the resolve timeout). An
    ///    error, a timeout, or an empty answer refuses it
    ///    ([`EgressDenied::Unresolvable`]).
    /// 3. Refuse if ANY resolved address is internal
    ///    ([`EgressDenied::ResolvesInternal`]).
    /// 4. Return the vetted addresses. The caller must connect to these and
    ///    only these ([`VettedTarget`]).
    ///
    /// # Errors
    ///
    /// [`EgressDenied`] naming the rule the URL tripped.
    pub async fn vet(&self, raw: &str) -> Result<VettedTarget, EgressDenied> {
        let checked = parse_and_classify(raw)?;
        let port = checked.port();

        let addrs = match checked.host() {
            CheckedHost::Ip(ip) => vec![std::net::SocketAddr::new(*ip, port)],
            CheckedHost::Domain(name) => {
                let unresolvable = |reason: String| EgressDenied::Unresolvable {
                    host: name.clone(),
                    reason,
                };
                let ips =
                    tokio::time::timeout(self.resolve_timeout, self.resolver.resolve(name, port))
                        .await
                        .map_err(|_| {
                            unresolvable(format!("timed out after {:?}", self.resolve_timeout))
                        })?
                        .map_err(|e| unresolvable(e.to_string()))?;
                if ips.is_empty() {
                    return Err(unresolvable("no addresses".to_string()));
                }

                let mut addrs: Vec<std::net::SocketAddr> = Vec::with_capacity(ips.len());
                for ip in ips {
                    let sa = std::net::SocketAddr::new(ip, port);
                    if let Some(category) = internal_category(ip) {
                        if !self.is_exempt(sa) {
                            return Err(EgressDenied::ResolvesInternal {
                                host: name.clone(),
                                addr: ip,
                                category,
                            });
                        }
                    }
                    if !addrs.contains(&sa) {
                        addrs.push(sa);
                    }
                }
                addrs
            }
        };

        Ok(VettedTarget { checked, addrs })
    }
}

/// Name the reason `addr` must not be dialled, or `None` if it is a globally
/// reachable unicast address.
///
/// The category is returned rather than a bare `bool` so a refusal can say
/// which rule the caller tripped. [`is_internal_addr`] is the boolean view.
#[must_use]
pub fn internal_category(addr: IpAddr) -> Option<&'static str> {
    match addr {
        IpAddr::V4(v4) => ipv4_category(v4),
        IpAddr::V6(v6) => ipv6_category(v6),
    }
}

/// Is `addr` internal, private, or otherwise not a legitimate webhook target?
///
/// `true` means refuse. See [`internal_category`] for the table.
#[must_use]
pub fn is_internal_addr(addr: IpAddr) -> bool {
    internal_category(addr).is_some()
}

/// Does `addr` lie inside `net/prefix`?
fn v4_in(addr: Ipv4Addr, net: [u8; 4], prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(addr) & mask) == (u32::from(Ipv4Addr::from(net)) & mask)
}

/// Does `addr` lie inside `net/prefix`?
fn v6_in(addr: Ipv6Addr, net: Ipv6Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(addr) & mask) == (u128::from(net) & mask)
}

/// The IPv4 table, most specific first.
fn ipv4_category(v4: Ipv4Addr) -> Option<&'static str> {
    // (network, prefix, category). Order matters only where blocks nest:
    // the limited-broadcast address sits inside 240/4 and is named on its own.
    const TABLE: &[([u8; 4], u32, &str)] = &[
        ([255, 255, 255, 255], 32, "limited broadcast"),
        ([0, 0, 0, 0], 8, "this network / unspecified"),
        ([10, 0, 0, 0], 8, "private range"),
        ([100, 64, 0, 0], 10, "shared address space (CGNAT)"),
        ([127, 0, 0, 0], 8, "loopback"),
        // 169.254.0.0/16 is where cloud instance-metadata services live.
        ([169, 254, 0, 0], 16, "link-local"),
        ([172, 16, 0, 0], 12, "private range"),
        ([192, 0, 0, 0], 24, "IETF protocol assignments"),
        ([192, 0, 2, 0], 24, "documentation (TEST-NET-1)"),
        ([192, 88, 99, 0], 24, "6to4 relay anycast (deprecated)"),
        ([192, 168, 0, 0], 16, "private range"),
        ([198, 18, 0, 0], 15, "benchmarking"),
        ([198, 51, 100, 0], 24, "documentation (TEST-NET-2)"),
        ([203, 0, 113, 0], 24, "documentation (TEST-NET-3)"),
        ([224, 0, 0, 0], 4, "multicast"),
        ([240, 0, 0, 0], 4, "reserved"),
    ];
    TABLE
        .iter()
        .find(|(net, prefix, _)| v4_in(v4, *net, *prefix))
        .map(|(_, _, category)| *category)
}

/// The IPv6 table. Embedded-IPv4 forms defer to [`ipv4_category`].
fn ipv6_category(v6: Ipv6Addr) -> Option<&'static str> {
    let seg = v6.segments();
    let bits = u128::from(v6);

    if v6.is_unspecified() {
        return Some("unspecified");
    }
    if v6.is_loopback() {
        return Some("loopback");
    }

    // ::ffff:a.b.c.d — IPv4-mapped. The same destination as the IPv4 address,
    // written differently, so it is judged as that address.
    if let Some(v4) = v6.to_ipv4_mapped() {
        return ipv4_category(v4);
    }

    // ::a.b.c.d — IPv4-compatible (::/96, deprecated by RFC 4291). Not mapped,
    // so `to_ipv4_mapped` returns None for it and it used to fall through as
    // public; `::127.0.0.1` is the loopback address in this spelling. Nothing
    // legitimate is addressed this way any more, so the whole block is refused.
    if v6_in(v6, Ipv6Addr::UNSPECIFIED, 96) {
        return Some("IPv4-compatible (deprecated)");
    }

    // ::ffff:0:a.b.c.d — IPv4-translated (RFC 2765). Refused outright.
    if v6_in(v6, Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, 0, 0), 96) {
        return Some("IPv4-translated");
    }

    // 64:ff9b::/96 — NAT64 well-known prefix. A DNS64 resolver synthesises
    // these for ordinary public IPv4-only names, so the block cannot be refused
    // wholesale without breaking delivery on IPv6-only hosts; the embedded IPv4
    // address is judged instead, which is what the translator will dial.
    if v6_in(v6, Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96) {
        #[allow(clippy::cast_possible_truncation)]
        let embedded = Ipv4Addr::from(bits as u32);
        return ipv4_category(embedded).map(|_| "NAT64 of an internal IPv4 address");
    }

    // 2002::/16 — 6to4. The 32 bits after the prefix are the IPv4 address the
    // relay tunnels to; judge that.
    if seg[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            (seg[1] & 0xff) as u8,
            (seg[2] >> 8) as u8,
            (seg[2] & 0xff) as u8,
        );
        return ipv4_category(embedded).map(|_| "6to4 of an internal IPv4 address");
    }

    const TABLE: &[(Ipv6Addr, u32, &str)] = &[
        // 64:ff9b:1::/48 — local-use NAT64 (RFC 8215): translates into a
        // network-local IPv4 space by definition.
        (
            Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0),
            48,
            "local-use NAT64",
        ),
        (
            Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0),
            64,
            "discard-only",
        ),
        // 2001:db8::/32 is inside 2001::/16 but not 2001::/23; checked first
        // only for the better name.
        (
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            32,
            "documentation",
        ),
        // 2001::/23 — IETF protocol assignments: Teredo (2001::/32, whose
        // embedded client address is obfuscated and cannot be judged), ORCHID,
        // benchmarking, AMT, AS112. None is a webhook receiver.
        (
            Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0),
            23,
            "IETF protocol assignments (incl. Teredo)",
        ),
        (
            Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0),
            20,
            "documentation",
        ),
        (Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16, "SRv6 SIDs"),
        (
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
            7,
            "unique-local",
        ),
        (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10, "link-local"),
        (
            Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0),
            10,
            "site-local (deprecated)",
        ),
        (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8, "multicast"),
    ];
    TABLE
        .iter()
        .find(|(net, prefix, _)| v6_in(v6, *net, *prefix))
        .map(|(_, _, category)| *category)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Backlog e4916d42: every one of these reaches loopback (or metadata), and
    /// the string-slicing extractor let each through. Parsing first means the
    /// normalised authority is what gets judged.
    #[test]
    fn parse_and_classify_refuses_obfuscated_internal_authorities() {
        for raw in [
            "http://example.com@127.0.0.1/hook", // userinfo
            "http://user:pw@169.254.169.254/latest/meta-data/",
            "http://[::1]:8080/hook",         // bracketed IPv6 with port
            "http://127.1/hook",              // short-form IPv4
            "http://2130706433/hook",         // decimal IPv4
            "http://0x7f.0.0.1/hook",         // hex octet
            "http://0177.0.0.1/hook",         // octal octet
            "http://[::ffff:127.0.0.1]/hook", // IPv4-mapped
            "http://127.0.0.1.:80/hook",      // trailing root dot
            "HTTP://LOCALHOST/hook",          // reserved name, case
            "http://localhost./hook",         // reserved name, root dot
        ] {
            let got = parse_and_classify(raw);
            assert!(
                matches!(
                    got,
                    Err(EgressDenied::InternalAddress { .. } | EgressDenied::ReservedName(_))
                ),
                "{raw} must be refused as internal, got {got:?}"
            );
        }
    }

    fn stub_guard(stub: StubResolver) -> (EgressGuard, std::sync::Arc<StubResolver>) {
        let stub = std::sync::Arc::new(stub);
        (EgressGuard::with_resolver(stub.clone()), stub)
    }

    /// Backlog c89b65b0: a public NAME that resolves to loopback or to the
    /// metadata address passed every gate, because names were never resolved.
    #[tokio::test]
    async fn vet_refuses_names_that_resolve_internal() {
        let (guard, _) = stub_guard(
            StubResolver::new()
                .with("loopback-alias.example", [ip("127.0.0.1")])
                .with("metadata-alias.example", [ip("169.254.169.254")])
                .with("mapped-alias.example", [ip("::ffff:10.0.0.1")])
                .with("cgnat-alias.example", [ip("100.64.1.1")])
                // Round-robin with ONE internal member: the client may pick
                // either, so the whole name is refused.
                .with("mixed.example", [ip("93.184.216.34"), ip("10.0.0.5")]),
        );
        for name in [
            "loopback-alias.example",
            "metadata-alias.example",
            "mapped-alias.example",
            "cgnat-alias.example",
            "mixed.example",
        ] {
            let got = guard.vet(&format!("https://{name}/hook")).await;
            assert!(
                matches!(got, Err(EgressDenied::ResolvesInternal { .. })),
                "{name} must be refused, got {got:?}"
            );
        }
    }

    /// The control: a name resolving only to public addresses is accepted,
    /// and the vetted set is exactly the resolved answer on the URL's port.
    #[tokio::test]
    async fn vet_accepts_public_names_and_returns_the_answer_to_pin() {
        let (guard, stub) = stub_guard(
            StubResolver::new().with("hooks.example", [ip("93.184.216.34"), ip("2606:4700::1")]),
        );
        let t = guard
            .vet("https://Hooks.Example:8443/x")
            .await
            .expect("public name");
        assert_eq!(t.domain(), Some("hooks.example"));
        assert_eq!(
            t.addrs(),
            &[
                "93.184.216.34:8443".parse().unwrap(),
                "[2606:4700::1]:8443".parse().unwrap()
            ]
        );
        assert_eq!(t.url().as_str(), "https://hooks.example:8443/x");
        assert_eq!(stub.calls("hooks.example"), 1, "resolved exactly once");

        let lit = guard.vet("http://93.184.216.34/x").await.expect("literal");
        assert_eq!(lit.domain(), None);
        assert_eq!(lit.addrs(), &["93.184.216.34:80".parse().unwrap()]);
    }

    /// A name that does not resolve cannot be vetted, so it is refused — and
    /// the refusal is transient, not an SSRF verdict.
    #[tokio::test]
    async fn vet_refuses_unresolvable_names() {
        let (guard, _) = stub_guard(StubResolver::new().with("empty.example", []));
        for raw in ["https://nxdomain.example/x", "https://empty.example/x"] {
            let got = guard.vet(raw).await;
            match got {
                Err(ref d @ EgressDenied::Unresolvable { .. }) => {
                    assert!(d.is_transient());
                    assert_eq!(d.blocked_destination(), None);
                }
                other => panic!("{raw} must be Unresolvable, got {other:?}"),
            }
        }
    }

    /// The caller-facing text of a resolution verdict carries nothing the
    /// caller did not supply: no resolved address, no range name, no resolver
    /// error — and "internal" and "does not exist" read identically, so the
    /// text cannot distinguish an internal-only name from a missing one.
    #[tokio::test]
    async fn public_message_of_a_resolution_verdict_names_only_the_host() {
        let (guard, _) = stub_guard(
            StubResolver::new()
                .with("loopback-alias.example", [ip("127.0.0.1")])
                .with("private-alias.example", [ip("10.0.0.9")]),
        );
        let mut texts = Vec::new();
        for name in [
            "loopback-alias.example",
            "private-alias.example",
            "nxdomain.example",
        ] {
            let denied = guard
                .vet(&format!("https://{name}/hook"))
                .await
                .expect_err("refused");
            let text = denied.public_message();
            for leak in [
                "127.0.0.1",
                "10.0.0.9",
                "loopback",
                "private",
                "resolve",
                "stub resolver",
            ] {
                assert!(
                    !text.replace(name, "<host>").contains(leak),
                    "{name}: caller-facing text leaks {leak:?}: {text}"
                );
            }
            texts.push(text.replace(name, "<host>"));
        }
        assert!(
            texts.windows(2).all(|w| w[0] == w[1]),
            "every resolution verdict must read the same: {texts:?}"
        );

        // URL-only verdicts echo caller input and keep their full text.
        let literal = parse_and_classify("http://127.0.0.1/x").expect_err("literal");
        assert_eq!(literal.public_message(), literal.to_string());
    }

    /// Literals and reserved names are refused BEFORE the resolver is asked.
    #[tokio::test]
    async fn vet_does_not_resolve_what_parse_already_refused() {
        let (guard, stub) = stub_guard(StubResolver::new().with_fallback([ip("93.184.216.34")]));
        assert!(guard.vet("http://127.0.0.1/x").await.is_err());
        assert!(guard.vet("http://localhost/x").await.is_err());
        assert_eq!(stub.calls("localhost"), 0);
    }

    /// The control, and the shape checks.
    #[test]
    fn parse_and_classify_accepts_public_and_rejects_bad_shapes() {
        let ok = parse_and_classify("  https://hooks.example.com:8443/x  ").expect("public");
        assert_eq!(ok.host(), &CheckedHost::Domain("hooks.example.com".into()));
        assert_eq!(ok.port(), 8443);
        assert_eq!(ok.url().as_str(), "https://hooks.example.com:8443/x");
        let lit = parse_and_classify("http://93.184.216.34/x").expect("public literal");
        assert_eq!(
            lit.host(),
            &CheckedHost::Ip("93.184.216.34".parse().unwrap())
        );
        assert_eq!(lit.port(), 80);

        assert!(matches!(
            parse_and_classify("ftp://example.com/x"),
            Err(EgressDenied::Scheme(_))
        ));
        assert!(matches!(
            parse_and_classify("/relative"),
            Err(EgressDenied::Unparseable(_))
        ));
        assert!(matches!(
            parse_and_classify("not a url"),
            Err(EgressDenied::Unparseable(_))
        ));
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    /// Backlog b159a7fd: every range the previous table classified as public,
    /// each one a reachable-but-not-public destination, plus the ranges that
    /// were already refused (so a rewrite cannot lose one).
    #[test]
    fn refuses_every_non_global_range() {
        for s in [
            // Previously refused — must stay refused.
            "127.0.0.1",
            "127.255.255.254",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "0.1.2.3",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "fc00::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            // b159a7fd — previously ALLOWED.
            "100.64.0.1",             // CGNAT
            "100.127.255.254",        // CGNAT, top of the /10
            "224.0.0.1",              // multicast
            "239.255.255.250",        // multicast (SSDP)
            "255.255.255.255",        // limited broadcast
            "240.0.0.1",              // reserved
            "192.0.0.1",              // IETF protocol assignments
            "192.0.0.170",            // NAT64 discovery
            "192.0.2.1",              // TEST-NET-1
            "198.51.100.1",           // TEST-NET-2
            "203.0.113.1",            // TEST-NET-3
            "198.18.0.1",             // benchmarking
            "198.19.255.255",         // benchmarking, top of the /15
            "192.88.99.1",            // 6to4 relay anycast
            "::127.0.0.1",            // IPv4-compatible loopback (::7f00:1)
            "::7f00:1",               // same address, hex spelling
            "::8.8.8.8",              // IPv4-compatible is refused wholesale
            "::ffff:0:127.0.0.1",     // IPv4-translated
            "::ffff:100.64.0.1",      // IPv4-mapped CGNAT
            "::ffff:255.255.255.255", // IPv4-mapped broadcast
            "fec0::1",                // deprecated site-local
            "feff::1",                // site-local, top of the /10
            "ff02::1",                // multicast
            "ff05::1:3",              // multicast
            "2002:7f00:1::",          // 6to4 of 127.0.0.1
            "2002:a9fe:a9fe::1",      // 6to4 of 169.254.169.254
            "64:ff9b::7f00:1",        // NAT64 of 127.0.0.1
            "64:ff9b::a9fe:a9fe",     // NAT64 of 169.254.169.254
            "64:ff9b::a00:1",         // NAT64 of 10.0.0.1
            "64:ff9b:1::1",           // local-use NAT64
            "100::1",                 // discard-only
            "2001::1",                // Teredo
            "2001:db8::1",            // documentation
            "2001:10::1",             // ORCHID
            "3fff::1",                // documentation (RFC 9637)
            "5f00::1",                // SRv6 SIDs
        ] {
            assert!(
                is_internal_addr(ip(s)),
                "{s} must be refused (category {:?})",
                internal_category(ip(s))
            );
        }
    }

    /// The control: a table that refuses everything passes the test above.
    /// Public unicast — including the public forms of every embedded-IPv4
    /// encoding that is judged by its payload rather than refused wholesale —
    /// must stay dialable.
    #[test]
    fn allows_global_unicast() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "100.63.255.255",  // just below CGNAT
            "100.128.0.0",     // just above CGNAT
            "172.15.255.255",  // just below 172.16/12
            "172.32.0.0",      // just above 172.16/12
            "192.0.1.1",       // just above 192.0.0/24
            "198.17.255.255",  // just below benchmarking
            "198.20.0.0",      // just above benchmarking
            "223.255.255.255", // just below multicast
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "2001:200::1",      // just above 2001::/23
            "::ffff:8.8.8.8",   // IPv4-mapped public
            "64:ff9b::808:808", // NAT64 of 8.8.8.8 (DNS64)
            "2002:808:808::1",  // 6to4 of 8.8.8.8
        ] {
            assert!(
                !is_internal_addr(ip(s)),
                "{s} is globally reachable and must be allowed (category {:?})",
                internal_category(ip(s))
            );
        }
    }
}
