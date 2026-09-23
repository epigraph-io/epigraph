//! Rate limiting for agent requests
//!
//! This module provides:
//! - Per-agent rate limiting based on configured quotas
//! - Global rate limiting to prevent system overload
//! - Token bucket algorithm with configurable replenishment
//!
//! # Design Principles
//!
//! 1. **Fairness**: Each agent gets their own quota
//! 2. **Protection**: Global limits prevent DoS attacks
//! 3. **Transparency**: Clients receive retry-after headers
//! 4. **Configurability**: Limits can be adjusted per-agent

use chrono::{DateTime, Utc};
use epigraph_core::domain::AgentId;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, RwLock};
use thiserror::Error;

/// How often, at most, [`AgentRateLimiter`] sweeps idle per-key buckets.
///
/// The sweep is amortised onto the request path (the first check after the
/// interval elapses pays an O(keys) pass), so there is no background task to
/// own or shut down. Ten seconds keeps the table near the working set: a
/// bucket touched once refills in `60 / rpm` seconds, and a fully drained one
/// in at most 60 seconds whatever its rpm.
const IDLE_SWEEP_INTERVAL_SECS: i64 = 10;

/// Error returned when rate limit is exceeded
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RateLimitError {
    #[error("Rate limit exceeded for agent {agent_id}. Retry after {retry_after_secs} seconds")]
    AgentLimitExceeded {
        agent_id: AgentId,
        retry_after_secs: u64,
        /// Current request rate (approximate)
        current_rate: u32,
        /// Configured limit for this agent
        limit: u32,
    },

    #[error("Global rate limit exceeded. Retry after {retry_after_secs} seconds")]
    GlobalLimitExceeded { retry_after_secs: u64 },
}

impl RateLimitError {
    /// Get the number of seconds to wait before retrying
    #[must_use]
    pub fn retry_after(&self) -> u64 {
        match self {
            Self::AgentLimitExceeded {
                retry_after_secs, ..
            } => *retry_after_secs,
            Self::GlobalLimitExceeded { retry_after_secs } => *retry_after_secs,
        }
    }
}

/// Configuration for rate limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Default requests per minute for agents without custom limits
    pub default_rpm: u32,
    /// Global requests per minute across all agents
    pub global_rpm: u32,
    /// How often tokens are replenished (in seconds)
    pub replenish_interval_secs: u64,
    /// Whether to enable global rate limiting
    pub enable_global_limit: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default_rpm: 60,  // 1 request per second
            global_rpm: 1000, // 1000 requests per minute total
            replenish_interval_secs: 1,
            enable_global_limit: true,
        }
    }
}

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Current number of available tokens
    tokens: f64,
    /// Maximum tokens (bucket capacity)
    max_tokens: f64,
    /// Tokens added per replenish interval
    refill_rate: f64,
    /// Last time tokens were refilled
    last_refill: DateTime<Utc>,
}

impl TokenBucket {
    /// Create a new token bucket
    fn new(max_tokens: u32, refill_rate_per_second: f64) -> Self {
        Self {
            tokens: max_tokens as f64,
            max_tokens: max_tokens as f64,
            refill_rate: refill_rate_per_second,
            last_refill: Utc::now(),
        }
    }

    /// Try to consume a token, refilling first if needed
    ///
    /// Returns `Ok(())` if a token was consumed, or `Err(seconds_until_available)`
    fn try_consume(&mut self) -> Result<(), u64> {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Calculate how long until we have a token
            let tokens_needed = 1.0 - self.tokens;
            let seconds_until_token = (tokens_needed / self.refill_rate).ceil() as u64;
            Err(seconds_until_token.max(1))
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Utc::now();
        let elapsed = now.signed_duration_since(self.last_refill);
        let elapsed_secs = elapsed.num_milliseconds() as f64 / 1000.0;

        if elapsed_secs > 0.0 {
            self.tokens = (self.tokens + elapsed_secs * self.refill_rate).min(self.max_tokens);
            self.last_refill = now;
        }
    }

    /// Get current available tokens (for testing/monitoring)
    #[allow(dead_code)]
    fn available_tokens(&mut self) -> f64 {
        self.refill();
        self.tokens
    }
}

/// Per-agent rate limiter with global limits
///
/// # Thread Safety
///
/// This struct uses internal locking and is safe to share across threads.
/// Clone creates a shallow copy that shares the same internal state.
#[derive(Clone)]
pub struct AgentRateLimiter {
    /// Configuration
    config: RateLimitConfig,
    /// Per-agent token buckets
    agent_buckets: Arc<RwLock<HashMap<AgentId, TokenBucket>>>,
    /// Global token bucket
    global_bucket: Arc<RwLock<TokenBucket>>,
    /// Custom limits per agent (requests per minute)
    agent_limits: Arc<RwLock<HashMap<AgentId, u32>>>,
    /// When `agent_buckets` was last swept of idle entries. Locked inside
    /// `check_agent` under `agent_buckets`' write lock, and by `advance_time`
    /// on its own; neither holds it while taking another lock, so no
    /// lock-order cycle exists.
    last_sweep: Arc<Mutex<DateTime<Utc>>>,
    /// Peers whose `X-Forwarded-For` / `X-Real-IP` the middleware may believe.
    /// See [`Self::with_trusted_proxies`].
    trusted_proxies: Arc<Vec<IpNet>>,
}

/// The trusted-proxy set a limiter starts with: loopback only.
///
/// The supported deployment fronts the API with Caddy on the same host
/// (`docs/deploy.md`), so its hop arrives from loopback. Anything that can
/// open a loopback connection is already on the host.
#[must_use]
pub fn default_trusted_proxies() -> Vec<IpNet> {
    vec![
        IpNet::V4(
            Ipv4Net::new(Ipv4Addr::LOCALHOST, 8)
                .expect("8 is a valid IPv4 prefix")
                .trunc(),
        ),
        IpNet::V6(Ipv6Net::new(Ipv6Addr::LOCALHOST, 128).expect("128 is a valid IPv6 prefix")),
    ]
}

impl AgentRateLimiter {
    /// Create a new rate limiter with the given configuration
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        let global_bucket = TokenBucket::new(
            config.global_rpm,
            config.global_rpm as f64 / 60.0, // Convert RPM to per-second rate
        );

        Self {
            config,
            agent_buckets: Arc::new(RwLock::new(HashMap::new())),
            global_bucket: Arc::new(RwLock::new(global_bucket)),
            agent_limits: Arc::new(RwLock::new(HashMap::new())),
            last_sweep: Arc::new(Mutex::new(Utc::now())),
            trusted_proxies: Arc::new(default_trusted_proxies()),
        }
    }

    /// Replace the set of peers whose forwarding headers are believed.
    ///
    /// The rate-limit middleware keys an anonymous request on the TCP peer
    /// address. Only when that peer is in this set does it consult
    /// `X-Forwarded-For` (right-most entry that is not itself a trusted
    /// proxy) and then `X-Real-IP`. A peer outside the set is keyed on its own
    /// address and its headers are ignored, because anyone can write them.
    ///
    /// An empty set trusts no one: every request is keyed on its TCP peer.
    /// Behind a reverse proxy that puts every client in the proxy's bucket,
    /// so do not pass an empty set unless the API is exposed directly.
    #[must_use]
    pub fn with_trusted_proxies(mut self, proxies: Vec<IpNet>) -> Self {
        self.trusted_proxies = Arc::new(proxies);
        self
    }

    /// The peers whose forwarding headers are believed.
    #[must_use]
    pub fn trusted_proxies(&self) -> &[IpNet] {
        &self.trusted_proxies
    }

    /// Whether `ip` is a trusted proxy. IPv4-mapped IPv6 addresses
    /// (`::ffff:a.b.c.d`) are compared as the IPv4 address they carry, which
    /// is how a dual-stack listener reports an IPv4 peer.
    #[must_use]
    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.trusted_proxies.iter().any(|net| net.contains(&ip))
    }

    /// Create a rate limiter with default configuration
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Get the rate limiter configuration
    #[must_use]
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Check if a request from the given agent should be allowed
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the request is allowed
    /// * `Err(RateLimitError)` if the rate limit is exceeded
    ///
    /// # Order: the caller's own bucket first, the shared one second
    ///
    /// The per-agent bucket is charged BEFORE the global one, and a global
    /// rejection refunds the per-agent token it just took.
    ///
    /// The reverse order made the global bucket a quota that one caller could
    /// drain for everyone: every request spent a global token before its own
    /// limit was consulted, so a single client hammering past its own limit
    /// kept consuming global capacity with requests that were then rejected
    /// anyway, and every other client got `GlobalLimitExceeded`. That is the
    /// same "one client 429s everyone" failure as a shared bucket, only
    /// larger. Charging the private bucket first means a request the caller's
    /// own limit rejects never touches shared capacity.
    ///
    /// The refund keeps the converse honest: a request the SERVICE refused for
    /// load is not billed to the caller's private quota.
    pub fn check(&self, agent_id: &AgentId) -> Result<(), RateLimitError> {
        self.check_agent(agent_id)?;

        if self.config.enable_global_limit {
            if let Err(global) = self.check_global() {
                self.refund_agent(agent_id);
                return Err(global);
            }
        }

        Ok(())
    }

    /// Return the token [`Self::check_agent`] just took, capped at capacity.
    fn refund_agent(&self, agent_id: &AgentId) {
        let mut buckets = self
            .agent_buckets
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(bucket) = buckets.get_mut(agent_id) {
            bucket.tokens = (bucket.tokens + 1.0).min(bucket.max_tokens);
        }
    }

    /// Check global rate limit
    fn check_global(&self) -> Result<(), RateLimitError> {
        let mut bucket = self
            .global_bucket
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        bucket
            .try_consume()
            .map_err(|retry_after| RateLimitError::GlobalLimitExceeded {
                retry_after_secs: retry_after,
            })
    }

    /// Check per-agent rate limit
    fn check_agent(&self, agent_id: &AgentId) -> Result<(), RateLimitError> {
        let mut buckets = self
            .agent_buckets
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.sweep_idle_if_due(&mut buckets);
        let limit = self.get_agent_limit(agent_id);

        let bucket = buckets
            .entry(*agent_id)
            .or_insert_with(|| TokenBucket::new(limit, limit as f64 / 60.0));

        bucket.try_consume().map_err(|retry_after| {
            // Calculate approximate current rate (tokens used)
            let used_tokens = (limit as f64 - bucket.tokens).max(0.0) as u32;
            RateLimitError::AgentLimitExceeded {
                agent_id: *agent_id,
                retry_after_secs: retry_after,
                current_rate: used_tokens.min(limit) + 1, // +1 for the current request
                limit,
            }
        })
    }

    /// Drop every bucket that has refilled to capacity, at most once per
    /// [`IDLE_SWEEP_INTERVAL_SECS`].
    ///
    /// # Why this exists
    ///
    /// Buckets were created per key on first sight and removed only by
    /// [`Self::reset_agent`], so the table grew by one entry for every distinct
    /// key the limiter was ever asked about. Keyed by client address, that is
    /// memory an unauthenticated caller can grow without bound just by
    /// arriving from new addresses.
    ///
    /// # Why evicting a FULL bucket is exact, not approximate
    ///
    /// A bucket is created full. A bucket that has refilled to capacity is
    /// therefore indistinguishable from the one `check_agent` would create for
    /// that key on its next request, so dropping it changes no decision the
    /// limiter makes. A bucket that is still below capacity is kept: evicting
    /// it would hand a throttled caller a fresh quota, which is a bypass.
    fn sweep_idle_if_due(&self, buckets: &mut HashMap<AgentId, TokenBucket>) {
        let now = Utc::now();
        {
            let mut last = self
                .last_sweep
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if now.signed_duration_since(*last)
                < chrono::Duration::seconds(IDLE_SWEEP_INTERVAL_SECS)
            {
                return;
            }
            *last = now;
        }
        buckets.retain(|_, bucket| {
            bucket.refill();
            bucket.tokens < bucket.max_tokens
        });
    }

    /// Number of keys that currently hold a bucket (for monitoring and tests).
    #[must_use]
    pub fn tracked_keys(&self) -> usize {
        self.agent_buckets
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Get the rate limit for a specific agent
    fn get_agent_limit(&self, agent_id: &AgentId) -> u32 {
        let limits = self
            .agent_limits
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        limits
            .get(agent_id)
            .copied()
            .unwrap_or(self.config.default_rpm)
    }

    /// Set a custom rate limit for an agent
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The agent to set the limit for
    /// * `rpm` - Requests per minute allowed
    pub fn set_agent_limit(&self, agent_id: AgentId, rpm: u32) {
        let mut limits = self
            .agent_limits
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        limits.insert(agent_id, rpm);

        // Also update the bucket if it exists
        let mut buckets = self
            .agent_buckets
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(bucket) = buckets.get_mut(&agent_id) {
            bucket.max_tokens = rpm as f64;
            bucket.refill_rate = rpm as f64 / 60.0;
        }
    }

    /// Remove custom limit for an agent, reverting to default
    pub fn remove_agent_limit(&self, agent_id: &AgentId) {
        let mut limits = self
            .agent_limits
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        limits.remove(agent_id);
    }

    /// Get the remaining quota for an agent
    ///
    /// Returns the approximate number of requests the agent can make
    /// before hitting their limit.
    #[must_use]
    pub fn remaining_quota(&self, agent_id: &AgentId) -> u32 {
        let mut buckets = self
            .agent_buckets
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(bucket) = buckets.get_mut(agent_id) {
            bucket.refill();
            bucket.tokens as u32
        } else {
            // Agent hasn't made any requests yet, they have their full quota
            self.get_agent_limit(agent_id)
        }
    }

    /// Reset rate limits for an agent (for testing or admin use)
    pub fn reset_agent(&self, agent_id: &AgentId) {
        let mut buckets = self
            .agent_buckets
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        buckets.remove(agent_id);
    }

    /// Reset global rate limit (for testing or admin use)
    pub fn reset_global(&self) {
        let mut bucket = self
            .global_bucket
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *bucket = TokenBucket::new(self.config.global_rpm, self.config.global_rpm as f64 / 60.0);
    }

    /// Simulate time passing for testing purposes
    ///
    /// # Arguments
    ///
    /// * `duration` - The duration to advance time by
    ///
    /// # Note
    ///
    /// This is a testing helper that manually triggers token replenishment
    /// as if time had passed. In production, tokens replenish naturally
    /// based on wall clock time.
    ///
    /// # Warning
    ///
    /// This method is intended for testing only. Do not use in production code.
    pub fn advance_time(&self, duration: chrono::Duration) {
        // For testing, we manually adjust the last_refill time backwards
        // to simulate time passing. The idle-sweep clock moves with them, so
        // a simulated interval makes a sweep due exactly as real time would.
        {
            let mut last = self
                .last_sweep
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *last -= duration;
        }

        {
            let mut bucket = self
                .global_bucket
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            bucket.last_refill -= duration;
        }

        {
            let mut buckets = self
                .agent_buckets
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for bucket in buckets.values_mut() {
                bucket.last_refill -= duration;
            }
        }
    }
}

/// Build the API rate limiter from operator settings, or `None` when it is
/// off.
///
/// Pure: `bin/server.rs` reads `EPIGRAPH_RATE_LIMIT_RPM`,
/// `EPIGRAPH_RATE_LIMIT_GLOBAL_RPM` and `EPIGRAPH_TRUSTED_PROXIES` and passes
/// the raw values in, so every branch is testable without touching process
/// state. `docs/deploy.md` ("API rate limiting") is the operator contract.
///
/// # Off unless asked for
///
/// `rpm` unset, empty or `0` disables rate limiting. It is opt-in because a
/// per-principal quota that suits interactive traffic throttles batch
/// callers (ingestion scripts, bulk `submit/packet`, MCP-over-HTTP), and a
/// deployment should choose its number rather than inherit one.
///
/// # Global limit off unless asked for
///
/// `global_rpm` unset, empty or `0` leaves the global bucket disabled: it is
/// shared by every caller, so a value below real aggregate load turns one busy
/// client into everyone's 429.
///
/// # Trusted proxies
///
/// Unset or empty: loopback ([`default_trusted_proxies`]), which is where the
/// same-host reverse proxy connects from. `none`: trust no one. Otherwise a
/// comma-separated list of addresses and CIDRs. Parsed, and so validated, even
/// when the limiter is off, so a typo fails the boot that introduced it.
///
/// # Errors
///
/// A value that does not parse, or a global limit set without a per-client
/// one (a limit the operator believes is enforced but would not be). The
/// caller refuses to start rather than run with a limit other than the one
/// configured.
pub fn rate_limiter_from_settings(
    rpm: Option<&str>,
    global_rpm: Option<&str>,
    trusted_proxies: Option<&str>,
) -> Result<Option<AgentRateLimiter>, String> {
    fn positive(name: &str, value: Option<&str>) -> Result<Option<u32>, String> {
        match value.map(str::trim).filter(|v| !v.is_empty()) {
            None => Ok(None),
            Some(v) => match v.parse::<u32>() {
                Ok(0) => Ok(None),
                Ok(n) => Ok(Some(n)),
                Err(e) => Err(format!(
                    "{name}={v:?} is not a whole number of requests per minute: {e}"
                )),
            },
        }
    }

    // Empty is unset, as for the two limits: `Environment=EPIGRAPH_TRUSTED_PROXIES=`
    // in a unit file must not quietly mean "trust no one", which behind a
    // same-host proxy puts every client in the proxy's bucket.
    let trusted = match trusted_proxies.map(str::trim).filter(|v| !v.is_empty()) {
        None => default_trusted_proxies(),
        Some(v) if v.eq_ignore_ascii_case("none") => Vec::new(),
        Some(v) => v
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                entry
                    .parse::<IpNet>()
                    .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                    .map(|net| net.trunc())
                    .map_err(|_| {
                        format!(
                            "EPIGRAPH_TRUSTED_PROXIES entry {entry:?} is neither an IP address \
                             nor a CIDR (use `none` to trust no proxy)"
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?,
    };

    let per_client = positive("EPIGRAPH_RATE_LIMIT_RPM", rpm)?;
    let global = positive("EPIGRAPH_RATE_LIMIT_GLOBAL_RPM", global_rpm)?;

    let Some(default_rpm) = per_client else {
        if global.is_some() {
            return Err(
                "EPIGRAPH_RATE_LIMIT_GLOBAL_RPM is set but EPIGRAPH_RATE_LIMIT_RPM \
                        is not, so no rate limiting would run at all; set both, or unset \
                        the global limit"
                    .to_string(),
            );
        }
        return Ok(None);
    };

    let config = RateLimitConfig {
        default_rpm,
        global_rpm: global.unwrap_or(0),
        replenish_interval_secs: 1,
        enable_global_limit: global.is_some(),
    };
    Ok(Some(
        AgentRateLimiter::new(config).with_trusted_proxies(trusted),
    ))
}

impl std::fmt::Debug for AgentRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentRateLimiter")
            .field("config", &self.config)
            .field("trusted_proxies", &self.trusted_proxies)
            .field(
                "agent_buckets_count",
                &self
                    .agent_buckets
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .len(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_requests_under_limit() {
        let mut bucket = TokenBucket::new(10, 1.0);
        for _ in 0..10 {
            assert!(bucket.try_consume().is_ok());
        }
    }

    #[test]
    fn token_bucket_rejects_when_empty() {
        let mut bucket = TokenBucket::new(1, 0.1);
        assert!(bucket.try_consume().is_ok());
        assert!(bucket.try_consume().is_err());
    }

    #[test]
    fn rate_limiter_uses_default_config() {
        let limiter = AgentRateLimiter::with_defaults();
        assert_eq!(limiter.config.default_rpm, 60);
        assert_eq!(limiter.config.global_rpm, 1000);
    }

    fn slow_config(default_rpm: u32, global_rpm: u32) -> RateLimitConfig {
        RateLimitConfig {
            default_rpm,
            global_rpm,
            replenish_interval_secs: 60,
            enable_global_limit: true,
        }
    }

    /// One caller hammering past its OWN limit must not spend the global
    /// quota. With the global bucket charged first, the flood's rejected
    /// requests drained it and the next, well-behaved caller got
    /// `GlobalLimitExceeded` without having made a single prior request.
    #[test]
    fn a_caller_over_its_own_limit_does_not_drain_the_global_bucket() {
        let limiter = AgentRateLimiter::new(slow_config(1, 3));
        let flooder = AgentId::new();
        let bystander = AgentId::new();

        assert!(limiter.check(&flooder).is_ok(), "first request is in quota");
        for _ in 0..10 {
            assert!(
                matches!(
                    limiter.check(&flooder),
                    Err(RateLimitError::AgentLimitExceeded { .. })
                ),
                "the flooder is refused by its own bucket"
            );
        }

        assert_eq!(
            limiter.check(&bystander),
            Ok(()),
            "a bystander's first request must not be refused because another \
             caller's rejected requests spent the shared quota"
        );
    }

    /// Churning through keys must not grow the table without bound: once the
    /// sweep interval has passed and the buckets have refilled, they go.
    #[test]
    fn idle_buckets_are_evicted_once_they_have_refilled() {
        let limiter = AgentRateLimiter::new(RateLimitConfig {
            default_rpm: 60,
            global_rpm: 1000,
            replenish_interval_secs: 1,
            enable_global_limit: false,
        });
        for _ in 0..1000 {
            assert!(limiter.check(&AgentId::new()).is_ok());
        }
        assert_eq!(limiter.tracked_keys(), 1000);

        limiter.advance_time(chrono::Duration::seconds(61));
        assert!(limiter.check(&AgentId::new()).is_ok());

        assert_eq!(
            limiter.tracked_keys(),
            1,
            "every refilled bucket must be swept; only the key just checked remains"
        );
    }

    /// The converse, and the one that matters for correctness: a bucket that
    /// is still below capacity survives the sweep, so eviction can never hand
    /// a throttled caller a fresh quota.
    #[test]
    fn a_drained_bucket_survives_the_sweep_and_stays_throttled() {
        let limiter = AgentRateLimiter::new(RateLimitConfig {
            default_rpm: 2,
            global_rpm: 1000,
            replenish_interval_secs: 60,
            enable_global_limit: false,
        });
        let throttled = AgentId::new();
        assert!(limiter.check(&throttled).is_ok());
        assert!(limiter.check(&throttled).is_ok());
        assert!(limiter.check(&throttled).is_err(), "quota of 2 is spent");

        // Due for a sweep, but 10s at 2 rpm refills only a third of a token.
        limiter.advance_time(chrono::Duration::seconds(IDLE_SWEEP_INTERVAL_SECS));
        assert!(limiter.check(&AgentId::new()).is_ok(), "triggers the sweep");

        assert_eq!(limiter.tracked_keys(), 2, "the drained bucket is kept");
        assert!(
            limiter.check(&throttled).is_err(),
            "a sweep must not reset a throttled caller's quota"
        );
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn settings_leave_rate_limiting_off_unless_a_per_client_rpm_is_given() {
        for rpm in [None, Some(""), Some("  "), Some("0")] {
            assert!(
                rate_limiter_from_settings(rpm, None, None)
                    .expect("valid")
                    .is_none(),
                "rpm {rpm:?} must mean disabled"
            );
        }
    }

    #[test]
    fn settings_pass_the_configured_numbers_through() {
        let limiter = rate_limiter_from_settings(Some("120"), None, None)
            .expect("valid")
            .expect("enabled");
        assert_eq!(limiter.config().default_rpm, 120);
        assert!(
            !limiter.config().enable_global_limit,
            "no global limit unless one is configured"
        );
        assert_eq!(limiter.trusted_proxies(), default_trusted_proxies());

        let limiter = rate_limiter_from_settings(Some(" 600 "), Some("50000"), None)
            .expect("valid")
            .expect("enabled");
        assert_eq!(limiter.config().default_rpm, 600);
        assert!(limiter.config().enable_global_limit);
        assert_eq!(limiter.config().global_rpm, 50_000);

        let limiter = rate_limiter_from_settings(Some("60"), Some("0"), None)
            .expect("valid")
            .expect("enabled");
        assert!(
            !limiter.config().enable_global_limit,
            "0 disables the global limit"
        );
    }

    #[test]
    fn settings_parse_trusted_proxies() {
        let limiter = rate_limiter_from_settings(
            Some("60"),
            None,
            Some("10.0.0.0/8, 192.168.1.5,2001:db8::/32,"),
        )
        .expect("valid")
        .expect("enabled");
        assert_eq!(
            limiter.trusted_proxies(),
            [
                net("10.0.0.0/8"),
                net("192.168.1.5/32"),
                net("2001:db8::/32")
            ]
        );
        assert!(limiter.is_trusted_proxy("10.1.2.3".parse().unwrap()));
        assert!(
            !limiter.is_trusted_proxy("127.0.0.1".parse().unwrap()),
            "an explicit list replaces the loopback default"
        );

        let limiter = rate_limiter_from_settings(Some("60"), None, Some("None"))
            .expect("valid")
            .expect("enabled");
        assert!(limiter.trusted_proxies().is_empty());
    }

    #[test]
    fn settings_refuse_values_that_would_not_do_what_they_say() {
        assert!(rate_limiter_from_settings(Some("sixty"), None, None).is_err());
        assert!(rate_limiter_from_settings(Some("-1"), None, None).is_err());
        assert!(rate_limiter_from_settings(Some("60"), Some("lots"), None).is_err());
        assert!(
            rate_limiter_from_settings(None, Some("5000"), None).is_err(),
            "a global limit with no per-client limit would enforce nothing"
        );
        assert!(
            rate_limiter_from_settings(None, None, Some("10.0.0.0/33")).is_err(),
            "a malformed proxy list fails even while the limiter is off"
        );
        assert_eq!(
            rate_limiter_from_settings(Some("60"), None, Some(" "))
                .expect("valid")
                .expect("enabled")
                .trusted_proxies(),
            default_trusted_proxies(),
            "an empty proxy list is unset, not `none`"
        );
    }

    #[test]
    fn the_default_trusted_set_is_loopback_only() {
        let limiter = AgentRateLimiter::with_defaults();
        assert!(limiter.is_trusted_proxy("127.0.0.1".parse().unwrap()));
        assert!(limiter.is_trusted_proxy("127.3.4.5".parse().unwrap()));
        assert!(limiter.is_trusted_proxy("::1".parse().unwrap()));
        assert!(limiter.is_trusted_proxy("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!limiter.is_trusted_proxy("10.0.0.1".parse().unwrap()));
        assert!(!limiter.is_trusted_proxy("::2".parse().unwrap()));
    }

    /// A request the SERVICE refused for load is not billed to the caller.
    #[test]
    fn a_global_rejection_refunds_the_callers_own_token() {
        let limiter = AgentRateLimiter::new(slow_config(2, 1));
        let first = AgentId::new();
        let second = AgentId::new();

        assert!(
            limiter.check(&first).is_ok(),
            "spends the only global token"
        );
        assert!(matches!(
            limiter.check(&second),
            Err(RateLimitError::GlobalLimitExceeded { .. })
        ));
        assert_eq!(
            limiter.remaining_quota(&second),
            2,
            "the globally-refused request must not have cost the caller a token"
        );
    }
}
