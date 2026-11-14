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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use thiserror::Error;

/// The reverse proxies whose `X-Forwarded-For` this process believes.
///
/// A rate-limit key taken from `X-Forwarded-For` is only as honest as the hop
/// that wrote it. Every hop to the LEFT of the last one a trusted proxy
/// appended was written by the client, so it can be anything. The middleware
/// therefore reads the header only when the TCP peer is in this set, and then
/// takes the right-most hop that is not itself a trusted proxy
/// (`middleware::rate_limit`). With an empty set the header is ignored and the
/// TCP peer is the key.
///
/// Entries are single addresses or CIDR prefixes. IPv4-mapped IPv6 addresses
/// (`::ffff:a.b.c.d`) are matched as IPv4.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies {
    nets: Vec<(IpAddr, u8)>,
}

impl TrustedProxies {
    /// Trust no proxy: the TCP peer is always the client.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Trust the loopback interface only (`127.0.0.0/8`, `::1`): a reverse
    /// proxy on the same host. No remote client can be a loopback peer.
    #[must_use]
    pub fn loopback() -> Self {
        Self {
            nets: vec![
                (IpAddr::from([127, 0, 0, 0]), 8),
                (IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]), 128),
            ],
        }
    }

    /// Parse a comma-separated list of addresses and CIDR prefixes, or the
    /// literal `none`. Whitespace around entries is ignored; an empty entry,
    /// an unparseable address and an out-of-range prefix are errors, so a
    /// typo refuses rather than silently trusting less (or more) than meant.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.eq_ignore_ascii_case("none") {
            return Ok(Self::none());
        }
        let mut nets = Vec::new();
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                return Err(format!("empty entry in trusted-proxy list {raw:?}"));
            }
            let (addr, prefix) = match entry.split_once('/') {
                Some((a, p)) => (a, Some(p)),
                None => (entry, None),
            };
            let ip: IpAddr = addr
                .parse()
                .map_err(|_| format!("{entry:?} is not an IP address or CIDR prefix"))?;
            let ip = ip.to_canonical();
            let max = if ip.is_ipv4() { 32 } else { 128 };
            let len = match prefix {
                None => max,
                Some(p) => p
                    .parse::<u8>()
                    .ok()
                    .filter(|l| *l <= max)
                    .ok_or_else(|| format!("{entry:?} has an invalid prefix length"))?,
            };
            nets.push((ip, len));
        }
        Ok(Self { nets })
    }

    /// Whether `ip` is one of the trusted proxies.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.nets
            .iter()
            .any(|(net, len)| prefix_matches(*net, *len, ip))
    }

    /// Whether the set is empty (`X-Forwarded-For` is never read).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }
}

impl std::fmt::Display for TrustedProxies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.nets.is_empty() {
            return f.write_str("none");
        }
        let list: Vec<String> = self
            .nets
            .iter()
            .map(|(ip, len)| format!("{ip}/{len}"))
            .collect();
        f.write_str(&list.join(","))
    }
}

fn prefix_matches(net: IpAddr, len: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
    }
}

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
    /// Last time a refusal from this bucket was recorded
    /// ([`AgentRateLimiter::should_record_rejection`])
    last_recorded: Option<DateTime<Utc>>,
}

impl TokenBucket {
    /// Create a new token bucket
    fn new(max_tokens: u32, refill_rate_per_second: f64) -> Self {
        Self {
            tokens: max_tokens as f64,
            max_tokens: max_tokens as f64,
            refill_rate: refill_rate_per_second,
            last_refill: Utc::now(),
            last_recorded: None,
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

    /// Whether a refusal from this bucket is due to be recorded, marking it
    /// recorded if so.
    fn take_record_slot(&mut self, now: DateTime<Utc>) -> bool {
        match self.last_recorded {
            Some(t)
                if now.signed_duration_since(t).num_seconds() < REJECTION_RECORD_INTERVAL_SECS =>
            {
                false
            }
            _ => {
                self.last_recorded = Some(now);
                true
            }
        }
    }

    /// Get current available tokens (for testing/monitoring)
    #[allow(dead_code)]
    fn available_tokens(&mut self) -> f64 {
        self.refill();
        self.tokens
    }
}

/// Seconds between two recorded refusals of one bucket
/// ([`AgentRateLimiter::should_record_rejection`]).
pub const REJECTION_RECORD_INTERVAL_SECS: i64 = 60;

/// How many per-key buckets a limiter tracks before it prunes ([`BucketMap`]).
pub const DEFAULT_MAX_TRACKED_KEYS: usize = 100_000;

/// The least time between two prune passes over a full map: a pass is
/// O(tracked keys), and a flood of new keys at the cap would otherwise pay it
/// on every request.
const PRUNE_INTERVAL_MS: i64 = 1_000;

/// The per-key buckets, bounded.
///
/// A key is any client the middleware can tell apart, so an anonymous client
/// that rotates its address mints keys at will. At `max` keys the map first
/// drops every bucket that has refilled to capacity (lossless: a full bucket
/// behaves exactly like a fresh one). If that frees nothing, a NEW key is
/// charged to one shared overflow bucket until a later prune frees a slot;
/// tracked keys, including throttled ones, keep their own buckets and debts.
#[derive(Debug, Default)]
struct BucketMap {
    map: HashMap<AgentId, TokenBucket>,
    overflow: Option<TokenBucket>,
    last_prune: Option<DateTime<Utc>>,
}

impl BucketMap {
    /// Drop refilled buckets, at most once per [`PRUNE_INTERVAL_MS`].
    fn prune(&mut self) {
        let now = Utc::now();
        if let Some(last) = self.last_prune {
            if now.signed_duration_since(last).num_milliseconds() < PRUNE_INTERVAL_MS {
                return;
            }
        }
        self.last_prune = Some(now);
        self.map.retain(|_, bucket| {
            bucket.refill();
            bucket.tokens < bucket.max_tokens
        });
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
    /// Per-agent token buckets, bounded by `max_tracked_keys`
    agent_buckets: Arc<RwLock<BucketMap>>,
    /// The most per-key buckets tracked at once ([`BucketMap`])
    max_tracked_keys: usize,
    /// Global token bucket
    global_bucket: Arc<RwLock<TokenBucket>>,
    /// Custom limits per agent (requests per minute)
    agent_limits: Arc<RwLock<HashMap<AgentId, u32>>>,
    /// Proxies whose `X-Forwarded-For` the HTTP middleware believes when it
    /// keys an anonymous request. Empty by default: the TCP peer is the key.
    trusted_proxies: TrustedProxies,
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
            agent_buckets: Arc::new(RwLock::new(BucketMap::default())),
            max_tracked_keys: DEFAULT_MAX_TRACKED_KEYS,
            global_bucket: Arc::new(RwLock::new(global_bucket)),
            agent_limits: Arc::new(RwLock::new(HashMap::new())),
            trusted_proxies: TrustedProxies::none(),
        }
    }

    /// Cap the number of per-key buckets tracked at once (builder pattern;
    /// at least 1). See [`BucketMap`] for what happens at the cap.
    #[must_use]
    pub fn with_max_tracked_keys(mut self, max: usize) -> Self {
        self.max_tracked_keys = max.max(1);
        self
    }

    /// How many per-key buckets are tracked now (never above the cap).
    #[must_use]
    pub fn tracked_keys(&self) -> usize {
        self.agent_buckets
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .map
            .len()
    }

    /// Set the proxies whose `X-Forwarded-For` is believed (builder pattern).
    #[must_use]
    pub fn with_trusted_proxies(mut self, trusted_proxies: TrustedProxies) -> Self {
        self.trusted_proxies = trusted_proxies;
        self
    }

    /// The proxies whose `X-Forwarded-For` is believed.
    #[must_use]
    pub fn trusted_proxies(&self) -> &TrustedProxies {
        &self.trusted_proxies
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
    pub fn check(&self, agent_id: &AgentId) -> Result<(), RateLimitError> {
        // Per-key limit FIRST. A request it refuses must not spend a global
        // token, or one throttled client that keeps retrying drains the global
        // bucket and every other client is refused with it. (A request the
        // global limit then refuses has spent its key's token; that only
        // under-serves a client while the whole service is over its limit.)
        self.check_agent(agent_id)?;

        if self.config.enable_global_limit {
            self.check_global()?;
        }
        Ok(())
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
        // Read the limit BEFORE taking the bucket lock: `set_agent_limit`
        // takes the limits lock and then the bucket lock, so holding the
        // bucket lock while reading limits could deadlock against it.
        let limit = self.get_agent_limit(agent_id);
        let mut guard = self
            .agent_buckets
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let buckets = &mut *guard;

        if !buckets.map.contains_key(agent_id) && buckets.map.len() >= self.max_tracked_keys {
            buckets.prune();
        }
        let bucket =
            if buckets.map.contains_key(agent_id) || buckets.map.len() < self.max_tracked_keys {
                buckets
                    .map
                    .entry(*agent_id)
                    .or_insert_with(|| TokenBucket::new(limit, limit as f64 / 60.0))
            } else {
                let rpm = self.config.default_rpm;
                buckets
                    .overflow
                    .get_or_insert_with(|| TokenBucket::new(rpm, rpm as f64 / 60.0))
            };
        let bucket_limit = bucket.max_tokens as u32;

        bucket.try_consume().map_err(|retry_after| {
            // Calculate approximate current rate (tokens used)
            let used_tokens = (bucket.max_tokens - bucket.tokens).max(0.0) as u32;
            RateLimitError::AgentLimitExceeded {
                agent_id: *agent_id,
                retry_after_secs: retry_after,
                current_rate: used_tokens.min(bucket_limit) + 1, // +1 for the current request
                limit: bucket_limit,
            }
        })
    }

    /// Whether the caller should RECORD this refusal (audit event, database
    /// row, info log): true for the first refusal of a bucket in each
    /// [`REJECTION_RECORD_INTERVAL_SECS`] window, false for the rest.
    ///
    /// Every refusal is still answered 429. Recording each one would let a
    /// single client turn its own refusals into unbounded write load and flush
    /// every other event out of a bounded in-memory audit log. A key charged
    /// to the shared overflow bucket shares its window.
    pub fn should_record_rejection(&self, err: &RateLimitError) -> bool {
        let now = Utc::now();
        match err {
            RateLimitError::AgentLimitExceeded { agent_id, .. } => {
                let mut guard = self
                    .agent_buckets
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let buckets = &mut *guard;
                match buckets.map.get_mut(agent_id) {
                    Some(bucket) => bucket.take_record_slot(now),
                    None => buckets
                        .overflow
                        .as_mut()
                        .map_or(true, |bucket| bucket.take_record_slot(now)),
                }
            }
            RateLimitError::GlobalLimitExceeded { .. } => self
                .global_bucket
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take_record_slot(now),
        }
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
        if let Some(bucket) = buckets.map.get_mut(&agent_id) {
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

        if let Some(bucket) = buckets.map.get_mut(agent_id) {
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
        buckets.map.remove(agent_id);
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
        // to simulate time passing
        {
            let mut bucket = self
                .global_bucket
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            bucket.last_refill -= duration;
            if let Some(t) = bucket.last_recorded.as_mut() {
                *t -= duration;
            }
        }

        {
            let mut guard = self
                .agent_buckets
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let buckets = &mut *guard;
            for bucket in buckets.map.values_mut().chain(buckets.overflow.as_mut()) {
                bucket.last_refill -= duration;
                if let Some(t) = bucket.last_recorded.as_mut() {
                    *t -= duration;
                }
            }
        }
    }
}

impl std::fmt::Debug for AgentRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentRateLimiter")
            .field("config", &self.config)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("agent_buckets_count", &self.tracked_keys())
            .field("max_tracked_keys", &self.max_tracked_keys)
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
    fn trusted_proxies_parse_addresses_and_prefixes() {
        let t = TrustedProxies::parse(" 192.0.2.1, 198.51.100.0/24 ,2001:db8::/32").unwrap();
        assert!(t.contains("192.0.2.1".parse().unwrap()));
        assert!(!t.contains("192.0.2.2".parse().unwrap()));
        assert!(t.contains("198.51.100.77".parse().unwrap()));
        assert!(!t.contains("198.51.101.1".parse().unwrap()));
        assert!(t.contains("2001:db8:1::5".parse().unwrap()));
        assert!(!t.contains("2001:db9::1".parse().unwrap()));
        // IPv4-mapped IPv6 peers match their IPv4 entry.
        assert!(t.contains("::ffff:192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn trusted_proxies_refuse_malformed_lists() {
        assert!(TrustedProxies::parse("192.0.2.1,").is_err());
        assert!(TrustedProxies::parse("not-an-ip").is_err());
        assert!(TrustedProxies::parse("192.0.2.0/33").is_err());
        assert!(TrustedProxies::parse("2001:db8::/129").is_err());
        assert!(TrustedProxies::parse("none").unwrap().is_empty());
        assert!(TrustedProxies::parse("0.0.0.0/0")
            .unwrap()
            .contains("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn loopback_trusts_only_loopback() {
        let t = TrustedProxies::loopback();
        assert!(t.contains("127.0.0.1".parse().unwrap()));
        assert!(t.contains("127.8.9.10".parse().unwrap()));
        assert!(t.contains("::1".parse().unwrap()));
        assert!(!t.contains("203.0.113.1".parse().unwrap()));
        assert!(!t.contains("::2".parse().unwrap()));
    }

    fn key(n: u128) -> AgentId {
        AgentId::from_uuid(uuid::Uuid::from_u128(n))
    }

    fn per_key(rpm: u32) -> AgentRateLimiter {
        AgentRateLimiter::new(RateLimitConfig {
            default_rpm: rpm,
            global_rpm: 1_000_000,
            replenish_interval_secs: 60,
            enable_global_limit: false,
        })
    }

    /// bd5c0f40: one bucket per distinct key, forever, is a memory leak an
    /// anonymous client drives by rotating its address. Buckets that have
    /// refilled are indistinguishable from fresh ones, so dropping them at
    /// the cap loses nothing.
    #[test]
    fn the_bucket_map_is_capped_and_refilled_buckets_are_pruned() {
        let limiter = per_key(2).with_max_tracked_keys(4);
        for n in 0..4 {
            limiter.check(&key(n)).unwrap();
        }
        assert_eq!(limiter.tracked_keys(), 4);
        // Every bucket refills fully.
        limiter.advance_time(chrono::Duration::minutes(2));
        for n in 4..8 {
            // Each newcomer gets a bucket of its OWN (2 requests, then 429):
            // the refilled buckets made room, so nobody lands in the shared
            // overflow bucket.
            limiter.check(&key(n)).unwrap();
            limiter.check(&key(n)).unwrap();
            assert!(limiter.check(&key(n)).is_err());
            assert!(limiter.tracked_keys() <= 4, "map grew past its cap");
        }
    }

    /// When every tracked bucket is still draining, nothing can be dropped
    /// without forgiving a client its debt. New keys then share ONE overflow
    /// bucket, so the map stays bounded and a client already being throttled
    /// stays throttled.
    #[test]
    fn at_the_cap_new_keys_share_an_overflow_bucket() {
        let limiter = per_key(2).with_max_tracked_keys(2);
        for n in 0..2 {
            limiter.check(&key(n)).unwrap();
            limiter.check(&key(n)).unwrap();
            assert!(limiter.check(&key(n)).is_err());
        }
        // The overflow bucket holds default_rpm (2) between all newcomers.
        limiter.check(&key(100)).unwrap();
        limiter.check(&key(101)).unwrap();
        assert!(
            limiter.check(&key(102)).is_err(),
            "the third newcomer at the cap is charged to the spent overflow bucket"
        );
        assert!(limiter.tracked_keys() <= 2, "map grew past its cap");
        assert!(
            limiter.check(&key(0)).is_err(),
            "a tracked, throttled key keeps its debt"
        );
    }

    /// A request the per-key limit refuses must not spend a global token.
    /// Otherwise one throttled client, retrying, drains the global bucket and
    /// every other client gets 429 too: the limiter becomes the DoS.
    #[test]
    fn a_throttled_key_cannot_drain_the_global_bucket() {
        let limiter = AgentRateLimiter::new(RateLimitConfig {
            default_rpm: 1,
            global_rpm: 3,
            replenish_interval_secs: 60,
            enable_global_limit: true,
        });
        limiter.check(&key(1)).unwrap();
        for _ in 0..10 {
            assert!(matches!(
                limiter.check(&key(1)),
                Err(RateLimitError::AgentLimitExceeded { .. })
            ));
        }
        limiter
            .check(&key(2))
            .expect("another client is within both limits");
        limiter
            .check(&key(3))
            .expect("the global bucket still has its third token");
        assert!(matches!(
            limiter.check(&key(4)),
            Err(RateLimitError::GlobalLimitExceeded { .. })
        ));
    }

    #[test]
    fn a_refusal_is_recorded_once_per_key_per_window() {
        let limiter = per_key(1);
        limiter.check(&key(1)).unwrap();
        let err = limiter.check(&key(1)).unwrap_err();
        assert!(limiter.should_record_rejection(&err), "first refusal");
        let err = limiter.check(&key(1)).unwrap_err();
        assert!(!limiter.should_record_rejection(&err), "same window");
        // Another key's refusal is its own.
        limiter.check(&key(2)).unwrap();
        let other = limiter.check(&key(2)).unwrap_err();
        assert!(limiter.should_record_rejection(&other));
        // A window later the same key is recorded again.
        limiter.advance_time(chrono::Duration::seconds(
            REJECTION_RECORD_INTERVAL_SECS + 1,
        ));
        limiter.check(&key(1)).unwrap();
        let err = limiter.check(&key(1)).unwrap_err();
        assert!(limiter.should_record_rejection(&err), "next window");
        // The global bucket has its own window.
        let g = RateLimitError::GlobalLimitExceeded {
            retry_after_secs: 1,
        };
        assert!(limiter.should_record_rejection(&g));
        assert!(!limiter.should_record_rejection(&g));
    }

    #[test]
    fn rate_limiter_uses_default_config() {
        let limiter = AgentRateLimiter::with_defaults();
        assert_eq!(limiter.config.default_rpm, 60);
        assert_eq!(limiter.config.global_rpm, 1000);
    }
}
