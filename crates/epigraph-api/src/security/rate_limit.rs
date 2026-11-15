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
use std::sync::{Arc, RwLock};
use thiserror::Error;

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

/// Per-client requests per minute. Unset or empty: rate limiting is OFF.
pub const RATE_LIMIT_RPM_ENV: &str = "EPIGRAPH_RATE_LIMIT_RPM";
/// Requests per minute across all clients together. Optional; only read when
/// [`RATE_LIMIT_RPM_ENV`] is set. Unset: no global ceiling.
pub const RATE_LIMIT_GLOBAL_RPM_ENV: &str = "EPIGRAPH_RATE_LIMIT_GLOBAL_RPM";

impl RateLimitConfig {
    /// The rate limit an operator configured through
    /// [`RATE_LIMIT_RPM_ENV`] / [`RATE_LIMIT_GLOBAL_RPM_ENV`], given as the
    /// two variables' values so the rule is testable without touching the
    /// process environment.
    ///
    /// - `Ok(None)`: neither is set (or both are blank). Rate limiting is off.
    /// - `Ok(Some(config))`: the per-client limit, with the global ceiling
    ///   enabled only when one was given.
    /// - `Err(reason)`: a value was given and is unusable. The server refuses
    ///   to start on this rather than run with no limit while the operator
    ///   believes one is installed.
    ///
    /// # Errors
    /// A value that is not a positive integer; a global ceiling given without
    /// a per-client limit, or lower than it.
    pub fn from_env_values(
        per_client: Option<&str>,
        global: Option<&str>,
    ) -> Result<Option<Self>, String> {
        fn given(v: Option<&str>) -> Option<&str> {
            v.map(str::trim).filter(|v| !v.is_empty())
        }
        let parse = |name: &str, raw: &str| -> Result<u32, String> {
            match raw.parse::<u32>() {
                Ok(n) if n > 0 => Ok(n),
                _ => Err(format!(
                    "{name}={raw:?} is not a positive whole number of requests per minute"
                )),
            }
        };
        let (per_client, global) = (given(per_client), given(global));
        let Some(per_client) = per_client else {
            return match global {
                None => Ok(None),
                Some(_) => Err(format!(
                    "{RATE_LIMIT_GLOBAL_RPM_ENV} is set but {RATE_LIMIT_RPM_ENV} is not; the \
                     per-client limit is what turns rate limiting on"
                )),
            };
        };
        let default_rpm = parse(RATE_LIMIT_RPM_ENV, per_client)?;
        let global_rpm = match global {
            Some(raw) => {
                let g = parse(RATE_LIMIT_GLOBAL_RPM_ENV, raw)?;
                if g < default_rpm {
                    return Err(format!(
                        "{RATE_LIMIT_GLOBAL_RPM_ENV}={g} is below {RATE_LIMIT_RPM_ENV}=\
                         {default_rpm}: one client could never reach its own limit"
                    ));
                }
                Some(g)
            }
            None => None,
        };
        Ok(Some(Self {
            default_rpm,
            // Unused when the global limit is off, but the bucket is still
            // built from it, so it is given a sane value rather than zero.
            global_rpm: global_rpm.unwrap_or(default_rpm),
            replenish_interval_secs: 1,
            enable_global_limit: global_rpm.is_some(),
        }))
    }
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
        }
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
        // Check global limit first
        if self.config.enable_global_limit {
            self.check_global()?;
        }

        // Check per-agent limit
        self.check_agent(agent_id)
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
        // to simulate time passing
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

impl std::fmt::Debug for AgentRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentRateLimiter")
            .field("config", &self.config)
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
mod env_config_tests {
    use super::RateLimitConfig;

    #[test]
    fn unset_or_blank_is_off() {
        assert!(RateLimitConfig::from_env_values(None, None)
            .unwrap()
            .is_none());
        assert!(RateLimitConfig::from_env_values(Some("  "), Some(""))
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_per_client_limit_alone_has_no_global_ceiling() {
        let c = RateLimitConfig::from_env_values(Some("120"), None)
            .unwrap()
            .expect("configured");
        assert_eq!(c.default_rpm, 120);
        assert!(!c.enable_global_limit);
    }

    #[test]
    fn both_limits_are_carried() {
        let c = RateLimitConfig::from_env_values(Some("120"), Some("3000"))
            .unwrap()
            .expect("configured");
        assert_eq!((c.default_rpm, c.global_rpm), (120, 3000));
        assert!(c.enable_global_limit);
    }

    /// An unusable value is an error, never "off": the operator set a limit
    /// and must not get a server with none.
    #[test]
    fn an_unusable_value_is_refused() {
        for (per_client, global) in [
            (Some("0"), None),
            (Some("-5"), None),
            (Some("sixty"), None),
            (Some("60"), Some("0")),
            (Some("60"), Some("lots")),
            (Some("600"), Some("60")),
            (None, Some("1000")),
        ] {
            assert!(
                RateLimitConfig::from_env_values(per_client, global).is_err(),
                "({per_client:?}, {global:?}) must be refused"
            );
        }
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
}
