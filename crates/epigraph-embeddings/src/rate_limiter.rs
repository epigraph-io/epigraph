//! Rate limiting for API calls
//!
//! Implements token bucket rate limiting to respect API quotas.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::RateLimitConfig;
use crate::errors::EmbeddingError;

// =============================================================================
// RATE LIMITING CONSTANTS
// =============================================================================

/// Duration of the rate limit window in seconds.
/// Counters reset after this period elapses.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Token bucket rate limiter
pub struct RateLimiter {
    /// Whether rate limiting is enabled
    enabled: bool,
    /// Maximum requests per minute
    max_rpm: u32,
    /// Maximum tokens per minute
    max_tpm: u32,
    /// Current request count in the window
    request_count: AtomicU32,
    /// Current token count in the window
    token_count: AtomicU32,
    /// Start of current rate limit window
    window_start: Mutex<Instant>,
    /// Total requests made
    total_requests: AtomicU64,
    /// Total tokens used
    total_tokens: AtomicU64,
}

impl RateLimiter {
    /// Create a new rate limiter from configuration
    #[must_use]
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            enabled: config.enabled,
            max_rpm: config.requests_per_minute,
            max_tpm: config.tokens_per_minute,
            request_count: AtomicU32::new(0),
            token_count: AtomicU32::new(0),
            window_start: Mutex::new(Instant::now()),
            total_requests: AtomicU64::new(0),
            total_tokens: AtomicU64::new(0),
        }
    }

    /// Create a disabled rate limiter
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            max_rpm: 0,
            max_tpm: 0,
            request_count: AtomicU32::new(0),
            token_count: AtomicU32::new(0),
            window_start: Mutex::new(Instant::now()),
            total_requests: AtomicU64::new(0),
            total_tokens: AtomicU64::new(0),
        }
    }

    /// Check if a request with the given token count can proceed
    ///
    /// # Arguments
    /// * `tokens` - Number of tokens this request will use
    ///
    /// # Returns
    /// * `Ok(())` - Request can proceed
    /// * `Err(EmbeddingError::RateLimitExceeded)` - Must wait before retrying
    pub fn check(&self, tokens: u32) -> Result<(), EmbeddingError> {
        if !self.enabled {
            return Ok(());
        }

        self.maybe_reset_window();

        let current_requests = self.request_count.load(Ordering::SeqCst);
        let current_tokens = self.token_count.load(Ordering::SeqCst);

        if current_requests >= self.max_rpm {
            return Err(EmbeddingError::RateLimitExceeded {
                retry_after_secs: self.seconds_until_reset(),
            });
        }

        if current_tokens + tokens > self.max_tpm {
            return Err(EmbeddingError::RateLimitExceeded {
                retry_after_secs: self.seconds_until_reset(),
            });
        }

        Ok(())
    }

    /// Record that a request was made with the given token count
    ///
    /// # Arguments
    /// * `tokens` - Number of tokens used by this request
    pub fn record(&self, tokens: u32) {
        if !self.enabled {
            return;
        }

        self.maybe_reset_window();
        self.request_count.fetch_add(1, Ordering::SeqCst);
        self.token_count.fetch_add(tokens, Ordering::SeqCst);
        self.total_requests.fetch_add(1, Ordering::SeqCst);
        self.total_tokens
            .fetch_add(u64::from(tokens), Ordering::SeqCst);
    }

    /// Wait until a request can proceed
    ///
    /// # Arguments
    /// * `tokens` - Number of tokens this request will use
    pub async fn wait_if_needed(&self, tokens: u32) {
        if !self.enabled {
            return;
        }

        while let Err(EmbeddingError::RateLimitExceeded { retry_after_secs }) = self.check(tokens) {
            tokio::time::sleep(Duration::from_secs(retry_after_secs)).await;
        }
    }

    /// Get total requests made
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::SeqCst)
    }

    /// Get total tokens used
    #[must_use]
    pub fn total_tokens(&self) -> u64 {
        self.total_tokens.load(Ordering::SeqCst)
    }

    /// Reset the window if a minute has passed
    fn maybe_reset_window(&self) {
        let mut window_start = self.window_start.lock().unwrap();
        if window_start.elapsed() >= Duration::from_secs(RATE_LIMIT_WINDOW_SECS) {
            *window_start = Instant::now();
            self.request_count.store(0, Ordering::SeqCst);
            self.token_count.store(0, Ordering::SeqCst);
        }
    }

    /// Calculate seconds until the rate limit window resets
    fn seconds_until_reset(&self) -> u64 {
        let window_start = self.window_start.lock().unwrap();
        let elapsed = window_start.elapsed().as_secs();
        RATE_LIMIT_WINDOW_SECS.saturating_sub(elapsed)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(&RateLimitConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_rate_limiter_allows_all() {
        let limiter = RateLimiter::disabled();
        for _ in 0..10000 {
            assert!(limiter.check(1000).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_tracks_totals() {
        // Use an enabled rate limiter to test tracking
        let config = super::RateLimitConfig::default();
        let limiter = RateLimiter::new(&config);
        limiter.record(100);
        limiter.record(200);
        assert_eq!(limiter.total_tokens(), 300);
        assert_eq!(limiter.total_requests(), 2);
    }
}
