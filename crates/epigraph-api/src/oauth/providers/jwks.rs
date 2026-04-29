//! Cached JWKS fetcher shared by all providers.
//!
//! - TTL: 1h.
//! - Stale-grace: 5m beyond TTL if upstream is unreachable on refresh.
//! - Kid-not-found: a single forced refetch; if still missing, validation fails.
//! - Concurrent fetches for the same URL are coalesced (single-flight).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::sync::Mutex;

use super::traits::ProviderError;

const TTL: Duration = Duration::from_secs(60 * 60);
const STALE_GRACE: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
struct Entry {
    keys: Value, // the "keys" array as a Value
    fetched_at: Instant,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    /// Per-URL coalescing locks. Holding the mutex serializes refresh for that URL.
    locks: HashMap<String, Arc<Mutex<()>>>,
}

#[derive(Default, Clone)]
pub struct JwksCache {
    inner: Arc<Mutex<Inner>>,
    fetcher: Option<Arc<dyn JwksFetcher>>,
}

#[async_trait::async_trait]
pub trait JwksFetcher: Send + Sync {
    async fn fetch(&self, url: &str) -> Result<Value, String>;
}

struct ReqwestFetcher;

#[async_trait::async_trait]
impl JwksFetcher for ReqwestFetcher {
    async fn fetch(&self, url: &str) -> Result<Value, String> {
        let resp = reqwest::get(url).await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("status {}", resp.status()));
        }
        resp.json::<Value>().await.map_err(|e| e.to_string())
    }
}

impl JwksCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            fetcher: Some(Arc::new(ReqwestFetcher)),
        }
    }

    /// Test-only constructor that injects a custom fetcher.
    #[cfg(test)]
    pub fn with_fetcher(fetcher: Arc<dyn JwksFetcher>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            fetcher: Some(fetcher),
        }
    }

    /// Fetch (or return cached) JWKS keys array for the given URL.
    pub async fn get(&self, url: &str) -> Result<Value, ProviderError> {
        if let Some(keys) = self.fresh(url).await {
            return Ok(keys);
        }
        self.refresh(url).await
    }

    /// Force a refetch (used when a kid lookup misses on cached JWKS).
    /// Bypasses the TTL check to guarantee an upstream fetch.
    pub async fn refetch(&self, url: &str) -> Result<Value, ProviderError> {
        self.refresh_internal(url, true).await
    }

    async fn fresh(&self, url: &str) -> Option<Value> {
        let inner = self.inner.lock().await;
        let entry = inner.entries.get(url)?;
        if entry.fetched_at.elapsed() < TTL {
            Some(entry.keys.clone())
        } else {
            None
        }
    }

    async fn refresh(&self, url: &str) -> Result<Value, ProviderError> {
        self.refresh_internal(url, false).await
    }

    async fn refresh_internal(&self, url: &str, force_fetch: bool) -> Result<Value, ProviderError> {
        // Acquire per-URL lock for single-flight coalescing.
        let lock = {
            let mut inner = self.inner.lock().await;
            inner
                .locks
                .entry(url.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;

        // Re-check freshness after acquiring the lock — another caller may have refreshed.
        // Skip this check if force_fetch is true (used by refetch).
        if !force_fetch {
            if let Some(keys) = self.fresh(url).await {
                return Ok(keys);
            }
        }

        let fetcher = self
            .fetcher
            .as_ref()
            .expect("JwksCache::new must set fetcher");
        match fetcher.fetch(url).await {
            Ok(body) => {
                let keys = body
                    .get("keys")
                    .cloned()
                    .ok_or_else(|| ProviderError::JwksFetch("missing 'keys' array".into()))?;
                let mut inner = self.inner.lock().await;
                inner.entries.insert(
                    url.to_string(),
                    Entry {
                        keys: keys.clone(),
                        fetched_at: Instant::now(),
                    },
                );
                Ok(keys)
            }
            Err(e) => {
                // Stale-grace: serve cached value if still within TTL+STALE_GRACE.
                let inner = self.inner.lock().await;
                if let Some(entry) = inner.entries.get(url) {
                    if entry.fetched_at.elapsed() < TTL + STALE_GRACE {
                        tracing::warn!(url, error = %e, "JWKS refresh failed, serving stale cache");
                        return Ok(entry.keys.clone());
                    }
                }
                Err(ProviderError::JwksFetch(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingFetcher {
        count: AtomicUsize,
        body: Value,
    }

    #[async_trait::async_trait]
    impl JwksFetcher for CountingFetcher {
        async fn fetch(&self, _url: &str) -> Result<Value, String> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(self.body.clone())
        }
    }

    fn body() -> Value {
        serde_json::json!({"keys":[{"kid":"a","kty":"RSA"}]})
    }

    #[tokio::test]
    async fn caches_within_ttl() {
        let f = Arc::new(CountingFetcher {
            count: AtomicUsize::new(0),
            body: body(),
        });
        let cache = JwksCache::with_fetcher(f.clone());
        cache.get("https://example/jwks").await.unwrap();
        cache.get("https://example/jwks").await.unwrap();
        assert_eq!(f.count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn coalesces_concurrent_misses() {
        let f = Arc::new(CountingFetcher {
            count: AtomicUsize::new(0),
            body: body(),
        });
        let cache = JwksCache::with_fetcher(f.clone());
        let mut handles = vec![];
        for _ in 0..10 {
            let c = cache.clone();
            handles.push(tokio::spawn(async move {
                c.get("https://example/jwks").await.unwrap()
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            f.count.load(Ordering::SeqCst),
            1,
            "10 concurrent gets must hit upstream exactly once"
        );
    }

    struct FailingFetcher {
        count: AtomicUsize,
        succeed_first: bool,
        body: Value,
    }

    #[async_trait::async_trait]
    impl JwksFetcher for FailingFetcher {
        async fn fetch(&self, _url: &str) -> Result<Value, String> {
            let n = self.count.fetch_add(1, Ordering::SeqCst);
            if n == 0 && self.succeed_first {
                Ok(self.body.clone())
            } else {
                Err("upstream 503".into())
            }
        }
    }

    #[tokio::test]
    async fn stale_grace_serves_old_value() {
        let f = Arc::new(FailingFetcher {
            count: AtomicUsize::new(0),
            succeed_first: true,
            body: body(),
        });
        let cache = JwksCache::with_fetcher(f.clone());

        // Seed cache.
        cache.get("https://example/jwks").await.unwrap();

        // Force a refetch — upstream is now failing, but stale cache should serve.
        let result = cache.refetch("https://example/jwks").await.unwrap();
        assert_eq!(result, body().get("keys").cloned().unwrap());
    }

    #[tokio::test]
    async fn cold_failure_returns_error() {
        let f = Arc::new(FailingFetcher {
            count: AtomicUsize::new(0),
            succeed_first: false,
            body: body(),
        });
        let cache = JwksCache::with_fetcher(f);
        let err = cache.get("https://example/jwks").await.unwrap_err();
        assert!(matches!(err, ProviderError::JwksFetch(_)));
    }

    #[tokio::test]
    async fn refetch_forces_upstream_call_even_when_fresh() {
        let f = Arc::new(CountingFetcher {
            count: AtomicUsize::new(0),
            body: body(),
        });
        let cache = JwksCache::with_fetcher(f.clone());
        // Seed the cache.
        cache.get("https://example/jwks").await.unwrap();
        assert_eq!(f.count.load(Ordering::SeqCst), 1);

        // get() within TTL must not refetch.
        cache.get("https://example/jwks").await.unwrap();
        assert_eq!(
            f.count.load(Ordering::SeqCst),
            1,
            "fresh get should not hit upstream"
        );

        // refetch() MUST hit upstream even when cache is fresh — that's its whole purpose.
        cache.refetch("https://example/jwks").await.unwrap();
        assert_eq!(
            f.count.load(Ordering::SeqCst),
            2,
            "refetch must bypass cache"
        );
    }
}
