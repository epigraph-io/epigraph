//! Embedding cache to prevent duplicate API calls
//!
//! The cache stores text -> embedding mappings to avoid regenerating
//! embeddings for previously seen text.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::errors::EmbeddingError;

// =============================================================================
// CACHE CONSTANTS
// =============================================================================

/// Default time-to-live for cache entries in seconds (1 hour).
/// After this duration, cached embeddings are considered stale.
pub const DEFAULT_CACHE_TTL_SECS: u64 = 3600;

/// Default maximum number of entries in the cache.
/// When exceeded, oldest entries are evicted (LRU-style).
pub const DEFAULT_CACHE_MAX_ENTRIES: usize = 10_000;

/// Entry in the embedding cache
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The embedding vector
    embedding: Vec<f32>,
    /// When this entry was created
    created_at: Instant,
}

/// Thread-safe embedding cache
pub struct EmbeddingCache {
    /// The cache storage
    entries: RwLock<HashMap<String, CacheEntry>>,
    /// Time-to-live for cache entries
    ttl: Option<Duration>,
    /// Maximum number of entries
    max_entries: usize,
}

impl EmbeddingCache {
    /// Create a new cache with the given TTL
    ///
    /// # Arguments
    /// * `ttl_secs` - Time-to-live in seconds (0 = no expiration)
    /// * `max_entries` - Maximum number of entries to store
    #[must_use]
    pub fn new(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl: if ttl_secs == 0 {
                None
            } else {
                Some(Duration::from_secs(ttl_secs))
            },
            max_entries,
        }
    }

    /// Create a cache with no expiration
    #[must_use]
    pub fn no_expiration(max_entries: usize) -> Self {
        Self::new(0, max_entries)
    }

    /// Get an embedding from the cache
    ///
    /// Returns `None` if the entry doesn't exist or has expired.
    pub fn get(&self, text: &str) -> Option<Vec<f32>> {
        let key = Self::make_key(text);
        let entries = self.entries.read().ok()?;

        if let Some(entry) = entries.get(&key) {
            // Check TTL
            if let Some(ttl) = self.ttl {
                if entry.created_at.elapsed() > ttl {
                    return None;
                }
            }
            Some(entry.embedding.clone())
        } else {
            None
        }
    }

    /// Store an embedding in the cache
    ///
    /// # Errors
    /// Returns error if the cache lock cannot be acquired.
    pub fn put(&self, text: &str, embedding: Vec<f32>) -> Result<(), EmbeddingError> {
        let key = Self::make_key(text);
        let mut entries = self
            .entries
            .write()
            .map_err(|e| EmbeddingError::CacheError(e.to_string()))?;

        // Evict oldest entries if at capacity
        if entries.len() >= self.max_entries {
            self.evict_oldest(&mut entries);
        }

        entries.insert(
            key,
            CacheEntry {
                embedding,
                created_at: Instant::now(),
            },
        );

        Ok(())
    }

    /// Check if the cache contains an entry for the given text
    pub fn contains(&self, text: &str) -> bool {
        self.get(text).is_some()
    }

    /// Clear all entries from the cache
    pub fn clear(&self) -> Result<(), EmbeddingError> {
        let mut entries = self
            .entries
            .write()
            .map_err(|e| EmbeddingError::CacheError(e.to_string()))?;
        entries.clear();
        Ok(())
    }

    /// Get the number of entries in the cache
    pub fn len(&self) -> usize {
        self.entries.read().map(|e| e.len()).unwrap_or(0)
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get cache hit statistics
    ///
    /// Returns (hits, misses) since creation.
    /// Note: This is a simplified implementation without actual tracking.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entries: self.len(),
            max_entries: self.max_entries,
        }
    }

    /// Create a cache key from text
    fn make_key(text: &str) -> String {
        // Use the text directly as key (could hash for memory efficiency)
        text.to_string()
    }

    /// Evict the oldest entry
    #[allow(clippy::unused_self)]
    fn evict_oldest(&self, entries: &mut HashMap<String, CacheEntry>) {
        if let Some(oldest_key) = entries
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(k, _)| k.clone())
        {
            entries.remove(&oldest_key);
        }
    }
}

impl Default for EmbeddingCache {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_TTL_SECS, DEFAULT_CACHE_MAX_ENTRIES)
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Current number of entries
    pub entries: usize,
    /// Maximum entries allowed
    pub max_entries: usize,
}
