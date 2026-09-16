//! Small in-memory maps with per-entry expiry.
//!
//! [`TtlMap`] backs short-lived auth state (pending logins, embed handoff
//! codes); [`ResponseCache`] backs the per-user 60 s overview caches (plan
//! §3.4). Both are process-local: a restart empties them, like the session
//! store.

use std::any::Any;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A clonable handle to a mutex-guarded map whose entries expire.
///
/// Expired entries are invisible to every read; [`TtlMap::purge_expired`]
/// reclaims their memory (main.rs runs it periodically).
pub struct TtlMap<K, V> {
    inner: Arc<Mutex<HashMap<K, (Instant, V)>>>,
}

impl<K, V> Clone for TtlMap<K, V> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<K: Eq + Hash, V: Clone> Default for TtlMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Eq + Hash, V: Clone> TtlMap<K, V> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<K, (Instant, V)>> {
        // A panic while holding the lock cannot leave the map half-written
        // (every critical section is a single HashMap call), so recover.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Insert or replace `key`, visible for `ttl` from now.
    pub fn insert(&self, key: K, value: V, ttl: Duration) {
        let deadline = Instant::now() + ttl;
        self.lock().insert(key, (deadline, value));
    }

    /// A clone of the live value for `key`.
    pub fn get(&self, key: &K) -> Option<V> {
        let now = Instant::now();
        let mut map = self.lock();
        match map.get(key) {
            Some((deadline, v)) if *deadline > now => Some(v.clone()),
            Some(_) => {
                map.remove(key);
                None
            }
            None => None,
        }
    }

    /// Remove `key` and return its value if it was still live. Use this for
    /// single-use values (OAuth `state`, handoff codes): a second `take`
    /// always returns `None`.
    pub fn take(&self, key: &K) -> Option<V> {
        let now = Instant::now();
        match self.lock().remove(key) {
            Some((deadline, v)) if deadline > now => Some(v),
            _ => None,
        }
    }

    pub fn remove(&self, key: &K) {
        self.lock().remove(key);
    }

    /// Drop every expired entry; returns how many were dropped.
    pub fn purge_expired(&self) -> usize {
        let now = Instant::now();
        let mut map = self.lock();
        let before = map.len();
        map.retain(|_, (deadline, _)| *deadline > now);
        before - map.len()
    }

    /// Entries currently held, including expired ones not yet purged.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<K: Eq + Hash + Clone, V: Clone> TtlMap<K, V> {
    /// Shrink the map to at most `max` entries by dropping the ones whose
    /// deadlines are nearest; returns how many were dropped.
    ///
    /// This is the bound for maps anyone can fill (pending logins): refusing
    /// a new entry when the map is full turns a flood into a denial of
    /// service for every user, so the cap evicts instead. Entries share one
    /// TTL there, so "nearest deadline" is "inserted longest ago" — a flood
    /// mostly evicts its own earlier entries, and an evicted sign-in fails
    /// the way an expired one does (the browser can retry).
    pub fn evict_oldest_beyond(&self, max: usize) -> usize {
        let mut map = self.lock();
        let excess = map.len().saturating_sub(max);
        if excess == 0 {
            return 0;
        }
        let mut by_deadline: Vec<(Instant, K)> =
            map.iter().map(|(k, (d, _))| (*d, k.clone())).collect();
        by_deadline.sort_unstable_by_key(|(d, _)| *d);
        for (_, key) in by_deadline.into_iter().take(excess) {
            map.remove(&key);
        }
        excess
    }
}

type AnyArc = Arc<dyn Any + Send + Sync>;

/// A typed-on-read TTL cache keyed by string.
///
/// Keys must include the viewer's [`crate::auth::RequestAuth::cache_key`]
/// whenever the cached value came from an authenticated upstream call:
/// upstream redaction differs per viewer.
#[derive(Clone, Default)]
pub struct ResponseCache {
    map: TtlMap<String, AnyArc>,
}

impl ResponseCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The cached value for `key` if it is live and of type `T`.
    pub fn get<T: Any + Send + Sync>(&self, key: &str) -> Option<Arc<T>> {
        self.map
            .get(&key.to_string())
            .and_then(|v| v.downcast::<T>().ok())
    }

    pub fn insert<T: Any + Send + Sync>(
        &self,
        key: impl Into<String>,
        value: Arc<T>,
        ttl: Duration,
    ) {
        self.map.insert(key.into(), value, ttl);
    }

    pub fn purge_expired(&self) -> usize {
        self.map.purge_expired()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_expire() {
        let m: TtlMap<&str, u32> = TtlMap::new();
        m.insert("a", 1, Duration::from_secs(60));
        m.insert("b", 2, Duration::ZERO);
        assert_eq!(m.get(&"a"), Some(1));
        assert_eq!(m.get(&"b"), None);
        assert_eq!(
            m.purge_expired(),
            0,
            "get already dropped the expired entry"
        );
        m.insert("c", 3, Duration::ZERO);
        assert_eq!(m.purge_expired(), 1);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn take_is_single_use() {
        let m: TtlMap<String, u32> = TtlMap::new();
        m.insert("code".into(), 7, Duration::from_secs(60));
        assert_eq!(m.take(&"code".into()), Some(7));
        assert_eq!(m.take(&"code".into()), None);

        m.insert("late".into(), 8, Duration::ZERO);
        assert_eq!(m.take(&"late".into()), None);
    }

    #[test]
    fn eviction_drops_the_nearest_deadlines_first() {
        let m: TtlMap<String, u32> = TtlMap::new();
        for (i, secs) in [30u64, 10, 20, 40].into_iter().enumerate() {
            m.insert(format!("k{i}"), i as u32, Duration::from_secs(secs));
        }
        assert_eq!(m.evict_oldest_beyond(4), 0, "already within the cap");
        assert_eq!(m.evict_oldest_beyond(2), 2);
        assert_eq!(m.len(), 2);
        assert_eq!(m.get(&"k1".to_string()), None, "10 s deadline went first");
        assert_eq!(m.get(&"k2".to_string()), None, "then the 20 s one");
        assert_eq!(m.get(&"k0".to_string()), Some(0));
        assert_eq!(m.get(&"k3".to_string()), Some(3));

        // Evicting to zero empties the map rather than panicking.
        assert_eq!(m.evict_oldest_beyond(0), 2);
        assert!(m.is_empty());
        assert_eq!(m.evict_oldest_beyond(0), 0);
    }

    #[test]
    fn response_cache_is_typed() {
        let c = ResponseCache::new();
        c.insert("k", Arc::new(vec![1u8, 2]), Duration::from_secs(60));
        assert_eq!(c.get::<Vec<u8>>("k").as_deref(), Some(&vec![1u8, 2]));
        assert!(c.get::<String>("k").is_none(), "wrong type reads as a miss");
        assert!(c.get::<Vec<u8>>("missing").is_none());
    }
}
