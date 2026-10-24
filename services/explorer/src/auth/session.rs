//! In-memory sessions and the `epx_session` cookie (plan §3.3).
//!
//! A session id is 256 random bits, base64url (43 chars). The store maps it to
//! the user's upstream tokens. A restart empties the store and every user
//! signs in again (documented in the README).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use axum::http::{header, HeaderMap, HeaderValue};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use cookie::{Cookie, SameSite};
use rand::RngCore;

use crate::config::Config;

pub const SESSION_COOKIE: &str = "epx_session";
/// Cookie lifetime; matches the upstream refresh token's 30 days.
pub const SESSION_COOKIE_MAX_AGE_SECS: i64 = 30 * 24 * 60 * 60;

/// `nbytes` of OS-seeded CSPRNG output, base64url without padding. Use for
/// session ids, OAuth `state`, PKCE verifiers (32 bytes → 43 chars) and
/// handoff codes.
pub fn random_token(nbytes: usize) -> String {
    let mut buf = vec![0u8; nbytes];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Opaque session identifier. `Debug`/`Display` never print the value.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    const LEN: usize = 43;

    pub fn generate() -> Self {
        SessionId(random_token(32))
    }

    /// Accepts only the exact shape [`SessionId::generate`] produces, so a
    /// junk cookie never reaches the store.
    pub fn parse(raw: &str) -> Option<Self> {
        let ok = raw.len() == Self::LEN
            && raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        ok.then(|| SessionId(raw.to_string()))
    }

    /// The raw value — only for the cookie and for store keys.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionId(<redacted>)")
    }
}

/// One signed-in browser. `Debug` hides the tokens.
#[derive(Clone)]
pub struct Session {
    pub access_token: String,
    /// Rotated on every refresh; always store the new one.
    pub refresh_token: String,
    /// Access-token expiry (from `expires_in` at mint/refresh time).
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

struct Entry {
    session: Session,
    /// Serialises refreshes for this session (single-flight, plan §3.3).
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

/// Clonable handle to the process-wide session map.
#[derive(Clone, Default)]
pub struct SessionStore {
    inner: Arc<RwLock<HashMap<String, Entry>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, Entry>> {
        self.inner.read().unwrap_or_else(|p| p.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, Entry>> {
        self.inner.write().unwrap_or_else(|p| p.into_inner())
    }

    /// Store a new session under a fresh random id.
    pub fn create(
        &self,
        access_token: String,
        refresh_token: String,
        expires_at: DateTime<Utc>,
    ) -> SessionId {
        let id = SessionId::generate();
        let entry = Entry {
            session: Session {
                access_token,
                refresh_token,
                expires_at,
                created_at: Utc::now(),
            },
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        self.write().insert(id.0.clone(), entry);
        id
    }

    pub fn get(&self, id: &SessionId) -> Option<Session> {
        self.read().get(&id.0).map(|e| e.session.clone())
    }

    /// Replace the tokens after a refresh. Returns false if the session is
    /// gone (logged out or expired meanwhile).
    pub fn update_tokens(
        &self,
        id: &SessionId,
        access_token: String,
        refresh_token: String,
        expires_at: DateTime<Utc>,
    ) -> bool {
        match self.write().get_mut(&id.0) {
            Some(e) => {
                e.session.access_token = access_token;
                e.session.refresh_token = refresh_token;
                e.session.expires_at = expires_at;
                true
            }
            None => false,
        }
    }

    pub fn remove(&self, id: &SessionId) -> Option<Session> {
        self.write().remove(&id.0).map(|e| e.session)
    }

    /// The per-session refresh mutex. Hold it across "re-read session →
    /// refresh upstream → store rotated tokens".
    pub fn refresh_lock(&self, id: &SessionId) -> Option<Arc<tokio::sync::Mutex<()>>> {
        self.read().get(&id.0).map(|e| Arc::clone(&e.refresh_lock))
    }

    /// Drop sessions created more than `max_age` ago (their refresh token
    /// has expired upstream anyway). Returns how many were dropped.
    pub fn purge_older_than(&self, max_age: chrono::Duration) -> usize {
        let cutoff = Utc::now() - max_age;
        let mut map = self.write();
        let before = map.len();
        map.retain(|_, e| e.session.created_at > cutoff);
        before - map.len()
    }

    pub fn len(&self) -> usize {
        self.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---- cookies ----------------------------------------------------------------

fn to_header(c: &Cookie<'_>) -> HeaderValue {
    HeaderValue::from_str(&c.to_string()).expect("cookie built from validated parts")
}

fn base_cookie<'c>(config: &Config, value: String) -> Cookie<'c> {
    let mut c = Cookie::new(SESSION_COOKIE, value);
    c.set_path(config.cookie_path().to_string());
    c.set_http_only(true);
    c
}

/// `Set-Cookie` for a first-party sign-in: `HttpOnly; SameSite=Lax;
/// Path={base_path}; Secure` (unless `INSECURE_COOKIES`), 30-day max-age.
pub fn session_cookie(config: &Config, id: &SessionId) -> HeaderValue {
    let mut c = base_cookie(config, id.as_str().to_string());
    c.set_same_site(SameSite::Lax);
    c.set_secure(config.cookie_secure());
    c.set_max_age(cookie::time::Duration::seconds(SESSION_COOKIE_MAX_AGE_SECS));
    to_header(&c)
}

/// `Set-Cookie` for the embed redeem (`POST /auth/redeem`, plan §3.3):
/// `SameSite=None; Secure; Partitioned` so the third-party Notion iframe can
/// hold it. Always `Secure` — browsers drop `SameSite=None` without it.
pub fn embed_session_cookie(config: &Config, id: &SessionId) -> HeaderValue {
    let mut c = base_cookie(config, id.as_str().to_string());
    c.set_same_site(SameSite::None);
    c.set_secure(true);
    c.set_partitioned(true);
    c.set_max_age(cookie::time::Duration::seconds(SESSION_COOKIE_MAX_AGE_SECS));
    to_header(&c)
}

/// Expire the first-party cookie.
pub fn clear_session_cookie(config: &Config) -> HeaderValue {
    let mut c = base_cookie(config, String::new());
    c.set_same_site(SameSite::Lax);
    c.set_secure(config.cookie_secure());
    c.set_max_age(cookie::time::Duration::ZERO);
    to_header(&c)
}

/// Expire the partitioned embed cookie (a separate jar entry, so it needs
/// its own `Partitioned` removal).
pub fn clear_embed_session_cookie(config: &Config) -> HeaderValue {
    let mut c = base_cookie(config, String::new());
    c.set_same_site(SameSite::None);
    c.set_secure(true);
    c.set_partitioned(true);
    c.set_max_age(cookie::time::Duration::ZERO);
    to_header(&c)
}

/// Read one cookie's value from every `Cookie` header on the request.
pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim().to_string())
}

/// The session id from `epx_session`, if well-formed. Does not check the
/// store.
pub fn read_session_cookie(headers: &HeaderMap) -> Option<SessionId> {
    read_cookie(headers, SESSION_COOKIE).and_then(|v| SessionId::parse(&v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ENV_INSECURE_COOKIES, ENV_PUBLIC_BASE_URL};
    use std::collections::HashMap;

    fn config(pairs: &[(&str, &str)]) -> Config {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|k| map.get(k).cloned()).unwrap()
    }

    #[test]
    fn ids_are_256_bit_and_unique() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert_eq!(a.as_str().len(), 43);
        assert_ne!(a, b);
        assert_eq!(SessionId::parse(a.as_str()), Some(a.clone()));
        assert!(SessionId::parse("short").is_none());
        assert!(SessionId::parse(&"=".repeat(43)).is_none());
        assert_eq!(format!("{a:?}"), "SessionId(<redacted>)");
    }

    #[test]
    fn store_round_trip() {
        let s = SessionStore::new();
        let exp = Utc::now() + chrono::Duration::hours(1);
        let id = s.create("a1".into(), "r1".into(), exp);
        assert_eq!(s.get(&id).unwrap().access_token, "a1");
        assert!(s.update_tokens(&id, "a2".into(), "r2".into(), exp));
        let got = s.get(&id).unwrap();
        assert_eq!(
            (got.access_token.as_str(), got.refresh_token.as_str()),
            ("a2", "r2")
        );
        assert!(s.refresh_lock(&id).is_some());
        assert!(!format!("{got:?}").contains("a2"));
        assert!(s.remove(&id).is_some());
        assert!(s.get(&id).is_none());
        assert!(!s.update_tokens(&id, "x".into(), "y".into(), exp));
        assert!(s.refresh_lock(&id).is_none());
    }

    #[test]
    fn purge_by_age() {
        let s = SessionStore::new();
        s.create("a".into(), "r".into(), Utc::now());
        assert_eq!(s.purge_older_than(chrono::Duration::days(30)), 0);
        assert_eq!(s.purge_older_than(chrono::Duration::seconds(-1)), 1);
        assert!(s.is_empty());
    }

    #[test]
    fn session_cookie_attributes() {
        let c = config(&[(ENV_PUBLIC_BASE_URL, "https://explorer.example.com/explorer")]);
        let id = SessionId::generate();
        let v = session_cookie(&c, &id).to_str().unwrap().to_string();
        assert!(
            v.starts_with(&format!("epx_session={}", id.as_str())),
            "{v}"
        );
        for attr in [
            "HttpOnly",
            "SameSite=Lax",
            "Secure",
            "Path=/explorer",
            "Max-Age=2592000",
        ] {
            assert!(v.contains(attr), "{attr} missing from {v}");
        }
        assert!(!v.contains("Partitioned"));

        let insecure = config(&[
            (ENV_PUBLIC_BASE_URL, "http://localhost:8096"),
            (ENV_INSECURE_COOKIES, "true"),
        ]);
        let v = session_cookie(&insecure, &id).to_str().unwrap().to_string();
        assert!(!v.contains("Secure"), "{v}");
        assert!(v.contains("Path=/"), "{v}");
    }

    #[test]
    fn embed_cookie_is_partitioned_and_always_secure() {
        let c = config(&[
            (ENV_PUBLIC_BASE_URL, "https://explorer.example.com/explorer"),
            (ENV_INSECURE_COOKIES, "true"),
        ]);
        let v = embed_session_cookie(&c, &SessionId::generate())
            .to_str()
            .unwrap()
            .to_string();
        for attr in [
            "HttpOnly",
            "SameSite=None",
            "Secure",
            "Partitioned",
            "Path=/explorer",
        ] {
            assert!(v.contains(attr), "{attr} missing from {v}");
        }
    }

    #[test]
    fn clearing_expires_the_cookie() {
        let c = config(&[(ENV_PUBLIC_BASE_URL, "https://explorer.example.com/explorer")]);
        let v = clear_session_cookie(&c).to_str().unwrap().to_string();
        assert!(v.starts_with("epx_session=;"), "{v}");
        assert!(
            v.contains("Max-Age=0") && v.contains("Path=/explorer"),
            "{v}"
        );
        let v = clear_embed_session_cookie(&c).to_str().unwrap().to_string();
        assert!(v.contains("Max-Age=0") && v.contains("Partitioned"), "{v}");
    }

    #[test]
    fn reads_cookie_from_any_header() {
        let id = SessionId::generate();
        let mut h = HeaderMap::new();
        h.append(header::COOKIE, HeaderValue::from_static("a=1; b=2"));
        h.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("x=y; epx_session={}", id.as_str())).unwrap(),
        );
        assert_eq!(read_cookie(&h, "b").as_deref(), Some("2"));
        assert_eq!(read_session_cookie(&h), Some(id));

        let mut junk = HeaderMap::new();
        junk.insert(
            header::COOKIE,
            HeaderValue::from_static("epx_session=../../etc"),
        );
        assert_eq!(read_session_cookie(&junk), None);
    }
}
