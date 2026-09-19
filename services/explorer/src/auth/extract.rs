//! Per-request auth and page context.
//!
//! Handlers take one of two extractors:
//!
//! - [`Caller`] never rejects: anonymous, session, or dev-bearer. Use it for
//!   the few pages that render for anonymous viewers (`/claim/:id` returns 200
//!   with a sign-in prompt and OG tags, plan §3.3) and for auth routes.
//! - [`SignedIn`] rejects anonymous viewers with [`AppError::Unauthorized`],
//!   which the error layer turns into a 303 to `/auth/login?return_to=…` for
//!   pages and a JSON 401 for `/bff/*`.
//!
//! Both carry a [`PageCtx`] for templates.

use axum::extract::{FromRequestParts, OriginalUri};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use chrono::Utc;
use sha2::{Digest, Sha256};

use super::refresh::RefreshError;
use super::session::{read_session_cookie, SessionId};
use crate::error::AppError;
use crate::links::Links;
use crate::state::AppState;
use crate::upstream::Api;

/// The product name shown in the header and OG `site_name`.
pub const PRODUCT_NAME: &str = "EpiGraph Explorer";

/// Refresh this long before the access token expires (plan §3.3).
pub const PROACTIVE_REFRESH_WINDOW: chrono::Duration = chrono::Duration::seconds(60);

/// Whose bearer, if any, upstream calls carry.
#[derive(Clone, PartialEq, Eq)]
pub enum RequestAuth {
    /// No bearer: upstream sees an anonymous caller.
    Anonymous,
    /// A signed-in browser. `access_token` is the token current when the
    /// request started; [`Api`] swaps in a refreshed one if needed.
    Session { id: SessionId, access_token: String },
    /// `EPIGRAPH_EXPLORER_DEV_BEARER` (localhost only).
    DevBearer(String),
}

impl std::fmt::Debug for RequestAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestAuth::Anonymous => f.write_str("Anonymous"),
            RequestAuth::Session { .. } => f.write_str("Session(<redacted>)"),
            RequestAuth::DevBearer(_) => f.write_str("DevBearer(<redacted>)"),
        }
    }
}

impl RequestAuth {
    /// The bearer to send upstream.
    pub fn bearer(&self) -> Option<&str> {
        match self {
            RequestAuth::Anonymous => None,
            RequestAuth::Session { access_token, .. } => Some(access_token),
            RequestAuth::DevBearer(t) => Some(t),
        }
    }

    pub fn is_signed_in(&self) -> bool {
        !matches!(self, RequestAuth::Anonymous)
    }

    pub fn session_id(&self) -> Option<&SessionId> {
        match self {
            RequestAuth::Session { id, .. } => Some(id),
            _ => None,
        }
    }

    /// A stable, non-secret key for per-viewer caches (plan §3.4 "60 s
    /// cache, keyed per user"): `anon`, `dev`, or `s:<16 hex of
    /// sha256(session id)>`. Upstream redaction differs per viewer, so any
    /// cached upstream data must be keyed by this.
    pub fn cache_key(&self) -> String {
        match self {
            RequestAuth::Anonymous => "anon".into(),
            RequestAuth::DevBearer(_) => "dev".into(),
            RequestAuth::Session { id, .. } => {
                let digest = Sha256::digest(id.as_str().as_bytes());
                let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
                format!("s:{hex}")
            }
        }
    }
}

/// Everything `templates/base.html` needs. Every page template struct has a
/// `ctx: PageCtx` field.
#[derive(Clone, Debug)]
pub struct PageCtx {
    pub links: Links,
    /// `""` or `"/explorer"`.
    pub base_path: String,
    pub signed_in: bool,
    /// Browser-visible path + query of this request, base path included.
    pub current_path: String,
    /// Prefill for the header search box; the search page sets it.
    pub search_query: String,
}

impl PageCtx {
    pub fn new(links: Links, current_path: String, signed_in: bool) -> Self {
        Self {
            base_path: links.base_path().to_string(),
            links,
            signed_in,
            current_path,
            search_query: String::new(),
        }
    }

    pub fn product_name(&self) -> &'static str {
        PRODUCT_NAME
    }

    pub fn home_url(&self) -> String {
        self.links.home()
    }

    /// Sign-in link that comes back to this page.
    pub fn login_url(&self) -> String {
        self.links.login(Some(&self.current_path))
    }

    /// Action of the sign-out `<form method="post">`.
    pub fn logout_url(&self) -> String {
        self.links.logout()
    }

    /// Action of the header search `<form method="get">`.
    pub fn search_url(&self) -> String {
        self.links.search_page()
    }

    pub fn static_url(&self, name: &str) -> String {
        self.links.static_asset(name)
    }

    /// Absolute URL of this page, for `og:url` / canonical links.
    pub fn absolute_url(&self) -> String {
        self.links.absolute(&self.current_path)
    }
}

/// Resolve the viewer from the `epx_session` cookie, refreshing the access
/// token when it is within [`PROACTIVE_REFRESH_WINDOW`] of expiry.
///
/// A session is dropped only when upstream *refuses* the refresh
/// ([`RefreshError::Rejected`], `NoSession`). If `/oauth/token` could not be
/// reached at all, the session is kept with its existing token — a restart of
/// the API is transient and must not sign every user out. Falls back to the
/// dev bearer, then to anonymous.
pub async fn resolve_auth(state: &AppState, headers: &HeaderMap) -> RequestAuth {
    if let Some(id) = read_session_cookie(headers) {
        if let Some(session) = state.sessions.get(&id) {
            let now = Utc::now();
            if session.expires_at - now > PROACTIVE_REFRESH_WINDOW {
                return RequestAuth::Session {
                    id,
                    access_token: session.access_token,
                };
            }
            match super::refresh_session(state, &id, &session.access_token).await {
                Ok(access_token) => return RequestAuth::Session { id, access_token },
                Err(e) if session.expires_at > now => {
                    tracing::debug!(error = %e, "proactive refresh failed; token still valid");
                    return RequestAuth::Session {
                        id,
                        access_token: session.access_token,
                    };
                }
                // The token has expired and the refresh was *refused*: the
                // credential is dead, so end the session.
                Err(e @ (RefreshError::Rejected(_) | RefreshError::NoSession)) => {
                    tracing::info!(error = %e, "session token expired and refresh was rejected; ending session");
                    state.sessions.remove(&id);
                }
                // The refresh could not reach `/oauth/token` (transport,
                // timeout, 5xx). An API restart must not sign everyone out,
                // so keep the session and carry the stale token: upstream
                // answers 401, `Api::send` refreshes once more, and if that
                // is refused *then* the session ends.
                Err(e) => {
                    tracing::warn!(error = %e, "proactive refresh could not reach upstream; keeping the session with its stale token");
                    return RequestAuth::Session {
                        id,
                        access_token: session.access_token,
                    };
                }
            }
        }
    }
    match &state.config.dev_bearer {
        Some(t) => RequestAuth::DevBearer(t.clone()),
        None => RequestAuth::Anonymous,
    }
}

/// Browser-visible path + query of the request (works whether or not a
/// proxy stripped the base path, and inside nested routers).
pub fn browser_path(state: &AppState, parts: &Parts) -> String {
    let uri = parts
        .extensions
        .get::<OriginalUri>()
        .map(|o| &o.0)
        .unwrap_or(&parts.uri);
    let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    state.links.browser_path(pq)
}

/// Resolved once per request and cached in the request extensions, so
/// several extractors never trigger several refreshes.
#[derive(Clone)]
struct Resolved(RequestAuth);

async fn resolve_cached(parts: &mut Parts, state: &AppState) -> RequestAuth {
    if let Some(Resolved(a)) = parts.extensions.get::<Resolved>() {
        return a.clone();
    }
    let auth = resolve_auth(state, &parts.headers).await;
    parts.extensions.insert(Resolved(auth.clone()));
    auth
}

/// Any viewer. Never rejects.
pub struct Caller {
    pub auth: RequestAuth,
    pub ctx: PageCtx,
}

impl Caller {
    /// An upstream client bound to this viewer.
    pub fn api<'a>(&self, state: &'a AppState) -> Api<'a> {
        Api::new(state, &self.auth)
    }
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = resolve_cached(parts, state).await;
        let ctx = PageCtx::new(
            state.links.clone(),
            browser_path(state, parts),
            auth.is_signed_in(),
        );
        Ok(Caller { auth, ctx })
    }
}

/// A signed-in viewer (session or dev bearer). Anonymous → `AppError::Unauthorized`.
pub struct SignedIn {
    pub auth: RequestAuth,
    pub ctx: PageCtx,
}

impl SignedIn {
    /// An upstream client bound to this viewer.
    pub fn api<'a>(&self, state: &'a AppState) -> Api<'a> {
        Api::new(state, &self.auth)
    }
}

impl FromRequestParts<AppState> for SignedIn {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Caller { auth, ctx } = Caller::from_request_parts(parts, state).await?;
        if !auth.is_signed_in() {
            return Err(AppError::Unauthorized);
        }
        Ok(SignedIn { auth, ctx })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_keys_are_stable_and_opaque() {
        let id = SessionId::generate();
        let a = RequestAuth::Session {
            id: id.clone(),
            access_token: "t".into(),
        };
        let k = a.cache_key();
        assert!(k.starts_with("s:") && k.len() == 18, "{k}");
        assert!(!k.contains(id.as_str()));
        assert_eq!(k, a.cache_key());
        assert_eq!(RequestAuth::Anonymous.cache_key(), "anon");
        assert_eq!(RequestAuth::DevBearer("x".into()).cache_key(), "dev");
    }

    #[test]
    fn debug_hides_tokens() {
        let a = RequestAuth::Session {
            id: SessionId::generate(),
            access_token: "secret-token".into(),
        };
        assert!(!format!("{a:?}").contains("secret"));
        assert!(!format!("{:?}", RequestAuth::DevBearer("secret".into())).contains("secret"));
    }
}
