//! Per-request auth and page context.
//!
//! Handlers take one of two extractors:
//!
//! - [`Caller`] does not reject for being anonymous: anonymous, session, or
//!   dev-bearer (only a session found over is `SessionExpired`). Use it for
//!   the few pages that render for anonymous viewers (`/claim/:id` returns 200
//!   with a sign-in prompt and OG tags, plan §3.3) and for auth routes.
//! - [`SignedIn`] rejects anonymous viewers with [`AppError::Unauthorized`],
//!   which the error layer turns into a 303 to `/auth/login?return_to=…` for
//!   pages and a JSON 401 for `/bff/*`.
//!
//! Both carry a [`PageCtx`] for templates.

use axum::extract::{FromRequestParts, OriginalUri};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use super::refresh::RefreshError;
use super::session::{read_session_cookie, Session, SessionId};
use crate::error::AppError;
use crate::links::Links;
use crate::state::AppState;
use crate::upstream::capabilities::Capability;
use crate::upstream::{Api, Degraded};

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
    /// sha256(session id)>`. Upstream visibility differs per viewer — two
    /// viewers get different result sets from the same URL — so any cached
    /// upstream data must be keyed by this.
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

/// Characters of the principal shown in the header; the whole id is in the
/// element's tooltip.
const PRINCIPAL_SHORT_CHARS: usize = 8;

/// The header's identity strip (who the viewer is signed in as, and what
/// their token carries), copied from the session when the page is built.
/// Display only: no authorization decision reads it.
#[derive(Clone, Debug)]
pub struct IdentityStrip {
    principal: Degraded<String>,
    scope: Option<String>,
    widened: bool,
    expires_at: DateTime<Utc>,
}

impl IdentityStrip {
    pub fn of(session: &Session) -> Self {
        Self {
            principal: session.principal.clone(),
            scope: session.scope.clone(),
            widened: session.scope_widened,
            expires_at: session.expires_at,
        }
    }

    /// The token subject, if introspection named one.
    pub fn principal(&self) -> Option<&str> {
        self.principal.get().map(String::as_str)
    }

    /// Its first few characters, for the header.
    pub fn principal_short(&self) -> Option<String> {
        self.principal()
            .map(|p| p.chars().take(PRINCIPAL_SHORT_CHARS).collect())
    }

    /// The scopes the token was granted, as its token response listed
    /// them; never the scopes the Explorer asked for.
    pub fn scope_text(&self) -> &str {
        self.scope.as_deref().unwrap_or("not reported")
    }

    /// The token carries a scope the Explorer did not ask for.
    pub fn widened(&self) -> bool {
        self.widened
    }

    /// Whole minutes until the access token expires (never negative).
    pub fn minutes_left(&self) -> i64 {
        (self.expires_at - Utc::now()).num_minutes().max(0)
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
    /// The header's identity strip: set for a signed-in session, `None`
    /// for anonymous viewers and the dev bearer.
    pub identity: Option<IdentityStrip>,
    /// Whether the section nav shows "Admin acts": only when the capability
    /// probe has seen the API's admin-acts route (`Present`). Against an API
    /// without it, or while the answer is unknown, the item is left out of
    /// the HTML, not hidden.
    pub admin_acts: bool,
}

impl PageCtx {
    pub fn new(links: Links, current_path: String, signed_in: bool) -> Self {
        Self {
            base_path: links.base_path().to_string(),
            links,
            signed_in,
            current_path,
            search_query: String::new(),
            identity: None,
            admin_acts: false,
        }
    }

    /// The same context with the session's identity strip.
    pub fn with_identity(mut self, identity: Option<IdentityStrip>) -> Self {
        self.identity = identity;
        self
    }

    /// The same context with "Admin acts" shown iff the API is remembered
    /// to have the route. For builders that must not call upstream (error
    /// and auth pages): they read the remembered answer only.
    pub fn with_remembered_capabilities(mut self, state: &AppState) -> Self {
        self.admin_acts = state
            .capabilities
            .cached_admin_acts()
            .is_some_and(Capability::is_present);
        self
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

/// Resolve the viewer from the session cookie, refreshing the access
/// token when it is within [`PROACTIVE_REFRESH_WINDOW`] of expiry.
///
/// A session ends when upstream *refuses* the refresh
/// ([`RefreshError::Rejected`], `NoSession`) once the token has expired, and
/// whenever the refresh got no usable answer ([`RefreshError::Upstream`]:
/// transport, timeout, 5xx), because the held refresh token may already be
/// spent and must not be replayed; [`super::refresh_session`] has then already
/// ended it. Falls back to the dev bearer, then to anonymous.
pub async fn resolve_auth(state: &AppState, headers: &HeaderMap) -> RequestAuth {
    if let Some(id) = read_session_cookie(&state.config, headers) {
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
                // No usable answer from `/oauth/token`: `refresh_session`
                // ended the session and revoked its refresh token, so this
                // request is signed out even if the access token has a few
                // seconds left.
                Err(e @ RefreshError::Upstream(_)) => {
                    tracing::info!(error = %e, "refresh outcome unknown; the session has ended");
                }
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
                // Refresh is not configured: nothing was presented upstream,
                // so keep the session and carry the stale token. Upstream
                // answers 401 and `Api::send` decides.
                Err(e) => {
                    tracing::warn!(error = %e, "proactive refresh unavailable; keeping the session with its stale token");
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

/// Any viewer. Never rejects, except with [`AppError::SessionExpired`] when
/// the section nav's capability probe found the session over (see
/// [`probe_capabilities`]), as the page's own upstream call would have.
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

/// Whether this request renders a page with the section nav: a signed-in
/// `GET`/`HEAD` outside `/bff/*` (JSON, no layout). Only those probe the
/// API's optional routes; anonymous pages have no section nav.
fn renders_section_nav(state: &AppState, parts: &Parts, auth: &RequestAuth) -> bool {
    if !auth.is_signed_in() || !matches!(parts.method, Method::GET | Method::HEAD) {
        return false;
    }
    let uri = parts
        .extensions
        .get::<OriginalUri>()
        .map(|o| &o.0)
        .unwrap_or(&parts.uri);
    let route = state.links.strip_base(uri.path());
    !(route == "/bff" || route.starts_with("/bff/"))
}

/// "Admin acts" for this page: the remembered answer, or a probe with the
/// viewer's own token. Returns the auth to carry on with: a probe that
/// refreshed the session hands over the new token, so the page never
/// presents the rotated-out one. A probe that ended the session (its
/// refresh was refused or its answer lost) is
/// [`AppError::SessionExpired`], exactly what the page's own first call
/// would have met: sign-in again, with the cookie cleared.
async fn probe_capabilities(
    parts: &mut Parts,
    state: &AppState,
    auth: RequestAuth,
) -> Result<(RequestAuth, bool), AppError> {
    let api = Api::new(state, &auth);
    let admin_acts = state.capabilities.admin_acts(&api).await.is_present();
    let now = api.current_auth();
    if let Some(id) = now.session_id() {
        if state.sessions.get(id).is_none() {
            return Err(AppError::SessionExpired);
        }
    }
    if now != auth {
        parts.extensions.insert(Resolved(now.clone()));
    }
    Ok((now, admin_acts))
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let mut auth = resolve_cached(parts, state).await;
        let mut admin_acts = false;
        if renders_section_nav(state, parts, &auth) {
            (auth, admin_acts) = probe_capabilities(parts, state, auth).await?;
        }
        let identity = auth
            .session_id()
            .and_then(|id| state.sessions.get(id))
            .map(|s| IdentityStrip::of(&s));
        let mut ctx = PageCtx::new(
            state.links.clone(),
            browser_path(state, parts),
            auth.is_signed_in(),
        )
        .with_identity(identity);
        ctx.admin_acts = admin_acts && auth.is_signed_in();
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

    fn strip(principal: Degraded<String>, scope: Option<&str>, mins: i64) -> IdentityStrip {
        IdentityStrip {
            principal,
            scope: scope.map(str::to_string),
            widened: false,
            expires_at: Utc::now()
                + chrono::Duration::minutes(mins)
                + chrono::Duration::seconds(30),
        }
    }

    #[test]
    fn identity_strip_fields() {
        let s = strip(
            Degraded::ok("0123456789abcdef".into()),
            Some("claims:read"),
            42,
        );
        assert_eq!(s.principal(), Some("0123456789abcdef"));
        assert_eq!(s.principal_short().as_deref(), Some("01234567"));
        assert_eq!(s.scope_text(), "claims:read");
        assert_eq!(s.minutes_left(), 42);

        let s = strip(Degraded::unavailable("down"), None, -5);
        assert_eq!(s.principal_short(), None);
        assert_eq!(s.scope_text(), "not reported", "never the requested set");
        assert_eq!(
            s.minutes_left(),
            0,
            "an expired token shows 0, not a negative"
        );
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
