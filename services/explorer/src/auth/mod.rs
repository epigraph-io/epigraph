//! Sign-in, sessions and per-request auth (plan §3.3).
//!
//! Shared seams (do not restructure): `session.rs` (store + cookies),
//! `extract.rs` (extractors + `PageCtx`), and the `refresh_session`
//! signature in `refresh.rs`. The route handlers below, `oauth.rs` and
//! `flow.rs` belong to the auth area; the handlers are stubs until then.

use axum::response::Html;
use axum::routing::{get, post};
use axum::Router;

use crate::error::AppError;
use crate::state::AppState;
use crate::view::stub_page;

pub mod extract;
pub mod flow;
pub mod oauth;
pub mod refresh;
pub mod session;

pub use extract::{resolve_auth, Caller, PageCtx, RequestAuth, SignedIn, PRODUCT_NAME};
pub use refresh::{refresh_session, RefreshError};
pub use session::{
    clear_embed_session_cookie, clear_session_cookie, embed_session_cookie, random_token,
    read_session_cookie, session_cookie, Session, SessionId, SessionStore, SESSION_COOKIE,
};

/// `/auth/*`. Merged into the app router by `app::build_app`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .route("/auth/redeem", post(redeem))
}

// STUB: authorization code + PKCE redirect to `{oauth_base}/oauth/authorize`.
async fn login(caller: Caller) -> Result<Html<String>, AppError> {
    stub_page(caller.ctx, "Sign in", "auth")
}

// STUB: state check, code redemption, session creation, cookie or handoff.
async fn callback(caller: Caller) -> Result<Html<String>, AppError> {
    stub_page(caller.ctx, "Signing in", "auth")
}

// STUB: Origin check, upstream revoke, drop session, clear cookie.
async fn logout(caller: Caller) -> Result<Html<String>, AppError> {
    stub_page(caller.ctx, "Sign out", "auth")
}

// STUB: redeem a single-use handoff code, set the partitioned cookie.
async fn redeem(caller: Caller) -> Result<Html<String>, AppError> {
    stub_page(caller.ctx, "Sign in", "auth")
}
