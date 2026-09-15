//! Sign-in, sessions and per-request auth (plan §3.3).
//!
//! Shared seams (do not restructure): `session.rs` (store + cookies),
//! `extract.rs` (extractors + `PageCtx`), and the `refresh_session`
//! signature in `refresh.rs`. The route handlers below, `oauth.rs` and
//! `flow.rs` belong to the auth area.
//!
//! The flow, against the API's own OAuth AS (oauth-auth.md §8):
//!
//! - `GET /auth/login?return_to=&mode=page|popup` stores a pending login
//!   (PKCE verifier, `return_to`, mode) under a random `state`, binds it to
//!   this browser with the `epx_login` cookie, and 303s to
//!   `{oauth_base}/oauth/authorize`. A navigation inside an iframe
//!   (`Sec-Fetch-Dest: iframe`, i.e. the Notion embed) gets a page with a
//!   button that opens the popup instead, because the AS cannot be framed.
//! - `GET /auth/callback` checks `state` and the binding, redeems the code at
//!   once (upstream codes live 60 s), and creates the session. Page mode sets
//!   the first-party cookie and 303s to `return_to`; popup mode renders a page
//!   that hands a single-use code to the opening iframe (`static/embed.js`).
//! - `POST /auth/redeem` (Origin-checked) swaps that code for the
//!   `SameSite=None; Partitioned` cookie the iframe can hold.
//! - `POST /auth/logout` (Origin-checked) revokes the refresh token upstream,
//!   drops the session and clears both cookies.

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::error::AppError;
use crate::state::AppState;
use crate::view::render;

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

use flow::{Handoff, PendingLogin, HANDOFF_TTL, MAX_PENDING_LOGINS, PENDING_LOGIN_TTL};

/// `/auth/*`. Merged into the app router by `app::build_app`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .route("/auth/redeem", post(redeem))
}

// ---- templates ----------------------------------------------------------------

/// Shown instead of the authorize redirect when the login navigation happens
/// inside an iframe: the button (wired by `static/embed.js`) opens the popup.
#[derive(askama::Template)]
#[template(path = "auth/embed_signin.html")]
struct EmbedSignInPage {
    ctx: PageCtx,
    popup_login_url: String,
    redeem_url: String,
    return_to: String,
    /// The destination as an absolute URL, for the "open in a new tab" link.
    open_url: String,
}

/// Rendered in the popup by `/auth/callback?mode=popup`. `status` is `ok`
/// (with a handoff code) or `error`; `static/embed.js` posts either to the
/// opener and closes the window.
#[derive(askama::Template)]
#[template(path = "auth/popup.html")]
struct PopupPage {
    ctx: PageCtx,
    status: &'static str,
    handoff: Option<String>,
    title: &'static str,
    message: String,
}

/// A page-mode sign-in that could not finish.
#[derive(askama::Template)]
#[template(path = "auth/failed.html")]
struct FailedPage {
    ctx: PageCtx,
    status: u16,
    title: &'static str,
    message: String,
    retry_url: String,
}

// ---- helpers ------------------------------------------------------------------

/// Every auth response carries credentials or single-use state.
const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");

/// Context for an auth page. `current_path` is the page the sign-in is
/// for (`return_to`), never this request's URL: callback URLs carry `code`
/// and `state`, which must not be reflected into `og:url` or the header's
/// sign-in link.
fn page_ctx(state: &AppState, headers: &HeaderMap, current_path: String) -> PageCtx {
    let signed_in =
        read_session_cookie(headers).is_some_and(|id| state.sessions.get(&id).is_some());
    PageCtx::new(state.links.clone(), current_path, signed_in)
}

fn html(status: StatusCode, body: Html<String>) -> Response {
    let mut resp = (status, body).into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, NO_STORE);
    resp
}

/// 303 to a URL we built or validated (never raw input), with cookies.
fn see_other(location: &str, cookies: &[HeaderValue]) -> Result<Response, AppError> {
    let location = HeaderValue::from_str(location)
        .map_err(|_| AppError::Internal("redirect target is not a valid header value".into()))?;
    let mut resp = StatusCode::SEE_OTHER.into_response();
    let h = resp.headers_mut();
    h.insert(header::LOCATION, location);
    h.insert(header::CACHE_CONTROL, NO_STORE);
    for c in cookies {
        h.append(header::SET_COOKIE, c.clone());
    }
    Ok(resp)
}

/// State-changing POSTs must come from our own pages: `Origin` must equal
/// the public origin exactly. A missing or `null` Origin is refused too;
/// browsers send it on every POST.
fn require_same_origin(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if origin == Some(state.config.public_origin.as_str()) {
        Ok(())
    } else {
        tracing::warn!(
            origin = origin.unwrap_or("<none>"),
            "cross-origin auth POST refused"
        );
        Err(AppError::Forbidden(
            "This request did not come from EpiGraph Explorer.".into(),
        ))
    }
}

/// Whether the browser says this navigation is loading an iframe (Fetch
/// Metadata; sent by current Chromium, Firefox and Safari).
fn is_iframe_navigation(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-dest")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|d| d.eq_ignore_ascii_case("iframe") || d.eq_ignore_ascii_case("frame"))
}

// ---- GET /auth/login ----------------------------------------------------------

#[derive(Deserialize)]
struct LoginQuery {
    return_to: Option<String>,
    mode: Option<String>,
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<LoginQuery>,
) -> Result<Response, AppError> {
    let Some(client_id) = state.config.client_id.clone() else {
        return Err(AppError::Degraded(
            "Sign-in is not configured on this server.".into(),
        ));
    };
    let return_to = flow::safe_return_to(&state.links, q.return_to.as_deref());
    let popup = q.mode.as_deref() == Some("popup");

    if !popup && is_iframe_navigation(&headers) {
        // The page stands in for `return_to`: its header links and og:url
        // point there, not back at this login URL.
        let ctx = page_ctx(&state, &headers, return_to.clone());
        let page = EmbedSignInPage {
            popup_login_url: state.links.login_popup(Some(&return_to)),
            redeem_url: state.links.redeem(),
            open_url: state.links.absolute(&return_to),
            return_to,
            ctx,
        };
        return Ok(html(StatusCode::OK, render(&page)?));
    }

    let pending = &state.auth_flow.pending;
    if pending.len() >= MAX_PENDING_LOGINS && {
        pending.purge_expired();
        pending.len() >= MAX_PENDING_LOGINS
    } {
        tracing::warn!(
            held = pending.len(),
            "pending-login cap reached; refusing new sign-ins"
        );
        return Err(AppError::Degraded(
            "Too many sign-ins are in progress. Try again in a few minutes.".into(),
        ));
    }

    // Reuse this browser's binding if it has one, so two tabs signing in at
    // once do not invalidate each other.
    let binding = flow::read_pre_auth_cookie(&headers).unwrap_or_else(|| random_token(32));
    let pkce_verifier = random_token(32);
    let code_challenge = oauth::pkce_challenge_s256(&pkce_verifier);
    let oauth_state = random_token(32);
    let authorize = oauth::authorize_url(&state.config, &client_id, &oauth_state, &code_challenge);

    pending.insert(
        oauth_state,
        PendingLogin {
            pkce_verifier,
            return_to,
            popup,
            binding: binding.clone(),
            created_at: std::time::Instant::now(),
        },
        PENDING_LOGIN_TTL,
    );
    see_other(
        authorize.as_str(),
        &[flow::pre_auth_cookie(&state.config, &binding)],
    )
}

// ---- GET /auth/callback -------------------------------------------------------

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    // Single use: the pending login is gone after this, whatever happens.
    let pending = q
        .state
        .as_deref()
        .filter(|s| flow::is_token_shaped(s))
        .and_then(|s| state.auth_flow.pending.take(&s.to_string()));
    let Some(pending) = pending else {
        return failed(
            &state,
            &headers,
            None,
            StatusCode::BAD_REQUEST,
            "This sign-in link has expired or was already used.".into(),
        );
    };

    let bound = flow::read_pre_auth_cookie(&headers)
        .is_some_and(|c| bool::from(c.as_bytes().ct_eq(pending.binding.as_bytes())));
    if !bound {
        tracing::warn!(
            "sign-in callback without its pre-auth cookie; refused (possible login CSRF)"
        );
        return failed(
            &state,
            &headers,
            Some(&pending),
            StatusCode::BAD_REQUEST,
            "We could not confirm this sign-in started in this browser. Please sign in again."
                .into(),
        );
    }

    if let Some(error) = q.error.as_deref() {
        // The AS redirects here only for a denied consent (`access_denied`);
        // its other failures dead-end on its own origin. The value is
        // attacker-controllable, so it is logged, never shown.
        tracing::info!(%error, "sign-in ended with an error from the authorization server");
        let (status, message) = if error == "access_denied" {
            (StatusCode::FORBIDDEN, "Sign-in was cancelled.")
        } else {
            (
                StatusCode::BAD_REQUEST,
                "EpiGraph could not complete the sign-in.",
            )
        };
        return failed(&state, &headers, Some(&pending), status, message.into());
    }

    let Some(code) = q.code.filter(|c| !c.is_empty() && c.len() <= 512) else {
        return failed(
            &state,
            &headers,
            Some(&pending),
            StatusCode::BAD_REQUEST,
            "The sign-in response was incomplete. Please sign in again.".into(),
        );
    };

    let tokens = match oauth::exchange_code(&state, &code, &pending.pkce_verifier).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "authorization code redemption failed");
            let status = StatusCode::from_u16(e.page_status()).unwrap_or(StatusCode::BAD_GATEWAY);
            return failed(
                &state,
                &headers,
                Some(&pending),
                status,
                e.user_message().into(),
            );
        }
    };
    let session_id =
        state
            .sessions
            .create(tokens.access_token, tokens.refresh_token, tokens.expires_at);
    tracing::info!(
        popup = pending.popup,
        took_ms = pending.created_at.elapsed().as_millis() as u64,
        "signed in"
    );

    if pending.popup {
        let code = random_token(32);
        state.auth_flow.handoffs.insert(
            code.clone(),
            Handoff {
                session_id: session_id.clone(),
            },
            HANDOFF_TTL,
        );
        let page = PopupPage {
            ctx: page_ctx(&state, &headers, pending.return_to.clone()),
            status: "ok",
            handoff: Some(code),
            title: "Signed in",
            message: "You are signed in. This window closes by itself.".into(),
        };
        return Ok(html(StatusCode::OK, render(&page)?));
    }

    // A fresh id on every sign-in (no fixation); the browser's previous
    // session, if any, is replaced rather than left in the store.
    if let Some(old) = read_session_cookie(&headers) {
        state.sessions.remove(&old);
    }
    see_other(
        &pending.return_to,
        &[session_cookie(&state.config, &session_id)],
    )
}

/// Report a callback failure: to the opener in popup mode (the popup page
/// posts an error message), else as a page with a "Sign in again" link.
fn failed(
    state: &AppState,
    headers: &HeaderMap,
    pending: Option<&PendingLogin>,
    status: StatusCode,
    message: String,
) -> Result<Response, AppError> {
    let title = if status == StatusCode::FORBIDDEN {
        "Not signed in"
    } else {
        "Sign-in failed"
    };
    let return_to = pending.map_or_else(|| state.links.home(), |p| p.return_to.clone());
    let ctx = page_ctx(state, headers, return_to.clone());
    if pending.is_some_and(|p| p.popup) {
        let page = PopupPage {
            ctx,
            status: "error",
            handoff: None,
            title,
            message,
        };
        return Ok(html(status, render(&page)?));
    }
    let page = FailedPage {
        retry_url: state.links.login(Some(&return_to)),
        ctx,
        status: status.as_u16(),
        title,
        message,
    };
    Ok(html(status, render(&page)?))
}

// ---- POST /auth/redeem --------------------------------------------------------

async fn redeem(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    require_same_origin(&state, &headers)?;

    let code = url::form_urlencoded::parse(&body)
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned());
    let handoff = code
        .filter(|c| flow::is_token_shaped(c))
        .and_then(|c| state.auth_flow.handoffs.take(&c))
        .filter(|h| state.sessions.get(&h.session_id).is_some());
    let Some(handoff) = handoff else {
        return Err(AppError::BadRequest(
            "This sign-in code has expired or was already used. Sign in again.".into(),
        ));
    };

    let mut resp = StatusCode::NO_CONTENT.into_response();
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, NO_STORE);
    h.append(
        header::SET_COOKIE,
        embed_session_cookie(&state.config, &handoff.session_id),
    );
    Ok(resp)
}

// ---- POST /auth/logout --------------------------------------------------------

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    require_same_origin(&state, &headers)?;

    if let Some(id) = read_session_cookie(&headers) {
        // Wait out an in-flight refresh so the token revoked below is the
        // latest rotation, not one that was replaced a moment later.
        let lock = state.sessions.refresh_lock(&id);
        let _guard = match &lock {
            Some(l) => Some(l.lock().await),
            None => None,
        };
        if let Some(session) = state.sessions.remove(&id) {
            if !session.refresh_token.is_empty() {
                // Best effort: the local session is gone either way.
                if let Err(e) = oauth::revoke_refresh_token(&state, &session.refresh_token).await {
                    tracing::warn!(error = %e, "refresh-token revocation failed at logout");
                }
            }
        }
    }

    see_other(
        &state.links.home(),
        &[
            clear_session_cookie(&state.config),
            clear_embed_session_cookie(&state.config),
        ],
    )
}
