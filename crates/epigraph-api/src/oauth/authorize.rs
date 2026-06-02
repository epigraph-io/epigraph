//! OAuth 2.1 authorization endpoint (`GET /oauth/authorize`).
//!
//! This is the entry point claude.ai (and any browser-based MCP client) hits to
//! begin the authorization-code flow. It validates the request, stashes a pending
//! authorize session keyed by a fresh Google CSRF `state`, and 302s the user into
//! the existing Google OIDC redirect flow. The Google callback (Task 8) recovers
//! the session, provisions the user, renders consent, and mints the code that the
//! `authorization_code` grant in `/oauth/token` (Task 6) redeems.
use axum::{
    extract::{Query, State},
    response::Response,
};
#[cfg(feature = "db")]
use axum::response::{Html, IntoResponse, Redirect};
use serde::Deserialize;

use crate::errors::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

const GOOGLE_PROVIDER: &str = "google";

/// Pending authorize-session lifetime: the user must complete the Google login +
/// consent within this window before the session expires.
#[cfg(feature = "db")]
const AUTHORIZE_SESSION_TTL: chrono::Duration = chrono::Duration::minutes(10);

/// Authorization-code lifetime: a freshly minted code is single-use and must be
/// redeemed at `/oauth/token` within this window (RFC 6749 §4.1.2 recommends short).
#[cfg(feature = "db")]
const AUTH_CODE_TTL: chrono::Duration = chrono::Duration::seconds(60);

/// Build a redirect URL by parsing the (allowlist-validated) `redirect_uri` and
/// appending query parameters via `url::Url::query_pairs_mut`. This percent-encodes
/// every value — including the attacker-supplied OAuth `state` — so a control byte
/// (e.g. a decoded `%0A`) can never reach `Redirect::to`'s `HeaderValue::try_from`
/// and panic the handler, and it merges correctly with a `redirect_uri` that already
/// carries a query component (no naive double-`?`).
#[cfg(feature = "db")]
fn build_redirect_url(redirect_uri: &str, params: &[(&str, &str)]) -> Result<String, ApiError> {
    let mut url = url::Url::parse(redirect_uri).map_err(|e| ApiError::InternalError {
        message: format!("validated redirect_uri did not parse: {e}"),
    })?;
    url.query_pairs_mut().extend_pairs(params.iter().copied());
    Ok(url.into())
}

#[cfg(feature = "db")]
pub async fn authorize_endpoint(
    State(state): State<AppState>,
    Query(q): Query<AuthorizeQuery>,
) -> Result<Response, ApiError> {
    use chrono::Utc;
    use epigraph_db::repos::authorize_session::AuthorizeSessionRepository;
    use epigraph_db::repos::oauth_client::OAuthClientRepository;

    // ── Validation that MUST precede any DB round-trip ───────────────────────
    // `app()` in tests builds AppState with a dummy/lazy pool, so the missing-PKCE
    // case has to 400 here, before `get_by_client_id`. Keep this order exactly:
    // response_type → non-empty code_challenge → S256 → client lookup.
    if q.response_type != "code" {
        return Err(ApiError::BadRequest {
            message: "unsupported_response_type".into(),
        });
    }
    // Mandatory PKCE S256 with a NON-EMPTY challenge. This is the only path that
    // mints codes, so the redeem grant (Task 6) relies on this guarantee — do not
    // relax it (closes the forward dependency the Phase 2 security review flagged).
    match q.code_challenge.as_deref() {
        Some(c) if !c.is_empty() => {}
        _ => {
            return Err(ApiError::BadRequest {
                message: "PKCE code_challenge required".into(),
            })
        }
    }
    if q.code_challenge_method.as_deref() != Some("S256") {
        return Err(ApiError::BadRequest {
            message: "PKCE code_challenge_method must be S256".into(),
        });
    }

    // ── Client + exact redirect_uri validation (DB) ──────────────────────────
    let client = OAuthClientRepository::get_by_client_id(&state.db_pool, &q.client_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
        .ok_or(ApiError::BadRequest {
            message: "invalid_client".into(),
        })?;
    let ok_redirect = client
        .redirect_uris
        .as_deref()
        .map(|uris| uris.iter().any(|u| u == &q.redirect_uri))
        .unwrap_or(false);
    if !ok_redirect {
        return Err(ApiError::BadRequest {
            message: "invalid redirect_uri".into(),
        });
    }

    // ── Build the EpiGraph↔Google PKCE + CSRF state, persist the pending request ─
    let (verifier, challenge) = crate::oauth::device::generate_pkce_public();
    let google_state = crate::oauth::device::generate_state_public();
    let flow = state
        .providers
        .redirect_flow(GOOGLE_PROVIDER)
        .ok_or(ApiError::InternalError {
            message: "google provider not configured".into(),
        })?;
    let google_redirect = format!(
        "{}/oauth/callback",
        state.config.public_base_url.trim_end_matches('/')
    );
    let auth_url = flow.build_auth_url(&google_state, &challenge, &google_redirect);

    AuthorizeSessionRepository::create(
        &state.db_pool,
        &google_state,
        &q.client_id,
        &q.redirect_uri,
        // SAFETY: the match above guarantees a non-empty challenge is present.
        q.code_challenge.as_deref().unwrap(),
        q.scope.as_deref(),
        // The client's OWN `state` (round-tripped back to it at the end of the
        // flow) is the `claude_state` column — distinct from the Google CSRF state
        // we key the session by. Do not cross the two.
        q.state.as_deref(),
        &verifier,
        Utc::now() + AUTHORIZE_SESSION_TTL,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: e.to_string(),
    })?;

    Ok(Redirect::to(&auth_url).into_response())
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

/// Google redirects here (`GET /oauth/callback`). Recover the pending authorize session by
/// the Google CSRF `state` (READ-ONLY), exchange the Google code for an id_token, validate
/// identity, provision the per-user client (no tokens yet), compute requested∩grantable
/// scopes, then ATOMICALLY rotate the session to a fresh consent nonce carrying the resolved
/// user + scopes server-side. Render consent keyed by that nonce. The user and scopes are
/// NEVER read from browser-supplied form fields — only from the server-side session row.
#[cfg(feature = "db")]
pub async fn callback_endpoint(
    State(state): State<AppState>,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    use crate::oauth::providers::provision_external_user_client;
    use epigraph_db::repos::authorize_session::AuthorizeSessionRepository;

    // 1. Read-only lookup (NO delete): we still need the verifier + request to transition.
    let session = AuthorizeSessionRepository::find_by_state(&state.db_pool, &q.state)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
        .ok_or(ApiError::BadRequest {
            message: "unknown or expired authorize session".into(),
        })?;

    // 2. Exchange the Google code -> id_token -> validated identity (reuse the provider flow).
    let provider =
        state
            .providers
            .by_name(GOOGLE_PROVIDER)
            .ok_or(ApiError::InternalError {
                message: "google provider missing".into(),
            })?;
    let flow = state
        .providers
        .redirect_flow(GOOGLE_PROVIDER)
        .ok_or(ApiError::InternalError {
            message: "google provider not configured".into(),
        })?;
    let google_redirect = format!(
        "{}/oauth/callback",
        state.config.public_base_url.trim_end_matches('/')
    );
    let id_token = flow
        .exchange_code(&q.code, &google_redirect, &session.google_code_verifier)
        .await
        .map_err(|e| ApiError::BadGateway {
            reason: format!("{e:?}"),
        })?;
    let identity = provider
        .validate(&id_token)
        .await
        .map_err(|e| ApiError::Unauthorized {
            reason: format!("{e:?}"),
        })?;

    // 3. Provision/find the per-user `human` oauth_client for this identity (no tokens yet).
    let user = provision_external_user_client(&state, provider.as_ref(), &identity).await?;

    // 4. Compute requested ∩ grantable scopes (server-side only).
    let requested: Vec<String> = session
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let grantable: Vec<String> = if requested.is_empty() {
        user.granted_scopes.clone()
    } else {
        requested
            .into_iter()
            .filter(|s| user.granted_scopes.contains(s))
            .collect()
    };

    // 5. Atomically rotate state -> fresh consent nonce, recording user + scopes server-side.
    let consent_nonce = crate::oauth::device::generate_state_public();
    let _consent_session = AuthorizeSessionRepository::transition_to_consent(
        &state.db_pool,
        &q.state,
        &consent_nonce,
        user.id,
        &grantable,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: e.to_string(),
    })?
    .ok_or(ApiError::BadRequest {
        message: "authorize session expired".into(),
    })?;

    // 6. Render consent keyed by the nonce. email + scopes are server-derived, not from a form.
    Ok(Html(render_consent_page(&consent_nonce, &user.client_name, &grantable)).into_response())
}

/// Pure HTML render. `ticket` is the consent-session nonce the POST handler will consume.
fn render_consent_page(ticket: &str, email: &str, scopes: &[String]) -> String {
    let scope_items: String = scopes
        .iter()
        .map(|s| format!("<li><code>{}</code></li>", html_escape(s)))
        .collect();
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8">
<title>Authorize Claude</title></head><body style="font-family:sans-serif;max-width:32rem;margin:4rem auto">
<h1>Authorize Claude</h1>
<p>Claude wants to access EpiGraph as <strong>{email}</strong> with:</p>
<ul>{scope_items}</ul>
<form method="post" action="/oauth/authorize/consent">
  <input type="hidden" name="ticket" value="{ticket}">
  <button name="decision" value="allow">Allow</button>
  <button name="decision" value="deny">Deny</button>
</form></body></html>"#,
        email = html_escape(email),
        ticket = html_escape(ticket),
        scope_items = scope_items
    )
}

/// Minimal HTML escaping for every value interpolated into the consent page.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    pub ticket: String,
    pub decision: String,
}

/// `POST /oauth/authorize/consent`. Consumes the consent ticket (single-use), and on Allow
/// mints a single-use 60s authorization code bound to client+user+PKCE+redirect+scopes —
/// the user and scopes come from the server-side session row, NEVER from the form — then
/// 302s back to the client's `redirect_uri` with `code` + the client's original `state`.
/// On Deny (or any non-Allow decision) it 302s with `error=access_denied`.
#[cfg(feature = "db")]
pub async fn consent_endpoint(
    State(state): State<AppState>,
    axum::extract::Form(form): axum::extract::Form<ConsentForm>,
) -> Result<Response, ApiError> {
    use chrono::Utc;
    use epigraph_db::repos::authorization_code::AuthorizationCodeRepository;
    use epigraph_db::repos::authorize_session::AuthorizeSessionRepository;

    let session = AuthorizeSessionRepository::take(&state.db_pool, &form.ticket)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
        .ok_or(ApiError::BadRequest {
            message: "expired consent ticket".into(),
        })?;

    let claude_state = session.claude_state.clone().unwrap_or_default();
    if form.decision != "allow" {
        // Build via url::Url so the client-supplied `state` is percent-encoded: a raw
        // control byte (a decoded `%0A`) would otherwise make `Redirect::to`'s
        // `HeaderValue::try_from` panic. This also merges correctly with a redirect_uri
        // that already has a query component.
        let url = build_redirect_url(
            &session.redirect_uri,
            &[("error", "access_denied"), ("state", &claude_state)],
        )?;
        return Ok(Redirect::to(&url).into_response());
    }

    // Mint the authorization code (single-use, 60s), bound to client+user+pkce+redirect+scopes.
    // user + scopes are read from the server-side session row recorded at the callback, never
    // from the browser-supplied form, to prevent scope/identity tampering.
    let resolved_user = session
        .resolved_oauth_client_id
        .ok_or(ApiError::InternalError {
            message: "consent ticket missing user".into(),
        })?;
    let scopes = session.granted_scopes.clone().unwrap_or_default();
    use rand::Rng;
    let raw: [u8; 32] = rand::thread_rng().gen();
    let code = hex::encode(raw);
    // Hash the SAME string we emit as `code`. The authorization_code redeem path
    // (`handle_authorization_code` in token.rs) computes `blake3::hash(code.as_bytes())`
    // over the received string — it does NOT hex-decode first (unlike the refresh-token
    // path). Hashing the raw 32 bytes here instead would store a digest the redeem path
    // can never reproduce, making every minted code unredeemable.
    let code_hash = blake3::hash(code.as_bytes());
    AuthorizationCodeRepository::create(
        &state.db_pool,
        code_hash.as_bytes(),
        &session.client_id,
        resolved_user,
        &session.redirect_uri,
        &session.code_challenge,
        &scopes,
        None,
        Utc::now() + AUTH_CODE_TTL,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: e.to_string(),
    })?;

    // Same url::Url construction as the deny branch: `code` is hex (URL-safe) but the
    // client-supplied `state` must be percent-encoded to avoid panicking on a control
    // byte, and to merge with a redirect_uri that already carries a query.
    let url = build_redirect_url(
        &session.redirect_uri,
        &[("code", &code), ("state", &claude_state)],
    )?;
    Ok(Redirect::to(&url).into_response())
}

#[cfg(not(feature = "db"))]
pub async fn authorize_endpoint(
    State(_state): State<AppState>,
    Query(_q): Query<AuthorizeQuery>,
) -> Result<Response, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database required for OAuth2".to_string(),
    })
}
