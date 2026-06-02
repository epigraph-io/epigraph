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
use axum::response::{IntoResponse, Redirect};
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

#[cfg(feature = "db")]
pub async fn authorize_endpoint(
    State(state): State<AppState>,
    Query(q): Query<AuthorizeQuery>,
) -> Result<Response, ApiError> {
    use chrono::{Duration, Utc};
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
        Utc::now() + Duration::minutes(10),
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: e.to_string(),
    })?;

    Ok(Redirect::to(&auth_url).into_response())
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
