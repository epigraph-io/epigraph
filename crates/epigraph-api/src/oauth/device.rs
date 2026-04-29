//! Generic browser-based OAuth2 redirect flow for any OIDC redirect provider.
//!
//! POST /oauth/{provider}/auth-url   — returns the consent URL + PKCE verifier
//! POST /oauth/{provider}/exchange   — exchanges auth code + verifier for EpiGraph tokens

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::errors::ApiError;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct AuthUrlResponse {
    pub auth_url: String,
    pub code_verifier: String,
    /// CSRF binding token. The caller must verify this matches the `state` returned
    /// on the redirect callback before calling `/oauth/{provider}/exchange`.
    pub state: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct AuthUrlRequest {
    /// Optional override; falls back to provider config or EPIGRAPH_REDIRECT_URI.
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExchangeRequest {
    pub code: String,
    pub code_verifier: String,
    pub redirect_uri: Option<String>,
}

fn generate_pkce() -> (String, String) {
    use base64::Engine;
    use sha2::Digest;
    let verifier_bytes: [u8; 32] = rand::random();
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifier_bytes);
    let challenge_hash = sha2::Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_hash);
    (verifier, challenge)
}

/// Generate an OAuth `state` value (32 random bytes, base64url-encoded). Used as a
/// CSRF binding token that the caller must verify on the redirect callback.
fn generate_state() -> String {
    use base64::Engine;
    let bytes: [u8; 32] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn extract_code(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.contains("code=") {
        if let Some(query_part) = trimmed.split('?').nth(1) {
            for pair in query_part.split('&') {
                if let Some(val) = pair.strip_prefix("code=") {
                    return percent_decode(val);
                }
            }
        }
    }
    trimmed.to_string()
}

fn percent_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Resolve the redirect URI in priority order:
/// 1. Caller-supplied (request body `redirect_uri`).
/// 2. Provider-configured default (from `OidcRedirectFlow::default_redirect_uri`).
/// 3. Legacy fallback: `EPIGRAPH_REDIRECT_URI` env var, defaulting to `http://127.0.0.1:1`.
fn resolve_redirect_uri(caller: Option<&str>, provider_default: Option<&str>) -> String {
    if let Some(uri) = caller {
        return uri.to_string();
    }
    if let Some(uri) = provider_default {
        return uri.to_string();
    }
    std::env::var("EPIGRAPH_REDIRECT_URI").unwrap_or_else(|_| "http://127.0.0.1:1".to_string())
}

#[cfg(feature = "db")]
pub async fn auth_url_endpoint(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
    body: Option<Json<AuthUrlRequest>>,
) -> Result<(StatusCode, Json<AuthUrlResponse>), ApiError> {
    if state.providers.by_name(&provider_name).is_none() {
        return Err(ApiError::NotFound {
            entity: "provider".into(),
            id: provider_name.clone(),
        });
    }
    let flow = state
        .providers
        .redirect_flow(&provider_name)
        .ok_or(ApiError::BadRequest {
            message: format!("provider {provider_name} does not support redirect flow"),
        })?;

    let req = body.map(|Json(b)| b).unwrap_or_default();
    let redirect_uri =
        resolve_redirect_uri(req.redirect_uri.as_deref(), flow.default_redirect_uri());
    let (verifier, challenge) = generate_pkce();
    let csrf_state = generate_state();
    let auth_url = flow.build_auth_url(&csrf_state, &challenge, &redirect_uri);

    Ok((
        StatusCode::OK,
        Json(AuthUrlResponse {
            auth_url,
            code_verifier: verifier,
            state: csrf_state,
        }),
    ))
}

#[cfg(feature = "db")]
pub async fn exchange_endpoint(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
    Json(req): Json<ExchangeRequest>,
) -> Result<(StatusCode, Json<super::token::TokenResponse>), ApiError> {
    use crate::oauth::providers::{provision_external_user, ProviderError};

    let provider = state
        .providers
        .by_name(&provider_name)
        .ok_or(ApiError::NotFound {
            entity: "provider".into(),
            id: provider_name.clone(),
        })?;
    let flow = state
        .providers
        .redirect_flow(&provider_name)
        .ok_or(ApiError::BadRequest {
            message: format!("provider {provider_name} does not support redirect flow"),
        })?;

    let code = extract_code(&req.code);
    if code.is_empty() {
        return Err(ApiError::BadRequest {
            message: "No authorization code found in input".into(),
        });
    }

    let redirect_uri =
        resolve_redirect_uri(req.redirect_uri.as_deref(), flow.default_redirect_uri());

    let id_token = flow
        .exchange_code(&code, &redirect_uri, &req.code_verifier)
        .await
        .map_err(|e| match e {
            ProviderError::Upstream(msg) => ApiError::BadGateway { reason: msg },
            ProviderError::InvalidAssertion(msg) => ApiError::BadRequest { message: msg },
            ProviderError::Config(msg) => ApiError::InternalError { message: msg },
            ProviderError::JwksFetch(msg) => ApiError::ServiceUnavailable {
                service: format!("JWKS unavailable: {msg}"),
            },
        })?;

    let identity = match provider.validate(&id_token).await {
        Ok(id) => id,
        Err(e) => {
            crate::oauth::providers::provision::emit_oauth_audit(
                &state.db_pool,
                "oauth_assertion_rejected",
                false,
                serde_json::json!({
                    "provider": provider.name(),
                    "flow": "redirect",
                    "reason": format!("{e}"),
                }),
            );
            return Err(match e {
                ProviderError::InvalidAssertion(msg) => ApiError::Unauthorized { reason: msg },
                ProviderError::JwksFetch(msg) => ApiError::ServiceUnavailable {
                    service: format!("JWKS unavailable: {msg}"),
                },
                ProviderError::Upstream(msg) => ApiError::BadGateway { reason: msg },
                ProviderError::Config(msg) => ApiError::InternalError { message: msg },
            });
        }
    };

    provision_external_user(&state, provider.as_ref(), &identity, None).await
}

#[cfg(not(feature = "db"))]
pub async fn auth_url_endpoint(
    State(_): State<AppState>,
    Path(_): Path<String>,
    _body: Option<Json<AuthUrlRequest>>,
) -> Result<(StatusCode, Json<AuthUrlResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database required for OAuth2".into(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn exchange_endpoint(
    State(_): State<AppState>,
    Path(_): Path<String>,
    Json(_): Json<ExchangeRequest>,
) -> Result<(StatusCode, Json<super::token::TokenResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database required for OAuth2".into(),
    })
}
