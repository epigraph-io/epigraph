//! OAuth2 Authorization Code exchange for browser-based Google login.
//!
//! POST /oauth/google/auth-url   — returns the Google consent URL + PKCE verifier
//! POST /oauth/google/exchange   — exchanges auth code + verifier for EpiGraph tokens

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::errors::ApiError;
use crate::state::AppState;

// ── Request / Response types ────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AuthUrlResponse {
    pub auth_url: String,
    pub code_verifier: String,
}

#[derive(Debug, Deserialize)]
pub struct ExchangeRequest {
    /// The authorization code from Google (or full redirect URL containing it)
    pub code: String,
    /// The PKCE code_verifier that was generated with the auth URL
    pub code_verifier: String,
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Generate PKCE code_verifier and code_challenge (S256).
fn generate_pkce() -> (String, String) {
    use base64::Engine;
    use sha2::Digest;

    let verifier_bytes: [u8; 32] = rand::random();
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifier_bytes);
    let challenge_hash = sha2::Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_hash);
    (verifier, challenge)
}

/// Extract the authorization code from user input.
/// They might paste the raw code or the full redirect URL.
fn extract_code(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.contains("code=") {
        // Parse query string from URL like http://127.0.0.1:1?code=4/0A...&scope=...
        if let Some(query_part) = trimmed.split('?').nth(1) {
            for pair in query_part.split('&') {
                if let Some(val) = pair.strip_prefix("code=") {
                    // URL-decode the value
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

// ── Endpoints ───────────────────────────────────────────────────────

/// POST /oauth/google/auth-url
///
/// Returns a Google consent URL and the PKCE code_verifier the client must
/// send back when exchanging the resulting authorization code.
#[cfg(feature = "db")]
pub async fn google_auth_url_endpoint(
    State(_state): State<AppState>,
) -> Result<(StatusCode, Json<AuthUrlResponse>), ApiError> {
    let client_id = std::env::var("GOOGLE_CLIENT_ID").map_err(|_| ApiError::InternalError {
        message: "GOOGLE_CLIENT_ID not configured on server".to_string(),
    })?;

    let redirect_uri =
        std::env::var("EPIGRAPH_REDIRECT_URI").unwrap_or_else(|_| "http://127.0.0.1:1".to_string());

    let (verifier, challenge) = generate_pkce();

    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth\
         ?client_id={client_id}\
         &redirect_uri={}\
         &response_type=code\
         &scope=openid+email+profile\
         &code_challenge={challenge}\
         &code_challenge_method=S256\
         &access_type=offline",
        redirect_uri.as_str(),
    );

    Ok((
        StatusCode::OK,
        Json(AuthUrlResponse {
            auth_url,
            code_verifier: verifier,
        }),
    ))
}

/// POST /oauth/google/exchange
///
/// Exchanges a Google authorization code + PKCE verifier for EpiGraph tokens.
/// The client obtains the code by completing Google sign-in in a browser tab
/// and copying the code from the redirect URL.
#[cfg(feature = "db")]
pub async fn google_exchange_endpoint(
    State(state): State<AppState>,
    Json(req): Json<ExchangeRequest>,
) -> Result<(StatusCode, Json<super::token::TokenResponse>), ApiError> {
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    let client_id = std::env::var("GOOGLE_CLIENT_ID").map_err(|_| ApiError::InternalError {
        message: "GOOGLE_CLIENT_ID not configured".to_string(),
    })?;
    let client_secret =
        std::env::var("GOOGLE_CLIENT_SECRET").map_err(|_| ApiError::InternalError {
            message: "GOOGLE_CLIENT_SECRET not configured".to_string(),
        })?;

    let redirect_uri =
        std::env::var("EPIGRAPH_REDIRECT_URI").unwrap_or_else(|_| "http://127.0.0.1:1".to_string());

    let code = extract_code(&req.code);
    if code.is_empty() {
        return Err(ApiError::BadRequest {
            message: "No authorization code found in input".to_string(),
        });
    }

    // Exchange the authorization code for Google tokens
    let params = [
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("code", code.as_str()),
        ("code_verifier", req.code_verifier.as_str()),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri.as_str()),
    ];

    let resp = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to contact Google token endpoint: {e}"),
        })?;

    let body = resp.text().await.unwrap_or_default();
    let parsed: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| ApiError::InternalError {
            message: format!("Failed to parse Google token response: {e}"),
        })?;

    if let Some(error) = parsed.get("error").and_then(|e| e.as_str()) {
        let desc = parsed
            .get("error_description")
            .and_then(|d| d.as_str())
            .unwrap_or("unknown error");
        return Err(ApiError::BadRequest {
            message: format!("Google token exchange failed: {error}: {desc}"),
        });
    }

    // Extract and validate the ID token
    let id_token_str =
        parsed
            .get("id_token")
            .and_then(|v| v.as_str())
            .ok_or(ApiError::InternalError {
                message: "Google returned no id_token".to_string(),
            })?;

    let header = decode_header(id_token_str).map_err(|e| ApiError::BadRequest {
        message: format!("Invalid ID token header: {e}"),
    })?;
    let kid = header.kid.ok_or(ApiError::BadRequest {
        message: "ID token missing kid header".to_string(),
    })?;

    // Fetch Google's JWKS
    let jwks_url = "https://www.googleapis.com/oauth2/v3/certs";
    let jwks_resp = reqwest::get(jwks_url)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to fetch Google JWKS: {e}"),
        })?;
    let jwks_body: serde_json::Value =
        jwks_resp
            .json()
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to parse Google JWKS: {e}"),
            })?;

    let keys = jwks_body["keys"]
        .as_array()
        .ok_or(ApiError::InternalError {
            message: "Google JWKS has no keys array".to_string(),
        })?;
    let jwk = keys
        .iter()
        .find(|k| k["kid"].as_str() == Some(&kid))
        .ok_or(ApiError::Unauthorized {
            reason: "ID token kid not found in Google JWKS".to_string(),
        })?;

    let n = jwk["n"].as_str().ok_or(ApiError::InternalError {
        message: "Google JWK missing 'n' field".to_string(),
    })?;
    let e_val = jwk["e"].as_str().ok_or(ApiError::InternalError {
        message: "Google JWK missing 'e' field".to_string(),
    })?;

    let decoding_key =
        DecodingKey::from_rsa_components(n, e_val).map_err(|err| ApiError::InternalError {
            message: format!("Failed to build RSA key from Google JWK: {err}"),
        })?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&client_id]);
    validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);

    let token_data =
        decode::<super::token::GoogleIdTokenClaims>(id_token_str, &decoding_key, &validation)
            .map_err(|e| ApiError::Unauthorized {
                reason: format!("Google ID token validation failed: {e}"),
            })?;

    // Use shared provisioning logic
    super::token::provision_google_user(&state, &token_data.claims, None).await
}

#[cfg(not(feature = "db"))]
pub async fn google_auth_url_endpoint(
    State(_state): State<AppState>,
) -> Result<(StatusCode, Json<AuthUrlResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database required for OAuth2".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn google_exchange_endpoint(
    State(_state): State<AppState>,
    Json(_req): Json<ExchangeRequest>,
) -> Result<(StatusCode, Json<super::token::TokenResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database required for OAuth2".to_string(),
    })
}
