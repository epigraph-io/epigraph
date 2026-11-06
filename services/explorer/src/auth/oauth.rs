//! OAuth client against the API's own authorization server (plan §3.3).
//!
//! Hand-written rather than the `oauth2` crate, because upstream is not RFC
//! 6749 on the wire (oauth-auth.md §1.4, §6):
//!
//! - `/oauth/token` takes form bodies, reads `client_id` from the body only,
//!   and checks no secret for this public client;
//! - its errors are `{error, message, details: {message}}` JSON, e.g.
//!   `{"error":"BadRequest","message":"Bad request: invalid_grant: PKCE
//!   mismatch","details":{"message":"invalid_grant: PKCE mismatch"}}`;
//! - `/oauth/revoke` takes JSON only (a form body gets a 415).
//!
//! The browser is sent to `{EPIGRAPH_OAUTH_BASE_URL}/oauth/authorize`. The
//! server-to-server calls (`/oauth/token`, `/oauth/revoke`) go to
//! `EPIGRAPH_API_URL`, the same process the BFF already calls for data, so
//! they never hairpin through the public edge.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use super::refresh::RefreshError;
use crate::config::Config;
use crate::state::AppState;
use crate::upstream::truncate_chars;

/// The scope the Explorer asks for. Upstream widens it to the user's full
/// grant on the first refresh (oauth-auth.md §3); it is a statement of
/// intent, not a boundary.
pub const SCOPE: &str = "claims:read";
/// Largest token-endpoint body the BFF will buffer.
const MAX_TOKEN_BODY: usize = 64 * 1024;
/// `expires_in` is believed only up to this (upstream issues 1 h tokens).
const MAX_TOKEN_LIFETIME_SECS: i64 = 24 * 60 * 60;
/// Longest upstream error message kept for logs.
const MAX_ERROR_MESSAGE_CHARS: usize = 300;

/// A token pair from `/oauth/token`, with `expires_in` already turned into
/// an absolute instant.
#[derive(Clone)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSet")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// `TokenResponse` (`token.rs:68-75`). `refresh_token` is always sent in
/// practice but is not guaranteed by the type.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
    expires_in: i64,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

/// Every error body the token and revoke endpoints produce: upstream's
/// `{error, message, details}`, plus RFC 6749's `error_description` in case
/// the AS ever becomes conformant.
#[derive(Deserialize, Default)]
struct OAuthErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
    #[serde(default)]
    details: Option<serde_json::Value>,
}

/// Why a token-endpoint exchange failed.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TokenError {
    /// `EPIGRAPH_EXPLORER_CLIENT_ID` is unset: sign-in is disabled.
    #[error("sign-in is not configured (no client id)")]
    NotConfigured,
    /// A 4xx: bad or used code, PKCE mismatch, revoked refresh token, an
    /// account off the allowlist (403), …
    #[error("token endpoint rejected the request ({status}): {message}")]
    Rejected {
        status: u16,
        /// The body's `error` field (`"BadRequest"`, `"Forbidden"`, …).
        kind: Option<String>,
        /// `details.message` when present (`"invalid_grant: PKCE
        /// mismatch"`), else `message`, else the text body.
        message: String,
    },
    /// Transport failure, timeout or 5xx.
    #[error("token endpoint unavailable: {0}")]
    Unavailable(String),
    /// A 2xx whose body is not a usable token response.
    #[error("unexpected token endpoint response: {0}")]
    Decode(String),
}

impl TokenError {
    /// The code grant's "this code is no good" family: expired, used,
    /// PKCE or redirect mismatch. Upstream only says so in the message.
    pub fn is_invalid_grant(&self) -> bool {
        match self {
            TokenError::Rejected { kind, message, .. } => {
                kind.as_deref() == Some("invalid_grant") || message.starts_with("invalid_grant")
            }
            _ => false,
        }
    }

    /// HTTP status for the page that reports this failure.
    pub fn page_status(&self) -> u16 {
        match self {
            TokenError::NotConfigured => 503,
            TokenError::Rejected { status: 403, .. } => 403,
            TokenError::Rejected { .. } => 400,
            TokenError::Unavailable(_) | TokenError::Decode(_) => 502,
        }
    }

    /// Viewer-safe sentence. Upstream detail is logged, never shown.
    pub fn user_message(&self) -> &'static str {
        match self {
            TokenError::NotConfigured => "Sign-in is not configured on this server.",
            e if e.is_invalid_grant() => {
                "The sign-in took too long or was already used. Please sign in again."
            }
            TokenError::Rejected { status: 403, .. } => {
                "EpiGraph did not allow this account to sign in."
            }
            TokenError::Rejected { .. } => "EpiGraph refused the sign-in. Please sign in again.",
            TokenError::Unavailable(_) | TokenError::Decode(_) => {
                "EpiGraph's sign-in service is unavailable right now. Please try again shortly."
            }
        }
    }
}

/// PKCE S256 challenge: `base64url_nopad(sha256(verifier))` (RFC 7636 §4.2).
pub fn pkce_challenge_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The browser-facing authorize URL (oauth-auth.md §8 step 2). The
/// `redirect_uri` is [`Config::redirect_uri`], which must equal the one in
/// the operator-inserted client row exactly.
pub fn authorize_url(config: &Config, client_id: &str, state: &str, code_challenge: &str) -> Url {
    let base = config.oauth_base_url.as_str().trim_end_matches('/');
    let mut url = Url::parse(&format!("{base}/oauth/authorize"))
        .expect("a validated http(s) URL plus a fixed path parses");
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", &config.redirect_uri())
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state)
        .append_pair("scope", SCOPE);
    url
}

/// `grant_type=authorization_code`. Upstream codes live 60 s, so the
/// callback calls this before doing anything else.
pub async fn exchange_code(
    state: &AppState,
    code: &str,
    code_verifier: &str,
) -> Result<TokenSet, TokenError> {
    let client_id = state
        .config
        .client_id
        .as_deref()
        .ok_or(TokenError::NotConfigured)?;
    let redirect_uri = state.config.redirect_uri();
    let body = post_token_form(
        state,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", code_verifier),
            ("redirect_uri", &redirect_uri),
            ("client_id", client_id),
        ],
    )
    .await?;
    let tokens = token_set(body)?;
    if tokens.refresh_token.is_empty() {
        tracing::warn!("token response carried no refresh token; the session ends when the access token expires");
    }
    Ok(tokens)
}

/// `grant_type=refresh_token` (oauth-auth.md §8 step 4). Upstream rotates
/// the refresh token on every use and revokes the old one, so the caller
/// ([`super::refresh_session`]) must store the returned pair.
///
/// `client_id` is sent when configured although upstream neither requires
/// nor checks it today (`token.rs:469-608`); it costs nothing and keeps
/// working if refresh tokens are ever bound to their client.
pub async fn refresh_grant(
    state: &AppState,
    refresh_token: &str,
) -> Result<TokenSet, RefreshError> {
    if refresh_token.is_empty() {
        return Err(RefreshError::Rejected("no refresh token stored".into()));
    }
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    if let Some(client_id) = state.config.client_id.as_deref() {
        form.push(("client_id", client_id));
    }
    let body = post_token_form(state, &form).await.map_err(refresh_error)?;
    let mut tokens = token_set(body).map_err(refresh_error)?;
    if tokens.refresh_token.is_empty() {
        // Not expected (upstream always rotates). Keeping the old token is
        // the only option left; if it was revoked, the next refresh fails
        // and the session ends then.
        tracing::warn!("refresh response carried no refresh token; keeping the previous one");
        tokens.refresh_token = refresh_token.to_string();
    }
    Ok(tokens)
}

fn refresh_error(e: TokenError) -> RefreshError {
    match e {
        TokenError::NotConfigured => RefreshError::Unavailable,
        TokenError::Rejected { message, .. } => RefreshError::Rejected(message),
        TokenError::Unavailable(m) | TokenError::Decode(m) => RefreshError::Upstream(m),
    }
}

/// `POST /oauth/revoke` with the JSON body `{token, token_type_hint:
/// "refresh_token"}` (JSON only upstream, `revoke.rs:9-61`). Revoking the
/// access token would only reach one API process's memory, so logout
/// revokes the refresh token and lets the access token run out.
pub async fn revoke_refresh_token(state: &AppState, refresh_token: &str) -> Result<(), TokenError> {
    #[derive(Serialize)]
    struct RevokeRequest<'a> {
        token: &'a str,
        token_type_hint: &'static str,
    }
    let up = &state.upstream;
    let resp = up
        .http()
        .post(format!("{}/oauth/revoke", up.base_url()))
        .timeout(up.timeout())
        .header(ACCEPT, "application/json")
        .json(&RevokeRequest {
            token: refresh_token,
            token_type_hint: "refresh_token",
        })
        .send()
        .await
        .map_err(transport)?;
    let (status, content_type, body) = read_capped(resp).await?;
    if status.is_success() {
        Ok(())
    } else {
        Err(error_from(status, &content_type, &body))
    }
}

/// POST a form to `{api}/oauth/token` and return the 2xx body, or the
/// failure as a [`TokenError`].
async fn post_token_form(state: &AppState, form: &[(&str, &str)]) -> Result<Vec<u8>, TokenError> {
    let up = &state.upstream;
    let resp = up
        .http()
        .post(format!("{}/oauth/token", up.base_url()))
        .timeout(up.timeout())
        .header(ACCEPT, "application/json")
        .form(form)
        .send()
        .await
        .map_err(transport)?;
    let (status, content_type, body) = read_capped(resp).await?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(error_from(status, &content_type, &body))
    }
}

async fn read_capped(
    mut resp: reqwest::Response,
) -> Result<(reqwest::StatusCode, String, Vec<u8>), TokenError> {
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(transport)? {
        if body.len() + chunk.len() > MAX_TOKEN_BODY {
            return Err(TokenError::Decode(format!(
                "response body over {MAX_TOKEN_BODY} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, content_type, body))
}

fn transport(e: reqwest::Error) -> TokenError {
    if e.is_timeout() {
        TokenError::Unavailable("timed out".into())
    } else {
        TokenError::Unavailable(e.without_url().to_string())
    }
}

/// Map a non-2xx token/revoke response. 5xx (and any 3xx: redirects are
/// never followed) count as unavailable; 4xx as rejected.
fn error_from(status: reqwest::StatusCode, content_type: &str, body: &[u8]) -> TokenError {
    let (kind, message) = error_message(status, content_type, body);
    if status.is_client_error() {
        TokenError::Rejected {
            status: status.as_u16(),
            kind,
            message,
        }
    } else {
        TokenError::Unavailable(format!("{}: {message}", status.as_u16()))
    }
}

/// `(error kind, message)` from an error body. Prefers `details.message`
/// (upstream's un-prefixed reason, e.g. `"invalid_grant: PKCE mismatch"`),
/// then `message`, then RFC 6749's `error_description`, then the text body.
fn error_message(
    status: reqwest::StatusCode,
    content_type: &str,
    body: &[u8],
) -> (Option<String>, String) {
    let parsed: Option<OAuthErrorBody> = if content_type.contains("json") {
        serde_json::from_slice(body).ok()
    } else {
        None
    };
    let parsed = parsed.unwrap_or_default();
    let detail = parsed
        .details
        .as_ref()
        .and_then(|d| d.get("message"))
        .and_then(|m| m.as_str())
        .map(str::to_string);
    let text = String::from_utf8_lossy(body).trim().to_string();
    let message = [detail, parsed.message, parsed.error_description]
        .into_iter()
        .flatten()
        .map(|m| m.trim().to_string())
        .find(|m| !m.is_empty())
        .or_else(|| (!content_type.contains("json") && !text.is_empty()).then_some(text))
        .or_else(|| parsed.error.clone())
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("error").to_string());
    (
        parsed.error,
        truncate_chars(&message, MAX_ERROR_MESSAGE_CHARS),
    )
}

/// Validate a 2xx token body and turn `expires_in` into an instant.
fn token_set(body: Vec<u8>) -> Result<TokenSet, TokenError> {
    let r: TokenResponse =
        serde_json::from_slice(&body).map_err(|e| TokenError::Decode(e.to_string()))?;
    if r.access_token.is_empty() {
        return Err(TokenError::Decode("empty access_token".into()));
    }
    if let Some(t) = r.token_type.as_deref() {
        if !t.eq_ignore_ascii_case("bearer") {
            return Err(TokenError::Decode(format!(
                "token_type {t:?} is not Bearer"
            )));
        }
    }
    tracing::debug!(
        scope = r.scope.as_deref().unwrap_or(""),
        expires_in = r.expires_in,
        "tokens issued"
    );
    let lifetime = r.expires_in.clamp(0, MAX_TOKEN_LIFETIME_SECS);
    Ok(TokenSet {
        access_token: r.access_token,
        refresh_token: r.refresh_token.unwrap_or_default(),
        expires_at: Utc::now() + chrono::Duration::seconds(lifetime),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ENV_CLIENT_ID, ENV_OAUTH_BASE_URL, ENV_PUBLIC_BASE_URL};
    use reqwest::StatusCode;
    use std::collections::HashMap;

    #[test]
    fn pkce_matches_rfc7636_appendix_b() {
        assert_eq!(
            pkce_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    fn config(pairs: &[(&str, &str)]) -> Config {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|k| map.get(k).cloned()).unwrap()
    }

    #[test]
    fn authorize_url_carries_every_required_parameter() {
        let c = config(&[
            (ENV_PUBLIC_BASE_URL, "https://explorer.example.com/explorer"),
            (ENV_OAUTH_BASE_URL, "https://api.example.com/"),
            (ENV_CLIENT_ID, "epigraph_explorer_abc"),
        ]);
        let url = authorize_url(&c, "epigraph_explorer_abc", "st&ate", "chal");
        assert_eq!(
            url.as_str(),
            "https://api.example.com/oauth/authorize?response_type=code\
             &client_id=epigraph_explorer_abc\
             &redirect_uri=https%3A%2F%2Fexplorer.example.com%2Fexplorer%2Fauth%2Fcallback\
             &code_challenge=chal&code_challenge_method=S256&state=st%26ate&scope=claims%3Aread"
        );
    }

    #[test]
    fn upstream_error_bodies_yield_the_detail_message() {
        let (kind, msg) = error_message(
            StatusCode::BAD_REQUEST,
            "application/json",
            br#"{"error":"BadRequest","message":"Bad request: invalid_grant: PKCE mismatch","details":{"message":"invalid_grant: PKCE mismatch"}}"#,
        );
        assert_eq!(kind.as_deref(), Some("BadRequest"));
        assert_eq!(msg, "invalid_grant: PKCE mismatch");
        let e = error_from(
            StatusCode::BAD_REQUEST,
            "application/json",
            br#"{"error":"BadRequest","message":"Bad request: invalid_grant: PKCE mismatch","details":{"message":"invalid_grant: PKCE mismatch"}}"#,
        );
        assert!(e.is_invalid_grant(), "{e:?}");
        assert_eq!(e.page_status(), 400);

        // No details: the top-level message.
        let (_, msg) = error_message(
            StatusCode::FORBIDDEN,
            "application/json; charset=utf-8",
            br#"{"error":"Forbidden","message":"Forbidden: client is not active"}"#,
        );
        assert_eq!(msg, "Forbidden: client is not active");

        // RFC 6749 shape.
        let e = error_from(
            StatusCode::BAD_REQUEST,
            "application/json",
            br#"{"error":"invalid_grant","error_description":"code expired"}"#,
        );
        assert_eq!(
            e,
            TokenError::Rejected {
                status: 400,
                kind: Some("invalid_grant".into()),
                message: "code expired".into()
            }
        );
        assert!(e.is_invalid_grant());

        // axum's text/plain rejections (415, 422).
        let (kind, msg) = error_message(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "text/plain; charset=utf-8",
            b"Expected request with `Content-Type: application/json`",
        );
        assert_eq!(kind, None);
        assert_eq!(
            msg,
            "Expected request with `Content-Type: application/json`"
        );

        // Empty body: the status reason.
        let e = error_from(StatusCode::BAD_GATEWAY, "", b"");
        assert_eq!(e, TokenError::Unavailable("502: Bad Gateway".into()));
        assert_eq!(e.page_status(), 502);
    }

    #[test]
    fn token_bodies_are_validated() {
        let t = token_set(
            br#"{"access_token":"a","token_type":"Bearer","expires_in":3600,"refresh_token":"r","scope":"claims:read"}"#
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            (t.access_token.as_str(), t.refresh_token.as_str()),
            ("a", "r")
        );
        let left = (t.expires_at - Utc::now()).num_seconds();
        assert!((3590..=3600).contains(&left), "{left}");
        assert!(!format!("{t:?}").contains("\"a\""), "Debug hides tokens");

        // Optional fields omitted; absurd lifetimes clamped.
        let t = token_set(br#"{"access_token":"a","expires_in":999999999}"#.to_vec()).unwrap();
        assert_eq!(t.refresh_token, "");
        assert!((t.expires_at - Utc::now()).num_seconds() <= MAX_TOKEN_LIFETIME_SECS);
        let t = token_set(br#"{"access_token":"a","expires_in":-5}"#.to_vec()).unwrap();
        assert!(t.expires_at <= Utc::now());

        for bad in [
            &br#"{"access_token":"","expires_in":1}"#[..],
            br#"{"access_token":"a","token_type":"mac","expires_in":1}"#,
            br#"{"access_token":"a"}"#,
            b"<html>",
        ] {
            assert!(
                matches!(token_set(bad.to_vec()), Err(TokenError::Decode(_))),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn user_messages_never_carry_upstream_detail() {
        let e = TokenError::Rejected {
            status: 403,
            kind: Some("Forbidden".into()),
            message: "email not authorized for this provider".into(),
        };
        assert_eq!(e.page_status(), 403);
        assert!(!e.user_message().contains("email"));
        assert_eq!(
            refresh_error(TokenError::Unavailable("timed out".into())),
            RefreshError::Upstream("timed out".into())
        );
        assert_eq!(
            refresh_error(TokenError::NotConfigured),
            RefreshError::Unavailable
        );
    }
}
