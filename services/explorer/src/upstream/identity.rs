//! `POST /oauth/introspect` (RFC 7662; `oauth/introspect.rs::introspect_endpoint`):
//! the token subject the identity strip shows as the viewer's principal.
//!
//! Called once per access token, when it is minted or refreshed
//! ([`crate::auth::refresh_session`]), never per page. The scope and expiry
//! the strip shows come from the token response itself, so only the
//! principal depends on this call.

use reqwest::Method;
use serde::{Deserialize, Serialize};

use super::{decode, degrade, truncate_chars, Api, Degraded, UpstreamError};
use crate::auth::RequestAuth;
use crate::state::AppState;

/// Longest subject kept for display (upstream's is a UUID).
const MAX_SUBJECT_CHARS: usize = 64;

/// The request body: JSON, as upstream takes it.
#[derive(Serialize)]
struct IntrospectRequest<'a> {
    token: &'a str,
}

/// The fields the strip reads. Upstream also sends `client_id`, but sets it
/// to the same value as `sub`, so it cannot say which sign-in application
/// a session uses; it is not read.
#[derive(Debug, Deserialize)]
pub struct IntrospectResponse {
    pub active: bool,
    #[serde(default)]
    pub sub: Option<String>,
}

impl IntrospectResponse {
    /// The subject of an active token.
    fn subject(self) -> Result<String, UpstreamError> {
        if !self.active {
            return Err(UpstreamError::Decode("token reported inactive".into()));
        }
        self.sub
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(|s| truncate_chars(&s, MAX_SUBJECT_CHARS))
            .ok_or_else(|| UpstreamError::Decode("introspection carried no subject".into()))
    }
}

/// The principal (token subject) of `access_token`, or why it is
/// unavailable. A failure degrades only this field.
///
/// One bare exchange under the usual semaphore, per-viewer cap and deadline,
/// with no bearer and no 401 handling: the token travels in the body, and
/// this runs right after a refresh, so nothing here may start another one.
/// The subject is not logged.
pub async fn token_principal(state: &AppState, access_token: &str) -> Degraded<String> {
    let result = introspect(state, access_token)
        .await
        .and_then(IntrospectResponse::subject);
    match degrade(result) {
        Ok(principal) => principal,
        // `degrade` passes up only `SessionExpired`, which this call never
        // returns.
        Err(_) => Degraded::unavailable(UpstreamError::SessionExpired.user_message()),
    }
}

async fn introspect(
    state: &AppState,
    access_token: &str,
) -> Result<IntrospectResponse, UpstreamError> {
    let body = serde_json::to_vec(&IntrospectRequest {
        token: access_token,
    })
    .map_err(|e| UpstreamError::Decode(format!("encoding request body: {e}")))?;
    let api = Api::new(state, &RequestAuth::Anonymous);
    let exchange = api
        .exchange(
            &Method::POST,
            "/oauth/introspect",
            None::<&()>,
            Some(&body),
            None,
        )
        .await?;
    decode(exchange)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(json: &str) -> IntrospectResponse {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn only_an_active_token_with_a_subject_names_a_principal() {
        let r = response(r#"{"active":true,"sub":" abc ","client_id":"abc","exp":1}"#);
        assert_eq!(r.subject().unwrap(), "abc");
        for inactive in [
            // An inactive token names no principal even if a subject is sent.
            r#"{"active":false,"sub":"abc"}"#,
            r#"{"active":false}"#,
            r#"{"active":true}"#,
            r#"{"active":true,"sub":"  "}"#,
        ] {
            assert!(
                matches!(response(inactive).subject(), Err(UpstreamError::Decode(_))),
                "{inactive}"
            );
        }
        let long = format!(r#"{{"active":true,"sub":"{}"}}"#, "x".repeat(200));
        assert_eq!(
            response(&long).subject().unwrap().chars().count(),
            MAX_SUBJECT_CHARS + 1,
            "cut, with an ellipsis"
        );
    }
}
