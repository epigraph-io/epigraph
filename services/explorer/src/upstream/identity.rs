//! Who the viewer is, for display.
//!
//! Two different ids, and the identity strip shows both under their own names:
//!
//! - **The principal** is the agent the access token names: its `agent_id`
//!   claim ([`token_agent_id`]). It is what the kernel calls the principal:
//!   `ViewerExtractor` refuses a token without one, row-level security is
//!   stamped with it, and it is the `agent_id` on the viewer's own security
//!   events, claims and events.
//! - **The sign-in client** is the token's subject as `POST /oauth/introspect`
//!   (RFC 7662; `oauth/introspect.rs::introspect_endpoint`) reports it
//!   ([`token_principal`], kept under its old name). The kernel mints access
//!   tokens with `sub` = the OAuth client row's id (a per-user client), so
//!   this is the sign-in client record, not the agent.
//!
//! Introspection is called once per access token, when it is minted or
//! refreshed ([`crate::auth::refresh_session`]), never per page. The scope and
//! expiry the strip shows come from the token response itself.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// Longest access token whose claims are read for display (EpiGraph's are a
/// few hundred bytes).
const MAX_TOKEN_CHARS: usize = 8 * 1024;

/// The `agent_id` claim of an EpiGraph access token (a JWT), read for
/// DISPLAY ONLY: who the identity strip names, and whose rows the audit page
/// calls "your own".
///
/// The payload is base64url-decoded WITHOUT verifying the signature. That is
/// sound only because nothing authorizes on the result: the token is the
/// viewer's own, issued to this Explorer and sent upstream as it is, where the
/// API verifies it on every call. A token that is not a JWT with a UUID
/// `agent_id` (an opaque or dev bearer) yields `None`, and callers must treat
/// that as "not known".
pub fn token_agent_id(access_token: &str) -> Option<Uuid> {
    #[derive(Deserialize)]
    struct Claims {
        agent_id: Option<Uuid>,
    }
    if access_token.len() > MAX_TOKEN_CHARS {
        return None;
    }
    let mut parts = access_token.split('.');
    let (_header, payload, _signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice::<Claims>(&bytes).ok()?.agent_id
}

/// The token subject `/oauth/introspect` reports for `access_token` (the
/// sign-in client record, see the module doc), or why it is unavailable. A
/// failure degrades only this field.
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

    fn jwt(payload: &str) -> String {
        format!(
            "{}.{}.c2ln",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(payload.as_bytes())
        )
    }

    #[test]
    fn the_principal_is_the_tokens_agent_id_claim() {
        let agent = "1b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
        let client = "11111111-1111-4111-8111-111111111111";
        let t = jwt(&format!(
            r#"{{"sub":"{client}","agent_id":"{agent}","scopes":["claims:read"],"exp":1}}"#
        ));
        assert_eq!(
            token_agent_id(&t),
            Some(Uuid::parse_str(agent).unwrap()),
            "the agent, never the subject"
        );
        for not_known in [
            "opaque-token".to_string(),
            jwt(&format!(r#"{{"sub":"{client}"}}"#)),
            jwt(&format!(r#"{{"sub":"{client}","agent_id":null}}"#)),
            jwt(r#"{"agent_id":"not-a-uuid"}"#),
            jwt("not json"),
            format!("{}.extra", jwt(&format!(r#"{{"agent_id":"{agent}"}}"#))),
            "a.!!!.c".to_string(),
            String::new(),
        ] {
            assert_eq!(token_agent_id(&not_known), None, "{not_known}");
        }
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
