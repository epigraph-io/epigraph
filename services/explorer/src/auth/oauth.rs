//! OAuth client against the API's own authorization server (plan §3.3).
//!
//! OWNED BY THE AUTH AREA. The skeleton ships only the PKCE helper and a
//! stubbed refresh grant so the upstream 401 path has something to call.
//! Wire formats (oauth-auth.md §1.4, §3): `/oauth/token` takes form bodies;
//! errors are `{error, message, details}` JSON, not RFC 6749.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use super::refresh::RefreshError;
use crate::state::AppState;

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

/// PKCE S256 challenge: `base64url_nopad(sha256(verifier))` (RFC 7636 §4.2).
pub fn pkce_challenge_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// `grant_type=refresh_token` against `{oauth_base}/oauth/token`.
///
/// STUB: always [`RefreshError::Unavailable`]. The auth area implements it
/// (form body `grant_type=refresh_token&refresh_token=<hex>`, no client
/// secret) and must return the ROTATED refresh token.
pub async fn refresh_grant(
    _state: &AppState,
    _refresh_token: &str,
) -> Result<TokenSet, RefreshError> {
    Err(RefreshError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_matches_rfc7636_appendix_b() {
        assert_eq!(
            pkce_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
