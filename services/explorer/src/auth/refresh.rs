//! The refresh hook the upstream client calls on a 401 (and the extractor
//! calls shortly before expiry).
//!
//! Signature and single-flight semantics are fixed; the network exchange is
//! [`super::oauth::refresh_grant`].

use thiserror::Error;

use super::oauth;
use super::session::SessionId;
use crate::state::AppState;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum RefreshError {
    /// Refresh is not implemented/configured (no client id, or stubbed).
    #[error("token refresh unavailable")]
    Unavailable,
    /// The session is gone (logged out, expired, or never existed).
    #[error("no such session")]
    NoSession,
    /// Upstream refused the refresh token (`invalid_grant`, revoked, …).
    #[error("refresh rejected: {0}")]
    Rejected(String),
    /// Transport/timeout/5xx talking to `/oauth/token`.
    #[error("refresh failed: {0}")]
    Upstream(String),
}

/// Obtain a usable access token for `id`, given the token that just failed
/// (or is about to expire).
///
/// Contract:
/// - **Single-flight per session.** Holds the session's refresh lock; if the
///   stored access token no longer equals `stale_access_token`, another task
///   already refreshed and that token is returned without calling upstream.
/// - Otherwise calls [`oauth::refresh_grant`] with the stored refresh token
///   and stores the rotated pair (upstream rotates on every use).
/// - Never removes the session; the caller decides (the upstream client
///   drops it and reports `SessionExpired`).
pub async fn refresh_session(
    state: &AppState,
    id: &SessionId,
    stale_access_token: &str,
) -> Result<String, RefreshError> {
    let lock = state
        .sessions
        .refresh_lock(id)
        .ok_or(RefreshError::NoSession)?;
    let _guard = lock.lock().await;

    let session = state.sessions.get(id).ok_or(RefreshError::NoSession)?;
    if session.access_token != stale_access_token {
        return Ok(session.access_token);
    }

    let tokens = oauth::refresh_grant(state, &session.refresh_token).await?;
    if !state.sessions.update_tokens(
        id,
        tokens.access_token.clone(),
        tokens.refresh_token,
        tokens.expires_at,
    ) {
        return Err(RefreshError::NoSession);
    }
    Ok(tokens.access_token)
}
