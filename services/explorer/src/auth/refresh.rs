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
    /// Refresh is not configured. The refresh grant needs no client id
    /// upstream, so [`oauth::refresh_grant`] does not return this today.
    #[error("token refresh unavailable")]
    Unavailable,
    /// The session is gone (logged out, expired, or never existed).
    #[error("no such session")]
    NoSession,
    /// Upstream refused the refresh token (`invalid_grant`, revoked, …).
    #[error("refresh rejected: {0}")]
    Rejected(String),
    /// Transport/timeout/5xx talking to `/oauth/token`. The outcome is
    /// unknown (upstream may have rotated the token before the answer was
    /// lost), so [`refresh_session`] has already ended the session.
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
/// - On [`RefreshError::Upstream`] (no usable answer: transport, timeout,
///   5xx) it **ends the session, still holding the lock**, and revokes the
///   refresh token it held, best effort. Upstream may already have rotated
///   that token; presenting it again later would be read as reuse and revoke
///   the whole rotation family. Ending it under the lock means a request
///   queued on the same session finds it gone (`NoSession`) instead of
///   replaying the token.
/// - On any other failure the session is left alone; the caller decides
///   (the upstream client drops it and reports `SessionExpired`).
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

    let tokens = match oauth::refresh_grant(state, &session.refresh_token).await {
        Ok(tokens) => tokens,
        Err(e @ RefreshError::Upstream(_)) => {
            end_after_lost_refresh(state, id, &session.refresh_token, &e).await;
            return Err(e);
        }
        Err(e) => return Err(e),
    };
    // Upstream may widen (or narrow) the scope on any refresh.
    let scope_widened = tokens.scope_widened;
    if !state.sessions.update_tokens(
        id,
        tokens.access_token.clone(),
        tokens.refresh_token,
        tokens.expires_at,
    ) {
        return Err(RefreshError::NoSession);
    }
    state.sessions.set_scope_widened(id, scope_widened);
    Ok(tokens.access_token)
}

/// The refresh's outcome is unknown: drop the session (the caller holds its
/// refresh lock) and revoke the refresh token it held. Revocation is best
/// effort, as at logout; it presents the token to `/oauth/revoke`, never to
/// `/oauth/token`, so it cannot trip reuse detection.
async fn end_after_lost_refresh(
    state: &AppState,
    id: &SessionId,
    refresh_token: &str,
    cause: &RefreshError,
) {
    tracing::warn!(error = %cause, "refresh outcome unknown; ending the session instead of replaying its refresh token");
    state.sessions.remove(id);
    if refresh_token.is_empty() {
        return;
    }
    if let Err(e) = oauth::revoke_refresh_token(state, refresh_token).await {
        tracing::warn!(error = %e, "refresh-token revocation failed after a lost refresh");
    }
}
