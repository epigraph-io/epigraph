//! Durable RFC 7009 revocation of JWT access tokens, keyed by `jti`
//! (migration 141).
//!
//! Written by `POST /oauth/revoke` on the HTTP API, read by both servers'
//! bearer middleware after the token's signature has been verified. Keyed by
//! `jti`, never by the token string: a `jti` is only meaningful on a token
//! whose signature checks, and a uuid key keeps the table free of bearer
//! material.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

pub struct RevokedAccessTokenRepository;

impl RevokedAccessTokenRepository {
    /// Record that the access token `jti` (issued to `client_id`, expiring at
    /// `expires_at`) is revoked, through migration 141's definer: the
    /// application role holds no write on the table. Returns whether a new row
    /// was written; an already revoked token, or one more than 24 hours past
    /// its expiry, is `false`, not an error. The definer also prunes rows whose
    /// token expired over 24 hours ago. Both margins are on the DATABASE clock
    /// and absorb clock skew against the hosts that check `exp` on their own
    /// clock with zero leeway (see migration 141's header).
    ///
    /// The caller must pass a `jti` read from a SIGNATURE-VERIFIED token: the
    /// endpoint that calls this is anonymous, and an unverified `jti` would let
    /// anyone fill the table.
    #[instrument(skip(pool))]
    pub async fn revoke(
        pool: &PgPool,
        jti: Uuid,
        client_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, DbError> {
        sqlx::query_scalar("SELECT public.epigraph_access_token_revoke($1, $2, $3)")
            .bind(jti)
            .bind(client_id)
            .bind(expires_at)
            .fetch_one(pool)
            .await
            .map_err(|e| DbError::QueryFailed { source: e })
    }

    /// Whether the access token `jti` has been revoked. A primary-key lookup on
    /// the application role (which keeps SELECT on the table).
    ///
    /// An `Err` means the answer is UNKNOWN; callers on an authentication path
    /// must refuse the token, never admit it.
    #[instrument(skip(pool))]
    pub async fn is_revoked(pool: &PgPool, jti: Uuid) -> Result<bool, DbError> {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM public.revoked_access_tokens WHERE jti = $1)",
        )
        .bind(jti)
        .fetch_one(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })
    }
}
