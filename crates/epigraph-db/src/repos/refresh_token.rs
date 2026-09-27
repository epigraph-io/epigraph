//! Refresh token storage for OAuth2 token rotation.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

#[derive(Debug, Clone, FromRow)]
pub struct RefreshTokenRow {
    pub id: Uuid,
    pub token_hash: Vec<u8>,
    pub client_id: Uuid,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

pub struct RefreshTokenRepository;

/// What [`RefreshTokenRepository::check`] found for a presented token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshCheck {
    /// Live and unexpired.
    Valid { id: Uuid, client_id: Uuid },
    /// Already spent by rotation: its family has been revoked.
    Reuse,
    /// Unknown, expired, or revoked for another reason.
    Invalid,
}

/// What [`RefreshTokenRepository::rotate`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshRotateOutcome {
    /// The presented token was claimed; `id` is its successor.
    Rotated { id: Uuid },
    /// The presented token had already been rotated: reuse, family revoked.
    Reuse,
    /// The presented token was not live (expired, or revoked otherwise).
    Invalid,
}

/// Why a single token is revoked outside rotation. `rotated` and `reuse` are
/// the rotation's and the reuse detector's own reasons and cannot be passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshRevokeReason {
    /// A refresh was denied (suspended client, identity no longer allowed,
    /// operated agent) and the presented token is burned.
    Denied,
    /// The holder revoked it (`/oauth/revoke`, RFC 7009).
    Revoked,
}

impl RefreshRevokeReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Revoked => "revoked",
        }
    }
}

impl RefreshTokenRepository {
    #[instrument(skip(pool, token_hash))]
    pub async fn create(
        pool: &PgPool,
        token_hash: &[u8],
        client_id: Uuid,
        scopes: &[String],
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at)
            VALUES ($1, $2, $3, $4) RETURNING id"#,
        )
        .bind(token_hash)
        .bind(client_id)
        .bind(scopes)
        .bind(expires_at)
        .fetch_one(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row.0)
    }

    #[instrument(skip(pool, token_hash))]
    pub async fn get_valid(
        pool: &PgPool,
        token_hash: &[u8],
    ) -> Result<Option<RefreshTokenRow>, DbError> {
        let row = sqlx::query_as::<_, RefreshTokenRow>(
            r#"SELECT * FROM refresh_tokens WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()"#,
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row)
    }

    /// The refresh grant's first read (migration 118,
    /// `epigraph_refresh_token_check`). [`RefreshCheck::Valid`] has no side
    /// effect. A token that was spent by ROTATION is reuse (OAuth 2.0 Security
    /// BCP): the definer revokes every live token of its family and writes a
    /// `security_events` row before answering [`RefreshCheck::Reuse`].
    /// Anything else (unknown, expired, revoked for another reason) is
    /// [`RefreshCheck::Invalid`].
    #[instrument(skip(pool, token_hash))]
    pub async fn check(pool: &PgPool, token_hash: &[u8]) -> Result<RefreshCheck, DbError> {
        let (outcome, id, client_id): (String, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            "SELECT outcome, token_id, client_id FROM public.epigraph_refresh_token_check($1)",
        )
        .bind(token_hash)
        .fetch_one(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(match (outcome.as_str(), id, client_id) {
            ("valid", Some(id), Some(client_id)) => RefreshCheck::Valid { id, client_id },
            ("reuse", _, _) => RefreshCheck::Reuse,
            _ => RefreshCheck::Invalid,
        })
    }

    /// Rotate ATOMICALLY (migration 118, `epigraph_refresh_token_rotate`):
    /// claim the presented token with one `UPDATE ... WHERE revoked_at IS NULL
    /// AND expires_at > now()` and insert its successor in the same family, for
    /// the same client. Of any number of concurrent calls presenting one token,
    /// exactly one gets [`RefreshRotateOutcome::Rotated`]; the others find it spent by
    /// rotation, which is reuse and revokes the family (the winner's new token
    /// included: the server cannot tell which presenter is the legitimate one,
    /// and the BCP's rule is to end the chain).
    #[instrument(skip(pool, old_hash, new_hash))]
    pub async fn rotate(
        pool: &PgPool,
        old_hash: &[u8],
        new_hash: &[u8],
        scopes: &[String],
        expires_at: DateTime<Utc>,
    ) -> Result<RefreshRotateOutcome, DbError> {
        let (outcome, id): (String, Option<Uuid>) = sqlx::query_as(
            "SELECT outcome, token_id FROM public.epigraph_refresh_token_rotate($1, $2, $3, $4)",
        )
        .bind(old_hash)
        .bind(new_hash)
        .bind(expires_at)
        .bind(scopes)
        .fetch_one(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(match (outcome.as_str(), id) {
            ("rotated", Some(id)) => RefreshRotateOutcome::Rotated { id },
            ("reuse", _) => RefreshRotateOutcome::Reuse,
            _ => RefreshRotateOutcome::Invalid,
        })
    }

    /// Revoke one live token (a denied refresh, `/oauth/revoke`) through
    /// migration 118's definer. Returns whether a live row was revoked.
    #[instrument(skip(pool))]
    pub async fn revoke(
        pool: &PgPool,
        id: Uuid,
        reason: RefreshRevokeReason,
    ) -> Result<bool, DbError> {
        sqlx::query_scalar("SELECT public.epigraph_refresh_token_revoke($1, $2)")
            .bind(id)
            .bind(reason.as_str())
            .fetch_one(pool)
            .await
            .map_err(|e| DbError::QueryFailed { source: e })
    }

    /// Revoke every live token of one client, through migration 118's definer.
    #[instrument(skip(pool))]
    pub async fn revoke_all_for_client(pool: &PgPool, client_id: Uuid) -> Result<u64, DbError> {
        let n: i64 = sqlx::query_scalar("SELECT public.epigraph_refresh_token_revoke_client($1)")
            .bind(client_id)
            .fetch_one(pool)
            .await
            .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Delete expired rows. A direct DELETE: since migration 118 the
    /// application role holds no DELETE on `refresh_tokens`, so this runs only
    /// on a privileged (maintenance or migration) connection. No request path
    /// calls it.
    #[instrument(skip(pool))]
    pub async fn cleanup_expired(pool: &PgPool) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < now()")
            .execute(pool)
            .await
            .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(result.rows_affected())
    }
}
