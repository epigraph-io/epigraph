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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshCheck {
    /// Live and unexpired. `scopes` are the scopes the token was minted with
    /// (the consent, or its rotation's narrowing): the ceiling of anything the
    /// refresh grant may issue from it (RFC 6749 section 6).
    Valid {
        id: Uuid,
        client_id: Uuid,
        scopes: Vec<String>,
    },
    /// Spent by its own rotation less than 30 seconds ago: a benign
    /// concurrent refresh. Refused like [`Self::Invalid`], and the family
    /// stays live (migration 118's grace window).
    Grace,
    /// Spent by rotation longer ago than the grace window: its family has been
    /// revoked.
    Reuse,
    /// Unknown, expired, or revoked for another reason.
    Invalid,
}

/// What [`RefreshTokenRepository::rotate`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshRotateOutcome {
    /// The presented token was claimed; `id` is its successor.
    Rotated { id: Uuid },
    /// The presented token was rotated less than 30 seconds ago (the loser of
    /// a concurrent refresh): refused, family left live.
    Grace,
    /// The presented token had been rotated before the grace window: reuse,
    /// family revoked.
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

    /// Read a live row by hash, `token_hash` included. Since migration 118 the
    /// application role cannot read `token_hash`, so this runs only on a
    /// privileged connection; no request path calls it (the refresh grant uses
    /// [`Self::check`], `/oauth/revoke` uses [`Self::revoke_by_hash`]).
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
    /// effect. A token that was spent by ROTATION less than 30 seconds ago is
    /// [`RefreshCheck::Grace`] (a benign concurrent refresh; nothing revoked).
    /// Spent by rotation longer ago than that, it is reuse (OAuth 2.0 Security
    /// BCP): the definer revokes every live token of its family and writes a
    /// `security_events` row before answering [`RefreshCheck::Reuse`].
    /// Anything else (unknown, expired, revoked for another reason) is
    /// [`RefreshCheck::Invalid`].
    ///
    /// A `valid` token's stored `scopes` are joined in by id rather than
    /// returned by the definer, so the definer's `RETURNS TABLE` (and its
    /// grants) is unchanged. The application role reads `scopes` and `id`
    /// (118's column grant withholds only `token_hash`), `refresh_tokens` has
    /// no row policy, and that role holds no UPDATE on it, so the scopes cannot
    /// change between this read and the rotation. A `valid` row whose scopes
    /// do not come back is refused as [`RefreshCheck::Invalid`]: it is never
    /// read as "no ceiling".
    #[instrument(skip(pool, token_hash))]
    pub async fn check(pool: &PgPool, token_hash: &[u8]) -> Result<RefreshCheck, DbError> {
        let (outcome, id, client_id, scopes): (
            String,
            Option<Uuid>,
            Option<Uuid>,
            Option<Vec<String>>,
        ) = sqlx::query_as(
            "SELECT c.outcome, c.token_id, c.client_id, t.scopes \
               FROM public.epigraph_refresh_token_check($1) c \
               LEFT JOIN public.refresh_tokens t ON t.id = c.token_id",
        )
        .bind(token_hash)
        .fetch_one(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(match (outcome.as_str(), id, client_id, scopes) {
            ("valid", Some(id), Some(client_id), Some(scopes)) => RefreshCheck::Valid {
                id,
                client_id,
                scopes,
            },
            ("grace", ..) => RefreshCheck::Grace,
            ("reuse", ..) => RefreshCheck::Reuse,
            _ => RefreshCheck::Invalid,
        })
    }

    /// Rotate ATOMICALLY (migration 118, `epigraph_refresh_token_rotate`):
    /// claim the presented token with one `UPDATE ... WHERE revoked_at IS NULL
    /// AND expires_at > now()` and insert its successor in the same family, for
    /// the same client. Of any number of concurrent calls presenting one token,
    /// exactly one gets [`RefreshRotateOutcome::Rotated`]; the others find it
    /// spent by a rotation inside the grace window and get
    /// [`RefreshRotateOutcome::Grace`], and the winner's successor stays live.
    ///
    /// The successor's scopes are the presented token's scopes narrowed to the
    /// client's current `granted_scopes`, in the presented token's order
    /// (migration 140; 118 gave it the whole grant, which widened a narrowed
    /// consent at its first refresh). Its expiry is `expires_at` capped at the
    /// client type's refresh TTL. Both are decided inside the definer: a
    /// caller can shorten a chain, never widen or lengthen it.
    #[instrument(skip(pool, old_hash, new_hash))]
    pub async fn rotate(
        pool: &PgPool,
        old_hash: &[u8],
        new_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<RefreshRotateOutcome, DbError> {
        let (outcome, id): (String, Option<Uuid>) = sqlx::query_as(
            "SELECT outcome, token_id FROM public.epigraph_refresh_token_rotate($1, $2, $3)",
        )
        .bind(old_hash)
        .bind(new_hash)
        .bind(expires_at)
        .fetch_one(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(match (outcome.as_str(), id) {
            ("rotated", Some(id)) => RefreshRotateOutcome::Rotated { id },
            ("grace", _) => RefreshRotateOutcome::Grace,
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

    /// RFC 7009 revocation by the presented token (`/oauth/revoke`), through
    /// migration 118's definer: the application role cannot read `token_hash`,
    /// so the lookup by hash happens inside it. Returns whether a live row was
    /// revoked; an unknown or already revoked token is `false`, not an error.
    #[instrument(skip(pool, token_hash))]
    pub async fn revoke_by_hash(pool: &PgPool, token_hash: &[u8]) -> Result<bool, DbError> {
        sqlx::query_scalar("SELECT public.epigraph_refresh_token_revoke_by_hash($1)")
            .bind(token_hash)
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
