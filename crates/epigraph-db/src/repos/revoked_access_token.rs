//! Durable RFC 7009 revocation of JWT access tokens, keyed by `jti`.
//!
//! STUB: neither method touches the database yet. `revoke` persists nothing
//! and `is_revoked` answers `false`, the behaviour of origin/main (where a
//! revocation lived only in one API process's memory). The tests that pin the
//! durable behaviour are written against this stub first, so they fail on
//! their assertions rather than on a missing symbol.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::DbError;

pub struct RevokedAccessTokenRepository;

impl RevokedAccessTokenRepository {
    /// Record that the access token `jti` (issued to `client_id`, expiring at
    /// `expires_at`) is revoked. Returns whether a new row was written.
    pub async fn revoke(
        _pool: &PgPool,
        _jti: Uuid,
        _client_id: Uuid,
        _expires_at: DateTime<Utc>,
    ) -> Result<bool, DbError> {
        Ok(false)
    }

    /// Whether the access token `jti` has been revoked.
    pub async fn is_revoked(_pool: &PgPool, _jti: Uuid) -> Result<bool, DbError> {
        Ok(false)
    }
}
