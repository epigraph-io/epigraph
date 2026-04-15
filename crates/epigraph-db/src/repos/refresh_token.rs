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

    #[instrument(skip(pool))]
    pub async fn revoke(pool: &PgPool, id: Uuid) -> Result<(), DbError> {
        sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(())
    }

    #[instrument(skip(pool))]
    pub async fn revoke_all_for_client(pool: &PgPool, client_id: Uuid) -> Result<u64, DbError> {
        let result = sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = now() WHERE client_id = $1 AND revoked_at IS NULL",
        )
        .bind(client_id)
        .execute(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(result.rows_affected())
    }

    #[instrument(skip(pool))]
    pub async fn cleanup_expired(pool: &PgPool) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < now()")
            .execute(pool)
            .await
            .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(result.rows_affected())
    }
}
