//! Append-only provenance log repository.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

use serde_json::Value;

#[derive(Debug, Clone, FromRow)]
pub struct ProvenanceLogRow {
    pub id: Uuid,
    pub record_type: String,
    pub record_id: Uuid,
    pub action: String,
    pub submitted_by: Uuid,
    pub principal_id: Uuid,
    pub authorization_chain: Vec<Uuid>,
    pub authorization_type: String,
    pub content_hash: Vec<u8>,
    pub provenance_sig: Vec<u8>,
    pub token_jti: Uuid,
    pub scopes_used: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// Auto-policy authorizer UUID (seeded in migration 062).
pub const AUTO_POLICY_AUTHORIZER_ID: Uuid =
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

pub struct ProvenanceRepository;

impl ProvenanceRepository {
    /// Append a provenance log entry. This is the ONLY write operation —
    /// the table is append-only (UPDATE/DELETE blocked by trigger).
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool, content_hash, provenance_sig))]
    pub async fn append(
        pool: &PgPool,
        record_type: &str,
        record_id: Uuid,
        action: &str,
        submitted_by: Uuid,
        principal_id: Uuid,
        authorization_chain: &[Uuid],
        authorization_type: &str,
        content_hash: &[u8],
        provenance_sig: &[u8],
        token_jti: Uuid,
        scopes_used: &[String],
        patch_payload: Option<&Value>,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"INSERT INTO provenance_log
                (record_type, record_id, action, submitted_by, principal_id,
                 authorization_chain, authorization_type, content_hash,
                 provenance_sig, token_jti, scopes_used, patch_payload)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id"#,
        )
        .bind(record_type)
        .bind(record_id)
        .bind(action)
        .bind(submitted_by)
        .bind(principal_id)
        .bind(authorization_chain)
        .bind(authorization_type)
        .bind(content_hash)
        .bind(provenance_sig)
        .bind(token_jti)
        .bind(scopes_used)
        .bind(patch_payload)
        .fetch_one(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row.0)
    }

    /// Append a provenance log entry within a caller-managed transaction.
    /// Identical to `append()` but accepts `&mut sqlx::PgConnection` so the
    /// insert can participate in the caller's transaction.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(conn, content_hash, provenance_sig))]
    pub async fn append_conn(
        conn: &mut sqlx::PgConnection,
        record_type: &str,
        record_id: Uuid,
        action: &str,
        submitted_by: Uuid,
        principal_id: Uuid,
        authorization_chain: &[Uuid],
        authorization_type: &str,
        content_hash: &[u8],
        provenance_sig: &[u8],
        token_jti: Uuid,
        scopes_used: &[String],
        patch_payload: Option<&Value>,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"INSERT INTO provenance_log
                (record_type, record_id, action, submitted_by, principal_id,
                 authorization_chain, authorization_type, content_hash,
                 provenance_sig, token_jti, scopes_used, patch_payload)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id"#,
        )
        .bind(record_type)
        .bind(record_id)
        .bind(action)
        .bind(submitted_by)
        .bind(principal_id)
        .bind(authorization_chain)
        .bind(authorization_type)
        .bind(content_hash)
        .bind(provenance_sig)
        .bind(token_jti)
        .bind(scopes_used)
        .bind(patch_payload)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row.0)
    }

    /// Get provenance history for a record.
    #[instrument(skip(pool))]
    pub async fn get_history(
        pool: &PgPool,
        record_type: &str,
        record_id: Uuid,
    ) -> Result<Vec<ProvenanceLogRow>, DbError> {
        let rows = sqlx::query_as::<_, ProvenanceLogRow>(
            r#"SELECT * FROM provenance_log
            WHERE record_type = $1 AND record_id = $2
            ORDER BY created_at ASC"#,
        )
        .bind(record_type)
        .bind(record_id)
        .fetch_all(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(rows)
    }
}
