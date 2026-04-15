//! OAuth2 client CRUD repository.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

#[derive(Debug, Clone, FromRow)]
pub struct OAuthClientRow {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<Vec<u8>>,
    pub client_name: String,
    pub client_type: String,
    pub redirect_uris: Option<Vec<String>>,
    pub allowed_scopes: Vec<String>,
    pub granted_scopes: Vec<String>,
    pub status: String,
    pub agent_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub legal_entity_name: Option<String>,
    pub legal_entity_id: Option<String>,
    pub legal_contact_email: Option<String>,
    pub legal_accepted_tos_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct OAuthClientRepository;

impl OAuthClientRepository {
    #[instrument(skip(pool))]
    pub async fn get_by_client_id(
        pool: &PgPool,
        client_id: &str,
    ) -> Result<Option<OAuthClientRow>, DbError> {
        let row = sqlx::query_as::<_, OAuthClientRow>(
            "SELECT * FROM oauth_clients WHERE client_id = $1 AND status = 'active'",
        )
        .bind(client_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row)
    }

    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<OAuthClientRow>, DbError> {
        let row = sqlx::query_as::<_, OAuthClientRow>("SELECT * FROM oauth_clients WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row)
    }

    #[instrument(skip(pool, client_secret_hash))]
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        pool: &PgPool,
        client_id: &str,
        client_secret_hash: Option<&[u8]>,
        client_name: &str,
        client_type: &str,
        allowed_scopes: &[String],
        granted_scopes: &[String],
        status: &str,
        agent_id: Option<Uuid>,
        owner_id: Option<Uuid>,
        legal_entity_name: Option<&str>,
        legal_contact_email: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"INSERT INTO oauth_clients
                (client_id, client_secret_hash, client_name, client_type,
                 allowed_scopes, granted_scopes, status, agent_id, owner_id,
                 legal_entity_name, legal_contact_email)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id"#,
        )
        .bind(client_id)
        .bind(client_secret_hash)
        .bind(client_name)
        .bind(client_type)
        .bind(allowed_scopes)
        .bind(granted_scopes)
        .bind(status)
        .bind(agent_id)
        .bind(owner_id)
        .bind(legal_entity_name)
        .bind(legal_contact_email)
        .fetch_one(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row.0)
    }

    #[instrument(skip(pool))]
    pub async fn update_status(pool: &PgPool, id: Uuid, status: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE oauth_clients SET status = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(status)
            .execute(pool)
            .await
            .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(())
    }

    #[instrument(skip(pool))]
    pub async fn approve(
        pool: &PgPool,
        id: Uuid,
        granted_scopes: &[String],
        approved_by: Uuid,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"UPDATE oauth_clients SET granted_scopes = $2, status = 'active', created_by = $3, updated_at = now() WHERE id = $1"#,
        )
        .bind(id)
        .bind(granted_scopes)
        .bind(approved_by)
        .execute(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(())
    }

    #[instrument(skip(pool))]
    pub async fn get_by_owner(
        pool: &PgPool,
        owner_id: Uuid,
    ) -> Result<Vec<OAuthClientRow>, DbError> {
        let rows =
            sqlx::query_as::<_, OAuthClientRow>("SELECT * FROM oauth_clients WHERE owner_id = $1")
                .bind(owner_id)
                .fetch_all(pool)
                .await
                .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(rows)
    }

    #[instrument(skip(pool))]
    pub async fn suspend_by_owner(pool: &PgPool, owner_id: Uuid) -> Result<u64, DbError> {
        let result = sqlx::query(
            "UPDATE oauth_clients SET status = 'suspended', updated_at = now() WHERE owner_id = $1 AND status = 'active'",
        )
        .bind(owner_id)
        .execute(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(result.rows_affected())
    }
}
