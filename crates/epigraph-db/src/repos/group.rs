//! Repository for the `groups` table

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the `groups` table
#[derive(Debug, Clone, FromRow)]
pub struct GroupRow {
    pub id: Uuid,
    pub display_name: Option<String>,
    pub did_key: String,
    pub public_key: Vec<u8>,
    pub pre_public_key: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Repository for Group operations
pub struct GroupRepository;

impl GroupRepository {
    /// Create a new group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, public_key, pre_public_key))]
    pub async fn create(
        pool: &PgPool,
        id: Uuid,
        display_name: Option<&str>,
        did_key: &str,
        public_key: &[u8],
        pre_public_key: Option<&[u8]>,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO groups (id, display_name, did_key, public_key, pre_public_key)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(id)
        .bind(display_name)
        .bind(did_key)
        .bind(public_key)
        .bind(pre_public_key)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Get a group by its UUID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<GroupRow>, DbError> {
        let row: Option<GroupRow> = sqlx::query_as(
            r#"
            SELECT id, display_name, did_key, public_key, pre_public_key, created_at, updated_at
            FROM groups
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Get a group by its DID key
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_did_key(pool: &PgPool, did_key: &str) -> Result<Option<GroupRow>, DbError> {
        let row: Option<GroupRow> = sqlx::query_as(
            r#"
            SELECT id, display_name, did_key, public_key, pre_public_key, created_at, updated_at
            FROM groups
            WHERE did_key = $1
            "#,
        )
        .bind(did_key)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// List all groups
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_all(pool: &PgPool) -> Result<Vec<GroupRow>, DbError> {
        let rows: Vec<GroupRow> = sqlx::query_as(
            r#"
            SELECT id, display_name, did_key, public_key, pre_public_key, created_at, updated_at
            FROM groups
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }
}
