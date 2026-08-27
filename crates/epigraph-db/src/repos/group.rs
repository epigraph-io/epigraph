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
    /// Create a `kind='team'` group, its epoch-0 row, and the creator's own
    /// `role='admin'` membership — all in ONE transaction.
    ///
    /// This replaces the former `create` + `GroupKeyEpochRepository::create_epoch`
    /// pair, which wrote a group nobody was a member of. That is what made the
    /// documented happy path impossible: `require_group_admin` consults
    /// `group_memberships`, so the creator's first `add_member` on their own
    /// brand-new group always 403'd.
    ///
    /// **The creator's `wrapped_key_share` is empty by construction.** There is
    /// nothing to wrap: the creator generated the group base key client-side in
    /// the `--init-group` ceremony and already holds it. Every LATER member
    /// added through `POST /api/v1/groups/:id/members` carries a real 60-byte
    /// wrapped share (12-byte nonce + 32-byte key + 16-byte GCM tag), which
    /// that route now enforces. The two rows are deliberately different shapes;
    /// do not "fix" one to match the other.
    ///
    /// No `wrapped_key` is stored on the epoch row either — the server never
    /// holds group key material.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any statement fails; the transaction
    /// is rolled back, so a duplicate `did_key` leaves no partial group behind.
    #[instrument(skip(pool, public_key, pre_public_key))]
    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_admin(
        pool: &PgPool,
        id: Uuid,
        display_name: Option<&str>,
        did_key: &str,
        public_key: &[u8],
        pre_public_key: Option<&[u8]>,
        creator_agent_id: Uuid,
    ) -> Result<Uuid, DbError> {
        let mut tx = pool.begin().await?;

        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO groups
                (id, display_name, did_key, public_key, pre_public_key, kind, created_by_agent_id)
            VALUES ($1, $2, $3, $4, $5, 'team', $6)
            RETURNING id
            "#,
        )
        .bind(id)
        .bind(display_name)
        .bind(did_key)
        .bind(public_key)
        .bind(pre_public_key)
        .bind(creator_agent_id)
        .fetch_one(&mut *tx)
        .await?;

        // Via the repo helper, not an inlined INSERT: the inlined copy left
        // `GroupKeyEpochRepository::create_epoch` with zero callers and the two
        // statements free to drift (migration 060's ROTATION CONTRACT names
        // that pair).
        crate::repos::group_key_epoch::GroupKeyEpochRepository::create_epoch_conn(
            &mut tx, row.0, 0, None, "active",
        )
        .await?;

        sqlx::query(
            r#"
            INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role)
            VALUES ($1, $2, ''::bytea, 0, 'admin')
            "#,
        )
        .bind(row.0)
        .bind(creator_agent_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

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
