//! Repository for the `group_memberships` table

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the `group_memberships` table
#[derive(Debug, Clone, FromRow)]
pub struct MembershipRow {
    pub id: Uuid,
    pub group_id: Uuid,
    pub agent_id: Uuid,
    pub wrapped_key_share: Vec<u8>,
    pub epoch: i32,
    pub role: String,
    pub joined_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Repository for GroupMembership operations
pub struct GroupMembershipRepository;

impl GroupMembershipRepository {
    /// Add an agent to a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, wrapped_key_share))]
    pub async fn add_member(
        pool: &PgPool,
        group_id: Uuid,
        agent_id: Uuid,
        wrapped_key_share: &[u8],
        epoch: i32,
        role: &str,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(group_id)
        .bind(agent_id)
        .bind(wrapped_key_share)
        .bind(epoch)
        .bind(role)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Revoke a member's access by setting `revoked_at`
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn remove_member(
        pool: &PgPool,
        group_id: Uuid,
        agent_id: Uuid,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            UPDATE group_memberships
            SET revoked_at = now()
            WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL
            "#,
        )
        .bind(group_id)
        .bind(agent_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get active (non-revoked) members of a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_members(pool: &PgPool, group_id: Uuid) -> Result<Vec<MembershipRow>, DbError> {
        let rows: Vec<MembershipRow> = sqlx::query_as(
            r#"
            SELECT id, group_id, agent_id, wrapped_key_share, epoch, role, joined_at, revoked_at
            FROM group_memberships
            WHERE group_id = $1 AND revoked_at IS NULL
            ORDER BY joined_at ASC
            "#,
        )
        .bind(group_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Check whether an agent is an active member of a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn is_member(pool: &PgPool, group_id: Uuid, agent_id: Uuid) -> Result<bool, DbError> {
        let row: (bool,) = sqlx::query_as(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM group_memberships
                WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL
            )
            "#,
        )
        .bind(group_id)
        .bind(agent_id)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Get the role of an active member within a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_member_role(
        pool: &PgPool,
        group_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Option<String>, DbError> {
        let row: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT role FROM group_memberships
            WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL
            LIMIT 1
            "#,
        )
        .bind(group_id)
        .bind(agent_id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| r.0))
    }
}
