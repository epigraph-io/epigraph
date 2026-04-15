//! Community repository
//!
//! CRUD operations for communities (groups of perspectives with shared epistemic standards)
//! and community membership management.

use crate::errors::DbError;
use crate::repos::perspective::PerspectiveRow;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the communities table
#[derive(Debug, Clone, FromRow)]
pub struct CommunityRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub governance_type: Option<String>,
    pub ownership_type: Option<String>,
    pub mass_override: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// A row from the community_members junction table
#[derive(Debug, Clone, FromRow)]
pub struct CommunityMemberRow {
    pub community_id: Uuid,
    pub perspective_id: Uuid,
    pub joined_at: DateTime<Utc>,
}

/// Repository for Community operations
pub struct CommunityRepository;

impl CommunityRepository {
    /// Create a new community
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn create(
        pool: &PgPool,
        name: &str,
        description: Option<&str>,
        governance_type: Option<&str>,
        ownership_type: Option<&str>,
    ) -> Result<CommunityRow, DbError> {
        let row: CommunityRow = sqlx::query_as(
            r#"
            INSERT INTO communities (name, description, governance_type, ownership_type)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, description, governance_type, ownership_type, mass_override, created_at
            "#,
        )
        .bind(name)
        .bind(description)
        .bind(governance_type)
        .bind(ownership_type)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// Get a community by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<CommunityRow>, DbError> {
        let row: Option<CommunityRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, governance_type, ownership_type, mass_override, created_at
            FROM communities
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// List all communities with pagination
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list(
        pool: &PgPool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CommunityRow>, DbError> {
        let rows: Vec<CommunityRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, governance_type, ownership_type, mass_override, created_at
            FROM communities
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Add a perspective as a community member
    ///
    /// Uses ON CONFLICT to be idempotent.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn add_member(
        pool: &PgPool,
        community_id: Uuid,
        perspective_id: Uuid,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO community_members (community_id, perspective_id)
            VALUES ($1, $2)
            ON CONFLICT (community_id, perspective_id) DO NOTHING
            "#,
        )
        .bind(community_id)
        .bind(perspective_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Remove a perspective from a community
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn remove_member(
        pool: &PgPool,
        community_id: Uuid,
        perspective_id: Uuid,
    ) -> Result<bool, DbError> {
        let result = sqlx::query(
            r#"
            DELETE FROM community_members
            WHERE community_id = $1 AND perspective_id = $2
            "#,
        )
        .bind(community_id)
        .bind(perspective_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get all member perspectives for a community
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_members(
        pool: &PgPool,
        community_id: Uuid,
    ) -> Result<Vec<PerspectiveRow>, DbError> {
        let rows: Vec<PerspectiveRow> = sqlx::query_as(
            r#"
            SELECT p.id, p.name, p.description, p.owner_agent_id, p.perspective_type,
                   p.frame_ids, p.extraction_method, p.confidence_calibration, p.created_at
            FROM perspectives p
            JOIN community_members cm ON cm.perspective_id = p.id
            WHERE cm.community_id = $1
            ORDER BY cm.joined_at ASC
            "#,
        )
        .bind(community_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Get all community IDs that a perspective belongs to
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn communities_for_perspective(
        pool: &PgPool,
        perspective_id: Uuid,
    ) -> Result<Vec<Uuid>, DbError> {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT community_id FROM community_members
            WHERE perspective_id = $1
            "#,
        )
        .bind(perspective_id)
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Get all member perspective IDs for a community
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn member_perspective_ids(
        pool: &PgPool,
        community_id: Uuid,
    ) -> Result<Vec<Uuid>, DbError> {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT perspective_id FROM community_members
            WHERE community_id = $1
            "#,
        )
        .bind(community_id)
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn community_row_has_expected_fields() {
        let _row = CommunityRow {
            id: Uuid::new_v4(),
            name: "epistemic_community".to_string(),
            description: Some("A test community".to_string()),
            governance_type: Some("open".to_string()),
            ownership_type: Some("public".to_string()),
            mass_override: None,
            created_at: Utc::now(),
        };
    }

    #[test]
    fn community_row_allows_none_optionals() {
        let _row = CommunityRow {
            id: Uuid::new_v4(),
            name: "minimal".to_string(),
            description: None,
            governance_type: None,
            ownership_type: None,
            mass_override: None,
            created_at: Utc::now(),
        };
    }

    #[test]
    fn community_row_with_mass_override() {
        let _row = CommunityRow {
            id: Uuid::new_v4(),
            name: "overriding_community".to_string(),
            description: Some("Community with mass override".to_string()),
            governance_type: Some("delegated".to_string()),
            ownership_type: Some("community".to_string()),
            mass_override: Some(serde_json::json!({
                "frame_id_placeholder": {"0,1": 0.8, "": 0.2}
            })),
            created_at: Utc::now(),
        };
    }

    #[test]
    fn community_member_row_has_expected_fields() {
        let _row = CommunityMemberRow {
            community_id: Uuid::new_v4(),
            perspective_id: Uuid::new_v4(),
            joined_at: Utc::now(),
        };
    }
}
