//! Ownership repository
//!
//! CRUD operations for node ownership / partition assignment (§3 Ownership & Privacy).
//! Each node can be assigned to a partition: public, community, or private.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the ownership table
#[derive(Debug, Clone, FromRow)]
pub struct OwnershipRow {
    pub node_id: Uuid,
    pub node_type: String,
    pub partition_type: String,
    pub owner_id: Uuid,
    pub encryption_key_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Valid partition types for ownership
const VALID_PARTITIONS: &[&str] = &["public", "community", "private"];

/// Valid node types for ownership
const VALID_NODE_TYPES: &[&str] = &[
    "claim",
    "agent",
    "evidence",
    "perspective",
    "community",
    "context",
    "frame",
];

/// Repository for Ownership operations
pub struct OwnershipRepository;

impl OwnershipRepository {
    /// Assign ownership of a node to an agent with a partition type
    ///
    /// Uses ON CONFLICT to update if ownership already exists.
    ///
    /// # Errors
    /// Returns `DbError::InvalidData` if partition_type or node_type is invalid.
    /// Returns `DbError::QueryFailed` if the database query fails.
    /// Assign ownership of a node to an agent with a partition type.
    ///
    /// For `community` partitions, pass `community_id` to store the gating community
    /// UUID in `encryption_key_id`. The access control layer reads this to check
    /// community membership.
    ///
    /// # Errors
    /// Returns `DbError::InvalidData` if partition_type or node_type is invalid.
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn assign(
        pool: &PgPool,
        node_id: Uuid,
        node_type: &str,
        partition_type: &str,
        owner_id: Uuid,
    ) -> Result<OwnershipRow, DbError> {
        Self::assign_with_community(pool, node_id, node_type, partition_type, owner_id, None).await
    }

    /// Assign ownership with an optional community_id for community-partitioned nodes.
    ///
    /// The `community_id` is stored in `encryption_key_id` so the access control
    /// layer can look up community membership without changing the DB schema.
    #[instrument(skip(pool))]
    pub async fn assign_with_community(
        pool: &PgPool,
        node_id: Uuid,
        node_type: &str,
        partition_type: &str,
        owner_id: Uuid,
        community_id: Option<Uuid>,
    ) -> Result<OwnershipRow, DbError> {
        if !VALID_PARTITIONS.contains(&partition_type) {
            return Err(DbError::InvalidData {
                reason: format!(
                    "Invalid partition_type '{}'. Must be one of: {}",
                    partition_type,
                    VALID_PARTITIONS.join(", ")
                ),
            });
        }
        if !VALID_NODE_TYPES.contains(&node_type) {
            return Err(DbError::InvalidData {
                reason: format!(
                    "Invalid node_type '{}'. Must be one of: {}",
                    node_type,
                    VALID_NODE_TYPES.join(", ")
                ),
            });
        }

        let encryption_key_id = community_id.map(|id| id.to_string());

        let row: OwnershipRow = sqlx::query_as(
            r#"
            INSERT INTO ownership (node_id, node_type, partition_type, owner_id, encryption_key_id)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (node_id) DO UPDATE
                SET partition_type = EXCLUDED.partition_type,
                    owner_id = EXCLUDED.owner_id,
                    node_type = EXCLUDED.node_type,
                    encryption_key_id = EXCLUDED.encryption_key_id
            RETURNING node_id, node_type, partition_type, owner_id,
                      encryption_key_id, created_at, updated_at
            "#,
        )
        .bind(node_id)
        .bind(node_type)
        .bind(partition_type)
        .bind(owner_id)
        .bind(encryption_key_id)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// Get ownership info for a node
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get(pool: &PgPool, node_id: Uuid) -> Result<Option<OwnershipRow>, DbError> {
        let row: Option<OwnershipRow> = sqlx::query_as(
            r#"
            SELECT node_id, node_type, partition_type, owner_id,
                   encryption_key_id, created_at, updated_at
            FROM ownership
            WHERE node_id = $1
            "#,
        )
        .bind(node_id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Get all nodes owned by an agent, with optional node_type filter
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_for_owner(
        pool: &PgPool,
        owner_id: Uuid,
        node_type_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<OwnershipRow>, DbError> {
        let rows: Vec<OwnershipRow> = sqlx::query_as(
            r#"
            SELECT node_id, node_type, partition_type, owner_id,
                   encryption_key_id, created_at, updated_at
            FROM ownership
            WHERE owner_id = $1
              AND ($2::text IS NULL OR node_type = $2)
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(owner_id)
        .bind(node_type_filter)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Update the partition type of a node
    ///
    /// # Errors
    /// Returns `DbError::InvalidData` if partition_type is invalid.
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn update_partition(
        pool: &PgPool,
        node_id: Uuid,
        partition_type: &str,
    ) -> Result<Option<OwnershipRow>, DbError> {
        if !VALID_PARTITIONS.contains(&partition_type) {
            return Err(DbError::InvalidData {
                reason: format!(
                    "Invalid partition_type '{}'. Must be one of: {}",
                    partition_type,
                    VALID_PARTITIONS.join(", ")
                ),
            });
        }

        let row: Option<OwnershipRow> = sqlx::query_as(
            r#"
            UPDATE ownership
            SET partition_type = $2
            WHERE node_id = $1
            RETURNING node_id, node_type, partition_type, owner_id,
                      encryption_key_id, created_at, updated_at
            "#,
        )
        .bind(node_id)
        .bind(partition_type)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Count nodes by partition type for a given owner
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn count_by_partition(
        pool: &PgPool,
        owner_id: Uuid,
    ) -> Result<Vec<(String, i64)>, DbError> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT partition_type, COUNT(*) as count
            FROM ownership
            WHERE owner_id = $1
            GROUP BY partition_type
            "#,
        )
        .bind(owner_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_row_has_expected_fields() {
        let _row = OwnershipRow {
            node_id: Uuid::new_v4(),
            node_type: "claim".to_string(),
            partition_type: "public".to_string(),
            owner_id: Uuid::new_v4(),
            encryption_key_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
    }

    #[test]
    fn ownership_row_with_encryption_key() {
        let _row = OwnershipRow {
            node_id: Uuid::new_v4(),
            node_type: "evidence".to_string(),
            partition_type: "private".to_string(),
            owner_id: Uuid::new_v4(),
            encryption_key_id: Some("key-2026-001".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
    }

    #[test]
    fn valid_partitions_list() {
        assert!(VALID_PARTITIONS.contains(&"public"));
        assert!(VALID_PARTITIONS.contains(&"community"));
        assert!(VALID_PARTITIONS.contains(&"private"));
        assert!(!VALID_PARTITIONS.contains(&"secret"));
    }

    #[test]
    fn valid_node_types_list() {
        assert!(VALID_NODE_TYPES.contains(&"claim"));
        assert!(VALID_NODE_TYPES.contains(&"agent"));
        assert!(VALID_NODE_TYPES.contains(&"evidence"));
        assert!(VALID_NODE_TYPES.contains(&"frame"));
        assert!(!VALID_NODE_TYPES.contains(&"unknown"));
    }
}
