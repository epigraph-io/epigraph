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
    /// DEPRECATED. Held a stringified community UUID until migration 068
    /// drained it into `community_id`. Nothing writes it any more; it is still
    /// SELECTed so the quarantine/report path can see a legacy value, and is
    /// dropped with the table in migration 084.
    pub encryption_key_id: Option<String>,
    /// The gating community for `partition_type = 'community'` (migration 068).
    /// `NULL` for every other partition, and for a community row whose legacy
    /// `encryption_key_id` did not resolve to a live `communities.id`.
    pub community_id: Option<Uuid>,
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
    /// For `community` partitions, pass `community_id` to record the gating
    /// community in `ownership.community_id`. The access control layer reads
    /// that column to check community membership.
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
    /// `community_id` is written to the typed `ownership.community_id` column
    /// (migration 068). `encryption_key_id` — which held a stringified copy of
    /// this UUID before 068 — is bound explicitly to `NULL` on BOTH the insert
    /// and the conflict arm. Omitting it on the conflict arm would strand a
    /// stale string while `community_id` went `NULL`, which would populate
    /// `ownership_key_id_quarantine` and block migration 084's pre-flight.
    ///
    /// A `community_id` on a NON-community partition is refused here with
    /// [`DbError::InvalidData`] (a 400, not the database's 23514 as a 500). The
    /// database enforces the same rule structurally via
    /// `ownership_community_needs_community_partition` (migration 068); this
    /// arm exists so the caller gets a reason instead of a constraint name.
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
        if community_id.is_some() && partition_type != "community" {
            return Err(DbError::InvalidData {
                reason: format!(
                    "community_id may only be set on partition_type 'community', not '{partition_type}'. \
                     A gate on a non-community row gates nothing today and is silently \
                     inherited by a later promotion to 'community'."
                ),
            });
        }

        let row: OwnershipRow = sqlx::query_as(
            r#"
            INSERT INTO ownership (node_id, node_type, partition_type, owner_id,
                                   community_id, encryption_key_id)
            VALUES ($1, $2, $3, $4, $5, NULL)
            ON CONFLICT (node_id) DO UPDATE
                SET partition_type = EXCLUDED.partition_type,
                    owner_id = EXCLUDED.owner_id,
                    node_type = EXCLUDED.node_type,
                    community_id = EXCLUDED.community_id,
                    encryption_key_id = NULL
            RETURNING node_id, node_type, partition_type, owner_id,
                      encryption_key_id, community_id, created_at, updated_at
            "#,
        )
        .bind(node_id)
        .bind(node_type)
        .bind(partition_type)
        .bind(owner_id)
        .bind(community_id)
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
                   encryption_key_id, community_id, created_at, updated_at
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
                   encryption_key_id, community_id, created_at, updated_at
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
            SET partition_type = $2,
                -- Demoting a node OUT of the community partition must not leave
                -- a dangling gate behind: a later re-promotion would silently
                -- reuse a community the caller never named.
                community_id = CASE WHEN $2 = 'community' THEN community_id ELSE NULL END,
                -- And the DEPRECATED string must go with it, for the same
                -- reason `assign_with_community` binds it to NULL on both arms.
                -- Two failures if it does not:
                --   (a) a drained legacy row demoted to 'private' keeps its
                --       string while community_id goes NULL, which is exactly
                --       the `ownership_key_id_quarantine` predicate — the row
                --       becomes indistinguishable from a genuinely unresolvable
                --       value and blocks migration 084's pre-flight forever;
                --   (b) `ownership_key_id_is_uuid` is NOT VALID, which skips
                --       the initial back-scan but NOT rows a statement UPDATEs,
                --       and Postgres re-checks the whole new row version even
                --       when the constrained column is untouched. On a database
                --       holding a pre-068 non-UUID value (`'key-2026-001'`),
                --       this UPDATE would raise 23514 and the endpoint would
                --       500. Writing NULL satisfies the CHECK unconditionally.
                encryption_key_id = NULL
            WHERE node_id = $1
            RETURNING node_id, node_type, partition_type, owner_id,
                      encryption_key_id, community_id, created_at, updated_at
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
            community_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
    }

    /// A struct literal ONLY — never a DB write. Migration 068's
    /// `ownership_key_id_is_uuid` CHECK would reject `"key-2026-001"` at the
    /// database, which is the point: the row shape must still be able to
    /// REPRESENT a legacy value so `ownership_key_id_quarantine` has something
    /// to report, even though nothing writes one any more.
    #[test]
    fn ownership_row_can_still_represent_a_legacy_key_id() {
        let _row = OwnershipRow {
            node_id: Uuid::new_v4(),
            node_type: "evidence".to_string(),
            partition_type: "private".to_string(),
            owner_id: Uuid::new_v4(),
            encryption_key_id: Some("key-2026-001".to_string()),
            community_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
    }

    /// A community-partitioned row carries its gate in the TYPED column.
    #[test]
    fn ownership_row_carries_a_typed_community_id() {
        let community = Uuid::new_v4();
        let row = OwnershipRow {
            node_id: Uuid::new_v4(),
            node_type: "claim".to_string(),
            partition_type: "community".to_string(),
            owner_id: Uuid::new_v4(),
            encryption_key_id: None,
            community_id: Some(community),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(row.community_id, Some(community));
        assert!(row.encryption_key_id.is_none());
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
