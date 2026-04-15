//! Semantic link repository for database operations
//!
//! This repository provides CRUD operations for `SemanticLink` entities,
//! which represent semantic relationships between claims in the knowledge graph.
//!
//! # Design Notes
//!
//! This repository uses the generic `edges` table from the LPG schema, storing:
//! - `source_claim_id` -> `source_id` (with `source_type = 'claim'`)
//! - `target_claim_id` -> `target_id` (with `target_type = 'claim'`)
//! - `link_type` -> `relationship` field
//! - `strength` -> `properties.strength` JSONB field
//! - `created_by` -> `properties.created_by` JSONB field
//! - `created_at` -> `properties.created_at` JSONB field (for precise timestamp)

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use epigraph_core::{
    AgentId, ClaimId, LinkStrength, SemanticLink, SemanticLinkId, SemanticLinkType,
};
use sqlx::{FromRow, PgPool, Row};
use tracing::instrument;
use uuid::Uuid;

/// Repository for SemanticLink operations
pub struct SemanticLinkRepository;

/// Database row representation for edges table
#[derive(Debug, FromRow)]
struct EdgeRow {
    id: Uuid,
    source_id: Uuid,
    target_id: Uuid,
    relationship: String,
    properties: serde_json::Value,
}

/// Convert `SemanticLinkType` to database string representation
fn link_type_to_str(link_type: SemanticLinkType) -> &'static str {
    match link_type {
        SemanticLinkType::Supports => "supports",
        SemanticLinkType::Contradicts => "contradicts",
        SemanticLinkType::DerivesFrom => "derives_from",
        SemanticLinkType::Refines => "refines",
        SemanticLinkType::Analogous => "analogous",
    }
}

/// Convert database string to `SemanticLinkType`
fn str_to_link_type(s: &str) -> Result<SemanticLinkType, DbError> {
    match s {
        "supports" => Ok(SemanticLinkType::Supports),
        "contradicts" => Ok(SemanticLinkType::Contradicts),
        "derives_from" => Ok(SemanticLinkType::DerivesFrom),
        "refines" => Ok(SemanticLinkType::Refines),
        "analogous" => Ok(SemanticLinkType::Analogous),
        other => Err(DbError::InvalidData {
            reason: format!("Unknown semantic link type: {other}"),
        }),
    }
}

/// Build a `SemanticLink` from database row data.
///
/// This helper function reconstructs the domain object from the edges table row.
/// The `created_at` timestamp is stored in the properties JSONB since the edges
/// table query results don't include it in the standard column set.
///
/// # Errors
/// Returns `DbError::InvalidData` if the row data cannot be converted to valid domain types.
fn semantic_link_from_row(row: EdgeRow) -> Result<SemanticLink, DbError> {
    let link_type = str_to_link_type(&row.relationship)?;

    // Extract strength from properties, default to 0.5 if not present
    let strength_value = row
        .properties
        .get("strength")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.5);
    let strength = LinkStrength::clamped(strength_value);

    // Extract created_by from properties
    let created_by_str = row
        .properties
        .get("created_by")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DbError::InvalidData {
            reason: "Semantic link missing created_by in properties".to_string(),
        })?;
    let created_by_uuid = Uuid::parse_str(created_by_str).map_err(|_| DbError::InvalidData {
        reason: format!("Invalid created_by UUID: {created_by_str}"),
    })?;

    // Extract created_at from properties, fallback to current time if not present
    let created_at: DateTime<Utc> = row
        .properties
        .get("created_at")
        .and_then(|v| v.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    SemanticLink::with_id(
        SemanticLinkId::from_uuid(row.id),
        ClaimId::from_uuid(row.source_id),
        ClaimId::from_uuid(row.target_id),
        link_type,
        strength,
        created_at,
        AgentId::from_uuid(created_by_uuid),
    )
    .map_err(|e| DbError::CoreError { source: e })
}

impl SemanticLinkRepository {
    /// Create a new semantic link in the database
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, link))]
    pub async fn create(pool: &PgPool, link: &SemanticLink) -> Result<SemanticLink, DbError> {
        let source_id: Uuid = link.source_claim_id.into();
        let target_id: Uuid = link.target_claim_id.into();
        let relationship = link_type_to_str(link.link_type);
        let created_by: Uuid = link.created_by.into();

        // Store strength, created_by, and created_at in properties JSONB
        let properties = serde_json::json!({
            "strength": link.strength.value(),
            "created_by": created_by.to_string(),
            "created_at": link.created_at.to_rfc3339()
        });

        // Use the existing cached INSERT query pattern
        let row = sqlx::query!(
            r#"
            INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
            source_id,
            "claim",
            target_id,
            "claim",
            relationship,
            properties
        )
        .fetch_one(pool)
        .await?;

        // Return the link with the DB-generated ID
        SemanticLink::with_id(
            SemanticLinkId::from_uuid(row.id),
            link.source_claim_id,
            link.target_claim_id,
            link.link_type,
            link.strength,
            link.created_at,
            link.created_by,
        )
        .map_err(|e| DbError::CoreError { source: e })
    }

    /// Get a semantic link by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(
        pool: &PgPool,
        id: SemanticLinkId,
    ) -> Result<Option<SemanticLink>, DbError> {
        let uuid: Uuid = id.into();

        // Use runtime query with FromRow derive
        let row: Option<EdgeRow> = sqlx::query_as(
            r#"
            SELECT id, source_id, target_id, relationship, properties
            FROM edges
            WHERE id = $1
              AND source_type = 'claim'
              AND target_type = 'claim'
            "#,
        )
        .bind(uuid)
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => Ok(Some(semantic_link_from_row(row)?)),
            None => Ok(None),
        }
    }

    /// Get all semantic links from a source claim
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_source(
        pool: &PgPool,
        source_claim_id: ClaimId,
    ) -> Result<Vec<SemanticLink>, DbError> {
        let uuid: Uuid = source_claim_id.into();

        let rows: Vec<EdgeRow> = sqlx::query_as(
            r#"
            SELECT id, source_id, target_id, relationship, properties
            FROM edges
            WHERE source_id = $1
              AND source_type = 'claim'
              AND target_type = 'claim'
            ORDER BY created_at DESC
            "#,
        )
        .bind(uuid)
        .fetch_all(pool)
        .await?;

        let mut links = Vec::with_capacity(rows.len());
        for row in rows {
            links.push(semantic_link_from_row(row)?);
        }

        Ok(links)
    }

    /// Get all semantic links to a target claim
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_target(
        pool: &PgPool,
        target_claim_id: ClaimId,
    ) -> Result<Vec<SemanticLink>, DbError> {
        let uuid: Uuid = target_claim_id.into();

        let rows: Vec<EdgeRow> = sqlx::query_as(
            r#"
            SELECT id, source_id, target_id, relationship, properties
            FROM edges
            WHERE target_id = $1
              AND source_type = 'claim'
              AND target_type = 'claim'
            ORDER BY created_at DESC
            "#,
        )
        .bind(uuid)
        .fetch_all(pool)
        .await?;

        let mut links = Vec::with_capacity(rows.len());
        for row in rows {
            links.push(semantic_link_from_row(row)?);
        }

        Ok(links)
    }

    /// Get all semantic links between two specific claims
    ///
    /// Returns links in both directions (source -> target and target -> source).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_between(
        pool: &PgPool,
        claim_a: ClaimId,
        claim_b: ClaimId,
    ) -> Result<Vec<SemanticLink>, DbError> {
        let uuid_a: Uuid = claim_a.into();
        let uuid_b: Uuid = claim_b.into();

        let rows: Vec<EdgeRow> = sqlx::query_as(
            r#"
            SELECT id, source_id, target_id, relationship, properties
            FROM edges
            WHERE ((source_id = $1 AND target_id = $2)
                OR (source_id = $2 AND target_id = $1))
              AND source_type = 'claim'
              AND target_type = 'claim'
            ORDER BY created_at DESC
            "#,
        )
        .bind(uuid_a)
        .bind(uuid_b)
        .fetch_all(pool)
        .await?;

        let mut links = Vec::with_capacity(rows.len());
        for row in rows {
            links.push(semantic_link_from_row(row)?);
        }

        Ok(links)
    }

    /// Get all semantic links of a specific type
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_type(
        pool: &PgPool,
        link_type: SemanticLinkType,
    ) -> Result<Vec<SemanticLink>, DbError> {
        let relationship = link_type_to_str(link_type);

        let rows: Vec<EdgeRow> = sqlx::query_as(
            r#"
            SELECT id, source_id, target_id, relationship, properties
            FROM edges
            WHERE relationship = $1
              AND source_type = 'claim'
              AND target_type = 'claim'
            ORDER BY created_at DESC
            "#,
        )
        .bind(relationship)
        .fetch_all(pool)
        .await?;

        let mut links = Vec::with_capacity(rows.len());
        for row in rows {
            links.push(semantic_link_from_row(row)?);
        }

        Ok(links)
    }

    /// Delete a semantic link by ID
    ///
    /// # Returns
    /// Returns `true` if the link was deleted, `false` if it didn't exist.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn delete(pool: &PgPool, id: SemanticLinkId) -> Result<bool, DbError> {
        let uuid: Uuid = id.into();

        let result = sqlx::query(
            r#"
            DELETE FROM edges
            WHERE id = $1
              AND source_type = 'claim'
              AND target_type = 'claim'
            "#,
        )
        .bind(uuid)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// List semantic links with pagination
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list(
        pool: &PgPool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SemanticLink>, DbError> {
        let rows: Vec<EdgeRow> = sqlx::query_as(
            r#"
            SELECT id, source_id, target_id, relationship, properties
            FROM edges
            WHERE source_type = 'claim'
              AND target_type = 'claim'
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        let mut links = Vec::with_capacity(rows.len());
        for row in rows {
            links.push(semantic_link_from_row(row)?);
        }

        Ok(links)
    }

    /// Count total number of semantic links
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn count(pool: &PgPool) -> Result<i64, DbError> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM edges
            WHERE source_type = 'claim'
              AND target_type = 'claim'
            "#,
        )
        .fetch_one(pool)
        .await?;

        let count: Option<i64> = row.try_get("count")?;
        Ok(count.unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =============================================================================
    // Unit Tests for Helper Functions
    // =============================================================================

    #[test]
    fn test_link_type_to_str_roundtrip() {
        let types = [
            SemanticLinkType::Supports,
            SemanticLinkType::Contradicts,
            SemanticLinkType::DerivesFrom,
            SemanticLinkType::Refines,
            SemanticLinkType::Analogous,
        ];

        for link_type in types {
            let s = link_type_to_str(link_type);
            let roundtrip = str_to_link_type(s).expect("Should parse valid link type");
            assert_eq!(roundtrip, link_type);
        }
    }

    #[test]
    fn test_str_to_link_type_invalid() {
        let result = str_to_link_type("invalid_type");
        assert!(result.is_err());
        match result {
            Err(DbError::InvalidData { reason }) => {
                assert!(reason.contains("Unknown semantic link type"));
            }
            _ => panic!("Expected InvalidData error"),
        }
    }

    #[test]
    fn test_semantic_link_from_row_success() {
        let id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let created_by = Uuid::new_v4();
        let created_at = Utc::now();

        let properties = serde_json::json!({
            "strength": 0.75,
            "created_by": created_by.to_string(),
            "created_at": created_at.to_rfc3339()
        });

        let row = EdgeRow {
            id,
            source_id,
            target_id,
            relationship: "supports".to_string(),
            properties,
        };

        let link = semantic_link_from_row(row).expect("Should create link from valid row data");

        assert_eq!(link.id.as_uuid(), id);
        assert_eq!(link.source_claim_id.as_uuid(), source_id);
        assert_eq!(link.target_claim_id.as_uuid(), target_id);
        assert_eq!(link.link_type, SemanticLinkType::Supports);
        assert!((link.strength.value() - 0.75).abs() < f64::EPSILON);
        assert_eq!(link.created_by.as_uuid(), created_by);
    }

    #[test]
    fn test_semantic_link_from_row_default_strength() {
        let id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let created_by = Uuid::new_v4();

        // Properties without strength field
        let properties = serde_json::json!({
            "created_by": created_by.to_string()
        });

        let row = EdgeRow {
            id,
            source_id,
            target_id,
            relationship: "contradicts".to_string(),
            properties,
        };

        let link = semantic_link_from_row(row).expect("Should use default strength");

        assert!((link.strength.value() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_semantic_link_from_row_missing_created_by() {
        let id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        let properties = serde_json::json!({
            "strength": 0.5
        });

        let row = EdgeRow {
            id,
            source_id,
            target_id,
            relationship: "supports".to_string(),
            properties,
        };

        let result = semantic_link_from_row(row);

        assert!(result.is_err());
        match result {
            Err(DbError::InvalidData { reason }) => {
                assert!(reason.contains("missing created_by"));
            }
            _ => panic!("Expected InvalidData error"),
        }
    }

    #[test]
    fn test_semantic_link_from_row_invalid_created_by_uuid() {
        let id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        let properties = serde_json::json!({
            "strength": 0.5,
            "created_by": "not-a-uuid"
        });

        let row = EdgeRow {
            id,
            source_id,
            target_id,
            relationship: "supports".to_string(),
            properties,
        };

        let result = semantic_link_from_row(row);

        assert!(result.is_err());
        match result {
            Err(DbError::InvalidData { reason }) => {
                assert!(reason.contains("Invalid created_by UUID"));
            }
            _ => panic!("Expected InvalidData error"),
        }
    }

    #[test]
    fn test_semantic_link_from_row_self_reference_rejected() {
        let id = Uuid::new_v4();
        let claim_id = Uuid::new_v4(); // Same for source and target
        let created_by = Uuid::new_v4();

        let properties = serde_json::json!({
            "strength": 0.5,
            "created_by": created_by.to_string()
        });

        let row = EdgeRow {
            id,
            source_id: claim_id,
            target_id: claim_id, // Self-reference
            relationship: "supports".to_string(),
            properties,
        };

        let result = semantic_link_from_row(row);

        // This should be rejected by the domain model's with_id constructor
        assert!(result.is_err());
    }

    #[test]
    fn test_semantic_link_from_row_fallback_created_at() {
        let id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let created_by = Uuid::new_v4();

        // Properties without created_at field
        let properties = serde_json::json!({
            "strength": 0.5,
            "created_by": created_by.to_string()
        });

        let row = EdgeRow {
            id,
            source_id,
            target_id,
            relationship: "supports".to_string(),
            properties,
        };

        let before = Utc::now();
        let link = semantic_link_from_row(row).expect("Should fallback to current time");
        let after = Utc::now();

        // created_at should be approximately now
        assert!(link.created_at >= before);
        assert!(link.created_at <= after);
    }

    // =============================================================================
    // Integration Tests (require database)
    // =============================================================================

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_semantic_link_crud(_pool: sqlx::PgPool) {
        // Placeholder: full CRUD coverage is in tests/semantic_link_tests.rs
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_get_by_source_returns_empty_for_nonexistent(_pool: sqlx::PgPool) {
        // Placeholder: covered by integration tests
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_get_between_bidirectional(_pool: sqlx::PgPool) {
        // Placeholder: covered by integration tests
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_list_pagination(_pool: sqlx::PgPool) {
        // Placeholder: covered by integration tests
    }
}
