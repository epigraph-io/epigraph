//! Context repository
//!
//! CRUD operations for epistemic contexts (temporal/situational scoping).

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the contexts table
#[derive(Debug, Clone, FromRow)]
pub struct ContextRow {
    pub id: Uuid,
    pub name: String,
    pub context_type: String,
    pub description: Option<String>,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    pub applicable_frame_ids: Option<Vec<Uuid>>,
    pub parameters: Option<serde_json::Value>,
    pub modifier_type: Option<String>,
    pub properties: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Repository for Context operations
pub struct ContextRepository;

impl ContextRepository {
    /// Create a new context
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool))]
    pub async fn create(
        pool: &PgPool,
        name: &str,
        context_type: &str,
        description: Option<&str>,
        valid_from: Option<DateTime<Utc>>,
        valid_until: Option<DateTime<Utc>>,
        applicable_frame_ids: &[Uuid],
        parameters: Option<&serde_json::Value>,
        modifier_type: Option<&str>,
    ) -> Result<ContextRow, DbError> {
        let params = parameters.cloned().unwrap_or(serde_json::json!({}));
        let mod_type = modifier_type.unwrap_or("filter");

        let row: ContextRow = sqlx::query_as(
            r#"
            INSERT INTO contexts (name, context_type, description, valid_from, valid_until,
                                  applicable_frame_ids, parameters, modifier_type)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, name, context_type, description, valid_from, valid_until,
                      applicable_frame_ids, parameters, modifier_type, properties, created_at
            "#,
        )
        .bind(name)
        .bind(context_type)
        .bind(description)
        .bind(valid_from)
        .bind(valid_until)
        .bind(applicable_frame_ids)
        .bind(&params)
        .bind(mod_type)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// Get a context by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<ContextRow>, DbError> {
        let row: Option<ContextRow> = sqlx::query_as(
            r#"
            SELECT id, name, context_type, description, valid_from, valid_until,
                   applicable_frame_ids, parameters, modifier_type, properties, created_at
            FROM contexts
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// List contexts with pagination
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<ContextRow>, DbError> {
        let rows: Vec<ContextRow> = sqlx::query_as(
            r#"
            SELECT id, name, context_type, description, valid_from, valid_until,
                   applicable_frame_ids, parameters, modifier_type, properties, created_at
            FROM contexts
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

    /// List currently active contexts (now() within valid_from..valid_until)
    ///
    /// Contexts with NULL valid_from or valid_until are treated as unbounded
    /// on that end (always valid in that direction).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_active(pool: &PgPool) -> Result<Vec<ContextRow>, DbError> {
        let rows: Vec<ContextRow> = sqlx::query_as(
            r#"
            SELECT id, name, context_type, description, valid_from, valid_until,
                   applicable_frame_ids, parameters, modifier_type, properties, created_at
            FROM contexts
            WHERE (valid_from IS NULL OR valid_from <= NOW())
              AND (valid_until IS NULL OR valid_until >= NOW())
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// List contexts applicable to a specific frame
    ///
    /// Matches contexts whose `applicable_frame_ids` array contains the given frame_id,
    /// or whose `applicable_frame_ids` is empty (applies to all frames).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_for_frame(pool: &PgPool, frame_id: Uuid) -> Result<Vec<ContextRow>, DbError> {
        let rows: Vec<ContextRow> = sqlx::query_as(
            r#"
            SELECT id, name, context_type, description, valid_from, valid_until,
                   applicable_frame_ids, parameters, modifier_type, properties, created_at
            FROM contexts
            WHERE $1 = ANY(applicable_frame_ids)
               OR applicable_frame_ids = '{}'
               OR applicable_frame_ids IS NULL
            ORDER BY created_at DESC
            "#,
        )
        .bind(frame_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_row_has_expected_fields() {
        let _row = ContextRow {
            id: Uuid::new_v4(),
            name: "2024-experiment".to_string(),
            context_type: "temporal".to_string(),
            description: Some("Experimental context".to_string()),
            valid_from: Some(Utc::now()),
            valid_until: None,
            applicable_frame_ids: Some(vec![Uuid::new_v4()]),
            parameters: Some(serde_json::json!({"region": "EU"})),
            modifier_type: Some("filter".to_string()),
            properties: serde_json::json!({}),
            created_at: Utc::now(),
        };
    }

    #[test]
    fn context_row_with_no_optional_fields() {
        let _row = ContextRow {
            id: Uuid::new_v4(),
            name: "global-context".to_string(),
            context_type: "domain".to_string(),
            description: None,
            valid_from: None,
            valid_until: None,
            applicable_frame_ids: None,
            parameters: None,
            modifier_type: None,
            properties: serde_json::json!({}),
            created_at: Utc::now(),
        };
    }
}
