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
    #[instrument(skip(pool, viewer))]
    pub async fn get_by_id(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        id: Uuid,
    ) -> Result<Option<ContextRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT id, name, context_type, description, valid_from, valid_until,
                   applicable_frame_ids, parameters, modifier_type, properties, created_at
            FROM contexts
            WHERE id = $1
              /* {VISIBILITY:contexts} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, ContextRow>(&sql).bind(id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row: Option<ContextRow> = q.fetch_optional(pool).await?;

        Ok(row)
    }

    /// List contexts with pagination
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn list(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ContextRow>, DbError> {
        // No WHERE clause to append to, so the marker introduces one.
        let sql = viewer.splice(
            r#"
            SELECT id, name, context_type, description, valid_from, valid_until,
                   applicable_frame_ids, parameters, modifier_type, properties, created_at
            FROM contexts
            WHERE true /* {VISIBILITY:contexts} */
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, ContextRow>(&sql)
            .bind(limit)
            .bind(offset);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<ContextRow> = q.fetch_all(pool).await?;

        Ok(rows)
    }

    /// List currently active contexts (now() within valid_from..valid_until)
    ///
    /// Contexts with NULL valid_from or valid_until are treated as unbounded
    /// on that end (always valid in that direction).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn list_active(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
    ) -> Result<Vec<ContextRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT id, name, context_type, description, valid_from, valid_until,
                   applicable_frame_ids, parameters, modifier_type, properties, created_at
            FROM contexts
            WHERE (valid_from IS NULL OR valid_from <= NOW())
              AND (valid_until IS NULL OR valid_until >= NOW())
              /* {VISIBILITY:contexts} */
            ORDER BY created_at DESC
            "#,
            1,
        );
        let mut q = sqlx::query_as::<_, ContextRow>(&sql);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<ContextRow> = q.fetch_all(pool).await?;

        Ok(rows)
    }

    /// List contexts applicable to a specific frame
    ///
    /// Matches contexts whose `applicable_frame_ids` array contains the given frame_id,
    /// or whose `applicable_frame_ids` is empty (applies to all frames).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn list_for_frame(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        frame_id: Uuid,
    ) -> Result<Vec<ContextRow>, DbError> {
        // PARENTHESES ARE LOAD-BEARING. The pre-existing predicate is an OR
        // chain; `AND` binds tighter than `OR`, so appending the fragment
        // without wrapping would parse as
        // `a OR b OR (c AND visible)` — two thirds of the rows unfiltered.
        let sql = viewer.splice(
            r#"
            SELECT id, name, context_type, description, valid_from, valid_until,
                   applicable_frame_ids, parameters, modifier_type, properties, created_at
            FROM contexts
            WHERE ($1 = ANY(applicable_frame_ids)
                   OR applicable_frame_ids = '{}'
                   OR applicable_frame_ids IS NULL)
              /* {VISIBILITY:contexts} */
            ORDER BY created_at DESC
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, ContextRow>(&sql).bind(frame_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<ContextRow> = q.fetch_all(pool).await?;

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
