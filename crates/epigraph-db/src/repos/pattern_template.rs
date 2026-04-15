//! Repository for the `pattern_templates` table

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the `pattern_templates` table
#[derive(Debug, Clone, FromRow)]
pub struct PatternTemplateRow {
    pub id: Uuid,
    pub name: String,
    pub category: String,
    pub description: Option<String>,
    pub skeleton: serde_json::Value,
    pub min_confidence: f64,
    pub created_at: DateTime<Utc>,
}

/// Repository for PatternTemplate operations
pub struct PatternTemplateRepository;

impl PatternTemplateRepository {
    /// Get all pattern templates
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_all(pool: &PgPool) -> Result<Vec<PatternTemplateRow>, DbError> {
        let rows: Vec<PatternTemplateRow> = sqlx::query_as(
            r#"
            SELECT id, name, category, description, skeleton, min_confidence, created_at
            FROM pattern_templates
            ORDER BY category ASC, name ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Get pattern templates by category
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_category(
        pool: &PgPool,
        category: &str,
    ) -> Result<Vec<PatternTemplateRow>, DbError> {
        let rows: Vec<PatternTemplateRow> = sqlx::query_as(
            r#"
            SELECT id, name, category, description, skeleton, min_confidence, created_at
            FROM pattern_templates
            WHERE category = $1
            ORDER BY name ASC
            "#,
        )
        .bind(category)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Get a pattern template by name
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_name(
        pool: &PgPool,
        name: &str,
    ) -> Result<Option<PatternTemplateRow>, DbError> {
        let row: Option<PatternTemplateRow> = sqlx::query_as(
            r#"
            SELECT id, name, category, description, skeleton, min_confidence, created_at
            FROM pattern_templates
            WHERE name = $1
            "#,
        )
        .bind(name)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Insert a new pattern template
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, skeleton))]
    pub async fn insert(
        pool: &PgPool,
        name: &str,
        category: &str,
        description: Option<&str>,
        skeleton: serde_json::Value,
        min_confidence: f64,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO pattern_templates (name, category, description, skeleton, min_confidence)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(name)
        .bind(category)
        .bind(description)
        .bind(&skeleton)
        .bind(min_confidence)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }
}
