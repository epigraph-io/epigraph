//! Activity repository for PROV-O activity tracking

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the activities table
#[derive(Debug, Clone, FromRow)]
pub struct ActivityRow {
    pub id: Uuid,
    pub activity_type: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub agent_id: Option<Uuid>,
    pub description: Option<String>,
    pub properties: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Repository for Activity operations
pub struct ActivityRepository;

impl ActivityRepository {
    /// Create a new activity record
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, properties))]
    pub async fn create(
        pool: &PgPool,
        activity_type: &str,
        started_at: DateTime<Utc>,
        agent_id: Option<Uuid>,
        description: Option<&str>,
        properties: serde_json::Value,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO activities (activity_type, started_at, agent_id, description, properties)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(activity_type)
        .bind(started_at)
        .bind(agent_id)
        .bind(description)
        .bind(&properties)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Get an activity by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<ActivityRow>, DbError> {
        let row: Option<ActivityRow> = sqlx::query_as(
            r#"
            SELECT id, activity_type, started_at, ended_at, agent_id, description, properties, created_at
            FROM activities
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// List activities by agent
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_by_agent(pool: &PgPool, agent_id: Uuid) -> Result<Vec<ActivityRow>, DbError> {
        let rows: Vec<ActivityRow> = sqlx::query_as(
            r#"
            SELECT id, activity_type, started_at, ended_at, agent_id, description, properties, created_at
            FROM activities
            WHERE agent_id = $1
            ORDER BY started_at DESC
            "#,
        )
        .bind(agent_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Mark an activity as completed by setting ended_at and optionally updating properties
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, properties))]
    pub async fn complete(
        pool: &PgPool,
        id: Uuid,
        ended_at: DateTime<Utc>,
        properties: Option<serde_json::Value>,
    ) -> Result<(), DbError> {
        if let Some(props) = properties {
            // Merge new properties into existing
            sqlx::query(
                r#"
                UPDATE activities
                SET ended_at = $1, properties = properties || $2
                WHERE id = $3
                "#,
            )
            .bind(ended_at)
            .bind(&props)
            .bind(id)
            .execute(pool)
            .await?;
        } else {
            sqlx::query(
                r#"
                UPDATE activities
                SET ended_at = $1
                WHERE id = $2
                "#,
            )
            .bind(ended_at)
            .bind(id)
            .execute(pool)
            .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_row_has_expected_fields() {
        // Ensure the struct compiles with all expected fields
        let _row = ActivityRow {
            id: Uuid::new_v4(),
            activity_type: "ingestion".to_string(),
            started_at: Utc::now(),
            ended_at: None,
            agent_id: Some(Uuid::new_v4()),
            description: Some("Test activity".to_string()),
            properties: serde_json::json!({"source_file": "test.json"}),
            created_at: Utc::now(),
        };
    }
}
