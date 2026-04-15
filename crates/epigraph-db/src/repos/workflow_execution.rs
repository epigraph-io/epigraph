//! Repository for workflow execution persistence.
//!
//! A workflow execution tracks the lifecycle of a multi-task workflow run,
//! including task completion/failure counts and overall state.
//! Uses runtime sqlx queries (not compile-time macros) for SQLX_OFFLINE compatibility.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// A database row from the `workflow_executions` table.
///
/// Uses primitive types to stay decoupled from higher-level domain models.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WorkflowExecutionRow {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub state: String,
    pub created_by: Uuid,
    pub task_count: i32,
    pub tasks_completed: i32,
    pub tasks_failed: i32,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Repository for `workflow_executions` table operations.
///
/// All methods are static async and take a `&PgPool`.
pub struct WorkflowExecutionRepository;

impl WorkflowExecutionRepository {
    /// Insert a new workflow execution row, returning the persisted row.
    ///
    /// The caller is responsible for generating the `id` and setting sensible
    /// defaults (e.g. `state = "created"`, `task_count = 0`).
    ///
    /// # Errors
    /// Returns `DbError::DuplicateKey` if an execution with the same ID exists.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[instrument(skip(pool, row))]
    pub async fn create(
        pool: &PgPool,
        row: WorkflowExecutionRow,
    ) -> Result<WorkflowExecutionRow, DbError> {
        let result: WorkflowExecutionRow = sqlx::query_as(
            r#"
            INSERT INTO workflow_executions (
                id, name, description, state, created_by,
                task_count, tasks_completed, tasks_failed, error_message,
                created_at, updated_at, started_at, completed_at
            )
            VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9,
                $10, $11, $12, $13
            )
            RETURNING *
            "#,
        )
        .bind(row.id)
        .bind(&row.name)
        .bind(&row.description)
        .bind(&row.state)
        .bind(row.created_by)
        .bind(row.task_count)
        .bind(row.tasks_completed)
        .bind(row.tasks_failed)
        .bind(&row.error_message)
        .bind(row.created_at)
        .bind(row.updated_at)
        .bind(row.started_at)
        .bind(row.completed_at)
        .fetch_one(pool)
        .await
        .map_err(|err| {
            if let sqlx::Error::Database(ref db_err) = err {
                if db_err.is_unique_violation() {
                    return DbError::DuplicateKey {
                        entity: "WorkflowExecution".to_string(),
                    };
                }
            }
            DbError::from(err)
        })?;

        Ok(result)
    }

    /// Fetch a workflow execution by its UUID.
    ///
    /// Returns `None` if no execution with the given ID exists.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(
        pool: &PgPool,
        id: Uuid,
    ) -> Result<Option<WorkflowExecutionRow>, DbError> {
        let row: Option<WorkflowExecutionRow> =
            sqlx::query_as("SELECT * FROM workflow_executions WHERE id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await?;

        Ok(row)
    }

    /// Update the `state` field of a workflow execution, refreshing `updated_at`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn update_state(pool: &PgPool, id: Uuid, state: &str) -> Result<(), DbError> {
        sqlx::query(
            r#"
            UPDATE workflow_executions
            SET state      = $2,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(state)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Update task completion and failure counters for a workflow execution.
    ///
    /// Sets `tasks_completed` and `tasks_failed` to the supplied values and
    /// refreshes `updated_at = NOW()`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn update_progress(
        pool: &PgPool,
        id: Uuid,
        completed_count: i32,
        failed_count: i32,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            UPDATE workflow_executions
            SET tasks_completed = $2,
                tasks_failed    = $3,
                updated_at      = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(completed_count)
        .bind(failed_count)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// List all active workflow executions (state `'created'` or `'running'`).
    ///
    /// Ordered by `created_at` ascending so the oldest active runs appear first.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_active(pool: &PgPool) -> Result<Vec<WorkflowExecutionRow>, DbError> {
        let rows: Vec<WorkflowExecutionRow> = sqlx::query_as(
            r#"
            SELECT * FROM workflow_executions
            WHERE state IN ('created', 'running')
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// List all workflow executions created by a given agent.
    ///
    /// Ordered by `created_at` descending so the most recent runs appear first.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_by_agent(
        pool: &PgPool,
        agent_id: Uuid,
    ) -> Result<Vec<WorkflowExecutionRow>, DbError> {
        let rows: Vec<WorkflowExecutionRow> = sqlx::query_as(
            "SELECT * FROM workflow_executions WHERE created_by = $1 ORDER BY created_at DESC",
        )
        .bind(agent_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_workflow_execution_placeholder(_pool: sqlx::PgPool) {
        // Integration tests live in tests/workflow_execution_tests.rs once fixture is ready.
    }
}
