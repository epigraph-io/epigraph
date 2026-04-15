//! Task persistence for the orchestration engine.
//! Tasks are agent-assigned work items within workflows.
//! For system-level background work, see epigraph-jobs.
//!
//! Tasks represent units of work assigned to agents within a workflow or standalone.
//! Uses runtime sqlx queries (not compile-time macros) for SQLX_OFFLINE compatibility.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// A database row from the `tasks` table.
///
/// Uses primitive types to stay decoupled from higher-level domain models.
/// The API layer converts this to its task representation as needed.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TaskRow {
    pub id: Uuid,
    pub description: String,
    pub task_type: String,
    pub input: serde_json::Value,
    pub output_schema: Option<serde_json::Value>,
    pub assigned_agent: Option<Uuid>,
    pub priority: i32,
    pub state: String,
    pub parent_task_id: Option<Uuid>,
    pub workflow_id: Option<Uuid>,
    pub timeout_seconds: Option<i32>,
    pub retry_max: i32,
    pub retry_count: i32,
    pub result: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Repository for `tasks` table operations.
///
/// All methods are static async and take a `&PgPool`.
pub struct TaskRepository;

impl TaskRepository {
    /// Insert a new task row, returning the persisted row.
    ///
    /// The caller is responsible for generating the `id` field and setting
    /// sensible defaults (e.g. `state = "created"`, `retry_count = 0`).
    ///
    /// # Errors
    /// Returns `DbError::DuplicateKey` if a task with the same ID already exists.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[instrument(skip(pool, row))]
    pub async fn create(pool: &PgPool, row: TaskRow) -> Result<TaskRow, DbError> {
        let result: TaskRow = sqlx::query_as(
            r#"
            INSERT INTO tasks (
                id, description, task_type, input, output_schema,
                assigned_agent, priority, state, parent_task_id, workflow_id,
                timeout_seconds, retry_max, retry_count, result, error_message,
                created_at, updated_at, started_at, completed_at
            )
            VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15,
                $16, $17, $18, $19
            )
            RETURNING *
            "#,
        )
        .bind(row.id)
        .bind(&row.description)
        .bind(&row.task_type)
        .bind(&row.input)
        .bind(&row.output_schema)
        .bind(row.assigned_agent)
        .bind(row.priority)
        .bind(&row.state)
        .bind(row.parent_task_id)
        .bind(row.workflow_id)
        .bind(row.timeout_seconds)
        .bind(row.retry_max)
        .bind(row.retry_count)
        .bind(&row.result)
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
                        entity: "Task".to_string(),
                    };
                }
            }
            DbError::from(err)
        })?;

        Ok(result)
    }

    /// Fetch a task by its UUID.
    ///
    /// Returns `None` if no task with the given ID exists.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<TaskRow>, DbError> {
        let row: Option<TaskRow> = sqlx::query_as("SELECT * FROM tasks WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;

        Ok(row)
    }

    /// Update the `state` field of a task, refreshing `updated_at` to now.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn update_state(pool: &PgPool, id: Uuid, state: &str) -> Result<(), DbError> {
        sqlx::query(
            r#"
            UPDATE tasks
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

    /// Assign a task to an agent, transitioning state to `'assigned'`.
    ///
    /// Sets `assigned_agent`, `state = 'assigned'`, and `updated_at = NOW()`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn assign(pool: &PgPool, task_id: Uuid, agent_id: Uuid) -> Result<(), DbError> {
        sqlx::query(
            r#"
            UPDATE tasks
            SET assigned_agent = $2,
                state          = 'assigned',
                updated_at     = NOW()
            WHERE id = $1
            "#,
        )
        .bind(task_id)
        .bind(agent_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Mark a task as completed, storing its result JSON.
    ///
    /// Sets `state = 'completed'`, `result`, `completed_at = NOW()`,
    /// and `updated_at = NOW()`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, result_json))]
    pub async fn complete(
        pool: &PgPool,
        id: Uuid,
        result_json: serde_json::Value,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            UPDATE tasks
            SET state        = 'completed',
                result       = $2,
                completed_at = NOW(),
                updated_at   = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(result_json)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Mark a task as failed, recording the error message and incrementing retry count.
    ///
    /// Sets `state = 'failed'`, `error_message`, increments `retry_count`,
    /// and refreshes `updated_at = NOW()`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn fail(pool: &PgPool, id: Uuid, error: &str) -> Result<(), DbError> {
        sqlx::query(
            r#"
            UPDATE tasks
            SET state         = 'failed',
                error_message = $2,
                retry_count   = retry_count + 1,
                updated_at    = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(error)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// List pending tasks (state `'created'` or `'queued'`), ordered by priority
    /// descending then creation time ascending, up to `limit` rows.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_pending(pool: &PgPool, limit: i64) -> Result<Vec<TaskRow>, DbError> {
        let rows: Vec<TaskRow> = sqlx::query_as(
            r#"
            SELECT * FROM tasks
            WHERE state IN ('created', 'queued')
            ORDER BY priority DESC, created_at ASC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// List all tasks belonging to a workflow.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_by_workflow(
        pool: &PgPool,
        workflow_id: Uuid,
    ) -> Result<Vec<TaskRow>, DbError> {
        let rows: Vec<TaskRow> =
            sqlx::query_as("SELECT * FROM tasks WHERE workflow_id = $1 ORDER BY created_at ASC")
                .bind(workflow_id)
                .fetch_all(pool)
                .await?;

        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_task_placeholder(_pool: sqlx::PgPool) {
        // Integration tests live in tests/task_tests.rs once the DB fixture is ready.
    }
}
