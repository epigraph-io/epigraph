//! `PostgreSQL`-backed job queue for persistent job storage.
//!
//! This module provides `PostgresJobQueue`, a production-ready implementation
//! of the [`JobQueue`] trait that persists jobs to `PostgreSQL`.
//!
//! # Features
//!
//! - **Persistence**: Jobs survive application restarts
//! - **Concurrent access**: Uses `FOR UPDATE SKIP LOCKED` for safe dequeuing
//! - **JSONB payloads**: Efficient storage and querying of job payloads
//! - **ACID guarantees**: Full transaction support from `PostgreSQL`
//!
//! # Example
//!
//! ```ignore
//! use epigraph_jobs::{PostgresJobQueue, Job, JobQueue};
//! use sqlx::PgPool;
//!
//! let pool = PgPool::connect("postgres://...").await?;
//! let queue = PostgresJobQueue::new(pool);
//!
//! // Enqueue a job
//! let job = Job::new("my_job", serde_json::json!({"key": "value"}));
//! queue.enqueue(job).await?;
//!
//! // Dequeue for processing (with row locking)
//! if let Some(job) = queue.dequeue().await {
//!     // Process job...
//! }
//! ```
//!
//! # Database Schema
//!
//! Requires the `jobs` table. See migration `008_create_jobs.sql`.

use crate::{async_trait, Job, JobError, JobId, JobQueue, JobState};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use tracing::instrument;
use uuid::Uuid;

// ============================================================================
// PostgreSQL Job Queue
// ============================================================================

/// `PostgreSQL`-backed job queue.
///
/// This queue implementation provides persistent storage for jobs using
/// `PostgreSQL`. It's designed for production use where job persistence
/// across restarts is required.
///
/// # Concurrency
///
/// The `dequeue` method uses `FOR UPDATE SKIP LOCKED` to safely handle
/// concurrent workers. This ensures:
/// - Each job is only processed by one worker
/// - Workers don't block each other waiting for locks
/// - Jobs are processed in FIFO order (by `created_at`)
///
/// # Error Handling
///
/// Database errors are mapped to `JobError::ProcessingFailed` with
/// descriptive messages. Callers should implement retry logic for
/// transient failures.
#[derive(Clone)]
pub struct PostgresJobQueue {
    pool: PgPool,
}

impl PostgresJobQueue {
    /// Create a new `PostgreSQL` job queue with the given connection pool.
    ///
    /// # Arguments
    ///
    /// * `pool` - `PostgreSQL` connection pool (from sqlx)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let pool = PgPool::connect("postgres://localhost/epigraph").await?;
    /// let queue = PostgresJobQueue::new(pool);
    /// ```
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a reference to the underlying connection pool.
    ///
    /// Useful for running custom queries or health checks.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert a database row to a Job struct.
///
/// This function handles the mapping from `PostgreSQL` types to Rust types,
/// including:
/// - UUID to `JobId`
/// - TEXT to `JobState` (with validation)
/// - JSONB to `serde_json::Value`
/// - TIMESTAMPTZ to `DateTime`<Utc>
///
/// # Errors
///
/// Returns `JobError::ProcessingFailed` if:
/// - The state string is invalid
/// - Required fields are missing
fn job_from_row(row: &sqlx::postgres::PgRow) -> Result<Job, JobError> {
    // Extract UUID and convert to JobId
    let id: Uuid = row.try_get("id").map_err(|e| JobError::ProcessingFailed {
        message: format!("Failed to get job id: {e}"),
    })?;

    let job_type: String = row
        .try_get("job_type")
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to get job_type: {e}"),
        })?;

    let payload: serde_json::Value =
        row.try_get("payload")
            .map_err(|e| JobError::ProcessingFailed {
                message: format!("Failed to get payload: {e}"),
            })?;

    let state_str: String = row
        .try_get("state")
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to get state: {e}"),
        })?;

    let state = match state_str.as_str() {
        "pending" => JobState::Pending,
        "running" => JobState::Running,
        "completed" => JobState::Completed,
        "failed" => JobState::Failed,
        "cancelled" => JobState::Cancelled,
        other => {
            return Err(JobError::ProcessingFailed {
                message: format!("Invalid job state in database: {other}"),
            })
        }
    };

    let retry_count: i32 = row
        .try_get("retry_count")
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to get retry_count: {e}"),
        })?;

    let max_retries: i32 = row
        .try_get("max_retries")
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to get max_retries: {e}"),
        })?;

    let created_at: DateTime<Utc> =
        row.try_get("created_at")
            .map_err(|e| JobError::ProcessingFailed {
                message: format!("Failed to get created_at: {e}"),
            })?;

    let updated_at: DateTime<Utc> =
        row.try_get("updated_at")
            .map_err(|e| JobError::ProcessingFailed {
                message: format!("Failed to get updated_at: {e}"),
            })?;

    // Optional fields
    let started_at: Option<DateTime<Utc>> = row.try_get("started_at").ok();
    let completed_at: Option<DateTime<Utc>> = row.try_get("completed_at").ok();
    let error_message: Option<String> = row.try_get("error_message").ok();

    Ok(Job {
        id: JobId::from_uuid(id),
        job_type,
        payload,
        state,
        retry_count: retry_count as u32,
        max_retries: max_retries as u32,
        created_at,
        updated_at,
        started_at,
        completed_at,
        error_message,
    })
}

/// Convert `JobState` to its database string representation.
const fn job_state_to_str(state: JobState) -> &'static str {
    match state {
        JobState::Pending => "pending",
        JobState::Running => "running",
        JobState::Completed => "completed",
        JobState::Failed => "failed",
        JobState::Cancelled => "cancelled",
    }
}

// ============================================================================
// JobQueue Implementation
// ============================================================================

#[async_trait]
impl JobQueue for PostgresJobQueue {
    /// Enqueue a new job into the database.
    ///
    /// Inserts the job with `Pending` state. The job's existing state is
    /// preserved if it's being re-enqueued after a retry.
    ///
    /// # SQL
    ///
    /// Uses an INSERT with ON CONFLICT DO UPDATE to handle re-enqueuing
    /// of jobs that were previously processed but need retry.
    #[instrument(skip(self, job), fields(job_id = %job.id, job_type = %job.job_type))]
    async fn enqueue(&self, job: Job) -> Result<JobId, JobError> {
        let id: Uuid = job.id.into();
        let state_str = job_state_to_str(job.state);

        sqlx::query(
            r"
            INSERT INTO jobs (
                id, job_type, payload, state, retry_count, max_retries,
                created_at, updated_at, started_at, completed_at, error_message
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (id) DO UPDATE SET
                state = EXCLUDED.state,
                retry_count = EXCLUDED.retry_count,
                updated_at = EXCLUDED.updated_at,
                started_at = EXCLUDED.started_at,
                completed_at = EXCLUDED.completed_at,
                error_message = EXCLUDED.error_message
            ",
        )
        .bind(id)
        .bind(&job.job_type)
        .bind(&job.payload)
        .bind(state_str)
        .bind(job.retry_count as i32)
        .bind(job.max_retries as i32)
        .bind(job.created_at)
        .bind(job.updated_at)
        .bind(job.started_at)
        .bind(job.completed_at)
        .bind(&job.error_message)
        .execute(&self.pool)
        .await
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to enqueue job: {e}"),
        })?;

        tracing::debug!(job_id = %job.id, "Job enqueued successfully");
        Ok(job.id)
    }

    /// Dequeue the next pending job for processing.
    ///
    /// Uses `FOR UPDATE SKIP LOCKED` to safely handle concurrent workers:
    /// - `FOR UPDATE`: Locks the row to prevent other workers from claiming it
    /// - `SKIP LOCKED`: Skips rows locked by other workers instead of blocking
    ///
    /// The job's state is atomically updated to `Running` in the same transaction.
    ///
    /// # Returns
    ///
    /// - `Some(Job)` if a pending job was found and claimed
    /// - `None` if no pending jobs are available
    #[instrument(skip(self))]
    async fn dequeue(&self) -> Option<Job> {
        // Use a single query with CTE to atomically select and update
        // This ensures the job is claimed in a single round-trip
        let result = sqlx::query(
            r"
            WITH next_job AS (
                SELECT id
                FROM jobs
                WHERE state = 'pending'
                ORDER BY created_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE jobs
            SET state = 'running',
                started_at = NOW(),
                updated_at = NOW()
            FROM next_job
            WHERE jobs.id = next_job.id
            RETURNING jobs.id, jobs.job_type, jobs.payload, jobs.state,
                      jobs.retry_count, jobs.max_retries, jobs.created_at,
                      jobs.updated_at, jobs.started_at, jobs.completed_at,
                      jobs.error_message
            ",
        )
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(Some(row)) => match job_from_row(&row) {
                Ok(job) => {
                    tracing::debug!(job_id = %job.id, job_type = %job.job_type, "Job dequeued");
                    Some(job)
                }
                Err(e) => {
                    tracing::error!("Failed to parse job from row: {e}");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                tracing::error!("Failed to dequeue job: {e}");
                None
            }
        }
    }

    /// Update the state of a job in the database.
    ///
    /// Updates all mutable fields of the job: state, `retry_count`, timestamps,
    /// and `error_message`.
    ///
    /// # Errors
    ///
    /// Returns `JobError::ProcessingFailed` if the database update fails.
    #[instrument(skip(self, job), fields(job_id = %job.id, new_state = %job.state))]
    async fn update(&self, job: &Job) -> Result<(), JobError> {
        let id: Uuid = job.id.into();
        let state_str = job_state_to_str(job.state);

        let result = sqlx::query(
            r"
            UPDATE jobs
            SET state = $2,
                retry_count = $3,
                updated_at = $4,
                started_at = $5,
                completed_at = $6,
                error_message = $7
            WHERE id = $1
            ",
        )
        .bind(id)
        .bind(state_str)
        .bind(job.retry_count as i32)
        .bind(job.updated_at)
        .bind(job.started_at)
        .bind(job.completed_at)
        .bind(&job.error_message)
        .execute(&self.pool)
        .await
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to update job: {e}"),
        })?;

        if result.rows_affected() == 0 {
            tracing::warn!(job_id = %job.id, "Job not found for update");
        } else {
            tracing::debug!(job_id = %job.id, "Job updated successfully");
        }

        Ok(())
    }

    /// Get a job by its ID.
    ///
    /// # Returns
    ///
    /// - `Some(Job)` if the job exists
    /// - `None` if no job with that ID exists
    #[instrument(skip(self))]
    async fn get(&self, id: JobId) -> Option<Job> {
        let uuid: Uuid = id.into();

        let result = sqlx::query(
            r"
            SELECT id, job_type, payload, state, retry_count, max_retries,
                   created_at, updated_at, started_at, completed_at, error_message
            FROM jobs
            WHERE id = $1
            ",
        )
        .bind(uuid)
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(Some(row)) => match job_from_row(&row) {
                Ok(job) => Some(job),
                Err(e) => {
                    tracing::error!("Failed to parse job from row: {e}");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                tracing::error!("Failed to get job {id}: {e}");
                None
            }
        }
    }

    /// Get all pending jobs in FIFO order.
    ///
    /// Returns jobs ordered by `created_at` ascending (oldest first).
    /// This is useful for monitoring and debugging.
    ///
    /// # Note
    ///
    /// This does NOT lock the jobs. For processing, use `dequeue()` instead.
    #[instrument(skip(self))]
    async fn pending_jobs(&self) -> Vec<Job> {
        let result = sqlx::query(
            r"
            SELECT id, job_type, payload, state, retry_count, max_retries,
                   created_at, updated_at, started_at, completed_at, error_message
            FROM jobs
            WHERE state = 'pending'
            ORDER BY created_at ASC
            ",
        )
        .fetch_all(&self.pool)
        .await;

        match result {
            Ok(rows) => {
                let mut jobs = Vec::with_capacity(rows.len());
                for row in rows {
                    match job_from_row(&row) {
                        Ok(job) => jobs.push(job),
                        Err(e) => {
                            tracing::error!("Failed to parse job from row: {e}");
                        }
                    }
                }
                jobs
            }
            Err(e) => {
                tracing::error!("Failed to get pending jobs: {e}");
                Vec::new()
            }
        }
    }
}

// ============================================================================
// Additional PostgresJobQueue Methods
// ============================================================================

impl PostgresJobQueue {
    /// Get jobs by state.
    ///
    /// Useful for monitoring dashboards and administrative tasks.
    #[instrument(skip(self))]
    pub async fn jobs_by_state(&self, state: JobState) -> Vec<Job> {
        let state_str = job_state_to_str(state);

        let result = sqlx::query(
            r"
            SELECT id, job_type, payload, state, retry_count, max_retries,
                   created_at, updated_at, started_at, completed_at, error_message
            FROM jobs
            WHERE state = $1
            ORDER BY created_at ASC
            ",
        )
        .bind(state_str)
        .fetch_all(&self.pool)
        .await;

        match result {
            Ok(rows) => {
                let mut jobs = Vec::with_capacity(rows.len());
                for row in rows {
                    match job_from_row(&row) {
                        Ok(job) => jobs.push(job),
                        Err(e) => {
                            tracing::error!("Failed to parse job from row: {e}");
                        }
                    }
                }
                jobs
            }
            Err(e) => {
                tracing::error!("Failed to get jobs by state {state}: {e}");
                Vec::new()
            }
        }
    }

    /// Count jobs by state.
    ///
    /// More efficient than loading all jobs when you only need counts.
    #[instrument(skip(self))]
    pub async fn count_by_state(&self, state: JobState) -> Result<i64, JobError> {
        let state_str = job_state_to_str(state);

        let row = sqlx::query("SELECT COUNT(*) as count FROM jobs WHERE state = $1")
            .bind(state_str)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| JobError::ProcessingFailed {
                message: format!("Failed to count jobs: {e}"),
            })?;

        let count: i64 = row
            .try_get("count")
            .map_err(|e| JobError::ProcessingFailed {
                message: format!("Failed to get count: {e}"),
            })?;

        Ok(count)
    }

    /// Delete completed and failed jobs older than the specified duration.
    ///
    /// Useful for cleaning up old jobs to prevent table bloat.
    ///
    /// # Arguments
    ///
    /// * `older_than` - Delete jobs with `completed_at` older than this duration ago
    ///
    /// # Returns
    ///
    /// The number of jobs deleted.
    #[instrument(skip(self))]
    pub async fn cleanup_old_jobs(&self, older_than: std::time::Duration) -> Result<u64, JobError> {
        let cutoff = Utc::now()
            - chrono::Duration::from_std(older_than).map_err(|e| JobError::ProcessingFailed {
                message: format!("Invalid duration: {e}"),
            })?;

        let result = sqlx::query(
            r"
            DELETE FROM jobs
            WHERE state IN ('completed', 'failed')
              AND completed_at < $1
            ",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to cleanup old jobs: {e}"),
        })?;

        let deleted = result.rows_affected();
        tracing::info!(deleted_count = deleted, "Cleaned up old jobs");
        Ok(deleted)
    }

    /// Recover stale running jobs.
    ///
    /// Jobs that have been in `Running` state for too long may indicate
    /// crashed workers. This method resets them to `Pending` for retry.
    ///
    /// # Arguments
    ///
    /// * `stale_threshold` - Consider jobs running longer than this as stale
    ///
    /// # Returns
    ///
    /// The number of jobs recovered.
    #[instrument(skip(self))]
    pub async fn recover_stale_jobs(
        &self,
        stale_threshold: std::time::Duration,
    ) -> Result<u64, JobError> {
        let cutoff = Utc::now()
            - chrono::Duration::from_std(stale_threshold).map_err(|e| {
                JobError::ProcessingFailed {
                    message: format!("Invalid duration: {e}"),
                }
            })?;

        let result = sqlx::query(
            r"
            UPDATE jobs
            SET state = 'pending',
                started_at = NULL,
                updated_at = NOW()
            WHERE state = 'running'
              AND started_at < $1
            ",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to recover stale jobs: {e}"),
        })?;

        let recovered = result.rows_affected();
        if recovered > 0 {
            tracing::warn!(recovered_count = recovered, "Recovered stale running jobs");
        }
        Ok(recovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Unit Tests for Helper Functions
    // ========================================================================

    #[test]
    fn test_job_state_to_str() {
        assert_eq!(job_state_to_str(JobState::Pending), "pending");
        assert_eq!(job_state_to_str(JobState::Running), "running");
        assert_eq!(job_state_to_str(JobState::Completed), "completed");
        assert_eq!(job_state_to_str(JobState::Failed), "failed");
        assert_eq!(job_state_to_str(JobState::Cancelled), "cancelled");
    }

    #[test]
    fn test_job_state_round_trip() {
        // Verify that each state string maps back correctly
        for state in [
            JobState::Pending,
            JobState::Running,
            JobState::Completed,
            JobState::Failed,
            JobState::Cancelled,
        ] {
            let str_rep = job_state_to_str(state);
            let parsed = match str_rep {
                "pending" => JobState::Pending,
                "running" => JobState::Running,
                "completed" => JobState::Completed,
                "failed" => JobState::Failed,
                "cancelled" => JobState::Cancelled,
                _ => panic!("Unknown state string: {str_rep}"),
            };
            assert_eq!(state, parsed, "Round-trip failed for {state:?}");
        }
    }
}
