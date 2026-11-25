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

/// The `error_message` of a row the reaper failed: it was still `running`
/// past the stale bound on its last attempt.
pub const REAPED_SPENT_MESSAGE: &str = "reaped: still running past the stale bound on its last \
     attempt (the drain run was killed or died mid-job); no further attempt";

/// The `error_message` of a ONE-attempt row the reaper failed: it was still
/// `running` past the stale bound after [`MAX_CRASH_REDELIVERIES`] uncounted
/// re-deliveries, so its handler crashes or is killed on every run.
pub const REAPED_REDELIVERIES_SPENT_MESSAGE: &str = "reaped: a one-attempt job still running past \
     the stale bound after its last crash re-delivery (the drain run was killed or died mid-job \
     on every run); no further delivery";

/// How many times the reaper re-delivers a ONE-attempt row (`max_retries <=
/// 1`) that was still `running` past the stale bound, before it fails the row
/// with [`REAPED_REDELIVERIES_SPENT_MESSAGE`] (migration 220's
/// `jobs.redelivery_count`, backlog 1320b4e3). Three re-deliveries: four runs
/// that each died mid-job is a crash loop, not bad luck.
pub const MAX_CRASH_REDELIVERIES: i32 = 3;

/// One row [`PostgresJobQueue::reap_stale_jobs_counting_attempts`] touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReapedJob {
    /// The job row.
    pub id: Uuid,
    /// Its type.
    pub job_type: String,
    /// `true`: the row is now `failed`, because the reap used its last
    /// attempt or (a one-attempt row) its last crash re-delivery. `false`: it
    /// is back to `pending`.
    pub failed: bool,
    /// `true`: a one-attempt row (`max_retries <= 1`), whose reap is bounded
    /// by `redelivery_count` instead of `retry_count`; a failed one carries
    /// [`REAPED_REDELIVERIES_SPENT_MESSAGE`], any other failed row
    /// [`REAPED_SPENT_MESSAGE`].
    pub one_attempt: bool,
}

/// A privatization plan left in a RUNNING state (`applying` or `reverting`)
/// with no `pending` or `running` apply or revert job naming it, found by
/// [`PostgresJobQueue::stranded_privatization_plans`] (backlog e8c8dd03).
///
/// Nothing will move such a plan: its job ended (failed by the reaper after
/// its crash re-deliveries, failed by its handler, or cancelled) without the
/// plan reaching `applied`, `reverted` or `failed`. Its claims may be partly
/// moved. Recovery is the operator's: abort the plan, then revert it, with
/// `epigraph-operator privatization abort|revert --plan <id>` on the
/// maintenance DSN (backlog bb682f72; see `docs/tenancy.md`, "A plan stranded
/// in `applying` or `reverting`").
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StrandedPlan {
    /// The plan.
    pub plan_id: Uuid,
    /// `applying` or `reverting`.
    pub state: String,
    /// The newest apply or revert job naming the plan, if any.
    pub last_job_id: Option<Uuid>,
    /// That job's state (`failed`, `cancelled`, or `completed`).
    pub last_job_state: Option<String>,
    /// That job's `error_message`.
    pub last_job_error: Option<String>,
}

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
    /// A pending row whose `run_after` (migration 261) is still in the future
    /// is skipped: it is waiting out its handler's backoff
    /// ([`PostgresJobQueue::requeue_after`]).
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
                  AND (run_after IS NULL OR run_after <= now())
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

/// The advisory-lock class [`PostgresJobQueue::enqueue_unique_pending`]
/// serializes on: the lock is `pg_advisory_xact_lock(hashtext(this),
/// hashtext(job_type))`, one per job type. The two-int form never collides
/// with the bigint keys in `epigraph_db::repos::maintenance_lock`.
pub const ENQUEUE_UNIQUE_LOCK_CLASS: &str = "epigraph.jobs.enqueue_unique";

impl PostgresJobQueue {
    /// Enqueue `job` unless a job of the same `job_type` is already `pending`.
    /// Returns `Ok(Some(id))` when it enqueued, `Ok(None)` when a pending job
    /// of that type was found and nothing was written. A `running`,
    /// `completed`, `failed` or `cancelled` job of the type does not block it,
    /// and the payload is not compared: one pending job per type.
    ///
    /// The caller is the operator CLI `enqueue_job --unique`, which a timer
    /// runs so that a missed drain cannot stack a second job of the type.
    ///
    /// # Atomic among its callers
    ///
    /// One transaction: first `pg_advisory_xact_lock` on
    /// ([`ENQUEUE_UNIQUE_LOCK_CLASS`], `job_type`), as its OWN statement, then
    /// the guarded `INSERT ... SELECT ... WHERE NOT EXISTS`. Under READ
    /// COMMITTED each statement takes a fresh snapshot, so the INSERT's
    /// snapshot is taken after the lock wait and sees a row a concurrent
    /// caller committed while this one waited. (Folded into the INSERT, the
    /// lock would be taken inside a snapshot that predates the wait, and two
    /// callers could both insert.) A plain [`JobQueue::enqueue`] of the same
    /// type does not take the lock and is not serialized against this.
    ///
    /// The deleted predecessor of this method had the same guard without the
    /// lock (backlog cbf57f24). A unique partial index with `ON CONFLICT`
    /// would also close the race against plain enqueues; that needs a
    /// migration, and the only enqueuer of the scheduled types is this path.
    ///
    /// # Pool
    ///
    /// Run it on the maintenance pool, as `enqueue_job` does after asserting
    /// the connection satisfies `epigraph_bypass()`. On an application
    /// session row security would hide the pending rows from the guard and
    /// turn it into an unconditional insert, except that since migration 119
    /// `jobs_app` refuses an application session's INSERT into `jobs`
    /// outright, so there it fails closed with an error.
    ///
    /// # Errors
    /// `JobError::ProcessingFailed` if a statement fails.
    #[instrument(skip(self, job), fields(job_id = %job.id, job_type = %job.job_type))]
    pub async fn enqueue_unique_pending(&self, job: Job) -> Result<Option<JobId>, JobError> {
        let fail = |what: &str, e: sqlx::Error| JobError::ProcessingFailed {
            message: format!("Failed to enqueue (unique pending): {what}: {e}"),
        };
        let id: Uuid = job.id.into();
        let state_str = job_state_to_str(job.state);

        let mut tx = self.pool.begin().await.map_err(|e| fail("begin", e))?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
            .bind(ENQUEUE_UNIQUE_LOCK_CLASS)
            .bind(&job.job_type)
            .execute(&mut *tx)
            .await
            .map_err(|e| fail("lock", e))?;
        let inserted = sqlx::query(
            r"
            INSERT INTO jobs (
                id, job_type, payload, state, retry_count, max_retries,
                created_at, updated_at, started_at, completed_at, error_message
            )
            SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
            WHERE NOT EXISTS (
                SELECT 1 FROM jobs WHERE job_type = $2 AND state = 'pending'
            )
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
        .execute(&mut *tx)
        .await
        .map_err(|e| fail("insert", e))?
        .rows_affected();
        tx.commit().await.map_err(|e| fail("commit", e))?;

        if inserted == 0 {
            tracing::debug!(
                job_type = %job.job_type,
                "enqueue_unique_pending: a pending job of this type already exists; skipped"
            );
            Ok(None)
        } else {
            tracing::debug!(job_id = %job.id, "enqueue_unique_pending: enqueued");
            Ok(Some(job.id))
        }
    }

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

    /// Claim the oldest pending job whose type is in `job_types` and whose id
    /// is not in `exclude`, flipping it to `running` in the same statement
    /// (`FOR UPDATE SKIP LOCKED`, as [`JobQueue::dequeue`]).
    ///
    /// The drain timer (`drain_jobs`, operator decision D9) uses this instead
    /// of the trait's `dequeue` for two reasons, both about a run that must
    /// terminate:
    ///
    /// * a pending job of a type no handler is registered for (an
    ///   `embedding_generation` job on an instance whose embedding provider
    ///   may not write `claims.embedding`) would otherwise be dequeued at the
    ///   head of the queue on every iteration, and the run would never reach
    ///   the jobs behind it;
    /// * a job that failed and was put back to `pending` in this run is
    ///   excluded, so its retry waits for the next run instead of spinning.
    ///
    /// A pending row whose `run_after` (migration 261) is still in the future
    /// is not claimed either: it is waiting out its handler's backoff
    /// ([`Self::requeue_after`]). NULL is due now.
    ///
    /// # Errors
    /// `JobError::ProcessingFailed` on a database error, or when the claimed
    /// row cannot be parsed.
    #[instrument(skip(self))]
    pub async fn dequeue_of_types(
        &self,
        job_types: &[String],
        exclude: &[Uuid],
    ) -> Result<Option<Job>, JobError> {
        let row = sqlx::query(
            r"
            WITH next_job AS (
                SELECT id
                FROM jobs
                WHERE state = 'pending'
                  AND job_type = ANY($1)
                  AND NOT (id = ANY($2))
                  AND (run_after IS NULL OR run_after <= now())
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
        .bind(job_types)
        .bind(exclude)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to dequeue job: {e}"),
        })?;
        row.map(|r| job_from_row(&r)).transpose()
    }

    /// How many `pending` jobs have a type in `job_types`, an id not in
    /// `exclude`, and no `run_after` in the future: the work
    /// [`Self::dequeue_of_types`] would still hand out now. A row waiting out
    /// its backoff is not counted, so a run whose only leftover work is
    /// deferred retries has not run out of time.
    ///
    /// # Errors
    /// `JobError::ProcessingFailed` on a database error.
    #[instrument(skip(self))]
    pub async fn count_pending_of_types(
        &self,
        job_types: &[String],
        exclude: &[Uuid],
    ) -> Result<i64, JobError> {
        sqlx::query_scalar(
            "SELECT count(*) FROM jobs \
              WHERE state = 'pending' AND job_type = ANY($1) AND NOT (id = ANY($2)) \
                AND (run_after IS NULL OR run_after <= now())",
        )
        .bind(job_types)
        .bind(exclude)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to count pending jobs: {e}"),
        })
    }

    /// The longest delay [`Self::requeue_after`] stores: 30 days. A handler's
    /// `backoff` is clamped to it, so an absurd custom value cannot overflow
    /// the database's interval arithmetic (which would abort the drain run
    /// with the job still `running`) and a job is never parked for ever.
    pub const MAX_REQUEUE_DELAY: std::time::Duration =
        std::time::Duration::from_secs(30 * 24 * 60 * 60);

    /// Put `job` back to `pending` after a retryable failure, not to be
    /// claimed before `delay` has passed: writes its `retry_count` and
    /// `error_message`, clears `started_at` and `completed_at`, and sets
    /// `run_after` (migration 261) to the database's `now() + delay`. Returns
    /// the stored `run_after`.
    ///
    /// The drain (`jobs_drain::drain` in `epigraph-api`) calls this with the
    /// handler's [`crate::JobHandler::backoff`], which the in-process worker
    /// loop honours by sleeping. The time is computed on the DATABASE clock
    /// because the claims compare it with the database's `now()`; a host
    /// clock ahead of or behind it would shorten or stretch the wait.
    /// `delay` is clamped to [`Self::MAX_REQUEUE_DELAY`].
    ///
    /// # Errors
    /// `JobError::ProcessingFailed` on a database error, or when no row has
    /// the job's id.
    #[instrument(skip(self, job), fields(job_id = %job.id, job_type = %job.job_type))]
    pub async fn requeue_after(
        &self,
        job: &Job,
        delay: std::time::Duration,
    ) -> Result<DateTime<Utc>, JobError> {
        let id: Uuid = job.id.into();
        let micros =
            i64::try_from(delay.min(Self::MAX_REQUEUE_DELAY).as_micros()).unwrap_or(i64::MAX);
        let run_after: Option<DateTime<Utc>> = sqlx::query_scalar(
            r"
            UPDATE jobs
               SET state = 'pending',
                   retry_count = $2,
                   error_message = $3,
                   started_at = NULL,
                   completed_at = NULL,
                   updated_at = now(),
                   run_after = now() + make_interval(secs => $4::double precision / 1000000)
             WHERE id = $1
            RETURNING run_after
            ",
        )
        .bind(id)
        .bind(job.retry_count as i32)
        .bind(&job.error_message)
        .bind(micros)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to requeue job: {e}"),
        })?;
        run_after.ok_or_else(|| JobError::ProcessingFailed {
            message: format!("Failed to requeue job {id}: no such row"),
        })
    }

    /// How many `pending` jobs there are of each type NOT in `job_types`: the
    /// work a drain registered for `job_types` will never claim (one
    /// `GROUP BY`). Types with no pending job are absent.
    ///
    /// # Errors
    /// `JobError::ProcessingFailed` on a database error.
    #[instrument(skip(self))]
    pub async fn count_pending_by_type_outside(
        &self,
        job_types: &[String],
    ) -> Result<std::collections::BTreeMap<String, i64>, JobError> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT job_type, count(*) FROM jobs \
              WHERE state = 'pending' AND NOT (job_type = ANY($1)) \
              GROUP BY job_type",
        )
        .bind(job_types)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to count pending jobs of unregistered types: {e}"),
        })?;
        Ok(rows.into_iter().collect())
    }

    /// Every privatization plan in `applying` or `reverting` that no `pending`
    /// or `running` apply or revert job names: a [`StrandedPlan`] (backlog
    /// e8c8dd03), ordered by plan id. One read; it writes nothing.
    ///
    /// The apply and revert jobs are one-attempt rows, so once the reaper
    /// fails one after [`MAX_CRASH_REDELIVERIES`] crash re-deliveries, or its
    /// handler fails on a fault that is not a refusal (a refusal sets the plan
    /// `failed` itself), the plan keeps its running state with nothing left to
    /// finish it. The dispatch writes the state flip and the job in one
    /// transaction, so a plan in a running state with no live job is never a
    /// dispatch in progress.
    ///
    /// A job names its plan in its payload (`EpiGraphJob`'s externally tagged
    /// `{"PrivatizationApply": {"plan_id": …}}` or `PrivatizationRevert`);
    /// the reseal job is keyed on a group and cannot strand a plan.
    ///
    /// # Errors
    /// `JobError::ProcessingFailed` on a database error.
    #[instrument(skip(self))]
    pub async fn stranded_privatization_plans(&self) -> Result<Vec<StrandedPlan>, JobError> {
        /// `(plan id, plan state, last job id, its state, its error)`.
        type Row = (Uuid, String, Option<Uuid>, Option<String>, Option<String>);
        let rows: Vec<Row> = sqlx::query_as(
            "WITH named AS ( \
                    SELECT j.id, j.state, j.error_message, j.created_at, \
                           COALESCE(j.payload -> 'PrivatizationApply' ->> 'plan_id', \
                                    j.payload -> 'PrivatizationRevert' ->> 'plan_id') AS plan_id \
                      FROM jobs j \
                     WHERE j.job_type IN ($1, $2) \
                 ) \
                 SELECT p.id, p.state::text, last.id, last.state, last.error_message \
                   FROM privatization_plans p \
                   LEFT JOIN LATERAL ( \
                        SELECT n.id, n.state, n.error_message FROM named n \
                         WHERE n.plan_id = p.id::text \
                         ORDER BY n.created_at DESC, n.id DESC LIMIT 1 \
                   ) last ON true \
                  WHERE p.state IN ('applying', 'reverting') \
                    AND NOT EXISTS (SELECT 1 FROM named n \
                                     WHERE n.plan_id = p.id::text \
                                       AND n.state IN ('pending', 'running')) \
                  ORDER BY p.id",
        )
        .bind(crate::privatization::APPLY_JOB_TYPE)
        .bind(crate::privatization::REVERT_JOB_TYPE)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to read stranded privatization plans: {e}"),
        })?;
        Ok(rows
            .into_iter()
            .map(
                |(plan_id, state, last_job_id, last_job_state, last_job_error)| StrandedPlan {
                    plan_id,
                    state,
                    last_job_id,
                    last_job_state,
                    last_job_error,
                },
            )
            .collect())
    }

    /// Set every `pending` job whose type is in `job_types` to `cancelled`,
    /// with `error_message = message`, and return how many of each type it
    /// cancelled (one `UPDATE`). Rows in any other state are untouched, so a
    /// job a run is executing, or one already finished, is never rewritten.
    ///
    /// The caller decides which types may be cancelled: `drain_jobs
    /// --cancel-pending` passes only types its run has NO handler for
    /// (`jobs_drain::drain_cancelling` refuses any other), so this never
    /// discards work the queue could still do.
    ///
    /// # Errors
    /// `JobError::ProcessingFailed` on a database error.
    #[instrument(skip(self, message))]
    pub async fn cancel_pending_of_types(
        &self,
        job_types: &[String],
        message: &str,
    ) -> Result<std::collections::BTreeMap<String, i64>, JobError> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "WITH cancelled AS ( \
                UPDATE jobs \
                   SET state = 'cancelled', error_message = $2, \
                       updated_at = now(), completed_at = now() \
                 WHERE state = 'pending' AND job_type = ANY($1) \
                RETURNING job_type \
             ) \
             SELECT job_type, count(*) FROM cancelled GROUP BY job_type",
        )
        .bind(job_types)
        .bind(message)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to cancel pending jobs: {e}"),
        })?;
        Ok(rows.into_iter().collect())
    }

    /// The drain timer's reaper (`drain_jobs`, operator decision D9): reset
    /// every `running` row whose `started_at` is older than `stale_threshold`,
    /// COUNTING the reap as a used attempt, and fail the row outright once its
    /// attempts are used up.
    ///
    /// # Why a reap counts
    ///
    /// Under D9 the queue is drained by a oneshot unit that systemd kills after
    /// its start timeout. A job that needs longer than that is killed mid-run,
    /// left `running`, reset by a later run's reaper, re-run and killed again.
    /// [`Self::recover_stale_jobs`] resets without counting, so that loop never
    /// ends and starves the queue behind it on every cycle. Counting the reap
    /// bounds it by `max_retries`, like a handler error.
    ///
    /// The row that uses its last attempt here is set `failed` by the reaper
    /// itself, with an `error_message` that says why, rather than left `pending`
    /// for the runner's pre-check to fail without a word.
    ///
    /// # A one-attempt row (`max_retries <= 1`) is reset WITHOUT counting
    ///
    /// The row's own attempt budget decides, not a list of job types. A row
    /// enqueued with one attempt (`PrivatizationRepository::enqueue_job_conn`
    /// writes `max_retries = 1` for the privatization apply, revert and reseal
    /// jobs; the unseal's `embedding_generation` jobs get a retry budget since
    /// backlog 1320b4e3) is built around ONE attempt plus re-delivery: a worker
    /// that died mid-job is re-delivered, and the handler's own state check
    /// makes a re-delivery after its terminal write a no-op refusal. A counted
    /// reap would compute `0 + 1 >= 1` and fail such a job before its handler
    /// ever runs (a privatization plan left mid-flight). So those rows keep
    /// [`Self::recover_stale_jobs`]' behaviour.
    ///
    /// Deciding by the row means a new one-attempt enqueuer is covered without
    /// editing a list here.
    ///
    /// # A one-attempt row's re-deliveries are bounded by their own counter
    ///
    /// An uncounted reset bumps `jobs.redelivery_count` (migration 220) instead
    /// of `retry_count`, and the reap that would take it past
    /// [`MAX_CRASH_REDELIVERIES`] fails the row with
    /// [`REAPED_REDELIVERIES_SPENT_MESSAGE`]. Before that bound a one-attempt
    /// job killed on EVERY run was re-delivered on every run, for ever
    /// (backlog 1320b4e3). A privatization job failed this way leaves its plan
    /// in `applying` / `reverting`; the operator's recovery is the plan's abort.
    ///
    /// # Errors
    /// `JobError::ProcessingFailed` on a database error or an invalid duration.
    #[instrument(skip(self))]
    pub async fn reap_stale_jobs_counting_attempts(
        &self,
        stale_threshold: std::time::Duration,
    ) -> Result<Vec<ReapedJob>, JobError> {
        let cutoff = Utc::now()
            - chrono::Duration::from_std(stale_threshold).map_err(|e| {
                JobError::ProcessingFailed {
                    message: format!("Invalid duration: {e}"),
                }
            })?;
        let rows: Vec<(Uuid, String, String, bool)> = sqlx::query_as(
            r"
            WITH stale AS (
                SELECT id,
                       max_retries > 1 AS counted,
                       CASE WHEN max_retries > 1 THEN retry_count + 1 >= max_retries
                            ELSE redelivery_count + 1 > $3 END AS spent
                  FROM jobs
                 WHERE state = 'running' AND started_at < $1
                 FOR UPDATE SKIP LOCKED
            )
            UPDATE jobs j
               SET retry_count      = CASE WHEN s.counted THEN j.retry_count + 1
                                           ELSE j.retry_count END,
                   redelivery_count = CASE WHEN s.counted OR s.spent THEN j.redelivery_count
                                           ELSE j.redelivery_count + 1 END,
                   state            = CASE WHEN s.spent THEN 'failed' ELSE 'pending' END,
                   started_at       = CASE WHEN s.spent THEN j.started_at ELSE NULL END,
                   completed_at     = CASE WHEN s.spent THEN NOW() ELSE j.completed_at END,
                   error_message    = CASE WHEN NOT s.spent THEN j.error_message
                                           WHEN s.counted THEN $2
                                           ELSE $4 END,
                   updated_at       = NOW()
              FROM stale s
             WHERE j.id = s.id
            RETURNING j.id, j.job_type, j.state, NOT s.counted
            ",
        )
        .bind(cutoff)
        .bind(REAPED_SPENT_MESSAGE)
        .bind(MAX_CRASH_REDELIVERIES)
        .bind(REAPED_REDELIVERIES_SPENT_MESSAGE)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("Failed to reap stale jobs: {e}"),
        })?;
        let reaped: Vec<ReapedJob> = rows
            .into_iter()
            .map(|(id, job_type, state, one_attempt)| ReapedJob {
                id,
                job_type,
                failed: state == "failed",
                one_attempt,
            })
            .collect();
        if !reaped.is_empty() {
            tracing::warn!(
                reaped = reaped.len(),
                failed = reaped.iter().filter(|r| r.failed).count(),
                "Reaped stale running jobs"
            );
        }
        Ok(reaped)
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
