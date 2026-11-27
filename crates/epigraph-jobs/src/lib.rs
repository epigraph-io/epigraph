// Jobs crate: allow pedantic/nursery lints that are non-critical in this crate.
// - missing_errors_doc: doc coverage will be improved in a follow-up
// - missing_panics_doc: panic docs will be added in a follow-up
// - significant_drop_tightening: lock usage patterns are intentional
// - cast_possible_truncation/wrap/sign_loss: job queue sizes and retry counts are always small
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::significant_drop_tightening,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
//! Background job runner and task processing for `EpiGraph` agentic framework.
//!
//! This crate provides:
//! - [`Job`]: Represents a unit of background work
//! - [`JobState`]: State machine for job lifecycle
//! - [`JobHandler`]: Trait for implementing job processors
//! - [`JobRunner`]: Worker pool for processing jobs
//! - [`EpiGraphJob`]: the built-in job kinds. Their handlers are
//!   [`cluster_graph::ClusterGraphHandler`], the three in [`privatization`] and
//!   [`ConfigurableEmbeddingHandler`]; `epigraph-api`'s `jobs_drain` registers
//!   them, and every handler this crate defines is registered there (pinned by
//!   `tests/only_registered_handlers.rs`). Four kinds are retired
//!   ([`EpiGraphJob::is_retired`]).
//!
//! # Design Principles
//!
//! - Jobs are persistent and can survive restarts
//! - Failed jobs are retried with exponential backoff
//! - Job handlers are stateless and idempotent
//! - Graceful shutdown waits for in-flight jobs
//!
//! # Tasks vs Jobs
//!
//! EpiGraph distinguishes between **tasks** and **jobs**:
//!
//! - **Tasks** (epigraph-orchestrator + epigraph-db repos/task.rs): Agent-facing work items
//!   within workflows. Assigned to specific agents, have priorities, parent-child hierarchies,
//!   and track results. Exposed via REST API. Think: "Agent X, validate this claim."
//!
//! - **Jobs** (this crate): System-facing background work. Fire-and-forget, processed by
//!   worker pools, retried with exponential backoff. Not agent-assigned. Think: "Recompute
//!   embeddings for claim Y" or "Recompute the graph clusters."
//!
//! Tasks are the coordination layer; jobs are the execution layer.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

// Re-export dependencies that are part of public API
pub use async_trait::async_trait;

// PostgreSQL job queue module
mod postgres_queue;
pub use postgres_queue::{
    PostgresJobQueue, ReapedJob, StrandedPlan, ENQUEUE_UNIQUE_LOCK_CLASS, MAX_CRASH_REDELIVERIES,
    REAPED_REDELIVERIES_SPENT_MESSAGE, REAPED_SPENT_MESSAGE,
};

pub mod cluster_graph;
pub mod egress;
pub use egress::is_internal_addr;
pub mod coordination;
pub mod privatization;

pub use coordination::{apply_job_connection_settings, run_serialized, CLUSTER_GRAPH_LOCK_KEY};

// ============================================================================
// Job Identifier
// ============================================================================

/// Unique identifier for a Job
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JobId(Uuid);

impl JobId {
    /// Create a new random `JobId`
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a `JobId` from an existing UUID
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the underlying UUID
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "job:{}", self.0)
    }
}

impl From<Uuid> for JobId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<JobId> for Uuid {
    fn from(id: JobId) -> Self {
        id.0
    }
}

// ============================================================================
// Job State
// ============================================================================

/// State of a job in its lifecycle.
///
/// State transitions:
/// - `Pending` -> `Running`: Job picked up by worker
/// - `Running` -> `Completed`: Job finished successfully
/// - `Running` -> `Failed`: Job failed (may retry)
/// - `Pending` | `Running` -> `Cancelled`: Job cancelled
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JobState {
    /// Job is queued and waiting to be processed
    Pending,
    /// Job is currently being processed by a worker
    Running,
    /// Job completed successfully
    Completed,
    /// Job failed after all retries exhausted
    Failed,
    /// Job was cancelled before completion
    Cancelled,
}

impl JobState {
    /// Check if this state is terminal (no further transitions possible)
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// Check if transition to target state is valid
    #[must_use]
    pub const fn can_transition_to(&self, target: &Self) -> bool {
        match (self, target) {
            // From Pending: can go to Running or Cancelled
            (Self::Pending, Self::Running | Self::Cancelled)
            // From Running: can go to Completed, Failed, or Cancelled
            | (Self::Running, Self::Completed | Self::Failed | Self::Cancelled) => true,
            // Terminal states and all other transitions are invalid
            _ => false,
        }
    }
}

impl fmt::Display for JobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

// ============================================================================
// Job
// ============================================================================

/// A unit of background work to be processed.
///
/// Jobs are:
/// - Persistable to survive restarts
/// - Retryable with configurable backoff
/// - Traceable with timestamps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    /// Unique identifier for this job
    pub id: JobId,
    /// Type of job (used for routing to handlers)
    pub job_type: String,
    /// Job payload as JSON
    pub payload: serde_json::Value,
    /// Current state of the job
    pub state: JobState,
    /// Number of times this job has been retried
    pub retry_count: u32,
    /// Maximum number of retries allowed
    pub max_retries: u32,
    /// When the job was created
    pub created_at: DateTime<Utc>,
    /// When the job was last updated
    pub updated_at: DateTime<Utc>,
    /// When the job started running (if running or completed)
    pub started_at: Option<DateTime<Utc>>,
    /// When the job completed (if completed or failed)
    pub completed_at: Option<DateTime<Utc>>,
    /// Error message if the job failed
    pub error_message: Option<String>,
}

impl Job {
    /// Create a new job with the given type and payload.
    ///
    /// # Arguments
    /// * `job_type` - Type identifier for routing to the correct handler
    /// * `payload` - JSON payload containing job-specific data
    #[must_use]
    pub fn new(job_type: impl Into<String>, payload: serde_json::Value) -> Self {
        let now = Utc::now();
        Self {
            id: JobId::new(),
            job_type: job_type.into(),
            payload,
            state: JobState::Pending,
            retry_count: 0,
            max_retries: 3,
            created_at: now,
            updated_at: now,
            started_at: None,
            completed_at: None,
            error_message: None,
        }
    }

    /// Create a new job with custom max retries
    #[must_use]
    pub const fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Transition the job to a new state.
    ///
    /// # Errors
    /// Returns `JobError::InvalidStateTransition` if the transition is not allowed.
    pub fn transition_to(&mut self, new_state: JobState) -> Result<(), JobError> {
        if !self.state.can_transition_to(&new_state) {
            return Err(JobError::InvalidStateTransition {
                from: self.state,
                to: new_state,
            });
        }

        let now = Utc::now();
        self.state = new_state;
        self.updated_at = now;

        // Set timestamps based on target state
        match new_state {
            JobState::Running => {
                self.started_at = Some(now);
            }
            JobState::Completed | JobState::Failed | JobState::Cancelled => {
                self.completed_at = Some(now);
            }
            JobState::Pending => {}
        }

        Ok(())
    }
}

// ============================================================================
// Job Result & Error
// ============================================================================

/// Result of successfully processing a job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    /// Output data from the job
    pub output: serde_json::Value,
    /// How long the job took to execute
    pub execution_duration: Duration,
    /// Additional metadata about the execution
    pub metadata: JobResultMetadata,
}

/// Metadata about job execution
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JobResultMetadata {
    /// Worker ID that processed the job
    pub worker_id: Option<String>,
    /// Number of items processed (if applicable)
    pub items_processed: Option<u64>,
    /// Additional key-value metadata
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// Errors that can occur during job processing
#[derive(Debug, Clone, thiserror::Error)]
pub enum JobError {
    /// Job type has no registered handler
    #[error("no handler registered for job type: {job_type}")]
    NoHandler { job_type: String },

    /// Invalid state transition attempted
    #[error("invalid state transition from {from} to {to}")]
    InvalidStateTransition { from: JobState, to: JobState },

    /// Job processing failed (transient, may retry)
    #[error("job processing failed: {message}")]
    ProcessingFailed { message: String },

    /// Permanent failure - should NOT be retried (e.g., 4xx client errors except 429)
    #[error("permanent failure (no retry): {message}")]
    PermanentFailure { message: String },

    /// Rate limited - should retry after specified delay
    #[error("rate limited, retry after {retry_after_secs} seconds")]
    RateLimited { retry_after_secs: u64 },

    /// SSRF attack detected - internal IP blocked
    #[error("SSRF protection: blocked internal address {address}")]
    SsrfBlocked { address: String },

    /// Job timed out
    #[error("job timed out after {timeout:?}")]
    Timeout { timeout: Duration },

    /// Payload deserialization failed
    #[error("failed to deserialize job payload: {message}")]
    PayloadError { message: String },

    /// Job was cancelled
    #[error("job was cancelled")]
    Cancelled,

    /// Maximum retries exceeded
    #[error("maximum retries ({max_retries}) exceeded")]
    MaxRetriesExceeded { max_retries: u32 },
}

impl JobError {
    /// Check if this error type should trigger a retry.
    ///
    /// Returns `false` for permanent failures (4xx except 429, SSRF, cancelled).
    /// Returns `true` for transient failures (5xx, timeouts, rate limits).
    #[must_use]
    pub const fn should_retry(&self) -> bool {
        match self {
            // Transient failures - should retry
            Self::ProcessingFailed { .. } | Self::Timeout { .. } | Self::RateLimited { .. } => true,

            // Permanent failures - should NOT retry
            Self::PermanentFailure { .. }
            | Self::SsrfBlocked { .. }
            | Self::NoHandler { .. }
            | Self::InvalidStateTransition { .. }
            | Self::PayloadError { .. }
            | Self::Cancelled
            | Self::MaxRetriesExceeded { .. } => false,
        }
    }
}

// ============================================================================
// Job Handler Trait
// ============================================================================

/// Trait for implementing job handlers.
///
/// Handlers are stateless and should be idempotent - processing the same
/// job multiple times should produce the same result.
#[allow(clippy::double_must_use)] // async_trait's generated #[must_use] on an already-must-use boxed future
#[async_trait]
pub trait JobHandler: Send + Sync {
    /// Execute the job and return a result.
    ///
    /// # Errors
    /// Returns `JobError` if processing fails.
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError>;

    /// Job type this handler processes.
    ///
    /// This string must match the `job_type` field on `Job` for routing.
    fn job_type(&self) -> &str;

    /// Maximum number of retries for jobs of this type.
    ///
    /// Default: 3
    fn max_retries(&self) -> u32 {
        3
    }

    /// Calculate backoff duration for the given retry attempt.
    ///
    /// Default: Exponential backoff starting at 2 seconds, capped at 1 hour.
    ///
    /// # Arguments
    /// * `attempt` - The retry attempt number (0 = first retry)
    fn backoff(&self, attempt: u32) -> Duration {
        default_backoff(attempt)
    }
}

/// [`JobHandler::backoff`]'s default: `2^attempt` seconds, capped at one hour
/// (`attempt` 0 = the first retry). Also the backoff the drain's reaper gives a
/// reset row whose type has no handler in the run
/// (`PostgresJobQueue::reap_stale_jobs_counting_attempts`).
#[must_use]
pub fn default_backoff(attempt: u32) -> Duration {
    // Cap at 1 hour (3600 seconds) to prevent excessive waits and overflow
    const MAX_BACKOFF_SECS: u64 = 3600;

    let backoff_secs = if attempt >= 63 {
        MAX_BACKOFF_SECS
    } else {
        2u64.saturating_pow(attempt).min(MAX_BACKOFF_SECS)
    };

    Duration::from_secs(backoff_secs)
}

/// How long a retryable failure waits before its retry: the handler's
/// `backoff`, or, when the failure is [`JobError::RateLimited`], the LONGER of
/// that backoff and the `retry_after_secs` the rate limit asked for (backlog
/// 000cca08). A retry inside the provider's window only hits the same limit
/// and spends another attempt.
///
/// The worker loop sleeps this long, capped by [`worker_retry_sleep`], before
/// it re-enqueues; the drain (`jobs_drain::drain` in `epigraph-api`) stores it as the row's not-before
/// time (`PostgresJobQueue::requeue_after`, which clamps it to
/// `PostgresJobQueue::MAX_REQUEUE_DELAY`).
#[must_use]
pub fn retry_delay(error: &JobError, backoff: Duration) -> Duration {
    match error {
        JobError::RateLimited { retry_after_secs } => {
            backoff.max(Duration::from_secs(*retry_after_secs))
        }
        _ => backoff,
    }
}

/// The longest a [`JobRunner`] worker sleeps to honour a rate limit's
/// `retry_after_secs` before it retries in place: one hour, the default
/// backoff's own cap ([`default_backoff`]).
///
/// The worker sleeps while the job's row is still `running` and writes it back
/// only after the sleep, so a sleep past a stale-job reaper's threshold (the
/// drain's `STALE_AFTER`, 90 minutes, in `epigraph-api`) would let the reaper
/// reset and re-claim the row while this worker still holds it: the job would
/// run twice and the later write-back would overwrite the other's. A longer
/// retry-after is therefore cut to this cap here; the drain, which stores the
/// delay as the row's not-before time instead of sleeping, is not capped by it.
/// A handler's OWN backoff is never shortened.
pub const MAX_WORKER_RATE_LIMIT_SLEEP: Duration = Duration::from_secs(3600);

/// How long the [`JobRunner`] worker loop sleeps before a retry: the
/// [`retry_delay`], with a rate limit's extension beyond the handler's backoff
/// capped at [`MAX_WORKER_RATE_LIMIT_SLEEP`].
#[must_use]
pub fn worker_retry_sleep(error: &JobError, backoff: Duration) -> Duration {
    retry_delay(error, backoff).min(backoff.max(MAX_WORKER_RATE_LIMIT_SLEEP))
}

// ============================================================================
// Job Queue Trait
// ============================================================================

/// Trait for job queue implementations.
///
/// Queues are responsible for persisting jobs and providing them to workers.
#[allow(clippy::double_must_use)] // async_trait's generated #[must_use] on an already-must-use boxed future
#[async_trait]
pub trait JobQueue: Send + Sync {
    /// Enqueue a new job.
    async fn enqueue(&self, job: Job) -> Result<JobId, JobError>;

    /// Dequeue the next pending job for processing.
    ///
    /// Returns `None` if no jobs are available.
    async fn dequeue(&self) -> Option<Job>;

    /// Update the state of a job.
    async fn update(&self, job: &Job) -> Result<(), JobError>;

    /// Get a job by ID.
    async fn get(&self, id: JobId) -> Option<Job>;

    /// Get all pending jobs in FIFO order.
    async fn pending_jobs(&self) -> Vec<Job>;
}

// ============================================================================
// Job Runner
// ============================================================================

/// Background job runner with worker pool.
///
/// The runner manages a pool of workers that process jobs from a queue.
/// It supports graceful shutdown, waiting for in-flight jobs to complete.
pub struct JobRunner {
    /// Number of worker threads
    worker_count: usize,
    /// Job queue
    queue: std::sync::Arc<dyn JobQueue>,
    /// Registered job handlers (shared across workers)
    handlers: std::sync::Arc<std::collections::HashMap<String, std::sync::Arc<dyn JobHandler>>>,
    /// Mutable handlers for registration phase
    handlers_mut: std::collections::HashMap<String, std::sync::Arc<dyn JobHandler>>,
    /// Shutdown signal sender
    shutdown_tx: Option<tokio::sync::broadcast::Sender<()>>,
    /// Worker task handles
    worker_handles: Vec<tokio::task::JoinHandle<()>>,
}

/// Write a job's state back to its queue from the worker loop, logging (not
/// dropping) a queue error: the loop has no caller to return it to, and a
/// silently lost write leaves the row in whatever state the queue last held.
async fn write_back(queue: &dyn JobQueue, job: &Job) {
    if let Err(e) = queue.update(job).await {
        tracing::error!(job_id = %job.id, job_type = %job.job_type, state = %job.state,
            error = %e, "job runner: could not write the job's state back to the queue");
    }
}

impl JobRunner {
    /// Create a new job runner with the specified worker count.
    ///
    /// # Arguments
    /// * `worker_count` - Number of concurrent workers
    /// * `queue` - Job queue implementation
    #[must_use]
    pub fn new(worker_count: usize, queue: std::sync::Arc<dyn JobQueue>) -> Self {
        Self {
            worker_count,
            queue,
            handlers: std::sync::Arc::new(std::collections::HashMap::new()),
            handlers_mut: std::collections::HashMap::new(),
            shutdown_tx: None,
            worker_handles: Vec::new(),
        }
    }

    /// Register a job handler.
    ///
    /// # Panics
    /// Panics if a handler for the same job type is already registered.
    pub fn register_handler(&mut self, handler: std::sync::Arc<dyn JobHandler>) {
        let job_type = handler.job_type().to_string();
        assert!(
            !self.handlers_mut.contains_key(&job_type),
            "Handler for job type '{job_type}' is already registered"
        );
        self.handlers_mut.insert(job_type, handler);
    }

    /// Get the configured worker count.
    #[must_use]
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Start the job runner.
    ///
    /// This spawns worker tasks and begins processing jobs.
    #[allow(clippy::unused_async)]
    pub async fn start(&mut self) {
        // Move handlers to shared Arc
        let handlers = std::mem::take(&mut self.handlers_mut);
        self.handlers = std::sync::Arc::new(handlers);

        // Create shutdown channel
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        // Spawn workers
        for _worker_id in 0..self.worker_count {
            let queue = self.queue.clone();
            let handlers = self.handlers.clone();
            let mut shutdown_rx = shutdown_tx.subscribe();

            let handle = tokio::spawn(async move {
                loop {
                    // Check for shutdown signal (non-blocking)
                    if shutdown_rx.try_recv().is_ok() {
                        break;
                    }

                    // Try to get a job
                    let Some(mut job) = queue.dequeue().await else {
                        // No jobs available, sleep briefly
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        continue;
                    };

                    // A job of a type this runner has no handler for is failed
                    // with the reason. A persistent queue has already flipped
                    // the row to `running`; writing nothing back would strand
                    // it there with no handler ever to finish it, and putting
                    // it back to `pending` would hand it straight out again at
                    // the head of the queue (backlog 99dc2bbd).
                    let Some(handler) = handlers.get(&job.job_type) else {
                        let err = JobError::NoHandler {
                            job_type: job.job_type.clone(),
                        };
                        tracing::error!(job_id = %job.id, job_type = %job.job_type,
                            "job runner: no handler registered; failing the job");
                        let now = Utc::now();
                        job.state = JobState::Failed;
                        job.error_message = Some(err.to_string());
                        job.updated_at = now;
                        job.completed_at = Some(now);
                        write_back(queue.as_ref(), &job).await;
                        continue;
                    };

                    // Check if we've exceeded max retries.
                    //
                    // Path A — the dequeue handed us a job that was already at
                    // retry_count >= max_retries. Mark it failed, but PRESERVE
                    // any prior error_message that earlier retry attempts
                    // captured. Replacing it with a generic "Maximum retries
                    // exceeded" hides the actual stage failure; instead we
                    // append.
                    if job.retry_count >= job.max_retries {
                        job.state = JobState::Failed;
                        let prior = job.error_message.clone().unwrap_or_default();
                        job.error_message = Some(if prior.is_empty() {
                            "Maximum retries exceeded (no prior error captured)".to_string()
                        } else {
                            format!("Maximum retries exceeded; last error: {prior}")
                        });
                        write_back(queue.as_ref(), &job).await;
                        continue;
                    }

                    // Transition to Running (a persistent queue's dequeue
                    // already did; the refused Running -> Running is moot).
                    let _ = job.transition_to(JobState::Running);

                    // Execute handler
                    match handler.handle(&job).await {
                        Ok(_result) => {
                            let _ = job.transition_to(JobState::Completed);
                            write_back(queue.as_ref(), &job).await;
                        }
                        Err(e) => {
                            job.retry_count += 1;
                            job.error_message = Some(e.to_string());

                            // A permanent error is terminal at once; only a
                            // transient one spends the retry budget.
                            if !e.should_retry() || job.retry_count >= job.max_retries {
                                job.state = JobState::Failed;
                                job.updated_at = Utc::now();
                                job.completed_at = Some(Utc::now());
                            } else {
                                // Reset to Pending for retry after backoff
                                job.state = JobState::Pending;
                                job.started_at = None;
                                job.updated_at = Utc::now();

                                // Apply backoff before re-enqueueing: the
                                // handler's, or a rate limit's retry-after
                                // when that is longer, capped below the
                                // drain reaper's stale threshold.
                                let delay =
                                    worker_retry_sleep(&e, handler.backoff(job.retry_count - 1));
                                tokio::time::sleep(delay).await;
                            }
                            write_back(queue.as_ref(), &job).await;

                            // Re-enqueue for retry if not failed
                            if job.state == JobState::Pending {
                                let job_id = job.id;
                                if let Err(e) = queue.enqueue(job).await {
                                    tracing::error!(%job_id, error = %e,
                                        "job runner: could not re-enqueue a job for its retry");
                                }
                            }
                        }
                    }
                }
            });

            self.worker_handles.push(handle);
        }
    }

    /// Signal graceful shutdown.
    ///
    /// Workers will finish their current jobs before stopping.
    pub async fn shutdown(&mut self) {
        // Send shutdown signal
        if let Some(ref tx) = self.shutdown_tx {
            let _ = tx.send(());
        }

        // Wait for all workers to complete
        for handle in self.worker_handles.drain(..) {
            let _ = handle.await;
        }
    }

    /// Process a single job.
    ///
    /// # Errors
    /// Returns `JobError` if processing fails.
    pub async fn process_job(&self, job: &mut Job) -> Result<JobResult, JobError> {
        // Check max retries first
        if job.retry_count >= job.max_retries {
            job.state = JobState::Failed;
            job.updated_at = Utc::now();
            job.completed_at = Some(Utc::now());
            return Err(JobError::MaxRetriesExceeded {
                max_retries: job.max_retries,
            });
        }

        // Find handler - check both handlers_mut (before start) and handlers (after start)
        let handler = self
            .handlers_mut
            .get(&job.job_type)
            .or_else(|| self.handlers.get(&job.job_type))
            .ok_or_else(|| JobError::NoHandler {
                job_type: job.job_type.clone(),
            })?;

        // Execute handler
        match handler.handle(job).await {
            Ok(result) => Ok(result),
            Err(e) => {
                job.retry_count += 1;
                job.error_message = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// The backoff the handler registered for `job_type` declares before retry
    /// `attempt` (0 = the first retry), as [`JobHandler::backoff`]; `None` when
    /// no handler for the type is registered. The same lookup as
    /// [`Self::process_job`], before and after [`Self::start`].
    ///
    /// The worker loop sleeps this long before it re-enqueues; the drain
    /// (`jobs_drain::drain` in `epigraph-api`), which has no loop to sleep in,
    /// stores it as the row's not-before time instead
    /// ([`PostgresJobQueue::requeue_after`]). Both lengthen it to a rate
    /// limit's retry-after ([`retry_delay`]).
    #[must_use]
    pub fn retry_backoff(&self, job_type: &str, attempt: u32) -> Option<Duration> {
        self.handlers_mut
            .get(job_type)
            .or_else(|| self.handlers.get(job_type))
            .map(|h| h.backoff(attempt))
    }

    /// Get list of all registered job types.
    ///
    /// Returns the job type strings for all registered handlers.
    #[must_use]
    pub fn registered_job_types(&self) -> Vec<String> {
        // Check both mutable handlers (before start) and immutable handlers (after start)
        if self.handlers_mut.is_empty() {
            self.handlers.keys().cloned().collect()
        } else {
            self.handlers_mut.keys().cloned().collect()
        }
    }
}

// ============================================================================
// Built-in EpiGraph Job Types
// ============================================================================

/// Built-in job types for `EpiGraph` operations.
///
/// # Retired kinds
///
/// `TruthPropagation`, `ReputationUpdate`, `WebhookNotification` and
/// `DataCleanup` are RETIRED ([`Self::is_retired`]): no handler for them
/// exists, and `drain_jobs` never ran one (webhooks are delivered by the API's
/// dispatcher, not by a job). The variants and their `job_type` strings stay so
/// a `jobs` row already stored with one of those types still deserializes and
/// still names its type. Such a row is reported by every drain as pending and
/// unregistered (exit 4) until an operator cancels it with
/// `drain_jobs --cancel-pending <TYPE>`, exactly as before the handlers were
/// deleted, and `enqueue_job` refuses to write a new one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EpiGraphJob {
    /// RETIRED (see the enum doc): propagate truth updates through the
    /// reasoning DAG.
    TruthPropagation {
        /// ID of the source claim that triggered propagation
        source_claim_id: Uuid,
    },

    /// Generate embeddings for a claim
    EmbeddingGeneration {
        /// ID of the claim to generate embeddings for
        claim_id: Uuid,
    },

    /// RETIRED (see the enum doc): recompute an agent's reputation score.
    ReputationUpdate {
        /// ID of the agent to update
        agent_id: Uuid,
    },

    /// RETIRED (see the enum doc): send a webhook notification.
    WebhookNotification {
        /// ID of the webhook configuration
        webhook_id: Uuid,
        /// Payload to send
        payload: serde_json::Value,
    },

    /// RETIRED (see the enum doc): clean up expired data.
    DataCleanup {
        /// Number of days to retain data
        retention_days: u32,
    },

    /// Recompute graph clusters via Louvain over the epistemic edge subgraph.
    ClusterGraph {
        /// Resolution parameter (1.0 default; >1.0 finer, <1.0 coarser).
        resolution: f64,
        /// Maximum number of historical runs to retain.
        retain_runs: u32,
    },

    /// Apply a D4 privatization plan (FINAL-PLAN §6.5.5).
    ///
    /// **The three fields are not the authorization and must not be read as
    /// it.** They are the claim the enqueuer makes about itself; the handler
    /// re-derives every one of them from the database before it touches a row,
    /// and refuses the whole plan when they disagree. See
    /// `crate::privatization` for the six conditions.
    ///
    /// `correlation_id` ties this job to the `security_events` row the HTTP
    /// layer wrote for the same request. `privatization_plans` has no
    /// `correlation_id` column — migration 080 is applied and frozen — so the
    /// value rides in the payload, and the handler's check is that a
    /// `privatization_dispatch` event with this correlation id is attributed to
    /// `dispatched_by`.
    PrivatizationApply {
        /// The plan to apply.
        plan_id: Uuid,
        /// The agent whose `POST …/apply` this is.
        dispatched_by: Uuid,
        /// Matches `security_events.correlation_id` for the dispatching request.
        correlation_id: String,
    },

    /// Un-apply a D4 privatization plan, restoring each item's captured
    /// `before_visibility` / `before_owner_group_id`.
    ///
    /// The mirror of [`Self::PrivatizationApply`] in every respect including the
    /// warning above: the handler re-validates.
    PrivatizationRevert {
        /// The plan to revert.
        plan_id: Uuid,
        /// The agent whose `POST …/revert` this is.
        dispatched_by: Uuid,
        /// Matches `security_events.correlation_id` for the dispatching request.
        correlation_id: String,
    },

    /// Finish a group's re-seal: clear `groups.reseal_required_at` once no
    /// ciphertext row is still bound to a retired key epoch (§6.7 point 3).
    ///
    /// **It is keyed on a GROUP, not on a plan, and that is a correction to the
    /// plan text.** FINAL-PLAN §6.7 describes reseal as `mode='reseal'`, and
    /// migration 080's applied, frozen `pp_mode_check` admits only `restrict`
    /// and `seal` — so a reseal plan is not representable without DDL, and
    /// PR-21 is assigned no migration.
    ///
    /// It also does no crypto, which §6.7's own closing paragraph requires:
    /// "re-sealing requires the group key, which by §6.5.6 the server does not
    /// have. The server can mark, measure and prepare the manifest; only a
    /// key-holding admin can complete it." The admin completes it through the
    /// seal/unseal ceremony; this job is what OBSERVES completion.
    PrivatizationReseal {
        /// The group whose re-seal is being checked.
        group_id: Uuid,
        /// The agent whose commit triggered the check.
        dispatched_by: Uuid,
        /// Matches `security_events.correlation_id` for the triggering request.
        correlation_id: String,
    },
}

impl EpiGraphJob {
    /// Get the job type string for this job variant.
    #[must_use]
    pub const fn job_type(&self) -> &'static str {
        match self {
            Self::TruthPropagation { .. } => "truth_propagation",
            Self::EmbeddingGeneration { .. } => "embedding_generation",
            Self::ReputationUpdate { .. } => "reputation_update",
            Self::WebhookNotification { .. } => "webhook_notification",
            Self::DataCleanup { .. } => "data_cleanup",
            Self::ClusterGraph { .. } => "cluster_graph",
            // The three names migration 077's `jobs_app` WITH CHECK already
            // spells. They must agree EXACTLY or the policy arm that refuses an
            // app-role enqueue of privatization work stops matching.
            Self::PrivatizationApply { .. } => crate::privatization::APPLY_JOB_TYPE,
            Self::PrivatizationRevert { .. } => crate::privatization::REVERT_JOB_TYPE,
            Self::PrivatizationReseal { .. } => crate::privatization::RESEAL_JOB_TYPE,
        }
    }

    /// Whether this is a RETIRED kind: one no handler exists for, kept only so
    /// a stored row still deserializes (see the enum doc). A new job of a
    /// retired kind must not be enqueued.
    #[must_use]
    pub const fn is_retired(&self) -> bool {
        matches!(
            self,
            Self::TruthPropagation { .. }
                | Self::ReputationUpdate { .. }
                | Self::WebhookNotification { .. }
                | Self::DataCleanup { .. }
        )
    }

    /// Convert this job to a generic `Job` instance.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn into_job(self) -> Result<Job, serde_json::Error> {
        let job_type = self.job_type();
        let payload = serde_json::to_value(&self)?;
        Ok(Job::new(job_type, payload))
    }
}

// ============================================================================
// Embedding Job Service Trait
// ============================================================================

/// Token usage statistics for embedding operations.
///
/// This mirrors `TokenUsage` from `epigraph-embeddings` but is defined here
/// to avoid a hard dependency, allowing the jobs crate to be used independently.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmbeddingTokenUsage {
    /// Total tokens used in the request
    pub total_tokens: usize,
    /// Prompt tokens (for embedding, this equals total)
    pub prompt_tokens: usize,
}

impl EmbeddingTokenUsage {
    /// Create new token usage record
    #[must_use]
    pub const fn new(total_tokens: usize) -> Self {
        Self {
            total_tokens,
            prompt_tokens: total_tokens,
        }
    }

    /// Add usage from another record
    pub const fn add(&mut self, other: &Self) {
        self.total_tokens += other.total_tokens;
        self.prompt_tokens += other.prompt_tokens;
    }
}

/// Error types for embedding job operations.
///
/// These map to common embedding service errors and are used by the
/// `EmbeddingJobService` trait.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EmbeddingJobError {
    /// The input text was empty
    #[error("Cannot generate embedding for empty text")]
    EmptyText,

    /// The embedding dimension does not match expected
    #[error("Embedding dimension mismatch: expected {expected}, got {actual}")]
    DimensionMismatch {
        /// Expected dimension
        expected: usize,
        /// Actual dimension received
        actual: usize,
    },

    /// API rate limit exceeded
    #[error("Rate limit exceeded, retry after {retry_after_secs} seconds")]
    RateLimitExceeded {
        /// Seconds to wait before retrying
        retry_after_secs: u64,
    },

    /// API request failed
    #[error("API error: {message}")]
    ApiError {
        /// Error message from the API
        message: String,
    },

    /// The embedding was not found in storage
    #[error("Embedding not found for claim {claim_id}")]
    NotFound {
        /// The claim ID that was not found
        claim_id: Uuid,
    },

    /// Claim text not found
    #[error("Claim not found: {claim_id}")]
    ClaimNotFound {
        /// The claim ID that was not found
        claim_id: Uuid,
    },

    /// The claim gained a vector while the job was calling the provider, so
    /// the store wrote nothing rather than overwrite it (backlog 1b83b2a1).
    ///
    /// Not a failure: [`ConfigurableEmbeddingHandler`] completes the job as a
    /// skip when `generate_and_store` returns it.
    #[error("Claim {claim_id} already has an embedding")]
    AlreadyEmbedded {
        /// The claim that already carries a vector
        claim_id: Uuid,
    },
}

/// Service trait for embedding generation in job handlers.
///
/// This trait abstracts the embedding service to enable:
/// - Testing with mock implementations
/// - Production use with real embedding providers (`OpenAI`, local models)
/// - Different storage backends (in-memory, database, vector DB)
///
/// # Design
///
/// The trait combines claim lookup and embedding operations because
/// the job handler needs both. Implementations can internally use
/// separate repositories for claims and embeddings.
#[allow(clippy::double_must_use)] // async_trait's generated #[must_use] on an already-must-use boxed future
#[async_trait]
pub trait EmbeddingJobService: Send + Sync {
    /// Get the text content of a claim by ID.
    ///
    /// Returns `None` if the claim does not exist.
    async fn get_claim_text(&self, claim_id: Uuid) -> Option<String>;

    /// Whether the claim already carries a stored vector.
    ///
    /// The handler asks this first and, on `Ok(true)`, completes the job as a
    /// skip without reading the text or calling the provider (backlog
    /// 1b83b2a1): the job exists to fill a missing vector, and an inline write
    /// may have filled it since the job was enqueued. Required rather than
    /// defaulted to `Ok(false)`, so an implementor cannot opt out silently.
    ///
    /// # Errors
    /// An `EmbeddingJobError` when the check itself could not run; the handler
    /// classifies it like a store error.
    async fn already_embedded(&self, claim_id: Uuid) -> Result<bool, EmbeddingJobError>;

    /// Generate an embedding for the text and store it for the claim, without
    /// overwriting a vector the claim gained in the meantime.
    ///
    /// # Arguments
    /// * `claim_id` - The claim ID to associate with the embedding
    /// * `text` - The text to generate an embedding for
    ///
    /// # Returns
    /// * `Ok(Vec<f32>)` - The generated embedding vector
    /// * `Err(EmbeddingJobError::AlreadyEmbedded)` - The claim gained a vector
    ///   during the provider call; nothing was stored (the handler skips)
    /// * `Err(EmbeddingJobError)` - If generation or storage fails
    async fn generate_and_store(
        &self,
        claim_id: Uuid,
        text: &str,
    ) -> Result<Vec<f32>, EmbeddingJobError>;

    /// Get the configured embedding dimension.
    ///
    /// Standard dimensions: 384 (`MiniLM`), 768 (BERT), 1024, 1536 (`OpenAI`)
    fn dimension(&self) -> usize;

    /// Get cumulative token usage statistics.
    fn token_usage(&self) -> EmbeddingTokenUsage;
}

// ============================================================================
// Configurable Embedding Generation Handler
// ============================================================================

/// A configurable embedding generation handler that uses dependency injection.
///
/// This handler can be configured with any implementation of `EmbeddingJobService`,
/// making it suitable for both production use (with real embedding providers)
/// and testing (with mock services).
pub struct ConfigurableEmbeddingHandler<S: EmbeddingJobService> {
    embedding_service: Arc<S>,
}

impl<S: EmbeddingJobService> ConfigurableEmbeddingHandler<S> {
    /// Create a new handler with the given embedding service.
    pub const fn new(embedding_service: Arc<S>) -> Self {
        Self { embedding_service }
    }
}

#[async_trait]
impl<S: EmbeddingJobService + 'static> JobHandler for ConfigurableEmbeddingHandler<S> {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        // Step 1: Parse the job payload to extract claim_id
        let epigraph_job: EpiGraphJob =
            serde_json::from_value(job.payload.clone()).map_err(|e| JobError::PayloadError {
                message: format!("Failed to deserialize job payload: {e}"),
            })?;

        // A payload of another variant will never become an embedding job, so
        // retrying it only spends the budget: permanent.
        let EpiGraphJob::EmbeddingGeneration { claim_id } = epigraph_job else {
            return Err(JobError::PermanentFailure {
                message: "Expected EmbeddingGeneration job".to_string(),
            });
        };

        let start = std::time::Instant::now();

        // Step 2: A claim that already has a vector is done: no text read, no
        // provider call, nothing stored (backlog 1b83b2a1). The job fills a
        // missing vector; an inline write may have filled it since enqueue.
        if self
            .embedding_service
            .already_embedded(claim_id)
            .await
            .map_err(embedding_job_error)?
        {
            return Ok(already_embedded_result(claim_id, start.elapsed()));
        }

        // Step 3: Get the claim text from the service. `None` stays TRANSIENT:
        // the service also answers `None` when it could not get a connection
        // or the read failed, which a later run may not hit.
        let claim_text = self
            .embedding_service
            .get_claim_text(claim_id)
            .await
            .ok_or_else(|| JobError::ProcessingFailed {
                message: format!("Claim not found: {claim_id}"),
            })?;

        // Step 4: Generate and store the embedding. A vector that landed
        // during the provider call is kept, and the job completes as a skip
        // rather than failing a claim that has what the job was for.
        let embedding = match self
            .embedding_service
            .generate_and_store(claim_id, &claim_text)
            .await
        {
            Ok(embedding) => embedding,
            Err(EmbeddingJobError::AlreadyEmbedded { .. }) => {
                return Ok(already_embedded_result(claim_id, start.elapsed()));
            }
            Err(e) => return Err(embedding_job_error(e)),
        };

        let execution_duration = start.elapsed();

        // Step 5: Get token usage for metadata
        let token_usage = self.embedding_service.token_usage();

        // Step 6: Build result metadata
        let mut extra = std::collections::HashMap::new();
        extra.insert(
            "embedding_dimension".to_string(),
            serde_json::json!(embedding.len()),
        );
        extra.insert(
            "tokens_used".to_string(),
            serde_json::json!(token_usage.total_tokens),
        );

        Ok(JobResult {
            output: serde_json::json!({
                "claim_id": claim_id,
                "embedding_dimension": embedding.len(),
                "tokens_used": token_usage.total_tokens,
            }),
            execution_duration,
            metadata: JobResultMetadata {
                worker_id: Some("embedding-worker".to_string()),
                items_processed: Some(1),
                extra,
            },
        })
    }

    fn job_type(&self) -> &'static str {
        "embedding_generation"
    }

    fn max_retries(&self) -> u32 {
        3
    }

    fn backoff(&self, attempt: u32) -> Duration {
        // Exponential backoff: 2^attempt seconds, capped at 1 hour
        let secs = 2u64.saturating_pow(attempt).min(3600);
        Duration::from_secs(secs)
    }
}

/// The result of an `embedding_generation` job whose claim already carries a
/// vector: completed, nothing generated or stored (backlog 1b83b2a1).
fn already_embedded_result(claim_id: Uuid, execution_duration: Duration) -> JobResult {
    let mut extra = std::collections::HashMap::new();
    extra.insert("skipped".to_string(), serde_json::json!("already_embedded"));
    JobResult {
        output: serde_json::json!({
            "claim_id": claim_id,
            "skipped": "already_embedded",
        }),
        execution_duration,
        metadata: JobResultMetadata {
            worker_id: Some("embedding-worker".to_string()),
            items_processed: Some(0),
            extra,
        },
    }
}

/// Classify an [`EmbeddingJobError`] for the runner's retry decision
/// ([`JobError::should_retry`]).
///
/// Permanent: the claim is gone, sealed or retired (`NotFound`,
/// `ClaimNotFound`: a re-run reads the same row), its text is empty, or the
/// provider returns the wrong dimension (a configuration error a retry does not
/// change). Transient: a provider or database error (`ApiError`) and a rate
/// limit, which a later run may not hit.
fn embedding_job_error(e: EmbeddingJobError) -> JobError {
    let message = e.to_string();
    match e {
        EmbeddingJobError::NotFound { .. }
        | EmbeddingJobError::ClaimNotFound { .. }
        | EmbeddingJobError::EmptyText
        | EmbeddingJobError::DimensionMismatch { .. }
        // The handler turns a store's `AlreadyEmbedded` into a skip before it
        // gets here; from anywhere else, a re-run would find the same vector.
        | EmbeddingJobError::AlreadyEmbedded { .. } => JobError::PermanentFailure { message },
        EmbeddingJobError::RateLimitExceeded { .. } | EmbeddingJobError::ApiError { .. } => {
            JobError::ProcessingFailed { message }
        }
    }
}

// ============================================================================
// In-Memory Job Queue (for testing)
// ============================================================================

/// In-memory job queue for testing purposes.
pub struct InMemoryJobQueue {
    jobs: std::sync::RwLock<Vec<Job>>,
}

impl InMemoryJobQueue {
    /// Create a new empty in-memory queue.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            jobs: std::sync::RwLock::new(Vec::new()),
        }
    }
}

impl Default for InMemoryJobQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JobQueue for InMemoryJobQueue {
    async fn enqueue(&self, job: Job) -> Result<JobId, JobError> {
        let id = job.id;
        self.jobs
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(job);
        Ok(id)
    }

    async fn dequeue(&self) -> Option<Job> {
        let mut jobs = self.jobs.write().unwrap_or_else(|e| e.into_inner());
        // Find first pending job (FIFO order)
        jobs.iter()
            .position(|j| j.state == JobState::Pending)
            .map(|idx| jobs.remove(idx))
    }

    async fn update(&self, job: &Job) -> Result<(), JobError> {
        let mut jobs = self.jobs.write().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = jobs.iter_mut().find(|j| j.id == job.id) {
            *existing = job.clone();
        }
        Ok(())
    }

    async fn get(&self, id: JobId) -> Option<Job> {
        self.jobs
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|j| j.id == id)
            .cloned()
    }

    async fn pending_jobs(&self) -> Vec<Job> {
        self.jobs
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|j| j.state == JobState::Pending)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rate limit's retry-after is a floor on the retry delay, not a
    /// replacement for the handler's backoff: the longer of the two wins, in
    /// either direction. Any other error waits the backoff alone.
    /// The worker loop's sleep honours a rate limit up to the cap and no
    /// further, and never shortens the handler's own backoff.
    #[test]
    fn worker_retry_sleep_caps_only_the_rate_limit_extension() {
        let cap = MAX_WORKER_RATE_LIMIT_SLEEP;
        let limited = |secs| JobError::RateLimited {
            retry_after_secs: secs,
        };
        assert_eq!(
            worker_retry_sleep(&limited(600), Duration::ZERO),
            Duration::from_secs(600)
        );
        assert_eq!(
            worker_retry_sleep(&limited(u64::MAX), Duration::from_secs(1)),
            cap
        );
        let long = cap + Duration::from_secs(7200);
        assert_eq!(worker_retry_sleep(&limited(u64::MAX), long), long);
        assert_eq!(
            worker_retry_sleep(
                &JobError::ProcessingFailed {
                    message: "503".into()
                },
                long
            ),
            long
        );
    }

    #[test]
    fn retry_delay_is_the_longer_of_retry_after_and_the_backoff() {
        let limited = JobError::RateLimited {
            retry_after_secs: 600,
        };
        assert_eq!(
            retry_delay(&limited, Duration::from_secs(1)),
            Duration::from_secs(600)
        );
        assert_eq!(
            retry_delay(&limited, Duration::from_secs(3600)),
            Duration::from_secs(3600)
        );
        assert_eq!(
            retry_delay(
                &JobError::ProcessingFailed {
                    message: "503".into()
                },
                Duration::from_secs(4)
            ),
            Duration::from_secs(4)
        );
        assert_eq!(
            retry_delay(
                &JobError::RateLimited {
                    retry_after_secs: u64::MAX
                },
                Duration::ZERO
            ),
            Duration::from_secs(u64::MAX),
            "no overflow; requeue_after clamps the stored delay"
        );
    }

    #[test]
    fn job_id_display() {
        let id = JobId::from_uuid(Uuid::nil());
        assert!(id.to_string().starts_with("job:"));
    }

    #[test]
    fn job_state_terminal() {
        assert!(!JobState::Pending.is_terminal());
        assert!(!JobState::Running.is_terminal());
        assert!(JobState::Completed.is_terminal());
        assert!(JobState::Failed.is_terminal());
        assert!(JobState::Cancelled.is_terminal());
    }
}
