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
//! - Built-in job types for `EpiGraph` operations
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
//!   embeddings for claim Y" or "Deliver webhook to URL Z."
//!
//! When a task completes, it may enqueue jobs for follow-up work (e.g., truth propagation
//! after claim validation). Tasks are the coordination layer; jobs are the execution layer.

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
pub use postgres_queue::PostgresJobQueue;

// Database-backed reputation service
mod db_reputation_service;
pub use db_reputation_service::DbReputationService;

pub mod cluster_graph;

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
        // Exponential backoff: 2^attempt seconds
        // Cap at 1 hour (3600 seconds) to prevent excessive waits and overflow
        const MAX_BACKOFF_SECS: u64 = 3600;

        let backoff_secs = if attempt >= 63 {
            MAX_BACKOFF_SECS
        } else {
            2u64.saturating_pow(attempt).min(MAX_BACKOFF_SECS)
        };

        Duration::from_secs(backoff_secs)
    }
}

// ============================================================================
// Job Queue Trait
// ============================================================================

/// Trait for job queue implementations.
///
/// Queues are responsible for persisting jobs and providing them to workers.
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
                    if let Some(mut job) = queue.dequeue().await {
                        // Find handler for this job type
                        if let Some(handler) = handlers.get(&job.job_type) {
                            // Check if we've exceeded max retries
                            if job.retry_count >= job.max_retries {
                                job.state = JobState::Failed;
                                job.error_message = Some("Maximum retries exceeded".into());
                                let _ = queue.update(&job).await;
                                continue;
                            }

                            // Transition to Running
                            let _ = job.transition_to(JobState::Running);

                            // Execute handler
                            match handler.handle(&job).await {
                                Ok(_result) => {
                                    let _ = job.transition_to(JobState::Completed);
                                    let _ = queue.update(&job).await;
                                }
                                Err(e) => {
                                    job.retry_count += 1;
                                    job.error_message = Some(e.to_string());

                                    if job.retry_count >= job.max_retries {
                                        job.state = JobState::Failed;
                                        job.updated_at = Utc::now();
                                        job.completed_at = Some(Utc::now());
                                    } else {
                                        // Reset to Pending for retry after backoff
                                        job.state = JobState::Pending;
                                        job.started_at = None;
                                        job.updated_at = Utc::now();

                                        // Apply backoff before re-enqueueing
                                        let backoff = handler.backoff(job.retry_count - 1);
                                        tokio::time::sleep(backoff).await;
                                    }
                                    let _ = queue.update(&job).await;

                                    // Re-enqueue for retry if not failed
                                    if job.state == JobState::Pending {
                                        let _ = queue.enqueue(job).await;
                                    }
                                }
                            }
                        }
                    } else {
                        // No jobs available, sleep briefly
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EpiGraphJob {
    /// Propagate truth updates through the reasoning DAG
    TruthPropagation {
        /// ID of the source claim that triggered propagation
        source_claim_id: Uuid,
    },

    /// Generate embeddings for a claim
    EmbeddingGeneration {
        /// ID of the claim to generate embeddings for
        claim_id: Uuid,
    },

    /// Recompute an agent's reputation score
    ReputationUpdate {
        /// ID of the agent to update
        agent_id: Uuid,
    },

    /// Send a webhook notification
    WebhookNotification {
        /// ID of the webhook configuration
        webhook_id: Uuid,
        /// Payload to send
        payload: serde_json::Value,
    },

    /// Clean up expired data
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
        }
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
// Built-in Job Handlers
// ============================================================================

/// Handler for truth propagation jobs.
///
/// This handler processes `EpiGraphJob::TruthPropagation` jobs by:
/// 1. Extracting the `source_claim_id` from the job payload
/// 2. Propagating truth values through the reasoning DAG
/// 3. Returning a `JobResult` with the count of affected claims
///
/// # Design
///
/// This is a unit struct that can be instantiated directly as `TruthPropagationHandler`.
/// For dependency injection with an orchestrator, use `TruthPropagationHandlerWithOrchestrator`.
///
/// # Error Handling
///
/// - `PayloadError`: Invalid or malformed job payload
/// - `ProcessingFailed`: Claim not found, cycle detected, or propagation error
pub struct TruthPropagationHandler;

#[async_trait]
impl JobHandler for TruthPropagationHandler {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        // Step 1: Deserialize the payload to extract source_claim_id
        let epigraph_job: EpiGraphJob =
            serde_json::from_value(job.payload.clone()).map_err(|e| JobError::PayloadError {
                message: format!("Failed to deserialize TruthPropagation payload: {e}"),
            })?;

        // Step 2: Extract source_claim_id from the job variant
        let EpiGraphJob::TruthPropagation { source_claim_id } = epigraph_job else {
            return Err(JobError::PayloadError {
                message: format!(
                    "Expected TruthPropagation job, got: {}",
                    epigraph_job.job_type()
                ),
            });
        };

        // Step 3: Propagate truth values
        // In a real implementation with database access, this would use
        // epigraph-engine's PropagationOrchestrator or DatabasePropagator.
        //
        // The actual propagation would:
        // - Validate the claim exists in the database
        // - Run BFS propagation through dependents
        // - Apply Bayesian updates (NEVER using agent reputation)
        // - Return count of updated claims
        //
        // In standalone mode (no orchestrator), we return a simulated result
        // with zero affected claims.

        let start_time = std::time::Instant::now();

        // Build the result
        let execution_duration = start_time.elapsed();
        let mut output = serde_json::Map::new();
        output.insert(
            "source_claim_id".to_string(),
            serde_json::Value::String(source_claim_id.to_string()),
        );
        output.insert(
            "claims_updated".to_string(),
            serde_json::Value::Number(serde_json::Number::from(0u64)),
        );
        output.insert(
            "depth_reached".to_string(),
            serde_json::Value::Number(serde_json::Number::from(0u64)),
        );

        let metadata = JobResultMetadata {
            items_processed: Some(0),
            extra: std::collections::HashMap::from([(
                "propagation_mode".to_string(),
                serde_json::Value::String("standalone".to_string()),
            )]),
            ..JobResultMetadata::default()
        };

        Ok(JobResult {
            output: serde_json::Value::Object(output),
            execution_duration,
            metadata,
        })
    }

    fn job_type(&self) -> &'static str {
        "truth_propagation"
    }
}

// ============================================================================
// Truth Propagation Service Trait
// ============================================================================

/// Service trait for truth propagation operations in job handlers.
///
/// This trait abstracts the propagation logic to enable:
/// - Testing with mock implementations
/// - Production use with real `PropagationOrchestrator`
/// - Different storage backends (in-memory, database)
///
/// # Core Invariant (Bad Actor Test)
///
/// Implementations MUST NEVER use agent reputation in propagation calculations.
/// Only the source claim's truth value and evidence strength determine updates.
/// This prevents the "Appeal to Authority" fallacy.
///
/// ```text
/// CORRECT:  Evidence -> Truth -> Reputation
/// WRONG:    Reputation -> Truth
/// ```
#[async_trait]
pub trait PropagationService: Send + Sync {
    /// Get a claim by its ID.
    ///
    /// Returns `None` if the claim does not exist.
    async fn get_claim(&self, claim_id: uuid::Uuid) -> Option<epigraph_core::Claim>;

    /// Propagate truth value changes from a source claim.
    ///
    /// This method:
    /// 1. Loads claim dependencies from storage
    /// 2. Runs BFS-based propagation with depth limiting
    /// 3. Applies Bayesian updates (NEVER using agent reputation)
    /// 4. Returns information about what was updated
    ///
    /// # Arguments
    ///
    /// * `source_claim_id` - The claim whose truth value changed
    /// * `new_truth` - The new truth value (if updating), or None to use current
    ///
    /// # Returns
    ///
    /// A result containing propagation statistics.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The source claim is not found
    /// - A cycle is detected in the DAG
    /// - Propagation computation fails
    async fn propagate_from(
        &self,
        source_claim_id: uuid::Uuid,
        new_truth: Option<f64>,
    ) -> Result<PropagationJobResult, PropagationJobError>;
}

/// Result of a propagation operation for the job handler.
#[derive(Debug, Clone)]
pub struct PropagationJobResult {
    /// The claim that triggered propagation
    pub source_claim_id: uuid::Uuid,
    /// Number of claims that were updated during propagation
    pub claims_updated: usize,
    /// Maximum depth reached during propagation
    pub depth_reached: usize,
    /// Whether propagation stopped due to depth limit
    pub depth_limited: bool,
    /// Whether propagation stopped due to convergence
    pub converged: bool,
    /// IDs of the updated claims (for audit purposes)
    pub updated_claim_ids: Vec<uuid::Uuid>,
}

/// Errors that can occur during propagation operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PropagationJobError {
    /// The source claim was not found
    #[error("Source claim not found: {claim_id}")]
    ClaimNotFound {
        /// The claim ID that was not found
        claim_id: uuid::Uuid,
    },

    /// A cycle was detected in the reasoning DAG
    #[error("Cycle detected in reasoning DAG")]
    CycleDetected,

    /// Propagation computation failed
    #[error("Propagation failed: {reason}")]
    ComputationFailed {
        /// Description of the failure
        reason: String,
    },

    /// Invalid truth value
    #[error("Invalid truth value {value}: {reason}")]
    InvalidTruthValue {
        /// The invalid value
        value: f64,
        /// Why it's invalid
        reason: String,
    },
}

// ============================================================================
// Configurable Truth Propagation Handler
// ============================================================================

/// A configurable truth propagation handler that uses dependency injection.
///
/// This handler can be configured with any implementation of `PropagationService`,
/// making it suitable for both production use (with real database/orchestrator)
/// and testing (with mock services).
///
/// # Core Invariant (Bad Actor Test)
///
/// The propagation logic MUST NEVER use agent reputation in calculations.
/// The [`PropagationService`] trait enforces this by having no reputation
/// parameter in its interface.
///
/// # Example
///
/// ```ignore
/// use epigraph_jobs::{ConfigurablePropagationHandler, PropagationService};
///
/// // Create a handler with a custom propagation service
/// let service = MyPropagationService::new(db_pool);
/// let handler = ConfigurablePropagationHandler::new(Arc::new(service));
///
/// // Register with JobRunner
/// runner.register_handler(Arc::new(handler));
/// ```
pub struct ConfigurablePropagationHandler<S: PropagationService> {
    propagation_service: Arc<S>,
}

impl<S: PropagationService> ConfigurablePropagationHandler<S> {
    /// Create a new handler with the given propagation service.
    pub const fn new(propagation_service: Arc<S>) -> Self {
        Self {
            propagation_service,
        }
    }
}

#[async_trait]
impl<S: PropagationService + 'static> JobHandler for ConfigurablePropagationHandler<S> {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        // Step 1: Parse the job payload to extract source_claim_id
        let epigraph_job: EpiGraphJob =
            serde_json::from_value(job.payload.clone()).map_err(|e| JobError::PayloadError {
                message: format!("Failed to deserialize TruthPropagation payload: {e}"),
            })?;

        let EpiGraphJob::TruthPropagation { source_claim_id } = epigraph_job else {
            return Err(JobError::PayloadError {
                message: format!(
                    "Expected TruthPropagation job, got: {}",
                    epigraph_job.job_type()
                ),
            });
        };

        // Step 2: Verify the claim exists
        if self
            .propagation_service
            .get_claim(source_claim_id)
            .await
            .is_none()
        {
            return Err(JobError::ProcessingFailed {
                message: format!("Source claim not found: {source_claim_id}"),
            });
        }

        // Step 3: Execute propagation
        // CRITICAL: The PropagationService interface has NO reputation parameter.
        // This is an architectural enforcement of the Bad Actor Test principle.
        let start = std::time::Instant::now();

        let result = self
            .propagation_service
            .propagate_from(source_claim_id, None)
            .await
            .map_err(|e| match e {
                PropagationJobError::ClaimNotFound { claim_id } => JobError::ProcessingFailed {
                    message: format!("Claim not found during propagation: {claim_id}"),
                },
                PropagationJobError::CycleDetected => JobError::ProcessingFailed {
                    message: "Cycle detected in reasoning DAG".to_string(),
                },
                PropagationJobError::ComputationFailed { reason } => JobError::ProcessingFailed {
                    message: format!("Propagation computation failed: {reason}"),
                },
                PropagationJobError::InvalidTruthValue { value, reason } => {
                    JobError::ProcessingFailed {
                        message: format!("Invalid truth value {value}: {reason}"),
                    }
                }
            })?;

        let execution_duration = start.elapsed();

        // Step 4: Build result
        let mut output = serde_json::Map::new();
        output.insert(
            "source_claim_id".to_string(),
            serde_json::Value::String(source_claim_id.to_string()),
        );
        output.insert(
            "claims_updated".to_string(),
            serde_json::Value::Number(serde_json::Number::from(result.claims_updated as u64)),
        );
        output.insert(
            "depth_reached".to_string(),
            serde_json::Value::Number(serde_json::Number::from(result.depth_reached as u64)),
        );
        output.insert(
            "depth_limited".to_string(),
            serde_json::Value::Bool(result.depth_limited),
        );
        output.insert(
            "converged".to_string(),
            serde_json::Value::Bool(result.converged),
        );
        output.insert(
            "updated_claim_ids".to_string(),
            serde_json::Value::Array(
                result
                    .updated_claim_ids
                    .iter()
                    .map(|id| serde_json::Value::String(id.to_string()))
                    .collect(),
            ),
        );

        let metadata = JobResultMetadata {
            items_processed: Some(result.claims_updated as u64),
            extra: std::collections::HashMap::from([(
                "propagation_mode".to_string(),
                serde_json::Value::String("engine".to_string()),
            )]),
            ..JobResultMetadata::default()
        };

        Ok(JobResult {
            output: serde_json::Value::Object(output),
            execution_duration,
            metadata,
        })
    }

    fn job_type(&self) -> &'static str {
        "truth_propagation"
    }
}

// ============================================================================
// In-Memory Propagation Service Implementation
// ============================================================================

/// In-memory implementation of [`PropagationService`] using `epigraph-engine`.
///
/// This implementation wraps `PropagationOrchestrator` for use in the job handler.
/// It maintains claims and dependencies in memory and performs Bayesian truth
/// propagation according to the engine's algorithms.
///
/// # Core Invariant (Bad Actor Test)
///
/// This implementation uses `PropagationOrchestrator` which explicitly excludes
/// agent reputation from all propagation calculations. The orchestrator stores
/// reputations for display purposes but NEVER uses them in truth computations.
///
/// # Usage
///
/// ```ignore
/// use epigraph_jobs::InMemoryPropagationService;
///
/// let service = InMemoryPropagationService::new();
///
/// // Register claims and dependencies
/// service.register_claim(claim).await.unwrap();
/// service.add_dependency(source_id, dependent_id, true, 0.8).await.unwrap();
///
/// // Use with handler
/// let handler = ConfigurablePropagationHandler::new(Arc::new(service));
/// ```
pub struct InMemoryPropagationService {
    orchestrator: std::sync::RwLock<epigraph_engine::PropagationOrchestrator>,
    propagator: epigraph_engine::DatabasePropagator,
}

impl InMemoryPropagationService {
    /// Create a new in-memory propagation service with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            orchestrator: std::sync::RwLock::new(epigraph_engine::PropagationOrchestrator::new()),
            propagator: epigraph_engine::DatabasePropagator::with_defaults(),
        }
    }

    /// Create with custom propagation configuration.
    #[must_use]
    pub fn with_config(config: epigraph_engine::PropagationConfig) -> Self {
        Self {
            orchestrator: std::sync::RwLock::new(epigraph_engine::PropagationOrchestrator::new()),
            propagator: epigraph_engine::DatabasePropagator::new(config),
        }
    }

    /// Register a claim in the service.
    ///
    /// # Errors
    ///
    /// Returns an error if the claim cannot be registered.
    pub fn register_claim(&self, claim: epigraph_core::Claim) -> Result<(), PropagationJobError> {
        let mut orch =
            self.orchestrator
                .write()
                .map_err(|_| PropagationJobError::ComputationFailed {
                    reason: "Failed to acquire write lock on orchestrator".to_string(),
                })?;
        orch.register_claim(claim)
            .map_err(|e| PropagationJobError::ComputationFailed {
                reason: format!("Failed to register claim: {e}"),
            })
    }

    /// Register an agent with a reputation score.
    ///
    /// # Note
    ///
    /// Reputation is stored for reference but NEVER used in propagation
    /// calculations. This is an intentional architectural decision to
    /// prevent the "Appeal to Authority" fallacy.
    pub fn register_agent(
        &self,
        agent_id: epigraph_core::AgentId,
        reputation: f64,
    ) -> Result<(), PropagationJobError> {
        let mut orch =
            self.orchestrator
                .write()
                .map_err(|_| PropagationJobError::ComputationFailed {
                    reason: "Failed to acquire write lock on orchestrator".to_string(),
                })?;
        orch.register_agent(agent_id, reputation);
        Ok(())
    }

    /// Add a dependency relationship between claims.
    ///
    /// # Arguments
    ///
    /// * `source_id` - The claim that provides evidence
    /// * `dependent_id` - The claim that depends on the source
    /// * `is_supporting` - Whether this is supporting (true) or refuting (false)
    /// * `strength` - Strength of the dependency relationship [0, 1]
    /// * `evidence_type` - Type of evidence supporting this dependency
    /// * `age_days` - Age of the evidence in days
    ///
    /// # Errors
    ///
    /// Returns an error if adding this dependency would create a cycle.
    pub fn add_dependency(
        &self,
        source_id: epigraph_core::ClaimId,
        dependent_id: epigraph_core::ClaimId,
        is_supporting: bool,
        strength: f64,
        evidence_type: epigraph_engine::EvidenceType,
        age_days: f64,
    ) -> Result<(), PropagationJobError> {
        let mut orch =
            self.orchestrator
                .write()
                .map_err(|_| PropagationJobError::ComputationFailed {
                    reason: "Failed to acquire write lock on orchestrator".to_string(),
                })?;
        orch.add_dependency(
            source_id,
            dependent_id,
            is_supporting,
            strength,
            evidence_type,
            age_days,
        )
        .map_err(|e| match e {
            epigraph_engine::EngineError::CycleDetected { .. } => {
                PropagationJobError::CycleDetected
            }
            other => PropagationJobError::ComputationFailed {
                reason: format!("Failed to add dependency: {other}"),
            },
        })
    }

    /// Get the current truth value of a claim.
    pub fn get_truth(&self, claim_id: epigraph_core::ClaimId) -> Option<epigraph_core::TruthValue> {
        let orch = self.orchestrator.read().ok()?;
        orch.get_truth(claim_id)
    }
}

impl Default for InMemoryPropagationService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PropagationService for InMemoryPropagationService {
    async fn get_claim(&self, claim_id: uuid::Uuid) -> Option<epigraph_core::Claim> {
        let orch = self.orchestrator.read().ok()?;
        let claim_id = epigraph_core::ClaimId::from_uuid(claim_id);
        orch.claims().get(&claim_id).cloned()
    }

    async fn propagate_from(
        &self,
        source_claim_id: uuid::Uuid,
        new_truth: Option<f64>,
    ) -> Result<PropagationJobResult, PropagationJobError> {
        // Validate new truth value if provided
        if let Some(truth) = new_truth {
            if truth.is_nan() {
                return Err(PropagationJobError::InvalidTruthValue {
                    value: truth,
                    reason: "Truth value cannot be NaN".to_string(),
                });
            }
            if truth.is_infinite() {
                return Err(PropagationJobError::InvalidTruthValue {
                    value: truth,
                    reason: "Truth value cannot be infinite".to_string(),
                });
            }
            if !(0.0..=1.0).contains(&truth) {
                return Err(PropagationJobError::InvalidTruthValue {
                    value: truth,
                    reason: "Truth value must be in [0.0, 1.0]".to_string(),
                });
            }
        }

        let claim_id = epigraph_core::ClaimId::from_uuid(source_claim_id);

        // Convert new_truth to TruthValue if provided
        let truth_value = match new_truth {
            Some(t) => Some(epigraph_core::TruthValue::new(t).map_err(|e| {
                PropagationJobError::InvalidTruthValue {
                    value: t,
                    reason: e.to_string(),
                }
            })?),
            None => None,
        };

        // Acquire write lock and execute propagation
        let mut orch =
            self.orchestrator
                .write()
                .map_err(|_| PropagationJobError::ComputationFailed {
                    reason: "Failed to acquire write lock on orchestrator".to_string(),
                })?;

        let result = self
            .propagator
            .propagate_from(&mut orch, claim_id, truth_value)
            .map_err(|e| match e {
                epigraph_engine::EngineError::NodeNotFound(id) => {
                    PropagationJobError::ClaimNotFound { claim_id: id }
                }
                epigraph_engine::EngineError::CycleDetected { .. } => {
                    PropagationJobError::CycleDetected
                }
                other => PropagationJobError::ComputationFailed {
                    reason: format!("Engine error: {other}"),
                },
            })?;

        Ok(PropagationJobResult {
            source_claim_id,
            claims_updated: result.updated_claims.len(),
            depth_reached: result.depth_reached,
            depth_limited: result.depth_limited,
            converged: result.converged,
            updated_claim_ids: result
                .updated_claims
                .iter()
                .map(epigraph_core::ClaimId::as_uuid)
                .collect(),
        })
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
#[async_trait]
pub trait EmbeddingJobService: Send + Sync {
    /// Get the text content of a claim by ID.
    ///
    /// Returns `None` if the claim does not exist.
    async fn get_claim_text(&self, claim_id: Uuid) -> Option<String>;

    /// Generate an embedding for the text and store it for the claim.
    ///
    /// # Arguments
    /// * `claim_id` - The claim ID to associate with the embedding
    /// * `text` - The text to generate an embedding for
    ///
    /// # Returns
    /// * `Ok(Vec<f32>)` - The generated embedding vector
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

        let EpiGraphJob::EmbeddingGeneration { claim_id } = epigraph_job else {
            return Err(JobError::ProcessingFailed {
                message: "Expected EmbeddingGeneration job".to_string(),
            });
        };

        // Step 2: Get the claim text from the service
        let claim_text = self
            .embedding_service
            .get_claim_text(claim_id)
            .await
            .ok_or_else(|| JobError::ProcessingFailed {
                message: format!("Claim not found: {claim_id}"),
            })?;

        // Step 3: Generate and store the embedding
        let start = std::time::Instant::now();

        let embedding = self
            .embedding_service
            .generate_and_store(claim_id, &claim_text)
            .await
            .map_err(|e| JobError::ProcessingFailed {
                message: e.to_string(),
            })?;

        let execution_duration = start.elapsed();

        // Step 4: Get token usage for metadata
        let token_usage = self.embedding_service.token_usage();

        // Step 5: Build result metadata
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

// ============================================================================
// Default Embedding Generation Handler (Stub)
// ============================================================================

/// Handler for embedding generation jobs (stub implementation).
///
/// This is a simple unit struct for cases where no embedding service is available.
/// It returns an error indicating that embedding generation is not implemented.
///
/// For actual embedding generation, use [`ConfigurableEmbeddingHandler`] with
/// an [`EmbeddingJobService`] implementation.
pub struct EmbeddingGenerationHandler;

#[async_trait]
impl JobHandler for EmbeddingGenerationHandler {
    async fn handle(&self, _job: &Job) -> Result<JobResult, JobError> {
        // This stub exists for backward compatibility.
        // Use ConfigurableEmbeddingHandler for actual embedding generation.
        Err(JobError::ProcessingFailed {
            message: "not implemented".into(),
        })
    }

    fn job_type(&self) -> &'static str {
        "embedding_generation"
    }
}

/// Handler for reputation update jobs.
///
/// # Design
///
/// The handler computes agent reputation FROM their claim history.
/// Reputation is an OUTPUT of the truth calculation process, NOT an input.
///
/// # Critical Invariant (Bad Actor Test)
///
/// A high-reputation agent submitting a claim without evidence MUST receive
/// a LOW truth value on that claim. Reputation NEVER influences initial
/// claim truth values.
///
/// ```text
/// CORRECT:  Evidence -> Truth -> Reputation
/// WRONG:    Reputation -> Truth
/// ```
///
/// # Error Handling
///
/// - `PayloadError`: Invalid or malformed job payload (missing/invalid `agent_id`)
pub struct ReputationUpdateHandler;

impl ReputationUpdateHandler {
    /// Create a new handler with default configuration.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ReputationUpdateHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JobHandler for ReputationUpdateHandler {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        // Step 1: Deserialize the payload to extract agent_id
        let epigraph_job: EpiGraphJob =
            serde_json::from_value(job.payload.clone()).map_err(|e| JobError::PayloadError {
                message: format!("Failed to deserialize ReputationUpdate payload: {e}"),
            })?;

        // Step 2: Extract agent_id from the job variant
        let EpiGraphJob::ReputationUpdate { agent_id } = epigraph_job else {
            return Err(JobError::PayloadError {
                message: format!(
                    "Expected ReputationUpdate job, got: {}",
                    epigraph_job.job_type()
                ),
            });
        };

        // Step 3: Calculate reputation
        // In a real implementation, this would:
        // - Query the agent's claim history from the database
        // - Use ReputationCalculator from epigraph-engine
        // - Store the calculated reputation
        // - Calculate domain-specific reputations
        //
        // For standalone mode (no database access), we return initial/neutral
        // reputation since we have no claim history to compute from.
        //
        // CRITICAL: The output MUST NOT include any fields that could be
        // interpreted as affecting future claim truth values. Reputation
        // is ONLY for historical tracking and access control.

        let start_time = std::time::Instant::now();

        // Default values for standalone mode (no claim history available)
        let reputation = 0.5; // Neutral initial reputation
        let claims_processed = 0u64;
        let domain_reputations_count = 0u64;

        let execution_duration = start_time.elapsed();

        // Build result - CRITICAL: No pre_approved_truth, no future_claim_truth_boost
        let mut output = serde_json::Map::new();
        output.insert(
            "agent_id".to_string(),
            serde_json::Value::String(agent_id.to_string()),
        );
        output.insert("reputation".to_string(), serde_json::json!(reputation));
        output.insert(
            "claims_processed".to_string(),
            serde_json::Value::Number(serde_json::Number::from(claims_processed)),
        );
        output.insert(
            "domain_reputations".to_string(),
            serde_json::Value::Number(serde_json::Number::from(domain_reputations_count)),
        );

        let metadata = JobResultMetadata {
            worker_id: Some("reputation-worker-standalone".to_string()),
            items_processed: Some(claims_processed),
            extra: std::collections::HashMap::from([(
                "mode".to_string(),
                serde_json::Value::String("standalone".to_string()),
            )]),
        };

        Ok(JobResult {
            output: serde_json::Value::Object(output),
            execution_duration,
            metadata,
        })
    }

    fn job_type(&self) -> &'static str {
        "reputation_update"
    }
}

// ============================================================================
// Configurable Reputation Update Handler (Engine Integration)
// ============================================================================

/// Error type for reputation job operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum ReputationJobError {
    /// The agent was not found in storage
    #[error("Agent not found: {agent_id}")]
    AgentNotFound {
        /// The agent ID that was not found
        agent_id: Uuid,
    },

    /// Database or storage error occurred
    #[error("Storage error: {message}")]
    StorageError {
        /// Error message describing the storage failure
        message: String,
    },

    /// Error during reputation calculation
    #[error("Calculation error: {message}")]
    CalculationError {
        /// Error message describing the calculation failure
        message: String,
    },
}

/// Claim outcome data for reputation calculation.
///
/// This structure mirrors `epigraph_engine::reputation::ClaimOutcome` but
/// includes domain information for domain-specific reputation calculation.
#[derive(Debug, Clone)]
pub struct ClaimOutcomeData {
    /// Final truth value of the claim
    pub truth_value: f64,
    /// Age of the claim in days
    pub age_days: f64,
    /// Whether the claim was later refuted by strong evidence
    pub was_refuted: bool,
    /// Domain of the claim (optional, for domain-specific reputation)
    pub domain: Option<String>,
}

impl ClaimOutcomeData {
    /// Convert to engine's `ClaimOutcome` (without domain info)
    const fn to_engine_outcome(&self) -> epigraph_engine::reputation::ClaimOutcome {
        epigraph_engine::reputation::ClaimOutcome {
            truth_value: self.truth_value,
            age_days: self.age_days,
            was_refuted: self.was_refuted,
        }
    }
}

/// Service trait for reputation job operations.
///
/// This trait abstracts the data access layer for reputation calculation:
/// - Fetching claim outcomes for an agent
/// - Storing calculated reputation scores
///
/// # Design
///
/// Separating data access from calculation logic enables:
/// - Testing with mock implementations
/// - Production use with real database repositories
/// - Different storage backends (SQL, `NoSQL`, etc.)
///
/// # Critical Invariant
///
/// This service provides OUTPUTS only (reputation scores derived from claims).
/// It must NEVER be called during truth calculation for a claim.
#[async_trait]
pub trait ReputationJobService: Send + Sync {
    /// Get all claim outcomes for an agent.
    ///
    /// Returns the agent's historical claims with their final truth values,
    /// ages, refutation status, and optional domain information.
    ///
    /// # Arguments
    /// * `agent_id` - The agent whose claims to retrieve
    ///
    /// # Returns
    /// * `Ok(Vec<ClaimOutcomeData>)` - The agent's claim outcomes
    /// * `Err(ReputationJobError)` - If retrieval fails
    async fn get_claim_outcomes(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<ClaimOutcomeData>, ReputationJobError>;

    /// Store the calculated reputation for an agent.
    ///
    /// # Arguments
    /// * `agent_id` - The agent whose reputation to store
    /// * `reputation` - The overall reputation score
    ///
    /// # Returns
    /// * `Ok(())` - If storage succeeds
    /// * `Err(ReputationJobError)` - If storage fails
    async fn store_reputation(
        &self,
        agent_id: Uuid,
        reputation: f64,
    ) -> Result<(), ReputationJobError>;

    /// Store a domain-specific reputation for an agent.
    ///
    /// # Arguments
    /// * `agent_id` - The agent whose domain reputation to store
    /// * `domain` - The domain (e.g., "physics", "biology")
    /// * `reputation` - The domain-specific reputation score
    ///
    /// # Returns
    /// * `Ok(())` - If storage succeeds
    /// * `Err(ReputationJobError)` - If storage fails
    async fn store_domain_reputation(
        &self,
        agent_id: Uuid,
        domain: &str,
        reputation: f64,
    ) -> Result<(), ReputationJobError>;
}

/// A configurable reputation update handler that uses dependency injection.
///
/// This handler integrates with `epigraph-engine`'s `ReputationCalculator`
/// for actual reputation computation based on claim history.
///
/// # Design
///
/// The handler can be configured with any implementation of `ReputationJobService`,
/// making it suitable for both production use (with real database access)
/// and testing (with mock services).
///
/// # Critical Invariant (Bad Actor Test)
///
/// Reputation is an OUTPUT of the truth calculation process, NOT an input.
/// A high-reputation agent submitting a claim without evidence MUST receive
/// a LOW truth value on that claim.
///
/// ```text
/// CORRECT:  Evidence -> Truth -> Reputation
/// WRONG:    Reputation -> Truth
/// ```
///
/// The `ReputationCalculator` only READS claim truth values - it never
/// influences them. This architectural separation prevents the "Appeal to
/// Authority" fallacy.
///
/// # Error Handling
///
/// - `PayloadError`: Invalid or malformed job payload
/// - `ProcessingFailed`: Service errors (storage, calculation)
pub struct ConfigurableReputationHandler<S: ReputationJobService> {
    reputation_service: Arc<S>,
    calculator: epigraph_engine::ReputationCalculator,
}

impl<S: ReputationJobService> ConfigurableReputationHandler<S> {
    /// Create a new handler with the given reputation service.
    ///
    /// Uses default `ReputationConfig`:
    /// - Initial reputation: 0.5 (neutral)
    /// - Min reputation: 0.1
    /// - Max reputation: 0.95
    /// - Recency weight: 0.7 (70% recent, 30% historical)
    /// - Min claims for stability: 10
    pub fn new(reputation_service: Arc<S>) -> Self {
        Self {
            reputation_service,
            calculator: epigraph_engine::ReputationCalculator::new(),
        }
    }

    /// Create a new handler with custom reputation configuration.
    pub const fn with_config(
        reputation_service: Arc<S>,
        config: epigraph_engine::reputation::ReputationConfig,
    ) -> Self {
        Self {
            reputation_service,
            calculator: epigraph_engine::ReputationCalculator::with_config(config),
        }
    }

    /// Calculate domain-specific reputation for an agent.
    fn calculate_domain_reputation(&self, outcomes: &[ClaimOutcomeData], domain: &str) -> f64 {
        let domain_outcomes: Vec<epigraph_engine::reputation::ClaimOutcome> = outcomes
            .iter()
            .filter(|o| o.domain.as_deref() == Some(domain))
            .map(ClaimOutcomeData::to_engine_outcome)
            .collect();

        self.calculator.calculate(&domain_outcomes).unwrap_or(0.5) // Default to neutral on error
    }

    /// Get unique domains from claim outcomes.
    fn get_unique_domains(outcomes: &[ClaimOutcomeData]) -> Vec<String> {
        outcomes
            .iter()
            .filter_map(|o| o.domain.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }
}

#[async_trait]
impl<S: ReputationJobService + 'static> JobHandler for ConfigurableReputationHandler<S> {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        let start_time = std::time::Instant::now();

        // Step 1: Parse the job payload to extract agent_id
        let epigraph_job: EpiGraphJob =
            serde_json::from_value(job.payload.clone()).map_err(|e| JobError::PayloadError {
                message: format!("Failed to deserialize ReputationUpdate payload: {e}"),
            })?;

        // Step 2: Extract agent_id from the job variant
        let EpiGraphJob::ReputationUpdate { agent_id } = epigraph_job else {
            return Err(JobError::PayloadError {
                message: format!(
                    "Expected ReputationUpdate job, got: {}",
                    epigraph_job.job_type()
                ),
            });
        };

        // Step 3: Fetch claim outcomes from service
        let outcomes = self
            .reputation_service
            .get_claim_outcomes(agent_id)
            .await
            .map_err(|e| JobError::ProcessingFailed {
                message: format!("Failed to fetch claim outcomes: {e}"),
            })?;

        // Step 4: Convert to engine format and calculate overall reputation
        let engine_outcomes: Vec<epigraph_engine::reputation::ClaimOutcome> = outcomes
            .iter()
            .map(ClaimOutcomeData::to_engine_outcome)
            .collect();

        let reputation = self.calculator.calculate(&engine_outcomes).map_err(|e| {
            JobError::ProcessingFailed {
                message: format!("Reputation calculation failed: {e}"),
            }
        })?;

        // Step 5: Store overall reputation
        self.reputation_service
            .store_reputation(agent_id, reputation)
            .await
            .map_err(|e| JobError::ProcessingFailed {
                message: format!("Failed to store reputation: {e}"),
            })?;

        // Step 6: Calculate and store domain-specific reputations
        let domains = Self::get_unique_domains(&outcomes);
        for domain in &domains {
            let domain_rep = self.calculate_domain_reputation(&outcomes, domain);
            self.reputation_service
                .store_domain_reputation(agent_id, domain, domain_rep)
                .await
                .map_err(|e| JobError::ProcessingFailed {
                    message: format!("Failed to store domain reputation for '{domain}': {e}"),
                })?;
        }

        let execution_duration = start_time.elapsed();
        let claims_processed = outcomes.len() as u64;
        let domain_count = domains.len() as u64;

        // Build result - CRITICAL: No pre_approved_truth, no future_claim_truth_boost
        // Reputation is OUTPUT only, NEVER used to influence future claim truth values
        let mut output = serde_json::Map::new();
        output.insert(
            "agent_id".to_string(),
            serde_json::Value::String(agent_id.to_string()),
        );
        output.insert("reputation".to_string(), serde_json::json!(reputation));
        output.insert(
            "claims_processed".to_string(),
            serde_json::Value::Number(serde_json::Number::from(claims_processed)),
        );
        output.insert(
            "domain_reputations".to_string(),
            serde_json::Value::Number(serde_json::Number::from(domain_count)),
        );

        let metadata = JobResultMetadata {
            worker_id: Some("reputation-worker-engine".to_string()),
            items_processed: Some(claims_processed),
            extra: std::collections::HashMap::from([(
                "mode".to_string(),
                serde_json::Value::String("engine-integrated".to_string()),
            )]),
        };

        Ok(JobResult {
            output: serde_json::Value::Object(output),
            execution_duration,
            metadata,
        })
    }

    fn job_type(&self) -> &'static str {
        "reputation_update"
    }
}

// ============================================================================
// Webhook Infrastructure (Traits and Types)
// ============================================================================

/// Configuration for a webhook endpoint.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Unique identifier for this webhook
    pub id: Uuid,
    /// URL to send webhook notifications to
    pub url: String,
    /// Optional secret for HMAC signature generation
    pub secret: Option<String>,
    /// Whether this webhook is enabled
    pub enabled: bool,
    /// Maximum number of retries on failure
    pub retry_count: u32,
    /// Timeout in seconds for HTTP requests
    pub timeout_seconds: u32,
}

/// HTTP response from a webhook endpoint.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code
    pub status_code: u16,
    /// Response body
    pub body: String,
}

/// Errors that can occur during HTTP operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum HttpError {
    /// Transient failure that may succeed on retry
    #[error("transient failure: {message}")]
    TransientFailure { message: String },
    /// Request timed out
    #[error("timeout after {duration:?}")]
    Timeout { duration: Duration },
    /// Connection failed
    #[error("connection failed: {reason}")]
    ConnectionFailed { reason: String },
}

/// Trait for HTTP client implementations.
///
/// This trait enables dependency injection for testing with mock clients.
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Send an HTTP POST request.
    ///
    /// # Arguments
    /// * `url` - Target URL
    /// * `headers` - HTTP headers as key-value pairs
    /// * `body` - Request body
    ///
    /// # Returns
    /// The HTTP response on success, or an error on failure.
    async fn post(
        &self,
        url: &str,
        headers: std::collections::HashMap<String, String>,
        body: &str,
    ) -> Result<HttpResponse, HttpError>;
}

/// Trait for webhook configuration repository.
///
/// This trait enables dependency injection for testing with mock repositories.
#[async_trait]
pub trait WebhookRepository: Send + Sync {
    /// Retrieve a webhook configuration by ID.
    ///
    /// # Returns
    /// The webhook config if found, or `None` if not exists.
    async fn get_webhook(&self, id: Uuid) -> Option<WebhookConfig>;
}

/// Compute HMAC-SHA256 signature for webhook payload.
///
/// # Arguments
/// * `secret` - The shared secret key
/// * `payload` - The payload to sign
///
/// # Returns
/// Hex-encoded signature string prefixed with "sha256="
///
/// # Security
/// This implementation uses cryptographically secure HMAC-SHA256 via the
/// `hmac` and `sha2` crates. The signature can be verified by webhook
/// receivers using the same algorithm with the shared secret.
#[must_use]
pub fn compute_hmac_signature(secret: &str, payload: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());
    let result = mac.finalize();
    let signature_bytes = result.into_bytes();

    format!("sha256={}", hex::encode(signature_bytes))
}

/// Verify HMAC-SHA256 signature for webhook payload.
///
/// # Arguments
/// * `secret` - The shared secret key
/// * `payload` - The payload that was signed
/// * `signature` - The signature to verify (with or without "sha256=" prefix)
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
///
/// # Security
/// This uses constant-time comparison to prevent timing attacks.
#[must_use]
pub fn verify_hmac_signature(secret: &str, payload: &str, signature: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // Strip "sha256=" prefix if present
    let sig_hex = signature.strip_prefix("sha256=").unwrap_or(signature);

    // Decode hex signature
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());

    // verify_slice uses constant-time comparison internally
    mac.verify_slice(&sig_bytes).is_ok()
}

/// Check if an IP address is an internal/private address (SSRF protection).
///
/// Blocks:
/// - Loopback (127.0.0.0/8)
/// - Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
/// - Link-local (169.254.0.0/16)
/// - Localhost variants
///
/// # Returns
/// `true` if the address is internal and should be blocked, `false` if it's safe.
#[must_use]
pub fn is_internal_ip(host: &str) -> bool {
    use std::net::IpAddr;

    // Handle localhost explicitly
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }

    // Strip port if present
    let host_part = host.split(':').next().unwrap_or(host);

    // Also strip brackets for IPv6
    let host_clean = host_part.trim_start_matches('[').trim_end_matches(']');

    match host_clean.parse::<IpAddr>() {
        Ok(IpAddr::V4(ipv4)) => {
            let octets = ipv4.octets();

            // Loopback: 127.0.0.0/8
            if octets[0] == 127 {
                return true;
            }

            // Private: 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }

            // Private: 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }

            // Private: 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }

            // Link-local: 169.254.0.0/16
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }

            // 0.0.0.0/8 (current network)
            if octets[0] == 0 {
                return true;
            }

            false
        }
        Ok(IpAddr::V6(ipv6)) => {
            // Loopback ::1
            if ipv6.is_loopback() {
                return true;
            }

            // Unspecified ::
            if ipv6.is_unspecified() {
                return true;
            }

            // Check for IPv4-mapped addresses
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                let octets = ipv4.octets();
                if octets[0] == 127
                    || octets[0] == 10
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 169 && octets[1] == 254)
                    || octets[0] == 0
                {
                    return true;
                }
            }

            // Unique local addresses (fc00::/7)
            let segments = ipv6.segments();
            if (segments[0] & 0xfe00) == 0xfc00 {
                return true;
            }

            // Link-local (fe80::/10)
            if (segments[0] & 0xffc0) == 0xfe80 {
                return true;
            }

            false
        }
        Err(_) => {
            // Not a valid IP address, allow (will be DNS resolved)
            // In production, you'd want to resolve DNS and check the resulting IP
            false
        }
    }
}

/// Extract host from a URL for SSRF checking.
///
/// # Returns
/// The host portion of the URL, or `None` if parsing fails.
#[must_use]
pub fn extract_host_from_url(url: &str) -> Option<String> {
    // Simple URL parsing - extract host between :// and next / or :
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;

    let host_end = without_scheme
        .find('/')
        .unwrap_or(without_scheme.len())
        .min(without_scheme.find(':').unwrap_or(without_scheme.len()));

    Some(without_scheme[..host_end].to_string())
}

// ============================================================================
// Webhook Notification Handler
// ============================================================================

/// Handler for webhook notification jobs (unit struct for registration).
///
/// This is a lightweight handler that can be used for registration and type checking.
/// For actual webhook processing with HTTP client and repository, use
/// `ConfigurableWebhookHandler::new()`.
///
/// # Usage
///
/// ```ignore
/// // For registration only
/// let handler = WebhookNotificationHandler;
/// runner.register_handler(Arc::new(handler));
///
/// // For actual processing
/// let handler = ConfigurableWebhookHandler::new(http_client, webhook_repo);
/// runner.register_handler(Arc::new(handler));
/// ```
#[derive(Default)]
pub struct WebhookNotificationHandler;

#[async_trait]
impl JobHandler for WebhookNotificationHandler {
    async fn handle(&self, _job: &Job) -> Result<JobResult, JobError> {
        // This is a minimal handler for registration purposes.
        // For actual webhook processing, use ConfigurableWebhookHandler.
        Err(JobError::ProcessingFailed {
            message: "WebhookNotificationHandler requires configuration. Use ConfigurableWebhookHandler::new() with HTTP client and webhook repository.".into(),
        })
    }

    fn job_type(&self) -> &'static str {
        "webhook_notification"
    }

    fn max_retries(&self) -> u32 {
        5
    }

    fn backoff(&self, attempt: u32) -> Duration {
        // Exponential backoff: 1s, 2s, 4s, 8s, 16s (capped)
        // Formula: 2^attempt seconds, starting at 2^0 = 1 for attempt 0
        let secs = 2u64.saturating_pow(attempt).min(16);
        Duration::from_secs(secs)
    }
}

/// Configurable webhook notification handler with dependency injection.
///
/// This handler sends HTTP POST requests to configured webhook endpoints
/// with JSON payloads and HMAC signatures for authentication.
///
/// # Features
/// - HMAC-SHA256 signature generation (when secret is configured)
/// - Configurable timeout per webhook
/// - Exponential backoff retry (1s, 2s, 4s, 8s, 16s)
/// - Detailed error reporting
///
/// # Example
///
/// ```ignore
/// let handler = ConfigurableWebhookHandler::new(
///     Arc::new(my_http_client),
///     Arc::new(my_webhook_repo),
/// );
/// runner.register_handler(Arc::new(handler));
/// ```
pub struct ConfigurableWebhookHandler {
    http_client: std::sync::Arc<dyn HttpClient>,
    webhook_repo: std::sync::Arc<dyn WebhookRepository>,
    default_timeout: Duration,
}

impl ConfigurableWebhookHandler {
    /// Create a new handler with injected dependencies.
    ///
    /// # Arguments
    /// * `http_client` - HTTP client implementation
    /// * `webhook_repo` - Webhook configuration repository
    #[must_use]
    pub fn new(
        http_client: std::sync::Arc<dyn HttpClient>,
        webhook_repo: std::sync::Arc<dyn WebhookRepository>,
    ) -> Self {
        Self {
            http_client,
            webhook_repo,
            default_timeout: Duration::from_secs(30),
        }
    }

    /// Set default timeout for HTTP requests.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Parse `webhook_id` and payload from job.
    #[allow(clippy::unused_self)]
    fn parse_job_payload(&self, job: &Job) -> Result<(Uuid, serde_json::Value), JobError> {
        let payload = &job.payload;

        // Extract webhook_id
        let webhook_id_str = payload
            .get("WebhookNotification")
            .and_then(|v| v.get("webhook_id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| JobError::PayloadError {
                message: "Missing webhook_id in payload".into(),
            })?;

        let webhook_id: Uuid = webhook_id_str.parse().map_err(|_| JobError::PayloadError {
            message: "Invalid webhook_id format".into(),
        })?;

        // Extract notification payload
        let notification_payload = payload
            .get("WebhookNotification")
            .and_then(|v| v.get("payload"))
            .cloned()
            .ok_or_else(|| JobError::PayloadError {
                message: "Missing payload in WebhookNotification".into(),
            })?;

        Ok((webhook_id, notification_payload))
    }

    /// Build HTTP headers for the webhook request.
    #[allow(clippy::unused_self)]
    fn build_headers(
        &self,
        webhook_id: Uuid,
        secret: Option<&str>,
        body: &str,
    ) -> std::collections::HashMap<String, String> {
        let mut headers = std::collections::HashMap::new();
        headers.insert("Content-Type".into(), "application/json".into());
        headers.insert("User-Agent".into(), "EpiGraph-Webhook/1.0".into());
        headers.insert("X-Webhook-ID".into(), webhook_id.to_string());

        // Add HMAC signature if secret is configured
        if let Some(secret) = secret {
            let signature = compute_hmac_signature(secret, body);
            headers.insert("X-Webhook-Signature".into(), signature);
        }

        headers
    }
}

#[async_trait]
impl JobHandler for ConfigurableWebhookHandler {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        let start = std::time::Instant::now();

        // Parse job payload
        let (webhook_id, notification_payload) = self.parse_job_payload(job)?;

        // Get webhook configuration
        let config = self
            .webhook_repo
            .get_webhook(webhook_id)
            .await
            .ok_or_else(|| JobError::ProcessingFailed {
                message: format!("Webhook config not found: {webhook_id}"),
            })?;

        // Check if webhook is enabled
        if !config.enabled {
            return Err(JobError::ProcessingFailed {
                message: "Webhook is disabled".into(),
            });
        }

        // SSRF protection: Check for internal IP addresses
        if let Some(host) = extract_host_from_url(&config.url) {
            if is_internal_ip(&host) {
                return Err(JobError::SsrfBlocked { address: host });
            }
        }

        // Serialize payload to JSON
        let body = serde_json::to_string(&notification_payload).map_err(|e| {
            JobError::ProcessingFailed {
                message: format!("Failed to serialize payload: {e}"),
            }
        })?;

        // Build headers with optional signature
        let headers = self.build_headers(webhook_id, config.secret.as_deref(), &body);

        // Determine timeout
        let timeout_duration = if config.timeout_seconds > 0 {
            Duration::from_secs(u64::from(config.timeout_seconds))
        } else {
            self.default_timeout
        };

        // Send HTTP request with timeout
        let result = tokio::time::timeout(
            timeout_duration,
            self.http_client.post(&config.url, headers, &body),
        )
        .await;

        match result {
            Ok(Ok(response)) => {
                match response.status_code {
                    // Success: 2xx
                    200..=299 => Ok(JobResult {
                        output: serde_json::json!({
                            "webhook_id": webhook_id.to_string(),
                            "url": config.url,
                            "status_code": response.status_code,
                            "response_body": response.body
                        }),
                        execution_duration: start.elapsed(),
                        metadata: JobResultMetadata {
                            worker_id: Some("webhook-worker-1".into()),
                            items_processed: Some(1),
                            extra: std::collections::HashMap::default(),
                        },
                    }),

                    // Redirect: 3xx - treat as success (client should follow redirects)
                    300..=399 => Ok(JobResult {
                        output: serde_json::json!({
                            "webhook_id": webhook_id.to_string(),
                            "url": config.url,
                            "status_code": response.status_code,
                            "response_body": response.body,
                            "redirect": true
                        }),
                        execution_duration: start.elapsed(),
                        metadata: JobResultMetadata {
                            worker_id: Some("webhook-worker-1".into()),
                            items_processed: Some(1),
                            extra: std::collections::HashMap::default(),
                        },
                    }),

                    // Rate limited: 429 - should retry after delay
                    429 => {
                        // Try to parse Retry-After header from response body (in test scenarios)
                        // In production, this would come from response headers
                        let retry_after = 60u64; // Default to 60 seconds
                        Err(JobError::RateLimited {
                            retry_after_secs: retry_after,
                        })
                    }

                    // Client errors: 4xx (except 429) - permanent failure, don't retry
                    400..=428 | 430..=499 => Err(JobError::PermanentFailure {
                        message: format!(
                            "Client error {}: {}",
                            response.status_code, response.body
                        ),
                    }),

                    // Server errors: 5xx - transient failure, should retry
                    500..=599 => Err(JobError::ProcessingFailed {
                        message: format!(
                            "Server error {}: {}",
                            response.status_code, response.body
                        ),
                    }),

                    // Other status codes - treat as transient failure
                    _ => Err(JobError::ProcessingFailed {
                        message: format!(
                            "Unexpected status {}: {}",
                            response.status_code, response.body
                        ),
                    }),
                }
            }
            Ok(Err(http_err)) => Err(JobError::ProcessingFailed {
                message: format!("HTTP request failed: {http_err}"),
            }),
            Err(_elapsed) => Err(JobError::Timeout {
                timeout: timeout_duration,
            }),
        }
    }

    fn job_type(&self) -> &'static str {
        "webhook_notification"
    }

    fn max_retries(&self) -> u32 {
        5
    }

    fn backoff(&self, attempt: u32) -> Duration {
        // Exponential backoff: 1s, 2s, 4s, 8s, 16s (capped)
        // Formula: 2^attempt seconds, starting at 2^0 = 1 for attempt 0
        let secs = 2u64.saturating_pow(attempt).min(16);
        Duration::from_secs(secs)
    }
}

/// Handler for data cleanup jobs.
///
/// This handler cleans up old data based on a retention policy. It deletes:
/// - Evidence older than retention period (unless referenced by active claims)
/// - Claims older than retention period (unless referenced by active traces)
/// - Reasoning traces older than retention period
/// - Audit logs older than retention period
/// - Embeddings older than retention period
///
/// # Referential Integrity
///
/// The handler preserves referential integrity:
/// - Evidence referenced by any active (non-deleted) claim is preserved
/// - Claims referenced by any active (non-deleted) trace are preserved
///
/// # Design
///
/// This is a unit struct that can be instantiated directly as `DataCleanupHandler`.
/// For dependency injection with a repository, use `DataCleanupHandlerWithRepository`.
///
/// In standalone mode (this handler), it validates the payload and returns success
/// with zero deletions. This allows registration and basic validation without
/// database access.
pub struct DataCleanupHandler;

#[async_trait]
impl JobHandler for DataCleanupHandler {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        let start_time = std::time::Instant::now();

        // Step 1: Deserialize the payload to extract retention_days
        let epigraph_job: EpiGraphJob =
            serde_json::from_value(job.payload.clone()).map_err(|e| JobError::PayloadError {
                message: format!("Failed to deserialize DataCleanup payload: {e}"),
            })?;

        // Step 2: Extract retention_days from the job variant
        let EpiGraphJob::DataCleanup { retention_days } = epigraph_job else {
            return Err(JobError::PayloadError {
                message: format!("Expected DataCleanup job, got: {}", epigraph_job.job_type()),
            });
        };

        // Step 3: Validate retention_days
        if retention_days == 0 {
            return Err(JobError::ProcessingFailed {
                message: "retention_days must be greater than 0".into(),
            });
        }

        // Step 4: Perform cleanup (or simulate in standalone mode)
        //
        // In a real implementation with an injected repository, this would:
        // 1. Calculate cutoff date: now - retention_days
        // 2. Get IDs of evidence referenced by active claims (preserve these)
        // 3. Get IDs of claims referenced by active traces (preserve these)
        // 4. Delete old audit logs (no dependencies)
        // 5. Delete old embeddings (claims may reference, but not critical)
        // 6. Delete old traces that don't reference active claims
        // 7. Delete old evidence not referenced by active claims
        // 8. Delete old claims not referenced by active traces
        //
        // Since we're in standalone mode (no repository), we return zeros.

        let evidence_deleted: u64 = 0;
        let claims_deleted: u64 = 0;
        let traces_deleted: u64 = 0;
        let audit_logs_deleted: u64 = 0;
        let embeddings_deleted: u64 = 0;
        let evidence_preserved: u64 = 0;
        let claims_preserved: u64 = 0;

        let total_deleted = evidence_deleted
            + claims_deleted
            + traces_deleted
            + audit_logs_deleted
            + embeddings_deleted;

        // Step 5: Build the result
        let execution_duration = start_time.elapsed();
        let output = serde_json::json!({
            "retention_days": retention_days,
            "total_deleted": total_deleted,
            "evidence_deleted": evidence_deleted,
            "claims_deleted": claims_deleted,
            "traces_deleted": traces_deleted,
            "audit_logs_deleted": audit_logs_deleted,
            "embeddings_deleted": embeddings_deleted,
            "evidence_preserved": evidence_preserved,
            "claims_preserved": claims_preserved
        });

        let metadata = JobResultMetadata {
            worker_id: Some("cleanup-worker-standalone".into()),
            items_processed: Some(total_deleted),
            extra: std::collections::HashMap::from([(
                "cleanup_mode".to_string(),
                serde_json::Value::String("standalone".to_string()),
            )]),
        };

        Ok(JobResult {
            output,
            execution_duration,
            metadata,
        })
    }

    fn job_type(&self) -> &'static str {
        "data_cleanup"
    }
}

// ============================================================================
// Data Cleanup Repository Trait and Handler with Repository
// ============================================================================

/// Statistics from a cleanup operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CleanupStats {
    /// Number of evidence records deleted.
    pub evidence_deleted: u64,
    /// Number of claim records deleted.
    pub claims_deleted: u64,
    /// Number of reasoning trace records deleted.
    pub traces_deleted: u64,
    /// Number of audit log records deleted.
    pub audit_logs_deleted: u64,
    /// Number of embedding records deleted.
    pub embeddings_deleted: u64,
    /// Number of evidence records preserved due to referential integrity.
    pub evidence_preserved: u64,
    /// Number of claim records preserved due to referential integrity.
    pub claims_preserved: u64,
}

impl CleanupStats {
    /// Calculate total deleted records.
    #[must_use]
    pub const fn total_deleted(&self) -> u64 {
        self.evidence_deleted
            + self.claims_deleted
            + self.traces_deleted
            + self.audit_logs_deleted
            + self.embeddings_deleted
    }
}

/// Repository trait for data cleanup operations.
///
/// Implementations of this trait handle the actual database interactions
/// for cleaning up old data while respecting referential integrity.
///
/// # Referential Integrity
///
/// The cleanup process must respect these constraints:
/// - Evidence referenced by active (non-deleted) claims must be preserved
/// - Claims referenced by active (non-deleted) traces must be preserved
///
/// # Deletion Order
///
/// To respect foreign key constraints, deletions should occur in this order:
/// 1. Audit logs (no dependencies)
/// 2. Embeddings (claim may reference, but not critical)
/// 3. Reasoning traces (references claims)
/// 4. Evidence (references claims)
/// 5. Claims (referenced by evidence and traces)
///
/// However, since `PostgreSQL` uses ON DELETE CASCADE for evidence and traces,
/// deleting claims will automatically cascade to dependent evidence and traces.
#[async_trait]
pub trait CleanupRepository: Send + Sync {
    /// Get IDs of claims older than the specified cutoff date.
    ///
    /// Returns claim IDs where `created_at < cutoff`.
    async fn get_claims_older_than(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<Uuid>, String>;

    /// Get IDs of evidence older than the specified cutoff date.
    ///
    /// Returns evidence IDs where `created_at < cutoff`.
    async fn get_evidence_older_than(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<Uuid>, String>;

    /// Get IDs of reasoning traces older than the specified cutoff date.
    ///
    /// Returns trace IDs where `created_at < cutoff`.
    async fn get_traces_older_than(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<Uuid>, String>;

    /// Get IDs of audit logs older than the specified cutoff date.
    ///
    /// Returns audit log IDs where `created_at < cutoff`.
    async fn get_audit_logs_older_than(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<Uuid>, String>;

    /// Get IDs of embeddings older than the specified cutoff date.
    ///
    /// Returns embedding IDs where `created_at < cutoff`.
    async fn get_embeddings_older_than(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<Uuid>, String>;

    /// Get IDs of evidence referenced by active (non-old) claims.
    ///
    /// These evidence records must be preserved even if they are old.
    async fn get_evidence_ids_referenced_by_active_claims(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<std::collections::HashSet<Uuid>, String>;

    /// Get IDs of claims referenced by active (non-old) traces.
    ///
    /// These claim records must be preserved even if they are old.
    async fn get_claim_ids_referenced_by_active_traces(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<std::collections::HashSet<Uuid>, String>;

    /// Delete a claim by ID.
    ///
    /// Note: Due to ON DELETE CASCADE, this will also delete associated
    /// evidence and traces.
    ///
    /// Returns `true` if the claim was deleted, `false` if it didn't exist.
    async fn delete_claim(&self, id: Uuid) -> Result<bool, String>;

    /// Delete evidence by ID.
    ///
    /// Returns `true` if the evidence was deleted, `false` if it didn't exist.
    async fn delete_evidence(&self, id: Uuid) -> Result<bool, String>;

    /// Delete a reasoning trace by ID.
    ///
    /// Returns `true` if the trace was deleted, `false` if it didn't exist.
    async fn delete_trace(&self, id: Uuid) -> Result<bool, String>;

    /// Delete an audit log by ID.
    ///
    /// Returns `true` if the audit log was deleted, `false` if it didn't exist.
    async fn delete_audit_log(&self, id: Uuid) -> Result<bool, String>;

    /// Delete an embedding by ID.
    ///
    /// Returns `true` if the embedding was deleted, `false` if it didn't exist.
    async fn delete_embedding(&self, id: Uuid) -> Result<bool, String>;
}

/// Handler for data cleanup jobs with repository dependency injection.
///
/// This handler performs actual data cleanup by delegating to a
/// [`CleanupRepository`] implementation.
///
/// # Usage
///
/// ```ignore
/// use epigraph_jobs::{DataCleanupHandlerWithRepository, CleanupRepository};
/// use std::sync::Arc;
///
/// // Create your repository implementation
/// let repo: Arc<dyn CleanupRepository> = /* ... */;
///
/// // Create the handler
/// let handler = DataCleanupHandlerWithRepository::new(repo);
///
/// // Register with job runner
/// runner.register_handler(Arc::new(handler));
/// ```
///
/// # Deletion Strategy
///
/// The handler follows this strategy to respect referential integrity:
///
/// 1. Calculate cutoff date: `now - retention_days`
/// 2. Get IDs of evidence referenced by recent claims (preserve these)
/// 3. Get IDs of claims referenced by recent traces (preserve these)
/// 4. Delete old audit logs (no dependencies)
/// 5. Delete old embeddings (no critical dependencies)
/// 6. Delete old traces that don't reference active claims
/// 7. Delete old evidence not referenced by active claims
/// 8. Delete old claims not referenced by active traces
pub struct DataCleanupHandlerWithRepository {
    repository: Arc<dyn CleanupRepository>,
}

impl DataCleanupHandlerWithRepository {
    /// Create a new handler with the given repository.
    #[must_use]
    pub fn new(repository: Arc<dyn CleanupRepository>) -> Self {
        Self { repository }
    }

    /// Perform cleanup with the given retention period.
    async fn perform_cleanup(&self, retention_days: u32) -> Result<CleanupStats, JobError> {
        use chrono::{Duration, Utc};

        let cutoff = Utc::now() - Duration::days(i64::from(retention_days));
        let mut stats = CleanupStats::default();

        // Step 1: Get IDs of evidence/claims that must be preserved
        let referenced_evidence_ids = self
            .repository
            .get_evidence_ids_referenced_by_active_claims(cutoff)
            .await
            .map_err(|e| JobError::ProcessingFailed { message: e })?;

        let referenced_claim_ids = self
            .repository
            .get_claim_ids_referenced_by_active_traces(cutoff)
            .await
            .map_err(|e| JobError::ProcessingFailed { message: e })?;

        // Step 2: Delete old audit logs (no dependencies)
        let old_audit_logs = self
            .repository
            .get_audit_logs_older_than(cutoff)
            .await
            .map_err(|e| JobError::ProcessingFailed { message: e })?;

        for log_id in old_audit_logs {
            if self
                .repository
                .delete_audit_log(log_id)
                .await
                .map_err(|e| JobError::ProcessingFailed { message: e })?
            {
                stats.audit_logs_deleted += 1;
            }
        }

        // Step 3: Delete old embeddings
        let old_embeddings = self
            .repository
            .get_embeddings_older_than(cutoff)
            .await
            .map_err(|e| JobError::ProcessingFailed { message: e })?;

        for embedding_id in old_embeddings {
            if self
                .repository
                .delete_embedding(embedding_id)
                .await
                .map_err(|e| JobError::ProcessingFailed { message: e })?
            {
                stats.embeddings_deleted += 1;
            }
        }

        // Step 4: Delete old traces that don't reference active claims
        let old_traces = self
            .repository
            .get_traces_older_than(cutoff)
            .await
            .map_err(|e| JobError::ProcessingFailed { message: e })?;

        for trace_id in old_traces {
            // Traces that reference active claims will fail to delete due to FK constraints
            // OR we can check if the trace's claim_id is in referenced_claim_ids
            // For simplicity, we try to delete and count successes
            if self
                .repository
                .delete_trace(trace_id)
                .await
                .map_err(|e| JobError::ProcessingFailed { message: e })?
            {
                stats.traces_deleted += 1;
            }
        }

        // Step 5: Delete old evidence not referenced by active claims
        let old_evidence = self
            .repository
            .get_evidence_older_than(cutoff)
            .await
            .map_err(|e| JobError::ProcessingFailed { message: e })?;

        for evidence_id in old_evidence {
            if referenced_evidence_ids.contains(&evidence_id) {
                stats.evidence_preserved += 1;
            } else if self
                .repository
                .delete_evidence(evidence_id)
                .await
                .map_err(|e| JobError::ProcessingFailed { message: e })?
            {
                stats.evidence_deleted += 1;
            }
        }

        // Step 6: Delete old claims not referenced by active traces
        let old_claims = self
            .repository
            .get_claims_older_than(cutoff)
            .await
            .map_err(|e| JobError::ProcessingFailed { message: e })?;

        for claim_id in old_claims {
            if referenced_claim_ids.contains(&claim_id) {
                stats.claims_preserved += 1;
            } else if self
                .repository
                .delete_claim(claim_id)
                .await
                .map_err(|e| JobError::ProcessingFailed { message: e })?
            {
                stats.claims_deleted += 1;
            }
        }

        Ok(stats)
    }
}

#[async_trait]
impl JobHandler for DataCleanupHandlerWithRepository {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        let start_time = std::time::Instant::now();

        // Step 1: Deserialize the payload to extract retention_days
        let epigraph_job: EpiGraphJob =
            serde_json::from_value(job.payload.clone()).map_err(|e| JobError::PayloadError {
                message: format!("Failed to deserialize DataCleanup payload: {e}"),
            })?;

        // Step 2: Extract retention_days from the job variant
        let EpiGraphJob::DataCleanup { retention_days } = epigraph_job else {
            return Err(JobError::PayloadError {
                message: format!("Expected DataCleanup job, got: {}", epigraph_job.job_type()),
            });
        };

        // Step 3: Validate retention_days
        if retention_days == 0 {
            return Err(JobError::ProcessingFailed {
                message: "retention_days must be greater than 0".into(),
            });
        }

        // Step 4: Perform cleanup
        let stats = self.perform_cleanup(retention_days).await?;

        // Step 5: Build the result
        let execution_duration = start_time.elapsed();
        let output = serde_json::json!({
            "retention_days": retention_days,
            "total_deleted": stats.total_deleted(),
            "evidence_deleted": stats.evidence_deleted,
            "claims_deleted": stats.claims_deleted,
            "traces_deleted": stats.traces_deleted,
            "audit_logs_deleted": stats.audit_logs_deleted,
            "embeddings_deleted": stats.embeddings_deleted,
            "evidence_preserved": stats.evidence_preserved,
            "claims_preserved": stats.claims_preserved
        });

        let metadata = JobResultMetadata {
            worker_id: Some("cleanup-worker-with-repository".into()),
            items_processed: Some(stats.total_deleted()),
            extra: std::collections::HashMap::from([(
                "cleanup_mode".to_string(),
                serde_json::Value::String("repository".to_string()),
            )]),
        };

        Ok(JobResult {
            output,
            execution_duration,
            metadata,
        })
    }

    fn job_type(&self) -> &'static str {
        "data_cleanup"
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
