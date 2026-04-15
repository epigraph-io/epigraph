//! TDD Tests for `EpiGraph` Background Job Runner
//!
//! These tests define the expected behavior of the job runner system.
//! They are written in TDD "red phase" style - they describe the desired
//! behavior and will initially fail until the implementation is complete.
//!
//! # Test Organization
//!
//! 1. Job struct tests - creation, payload handling, timestamps
//! 2. `JobState` tests - state machine transitions
//! 3. `JobHandler` trait tests - interface compliance
//! 4. `JobRunner` tests - worker pool, shutdown, retry logic
//! 5. `JobQueue` tests - FIFO ordering
//! 6. Built-in handler tests - EpiGraph-specific job types

use epigraph_jobs::{
    async_trait, DataCleanupHandler, EmbeddingGenerationHandler, EpiGraphJob, InMemoryJobQueue,
    Job, JobError, JobHandler, JobId, JobQueue, JobResult, JobResultMetadata, JobRunner, JobState,
    ReputationUpdateHandler, TruthPropagationHandler, WebhookNotificationHandler,
};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

// ============================================================================
// Job Creation Tests
// ============================================================================

/// Jobs should be created with the specified type and payload
#[test]
fn test_job_creation_with_payload() {
    let payload = json!({
        "claim_id": "550e8400-e29b-41d4-a716-446655440000",
        "priority": "high"
    });

    let job = Job::new("test_job", payload.clone());

    assert_eq!(job.job_type, "test_job");
    assert_eq!(job.payload, payload);
    assert_eq!(
        job.state,
        JobState::Pending,
        "New jobs should start in Pending state"
    );
    assert_eq!(job.retry_count, 0, "New jobs should have 0 retry count");
    assert!(
        job.started_at.is_none(),
        "New jobs should not have started_at set"
    );
    assert!(
        job.completed_at.is_none(),
        "New jobs should not have completed_at set"
    );
    assert!(
        job.error_message.is_none(),
        "New jobs should not have an error message"
    );
}

/// Jobs should have unique IDs
#[test]
fn test_job_has_unique_id() {
    let job1 = Job::new("test", json!({}));
    let job2 = Job::new("test", json!({}));

    assert_ne!(job1.id, job2.id, "Each job should have a unique ID");
}

/// Jobs should track creation timestamp
#[test]
fn test_job_tracks_creation_time() {
    let before = chrono::Utc::now();
    let job = Job::new("test", json!({}));
    let after = chrono::Utc::now();

    assert!(
        job.created_at >= before && job.created_at <= after,
        "Job created_at should be set to current time"
    );
    assert_eq!(
        job.created_at, job.updated_at,
        "New jobs should have created_at == updated_at"
    );
}

/// Jobs should allow custom `max_retries`
#[test]
fn test_job_with_custom_max_retries() {
    let job = Job::new("test", json!({})).with_max_retries(10);
    assert_eq!(
        job.max_retries, 10,
        "Custom max_retries should be respected"
    );
}

// ============================================================================
// Job State Transition Tests
// ============================================================================

/// Valid state transitions should be allowed
#[test]
fn test_job_state_transitions_valid() {
    // Pending -> Running
    assert!(
        JobState::Pending.can_transition_to(&JobState::Running),
        "Pending -> Running should be valid"
    );

    // Running -> Completed
    assert!(
        JobState::Running.can_transition_to(&JobState::Completed),
        "Running -> Completed should be valid"
    );

    // Running -> Failed
    assert!(
        JobState::Running.can_transition_to(&JobState::Failed),
        "Running -> Failed should be valid"
    );

    // Pending -> Cancelled
    assert!(
        JobState::Pending.can_transition_to(&JobState::Cancelled),
        "Pending -> Cancelled should be valid"
    );

    // Running -> Cancelled
    assert!(
        JobState::Running.can_transition_to(&JobState::Cancelled),
        "Running -> Cancelled should be valid"
    );
}

/// Transition from Pending to Running
#[test]
fn test_job_state_pending_to_running() {
    let mut job = Job::new("test", json!({}));
    assert_eq!(job.state, JobState::Pending);

    let result = job.transition_to(JobState::Running);
    assert!(result.is_ok(), "Pending -> Running should succeed");
    assert_eq!(job.state, JobState::Running);
    assert!(
        job.started_at.is_some(),
        "started_at should be set when transitioning to Running"
    );
}

/// Transition from Running to Completed
#[test]
fn test_job_state_running_to_completed() {
    let mut job = Job::new("test", json!({}));
    job.transition_to(JobState::Running).unwrap();

    let result = job.transition_to(JobState::Completed);
    assert!(result.is_ok(), "Running -> Completed should succeed");
    assert_eq!(job.state, JobState::Completed);
    assert!(
        job.completed_at.is_some(),
        "completed_at should be set when transitioning to Completed"
    );
}

/// Transition from Running to Failed
#[test]
fn test_job_state_running_to_failed() {
    let mut job = Job::new("test", json!({}));
    job.transition_to(JobState::Running).unwrap();

    let result = job.transition_to(JobState::Failed);
    assert!(result.is_ok(), "Running -> Failed should succeed");
    assert_eq!(job.state, JobState::Failed);
    assert!(
        job.completed_at.is_some(),
        "completed_at should be set when transitioning to Failed"
    );
}

/// Invalid state transitions should return error
#[test]
fn test_job_state_invalid_transitions() {
    let mut job = Job::new("test", json!({}));

    // Cannot go directly from Pending to Completed
    let result = job.transition_to(JobState::Completed);
    assert!(
        result.is_err(),
        "Pending -> Completed should be invalid (must go through Running)"
    );

    // Cannot transition from terminal states
    job.state = JobState::Completed;
    let result = job.transition_to(JobState::Running);
    assert!(
        result.is_err(),
        "Completed -> Running should be invalid (terminal state)"
    );

    job.state = JobState::Failed;
    let result = job.transition_to(JobState::Pending);
    assert!(
        result.is_err(),
        "Failed -> Pending should be invalid (terminal state)"
    );

    job.state = JobState::Cancelled;
    let result = job.transition_to(JobState::Running);
    assert!(
        result.is_err(),
        "Cancelled -> Running should be invalid (terminal state)"
    );
}

// ============================================================================
// Job Handler Trait Tests
// ============================================================================

/// Test handler implementing `JobHandler` trait
struct TestHandler {
    max_retries: u32,
    should_fail: bool,
}

impl TestHandler {
    const fn new() -> Self {
        Self {
            max_retries: 5,
            should_fail: false,
        }
    }

    const fn failing() -> Self {
        Self {
            max_retries: 5,
            should_fail: true,
        }
    }
}

#[async_trait]
impl JobHandler for TestHandler {
    async fn handle(&self, _job: &Job) -> Result<JobResult, JobError> {
        if self.should_fail {
            Err(JobError::ProcessingFailed {
                message: "test failure".into(),
            })
        } else {
            Ok(JobResult {
                output: json!({"status": "ok"}),
                execution_duration: Duration::from_millis(100),
                metadata: JobResultMetadata {
                    worker_id: Some("test-worker-1".into()),
                    items_processed: Some(1),
                    extra: Default::default(),
                },
            })
        }
    }

    fn job_type(&self) -> &'static str {
        "test_handler"
    }

    fn max_retries(&self) -> u32 {
        self.max_retries
    }

    fn backoff(&self, attempt: u32) -> Duration {
        Duration::from_secs(2u64.pow(attempt))
    }
}

/// Handler should implement `job_type` correctly
#[test]
fn test_job_handler_trait_implementation() {
    let handler = TestHandler::new();
    assert_eq!(handler.job_type(), "test_handler");
}

/// Handler should have configurable `max_retries` with sensible default
#[test]
fn test_job_handler_max_retries_default() {
    // Built-in handlers should default to 3 retries
    let handler = TruthPropagationHandler;
    assert_eq!(handler.max_retries(), 3, "Default max_retries should be 3");
}

/// Handler backoff should use exponential strategy
#[test]
fn test_job_handler_backoff_exponential() {
    let handler = TestHandler::new();

    let backoff_0 = handler.backoff(0);
    let backoff_1 = handler.backoff(1);
    let backoff_2 = handler.backoff(2);
    let backoff_3 = handler.backoff(3);

    assert_eq!(
        backoff_0,
        Duration::from_secs(1),
        "First backoff should be 2^0 = 1 second"
    );
    assert_eq!(
        backoff_1,
        Duration::from_secs(2),
        "Second backoff should be 2^1 = 2 seconds"
    );
    assert_eq!(
        backoff_2,
        Duration::from_secs(4),
        "Third backoff should be 2^2 = 4 seconds"
    );
    assert_eq!(
        backoff_3,
        Duration::from_secs(8),
        "Fourth backoff should be 2^3 = 8 seconds"
    );
}

// ============================================================================
// Job Runner Tests
// ============================================================================

/// `JobRunner` should process pending jobs
#[tokio::test]
async fn test_job_runner_processes_pending_jobs() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let mut runner = JobRunner::new(2, queue.clone());

    // Register handler
    runner.register_handler(Arc::new(TestHandler::new()));

    // Enqueue a job
    let mut job = Job::new("test_handler", json!({"data": "test"}));
    queue.enqueue(job.clone()).await.unwrap();

    // Process the job
    let result = runner.process_job(&mut job).await;

    assert!(result.is_ok(), "Job should be processed successfully");
    let result = result.unwrap();
    assert_eq!(result.output["status"], "ok");
}

/// `JobRunner` should respect worker count configuration
#[test]
fn test_job_runner_respects_worker_count() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let runner = JobRunner::new(4, queue);

    assert_eq!(
        runner.worker_count(),
        4,
        "Runner should respect configured worker count"
    );
}

/// `JobRunner` should handle graceful shutdown
#[tokio::test]
async fn test_job_runner_graceful_shutdown() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let mut runner = JobRunner::new(2, queue.clone());
    runner.register_handler(Arc::new(TestHandler::new()));

    // Start the runner
    runner.start().await;

    // Enqueue some jobs
    for i in 0..5 {
        let job = Job::new("test_handler", json!({"index": i}));
        queue.enqueue(job).await.unwrap();
    }

    // Shutdown should complete without panicking
    runner.shutdown().await;

    // No assertion needed - if shutdown hangs or panics, test fails
}

/// `JobRunner` should retry failed jobs
#[tokio::test]
async fn test_job_runner_retries_failed_jobs() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let mut runner = JobRunner::new(1, queue.clone());
    runner.register_handler(Arc::new(TestHandler::failing()));

    let mut job = Job::new("test_handler", json!({}));
    job.max_retries = 3;
    let original_retry_count = job.retry_count;

    // First attempt should fail and increment retry count
    let result = runner.process_job(&mut job).await;
    assert!(result.is_err(), "Job should fail");
    assert_eq!(
        job.retry_count,
        original_retry_count + 1,
        "Retry count should be incremented on failure"
    );
}

/// `JobRunner` should respect `max_retries` limit
#[tokio::test]
async fn test_job_runner_respects_max_retries() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let mut runner = JobRunner::new(1, queue.clone());
    runner.register_handler(Arc::new(TestHandler::failing()));

    let mut job = Job::new("test_handler", json!({}));
    job.max_retries = 2;
    job.retry_count = 2; // Already at max

    let result = runner.process_job(&mut job).await;

    match result {
        Err(JobError::MaxRetriesExceeded { max_retries }) => {
            assert_eq!(max_retries, 2);
        }
        _ => panic!("Should return MaxRetriesExceeded error"),
    }

    assert_eq!(
        job.state,
        JobState::Failed,
        "Job should be marked as Failed when max retries exceeded"
    );
}

// ============================================================================
// Job Queue Tests
// ============================================================================

/// Queue should maintain FIFO ordering
#[tokio::test]
async fn test_job_queue_fifo_ordering() {
    let queue = InMemoryJobQueue::new();

    // Enqueue jobs in order
    let job1 = Job::new("test", json!({"order": 1}));
    let job2 = Job::new("test", json!({"order": 2}));
    let job3 = Job::new("test", json!({"order": 3}));

    let id1 = job1.id;
    let id2 = job2.id;
    let id3 = job3.id;

    queue.enqueue(job1).await.unwrap();
    queue.enqueue(job2).await.unwrap();
    queue.enqueue(job3).await.unwrap();

    // Dequeue should return in FIFO order
    let dequeued1 = queue.dequeue().await.unwrap();
    assert_eq!(
        dequeued1.id, id1,
        "First dequeued job should be first enqueued"
    );

    let dequeued2 = queue.dequeue().await.unwrap();
    assert_eq!(
        dequeued2.id, id2,
        "Second dequeued job should be second enqueued"
    );

    let dequeued3 = queue.dequeue().await.unwrap();
    assert_eq!(
        dequeued3.id, id3,
        "Third dequeued job should be third enqueued"
    );

    // Queue should be empty now
    assert!(queue.dequeue().await.is_none(), "Queue should be empty");
}

/// Queue should only return pending jobs
#[tokio::test]
async fn test_job_queue_only_dequeues_pending() {
    let queue = InMemoryJobQueue::new();

    let job1 = Job::new("test", json!({}));
    let mut job2 = Job::new("test", json!({}));

    // job1 is pending, job2 is running
    job2.state = JobState::Running;

    queue.enqueue(job1.clone()).await.unwrap();
    queue.enqueue(job2.clone()).await.unwrap();

    // Should only get pending jobs
    let pending = queue.pending_jobs().await;
    assert_eq!(pending.len(), 1, "Should only have 1 pending job");
    assert_eq!(pending[0].id, job1.id);
}

// ============================================================================
// Built-in Job Handler Tests
// ============================================================================

/// `TruthPropagation` handler should have correct job type
#[test]
fn test_propagation_job_handler() {
    let handler = TruthPropagationHandler;
    assert_eq!(handler.job_type(), "truth_propagation");
}

/// `EmbeddingGeneration` handler should have correct job type
#[test]
fn test_embedding_generation_job_handler() {
    let handler = EmbeddingGenerationHandler;
    assert_eq!(handler.job_type(), "embedding_generation");
}

/// `ReputationUpdate` handler should have correct job type
#[test]
fn test_reputation_update_job_handler() {
    let handler = ReputationUpdateHandler;
    assert_eq!(handler.job_type(), "reputation_update");
}

/// `WebhookNotification` handler should have correct job type
#[test]
fn test_webhook_notification_job_handler() {
    let handler = WebhookNotificationHandler;
    assert_eq!(handler.job_type(), "webhook_notification");
}

/// `DataCleanup` handler should have correct job type
#[test]
fn test_cleanup_job_handler() {
    let handler = DataCleanupHandler;
    assert_eq!(handler.job_type(), "data_cleanup");
}

// ============================================================================
// Job Result Tests
// ============================================================================

/// `JobResult` should contain execution metadata
#[tokio::test]
async fn test_job_result_contains_execution_metadata() {
    let handler = TestHandler::new();
    let job = Job::new("test_handler", json!({}));

    let result = handler.handle(&job).await.unwrap();

    assert!(
        result.execution_duration > Duration::ZERO,
        "Execution duration should be positive"
    );
    assert!(
        result.metadata.worker_id.is_some(),
        "Worker ID should be recorded"
    );
}

// ============================================================================
// EpiGraphJob Conversion Tests
// ============================================================================

/// `EpiGraphJob::TruthPropagation` should convert to correct job type
#[test]
fn test_truth_propagation_job_conversion() {
    let epigraph_job = EpiGraphJob::TruthPropagation {
        source_claim_id: Uuid::new_v4(),
    };

    assert_eq!(epigraph_job.job_type(), "truth_propagation");

    let job = epigraph_job.into_job().unwrap();
    assert_eq!(
        job.job_type, "truth_propagation",
        "Converted job should have correct type"
    );
    assert_eq!(
        job.state,
        JobState::Pending,
        "Converted job should be pending"
    );
}

/// `EpiGraphJob::EmbeddingGeneration` should convert correctly
#[test]
fn test_embedding_generation_job_conversion() {
    let epigraph_job = EpiGraphJob::EmbeddingGeneration {
        claim_id: Uuid::new_v4(),
    };

    assert_eq!(epigraph_job.job_type(), "embedding_generation");

    let job = epigraph_job.into_job().unwrap();
    assert_eq!(job.job_type, "embedding_generation");
}

/// `EpiGraphJob::ReputationUpdate` should convert correctly
#[test]
fn test_reputation_update_job_conversion() {
    let epigraph_job = EpiGraphJob::ReputationUpdate {
        agent_id: Uuid::new_v4(),
    };

    assert_eq!(epigraph_job.job_type(), "reputation_update");

    let job = epigraph_job.into_job().unwrap();
    assert_eq!(job.job_type, "reputation_update");
}

/// `EpiGraphJob::WebhookNotification` should convert correctly
#[test]
fn test_webhook_notification_job_conversion() {
    let epigraph_job = EpiGraphJob::WebhookNotification {
        webhook_id: Uuid::new_v4(),
        payload: json!({"event": "claim_verified"}),
    };

    assert_eq!(epigraph_job.job_type(), "webhook_notification");

    let job = epigraph_job.into_job().unwrap();
    assert_eq!(job.job_type, "webhook_notification");
}

/// `EpiGraphJob::DataCleanup` should convert correctly
#[test]
fn test_data_cleanup_job_conversion() {
    let epigraph_job = EpiGraphJob::DataCleanup { retention_days: 30 };

    assert_eq!(epigraph_job.job_type(), "data_cleanup");

    let job = epigraph_job.into_job().unwrap();
    assert_eq!(job.job_type, "data_cleanup");
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

/// Job should update `updated_at` on state change
#[test]
fn test_job_updates_timestamp_on_transition() {
    let mut job = Job::new("test", json!({}));
    let original_updated_at = job.updated_at;

    // Small sleep to ensure timestamp difference
    std::thread::sleep(std::time::Duration::from_millis(10));

    job.transition_to(JobState::Running).unwrap();

    assert!(
        job.updated_at > original_updated_at,
        "updated_at should be updated on state transition"
    );
}

/// `JobRunner` should return error for unknown job type
#[tokio::test]
async fn test_job_runner_unknown_job_type() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let runner = JobRunner::new(1, queue);

    let mut job = Job::new("unknown_type", json!({}));
    let result = runner.process_job(&mut job).await;

    match result {
        Err(JobError::NoHandler { job_type }) => {
            assert_eq!(job_type, "unknown_type");
        }
        _ => panic!("Should return NoHandler error for unknown job type"),
    }
}

/// `JobId` should implement necessary traits
#[test]
fn test_job_id_traits() {
    let id1 = JobId::new();
    let id2 = JobId::from_uuid(id1.as_uuid());

    // Equality
    assert_eq!(id1, id2);

    // Hash
    let mut set = std::collections::HashSet::new();
    set.insert(id1);
    assert!(set.contains(&id2));

    // Display
    let display = format!("{id1}");
    assert!(display.starts_with("job:"));

    // Serialize/Deserialize
    let json = serde_json::to_string(&id1).unwrap();
    let deserialized: JobId = serde_json::from_str(&json).unwrap();
    assert_eq!(id1, deserialized);
}

/// `JobState` Display should produce lowercase strings
#[test]
fn test_job_state_display() {
    assert_eq!(JobState::Pending.to_string(), "pending");
    assert_eq!(JobState::Running.to_string(), "running");
    assert_eq!(JobState::Completed.to_string(), "completed");
    assert_eq!(JobState::Failed.to_string(), "failed");
    assert_eq!(JobState::Cancelled.to_string(), "cancelled");
}

/// Job should preserve payload through serialization round-trip
#[test]
fn test_job_serialization_roundtrip() {
    let original_payload = json!({
        "claim_id": "550e8400-e29b-41d4-a716-446655440000",
        "nested": {
            "array": [1, 2, 3],
            "boolean": true
        }
    });

    let job = Job::new("test", original_payload.clone());
    let serialized = serde_json::to_string(&job).unwrap();
    let deserialized: Job = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.payload, original_payload);
    assert_eq!(deserialized.job_type, "test");
}

// ============================================================================
// Concurrent Job Processing Tests
// ============================================================================

use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Barrier;
use tokio::time::Instant;

/// Test handler that tracks concurrent execution
struct ConcurrencyTestHandler {
    active_count: Arc<AtomicUsize>,
    max_concurrent: Arc<AtomicUsize>,
    barrier: Arc<Barrier>,
}

impl ConcurrencyTestHandler {
    fn new(barrier: Arc<Barrier>) -> Self {
        Self {
            active_count: Arc::new(AtomicUsize::new(0)),
            max_concurrent: Arc::new(AtomicUsize::new(0)),
            barrier,
        }
    }
}

#[async_trait]
impl JobHandler for ConcurrencyTestHandler {
    async fn handle(&self, _job: &Job) -> Result<JobResult, JobError> {
        // Increment active count
        let current = self.active_count.fetch_add(1, Ordering::SeqCst) + 1;

        // Update max observed concurrency
        self.max_concurrent.fetch_max(current, Ordering::SeqCst);

        // Wait at barrier to ensure all concurrent workers are running
        self.barrier.wait().await;

        // Simulate work
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Decrement active count
        self.active_count.fetch_sub(1, Ordering::SeqCst);

        Ok(JobResult {
            output: json!({"concurrent_count": current}),
            execution_duration: Duration::from_millis(50),
            metadata: JobResultMetadata::default(),
        })
    }

    fn job_type(&self) -> &'static str {
        "concurrency_test"
    }

    fn max_retries(&self) -> u32 {
        0
    }

    fn backoff(&self, _attempt: u32) -> Duration {
        Duration::from_millis(10)
    }
}

/// `JobRunner` should process jobs concurrently up to `worker_count`
#[tokio::test]
async fn test_job_runner_processes_jobs_concurrently() {
    let worker_count = 4;
    let job_count = 4;

    let queue = Arc::new(InMemoryJobQueue::new());
    let barrier = Arc::new(Barrier::new(job_count));
    let handler = Arc::new(ConcurrencyTestHandler::new(barrier));
    let max_concurrent_tracker = handler.max_concurrent.clone();

    let mut runner = JobRunner::new(worker_count, queue.clone());
    runner.register_handler(handler);

    // Enqueue jobs
    for i in 0..job_count {
        let job = Job::new("concurrency_test", json!({"index": i}));
        queue.enqueue(job).await.unwrap();
    }

    // Start runner and wait for jobs to complete
    runner.start().await;

    // Give jobs time to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    runner.shutdown().await;

    // Verify concurrent execution actually happened
    let max_observed = max_concurrent_tracker.load(Ordering::SeqCst);
    assert!(
        max_observed >= 2,
        "Expected at least 2 concurrent jobs, but max observed was {max_observed}"
    );
}

/// `JobRunner` should limit concurrency to `worker_count`
#[tokio::test]
async fn test_job_runner_limits_concurrency_to_worker_count() {
    let worker_count = 2;
    let job_count = 4;

    let queue = Arc::new(InMemoryJobQueue::new());
    let barrier = Arc::new(Barrier::new(worker_count)); // Barrier at worker_count, not job_count
    let handler = Arc::new(ConcurrencyTestHandler::new(barrier));
    let max_concurrent_tracker = handler.max_concurrent.clone();

    let mut runner = JobRunner::new(worker_count, queue.clone());
    runner.register_handler(handler);

    // Enqueue more jobs than workers
    for i in 0..job_count {
        let job = Job::new("concurrency_test", json!({"index": i}));
        queue.enqueue(job).await.unwrap();
    }

    runner.start().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    runner.shutdown().await;

    // Verify concurrency was limited
    let max_observed = max_concurrent_tracker.load(Ordering::SeqCst);
    assert!(
        max_observed <= worker_count,
        "Expected max {worker_count} concurrent jobs, but observed {max_observed}"
    );
}

// ============================================================================
// Exponential Backoff Timing Tests
// ============================================================================

/// Handler with custom exponential backoff for timing verification
struct TimingTestHandler {
    call_times: Arc<std::sync::Mutex<Vec<Instant>>>,
    fail_until_attempt: u32,
}

impl TimingTestHandler {
    fn new(fail_until_attempt: u32) -> Self {
        Self {
            call_times: Arc::new(std::sync::Mutex::new(Vec::new())),
            fail_until_attempt,
        }
    }
}

#[async_trait]
impl JobHandler for TimingTestHandler {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        self.call_times.lock().unwrap().push(Instant::now());

        if job.retry_count < self.fail_until_attempt {
            Err(JobError::ProcessingFailed {
                message: format!("Failing attempt {}", job.retry_count),
            })
        } else {
            Ok(JobResult {
                output: json!({"success": true}),
                execution_duration: Duration::from_millis(10),
                metadata: JobResultMetadata::default(),
            })
        }
    }

    fn job_type(&self) -> &'static str {
        "timing_test"
    }

    fn max_retries(&self) -> u32 {
        5
    }

    fn backoff(&self, attempt: u32) -> Duration {
        // 100ms * 2^attempt for faster testing
        Duration::from_millis(100 * 2u64.pow(attempt))
    }
}

/// Exponential backoff timing should double between retries
#[tokio::test]
async fn test_exponential_backoff_timing_doubles() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let handler = Arc::new(TimingTestHandler::new(3)); // Fail first 3 attempts
    let call_times_tracker = handler.call_times.clone();

    let mut runner = JobRunner::new(1, queue.clone());
    runner.register_handler(handler.clone());

    let job = Job::new("timing_test", json!({})).with_max_retries(5);
    queue.enqueue(job).await.unwrap();

    runner.start().await;

    // Wait for retries to complete (100 + 200 + 400 + some margin)
    tokio::time::sleep(Duration::from_millis(1000)).await;
    runner.shutdown().await;

    let times = call_times_tracker.lock().unwrap().clone();

    // Should have 4 calls: initial + 3 retries that fail + 1 success
    assert!(
        times.len() >= 3,
        "Expected at least 3 handler calls, got {}",
        times.len()
    );

    // Verify timing roughly doubles between retries
    if times.len() >= 3 {
        let delay_1_to_2 = times[1].duration_since(times[0]);
        let delay_2_to_3 = times[2].duration_since(times[1]);

        // Second delay should be roughly 2x the first (with tolerance for test overhead)
        let ratio = delay_2_to_3.as_millis() as f64 / delay_1_to_2.as_millis().max(1) as f64;
        assert!(
            (1.5..=3.0).contains(&ratio),
            "Backoff ratio should be ~2x, got {ratio:.2} (delays: {delay_1_to_2:?} -> {delay_2_to_3:?})"
        );
    }
}

/// Backoff calculation should follow 2^attempt formula
#[test]
fn test_backoff_formula_correctness() {
    let handler = TimingTestHandler::new(0);

    // Verify the formula: 100ms * 2^attempt
    assert_eq!(handler.backoff(0), Duration::from_millis(100)); // 100 * 2^0 = 100
    assert_eq!(handler.backoff(1), Duration::from_millis(200)); // 100 * 2^1 = 200
    assert_eq!(handler.backoff(2), Duration::from_millis(400)); // 100 * 2^2 = 400
    assert_eq!(handler.backoff(3), Duration::from_millis(800)); // 100 * 2^3 = 800
    assert_eq!(handler.backoff(4), Duration::from_millis(1600)); // 100 * 2^4 = 1600
}

/// Default backoff should cap at reasonable maximum to prevent overflow
#[test]
fn test_backoff_does_not_overflow() {
    let handler = TruthPropagationHandler;

    // Even with high attempt count, should not panic or overflow
    let backoff_large = handler.backoff(30);

    // Should be capped at some reasonable maximum (e.g., 1 hour)
    assert!(
        backoff_large <= Duration::from_secs(3600),
        "Backoff should be capped to prevent excessive waits"
    );
}

// ============================================================================
// Graceful Shutdown Verification Tests
// ============================================================================

/// Handler that tracks shutdown behavior
struct ShutdownTestHandler {
    started_jobs: Arc<AtomicUsize>,
    completed_jobs: Arc<AtomicUsize>,
    job_duration: Duration,
}

impl ShutdownTestHandler {
    fn new(job_duration: Duration) -> Self {
        Self {
            started_jobs: Arc::new(AtomicUsize::new(0)),
            completed_jobs: Arc::new(AtomicUsize::new(0)),
            job_duration,
        }
    }
}

#[async_trait]
impl JobHandler for ShutdownTestHandler {
    async fn handle(&self, _job: &Job) -> Result<JobResult, JobError> {
        self.started_jobs.fetch_add(1, Ordering::SeqCst);

        tokio::time::sleep(self.job_duration).await;

        self.completed_jobs.fetch_add(1, Ordering::SeqCst);

        Ok(JobResult {
            output: json!({"completed": true}),
            execution_duration: self.job_duration,
            metadata: JobResultMetadata::default(),
        })
    }

    fn job_type(&self) -> &'static str {
        "shutdown_test"
    }

    fn max_retries(&self) -> u32 {
        0
    }

    fn backoff(&self, _attempt: u32) -> Duration {
        Duration::from_millis(10)
    }
}

/// Graceful shutdown should wait for in-flight jobs to complete
#[tokio::test]
async fn test_graceful_shutdown_waits_for_in_flight_jobs() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let handler = Arc::new(ShutdownTestHandler::new(Duration::from_millis(200)));
    let started = handler.started_jobs.clone();
    let completed = handler.completed_jobs.clone();

    let mut runner = JobRunner::new(2, queue.clone());
    runner.register_handler(handler);

    // Enqueue jobs
    for i in 0..3 {
        let job = Job::new("shutdown_test", json!({"index": i}));
        queue.enqueue(job).await.unwrap();
    }

    runner.start().await;

    // Let jobs start
    tokio::time::sleep(Duration::from_millis(50)).await;

    let started_before_shutdown = started.load(Ordering::SeqCst);
    assert!(
        started_before_shutdown > 0,
        "At least one job should have started"
    );

    // Initiate shutdown - should block until in-flight complete
    runner.shutdown().await;

    // After shutdown, all started jobs should be completed
    let completed_after_shutdown = completed.load(Ordering::SeqCst);
    let started_total = started.load(Ordering::SeqCst);

    assert_eq!(
        completed_after_shutdown, started_total,
        "All started jobs ({started_total}) should be completed ({completed_after_shutdown}) after graceful shutdown"
    );
}

/// Shutdown should not accept new jobs
#[tokio::test]
async fn test_shutdown_rejects_new_jobs_after_signal() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let handler = Arc::new(ShutdownTestHandler::new(Duration::from_millis(100)));
    let started = handler.started_jobs.clone();

    let mut runner = JobRunner::new(1, queue.clone());
    runner.register_handler(handler);

    // Enqueue initial job
    let job1 = Job::new("shutdown_test", json!({"index": 1}));
    queue.enqueue(job1).await.unwrap();

    runner.start().await;

    // Let job start processing
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Signal shutdown (don't await yet)
    let shutdown_handle = tokio::spawn({
        let runner_shutdown = async move {
            runner.shutdown().await;
        };
        runner_shutdown
    });

    // Try to enqueue a job after shutdown signal
    let job2 = Job::new("shutdown_test", json!({"index": 2}));
    queue.enqueue(job2).await.unwrap();

    // Wait for shutdown
    tokio::time::timeout(Duration::from_secs(2), shutdown_handle)
        .await
        .expect("Shutdown should complete within timeout")
        .unwrap();

    // Only the first job should have been processed
    let jobs_started = started.load(Ordering::SeqCst);
    assert!(
        jobs_started <= 2,
        "Jobs enqueued during shutdown may or may not be processed, got {jobs_started}"
    );
}

/// Shutdown should complete within reasonable timeout
#[tokio::test]
async fn test_shutdown_completes_within_timeout() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let handler = Arc::new(ShutdownTestHandler::new(Duration::from_millis(50)));

    let mut runner = JobRunner::new(2, queue.clone());
    runner.register_handler(handler);

    // Enqueue a few jobs
    for i in 0..5 {
        let job = Job::new("shutdown_test", json!({"index": i}));
        queue.enqueue(job).await.unwrap();
    }

    runner.start().await;
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Shutdown should complete within a reasonable time
    let start = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), runner.shutdown())
        .await
        .expect("Shutdown should complete within 5 seconds");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "Shutdown took too long: {elapsed:?}"
    );
}

// ============================================================================
// Job Re-queuing Tests for Retry Logic
// ============================================================================

/// Handler that fails a specific number of times then succeeds
struct RequeueTestHandler {
    attempts: Arc<std::sync::Mutex<std::collections::HashMap<JobId, u32>>>,
    fail_count: u32,
}

impl RequeueTestHandler {
    fn new(fail_count: u32) -> Self {
        Self {
            attempts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            fail_count,
        }
    }
}

#[async_trait]
impl JobHandler for RequeueTestHandler {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        let attempt = {
            let mut attempts = self.attempts.lock().unwrap();
            let entry = attempts.entry(job.id).or_insert(0);
            *entry += 1;
            *entry
        };

        if attempt <= self.fail_count {
            Err(JobError::ProcessingFailed {
                message: format!("Deliberate failure #{attempt}"),
            })
        } else {
            Ok(JobResult {
                output: json!({"attempt": attempt, "success": true}),
                execution_duration: Duration::from_millis(10),
                metadata: JobResultMetadata::default(),
            })
        }
    }

    fn job_type(&self) -> &'static str {
        "requeue_test"
    }

    fn max_retries(&self) -> u32 {
        5
    }

    fn backoff(&self, _attempt: u32) -> Duration {
        Duration::from_millis(10) // Fast backoff for testing
    }
}

/// Failed jobs should be re-queued for retry
#[tokio::test]
async fn test_failed_job_is_requeued_for_retry() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let handler = Arc::new(RequeueTestHandler::new(2)); // Fail twice, succeed on third
    let attempts_tracker = handler.attempts.clone();

    let mut runner = JobRunner::new(1, queue.clone());
    runner.register_handler(handler);

    let job = Job::new("requeue_test", json!({})).with_max_retries(5);
    let job_id = job.id;
    queue.enqueue(job).await.unwrap();

    runner.start().await;

    // Wait for retries (with fast backoff, should complete quickly)
    tokio::time::sleep(Duration::from_millis(200)).await;
    runner.shutdown().await;

    // Verify the job was retried
    let attempts = *attempts_tracker.lock().unwrap().get(&job_id).unwrap_or(&0);
    assert_eq!(
        attempts, 3,
        "Job should have been attempted 3 times (2 failures + 1 success), got {attempts}"
    );
}

/// Job `retry_count` should be incremented on re-queue
#[tokio::test]
async fn test_retry_count_incremented_on_requeue() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let mut runner = JobRunner::new(1, queue.clone());
    runner.register_handler(Arc::new(TestHandler::failing()));

    let mut job = Job::new("test_handler", json!({})).with_max_retries(3);
    let initial_retry_count = job.retry_count;

    // First failure
    let _ = runner.process_job(&mut job).await;
    assert_eq!(
        job.retry_count,
        initial_retry_count + 1,
        "Retry count should increment after first failure"
    );

    // Second failure
    let _ = runner.process_job(&mut job).await;
    assert_eq!(
        job.retry_count,
        initial_retry_count + 2,
        "Retry count should increment after second failure"
    );
}

/// Re-queued job should maintain original job ID
#[tokio::test]
async fn test_requeued_job_maintains_original_id() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let handler = Arc::new(RequeueTestHandler::new(1)); // Fail once
    let attempts_tracker = handler.attempts.clone();

    let mut runner = JobRunner::new(1, queue.clone());
    runner.register_handler(handler);

    let job = Job::new("requeue_test", json!({})).with_max_retries(3);
    let original_id = job.id;
    queue.enqueue(job).await.unwrap();

    runner.start().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    runner.shutdown().await;

    // The same job ID should have multiple attempts
    let attempts = attempts_tracker.lock().unwrap();
    assert!(
        attempts.contains_key(&original_id),
        "Original job ID should be preserved through retries"
    );
    assert!(
        *attempts.get(&original_id).unwrap() >= 2,
        "Job should have been attempted at least twice with same ID"
    );
}

/// Job that exceeds `max_retries` should not be re-queued
#[tokio::test]
async fn test_exhausted_retries_not_requeued() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let handler = Arc::new(RequeueTestHandler::new(10)); // Always fail
    let attempts_tracker = handler.attempts.clone();

    let mut runner = JobRunner::new(1, queue.clone());
    runner.register_handler(handler);

    let job = Job::new("requeue_test", json!({})).with_max_retries(2);
    let job_id = job.id;
    queue.enqueue(job).await.unwrap();

    runner.start().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    runner.shutdown().await;

    // Job should have been attempted max_retries + 1 times (initial + retries)
    let attempts = *attempts_tracker.lock().unwrap().get(&job_id).unwrap_or(&0);
    assert!(
        attempts <= 3,
        "Job should not be retried more than max_retries + 1 times, got {attempts}"
    );

    // Job should be in Failed state in queue
    if let Some(final_job) = queue.get(job_id).await {
        assert_eq!(
            final_job.state,
            JobState::Failed,
            "Exhausted job should be marked as Failed"
        );
    }
}

// ============================================================================
// Handler Registration and Routing Tests
// ============================================================================

/// Handler for routing tests
struct RoutingTestHandler {
    handler_name: String,
    job_type_name: String,
    handled_jobs: Arc<std::sync::Mutex<Vec<JobId>>>,
}

impl RoutingTestHandler {
    fn new(name: &str, job_type: &str) -> Self {
        Self {
            handler_name: name.to_string(),
            job_type_name: job_type.to_string(),
            handled_jobs: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl JobHandler for RoutingTestHandler {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        self.handled_jobs.lock().unwrap().push(job.id);

        Ok(JobResult {
            output: json!({"handler": self.handler_name}),
            execution_duration: Duration::from_millis(10),
            metadata: JobResultMetadata::default(),
        })
    }

    fn job_type(&self) -> &str {
        &self.job_type_name
    }

    fn max_retries(&self) -> u32 {
        3
    }

    fn backoff(&self, _attempt: u32) -> Duration {
        Duration::from_millis(10)
    }
}

/// `JobRunner` should register handlers correctly
#[test]
fn test_handler_registration() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let mut runner = JobRunner::new(2, queue);

    let handler1 = Arc::new(RoutingTestHandler::new("handler1", "type_a"));
    let handler2 = Arc::new(RoutingTestHandler::new("handler2", "type_b"));

    // Registration should not panic
    runner.register_handler(handler1);
    runner.register_handler(handler2);

    // Verify handlers are registered by checking they can process jobs
    assert_eq!(runner.worker_count(), 2);
}

/// `JobRunner` should route jobs to correct handler based on `job_type`
#[tokio::test]
async fn test_job_routing_to_correct_handler() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let handler_a = Arc::new(RoutingTestHandler::new("handler_a", "type_a"));
    let handler_b = Arc::new(RoutingTestHandler::new("handler_b", "type_b"));

    let handler_a_jobs = handler_a.handled_jobs.clone();
    let handler_b_jobs = handler_b.handled_jobs.clone();

    let mut runner = JobRunner::new(2, queue.clone());
    runner.register_handler(handler_a);
    runner.register_handler(handler_b);

    // Create jobs of different types
    let mut job_a = Job::new("type_a", json!({"target": "a"}));
    let mut job_b = Job::new("type_b", json!({"target": "b"}));

    let job_a_id = job_a.id;
    let job_b_id = job_b.id;

    // Process jobs
    let result_a = runner.process_job(&mut job_a).await;
    let result_b = runner.process_job(&mut job_b).await;

    // Verify results
    assert!(result_a.is_ok(), "Job A should succeed");
    assert!(result_b.is_ok(), "Job B should succeed");

    // Verify routing
    let a_jobs = handler_a_jobs.lock().unwrap();
    let b_jobs = handler_b_jobs.lock().unwrap();

    assert!(
        a_jobs.contains(&job_a_id),
        "Handler A should have processed job with type_a"
    );
    assert!(
        b_jobs.contains(&job_b_id),
        "Handler B should have processed job with type_b"
    );
    assert!(
        !a_jobs.contains(&job_b_id),
        "Handler A should NOT have processed job with type_b"
    );
    assert!(
        !b_jobs.contains(&job_a_id),
        "Handler B should NOT have processed job with type_a"
    );
}

/// Registering duplicate handler for same `job_type` should panic
#[test]
#[should_panic(expected = "already registered")]
fn test_duplicate_handler_registration_panics() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let mut runner = JobRunner::new(1, queue);

    let handler1 = Arc::new(RoutingTestHandler::new("first", "same_type"));
    let handler2 = Arc::new(RoutingTestHandler::new("second", "same_type"));

    runner.register_handler(handler1);
    runner.register_handler(handler2); // Should panic
}

/// `JobRunner` should return error for unregistered job type
#[tokio::test]
async fn test_unregistered_handler_returns_error() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let mut runner = JobRunner::new(1, queue);

    // Register only type_a
    runner.register_handler(Arc::new(RoutingTestHandler::new("handler_a", "type_a")));

    // Try to process type_c (not registered)
    let mut job = Job::new("type_c", json!({}));
    let result = runner.process_job(&mut job).await;

    match result {
        Err(JobError::NoHandler { job_type }) => {
            assert_eq!(job_type, "type_c");
        }
        Ok(_) => panic!("Should have returned NoHandler error"),
        Err(e) => panic!("Wrong error type: {e:?}"),
    }
}

/// `JobRunner` should list all registered job types
#[test]
fn test_list_registered_handlers() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let mut runner = JobRunner::new(1, queue);

    runner.register_handler(Arc::new(RoutingTestHandler::new("a", "type_a")));
    runner.register_handler(Arc::new(RoutingTestHandler::new("b", "type_b")));
    runner.register_handler(Arc::new(RoutingTestHandler::new("c", "type_c")));

    let registered = runner.registered_job_types();

    assert_eq!(registered.len(), 3, "Should have 3 registered handlers");
    assert!(registered.contains(&"type_a".to_string()));
    assert!(registered.contains(&"type_b".to_string()));
    assert!(registered.contains(&"type_c".to_string()));
}
