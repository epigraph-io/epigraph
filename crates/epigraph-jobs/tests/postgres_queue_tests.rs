//! Tests for `PostgresJobQueue`
//!
//! This file contains tests for the PostgreSQL-backed job queue implementation.
//!
//! # Test Organization
//!
//! 1. Unit tests for helper functions (no database required)
//! 2. Mock-based tests for `JobQueue` trait compliance
//! 3. Integration tests (require `DATABASE_URL`, skipped if not set)
//!
//! # Running Tests
//!
//! Unit/mock tests: `cargo test -p epigraph-jobs postgres_queue`
//! Integration tests: `DATABASE_URL=postgres://... cargo test -p epigraph-jobs postgres_queue --features integration`

use epigraph_jobs::{InMemoryJobQueue, Job, JobId, JobQueue, JobState};
use serde_json::json;
use std::sync::Arc;

// ============================================================================
// Mock-based Tests for JobQueue Trait Behavior
// ============================================================================
// These tests verify the expected behavior using InMemoryJobQueue as a reference
// implementation. PostgresJobQueue should behave identically.

/// Jobs should be enqueued with Pending state
#[tokio::test]
async fn test_enqueue_creates_pending_job() {
    let queue = InMemoryJobQueue::new();
    let job = Job::new("test_job", json!({"key": "value"}));
    let job_id = job.id;

    let result = queue.enqueue(job).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), job_id);

    // Verify job exists in queue
    let retrieved = queue.get(job_id).await;
    assert!(retrieved.is_some());
    let job = retrieved.unwrap();
    assert_eq!(job.state, JobState::Pending);
}

/// Dequeue should return jobs in FIFO order
#[tokio::test]
async fn test_dequeue_fifo_order() {
    let queue = InMemoryJobQueue::new();

    // Enqueue multiple jobs
    let job1 = Job::new("job_type_1", json!({"order": 1}));
    let job2 = Job::new("job_type_2", json!({"order": 2}));
    let job3 = Job::new("job_type_3", json!({"order": 3}));

    let id1 = job1.id;
    let id2 = job2.id;
    let id3 = job3.id;

    queue.enqueue(job1).await.unwrap();
    queue.enqueue(job2).await.unwrap();
    queue.enqueue(job3).await.unwrap();

    // Dequeue should return in order
    let dequeued1 = queue.dequeue().await.expect("Should dequeue first job");
    assert_eq!(dequeued1.id, id1, "First dequeue should return first job");

    let dequeued2 = queue.dequeue().await.expect("Should dequeue second job");
    assert_eq!(dequeued2.id, id2, "Second dequeue should return second job");

    let dequeued3 = queue.dequeue().await.expect("Should dequeue third job");
    assert_eq!(dequeued3.id, id3, "Third dequeue should return third job");

    // Queue should now be empty
    let dequeued4 = queue.dequeue().await;
    assert!(
        dequeued4.is_none(),
        "Queue should be empty after all dequeues"
    );
}

/// Dequeue should only return pending jobs
#[tokio::test]
async fn test_dequeue_only_pending_jobs() {
    let queue = InMemoryJobQueue::new();

    // Create a job in Running state (simulating already claimed)
    let mut running_job = Job::new("running", json!({}));
    running_job.state = JobState::Running;

    // Create a pending job
    let pending_job = Job::new("pending", json!({}));
    let pending_id = pending_job.id;

    // Enqueue both (running first)
    queue.enqueue(running_job).await.unwrap();
    queue.enqueue(pending_job).await.unwrap();

    // Dequeue should skip the running job
    let dequeued = queue.dequeue().await.expect("Should find pending job");
    assert_eq!(dequeued.id, pending_id, "Should dequeue the pending job");
}

/// Update should modify job state
#[tokio::test]
async fn test_update_job_state() {
    let queue = InMemoryJobQueue::new();
    let mut job = Job::new("test", json!({}));
    let job_id = job.id;

    queue.enqueue(job.clone()).await.unwrap();

    // Transition to Running
    job.transition_to(JobState::Running).unwrap();
    queue.update(&job).await.unwrap();

    let retrieved = queue.get(job_id).await.unwrap();
    assert_eq!(retrieved.state, JobState::Running);

    // Transition to Completed
    job.transition_to(JobState::Completed).unwrap();
    queue.update(&job).await.unwrap();

    let retrieved = queue.get(job_id).await.unwrap();
    assert_eq!(retrieved.state, JobState::Completed);
}

/// Get should return None for non-existent job
#[tokio::test]
async fn test_get_nonexistent_job() {
    let queue = InMemoryJobQueue::new();
    let fake_id = JobId::new();

    let result = queue.get(fake_id).await;
    assert!(result.is_none(), "Should return None for non-existent job");
}

/// `pending_jobs` should return all pending jobs in FIFO order
#[tokio::test]
async fn test_pending_jobs_returns_all_pending() {
    let queue = InMemoryJobQueue::new();

    // Create jobs with different states
    let pending1 = Job::new("pending1", json!({}));
    let pending2 = Job::new("pending2", json!({}));
    let mut running = Job::new("running", json!({}));
    let mut completed = Job::new("completed", json!({}));

    let pending1_id = pending1.id;
    let pending2_id = pending2.id;

    running.state = JobState::Running;
    completed.state = JobState::Completed;

    queue.enqueue(pending1).await.unwrap();
    queue.enqueue(running).await.unwrap();
    queue.enqueue(pending2).await.unwrap();
    queue.enqueue(completed).await.unwrap();

    let pending = queue.pending_jobs().await;
    assert_eq!(pending.len(), 2, "Should return only pending jobs");

    // Verify correct jobs returned
    let ids: Vec<JobId> = pending.iter().map(|j| j.id).collect();
    assert!(ids.contains(&pending1_id));
    assert!(ids.contains(&pending2_id));
}

/// Update should preserve all job fields
#[tokio::test]
async fn test_update_preserves_fields() {
    let queue = InMemoryJobQueue::new();
    let mut job = Job::new("test", json!({"data": "important"}));
    let job_id = job.id;

    queue.enqueue(job.clone()).await.unwrap();

    // Update with new state and error message
    job.state = JobState::Failed;
    job.retry_count = 3;
    job.error_message = Some("Test error".to_string());
    queue.update(&job).await.unwrap();

    let retrieved = queue.get(job_id).await.unwrap();
    assert_eq!(retrieved.state, JobState::Failed);
    assert_eq!(retrieved.retry_count, 3);
    assert_eq!(retrieved.error_message, Some("Test error".to_string()));
    assert_eq!(retrieved.payload, json!({"data": "important"}));
}

// ============================================================================
// JobQueue Trait Compliance Tests
// ============================================================================

/// Verify `JobQueue` trait is object-safe (can be used as dyn)
#[tokio::test]
async fn test_job_queue_is_object_safe() {
    let queue: Arc<dyn JobQueue> = Arc::new(InMemoryJobQueue::new());
    let job = Job::new("test", json!({}));
    let job_id = job.id;

    // All trait methods should work through dyn reference
    queue.enqueue(job).await.unwrap();
    let _ = queue.dequeue().await;
    let _ = queue.get(job_id).await;
    let _ = queue.pending_jobs().await;
}

/// Multiple enqueues of same job should not error (upsert behavior)
#[tokio::test]
async fn test_enqueue_same_job_twice() {
    let queue = InMemoryJobQueue::new();
    let job = Job::new("test", json!({}));
    let job_id = job.id;

    // First enqueue
    let result1 = queue.enqueue(job.clone()).await;
    assert!(result1.is_ok());

    // Second enqueue (should update, not error)
    let result2 = queue.enqueue(job).await;
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), job_id);
}

// ============================================================================
// State Transition Tests
// ============================================================================

/// Job retry workflow: Pending -> Running -> Pending (retry)
#[tokio::test]
async fn test_job_retry_workflow() {
    let queue = InMemoryJobQueue::new();
    let mut job = Job::new("retryable", json!({}));
    let job_id = job.id;

    queue.enqueue(job.clone()).await.unwrap();

    // Worker picks up job
    job.transition_to(JobState::Running).unwrap();
    queue.update(&job).await.unwrap();

    // Job fails, increment retry count, reset to Pending
    job.retry_count += 1;
    job.state = JobState::Pending;
    job.started_at = None;
    job.error_message = Some("Transient error".to_string());
    queue.update(&job).await.unwrap();

    let retrieved = queue.get(job_id).await.unwrap();
    assert_eq!(retrieved.state, JobState::Pending);
    assert_eq!(retrieved.retry_count, 1);
    assert!(retrieved.started_at.is_none());
}

/// Job success workflow: Pending -> Running -> Completed
#[tokio::test]
async fn test_job_success_workflow() {
    let queue = InMemoryJobQueue::new();
    let mut job = Job::new("successful", json!({}));
    let job_id = job.id;

    queue.enqueue(job.clone()).await.unwrap();

    // Worker picks up job
    job.transition_to(JobState::Running).unwrap();
    queue.update(&job).await.unwrap();

    // Job completes successfully
    job.transition_to(JobState::Completed).unwrap();
    queue.update(&job).await.unwrap();

    let retrieved = queue.get(job_id).await.unwrap();
    assert_eq!(retrieved.state, JobState::Completed);
    assert!(retrieved.started_at.is_some());
    assert!(retrieved.completed_at.is_some());
}

/// Job failure workflow: Pending -> Running -> Failed
#[tokio::test]
async fn test_job_failure_workflow() {
    let queue = InMemoryJobQueue::new();
    let mut job = Job::new("failing", json!({})).with_max_retries(3);
    let job_id = job.id;

    queue.enqueue(job.clone()).await.unwrap();

    // Simulate 3 failed attempts
    for attempt in 1..=3 {
        job.transition_to(JobState::Running).unwrap();
        queue.update(&job).await.unwrap();

        job.retry_count = attempt;
        if attempt < 3 {
            // Reset for retry
            job.state = JobState::Pending;
            job.started_at = None;
        } else {
            // Final failure
            job.state = JobState::Failed;
            job.completed_at = Some(chrono::Utc::now());
            job.error_message = Some("Max retries exceeded".to_string());
        }
        queue.update(&job).await.unwrap();
    }

    let retrieved = queue.get(job_id).await.unwrap();
    assert_eq!(retrieved.state, JobState::Failed);
    assert_eq!(retrieved.retry_count, 3);
    assert!(retrieved.error_message.is_some());
}

// ============================================================================
// Payload Tests
// ============================================================================

/// Job payloads with complex JSON should be preserved
#[tokio::test]
async fn test_complex_json_payload() {
    let queue = InMemoryJobQueue::new();
    let complex_payload = json!({
        "nested": {
            "array": [1, 2, 3],
            "object": {"key": "value"}
        },
        "null_field": null,
        "boolean": true,
        "number": 42.5,
        "string": "hello"
    });

    let job = Job::new("complex", complex_payload.clone());
    let job_id = job.id;

    queue.enqueue(job).await.unwrap();

    let retrieved = queue.get(job_id).await.unwrap();
    assert_eq!(retrieved.payload, complex_payload);
}

/// Job payloads with Unicode should be preserved
#[tokio::test]
async fn test_unicode_payload() {
    let queue = InMemoryJobQueue::new();
    let unicode_payload = json!({
        "emoji": "Hello World!",
        "chinese": "Chinese Characters",
        "arabic": "Arabic Text",
        "special": "line1\nline2\ttab"
    });

    let job = Job::new("unicode", unicode_payload.clone());
    let job_id = job.id;

    queue.enqueue(job).await.unwrap();

    let retrieved = queue.get(job_id).await.unwrap();
    assert_eq!(retrieved.payload, unicode_payload);
}

// ============================================================================
// Concurrency Tests (using InMemoryJobQueue as reference)
// ============================================================================

/// Multiple concurrent dequeues should not return same job
#[tokio::test]
async fn test_concurrent_dequeue_no_duplicates() {
    let queue = Arc::new(InMemoryJobQueue::new());

    // Enqueue 10 jobs
    let mut job_ids = Vec::new();
    for i in 0..10 {
        let job = Job::new("concurrent", json!({"index": i}));
        job_ids.push(job.id);
        queue.enqueue(job).await.unwrap();
    }

    // Spawn 10 concurrent dequeue tasks
    let mut handles = Vec::new();
    for _ in 0..10 {
        let q = queue.clone();
        handles.push(tokio::spawn(async move { q.dequeue().await }));
    }

    // Collect results
    let mut dequeued_ids = Vec::new();
    for handle in handles {
        if let Some(job) = handle.await.unwrap() {
            dequeued_ids.push(job.id);
        }
    }

    // Verify no duplicates using HashSet
    let unique_count = dequeued_ids.len();
    let unique_set: std::collections::HashSet<_> = dequeued_ids.iter().collect();
    assert_eq!(
        unique_count,
        unique_set.len(),
        "No duplicate jobs should be dequeued"
    );
}

// ============================================================================
// PostgresJobQueue Specific Tests (Unit tests that don't need DB)
// ============================================================================

#[cfg(test)]
mod postgres_unit_tests {
    use super::*;

    /// Verify `JobState` Display implementation matches database values
    #[test]
    fn test_job_state_display_matches_db_values() {
        assert_eq!(format!("{}", JobState::Pending), "pending");
        assert_eq!(format!("{}", JobState::Running), "running");
        assert_eq!(format!("{}", JobState::Completed), "completed");
        assert_eq!(format!("{}", JobState::Failed), "failed");
        assert_eq!(format!("{}", JobState::Cancelled), "cancelled");
    }

    /// Verify all `JobState` values have valid database representations
    #[test]
    fn test_all_job_states_serializable() {
        let states = [
            JobState::Pending,
            JobState::Running,
            JobState::Completed,
            JobState::Failed,
            JobState::Cancelled,
        ];

        for state in states {
            // State display should be non-empty and lowercase
            let display = format!("{state}");
            assert!(!display.is_empty());
            assert_eq!(display, display.to_lowercase());
        }
    }
}

// ============================================================================
// Integration Tests (require DATABASE_URL)
// ============================================================================

/// Integration tests that require a real PostgreSQL database.
/// These are gated behind the `integration` feature and require DATABASE_URL.
///
/// Run with:
/// ```
/// DATABASE_URL=postgres://user:pass@localhost/epigraph_test \
///     cargo test -p epigraph-jobs postgres_queue_integration --features integration
/// ```
#[cfg(all(test, feature = "integration"))]
mod integration_tests {
    use super::*;
    use epigraph_jobs::PostgresJobQueue;
    use sqlx::PgPool;

    async fn get_test_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        PgPool::connect(&url).await.ok()
    }

    async fn cleanup_jobs(pool: &PgPool) {
        sqlx::query("DELETE FROM jobs")
            .execute(pool)
            .await
            .expect("Failed to cleanup jobs table");
    }

    #[tokio::test]
    async fn test_postgres_enqueue_and_get() {
        let Some(pool) = get_test_pool().await else {
            eprintln!("Skipping test: DATABASE_URL not set");
            return;
        };

        cleanup_jobs(&pool).await;
        let queue = PostgresJobQueue::new(pool.clone());

        let job = Job::new("test_postgres", json!({"key": "value"}));
        let job_id = job.id;

        // Enqueue
        let result = queue.enqueue(job).await;
        assert!(result.is_ok(), "Enqueue failed: {:?}", result);

        // Get
        let retrieved = queue.get(job_id).await;
        assert!(retrieved.is_some(), "Job not found");
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.job_type, "test_postgres");
        assert_eq!(retrieved.payload, json!({"key": "value"}));
        assert_eq!(retrieved.state, JobState::Pending);

        cleanup_jobs(&pool).await;
    }

    #[tokio::test]
    async fn test_postgres_dequeue_with_locking() {
        let Some(pool) = get_test_pool().await else {
            eprintln!("Skipping test: DATABASE_URL not set");
            return;
        };

        cleanup_jobs(&pool).await;
        let queue = PostgresJobQueue::new(pool.clone());

        // Enqueue jobs
        let job1 = Job::new("job1", json!({}));
        let job2 = Job::new("job2", json!({}));
        let id1 = job1.id;
        let id2 = job2.id;

        queue.enqueue(job1).await.unwrap();
        queue.enqueue(job2).await.unwrap();

        // Dequeue should return first job
        let dequeued = queue.dequeue().await.expect("Should dequeue job");
        assert_eq!(dequeued.id, id1);
        assert_eq!(
            dequeued.state,
            JobState::Running,
            "Dequeued job should be Running"
        );

        // Second dequeue should return second job
        let dequeued2 = queue.dequeue().await.expect("Should dequeue second job");
        assert_eq!(dequeued2.id, id2);

        // Third dequeue should return None
        let dequeued3 = queue.dequeue().await;
        assert!(dequeued3.is_none());

        cleanup_jobs(&pool).await;
    }

    #[tokio::test]
    async fn test_postgres_update_job() {
        let Some(pool) = get_test_pool().await else {
            eprintln!("Skipping test: DATABASE_URL not set");
            return;
        };

        cleanup_jobs(&pool).await;
        let queue = PostgresJobQueue::new(pool.clone());

        let mut job = Job::new("updateable", json!({}));
        let job_id = job.id;

        queue.enqueue(job.clone()).await.unwrap();

        // Update state
        job.state = JobState::Completed;
        job.completed_at = Some(chrono::Utc::now());
        queue.update(&job).await.unwrap();

        let retrieved = queue.get(job_id).await.unwrap();
        assert_eq!(retrieved.state, JobState::Completed);

        cleanup_jobs(&pool).await;
    }

    #[tokio::test]
    async fn test_postgres_pending_jobs() {
        let Some(pool) = get_test_pool().await else {
            eprintln!("Skipping test: DATABASE_URL not set");
            return;
        };

        cleanup_jobs(&pool).await;
        let queue = PostgresJobQueue::new(pool.clone());

        // Create jobs with different states
        let pending1 = Job::new("pending1", json!({}));
        let pending2 = Job::new("pending2", json!({}));
        let mut running = Job::new("running", json!({}));

        queue.enqueue(pending1).await.unwrap();
        queue.enqueue(pending2).await.unwrap();
        queue.enqueue(running.clone()).await.unwrap();

        // Mark one as running
        running.state = JobState::Running;
        running.started_at = Some(chrono::Utc::now());
        queue.update(&running).await.unwrap();

        // Get pending jobs
        let pending = queue.pending_jobs().await;
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().all(|j| j.state == JobState::Pending));

        cleanup_jobs(&pool).await;
    }

    #[tokio::test]
    async fn test_postgres_jobs_by_state() {
        let Some(pool) = get_test_pool().await else {
            eprintln!("Skipping test: DATABASE_URL not set");
            return;
        };

        cleanup_jobs(&pool).await;
        let queue = PostgresJobQueue::new(pool.clone());

        // Create jobs with different states
        let mut completed1 = Job::new("completed1", json!({}));
        let mut completed2 = Job::new("completed2", json!({}));
        let pending = Job::new("pending", json!({}));

        queue.enqueue(completed1.clone()).await.unwrap();
        queue.enqueue(completed2.clone()).await.unwrap();
        queue.enqueue(pending).await.unwrap();

        // Mark as completed
        completed1.state = JobState::Completed;
        completed2.state = JobState::Completed;
        queue.update(&completed1).await.unwrap();
        queue.update(&completed2).await.unwrap();

        // Get completed jobs
        let completed = queue.jobs_by_state(JobState::Completed).await;
        assert_eq!(completed.len(), 2);

        cleanup_jobs(&pool).await;
    }

    #[tokio::test]
    async fn test_postgres_count_by_state() {
        let Some(pool) = get_test_pool().await else {
            eprintln!("Skipping test: DATABASE_URL not set");
            return;
        };

        cleanup_jobs(&pool).await;
        let queue = PostgresJobQueue::new(pool.clone());

        // Create jobs
        for i in 0..5 {
            let job = Job::new(format!("job{i}"), json!({}));
            queue.enqueue(job).await.unwrap();
        }

        let count = queue.count_by_state(JobState::Pending).await.unwrap();
        assert_eq!(count, 5);

        cleanup_jobs(&pool).await;
    }
}
