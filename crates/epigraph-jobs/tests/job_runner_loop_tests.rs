//! `JobRunner::start`'s worker loop, observed through a queue that records
//! every write the loop makes.
//!
//! `InMemoryJobQueue::dequeue` REMOVES the job it hands out, so its `update`
//! of that job is a no-op and a test on it cannot see what the loop wrote.
//! [`RecordingQueue`] keeps every `update` and `enqueue` instead, which is
//! what a persistent queue (`PostgresJobQueue`) would have stored.
//!
//! The drain timer (`epigraph-api`'s `jobs_drain`) does not use this loop; a
//! downstream embedder of the crate does (`JobRunner::new` + `start`).

use epigraph_jobs::{
    async_trait, Job, JobError, JobHandler, JobId, JobQueue, JobResult, JobRunner, JobState,
};
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A queue that hands each enqueued job out once and records every write.
#[derive(Default)]
struct RecordingQueue {
    pending: Mutex<Vec<Job>>,
    updates: Mutex<Vec<Job>>,
}

impl RecordingQueue {
    fn updates(&self) -> Vec<Job> {
        self.updates.lock().unwrap().clone()
    }
}

#[async_trait]
impl JobQueue for RecordingQueue {
    async fn enqueue(&self, job: Job) -> Result<JobId, JobError> {
        let id = job.id;
        self.pending.lock().unwrap().push(job);
        Ok(id)
    }

    async fn dequeue(&self) -> Option<Job> {
        let mut pending = self.pending.lock().unwrap();
        let idx = pending.iter().position(|j| j.state == JobState::Pending)?;
        let mut job = pending.remove(idx);
        // As `PostgresJobQueue::dequeue` does: the claimed row is `running`.
        job.state = JobState::Running;
        Some(job)
    }

    async fn update(&self, job: &Job) -> Result<(), JobError> {
        self.updates.lock().unwrap().push(job.clone());
        Ok(())
    }

    async fn get(&self, _id: JobId) -> Option<Job> {
        None
    }

    async fn pending_jobs(&self) -> Vec<Job> {
        self.pending.lock().unwrap().clone()
    }
}

/// Run the loop over `queue` with `handlers` until it has had time to drain.
async fn run_loop(queue: &Arc<RecordingQueue>, handlers: Vec<Arc<dyn JobHandler>>) {
    let mut runner = JobRunner::new(1, Arc::clone(queue) as Arc<dyn JobQueue>);
    for h in handlers {
        runner.register_handler(h);
    }
    runner.start().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    runner.shutdown().await;
}

/// A dequeued job whose type has no registered handler is written back as
/// `failed`, with the reason, instead of being dropped by the loop. On a
/// persistent queue `dequeue` has already flipped the row to `running`, so a
/// loop that writes nothing strands it there: no handler will ever finish it
/// and nothing says why (backlog 99dc2bbd).
#[tokio::test]
async fn a_job_with_no_handler_is_failed_not_stranded_in_running() {
    let queue = Arc::new(RecordingQueue::default());
    let orphan = Job::new("no_such_handler", json!({}));
    let orphan_id = orphan.id;
    queue.enqueue(orphan).await.unwrap();

    run_loop(&queue, Vec::new()).await;

    let updates = queue.updates();
    let last = updates
        .iter()
        .rev()
        .find(|j| j.id == orphan_id)
        .unwrap_or_else(|| {
            panic!(
                "the loop dequeued a handler-less job and wrote nothing back: on a persistent \
                 queue it stays `running` forever"
            )
        });
    assert_eq!(last.state, JobState::Failed, "{last:?}");
    assert!(
        last.error_message
            .as_deref()
            .is_some_and(|m| m.contains("no handler registered for job type: no_such_handler")),
        "the failure does not say why: {last:?}"
    );
    assert!(last.completed_at.is_some(), "{last:?}");
}

/// A handler whose every attempt fails with the given error.
struct AlwaysFails {
    job_type: &'static str,
    error: JobError,
}

#[async_trait]
impl JobHandler for AlwaysFails {
    async fn handle(&self, _job: &Job) -> Result<JobResult, JobError> {
        Err(self.error.clone())
    }

    fn job_type(&self) -> &str {
        self.job_type
    }

    fn backoff(&self, _attempt: u32) -> Duration {
        Duration::from_millis(1)
    }
}

/// Calibration for the handler-less arm: a job whose handler IS registered
/// still runs through it, and a transient failure is retried by the loop.
#[tokio::test]
async fn a_registered_handler_still_runs_and_a_transient_failure_is_retried() {
    let queue = Arc::new(RecordingQueue::default());
    let job = Job::new("transient", json!({})).with_max_retries(3);
    let id = job.id;
    queue.enqueue(job).await.unwrap();

    run_loop(
        &queue,
        vec![Arc::new(AlwaysFails {
            job_type: "transient",
            error: JobError::ProcessingFailed {
                message: "provider 503".into(),
            },
        })],
    )
    .await;

    let mine: Vec<Job> = queue.updates().into_iter().filter(|j| j.id == id).collect();
    let last = mine.last().expect("the loop wrote the job back");
    assert_eq!(
        (last.state, last.retry_count),
        (JobState::Failed, 3),
        "a transient failure must use its whole budget: {mine:?}"
    );
    assert!(
        mine.iter().any(|j| j.state == JobState::Pending),
        "a transient failure was never put back for a retry: {mine:?}"
    );
}
