//! The job queue's drain, run by the `drain_jobs` timer binary (operator
//! decision D9, batch W12a).
//!
//! # Why the queue left `server`
//!
//! Before D9 `bin/server.rs` ran a `JobRunner` forever on a job pool built from
//! the maintenance DSN, beside a stale-job reaper. D9 removes the maintenance
//! DSN from every request-serving process, so the queue moved to a scheduled,
//! privileged binary: `drain_jobs`, run by `epigraph-jobs-drain.timer` as a
//! non-superuser LOGIN in `epigraph_maintenance`. Each run reaps stale
//! `running` rows, then drains the queue until it is empty or the run is out
//! of time, and exits.
//!
//! # This module is the ONE place the handlers are registered
//!
//! [`build_job_runner`] is the registration `bin/server.rs` used to carry,
//! moved here whole (the six handlers and the provider gate on the embedding
//! one), and only `bin/drain_jobs.rs` calls it.
//! `crates/epigraph-db/tests/maintenance_surface_register.rs` pins that no
//! other request-path source constructs a job runner or a job queue.
//!
//! In the library, not in the binary, because a type or function defined in a
//! `[[bin]]` exports nothing: the drain's behaviour is tested by driving
//! [`drain`] directly on a maintenance login.

use std::sync::Arc;
use std::time::{Duration, Instant};

use epigraph_jobs::{
    cluster_graph::ClusterGraphHandler,
    privatization::{
        PrivatizationApplyHandler, PrivatizationResealHandler, PrivatizationRevertHandler,
    },
    theme_cluster_rebuild::ThemeClusterRebuildHandler,
    ConfigurableEmbeddingHandler, JobError, JobQueue, JobRunner, JobState, PostgresJobQueue,
};
use serde::Serialize;
use uuid::Uuid;

use crate::embedding_restore::{ClaimEmbeddingJobService, EmbeddingProviderKind};

/// A job left in `running` longer than this is reset to `pending` at the start
/// of a run. It exceeds the 45-minute statement timeout, so a job that is
/// legitimately running is never reset out from under itself.
pub const STALE_AFTER: Duration = Duration::from_secs(90 * 60);

/// The per-connection statement timeout of the drain's pool, unless
/// `EPIGRAPH_JOB_STATEMENT_TIMEOUT_MS` overrides it: a runaway clustering query,
/// or a backend orphaned by a hard restart, self-aborts instead of grinding for
/// hours and saturating Postgres (incident 2026-05-29).
pub const DEFAULT_STATEMENT_TIMEOUT: Duration = Duration::from_secs(45 * 60);

/// The default `--max-runtime`: the run stops claiming new jobs after this.
pub const DEFAULT_MAX_RUNTIME: Duration = Duration::from_secs(50 * 60);

/// Build the job runner with every production handler registered, on the
/// maintenance pool.
///
/// `handler_scoped` must be the drain's maintenance `ScopedPool` (the
/// privatization handlers need `unscoped_for_maintenance`, the only mint of the
/// lease `Viewer::system` requires); `queue` is the queue the theme rebuild
/// enqueues its follow-up on; `embedder` and `provider` come from
/// [`crate::embedding_restore::embedding_service_from_env`].
///
/// # The embedding handler is registered CONDITIONALLY
///
/// `embedding_generation`, which `unseal-commit` enqueues once per restored
/// claim, is registered only when the provider OWNS `claims.embedding`
/// ([`EmbeddingProviderKind::may_restore_claim_embeddings`]). The provider
/// chain falls through to a mock without failing, which is correct for a query
/// path and destructive for a write path: an unconditional registration would
/// fill the live ANN column with vectors from whatever provider happened to be
/// configured. Declining leaves the jobs pending; `epigraph-cli reembed` is the
/// recovery path.
///
/// # The privatization handlers are registered together
///
/// An unregistered privatization job type would leave a plan mid-flight
/// forever with no error, so `privatization_apply`, `privatization_revert` and
/// `privatization_reseal` are registered side by side. (Under D9 the lifecycle
/// routes that enqueue them answer 501 MOVED; the handlers stay registered so
/// any job already queued is still carried out.)
#[must_use]
pub fn build_job_runner(
    handler_scoped: Arc<epigraph_db::ScopedPool>,
    queue: Arc<dyn JobQueue>,
    embedder: Arc<dyn epigraph_embeddings::EmbeddingService>,
    provider: EmbeddingProviderKind,
) -> JobRunner {
    let handler_pool = Arc::new(handler_scoped.inner().clone());
    // One worker: the drain processes jobs one at a time (see `drain`), and
    // `JobRunner::start` is never called, so the count is not used for
    // concurrency. It is 1 so nothing reads as if it were.
    let mut runner = JobRunner::new(1, Arc::clone(&queue));
    runner.register_handler(Arc::new(ClusterGraphHandler::new(Arc::clone(
        &handler_pool,
    ))));
    runner.register_handler(Arc::new(ThemeClusterRebuildHandler::with_followup_queue(
        Arc::clone(&handler_pool),
        queue,
    )));
    runner.register_handler(Arc::new(PrivatizationApplyHandler::new(Arc::clone(
        &handler_scoped,
    ))));
    runner.register_handler(Arc::new(PrivatizationRevertHandler::new(Arc::clone(
        &handler_scoped,
    ))));
    runner.register_handler(Arc::new(PrivatizationResealHandler::new(Arc::clone(
        &handler_scoped,
    ))));
    if provider.may_restore_claim_embeddings() {
        runner.register_handler(Arc::new(ConfigurableEmbeddingHandler::new(Arc::new(
            ClaimEmbeddingJobService::new(Arc::clone(&handler_scoped), embedder),
        ))));
        tracing::info!(
            provider = provider.as_str(),
            "embedding_generation handler registered; unsealed claims regain claims.embedding"
        );
    } else {
        tracing::warn!(
            provider = provider.as_str(),
            "embedding_generation NOT registered: this provider must not write \
             claims.embedding. Unsealed claims keep NULL vectors until \
             `epigraph-cli reembed` runs"
        );
    }
    runner
}

/// One job the run could not complete.
#[derive(Debug, Clone, Serialize)]
pub struct DrainFailure {
    /// The job row.
    pub job_id: Uuid,
    /// Its type.
    pub job_type: String,
    /// The handler's error.
    pub error: String,
    /// `true`: it used its last retry and is now `failed`. `false`: it is back
    /// to `pending` and the next run retries it.
    pub terminal: bool,
}

/// What one drain run did. Printed as JSON by `drain_jobs`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DrainReport {
    /// `true` when another run held the drain lock, so this one did nothing.
    /// Set by the binary, never by [`drain`].
    pub locked: bool,
    /// Stale `running` rows reset to `pending` before draining.
    pub recovered_stale: u64,
    /// The job types this run had a handler for.
    pub registered: Vec<String>,
    /// Jobs completed.
    pub completed: u64,
    /// Jobs whose handler failed, terminal or awaiting the next run's retry.
    pub failures: Vec<DrainFailure>,
    /// `true` when the run stopped claiming jobs because `max_runtime` ran out
    /// with work still pending.
    pub out_of_time: bool,
}

impl DrainReport {
    /// The process exit code: 1 when any job failed in this run, retryable or
    /// terminal; otherwise 3 when the run ran out of time with work pending;
    /// otherwise 0 (drained, or locked).
    ///
    /// A retryable failure is a failed run: the job is back to `pending` and
    /// the next run retries it, but an operator hears about it the first time
    /// (the timer's `OnFailure=` alert), not only once its retries are spent.
    /// A failure outranks running out of time because the unit treats exit 3
    /// as success (`SuccessExitStatus=3`): a failure in a long run must not be
    /// reported as a clean continuation.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if !self.failures.is_empty() {
            1
        } else if self.out_of_time {
            3
        } else {
            0
        }
    }
}

/// Drain the queue once: reset stale `running` rows, then claim and run the
/// oldest pending job of a registered type, one at a time, until none is left
/// or `max_runtime` has elapsed.
///
/// Each job's final state is written back with `JobQueue::update`:
/// `completed`; or, on a handler error, `pending` again with the retry counted
/// (not retried in this run: the next run is the backoff), or `failed` once
/// its retries are used up.
///
/// # Errors
/// A database error reading or claiming from the queue (the run stops; the
/// rows it had not reached are untouched).
pub async fn drain(
    runner: &JobRunner,
    queue: &PostgresJobQueue,
    max_runtime: Duration,
) -> Result<DrainReport, JobError> {
    let started = Instant::now();
    let mut report = DrainReport {
        recovered_stale: queue.recover_stale_jobs(STALE_AFTER).await?,
        registered: {
            let mut t = runner.registered_job_types();
            t.sort();
            t
        },
        ..DrainReport::default()
    };
    let mut retry_next_run: Vec<Uuid> = Vec::new();
    loop {
        if started.elapsed() >= max_runtime {
            // Out of time only if work this run could have done is left.
            report.out_of_time = queue
                .count_pending_of_types(&report.registered, &retry_next_run)
                .await?
                > 0;
            break;
        }
        let Some(mut job) = queue
            .dequeue_of_types(&report.registered, &retry_next_run)
            .await?
        else {
            break;
        };
        match runner.process_job(&mut job).await {
            Ok(_) => {
                job.state = JobState::Completed;
                job.updated_at = chrono::Utc::now();
                job.completed_at = Some(job.updated_at);
                queue.update(&job).await?;
                report.completed += 1;
            }
            Err(e) => {
                let terminal = job.retry_count >= job.max_retries;
                job.error_message = Some(e.to_string());
                job.updated_at = chrono::Utc::now();
                if terminal {
                    job.state = JobState::Failed;
                    job.completed_at = Some(job.updated_at);
                } else {
                    job.state = JobState::Pending;
                    job.started_at = None;
                    retry_next_run.push(job.id.into());
                }
                queue.update(&job).await?;
                tracing::warn!(
                    job_id = %job.id,
                    job_type = %job.job_type,
                    terminal,
                    error = %e,
                    "drain: job failed"
                );
                report.failures.push(DrainFailure {
                    job_id: job.id.into(),
                    job_type: job.job_type.clone(),
                    error: e.to_string(),
                    terminal,
                });
            }
        }
    }
    Ok(report)
}
