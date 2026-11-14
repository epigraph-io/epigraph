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

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use epigraph_jobs::{
    cluster_graph::ClusterGraphHandler,
    privatization::{
        PrivatizationApplyHandler, PrivatizationResealHandler, PrivatizationRevertHandler,
    },
    ConfigurableEmbeddingHandler, JobError, JobQueue, JobRunner, JobState, PostgresJobQueue,
};
use serde::Serialize;
use uuid::Uuid;

use crate::embedding_restore::{ClaimEmbeddingJobService, EmbeddingProviderKind};

/// A job left in `running` longer than this is reaped at the start of a run.
/// It exceeds the 45-minute statement timeout, so a job that is legitimately
/// running is never reset out from under itself.
///
/// A reap COUNTS as a used attempt ([`PostgresJobQueue::reap_stale_jobs_counting_attempts`]):
/// a job that outlives the unit's start timeout is killed by systemd, and an
/// uncounted reset would re-run it and have it killed again forever. The
/// counted reset bounds that loop by the job's `max_retries`, then fails the
/// row (a failure of the run: exit 1). A one-attempt row (`max_retries <= 1`:
/// the privatization apply, revert and reseal jobs) is reset uncounted and
/// re-delivered to its handler instead, at most
/// [`epigraph_jobs::MAX_CRASH_REDELIVERIES`] times (migration 220's
/// `redelivery_count`); the reap after that fails it, also exit 1. (The
/// unseal's `embedding_generation` jobs carry a retry budget since backlog
/// 1320b4e3, so their reaps count.)
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
/// lease `Viewer::system` requires); `queue` is the queue the runner claims
/// from; `embedder` and `provider` come from
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
/// configured. Declining leaves the jobs pending, and every run reports them
/// and exits [`EXIT_PENDING_UNREGISTERED`] until a run that registers the type
/// drains them or an operator cancels them (`drain_jobs --cancel-pending
/// embedding_generation`, [`drain_cancelling`]). The claims keep a NULL
/// `claims.embedding` until `embed_backfill` runs with an owning provider;
/// `epigraph-cli reembed` does not restore them (it writes `embedding_3072`).
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
             `embed_backfill` runs with an owning provider; their pending jobs \
             wait (exit 4) until cancelled with `--cancel-pending`"
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
    /// `true`: it is now `failed`, because the error was permanent
    /// ([`JobError::should_retry`] false) or it used its last retry. `false`:
    /// it is back to `pending` and the next run retries it.
    pub terminal: bool,
}

/// What one drain run did. Printed as JSON by `drain_jobs`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DrainReport {
    /// `true` when another run held the drain lock, so this one did nothing.
    /// Set by the binary, never by [`drain`].
    pub locked: bool,
    /// Stale `running` rows reset to `pending` before draining. A stale row
    /// whose reap used its last attempt is not counted here: it is `failed`
    /// and listed in `failures` (terminal).
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
    /// Pending jobs of a type this run has NO handler for, counted per type at
    /// the end of the run. The drain never claims them, so they wait until a
    /// run registers their type (an `embedding_generation` job on an instance
    /// whose embedding provider may not write `claims.embedding`, or a type no
    /// handler exists for at all). Empty when there are none.
    pub pending_unregistered: BTreeMap<String, i64>,
    /// Pending jobs this run CANCELLED because the operator named their type
    /// in `--cancel-pending` ([`drain_cancelling`]), per type. Each such type
    /// had no handler in this run. Empty when none were named or none were
    /// pending.
    pub cancelled_unregistered: BTreeMap<String, i64>,
}

/// The `error_message` of a pending job `drain_jobs --cancel-pending` cancelled.
pub const CANCELLED_UNREGISTERED_MESSAGE: &str =
    "cancelled by drain_jobs --cancel-pending: no handler for this job type is registered \
     on this instance";

/// The exit code of a run that left pending jobs no handler of this run can
/// claim (and had no job failure): see [`DrainReport::exit_code`].
pub const EXIT_PENDING_UNREGISTERED: i32 = 4;

impl DrainReport {
    /// The process exit code: 1 when any job failed in this run, retryable or
    /// terminal; otherwise 4 ([`EXIT_PENDING_UNREGISTERED`]) when pending jobs
    /// of an unregistered type are waiting; otherwise 3 when the run ran out of
    /// time with work pending; otherwise 0 (drained, or locked).
    ///
    /// A retryable failure is a failed run: the job is back to `pending` and
    /// the next run retries it, but an operator hears about it the first time
    /// (the timer's `OnFailure=` alert), not only once its retries are spent.
    /// A failure outranks running out of time because the unit treats exit 3
    /// as success (`SuccessExitStatus=3`): a failure in a long run must not be
    /// reported as a clean continuation.
    ///
    /// Unregistered pending work is its own code, not 0: before it the run
    /// exited 0 while those jobs sat in the queue for ever, which reads as
    /// "drained" (backlog f5448fed). It outranks 3 for the same reason a
    /// failure does, and ranks below 1 so a job failure is never hidden.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if !self.failures.is_empty() {
            1
        } else if !self.pending_unregistered.is_empty() {
            EXIT_PENDING_UNREGISTERED
        } else if self.out_of_time {
            3
        } else {
            0
        }
    }
}

/// Drain the queue once: reap stale `running` rows (a counted attempt, see
/// [`STALE_AFTER`]), then claim and run the oldest pending job of a registered
/// type, one at a time, until none is left or `max_runtime` has elapsed.
///
/// Each job's final state is written back with `JobQueue::update`:
/// `completed`; or, on a transient handler error
/// ([`JobError::should_retry`]), `pending` again with the retry counted (not
/// retried in this run: the next run is the backoff), or `failed` once its
/// retries are used up; or, on a permanent handler error, `failed` at once.
///
/// # Errors
/// A database error reading or claiming from the queue (the run stops; the
/// rows it had not reached are untouched).
pub async fn drain(
    runner: &JobRunner,
    queue: &PostgresJobQueue,
    max_runtime: Duration,
) -> Result<DrainReport, JobError> {
    drain_cancelling(runner, queue, max_runtime, &[]).await
}

/// [`drain`], after cancelling every pending job whose type is in `cancel`
/// (`drain_jobs --cancel-pending <TYPE>`, repeatable).
///
/// This is the supported way out of exit [`EXIT_PENDING_UNREGISTERED`] on an
/// instance that will never register a type, such as `embedding_generation`
/// where the embedding provider may not write `claims.embedding`: without it
/// those rows keep every run at exit 4 and only raw SQL on `jobs` clears them.
/// The cancelled rows end `cancelled` with [`CANCELLED_UNREGISTERED_MESSAGE`]
/// and are counted in [`DrainReport::cancelled_unregistered`];
/// `pending_unregistered` is counted after the cancel, so a run that cancels
/// the only such type exits 0 (or 3).
///
/// # Errors
/// `JobError::PermanentFailure`, before ANY write (no reap, no cancel), when a
/// type in `cancel` has a handler in this run: those jobs are work this run
/// can do, and cancelling them would discard it. Otherwise as [`drain`].
pub async fn drain_cancelling(
    runner: &JobRunner,
    queue: &PostgresJobQueue,
    max_runtime: Duration,
    cancel: &[String],
) -> Result<DrainReport, JobError> {
    let started = Instant::now();
    let registered = runner.registered_job_types();
    let refused: Vec<&String> = cancel.iter().filter(|t| registered.contains(t)).collect();
    if !refused.is_empty() {
        return Err(JobError::PermanentFailure {
            message: format!(
                "refusing --cancel-pending for {refused:?}: this run has a handler for it, so its \
                 pending jobs are work the drain can do"
            ),
        });
    }
    let reaped = queue.reap_stale_jobs_counting_attempts(STALE_AFTER).await?;
    let mut report = DrainReport {
        recovered_stale: reaped.iter().filter(|r| !r.failed).count() as u64,
        failures: reaped
            .iter()
            .filter(|r| r.failed)
            .map(|r| DrainFailure {
                job_id: r.id,
                job_type: r.job_type.clone(),
                error: if r.one_attempt {
                    epigraph_jobs::REAPED_REDELIVERIES_SPENT_MESSAGE
                } else {
                    epigraph_jobs::REAPED_SPENT_MESSAGE
                }
                .to_string(),
                terminal: true,
            })
            .collect(),
        registered: {
            let mut t = runner.registered_job_types();
            t.sort();
            t
        },
        ..DrainReport::default()
    };
    if !cancel.is_empty() {
        report.cancelled_unregistered = queue
            .cancel_pending_of_types(cancel, CANCELLED_UNREGISTERED_MESSAGE)
            .await?;
        tracing::warn!(
            cancelled_unregistered = ?report.cancelled_unregistered,
            "drain: cancelled pending jobs of types this run has no handler for (--cancel-pending)"
        );
    }
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
                // A permanent error (`JobError::should_retry` false: a refusal,
                // a payload that will never parse, an SSRF block) is terminal on
                // its first occurrence; only a transient one spends the budget.
                let terminal = !e.should_retry() || job.retry_count >= job.max_retries;
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
    report.pending_unregistered = queue
        .count_pending_by_type_outside(&report.registered)
        .await?;
    if !report.pending_unregistered.is_empty() {
        tracing::warn!(
            pending_unregistered = ?report.pending_unregistered,
            "drain: pending jobs of a type this run has no handler for are waiting"
        );
    }
    Ok(report)
}
