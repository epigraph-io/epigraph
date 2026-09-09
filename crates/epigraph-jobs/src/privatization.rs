//! D4 privatization: the apply and revert job handlers.
//!
//! FINAL-PLAN §6.5.5. A 100k-item plan would hold row locks on `claims`,
//! `evidence`, `edges` and seventeen derived tables for minutes, so this is not
//! one transaction — it is a job, batched, resumable, and ordered so that every
//! commit boundary leaves a consistent world.
//!
//! # THE HANDLER RE-VALIDATES. THE HTTP LAYER'S CHECKS ARE NOT THE
//! AUTHORIZATION (sec F5).
//!
//! FINAL-PLAN §6.5.5 states it in those words and the shape of this module is
//! that sentence. `POST …/apply` validates, flips `state='applying'`, enqueues
//! and returns `202`. Everything the enqueuer asserted then arrives here as
//! three fields of a JSON payload, and the plan's own words are that "anything
//! that can insert a `jobs` row could otherwise apply an unapproved,
//! un-second-approved, stale-digest plan with full RLS bypass, and the 409/428
//! responses would be decorative".
//!
//! So [`validate`] re-reads the plan `FOR UPDATE` and refuses unless ALL SIX
//! of §6.5.5's conditions hold, before a single row is touched:
//!
//! 1. `state` is the running state this job is for (`applying` / `reverting`);
//! 2. `approved_by IS NOT NULL AND approved_by <> created_by` whenever
//!    `item_count > 1000` **or** `authors_losing_count > 0`;
//! 3. the approver is a LIVE `role='admin'` of `target_group_id` — re-checked
//!    here because membership can be revoked between approve and dispatch, which
//!    is a window migration 081's approver guard cannot see;
//! 4. the stored `plan_digest` equals a digest RECOMPUTED from
//!    `privatization_plan_items` at dispatch time, not the stored value compared
//!    with itself;
//! 5. `acknowledge_author_loss` is true whenever
//!    `mode='seal' AND authors_losing_count > 0`;
//! 6. `dispatched_by` matches the payload AND a `privatization_dispatch`
//!    `security_events` row with this `correlation_id` is attributed to that
//!    same agent.
//!
//! **Every refusal writes `privatization_audit(action='plan.abort')` and sets
//! `state='failed'`**, commits that, and only then returns
//! [`JobError::PermanentFailure`] — a refusal is not a transient fault and must
//! not be retried into a hot loop.
//!
//! # The pool type, and an honest accounting of what it guarantees
//!
//! §6.5.5 sketches these handlers as `{ pool: MaintenancePool }` and notes "NOT
//! PgPool (ops F5)". `MaintenancePool` is `epigraph_cli::MaintenancePool` and
//! this crate does not depend on `epigraph-cli`; inverting that layering to name
//! a type would be a larger change than the guarantee is worth. What is taken
//! instead is [`epigraph_db::ScopedPool`], which is nameable here and which is
//! the type that mints a `MaintenanceLease` — and `Viewer::system` cannot be
//! built without one. So the bypass viewer the drift rescan needs is reachable
//! only through `ScopedPool::unscoped_for_maintenance`, by construction rather
//! than by convention.
//!
//! What that does NOT buy: `ScopedPool` does not prove the DSN behind it is
//! privileged. `bin/server.rs` probes that once at boot with
//! `epigraph_db::assert_maintenance_privilege` and refuses to start otherwise,
//! and the job pool shares that DSN. The coupling between "this is a job
//! handler" and "this connection can bypass" therefore remains a convention,
//! which is the already-recorded `D-PR17-maintenance-lease-coupling-is-a-convention`
//! rather than a new finding.
//!
//! # Ordering, batching and the invariant a `kill -9` leaves behind
//!
//! Batch 50 (§6.5.5's ops-F11 correction; the ceiling is [`MAX_BATCH`]), one
//! transaction each, `ORDER BY depth DESC, kind, entity_id` on apply and
//! `depth ASC` on revert, `FOR UPDATE` and never `SKIP LOCKED`.
//!
//! Deepest-first is the invariant, not a preference: at every commit boundary
//! the private set is CLOSED DOWNWARD under the content-derivation relation, so
//! an interrupted apply leaves a downward-closed prefix private and the rest
//! public. The inverse order would leave a private parent with public
//! `decomposes_to` children, and a `kill -9` would leave that state permanently.
//! Revert walks the mirror.
//!
//! Each batch takes ONE GLOBAL advisory lock
//! (`pg_advisory_xact_lock(hashtext('epigraph.privatization'))`, ops F12) rather
//! than a per-plan one: two plans against different target groups can touch the
//! same boundary `edges` rows in opposite orders, and `ClaimRepository::consolidate`
//! takes the opposite lock order to this batch. There is no stated need for
//! concurrent privatizations.
//!
//! # What is NOT here
//!
//! `PrivatizationResealHandler`. §6.5.5 names three handlers; the third reseals
//! group-key-rotated ciphertext, and `seal` mode is PR-21's —
//! `routes/privatization.rs::create_plan` still returns `501` for it. The
//! sealing primitives now exist in `crates/epigraph-privacy`, but they are
//! client-side by construction: no server-side job can reseal content whose key
//! the server does not hold, so this handler waits on the manifest ceremony
//! that carries the ciphertext, not on the encryptor.
//!
//! Migration 077's `jobs_app` policy already names
//! `privatization_reseal` and keeps naming it; the job type exists in the policy
//! and has no producer, which is the same forward-staging that file describes.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use epigraph_db::repos::privatization::{
    ItemAuditBatch, ItemAuditDirection, PlanAuditEntry, PlanRow, PlanTransition,
    PrivatizationRepository, SelectionError,
};
use epigraph_db::repos::security_event::SecurityEventRepository;
use epigraph_db::visibility::SystemReason;
use epigraph_db::ScopedPool;

use crate::{EpiGraphJob, Job, JobError, JobHandler, JobResult, JobResultMetadata};

/// The `jobs.job_type` migration 077's `jobs_app` policy names for apply.
///
/// Spelled as a constant in ONE place and referenced from
/// [`EpiGraphJob::job_type`], because the policy arm that refuses an app-role
/// enqueue of privatization work is a string comparison: a job type that drifts
/// from the policy's spelling is not refused and raises nothing.
pub const APPLY_JOB_TYPE: &str = "privatization_apply";

/// The `jobs.job_type` migration 077's `jobs_app` policy names for revert.
pub const REVERT_JOB_TYPE: &str = "privatization_revert";

/// The `security_events.event_type` the dispatching route writes and condition 6
/// looks for.
pub const DISPATCH_EVENT_TYPE: &str = "privatization_dispatch";

/// The `security_events.details` key that binds a dispatch event to the plan it
/// authorises.
///
/// Condition 6 compares it against the plan the job names, so that a correlation
/// id issued for one plan cannot satisfy the condition for another plan of the
/// same dispatcher. The dispatching route writes this key; a row without it
/// fails the condition.
pub const DISPATCH_SUBJECT_KEY: &str = "plan_id";

/// Items per transaction. FINAL-PLAN §6.5.5's ops-F11 correction: "start at
/// batch = 50 and ramp on measured p95 lock-wait, to a ceiling of 500".
///
/// 50 and not 500 because one 500-claim batch row-locks well over ten thousand
/// derived rows plus the edge set until commit, and the job pool's
/// `statement_timeout` is long enough that nothing would kill it.
pub const DEFAULT_BATCH: i64 = 50;

/// The ceiling [`DEFAULT_BATCH`] may be ramped to, from the same paragraph.
pub const MAX_BATCH: i64 = 500;

/// `node_cap` for the post-apply drift rescan.
///
/// The rescan is one hop along the restatement tier plus the hull, so it is
/// bounded by the applied set's own neighbourhood rather than by the corpus. The
/// cap is here so that a pathological fan-out REFUSES — surfacing as a plan left
/// `applied` with the drift unrecorded and an error in the log — rather than
/// walking the whole graph inside a batch transaction.
pub const DRIFT_NODE_CAP: i32 = 50_000;

/// Which direction a run walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// `previewed`/`approved` → `applying` → `applied`.
    Apply,
    /// `applied`/`applied_with_drift` → `reverting` → `reverted`.
    Revert,
}

impl Direction {
    /// The plan state a dispatched job of this direction must find.
    const fn running_state(self) -> &'static str {
        match self {
            Direction::Apply => "applying",
            Direction::Revert => "reverting",
        }
    }

    /// The per-item state this direction consumes.
    ///
    /// Revert consumes `applied` and not `pending`, because §6.5.5 says a revert
    /// "un-applies exactly the items with `state='applied'`" — an item the apply
    /// skipped or failed on was never applied and restoring it would write a
    /// tenancy the plan never changed.
    const fn source_item_state(self) -> &'static str {
        match self {
            Direction::Apply => "pending",
            Direction::Revert => "applied",
        }
    }

    /// The per-item state this direction produces.
    const fn target_item_state(self) -> &'static str {
        match self {
            Direction::Apply => "applied",
            Direction::Revert => "reverted",
        }
    }

    /// The `privatization_audit.action` for a per-item row.
    const fn item_action(self) -> &'static str {
        match self {
            Direction::Apply => "item.apply",
            Direction::Revert => "item.revert",
        }
    }

    /// Which projection the per-item audit row takes, and therefore which side
    /// of the tenancy write it is written on.
    const fn item_audit_direction(self) -> ItemAuditDirection {
        match self {
            Direction::Apply => ItemAuditDirection::Apply,
            Direction::Revert => ItemAuditDirection::Revert,
        }
    }

    /// Deepest-first on apply, shallowest-first on revert.
    const fn deepest_first(self) -> bool {
        matches!(self, Direction::Apply)
    }
}

/// The plan states the refusal path may move to `failed` — every PRE-TERMINAL
/// state migration 080's `pp_state_check` admits.
///
/// Deliberately not the empty list. A refusal must be able to fail a plan that a
/// forged job named in any pre-terminal state, and must NOT relabel a plan that
/// already reached `applied`, `applied_with_drift` or `reverted`. That second
/// case is not hypothetical: `postgres_queue.rs::recover_stale_jobs` resets any
/// job still `running` past its threshold back to `pending` — the recovery this
/// module's one-attempt budget leans on — so a job whose worker died after the
/// terminal write arrives here with the plan already terminal, and condition 1
/// refuses it. An unconditional `failed` would then record a SUCCESSFUL
/// privatization as having failed, and attribute the abort to the plan's author.
/// `failed` is omitted because it is already the destination.
const REFUSABLE_PLAN_STATES: [&str; 6] = [
    "draft",
    "selecting",
    "previewed",
    "approved",
    "applying",
    "reverting",
];

/// Why a run was refused. Each variant is one of §6.5.5's six conditions.
///
/// The `Display` text is what lands in `privatization_audit` and in the job's
/// failure message. It names the condition and NOT the values that failed it: a
/// refusal reason that quoted the digest or the approver would put plan detail
/// into a job row, which is not a `FORCE`-protected table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// Condition 1.
    #[error("the plan is not in the state a dispatched job must find")]
    WrongState,
    /// Condition 2.
    #[error("the plan needs a second approver and does not have a valid one")]
    SecondApproverMissing,
    /// Condition 3.
    #[error("the approver is no longer a live admin of the target group")]
    ApproverNotGroupAdmin,
    /// Condition 4.
    #[error("the stored digest does not describe the frozen item set")]
    DigestStale,
    /// Condition 5.
    #[error("a seal plan that costs an author access needs an acknowledgement")]
    AuthorLossUnacknowledged,
    /// Condition 6.
    #[error("the dispatch is not attributed to an audited request")]
    DispatchUnattributed,
}

/// Apply a frozen privatization plan.
pub struct PrivatizationApplyHandler {
    pool: Arc<ScopedPool>,
    batch_size: i64,
}

/// Un-apply a frozen privatization plan.
pub struct PrivatizationRevertHandler {
    pool: Arc<ScopedPool>,
    batch_size: i64,
}

impl PrivatizationApplyHandler {
    /// Bind a handler to the maintenance-DSN pool.
    ///
    /// The pool's privilege is asserted once at process start by
    /// `epigraph_db::assert_maintenance_privilege`; see the module doc for what
    /// that does and does not guarantee.
    #[must_use]
    pub const fn new(pool: Arc<ScopedPool>) -> Self {
        Self {
            pool,
            batch_size: DEFAULT_BATCH,
        }
    }

    /// Override the batch size, clamped to `1..=`[`MAX_BATCH`].
    ///
    /// Present so `privatization_resume.rs` can interrupt a run at a chosen
    /// batch boundary without seeding fifty-one claims per assertion.
    #[must_use]
    pub const fn with_batch_size(mut self, batch: i64) -> Self {
        self.batch_size = clamp_batch(batch);
        self
    }
}

impl PrivatizationRevertHandler {
    /// Bind a handler to the maintenance-DSN pool.
    #[must_use]
    pub const fn new(pool: Arc<ScopedPool>) -> Self {
        Self {
            pool,
            batch_size: DEFAULT_BATCH,
        }
    }

    /// Override the batch size, clamped to `1..=`[`MAX_BATCH`].
    #[must_use]
    pub const fn with_batch_size(mut self, batch: i64) -> Self {
        self.batch_size = clamp_batch(batch);
        self
    }
}

/// `const`-compatible clamp; `Ord::clamp` is not a `const fn`.
const fn clamp_batch(batch: i64) -> i64 {
    if batch < 1 {
        1
    } else if batch > MAX_BATCH {
        MAX_BATCH
    } else {
        batch
    }
}

#[async_trait]
impl JobHandler for PrivatizationApplyHandler {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        let (plan_id, dispatched_by, correlation_id) = decode(job, Direction::Apply)?;
        run(
            &self.pool,
            Direction::Apply,
            plan_id,
            dispatched_by,
            &correlation_id,
            self.batch_size,
        )
        .await
    }

    fn job_type(&self) -> &str {
        APPLY_JOB_TYPE
    }

    /// ONE ATTEMPT, NO RETRY BACKOFF BEYOND THE REAPER.
    ///
    /// A privatization that failed mid-way has left a downward-closed prefix
    /// applied and a plan in `applying`; §6.5.5's recovery story is that the
    /// stale-job reaper re-dispatches it and the handler resumes, re-running the
    /// full re-validation. An exponential retry ladder on top of that would
    /// re-enter the same batch every two seconds while the underlying fault —
    /// a lock timeout, a statement timeout — is still true.
    fn max_retries(&self) -> u32 {
        0
    }
}

#[async_trait]
impl JobHandler for PrivatizationRevertHandler {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        let (plan_id, dispatched_by, correlation_id) = decode(job, Direction::Revert)?;
        run(
            &self.pool,
            Direction::Revert,
            plan_id,
            dispatched_by,
            &correlation_id,
            self.batch_size,
        )
        .await
    }

    fn job_type(&self) -> &str {
        REVERT_JOB_TYPE
    }

    /// See [`PrivatizationApplyHandler::max_retries`].
    fn max_retries(&self) -> u32 {
        0
    }
}

/// Pull the three payload fields out of a `Job`, refusing the wrong variant.
fn decode(job: &Job, direction: Direction) -> Result<(Uuid, Uuid, String), JobError> {
    let decoded: EpiGraphJob =
        serde_json::from_value(job.payload.clone()).map_err(|e| JobError::PayloadError {
            message: format!("privatization payload is not an EpiGraphJob: {e}"),
        })?;
    match (direction, decoded) {
        (
            Direction::Apply,
            EpiGraphJob::PrivatizationApply {
                plan_id,
                dispatched_by,
                correlation_id,
            },
        )
        | (
            Direction::Revert,
            EpiGraphJob::PrivatizationRevert {
                plan_id,
                dispatched_by,
                correlation_id,
            },
        ) => Ok((plan_id, dispatched_by, correlation_id)),
        (_, other) => Err(JobError::PayloadError {
            message: format!(
                "expected a {} payload, got {}",
                match direction {
                    Direction::Apply => APPLY_JOB_TYPE,
                    Direction::Revert => REVERT_JOB_TYPE,
                },
                other.job_type()
            ),
        }),
    }
}

/// The whole run: re-validate, then batch until the work runs out, then (on
/// apply) rescan for drift and record a terminal state.
async fn run(
    pool: &ScopedPool,
    direction: Direction,
    plan_id: Uuid,
    dispatched_by: Uuid,
    correlation_id: &str,
    batch_size: i64,
) -> Result<JobResult, JobError> {
    let started = std::time::Instant::now();

    let plan = match validate(pool, direction, plan_id, dispatched_by, correlation_id).await? {
        Ok(plan) => plan,
        Err(refusal) => {
            return Err(JobError::PermanentFailure {
                message: format!("privatization plan refused by the handler: {refusal}"),
            })
        }
    };

    let mut processed = 0u64;
    let mut aborted = false;
    loop {
        match run_batch(
            pool,
            direction,
            &plan,
            dispatched_by,
            correlation_id,
            batch_size,
        )
        .await
        .map_err(processing_failed)?
        {
            BatchOutcome::Moved(moved) => processed += moved,
            BatchOutcome::Drained => break,
            BatchOutcome::Aborted => {
                aborted = true;
                break;
            }
        }
    }

    // `POST …/abort` set `state='failed'` and the applied prefix stays applied
    // (§6.5.5). Writing a terminal state here would undo the operator's decision
    // one batch later, which is the shape of bug that makes an abort button
    // untrustworthy.
    if aborted {
        tracing::info!(
            target: "tenancy.privatization",
            plan_id = %plan_id,
            items_processed = processed,
            "a privatization run stopped because the plan left its running state"
        );
        let mut extra = HashMap::new();
        extra.insert("plan_id".to_string(), serde_json::json!(plan_id));
        extra.insert("aborted".to_string(), serde_json::json!(true));
        return Ok(JobResult {
            output: serde_json::json!({ "plan_id": plan_id, "aborted": true }),
            execution_duration: started.elapsed(),
            metadata: JobResultMetadata {
                worker_id: Some("privatization".to_string()),
                items_processed: Some(processed),
                extra,
            },
        });
    }

    let drift = if direction == Direction::Apply {
        rescan_for_drift(pool, &plan, dispatched_by, correlation_id).await
    } else {
        0
    };

    let terminal = match (direction, drift) {
        (Direction::Apply, 0) => "applied",
        (Direction::Apply, _) => "applied_with_drift",
        (Direction::Revert, _) => "reverted",
    };
    // THE TERMINAL WRITE IS CONDITIONAL, AND IT IS CONDITIONAL FOR A RACE THAT
    // IS EASY TO MISS. `POST …/abort` can commit between the last batch and this
    // statement. A terminal state written unconditionally would land on top of
    // the `failed` the operator just asked for, one statement later, and the
    // abort button would silently do nothing on the runs where it mattered
    // most. `from_states` is the running state alone, so a plan that has left it
    // is not re-labelled, and `transition_plan_conn`'s row count tells us which
    // happened.
    let finished = {
        let (mut conn, _lease) = pool
            .unscoped_for_maintenance(reason(direction))
            .await
            .map_err(processing_failed)?;
        PrivatizationRepository::transition_plan_conn(
            &mut conn,
            plan_id,
            PlanTransition::Finish {
                state: terminal,
                from_states: &[direction.running_state().to_string()],
            },
        )
        .await
        .map_err(processing_failed)?
    };
    let terminal = if finished == 1 {
        terminal
    } else {
        tracing::info!(
            target: "tenancy.privatization",
            plan_id = %plan_id,
            "the plan left its running state before the terminal write; the state it was left \
             in stands"
        );
        "aborted-before-terminal"
    };

    let mut extra = HashMap::new();
    extra.insert("plan_id".to_string(), serde_json::json!(plan_id));
    extra.insert("state".to_string(), serde_json::json!(terminal));
    extra.insert("drift".to_string(), serde_json::json!(drift));
    Ok(JobResult {
        output: serde_json::json!({ "plan_id": plan_id, "state": terminal, "drift": drift }),
        execution_duration: started.elapsed(),
        metadata: JobResultMetadata {
            worker_id: Some("privatization".to_string()),
            items_processed: Some(processed),
            extra,
        },
    })
}

/// The `SystemReason` a bypass on this path is granted under.
const fn reason(direction: Direction) -> SystemReason {
    match direction {
        // There is no `SystemReason::PrivatizationRevert`. `SystemReason::ALL`
        // is a MONOTONICALLY DECREASING register (`viewer_ratchet.rs`), so a
        // slice that adds a variant has to argue for it; a revert is the same
        // authority as an apply over the same rows, so it reuses the reason
        // rather than growing the set.
        Direction::Apply | Direction::Revert => SystemReason::PrivatizationApply,
    }
}

/// §6.5.5's six conditions, on a `FOR UPDATE` re-read.
///
/// Returns `Ok(Ok(plan))` when the run may proceed and `Ok(Err(refusal))` when
/// it may not — the refusal having already been audited and the plan already
/// moved to `failed`, in the same transaction as the re-read. The outer `Err`
/// is a database fault, which is a different thing from a refusal and must not
/// be recorded as one.
async fn validate(
    pool: &ScopedPool,
    direction: Direction,
    plan_id: Uuid,
    dispatched_by: Uuid,
    correlation_id: &str,
) -> Result<Result<PlanRow, Refusal>, JobError> {
    let (mut conn, _lease) = pool
        .unscoped_for_maintenance(reason(direction))
        .await
        .map_err(processing_failed)?;
    let mut tx =
        sqlx::Connection::begin(&mut *conn)
            .await
            .map_err(|e| JobError::ProcessingFailed {
                message: format!("privatization: could not open the validation transaction: {e}"),
            })?;

    PrivatizationRepository::begin_batch_conn(&mut tx)
        .await
        .map_err(processing_failed)?;

    let Some(plan) = PrivatizationRepository::load_plan_for_update_conn(&mut tx, plan_id)
        .await
        .map_err(processing_failed)?
    else {
        // NOT AUDITED AND NOT FAILED, because there is no plan row to attach
        // either to. `privatization_audit.plan_id` is a NOT NULL FK.
        return Err(JobError::PermanentFailure {
            message: "privatization: no such plan".to_string(),
        });
    };

    let refusal = check(&mut tx, direction, &plan, dispatched_by, correlation_id).await?;

    if let Some(refusal) = refusal {
        // §6.5.5: "Every refusal writes privatization_audit(action='plan.abort')
        // and sets state='failed'." Both, in this transaction, before the
        // connection goes back to the pool.
        PrivatizationRepository::record_plan_audit_conn(
            &mut tx,
            PlanAuditEntry {
                plan_id,
                // The plan's AUTHOR, not the payload's `dispatched_by`. The
                // payload is the thing under suspicion here; attributing the
                // abort to it would let a forged enqueue choose whose name
                // appears in the audit trail.
                actor_agent_id: plan.created_by,
                action: "plan.abort",
                kind: None,
                entity_id: None,
                plan_digest: plan.plan_digest.as_deref(),
                correlation_id: Some(correlation_id),
            },
        )
        .await
        .map_err(processing_failed)?;
        let failed = PrivatizationRepository::transition_plan_conn(
            &mut tx,
            plan_id,
            PlanTransition::Finish {
                state: "failed",
                // EVERY PRE-TERMINAL STATE, and not the empty list. See
                // `REFUSABLE_PLAN_STATES` for why the difference matters.
                from_states: &REFUSABLE_PLAN_STATES
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect::<Vec<_>>(),
            },
        )
        .await
        .map_err(processing_failed)?;
        tx.commit().await.map_err(|e| JobError::ProcessingFailed {
            message: format!("privatization: could not commit the refusal: {e}"),
        })?;
        tracing::warn!(
            target: "tenancy.privatization",
            plan_id = %plan_id,
            refusal = %refusal,
            plan_failed = failed == 1,
            "a dispatched privatization job was refused by the handler"
        );
        return Ok(Err(refusal));
    }

    tx.commit().await.map_err(|e| JobError::ProcessingFailed {
        message: format!("privatization: could not commit the validation: {e}"),
    })?;
    Ok(Ok(plan))
}

/// The six conditions themselves, in §6.5.5's order.
///
/// Every arm returns `Some(_)` for "no". There is no arm that returns `None`
/// because a check could not be performed: a database fault propagates as the
/// outer `Err`, and an absent `security_events` row is condition 6 failing
/// rather than condition 6 being skipped.
async fn check(
    conn: &mut sqlx::PgConnection,
    direction: Direction,
    plan: &PlanRow,
    dispatched_by: Uuid,
    correlation_id: &str,
) -> Result<Option<Refusal>, JobError> {
    // 1.
    if plan.state != direction.running_state() {
        return Ok(Some(Refusal::WrongState));
    }

    // 2. The second-approver rule, thresholds from §6.5.5's "Refusal
    //    thresholds" paragraph. `approved_by <> created_by` is re-checked here
    //    even though `pp_four_eyes` is a CHECK constraint, because a constraint
    //    proves what the column holds and this proves what the handler read.
    let needs_second = plan.item_count > 1000 || plan.authors_losing_count > 0;
    if needs_second {
        match plan.approved_by {
            None => return Ok(Some(Refusal::SecondApproverMissing)),
            Some(approver) if approver == plan.created_by => {
                return Ok(Some(Refusal::SecondApproverMissing))
            }
            Some(_) => {}
        }
    }

    // 3. Membership can be revoked between approve and dispatch. Checked
    //    whenever an approver exists, not only when one was REQUIRED: a plan
    //    that carries a stale approver is not made safer by being small.
    if let Some(approver) = plan.approved_by {
        if !PrivatizationRepository::is_live_group_admin_conn(conn, plan.target_group_id, approver)
            .await
            .map_err(processing_failed)?
        {
            return Ok(Some(Refusal::ApproverNotGroupAdmin));
        }
    }

    // 4. RECOMPUTED from the items, never the stored value compared with itself.
    let frozen = PrivatizationRepository::frozen_digest_conn(conn, plan.id)
        .await
        .map_err(processing_failed)?;
    match plan.plan_digest.as_deref() {
        Some(stored) if stored == frozen => {}
        // A plan with no stored digest is refused rather than treated as
        // "nothing to compare": migration 080 makes `plan_digest` nullable
        // because a `draft` row has none, and a dispatched draft is exactly the
        // hand-enqueued case this function exists for.
        _ => return Ok(Some(Refusal::DigestStale)),
    }

    // 5.
    if plan.mode == "seal" && plan.authors_losing_count > 0 && !plan.acknowledge_author_loss {
        return Ok(Some(Refusal::AuthorLossUnacknowledged));
    }

    // 6. Two halves, and both are needed. The first is that the payload agrees
    //    with the row the dispatching UPDATE wrote; the second is that an
    //    audited request produced that row FOR THIS PLAN. A payload that named a
    //    real plan and a real agent would pass the first alone, and a
    //    correlation id issued for a different plan of the same dispatcher would
    //    pass an unbound second.
    if plan.dispatched_by != Some(dispatched_by) {
        return Ok(Some(Refusal::DispatchUnattributed));
    }
    if !SecurityEventRepository::correlation_is_attributed_to_conn(
        conn,
        DISPATCH_EVENT_TYPE,
        correlation_id,
        dispatched_by,
        (DISPATCH_SUBJECT_KEY, plan.id),
    )
    .await
    .map_err(processing_failed)?
    {
        return Ok(Some(Refusal::DispatchUnattributed));
    }

    Ok(None)
}

/// What one batch transaction concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchOutcome {
    /// This many items moved; there may be more.
    Moved(u64),
    /// No item remains in the source state; the run is complete.
    Drained,
    /// The plan left its running state between batches — `POST …/abort`, or a
    /// second dispatcher. The run stops and writes no terminal state.
    Aborted,
}

/// One batch, one transaction.
///
/// # The plan state is re-read EVERY batch, not only at dispatch
///
/// §6.5.5 gives the operator `POST …/abort`, which "sets `state='failed'`; the
/// applied prefix stays applied". That is only true if a run in flight notices.
/// The re-read is inside the same transaction as the batch and behind the same
/// global advisory lock, so an abort that commits between two batches is seen by
/// the next one and an abort that commits mid-batch is serialised behind it.
async fn run_batch(
    pool: &ScopedPool,
    direction: Direction,
    plan: &PlanRow,
    dispatched_by: Uuid,
    correlation_id: &str,
    batch_size: i64,
) -> Result<BatchOutcome, epigraph_db::DbError> {
    let (mut conn, _lease) = pool.unscoped_for_maintenance(reason(direction)).await?;
    let mut tx = sqlx::Connection::begin(&mut *conn)
        .await
        .map_err(|source| epigraph_db::DbError::QueryFailed { source })?;

    PrivatizationRepository::begin_batch_conn(&mut tx).await?;

    let still_running = PrivatizationRepository::load_plan_for_update_conn(&mut tx, plan.id)
        .await?
        .is_some_and(|p| p.state == direction.running_state());
    if !still_running {
        tx.commit()
            .await
            .map_err(|source| epigraph_db::DbError::QueryFailed { source })?;
        return Ok(BatchOutcome::Aborted);
    }

    let items = PrivatizationRepository::next_batch_conn(
        &mut tx,
        plan.id,
        direction.source_item_state(),
        direction.deepest_first(),
        batch_size,
    )
    .await?;
    if items.is_empty() {
        tx.commit()
            .await
            .map_err(|source| epigraph_db::DbError::QueryFailed { source })?;
        return Ok(BatchOutcome::Drained);
    }

    let ids: Vec<Uuid> = items.iter().map(|i| i.entity_id).collect();
    let audit = ItemAuditBatch {
        plan_id: plan.id,
        actor_agent_id: dispatched_by,
        action: direction.item_action(),
        entity_ids: &ids,
        correlation_id: Some(correlation_id),
        direction: direction.item_audit_direction(),
        target_group_id: plan.target_group_id,
    };

    // THE AUDIT ROW GOES ON A DIFFERENT SIDE OF THE TENANCY WRITE IN EACH
    // DIRECTION, and that is the only reason this is a `match` and not two
    // statements. `privatization_plan_items.before_visibility` is the frozen
    // PRE-APPLY image and never changes, so the "other" half of the pair has to
    // come from `claims` — which means it has to be read while `claims` still
    // holds the value that half is supposed to describe. On apply that is after
    // the write; on revert it is before it. See `ItemAuditDirection`.
    // `changed` is the subset of the batch this direction ACTUALLY MOVED, and
    // the rest of the function turns on the difference. See the `skipped` write
    // below for why "looked at" and "changed" must not be the same item state.
    let changed = match direction {
        Direction::Apply => {
            let changed =
                PrivatizationRepository::restrict_claims_conn(&mut tx, &ids, plan.target_group_id)
                    .await?;
            PrivatizationRepository::record_item_audit_conn(&mut tx, audit).await?;
            changed
        }
        Direction::Revert => {
            PrivatizationRepository::record_item_audit_conn(&mut tx, audit).await?;
            PrivatizationRepository::restore_claims_conn(
                &mut tx,
                plan.id,
                &ids,
                plan.target_group_id,
            )
            .await?;
            // A revert's terminal per-item state ends the item's life in this
            // plan, and nothing reads it back to decide a later write, so the
            // apply direction's distinction buys nothing here.
            ids.clone()
        }
    };

    // The meet re-run comes AFTER the tenancy write, in the same transaction, so
    // an edge is never committed disagreeing with its endpoints.
    PrivatizationRepository::recompute_boundary_meet_conn(&mut tx, &ids).await?;

    // AN ITEM STATE MUST MEAN "THIS PLAN CHANGED THIS ROW", NOT "THIS PLAN
    // LOOKED AT IT". `restrict_claims_conn` is a no-op on a row already sitting
    // in the target group, which a plan frozen while that row was public will
    // meet as an ordinary matter — `privatization_one_active_per_group` excludes
    // only CONCURRENT running plans, so two plans against the same group with
    // overlapping frozen sets need no race to occur. `Direction::Revert`
    // consumes items in `applied`, so an item marked `applied` on the strength
    // of having been read would put this plan's selection-time pre-image, and
    // `epigraph.allow_declassify`, over a row this plan never touched. `skipped`
    // is migration 080's own vocabulary for the difference.
    let skipped: Vec<Uuid> = ids
        .iter()
        .copied()
        .filter(|id| !changed.contains(id))
        .collect();
    let moved = PrivatizationRepository::mark_items_conn(
        &mut tx,
        plan.id,
        "claim",
        &changed,
        direction.target_item_state(),
        None,
    )
    .await?;
    let passed_over = PrivatizationRepository::mark_items_conn(
        &mut tx,
        plan.id,
        "claim",
        &skipped,
        "skipped",
        Some("the row already carried this plan's tenancy; this plan changed nothing about it"),
    )
    .await?;
    // A batch that selected items and decided none of them is a non-terminating
    // loop, not a quiet no-op: `run` would re-select the same rows forever while
    // holding the global privatization lock. `next_batch_conn` and
    // `mark_items_conn` agree on `kind = 'claim'` today, so this cannot fire; it
    // is here so that a future slice which breaks that agreement gets a
    // diagnosable failure instead of a wedge.
    let decided = moved + passed_over;
    if decided != ids.len() as u64 {
        return Err(epigraph_db::DbError::InvalidData {
            reason: format!(
                "privatization: a batch selected {} items and left {} of them undecided",
                ids.len(),
                ids.len() as u64 - decided
            ),
        });
    }

    // The cursor is the LAST item in the batch's total order, which is what
    // makes "resume from the cursor" and "resume from the item states" agree.
    if let Some(last) = items.last() {
        PrivatizationRepository::transition_plan_conn(
            &mut tx,
            plan.id,
            PlanTransition::Cursor {
                kind: &last.kind,
                depth: last.depth,
                id: last.entity_id,
            },
        )
        .await?;
    }

    tx.commit()
        .await
        .map_err(|source| epigraph_db::DbError::QueryFailed { source })?;
    Ok(BatchOutcome::Moved(decided))
}

/// The post-apply drift rescan (sec F9). Returns how many drifted ids it found.
///
/// §6.5.5's sec-F9 fix has two halves. This is the half that READS: after the
/// apply it re-derives the restatement neighbourhood of the applied set and
/// reports what the frozen selection does not cover. The half that WRITES — an
/// `AFTER INSERT` companion on `edges` — is not in this slice; see
/// `D-PR18-drift-write-guard` in `docs/tenancy/progress.json` for its location
/// and owner. Because the read half ships, the condition is REPORTED rather than
/// silent: it lands in `drift_ids`, in `plan.drift` audit rows and in a
/// follow-up plan an operator must review.
///
/// A non-empty result writes `drift_ids`, one `privatization_audit(action=
/// 'plan.drift')` row per id, and auto-creates a follow-up plan in `previewed`
/// against the same target group. The follow-up is `previewed` and not applied:
/// a handler that privatized rows nobody selected would be the standing
/// privatization rule §6.5.1 explicitly refuses to ship.
async fn rescan_for_drift(
    pool: &ScopedPool,
    plan: &PlanRow,
    dispatched_by: Uuid,
    correlation_id: &str,
) -> usize {
    // A RESCAN FAULT IS NOT A FAILED APPLY, AND THAT DECISION IS MADE ONCE HERE
    // RATHER THAN PER ERROR ARM. By the time this runs every item is `applied`
    // and every claim has moved; `run` writes the terminal state only after this
    // returns, so a propagated error would leave a fully applied plan advertising
    // `applying` forever — and, with a one-attempt budget, the stale-job reaper
    // would re-dispatch it into the same fault indefinitely. The refusal arm
    // already made exactly this call; the database arms had not inherited it.
    match rescan_for_drift_inner(pool, plan, dispatched_by, correlation_id).await {
        Ok(found) => found,
        Err(e) => {
            tracing::warn!(
                target: "tenancy.privatization",
                plan_id = %plan.id,
                error = %e,
                "the post-apply drift rescan faulted; the plan is applied and the rescan is \
                 not recorded"
            );
            0
        }
    }
}

/// The rescan itself. Its caller decides what a fault means.
async fn rescan_for_drift_inner(
    pool: &ScopedPool,
    plan: &PlanRow,
    dispatched_by: Uuid,
    correlation_id: &str,
) -> Result<usize, epigraph_db::DbError> {
    let (mut conn, lease) = pool
        .unscoped_for_maintenance(reason(Direction::Apply))
        .await?;
    let bypass = epigraph_db::visibility::Viewer::system(&lease, reason(Direction::Apply));

    let applied = PrivatizationRepository::applied_entity_ids_conn(&mut conn, plan.id).await?;
    if applied.is_empty() {
        return Ok(0);
    }

    let drift = match PrivatizationRepository::restatement_drift_conn(
        &mut conn,
        &bypass,
        &applied,
        DRIFT_NODE_CAP,
    )
    .await
    {
        Ok(drift) => drift,
        // A REFUSED rescan is not a failed apply. The rows are private; what
        // is missing is the report that something restates them. Surfaced as
        // a log line and a zero, so the plan lands `applied` rather than
        // `failed` and an operator can re-run the selection by hand.
        Err(SelectionError::Refused(refusal)) => {
            tracing::warn!(
                target: "tenancy.privatization",
                plan_id = %plan.id,
                refusal = %refusal,
                "the post-apply drift rescan was refused; the plan is applied and the \
                 rescan is not recorded"
            );
            return Ok(0);
        }
        Err(SelectionError::Db(e)) => return Err(e),
    };
    if drift.is_empty() {
        return Ok(0);
    }

    let drift_ids: Vec<Uuid> = drift.iter().map(|c| c.claim_id).collect();

    let mut tx = sqlx::Connection::begin(&mut *conn)
        .await
        .map_err(|source| epigraph_db::DbError::QueryFailed { source })?;
    PrivatizationRepository::transition_plan_conn(
        &mut tx,
        plan.id,
        PlanTransition::Drift { ids: &drift_ids },
    )
    .await?;
    for id in &drift_ids {
        PrivatizationRepository::record_plan_audit_conn(
            &mut tx,
            PlanAuditEntry {
                plan_id: plan.id,
                actor_agent_id: dispatched_by,
                action: "plan.drift",
                kind: Some("claim"),
                entity_id: Some(*id),
                plan_digest: plan.plan_digest.as_deref(),
                correlation_id: Some(correlation_id),
            },
        )
        .await?;
    }
    PrivatizationRepository::create_followup_drift_plan_conn(
        &mut tx,
        &bypass,
        plan,
        &drift,
        dispatched_by,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|source| epigraph_db::DbError::QueryFailed { source })?;

    Ok(drift_ids.len())
}

/// A database fault is a transient job failure, not a refusal.
fn processing_failed<E: std::fmt::Display>(e: E) -> JobError {
    JobError::ProcessingFailed {
        message: format!("privatization: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_job_type_constants_are_the_names_migration_077_spells() {
        // `jobs_app`'s WITH CHECK is a string comparison against these three
        // literals. A rename here that is not made there silently stops the
        // policy from matching, and nothing else in the tree would notice.
        assert_eq!(APPLY_JOB_TYPE, "privatization_apply");
        assert_eq!(REVERT_JOB_TYPE, "privatization_revert");
        let apply = EpiGraphJob::PrivatizationApply {
            plan_id: Uuid::nil(),
            dispatched_by: Uuid::nil(),
            correlation_id: String::new(),
        };
        assert_eq!(apply.job_type(), APPLY_JOB_TYPE);
        let revert = EpiGraphJob::PrivatizationRevert {
            plan_id: Uuid::nil(),
            dispatched_by: Uuid::nil(),
            correlation_id: String::new(),
        };
        assert_eq!(revert.job_type(), REVERT_JOB_TYPE);
    }

    #[test]
    fn the_batch_size_is_clamped_at_both_ends() {
        assert_eq!(clamp_batch(0), 1);
        assert_eq!(clamp_batch(-7), 1);
        assert_eq!(clamp_batch(50), 50);
        assert_eq!(
            clamp_batch(100_000),
            MAX_BATCH,
            "FINAL-PLAN §6.5.5 caps the ramp at 500; an unbounded batch is the \
             ops-F11 lock-hold this correction exists to prevent"
        );
    }

    #[test]
    fn apply_walks_deepest_first_and_revert_walks_the_mirror() {
        assert!(
            Direction::Apply.deepest_first(),
            "the private set must be closed downward at every commit boundary; \
             the inverse order leaves a private parent with public children"
        );
        assert!(!Direction::Revert.deepest_first());
    }

    #[test]
    fn revert_consumes_applied_items_and_not_pending_ones() {
        assert_eq!(Direction::Revert.source_item_state(), "applied");
        assert_eq!(Direction::Apply.source_item_state(), "pending");
    }

    #[test]
    fn a_wrong_variant_payload_is_refused_rather_than_reinterpreted() {
        let job = EpiGraphJob::PrivatizationRevert {
            plan_id: Uuid::nil(),
            dispatched_by: Uuid::nil(),
            correlation_id: "c".to_string(),
        }
        .into_job()
        .expect("serialises");
        let err = decode(&job, Direction::Apply).expect_err("an apply handler must refuse it");
        assert!(matches!(err, JobError::PayloadError { .. }));
    }
}
