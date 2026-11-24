//! `privatization abort|revert`: the operator's recovery path for a
//! privatization plan (backlog bb682f72).
//!
//! # Why an operator verb
//!
//! An apply or revert job is a one-attempt row. When the drain's reaper fails
//! one after its crash re-deliveries, or its handler fails on a database fault,
//! the plan stays in `applying` or `reverting` with nothing to finish it, and
//! `drain_jobs` exits 5 on every run until the plan is recovered
//! (`PostgresJobQueue::stranded_privatization_plans`). The recovery §6.5.5
//! gives is abort, then revert. Its HTTP routes answer only on a deployment
//! that attaches a maintenance pool to the API, and under operator decision D9
//! the stock server attaches none, so these verbs are that recovery on the
//! maintenance DSN.
//!
//! They make the routes' writes, through the same code
//! (`epigraph_jobs::privatization::abort_plan_conn` and `dispatch_conn`): the
//! conditional state flip, the `privatization_audit` row and, for a revert,
//! the `security_events` row the revert job's sixth re-validation condition
//! reads and the job itself. The drain runs the job, which re-validates the
//! plan as it does for a route dispatch.
//!
//! # Authority and audit
//!
//! The DSN is the authority to write; the act is attributed to `--actor`, a
//! registered human, and recorded as a `platform.custodial_act`
//! (`privatization.plan_transition`) against `--assignment`, the actor's LIVE
//! `role:platform-custodian` assignment, in the same transaction. The act
//! recorder refuses (`CUS04`) any other assignment, which rolls the whole act
//! back. The custodial act carries `--reason`.
//!
//! # Dry run by default
//!
//! Every verb runs its writes in ONE transaction and rolls it back unless
//! `--apply` is given, so a dry run prints exactly what the act would do.
//! A revert under `--apply` also needs `--plan-digest`, the plan's digest
//! (`b3:<hex>`, printed by the dry run) echoed back, as the route needs it.
//!
//! Idempotent: aborting a plan that is already `failed` writes nothing and
//! exits 0. A plan in any other state that is not running is refused (exit 1).

use anyhow::Context;
use epigraph_db::repos::privatization::{PlanRow, PrivatizationRepository};
use epigraph_jobs::privatization::{self as lifecycle, DispatchKind};
use sqlx::PgConnection;
use uuid::Uuid;

/// The custodial act both transitions are recorded as.
const ACT: &str = "privatization.plan_transition";

/// Who acts, on whose authority, and why.
#[derive(Debug, Clone)]
pub struct Actor {
    /// The registered human the act is attributed to.
    pub agent: Uuid,
    /// Their live `role:platform-custodian` assignment.
    pub assignment: Uuid,
    /// Recorded on the custodial act.
    pub reason: String,
}

/// What a verb did, or (dry run) would have done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The plan was (or would be) set `failed`.
    Aborted { from_state: String },
    /// The plan was already `failed`; nothing was written.
    AlreadyFailed,
    /// The plan was (or would be) dispatched for revert.
    RevertDispatched {
        from_state: String,
        job_id: Uuid,
        correlation_id: String,
    },
    /// The dry run of a revert: what `--apply` needs echoed back.
    RevertWouldDispatch { from_state: String, digest: String },
    /// Refused before anything was written.
    Refused(String),
}

impl Outcome {
    /// The process exit code: a refusal is a failure, everything else 0.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Refused(_) => 1,
            _ => 0,
        }
    }
}

/// One stable, grep-able line.
#[must_use]
pub fn describe(plan: Uuid, outcome: &Outcome, apply: bool) -> String {
    let would = if apply { "" } else { "WOULD BE " };
    match outcome {
        Outcome::Aborted { from_state } => {
            format!("{would}ABORTED\tplan={plan}\tfrom={from_state}\tto=failed")
        }
        Outcome::AlreadyFailed => {
            format!("ALREADY-FAILED\tplan={plan}\tnothing was written")
        }
        Outcome::RevertDispatched {
            from_state,
            job_id,
            correlation_id,
        } => format!(
            "{would}REVERT-DISPATCHED\tplan={plan}\tfrom={from_state}\tto=reverting\t\
             job={job_id}\tcorrelation={correlation_id}"
        ),
        Outcome::RevertWouldDispatch { from_state, digest } => format!(
            "WOULD BE REVERT-DISPATCHED\tplan={plan}\tfrom={from_state}\tto=reverting\t\
             plan_digest={digest}\t(re-run with --apply --plan-digest {digest})"
        ),
        Outcome::Refused(why) => format!("REFUSED\tplan={plan}\t{why}; nothing was written"),
    }
}

/// `b3:<hex>`, the spelling the routes echo and print.
#[must_use]
pub fn render_digest(digest: Option<&[u8]>) -> String {
    digest.map_or_else(|| "none".to_string(), |d| format!("b3:{}", hex::encode(d)))
}

/// Whether `echoed` is the plan's stored digest, as `routes/privatization.rs`
/// `refuse_stale_digest` compares it.
fn digest_matches(plan: &PlanRow, echoed: &str) -> bool {
    match (plan.plan_digest.as_deref(), echoed.strip_prefix("b3:")) {
        (Some(stored), Some(hex_digits)) => hex::decode(hex_digits).is_ok_and(|b| b == stored),
        _ => false,
    }
}

async fn record_act(
    tx: &mut PgConnection,
    actor: &Actor,
    plan: Uuid,
    details: serde_json::Value,
) -> anyhow::Result<()> {
    epigraph_db::RoleAssignmentRepository::record_custodial_act(
        tx,
        actor.assignment,
        actor.agent,
        ACT,
        "privatization_plan",
        plan,
        details,
    )
    .await
    .context(
        "recording the custodial act (CUS04: --assignment is not a live \
         role:platform-custodian assignment of --actor)",
    )?;
    Ok(())
}

async fn finish(tx: sqlx::Transaction<'_, sqlx::Postgres>, apply: bool) -> anyhow::Result<()> {
    if apply {
        tx.commit().await.context("commit")?;
    } else {
        tx.rollback().await.context("roll back the dry run")?;
    }
    Ok(())
}

/// Stop a running (or stranded) plan: `failed`, with its `plan.abort` audit row
/// and the custodial act, committed under `apply`.
///
/// # Errors
/// A statement failed or the act recorder refused; nothing is written.
pub async fn abort(
    conn: &mut PgConnection,
    plan_id: Uuid,
    actor: &Actor,
    apply: bool,
) -> anyhow::Result<Outcome> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let Some(plan) = PrivatizationRepository::load_plan_conn(&mut tx, plan_id).await? else {
        return Ok(Outcome::Refused("no such plan".to_string()));
    };
    let from_state = plan.state.clone();
    match from_state.as_str() {
        "failed" => return Ok(Outcome::AlreadyFailed),
        "applying" | "reverting" => {}
        other => {
            return Ok(Outcome::Refused(format!(
                "only a running plan can be aborted; this one is '{other}'"
            )))
        }
    }
    if !lifecycle::abort_plan_conn(&mut tx, &plan, actor.agent).await? {
        return Ok(Outcome::Refused(
            "the plan reached a terminal state while it was being aborted; re-read it".to_string(),
        ));
    }
    record_act(
        &mut tx,
        actor,
        plan_id,
        serde_json::json!({"transition": "abort", "to_state": "failed",
                           "via": "epigraph-operator", "reason": actor.reason}),
    )
    .await?;
    finish(tx, apply).await?;
    Ok(Outcome::Aborted { from_state })
}

/// Dispatch a revert of an applied or aborted plan, which un-applies exactly
/// its items in state `applied` when the drain runs the job. Refused while any
/// item of a `seal` plan is still sealed, and under `apply` unless
/// `plan_digest` is the plan's own.
///
/// # Errors
/// A statement failed or the act recorder refused; nothing is written.
pub async fn revert(
    conn: &mut PgConnection,
    plan_id: Uuid,
    actor: &Actor,
    plan_digest: Option<&str>,
    apply: bool,
) -> anyhow::Result<Outcome> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let Some(plan) = PrivatizationRepository::load_plan_conn(&mut tx, plan_id).await? else {
        return Ok(Outcome::Refused("no such plan".to_string()));
    };
    let from_state = plan.state.clone();
    if !matches!(
        from_state.as_str(),
        "applied" | "applied_with_drift" | "failed"
    ) {
        return Ok(Outcome::Refused(format!(
            "only an applied or aborted plan can be reverted; this one is '{from_state}' \
             (abort a running one first)"
        )));
    }
    let sealed = PrivatizationRepository::sealed_item_count_conn(&mut tx, plan_id).await?;
    if sealed > 0 {
        return Ok(Outcome::Refused(format!(
            "{sealed} of this plan's items are still sealed; unseal them before reverting"
        )));
    }
    let digest = render_digest(plan.plan_digest.as_deref());
    match (apply, plan_digest) {
        (false, _) => {}
        (true, Some(echoed)) if digest_matches(&plan, echoed) => {}
        (true, _) => {
            return Ok(Outcome::Refused(format!(
                "--apply needs --plan-digest {digest}, this plan's current digest"
            )))
        }
    }
    let from_states = [
        "applied".to_string(),
        "applied_with_drift".to_string(),
        "failed".to_string(),
    ];
    let Some(dispatched) = lifecycle::dispatch_conn(
        &mut tx,
        &plan,
        actor.agent,
        DispatchKind::Revert,
        "reverting",
        &from_states,
    )
    .await?
    else {
        return Ok(Outcome::Refused(
            "the plan moved while it was being dispatched; re-read it".to_string(),
        ));
    };
    record_act(
        &mut tx,
        actor,
        plan_id,
        serde_json::json!({"transition": "dispatch", "to_state": "reverting",
                           "correlation_id": dispatched.correlation_id,
                           "via": "epigraph-operator", "reason": actor.reason}),
    )
    .await?;
    finish(tx, apply).await?;
    Ok(if apply {
        Outcome::RevertDispatched {
            from_state,
            job_id: dispatched.job_id,
            correlation_id: dispatched.correlation_id,
        }
    } else {
        Outcome::RevertWouldDispatch { from_state, digest }
    })
}
