//! `privatization abort|revert|purge-sealed-centroids`: the operator's
//! recovery path for a privatization plan, and the one-off pass for cluster
//! centroids an earlier seal left (backlogs bb682f72, 06cdffaa).
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
//! They make the routes' WRITES through the routes' own write code
//! (`epigraph_jobs::privatization::abort_plan_conn` and `dispatch_conn`): the
//! conditional state flip, the `privatization_audit` row and, for a revert,
//! the `security_events` row the revert job's sixth re-validation condition
//! reads and the job itself. The drain runs the job, which re-validates the
//! plan as it does for a route dispatch. The routes' AUTHORITY check is
//! HTTP middleware this crate cannot call; the gate each verb applies instead
//! is below, and the two verbs deliberately differ.
//!
//! # Authority and audit
//!
//! Every act is attributed to `--actor`, a registered human, and recorded as a
//! `platform.custodial_act` (`privatization.plan_transition`) against
//! `--assignment`, the actor's LIVE `role:platform-custodian` assignment, in
//! the same transaction. The act recorder refuses (`CUS04`) any other
//! assignment, which rolls the whole act back. The custodial act carries
//! `--reason`.
//!
//! * `revert` applies the route's gate (`instance_authz::
//!   require_instance_admin_for_group`), conditions 2 to 4, read through the
//!   same one-statement probe (`InstanceAdminRepository::
//!   privatization_authority`): the actor is a live custodian (2), the target
//!   group is at least [`TARGET_GROUP_MIN_AGE_HOURS`] old (3a) and has at
//!   least [`TARGET_GROUP_MIN_OTHER_ADMINS`] live admins besides the actor
//!   (3b), and the actor is a live `admin` of the target group (4). A revert
//!   moves claims back to their pre-plan tenancy, so holding the maintenance
//!   DSN and a custodian assignment is not enough to revert a group one does
//!   not administer. Checked in the dry run too, so the dry run tells the
//!   truth.
//! * `abort` needs condition 2 only (the `CUS04` act recorder). An abort
//!   changes no tenancy: it stops a run and leaves the applied prefix
//!   applied, and it is on its own what clears `drain_jobs` exit 5. Gating it
//!   on the target group's roster would leave a plan whose group lost its
//!   co-admins stranded for good, the availability defect migration 081's
//!   plan guard declines to create for the same reason. Such a plan can be
//!   aborted by any custodian but reverted, here as through the route, only by
//!   one who passes the gate above.
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
use epigraph_db::{SecurityEventRepository, SecurityEventRow};
use epigraph_jobs::privatization::{self as lifecycle, DispatchKind};
use sqlx::PgConnection;
use uuid::Uuid;

/// The custodial act both transitions are recorded as.
const ACT: &str = "privatization.plan_transition";

/// Condition 3a of the revert gate: the target group's minimum age. The same
/// decision as `epigraph_api::middleware::instance_authz::
/// TARGET_GROUP_MIN_AGE_HOURS` and migration 081's literal; the
/// `operator_privatization` test pins the two constants together.
pub const TARGET_GROUP_MIN_AGE_HOURS: i64 = 24;

/// Condition 3b of the revert gate: live admins of the target group besides
/// the actor. Pinned as [`TARGET_GROUP_MIN_AGE_HOURS`] is.
pub const TARGET_GROUP_MIN_OTHER_ADMINS: i64 = 2;

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

/// The route's gate for a revert, conditions 2 to 4 of
/// `instance_authz::require_instance_admin_for_group`, in its order, read in
/// one statement: `None` when `actor` passes, else why not.
async fn revert_authority_refusal(
    conn: &mut PgConnection,
    actor: &Actor,
    target_group: Uuid,
) -> anyhow::Result<Option<String>> {
    let authority = epigraph_db::InstanceAdminRepository::privatization_authority(
        conn,
        actor.agent,
        target_group,
    )
    .await
    .context("reading the actor's authority over the plan's target group")?;
    // 2. A live role:platform-custodian assignment.
    if !authority.is_instance_admin || authority.custodian_assignment_id.is_none() {
        return Ok(Some("--actor is not a platform custodian".to_string()));
    }
    // 3a. Maturity.
    let Some(created_at) = authority.target_group_created_at else {
        return Ok(Some(format!(
            "the plan's target group {target_group} does not exist"
        )));
    };
    if created_at > chrono::Utc::now() - chrono::Duration::hours(TARGET_GROUP_MIN_AGE_HOURS) {
        return Ok(Some(format!(
            "the target group must pre-exist the plan by {TARGET_GROUP_MIN_AGE_HOURS}h"
        )));
    }
    // 3b. Plurality.
    if authority.other_live_admins < TARGET_GROUP_MIN_OTHER_ADMINS {
        return Ok(Some(format!(
            "the target group needs >= {TARGET_GROUP_MIN_OTHER_ADMINS} live admins besides \
             --actor"
        )));
    }
    // 4. Admin of the TARGET group.
    if !authority.is_target_group_admin {
        return Ok(Some(
            "--actor must hold the admin role in the plan's target group to revert it".to_string(),
        ));
    }
    Ok(None)
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
/// its items in state `applied` when the drain runs the job. Refused unless
/// `actor` passes the route's gate (module docs), while any item of a `seal`
/// plan is still sealed, and under `apply` unless `plan_digest` is the plan's
/// own.
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
    if let Some(why) = revert_authority_refusal(&mut tx, actor, plan.target_group_id).await? {
        return Ok(Outcome::Refused(why));
    }
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

/// The `security_events.event_type` of an applied centroid pass.
pub const PURGE_EVENT: &str = "operator.sealed_centroids_purged";

/// The one-off pass of backlog 06cdffaa: the `cluster_centroids` rows whose
/// clusters' members are all sealed, which a seal before the seal cleared
/// clusters left. A dry run only READS (it needs no DELETE grant); `apply`
/// deletes them and writes one [`PURGE_EVENT`] `security_events` row naming
/// the deleted `(run, cluster)` pairs, the operator's origin and `reason`, in
/// one transaction, and returns what it deleted.
///
/// `--apply` needs DELETE on `cluster_centroids`, which migration 070 does not
/// grant `epigraph_maintenance`; on such a login it fails with `42501` and
/// writes nothing. Run it as the table owner, as the seal itself runs.
///
/// # Errors
/// A blank `reason` (before any statement), or a statement failed (including
/// the missing grant); nothing is written.
pub async fn purge_sealed_centroids(
    conn: &mut PgConnection,
    apply: bool,
    reason: &str,
) -> anyhow::Result<Vec<(Uuid, i32)>> {
    if reason.trim().is_empty() {
        anyhow::bail!("--reason must say why (it is recorded in the audit row); nothing was done");
    }
    if !apply {
        return Ok(PrivatizationRepository::sealed_only_cluster_centroids_conn(conn, None).await?);
    }
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let deleted = PrivatizationRepository::delete_sealed_only_cluster_centroids_conn(&mut tx, None)
        .await
        .context(
            "deleting cluster_centroids rows (a 42501 means this login holds no DELETE on \
                 cluster_centroids: run --apply as the table owner)",
        )?;
    let details = serde_json::json!({
        "command": "privatization purge-sealed-centroids",
        "operator": super::restrict::operator_details(&mut tx).await?,
        "deleted_count": deleted.len(),
        "deleted": deleted.iter().map(|(run, cluster)| serde_json::json!({
            "cluster_run_id": run,
            "cluster_id": cluster,
        })).collect::<Vec<_>>(),
        "reason": reason,
    });
    let (client_addr, _) = SecurityEventRepository::connection_origin_conn(&mut tx).await?;
    SecurityEventRepository::log_conn(
        &mut tx,
        &SecurityEventRow {
            id: Uuid::new_v4(),
            event_type: PURGE_EVENT.to_string(),
            agent_id: None,
            success: Some(true),
            details,
            ip_address: client_addr,
            user_agent: None,
            correlation_id: None,
            created_at: chrono::Utc::now(),
        },
    )
    .await
    .context("writing the audit row")?;
    tx.commit().await.context("commit")?;
    Ok(deleted)
}
