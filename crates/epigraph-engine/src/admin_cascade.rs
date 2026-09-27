//! The retraction cascade as an ADMINISTRATIVE act (migration 117, batch W10).
//!
//! # The rule
//!
//! A supersede, a dedup or a match-candidate retirement is two things:
//!
//! * the CALLER's act -- retire its claim and insert the replacement, mark its
//!   duplicate, flip the candidate to `stale` -- which runs with the caller's
//!   own write authority on its own stamped transaction, exactly as before; and
//! * the CASCADE that follows -- re-pointing and retracting edges other writers
//!   asserted, moving, dropping and invalidating their edge-keyed BBAs, and
//!   re-deriving belief downstream -- which touches rows the caller does not
//!   own, and so runs with administrative authority: on the server's
//!   privileged maintenance connection, with that connection's bypass viewer,
//!   never with the caller's stamp.
//!
//! Every function here takes that maintenance connection. The request paths
//! (MCP `supersede_claim` / `mark_duplicate` / `retire_match_candidate`, and the
//! matching HTTP routes) commit the act first, then acquire the connection and
//! call one of the `apply_after_*` functions. Each writes ONE `security_events`
//! row ([`epigraph_db::repos::admin_cascade::EVENT_APPLIED`]) naming the
//! triggering principal ([`CascadeTrigger`]), the cause, and what it touched.
//!
//! # No maintenance connection: deferred, never skipped
//!
//! A server without an explicitly configured maintenance DSN cannot run the
//! cascade. It still commits the caller's act, reports the cascade as
//! [`CascadeState::Deferred`] with a reason, and writes a
//! [`epigraph_db::repos::admin_cascade::EVENT_DEFERRED`] row through
//! [`record_deferral`]. Every repair below re-verifies the committed act and is
//! idempotent, so an operator replays a deferred cascade by running the same
//! `apply_after_*` call on a maintenance connection later.
//!
//! # Best-effort, like the belief cascade
//!
//! The act has committed by the time any of this runs. A failure here is
//! reported in the returned [`CascadeStatus`] (and in the audit row), never as
//! an `Err` that would tell the caller a committed write failed.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use epigraph_db::repos::admin_cascade::{self as audit, EVENT_APPLIED, EVENT_DEFERRED};
use epigraph_db::repos::match_candidate::RetirementOutcome;
use epigraph_db::{ClaimRepository, DbError, MatchCandidateRepo};

use crate::retraction_cascade::{cascade_after_dedup, cascade_after_supersede, CascadeReport};

/// The reason a request path reports when no maintenance connection is
/// configured for this process.
pub const REASON_NOT_CONFIGURED: &str =
    "no administrative (maintenance) connection is configured for this server \
     (MAINTENANCE_DATABASE_URL unset, or not a member of epigraph_maintenance); the caller's \
     act committed and the cascade across other writers' rows is deferred for an operator to \
     replay";

/// What triggered an administrative cascade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CascadeCause {
    /// A claim was superseded by its author.
    Supersede,
    /// A claim was marked a duplicate of a canonical claim.
    Dedup,
    /// A promoted match candidate was retired.
    MatchRetire,
}

impl CascadeCause {
    /// The literal recorded in the audit row.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supersede => "supersede",
            Self::Dedup => "dedup",
            Self::MatchRetire => "match_retire",
        }
    }
}

/// The OAuth principal behind a request, where the transport has one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OauthPrincipal {
    /// The OAuth client that presented the token.
    pub client_id: Option<Uuid>,
    /// The human (or service) the token was issued to, when recorded.
    pub owner_id: Option<Uuid>,
    /// The agent the token carries, when it carries one.
    pub agent_id: Option<Uuid>,
}

/// Who triggered a cascade, and on what.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CascadeTrigger {
    /// Why the cascade runs.
    pub cause: CascadeCause,
    /// The agent the caller's act was written as (the session principal of
    /// the act's stamped transaction). This is the audit row's `agent_id`.
    pub agent_id: Option<Uuid>,
    /// The OAuth principal behind the request, where present.
    pub oauth: Option<OauthPrincipal>,
    /// The retired claim (supersede), the duplicate (dedup), or the candidate
    /// (match retirement).
    pub subject_id: Uuid,
    /// The replacement (supersede) or the canonical claim (dedup).
    pub object_id: Option<Uuid>,
}

impl CascadeTrigger {
    fn audit_details(&self) -> serde_json::Value {
        serde_json::json!({
            "cause": self.cause.as_str(),
            "trigger": {
                "agent_id": self.agent_id,
                "oauth": self.oauth,
                "subject_id": self.subject_id,
                "object_id": self.object_id,
            },
            "migration": 117,
        })
    }
}

/// Whether the administrative cascade ran.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CascadeState {
    /// It ran on the maintenance connection (`touched` says what it did; any
    /// per-row failures are in the belief cascade's `errors`).
    Applied,
    /// It did not run: no maintenance connection. The act committed.
    #[default]
    Deferred,
    /// It started on the maintenance connection and its repair step failed.
    /// The act committed; the repair is idempotent and can be replayed.
    Failed,
}

/// The `cascade` object a tool or route returns next to the caller's result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CascadeStatus {
    /// Applied, deferred or failed.
    pub status: CascadeState,
    /// Why it was deferred or failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The `security_events` row recording it; `None` only when writing that
    /// row itself failed (and then `audit_error` says why).
    pub audit_event_id: Option<Uuid>,
    /// Why the audit row could not be written, when it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_error: Option<String>,
    /// What an applied cascade touched: counts and ids.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub touched: Option<serde_json::Value>,
}

impl CascadeStatus {
    /// A deferral whose audit row could not be written, for a caller that has
    /// already committed the act and can only report.
    #[must_use]
    pub fn deferred_unaudited(reason: &str, audit_error: impl std::fmt::Display) -> Self {
        Self {
            status: CascadeState::Deferred,
            reason: Some(reason.to_string()),
            audit_event_id: None,
            audit_error: Some(audit_error.to_string()),
            touched: None,
        }
    }
}

/// Record that `trigger`'s cascade was deferred, on `executor`.
///
/// A request path calls this on the CALLER's session -- inside the act's own
/// transaction when it already knows no maintenance connection is configured,
/// so the act and its audit row commit together -- which is why the row's
/// `agent_id` must be the session principal (077's `security_events_append`).
///
/// # Errors
/// The INSERT's error. A caller inside the act's transaction propagates it
/// (nothing commits); one after the commit reports
/// [`CascadeStatus::deferred_unaudited`].
pub async fn record_deferral<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    trigger: &CascadeTrigger,
    reason: &str,
) -> Result<CascadeStatus, DbError> {
    let mut details = trigger.audit_details();
    details["reason"] = serde_json::Value::String(reason.to_string());
    let id = audit::record(executor, EVENT_DEFERRED, trigger.agent_id, false, &details).await?;
    tracing::warn!(
        target: "tenancy.admin_cascade",
        cause = trigger.cause.as_str(),
        subject = %trigger.subject_id,
        audit_event_id = %id,
        "administrative cascade deferred: {reason}"
    );
    Ok(CascadeStatus {
        status: CascadeState::Deferred,
        reason: Some(reason.to_string()),
        audit_event_id: Some(id),
        audit_error: None,
        touched: None,
    })
}

/// Append the applied/failed audit row on the maintenance connection and
/// build the status. An audit failure is reported, never raised.
async fn finish(
    admin: &mut sqlx::PgConnection,
    trigger: &CascadeTrigger,
    state: CascadeState,
    reason: Option<String>,
    touched: serde_json::Value,
    success: bool,
) -> CascadeStatus {
    let mut details = trigger.audit_details();
    details["outcome"] = serde_json::to_value(state).unwrap_or(serde_json::Value::Null);
    details["touched"] = touched.clone();
    if let Some(r) = &reason {
        details["reason"] = serde_json::Value::String(r.clone());
    }
    let (audit_event_id, audit_error) = match audit::record(
        &mut *admin,
        EVENT_APPLIED,
        trigger.agent_id,
        success,
        &details,
    )
    .await
    {
        Ok(id) => (Some(id), None),
        Err(e) => {
            tracing::error!(
                target: "tenancy.admin_cascade",
                cause = trigger.cause.as_str(),
                subject = %trigger.subject_id,
                error = %e,
                "administrative cascade ran but its audit row could not be written"
            );
            (None, Some(e.to_string()))
        }
    };
    CascadeStatus {
        status: state,
        reason,
        audit_event_id,
        audit_error,
        touched: Some(touched),
    }
}

fn report_json(report: &CascadeReport) -> serde_json::Value {
    serde_json::json!({
        "invalidated_bbas": report.invalidated_bbas,
        "targets": report.targets,
        "recomputed": report.recomputed,
        "unbacked": report.unbacked,
        "errors": report.errors,
    })
}

async fn failed(
    admin: &mut sqlx::PgConnection,
    trigger: &CascadeTrigger,
    step: &str,
    e: impl std::fmt::Display,
) -> CascadeStatus {
    let reason = format!("{step} failed on the maintenance connection: {e}");
    tracing::warn!(
        target: "tenancy.admin_cascade",
        cause = trigger.cause.as_str(),
        subject = %trigger.subject_id,
        "{reason}"
    );
    finish(
        admin,
        trigger,
        CascadeState::Failed,
        Some(reason),
        serde_json::json!({}),
        false,
    )
    .await
}

/// The supersede cascade: migrate the retired claim's edges onto the
/// replacement, then invalidate and re-derive the BBAs frozen from its
/// interval ([`cascade_after_supersede`]).
///
/// `admin` must be the maintenance connection and `viewer` its bypass viewer
/// (`MaintenanceSession::split`): the cascade walks downstream claims of any
/// owner, and a caller's viewer would hide other groups' rows from it.
pub async fn apply_after_supersede(
    admin: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    trigger: &CascadeTrigger,
    old_id: Uuid,
    new_id: Uuid,
) -> (CascadeStatus, CascadeReport) {
    let migration =
        match ClaimRepository::migrate_superseded_edges_conn(&mut *admin, old_id, new_id).await {
            Ok(m) => m,
            Err(e) => {
                return (
                    failed(admin, trigger, "the supersede edge migration", e).await,
                    CascadeReport::default(),
                )
            }
        };
    let report = cascade_after_supersede(&mut *admin, viewer, new_id).await;
    let touched = serde_json::json!({
        "edges_retargeted": migration.retargeted,
        "edges_resourced": migration.resourced,
        "belief": report_json(&report),
    });
    let ok = report.errors.is_empty();
    let status = finish(admin, trigger, CascadeState::Applied, None, touched, ok).await;
    (status, report)
}

/// The dedup cascade: repair the edge and derived-record layers
/// ([`ClaimRepository::repair_marked_duplicate_conn`]), then recompute and
/// re-derive ([`cascade_after_dedup`]). `admin` / `viewer` as for
/// [`apply_after_supersede`].
pub async fn apply_after_dedup(
    admin: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    trigger: &CascadeTrigger,
    dup_id: Uuid,
    canonical_id: Uuid,
) -> (CascadeStatus, CascadeReport) {
    use epigraph_core::ClaimId;
    let repair = match ClaimRepository::repair_marked_duplicate_conn(
        &mut *admin,
        ClaimId::from_uuid(dup_id),
        ClaimId::from_uuid(canonical_id),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                failed(admin, trigger, "the dedup repair", e).await,
                CascadeReport::default(),
            )
        }
    };
    let report = cascade_after_dedup(&mut *admin, viewer, canonical_id, &repair).await;
    let touched = serde_json::json!({
        "edges_retracted": repair.retracted_edges,
        "edges_retargeted": repair.retargeted_edges,
        "edges_resourced": repair.resourced_edges.iter().map(|(id, _, _)| *id).collect::<Vec<_>>(),
        "bbas_deleted_with_retracted_edges": repair.deleted_bbas,
        "bbas_moved": repair.moved_bbas,
        "duplicate_copies_dropped": repair.dropped_duplicate_copies,
        "false_bindings_not_copied": repair.skipped_false_bindings,
        "belief": report_json(&report),
    });
    let ok = report.errors.is_empty();
    let status = finish(admin, trigger, CascadeState::Applied, None, touched, ok).await;
    (status, report)
}

/// The match-candidate retirement cascade: retract the candidate's matcher
/// edges and remove their derived rows
/// ([`MatchCandidateRepo::retract_candidate_edges_conn`]).
pub async fn apply_after_match_retire(
    admin: &mut sqlx::PgConnection,
    trigger: &CascadeTrigger,
    candidate_id: Uuid,
) -> (CascadeStatus, Option<RetirementOutcome>) {
    match MatchCandidateRepo::retract_candidate_edges_conn(&mut *admin, candidate_id).await {
        Ok(outcome) => {
            let touched = serde_json::json!({
                "edges_retracted": outcome.retracted_edges.iter().map(|e| e.edge_id).collect::<Vec<_>>(),
                "edges_retracted_now": outcome.edges_retracted,
                "factors_deleted": outcome.factors_deleted,
                "bp_messages_deleted": outcome.bp_messages_deleted,
                "bbas_invalidated": outcome.bbas_invalidated,
                "affected_claims": outcome.affected_claims,
            });
            let status = finish(admin, trigger, CascadeState::Applied, None, touched, true).await;
            (status, Some(outcome))
        }
        Err(e) => (
            failed(admin, trigger, "the match-candidate retirement cascade", e).await,
            None,
        ),
    }
}
