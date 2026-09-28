//! The retraction cascade as an ADMINISTRATIVE act (migration 117, batch W10).
//!
//! # The rule
//!
//! A supersede, a dedup, a consolidation or a match-candidate retirement is
//! two things:
//!
//! * the CALLER's act -- retire its claim and insert the replacement, mark its
//!   duplicate, merge its sources -- which runs with the caller's own write
//!   authority on its own stamped transaction, exactly as before; and
//! * the CASCADE that follows -- re-pointing and retracting edges other writers
//!   asserted, moving, dropping and invalidating their edge-keyed BBAs, and
//!   re-deriving belief downstream -- which touches rows the caller does not
//!   own, and so runs with administrative authority: on the server's
//!   privileged maintenance connection, with that connection's bypass viewer,
//!   never with the caller's stamp.
//!
//! Every `apply_after_*` function here takes that maintenance connection. The
//! request paths (MCP `supersede_claim` / `mark_duplicate` /
//! `consolidate_claims`, and the matching HTTP routes) acquire it BEFORE
//! committing the act, commit the act, then call one of the `apply_after_*`
//! functions.
//!
//! # A match-candidate retirement has no caller's act
//!
//! Its act, the flip to `stale`, is administrative too: migration 118's
//! `match_candidates_stale_guard` refuses it on a non-privileged session. So
//! [`apply_match_retire`] runs the flip AND the cascade in one transaction on
//! the maintenance connection, with the applied row naming the caller. Without
//! a maintenance connection nothing about the candidate changes: the request
//! path records the whole retirement as deferred ([`record_deferral`], whose
//! definer records the candidate's status at that moment), and the replay
//! carries it out only while the candidate still has that status.
//!
//! # The audit trail
//!
//! * The repair and its [`EVENT_APPLIED`] row commit in ONE transaction on the
//!   maintenance connection, so an applied cross-owner repair never exists
//!   without the row naming the triggering principal ([`CascadeTrigger`]), the
//!   cause and what it touched (counts and ids).
//! * A repair that fails rolls back and writes [`EVENT_FAILED`].
//! * The belief re-derivation that follows is best-effort (per claim) and
//!   writes its own [`EVENT_BELIEF`] row naming the applied row.
//!
//! # What the CALLER is told
//!
//! The caller triggered the cascade but cannot read every row it touched: an
//! edge between another group's private claim and the caller's public one is
//! re-pointed with the rest. So the result a tool or route returns is filtered
//! to the caller's view: `cascade.touched` carries COUNTS only, the belief
//! report keeps only claim ids the caller's viewer can read (and drops any
//! error text naming anything else), and a failure's reason is generic. The
//! ids live in the audit rows, which only a privileged session reads.
//!
//! # No maintenance connection: deferred, never skipped
//!
//! A server without an explicitly configured maintenance DSN cannot run the
//! cascade. It still commits the caller's act, reports the cascade as
//! [`CascadeState::Deferred`] with a reason, and writes an
//! [`EVENT_DEFERRED`](epigraph_db::repos::admin_cascade::EVENT_DEFERRED)
//! row through [`record_deferral`] IN THE ACT'S OWN TRANSACTION, so the act and
//! its deferral commit together. Every repair re-verifies the committed act
//! and is idempotent, so [`replay_deferred`] runs the same `apply_after_*` call
//! on a maintenance connection later (`replay_deferred_cascades`, a CLI on the
//! operator's maintenance DSN). A match-candidate retirement commits no act:
//! its deferral is the whole request, and the replay runs
//! [`apply_match_retire`] against the status the deferral recorded.
//!
//! # Best-effort, like the belief cascade
//!
//! The act has committed by the time any of this runs. A failure here is
//! reported in the returned [`CascadeStatus`] (and in the audit row), never as
//! an `Err` that would tell the caller a committed write failed.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use epigraph_db::repos::admin_cascade::{self as audit, EVENT_APPLIED, EVENT_BELIEF, EVENT_FAILED};
use epigraph_db::repos::match_candidate::RetirementOutcome;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, DbError, MatchCandidateRepo};

use crate::retraction_cascade::{cascade_after_dedup, cascade_after_supersede, CascadeReport};

/// The reason a request path reports when it holds no maintenance connection,
/// which under operator decision D9 (batch W12a) is every request-serving
/// process: the cascade is deferred and the replay timer
/// (`epigraph-cascade-replay.timer`, `replay_deferred_cascades`) applies it.
///
/// Names no row: it reaches the caller. A client must not retry the act (a
/// retry hits "already superseded" / "already retired"); completion is
/// observable as the edges moving and beliefs changing.
pub const REASON_NOT_CONFIGURED: &str =
    "this server does not hold the administrative connection (operator decision D9); the \
     caller's act committed and the cascade across other writers' rows is applied by the \
     maintenance replay (normally within about two minutes)";

/// What triggered an administrative cascade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CascadeCause {
    /// A claim was superseded by its author.
    Supersede,
    /// A claim was marked a duplicate of a canonical claim.
    Dedup,
    /// Two or more claims were consolidated into one merged claim.
    Consolidate,
    /// A promoted match candidate was retired.
    MatchRetire,
    /// An edge's owner retracted or deleted it (migration 120): every OTHER
    /// writer's edge-keyed BBA on it is removed administratively and the
    /// affected beliefs re-derived.
    EdgeRetract,
}

impl CascadeCause {
    /// The literal recorded in the audit row.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supersede => "supersede",
            Self::Dedup => "dedup",
            Self::Consolidate => "consolidate",
            Self::MatchRetire => "match_retire",
            Self::EdgeRetract => "edge_retract",
        }
    }

    /// The inverse of [`Self::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "supersede" => Some(Self::Supersede),
            "dedup" => Some(Self::Dedup),
            "consolidate" => Some(Self::Consolidate),
            "match_retire" => Some(Self::MatchRetire),
            "edge_retract" => Some(Self::EdgeRetract),
            _ => None,
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

/// Where a replayed cascade came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayOrigin {
    /// The `cascade.deferred` / `cascade.admin_failed` row being replayed.
    pub deferred_event_id: Uuid,
    /// Who ran the replay (the operator-supplied label of the replay run).
    pub replayed_by: String,
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
    /// The retired claim (supersede), the duplicate (dedup), the merged claim
    /// (consolidate), or the candidate (match retirement).
    pub subject_id: Uuid,
    /// The replacement (supersede) or the canonical claim (dedup).
    pub object_id: Option<Uuid>,
    /// The retired sources of a consolidation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<Uuid>,
    /// A match-candidate retirement's precondition: the candidate's status
    /// when the retirement was requested. The retirement is carried out only
    /// while the candidate still has it (or is already `stale`); see
    /// [`MatchCandidateRepo::retire_conn`]. A deferral's is recorded by the
    /// database, not by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_status: Option<String>,
    /// Set when this run replays a deferred or failed cascade.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_of: Option<ReplayOrigin>,
}

impl CascadeTrigger {
    /// A trigger for a caller's act (not a replay, no consolidation sources).
    #[must_use]
    pub fn new(
        cause: CascadeCause,
        agent_id: Option<Uuid>,
        oauth: Option<OauthPrincipal>,
        subject_id: Uuid,
        object_id: Option<Uuid>,
    ) -> Self {
        Self {
            cause,
            agent_id,
            oauth,
            subject_id,
            object_id,
            sources: Vec::new(),
            candidate_status: None,
            replay_of: None,
        }
    }

    fn audit_details(&self) -> serde_json::Value {
        let mut trigger = serde_json::json!({
            "agent_id": self.agent_id,
            "oauth": self.oauth,
            "subject_id": self.subject_id,
            "object_id": self.object_id,
        });
        if !self.sources.is_empty() {
            trigger["sources"] = serde_json::json!(self.sources);
        }
        if let Some(status) = &self.candidate_status {
            trigger["candidate_status"] = serde_json::json!(status);
        }
        let mut details = serde_json::json!({
            "cause": self.cause.as_str(),
            "trigger": trigger,
            "migration": 117,
        });
        if let Some(r) = &self.replay_of {
            details["replay_of"] = serde_json::json!(r);
        }
        details
    }

    /// Rebuild the trigger an audit row recorded (for the replay). `None` when
    /// the row does not carry a well-formed trigger.
    #[must_use]
    pub fn from_audit(details: &serde_json::Value) -> Option<Self> {
        let cause = CascadeCause::parse(details.get("cause")?.as_str()?)?;
        let t = details.get("trigger")?;
        let uuid = |v: Option<&serde_json::Value>| -> Option<Uuid> {
            v.and_then(serde_json::Value::as_str)
                .and_then(|s| s.parse().ok())
        };
        let subject_id = uuid(t.get("subject_id"))?;
        let sources = match t.get("sources") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(v) => serde_json::from_value(v.clone()).ok()?,
        };
        let oauth = match t.get("oauth") {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => serde_json::from_value(v.clone()).ok(),
        };
        Some(Self {
            cause,
            agent_id: uuid(t.get("agent_id")),
            oauth,
            subject_id,
            object_id: uuid(t.get("object_id")),
            sources,
            candidate_status: t
                .get("candidate_status")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            replay_of: None,
        })
    }
}

/// Whether the administrative cascade ran.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CascadeState {
    /// The repair ran on the maintenance connection and committed with its
    /// audit row (`touched` counts what it did; per-claim belief failures are
    /// in the belief report's `errors`).
    Applied,
    /// It did not run: no maintenance connection. The act committed.
    #[default]
    Deferred,
    /// It started on the maintenance connection and its repair failed and
    /// rolled back. The act committed; the repair is idempotent and replayable.
    Failed,
}

/// The `cascade` object a tool or route returns next to the caller's result.
///
/// This is the CALLER's copy: `touched` carries counts only and `reason` names
/// no row. The full record is the audit row `audit_event_id` names.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CascadeStatus {
    /// Applied, deferred or failed.
    pub status: CascadeState,
    /// Why it was deferred or failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The `security_events` row recording it; `None` only when writing that
    /// row itself failed (and then `audit_error` says so).
    pub audit_event_id: Option<Uuid>,
    /// The `security_events` row recording the belief re-derivation that
    /// followed an applied repair, when it could be written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub belief_audit_event_id: Option<Uuid>,
    /// Set when an audit row could not be written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_error: Option<String>,
    /// What an applied cascade touched, as COUNTS (the ids are in the audit
    /// row).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub touched: Option<serde_json::Value>,
}

/// Record that `trigger`'s cascade was deferred, on `executor`.
///
/// A request path calls this on the CALLER's session, inside the act's own
/// transaction and after the act, so the act and its audit row commit
/// together (or neither does). The row is written by 117's
/// `epigraph_record_cascade_deferral` definer, which the replay trusts and a
/// session cannot bypass: `trigger.agent_id` must be the session principal,
/// and the act must be one the session made (see
/// [`epigraph_db::repos::admin_cascade::record_deferral`]). The row it writes
/// reads back through [`CascadeTrigger::from_audit`] as `trigger`. The reason
/// is the server's own text and names no row.
///
/// # Errors
/// The definer's refusal or the call's error; the caller propagates it, and
/// nothing commits.
pub async fn record_deferral<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    trigger: &CascadeTrigger,
    reason: &str,
) -> Result<CascadeStatus, DbError> {
    let oauth = trigger
        .oauth
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|e| DbError::InvalidData {
            reason: format!("the OAuth principal could not be encoded: {e}"),
        })?;
    let id = audit::record_deferral(
        executor,
        trigger.cause.as_str(),
        trigger.agent_id,
        trigger.subject_id,
        trigger.object_id,
        &trigger.sources,
        oauth.as_ref(),
        reason,
    )
    .await?;
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
        ..CascadeStatus::default()
    })
}

/// Replace every array in `v` by its length, recursively: the caller's copy of
/// what a cascade touched.
fn counts_only(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Array(a) => serde_json::json!(a.len()),
        serde_json::Value::Object(o) => {
            serde_json::Value::Object(o.iter().map(|(k, v)| (k.clone(), counts_only(v))).collect())
        }
        other => other.clone(),
    }
}

/// Every UUID spelled inside `s`.
fn uuids_in(s: &str) -> Vec<Uuid> {
    s.split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
        .filter(|t| t.len() == 36)
        .filter_map(|t| t.parse().ok())
        .collect()
}

/// Filter a belief report to what `caller` may read: claim ids outside its
/// view are dropped, and an error that names anything but a claim it can read
/// is replaced by a generic line. A bypass caller (a replay, a maintenance
/// job) gets the report unchanged. If the filter itself cannot run, the
/// caller gets no ids at all.
pub async fn report_for_caller(
    conn: &mut sqlx::PgConnection,
    caller: &Viewer,
    report: &CascadeReport,
) -> CascadeReport {
    if caller.is_bypass() {
        return report.clone();
    }
    let mut ids: Vec<Uuid> = report
        .targets
        .iter()
        .chain(&report.recomputed)
        .chain(&report.unbacked)
        .copied()
        .collect();
    for e in &report.errors {
        ids.extend(uuids_in(e));
    }
    ids.sort_unstable();
    ids.dedup();
    let visible = match ClaimRepository::visible_claim_ids(&mut *conn, caller, &ids).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                target: "tenancy.admin_cascade",
                error = %e,
                "the cascade report could not be filtered to the caller's view; withholding it"
            );
            return CascadeReport {
                invalidated_bbas: report.invalidated_bbas,
                errors: vec![
                    "the cascade report could not be filtered to the caller's view; the \
                     details are in the audit row"
                        .to_string(),
                ],
                ..CascadeReport::default()
            };
        }
    };
    let keep = |v: &[Uuid]| {
        v.iter()
            .copied()
            .filter(|id| visible.contains(id))
            .collect()
    };
    CascadeReport {
        targets: keep(&report.targets),
        invalidated_bbas: report.invalidated_bbas,
        recomputed: keep(&report.recomputed),
        unbacked: keep(&report.unbacked),
        errors: report
            .errors
            .iter()
            .map(|e| {
                if uuids_in(e).iter().all(|id| visible.contains(id)) {
                    e.clone()
                } else {
                    "a cascade step failed on a row outside the caller's view; the details are \
                     in the audit row"
                        .to_string()
                }
            })
            .collect(),
    }
}

/// Filter a retirement outcome to what `caller` may read: endpoints and
/// retracted edges between claims outside its view are dropped.
pub async fn retirement_for_caller(
    conn: &mut sqlx::PgConnection,
    caller: &Viewer,
    outcome: &RetirementOutcome,
) -> RetirementOutcome {
    if caller.is_bypass() {
        return outcome.clone();
    }
    let mut ids: Vec<Uuid> = outcome.affected_claims.clone();
    for e in &outcome.retracted_edges {
        ids.push(e.source_id);
        ids.push(e.target_id);
    }
    ids.sort_unstable();
    ids.dedup();
    let visible = ClaimRepository::visible_claim_ids(&mut *conn, caller, &ids)
        .await
        .unwrap_or_default();
    let mut out = outcome.clone();
    out.affected_claims.retain(|id| visible.contains(id));
    out.retracted_edges
        .retain(|e| visible.contains(&e.source_id) && visible.contains(&e.target_id));
    out
}

/// Record a repair that failed (and rolled back), on the maintenance
/// connection, and build the caller's status: the reason it gets is generic,
/// the audit row carries the error.
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
    let mut details = trigger.audit_details();
    details["outcome"] = serde_json::json!("failed");
    details["reason"] = serde_json::Value::String(reason);
    let (audit_event_id, audit_error) =
        match audit::record(&mut *admin, EVENT_FAILED, trigger.agent_id, false, &details).await {
            Ok(id) => (Some(id), None),
            Err(e) => {
                tracing::error!(
                    target: "tenancy.admin_cascade",
                    cause = trigger.cause.as_str(),
                    subject = %trigger.subject_id,
                    error = %e,
                    "administrative cascade failed and its audit row could not be written"
                );
                (
                    None,
                    Some("the audit row could not be written; see the server log".to_string()),
                )
            }
        };
    CascadeStatus {
        status: CascadeState::Failed,
        reason: Some(format!(
            "{step} failed on the maintenance connection; the caller's act committed, the \
             repair rolled back and is replayable"
        )),
        audit_event_id,
        audit_error,
        ..CascadeStatus::default()
    }
}

/// Run `repair` and write its [`EVENT_APPLIED`] row in ONE transaction on the
/// maintenance connection. Returns the repair's outcome and the row's id, or
/// the error text (the transaction rolled back; nothing of the repair or the
/// row committed).
macro_rules! repair_with_audit {
    ($admin:expr, $trigger:expr, |$tx:ident| $repair:expr, |$out:ident| $touched:expr) => {{
        let res: Result<_, String> = async {
            let mut $tx = sqlx::Acquire::begin(&mut *$admin)
                .await
                .map_err(|e| e.to_string())?;
            let $out = $repair.await.map_err(|e| e.to_string())?;
            let mut details = $trigger.audit_details();
            details["outcome"] = serde_json::json!("applied");
            details["touched"] = $touched;
            let id = audit::record(&mut *$tx, EVENT_APPLIED, $trigger.agent_id, true, &details)
                .await
                .map_err(|e| format!("the audit row could not be written: {e}"))?;
            $tx.commit().await.map_err(|e| e.to_string())?;
            Ok(($out, id, details["touched"].clone()))
        }
        .await;
        res
    }};
}

/// The belief audit row's id, or why it could not be written.
type BeliefAudit = (Option<Uuid>, Option<String>);

/// Write the belief re-derivation's row after the applied repair (best-effort).
async fn record_belief(
    admin: &mut sqlx::PgConnection,
    trigger: &CascadeTrigger,
    applied_event_id: Uuid,
    report: &CascadeReport,
) -> BeliefAudit {
    let mut details = trigger.audit_details();
    details["applied_event_id"] = serde_json::json!(applied_event_id);
    details["belief"] = serde_json::json!({
        "invalidated_bbas": report.invalidated_bbas,
        "targets": report.targets,
        "recomputed": report.recomputed,
        "unbacked": report.unbacked,
        "errors": report.errors,
    });
    match audit::record(
        &mut *admin,
        EVENT_BELIEF,
        trigger.agent_id,
        report.errors.is_empty(),
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
                "belief re-derivation ran but its audit row could not be written"
            );
            (
                None,
                Some("the belief audit row could not be written; see the server log".to_string()),
            )
        }
    }
}

fn belief_counts(report: &CascadeReport) -> serde_json::Value {
    serde_json::json!({
        "invalidated_bbas": report.invalidated_bbas,
        "targets": report.targets.len(),
        "recomputed": report.recomputed.len(),
        "unbacked": report.unbacked.len(),
        "errors": report.errors.len(),
    })
}

/// The applied status, the caller's copy.
fn applied(
    applied_event_id: Uuid,
    touched: &serde_json::Value,
    belief: Option<(&CascadeReport, BeliefAudit)>,
) -> CascadeStatus {
    let mut counts = counts_only(touched);
    let (belief_audit_event_id, audit_error) = match belief {
        Some((report, (id, err))) => {
            counts["belief"] = belief_counts(report);
            (id, err)
        }
        None => (None, None),
    };
    CascadeStatus {
        status: CascadeState::Applied,
        reason: None,
        audit_event_id: Some(applied_event_id),
        belief_audit_event_id,
        audit_error,
        touched: Some(counts),
    }
}

/// The supersede cascade: migrate the retired claim's edges onto the
/// replacement (with its audit row, atomically), then invalidate and re-derive
/// the BBAs frozen from its interval ([`cascade_after_supersede`]).
///
/// `admin` must be the maintenance connection and `admin_viewer` its bypass
/// viewer (`MaintenanceSession::split`): the cascade walks downstream claims of
/// any owner, and a caller's viewer would hide other groups' rows from it.
/// `caller` is the triggering caller's viewer; the returned status and report
/// are filtered to it (see the module docs).
pub async fn apply_after_supersede(
    admin: &mut sqlx::PgConnection,
    admin_viewer: &Viewer,
    caller: &Viewer,
    trigger: &CascadeTrigger,
    old_id: Uuid,
    new_id: Uuid,
) -> (CascadeStatus, CascadeReport) {
    let repaired = repair_with_audit!(
        admin,
        trigger,
        |tx| ClaimRepository::migrate_superseded_edges_conn(&mut tx, old_id, new_id),
        |m| serde_json::json!({
            "edges_retargeted": m.retargeted,
            "edges_resourced": m.resourced,
        })
    );
    let (_, applied_id, touched) = match repaired {
        Ok(r) => r,
        Err(e) => {
            return (
                failed(admin, trigger, "the supersede edge migration", e).await,
                CascadeReport::default(),
            )
        }
    };
    let report = cascade_after_supersede(&mut *admin, admin_viewer, new_id).await;
    let belief = record_belief(admin, trigger, applied_id, &report).await;
    let status = applied(applied_id, &touched, Some((&report, belief)));
    (status, report_for_caller(admin, caller, &report).await)
}

/// The dedup cascade: repair the edge and derived-record layers
/// ([`ClaimRepository::repair_marked_duplicate_conn`], with its audit row,
/// atomically), then recompute and re-derive ([`cascade_after_dedup`]).
/// `admin` / `admin_viewer` / `caller` as for [`apply_after_supersede`].
pub async fn apply_after_dedup(
    admin: &mut sqlx::PgConnection,
    admin_viewer: &Viewer,
    caller: &Viewer,
    trigger: &CascadeTrigger,
    dup_id: Uuid,
    canonical_id: Uuid,
) -> (CascadeStatus, CascadeReport) {
    use epigraph_core::ClaimId;
    let repaired = repair_with_audit!(
        admin,
        trigger,
        |tx| ClaimRepository::repair_marked_duplicate_conn(
            &mut tx,
            ClaimId::from_uuid(dup_id),
            ClaimId::from_uuid(canonical_id),
        ),
        |r| serde_json::json!({
            "edges_retracted": r.retracted_edges,
            "edges_retargeted": r.retargeted_edges,
            "edges_resourced": r.resourced_edges.iter().map(|(id, _, _)| *id).collect::<Vec<_>>(),
            "bbas_deleted_with_retracted_edges": r.deleted_bbas,
            "bbas_moved": r.moved_bbas,
            "duplicate_copies_dropped": r.dropped_duplicate_copies,
            "false_bindings_not_copied": r.skipped_false_bindings,
        })
    );
    let (repair, applied_id, touched) = match repaired {
        Ok(r) => r,
        Err(e) => {
            return (
                failed(admin, trigger, "the dedup repair", e).await,
                CascadeReport::default(),
            )
        }
    };
    let report = cascade_after_dedup(&mut *admin, admin_viewer, canonical_id, &repair).await;
    let belief = record_belief(admin, trigger, applied_id, &report).await;
    let status = applied(applied_id, &touched, Some((&report, belief)));
    (status, report_for_caller(admin, caller, &report).await)
}

/// The consolidation cascade: migrate the retired sources' live edges onto
/// the merged claim and retract the redundant copies
/// ([`ClaimRepository::migrate_consolidated_edges_conn`], with its audit row,
/// atomically). `trigger.subject_id` is the merged claim and
/// `trigger.sources` the retired sources. No belief cascade follows, as none
/// did before the split.
pub async fn apply_after_consolidate(
    admin: &mut sqlx::PgConnection,
    trigger: &CascadeTrigger,
) -> CascadeStatus {
    let merged_id = trigger.subject_id;
    let sources = trigger.sources.clone();
    let repaired = repair_with_audit!(
        admin,
        trigger,
        |tx| ClaimRepository::migrate_consolidated_edges_conn(&mut tx, merged_id, &sources),
        |m| serde_json::json!({
            "edges_migrated": m.migrated,
            "edges_retracted": m.retracted,
        })
    );
    match repaired {
        Ok((_, applied_id, touched)) => applied(applied_id, &touched, None),
        Err(e) => failed(admin, trigger, "the consolidation edge migration", e).await,
    }
}

/// The whole match-candidate retirement, on the maintenance connection: flip
/// the candidate to `stale` (decided by `trigger.agent_id`), retract its
/// matcher edges and remove their derived rows
/// ([`MatchCandidateRepo::retire_conn`]), and write its audit row, in ONE
/// transaction. `trigger.candidate_status`, when set, is the status the
/// retirement was requested against, and a candidate decided again since is
/// refused (the status is `failed` and nothing changed). The returned outcome
/// is filtered to `caller`.
pub async fn apply_match_retire(
    admin: &mut sqlx::PgConnection,
    caller: &Viewer,
    trigger: &CascadeTrigger,
    candidate_id: Uuid,
) -> (CascadeStatus, Option<RetirementOutcome>) {
    let expected = trigger.candidate_status.clone();
    let repaired = repair_with_audit!(
        admin,
        trigger,
        |tx| MatchCandidateRepo::retire_conn(
            &mut tx,
            candidate_id,
            trigger.agent_id,
            expected.as_deref()
        ),
        |o| serde_json::json!({
            "previous_status": o.previous_status,
            "edges_retracted": o.retracted_edges.iter().map(|e| e.edge_id).collect::<Vec<_>>(),
            "edges_retracted_now": o.edges_retracted,
            "factors_deleted": o.factors_deleted,
            "bp_messages_deleted": o.bp_messages_deleted,
            "bbas_invalidated": o.bbas_invalidated,
            "affected_claims": o.affected_claims,
        })
    );
    match repaired {
        Ok((outcome, applied_id, touched)) => {
            let status = applied(applied_id, &touched, None);
            let outcome = retirement_for_caller(admin, caller, &outcome).await;
            (status, Some(outcome))
        }
        Err(e) => (
            failed(admin, trigger, "the match-candidate retirement", e).await,
            None,
        ),
    }
}

/// The `edge_retract` cascade (migration 120), on the maintenance connection:
/// remove every BBA keyed on the withdrawn edge
/// ([`epigraph_db::EdgeRepository::remove_withdrawn_edge_bbas_conn`], keyed on
/// `perspective_type = 'edge'`) with its audit row, atomically, then re-derive
/// the affected claims' beliefs
/// ([`crate::retraction_cascade::cascade_after_edge_withdrawal`]).
///
/// STATE-DERIVED: when the edge is in force at the time of the call (its owner
/// un-retracted it, or the deferral was stale) nothing is removed and the
/// applied row says so (`touched.edge_withdrawn = false`, zero counts, and a
/// reason). That is a legitimate state, so it is `admin_applied`, never
/// `admin_failed`, which would go stuck and page the operator.
///
/// The applied row names `trigger.agent_id`: the edge's owner whose act
/// deferred it (or, for the one-shot legacy sweep, the acting operator).
/// `touched` carries COUNTS only, never another writer's BBA ids or source
/// agents, because the row's `agent_id` can read it. `sweep_reason` is the
/// operator's text for the one-shot sweep, recorded in `touched`.
pub async fn apply_after_edge_retract(
    admin: &mut sqlx::PgConnection,
    admin_viewer: &Viewer,
    trigger: &CascadeTrigger,
    sweep_reason: Option<&str>,
) -> CascadeStatus {
    let edge_id = trigger.subject_id;
    let repaired = repair_with_audit!(
        admin,
        trigger,
        |tx| epigraph_db::EdgeRepository::remove_withdrawn_edge_bbas_conn(&mut tx, edge_id),
        |r| {
            let mut t = serde_json::json!({
                "edge_withdrawn": r.withdrawn,
                "bbas_deleted": r.deleted,
                "claims_affected": r.claims.len(),
            });
            if !r.withdrawn {
                t["reason"] = serde_json::json!(
                    "the edge is in force at the time of the replay; nothing was removed"
                );
            }
            if let Some(why) = sweep_reason {
                t["sweep_reason"] = serde_json::json!(why);
            }
            t
        }
    );
    let (removed, applied_id, touched) = match repaired {
        Ok(r) => r,
        Err(e) => return failed(admin, trigger, "the edge-keyed BBA removal", e).await,
    };
    if removed.claims.is_empty() {
        return applied(applied_id, &touched, None);
    }
    let report = crate::retraction_cascade::cascade_after_edge_withdrawal(
        &mut *admin,
        admin_viewer,
        &removed.claims,
        removed.deleted,
    )
    .await;
    let belief = record_belief(admin, trigger, applied_id, &report).await;
    applied(applied_id, &touched, Some((&report, belief)))
}

/// One edge the one-shot legacy sweep handled.
#[derive(Debug, Clone, Serialize)]
pub struct WithdrawnEdgeSweepItem {
    /// The withdrawn edge whose BBAs were removed.
    pub edge_id: Uuid,
    /// What the removal did (its audit row names the acting operator).
    pub status: CascadeStatus,
}

/// The one-shot legacy sweep (`replay_deferred_cascades
/// --sweep-withdrawn-edge-bbas`), on the maintenance connection: every edge
/// whose edge-keyed BBAs outlived it (an edge-factor perspective with BBAs whose
/// edge is absent or out of force, retracted before migration 120 recorded
/// deferrals) goes through [`apply_after_edge_retract`], audited as cause
/// `edge_retract` naming `acting_agent` (the operator running it, D1) with
/// `reason`. NOT on the timer. Up to `limit` edges per run.
///
/// # Errors
/// Only the candidate query's error; each edge's own failure is in its item.
pub async fn sweep_withdrawn_edge_bbas(
    admin: &mut sqlx::PgConnection,
    admin_viewer: &Viewer,
    acting_agent: Uuid,
    reason: &str,
    limit: i64,
) -> Result<Vec<WithdrawnEdgeSweepItem>, DbError> {
    let edges =
        epigraph_db::EdgeRepository::withdrawn_edges_with_bbas_conn(&mut *admin, limit).await?;
    let mut items = Vec::with_capacity(edges.len());
    for edge_id in edges {
        let trigger = CascadeTrigger::new(
            CascadeCause::EdgeRetract,
            Some(acting_agent),
            None,
            edge_id,
            None,
        );
        let status = apply_after_edge_retract(admin, admin_viewer, &trigger, Some(reason)).await;
        items.push(WithdrawnEdgeSweepItem { edge_id, status });
    }
    Ok(items)
}

/// One replayed cascade.
#[derive(Debug, Clone, Serialize)]
pub struct ReplayItem {
    /// The deferred (or failed) row replayed.
    pub deferred_event_id: Uuid,
    /// Its cause, when the row carried one.
    pub cause: Option<CascadeCause>,
    /// Its subject, when the row carried one.
    pub subject_id: Option<Uuid>,
    /// What the replay did.
    pub status: CascadeStatus,
}

/// A pending cascade held out of the replay window because its repair has
/// failed `max_failures` times: an operator reads why and retires it
/// (`replay_deferred_cascades --retire`).
#[derive(Debug, Clone, Serialize)]
pub struct StuckItem {
    /// Its oldest pending deferred (or failed) row: the id to retire.
    pub deferred_event_id: Uuid,
    /// Its cause, when the row carried one.
    pub cause: Option<CascadeCause>,
    /// Its subject, when the row carried one.
    pub subject_id: Option<Uuid>,
    /// How many times its repair has failed since it was deferred.
    pub failures: i64,
}

/// The default of [`replay_deferred`]'s `max_failures`: a cascade whose
/// repair has failed this many times leaves the window for an operator.
pub const DEFAULT_MAX_FAILURES: i64 = 5;

/// What [`replay_deferred`] did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ReplayReport {
    /// Cascades in this run's window (up to the limit).
    pub pending: usize,
    /// Cascades applied by this run.
    pub applied: usize,
    /// Cascades whose repair failed again (still pending).
    pub failed: usize,
    /// Rows whose trigger could not be read (left pending, reported).
    pub unreadable: usize,
    /// One entry per row considered.
    pub items: Vec<ReplayItem>,
    /// Cascades held out of the window (failed `max_failures` times or more),
    /// after this run.
    pub stuck: Vec<StuckItem>,
}

/// Replay the pending administrative cascades
/// ([`epigraph_db::repos::admin_cascade::pending_replays`]: one per cause and
/// subject, fewest failures first, then oldest), up to `limit` cascades, and
/// report the ones held back after `max_failures` failed repairs. Runs on the
/// maintenance connection with its bypass viewer.
///
/// Every row it reads was written by 117's deferral definer (which checked the
/// act was the recorded principal's own) or by a privileged session: a
/// non-privileged session cannot write a `cascade.*` row.
///
/// Each replay runs the same `apply_after_*` call the request path would have,
/// with the trigger the deferral recorded (so the applied row still names the
/// original caller) plus `replay_of` naming the deferral and `replayed_by`.
/// Every repair re-verifies the committed act, so a deferral whose act was
/// since undone fails loudly instead of repairing, and is left pending. A
/// deferred match-candidate retirement is the request itself: the replay
/// carries it out while the candidate still has the status the deferral
/// recorded, and fails loudly (left pending) once it was decided again.
///
/// # Errors
/// Only the pending-row query's error; each cascade's own failure is reported
/// in its [`ReplayItem`].
pub async fn replay_deferred(
    admin: &mut sqlx::PgConnection,
    admin_viewer: &Viewer,
    replayed_by: &str,
    limit: i64,
    max_failures: i64,
) -> Result<ReplayReport, DbError> {
    let rows = audit::pending_replays(&mut *admin, limit, max_failures).await?;
    let mut report = ReplayReport {
        pending: rows.len(),
        ..ReplayReport::default()
    };
    let mut seen: HashSet<(CascadeCause, Uuid)> = HashSet::new();
    for audit::PendingReplay {
        event_id, details, ..
    } in rows
    {
        let Some(mut trigger) = CascadeTrigger::from_audit(&details) else {
            report.unreadable += 1;
            report.items.push(ReplayItem {
                deferred_event_id: event_id,
                cause: None,
                subject_id: None,
                status: CascadeStatus {
                    status: CascadeState::Deferred,
                    reason: Some("the deferral row carries no readable trigger".to_string()),
                    audit_event_id: Some(event_id),
                    ..CascadeStatus::default()
                },
            });
            continue;
        };
        if !seen.insert((trigger.cause, trigger.subject_id)) {
            continue;
        }
        trigger.replay_of = Some(ReplayOrigin {
            deferred_event_id: event_id,
            replayed_by: replayed_by.to_string(),
        });
        let subject = trigger.subject_id;
        let status = match (trigger.cause, trigger.object_id) {
            (CascadeCause::Supersede, Some(new_id)) => {
                apply_after_supersede(admin, admin_viewer, admin_viewer, &trigger, subject, new_id)
                    .await
                    .0
            }
            (CascadeCause::Dedup, Some(canonical)) => {
                apply_after_dedup(
                    admin,
                    admin_viewer,
                    admin_viewer,
                    &trigger,
                    subject,
                    canonical,
                )
                .await
                .0
            }
            (CascadeCause::Consolidate, _) => apply_after_consolidate(admin, &trigger).await,
            (CascadeCause::MatchRetire, _) => {
                apply_match_retire(admin, admin_viewer, &trigger, subject)
                    .await
                    .0
            }
            (CascadeCause::EdgeRetract, _) => {
                apply_after_edge_retract(admin, admin_viewer, &trigger, None).await
            }
            (CascadeCause::Supersede | CascadeCause::Dedup, None) => {
                report.unreadable += 1;
                report.items.push(ReplayItem {
                    deferred_event_id: event_id,
                    cause: Some(trigger.cause),
                    subject_id: Some(subject),
                    status: CascadeStatus {
                        status: CascadeState::Deferred,
                        reason: Some("the deferral row names no object claim".to_string()),
                        audit_event_id: Some(event_id),
                        ..CascadeStatus::default()
                    },
                });
                continue;
            }
        };
        match status.status {
            CascadeState::Applied => report.applied += 1,
            _ => report.failed += 1,
        }
        report.items.push(ReplayItem {
            deferred_event_id: event_id,
            cause: Some(trigger.cause),
            subject_id: Some(subject),
            status,
        });
    }
    report.stuck = audit::stuck_replays(&mut *admin, max_failures)
        .await?
        .into_iter()
        .map(|p| {
            let trigger = CascadeTrigger::from_audit(&p.details);
            StuckItem {
                deferred_event_id: p.event_id,
                cause: trigger.as_ref().map(|t| t.cause),
                subject_id: trigger.as_ref().map(|t| t.subject_id),
                failures: p.failures,
            }
        })
        .collect();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_only_replaces_every_array_by_its_length() {
        let v = serde_json::json!({
            "edges_retargeted": [Uuid::nil(), Uuid::nil()],
            "bbas_moved": 3,
            "belief": {"targets": [Uuid::nil()], "errors": []},
        });
        assert_eq!(
            counts_only(&v),
            serde_json::json!({
                "edges_retargeted": 2,
                "bbas_moved": 3,
                "belief": {"targets": 1, "errors": 0},
            })
        );
    }

    #[test]
    fn uuids_in_finds_every_spelled_uuid() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let found = uuids_in(&format!("target {a}: failed (edge {b}); code 42501"));
        assert_eq!(found, vec![a, b]);
        assert!(uuids_in("no ids here, just 42501").is_empty());
    }

    #[test]
    fn a_trigger_round_trips_through_its_audit_row() {
        let mut t = CascadeTrigger::new(
            CascadeCause::Consolidate,
            Some(Uuid::new_v4()),
            Some(OauthPrincipal {
                client_id: Some(Uuid::new_v4()),
                owner_id: None,
                agent_id: None,
            }),
            Uuid::new_v4(),
            None,
        );
        t.sources = vec![Uuid::new_v4(), Uuid::new_v4()];
        assert_eq!(CascadeTrigger::from_audit(&t.audit_details()), Some(t));
        let mut r = CascadeTrigger::new(
            CascadeCause::MatchRetire,
            Some(Uuid::new_v4()),
            None,
            Uuid::new_v4(),
            None,
        );
        r.candidate_status = Some("promoted".to_string());
        assert_eq!(CascadeTrigger::from_audit(&r.audit_details()), Some(r));
        for c in [
            CascadeCause::Supersede,
            CascadeCause::Dedup,
            CascadeCause::Consolidate,
            CascadeCause::MatchRetire,
        ] {
            assert_eq!(CascadeCause::parse(c.as_str()), Some(c));
        }
    }
}
