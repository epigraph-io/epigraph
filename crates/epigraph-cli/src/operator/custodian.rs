//! `grant-role` / `end-role-assignment` / `list-role-assignments`: the
//! platform roles of migration 123 (`role:platform-custodian`,
//! `role:auditor`), held by registered humans through timestamped
//! assignments.
//!
//! Every write goes through 123's maintenance-only definers
//! (`epigraph_grant_role`, `epigraph_end_role_assignment`), whose table
//! triggers enforce the rules (CUS01 agents never hold a role, CUS02
//! append-only, CUS03 the grantor rule) and write one `platform.` audit row
//! per change. This module runs each call in one transaction, committed under
//! `--apply` and rolled back otherwise (its audit row and its OCCUPIES
//! projection with it), so a dry run prints exactly what the definer did.
//!
//! The window is always explicit: a grant names `--valid-to` or says
//! `--open-ended`, never neither. `valid_from` is now unless given, and never in
//! the past (the table refuses a back-dated grant).
//!
//! # `custodial-supersede`: the custodian's edit of the platform corpus
//!
//! The one write path for a claim the platform owns (the world-owned legacy
//! corpus, whose authors are retired or unbound identities by construction):
//! on the maintenance DSN, in ONE transaction, the supersede act
//! (`ClaimRepository::supersede_act_conn`: retire, restate under the inherited
//! author and owner, the `supersedes` edge), the edge migration
//! (`migrate_superseded_edges_conn`: strengthening edges follow the
//! successor; `contradicts` / `refutes` stay), and
//! `epigraph_record_custodial_act` against a NAMED live custodian assignment
//! of a NAMED human actor (CUS04 otherwise, which rolls the act back). So no
//! revision lands unrecorded and no record names an authority that did not
//! hold. It replaces the hand-run SQL sequence the operator-binding runbook
//! carried for this.

use chrono::{DateTime, Utc};
use epigraph_db::{RoleAssignmentRepository, RoleAssignmentRow};
use serde_json::json;
use sqlx::PgConnection;
use uuid::Uuid;

/// The catalog roles a grant may name (migration 123's seed).
pub const ROLES: &[&str] = &["role:platform-custodian", "role:auditor"];

/// The validated window of a grant: `valid_to` `None` is open-ended, and
/// only an explicit `--open-ended` produces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_to: Option<DateTime<Utc>>,
}

impl Window {
    /// Exactly one of `valid_to` / `open_ended`, and a role from [`ROLES`].
    ///
    /// # Errors
    /// Neither or both window flags; a `valid_to` not after `valid_from` (or
    /// not in the future); an unknown role.
    pub fn from_flags(
        role: &str,
        valid_from: Option<DateTime<Utc>>,
        valid_to: Option<DateTime<Utc>>,
        open_ended: bool,
    ) -> anyhow::Result<Self> {
        if !ROLES.contains(&role) {
            anyhow::bail!("--role {role} is not a platform role; one of {ROLES:?}");
        }
        match (valid_to, open_ended) {
            (None, false) => anyhow::bail!(
                "name the end of the assignment: --valid-to <RFC3339>, or --open-ended to grant \
                 it with no end (it is then ended only by end-role-assignment)"
            ),
            (Some(_), true) => anyhow::bail!("--valid-to and --open-ended are exclusive"),
            (Some(to), false) => {
                let from = valid_from.unwrap_or_else(Utc::now);
                if to <= from {
                    anyhow::bail!(
                        "--valid-to {to} is not after the start of the assignment {from}"
                    );
                }
            }
            (None, true) => {}
        }
        Ok(Self {
            valid_from,
            valid_to,
        })
    }
}

/// Grant `role` to `holder` in one transaction (committed under `apply`).
/// Returns the assignment as written.
///
/// # Errors
/// The table's guards refused it (CUS01 a holder that is not a registered
/// human, CUS02 a back-dated start, CUS03 the grantor rule), or a statement
/// failed.
pub async fn grant(
    conn: &mut PgConnection,
    role: &str,
    holder: Uuid,
    window: Window,
    granted_by: Option<Uuid>,
    reason: &str,
    apply: bool,
) -> anyhow::Result<RoleAssignmentRow> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let id = RoleAssignmentRepository::grant(
        &mut tx,
        role,
        holder,
        window.valid_from,
        window.valid_to,
        granted_by,
        reason,
    )
    .await?;
    let row = RoleAssignmentRepository::get(&mut tx, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("assignment {id} not readable after its grant"))?;
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(row)
}

/// End `assignment` now, in one transaction (committed under `apply`).
/// Returns whether this call ended it and the row as it stands.
///
/// # Errors
/// The assignment does not exist, or a statement failed.
pub async fn end(
    conn: &mut PgConnection,
    assignment: Uuid,
    reason: &str,
    apply: bool,
) -> anyhow::Result<(bool, RoleAssignmentRow)> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    if RoleAssignmentRepository::get(&mut tx, assignment)
        .await?
        .is_none()
    {
        anyhow::bail!("no role assignment {assignment}; nothing was changed");
    }
    let ended = RoleAssignmentRepository::end(&mut tx, assignment, reason).await?;
    let row = RoleAssignmentRepository::get(&mut tx, assignment)
        .await?
        .ok_or_else(|| anyhow::anyhow!("assignment {assignment} vanished"))?;
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok((ended, row))
}

/// One tab-separated line per assignment.
#[must_use]
pub fn describe(row: &RoleAssignmentRow) -> String {
    let fmt = |t: Option<DateTime<Utc>>| t.map_or_else(|| "-".to_string(), |t| t.to_rfc3339());
    format!(
        "{}\trole={}\tholder={}\tvalid_from={}\tvalid_to={}\tgranted_by={}\tgranted_via={}\t\
         revoked_at={}\treason={:?}",
        row.id,
        row.role,
        row.holder_person_id
            .map_or_else(|| "-".to_string(), |h| h.to_string()),
        row.valid_from.to_rfc3339(),
        fmt(row.valid_to),
        row.granted_by
            .map_or_else(|| "-".to_string(), |g| g.to_string()),
        row.granted_via,
        fmt(row.revoked_at),
        row.reason,
    )
}

/// A custodial supersede, as the operator asked for it.
#[derive(Debug, Clone)]
pub struct SupersedeRequest {
    pub claim: Uuid,
    pub content: String,
    pub truth: f64,
    pub assignment: Uuid,
    pub actor: Uuid,
    pub reason: String,
    /// Admit a claim the world group does not own (OQ-8: the platform corpus
    /// is the default scope).
    pub allow_owned: bool,
    pub apply: bool,
}

/// What a custodial supersede did (or, on a dry run, would have done).
#[derive(Debug, Clone)]
pub struct SupersedeReport {
    pub old: Uuid,
    pub new: Uuid,
    pub author: Uuid,
    pub owner: Uuid,
    pub edges_moved: usize,
    pub act_event: Uuid,
    pub applied: bool,
}

/// The three outcomes, mapped to the binary's exit codes 0 / 1 / 2.
#[derive(Debug)]
pub enum SupersedeOutcome {
    /// Committed (`--apply`) or rolled back (dry run) after a complete act.
    Done(SupersedeReport),
    /// Refused before anything was written (exit 1).
    Refused(String),
    /// The act ran but did not leave what it must; rolled back (exit 2).
    Invariant(String),
}

/// Run one custodial supersede (module docs).
///
/// # Errors
/// A statement failed or the database refused (CUS04 for an assignment that
/// is not a live custodian assignment of `actor`, OPL0x from the binding
/// trigger); the transaction is rolled back and nothing is written.
pub async fn custodial_supersede(
    conn: &mut PgConnection,
    req: &SupersedeRequest,
) -> anyhow::Result<SupersedeOutcome> {
    use epigraph_core::{ClaimId, TruthValue};
    use epigraph_db::ClaimRepository;

    let Ok(truth) = TruthValue::new(req.truth) else {
        return Ok(SupersedeOutcome::Refused(format!(
            "--truth {} is not a truth value in [0, 1]",
            req.truth
        )));
    };
    if req.content.trim().is_empty() || req.reason.trim().is_empty() {
        return Ok(SupersedeOutcome::Refused(
            "the revised content and a reason are required".to_string(),
        ));
    }
    let old: Option<(Uuid, Uuid, bool, f64, Vec<u8>)> = sqlx::query_as(
        "SELECT agent_id, owner_group_id, COALESCE(is_current, true), truth_value, content_hash \
           FROM claims WHERE id = $1",
    )
    .bind(req.claim)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((author, owner, current, old_truth, old_hash)) = old else {
        return Ok(SupersedeOutcome::Refused(format!(
            "no claim {}; nothing was changed",
            req.claim
        )));
    };
    if !current {
        return Ok(SupersedeOutcome::Refused(format!(
            "claim {} is not current (it was already superseded or retired); revise its current \
             successor instead. Nothing was changed.",
            req.claim
        )));
    }
    if owner != super::WORLD && !req.allow_owned {
        return Ok(SupersedeOutcome::Refused(format!(
            "claim {} is owned by group {owner}, not the world group: it is not platform corpus. \
             A custodial revision of an owned claim needs --allow-owned. Nothing was changed.",
            req.claim
        )));
    }

    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let (new, old_id) = ClaimRepository::supersede_act_conn(
        &mut tx,
        ClaimId::from_uuid(req.claim),
        &req.content,
        truth,
        &req.reason,
    )
    .await?;
    let migration = ClaimRepository::migrate_superseded_edges_conn(&mut tx, old_id, new).await?;
    let edges_moved = migration.retargeted.len() + migration.resourced.len();

    let successor: (Uuid, Uuid, Option<Uuid>, bool, bool, Vec<u8>) = sqlx::query_as(
        "SELECT n.agent_id, n.owner_group_id, n.supersedes, COALESCE(n.is_current, true), \
                COALESCE(o.is_current, true), n.content_hash \
           FROM claims n JOIN claims o ON o.id = $2 WHERE n.id = $1",
    )
    .bind(new)
    .bind(old_id)
    .fetch_one(&mut *tx)
    .await?;
    let (s_author, s_owner, s_sup, s_current, old_still_current, new_hash) = successor;
    if s_author != author
        || s_owner != owner
        || s_sup != Some(old_id)
        || !s_current
        || old_still_current
    {
        tx.rollback().await?;
        return Ok(SupersedeOutcome::Invariant(format!(
            "the successor {new} does not restate {old_id} as the act must (author {s_author} \
             vs {author}, owner {s_owner} vs {owner}, supersedes {s_sup:?}, current {s_current}, \
             predecessor still current {old_still_current}); rolled back"
        )));
    }

    let act_event = RoleAssignmentRepository::record_custodial_act(
        &mut tx,
        req.assignment,
        req.actor,
        "claim.supersede",
        "claim",
        old_id,
        json!({
            "new_id": new,
            "old_hash": hex::encode(&old_hash),
            "new_hash": hex::encode(&new_hash),
            "old_truth": old_truth,
            "new_truth": req.truth,
            "owner_group_id": owner,
            // OQ-8 (a): the override that admitted a claim the world group
            // does not own is part of the record, not only of the check.
            "allow_owned": req.allow_owned,
            "author": author,
            "reason": req.reason,
            "edges_moved": edges_moved,
        }),
    )
    .await?;
    if req.apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(SupersedeOutcome::Done(SupersedeReport {
        old: old_id,
        new,
        author,
        owner,
        edges_moved,
        act_event,
        applied: req.apply,
    }))
}
