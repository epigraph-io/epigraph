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

use chrono::{DateTime, Utc};
use epigraph_db::{RoleAssignmentRepository, RoleAssignmentRow};
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
