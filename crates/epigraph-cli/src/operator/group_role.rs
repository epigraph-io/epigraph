//! `define-group-role`, `bind-group-role`, `end-group-role-binding` and
//! `group-roster`: a group whose membership FOLLOWS a platform role
//! (migration 165), on the maintenance DSN.
//!
//! A binding makes every registered human holding a live assignment of the
//! role (its `grant-role` window) a `reader` or `writer` of the group, and,
//! with `--include-agents`, every agent registered to such a human (an acting
//! live link or a live client allowance). Nothing is written to the group's
//! roster: the membership is computed when a viewer is resolved, so it lapses
//! at the window's end with no job.
//!
//! Each write calls ONE maintenance-only definer in one transaction,
//! committed under `--apply` and rolled back otherwise (the audit row with
//! it), so a dry run prints exactly what the definer decided. The definers
//! and the table's triggers hold every rule (no elevating or audit-reading
//! role, GRB01; no personal, world or seed group, GRB02; a new key only,
//! GRB03; never `admin`); this module adds only the checks that can be made
//! before connecting.

use anyhow::bail;
use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

/// The member roles a binding confers. Never `admin`: a derived member never
/// administers the roster.
pub const MEMBER_ROLES: [&str; 2] = ["reader", "writer"];

/// Refuse a `--member-role` outside reader|writer before any connection.
///
/// # Errors
/// `role` is not one of [`MEMBER_ROLES`].
pub fn validate_member_role(role: &str) -> anyhow::Result<()> {
    if !MEMBER_ROLES.contains(&role) {
        bail!(
            "--member-role {role:?} is not a role a binding confers (valid: {}; a role never \
             confers admin); nothing was done",
            MEMBER_ROLES.join(", ")
        );
    }
    Ok(())
}

/// Refuse a role key that is not `role:<lowercase-key>` before any connection.
///
/// # Errors
/// `key` does not have the catalog's key shape.
pub fn validate_key(flag: &str, key: &str) -> anyhow::Result<()> {
    if !super::custodian::is_role_key(key) {
        bail!("{flag} {key:?} is not a role key (role:<lowercase-key>); nothing was done");
    }
    Ok(())
}

async fn finish(tx: sqlx::Transaction<'_, sqlx::Postgres>, apply: bool) -> anyhow::Result<()> {
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(())
}

/// Define the catalog role `key` (non-elevating, no audit read) and bind it
/// to `group`, in one transaction. Returns the binding id.
///
/// # Errors
/// The definer refused (GRB03 the key is already in the catalog; GRB02 the
/// group cannot follow a role; a member role outside reader|writer), or a
/// statement failed.
#[allow(clippy::too_many_arguments)]
pub async fn define(
    conn: &mut PgConnection,
    key: &str,
    description: &str,
    group: Uuid,
    member_role: &str,
    include_agents: bool,
    reason: &str,
    apply: bool,
) -> anyhow::Result<Uuid> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let binding: Uuid =
        sqlx::query_scalar("SELECT public.epigraph_define_group_role($1, $2, $3, $4, $5, $6)")
            .bind(key)
            .bind(description)
            .bind(group)
            .bind(member_role)
            .bind(include_agents)
            .bind(reason)
            .fetch_one(&mut *tx)
            .await?;
    finish(tx, apply).await?;
    Ok(binding)
}

/// Bind the existing catalog role `role` to `group`. Returns the binding id.
///
/// # Errors
/// The definer or the table refused (GRB01 the role elevates or reads the
/// audit trail; GRB02 the group cannot follow a role; the role is already
/// bound to the group), or a statement failed.
pub async fn bind(
    conn: &mut PgConnection,
    role: &str,
    group: Uuid,
    member_role: &str,
    include_agents: bool,
    reason: &str,
    apply: bool,
) -> anyhow::Result<Uuid> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let binding: Uuid =
        sqlx::query_scalar("SELECT public.epigraph_bind_group_role($1, $2, $3, $4, $5)")
            .bind(role)
            .bind(group)
            .bind(member_role)
            .bind(include_agents)
            .bind(reason)
            .fetch_one(&mut *tx)
            .await?;
    finish(tx, apply).await?;
    Ok(binding)
}

/// End `binding` now. `false` when it had already ended (or does not exist).
///
/// # Errors
/// A statement failed.
pub async fn end(
    conn: &mut PgConnection,
    binding: Uuid,
    reason: &str,
    apply: bool,
) -> anyhow::Result<bool> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let ended: bool = sqlx::query_scalar("SELECT public.epigraph_end_group_role_binding($1, $2)")
        .bind(binding)
        .bind(reason)
        .fetch_one(&mut *tx)
        .await?;
    finish(tx, apply).await?;
    Ok(ended)
}

/// One member of a group through its role bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterRow {
    /// The member (a role holder, or an agent registered to one).
    pub agent: Uuid,
    /// `reader` or `writer`.
    pub role: String,
    /// The role-holding human it derives from.
    pub holder: Uuid,
}

/// Who holds `group` through its role bindings at `at` (now when `None`).
/// Read-only.
///
/// # Errors
/// A statement failed.
pub async fn roster(
    conn: &mut PgConnection,
    group: Uuid,
    at: Option<DateTime<Utc>>,
) -> anyhow::Result<Vec<RosterRow>> {
    let rows: Vec<(Uuid, String, Uuid)> = sqlx::query_as(
        "SELECT out_agent_id, out_role, out_holder \
           FROM public.epigraph_group_role_roster($1, COALESCE($2, now()))",
    )
    .bind(group)
    .bind(at)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(agent, role, holder)| RosterRow {
            agent,
            role,
            holder,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binding_never_confers_admin() {
        assert!(validate_member_role("admin").is_err());
        assert!(validate_member_role("owner").is_err());
        for ok in MEMBER_ROLES {
            assert!(validate_member_role(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn a_role_key_has_the_catalog_shape() {
        for bad in [
            "team-member",
            "role:",
            "role:Team",
            "role:1team",
            "role:team_member",
        ] {
            assert!(validate_key("--key", bad).is_err(), "{bad}");
        }
        for ok in ["role:team-member", "role:auditor", "role:t2"] {
            assert!(validate_key("--key", ok).is_ok(), "{ok}");
        }
    }
}
