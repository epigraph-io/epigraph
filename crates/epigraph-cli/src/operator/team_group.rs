//! `create-group` and `group-member add|remove|set-role`: keyless TEAM groups
//! (migration 164), on the maintenance DSN.
//!
//! Each command calls ONE maintenance-only, audited definer in one
//! transaction, committed under `--apply` and rolled back otherwise (the audit
//! row with it), so a dry run prints exactly what the definer decided. The
//! definers hold every rule (the admin is a registered human; an operated
//! agent is a member only where its operator writes; the last live admin
//! stays; a removal is a revoke; one active team group per name) and refuse
//! with a named SQLSTATE; this module adds only the checks that can be made
//! before connecting.

use anyhow::bail;
use sqlx::PgConnection;
use uuid::Uuid;

/// The only `--kind` the operator creates here. Personal groups come from the
/// operator link, community groups from the community routes, and world and
/// seed are fixed.
pub const KIND_TEAM: &str = "team";

/// The membership roles, as `group_memberships_role_check` (060) spells them.
pub const ROLES: [&str; 3] = ["reader", "writer", "admin"];

/// Refuse a `--kind` other than `team` before any connection.
///
/// # Errors
/// `kind` is not `team`.
pub fn validate_kind(kind: &str) -> anyhow::Result<()> {
    if kind != KIND_TEAM {
        bail!(
            "--kind {kind:?} is not supported: create-group makes only keyless `team` groups \
             (--kind team); nothing was done"
        );
    }
    Ok(())
}

/// Refuse a role outside reader|writer|admin before any connection.
///
/// # Errors
/// `role` is not one of [`ROLES`].
pub fn validate_role(role: &str) -> anyhow::Result<()> {
    if !ROLES.contains(&role) {
        bail!(
            "--role {role:?} is not a membership role (valid: {}); nothing was done",
            ROLES.join(", ")
        );
    }
    Ok(())
}

/// Refuse a blank `--reason` (every act is audited with it) or `--name`.
///
/// # Errors
/// The value is empty after trimming.
pub fn validate_text(flag: &str, value: &str) -> anyhow::Result<()> {
    if value.trim().is_empty() {
        bail!("{flag} must not be blank; nothing was done");
    }
    Ok(())
}

/// What a member verb did (rolled back on a dry run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberAct {
    /// The live membership row the verb wrote or found (`None` for a remove
    /// of an agent that is not a live member).
    pub membership: Option<Uuid>,
    /// `false` for a no-op: the member already held the role, or (remove) was
    /// not a live member.
    pub applied: bool,
    /// The role the row held before (remove and set-role).
    pub prior_role: Option<String>,
}

/// The transaction-local setting the definers read into each audit row's
/// `actor` (migration 164, `epigraph_team_group_actor`).
pub const ACTOR_SETTING: &str = "epigraph.operator_actor";

/// What this process says about itself in the audit row: the tool, the
/// command, its version, and [`super::client_scope::Operator`]'s identity of
/// the process (the environment's advisory user, the real and login uids from
/// the kernel, and their passwd names). `session_user` is recorded by the
/// definer itself.
#[must_use]
pub fn actor_context(command: &str, session_user: String) -> serde_json::Value {
    let op = super::client_scope::Operator::of_this_process(session_user);
    serde_json::json!({
        "tool": "epigraph-operator",
        "command": command,
        "cli_version": env!("CARGO_PKG_VERSION"),
        "os_user": op.os_user,
        "os_user_source": "environment (SUDO_USER, USER, LOGNAME): advisory, settable by the \
                           caller",
        "process_uid": op.process_uid,
        "process_user": op.process_user,
        "login_uid": op.login_uid,
        "login_user": op.login_user,
    })
}

/// Begin the one transaction a command runs in, with [`ACTOR_SETTING`] set
/// for it (transaction-local, so it ends with the transaction).
pub(crate) async fn begin_audited<'c>(
    conn: &'c mut PgConnection,
    command: &str,
) -> anyhow::Result<sqlx::Transaction<'c, sqlx::Postgres>> {
    let mut tx = sqlx::Connection::begin(conn).await?;
    let session_user: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config($1, $2, true)")
        .bind(ACTOR_SETTING)
        .bind(actor_context(command, session_user).to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

async fn finish(tx: sqlx::Transaction<'_, sqlx::Postgres>, apply: bool) -> anyhow::Result<()> {
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(())
}

/// Create a keyless team group named `name` whose admin is `admin`, in one
/// transaction: committed under `apply`, rolled back otherwise. Returns the
/// group id the definer assigned.
///
/// # Errors
/// The definer refused (GRP01 the admin is not a registered human operator;
/// GRP06 an active team group already has the name; a blank name or reason),
/// or a statement failed.
pub async fn create(
    conn: &mut PgConnection,
    name: &str,
    admin: Uuid,
    reason: &str,
    apply: bool,
) -> anyhow::Result<Uuid> {
    let mut tx = begin_audited(&mut *conn, "create-group").await?;
    let group: Uuid = sqlx::query_scalar("SELECT public.epigraph_create_team_group($1, $2, $3)")
        .bind(name)
        .bind(admin)
        .bind(reason)
        .fetch_one(&mut *tx)
        .await?;
    finish(tx, apply).await?;
    Ok(group)
}

/// Add `agent` to `group` at `role`.
///
/// # Errors
/// The definer refused (GRP05 not an active keyless team group; GRP04 the
/// agent belongs to no live human; GRP03 an operated agent whose operator does
/// not write the group; GRP01 an operated agent as admin; a live member at a
/// different role), or a statement failed.
pub async fn add(
    conn: &mut PgConnection,
    group: Uuid,
    agent: Uuid,
    role: &str,
    reason: &str,
    apply: bool,
) -> anyhow::Result<MemberAct> {
    let mut tx = begin_audited(&mut *conn, "group-member add").await?;
    let (membership, applied): (Option<Uuid>, bool) = sqlx::query_as(
        "SELECT out_membership_id, out_applied \
           FROM public.epigraph_team_group_add_member($1, $2, $3, $4)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .bind(reason)
    .fetch_one(&mut *tx)
    .await?;
    finish(tx, apply).await?;
    Ok(MemberAct {
        membership,
        applied,
        prior_role: None,
    })
}

/// Remove (revoke) `agent` from `group`.
///
/// # Errors
/// The definer refused (GRP05; GRP02 the last live admin; GRP03 the agent's
/// operated agents are still live members), or a statement failed.
pub async fn remove(
    conn: &mut PgConnection,
    group: Uuid,
    agent: Uuid,
    reason: &str,
    apply: bool,
) -> anyhow::Result<MemberAct> {
    let mut tx = begin_audited(&mut *conn, "group-member remove").await?;
    let (membership, applied, prior_role): (Option<Uuid>, bool, Option<String>) = sqlx::query_as(
        "SELECT out_membership_id, out_applied, out_prior_role \
           FROM public.epigraph_team_group_remove_member($1, $2, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(reason)
    .fetch_one(&mut *tx)
    .await?;
    finish(tx, apply).await?;
    Ok(MemberAct {
        membership,
        applied,
        prior_role,
    })
}

/// Set `agent`'s role in `group`.
///
/// # Errors
/// The definer refused (GRP05; not a live member; GRP02 demoting the last live
/// admin; GRP01 / GRP03 / GRP04 on a promotion; GRP03 demoting an operator to
/// reader under its live agents), or a statement failed.
pub async fn set_role(
    conn: &mut PgConnection,
    group: Uuid,
    agent: Uuid,
    role: &str,
    reason: &str,
    apply: bool,
) -> anyhow::Result<MemberAct> {
    let mut tx = begin_audited(&mut *conn, "group-member set-role").await?;
    let (membership, applied, prior_role): (Option<Uuid>, bool, Option<String>) = sqlx::query_as(
        "SELECT out_membership_id, out_applied, out_prior_role \
           FROM public.epigraph_team_group_set_member_role($1, $2, $3, $4)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .bind(reason)
    .fetch_one(&mut *tx)
    .await?;
    finish(tx, apply).await?;
    Ok(MemberAct {
        membership,
        applied,
        prior_role,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_team_is_a_kind() {
        assert!(validate_kind("team").is_ok());
        for bad in ["personal", "community", "world", "seed", "Team", ""] {
            let e = validate_kind(bad).expect_err(bad).to_string();
            assert!(e.contains("--kind team"), "{bad}: {e}");
        }
    }

    #[test]
    fn only_the_three_roles_are_roles() {
        for ok in ROLES {
            assert!(validate_role(ok).is_ok(), "{ok}");
        }
        for bad in ["owner", "manager", "Admin", ""] {
            let e = validate_role(bad).expect_err(bad).to_string();
            assert!(e.contains("reader, writer, admin"), "{bad}: {e}");
        }
    }

    #[test]
    fn the_actor_context_names_the_tool_command_version_and_process() {
        let a = actor_context("group-member add", "maint_login".to_string());
        assert!(a.is_object(), "{a}");
        assert_eq!(a["tool"], "epigraph-operator");
        assert_eq!(a["command"], "group-member add");
        assert_eq!(a["cli_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            a["process_uid"].as_u64(),
            super::super::client_scope::Operator::process_uid().map(u64::from)
        );
    }

    #[test]
    fn blank_text_is_refused() {
        assert!(validate_text("--reason", "why").is_ok());
        assert!(validate_text("--reason", "  \t").is_err());
    }
}
