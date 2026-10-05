//! `grant-client-scope` / `revoke-client-scope`: an operator grants or revokes
//! ONE admin-only scope on a HUMAN's own OAuth client, audited (batch OA1).
//!
//! # Why this exists
//!
//! No registration path hands a human client an admin-only scope
//! (`epigraph_core::canonical_scopes::ADMIN_ONLY_SCOPES`): `/oauth/register`
//! grants read scopes, the agent arm grants nothing, and only the
//! `epigraph-admin` service client carries the admin set. When an operator
//! decides that a particular human should hold, say, `claims:admin`, the only
//! ways to express that were a raw superuser `UPDATE oauth_clients` or
//! `POST /api/v1/admin/clients/:id/approve`, which writes `granted_scopes`
//! verbatim. Neither validates the scope, neither checks what kind of client it
//! is, and neither leaves an audit row. This command replaces the raw path.
//!
//! A human's agents act through that human's OAuth client, so they carry
//! exactly that human's scopes: the refresh grant re-reads
//! `oauth_clients.granted_scopes` on every refresh. A grant here therefore
//! reaches the human's agents at their next token refresh, and a revocation
//! leaves an already-minted access token valid until it expires.
//!
//! # The rules
//!
//! * **Maintenance DSN only.** It runs on [`super::connect`], which reads
//!   `EPIGRAPH_OPERATOR_MAINTENANCE_DSN` alone (never `DATABASE_URL` or
//!   `MAINTENANCE_DATABASE_URL`) and refuses a login that is not a member of
//!   `epigraph_maintenance`.
//! * **Admin-only scopes only.** The scope must be in `ADMIN_ONLY_SCOPES` (the
//!   constant itself, not a copy). Ordinary scopes are the registration and
//!   approval paths' business; this command exists for the scopes those paths
//!   never grant. Checked before any connection is used.
//! * **Human clients only.** A `service` client's scopes are managed by
//!   `bootstrap_clients` (the canonical names ARE their scope definition) and
//!   an `agent` client's by the approval route; both are refused.
//! * **Active clients only, for a grant.** A `revoked`, `suspended` or
//!   `pending` human client is refused a grant: it would carry the scope the
//!   moment it was reactivated or approved, and any party can DCR-register a
//!   `pending` human client, so a mistyped id could otherwise land on a
//!   look-alike. A revoke is allowed on any status (taking authority away is
//!   always safe). The dry run prints the status.
//! * **Both arrays, one scope.** The scope is added to (or removed from)
//!   `allowed_scopes` AND `granted_scopes`, so the two never disagree about it.
//!   Every other element of each array is kept, in its original order: the two
//!   arrays may legitimately differ in other scopes, and this command does not
//!   touch them.
//! * **Idempotent.** Granting a scope the client already holds in both arrays,
//!   or revoking one it holds in neither, changes nothing.
//! * **Audited.** Every `--apply` writes exactly one `security_events` row
//!   (`oauth.client_scope_granted` / `oauth.client_scope_revoked`) in the same
//!   transaction as the change: who ran it, the client, the scope, and both
//!   arrays before and after, with
//!   `changed` saying whether anything moved. A no-op `--apply` is recorded too
//!   (`changed: false`): it is how an operator ratifies a grant that was made
//!   some other way.
//!
//!   "Who ran it" is several facts, none of which is an identity on its own:
//!   the database login (`session_user`; a shared maintenance login names no
//!   person), the process's REAL uid and its passwd name (the first field of
//!   the kernel's `Uid:` line in `/proc/self/status`, not the environment),
//!   the process's audit login uid (`/proc/self/loginuid`: set at login, kept
//!   across `sudo`, and not settable by an unprivileged process; `None` where
//!   the kernel has none, as in many containers), the connection's client
//!   address and `application_name`, and `os_user`, which is `SUDO_USER` /
//!   `USER` / `LOGNAME` and therefore ADVISORY: anyone can set it. The row
//!   records `os_user_source` to say so. Run the binary directly as the
//!   operator: under `sudo -u <service account>` the real uid names that
//!   account, and only the login uid still names the person.
//! * **Not while admin scopes are armed.** Once migration 128's switch is
//!   armed (`arm-admin-scopes`), a grant is refused, dry run included: a
//!   standing admin scope would be stripped at every mint, and an admin act
//!   needs an elevation. A revoke still runs. A switch that cannot be read
//!   refuses the grant too; a database without 128 is unarmed.
//! * **`--dry-run`** runs the same statements, the audit row included, in a
//!   transaction that is rolled back, and prints what would change.
//!
//! The row is read `FOR UPDATE`, so the change is computed from the state it
//! replaces.

use anyhow::{bail, Context};
use epigraph_core::canonical_scopes::ADMIN_ONLY_SCOPES;
use epigraph_db::{
    AdminScopeEnforcement, AdminScopeSwitch, OAuthClientRepository, SecurityEventRepository,
    SecurityEventRow,
};
use sqlx::{Acquire, PgConnection};
use uuid::Uuid;

/// Grant or revoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeOp {
    Grant,
    Revoke,
}

impl ScopeOp {
    /// The `security_events.event_type` this operation writes.
    #[must_use]
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::Grant => "oauth.client_scope_granted",
            Self::Revoke => "oauth.client_scope_revoked",
        }
    }

    /// The subcommand's name, for output.
    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::Grant => "grant-client-scope",
            Self::Revoke => "revoke-client-scope",
        }
    }
}

/// Who ran the command, as recorded in the audit row.
#[derive(Debug, Clone)]
pub struct Operator {
    /// `session_user` of the maintenance connection.
    pub session_user: String,
    /// The OS user the ENVIRONMENT names (`SUDO_USER`, else `USER`, else
    /// `LOGNAME`). Advisory: any caller can set these variables.
    pub os_user: Option<String>,
    /// The process's REAL uid, from the kernel (the first field of the `Uid:`
    /// line in `/proc/self/status`). Not the owner of `/proc/self`, which is
    /// the EFFECTIVE uid, and root for a non-dumpable process.
    pub process_uid: Option<u32>,
    /// `process_uid`'s name in `/etc/passwd`, if it has one.
    pub process_user: Option<String>,
    /// The audit login uid (`/proc/self/loginuid`): the uid of the login
    /// session this process descends from. `sudo` does not change it and an
    /// unprivileged process cannot set it. `None` when the kernel reports it
    /// unset (`4294967295`) or the file is missing.
    pub login_uid: Option<u32>,
    /// `login_uid`'s name in `/etc/passwd`, if it has one.
    pub login_user: Option<String>,
}

impl Operator {
    /// The operator of THIS process: `session_user` as the maintenance
    /// connection reported it, the environment's (advisory) user name, the
    /// process's real uid, its audit login uid, and their passwd names.
    #[must_use]
    pub fn of_this_process(session_user: String) -> Self {
        let process_uid = Self::process_uid();
        let login_uid = Self::login_uid();
        Self {
            session_user,
            os_user: Self::os_user_from_env(),
            process_uid,
            process_user: process_uid.and_then(Self::passwd_name),
            login_uid,
            login_user: login_uid.and_then(Self::passwd_name),
        }
    }

    /// The REAL uid of this process, from the kernel's `/proc/self/status`,
    /// which no environment variable can change. `None` off Linux.
    #[must_use]
    pub fn process_uid() -> Option<u32> {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .as_deref()
            .and_then(Self::real_uid_from_status)
    }

    /// The real uid in a `/proc/<pid>/status` text: the FIRST of the four
    /// fields on its `Uid:` line (real, effective, saved set, filesystem).
    #[must_use]
    pub fn real_uid_from_status(status: &str) -> Option<u32> {
        status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|f| f.parse().ok())
    }

    /// The audit login uid of this process (`/proc/self/loginuid`), or `None`
    /// when unset or unavailable.
    #[must_use]
    pub fn login_uid() -> Option<u32> {
        std::fs::read_to_string("/proc/self/loginuid")
            .ok()
            .as_deref()
            .and_then(Self::login_uid_from_proc)
    }

    /// Parse a `/proc/<pid>/loginuid` text: `4294967295` (`(uid_t)-1`) means
    /// the kernel never set one, which is `None`, as is anything unparsable.
    #[must_use]
    pub fn login_uid_from_proc(text: &str) -> Option<u32> {
        text.trim().parse().ok().filter(|&u: &u32| u != u32::MAX)
    }

    /// `uid`'s login name from `/etc/passwd`, or `None` when it has no entry
    /// there (a container uid, an NSS-only account).
    #[must_use]
    pub fn passwd_name(uid: u32) -> Option<String> {
        let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
        passwd.lines().find_map(|line| {
            let mut f = line.split(':');
            let name = f.next()?;
            let _password = f.next()?;
            let id: u32 = f.next()?.parse().ok()?;
            (id == uid).then(|| name.to_string())
        })
    }

    /// The OS user from the environment: `SUDO_USER` first, so a `sudo -u`
    /// run records the person rather than the service account.
    #[must_use]
    pub fn os_user_from_env() -> Option<String> {
        ["SUDO_USER", "USER", "LOGNAME"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
    }
}

/// What a run found and did.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub op: ScopeOp,
    pub client: Uuid,
    pub client_name: String,
    /// `oauth_clients.status` as read (a grant is refused unless `active`).
    pub client_status: String,
    pub scope: String,
    pub allowed_before: Vec<String>,
    pub granted_before: Vec<String>,
    pub allowed_after: Vec<String>,
    pub granted_after: Vec<String>,
    /// Whether either array changed.
    pub changed: bool,
    /// The audit row's id (rolled back with everything else on a dry run).
    pub audit_event_id: Uuid,
    /// `false` for a dry run: nothing was committed.
    pub applied: bool,
}

/// Refuse any scope that is not admin-only.
///
/// # Errors
/// `scope` is not in `ADMIN_ONLY_SCOPES`.
pub fn validate_scope(scope: &str) -> anyhow::Result<()> {
    if ADMIN_ONLY_SCOPES.contains(&scope) {
        return Ok(());
    }
    bail!(
        "refusing scope {scope:?}: this command grants and revokes only admin-only scopes \
         ({}). Ordinary scopes are managed by client registration and approval.",
        ADMIN_ONLY_SCOPES.join(", ")
    )
}

/// `scopes` with `scope` added (at the end, if absent) or removed (every
/// occurrence), every other element kept in order.
#[must_use]
pub fn with_scope(scopes: &[String], scope: &str, op: ScopeOp) -> Vec<String> {
    match op {
        ScopeOp::Grant => {
            let mut out = scopes.to_vec();
            if !out.iter().any(|s| s == scope) {
                out.push(scope.to_string());
            }
            out
        }
        ScopeOp::Revoke => scopes.iter().filter(|s| *s != scope).cloned().collect(),
    }
}

/// Grant or revoke `scope` on the human client `client`.
///
/// Everything happens in one transaction on `conn`: the locked read, the
/// refusals, the UPDATE (only when something changes) and the audit row. It
/// commits when `apply` is true and is rolled back otherwise.
///
/// # Errors
/// The scope is not admin-only; no client has that id; the client is not a
/// human client; a grant targets a client whose status is not `active`; or a
/// statement fails (nothing is committed).
pub async fn run(
    conn: &mut PgConnection,
    op: ScopeOp,
    client: Uuid,
    scope: &str,
    apply: bool,
    reason: Option<&str>,
    operator: &Operator,
) -> anyhow::Result<Outcome> {
    validate_scope(scope)?;

    let mut tx = conn.begin().await.context("beginning the transaction")?;
    let Some(row) = OAuthClientRepository::lock_by_id_conn(&mut tx, client)
        .await
        .context("reading the client")?
    else {
        bail!("no OAuth client has id {client} (oauth_clients.id); nothing was written");
    };
    if row.client_type != "human" {
        bail!(
            "refusing client {client} ({:?}): it is a {} client. This command changes only a \
             HUMAN's own client; a service client's scopes are set by bootstrap_clients and an \
             agent client's by the approval route. Nothing was written.",
            row.client_name,
            row.client_type
        );
    }
    // Migration 128's admin-scope switch (elevation plan EL-9). Armed, a
    // standing admin scope is what elevation replaces: a grant is refused
    // (dry run included), a revoke is not (taking authority away is always
    // safe). A switch that cannot be read is not "unarmed": refused too. A
    // database without 128 (`Absent`) cannot have been armed.
    if op == ScopeOp::Grant {
        match AdminScopeEnforcement::read(&mut *tx).await {
            Ok(AdminScopeSwitch::Unarmed | AdminScopeSwitch::Absent) => {}
            Ok(AdminScopeSwitch::Armed) => bail!(
                "refusing to grant {scope} to client {client}: admin-scope enforcement is armed \
                 on this database (migration 128), so a standing admin scope would be stripped \
                 at every mint; an admin act needs an elevation. Disarm first \
                 (epigraph-operator disarm-admin-scopes) only if that is the decision. Nothing \
                 was written."
            ),
            Err(e) => bail!(
                "refusing to grant {scope} to client {client}: the admin-scope switch could not \
                 be read ({e}), and an unreadable switch is not \"unarmed\". Nothing was written."
            ),
        }
    }
    if op == ScopeOp::Grant && row.status != "active" {
        bail!(
            "refusing to grant {scope} to client {client} ({:?}): its status is {:?}, not \
             \"active\". A revoked, suspended or pending client would carry the scope the \
             moment it was reactivated or approved. Approve or reactivate it first, through \
             its own audited path, then grant. Nothing was written.",
            row.client_name,
            row.status
        );
    }
    let (client_addr, application_name) = SecurityEventRepository::connection_origin_conn(&mut tx)
        .await
        .context("reading the connection's origin")?;

    let allowed_after = with_scope(&row.allowed_scopes, scope, op);
    let granted_after = with_scope(&row.granted_scopes, scope, op);
    let changed = allowed_after != row.allowed_scopes || granted_after != row.granted_scopes;
    if changed {
        OAuthClientRepository::set_scopes_conn(&mut tx, client, &allowed_after, &granted_after)
            .await
            .context("writing the client's scopes")?;
    }

    let audit_event_id = Uuid::new_v4();
    let event = SecurityEventRow {
        id: audit_event_id,
        event_type: op.event_type().to_string(),
        // The principal whose authority changed, so the human can read their
        // own audit trail (`security_events_read` is keyed on the principal).
        agent_id: row.agent_id,
        success: Some(true),
        details: serde_json::json!({
            "tool": "epigraph-operator",
            "command": op.command(),
            "operator": {
                "session_user": operator.session_user,
                "os_user": operator.os_user,
                "os_user_source": "environment (SUDO_USER, USER, LOGNAME): advisory, settable \
                                   by the caller",
                "process_uid": operator.process_uid,
                "process_user": operator.process_user,
                "login_uid": operator.login_uid,
                "login_user": operator.login_user,
                "client_addr": client_addr,
                "application_name": application_name,
            },
            "client": {
                "id": client,
                "client_id": row.client_id,
                "client_name": row.client_name,
                "client_type": row.client_type,
                "status": row.status,
                "agent_id": row.agent_id,
                "owner_id": row.owner_id,
            },
            "scope": scope,
            "changed": changed,
            "before": {
                "allowed_scopes": row.allowed_scopes,
                "granted_scopes": row.granted_scopes,
            },
            "after": {
                "allowed_scopes": allowed_after,
                "granted_scopes": granted_after,
            },
            "reason": reason,
        }),
        ip_address: client_addr,
        user_agent: None,
        correlation_id: None,
        created_at: chrono::Utc::now(),
    };
    SecurityEventRepository::log_conn(&mut tx, &event)
        .await
        .context("writing the audit row")?;

    if apply {
        tx.commit().await.context("committing")?;
    } else {
        tx.rollback().await.context("rolling back the dry run")?;
    }

    Ok(Outcome {
        op,
        client,
        client_name: row.client_name,
        client_status: row.status,
        scope: scope.to_string(),
        allowed_before: row.allowed_scopes,
        granted_before: row.granted_scopes,
        allowed_after,
        granted_after,
        changed,
        audit_event_id,
        applied: apply,
    })
}

/// The lines the binary prints for an outcome.
#[must_use]
pub fn describe(o: &Outcome) -> String {
    let mode = if o.applied { "APPLIED" } else { "DRY RUN" };
    let what = match (o.op, o.changed) {
        (ScopeOp::Grant, true) => "granted",
        (ScopeOp::Revoke, true) => "revoked",
        (ScopeOp::Grant, false) => "unchanged (already held in allowed_scopes and granted_scopes)",
        (ScopeOp::Revoke, false) => "unchanged (held in neither allowed_scopes nor granted_scopes)",
    };
    let audit = if o.applied {
        format!("audit row {} ({})", o.audit_event_id, o.op.event_type())
    } else {
        format!(
            "audit row {} ({}) would be written; rolled back",
            o.audit_event_id,
            o.op.event_type()
        )
    };
    format!(
        "{mode}: {} {} on client {} ({:?}, status {}): {what}\n  allowed_scopes: {:?} -> \
         {:?}\n  granted_scopes: {:?} -> {:?}\n  {audit}",
        o.op.command(),
        o.scope,
        o.client,
        o.client_name,
        o.client_status,
        o.allowed_before,
        o.allowed_after,
        o.granted_before,
        o.granted_after,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn only_admin_only_scopes_are_accepted() {
        for s in ADMIN_ONLY_SCOPES {
            assert!(validate_scope(s).is_ok(), "{s}");
        }
        for s in [
            "claims:write",
            "claims:read",
            "edges:write",
            "claims:admin ",
            "",
        ] {
            assert!(validate_scope(s).is_err(), "{s:?} must be refused");
        }
    }

    /// The `Uid:` line lists real, effective, saved and filesystem uids. A
    /// line where they differ (a setuid run) must yield the REAL one.
    #[test]
    fn the_real_uid_is_the_first_field_of_the_uid_line() {
        let status = "Name:\tepigraph-operator\nUmask:\t0002\nState:\tR (running)\n\
                      Tgid:\t4242\nPid:\t4242\nPPid:\t4200\n\
                      Uid:\t1001\t0\t0\t0\nGid:\t1001\t1001\t1001\t1001\n";
        assert_eq!(Operator::real_uid_from_status(status), Some(1001));
        assert_eq!(Operator::real_uid_from_status("Name:\tx\n"), None);
        assert_eq!(Operator::real_uid_from_status("Uid:\tabc\t0\n"), None);
    }

    #[test]
    fn an_unset_login_uid_is_none() {
        assert_eq!(Operator::login_uid_from_proc("1001"), Some(1001));
        assert_eq!(Operator::login_uid_from_proc("1001\n"), Some(1001));
        assert_eq!(Operator::login_uid_from_proc("0"), Some(0));
        assert_eq!(Operator::login_uid_from_proc("4294967295"), None);
        assert_eq!(Operator::login_uid_from_proc(""), None);
    }

    #[test]
    fn grant_appends_once_and_keeps_the_rest_in_order() {
        let before = v(&["b", "a", "c"]);
        assert_eq!(
            with_scope(&before, "claims:admin", ScopeOp::Grant),
            v(&["b", "a", "c", "claims:admin"])
        );
        let held = v(&["claims:admin", "a"]);
        assert_eq!(with_scope(&held, "claims:admin", ScopeOp::Grant), held);
    }

    #[test]
    fn revoke_removes_every_occurrence_and_only_it() {
        let before = v(&["a", "claims:admin", "b", "claims:admin"]);
        assert_eq!(
            with_scope(&before, "claims:admin", ScopeOp::Revoke),
            v(&["a", "b"])
        );
        let absent = v(&["a", "b"]);
        assert_eq!(with_scope(&absent, "claims:admin", ScopeOp::Revoke), absent);
    }
}
