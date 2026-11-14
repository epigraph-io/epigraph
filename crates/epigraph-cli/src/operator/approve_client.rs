//! `approve-client`: approve ONE pending OAuth client on the maintenance DSN
//! (backlog f33bb29f item 3).
//!
//! # Why this exists
//!
//! Migration 188 made client approval a maintenance act: the application role
//! may no longer EXECUTE `epigraph_oauth_client_approve`, and
//! `POST /api/v1/admin/clients/:id/approve` answers 501 after its refusals.
//! Until this verb, an operator approved with a hand-written
//! `SELECT epigraph_oauth_client_approve(...)` on a maintenance session.
//!
//! # Which client
//!
//! `--client <uuid>` names the `oauth_clients.id` row (what every other
//! operator verb takes); `--client-id <string>` names the `client_id` string
//! `/oauth/register` returns, and is mapped to the row. Both are printed.
//!
//! # The rules
//!
//! * **Pending clients only.** The definer sets `status = 'active'` and
//!   overwrites `granted_scopes` whatever the row's status, and migration
//!   122's reactivation guard does not stop a maintenance session, so this
//!   verb refuses an `active` (it would rewrite its scopes), `suspended` or
//!   `revoked` (it would resurrect it) client. Reactivation and scope changes
//!   have their own audited paths.
//! * **The route's scope refusals.** `platform:admin` is never granted (the
//!   elevate grant alone mints it). An admin-only scope
//!   (`ADMIN_ONLY_SCOPES`) is refused while migration 128's switch is armed or
//!   cannot be read; unarmed, it is granted with a WARN line, as the route
//!   warned.
//! * **One transaction.** The definer (which writes its own
//!   `oauth.client_approved` row) and this verb's `oauth.client_approved_cli`
//!   row (who ran it, the reason, the scopes and status before and after, and
//!   the `created_by` the definer overwrites with `--approved-by`) commit
//!   together under `--apply` and roll back together otherwise, so a dry run
//!   prints exactly what the apply would do.

use super::client_scope::Operator;
use anyhow::{bail, Context};
use chrono::Utc;
use epigraph_core::canonical_scopes::{ADMIN_ONLY_SCOPES, PLATFORM_ADMIN_SCOPE};
use epigraph_db::{
    AdminScopeEnforcement, AdminScopeSwitch, OAuthClientRepository, SecurityEventRepository,
    SecurityEventRow,
};
use sqlx::{Acquire, PgConnection};
use uuid::Uuid;

/// `security_events.event_type` of this verb's own audit row (the definer
/// writes `oauth.client_approved` beside it).
pub const EVENT: &str = "oauth.client_approved_cli";

/// How the client is named on the command line.
#[derive(Debug, Clone)]
pub enum ClientRef {
    /// `oauth_clients.id`.
    Row(Uuid),
    /// `oauth_clients.client_id`, the string `/oauth/register` returns.
    ClientId(String),
}

/// What a run found and did.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub client_type: String,
    pub granted_scopes: Vec<String>,
    /// The admin-only scopes granted while the switch was unarmed.
    pub admin_scopes_warned: Vec<String>,
    pub audit_event_id: Uuid,
    pub applied: bool,
}

/// Refuse what can be refused before connecting: a blank reason, no scope,
/// `platform:admin`, a blank or duplicate scope. Returns the scopes, in
/// order.
///
/// # Errors
/// Any of those.
pub fn validate(scopes: &[String], reason: &str) -> anyhow::Result<Vec<String>> {
    if reason.trim().is_empty() {
        bail!("--reason must not be blank: it is the audit record of the approval");
    }
    if scopes.is_empty() {
        bail!("approve-client needs at least one --scope: the scopes the client is granted");
    }
    let mut out: Vec<String> = Vec::new();
    for s in scopes {
        let s = s.trim();
        if s.is_empty() {
            bail!("a --scope is blank; nothing was approved");
        }
        if s == PLATFORM_ADMIN_SCOPE {
            bail!(
                "{PLATFORM_ADMIN_SCOPE} is minted only by the elevate grant and is never granted \
                 to a client; nothing was approved"
            );
        }
        if out.iter().any(|x| x == s) {
            bail!("--scope {s} is given twice; nothing was approved");
        }
        out.push(s.to_string());
    }
    Ok(out)
}

/// Approve one pending client.
///
/// # Errors
/// [`validate`]'s refusals; an unknown client; a client that is not
/// `pending`; an admin-only scope while migration 128 is armed or unreadable;
/// a failed statement. Nothing is committed in any of these cases.
pub async fn run(
    conn: &mut PgConnection,
    client: &ClientRef,
    scopes: &[String],
    approved_by: Option<Uuid>,
    reason: &str,
    apply: bool,
    operator: &Operator,
) -> anyhow::Result<Outcome> {
    let scopes = validate(scopes, reason)?;
    let reason = reason.trim();
    let mut tx = conn.begin().await.context("beginning the transaction")?;

    let id = match client {
        ClientRef::Row(id) => *id,
        ClientRef::ClientId(s) => {
            let id: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM oauth_clients WHERE client_id = $1")
                    .bind(s)
                    .fetch_optional(&mut *tx)
                    .await
                    .context("mapping --client-id to its oauth_clients row")?;
            id.ok_or_else(|| {
                anyhow::anyhow!("no OAuth client has client_id {s:?}; nothing was approved")
            })?
        }
    };
    let Some(row) = OAuthClientRepository::lock_by_id_conn(&mut tx, id)
        .await
        .context("reading the client")?
    else {
        bail!("no OAuth client has id {id} (oauth_clients.id); nothing was approved");
    };
    if row.status != "pending" {
        bail!(
            "OAuth client {id} ({:?}, client_id {}) is {}, not pending; approve-client approves \
             a pending client only (on any other status the definer would rewrite an active \
             client's scopes or resurrect a suspended or revoked one); nothing was approved",
            row.client_name,
            row.client_id,
            row.status
        );
    }
    let admin: Vec<String> = scopes
        .iter()
        .filter(|s| ADMIN_ONLY_SCOPES.contains(&s.as_str()))
        .cloned()
        .collect();
    if !admin.is_empty() {
        match AdminScopeEnforcement::read(&mut *tx).await {
            Ok(AdminScopeSwitch::Unarmed | AdminScopeSwitch::Absent) => {}
            Ok(AdminScopeSwitch::Armed) => bail!(
                "admin-only scopes {admin:?} cannot be granted while admin-scope enforcement is \
                 armed (migration 128); admin acts need an elevation. Nothing was approved."
            ),
            Err(e) => bail!(
                "admin-only scopes {admin:?} refused: the admin-scope switch could not be read \
                 ({e}), and an unreadable switch is not \"unarmed\". Nothing was approved."
            ),
        }
    }

    let approved: bool =
        sqlx::query_scalar("SELECT public.epigraph_oauth_client_approve($1, $2, $3)")
            .bind(id)
            .bind(&scopes)
            .bind(approved_by)
            .fetch_one(&mut *tx)
            .await
            .context("epigraph_oauth_client_approve")?;
    if !approved {
        bail!("epigraph_oauth_client_approve found no client {id} under its lock; nothing was approved");
    }

    let (client_addr, application_name) = SecurityEventRepository::connection_origin_conn(&mut tx)
        .await
        .context("reading the connection's origin")?;
    let audit_event_id = Uuid::new_v4();
    let event = SecurityEventRow {
        id: audit_event_id,
        event_type: EVENT.to_string(),
        agent_id: row.agent_id,
        success: Some(true),
        details: serde_json::json!({
            "tool": "epigraph-operator",
            "command": "approve-client",
            "operator": {
                "session_user": operator.session_user,
                "os_user": operator.os_user,
                "os_user_source": "environment (SUDO_USER, USER, LOGNAME): advisory, \
                                   settable by the caller",
                "process_uid": operator.process_uid,
                "process_user": operator.process_user,
                "login_uid": operator.login_uid,
                "login_user": operator.login_user,
                "client_addr": client_addr,
                "application_name": application_name,
            },
            "client": {
                "id": row.id,
                "client_id": row.client_id,
                "client_name": row.client_name,
                "client_type": row.client_type,
                "agent_id": row.agent_id,
            },
            "status": { "before": row.status, "after": "active" },
            "granted_scopes": { "before": row.granted_scopes, "after": scopes },
            "allowed_scopes": row.allowed_scopes,
            "approved_by": approved_by,
            "created_by_before": row.created_by,
            "admin_scopes_granted_unarmed": admin,
            "reason": reason,
        }),
        ip_address: client_addr.clone(),
        user_agent: None,
        correlation_id: None,
        created_at: Utc::now(),
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
        id,
        client_id: row.client_id,
        client_name: row.client_name,
        client_type: row.client_type,
        granted_scopes: scopes,
        admin_scopes_warned: admin,
        audit_event_id,
        applied: apply,
    })
}

/// The lines the binary prints.
#[must_use]
pub fn describe(o: &Outcome) -> Vec<String> {
    let mut out = vec![format!(
        "{}APPROVED\tclient={}\tclient_id={}\ttype={}\tgranted_scopes={}\taudit_row={}{}",
        if o.applied { "" } else { "WOULD BE " },
        o.id,
        o.client_id,
        o.client_type,
        o.granted_scopes.join(","),
        o.audit_event_id,
        if o.applied { "" } else { " (rolled back)" }
    )];
    if !o.admin_scopes_warned.is_empty() {
        out.push(format!(
            "WARN\tadmin-only scopes granted while admin-scope enforcement is unarmed: {}; \
             once armed they are stripped at every mint",
            o.admin_scopes_warned.join(",")
        ));
    }
    if !o.applied {
        out.push("DRY RUN: the approval and its audit rows were rolled back.".to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn platform_admin_blank_duplicate_and_empty_are_refused_before_connecting() {
        assert!(validate(&v(&["claims:read", PLATFORM_ADMIN_SCOPE]), "r").is_err());
        assert!(validate(&v(&["claims:read", " "]), "r").is_err());
        assert!(validate(&v(&["claims:read", "claims:read"]), "r").is_err());
        assert!(validate(&[], "r").is_err());
        assert!(validate(&v(&["claims:read"]), "  ").is_err());
        assert_eq!(
            validate(&v(&[" claims:read", "claims:write"]), "r").unwrap(),
            v(&["claims:read", "claims:write"])
        );
    }
}
