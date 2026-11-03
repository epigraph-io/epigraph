//! `suspend-client` / `revoke-client`: the audited, one-step containment of
//! ONE OAuth client (backlog 0454cbcd).
//!
//! # Why this exists
//!
//! The kernel's only client-status route is the approval
//! (`POST /api/v1/admin/clients/:id/approve`). Suspending or revoking one
//! client (a leaked service secret, a compromised connector) took a
//! hand-written `UPDATE oauth_clients SET status = ...` on an admin DSN: no
//! audit row, and the client's live refresh chains left in place.
//!
//! # What one run does, in ONE transaction
//!
//! * reads the client row `FOR UPDATE` (by `oauth_clients.id`);
//! * moves its status: `suspend-client` takes an `active` or `pending` client
//!   to `suspended`; `revoke-client` takes an `active`, `pending` or
//!   `suspended` client to `revoked`. A client already at the target status is
//!   reported (`ALREADY-SUSPENDED` / `ALREADY-REVOKED`) and nothing is
//!   written: the command is idempotent. A `revoked` client is never
//!   suspended: revoke is final, and migration 122's reactivation guard does
//!   not stop a maintenance session (it holds `epigraph_bypass()`), so this
//!   module refuses it;
//! * revokes EVERY live refresh chain of the client through migration 118's
//!   `epigraph_refresh_token_revoke_client` (reason `client`), so no refresh
//!   token it handed out mints again;
//! * writes one `security_events` row (`oauth.client_suspended` /
//!   `oauth.client_revoked`; the `oauth.` prefix is reserved to privileged
//!   sessions by migration 118) with the operator facts `grant-client-scope`
//!   records, the client, the transition, the chain count and the reason.
//!
//! Without `--apply` the same statements, the audit row included, run and are
//! rolled back, so a dry run prints exactly what the apply would do.
//!
//! # What it does NOT revoke: access tokens already minted
//!
//! The token endpoint refuses a client that is not `active` on every grant
//! (`client_credentials`, `refresh_token`, `authorization_code`), but the
//! bearer check on a request reads only the signature, the expiry and the
//! `jti` revocation denylist, never the client's status, and no `jti` is
//! recorded at mint, so an access token minted before the act stays valid
//! until it expires: at most 1 hour (15 minutes for an `agent` client). Each
//! run prints that window.
//!
//! # A human's recorded client
//!
//! A human operator is registered for ONE client (migration 122); suspending
//! or revoking that client un-registers the human, and every agent
//! live-linked to it stops authoring. The command names such a human
//! (`HUMAN-OPERATOR`) in the dry run and the apply alike.
//!
//! # The HTTP route is not here
//!
//! The backlog item also asks for `POST /api/v1/admin/clients/:id/{suspend,
//! revoke}`. The application role holds no UPDATE on `oauth_clients`, a
//! request unit may not lease a maintenance connection, and an
//! application-granted status definer would let any holder of the
//! application DSN revoke any client, a human's included (final). That needs
//! a ruling; this module is the maintenance-DSN half.

use super::client_scope::Operator;
use anyhow::{bail, Context};
use chrono::Utc;
use epigraph_db::{SecurityEventRepository, SecurityEventRow};
use sqlx::{Acquire, PgConnection};
use uuid::Uuid;

/// The two acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusAct {
    Suspend,
    Revoke,
}

impl StatusAct {
    /// The status the act moves the client to.
    #[must_use]
    pub const fn target(self) -> &'static str {
        match self {
            Self::Suspend => "suspended",
            Self::Revoke => "revoked",
        }
    }

    /// The `security_events.event_type` of one act.
    #[must_use]
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::Suspend => "oauth.client_suspended",
            Self::Revoke => "oauth.client_revoked",
        }
    }

    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::Suspend => "suspend-client",
            Self::Revoke => "revoke-client",
        }
    }

    /// The statuses the act moves FROM (anything else but the target is
    /// refused).
    #[must_use]
    pub const fn from_statuses(self) -> &'static [&'static str] {
        match self {
            Self::Suspend => &["active", "pending"],
            Self::Revoke => &["active", "pending", "suspended"],
        }
    }
}

/// The client as the run found it.
#[derive(Debug, Clone)]
pub struct Client {
    pub id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub client_type: String,
    pub agent_id: Option<Uuid>,
    pub status: String,
}

/// What a run found and did.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub act: StatusAct,
    pub client: Client,
    /// `false`: the client was already at the target status; nothing written.
    pub changed: bool,
    /// Refresh chains revoked by this run.
    pub refresh_chains_revoked: i64,
    /// The human operator whose registration names this client, if any: the
    /// act un-registers that human.
    pub human_operator: Option<Uuid>,
    /// The audit row's id (rolled back with everything else on a dry run).
    pub audit_event_id: Option<Uuid>,
    /// `false` for a dry run: nothing was committed.
    pub applied: bool,
}

/// The access-token window a status change does not close, for `client_type`.
#[must_use]
pub fn access_token_window(client_type: &str) -> &'static str {
    match client_type {
        "human" | "service" => "1 hour",
        _ => "15 minutes",
    }
}

/// Run one act on `client`.
///
/// # Errors
/// A blank reason, an unknown client, a revoked client asked to be suspended
/// (or a status the act does not move from), or a failed statement. Nothing
/// is committed in any of these cases.
pub async fn run(
    conn: &mut PgConnection,
    act: StatusAct,
    client: Uuid,
    reason: &str,
    apply: bool,
    operator: &Operator,
) -> anyhow::Result<Outcome> {
    let reason = reason.trim();
    if reason.is_empty() {
        bail!("--reason must not be blank: it is the audit record of why the client was contained");
    }
    let mut tx = conn.begin().await.context("beginning the transaction")?;

    let row: Option<(String, String, String, Option<Uuid>, String)> = sqlx::query_as(
        "SELECT c.client_id::text, c.client_name::text, c.client_type::text, c.agent_id, \
                c.status::text \
           FROM oauth_clients c WHERE c.id = $1 FOR UPDATE",
    )
    .bind(client)
    .fetch_optional(&mut *tx)
    .await
    .context("reading the client")?;
    let Some((client_id, client_name, client_type, agent_id, status)) = row else {
        bail!("no OAuth client has id {client} (oauth_clients.id); nothing was changed");
    };
    let found = Client {
        id: client,
        client_id,
        client_name,
        client_type,
        agent_id,
        status: status.clone(),
    };
    let human_operator: Option<Uuid> = sqlx::query_scalar(
        "SELECT h.agent_id FROM human_operators h \
          WHERE h.client_id = $1 AND h.revoked_at IS NULL",
    )
    .bind(client)
    .fetch_optional(&mut *tx)
    .await
    .context("reading the human-operator registry")?;

    if status == act.target() {
        tx.rollback().await?;
        return Ok(Outcome {
            act,
            client: found,
            changed: false,
            refresh_chains_revoked: 0,
            human_operator,
            audit_event_id: None,
            applied: apply,
        });
    }
    if !act.from_statuses().contains(&status.as_str()) {
        tx.rollback().await?;
        bail!(
            "OAuth client {client} is {status}; {} moves a client only from {} (a revoked \
             client is final); nothing was changed",
            act.command(),
            act.from_statuses().join(" or ")
        );
    }

    let n = sqlx::query(
        "UPDATE oauth_clients SET status = $2, updated_at = now() \
          WHERE id = $1 AND status = $3",
    )
    .bind(client)
    .bind(act.target())
    .bind(&status)
    .execute(&mut *tx)
    .await
    .with_context(|| format!("setting client {client} to {}", act.target()))?
    .rows_affected();
    if n != 1 {
        bail!("client {client} changed under its row lock (updated {n} rows); nothing was written");
    }
    let chains: i64 = sqlx::query_scalar("SELECT public.epigraph_refresh_token_revoke_client($1)")
        .bind(client)
        .fetch_one(&mut *tx)
        .await
        .context("revoking the client's refresh chains")?;

    let (client_addr, application_name) = SecurityEventRepository::connection_origin_conn(&mut tx)
        .await
        .context("reading the connection's origin")?;
    let audit_event_id = Uuid::new_v4();
    let event = SecurityEventRow {
        id: audit_event_id,
        event_type: act.event_type().to_string(),
        agent_id: found.agent_id,
        success: Some(true),
        details: serde_json::json!({
            "tool": "epigraph-operator",
            "command": act.command(),
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
                "id": found.id,
                "client_id": found.client_id,
                "client_name": found.client_name,
                "client_type": found.client_type,
                "agent_id": found.agent_id,
            },
            "status": { "before": status, "after": act.target() },
            "refresh_chains_revoked": chains,
            "human_operator_unregistered": human_operator,
            "access_tokens_not_revoked": format!(
                "already-minted access tokens stay valid until they expire (at most {}); no \
                 jti is recorded at mint",
                access_token_window(&found.client_type)
            ),
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
        act,
        client: found,
        changed: true,
        refresh_chains_revoked: chains,
        human_operator,
        audit_event_id: Some(audit_event_id),
        applied: apply,
    })
}

/// The lines the binary prints.
#[must_use]
pub fn describe(o: &Outcome) -> Vec<String> {
    let c = &o.client;
    let target = o.act.target().to_uppercase();
    let mut out = Vec::new();
    if o.changed {
        out.push(format!(
            "{}{target}\tclient={}\tclient_id={}\ttype={}\tstatus_before={}\t\
             refresh_chains_revoked={}\taudit_row={}{}",
            if o.applied { "" } else { "WOULD BE " },
            c.id,
            c.client_id,
            c.client_type,
            c.status,
            o.refresh_chains_revoked,
            o.audit_event_id
                .map_or_else(|| "-".to_string(), |u| u.to_string()),
            if o.applied { "" } else { " (rolled back)" }
        ));
        out.push(format!(
            "NOTE\taccess tokens already minted stay valid until they expire (at most {} for a \
             {} client): the bearer check does not read the client's status and no jti is \
             recorded at mint",
            access_token_window(&c.client_type),
            c.client_type
        ));
    } else {
        out.push(format!(
            "ALREADY-{target}\tclient={}\tclient_id={}\tnothing was written",
            c.id, c.client_id
        ));
    }
    if let Some(h) = o.human_operator {
        out.push(format!(
            "HUMAN-OPERATOR\t{h}\tthis is the client the human's registration names: a \
             non-active client un-registers that human, and every agent live-linked to it stops \
             authoring"
        ));
    }
    if !o.applied && o.changed {
        out.push("DRY RUN: the change and its audit row were rolled back.".to_string());
    }
    out
}
