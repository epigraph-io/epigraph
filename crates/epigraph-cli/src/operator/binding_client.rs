//! `allow-author-binding-client` / `revoke-author-binding-client`: the
//! author-binding allowlist (migration 149, binding arm (c)).
//!
//! An allowance is a statement that THIS OAuth client's AGENT writes on behalf
//! of THIS registered human operator. The binding is keyed on the agent (the
//! session stamp), so any process holding that agent's private key writes as
//! the bound agent too. It never makes the agent OPERATED: no link record is
//! written, so the client keeps its HTTP token and viewer.
//!
//! The registry is written through two maintenance-only, audited definers
//! (`epigraph_allow_author_binding_client`, `epigraph_revoke_author_binding_client`);
//! this module calls them in one transaction, committed under `--apply` and
//! rolled back otherwise (the audit row with it), so a dry run prints exactly
//! what the definer did.
//!
//! * Revoking is FINAL for that client: a revoked client is never re-allowed;
//!   mint a new client instead.
//! * Suspending or revoking the client, revoking the human's registration, or
//!   a second non-revoked client of the same agent unbinds it at once; an
//!   incident response revokes the allowance AND the client (suspending alone
//!   is not a durable unbind: a privileged re-activation re-binds).
//! * The allowance binds a WRITER into its operator's groups. An allowlisted
//!   agent that authors AS ITSELF still declares its own personal group, which
//!   its operator does not write, so those writes are refused OPL02 once the
//!   database is armed. Allowlist a client only when its writes land in groups
//!   the operator writes.
//! * The membership door (`epigraph_require_operator_scope`) reads links only,
//!   so the allowance does not stop the agent's NON-claim writes in groups its
//!   operator does not write. [`allow`] therefore lists the agent's live
//!   writer/admin rows in such groups and, on request, revokes them in the
//!   same transaction.

use anyhow::Context;
use epigraph_db::CLIENT_ALLOWLIST_BINDING;
use sqlx::PgConnection;
use uuid::Uuid;

/// What [`allow`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowOutcome {
    pub client: Uuid,
    pub client_type: String,
    pub client_name: String,
    /// This call added the row (`false`: it already existed, live, for the
    /// same operator).
    pub allowed_now: bool,
    /// The agent the row pinned.
    pub agent: Uuid,
    pub operator: Uuid,
    /// The agent's binding after the call (`epigraph_author_binding`).
    pub effective_binding: Option<String>,
    /// Groups where the agent holds a live writer/admin row its operator does
    /// not write (its own personal group excepted).
    pub foreign_writes: Vec<Uuid>,
    /// Those rows were revoked in this transaction.
    pub foreign_revoked: bool,
}

impl AllowOutcome {
    /// The allowance is in force: the agent reads `client_allowlist`.
    #[must_use]
    pub fn effective(&self) -> bool {
        self.effective_binding.as_deref() == Some(CLIENT_ALLOWLIST_BINDING)
    }
}

/// Allow `client` (`oauth_clients.id`) for the human operator `operator`.
///
/// # Errors
/// The client does not exist, the definer refused (a human, pending,
/// suspended or revoked client, a client that never minted, an agent that is
/// human, linked, an operator of agents, a registered system agent or the
/// agent of another non-revoked client, an operator that is not a live
/// registered human or is itself linked, a revoked allowance, a live one for
/// another operator, a blank reason), or a statement failed.
pub async fn allow(
    conn: &mut PgConnection,
    client: Uuid,
    operator: Uuid,
    reason: &str,
    revoke_foreign_writes: bool,
    apply: bool,
) -> anyhow::Result<AllowOutcome> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let (client_type, client_name): (String, String) = sqlx::query_as(
        "SELECT client_type::text, client_name::text FROM oauth_clients WHERE id = $1",
    )
    .bind(client)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| anyhow::anyhow!("no OAuth client has id {client}; nothing was changed"))?;
    let (allowed_now, agent, row_operator, effective_binding): (bool, Uuid, Uuid, Option<String>) =
        sqlx::query_as(
            "SELECT allowed_now, agent_id, operator_id, effective_binding \
               FROM public.epigraph_allow_author_binding_client($1, $2, $3)",
        )
        .bind(client)
        .bind(operator)
        .bind(reason)
        .fetch_one(&mut *tx)
        .await
        .with_context(|| format!("allowing OAuth client {client} for operator {operator}"))?;
    let foreign_writes = super::bind::foreign_writes(&mut tx, agent, row_operator).await?;
    let foreign_revoked = revoke_foreign_writes && !foreign_writes.is_empty();
    if foreign_revoked {
        sqlx::query(
            "UPDATE group_memberships SET revoked_at = now() \
              WHERE agent_id = $1 AND group_id = ANY($2) AND revoked_at IS NULL \
                AND role IN ('writer', 'admin')",
        )
        .bind(agent)
        .bind(&foreign_writes)
        .execute(&mut *tx)
        .await
        .context("revoking the agent's writer rows in groups its operator does not write")?;
    }
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(AllowOutcome {
        client,
        client_type,
        client_name,
        allowed_now,
        agent,
        operator: row_operator,
        effective_binding,
        foreign_writes,
        foreign_revoked,
    })
}

/// What [`revoke`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// This call revoked the live allowance.
    RevokedNow,
    /// The allowance was already revoked (final): when, and by which session
    /// user.
    AlreadyRevoked {
        revoked_at: String,
        revoked_by: String,
    },
    /// No allowance row names this client: nothing to revoke. Usually a
    /// mistyped id, so the binary exits non-zero.
    NotAllowed,
}

/// Revoke `client`'s allowance. Final for that client. Tells "revoked now"
/// from "already revoked" from "never allowed", read in the same transaction
/// as the revoke.
///
/// # Errors
/// A blank reason, or a statement failed.
pub async fn revoke(
    conn: &mut PgConnection,
    client: Uuid,
    reason: &str,
    apply: bool,
) -> anyhow::Result<RevokeOutcome> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let now: bool = sqlx::query_scalar(
        "SELECT revoked_now FROM public.epigraph_revoke_author_binding_client($1, $2)",
    )
    .bind(client)
    .bind(reason)
    .fetch_one(&mut *tx)
    .await?;
    let outcome = if now {
        RevokeOutcome::RevokedNow
    } else {
        let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT revoked_at::text, revoked_by FROM public.author_binding_clients \
              WHERE client_id = $1",
        )
        .bind(client)
        .fetch_optional(&mut *tx)
        .await
        .context("reading the client's allowance row")?;
        match row {
            None => RevokeOutcome::NotAllowed,
            Some((revoked_at, revoked_by)) => RevokeOutcome::AlreadyRevoked {
                revoked_at: revoked_at.unwrap_or_else(|| "-".to_string()),
                revoked_by: revoked_by.unwrap_or_else(|| "-".to_string()),
            },
        }
    };
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(outcome)
}

/// The operator-facing line for a [`RevokeOutcome`].
#[must_use]
pub fn describe_revoke(client: Uuid, o: &RevokeOutcome, apply: bool) -> String {
    match o {
        RevokeOutcome::RevokedNow => format!(
            "{}REVOKED\tclient={client}",
            if apply { "" } else { "WOULD BE " }
        ),
        RevokeOutcome::AlreadyRevoked {
            revoked_at,
            revoked_by,
        } => format!(
            "ALREADY-REVOKED\tclient={client}\trevoked_at={revoked_at}\trevoked_by={revoked_by}"
        ),
        RevokeOutcome::NotAllowed => format!(
            "NOT-ALLOWED\tclient={client}\tno allowance row names this client, so nothing was \
             revoked; check the id (`oauth_clients.id`, not its `client_id`)"
        ),
    }
}

/// The operator-facing lines for an [`AllowOutcome`].
#[must_use]
pub fn describe(o: &AllowOutcome, apply: bool) -> Vec<String> {
    let verb = if !o.effective() {
        "ALLOWED-BUT-INEFFECTIVE"
    } else if o.allowed_now {
        "ALLOWED"
    } else {
        "ALREADY-ALLOWED"
    };
    let mut out = vec![format!(
        "{}{verb}\tclient={}\ttype={}\tname={}\tagent={}\toperator={}\tbinding={}",
        if apply { "" } else { "WOULD BE " },
        o.client,
        o.client_type,
        o.client_name,
        o.agent,
        o.operator,
        o.effective_binding.as_deref().unwrap_or("-")
    )];
    if !o.effective() {
        out.push(
            "INEFFECTIVE\tthe allowance exists but the agent is not bound by it: the client must \
             be active and its agent's only non-revoked client, and the operator a live \
             registered human (see docs/tenancy.md, \"Arm (c)\")"
                .to_string(),
        );
    }
    let state = match (o.foreign_revoked, apply) {
        (true, true) => "REVOKED",
        (true, false) => "WOULD BE REVOKED",
        (false, _) => "KEPT (pass --revoke-foreign-writes to revoke it)",
    };
    for g in &o.foreign_writes {
        out.push(format!(
            "FOREIGN-WRITE\tagent={}\tgroup={g}\ta writer/admin row in a group its operator \
             does not write: {state}",
            o.agent
        ));
    }
    if o.client_type == "agent" {
        out.push(
            "WARNING\tan agent-type client's agent signs with its own Ed25519 key; that private \
             key must be a real secret. A name-derived identity (a key derived from a public \
             string) is world-signable and must never be allowlisted."
                .to_string(),
        );
    }
    out
}
