//! `register-human-operator` / `revoke-human-operator`: the human-operator
//! registry (migration 122 section 1c).
//!
//! Who counts as a human is not inferred: an agent is a human operator only
//! with a live row in `human_operators` AND an active `human` OAuth client. The
//! registry is written through two maintenance-only, audited definers
//! (`epigraph_register_human_operator`, which refuses an agent with no active
//! human client, and `epigraph_revoke_human_operator`); this module calls them
//! in one transaction, committed under `--apply` and rolled back otherwise (the
//! audit row with it), so a dry run prints exactly what the definer did.
//!
//! Registering is a statement about a PERSON: run it for a human's own
//! principal only, never for a service or an agent. Revoking is final for that
//! row: every agent live-linked to the human stops authoring at once (OPL01).

use sqlx::PgConnection;
use uuid::Uuid;

/// Register `agent` as a human operator for the ONE OAuth client `client`
/// (`oauth_clients.id`). Returns whether this call registered it (`false`: it
/// already was, for that same client).
///
/// The client is NAMED, never inferred: the human test keys on the recorded
/// client, and the application role may insert `oauth_clients` rows (dynamic
/// client registration), so "the agent's one active human client" could be a
/// row an application session planted, or be ambiguous (the definer then
/// refuses). An agent already registered for a DIFFERENT client is refused
/// here, with nothing changed.
///
/// # Errors
/// The definer refused (`client` is not an active human client of `agent`, a
/// revoked registration, a missing reason), the agent is registered for
/// another client, or a statement failed.
pub async fn register(
    conn: &mut PgConnection,
    agent: Uuid,
    client: Uuid,
    reason: &str,
    apply: bool,
) -> anyhow::Result<bool> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let now: bool = sqlx::query_scalar(
        "SELECT registered_now FROM public.epigraph_register_human_operator($1, $2, $3)",
    )
    .bind(agent)
    .bind(reason)
    .bind(client)
    .fetch_one(&mut *tx)
    .await?;
    let recorded: Uuid =
        sqlx::query_scalar("SELECT client_id FROM public.human_operators WHERE agent_id = $1")
            .bind(agent)
            .fetch_one(&mut *tx)
            .await?;
    if recorded != client {
        tx.rollback().await?;
        anyhow::bail!(
            "{agent} is already registered as a human operator for OAuth client {recorded}, not \
             {client}; nothing was changed (a registration names one client for life; revoke it \
             to register the human again)"
        );
    }
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(now)
}

/// Revoke `agent`'s registration. Returns whether this call revoked it
/// (`false`: there was no live registration).
///
/// # Errors
/// A missing reason, or a statement failed.
pub async fn revoke(
    conn: &mut PgConnection,
    agent: Uuid,
    reason: &str,
    apply: bool,
) -> anyhow::Result<bool> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let now: bool =
        sqlx::query_scalar("SELECT revoked_now FROM public.epigraph_revoke_human_operator($1, $2)")
            .bind(agent)
            .bind(reason)
            .fetch_one(&mut *tx)
            .await?;
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(now)
}
