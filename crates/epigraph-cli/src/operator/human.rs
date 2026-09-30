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

/// Register `agent` as a human operator. Returns whether this call registered it
/// (`false`: it already was).
///
/// # Errors
/// The definer refused (no active human client, a revoked registration, a
/// missing reason), or a statement failed.
pub async fn register(
    conn: &mut PgConnection,
    agent: Uuid,
    reason: &str,
    apply: bool,
) -> anyhow::Result<bool> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let now: bool = sqlx::query_scalar(
        "SELECT registered_now FROM public.epigraph_register_human_operator($1, $2)",
    )
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
