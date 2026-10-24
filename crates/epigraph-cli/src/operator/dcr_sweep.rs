//! `sweep-dcr-clients` / `list-dcr-clients`: retire the dynamic-registration
//! (RFC 7591) clients that were registered and never used (backlog d3cdd376).
//!
//! # Why this exists
//!
//! `/oauth/register` without a `client_type` (DCR, what an MCP connector sends)
//! mints a fresh random `epigraph_<hex>` public client on EVERY call, `active`
//! from the start. A connector registers again on each reconnect, and its
//! tokens are minted on the user's own per-user client, never on the DCR row,
//! so each reconnect leaves another active, agent-less public client id that
//! `/oauth/authorize` accepts. Deduplicating at registration would key on the
//! `client_name`, which the caller chooses, so it is not done; this sweep
//! retires the rows that were never used instead.
//!
//! # Which rows: all of these
//!
//! * the DCR shape: `client_type = 'human'`, `status = 'active'`, no
//!   `client_secret_hash` (a public client), `agent_id IS NULL` (no principal),
//!   a `client_id` that starts with `epigraph_` (register.rs's form; a
//!   provisioned per-user client is `<provider>:<subject>` and is never
//!   touched), and at least one registered `redirect_uri` (the per-user client
//!   has none);
//! * registered more than `--older-than-hours` ago (default 24; at least 1),
//!   so a connector in the middle of its first authorization is never cut off;
//! * and NO authorization code was ever minted for it. A code row records the
//!   DCR `client_id` the flow ran under (`consent_endpoint`) and is kept after
//!   redemption (`used_at`), so "no code row" means "never completed an
//!   authorization". A client that ever did is kept, whatever its age.
//!
//! Such a row is set to `revoked`. Taking a client to `revoked` is open to
//! every path under migration 122's reactivation guard, and the maintenance
//! role holds UPDATE on `oauth_clients` (migration 070); nothing is deleted.
//! Re-activating one is a maintenance act, as for any revoked client.
//!
//! # The rules
//!
//! * **Maintenance DSN only**, through [`super::connect`].
//! * **Dry run by default.** Without `--apply` the same statements, audit rows
//!   included, run in a transaction that is rolled back.
//! * **One transaction.** The candidates are read `FOR UPDATE` with the
//!   predicate above. The lock serializes the sweep against other sweeps and
//!   against status writers on the same rows; it does NOT serialize it against
//!   a code being minted. `consent_endpoint` names the DCR client only by its
//!   text `client_id` on the code row (no foreign key to `oauth_clients`,
//!   migration 049) and never reads or locks the DCR row, so a code inserted
//!   while the sweep runs neither waits nor shows up in the `NOT EXISTS`
//!   snapshot. That race is harmless: the client is already older than the
//!   floor, and the code is redeemed against the PER-USER client
//!   (`handle_authorization_code` gates on `oauth_client_id`'s status), not the
//!   DCR row, so an in-flight flow still completes.
//! * **Audited.** Every swept client gets one `security_events` row
//!   (`oauth.dcr_client_swept`) in the same transaction: who ran it (the same
//!   facts as `grant-client-scope`), the client, the age floor and the reason.
//! * `list-dcr-clients` is read-only: every DCR-shaped client of any status,
//!   its code count and last code time, and whether a sweep would take it.

use super::client_scope::Operator;
use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use epigraph_db::{SecurityEventRepository, SecurityEventRow};
use sqlx::{Acquire, PgConnection};
use uuid::Uuid;

/// The `security_events.event_type` of one swept client.
pub const EVENT_TYPE: &str = "oauth.dcr_client_swept";

/// The smallest age floor accepted, in hours.
pub const MIN_AGE_HOURS: u32 = 1;

/// The DCR shape, whatever the status. Shared by the sweep and the listing so
/// the two cannot disagree about which rows are DCR clients.
const DCR_SHAPE: &str = "c.client_type = 'human' \
     AND c.client_secret_hash IS NULL \
     AND c.agent_id IS NULL \
     AND left(c.client_id, 9) = 'epigraph_' \
     AND cardinality(c.redirect_uris) > 0";

/// A client the sweep takes (or would take).
#[derive(Debug, Clone)]
pub struct Swept {
    pub id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub created_at: DateTime<Utc>,
    /// The audit row's id (rolled back with everything else on a dry run).
    pub audit_event_id: Uuid,
}

/// What a sweep found and did.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub swept: Vec<Swept>,
    pub older_than_hours: u32,
    /// `false` for a dry run: nothing was committed.
    pub applied: bool,
}

/// One DCR-shaped client, as `list-dcr-clients` prints it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CensusRow {
    pub id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub codes: i64,
    pub last_code_at: Option<DateTime<Utc>>,
    /// Whether `sweep-dcr-clients` with the same floor would revoke it.
    pub sweepable: bool,
}

/// Refuse an age floor below [`MIN_AGE_HOURS`].
///
/// # Errors
/// `hours` is below the floor.
pub fn validate_age(hours: u32) -> anyhow::Result<()> {
    if hours < MIN_AGE_HOURS {
        bail!(
            "--older-than-hours must be at least {MIN_AGE_HOURS}: a younger DCR client may be \
             in the middle of its first authorization"
        );
    }
    Ok(())
}

/// Revoke every unused DCR client older than `older_than_hours`, with one audit
/// row each, in one transaction that commits only when `apply` is true.
///
/// # Errors
/// The age floor is below [`MIN_AGE_HOURS`], or a statement fails (nothing is
/// committed).
pub async fn run(
    conn: &mut PgConnection,
    older_than_hours: u32,
    apply: bool,
    reason: Option<&str>,
    operator: &Operator,
) -> anyhow::Result<Outcome> {
    validate_age(older_than_hours)?;
    let mut tx = conn.begin().await.context("beginning the transaction")?;

    let candidates: Vec<(Uuid, String, String, DateTime<Utc>)> = sqlx::query_as(&format!(
        "SELECT c.id, c.client_id::text, c.client_name::text, c.created_at \
           FROM oauth_clients c \
          WHERE {DCR_SHAPE} \
            AND c.status = 'active' \
            AND c.created_at < now() - make_interval(hours => $1) \
            AND NOT EXISTS (SELECT 1 FROM oauth_authorization_codes a \
                             WHERE a.client_id = c.client_id) \
          ORDER BY c.created_at, c.id \
          FOR UPDATE OF c"
    ))
    .bind(i32::try_from(older_than_hours).context("--older-than-hours is too large")?)
    .fetch_all(&mut *tx)
    .await
    .context("selecting unused DCR clients")?;

    let (client_addr, application_name) = SecurityEventRepository::connection_origin_conn(&mut tx)
        .await
        .context("reading the connection's origin")?;

    let mut swept = Vec::with_capacity(candidates.len());
    for (id, client_id, client_name, created_at) in candidates {
        let n = sqlx::query(
            "UPDATE oauth_clients SET status = 'revoked', updated_at = now() \
              WHERE id = $1 AND status = 'active'",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("revoking client {id}"))?
        .rows_affected();
        if n != 1 {
            bail!("client {id} changed under its row lock (updated {n} rows); nothing was written");
        }

        let audit_event_id = Uuid::new_v4();
        let event = SecurityEventRow {
            id: audit_event_id,
            event_type: EVENT_TYPE.to_string(),
            // A DCR client has no principal (`agent_id IS NULL` is part of the
            // predicate), so the row names none.
            agent_id: None,
            success: Some(true),
            details: serde_json::json!({
                "tool": "epigraph-operator",
                "command": "sweep-dcr-clients",
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
                    "id": id,
                    "client_id": client_id,
                    "client_name": client_name,
                    "created_at": created_at,
                },
                "status": { "before": "active", "after": "revoked" },
                "criterion": {
                    "older_than_hours": older_than_hours,
                    "authorization_codes": 0,
                },
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
        swept.push(Swept {
            id,
            client_id,
            client_name,
            created_at,
            audit_event_id,
        });
    }

    if apply {
        tx.commit().await.context("committing")?;
    } else {
        tx.rollback().await.context("rolling back the dry run")?;
    }
    Ok(Outcome {
        swept,
        older_than_hours,
        applied: apply,
    })
}

/// Every DCR-shaped client, any status, oldest first, with its code count and
/// whether a sweep with `older_than_hours` would take it. Read-only.
///
/// # Errors
/// The age floor is below [`MIN_AGE_HOURS`], or the query fails.
pub async fn census(
    conn: &mut PgConnection,
    older_than_hours: u32,
) -> anyhow::Result<Vec<CensusRow>> {
    validate_age(older_than_hours)?;
    sqlx::query_as::<_, CensusRow>(&format!(
        "SELECT c.id, c.client_id::text AS client_id, c.client_name::text AS client_name, \
                c.status::text AS status, c.created_at, \
                count(a.code_hash) AS codes, max(a.created_at) AS last_code_at, \
                (c.status = 'active' \
                 AND c.created_at < now() - make_interval(hours => $1) \
                 AND count(a.code_hash) = 0) AS sweepable \
           FROM oauth_clients c \
           LEFT JOIN oauth_authorization_codes a ON a.client_id = c.client_id \
          WHERE {DCR_SHAPE} \
          GROUP BY c.id \
          ORDER BY c.created_at, c.id"
    ))
    .bind(i32::try_from(older_than_hours).context("--older-than-hours is too large")?)
    .fetch_all(&mut *conn)
    .await
    .context("listing DCR clients")
}

/// The lines the binary prints for a sweep.
#[must_use]
pub fn describe(o: &Outcome) -> Vec<String> {
    let mode = if o.applied { "APPLIED" } else { "DRY RUN" };
    let verb = if o.applied { "revoked" } else { "would revoke" };
    let mut out = vec![format!(
        "{mode}: sweep-dcr-clients --older-than-hours {}: {verb} {} unused DCR client(s)",
        o.older_than_hours,
        o.swept.len()
    )];
    for s in &o.swept {
        out.push(format!(
            "  {} {} ({:?}, registered {}) audit row {}{}",
            s.id,
            s.client_id,
            s.client_name,
            s.created_at.to_rfc3339(),
            s.audit_event_id,
            if o.applied { "" } else { " (rolled back)" }
        ));
    }
    out
}

/// One line per census row.
#[must_use]
pub fn describe_census(r: &CensusRow) -> String {
    format!(
        "{} {} ({:?}) status={} registered={} codes={} last_code={} sweepable={}",
        r.id,
        r.client_id,
        r.client_name,
        r.status,
        r.created_at.to_rfc3339(),
        r.codes,
        r.last_code_at
            .map_or_else(|| "-".to_string(), |t| t.to_rfc3339()),
        r.sweepable
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_age_floor_below_one_hour_is_refused() {
        assert!(validate_age(0).is_err());
        assert!(validate_age(1).is_ok());
        assert!(validate_age(24).is_ok());
    }
}
