//! `link-retired`: record retired operator links for historical identities.
//!
//! Each id goes through `epigraph_link_retired_agent` (migration 102 section
//! 7), whose refusals are the whole policy: this module adds none and removes
//! none. A dry run calls the SAME function inside one transaction, under a
//! savepoint per id, and rolls everything back, so what it prints is what the
//! function did rather than a re-derivation of what it would do.

use epigraph_db::{AgentRepository, RetiredLinkOutcome};
use sqlx::PgConnection;
use std::fmt::Write as _;
use uuid::Uuid;

/// What one id came to.
#[derive(Debug)]
pub enum LinkStatus {
    Linked(RetiredLinkOutcome),
    Refused(String),
}

/// One line per id, stable enough to grep.
#[must_use]
pub fn describe(agent: Uuid, status: &LinkStatus) -> String {
    match status {
        LinkStatus::Refused(msg) => format!("{agent}\tREFUSED\t{msg}"),
        LinkStatus::Linked(o) => {
            let mut s = format!("{agent}\t");
            if o.link_created {
                s.push_str("LINKED-RETIRED");
            } else if o.link_retired {
                s.push_str("ALREADY-RETIRED");
            } else {
                // `ON CONFLICT DO NOTHING` kept an existing ACTOR row for the
                // same operator exactly as it was.
                s.push_str("ALREADY-ACTOR-NOT-RETIRED");
            }
            let _ = write!(
                s,
                "\tgroup={} group_created={} edge_created={}",
                o.operator_group_id, o.group_created, o.edge_created
            );
            if o.membership_live {
                s.push_str(
                    "\tWARNING: holds a LIVE membership in the operator group; a retired \
                     identity has zero write authority only once that membership is revoked",
                );
            }
            s
        }
    }
}

/// Run every id. Under `apply`, each call commits on its own and a refusal of
/// one id does not stop the others. Otherwise all calls share one transaction
/// that is rolled back.
///
/// # Errors
/// A database error other than the function's own refusal of an id.
pub async fn run(
    conn: &mut PgConnection,
    agents: &[Uuid],
    operator: Uuid,
    apply: bool,
) -> anyhow::Result<Vec<(Uuid, LinkStatus)>> {
    let mut out = Vec::with_capacity(agents.len());
    if apply {
        for &agent in agents {
            let status = match AgentRepository::link_retired_agent(conn, agent, operator).await {
                Ok(o) => LinkStatus::Linked(o),
                Err(e) => LinkStatus::Refused(e.to_string()),
            };
            out.push((agent, status));
        }
        return Ok(out);
    }
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    for &agent in agents {
        sqlx::query("SAVEPOINT link_retired_one")
            .execute(&mut *tx)
            .await?;
        let status = match AgentRepository::link_retired_agent(&mut tx, agent, operator).await {
            Ok(o) => {
                sqlx::query("RELEASE SAVEPOINT link_retired_one")
                    .execute(&mut *tx)
                    .await?;
                LinkStatus::Linked(o)
            }
            Err(e) => {
                sqlx::query("ROLLBACK TO SAVEPOINT link_retired_one")
                    .execute(&mut *tx)
                    .await?;
                LinkStatus::Refused(e.to_string())
            }
        };
        out.push((agent, status));
    }
    tx.rollback().await?;
    Ok(out)
}
