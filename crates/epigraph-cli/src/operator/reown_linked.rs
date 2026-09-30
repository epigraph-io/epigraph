//! `reown-linked`: move every claim a LINKED author's OWN personal group owns
//! into the author's operator's group (operator binding, migration 122).
//!
//! An agent tied to an operator (an `operator_links` row, live or retired)
//! should have its claims owned by the operator's personal group. Claims it
//! wrote BEFORE it was linked (or while its membership was revoked) are still
//! owned by its own personal group, and the tenancy backfill never revisits
//! them because they are not world-owned. This command selects exactly those
//! claims for one operator and hands them to [`super::reown::run`] with
//! `--derived follow-claim`, so every guard of `reown-claims` applies unchanged:
//! only public claims whose attached rows are all public move, each batch checks
//! its invariants and rolls back on a violation, and the manifest (written and
//! fsynced before the first write) is what `reown-reverse` undoes. Derived rows
//! follow the claim through migration 070's arm (d) trigger.
//!
//! # Resumable, and single-operator
//!
//! The selection is the predicate itself ("owned by the author's own personal
//! group, author linked to this operator"), so a re-run after an interruption
//! simply selects what is left; give each run a NEW `--manifest-out`. Like the
//! tenancy backfill, run ONE instance at a time: two concurrent runs would each
//! plan the same claims and one would hold them as changed under the lock.

use sqlx::PgConnection;
use uuid::Uuid;

/// Claims owned by their author's own personal group (the canonical did_key,
/// created by the author) whose author has an `operator_links` row naming
/// `operator`, in id order.
///
/// # Errors
/// The read fails.
pub async fn candidates(conn: &mut PgConnection, operator: Uuid) -> anyhow::Result<Vec<Uuid>> {
    Ok(sqlx::query_scalar(
        "SELECT c.id FROM claims c \
           JOIN operator_links l ON l.agent_id = c.agent_id AND l.operator_id = $1 \
           JOIN groups g ON g.id = c.owner_group_id \
          WHERE g.kind = 'personal' \
            AND g.created_by_agent_id = c.agent_id \
            AND g.did_key = 'did:epigraph:personal:' || c.agent_id::text \
          ORDER BY c.id",
    )
    .bind(operator)
    .fetch_all(&mut *conn)
    .await?)
}
