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

/// Who owns the legacy corpus: the same decision `epigraph-tenancy-backfill
/// run --legacy-owner` takes, and required here for the same reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum LegacyOwner {
    /// Every linked author (live or retired) is the operator's.
    Operator,
    /// Only LIVE-linked authors are the operator's; a retired-linked author's
    /// claims are left where they are (reported), for the platform decision.
    Platform,
}

/// Claims owned by their author's own personal group (the canonical did_key,
/// created by the author) whose author has an `operator_links` row naming
/// `operator` (under `platform`: a LIVE row), in id order.
///
/// # Errors
/// The read fails.
pub async fn candidates(
    conn: &mut PgConnection,
    operator: Uuid,
    mode: LegacyOwner,
) -> anyhow::Result<Vec<Uuid>> {
    Ok(sqlx::query_scalar(
        "SELECT c.id FROM claims c \
           JOIN operator_links l ON l.agent_id = c.agent_id AND l.operator_id = $1 \
           JOIN groups g ON g.id = c.owner_group_id \
          WHERE g.kind = 'personal' \
            AND g.created_by_agent_id = c.agent_id \
            AND g.did_key = 'did:epigraph:personal:' || c.agent_id::text \
            AND ($2 OR NOT l.retired) \
          ORDER BY c.id",
    )
    .bind(operator)
    .bind(mode == LegacyOwner::Operator)
    .fetch_all(&mut *conn)
    .await?)
}

/// Under `platform`: how many claims a RETIRED-linked author's own personal
/// group still owns (left behind by the decision, reported).
///
/// # Errors
/// The read fails.
pub async fn retired_left_behind(conn: &mut PgConnection, operator: Uuid) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM claims c \
           JOIN operator_links l ON l.agent_id = c.agent_id AND l.operator_id = $1 AND l.retired \
           JOIN groups g ON g.id = c.owner_group_id \
          WHERE g.kind = 'personal' \
            AND g.created_by_agent_id = c.agent_id \
            AND g.did_key = 'did:epigraph:personal:' || c.agent_id::text",
    )
    .bind(operator)
    .fetch_one(&mut *conn)
    .await?)
}
