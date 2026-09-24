//! `link-retired`: record retired operator links for historical identities.
//!
//! Each id goes through `epigraph_link_retired_agent` (migration 107 section
//! 7), whose refusals are the whole policy: this module adds none and removes
//! none. A dry run calls the SAME function inside one transaction, under a
//! savepoint per id, and rolls everything back, so what it prints is what the
//! function did rather than a re-derivation of what it would do.
//!
//! # Two refusals are about the OPERATOR, not the id
//!
//! The function resolves the operator's personal group through migration 105's
//! `epigraph_ensure_personal_group` (107 section 3), so it inherits that
//! definer's two refusals: `RVK01` (the operator's OWN membership of its
//! personal group is only revoked) and `RVK02` (the group under the operator's
//! personal did_key is not the operator's own: a squat). Neither says anything
//! about the id being linked, and every later id would meet the same refusal,
//! so the run STOPS at the first one: that id is reported
//! [`LinkStatus::OperatorRefused`] with its cause, every id after it
//! [`LinkStatus::NotAttempted`], and nothing is written for any of them (the
//! function refuses before its first INSERT). Clearing either is an operator
//! action this tool does not take.
//!
//! # A retire that did not de-authorize is a refusal, never a success
//!
//! The point of a retired link is that a possibly-exposed key ends with ZERO
//! write authority. The function refuses (55000, with a HINT this module
//! prints) an id that still holds a live `writer`/`admin` row in the operator's
//! group, and an id whose link to this operator is an ACTOR link (a retire is
//! not a demotion). A [`LinkStatus::Linked`] outcome that is not retired, or
//! that still reports a live membership, is counted as a refusal too
//! ([`LinkStatus::is_refusal`]), so the binary exits non-zero and an operator
//! cannot read a clean run as "these keys are de-authorized" when one is not.

use epigraph_db::{AgentRepository, DbError, RetiredLinkOutcome};
use sqlx::PgConnection;
use std::fmt::Write as _;
use uuid::Uuid;

/// What one id came to.
#[derive(Debug)]
pub enum LinkStatus {
    Linked(RetiredLinkOutcome),
    /// The function refused THIS id (its own `RAISE`: a self-link, an agent
    /// already linked elsewhere, a shared signer, ...). Later ids still run.
    Refused(String),
    /// Migration 105's `RVK01` / `RVK02` on the OPERATOR's personal group
    /// ([`refusal_text`]). The run stops here.
    OperatorRefused(String),
    /// Not run, because an earlier id met [`LinkStatus::OperatorRefused`].
    NotAttempted,
}

impl LinkStatus {
    /// Every status that is not a clean retire: the binary exits 3 on any. A
    /// [`LinkStatus::Linked`] outcome counts as a refusal when the row is NOT
    /// retired (an actor row the call left in place) or a live membership
    /// remains: in both the id was not de-authorized (see the module doc).
    #[must_use]
    pub const fn is_refusal(&self) -> bool {
        match self {
            Self::Linked(o) => !o.link_retired || o.membership_live,
            _ => true,
        }
    }
}

/// The text for a refused call. `RVK01` and `RVK02` get their own, naming the
/// operator as the cause and the fix as an operator action, the distinction
/// `epigraph_mcp::operator::link_refusal_text` draws for the stdio self-link;
/// every other error keeps the function's own message.
#[must_use]
pub fn refusal_text(operator: Uuid, e: &DbError) -> String {
    match e {
        DbError::MembershipRevoked { message } => format!(
            "the operator {operator}'s OWN membership of its personal group is REVOKED \
             (migration 105, RVK01); no identity is linked into a group its owner was revoked \
             from. Restoring that membership is an operator action. Database: {message}"
        ),
        DbError::PersonalGroupNotOwned { message } => format!(
            "the group carrying did:epigraph:personal:{operator} is not the operator's own \
             (migration 105, RVK02: a squatted key). An operator must inspect and remove the \
             squatting group. Database: {message}"
        ),
        other => {
            let mut text = other.to_string();
            // The two retire-specific refusals (107 section 7) carry their
            // remedy in the HINT, which `Display` drops.
            if let DbError::QueryFailed { source } = other {
                if let Some(hint) = source
                    .as_database_error()
                    .and_then(|d| d.try_downcast_ref::<sqlx::postgres::PgDatabaseError>())
                    .and_then(sqlx::postgres::PgDatabaseError::hint)
                {
                    let _ = write!(text, " HINT: {hint}");
                }
            }
            text
        }
    }
}

/// One line per id, stable enough to grep.
#[must_use]
pub fn describe(agent: Uuid, status: &LinkStatus) -> String {
    match status {
        LinkStatus::Refused(msg) => format!("{agent}\tREFUSED\t{msg}"),
        LinkStatus::OperatorRefused(msg) => {
            format!("{agent}\tREFUSED-OPERATOR\t{msg}; stopping: every later id would meet it")
        }
        LinkStatus::NotAttempted => format!(
            "{agent}\tNOT-ATTEMPTED\tthe run stopped at an operator refusal above; nothing was \
             written for this id"
        ),
        LinkStatus::Linked(o) => {
            let mut s = format!("{agent}\t");
            if o.link_created {
                s.push_str("LINKED-RETIRED");
            } else if o.link_retired {
                s.push_str("ALREADY-RETIRED");
            } else {
                // Unreachable against 107 (the function refuses an actor row),
                // kept so an older schema cannot print a success: counted as a
                // refusal by `is_refusal`.
                s.push_str("REFUSED-ALREADY-ACTOR-NOT-RETIRED");
            }
            let _ = write!(
                s,
                "\tgroup={} group_created={} edge_created={}",
                o.operator_group_id, o.group_created, o.edge_created
            );
            if o.membership_live {
                s.push_str(
                    "\tNOT-DEAUTHORIZED: holds a LIVE membership in the operator group; revoke \
                     it (counted as a refusal: the run exits non-zero)",
                );
            }
            s
        }
    }
}

/// Classify a refused call: an operator refusal (`RVK01` / `RVK02`) or a
/// refusal of this id.
fn classify(operator: Uuid, e: &DbError) -> LinkStatus {
    if e.is_personal_group_refusal() {
        LinkStatus::OperatorRefused(refusal_text(operator, e))
    } else {
        LinkStatus::Refused(refusal_text(operator, e))
    }
}

/// After pushing id `i`'s status: when it was an operator refusal, report every
/// later id as not attempted and return `true` (stop).
fn stop_after(out: &mut Vec<(Uuid, LinkStatus)>, agents: &[Uuid], i: usize) -> bool {
    let stopped = matches!(out.last(), Some((_, LinkStatus::OperatorRefused(_))));
    if stopped {
        out.extend(
            agents[i + 1..]
                .iter()
                .map(|&a| (a, LinkStatus::NotAttempted)),
        );
    }
    stopped
}

/// Run every id. Under `apply`, each call commits on its own and a refusal of
/// one id does not stop the others. Otherwise all calls share one transaction
/// that is rolled back. Either way an operator refusal (`RVK01` / `RVK02`)
/// stops the run (see the module doc).
///
/// # Errors
/// A database error on the dry run's transaction or savepoint statements.
pub async fn run(
    conn: &mut PgConnection,
    agents: &[Uuid],
    operator: Uuid,
    apply: bool,
) -> anyhow::Result<Vec<(Uuid, LinkStatus)>> {
    let mut out = Vec::with_capacity(agents.len());
    if apply {
        for (i, &agent) in agents.iter().enumerate() {
            let status = match AgentRepository::link_retired_agent(conn, agent, operator).await {
                Ok(o) => LinkStatus::Linked(o),
                Err(e) => classify(operator, &e),
            };
            out.push((agent, status));
            if stop_after(&mut out, agents, i) {
                break;
            }
        }
        return Ok(out);
    }
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    for (i, &agent) in agents.iter().enumerate() {
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
                classify(operator, &e)
            }
        };
        out.push((agent, status));
        if stop_after(&mut out, agents, i) {
            break;
        }
    }
    tx.rollback().await?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(link_retired: bool, membership_live: bool) -> RetiredLinkOutcome {
        RetiredLinkOutcome {
            operator_group_id: Uuid::nil(),
            group_created: false,
            link_created: link_retired,
            link_retired,
            edge_created: false,
            membership_live,
        }
    }

    /// A linked outcome that did not de-authorize the key is a refusal: the
    /// binary's exit code is computed from this, and a clean exit on either
    /// case would read as "these keys are de-authorized".
    #[test]
    fn only_a_clean_retire_is_not_a_refusal() {
        assert!(!LinkStatus::Linked(outcome(true, false)).is_refusal());
        assert!(LinkStatus::Linked(outcome(true, true)).is_refusal());
        assert!(LinkStatus::Linked(outcome(false, false)).is_refusal());
        assert!(LinkStatus::NotAttempted.is_refusal());
    }
}
