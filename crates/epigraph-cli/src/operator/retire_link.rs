//! `retire-link`: retire ONE existing LIVE operator link (backlog 4dec90c2;
//! migration 191's `epigraph_retire_operator_link`).
//!
//! `link-retired` records a NEW retired link and refuses an agent that already
//! has a live one ("a retire is not a demotion"). This verb is the other half:
//! it flips an existing live link to retired. The definer decides everything:
//! it is maintenance-only, takes the operator-links advisory lock, refuses a
//! registered system agent (migration 148's trigger), and is idempotent (a
//! retired link is reported `already_retired` and nothing is written). Every
//! flip is audited by the table's own trigger (`operator.link_retired`), with
//! the reason this command passes.
//!
//! # A retire that did not de-authorize is a refusal
//!
//! A live link records the agent's `writer` row in the operator's group, and
//! that row would survive the retire. So the definer refuses (OLR03) while the
//! agent holds a live writer/admin row there, unless `--revoke-membership`
//! asks it to revoke those rows in the same act. The count it revoked is
//! printed and recorded in the audit row.
//!
//! This module runs the call in ONE transaction, committed under `--apply` and
//! rolled back otherwise, so a dry run prints exactly what the definer did.

use anyhow::Context;
use sqlx::PgConnection;
use std::fmt::Write as _;
use uuid::Uuid;

/// What the definer reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// This call retired the link (and revoked `memberships_revoked` rows).
    Retired {
        operator: Uuid,
        group: Uuid,
        memberships_revoked: i32,
    },
    /// The link was already retired; nothing was written.
    AlreadyRetired { operator: Uuid, group: Uuid },
    /// The agent has no operator link at all; nothing was written.
    NoLink,
}

impl Outcome {
    /// The process exit code: a missing link is a failure (usually a mistyped
    /// id); a repeat is a success.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::NoLink => 1,
            _ => 0,
        }
    }
}

/// One stable, grep-able line.
#[must_use]
pub fn describe(agent: Uuid, outcome: &Outcome, apply: bool) -> String {
    match outcome {
        Outcome::Retired {
            operator,
            group,
            memberships_revoked,
        } => format!(
            "{}RETIRED\tagent={agent}\toperator={operator}\tgroup={group}\t\
             memberships_revoked={memberships_revoked}",
            if apply { "" } else { "WOULD BE " }
        ),
        Outcome::AlreadyRetired { operator, group } => format!(
            "ALREADY-RETIRED\tagent={agent}\toperator={operator}\tgroup={group}\tnothing was \
             written"
        ),
        Outcome::NoLink => {
            format!("NO-LINK\tagent={agent}\tthe agent has no operator link; nothing was written")
        }
    }
}

/// The text of a refused call, with the definer's HINT (which `Display`
/// drops).
fn refusal(agent: Uuid, e: &sqlx::Error) -> String {
    let mut text = format!("retiring the operator link of {agent}: {e}");
    if let Some(hint) = e
        .as_database_error()
        .and_then(|d| d.try_downcast_ref::<sqlx::postgres::PgDatabaseError>())
        .and_then(sqlx::postgres::PgDatabaseError::hint)
    {
        let _ = write!(text, " HINT: {hint}");
    }
    text
}

/// Retire `agent`'s live link.
///
/// # Errors
/// The definer refused (not a maintenance session, a missing reason, a live
/// writer row without `revoke_membership` (OLR03), a registered system agent),
/// or a statement failed. Nothing is written in either case.
pub async fn run(
    conn: &mut PgConnection,
    agent: Uuid,
    reason: &str,
    revoke_membership: bool,
    apply: bool,
) -> anyhow::Result<Outcome> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let row: (String, Option<Uuid>, Option<Uuid>, i32) = sqlx::query_as(
        "SELECT outcome, operator_id, operator_group_id, memberships_revoked \
           FROM public.epigraph_retire_operator_link($1, $2, $3)",
    )
    .bind(agent)
    .bind(reason)
    .bind(revoke_membership)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| anyhow::anyhow!(refusal(agent, &e)))?;
    let outcome = match row {
        (o, Some(operator), Some(group), n) if o == "retired" => Outcome::Retired {
            operator,
            group,
            memberships_revoked: n,
        },
        (o, Some(operator), Some(group), _) if o == "already_retired" => {
            Outcome::AlreadyRetired { operator, group }
        }
        (o, None, None, _) if o == "no_link" => Outcome::NoLink,
        other => anyhow::bail!("unexpected outcome from epigraph_retire_operator_link: {other:?}"),
    };
    if apply {
        tx.commit().await.context("committing the retire")?;
    } else {
        tx.rollback().await?;
    }
    Ok(outcome)
}
