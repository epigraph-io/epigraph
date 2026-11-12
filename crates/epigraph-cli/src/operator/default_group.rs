//! `set-default-group`: set the default (a team, private, or clear) of agents a
//! live human operator operates (migration 209; operator ruling 2026-11-12:
//! "epiclaw defaults to my private group").
//!
//! The command runs on the maintenance DSN, but it decides nothing itself. It
//! stamps `--operator` as the transaction's principal (`epigraph.principal_id`,
//! transaction-local) and calls the same definer the API and MCP call,
//! `epigraph_set_agent_default_group`, once per agent. So the definer applies
//! the same rule on every surface: the operator must be a registered, live
//! human operator holding a live, non-retired operator link to each agent, and
//! a team must be one the agent may write. Each change writes one
//! `agent.default_group_set` audit row attributed to the operator. The audit
//! row's `session_user` records the maintenance login that ran the command.
//!
//! ONE transaction for every listed agent: committed under `--apply`, rolled
//! back otherwise, so a dry run executes the definer for real and prints exactly
//! what `--apply` would do, including a refusal. One refused agent refuses the
//! whole run, and nothing is changed.

use epigraph_db::{ClaimRepository, DbError, DefaultGroupSetting};
use sqlx::PgConnection;
use uuid::Uuid;

/// One agent's default before and after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The agent.
    pub agent: Uuid,
    /// How the definer admitted the operator: `operator`, or `self` when the
    /// agent is the operator itself.
    pub via: String,
    /// `(default_group_id, default_private)` before.
    pub before: (Option<Uuid>, bool),
    /// `(default_group_id, default_private)` after.
    pub after: (Option<Uuid>, bool),
}

/// What the run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Every listed agent's default was set (committed only under `--apply`).
    Set(Vec<Change>),
    /// The definer refused `agent`; nothing was changed for any agent.
    Refused { agent: Uuid, why: String },
}

impl Outcome {
    /// 0 when every agent was set; 1 when the definer refused one.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Set(_) => 0,
            Self::Refused { .. } => 1,
        }
    }
}

fn word((group, private): (Option<Uuid>, bool)) -> String {
    match (group, private) {
        (_, true) => "private".to_string(),
        (Some(g), false) => format!("team:{g}"),
        (None, false) => "none".to_string(),
    }
}

/// One stable, grep-able line per agent.
#[must_use]
pub fn describe(operator: Uuid, outcome: &Outcome, apply: bool) -> Vec<String> {
    match outcome {
        Outcome::Set(changes) => changes
            .iter()
            .map(|c| {
                format!(
                    "{}SET\tagent={}\tvia={}\toperator={operator}\tprevious={}\tnow={}",
                    if apply { "" } else { "WOULD BE " },
                    c.agent,
                    c.via,
                    word(c.before),
                    word(c.after)
                )
            })
            .collect(),
        Outcome::Refused { agent, why } => vec![format!(
            "REFUSED\tagent={agent}\toperator={operator}\t{why}\tnothing was changed for any \
             listed agent"
        )],
    }
}

async fn current(conn: &mut PgConnection, agent: Uuid) -> anyhow::Result<(Option<Uuid>, bool)> {
    Ok(sqlx::query_as::<_, (Option<Uuid>, bool)>(
        "SELECT default_group_id, default_private FROM public.agents WHERE id = $1",
    )
    .bind(agent)
    .fetch_optional(&mut *conn)
    .await?
    .unwrap_or((None, false)))
}

/// Set `setting` on every agent in `agents` (duplicates collapsed, order kept)
/// as `operator`.
///
/// # Errors
/// A statement failed for a reason other than the definer's designed refusals
/// (those are [`Outcome::Refused`]). Nothing is written in either case.
pub async fn run(
    conn: &mut PgConnection,
    operator: Uuid,
    agents: &[Uuid],
    setting: DefaultGroupSetting,
    apply: bool,
) -> anyhow::Result<Outcome> {
    anyhow::ensure!(!agents.is_empty(), "--agent names at least one agent");
    let mut seen = std::collections::BTreeSet::new();
    let agents: Vec<Uuid> = agents.iter().copied().filter(|a| seen.insert(*a)).collect();

    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    sqlx::query("SELECT set_config('epigraph.principal_id', $1, true)")
        .bind(operator.to_string())
        .execute(&mut *tx)
        .await?;
    let mut changes = Vec::with_capacity(agents.len());
    for agent in agents {
        let before = current(&mut tx, agent).await?;
        match ClaimRepository::set_agent_default_conn(&mut tx, agent, setting).await {
            Ok(via) => {
                let after = current(&mut tx, agent).await?;
                changes.push(Change {
                    agent,
                    via,
                    before,
                    after,
                });
            }
            Err(DbError::Refused { message, .. }) => {
                tx.rollback().await?;
                return Ok(Outcome::Refused {
                    agent,
                    why: message,
                });
            }
            Err(e) => {
                tx.rollback().await?;
                return Err(anyhow::anyhow!("setting the default of {agent}: {e}"));
            }
        }
    }
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(Outcome::Set(changes))
}
