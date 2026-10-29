//! The "no holder, no run" boot check (migration 166).
//!
//! An agent attached to a role (`role_agents`) runs only while a human holds
//! that role and the agent is linked to that holder. The database refuses its
//! writes otherwise (ROL01), so a process that started anyway would fail on
//! its first write. [`check_role_holder`] makes that a refusal to START, before
//! anything resolves (and so may create) the server's agent row: it only reads.
//!
//! An agent no row names (a first boot) is not attached and is admitted; the
//! host registers and attaches a role's identities before it starts them.

use epigraph_db::{AgentRepository, RoleAgentRunGate};
use sqlx::PgPool;
use uuid::Uuid;

/// Refuse to serve when the agent whose identity key is `identity_public_key`
/// is attached to a role that no human holds now, or whose holder is not the
/// agent's linked human. Returns the agent and its answer when it may run;
/// `Ok(None)` when no agent carries the key yet.
///
/// # Errors
///
/// The operator-facing refusal, or a failed read (a process that cannot ask
/// does not start as if the answer were yes).
pub async fn check_role_holder(
    pool: &PgPool,
    identity_public_key: &[u8; 32],
) -> Result<Option<(Uuid, RoleAgentRunGate)>, String> {
    let Some(agent) = AgentRepository::get_by_public_key(pool, identity_public_key)
        .await
        .map_err(|e| {
            format!(
                "could not look up the agent for public key {}: {e}",
                hex::encode(identity_public_key)
            )
        })?
    else {
        return Ok(None);
    };
    let agent = agent.id.as_uuid();
    let gate = AgentRepository::role_agent_may_run(pool, agent)
        .await
        .map_err(|e| {
            format!("could not ask whether agent {agent} may run (is migration 166 applied?): {e}")
        })?;
    if gate.may_run {
        return Ok(Some((agent, gate)));
    }
    Err(refusal_text(agent, &gate))
}

/// The refusal for an answer of `may_run = false`.
#[must_use]
pub fn refusal_text(agent: Uuid, gate: &RoleAgentRunGate) -> String {
    let role = gate.role.as_deref().unwrap_or("<unknown>");
    match gate.reason.as_str() {
        "no_holder" => format!(
            "agent {agent} is attached to role {role}, and no human holds it now; a role's \
             agents do not run while the role has no holder. Not starting: an operator grants \
             the role to the agent's linked human, or detaches the agent from the role."
        ),
        _ => format!(
            "agent {agent} is attached to role {role}, but is not linked to its holder now (the \
             role was handed over, or the agent's own link is not live); a role's agents run \
             only for the role's holder. Not starting: an operator grants the role back to the \
             agent's human, or detaches the agent from the role and attaches an identity \
             linked to the holder (a link never moves to another human)."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(reason: &str) -> RoleAgentRunGate {
        RoleAgentRunGate {
            may_run: false,
            role: Some("role:r".to_string()),
            holder: None,
            reason: reason.to_string(),
        }
    }

    /// The two refusals say which case it is and name the role; the operator
    /// reads which act fixes it.
    #[test]
    fn the_refusal_names_the_role_and_the_case() {
        let a = Uuid::nil();
        let none = refusal_text(a, &gate("no_holder"));
        assert!(
            none.contains("role:r") && none.contains("no human holds it"),
            "{none}"
        );
        let other = refusal_text(a, &gate("not_holder"));
        assert!(
            other.contains("role:r") && other.contains("is not linked to its holder"),
            "{other}"
        );
    }
}
