//! Operator-scoped ownership at process startup (migration 102).
//!
//! A per-agent stdio process that the host starts with `--operator-id` /
//! `EPIGRAPH_OPERATOR_ID` records, once, that its signer agent is operated by
//! that operator: `agent --OPERATED_BY--> operator` plus a `writer` membership in
//! the operator's personal group (`epigraph_link_operator`). From then on the
//! agent authors into the operator's group
//! (`ClaimRepository::default_decl_for_author`) and shares ownership with the
//! operator and its other agents (`tools::claims::require_owner_or_admin`).
//!
//! # Trust basis
//!
//! The env var DECLARES the operator; the DSN AUTHORIZES the link.
//! `epigraph_link_operator` is EXECUTE-able by `epigraph_maintenance` (and
//! superusers) only. Epiclaw's per-agent processes connect with a privileged DSN
//! today, so they can record their own link; on an `epigraph_app` DSN the call
//! fails with `42501` and [`self_link`] returns that error, which `main` treats
//! as FATAL — a declared operator the process cannot record is never silently
//! dropped. A host that moves agents onto `epigraph_app` must record the link
//! itself, on a maintenance connection, before starting them.
//!
//! # Never on a shared HTTP listener
//!
//! An HTTP listener authors EVERY authenticated caller's claims as its one
//! signer agent. If that signer were operated, every OAuth caller would write
//! into the operator's group and inherit the operator's ownership. So
//! [`check_operator_transport`] refuses `--operator-id` with `--listen` before
//! any database work, and [`refuse_operated_http_signer`] refuses to start an
//! HTTP listener whose signer ALREADY has a live operator link (recorded by some
//! earlier stdio process under the same key).

use crate::server::EpiGraphMcpFull;
use epigraph_db::{AgentRepository, OperatorLinkOutcome};
use uuid::Uuid;

/// Refuse `--operator-id` / `EPIGRAPH_OPERATOR_ID` on an HTTP listener, and on a
/// process whose signer identity was not declared.
///
/// Pure over its inputs so every arm is unit-testable, and called by `main`
/// BEFORE the database connect so a misconfiguration surfaces immediately.
///
/// * With `listen`: an HTTP listener signs every caller's claims as one agent;
///   operating that agent would hand every caller the operator's group.
/// * Without a declared identity (`--agent-key` / `--agent-model` absent,
///   `select_signer` rung 4): the signer is a fresh random keypair per process,
///   so every start would enrol a NEW throwaway agent as a writer in the
///   operator's group, permanently — memberships are never revived and never
///   cleaned up by this path.
///
/// # Errors
/// The operator-facing reason, when the combination is refused.
pub fn check_operator_transport(
    listen: Option<&str>,
    operator_id: Option<Uuid>,
    identity_declared: bool,
) -> Result<(), String> {
    let Some(operator) = operator_id else {
        return Ok(());
    };
    if let Some(listen) = listen {
        return Err(format!(
            "--operator-id / EPIGRAPH_OPERATOR_ID ({operator}) is refused on an HTTP listener \
             (--listen {listen}). An HTTP listener authors every authenticated caller's claims as \
             its ONE signer agent, so operating that agent would put every caller's writes into \
             the operator's personal group with the operator's ownership. Declare an operator \
             only on a per-agent stdio process."
        ));
    }
    if !identity_declared {
        return Err(format!(
            "--operator-id / EPIGRAPH_OPERATOR_ID ({operator}) requires a declared signer identity \
             (--agent-model or --agent-key). Without one this process signs as a fresh random \
             agent, and linking it would enrol a new throwaway writer in the operator's group on \
             every start."
        ));
    }
    Ok(())
}

/// Refuse to serve HTTP when this process's signer agent already has a live
/// operator link.
///
/// Read-only: the signer is looked up by public key and NOT created, so a
/// listener whose signer has never been registered passes without writing.
/// ANY live link refuses, including an ambiguous one — the opposite fail
/// direction from the authoring path, which treats ambiguity as "no operator".
/// A lookup failure also refuses: this gate cannot let a listener start on an
/// answer it did not get.
///
/// # Errors
/// The operator-facing reason when the listener must not start.
pub async fn refuse_operated_http_signer(
    pool: &sqlx::PgPool,
    signer_public_key: &[u8; 32],
) -> Result<(), String> {
    let agent = AgentRepository::get_by_public_key(pool, signer_public_key)
        .await
        .map_err(|e| {
            format!(
                "could not look up this listener's signer agent to check for an operator link: {e}"
            )
        })?;
    let Some(agent) = agent else {
        return Ok(());
    };
    let agent_id = agent.id.as_uuid();
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| format!("could not acquire a connection for the operator-link check: {e}"))?;
    let links = AgentRepository::operator_links(&mut conn, agent_id)
        .await
        .map_err(|e| {
            format!(
                "could not check whether this listener's signer agent {agent_id} has an operator \
                 link (is migration 102 applied?): {e}"
            )
        })?;
    if links.is_empty() {
        return Ok(());
    }
    let operators: Vec<String> = links.iter().map(|l| l.operator_id.to_string()).collect();
    Err(format!(
        "this HTTP listener's signer agent {agent_id} has a live operator link to {}. An HTTP \
         listener authors every caller's claims as that one agent, so every caller would write \
         into the operator's personal group with the operator's ownership. Run the listener \
         under a different --agent-key, or revoke the agent's membership in the operator's \
         personal group.",
        operators.join(", ")
    ))
}

/// Record `operator` as the operator of this server's own signer agent and log
/// the outcome. Resolves (and on first boot creates) the signer agent first.
///
/// A revoked link is REPORTED, not repaired: the membership stays revoked, the
/// process authors into its own personal group, and this logs a warning.
///
/// # Errors
/// The agent could not be resolved, or `epigraph_link_operator` refused — most
/// importantly `42501 permission denied` on an `epigraph_app` DSN. `main` exits
/// on any error: a declared operator that cannot be recorded must be loud.
pub async fn self_link(
    server: &EpiGraphMcpFull,
    operator: Uuid,
) -> Result<OperatorLinkOutcome, String> {
    let agent = server
        .server_agent_id()
        .await
        .map_err(|e| format!("could not resolve this process's signer agent: {e:?}"))?;
    let mut conn =
        server.pool.acquire().await.map_err(|e| {
            format!("could not acquire a connection to record the operator link: {e}")
        })?;
    let outcome = AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .map_err(|e| {
            format!(
                "could not record agent {agent} as operated by {operator} \
                 (epigraph_link_operator is EXECUTE-able by epigraph_maintenance only; on an \
                 epigraph_app DSN the host must record the link on a maintenance connection \
                 instead): {e}"
            )
        })?;
    if outcome.membership_live {
        tracing::info!(
            agent = %agent,
            operator = %operator,
            operator_group = %outcome.operator_group_id,
            group_created = outcome.group_created,
            membership_created = outcome.membership_created,
            edge_created = outcome.edge_created,
            "operator link recorded: this agent authors into the operator's personal group"
        );
    } else {
        tracing::warn!(
            agent = %agent,
            operator = %operator,
            operator_group = %outcome.operator_group_id,
            "operator link is REVOKED for this agent and was deliberately NOT restored; this \
             process authors into its own personal group and holds no operator ownership"
        );
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::check_operator_transport;
    use uuid::Uuid;

    #[test]
    fn no_operator_is_always_accepted() {
        assert!(check_operator_transport(None, None, false).is_ok());
        assert!(check_operator_transport(Some("127.0.0.1:0"), None, true).is_ok());
    }

    #[test]
    fn an_operator_on_an_http_listener_is_refused_for_tcp_and_unix() {
        for listen in ["127.0.0.1:3100", "unix:/run/mcp.sock"] {
            let err = check_operator_transport(Some(listen), Some(Uuid::new_v4()), true)
                .expect_err("an HTTP listener must refuse an operator");
            assert!(err.contains("HTTP listener"), "{err}");
        }
    }

    #[test]
    fn an_operator_without_a_declared_identity_is_refused() {
        let err = check_operator_transport(None, Some(Uuid::new_v4()), false)
            .expect_err("rung 4 must refuse an operator");
        assert!(err.contains("declared signer identity"), "{err}");
    }

    #[test]
    fn an_operator_on_stdio_with_a_declared_identity_is_accepted() {
        assert!(check_operator_transport(None, Some(Uuid::new_v4()), true).is_ok());
    }
}
