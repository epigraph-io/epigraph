//! Operator-scoped ownership at process startup (migration 107).
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
//! any database work, [`refuse_operated_http_signer`] refuses to start an HTTP
//! listener whose signer ALREADY has an operator link (recorded by some earlier
//! stdio process under the same key, or as a retired link), and
//! [`refuse_linked_http_signer`] re-checks the same predicate on EVERY HTTP tool
//! call, so a link recorded after the listener started takes effect as a
//! refusal at once rather than at the next restart.
//!
//! Both HTTP checks also refuse a signer that is anyone's OPERATOR
//! (`AgentRepository::operates_agents`, migration 107 section 9): on
//! `--allow-unauthenticated-http` every caller IS the signer, and would satisfy
//! "caller is the operator of the claim's author" for every linked agent.
//!
//! Both HTTP checks read the AUTHOR record (`AgentRepository::operator_of_author`,
//! retired links included), not the actor read. That is a REFUSAL-only use of
//! "whose are this agent's claims?": an HTTP signer with any link record would
//! either author into the operator's group (an acting link) or hand the operator
//! ownership of every HTTP caller's claims (either kind), and both are the
//! failure the listener must not serve through.

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;
use epigraph_db::{AgentRepository, AuthorOperator, OperatorLinkOutcome};
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

/// Refuse to serve HTTP when this process's signer agent already has an
/// operator link of either kind (see the module doc for why the author record,
/// retired links included, is the predicate), or is itself some agent's
/// OPERATOR (migration 107 section 9).
///
/// Read-only: the signer is looked up by public key and NOT created, so a
/// listener whose signer has never been registered passes without writing.
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
    let link = AgentRepository::operator_of_author(&mut conn, agent_id)
        .await
        .map_err(|e| {
            format!(
                "could not check whether this listener's signer agent {agent_id} has an operator \
                 link (is migration 107 applied?): {e}"
            )
        })?;
    if let Some(link) = link {
        return Err(linked_http_signer_reason(agent_id, &link));
    }
    let operates = AgentRepository::operates_agents(&mut conn, agent_id)
        .await
        .map_err(|e| {
            format!(
                "could not check whether this listener's signer agent {agent_id} is an operator \
                 (is migration 107 applied?): {e}"
            )
        })?;
    if operates {
        return Err(operator_http_signer_reason(agent_id));
    }
    Ok(())
}

/// The refusal text shared by the startup gate and the per-call guard.
fn linked_http_signer_reason(agent_id: Uuid, link: &AuthorOperator) -> String {
    let kind = if link.retired {
        "a retired link"
    } else {
        "an acting link"
    };
    format!(
        "this HTTP listener's signer agent {agent_id} has an operator link to {} ({kind}). An \
         HTTP listener authors every caller's claims as that one agent, so every caller would \
         write with the operator's ownership. Run the listener under a different --agent-key; \
         the link record is permanent.",
        link.operator_id
    )
}

/// The refusal text for a signer that is some agent's OPERATOR (107 section 9).
fn operator_http_signer_reason(agent_id: Uuid) -> String {
    format!(
        "this HTTP listener's signer agent {agent_id} is the operator of linked agents. On an \
         unauthenticated HTTP transport every caller IS the signer, and would own every claim \
         those agents authored. Run the listener under a different --agent-key; the link \
         records are permanent."
    )
}

/// Per-call twin of [`refuse_operated_http_signer`]: refuse an HTTP tool call
/// while this server's signer agent has an operator link of either kind.
///
/// The startup gate runs once. Every write re-reads the operator records
/// (`default_decl_for_author`, `require_owner_or_admin`), so a link recorded
/// AFTER the listener started — a stdio process under the same `--agent-key` or
/// `--agent-model` identity with `EPIGRAPH_OPERATOR_ID` set, or a retired link
/// recorded by an operator — would otherwise take effect immediately and stay
/// live until the next restart. `server::call_tool` calls this on every HTTP
/// call, before dispatch, so the listener refuses instead.
///
/// Logged at ERROR: it is a deployment fault, not a caller error. A failed
/// lookup also refuses — the guard does not serve on an answer it did not get.
///
/// # Errors
/// An `McpError` naming the link, or the lookup failure.
pub async fn refuse_linked_http_signer(server: &EpiGraphMcpFull) -> Result<(), McpError> {
    let agent_id = server.agent_id().await?;
    match AgentRepository::operator_of_author_pool(&server.pool, agent_id).await {
        Ok(None) => refuse_operator_http_signer(server, agent_id).await,
        Ok(Some(link)) => {
            let reason = linked_http_signer_reason(agent_id, &link);
            tracing::error!(
                agent = %agent_id,
                operator = %link.operator_id,
                retired = link.retired,
                "refusing an HTTP tool call: {reason}"
            );
            Err(internal_error(format!("refused: {reason}")))
        }
        Err(e) => {
            tracing::error!(
                agent = %agent_id,
                error = %e,
                "refusing an HTTP tool call: could not check the signer's operator link"
            );
            Err(internal_error(format!(
                "refused: could not verify that this HTTP listener's signer agent {agent_id} \
                 has no operator link: {e}"
            )))
        }
    }
}

/// The operator half of [`refuse_linked_http_signer`]: refuse while this
/// server's signer is anyone's OPERATOR (107 section 9). Fails closed.
async fn refuse_operator_http_signer(
    server: &EpiGraphMcpFull,
    agent_id: Uuid,
) -> Result<(), McpError> {
    match AgentRepository::operates_agents_pool(&server.pool, agent_id).await {
        Ok(false) => Ok(()),
        Ok(true) => {
            let reason = operator_http_signer_reason(agent_id);
            tracing::error!(agent = %agent_id, "refusing an HTTP tool call: {reason}");
            Err(internal_error(format!("refused: {reason}")))
        }
        Err(e) => {
            tracing::error!(
                agent = %agent_id,
                error = %e,
                "refusing an HTTP tool call: could not check whether the signer is an operator"
            );
            Err(internal_error(format!(
                "refused: could not verify that this HTTP listener's signer agent {agent_id} \
                 is no agent's operator: {e}"
            )))
        }
    }
}

/// The startup refusal text for a failed [`self_link`], naming the cause an
/// operator can act on.
///
/// `epigraph_link_operator` resolves the operator's personal group through
/// migration 105's `epigraph_ensure_personal_group` (107 section 3), so two of
/// its refusals are that definer's: `RVK01` (the OPERATOR's own membership of
/// its own group is only revoked) and `RVK02` (the group under the operator's
/// personal did_key is not the operator's own). Both are deliberate refusals,
/// not faults, and each gets its own text; everything else keeps the
/// EXECUTE-grant hint, because on a stdio host the usual cause is an
/// `epigraph_app` DSN (`42501`).
pub fn link_refusal_text(agent: Uuid, operator: Uuid, e: &epigraph_db::DbError) -> String {
    match e {
        epigraph_db::DbError::MembershipRevoked { message } => format!(
            "refused to record agent {agent} as operated by {operator}: the operator's OWN \
             membership of its personal group is REVOKED (migration 105, RVK01), and agents are \
             not linked into a group its owner was revoked from. Restoring that membership is an \
             operator action. Database: {message}"
        ),
        epigraph_db::DbError::PersonalGroupNotOwned { message } => format!(
            "refused to record agent {agent} as operated by {operator}: the group carrying the \
             operator's personal did_key is not the operator's own (migration 105, RVK02: a \
             squatted key). An operator must inspect and remove the squatting group. \
             Database: {message}"
        ),
        other => format!(
            "could not record agent {agent} as operated by {operator} \
             (epigraph_link_operator is EXECUTE-able by epigraph_maintenance only; on an \
             epigraph_app DSN the host must record the link on a maintenance connection \
             instead): {other}"
        ),
    }
}

/// Record `operator` as the operator of this server's own signer agent and log
/// the outcome. Resolves (and on first boot creates) the signer agent first.
///
/// A revoked link is REPORTED, not repaired: the membership stays revoked, the
/// process authors into its own personal group, and this logs a warning.
///
/// # Errors
/// The agent could not be resolved, or `epigraph_link_operator` refused — most
/// importantly `42501 permission denied` on an `epigraph_app` DSN, and 105's
/// `RVK01` / `RVK02` on the operator's own personal group
/// ([`link_refusal_text`]). `main` exits on any error: a declared operator that
/// cannot be recorded must be loud.
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
        .map_err(|e| link_refusal_text(agent, operator, &e))?;
    match LinkStatus::of(&outcome) {
        LinkStatus::Live => tracing::info!(
            agent = %agent,
            operator = %operator,
            operator_group = %outcome.operator_group_id,
            group_created = outcome.group_created,
            membership_created = outcome.membership_created,
            edge_created = outcome.edge_created,
            "operator link recorded: this agent authors into the operator's personal group"
        ),
        LinkStatus::Revoked => tracing::warn!(
            agent = %agent,
            operator = %operator,
            operator_group = %outcome.operator_group_id,
            "operator link is REVOKED for this agent and was deliberately NOT restored; this \
             process authors into its own personal group and holds no operator ownership"
        ),
        LinkStatus::Retired => tracing::warn!(
            agent = %agent,
            operator = %operator,
            operator_group = %outcome.operator_group_id,
            "operator link is RETIRED for this agent: its claims belong to the operator, but a \
             retired identity is never promoted to act for it (its key may be exposed). This \
             process authors into its own personal group and holds no operator ownership"
        ),
        LinkStatus::NotLive => tracing::warn!(
            agent = %agent,
            operator = %operator,
            operator_group = %outcome.operator_group_id,
            "operator link is NOT LIVE for this agent although its membership in the operator's \
             group is: the membership's role is no longer writer/admin. This process authors \
             into its own personal group and holds no operator ownership"
        ),
    }
    Ok(outcome)
}

/// What a [`self_link`] outcome means for this process, as the startup log
/// states it.
///
/// Keyed on [`OperatorLinkOutcome::link_live`] — the answer of the same
/// `epigraph_operator_actor` read the authoring and ownership paths use — and NOT
/// on `membership_live`. A live membership is necessary, not sufficient: with
/// its role changed to `reader` the membership is live and the link is not,
/// and logging "authors into the operator's group" then would be false.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    /// The link is live: this agent authors into the operator's group.
    Live,
    /// The agent's link record is RETIRED (migration 107 section 7) and is never
    /// promoted to an acting link.
    Retired,
    /// The agent's membership was revoked and deliberately not restored.
    Revoked,
    /// The membership is live but the link is not (its role is no longer
    /// `writer`/`admin`).
    NotLive,
}

impl LinkStatus {
    /// Classify one outcome. Pure, so every arm is unit-testable.
    #[must_use]
    pub fn of(outcome: &OperatorLinkOutcome) -> Self {
        if outcome.link_live {
            Self::Live
        } else if outcome.link_retired {
            Self::Retired
        } else if !outcome.membership_live {
            Self::Revoked
        } else {
            Self::NotLive
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{check_operator_transport, LinkStatus};
    use epigraph_db::OperatorLinkOutcome;
    use uuid::Uuid;

    fn outcome(membership_live: bool, link_live: bool) -> OperatorLinkOutcome {
        OperatorLinkOutcome {
            operator_group_id: Uuid::nil(),
            group_created: false,
            membership_created: false,
            membership_live,
            edge_created: false,
            link_live,
            link_retired: false,
        }
    }

    #[test]
    fn a_retired_link_is_reported_as_retired_not_revoked() {
        let retired = OperatorLinkOutcome {
            link_retired: true,
            ..outcome(false, false)
        };
        assert_eq!(LinkStatus::of(&retired), LinkStatus::Retired);
    }

    #[test]
    fn a_live_membership_that_is_not_a_live_link_is_not_reported_as_live() {
        // The review's probe: role set to 'reader', then re-link. The
        // membership is live, the link is not, and the log must say so.
        assert_eq!(LinkStatus::of(&outcome(true, false)), LinkStatus::NotLive);
        assert_eq!(LinkStatus::of(&outcome(true, true)), LinkStatus::Live);
        assert_eq!(LinkStatus::of(&outcome(false, false)), LinkStatus::Revoked);
    }

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

    #[test]
    fn the_personal_group_refusals_name_their_cause_not_the_grant() {
        let (a, o) = (Uuid::new_v4(), Uuid::new_v4());
        let revoked = super::link_refusal_text(
            a,
            o,
            &epigraph_db::DbError::MembershipRevoked {
                message: "m".into(),
            },
        );
        assert!(revoked.contains("RVK01") && !revoked.contains("EXECUTE-able"), "{revoked}");
        let squat = super::link_refusal_text(
            a,
            o,
            &epigraph_db::DbError::PersonalGroupNotOwned {
                message: "m".into(),
            },
        );
        assert!(squat.contains("RVK02") && !squat.contains("EXECUTE-able"), "{squat}");
        let other = super::link_refusal_text(
            a,
            o,
            &epigraph_db::DbError::QueryFailed {
                source: sqlx::Error::RowNotFound,
            },
        );
        assert!(other.contains("EXECUTE-able"), "{other}");
    }
}
