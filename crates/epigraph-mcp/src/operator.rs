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
//! superusers) only. Under operator decision D9 a request-serving process
//! (every per-agent stdio process included) holds only an `epigraph_app` DSN,
//! where that call fails with `42501`. So the link is recorded OUT OF BAND, by
//! the host, on a maintenance connection, BEFORE the process starts:
//! `epigraph-operator link --agent-model <m> --agent-system-prompt-hash <h>
//! --operator <human> --apply` (or `--agent <id>`). [`self_link`] then reads the
//! ACTOR record first and, when it already names the declared operator, starts
//! without calling the link function at all, so a correctly declared agent on
//! an app DSN is never stranded. Only when no such live link exists does it
//! call the link function, which records it on a maintenance DSN and, on an app
//! DSN, fails with `42501`: [`self_link`] returns that error, naming the
//! command above, and `main` treats it as FATAL — a declared operator the
//! process cannot record is never silently dropped.
//!
//! # Never on a shared HTTP listener
//!
//! An HTTP listener used to author EVERY caller's claims as its one signer
//! agent (before batch H-b), and its principal-less callers still act AS that
//! signer. If that signer were operated, those callers would write into the
//! operator's group and inherit the operator's ownership. So
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
//! "caller is the operator of the claim's author" for every linked agent. And
//! both refuse a signer that is a registered HUMAN operator (migration 122),
//! operating anyone or not, or the agent of an OAuth client on the
//! author-binding allowlist (migration 149): principal-less callers and
//! admin-borrowed writes are written as the signer, so each would author
//! claims as that person, or as a bound agent of that person.
//!
//! ## Why the gate stays strict after batch HTTP-id
//!
//! Since batch H-b an authenticated caller's writes are authored by the
//! caller's own agent, and since batch HTTP-id a caller with no authenticated
//! principal writes nothing unless the listener opts in. So a listener's
//! signer now authors nothing by default, and a FORMER shared signer can be
//! link-retired to its human (migration 116's attested variant). That does
//! not make a retired link on a RUNNING signer safe, and both checks keep
//! refusing one:
//!
//! * the signer is still the READ principal of the principal-less listener
//!   and still signs every digest, so a membership that predates the retire
//!   would widen what that listener's callers read;
//! * "authors nothing" is a runtime property the start-up gate cannot verify
//!   (`--allow-unauthenticated-writes` turns signer authoring back on);
//! * a retired identity's key may be exposed (migration 107 section 7), and a
//!   key that ever served as a shared signer should not run again.
//!
//! The supported sequence is therefore: move the listener to a FRESH
//! `--agent-key`, confirm the former signer authors nothing new, then
//! link-retire it. The refusal texts below say so.
//!
//! Both HTTP checks read the AUTHOR record (`AgentRepository::operator_of_author`,
//! retired links included), not the actor read. That is a REFUSAL-only use of
//! "whose are this agent's claims?": an HTTP signer with any link record would
//! either author into the operator's group (an acting link) or hand the operator
//! ownership of every HTTP caller's claims (either kind), and both are the
//! failure the listener must not serve through.

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;
use epigraph_db::{
    AgentRepository, AuthorOperator, OperatorLinkOutcome, CLIENT_ALLOWLIST_BINDING,
    HUMAN_OPERATOR_BINDING,
};
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
/// retired links included, is the predicate), is itself some agent's
/// OPERATOR (migration 107 section 9), is a registered HUMAN operator
/// (migration 122), or is the agent of an allowlisted OAuth client (migration
/// 149): principal-less callers and admin-borrowed writes are written as the
/// signer, so a human signer would put every such caller's words in that
/// person's mouth, before it operates any agent, and an allowlisted signer
/// would write them as a bound agent of that person.
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
    let binding = AgentRepository::author_binding(&mut conn, agent_id)
        .await
        .map_err(|e| {
            format!(
                "could not check whether this listener's signer agent {agent_id} is a registered \
                 human operator (is migration 122 applied?): {e}"
            )
        })?;
    match binding.as_deref() {
        Some(HUMAN_OPERATOR_BINDING) => Err(human_http_signer_reason(agent_id)),
        Some(CLIENT_ALLOWLIST_BINDING) => Err(allowlisted_http_signer_reason(agent_id)),
        _ => Ok(()),
    }
}

/// The refusal text for a signer that is a registered HUMAN OPERATOR
/// (migration 122 section 1c).
fn human_http_signer_reason(agent_id: Uuid) -> String {
    format!(
        "this HTTP listener's signer agent {agent_id} is a registered human operator. Every \
         principal-less caller of this listener, and every admin-borrowed write, is written as \
         the signer, so each would author claims as that human. Run the listener under a \
         different --agent-key; a listener's signer is never a person."
    )
}

/// The refusal text for a signer that is the agent of an OAuth client on the
/// author-binding allowlist (migration 149), and so bound to a human operator.
fn allowlisted_http_signer_reason(agent_id: Uuid) -> String {
    format!(
        "this HTTP listener's signer agent {agent_id} is the agent of an allowlisted OAuth \
         client, bound to a registered human operator (migration 149). Every principal-less \
         caller of this listener, and every admin-borrowed write, is written as the signer, so \
         each would write as a bound agent of that human. Run the listener under a different \
         --agent-key."
    )
}

/// The refusal text shared by the startup gate and the per-call guard.
fn linked_http_signer_reason(agent_id: Uuid, link: &AuthorOperator) -> String {
    let kind = if link.retired {
        "a retired link"
    } else {
        "an acting link"
    };
    format!(
        "this HTTP listener's signer agent {agent_id} has an operator link to {} ({kind}). A \
         listener's principal-less callers act as that one agent and it signs every digest, so \
         serving under it would lend them the operator's ownership. Run the listener under a \
         FRESH --agent-key (a retired former signer's key must not run again); the link record \
         is permanent.",
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
/// server's signer is anyone's OPERATOR (107 section 9), or a registered human
/// operator (migration 122). Fails closed.
async fn refuse_operator_http_signer(
    server: &EpiGraphMcpFull,
    agent_id: Uuid,
) -> Result<(), McpError> {
    match AgentRepository::operates_agents_pool(&server.pool, agent_id).await {
        Ok(false) => refuse_human_http_signer(server, agent_id).await,
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

/// The human half of [`refuse_linked_http_signer`]: refuse while this server's
/// signer is a registered human operator (migration 122), or the agent of an
/// allowlisted OAuth client (migration 149). Fails closed.
async fn refuse_human_http_signer(
    server: &EpiGraphMcpFull,
    agent_id: Uuid,
) -> Result<(), McpError> {
    match AgentRepository::author_binding_pool(&server.pool, agent_id).await {
        Ok(b) if b.as_deref() == Some(HUMAN_OPERATOR_BINDING) => {
            let reason = human_http_signer_reason(agent_id);
            tracing::error!(agent = %agent_id, "refusing an HTTP tool call: {reason}");
            Err(internal_error(format!("refused: {reason}")))
        }
        Ok(b) if b.as_deref() == Some(CLIENT_ALLOWLIST_BINDING) => {
            let reason = allowlisted_http_signer_reason(agent_id);
            tracing::error!(agent = %agent_id, "refusing an HTTP tool call: {reason}");
            Err(internal_error(format!("refused: {reason}")))
        }
        Ok(_) => Ok(()),
        Err(e) => {
            tracing::error!(
                agent = %agent_id,
                error = %e,
                "refusing an HTTP tool call: could not check whether the signer is a human operator"
            );
            Err(internal_error(format!(
                "refused: could not verify that this HTTP listener's signer agent {agent_id} \
                 is not a registered human operator: {e}"
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
/// not faults, and each gets its own text. So does migration 149's link guard
/// (the signer is the agent of an allowlisted HTTP OAuth client, which a link
/// would make stdio-only). Everything else keeps the EXECUTE-grant hint,
/// because on a stdio host the usual cause is an `epigraph_app` DSN (`42501`).
pub fn link_refusal_text(agent: Uuid, operator: Uuid, e: &epigraph_db::DbError) -> String {
    link_refusal_text_for(agent, operator, None, e)
}

/// The stable fragment of migration 149's link-guard message
/// (`epigraph_operator_links_refuse_allowlisted_agent`); the guard's SQLSTATE
/// (55000) is shared with other link refusals, so the text decides.
const ALLOWLIST_LINK_REFUSAL: &str = "on the author-binding allowlist";

/// [`link_refusal_text`] for a process that knows its LLM identity
/// (`--agent-model` + prompt hash): the printed fix then names that identity
/// (`epigraph-operator link --agent-model <m> --agent-system-prompt-hash <h>`),
/// which also records the agent's LLM provenance properties, where the
/// `--agent <id>` form would link a row an app DSN could not annotate (review
/// C5).
pub fn link_refusal_text_for(
    agent: Uuid,
    operator: Uuid,
    llm: Option<(&str, &str)>,
    e: &epigraph_db::DbError,
) -> String {
    let fix = match llm {
        Some((model, hash)) => format!(
            "`epigraph-operator link --agent-model {model} --agent-system-prompt-hash {hash} \
             --operator {operator} --apply`"
        ),
        None => format!("`epigraph-operator link --agent {agent} --operator {operator} --apply`"),
    };
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
        allowlisted if allowlisted.to_string().contains(ALLOWLIST_LINK_REFUSAL) => format!(
            "refused to record agent {agent} as operated by {operator}: this signer agent is \
             also the agent of an OAuth client on the author-binding allowlist (migration 149), \
             and a link would make it stdio-only, ending that client's HTTP access. Revoke the \
             allowance first (`epigraph-operator revoke-author-binding-client --client <id> \
             --reason <text> --apply`), or run this stdio process under a different key. \
             Database: {allowlisted}"
        ),
        other => format!(
            "could not record agent {agent} as operated by {operator} \
             (epigraph_link_operator is EXECUTE-able by epigraph_maintenance only; on an \
             epigraph_app DSN the host records the link on a maintenance connection BEFORE \
             starting this process: {fix} with EPIGRAPH_OPERATOR_MAINTENANCE_DSN set): {other}"
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
    // A live link the host already recorded on a maintenance connection (D9:
    // this process may hold only an app DSN, where the link function is 42501).
    // Read through the SAME actor read the authoring path uses; a link to a
    // DIFFERENT operator is not accepted here and falls through to the link
    // call, which refuses it by name.
    if let Some(outcome) = recorded_live_link(&mut conn, agent, operator).await? {
        tracing::info!(
            agent = %agent,
            operator = %operator,
            operator_group = %outcome.operator_group_id,
            "operator link recorded: this agent authors into the operator's personal group \
             (live link recorded out of band on a maintenance connection; not re-linked)"
        );
        return Ok(outcome);
    }
    let outcome = AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .map_err(|e| {
            let llm = server
                .llm_identity
                .as_ref()
                .map(|(m, h)| (m.as_str(), h.as_str()));
            link_refusal_text_for(agent, operator, llm, &e)
        })?;
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

/// The outcome of an ACTING link to `operator` that is already recorded for
/// `agent`, or `None`. Read with `epigraph_operator_actor`, which an
/// `epigraph_app` session may call, so it answers on the DSN a D9 process holds.
/// An acting link is, by that read's definition, not retired, with a live
/// writer/admin membership in the operator's own group, so the synthesised
/// outcome reports exactly that and claims nothing was created.
///
/// # Errors
/// The read fails (fail closed: a process that cannot ask does not start).
async fn recorded_live_link(
    conn: &mut sqlx::PgConnection,
    agent: Uuid,
    operator: Uuid,
) -> Result<Option<OperatorLinkOutcome>, String> {
    let actor = AgentRepository::operator_actor(conn, agent)
        .await
        .map_err(|e| {
            format!(
                "could not read whether agent {agent} already acts for operator {operator} \
                 (is migration 107 applied?): {e}"
            )
        })?;
    Ok(actor
        .filter(|link| link.operator_id == operator)
        .map(|link| OperatorLinkOutcome {
            operator_group_id: link.operator_group_id,
            group_created: false,
            membership_created: false,
            membership_live: true,
            edge_created: false,
            link_live: true,
            link_retired: false,
        }))
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
        assert!(
            revoked.contains("RVK01") && !revoked.contains("EXECUTE-able"),
            "{revoked}"
        );
        let squat = super::link_refusal_text(
            a,
            o,
            &epigraph_db::DbError::PersonalGroupNotOwned {
                message: "m".into(),
            },
        );
        assert!(
            squat.contains("RVK02") && !squat.contains("EXECUTE-able"),
            "{squat}"
        );
        let other = super::link_refusal_text(
            a,
            o,
            &epigraph_db::DbError::QueryFailed {
                source: sqlx::Error::RowNotFound,
            },
        );
        assert!(other.contains("EXECUTE-able"), "{other}");
        assert!(other.contains(&format!("--agent {a}")), "{other}");
        // Review C5: an LLM identity is told the form that records its
        // provenance, not the bare `--agent <id>` one.
        let llm = super::link_refusal_text_for(
            a,
            o,
            Some(("model-m", "abcd")),
            &epigraph_db::DbError::QueryFailed {
                source: sqlx::Error::RowNotFound,
            },
        );
        assert!(
            llm.contains("--agent-model model-m --agent-system-prompt-hash abcd")
                && !llm.contains(&format!("--agent {a}")),
            "{llm}"
        );
    }

    /// Migration 149's link guard refuses to link the agent of an allowlisted
    /// OAuth client (a link would make it stdio-only). A stdio process on such
    /// a signer is told THAT, and the remedy, not the EXECUTE-grant hint.
    #[test]
    fn an_allowlisted_signers_link_refusal_names_the_allowlist_not_the_grant() {
        let (a, o) = (Uuid::new_v4(), Uuid::new_v4());
        let text = super::link_refusal_text(
            a,
            o,
            &epigraph_db::DbError::QueryFailed {
                source: sqlx::Error::Protocol(format!(
                    "agent {a} is the agent of OAuth client c, which is on the author-binding \
                     allowlist; a linked agent is stdio-only"
                )),
            },
        );
        assert!(
            text.contains("revoke-author-binding-client") && !text.contains("EXECUTE-able"),
            "{text}"
        );
    }
}
