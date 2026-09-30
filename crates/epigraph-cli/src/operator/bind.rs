//! `link`: record a LIVE operator link for one agent, on the maintenance DSN
//! (migration 107's `epigraph_link_operator`), so the agent is BOUND to a human
//! operator (migration 122) and its claims are admitted once the database is
//! armed.
//!
//! # Why this command exists
//!
//! Under operator decision D9 a request-serving process holds only an
//! `epigraph_app` DSN, and `epigraph_link_operator` is EXECUTE-able by the
//! maintenance role only, so a stdio agent can no longer record its own link at
//! startup (it gets 42501). The host records it here, BEFORE it starts the
//! agent; the agent's startup then finds the live link and starts without
//! calling the link function (`epigraph_mcp::operator::self_link`).
//!
//! # Naming the agent
//!
//! * `--agent <uuid>`: an existing agent.
//! * `--agent-model <m> --agent-system-prompt-hash <h>`: the identity a stdio
//!   `epigraph-mcp` derives from the same pair
//!   (`epigraph_crypto::keypair_from_llm_agent_prehashed`). A host can therefore
//!   link a fleet agent before its first start: if no agent carries that public
//!   key yet, this creates it exactly as `epigraph-mcp` would (display name
//!   `mcp-agent`, then the LLM provenance properties), so the process adopts
//!   the same row. A changed prompt file is a changed hash, i.e. a NEW agent
//!   that needs its own link: run this at every spawn, it is idempotent.
//!
//! # Refusals of its own, before anything is written
//!
//! * the OPERATOR must be a human operator (`epigraph_is_human_operator`,
//!   migration 122 arm (a)): a live link to anything else would not bind the
//!   agent to a human at all;
//! * the AGENT must hold no un-revoked OAuth client: an agent with any operator
//!   link is refused a token and a viewer over HTTP (operated agents are
//!   stdio-only, migration 107), so linking an HTTP principal would silently
//!   cut it off. That is an operator decision, not something a link command
//!   decides by side effect.
//!
//! Every other refusal is the link function's (a self-link, a second operator,
//! a two-hop chain, a shared-signer fingerprint, 105's RVK01/RVK02), reported
//! with its own text. A dry run (the default) runs the whole thing, agent
//! creation included, in one transaction and rolls it back.
//!
//! # Writer rows in another human's groups (review SEC-9)
//!
//! A link makes the agent write only where its operator writes (migration
//! 122 section 1b), but a `writer`/`admin` row the agent ALREADY holds in a
//! group the operator does not write survives the link, and lets it write
//! evidence, edges and beliefs there. Every such row (other than the agent's
//! own personal group) is printed as a `FOREIGN-WRITE` line, and
//! `--revoke-foreign-writes` revokes them in the same transaction as the link.
//! Not a refusal: any application session can enrol an unlinked agent as a
//! writer in its own group, so refusing on these rows would let any session
//! strand a new agent.

use anyhow::{bail, Context};
use epigraph_db::{AgentRepository, OperatorLinkOutcome};
use sqlx::PgConnection;
use uuid::Uuid;

/// How the agent is named on the command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentSpec {
    /// An existing agent id.
    Id(Uuid),
    /// A stdio `epigraph-mcp` identity: `(model, lowercase-hex BLAKE3 hash)`.
    Llm { model: String, prompt_hash: String },
}

impl AgentSpec {
    /// Build from the three optional flags, refusing every combination but
    /// exactly one naming.
    ///
    /// # Errors
    /// Neither or both namings; a model without a hash (or the reverse); an
    /// empty model; a hash that is not 64 lowercase hex characters (what
    /// `blake3::Hash::to_hex` renders, and so what `epigraph-mcp` seeds with).
    pub fn from_flags(
        agent: Option<Uuid>,
        model: Option<String>,
        prompt_hash: Option<String>,
    ) -> anyhow::Result<Self> {
        match (agent, model, prompt_hash) {
            (Some(id), None, None) => Ok(Self::Id(id)),
            (None, Some(model), Some(prompt_hash)) => {
                if model.trim().is_empty() {
                    bail!("--agent-model is empty");
                }
                if prompt_hash.len() != 64
                    || !prompt_hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    bail!(
                        "--agent-system-prompt-hash must be the 64-character lowercase-hex \
                         BLAKE3 hash epigraph-mcp seeds its identity with"
                    );
                }
                Ok(Self::Llm {
                    model: model.trim().to_string(),
                    prompt_hash,
                })
            }
            (None, None, None) => bail!(
                "name the agent: --agent <uuid>, or --agent-model with --agent-system-prompt-hash"
            ),
            _ => bail!(
                "name the agent ONE way: --agent <uuid>, or --agent-model together with \
                 --agent-system-prompt-hash"
            ),
        }
    }

    /// The public key a stdio `epigraph-mcp` would sign with, for an LLM
    /// identity.
    #[must_use]
    pub fn public_key(&self) -> Option<[u8; 32]> {
        match self {
            Self::Id(_) => None,
            Self::Llm { model, prompt_hash } => Some(
                epigraph_crypto::keypair_from_llm_agent_prehashed(model, prompt_hash).public_key(),
            ),
        }
    }
}

/// What `link` did (or, in a dry run, would have done).
#[derive(Debug)]
pub struct BindOutcome {
    pub agent: Uuid,
    /// The agent row was created by this run (an LLM identity seen for the
    /// first time).
    pub agent_created: bool,
    pub link: OperatorLinkOutcome,
    /// Groups (other than the agent's own personal group) in which the agent
    /// holds a live writer/admin row and the operator does not write.
    pub foreign_writes: Vec<Uuid>,
    /// Those rows were revoked by this run (`--revoke-foreign-writes`).
    pub foreign_revoked: bool,
}

/// The groups, other than `agent`'s own personal group, in which `agent` holds
/// a live writer/admin row that `operator` does not write: migration 122's
/// `foreign_write_authority` predicate, the one the legacy tie skips on.
///
/// # Errors
/// A failed read.
pub async fn foreign_writes(
    conn: &mut PgConnection,
    agent: Uuid,
    operator: Uuid,
) -> anyhow::Result<Vec<Uuid>> {
    Ok(sqlx::query_scalar(
        "SELECT m.group_id FROM group_memberships m JOIN groups g ON g.id = m.group_id \
          WHERE m.agent_id = $1 AND m.revoked_at IS NULL AND m.role IN ('writer', 'admin') \
            AND NOT (g.kind = 'personal' AND g.created_by_agent_id = $1) \
            AND NOT public.epigraph_operator_writes_group($2, m.group_id) \
          ORDER BY m.group_id",
    )
    .bind(agent)
    .bind(operator)
    .fetch_all(&mut *conn)
    .await?)
}

/// Resolve (and, for a first-seen LLM identity, create) the agent, on `conn`.
async fn resolve_agent(conn: &mut PgConnection, spec: &AgentSpec) -> anyhow::Result<(Uuid, bool)> {
    match spec {
        AgentSpec::Id(id) => {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM agents WHERE id = $1)")
                    .bind(id)
                    .fetch_one(&mut *conn)
                    .await?;
            if !exists {
                bail!("agent {id} does not exist");
            }
            Ok((*id, false))
        }
        AgentSpec::Llm { .. } => {
            let key = spec.public_key().expect("an LLM spec has a key");
            if let Some(a) = AgentRepository::get_by_public_key(&mut *conn, &key).await? {
                return Ok((a.id.as_uuid(), false));
            }
            // Exactly what `EpiGraphMcpFull::agent_id` creates on first boot.
            let agent = epigraph_core::Agent::new(key, Some("mcp-agent".to_string()));
            let created = AgentRepository::create_conn(&mut *conn, &agent)
                .await
                .context("creating the agent row for this LLM identity")?;
            Ok((created.id.as_uuid(), true))
        }
    }
}

/// The two refusals this command adds (see the module doc). Read-only.
///
/// # Errors
/// A refusal, or a failed read.
async fn refuse(conn: &mut PgConnection, agent: Uuid, operator: Uuid) -> anyhow::Result<()> {
    let human: bool = sqlx::query_scalar("SELECT public.epigraph_is_human_operator($1)")
        .bind(operator)
        .fetch_one(&mut *conn)
        .await
        .context("asking whether the operator is a human operator (is migration 122 applied?)")?;
    if !human {
        bail!(
            "operator {operator} is not a human operator: a human operator needs BOTH a live \
             row in the human_operators registry and an active human OAuth client (register \
             one with `epigraph-operator register-human-operator --agent <id> --apply`). A live \
             link to it would not bind agent {agent} to a human; refusing."
        );
    }
    let clients: Vec<(String, String)> = sqlx::query_as(
        "SELECT client_type::text, status::text FROM oauth_clients \
          WHERE agent_id = $1 AND status <> 'revoked' ORDER BY created_at",
    )
    .bind(agent)
    .fetch_all(&mut *conn)
    .await?;
    if !clients.is_empty() {
        bail!(
            "agent {agent} is the principal of {} un-revoked OAuth client(s) ({:?}). An agent with \
             any operator link is refused a token and a viewer over HTTP (operated agents are \
             stdio-only, migration 107), so linking it would cut its HTTP access off. Decide that \
             first (docs/tenancy.md, \"Operator binding\"); refusing.",
            clients.len(),
            clients
        );
    }
    Ok(())
}

/// Resolve the agent, apply the refusals, and record the live link, in ONE
/// transaction that is committed under `apply` and rolled back otherwise. Under
/// `apply` a newly created LLM agent then gets its provenance properties
/// (best effort, as `epigraph-mcp` does it).
///
/// # Errors
/// A refusal (this module's or the link function's), or a failed statement.
pub async fn run(
    pool: &sqlx::PgPool,
    conn: &mut PgConnection,
    spec: &AgentSpec,
    operator: Uuid,
    revoke_foreign_writes: bool,
    apply: bool,
) -> anyhow::Result<BindOutcome> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let (agent, agent_created) = resolve_agent(&mut tx, spec).await?;
    refuse(&mut tx, agent, operator).await?;
    let foreign = foreign_writes(&mut tx, agent, operator).await?;
    if revoke_foreign_writes && !foreign.is_empty() {
        sqlx::query(
            "UPDATE group_memberships SET revoked_at = now() \
              WHERE agent_id = $1 AND group_id = ANY($2) AND revoked_at IS NULL \
                AND role IN ('writer', 'admin')",
        )
        .bind(agent)
        .bind(&foreign)
        .execute(&mut *tx)
        .await
        .context("revoking the agent's writer rows in groups its operator does not write")?;
    }
    let link = AgentRepository::link_operator(&mut tx, agent, operator)
        .await
        .map_err(|e| anyhow::anyhow!("{}", super::link::refusal_text(operator, &e)))?;
    if apply {
        tx.commit().await?;
        if agent_created {
            if let AgentSpec::Llm { model, prompt_hash } = spec {
                if let Err(e) =
                    AgentRepository::set_llm_properties(pool, agent, model, prompt_hash).await
                {
                    eprintln!(
                        "warning: agent {agent} was created and linked, but its LLM provenance \
                         properties were not recorded: {e}"
                    );
                }
            }
        }
    } else {
        tx.rollback().await?;
    }
    Ok(BindOutcome {
        agent,
        agent_created,
        link,
        foreign_revoked: revoke_foreign_writes && !foreign.is_empty(),
        foreign_writes: foreign,
    })
}

/// One `FOREIGN-WRITE` line per group in [`BindOutcome::foreign_writes`].
#[must_use]
pub fn describe_foreign(o: &BindOutcome, apply: bool) -> Vec<String> {
    let state = match (o.foreign_revoked, apply) {
        (true, true) => "REVOKED",
        (true, false) => "WOULD BE REVOKED",
        (false, _) => "KEPT (pass --revoke-foreign-writes to revoke it)",
    };
    o.foreign_writes
        .iter()
        .map(|g| {
            format!(
                "FOREIGN-WRITE\tagent={}\tgroup={g}\ta writer/admin row in a group its operator \
                 does not write: {state}",
                o.agent
            )
        })
        .collect()
}

/// One line for the operator. A link that is not LIVE after the call (the
/// agent's link is retired, or its membership was revoked and is never revived)
/// is reported as NOT BOUND BY A LIVE LINK, which the binary treats as a failure.
#[must_use]
pub fn describe(o: &BindOutcome, operator: Uuid, apply: bool) -> String {
    let verb = if apply { "" } else { "WOULD BE " };
    let created = if o.agent_created {
        " (agent created for this identity)"
    } else {
        ""
    };
    if o.link.link_live {
        format!(
            "{verb}LINKED-LIVE\tagent={}\toperator={operator}\toperator_group={}\t\
             membership_created={}{created}",
            o.agent, o.link.operator_group_id, o.link.membership_created
        )
    } else if o.link.link_retired {
        format!(
            "NOT-LIVE\tagent={}\toperator={operator}\tthe agent's link is RETIRED, and a retired \
             identity is never promoted; this agent cannot write once binding is armed",
            o.agent
        )
    } else {
        format!(
            "NOT-LIVE\tagent={}\toperator={operator}\tthe agent's membership in the operator's \
             group is revoked or not writer/admin, and it is never revived here",
            o.agent
        )
    }
}

#[cfg(test)]
mod tests {
    use super::AgentSpec;
    use uuid::Uuid;

    #[test]
    fn exactly_one_naming_is_accepted() {
        let id = Uuid::new_v4();
        let h = "ab".repeat(32);
        assert_eq!(
            AgentSpec::from_flags(Some(id), None, None).unwrap(),
            AgentSpec::Id(id)
        );
        assert!(matches!(
            AgentSpec::from_flags(None, Some(" m ".into()), Some(h.clone())).unwrap(),
            AgentSpec::Llm { ref model, .. } if model == "m"
        ));
        for (a, m, p) in [
            (None, None, None),
            (Some(id), Some("m".to_string()), Some(h.clone())),
            (None, Some("m".to_string()), None),
            (None, None, Some(h.clone())),
            (None, Some(" ".to_string()), Some(h.clone())),
            (None, Some("m".to_string()), Some("AB".repeat(32))),
            (None, Some("m".to_string()), Some("ab".repeat(31))),
        ] {
            assert!(
                AgentSpec::from_flags(a, m.clone(), p.clone()).is_err(),
                "{a:?} {m:?} {p:?} must be refused"
            );
        }
    }

    #[test]
    fn an_llm_identity_derives_the_key_epigraph_mcp_signs_with() {
        let h = "cd".repeat(32);
        let spec = AgentSpec::from_flags(None, Some("model-x".into()), Some(h.clone())).unwrap();
        assert_eq!(
            spec.public_key().unwrap(),
            epigraph_crypto::keypair_from_llm_agent_prehashed("model-x", &h).public_key()
        );
    }
}
