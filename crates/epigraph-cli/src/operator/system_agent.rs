//! `register-system-agent`: record which agent IS a system role (migration
//! 148's `system_agents`), e.g. the workflow-ingest system agent every
//! workflow-ingest row and every REST policy challenge is authored by.
//!
//! The registry is written through ONE maintenance-only, audited definer
//! (`epigraph_register_system_agent`); this module calls it in one transaction,
//! committed under `--apply` and rolled back otherwise (the audit row with
//! it), so a dry run prints exactly what the definer did. A registration is
//! IMMUTABLE: there is no revoke and no re-point, so the identity line below is
//! printed BEFORE the definer runs, and a wrong id is visible in the dry run.
//!
//! # The key must still be the legacy one, unless the operator says otherwise
//!
//! Registration snapshots the agent's CURRENT key, and from then on
//! `agents_refuse_registered_system_key` refuses that key to every other
//! agent. That protects the public-constant key only if the agent still holds
//! it when it is registered, i.e. registration happens BEFORE the key is
//! rotated. Registering after a rotation would protect the new secret key and
//! leave the public-constant key free to be re-minted on an unarmed database.
//! So `--apply` REFUSES an agent whose current key is not the role's legacy
//! key unless `--key-not-legacy-ok` is given (an agent that never held the
//! legacy key, e.g. one created with a secret key from the start). A dry run
//! only warns.
//!
//! The identity line is read before the transaction, so the refusal is checked
//! twice: once on that line, and again inside the transaction against the key
//! the definer actually recorded (`registered_public_key`). A rotation that
//! commits in between is therefore refused and rolled back, not registered.

use anyhow::bail;
use epigraph_db::SystemAgentRole;
use sqlx::PgConnection;
use uuid::Uuid;

/// What the operator should see before an immutable registration.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub id: Uuid,
    pub display_name: Option<String>,
    pub key_kind: String,
    /// `none`, `live:<operator>` or `retired:<operator>`.
    pub link: String,
    /// The agent's CURRENT key is the role's legacy public-constant key.
    pub key_is_legacy: bool,
}

/// Parse `--role` against the Rust vocabulary BEFORE any connection, so a typo
/// is refused by this tool with the valid values, not by the table's CHECK.
///
/// # Errors
/// The role is not in [`SystemAgentRole::ALL`].
pub fn parse_role(role: &str) -> anyhow::Result<SystemAgentRole> {
    SystemAgentRole::parse(role).ok_or_else(|| {
        let valid: Vec<&str> = SystemAgentRole::ALL.iter().map(|r| r.as_str()).collect();
        anyhow::anyhow!(
            "unknown system-agent role '{role}' (valid: {}); nothing was done",
            valid.join(", ")
        )
    })
}

/// The identity line's facts for `agent`, or `None` when no such agent exists.
///
/// # Errors
/// A statement failed.
pub async fn identity(
    conn: &mut PgConnection,
    role: SystemAgentRole,
    agent: Uuid,
) -> anyhow::Result<Option<AgentIdentity>> {
    let row: Option<(Option<String>, String, Vec<u8>)> = sqlx::query_as(
        "SELECT a.display_name, a.key_kind::text, a.public_key FROM public.agents a WHERE a.id = $1",
    )
    .bind(agent)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((display_name, key_kind, key)) = row else {
        return Ok(None);
    };
    let link: Option<(Uuid, bool)> = sqlx::query_as(
        "SELECT l.operator_id, l.retired FROM public.operator_links l WHERE l.agent_id = $1 \
          ORDER BY l.retired LIMIT 1",
    )
    .bind(agent)
    .fetch_optional(&mut *conn)
    .await?;
    let link = match link {
        None => "none".to_string(),
        Some((op, false)) => format!("live:{op}"),
        Some((op, true)) => format!("retired:{op}"),
    };
    Ok(Some(AgentIdentity {
        id: agent,
        display_name,
        key_kind,
        link,
        key_is_legacy: key.as_slice() == role.legacy_public_key().as_slice(),
    }))
}

/// The identity line, and the warning a non-legacy key earns.
#[must_use]
pub fn describe_identity(i: &AgentIdentity) -> Vec<String> {
    let mut out = vec![format!(
        "AGENT\tid={}\tdisplay_name={}\tkey_kind={}\tlink={}\tkey={}",
        i.id,
        i.display_name.as_deref().unwrap_or(""),
        i.key_kind,
        i.link,
        if i.key_is_legacy {
            "LEGACY"
        } else {
            "NOT-LEGACY"
        }
    )];
    if !i.key_is_legacy {
        out.push(
            "WARNING\tthis agent does not hold the role's legacy public-constant key. The \
             registration protects the key the agent holds NOW, so the legacy key stays free to be \
             re-created on an unarmed database (register BEFORE rotating the key). --apply \
             refuses this unless --key-not-legacy-ok is given."
                .to_string(),
        );
    }
    out
}

/// What [`register`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The definer registered it (rolled back on a dry run).
    Registered,
    /// It already was, for this same agent.
    AlreadyRegistered,
}

/// Register `agent` as the system agent for `role`, in one transaction:
/// committed under `apply`, rolled back otherwise.
///
/// # Errors
/// `apply` on an agent whose current key is not the legacy key without
/// `key_not_legacy_ok` (nothing was called, or, when the key changed after the
/// identity was read, the call was rolled back); the definer refused (another
/// agent is registered for the role, the agent is a human, an OAuth principal,
/// an operator, retired-linked, missing; a blank reason); or a statement
/// failed.
pub async fn register(
    conn: &mut PgConnection,
    role: SystemAgentRole,
    identity: &AgentIdentity,
    reason: &str,
    apply: bool,
    key_not_legacy_ok: bool,
) -> anyhow::Result<Outcome> {
    if apply && !identity.key_is_legacy && !key_not_legacy_ok {
        bail!(
            "refusing to register {} for the {role} role: its current key is NOT the role's legacy \
             key, so the registration would protect the new key and leave the legacy one free \
             to be re-created. Register BEFORE rotating the key, or pass --key-not-legacy-ok if \
             this agent never held it. Nothing was registered",
            identity.id
        );
    }
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let (now, registered): (bool, Uuid) = sqlx::query_as(
        "SELECT registered_now, registered_agent \
           FROM public.epigraph_register_system_agent($1, $2, $3)",
    )
    .bind(role.as_str())
    .bind(identity.id)
    .bind(reason)
    .fetch_one(&mut *tx)
    .await?;
    if registered != identity.id {
        tx.rollback().await?;
        bail!(
            "the {role} role is registered to {registered}, not {}; nothing was changed (a \
             registration is immutable)",
            identity.id
        );
    }
    // The key the definer snapshotted, not the one the identity line read: a
    // rotation committed in between must not slip past the refusal above.
    if apply && !key_not_legacy_ok {
        let recorded: Vec<u8> = sqlx::query_scalar(
            "SELECT s.registered_public_key FROM public.system_agents s WHERE s.role = $1",
        )
        .bind(role.as_str())
        .fetch_one(&mut *tx)
        .await?;
        if recorded.as_slice() != role.legacy_public_key().as_slice() {
            tx.rollback().await?;
            bail!(
                "refusing to register {} for the {role} role: its key changed after the identity \
                 line was read and is NOT the role's legacy key now, so the registration would \
                 protect the new key. Register BEFORE rotating the key, or pass \
                 --key-not-legacy-ok if this agent never held it. Nothing was registered",
                identity.id
            );
        }
    }
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(if now {
        Outcome::Registered
    } else {
        Outcome::AlreadyRegistered
    })
}
