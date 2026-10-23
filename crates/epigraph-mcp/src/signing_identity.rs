//! The separate-signing-key mode (agent identity lineage design D1, D2): the
//! boot check.
//!
//! # The two keys
//!
//! * The IDENTITY key names the agent (`agents.public_key`). The host derives
//!   it from a secret it never shares, registers the agent under it, and gives
//!   the container only its PUBLIC half (`EPIGRAPH_AGENT_IDENTITY_PUBKEY`). It
//!   signs nothing.
//! * The SIGNING key is random. The host registers its public half for the
//!   agent in `agent_keys` (`key_type 'signing'`, through migration 161's
//!   attestor-only registration) and gives the container the private half
//!   (`EPIGRAPH_AGENT_SIGNING_KEY`). Every signature this process makes is
//!   by it.
//!
//! # Why the boot check
//!
//! A container cannot register a signing key itself (migration 161 section
//! 7a refuses an attested key type to the application role). A signing key the
//! host did not register would produce signatures that verify against nothing
//! the database knows, and `verify_claim` would report them unbound forever.
//! So [`check_signing_key`] refuses to start unless the signing key is an
//! ACTIVE `signing` key of the identity's agent. It only reads: a refused boot
//! leaves no agent row behind.

use epigraph_db::{AgentKeyRepository, AgentKeyRow, AgentRepository};
use sqlx::PgPool;
use uuid::Uuid;

/// Refuse to serve unless `signing_public_key` is an ACTIVE `signing` key of
/// the agent whose identity key is `identity_public_key`. Returns that agent's
/// id. Read-only: nothing is created, so a refused boot leaves no row.
///
/// # Errors
///
/// The operator-facing refusal (it names public keys only; the private key is
/// never in scope here), or a failed read.
pub async fn check_signing_key(
    pool: &PgPool,
    identity_public_key: &[u8; 32],
    signing_public_key: &[u8; 32],
) -> Result<Uuid, String> {
    let identity_hex = hex::encode(identity_public_key);
    let agent = AgentRepository::get_by_public_key(pool, identity_public_key)
        .await
        .map_err(|e| format!("could not look up the identity public key {identity_hex}: {e}"))?
        .ok_or_else(|| {
            format!(
                "no agent has the identity public key {identity_hex} \
                 (EPIGRAPH_AGENT_IDENTITY_PUBKEY). The host registers an identity, with its \
                 signing key, before the container starts; refusing to start rather than create \
                 an unregistered identity."
            )
        })?
        .id
        .as_uuid();
    let rows = AgentKeyRepository::rows_with_public_key(pool, signing_public_key)
        .await
        .map_err(|e| format!("could not read the signing key's agent_keys rows: {e}"))?;
    signing_key_verdict(agent, signing_public_key, &rows)?;
    Ok(agent)
}

/// The pure half of [`check_signing_key`]: admit iff some row of `rows` (all
/// of them carry the signing public key) is an active `signing` key of
/// `agent`; otherwise say what the rows show instead.
fn signing_key_verdict(
    agent: Uuid,
    signing_public_key: &[u8; 32],
    rows: &[AgentKeyRow],
) -> Result<(), String> {
    let norm = |s: &str| s.trim().to_ascii_lowercase();
    if rows.iter().any(|r| {
        r.agent_id == agent && norm(&r.key_type) == "signing" && norm(&r.status) == "active"
    }) {
        return Ok(());
    }
    let signing_hex = hex::encode(signing_public_key);
    let found = if rows.is_empty() {
        "it is registered for no agent".to_string()
    } else {
        rows.iter()
            .map(|r| {
                let whose = if r.agent_id == agent {
                    "this agent".to_string()
                } else {
                    format!("agent {}", r.agent_id)
                };
                format!("a {} key of {whose} with status {}", r.key_type, r.status)
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    Err(format!(
        "the signing key {signing_hex} (public half of EPIGRAPH_AGENT_SIGNING_KEY) is not an \
         active signing key of agent {agent}: {found}. The host registers the signing key \
         (epigraph_register_agent_identity) before the container starts; refusing to start."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_row(agent: Uuid, key_type: &str, status: &str) -> AgentKeyRow {
        let now = chrono::Utc::now();
        AgentKeyRow {
            id: Uuid::new_v4(),
            agent_id: agent,
            public_key: vec![7; 32],
            key_type: key_type.to_string(),
            status: status.to_string(),
            valid_from: now,
            valid_until: None,
            revocation_reason: None,
            revoked_by: None,
            created_at: now,
        }
    }

    /// Exactly an active signing row of the agent admits; every near miss
    /// (other agent, legacy type, rotated, revoked, no row) refuses.
    #[test]
    fn the_verdict_admits_only_an_active_signing_row_of_the_agent() {
        let agent = Uuid::new_v4();
        let other = Uuid::new_v4();
        let pk = [7u8; 32];
        assert!(signing_key_verdict(agent, &pk, &[key_row(agent, "signing", "active")]).is_ok());
        assert!(signing_key_verdict(agent, &pk, &[key_row(agent, " Signing ", "ACTIVE")]).is_ok());
        for rows in [
            vec![],
            vec![key_row(other, "signing", "active")],
            vec![key_row(agent, "identity-legacy", "active")],
            vec![key_row(agent, "signing", "rotated")],
            vec![key_row(agent, "signing", "revoked")],
            vec![key_row(agent, "encryption", "active")],
        ] {
            let err = signing_key_verdict(agent, &pk, &rows).expect_err("refused");
            assert!(err.contains("is not an active signing key of"), "{err}");
        }
    }
}
