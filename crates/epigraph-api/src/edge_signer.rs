//! The API server's OWN entity signing key for the edges HTTP writers insert
//! (ruling R-50; backlog `dae795f8`).
//!
//! `epigraph-mcp` attests every edge it writes with its server key (R-49).
//! The API gets a separate key, held by a separate signer agent, so an HTTP
//! edge is attested too and an API signature is never an MCP one.
//!
//! # Configuration
//!
//! [`ENV_KEY_FILE`] (`EPIGRAPH_API_SIGNING_KEY_FILE`) names a file holding the
//! 32-byte Ed25519 private key as 64 hex characters (surrounding whitespace
//! ignored). Its own variable on purpose: the MCP server's key variables
//! (`EPIGRAPH_MCP_AGENT_KEY`, `EPIGRAPH_AGENT_SIGNING_KEY`) are never read
//! here, so an environment file shared by both units cannot make the API sign
//! as the MCP agent. The key never appears in a log line or a `Debug` print.
//!
//! * **Unset**: the API writes its edges unsigned, as before, and says so ONCE
//!   at boot (the ruling: no fail-closed boot on an absent key).
//! * **Set but unusable** (unreadable file, not 64 hex characters, or a key
//!   registered in `agent_keys` that is not an active, in-window `signing` key
//!   of exactly one agent): the server refuses to start. An operator who
//!   configured a key believes HTTP edges are being signed; serving unsigned
//!   would make that silently false.
//!
//! # The signer agent, and rotation
//!
//! The agent recorded as `edges.signer_id` is resolved from the key at boot,
//! by the same admission rule the edge verifier applies
//! (`agent_key::key_window_admits` / `admitted_signature_keys`):
//!
//! 1. the key is registered in `agent_keys`: it must be an ACTIVE `signing`
//!    key, inside its window now, of exactly one agent, and that agent signs
//!    (the separate-signing-key shape the MCP server uses; rotation = register
//!    the new key as the agent's active `signing` key, rotate the old row, and
//!    point the variable at the new file; no code change);
//! 2. otherwise the agent whose `agents.public_key` is the key;
//! 3. otherwise a new agent is registered with that public key (as the MCP
//!    server does for its own key), named [`SIGNER_DISPLAY_NAME`].
//!
//! The signer is never an edge's author: an edge's author is its source
//! claim's (`backfill_factors::EDGE_QUERY`, the operator's edge-writer read).

use std::sync::Arc;

use chrono::Utc;
use epigraph_crypto::AgentSigner;
use epigraph_db::repos::agent_key::key_window_admits;
use epigraph_db::repos::EdgeSigningKey;
use epigraph_db::{AgentKeyRepository, AgentRepository};
use sqlx::PgPool;
use uuid::Uuid;

/// The variable naming the API's signing key file.
pub const ENV_KEY_FILE: &str = "EPIGRAPH_API_SIGNING_KEY_FILE";

/// The display name of a signer agent this module registers (step 3).
pub const SIGNER_DISPLAY_NAME: &str = "epigraph-api-signer";

/// The boot line when no key is configured.
pub const UNSIGNED_AT_BOOT: &str = "EPIGRAPH_API_SIGNING_KEY_FILE is not set: HTTP edge \
     writers insert their edges UNSIGNED. Provision the API's own signing key to attest them \
     (ruling R-50).";

/// The API's edge signing key: its signer and the agent recorded as
/// `edges.signer_id`.
pub struct ApiEdgeSigner {
    signer: AgentSigner,
    signer_id: Uuid,
}

impl std::fmt::Debug for ApiEdgeSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The public half and the agent only.
        f.debug_struct("ApiEdgeSigner")
            .field("public_key", &hex::encode(self.signer.public_key()))
            .field("signer_id", &self.signer_id)
            .finish()
    }
}

impl ApiEdgeSigner {
    /// A signer whose public key `signer_id`'s registered key is. Tests and
    /// [`load`] construct it.
    #[must_use]
    pub fn new(signer: AgentSigner, signer_id: Uuid) -> Self {
        Self { signer, signer_id }
    }

    /// The key the edge insert primitives take.
    #[must_use]
    pub fn key(&self) -> EdgeSigningKey<'_> {
        EdgeSigningKey {
            signer: &self.signer,
            signer_id: self.signer_id,
        }
    }

    /// The agent recorded as `edges.signer_id`.
    #[must_use]
    pub fn signer_id(&self) -> Uuid {
        self.signer_id
    }
}

/// Parse a key file's text: 64 hex characters, surrounding whitespace ignored.
/// The error names the problem, never the content.
///
/// # Errors
/// When the text is not exactly 32 hex-encoded bytes.
pub fn parse_key_text(text: &str) -> Result<AgentSigner, String> {
    let mut bytes = hex::decode(text.trim()).map_err(|_| {
        format!("{ENV_KEY_FILE}: the file is not a hex-encoded Ed25519 private key")
    })?;
    let parsed = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        format!(
            "{ENV_KEY_FILE}: the key is {} bytes; an Ed25519 private key is 32",
            bytes.len()
        )
    });
    bytes.fill(0);
    let mut secret = parsed?;
    let signer = AgentSigner::from_bytes(&secret)
        .map_err(|e| format!("{ENV_KEY_FILE}: not a usable Ed25519 private key: {e}"));
    secret.fill(0);
    signer
}

/// The agent `signer` signs for (see the module docs, "The signer agent").
///
/// # Errors
/// When the key is registered in `agent_keys` but is not an active, in-window
/// `signing` key of exactly one agent, or a database call fails.
pub async fn resolve_signer_agent(pool: &PgPool, signer: &AgentSigner) -> Result<Uuid, String> {
    let public_key = signer.public_key();
    let rows = AgentKeyRepository::rows_with_public_key(pool, &public_key)
        .await
        .map_err(|e| format!("{ENV_KEY_FILE}: could not read agent_keys: {e}"))?;
    if !rows.is_empty() {
        let now = Utc::now();
        let mut agents: Vec<Uuid> = rows
            .iter()
            .filter(|r| {
                r.key_type == "signing"
                    && key_window_admits(&r.status, r.valid_from, r.valid_until, now)
                    && r.status == "active"
            })
            .map(|r| r.agent_id)
            .collect();
        agents.sort_unstable();
        agents.dedup();
        return match agents.as_slice() {
            [agent] => Ok(*agent),
            [] => Err(format!(
                "{ENV_KEY_FILE}: the key ({}) is registered in agent_keys but is not an \
                 active, in-window signing key of any agent; register it as the signer \
                 agent's active signing key or point the variable at its current key",
                hex::encode(public_key)
            )),
            _ => Err(format!(
                "{ENV_KEY_FILE}: the key ({}) is an active signing key of {} agents; it \
                 must name exactly one signer",
                hex::encode(public_key),
                agents.len()
            )),
        };
    }
    if let Some(agent) = AgentRepository::get_by_public_key(pool, &public_key)
        .await
        .map_err(|e| format!("{ENV_KEY_FILE}: could not read agents: {e}"))?
    {
        return Ok(agent.id.as_uuid());
    }
    let created = AgentRepository::create(
        pool,
        &epigraph_core::Agent::new(public_key, Some(SIGNER_DISPLAY_NAME.to_string())),
    )
    .await
    .map_err(|e| format!("{ENV_KEY_FILE}: could not register the signer agent: {e}"))?;
    Ok(created.id.as_uuid())
}

/// The API's signer from `key_file` (the value of [`ENV_KEY_FILE`]).
/// `Ok(None)` when unset or empty.
///
/// # Errors
/// When a key is configured and cannot be used (see the module docs).
pub async fn load(pool: &PgPool, key_file: Option<&str>) -> Result<Option<ApiEdgeSigner>, String> {
    let Some(path) = key_file.map(str::trim).filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    let mut text = std::fs::read_to_string(path)
        .map_err(|e| format!("{ENV_KEY_FILE}: cannot read the key file: {}", e.kind()))?;
    let signer = parse_key_text(&text);
    // Overwrite the key text before it is dropped (in place: `clear` keeps the
    // buffer, and the same length fits it).
    let len = text.len();
    text.clear();
    text.extend(std::iter::repeat_n('0', len));
    let signer = signer?;
    let signer_id = resolve_signer_agent(pool, &signer).await?;
    Ok(Some(ApiEdgeSigner::new(signer, signer_id)))
}

/// [`load`] from the environment, for `bin/server.rs`: logs the outcome once,
/// and exits the process non-zero on a configured key it cannot use.
pub async fn boot(pool: &PgPool) -> Option<Arc<ApiEdgeSigner>> {
    match load(pool, std::env::var(ENV_KEY_FILE).ok().as_deref()).await {
        Ok(Some(s)) => {
            tracing::info!(
                signer_id = %s.signer_id(),
                public_key = %hex::encode(s.signer.public_key()),
                "HTTP edge writers attest their edges with the API's signing key"
            );
            Some(Arc::new(s))
        }
        Ok(None) => {
            tracing::warn!("{UNSIGNED_AT_BOOT}");
            None
        }
        Err(refusal) => {
            eprintln!("ERROR: refusing to start: {refusal}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_file_parses_as_64_hex_characters_and_nothing_else() {
        let hex_key = "11".repeat(32);
        let s = parse_key_text(&format!("  {hex_key}\n")).expect("parses");
        assert_eq!(
            s.public_key(),
            AgentSigner::from_bytes(&[0x11; 32]).unwrap().public_key()
        );
        let short = parse_key_text(&"11".repeat(31)).expect_err("31 bytes");
        assert!(short.contains("31 bytes"), "{short}");
        let junk = parse_key_text("not hex at all").expect_err("not hex");
        assert!(junk.contains("not a hex-encoded"), "{junk}");
        // The error never echoes the file's content.
        let secretish = "zz".repeat(32);
        assert!(!parse_key_text(&secretish).unwrap_err().contains(&secretish));
    }

    #[test]
    fn debug_prints_the_public_half_only() {
        let s = ApiEdgeSigner::new(AgentSigner::from_bytes(&[0x22; 32]).unwrap(), Uuid::nil());
        let dbg = format!("{s:?}");
        assert!(dbg.contains(&hex::encode(s.signer.public_key())), "{dbg}");
        assert!(!dbg.contains(&"22".repeat(32)), "{dbg}");
    }
}
