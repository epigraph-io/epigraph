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
//!   carried by an ATTESTED `agent_keys` row (`signing`, `identity-legacy`)
//!   that is not an active, in-window `signing` key of exactly one agent): the
//!   server refuses to start. A row of another type is ignored, as the
//!   verifiers ignore it. An operator who
//!   configured a key believes HTTP edges are being signed; serving unsigned
//!   would make that silently false.
//!
//! # The signer agent, and rotation
//!
//! The agent recorded as `edges.signer_id` is resolved from the key at boot,
//! by the same admission rule the edge verifier applies
//! (`agent_key::key_window_admits` / `admitted_signature_keys`):
//!
//! 1. the key is carried by an attested `agent_keys` row: it must be an ACTIVE `signing`
//!    key, inside its window now, of exactly one agent, and that agent signs
//!    (the separate-signing-key shape the MCP server uses);
//! 2. otherwise the agent whose `agents.public_key` is the key. When that is
//!    not a signer agent step 3 registered (display name
//!    [`SIGNER_DISPLAY_NAME`]), the key is another agent's (the MCP server's,
//!    an author's) and the API would sign as it: boot logs a WARNING
//!    ([`NOT_A_DEDICATED_SIGNER`]) and still starts;
//! 3. otherwise a new agent is registered with that public key (as the MCP
//!    server does for its own key), named [`SIGNER_DISPLAY_NAME`], and boot
//!    logs a WARNING ([`REGISTERED_A_SIGNER`]), so an unplanned rotation that
//!    mints a second signer agent is visible.
//!
//! Rotation needs no code change, but it is a maintenance act (`signing` rows
//! are attested state, refused to the application role by migration 161).
//! The NEW key comes first: register it as the signer agent's `active`
//! `signing` row (`valid_from` no later than now) and point the variable at
//! its file, so any restart from then on boots on it. Then retire the OLD key
//! with a cut-over in the future: it must end up in `agent_keys` as a
//! `rotated` row with `valid_until` = the cut-over, because a key that is only
//! an `agents.public_key` (steps 2 and 3) is admitted by the verifier with no
//! window while no row carries its bytes, so without that row a retired key
//! keeps verifying. The running server stops [`STOP_LEAD_SECS`] before the
//! cut-over (below) and restarts on the new key. Retiring the old key first
//! would make boot refuse it (a `rotated` row is not an active one) on any
//! restart before the new key is in place.
//! `docs/architecture/noun-claims-and-verb-edges.md` has the operator steps.
//!
//! The signer is never an edge's author: an edge's author is its source
//! claim's (`backfill_factors::EDGE_QUERY`, the operator's edge-writer read).
//!
//! # While it runs
//!
//! Boot checks the key; [`spawn_admission_watch`] keeps checking it, at once
//! and then every [`ENV_RECHECK_SECS`] seconds (default 30, clamped to
//! 1..=300). Each check asks, on the DATABASE clock (which dates the edges the
//! verifier judges), whether and until when the edge verifier admits the key
//! for the signer agent (`AgentKeyRepository::signer_key_admission`, the
//! verifier's own admission rule). When it is not admitted (revoked, rotated
//! out, window closed) or its recorded window ends within [`STOP_LEAD_SECS`],
//! the watch logs an ERROR ([`KEY_NO_LONGER_ADMITTED`]) and EXITS the process.
//! A known end is not left to the interval: the watch sleeps until the lead
//! before it, so a planned cut-over stops the server before it, and no edge
//! it signs falls outside the key's window. A REVOCATION is only seen at the
//! next check, so edges written in the (at most one interval) between the
//! revocation and that check carry a signature the verifier refuses; a
//! shorter interval narrows that gap. Boot refuses a key the watch would stop
//! at once ([`KEY_ADMISSION_ENDING`]), so a key that passes boot never
//! restarts the unit in a loop.
//!
//! A failed re-read is logged (WARN, ERROR after
//! [`FAILED_RECHECKS_BEFORE_ERROR`] in a row) and the server keeps serving:
//! only a positive read of an inadmissible key stops it. The exit is abrupt:
//! requests in flight are cut off, as on any crash.
//!
//! So revoking or retiring the API's key stops the API (reads too) and a
//! restart refuses until the variable points at an admitted key: register and
//! point at the new key FIRST, then retire the old one (rotation, above).

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
     writers insert their edges UNSIGNED, and POST /api/v1/claims inserts its claims \
     UNSIGNED. Provision the API's own signing key to attest them \
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

/// How [`resolve_signer`] found the signer agent (the module docs' steps).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerResolution {
    /// Step 1: the key is an active, in-window `signing` row of one agent.
    SigningKeyRow,
    /// Step 2: the agent whose `agents.public_key` is the key. `dedicated`
    /// when it is a signer agent this module registered (display name
    /// [`SIGNER_DISPLAY_NAME`]); otherwise the key is some other agent's
    /// (the MCP server's, an author's) and the API would sign AS that agent.
    AgentPublicKey { dedicated: bool },
    /// Step 3: no agent had the key; a new signer agent was registered.
    Created,
}

/// The agent `signer` signs for (see the module docs, "The signer agent").
///
/// # Errors
/// When the key is carried by an attested `agent_keys` row but is not an
/// active, in-window `signing` key of exactly one agent, or a database call
/// fails.
pub async fn resolve_signer_agent(pool: &PgPool, signer: &AgentSigner) -> Result<Uuid, String> {
    resolve_signer(pool, signer).await.map(|(id, _)| id)
}

/// [`resolve_signer_agent`], saying which step resolved it.
///
/// # Errors
/// As [`resolve_signer_agent`].
pub async fn resolve_signer(
    pool: &PgPool,
    signer: &AgentSigner,
) -> Result<(Uuid, SignerResolution), String> {
    let public_key = signer.public_key();
    // Only ATTESTED rows (`signing`, `identity-legacy`) are a key's recorded
    // lifecycle: a row of any other type is application-insertable, and the
    // verifiers ignore it (`agent_key::admitted_signature_keys`), so it must
    // neither refuse the key here nor name its signer.
    let rows: Vec<_> = AgentKeyRepository::rows_with_public_key(pool, &public_key)
        .await
        .map_err(|e| format!("{ENV_KEY_FILE}: could not read agent_keys: {e}"))?
        .into_iter()
        .filter(|r| r.key_type == "signing" || r.key_type == "identity-legacy")
        .collect();
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
            [agent] => Ok((*agent, SignerResolution::SigningKeyRow)),
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
        let dedicated = agent.display_name.as_deref() == Some(SIGNER_DISPLAY_NAME);
        return Ok((
            agent.id.as_uuid(),
            SignerResolution::AgentPublicKey { dedicated },
        ));
    }
    let created = AgentRepository::create(
        pool,
        &epigraph_core::Agent::new(public_key, Some(SIGNER_DISPLAY_NAME.to_string())),
    )
    .await
    .map_err(|e| format!("{ENV_KEY_FILE}: could not register the signer agent: {e}"))?;
    Ok((created.id.as_uuid(), SignerResolution::Created))
}

/// What the server does about its edge signing key at boot: the signer (or
/// none: HTTP edges are written unsigned) and the warnings to log, once each.
/// [`boot`] logs them; tests read them.
#[derive(Debug)]
pub struct BootDecision {
    pub signer: Option<ApiEdgeSigner>,
    pub warnings: Vec<String>,
}

/// The warning when the key resolves to an agent that is not a dedicated API
/// signer (step 2 with `dedicated: false`). Not a refusal: refusing to start
/// over database state is an operator decision, not this module's default.
pub const NOT_A_DEDICATED_SIGNER: &str = "is not a dedicated API signer agent: the API signs its \
     HTTP edges AS that agent. Ruling R-50 gives the API a SEPARATE signer agent; point the \
     variable at a key of the API's own";

/// The warning when boot registered a new signer agent (step 3).
pub const REGISTERED_A_SIGNER: &str = "registered a NEW signer agent for the configured key. On \
     a first deploy this is expected; on a key rotation it splits attribution across two \
     signer agents: register the new key as the existing signer's active signing row first \
     (docs/architecture/noun-claims-and-verb-edges.md, rotation)";

/// The boot decision for `key_file` (the value of [`ENV_KEY_FILE`]; unset or
/// empty means no key).
///
/// # Errors
/// When a key is configured and cannot be used (see the module docs).
pub async fn decide(pool: &PgPool, key_file: Option<&str>) -> Result<BootDecision, String> {
    let Some(path) = key_file.map(str::trim).filter(|p| !p.is_empty()) else {
        return Ok(BootDecision {
            signer: None,
            warnings: vec![UNSIGNED_AT_BOOT.to_string()],
        });
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
    let (signer_id, how) = resolve_signer(pool, &signer).await?;
    // The running watch's own verdict, so a key that passes boot is never one
    // the watch stops at once (a key whose window ends within the stop lead
    // would restart the unit in a loop until the end).
    let public_key = signer.public_key();
    let read = AgentKeyRepository::signer_key_admission(pool, signer_id, &public_key)
        .await
        .map_err(|e| format!("{ENV_KEY_FILE}: could not read the key's admission: {e}"))?;
    if let AdmissionVerdict::Stop(_) = admission_verdict(&read) {
        return Err(format!(
            "{ENV_KEY_FILE}: the key ({}) of signer agent {signer_id} {KEY_ADMISSION_ENDING}",
            hex::encode(public_key)
        ));
    }
    let mut warnings = Vec::new();
    match how {
        SignerResolution::AgentPublicKey { dedicated: false } => warnings.push(format!(
            "{ENV_KEY_FILE}: the key is the public key of agent {signer_id}, which \
             {NOT_A_DEDICATED_SIGNER}"
        )),
        SignerResolution::Created => warnings.push(format!(
            "{ENV_KEY_FILE}: {REGISTERED_A_SIGNER} (agent {signer_id})"
        )),
        SignerResolution::SigningKeyRow | SignerResolution::AgentPublicKey { dedicated: true } => {}
    }
    Ok(BootDecision {
        signer: Some(ApiEdgeSigner::new(signer, signer_id)),
        warnings,
    })
}

/// The variable setting how often, in seconds, the running server re-checks
/// its signing key's admission ([`spawn_admission_watch`]).
pub const ENV_RECHECK_SECS: &str = "EPIGRAPH_API_SIGNING_KEY_RECHECK_SECS";

/// The stop lead, the verdict and the failed-re-read threshold are the shared
/// signer-admission policy ([`epigraph_db::signer_admission`]), which the MCP
/// server's watch applies too; re-exported under the names this module has
/// always had.
pub use epigraph_db::signer_admission::{
    admission_verdict, AdmissionVerdict, FAILED_RECHECKS_BEFORE_ERROR, STOP_LEAD_SECS,
};

/// The stop text's fixed part when the running server's key is not admitted,
/// or stops being admitted within [`STOP_LEAD_SECS`] ([`watch_admission`]).
pub const KEY_NO_LONGER_ADMITTED: &str = "is no longer admitted by the edge verifier, or stops \
     being admitted within the stop lead (revoked, rotated out, or its validity window \
     closes): an edge signed with it would fail verification. Stopping; point \
     EPIGRAPH_API_SIGNING_KEY_FILE at the signer agent's active signing key and restart";

/// The boot refusal's fixed part for a key whose admission ends within
/// [`STOP_LEAD_SECS`]: it passes the boot rule but the watch would stop the
/// server at once, so the unit would restart in a loop until the end.
pub const KEY_ADMISSION_ENDING: &str = "stops being admitted by the edge verifier within the \
     stop lead; the server would stop at once. Point the variable at the signer agent's next \
     active signing key";

/// Check whether the edge verifier still admits `signer`'s key for its signer
/// agent, now and then every `interval` (sooner when a recorded window ends
/// first), and return the stop text once [`admission_verdict`] says stop. A
/// failed re-read is logged (WARN, then ERROR after
/// [`FAILED_RECHECKS_BEFORE_ERROR`] in a row) and the watch goes on: the key
/// passed its fail-closed boot check, and a transient database error must not
/// stop the server. Only a positive read of an inadmissible key returns. The
/// loop is [`epigraph_db::signer_admission::watch_signer_admission`].
pub async fn watch_admission(
    pool: PgPool,
    signer: Arc<ApiEdgeSigner>,
    interval: std::time::Duration,
) -> String {
    let public_key = signer.signer.public_key();
    let stop = epigraph_db::signer_admission::watch_signer_admission(
        pool,
        epigraph_db::signer_admission::WatchedSigner::Agent(signer.signer_id),
        public_key,
        interval,
        ENV_KEY_FILE,
        // `boot` refused a key that is not admitted.
        epigraph_db::signer_admission::Arming::FromBoot,
    )
    .await;
    let ends = stop.end.map_or(String::new(), |t| {
        format!(" (its admission ends at {})", t.to_rfc3339())
    });
    let stop = format!(
        "{ENV_KEY_FILE}: the API's signing key ({}) of signer agent {} \
         {KEY_NO_LONGER_ADMITTED}{ends}",
        hex::encode(public_key),
        stop.signer_id
    );
    tracing::error!("{stop}");
    stop
}

/// Spawn [`watch_admission`] for `bin/server.rs`, at the interval
/// `recheck_secs` (the value of [`ENV_RECHECK_SECS`], which the binary reads)
/// sets, and EXIT the process (status 1, the stop text on stderr) when it
/// returns. Call it right after [`boot`] returns a signer.
///
/// The value is an argument, not an environment read here, so this library
/// reads no configuration of its own (`tests/no_library_env_reads.rs`).
pub fn spawn_admission_watch(pool: PgPool, signer: Arc<ApiEdgeSigner>, recheck_secs: Option<&str>) {
    let interval = epigraph_db::operator_binding::recheck_interval_from_env_value(recheck_secs);
    tokio::spawn(async move {
        let stop = watch_admission(pool, signer, interval).await;
        eprintln!("ERROR: {stop}");
        std::process::exit(1);
    });
}

/// The API's signer from `key_file` (the value of [`ENV_KEY_FILE`]).
/// `Ok(None)` when unset or empty. [`decide`] without its warnings.
///
/// # Errors
/// When a key is configured and cannot be used (see the module docs).
pub async fn load(pool: &PgPool, key_file: Option<&str>) -> Result<Option<ApiEdgeSigner>, String> {
    decide(pool, key_file).await.map(|d| d.signer)
}

/// [`decide`] on `key_file` (the value of [`ENV_KEY_FILE`], which
/// `bin/server.rs` reads from the environment), for `bin/server.rs`: logs the
/// outcome and each warning once, and exits the process non-zero on a
/// configured key it cannot use. The only part not under test: the logging and
/// the exit.
pub async fn boot(pool: &PgPool, key_file: Option<&str>) -> Option<Arc<ApiEdgeSigner>> {
    match decide(pool, key_file).await {
        Ok(decision) => {
            for w in &decision.warnings {
                tracing::warn!("{w}");
            }
            decision.signer.map(|s| {
                tracing::info!(
                    signer_id = %s.signer_id(),
                    public_key = %hex::encode(s.signer.public_key()),
                    "HTTP edge writers attest their edges with the API's signing key"
                );
                Arc::new(s)
            })
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
