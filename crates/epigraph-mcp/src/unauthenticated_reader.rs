//! The principal of the READ-ONLY `--allow-unauthenticated-http` listener: a
//! dedicated agent that belongs to no group (backlog fe514fc3).
//!
//! # The decision
//!
//! That listener validates no credential, so no request on it names anyone.
//! Before this module its injected context carried the server's own agent, so
//! every holder of the listener's one shared credential read with the server
//! agent's group set. The server agent authors every claim ingested over
//! stdio, so its personal group is plausibly the largest in the corpus, and the
//! flag (advertised as "no auth on a trusted socket") quietly handed it out.
//!
//! The operator chose a dedicated zero-membership principal: reads on that
//! listener are PUBLIC-ONLY, the posture fails closed, and the flag keeps its
//! advertised meaning. `docs/deploy.md` states it for operators.
//!
//! # How it holds
//!
//! * [`UnauthenticatedReader`] resolves (and on first use creates) one agent
//!   row under the fixed [`READER_PUBLIC_KEY`]. Nothing gives it a group: it
//!   is never passed to `AgentRepository::ensure_personal_group`, holds no
//!   client, and nobody holds a private key for its public key.
//! * Resolution REFUSES when the row holds any live membership, so the
//!   listener's content tools refuse instead of reading with that group.
//! * `tools::viewer::request_viewer` re-checks on every call: a principal-less
//!   read-only context whose viewer carries any group is refused. A membership
//!   granted to the reader after boot therefore closes the listener; it never
//!   widens it.
//!
//! # The opt-in listener is different, on purpose
//!
//! With `--allow-unauthenticated-writes` the listener's callers write as the
//! listener's own signer (`auth::UnauthenticatedWrites::AsListenerSigner`), and
//! a write's author must be the principal its viewer names
//! (`EpiGraphMcpFull::write_identity`). That listener keeps the server agent as
//! its principal, and so its group set. It is the explicit trusted-socket
//! opt-in (e.g. the e2e harness), refused anywhere but a unix socket.

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{ServerPrincipalSource, UnauthenticatedPrincipal, UnauthenticatedWrites};

/// The reader agent's public key: 32 ASCII bytes, chosen to be readable in an
/// `agents` row rather than derived from a keypair. No private key for it is
/// known to anyone, so nothing can authenticate or sign as this agent; it only
/// ever appears as the injected principal of the read-only listener.
pub const READER_PUBLIC_KEY: [u8; 32] = *b"epigraph-mcp:unauthenticated-rdr";

/// The reader agent's `display_name`.
pub const READER_DISPLAY_NAME: &str = "mcp-unauthenticated-reader";

/// Resolves the dedicated zero-membership agent of the read-only
/// `--allow-unauthenticated-http` listener. See the module doc.
///
/// Caches the id on success only, so a database that is unreachable at boot is
/// retried by the next request (the [`UnauthenticatedPrincipal`] cooldown
/// bounds the rate), exactly like the server agent's resolution.
pub struct UnauthenticatedReader {
    pool: PgPool,
    cached: tokio::sync::Mutex<Option<Uuid>>,
}

impl std::fmt::Debug for UnauthenticatedReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnauthenticatedReader")
            .field("cached", &self.cached.try_lock().ok().and_then(|g| *g))
            .finish_non_exhaustive()
    }
}

impl UnauthenticatedReader {
    /// A resolver over `pool` (the server's pool, the one its own agent is
    /// resolved on).
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cached: tokio::sync::Mutex::new(None),
        }
    }

    /// The reader agent's id: found by [`READER_PUBLIC_KEY`], or created.
    ///
    /// # Errors
    ///
    /// A displayable reason when the database cannot be read or written, or
    /// when the agent holds ANY live group membership (it must hold none, and
    /// reading with one is the widening this type exists to prevent).
    pub async fn resolve(&self) -> Result<Uuid, String> {
        let mut cached = self.cached.lock().await;
        if let Some(id) = *cached {
            return Ok(id);
        }
        let id = self.find_or_create().await?;
        let memberships =
            epigraph_db::GroupMembershipRepository::list_live_for_agent(&self.pool, id)
                .await
                .map_err(|e| {
                    format!("could not read the unauthenticated reader's memberships: {e}")
                })?;
        if !memberships.is_empty() {
            return Err(format!(
                "the --allow-unauthenticated-http reader agent {id} holds {} live group \
                 membership(s); it must hold none, so the listener refuses to read with them. \
                 Revoke them",
                memberships.len()
            ));
        }
        *cached = Some(id);
        Ok(id)
    }

    async fn find_or_create(&self) -> Result<Uuid, String> {
        let lookup = || async {
            epigraph_db::AgentRepository::get_by_public_key(&self.pool, &READER_PUBLIC_KEY)
                .await
                .map_err(|e| format!("could not look up the unauthenticated reader agent: {e}"))
        };
        if let Some(agent) = lookup().await? {
            return Ok(agent.id.as_uuid());
        }
        let agent = epigraph_core::Agent::new(READER_PUBLIC_KEY, Some(READER_DISPLAY_NAME.into()));
        match epigraph_db::AgentRepository::create(&self.pool, &agent).await {
            Ok(created) => Ok(created.id.as_uuid()),
            // Another process created it first: theirs is the row.
            Err(epigraph_db::DbError::DuplicateKey { .. }) => lookup()
                .await?
                .map(|a| a.id.as_uuid())
                .ok_or_else(|| "the unauthenticated reader agent vanished after a race".into()),
            Err(e) => Err(format!(
                "could not create the unauthenticated reader agent: {e}"
            )),
        }
    }
}

#[async_trait::async_trait]
impl ServerPrincipalSource for UnauthenticatedReader {
    async fn resolve_server_agent_id(&self) -> Result<Uuid, String> {
        self.resolve().await
    }
}

/// The principal the `--allow-unauthenticated-http` listener injects, as
/// `main` builds it (and the tests that stand in for `main`).
///
/// * [`UnauthenticatedWrites::Refused`] (the default): the dedicated
///   zero-membership [`UnauthenticatedReader`] on `pool`. Public reads only.
/// * [`UnauthenticatedWrites::AsListenerSigner`]: `server`, the listener's own
///   signer, which its callers' writes are authored by.
///
/// Warmed once here; a failed warm-up is logged and retried per request.
pub async fn listener_principal(
    writes: UnauthenticatedWrites,
    server: Arc<dyn ServerPrincipalSource>,
    pool: PgPool,
) -> UnauthenticatedPrincipal {
    let source: Arc<dyn ServerPrincipalSource> = match writes {
        UnauthenticatedWrites::Refused => Arc::new(UnauthenticatedReader::new(pool)),
        UnauthenticatedWrites::AsListenerSigner => server,
    };
    let principal = UnauthenticatedPrincipal::lazily_from(source.clone()).with_writes(writes);
    match source.resolve_server_agent_id().await {
        Ok(id) => principal.warmed_with(id),
        Err(e) => {
            // Loud, and not terminal for the listener.
            tracing::error!(
                error = %e,
                "could not resolve the --allow-unauthenticated-http principal at boot; \
                 content tools on that listener refuse (principal did not resolve) until a later \
                 request resolves it"
            );
            principal
        }
    }
}
