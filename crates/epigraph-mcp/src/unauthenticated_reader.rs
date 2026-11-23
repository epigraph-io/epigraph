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
//! * Migration 241 creates the one agent row under the fixed
//!   [`READER_PUBLIC_KEY`] and RESERVES the key: no other row may take it, on
//!   any role (backlog 14a38166). [`UnauthenticatedReader`] only looks the row
//!   up; it never creates one, so it cannot adopt a row someone else made
//!   after the migration.
//! * Migration 241 also refuses the reader every LIVE `group_memberships` row,
//!   on every role and every path, definers included (backlog 37844e1d), so a
//!   `groups:admin` holder can no longer close the listener by adding the
//!   reader to a group. Nothing gives it a group in code either: it is never
//!   passed to `AgentRepository::ensure_personal_group`, and nobody holds a
//!   private key for its public key.
//! * Resolution still REFUSES a row that holds any live membership or is the
//!   principal of any OAuth client that is not revoked. A row that existed
//!   before migration 241 (planted ahead of the listener's first boot) is
//!   adopted by the migration as it is, so this is where such a row is
//!   refused: the listener's content tools refuse instead of reading as it.
//! * `tools::viewer::request_viewer` re-checks on every call: a principal-less
//!   read-only context whose viewer carries any group is refused. A group that
//!   reaches the reader some other way (a derived membership) therefore closes
//!   the listener; it never widens it.
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
/// `--allow-unauthenticated-http` listener (migration 241's reserved row).
/// See the module doc.
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

    /// The reader agent's id: migration 241's row, found by
    /// [`READER_PUBLIC_KEY`].
    ///
    /// # Errors
    ///
    /// A displayable reason when the database cannot be read, when no row
    /// holds the key (migration 241 is not applied), when the row is the
    /// principal of an OAuth client that is not revoked, or when the agent
    /// holds ANY live group membership (it must hold none, and reading with
    /// one is the widening this type exists to prevent).
    pub async fn resolve(&self) -> Result<Uuid, String> {
        let mut cached = self.cached.lock().await;
        if let Some(id) = *cached {
            return Ok(id);
        }
        let id = self.find_reserved().await?;
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

    /// Migration 241's reserved row, refused when it is anybody's OAuth
    /// principal. Never creates: 241 is the row's only creator and its
    /// trigger refuses the key to every other INSERT, so a miss means the
    /// migration is not applied.
    async fn find_reserved(&self) -> Result<Uuid, String> {
        let agent = epigraph_db::AgentRepository::get_by_public_key(&self.pool, &READER_PUBLIC_KEY)
            .await
            .map_err(|e| format!("could not look up the unauthenticated reader agent: {e}"))?
            .ok_or_else(|| {
                format!(
                    "no agent holds the --allow-unauthenticated-http reader key; migration 241 \
                     creates it ({READER_DISPLAY_NAME}). Apply the migrations before this binary"
                )
            })?;
        let id = agent.id.as_uuid();
        let clients = epigraph_db::OAuthClientRepository::count_unrevoked_for_agent(&self.pool, id)
            .await
            .map_err(|e| {
                format!("could not read the unauthenticated reader's OAuth clients: {e}")
            })?;
        if clients > 0 {
            return Err(format!(
                "the --allow-unauthenticated-http reader agent {id} is the principal of {clients} \
                 OAuth client(s) that are not revoked; nobody may authenticate as it, so the \
                 listener refuses to read as it. Revoke them"
            ));
        }
        Ok(id)
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
