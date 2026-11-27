//! The context every shared operation runs in: [`Ctx`] (backlog 30133ca8,
//! work item 2 of 93e01896).
//!
//! It holds what a write or a read needs to run under the right tenancy, and
//! nothing a transport owns: the plain pool, the [`epigraph_db::ScopedPool`]
//! that stamps a connection with a viewer's tenancy context, the declaration
//! that the pool is a privileged maintenance pool, the signer and the identity
//! key it resolves the process's own agent from, and the set of detached
//! background tasks. Its methods are the tenancy entry points that used to be
//! methods of the MCP server (`EpiGraphMcpFull`), moved here verbatim:
//! [`Ctx::read_as`], [`Ctx::write_identity`],
//! [`Ctx::admin_borrowed_server_identity`], [`Ctx::signer_agent_id`] and
//! [`Ctx::agent_id`], plus the free functions [`begin_author_stamped_tx`],
//! [`begin_author_stamped_tx_for`] and [`resolve_claim_visibility`]. The MCP
//! server holds a `Ctx` and delegates to it, so a later step can run the same
//! operations from the HTTP API or the CLI without depending on the MCP crate.
//!
//! # Fail-closed, unchanged
//!
//! A `Ctx` built without a `ScopedPool` ([`Ctx::new`] alone) refuses every
//! stamped read ([`Ctx::read_as`]) and every author-stamped write
//! ([`begin_author_stamped_tx`]) with a designed error that names the fix. It
//! never falls back to the plain pool. Only [`Ctx::with_scoped_pool`] makes the
//! stamped paths available.
//!
//! # Why the write helpers are generic over a [`ServiceHost`]
//!
//! The MCP server's tools call `begin_author_stamped_tx(server, ..)` and
//! propagate its error with `?` into their own error type. Neither error type
//! can convert into the other through `From`: the MCP crate's error is rmcp's,
//! the orphan rule forbids an impl between two foreign types, and this crate
//! does not depend on rmcp. So the helpers take any host that can lend its
//! `Ctx` and map a [`ServiceError`] into its own error, and the MCP server is
//! one such host. Every call site stayed as it was, and these functions are the
//! only definitions of the helpers in the workspace.

use std::sync::Arc;

use epigraph_crypto::AgentSigner;
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use tokio::sync::Mutex;

use crate::background::BackgroundTasks;
use crate::errors::{Fault, ServiceError};

/// Something that holds a [`Ctx`] and answers a [`ServiceError`] with its own
/// error type: the MCP server (its JSON-RPC error), or a `Ctx` itself.
pub trait ServiceHost {
    /// The host's own error type.
    type Error;

    /// The context the host's operations run in.
    fn ctx(&self) -> &Ctx;

    /// `e`, as the host answers it.
    fn service_error(e: ServiceError) -> Self::Error;
}

impl ServiceHost for Ctx {
    type Error = ServiceError;

    fn ctx(&self) -> &Ctx {
        self
    }

    fn service_error(e: ServiceError) -> ServiceError {
        e
    }
}

/// The context a shared operation runs in. See the module doc.
///
/// `Clone` shares everything behind its `Arc`s, the resolved agent id cell
/// included: every per-session clone of the MCP server (its `SessionFactory`)
/// resolves the process's own agent ONCE, which is what keeps that
/// resolution's personal-group provisioning a once-per-process write.
#[derive(Clone)]
#[non_exhaustive]
pub struct Ctx {
    /// The plain application pool. Its connections carry EMPTY tenancy GUCs,
    /// so row security admits public rows only: reads that a viewer filters run
    /// on [`Self::read_as`], and writes on [`begin_author_stamped_tx`].
    pub pool: PgPool,
    /// The tenancy-aware pool, when this process built one.
    ///
    /// `Option` for the same reason as the HTTP API's `AppState::scoped`:
    /// `ScopedPool::connect` owns pool construction (the `after_release` scrub
    /// can only be installed at build time), so it cannot be wrapped around a
    /// `PgPool` a caller already has. [`Ctx::new`] sets `None`;
    /// [`Self::with_scoped_pool`] is the one that populates it.
    ///
    /// `None` here means the WRITE path fails closed:
    /// [`begin_author_stamped_tx`] refuses rather than running a write on an
    /// unstamped connection, where the claim commits and its trace is then
    /// refused with `42501`. It means the READ path fails closed too:
    /// [`Self::read_as`] refuses.
    ///
    /// `Some` here does NOT license the MCP server's three maintenance tools.
    /// They require a privileged maintenance pool attached to this
    /// `ScopedPool`, and a leased connection that passes
    /// `MaintenanceSession::assert_privileged` on every call.
    pub scoped: Option<epigraph_db::ScopedPool>,
    /// `Some(reason)` when the caller DECLARED that `pool` is a privileged
    /// (BYPASSRLS) maintenance pool, set only through
    /// [`Self::on_a_privileged_pool`]. The operator `ingest-document` CLI runs
    /// its whole ingest on `MaintenancePool`, where there is no tenancy context
    /// to stamp and a plain transaction is the correct shape. Declared rather
    /// than defaulted, mirroring the MCP embedder's `on_a_privileged_pool`: a
    /// context on an ORDINARY pool with no `ScopedPool` keeps failing closed.
    pub privileged_pool: Option<&'static str>,
    /// The tasks an operation detaches and answers ahead of (a queued document
    /// walk, a post-commit embedding loop), counted so the stdio entry point
    /// can wait for them before the process exits. Shared by every clone.
    /// See [`crate::background`].
    pub background: BackgroundTasks,
    /// The key every signature this process makes is by. In the legacy modes
    /// it is also the agent's identity (`agents.public_key`); in the
    /// separate-signing-key mode (agent identity lineage design D2) it is the
    /// agent's registered `agent_keys` signing key and names no agent.
    pub signer: Arc<AgentSigner>,
    /// The agent's IDENTITY public key when it is not the signer's
    /// ([`Self::with_identity_public_key`]): [`Self::agent_id`] finds the agent
    /// by this key, and the signer only signs. `None` from [`Ctx::new`], which
    /// keeps the legacy behaviour (the signer's key is the identity).
    pub identity_public_key: Option<[u8; 32]>,
    /// `(llm_model, llm_prompt_hash)` when this process's agent identity was
    /// derived deterministically from an LLM config, else `None`. When `Some`,
    /// [`Self::agent_id`]'s CREATE branch records these on the freshly-created
    /// agent row via `AgentRepository::set_llm_properties`. `None` preserves
    /// the legacy behavior exactly: no properties are written.
    pub llm_identity: Option<(String, String)>,
    /// The process's own `agents.id`, once [`Self::agent_id`] has resolved it.
    /// Written only on success, so a failed resolution is retried on the next
    /// call. Shared by every clone.
    agent_db_id: Arc<Mutex<Option<uuid::Uuid>>>,
}

impl Ctx {
    /// A context on `pool`, signing with `signer`, with no `ScopedPool` (every
    /// stamped read and write refuses until [`Self::with_scoped_pool`]), no
    /// privileged-pool declaration, no separate identity key and no tracked
    /// background task.
    #[must_use]
    pub fn new(
        pool: PgPool,
        signer: Arc<AgentSigner>,
        llm_identity: Option<(String, String)>,
    ) -> Self {
        Self {
            pool,
            scoped: None,
            privileged_pool: None,
            background: BackgroundTasks::default(),
            signer,
            identity_public_key: None,
            llm_identity,
            agent_db_id: Arc::new(Mutex::new(None)),
        }
    }

    /// Attach a [`epigraph_db::ScopedPool`]: the only way `self.scoped`
    /// becomes `Some`, and therefore the only way [`Self::read_as`] and
    /// [`begin_author_stamped_tx`] can stamp a connection.
    #[must_use]
    pub fn with_scoped_pool(mut self, scoped: epigraph_db::ScopedPool) -> Self {
        self.scoped = Some(scoped);
        self
    }

    /// Declare that `pool` is a PRIVILEGED (BYPASSRLS) maintenance pool (see
    /// the field's doc). `reason` is required and is logged by the paths that
    /// honour it.
    #[must_use]
    pub fn on_a_privileged_pool(mut self, reason: &'static str) -> Self {
        self.privileged_pool = Some(reason);
        self
    }

    /// Name this process's agent by a separate IDENTITY public key (agent
    /// identity lineage design D1, D2): [`Self::agent_id`] finds or creates the
    /// agent by `key`, while every signature is still the signer's.
    #[must_use]
    pub fn with_identity_public_key(mut self, key: [u8; 32]) -> Self {
        self.identity_public_key = Some(key);
        self
    }

    /// Whether `self` and `other` share ONE resolved-agent cell, as every clone
    /// of a context does. The MCP server's `SessionFactory` relies on it: its
    /// per-session clones resolve the process's own agent once per process,
    /// not once per session.
    #[must_use]
    pub fn shares_agent_cell_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.agent_db_id, &other.agent_db_id)
    }

    /// Fill the resolved-agent cell as a successful [`Self::agent_id`] would,
    /// without a database. Test builds only (`test-support`): production code
    /// resolves the agent from its identity key, never from a caller's id.
    #[cfg(feature = "test-support")]
    pub async fn seed_agent_id_for_tests(&self, id: uuid::Uuid) {
        *self.agent_db_id.lock().await = Some(id);
    }

    /// The public key this process's agent is found by: the declared identity
    /// key, else the signer's own.
    #[must_use]
    pub fn identity_key(&self) -> [u8; 32] {
        self.identity_public_key
            .unwrap_or_else(|| self.signer.public_key())
    }

    /// The agent a write on this request authors and stamps as (batch H-b, D1).
    ///
    /// * `Some(auth)` (the HTTP listener): the caller, `auth.agent_id`. A token
    ///   with no agent principal is refused, as `request_viewer` refuses it. So
    ///   is a principal-less caller ([`crate::write_identity::is_principal_less`], the
    ///   `--allow-unauthenticated-http` context) without a write scope: no human
    ///   is named there, so there is no author to write as (batch HTTP-id).
    /// * `None` (stdio, and the operator CLIs that drive the tool functions
    ///   directly): this server's own agent, exactly as before batch H-b.
    ///
    /// `viewer` is the request's own viewer, and over HTTP it MUST name the same
    /// principal: `request_viewer` resolved it from the same `auth`, so a
    /// mismatch means a caller wired a viewer from one principal to a write as
    /// another. That is refused rather than resolved in either direction, so a
    /// tool's read and write authority cannot silently name two agents. See
    /// [`crate::write_identity`] for the decision and the ratchet.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Denied`] for a token with no agent principal,
    /// [`ServiceError::Internal`] when `viewer`'s principal is not the token's, and
    /// whatever [`Self::agent_id`] returns on stdio.
    pub async fn write_identity(
        &self,
        auth: Option<&epigraph_auth::AuthContext>,
        viewer: &epigraph_db::visibility::Viewer,
    ) -> Result<crate::write_identity::WriteIdentity, ServiceError> {
        // An elevated request is read-only (elevation plan §1.4), on every
        // transport, before anything else: nothing below would see it.
        crate::write_identity::refuse_elevated(viewer)?;
        let Some(auth) = auth else {
            return Ok(crate::write_identity::WriteIdentity::from_resolved(
                self.agent_id().await?,
            ));
        };
        // Batch HTTP-id: a principal-less caller writes only where the listener
        // opted in (`--allow-unauthenticated-writes`, which grants the write
        // scopes); by default its context is read-only and nothing is authored.
        if crate::write_identity::is_principal_less(auth) && !auth.has_scope("claims:write") {
            return Err(crate::write_identity::principal_less_write_refusal());
        }
        let principal = auth
            .agent_id
            .ok_or_else(crate::write_identity::no_agent_principal_refusal)?;
        if viewer.principal() != Some(principal) {
            return Err(crate::write_identity::diverging_principals(
                principal,
                viewer.principal(),
            ));
        }
        Ok(crate::write_identity::WriteIdentity::from_resolved(
            principal,
        ))
    }

    /// The ONE way an authenticated caller acts under this server's own
    /// agent's stamp (batch OA1 on top of batch H-b).
    ///
    /// OA1 lets a `claims:admin` caller supersede or dedup a claim in a group
    /// it does not write by acting on a transaction stamped from this server's
    /// agent, as those tools did before OA1 when `claims:admin` was their scope
    /// (the MCP server's `tools::supersede::begin_claim_act`). No other admission may borrow
    /// that stamp: it would hand a `claims:write` caller the server agent's
    /// write authority. A front end cannot construct a
    /// [`crate::write_identity::WriteIdentity`] itself (its constructor is
    /// private to this crate), so the check that licenses the
    /// borrow lives here, beside [`Self::write_identity`], and is re-checked on
    /// every call rather than trusted from the caller.
    ///
    /// The token's `claims:admin` SCOPE is necessary, not sufficient. MCP
    /// verifies a token's signature and expiry but not its revocation, so the
    /// token's client record must still grant `claims:admin` to this principal:
    /// migration 111's `ADM02` predicate, re-read on `conn` (the caller's own
    /// stamped transaction) through
    /// `SecurityEventRepository::admin_grant_is_live`, exactly as the audited
    /// admin paths of `patch_claim` (111) and the workflow step ops do. A
    /// de-scoped or revoked client's still-unexpired token is refused here at
    /// once instead of borrowing the server agent's stamp until it expires. The
    /// only caller is the MCP server's `tools::supersede::begin_claim_act`; the
    /// MCP crate's `tests/write_identity_ratchet.rs` pins that.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Denied`] when `auth` does not carry `claims:admin`,
    /// names no agent principal, or its client record grants no live
    /// `claims:admin` to that principal (`ADM02`); [`ServiceError::InternalLogged`]
    /// when the grant cannot be read; and whatever [`Self::agent_id`] returns.
    pub async fn admin_borrowed_server_identity(
        &self,
        auth: &epigraph_auth::AuthContext,
        conn: &mut sqlx::PgConnection,
    ) -> Result<crate::write_identity::WriteIdentity, ServiceError> {
        if !auth.has_scope("claims:admin") {
            return Err(ServiceError::Denied(
                "only a claims:admin caller may act under this server's own agent's stamp; \
                 nothing was written"
                    .to_string(),
            ));
        }
        let principal = auth
            .agent_id
            .ok_or_else(crate::write_identity::no_agent_principal_refusal)?;
        let live = epigraph_db::SecurityEventRepository::admin_grant_is_live(
            &mut *conn,
            auth.client_id,
            principal,
            auth.admin_scopes == epigraph_auth::AdminScopePosture::Armed,
        )
        .await
        .map_err(|e| ServiceError::InternalLogged {
            message: "could not re-check the admin grant".to_string(),
            cause: e.to_string(),
        })?;
        if !live {
            return Err(ServiceError::Denied(format!(
                "caller agent {principal} holds claims:admin in its token, but the token's \
                     client record ({}) grants it no live claims:admin, so it may not act under \
                     this server's own agent's stamp (ADM02); nothing was written",
                auth.client_id
            )));
        }
        Ok(crate::write_identity::WriteIdentity::from_resolved(
            self.agent_id().await?,
        ))
    }

    /// The agent whose key SIGNS this server's digests: the server's own agent,
    /// whatever the author.
    ///
    /// Named apart from [`Self::write_identity`] because the two are different
    /// facts once an authenticated caller authors a row. `claims.signer_id` and
    /// `evidence.signer_id` record this agent, and `verify_claim` checks the
    /// stored signature against its `public_key`, so a row authored by the caller
    /// and signed by the server verifies instead of reporting a mismatch against
    /// the author's (often `derived`, keyless) agent.
    ///
    /// # Errors
    ///
    /// Propagates whatever [`Self::agent_id`] returns.
    pub async fn signer_agent_id(&self) -> Result<uuid::Uuid, ServiceError> {
        self.agent_id().await
    }

    /// Ensure agent exists in DB, return cached ID.
    ///
    /// # Tenancy (PR-09)
    ///
    /// This now calls `AgentRepository::ensure_personal_group` on **both**
    /// branches — the call sits after the if/else, not inside the create arm.
    /// That is deliberate and it is the only placement that works: an
    /// already-provisioned server agent (i.e. every existing deployment) takes
    /// the *found* branch, so a create-only call would leave exactly the
    /// installations that matter with no personal group.
    ///
    /// Without it this path — unlike `epigraph-api`'s `oauth/token.rs`, which has
    /// called it since PR-02 — left the server's own agent with **no**
    /// `group_memberships` row, so `Viewer::resolve(server_agent_id)` returned an
    /// empty group set. Every stdio read and every `--allow-unauthenticated-http`
    /// read was therefore public-only *by accident*, and PR-09's own acceptance
    /// criterion ("the stdio read default becomes `Viewer::resolve(pool,
    /// server_agent_id)`") would have been inert: the viewer would resolve, and
    /// mean nothing. It is best-effort for the same reason `set_llm_properties`
    /// below is: a failure here must not break agent resolution.
    ///
    /// ## Three properties an operator should know, stated rather than implied
    ///
    /// 1. **This is a write on a read path.** Resolving the agent id already
    ///    inserted into `agents` on first call; it now also writes `groups` and
    ///    `group_memberships`. `reject_if_read_only` is a per-tool gate, so a
    ///    `--read-only` server performs these writes on its first tool call.
    ///    That is pre-existing in kind (the `agents` insert) and widened in
    ///    degree here.
    /// 2. **It provisions; it does not restore.** It used to be an authority
    ///    restoration: migration 077's `epigraph_ensure_personal_group` ended in
    ///    `ON CONFLICT … DO UPDATE SET revoked_at = NULL, role = 'admin'`, so an
    ///    operator who revoked this membership saw it revived, at admin, on the
    ///    next process boot — and, before `SessionFactory`, on every new HTTP
    ///    session. Since migration 105 a revoked membership makes the call
    ///    REFUSE (`DbError::MembershipRevoked`), a live one is returned with its
    ///    role untouched, and only an agent with no row at all is provisioned.
    ///    The refusal takes arm 3 below: the id still resolves (it is the
    ///    process's identity, not an authority grant), and the revocation
    ///    stands.
    /// 3. **It fails closed.** A failure — the refusal included — warns and
    ///    leaves the agent with whatever live groups it has, which for a revoked
    ///    personal membership means no personal group: its writes are refused
    ///    by the ingest preflight and the author-stamped transaction.
    pub async fn agent_id(&self) -> Result<uuid::Uuid, ServiceError> {
        let mut cached = self.agent_db_id.lock().await;
        if let Some(id) = *cached {
            return Ok(id);
        }
        // The identity key names the agent; the signer only signs (D2). In the
        // legacy modes the two are one key.
        let pub_key = self.identity_key();
        let agent = if let Some(a) =
            epigraph_db::AgentRepository::get_by_public_key(&self.pool, &pub_key)
                .await
                .map_err(|e| ServiceError::Fault(Fault::Db(e)))?
        {
            a
        } else {
            let agent = epigraph_core::Agent::new(pub_key, Some("mcp-agent".to_string()));
            // Backlog 9d4673a0: the server's own signer is never a human, so
            // it is not left on migration 001's `agent_type` default
            // ('human'), which lineage-parent (161/166/195) and role-attach
            // (166 ROL02) gates read as a person. 'llm' when the identity is
            // derived from an LLM config, else 'software_agent'. Set at
            // INSERT: the application role cannot UPDATE `agent_type` (118).
            let agent_type = if self.llm_identity.is_some() {
                epigraph_db::SignerAgentType::Llm
            } else {
                epigraph_db::SignerAgentType::SoftwareAgent
            };
            let created =
                epigraph_db::AgentRepository::create_signer(&self.pool, &agent, agent_type)
                    .await
                    .map_err(|e| ServiceError::Fault(Fault::Db(e)))?;
            // CREATE branch ONLY: record the derived LLM identity on the fresh
            // row. Best-effort — a failure here must not break agent resolution
            // or any downstream dispatch (the agent still exists and is usable;
            // it just lacks the provenance annotation). The FOUND branch above
            // deliberately does NOT re-set properties: an identical-config
            // process reuses the SAME pubkey -> same row -> properties already
            // set by whoever created it first.
            if let Some((model, prompt_hash)) = &self.llm_identity {
                if let Err(e) = epigraph_db::AgentRepository::set_llm_properties(
                    &self.pool,
                    created.id.as_uuid(),
                    model,
                    prompt_hash,
                )
                .await
                {
                    tracing::warn!(
                        agent_id = %created.id.as_uuid(),
                        error = ?e,
                        "failed to record LLM identity on newly-created agent; \
                         continuing without provenance annotation"
                    );
                }
            }
            created
        };
        let id = agent.id.as_uuid();

        // PR-09: the server agent needs a personal group, or the viewer it
        // resolves to has an empty group set and reads public rows only. See
        // the doc comment above. Migration 105's contract: a LIVE membership
        // reads and writes nothing (role kept); a REVOKED one is refused with
        // `DbError::MembershipRevoked` (RVK01) and a group squatting the
        // agent's did_key with `PersonalGroupNotOwned` (RVK02), each logged
        // below as a warning, never restored; only an agent with no row of
        // any state is provisioned. It runs once per PROCESS: every session
        // shares this cell (`SessionFactory`), and later calls are served
        // from `cached`.
        match self.pool.acquire().await {
            Ok(mut conn) => {
                match epigraph_db::AgentRepository::ensure_personal_group(&mut conn, id).await {
                    Ok(_) => {}
                    // Migration 122 (armed): a LIVE-LINKED agent writes into its
                    // operator's group, and a writer/admin row in its own
                    // personal group is in a group its operator does not
                    // write, so the membership door refuses it. Expected on
                    // every boot of a correctly linked fleet agent, so neither
                    // a warning nor an OPL02 line in the log (review C5).
                    Err(epigraph_db::DbError::OperatorScopeRefused { .. }) => tracing::info!(
                        agent_id = %id,
                        "the server agent is live-linked and writes into its operator's group; \
                         its own personal group is not provisioned"
                    ),
                    Err(e) => tracing::warn!(
                        agent_id = %id,
                        error = %e,
                        "did not provision the server agent's personal group (a revoked \
                         membership is refused, never restored); its viewer resolves to its \
                         remaining live groups only"
                    ),
                }
            }
            Err(e) => tracing::warn!(
                agent_id = %id,
                error = ?e,
                "could not acquire a connection to ensure the server agent's personal group"
            ),
        }

        *cached = Some(id);
        drop(cached);
        Ok(id)
    }

    /// A connection stamped with `viewer`'s tenancy context, for a tool's
    /// READS: the twin of the HTTP API's `AppState::read_as`.
    ///
    /// A content-reading tool resolves its viewer and then reads
    /// on what this returns, `&mut *read` into the repo layer, never on the
    /// server's plain application pool. That pool's connections carry EMPTY
    /// tenancy GUCs, and row security, FORCEd on the application login, then
    /// admits public rows only: the in-query predicate admits a member's
    /// group-private row and the session's policy drops it, so a member read
    /// its own group's rows as absent, with no error. Measured on production
    /// 2026-11-05: every MCP caller saw public rows only. CI did not see it
    /// because it connects as a BYPASSRLS superuser, on which the policy filters
    /// nothing (`tests/mcp_reads_are_stamped_app_role.rs` reads as the
    /// application role instead).
    ///
    /// One per tool call where a tool makes several reads: take it once, keep
    /// it short-lived, and take it AFTER any embedder round trip rather than
    /// holding a pooled connection across one. Elevated viewers are handled by
    /// [`epigraph_db::ScopedPool::read_as`] itself (a `BEGIN READ ONLY` arm
    /// under transaction-mode pooling). Call [`epigraph_db::ScopedRead::commit`]
    /// at the end when convenient; dropping it instead is safe for a read (the
    /// transaction arm rolls back) and costs one wasted round trip.
    ///
    /// This is for reads. Writes take `ScopedPool::begin_as` through
    /// [`begin_author_stamped_tx`] and its siblings.
    ///
    /// # It REFUSES rather than falling back to the plain pool
    ///
    /// For the reason `AppState::read_as` documents: a fallback would be the
    /// only branch a fixture without a `ScopedPool` takes and the one branch a
    /// deployed server never takes, so no test could tell a stamped read from
    /// an unstamped one, and on a deployed server it would hide rows from their
    /// own owners without an error. `tool` names the caller in the refusal and
    /// in the log line.
    ///
    /// # Errors
    /// [`ServiceError::Internal`] naming the fix when this context was not
    /// built with [`Self::with_scoped_pool`]; [`ServiceError::InternalLogged`]
    /// (the cause for the log only) when the connection or the stamp fails, including for a bypass
    /// viewer, which belongs on the maintenance session instead.
    pub async fn read_as(
        &self,
        viewer: &Viewer,
        tool: &'static str,
    ) -> Result<epigraph_db::ScopedRead<'_>, ServiceError> {
        let scoped = self.scoped.as_ref().ok_or_else(|| {
            tracing::error!(
                target: "tenancy.scoped_read",
                tool,
                "read refused: this MCP process was not built from a ScopedPool"
            );
            ServiceError::Internal(format!(
                "{tool}: this MCP server was not built from a ScopedPool, so this read cannot \
                 be stamped with the caller's tenancy context. Refusing rather than reading on \
                 the plain application pool, where row security admits public rows only and \
                 the caller's own group-private rows would be silently missing. Nothing was \
                 read. Construct the server with EpiGraphMcpFull::with_scoped_pool."
            ))
        })?;
        scoped
            .read_as(viewer)
            .await
            .map_err(|e| ServiceError::InternalLogged {
                message: format!("{tool}: could not acquire a viewer-stamped connection"),
                cause: e.to_string(),
            })
    }
}

/// The two things every author-stamped write needs and neither can be faked:
/// the [`epigraph_db::ScopedPool`] that can stamp a connection at all, and the
/// author's own [`Viewer`](epigraph_db::visibility::Viewer), proven to carry
/// write authority.
///
/// Extracted from [`begin_author_stamped_tx`] when the post-commit embed became
/// the second caller. It is ONE function rather than two copies because the
/// three refusals below are the whole safety argument — a second site that
/// resolved a viewer and skipped the empty-writable check would stamp a session
/// with an empty writable set and get a bare `42501` from whichever statement
/// ran first, which is precisely the diagnosis-free failure this module exists
/// to remove.
///
/// # Why it takes the pool and the `ScopedPool` rather than the server
///
/// Because the MCP server's `McpEmbedder` is the third caller and is not the
/// server: it holds its own `ScopedPool` (declared via
/// `McpEmbedder::with_scoped_pool`) and is cloned into detached background tasks
/// where no server reference survives — `tools/ingestion.rs`'s embed queue is
/// `tokio::spawn`ed with `Arc::clone(&server.embedder)` alone. Parameterising
/// here is what lets all three write paths share ONE refusal triple instead of a
/// second copy that resolved a viewer and skipped the empty-writable check.
///
/// # Errors
/// * `ServiceError::Internal` if this process was not built from a
///   [`epigraph_db::ScopedPool`] — never a fallback to the unstamped pool.
/// * `ServiceError::Internal` if the author's viewer cannot be resolved.
/// * `ServiceError::Internal` if that viewer has no writable group.
pub async fn author_write_authority<'p>(
    scoped: Option<&'p epigraph_db::ScopedPool>,
    pool: &sqlx::PgPool,
    author_agent_id: uuid::Uuid,
    tool_name: &'static str,
) -> Result<(&'p epigraph_db::ScopedPool, epigraph_db::visibility::Viewer), ServiceError> {
    let scoped = scoped.ok_or_else(|| {
        tracing::error!(
            target: "tenancy.scoped_write",
            tool = tool_name,
            "write refused: this MCP process was not built from a ScopedPool, so no \
             connection can be stamped with the author's tenancy context. Refusing rather \
             than writing on the unstamped pool, which commits the claim and then loses its \
             trace, evidence and AUTHORED edge to a 42501. Construct the server with \
             EpiGraphMcpFull::with_scoped_pool."
        );
        ServiceError::Internal(format!(
            "{tool_name}: this MCP server was not built from a ScopedPool, so the write \
             path cannot stamp a connection with the author's tenancy context. Nothing was \
             written. Construct the server with EpiGraphMcpFull::with_scoped_pool."
        ))
    })?;

    let author_viewer = epigraph_db::visibility::Viewer::resolve(pool, author_agent_id)
        .await
        .map_err(|e| {
            tracing::error!(
                target: "tenancy.scoped_write",
                tool = tool_name,
                author = %author_agent_id,
                error = %e,
                "could not resolve the author's viewer"
            );
            ServiceError::Internal(format!(
                "{tool_name}: could not resolve the author's viewer"
            ))
        })?;

    if author_viewer.writable_groups().is_empty() {
        tracing::error!(
            target: "tenancy.scoped_write",
            tool = tool_name,
            author = %author_agent_id,
            "write refused: the author's viewer carries NO writable group, so the session \
             would be stamped with an empty writable set and every tier-A WITH CHECK would \
             refuse this submission from inside the transaction. What is missing is a live \
             `admin`/`writer` membership in a group the submission's rows would be owned by. \
             Nothing was written."
        );
        return Err(ServiceError::Internal(format!(
            "{tool_name}: the author ({author_agent_id}) has no live writable group membership, \
             so no connection can be stamped with write authority for the rows this submission \
             would own. Nothing was written."
        )));
    }

    Ok((scoped, author_viewer))
}

/// Begin the ONE transaction an MCP submission runs in, stamped from the
/// **author's** viewer.
///
/// # Whose viewer: the author's, which since batch H-b IS the caller's
///
/// The author is a [`crate::write_identity::WriteIdentity`], which only
/// [`Ctx::write_identity`] (and, for one admin act,
/// [`Ctx::admin_borrowed_server_identity`]) constructs: the principal of the request's
/// own viewer, i.e. `auth.agent_id` over HTTP and the server's own agent on
/// stdio. Taking the newtype rather than a bare `Uuid` is the ratchet: no tool
/// can stamp from an agent it picked itself, and the compiler enumerates every
/// site. Before batch H-b every tool passed `server.agent_id()` here whatever
/// the transport, so an authenticated caller's writes were authored and stamped
/// as the shared server signer (#505 F5).
///
/// The rows a submission writes inherit `owner_group_id` from the AUTHOR
/// (`default_decl_for_author`: the author's personal group, or its operator's
/// for an operated agent), and migration 077's `WITH CHECK` on every
/// claim-derived table asks `owner_group_id = ANY(epigraph_writable_groups())`,
/// so the stamp must be the author's writable set.
/// `epigraph-db/tests/rls_enforcement.rs::an_unstamped_app_connection_cannot_write_a_claim_derived_row`
/// is the pin: its arm 3 stamps the author's group and succeeds, its arm 4
/// stamps a *different* real group and is still refused.
///
/// `Viewer::resolve` reads `group_memberships` through
/// `epigraph_live_memberships(uuid)`, a SECURITY DEFINER function granted to
/// `epigraph_app` (migration 077), so resolving on the *unstamped* pool returns
/// the author's real memberships rather than the empty set
/// `group_memberships_tenancy` would otherwise yield. That is what makes this
/// bootstrap non-circular.
///
/// # Why `None` is a refusal and never a fallback
///
/// Falling back to `server.pool` when no `ScopedPool` is attached is precisely
/// how the defect this exists to fix presents: the claim INSERT is admitted (by
/// an orphan `claims_privacy` policy, where one exists), the trace INSERT is
/// refused with `42501`, and the caller receives an error carrying no claim id
/// for a row that is now a permanent orphan. A loud refusal with nothing written
/// is the only safe shape. Same decision, same reasoning and the same
/// `tenancy.scoped_write` log target as
/// `epigraph-api/src/routes/groups.rs::rotate_key`.
///
/// # Why an empty writable set is a REFUSAL, and why the group is NOT ensured here
///
/// The stamp is taken from the viewer as it is at `BEGIN` time, and every row
/// this submission writes is owned by the author's personal group — so if that
/// group has no live writable membership, the viewer's writable set is EMPTY and
/// the `WITH CHECK` on `claims` / `reasoning_traces` / `evidence` refuses the
/// write from inside the transaction. Minting inside the transaction cannot
/// repair that either: `create_claim_idempotent`'s first statement is
/// `ClaimRepository::default_decl_for_author`, whose `personal_group_of` does
/// mint on a miss, but the GUCs were stamped before it ran and a session's
/// writable set is not re-read per statement. So the empty set is refused up
/// front: it reports the real cause — this author has no writable group —
/// instead of a `42501` from whichever statement happened to be first, and
/// nothing is half-written.
///
/// A belt-and-braces `ClaimRepository::personal_group_of_pool` call was added
/// here first and then REMOVED, because on this connection it is not the
/// read-first lookup its name promises. MEASURED on a migrated database, as
/// `epigraph_app` with no GUCs: `SELECT id FROM groups WHERE did_key = …`
/// returns **0 rows** for a group that exists — `groups_tenancy`'s USING is
/// `bypass OR definer_bypass OR id = ANY(session_groups) OR created_by_agent_id =
/// principal_id`, and on an unstamped app session every arm is false. So the read
/// is BLIND in production and `personal_group_of` would take its mint path on
/// EVERY submission; migration 077's `epigraph_ensure_personal_group` membership
/// statement was `ON CONFLICT (group_id, agent_id, epoch) DO UPDATE SET
/// revoked_at = NULL, role = 'admin'`, which was measured to take a revoked
/// membership from 0 live rows back to 1 — a privilege change hidden inside an
/// unrelated claim insert. Migration 105 makes that call refuse a revoked row
/// instead of reviving it, so the hazard is gone at its root; the call stays
/// removed because a per-submission control-plane write on the pool buys
/// nothing the refusal below does not already report.
/// `epigraph-db/tests/author_stamped_write_loop.rs` pins both measurements.
///
/// The group is therefore ensured exactly where it already was:
/// `server.rs::agent_id`'s PR-09 block, once per process, before either caller
/// reaches this function.
///
/// The refusal is the one part of this conversion that changes behaviour for a
/// deployment that currently works: on a superuser DSN `epigraph_bypass()` is
/// true, so a submission by an author with no writable group commits today. That
/// is exactly the configuration whose DSN change turned the same write into a
/// half-landed orphan, and a write that only succeeds because the session
/// bypasses RLS is not a write this path should be making.
///
/// # Errors
/// * `ServiceError::Internal` if this process was not built from a
///   [`epigraph_db::ScopedPool`].
/// * `ServiceError::Internal` if the author's viewer cannot be resolved, if
///   that viewer has no writable group, or if `BEGIN` / the GUC stamp fails.
pub async fn begin_author_stamped_tx<'p, H: ServiceHost + Sync + ?Sized>(
    host: &'p H,
    author: crate::write_identity::WriteIdentity,
    tool_name: &'static str,
) -> Result<epigraph_db::ScopedTx<'p>, H::Error> {
    begin_author_stamped_tx_for(host, author, tool_name, None).await
}

/// [`begin_author_stamped_tx`] for a claim write whose declared tenancy may
/// name a TEAM the author writes only through its live human (owner decision
/// D-V3, `docs/tenancy/claim-visibility-controls.md`).
///
/// `grant` is the [`epigraph_db::TeamWriteGrant`] that
/// `ClaimRepository::resolve_write_decl` returned, and only that function mints
/// one. With it, the stamp carries the team in its writable set
/// (`Viewer::with_team_write_grant`). The grant must name THIS author, or the
/// write is refused. Everything else, including all three refusals of
/// [`author_write_authority`], is unchanged.
///
/// # Errors
/// As [`begin_author_stamped_tx`], plus `ServiceError::Internal` for a grant
/// that names another agent.
pub async fn begin_author_stamped_tx_for<'p, H: ServiceHost + Sync + ?Sized>(
    host: &'p H,
    author: crate::write_identity::WriteIdentity,
    tool_name: &'static str,
    grant: Option<&epigraph_db::TeamWriteGrant>,
) -> Result<epigraph_db::ScopedTx<'p>, H::Error> {
    let ctx = host.ctx();
    let author_agent_id = author.agent_id();
    let (scoped, author_viewer) =
        author_write_authority(ctx.scoped.as_ref(), &ctx.pool, author_agent_id, tool_name)
            .await
            .map_err(H::service_error)?;
    let author_viewer = match grant {
        None => author_viewer,
        Some(g) => author_viewer.with_team_write_grant(g).ok_or_else(|| {
            H::service_error(ServiceError::Internal(format!(
                "{tool_name}: the team-write grant names agent {}, not the author {author_agent_id}; \
                 nothing was written",
                g.agent()
            )))
        })?,
    };

    scoped.begin_as(&author_viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_write",
            tool = tool_name,
            author = %author_agent_id,
            error = %e,
            "could not begin an author-stamped transaction"
        );
        H::service_error(ServiceError::Internal(format!(
            "{tool_name}: could not begin an author-stamped transaction"
        )))
    })
}

/// Resolve a claim write's `visibility` / `group_id` parameters for `author`
/// (docs/tenancy/claim-visibility-controls.md): team by default, else private,
/// never public unless asked. Runs BEFORE the author-stamped transaction
/// because a team the author writes only through its human (D-V3) must be
/// stamped into it ([`begin_author_stamped_tx_for`]). Every read is a migration
/// 206 or 107 definer. Since migration 346 the team lists answer only for the
/// session principal, so `ClaimRepository::resolve_write_decl` stamps `author`
/// for its one team read on the pool connection (and rolls the stamp back);
/// callers pass the request's own principal as `author`.
///
/// # Errors
/// `INVALID_PARAMS` for a malformed or contradictory pair, and the caller
/// [`ServiceError::Repository`] for a refused team or author (the MCP server
/// answers it through its `visibility_caller_error`).
pub async fn resolve_claim_visibility<H: ServiceHost + Sync + ?Sized>(
    host: &H,
    author: uuid::Uuid,
    visibility: Option<&str>,
    group_id: Option<&str>,
) -> Result<epigraph_db::ResolvedWriteDecl, H::Error> {
    let choice = epigraph_core::VisibilityChoice::parse_str(visibility, group_id)
        .map_err(|e| H::service_error(ServiceError::InvalidParams(e)))?;
    let ctx = host.ctx();
    let fault = |e| H::service_error(ServiceError::Fault(Fault::Sqlx(e)));
    let mut conn = ctx.pool.acquire().await.map_err(fault)?;
    epigraph_db::ClaimRepository::resolve_write_decl(&mut conn, author, choice)
        .await
        .map_err(|e| H::service_error(ServiceError::Repository(e)))
}
