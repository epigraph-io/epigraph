#![allow(clippy::doc_markdown)]
#![allow(clippy::wildcard_imports)]

use std::collections::HashSet;
use std::sync::Arc;

use http::request::Parts;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{tool, tool_router, ServerHandler};
use sqlx::PgPool;
use tokio::sync::Mutex;

use crate::embed::McpEmbedder;
use crate::errors::{internal_error, McpError};
use crate::tools;
use crate::types::*;

use epigraph_crypto::AgentSigner;

#[derive(Clone)]
pub struct EpiGraphMcpFull {
    pub(crate) tool_router: ToolRouter<Self>,
    pub(crate) pool: PgPool,
    /// The tenancy-aware pool, when this process built one.
    ///
    /// `Option` for the same reason as `epigraph_api::AppState::scoped`:
    /// `ScopedPool::connect` owns pool construction (the `after_release` scrub
    /// can only be installed at build time), so it cannot be wrapped around a
    /// `PgPool` a caller already has. The four legacy constructors set `None`;
    /// [`Self::with_scoped_pool`] is the one that populates it.
    ///
    /// `None` here means the WRITE path fails closed:
    /// `crate::claim_helper::begin_author_stamped_tx` refuses rather than
    /// running `submit_claim` / `memorize` on an unstamped connection, where the
    /// claim commits and its trace is then refused with `42501`.
    ///
    /// `Some` here does NOT license the three maintenance tools. They require a
    /// privileged maintenance pool attached to this `ScopedPool`, and a leased
    /// connection that passes `MaintenanceSession::assert_privileged` on every
    /// call. See `crate::maintenance::maintenance_viewer`.
    pub(crate) scoped: Option<epigraph_db::ScopedPool>,
    /// `Some(reason)` when the caller DECLARED that `pool` is a privileged
    /// (BYPASSRLS) maintenance pool — set only through
    /// [`Self::on_a_privileged_pool`]. The operator `ingest-document` CLI runs
    /// its whole ingest on `MaintenancePool`, where there is no tenancy context
    /// to stamp and a plain transaction is the correct shape. Declared rather
    /// than defaulted, mirroring `McpEmbedder::on_a_privileged_pool`: a server
    /// on an ORDINARY pool with no `ScopedPool` keeps failing closed.
    pub(crate) privileged_pool: Option<&'static str>,
    pub(crate) signer: Arc<AgentSigner>,
    pub(crate) agent_db_id: Arc<Mutex<Option<uuid::Uuid>>>,
    pub(crate) embedder: Arc<McpEmbedder>,
    pub(crate) read_only: bool,
    /// The federation gateway's routing table over downstream extension MCPs.
    /// Built once in `main` (from `EPIGRAPH_MCP_EXTENSIONS`) and injected into
    /// both transport paths. When no extensions are configured this is an empty
    /// registry ([`crate::federation::SharedFederation::empty`]) and the server
    /// behaves exactly as it did pre-federation. The plain `new`/`new_shared`
    /// constructors default to empty (mirroring the `claim_from_row` house rule
    /// of not widening a ~30-caller signature); `main` and any caller that has a
    /// registry use `new_with_federation`/`new_shared_with_federation`.
    ///
    /// Shared behind an `RwLock` so `main`'s reconnect timer can revive an
    /// extension that was unreachable at boot without restarting the process.
    pub(crate) federation: crate::federation::SharedFederation,
    /// `(llm_model, llm_prompt_hash)` when this server's agent identity was
    /// derived deterministically from an LLM config (see `main::select_signer`),
    /// else `None`. When `Some`, `agent_id()`'s CREATE branch records these on
    /// the freshly-created agent row via `AgentRepository::set_llm_properties`.
    /// `None` (the default for every unconfigured process) preserves the legacy
    /// behavior exactly — no properties are written.
    pub(crate) llm_identity: Option<(String, String)>,
    /// Whether this server's signer identity was DECLARED by the operator
    /// (`--agent-key` / `--agent-model`) rather than freshly generated per
    /// process (`main::select_signer` rung 4).
    ///
    /// Read only by [`crate::tools::claims::require_owner_or_admin`], whose
    /// no-`AuthContext` fallback compares a claim's author against
    /// [`Self::agent_id`]. That comparison is a meaningful ownership policy
    /// only when the signer is stable across restarts. With a per-process
    /// random keypair the server's agent UUID is a throwaway that authored
    /// nothing, so the comparison is undecidable rather than failed.
    ///
    /// Defaults to `true` (the strict, pre-existing behavior) in every
    /// constructor; `main` opts out via
    /// [`Self::with_generated_signer_identity`] on rung 4. Defaulting strict
    /// means no embedding caller can widen the gate by omission.
    pub(crate) signer_identity_declared: bool,
    /// Per-session memoization of auth-lineage principals already linked via an
    /// `OPERATED_BY` edge, so `call_tool` writes that edge at most once per
    /// distinct `auth.agent_id` per session (a fast in-memory short-circuit; the
    /// DB `create_if_not_exists` is the actual dedup authority). Empty at boot.
    pub(crate) seen_auth_lineage: Arc<Mutex<HashSet<uuid::Uuid>>>,
    /// Write-authorization gate — the MCP twin of `epigraph_api::AppState`'s
    /// `policy_gate` field, and injected for the same reason.
    ///
    /// PR-11's first pass constructed `epigraph_authz::GroupPolicyGate::new()`
    /// *inline* inside `tools::perspectives::require_declassify_authority`,
    /// which made `AppState::with_policy_gate` — the documented seam for a
    /// deployment that installs its own policy — reach the HTTP surface and
    /// silently not the MCP one. The two surfaces would have diverged the first
    /// time anyone exercised the override, on the transport where the divergence
    /// matters most: `call_tool` runs `enforce_tool_scope` only for HTTP calls,
    /// so on stdio this gate is the only authorization that runs at all.
    ///
    /// Defaults to `GroupPolicyGate` in every constructor;
    /// [`Self::with_policy_gate`] replaces it.
    pub(crate) policy_gate: Arc<dyn epigraph_interfaces::PolicyGate>,
}

impl EpiGraphMcpFull {
    /// The server's own `agents.id`, for callers outside this crate's `crate::`
    /// visibility — specifically `main.rs`, which needs it to build the
    /// `--allow-unauthenticated-http` principal before the router is layered.
    ///
    /// # Errors
    ///
    /// Propagates whatever [`Self::agent_id`] returns.
    pub async fn server_agent_id(&self) -> Result<uuid::Uuid, McpError> {
        self.agent_id().await
    }
}

/// Builds the per-session servers of ONE HTTP listener, all sharing ONE
/// resolution of the server's own `agents.id`.
///
/// # Why this exists (backlog F1, `da432f25`)
///
/// rmcp's streamable-HTTP transport calls its factory closure once per SESSION,
/// and `main` used to build each session's server with
/// [`EpiGraphMcpFull::new_shared_with_federation`], which gives every server a
/// fresh, EMPTY `agent_db_id` cell. So [`EpiGraphMcpFull::agent_id`]'s
/// resolution — which ends in PR-09's `ensure_personal_group` call on the
/// UNSTAMPED pool — ran once per session, not once per process. On the old
/// migration-077 function that call is `ON CONFLICT … DO UPDATE SET revoked_at
/// = NULL, role = 'admin'`, so every new HTTP session re-opened any revocation
/// an operator had made of the server agent's personal membership. MEASURED on
/// the real binary as `epigraph_app` (`scripts/e2e/probe-unit-e.sh`,
/// PERSONAL-REVOKED fresh-session arm): `personal:admin(revoked)` came back
/// `(live)` and the first `ingest_document_inline` of the new session committed
/// +4 claims under it.
///
/// # The choice: resolve once per process, rather than discriminate per session
///
/// The alternative the backlog names is to apply the
/// `system_agent_write_authority` discriminator (a stamped read of the agent's
/// own rows) inside `agent_id()` on every session. That keeps one provisioning
/// attempt per session and makes each one safe. Sharing the cell removes the
/// attempts instead: the per-session servers are clones of one template, and
/// `EpiGraphMcpFull` is `Clone` over `Arc`s, so the clone SHARES `agent_db_id`.
/// MEASURED (`pg_stat_user_functions.calls` for `epigraph_ensure_personal_group`,
/// real binary as `epigraph_app`, `--allow-unauthenticated-http`, boot plus three
/// sequential sessions each calling one tool): 4 calls with a fresh cell per
/// session (the boot probe plus one per session), 1 call with the shared cell. A per-session write on what is, for every tool, a read
/// path is the thing removed. The one remaining per-process call cannot revive
/// a revocation made before the process started either: since migration 105
/// the provisioning function refuses a revoked row instead of restoring it.
///
/// # What is per-session, and stays so
///
/// Only `seen_auth_lineage`, the `OPERATED_BY` memo, whose doc makes it
/// per-session; [`Self::session`] resets it. Everything else a session server
/// holds is either immutable configuration or an `Arc` the old constructor
/// already shared (`signer`, `embedder`, `federation`, the `ScopedPool`).
///
/// # A cost, stated
///
/// `agent_id()` holds the cell's mutex across its database awaits. Sharing the
/// cell means that, until the FIRST resolution succeeds, concurrent sessions
/// queue on one mutex rather than each resolving on its own. After it succeeds
/// the lock is a cache read. `auth::UnauthenticatedPrincipal`'s cooldown already
/// bounds the unauthenticated listener's retry rate during an outage.
#[derive(Clone)]
pub struct SessionFactory {
    template: EpiGraphMcpFull,
}

impl SessionFactory {
    /// Wrap a fully configured server (scoped pool, signer-identity flag and
    /// policy gate already applied) as the template every session clones.
    #[must_use]
    pub fn new(template: EpiGraphMcpFull) -> Self {
        Self { template }
    }

    /// A server for one new session: a clone of the template that SHARES its
    /// `agent_db_id` cell and starts with an empty `OPERATED_BY` memo.
    #[must_use]
    pub fn session(&self) -> EpiGraphMcpFull {
        let mut srv = self.template.clone();
        srv.seen_auth_lineage = Arc::new(Mutex::new(HashSet::new()));
        srv
    }
}

/// Lets `auth::UnauthenticatedPrincipal` re-attempt the resolution on a later
/// request instead of treating a boot-time failure as final.
///
/// No caching is added here because [`EpiGraphMcpFull::agent_id`] already has the
/// right semantics: it writes `agent_db_id` only in the success arm, so a failed
/// attempt leaves the cell empty and the next call tries again, while a
/// successful one costs a mutex lock thereafter.
#[async_trait::async_trait]
impl crate::auth::ServerPrincipalSource for EpiGraphMcpFull {
    async fn resolve_server_agent_id(&self) -> Result<uuid::Uuid, String> {
        self.agent_id().await.map_err(|e| format!("{e:?}"))
    }
}

impl EpiGraphMcpFull {
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
    pub(crate) async fn agent_id(&self) -> Result<uuid::Uuid, McpError> {
        let mut cached = self.agent_db_id.lock().await;
        if let Some(id) = *cached {
            return Ok(id);
        }
        let pub_key = self.signer.public_key();
        let agent = if let Some(a) =
            epigraph_db::AgentRepository::get_by_public_key(&self.pool, &pub_key)
                .await
                .map_err(internal_error)?
        {
            a
        } else {
            let agent = epigraph_core::Agent::new(pub_key, Some("mcp-agent".to_string()));
            let created = epigraph_db::AgentRepository::create(&self.pool, &agent)
                .await
                .map_err(internal_error)?;
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
                if let Err(e) =
                    epigraph_db::AgentRepository::ensure_personal_group(&mut conn, id).await
                {
                    tracing::warn!(
                        agent_id = %id,
                        error = %e,
                        "did not provision the server agent's personal group (a revoked \
                         membership is refused, never restored); its viewer resolves to its \
                         remaining live groups only"
                    );
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

    /// Emit a durable `tool.invoked` event for an MCP dispatch.
    ///
    /// Called from `ServerHandler::call_tool` for every tool invocation
    /// (closes #61's tool.invoked requirement). Public so integration
    /// tests can exercise the same wiring without having to synthesize a
    /// full `rmcp::service::RequestContext`. Always best-effort: failure
    /// to publish must not break dispatch.
    pub async fn emit_tool_invoked(&self, tool_name: &str) {
        let actor_id = match self.agent_id().await {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::warn!(
                    tool = tool_name,
                    error = ?e,
                    "tool.invoked: could not resolve MCP agent_id; recording event with NULL actor"
                );
                None
            }
        };

        let _ = epigraph_db::EventRepository::publish_or_log(
            &self.pool,
            "tool.invoked",
            actor_id,
            &serde_json::json!({
                "tool": tool_name,
                "read_only": self.read_only,
            }),
        )
        .await;
    }

    /// Record an `OPERATED_BY` auth-lineage edge from THIS MCP agent to the
    /// principal a caller authenticated as:
    ///   `mcp_agent --OPERATED_BY--> principal`   (prov:actedOnBehalfOf)
    ///
    /// Called from `call_tool` once the caller's `AuthContext.agent_id` is known
    /// (HTTP path only; `None`/stdio -> no call). Factored out of `call_tool`,
    /// and made `pub`, so integration tests can exercise this wiring **without
    /// synthesizing a full `rmcp::service::RequestContext`** (mirrors
    /// [`emit_tool_invoked`](Self::emit_tool_invoked)).
    ///
    /// Semantics:
    /// - `principal == None` -> no-op (nothing to attribute).
    /// - Memoized per session via `seen_auth_lineage`: a principal already linked
    ///   in this session short-circuits before touching the DB. The DB
    ///   `create_if_not_exists` is the true idempotency authority (exactly one
    ///   edge across processes); the set is only a fast in-memory guard.
    /// - **Best-effort**: any failure (e.g. a stale `principal` that no longer
    ///   exists, which trips the `validate_edge_reference` existence trigger) is
    ///   logged at WARN and swallowed. The caller's tool result is NEVER affected.
    ///
    /// `OPERATED_BY` is an agent→agent relationship in the edge vocabulary
    /// (`epigraph_core::edge::relationships::OPERATED_BY`, also in the HTTP
    /// `VALID_RELATIONSHIPS` allow-list); `create_if_not_exists` does no
    /// relationship-vocab validation, so the write is accepted whenever both
    /// agent rows exist.
    pub async fn record_auth_lineage(&self, principal: Option<uuid::Uuid>) {
        let Some(principal) = principal else {
            return;
        };
        // Fast per-session short-circuit (lock released before any await on the DB).
        let already_seen = { self.seen_auth_lineage.lock().await.contains(&principal) };
        if already_seen {
            return;
        }

        let mcp_agent = match self.agent_id().await {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    principal = %principal,
                    error = ?e,
                    "could not resolve MCP agent_id for auth-lineage edge; skipping"
                );
                return;
            }
        };

        match epigraph_db::EdgeRepository::create_if_not_exists(
            &self.pool,
            mcp_agent,
            "agent",
            principal,
            "agent",
            epigraph_core::edge::relationships::OPERATED_BY,
            None,
            None,
            None,
        )
        .await
        {
            Ok(_) => {
                self.seen_auth_lineage.lock().await.insert(principal);
            }
            Err(e) => {
                tracing::warn!(
                    mcp_agent = %mcp_agent,
                    principal = %principal,
                    error = ?e,
                    "failed to write OPERATED_BY auth-lineage edge; \
                     continuing (tool result unaffected)"
                );
            }
        }
    }

    /// Return a JSON array of all registered MCP tools (name, description, schema).
    ///
    /// This is a static operation — no database access required. Used by the REST
    /// discovery endpoint so agents can introspect available tools at runtime.
    #[must_use]
    pub fn all_tools_json() -> serde_json::Value {
        let tools = Self::tool_router().list_all();
        serde_json::to_value(tools).unwrap_or(serde_json::Value::Array(vec![]))
    }

    /// Look up the required scope for `tool_name` and verify the
    /// caller has it. Returns `Err` with a JSON-RPC-style error if:
    /// - no `AuthContext` is attached (token validation never ran or
    ///   middleware was bypassed), or
    /// - the tool is not in `scope_map::SCOPE_MAP` (deny by default), or
    /// - the caller's token is missing the required scope.
    pub fn enforce_tool_scope(
        auth: Option<&epigraph_auth::AuthContext>,
        tool_name: &str,
    ) -> Result<(), McpError> {
        let Some(auth) = auth else {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Borrowed(
                    "Unauthorized: no auth context (Bearer token required)",
                ),
                data: None,
            });
        };
        let Some(required) = crate::scope_map::required_scope(tool_name) else {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Owned(format!(
                    "Forbidden: tool '{tool_name}' is not authorized (no scope mapping)"
                )),
                data: None,
            });
        };
        if !auth.has_scope(required) {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Owned(format!(
                    "Forbidden: tool '{tool_name}' requires scope '{required}'"
                )),
                data: None,
            });
        }
        Ok(())
    }

    /// Error for a tool name that **no route owns**: neither the static
    /// `tool_router` nor any mounted federation route.
    ///
    /// # Why this is not `enforce_tool_scope`'s job
    ///
    /// Before this existed, such a name fell through to
    /// [`enforce_tool_scope`](Self::enforce_tool_scope), whose deny-by-default
    /// arm answered `"Forbidden: tool 'X' is not authorized (no scope
    /// mapping)"`. That message describes the caller's credentials, and the
    /// caller's credentials were never consulted — the name simply does not
    /// route. Backlog ee50d10d is that misattribution reported as an
    /// authorization regression: `attach_blob` is a FEDERATED episcience tool
    /// with zero occurrences in this crate, so every call for it while the
    /// extension was unmounted produced an authz-shaped 403 and read as "the
    /// tool lost its authorization mid-session".
    ///
    /// `enforce_tool_scope` KEEPS its deny-by-default arm: it is the
    /// fail-closed gate for any name absent from `SCOPE_MAP`, and narrowing it
    /// to "known tools only" would be a fail-open. This function runs earlier
    /// and only for names that provably route nowhere, so the gate's behaviour
    /// is unchanged for every name it still sees.
    ///
    /// `unhealthy_extensions` comes from
    /// [`SharedFederation::unhealthy_extension_candidates`](crate::federation::SharedFederation::unhealthy_extension_candidates)
    /// — names only, never addresses. A configured-but-unreachable extension is
    /// the single most likely reason a name that *should* route does not, and
    /// saying so converts a dead end into a diagnosis.
    #[must_use]
    pub fn unknown_tool_error(tool_name: &str, unhealthy_extensions: &[String]) -> McpError {
        let mut message = format!(
            "Unknown or unavailable tool '{tool_name}': it is not a kernel tool and no mounted \
             extension provides it. This is a ROUTING failure, not an authorization failure — \
             your token's scopes were never consulted."
        );
        if !unhealthy_extensions.is_empty() {
            message.push_str(&format!(
                " Configured extension(s) currently unreachable: {}. If one of them owns this \
                 tool, it will route again once the gateway reconnects.",
                unhealthy_extensions.join(", ")
            ));
        }
        McpError {
            code: rmcp::model::ErrorCode::INVALID_REQUEST,
            message: std::borrow::Cow::Owned(message),
            data: None,
        }
    }

    /// Scope gate for FEDERATED tools, kept deliberately separate from
    /// [`enforce_tool_scope`](Self::enforce_tool_scope).
    ///
    /// Federated tools are NOT in the static `SCOPE_MAP` (its coverage is a
    /// compile-time invariant over kernel tools only), so the static gate would
    /// fail them closed with "no scope mapping". Instead the required scope comes
    /// from the extension's `EPIGRAPH_MCP_EXTENSIONS` config (`scope=…`), passed
    /// here as `required`. Same fail-closed shape as the static gate: no
    /// `AuthContext` (stdio, or middleware bypassed) is a hard reject, and a
    /// caller lacking the extension's scope is forbidden.
    pub fn enforce_federated_scope(
        auth: Option<&epigraph_auth::AuthContext>,
        tool_name: &str,
        required: &str,
    ) -> Result<(), McpError> {
        let Some(auth) = auth else {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Borrowed(
                    "Unauthorized: federated tools require a Bearer token (no auth context; \
                     not available over stdio)",
                ),
                data: None,
            });
        };
        if !auth.has_scope(required) {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Owned(format!(
                    "Forbidden: federated tool '{tool_name}' requires scope '{required}'"
                )),
                data: None,
            });
        }
        Ok(())
    }

    /// Return an error if the server is in read-only mode.
    pub(crate) fn reject_if_read_only(&self) -> Result<(), McpError> {
        if self.read_only {
            Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Borrowed(
                    "Server is in read-only mode. Write operations are disabled.",
                ),
                data: None,
            })
        } else {
            Ok(())
        }
    }
}

#[tool_router]
impl EpiGraphMcpFull {
    #[must_use]
    pub fn new(pool: PgPool, signer: AgentSigner, embedder: McpEmbedder, read_only: bool) -> Self {
        Self::new_with_federation(
            pool,
            signer,
            embedder,
            read_only,
            crate::federation::SharedFederation::empty(),
            None,
        )
    }

    /// Like [`new`](Self::new) but with a caller-supplied federation registry.
    /// `main` uses this for the stdio path so stdio's `list_tools` surfaces the
    /// same federated tools as the HTTP path (the registry is populated at build
    /// time with the discovery service token, independent of transport).
    #[must_use]
    pub fn new_with_federation(
        pool: PgPool,
        signer: AgentSigner,
        embedder: McpEmbedder,
        read_only: bool,
        federation: crate::federation::SharedFederation,
        llm_identity: Option<(String, String)>,
    ) -> Self {
        Self {
            tool_router: Self::tool_router(),
            pool,
            scoped: None,
            privileged_pool: None,
            signer: Arc::new(signer),
            agent_db_id: Arc::new(Mutex::new(None)),
            embedder: Arc::new(embedder),
            read_only,
            federation,
            llm_identity,
            signer_identity_declared: true,
            seen_auth_lineage: Arc::new(Mutex::new(HashSet::new())),
            policy_gate: Arc::new(epigraph_authz::GroupPolicyGate::new()),
        }
    }

    /// Attach a [`epigraph_db::ScopedPool`] to an already-built server.
    ///
    /// The only way `self.scoped` becomes `Some`, and therefore the only way the
    /// write path can stamp a connection with the author's tenancy context
    /// (`crate::claim_helper::begin_author_stamped_tx`). Consumed and returned so
    /// it composes with the four existing constructors rather than forcing a
    /// fifth:
    ///
    /// **This does NOT enable the three maintenance tools, and a reader
    /// reasonably expects that it would.** Those tools run on a connection leased
    /// from a separate, privileged maintenance pool that must be attached to the
    /// `ScopedPool` itself (`ScopedPool::with_maintenance_pool`, done by `main`
    /// only when the maintenance DSN's boot probe passes). Without one,
    /// `maintenance_viewer` refuses them, because a bypass viewer spent on the
    /// application pool returns zero rows with no error.
    /// `maintenance.rs::tests::attaching_a_scoped_pool_does_not_enable_the_maintenance_tools`
    /// is the pin.
    ///
    /// ```ignore
    /// let server = EpiGraphMcpFull::new(pool, signer, embedder, ro)
    ///     .with_scoped_pool(scoped);
    /// ```
    #[must_use]
    pub fn with_scoped_pool(mut self, scoped: epigraph_db::ScopedPool) -> Self {
        self.scoped = Some(scoped);
        self
    }

    /// Declare that this server's `pool` is a PRIVILEGED (BYPASSRLS)
    /// maintenance pool, so a write path that would otherwise stamp a
    /// connection may run a plain transaction on it instead. `reason` is
    /// required and is logged by the paths that honour it.
    ///
    /// Honoured today ONLY by the document ingest walk
    /// (`tools::ingestion::do_ingest_document` / `_spine`), which the operator
    /// `ingest-document` CLI drives on `MaintenancePool`. Every other write path
    /// still requires [`Self::with_scoped_pool`] and fails closed without it.
    #[must_use]
    pub fn on_a_privileged_pool(mut self, reason: &'static str) -> Self {
        self.privileged_pool = Some(reason);
        self
    }

    /// Create from pre-wrapped `Arc` values (for HTTP transport factory closure).
    /// Federation defaults to empty; the HTTP factory in `main` uses
    /// [`new_shared_with_federation`](Self::new_shared_with_federation) to inject
    /// the live registry per session.
    #[must_use]
    pub fn new_shared(
        pool: PgPool,
        signer: Arc<AgentSigner>,
        embedder: Arc<McpEmbedder>,
        read_only: bool,
    ) -> Self {
        Self::new_shared_with_federation(
            pool,
            signer,
            embedder,
            read_only,
            crate::federation::SharedFederation::empty(),
            None,
        )
    }

    /// Like [`new_shared`](Self::new_shared) but with a caller-supplied
    /// federation registry. The HTTP transport factory closure in `main` clones
    /// the one `SharedFederation` built at boot into every per-session server
    /// via this constructor, so a reconnect on the shared registry is visible to
    /// every session immediately.
    #[must_use]
    pub fn new_shared_with_federation(
        pool: PgPool,
        signer: Arc<AgentSigner>,
        embedder: Arc<McpEmbedder>,
        read_only: bool,
        federation: crate::federation::SharedFederation,
        llm_identity: Option<(String, String)>,
    ) -> Self {
        Self {
            tool_router: Self::tool_router(),
            pool,
            scoped: None,
            privileged_pool: None,
            signer,
            agent_db_id: Arc::new(Mutex::new(None)),
            embedder,
            read_only,
            federation,
            llm_identity,
            signer_identity_declared: true,
            seen_auth_lineage: Arc::new(Mutex::new(HashSet::new())),
            policy_gate: Arc::new(epigraph_authz::GroupPolicyGate::new()),
        }
    }

    /// Mark this server's signer identity as GENERATED — i.e. the operator
    /// declared neither `--agent-key` nor `--agent-model`, so
    /// `main::select_signer` fell through to `AgentSigner::generate()` and the
    /// signer is a fresh random keypair that exists only for this process.
    ///
    /// The single consumer is
    /// [`crate::tools::claims::require_owner_or_admin`]. Its no-`AuthContext`
    /// fallback (stdio) asks "is this claim authored by *this server's* agent?"
    /// — a question whose answer is structurally `no` for every pre-existing
    /// claim once the signer is random per process. Flagging the condition lets
    /// that fallback distinguish "not the owner" (a real denial) from "there is
    /// no stable owner to compare against" (undecidable).
    ///
    /// Consumed-self builder rather than a constructor parameter: both
    /// `new_*_with_federation` signatures already carry six arguments and every
    /// caller except `main` wants the strict default.
    #[must_use]
    pub fn with_generated_signer_identity(mut self) -> Self {
        self.signer_identity_declared = false;
        self
    }

    /// Inject a deployment's own write-authorization gate (builder pattern).
    ///
    /// The MCP counterpart of `epigraph_api::AppState::with_policy_gate`. Both
    /// exist so a deployment installs **one** policy and gets it on **both**
    /// surfaces; a gate installed on only one of them is a fail-open relative to
    /// the configured policy on whichever surface was missed.
    ///
    /// Consumed-self builder rather than a seventh constructor parameter, for
    /// the same reason as [`Self::with_generated_signer_identity`]: both
    /// `new_*_with_federation` signatures already carry six arguments and every
    /// caller except a deployment with its own policy wants the default.
    #[must_use]
    pub fn with_policy_gate(mut self, gate: Arc<dyn epigraph_interfaces::PolicyGate>) -> Self {
        self.policy_gate = gate;
        self
    }

    // ── Claims (11 tools) ──

    #[tool(
        description = "Submit an epistemic claim with evidence. The full evidence text is preserved for human audit. Supports all evidence types (empirical 1.0x, statistical 0.9x, logical 0.85x, testimonial 0.6x). Prefer this over memorize when you have a source or data to cite. The claim is authored by this server's agent and owned by that agent's personal group: if an operator has revoked the agent's personal-group membership, the call is refused and writes nothing. It never restores the membership; restoring it is an operator action. All-or-nothing: the claim, its evidence, reasoning trace, verb-edges and its Dempster-Shafer belief (BBA, frame assignment, cached belief and derived truth_value) commit together; if the belief cannot be wired the call fails and nothing is written, so a retry is safe. Only the embedding is best-effort after commit (embedded=false). If the claim already existed the response carries a deduplicated block {by: 'content_hash' | 'novelty_gate', existing_claim_id, inputs_applied, inputs_discarded}; it is absent on a fresh insert. content_hash (this agent already stored byte-identical content): labels are merged and a new evidence row and reasoning trace are recorded, but the existing belief and truth_value do not change. novelty_gate (a near-identical current claim exists, possibly another agent's): nothing from this call is written."
    )]
    async fn submit_claim(
        &self,
        Parameters(params): Parameters<SubmitClaimParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::claims::submit_claim(self, viewer, params).await
    }

    #[tool(
        description = "Query epistemic claims by truth value threshold. Returns claims with their truth values and epistemic status."
    )]
    async fn query_claims(
        &self,
        Parameters(params): Parameters<QueryClaimsParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::claims::query_claims(self, viewer, params).await
    }

    #[tool(
        description = "List claims that have NEVER been decomposed — claims that are neither parent (source) nor child (target) of any decomposes_to edge. These are standalone claims from non-hierarchical paths (memorize, submit_claim, legacy imports). Excludes host-telemetry claims and content <=10 chars. Ordered oldest-first. Step 1 of the 'Process undecomposed claims through decomposition pipeline' workflow; feed the returned claim_ids to the decompose_claims CLI."
    )]
    async fn query_undecomposed_claims(
        &self,
        Parameters(params): Parameters<crate::types::QueryUndecomposedClaimsParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::claims::query_undecomposed_claims(self, viewer, params).await
    }

    #[tool(
        description = "Retrieve a single epistemic claim by its UUID, including full epistemic state."
    )]
    async fn get_claim(
        &self,
        Parameters(params): Parameters<GetClaimParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::claims::get_claim(self, viewer, params).await
    }

    #[tool(
        description = "Verify a claim's Ed25519 signature and BLAKE3 content hash. Reports whether the claim has been tampered with."
    )]
    async fn verify_claim(
        &self,
        Parameters(params): Parameters<VerifyClaimParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::claims::verify_claim(self, viewer, params).await
    }

    #[tool(
        description = "Add new evidence to an existing claim and run a Dempster-Shafer belief update. Returns the before/after truth values plus belief_wired. The call is ATOMIC: the evidence row, its BBA, the truth_value update and any label merge commit together in one transaction or not at all. On success belief_wired and bba_stored are always true (both fields are retained for client compatibility). If the belief update fails, the call returns an error naming the failing step (e.g. `assign_claim: ...`) and writes nothing, so re-submitting the identical evidence_data once the cause is fixed is safe and is the recovery."
    )]
    async fn update_with_evidence(
        &self,
        Parameters(params): Parameters<UpdateWithEvidenceParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::claims::update_with_evidence(self, viewer, params).await
    }

    #[tool(
        description = "Create a new claim that supersedes an existing one (semantic versioning). Old claim's is_current flips to false; new claim's supersedes column points at the old. NEW CLAIM INHERITS THE OLD CLAIM'S agent_id. The read, the retirement and the new claim commit together on one transaction stamped from this server's agent: a claim the caller cannot read is reported as not found, and one owned by a group this server's agent cannot write is refused with nothing written. Use mark_duplicate to mark a duplicate WITHOUT creating a new claim."
    )]
    async fn supersede_claim(
        &self,
        Parameters(params): Parameters<crate::types::SupersedeClaimParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        crate::tools::supersede::supersede_claim(self, viewer, params, auth).await
    }

    #[tool(
        description = "Mark a claim as a duplicate of a canonical claim WITHOUT creating a new claim. Sets supersedes+is_current=false on the duplicate; canonical untouched. Use REST endpoint POST /api/v1/claims/:id/dedup for audit-trail provenance."
    )]
    async fn mark_duplicate(
        &self,
        Parameters(params): Parameters<crate::types::MarkDuplicateParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        crate::tools::supersede::mark_duplicate(self, viewer, params, auth).await
    }

    #[tool(
        description = "Atomically add and/or remove labels on an existing claim. Idempotent. Adding or removing the 'resolved' label requires claims:admin or ownership of the claim when the caller is authenticated (HTTP)."
    )]
    async fn update_labels(
        &self,
        Parameters(params): Parameters<crate::types::UpdateLabelsParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        // Needed only for the `resolved`-label gate (issue #374); every other
        // label mutation ignores it. Same propagation as `resolve_backlog_item`.
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        // Viewer acquired HERE, not inside the tool module. `tool_viewer_coverage`'s
        // `viewer_acquisition_lives_in_server_rs_not_in_the_tool_modules` asserts
        // `request_viewer(` appears under src/tools/ only in viewer.rs, and the
        // sibling partition test reads THIS file to decide which tools derive a
        // viewer — so acquiring it in the tool body would make that register
        // silently wrong about this tool rather than merely unscoped.
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        crate::tools::claims::update_labels(self, viewer, params, auth).await
    }

    #[tool(
        description = "Retire a backlog claim in one call: submits a resolution claim via the canonical submit_claim pipeline (idempotent create + Evidence + Trace + DERIVED_FROM/HAS_TRACE/AUTHORED edges + DS auto-wire + embedding), prefixed with 'Resolves <original_id>: ' and labeled ['resolved'], then patches the original claim's labels with add=['resolved'] (keeping 'backlog'). Label-side retirement — original stays is_current=true / supersedes=None. Optionally takes basis_claim_ids: the claims that justified the closure, each recorded as a `basis -justifies-> resolution` edge so a later retraction of a basis can be reverse-queried to find the closures resting on it (it does not reopen anything by itself). Returns {resolution_claim_id, original_id, original_labels, basis_claim_ids, basis_edge_ids}. All-or-nothing: the resolution claim, its justifies edges and the original's 'resolved' label commit together on one transaction with this server's agent's write authority, or nothing is written and the call fails (a retry is safe). An original owned by a group this server's agent cannot write (another agent's claim) is refused that way even with claims:admin. Only the resolution claim's embedding runs after commit, best-effort."
    )]
    async fn resolve_backlog_item(
        &self,
        Parameters(params): Parameters<crate::types::ResolveBacklogItemParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        // For HTTP callers `call_tool` copies the AuthContext into
        // `context.extensions` so admin-scope holders can bypass the
        // agent-equality ownership check. For stdio (no auth context)
        // we pass `None` and the handler falls back to agent-equality
        // against the server's own signer agent.
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        crate::tools::claims::resolve_backlog_item(self, viewer, params, auth).await
    }

    #[tool(
        description = "Patch a claim atomically (trace_id, properties JSONB merge, label add/remove). FAST PATH — does NOT emit provenance. Use REST PATCH /api/v1/claims/:id if audit trail required. When the caller is authenticated (HTTP), the whole patch requires claims:admin or ownership of the claim, as PATCH /api/v1/claims/:id does. All-or-nothing: the whole patch lands or nothing does. A claim you cannot read is reported as not found. A claim owned by a group this server's agent cannot write (another agent's claim) is refused with nothing written, even with claims:admin."
    )]
    async fn patch_claim(
        &self,
        Parameters(params): Parameters<crate::types::PatchClaimParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        // See `update_labels` — `add_labels`/`remove_labels` reach the same gate,
        // and the viewer is acquired here for the same register reason.
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        crate::tools::claims::patch_claim(self, viewer, params, auth).await
    }

    // ── Provenance (1 tool) ──

    #[tool(
        description = "Get the provenance lineage for a claim — all ancestor claims, evidence, and reasoning traces in topological order."
    )]
    async fn get_provenance(
        &self,
        Parameters(params): Parameters<GetProvenanceParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::provenance::get_provenance(self, viewer, params).await
    }

    #[tool(
        description = "Trace the full derivation chain behind a conclusion claim in ONE call \
                       — walks supports/corroborates/elaborates/decomposes_to backwards and \
                       supersedes forwards, returning nodes in topological order (evidence \
                       first, conclusion last) plus the connecting edges. Cycles are reported, \
                       not errors; superseded ancestors are included and flagged."
    )]
    async fn get_provenance_chain(
        &self,
        Parameters(params): Parameters<crate::types::GetProvenanceChainParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::provenance_chain::get_provenance_chain(self, viewer, params).await
    }

    #[tool(
        description = "Query the recall audit log — which claims a recall query returned, \
                       for which agent, when. Filter by claim_id to answer 'which queries \
                       ever surfaced this claim?'. query_embedding_hash distinguishes a \
                       corpus change from an embedder change when a replayed query differs."
    )]
    async fn get_recall_events(
        &self,
        Parameters(params): Parameters<crate::types::GetRecallEventsParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::recall_events::get_recall_events(self, viewer, params).await
    }

    #[tool(
        description = "Consolidate 2..=20 near-duplicate claims into ONE caller-synthesized \
                       claim. Each source is retired with a forwarding pointer to the merged \
                       claim, its edges migrated (cross-source duplicates collapsed so \
                       Dempster-Shafer mass is not double-counted), and lineage recorded as \
                       supersedes edges plus properties.merge. The caller supplies \
                       merged_content; the server never calls an LLM. ALL-OR-NOTHING: on any \
                       error no merged claim is written and no source is retired, so retrying \
                       a failed call is safe. A source owned by a group this server's agent \
                       cannot write, or sources spanning two owner groups, is refused \
                       permanently (sometimes as INTERNAL_ERROR); do not retry it. After a \
                       success the sources are no longer current, so repeating the call fails \
                       with 'source ... is not current', which means the first call landed. If \
                       this agent already holds a claim with identical merged_content, that \
                       claim is returned with already_existed=true and nothing changes."
    )]
    async fn consolidate_claims(
        &self,
        Parameters(params): Parameters<crate::types::ConsolidateClaimsParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::consolidate::consolidate_claims(self, viewer, params).await
    }

    #[tool(
        description = "Sweep a page of the corpus for semantic near-duplicates, clustering them \
                       with union-find and picking a survivor per cluster (highest truth, \
                       earliest wins ties). DRY RUN BY DEFAULT. Exact restatements are \
                       collapsed via mark_duplicate when dry_run=false; clusters that merely \
                       resemble each other are returned as merge_candidates for \
                       consolidate_claims so no wording is discarded. Resumable via offset. The sweep sees every tenant's claims, so it can pair a duplicate that spans two groups. Requires scope claims:admin over HTTP (it reads and writes across every tenant). Requires this server to have a privileged maintenance connection: start it with MAINTENANCE_DATABASE_URL explicitly set to a role that is a member of epigraph_maintenance; the application DSN is never used for this, even when it could bypass row-level security. Without one the call is refused with nothing written, and the boot log says why; it never reports a successful no-op."
    )]
    async fn sweep_semantic_duplicates(
        &self,
        Parameters(params): Parameters<crate::types::SweepSemanticDuplicatesParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        let mut session = crate::maintenance::maintenance_viewer(
            self,
            epigraph_db::visibility::SystemReason::DedupSweep,
        )
        .await?;
        tools::dedup_sweep::sweep_semantic_duplicates(self, &mut session, params).await
    }

    // ── Alternative-set candidate finder (1 tool) ──

    #[tool(
        description = "Suggest candidate alternative_of pairs: supporters of a shared target connected by a contradicts edge that are not already linked by alternative_of. Pure suggestion — operator promotes by submitting an explicit alternative_of edge. Returns ordered candidates with score = min(BetP_A, BetP_B)."
    )]
    async fn suggest_alternative_sets(
        &self,
        Parameters(params): Parameters<
            crate::tools::alternative_sets::SuggestAlternativeSetsParams,
        >,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        crate::tools::alternative_sets::suggest_alternative_sets(self, viewer, params).await
    }

    // ── Memory (2 tools) ──

    #[tool(
        description = "Quick-store a memory as a testimonial claim (0.6x evidence weight). For facts you want to recall later. Tags are persisted as claim labels — queryable via `query_claims_by_label`. The claim is authored by this server's agent and owned by that agent's personal group: if an operator has revoked the agent's personal-group membership, the call is refused and writes nothing. It never restores the membership; restoring it is an operator action. All-or-nothing: the claim, its tags, evidence, trace and Dempster-Shafer belief commit together; if the belief cannot be wired the call fails and nothing is written. Only the embedding is best-effort after commit. If the memory already existed the response carries a deduplicated block {by, existing_claim_id, inputs_applied, inputs_discarded}; it is absent on a fresh insert. content_hash: tags are merged, confidence is recorded only if the existing memory had no reasoning trace, and the belief does not change. novelty_gate: nothing from this call is written."
    )]
    async fn memorize(
        &self,
        Parameters(params): Parameters<MemorizeParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::memory::memorize(self, viewer, params).await
    }

    #[tool(
        description = "Recall relevant memories using semantic search with epistemic quality scoring. Optional theme_id / theme_label (from list_themes) PINS the candidate pool to one theme's members in SQL — on the hybrid dense leg, the hybrid lexical leg, and the embedder-down lexical fallback alike — before each leg's LIMIT, and echoes the resolved theme back as theme_scope. Unlike recall_with_context's diverse=true, which picks themes internally by centroid similarity and exposes neither the choice nor a way to override it. With offset, walks one theme to exhaustion: the response's paging.more_available (derived from the SQL page size, not the post-filtered results) is the stop condition, because min_truth / exclude_contested run after the page and can empty it while pages remain. theme_id/theme_label and offset are both rejected alongside include_workflows=true — workflows carry no theme_id and have no page-consistent counterpart. epistemic_partition=true CHANGES THE RESPONSE SHAPE: `results` is omitted and the same hits come back grouped under `epistemic_partition` as confirmed / uncertain / open_question. diversity_radius (cosine distance, (0.0,2.0], try 0.15) drops any hit too close to a better-ranked one already kept — it SHRINKS the page rather than back-filling, and hits with no measurable distance (workflow hits, unembedded claims, the embedder-down lexical leg) are always kept. The grouping is post-retrieval and order-preserving — same set, same ranking within each bucket — and contest wins over truth_value, so a 0.9 claim with a live refutation lands in open_question."
    )]
    async fn recall(
        &self,
        Parameters(params): Parameters<RecallParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::memory::recall(self, viewer, params).await
    }

    #[tool(
        description = "Paragraph-primary semantic search over the claim graph with batched structural context: parent paper, parent section, child atoms (with cross-paragraph bridges), sibling paragraphs, neighbor paragraphs reachable via continues_argument / atom-bridge / atom-atom-bridge, and CORROBORATES neighbors. Auto-detects centroid_dim (1536 vs 3072) by default. Set diverse=true (optional max_themes, diversity_weight) to spread results across multiple themes via submodular selection — falls back to flat ANN when the corpus has no themes yet. epistemic_partition=true CHANGES THE RESPONSE SHAPE: `results` is omitted and the same hits come back grouped under `epistemic_partition` as confirmed / uncertain / open_question. diversity_radius (cosine distance, (0.0,2.0], try 0.15) drops any hit too close to a better-ranked one already kept — it SHRINKS the page rather than back-filling, and hits with no measurable distance (workflow hits, unembedded claims, the embedder-down lexical leg) are always kept. The grouping is post-retrieval and order-preserving — same set, same ranking within each bucket — and contest wins over truth_value, so a 0.9 paragraph with a live refutation lands in open_question."
    )]
    async fn recall_with_context(
        &self,
        Parameters(params): Parameters<crate::tools::recall::RecallWithContextParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        crate::tools::recall::recall_with_context(self, viewer, params).await
    }

    #[tool(
        description = "Evolve a versioned step or operation by atomically creating a new claim that supersedes or revises an existing one. Use 'supersedes' for linear refinement; 'revises' for a concurrent branch from a common ancestor. The new claim shares the same step_lineage_id as the parent."
    )]
    async fn evolve_step(
        &self,
        Parameters(params): Parameters<crate::tools::evolve_step::EvolveStepParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        crate::tools::evolve_step::evolve_step(self, viewer, params).await
    }

    // ── Ingestion ──

    #[tool(
        description = "Ingest a hierarchical DocumentExtraction JSON file (thesis -> sections -> paragraphs -> atoms; the path must be inside the server's working directory). Creates a paper node, claims at each level, decomposes_to / section_follows / supports / contradicts / refines edges, evidence, traces, embeddings, and CDST mass functions for atoms. Same writer and same ASYNCHRONOUS contract as ingest_document_inline (read it): a write-authority refusal is a synchronous error with nothing written; otherwise the call returns {status: 'queued', paper_id, document_key} and the all-or-nothing walk runs in the background, where any failure (verbatim guard, malformed axis, a rejected row) reaches only the server log. Confirm it landed by query_paper(document_key)'s claim_count rising, not by the paper existing. Re-runs converge on existing nodes, so retrying is safe."
    )]
    async fn ingest_document(
        &self,
        Parameters(params): Parameters<IngestDocumentParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::ingestion::ingest_document(self, viewer, params).await
    }

    #[tool(
        description = "Check whether a paper has been ingested (has a processed_by edge). Returns {already_ingested, paper_id?, doi, pipeline_version}. Useful as a quick pre-flight read before calling ingest_document_spine. Note: with node-level dedup, already_ingested=true means the spine was previously run — it does NOT mean all atoms are present. Use ingest_document_spine to discover which paragraphs are new. The edge persists, so it cannot confirm a background ingest_document / ingest_document_inline of a document that was ingested or spine-ingested before; use query_paper's claim_count for that. Read-only."
    )]
    async fn check_already_ingested(
        &self,
        Parameters(params): Parameters<CheckAlreadyIngestedParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::ingestion::check_already_ingested(self, viewer, params).await
    }

    #[tool(
        description = "Phase 1 of the two-phase ingest flow. Ingests a DocumentExtraction with EMPTY atoms (e.g. output of structure_source): writes thesis + sections + paragraphs into the graph, ignores atom fields. Returns new_paragraph_paths — the paths (e.g. 'sections[0].paragraphs[1]') of paragraphs that are NEW to this ingest. Atomize only those paragraphs (LLM cost saved on already-ingested paragraphs), then call ingest_document_inline with atoms for those paths. Idempotent PER DOCUMENT: structural nodes are keyed on (document title, structural path, text), so re-running spine on a paper whose abstract was already ingested returns the abstract paragraphs in paragraphs_deduped and the new body paragraphs in new_paragraph_paths. A DIFFERENT paper that happens to share a section heading or a boilerplate paragraph does NOT dedup against it — each document owns its own spine. SYNCHRONOUS and all-or-nothing: on any error (including a refusal because this server's agent cannot write its personal group) no claims or edges are written, and retrying is safe. It writes the paper's processed_by edge, so check_already_ingested reports true from here on, before any atoms exist. A node another author already wrote is reused, never rewritten; converged_claims_unlabelled counts reused nodes you could not give this document's doi: label."
    )]
    async fn ingest_document_spine(
        &self,
        Parameters(params): Parameters<IngestDocumentSpineParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::ingestion::ingest_document_spine(self, params).await
    }

    #[tool(
        description = "Ingest a hierarchical DocumentExtraction passed INLINE (thesis -> sections -> paragraphs -> atoms) — same writer as `ingest_document` but the typed `extraction` is in the call, not a file path, so the full shape is self-documenting and no file write is needed (use this from MCP-only clients). Creates a paper node, claims at each level down to atoms, decomposes_to / section_follows / supports / contradicts / refines edges, evidence, traces, embeddings, and CDST mass functions for atoms (the mass functions are wired after the claims commit, best-effort). ASYNCHRONOUS: the call first checks write authority synchronously — if this server's agent cannot write its personal group (membership revoked or read-only) it returns an error and writes nothing — then creates the paper row and returns {status: 'queued', paper_id, document_key}, and everything else is written by a background task. That task is all-or-nothing: if it fails (verbatim-guard mismatch, malformed axis, a rejected row) the error reaches only the server log, no claims or edges are written, and retrying is safe. To confirm it landed, compare query_paper(document_key)'s claim_count before and after: the paper row exists as soon as the call returns, so finding the paper proves nothing, and check_already_ingested is already true after ingest_document_spine or any earlier ingest of the same document. Idempotent per document: structural nodes (thesis/section/paragraph) are keyed on (document title, structural path, text) and atoms on content hash, so re-ingesting a full paper after its abstract was ingested is safe — existing nodes are reused and only new content is written. Structural nodes are NOT shared between documents; atoms still converge across documents by design: an atom another author already stored is reused, never rewritten, and if its owner group is one you cannot write it does not get this document's doi: label. For AUTHORED records (an ELN entry, run summary, or other content with no external source to quote) omit the top-level source_text: the verbatim guard is then skipped and this is a supported SINGLE-CALL path — structure_source / ingest_document_spine are NOT required and exist only to re-verify EXTRACTED text byte-for-byte. For the two-phase flow that saves LLM atomization cost on extracted papers, use ingest_document_spine first. By default every atom's CDST mass function is placed on the binary {TRUE, FALSE} frame. To place atoms on a genuinely multi-valued field axis instead — an ordinal scale like {ineffective, mild, moderate, strong} or a categorical partition like {vata, pitta, kapha} — declare `axis: {frame, hypotheses, label}` on a paragraph (or on a section, inherited by its paragraphs), with optional per-atom `axis_labels` positionally overriding `label`. A binary opposition (safe/harmful) does NOT need an axis: model it as a proposition on {TRUE, FALSE} where harm is mass on FALSE. Frames dedupe by name, so one frame name must always mean one ordered hypothesis list; a malformed or inconsistent axis fails the ingest (in the background task, so only the server log shows it) rather than silently falling back to binary."
    )]
    async fn ingest_document_inline(
        &self,
        Parameters(params): Parameters<IngestDocumentInlineParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::ingestion::ingest_document_inline(self, viewer, params).await
    }

    #[tool(
        description = "Deterministically structure raw markdown/plaintext into a verbatim DocumentExtraction (sections + paragraphs as byte-exact source slices, source_text + spans populated, atoms EMPTY). This is for EXTRACTED source text that must be re-verified byte-for-byte; AUTHORED records (ELN entries, run summaries) need no structuring step and can call ingest_document_inline directly with source_text omitted. Fill atoms per paragraph and resubmit via ingest_document_inline. Read-only / no DB writes."
    )]
    async fn structure_source(
        &self,
        Parameters(params): Parameters<StructureSourceParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::ingestion::structure_source(self, params).await
    }

    #[tool(
        description = "Create a cross-tier structural edge between two existing claims (decomposes_to, section_follows, or continues_argument). Purpose-built for per-chapter ingest wire-ups (chapter thesis -> book thesis, chapter[N] -> chapter[N+1]). Idempotent on (source, target, relationship): re-runs return the existing edge_id with created=false. Bypasses HTTP and goes straight through the repo layer. All-or-nothing, on one transaction with this server's agent's write authority: an edge touching a group-private claim you cannot read is reported as not found, and one touching a group-private claim owned by a group this server's agent cannot write (another agent's private claim) is refused with nothing written."
    )]
    async fn link_hierarchical(
        &self,
        Parameters(params): Parameters<LinkHierarchicalParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::link_hierarchical::link_hierarchical(self, viewer, params).await
    }

    #[tool(
        description = "Promote two existing claims into a mutually-exclusive alternative_of pair — the symmetric edge suggest_alternative_sets tells you to submit but link_epistemic/link_hierarchical cannot create. Direction-agnostic and idempotent on the unordered {claim_a, claim_b} pair (migration 042's symmetric index): re-runs return the existing edge_id with created=false. Optional target_claim_id (the shared target the two claims are rival supporters of) and rationale are validated and stored on the edge. Deliberately inert at write time — the belief effect of an alternative set flows later through CDST max-plausibility combine over the alternative_set view, not a Dempster re-wire here. All-or-nothing, on one transaction with this server's agent's write authority: an edge touching a group-private claim you cannot read is reported as not found, and one touching a group-private claim owned by a group this server's agent cannot write (another agent's private claim) is refused with nothing written."
    )]
    async fn link_alternative(
        &self,
        Parameters(params): Parameters<crate::types::LinkAlternativeParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::link_alternative::link_alternative(self, viewer, params).await
    }

    #[tool(
        description = "Create a BELIEF-AFFECTING epistemic edge between two existing claims and wire it into Dempster-Shafer belief propagation. Direction is source -> target ('source RELATIONSHIP target'). Valid relationships: supports, corroborates, elaborates, generalizes, specializes (these STRENGTHEN the target's belief), contradicts, refutes (these WEAKEN it); cites is also accepted as a structural edge that moves no belief. Builds a mass function from the source claim's belief interval and recomputes the target claim's combined belief; a newly created edge also emits an edge.added event. Idempotent on (source, target, relationship), and on the unordered pair for contradicts / corroborates: a re-hit returns the existing edge with was_created=false. The edge is written even when no belief moves. belief_wired=true means THIS call materialized the edge's mass function and recomputed the target — including on a re-hit when the edge had none yet and its source has since gained belief. belief_wired=false means no belief moved: the source has no belief interval, the edge was already wired, the relationship is structural, or the wiring was refused (e.g. the target is owned by a group this server's agent cannot write). target_belief is the {belief, plausibility, pignistic_prob} of belief_target_claim_id, which is your SOURCE on a reverse-direction re-hit of a symmetric edge. For supersedes use supersede_claim instead. The edge, its belief wiring and its edge.added event commit together on one transaction with this server's agent's write authority. An endpoint in a group-private claim owned by a group this server's agent cannot write is refused with nothing written. Belief wiring into a target this server's agent cannot write moves no belief (belief_wired=false) and the edge still lands."
    )]
    async fn link_epistemic(
        &self,
        Parameters(params): Parameters<LinkEpistemicParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::link_epistemic::link_epistemic(self, viewer, params).await
    }

    #[tool(
        description = "Update an existing edge in place: retire it by closing its lifecycle window (valid_to) and/or shallow-merge a JSON object into its properties. MCP-native wrapper for PATCH /api/v1/edges/:id — before this tool the only way to act on a mislabeled edge from MCP was raw OAuth + curl. At least one of valid_to / properties is required; properties must be a JSON object (a non-object would silently convert the JSONB column to an array via Postgres `||`). valid_to accepts an RFC3339 timestamp or the literal \"now\" (resolved server-side, since an MCP client has no wall clock). Retiring is the NON-DESTRUCTIVE correction: the row and its audit history survive. Emits edge.updated, plus edge.retired when valid_to is set. NOTE: this does not invalidate the Dempster-Shafer mass function that edge creation wired onto the target claim — the target's cached belief still reflects the retired edge. The update and its events commit together, with this server's agent's write authority: an edge the CALLER cannot read, or one owned by a group this server's agent cannot write (one touching another agent's private claim), reports not found and nothing is written."
    )]
    async fn patch_edge(
        &self,
        Parameters(params): Parameters<crate::types::PatchEdgeParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::edge_mutation::patch_edge(self, viewer, params).await
    }

    #[tool(
        description = "Take an edge out of force by id: sets its valid_to to now (a RETRACTION; the row, its properties and signature survive and stay queryable). MCP-native wrapper for DELETE /api/v1/edges/:id. Use patch_edge with valid_to to retire an edge at a chosen time; delete_edge is for edges that should never have existed (e.g. a mislabeled contradicts edge). Errors if the edge id does not exist or is already retracted. Emits edge.deleted on the same transaction. An edge the CALLER cannot read, or one owned by a group this server's agent cannot write (one touching another agent's private claim), reports not found and nothing is written. NOTE: this does not invalidate the Dempster-Shafer mass function that edge creation wired onto the target claim — the target's cached belief still reflects the retracted edge."
    )]
    async fn delete_edge(
        &self,
        Parameters(params): Parameters<crate::types::DeleteEdgeParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::edge_mutation::delete_edge(self, viewer, params).await
    }

    // ── Paper Queries (3 tools) ──

    #[tool(description = "Look up a paper by its DOI, returning title, authors, and claims.")]
    async fn query_paper(
        &self,
        Parameters(params): Parameters<QueryPaperParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::paper_queries::query_paper(self, viewer, params).await
    }

    #[tool(
        description = "Find claims backed by a specific type of evidence (observation, computation, reference, testimony, document)."
    )]
    async fn query_claims_by_evidence(
        &self,
        Parameters(params): Parameters<QueryClaimsByEvidenceParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::paper_queries::query_claims_by_evidence(self, viewer, params).await
    }

    #[tool(
        description = "Find claims derived from a specific reasoning methodology (statistical, deductive, inductive, abductive, analogical)."
    )]
    async fn query_claims_by_methodology(
        &self,
        Parameters(params): Parameters<QueryClaimsByMethodologyParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::paper_queries::query_claims_by_methodology(self, viewer, params).await
    }

    #[tool(
        description = "Find claims by label using PostgreSQL array containment (GIN-indexed). Returns claims containing ALL specified labels. Useful for querying backlog items (e.g. [\"backlog\", \"pending\"]), workflows, or any labeled claim set."
    )]
    async fn query_claims_by_label(
        &self,
        Parameters(params): Parameters<QueryClaimsByLabelParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::paper_queries::query_claims_by_label(self, viewer, params).await
    }

    #[tool(
        description = "Recompute cached claim beliefs (Bel/Pl/BetP/conflict) from current mass_functions state, per-frame, in deterministic frame-name order. The in-server sibling of the epigraph-recompute-belief CLI. Target by `claim_ids` (explicit), `labels` (e.g. a paper's claim set), or neither (bulk over all claims with BBAs, bounded by `limit`). Use after ingest or after editing calibration.toml / per-frame overrides so the cached scalars catch up to the combine path. Each claim's cache is recomputed in its own transaction; claims_recomputed and frame_writes count only claims whose cached belief columns (belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing, belief_frame_id) were actually written and committed, and a per-claim failure is rolled back and listed in errors. Requires scope claims:admin over HTTP (it reads and writes across every tenant). Requires this server to have a privileged maintenance connection: start it with MAINTENANCE_DATABASE_URL explicitly set to a role that is a member of epigraph_maintenance; the application DSN is never used for this, even when it could bypass row-level security. Without one the call is refused with nothing written, and the boot log says why; it never reports a successful no-op."
    )]
    async fn recompute_beliefs(
        &self,
        Parameters(params): Parameters<RecomputeBeliefsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        let mut session = crate::maintenance::maintenance_viewer(
            self,
            epigraph_db::visibility::SystemReason::BeliefRecomputation,
        )
        .await?;
        tools::cdst_maintenance::recompute_beliefs(self, &mut session, params).await
    }

    // ── Workflows (8 tools) ──

    #[tool(
        description = "Store a new workflow with ordered steps and prerequisites. Returns a workflow_id from the hierarchical `workflows` table — NOT a claim id, so `get_claim` on it 404s. Retrieve it with `find_workflow` (which searches both stores) or `find_workflow_hierarchical`. Use `report_workflow_outcome` with the returned id to record execution results. All-or-nothing: on any error nothing is written. KNOWN ISSUE (not your error): the steps are filed under a constant 'Body' phase, so once any stored workflow has that phase this call can fail with 'Duplicate entity already exists' and write nothing. Workaround: `ingest_workflow` with a phase summary unique to this workflow (and different from its thesis) and step texts no other workflow uses."
    )]
    async fn store_workflow(
        &self,
        Parameters(params): Parameters<StoreWorkflowParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::workflows::store_workflow(self, viewer, params).await
    }

    #[tool(
        description = "Search for existing workflows by goal using semantic search. Searches BOTH workflow stores — flat `workflow`-labelled claims and hierarchical `workflows` rows (what `store_workflow` / `ingest_workflow` write) — and returns one list ranked by similarity. Hierarchical workflows whose steps cannot be resolved are withheld rather than returned with an empty `steps` array."
    )]
    async fn find_workflow(
        &self,
        Parameters(params): Parameters<FindWorkflowParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::workflows::find_workflow(self, viewer, params).await
    }

    #[tool(
        description = "List a workflow's most recent behavioral executions, newest first: per-run success, quality, tool_pattern, deviation_count and step_beliefs (per-step deviation_reason), plus a window success-rate. Read-only telemetry for analysing or evolving a workflow."
    )]
    async fn get_workflow_executions(
        &self,
        Parameters(params): Parameters<GetWorkflowExecutionsParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::workflows::get_workflow_executions(self, params).await
    }

    #[tool(
        description = "Evaluate whether a workflow variant is statistically ready to be promoted over its immediate (variant_of) parent: the Wilson lower bound of the variant's behavioral success rate vs the parent's rate, over the same window, gated on a minimum sample. Read-only — returns a verdict, does not promote."
    )]
    async fn evaluate_workflow_promotion(
        &self,
        Parameters(params): Parameters<EvaluateWorkflowPromotionParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::workflows::evaluate_workflow_promotion(self, viewer, params).await
    }

    #[tool(
        description = "Re-evaluate a workflow variant's promotion verdict and write it to the variant's properties.promotion, overwriting any prior value (so a regressed variant is demoted, not left stale). The apply layer of the workflow-evolution gate; the maintenance pass calls this per candidate variant. Write."
    )]
    async fn refresh_workflow_promotion(
        &self,
        Parameters(params): Parameters<EvaluateWorkflowPromotionParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::workflows::refresh_workflow_promotion(self, viewer, params).await
    }

    #[tool(
        description = "Record what actually happened when you used a workflow. For a workflows-table id (what `store_workflow` / `ingest_workflow` return) it delegates to `report_hierarchical_outcome` and has that tool's response and semantics: counters plus per-step rows, no evidence, no belief change, NOT idempotent, and execution_log[].step_index mapped to the steps in original plan order. Legacy flat workflow claim IDs are still supported: there the run is recorded as evidence plus a Dempster-Shafer truth update, all-or-nothing (an error writes nothing, so an identical retry is safe), and it is refused for a workflow claim owned by a group this server's agent cannot write."
    )]
    async fn report_workflow_outcome(
        &self,
        Parameters(params): Parameters<ReportWorkflowOutcomeParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::workflows::report_workflow_outcome(self, viewer, params).await
    }

    #[tool(
        description = "Deprecate a workflow (and optionally its variant_of / supersedes lineage), all-or-nothing. A workflow claim gets truth 0.05 and is_current=false; a hierarchical `workflows` row gets truth 0.05. WARNING: for a hierarchical workflow id (what store_workflow, ingest_workflow, find_workflow and find_workflow_hierarchical return for hierarchical workflows) only the `workflows` row changes: its thesis and step claims stay current, yet the id is still reported in deprecated_ids. The id you pass is always listed, whether or not a claim changed; cascaded ids are listed only when a claim was actually deprecated."
    )]
    async fn deprecate_workflow(
        &self,
        Parameters(params): Parameters<DeprecateWorkflowParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::workflows::deprecate_workflow(self, viewer, params).await
    }

    // ── Hierarchical Workflows (4 tools) ──
    //
    // Counterparts to the flat `store_workflow` family above. These operate
    // on the `workflows` table where every step is a claim node connected
    // via `executes` edges, so each step accrues evidence and Darwinian
    // variants independently of its workflow root.

    #[tool(
        description = "Ingest a hierarchical WorkflowExtraction: persists thesis → phases → steps → operation atoms as claim nodes, writes `executes` edges from the workflow root to every planned claim (recording plan order), and resolves author identities. All-or-nothing: on any error nothing is written. Idempotent: re-ingesting the same canonical_name+generation is a no-op. KNOWN ISSUE (not your error): a thesis, phase text (summary, or title when the summary is empty) or step text that another stored workflow already uses can fail the call with 'Duplicate entity already exists', writing nothing. Keep those texts unique to this workflow, and do not reuse the thesis text as a phase summary."
    )]
    async fn ingest_workflow(
        &self,
        Parameters(params): Parameters<IngestWorkflowParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::workflow_ingest::ingest_workflow(self, viewer, params).await
    }

    #[tool(
        description = "Create a generation-incremented hierarchical variant of an existing workflow. Looks up parent by canonical_name, finds its latest generation, and ingests the new extraction with generation = parent + 1 and parent_canonical_name linked. Same-lineage improvement only: the new variant's canonical_name and parent_canonical_name are both set to the tool's `parent_canonical_name` param; cross-lineage variants are not supported. Each call produces a new generation. Same all-or-nothing behaviour and duplicate-text known issue as ingest_workflow; texts unchanged from the parent are reused, not duplicated."
    )]
    async fn improve_workflow_hierarchy(
        &self,
        Parameters(params): Parameters<ImproveWorkflowHierarchyParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::workflow_ingest::improve_workflow_hierarchy(self, viewer, params).await
    }

    #[tool(
        description = "Search hierarchical workflows by free-text over goal and canonical_name (ILIKE). Returns rows from the `workflows` table ONLY, with canonical_name/generation/parent_id and optional resolve_to_latest step-head resolution — narrower and more detailed than `find_workflow`, which now also covers this table but merges it with flat workflow claims and returns frozen steps."
    )]
    async fn find_workflow_hierarchical(
        &self,
        Parameters(params): Parameters<FindWorkflowHierarchicalParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::workflow_hierarchical::find_workflow_hierarchical(self, viewer, params).await
    }

    #[tool(
        description = "Record an outcome for a hierarchical workflow run by workflows-table id. Updates rolling counters in workflows.metadata (use_count, success_count, failure_count, avg_variance) and writes one behavioral_executions row per step_execution, with step_index mapped to the workflow's steps in original PLAN order (the order find_workflow / find_workflow_hierarchical list them; steps added with add_step come after all planned steps). Writes no evidence and changes no belief. NOT idempotent: every call adds to the counters and rows, so do not retry a call that succeeded. Not all-or-nothing either: the counters are written first, a per-step row that fails is skipped (step_executions_written says how many landed), and an out-of-range step_index is stored with a null step_claim_id. There is no ownership check on the workflow. `report_workflow_outcome` is the compatibility entry point for callers that may have either store_workflow ids or legacy flat workflow claim ids."
    )]
    async fn report_hierarchical_outcome(
        &self,
        Parameters(params): Parameters<ReportHierarchicalOutcomeParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::workflow_hierarchical::report_hierarchical_outcome(self, params).await
    }

    #[tool(
        description = "Append or middle-insert a step into an existing hierarchical workflow. `position=None` appends; `position=Some(i)` inserts at the 0-indexed slot i of the `step_follows` chain, and the returned step_index is that chain slot. `position` does NOT change plan order: find_workflow, find_workflow_hierarchical and the step_index of report_workflow_outcome / report_hierarchical_outcome all place an added step AFTER every originally planned step (added steps in the order they were added). Idempotent on `(canonical_name, step_text)` via deterministic claim ID. All-or-nothing; a step text another workflow already uses can fail with 'Duplicate entity already exists' (known issue, see ingest_workflow)."
    )]
    async fn add_step(
        &self,
        Parameters(params): Parameters<crate::tools::step_ops::AddStepParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::step_ops::add_step(self, params).await
    }

    #[tool(
        description = "Soft-delete a workflow step by step_lineage_id. Sets the head claim's truth_value to 0.05; default min_truth filters hide it from active queries while preserving history. Does not rewire the step_follows chain."
    )]
    async fn delete_step(
        &self,
        Parameters(params): Parameters<crate::tools::step_ops::DeleteStepParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::step_ops::delete_step(self, params).await
    }

    // ── Graph (2 tools) ──

    #[tool(
        description = "Get the immediate graph neighborhood of any node — all connected edges with optional relationship and direction filters."
    )]
    async fn get_neighborhood(
        &self,
        Parameters(params): Parameters<GetNeighborhoodParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::graph::get_neighborhood(self, viewer, params).await
    }

    #[tool(
        description = "Multi-hop graph walk from a starting node. BFS traversal with optional relationship filter and truth threshold."
    )]
    async fn traverse(
        &self,
        Parameters(params): Parameters<TraverseParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::graph::traverse(self, viewer, params).await
    }

    // ── Challenges (2 tools) ──

    #[tool(
        description = "Submit a typed challenge against a claim. Types: insufficient_evidence, outdated_evidence, flawed_methodology, contradicting_evidence, factual_error. Returns {challenge_id, claim_id, challenge_type, state: 'pending'}. Refused with an error, writing nothing, when the claim is owned by a group this server's agent cannot write."
    )]
    async fn challenge_claim(
        &self,
        Parameters(params): Parameters<ChallengeclaimParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::challenges::challenge_claim(self, params).await
    }

    #[tool(description = "List all challenges filed against a specific claim.")]
    async fn list_challenges(
        &self,
        Parameters(params): Parameters<ListChallengesParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::challenges::list_challenges(self, viewer, params).await
    }

    // ── Events (2 tools) ──

    #[tool(
        description = "Query the event log with optional type and actor filters. Returns recent graph events."
    )]
    async fn list_events(
        &self,
        Parameters(params): Parameters<ListEventsParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::events::list_events(self, viewer, params).await
    }

    #[tool(
        description = "Manually publish an event to the graph event log for audit and traceability."
    )]
    async fn publish_event(
        &self,
        Parameters(params): Parameters<PublishEventParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::events::publish_event(self, params).await
    }

    // ── Batch / Staging / Stats (3 tools) ──

    #[tool(
        description = "Submit multiple claims in a single batch (max 100). Each entry accepts every submit_claim field: content, evidence_data and evidence_type are required; methodology, confidence, source_url, reasoning, labels and novelty_threshold are optional. An entry with no methodology is submitted as inductive_generalization and one with no confidence at 0.5, as before these fields existed. Entries are submitted one at a time, exactly as submit_claim, each on its own transaction. The response keeps submitted (a count), errors (a count) and error_details, and adds results: one object per entry in input order, either {index, status: 'ok', ...} carrying that entry's full submit_claim response (claim_id, truth_value, content_hash, embedded, and belief, plausibility, pignistic_prob, frame_id when a belief was wired, and the deduplicated block when the entry matched an existing claim, as submit_claim documents), or {index, status: 'error', error}. An entry that repeats an earlier entry of the same batch, or an existing claim, is reported with deduplicated rather than as a new insert. A refused entry (an unknown methodology or evidence_type, a bad label, a refused write) writes nothing, and the other entries still land. If an operator has revoked this server's agent's personal-group membership, every entry is refused that way. The membership is never restored; restoring it is an operator action."
    )]
    async fn batch_submit_claims(
        &self,
        Parameters(params): Parameters<BatchSubmitClaimsParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::batch::batch_submit_claims(self, viewer, params).await
    }

    #[tool(
        description = "Validate claims without persisting them. Returns validity checks and warnings for each claim."
    )]
    async fn stage_claims(
        &self,
        Parameters(params): Parameters<StageClaimsParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::batch::stage_claims(self, params).await
    }

    #[tool(
        description = "Get aggregate system statistics — claim, evidence, edge, agent, and frame counts. Set detailed=true for breakdowns."
    )]
    async fn system_stats(
        &self,
        Parameters(params): Parameters<SystemStatsParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::batch::system_stats(self, viewer, params).await
    }

    // ── Perspectives & Ownership (6 tools) ──

    #[tool(
        description = "Create a new perspective (viewpoint) for scoped belief reasoning. Perspectives can be associated with frames and agents."
    )]
    async fn create_perspective(
        &self,
        Parameters(params): Parameters<CreatePerspectiveParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::perspectives::create_perspective(self, params).await
    }

    #[tool(
        description = "Set a perspective's source-reliability map (evidence-type tag -> alpha in [0,1]) — the frame-function lens read by scoped_belief / get_perspective_belief, so two observers weight the same evidence differently. An empty map clears the override. Keys are matched against each BBA's evidence_type lowercased and strict-key: a key that is not lowercase, or not in the evidence-type vocabulary, is still stored but is returned in unknown_keys (with one sentence per key in warnings) because it can change no belief; both fields are omitted when every key is known. Unknown keys are a warning, never a refusal."
    )]
    async fn set_source_reliability(
        &self,
        Parameters(params): Parameters<SetSourceReliabilityParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::perspectives::set_source_reliability(self, params).await
    }

    #[tool(description = "List all perspectives with optional limit.")]
    async fn list_perspectives(
        &self,
        Parameters(params): Parameters<ListPerspectivesParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::perspectives::list_perspectives(self, viewer, params).await
    }

    #[tool(description = "Get a single perspective by UUID.")]
    async fn get_perspective(
        &self,
        Parameters(params): Parameters<GetPerspectiveParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::perspectives::get_perspective(self, viewer, params).await
    }

    // `assign_ownership`, `get_ownership` and `update_partition` were three
    // tool-router entries here until PR-14. (Spelled without the attribute
    // token on purpose: `tool_viewer_coverage.rs` slices this file on that
    // literal, so writing it in a comment would inflate the tool count and
    // trip `tools_are_line_initial_attributes`.) They were the MCP half of the
    // legacy `ownership` ACL; the tenancy columns replaced the model, and
    // `get_ownership` in particular answered "who owns this and how private is
    // it" for any node to any caller, with no `Viewer` involved.

    // ── DS/Belief (7 tools — 4 enhanced + 3 new) ──

    #[tool(
        description = "Create a frame of discernment (set of mutually exclusive hypotheses) for Dempster-Shafer belief reasoning. Supports refinement hierarchies."
    )]
    async fn create_frame(
        &self,
        Parameters(params): Parameters<CreateFrameParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::ds::create_frame(self, params).await
    }

    #[tool(
        description = "Submit Dempster-Shafer evidence (mass function / BBA) for a claim within a frame, optionally under a perspective_id, and recompute the claim's cached belief. The frame assignment, the BBA and the recomputed belief commit together; a refusal (e.g. the claim is owned by a group this server's agent cannot write, or the caller cannot read the claim, which is reported as not found) writes nothing, and every refusal is decided before the commit, never after the evidence is stored. Resubmitting for the same claim, frame and perspective_id REPLACES this agent's earlier BBA there rather than adding to it. The belief is recomputed by the same adaptive combine recompute_beliefs uses: combination_method is stored and echoed as method_used, but neither it nor gamma changes the returned belief: both are DEPRECATED, and sending a combination_method other than Dempster, or any gamma, adds an entry to the response's warnings array (omitted when empty). An evidence_type the recompute cannot resolve to a calibrated weight (not a calibration.toml [evidence_type_weights] key or [evidence_type_aliases] alias, nor in the frame's own evidence_type_weights override) is accepted and combined at the 0.5 unknown-type reliability, and is returned in unknown_keys with an explanatory entry in warnings: a warning, never a refusal."
    )]
    async fn submit_ds_evidence(
        &self,
        Parameters(params): Parameters<SubmitDsEvidenceParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        self.reject_if_read_only()?;
        tools::ds::submit_ds_evidence(self, viewer, params).await
    }

    #[tool(
        description = "Query the Dempster-Shafer belief interval for a claim. Returns Bel, Pl, ignorance, BetP, and CDST conflict/missing separation."
    )]
    async fn get_belief(
        &self,
        Parameters(params): Parameters<GetBeliefParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::ds::get_belief(self, viewer, params).await
    }

    #[tool(
        description = "List all frames of discernment with their hypotheses, version, and refinement info."
    )]
    async fn list_frames(
        &self,
        Parameters(params): Parameters<ListFramesParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::ds::list_frames(self, viewer, params).await
    }

    #[tool(
        description = "Run all 6 CDST combination methods on stored BBAs for a claim, returning side-by-side Bel/Pl/BetP and conflict metrics for comparison."
    )]
    async fn compare_methods(
        &self,
        Parameters(params): Parameters<CompareMethodsParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::ds::compare_methods(self, viewer, params).await
    }

    #[tool(
        description = "Get belief scoped to a specific perspective or community, showing how different viewpoints assess a claim."
    )]
    async fn scoped_belief(
        &self,
        Parameters(params): Parameters<ScopedBeliefParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::ds::scoped_belief(self, viewer, params).await
    }

    #[tool(
        description = "Get the DS-vs-Bayesian KL divergence for a claim, measuring how much the Dempster-Shafer and Bayesian assessments disagree."
    )]
    async fn get_divergence(
        &self,
        Parameters(params): Parameters<GetDivergenceParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::ds::get_divergence(self, viewer, params).await
    }

    // ── Sheaf (3 tools) ──

    #[tool(
        description = "Check CDST sheaf consistency across all claims. Computes per-node consistency radii using restriction maps — identifies claims whose local belief diverges from what their epistemic neighbors would predict. Returns sections sorted by inconsistency (worst first). Use this to find belief staleness, local contradictions, and open-world spread in the knowledge graph."
    )]
    async fn check_sheaf_consistency(
        &self,
        Parameters(params): Parameters<CheckSheafConsistencyParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::sheaf::check_sheaf_consistency(self, viewer, params).await
    }

    #[tool(
        description = "Compute CDST sheaf cohomology — the global inconsistency measure for the knowledge graph. Returns decomposed H¹ with three channels: conflict_h1 (genuine belief contradictions), ignorance_h1 (epistemic staleness), and open_world_h1 (frame incompleteness spread). Use this to assess overall knowledge-graph health and triage which type of inconsistency dominates."
    )]
    async fn sheaf_cohomology(
        &self,
        Parameters(params): Parameters<SheafCohomologyParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::sheaf::sheaf_cohomology(self, viewer, params).await
    }

    #[tool(
        description = "Run Phase 2 sheaf reconciliation: clusters obstruction subgraphs and runs interval belief propagation within each cluster to propose updated belief intervals. Returns updated_intervals (suggested BetP/Bel/Pl corrections), frame_evidence_proposals (claims where new frame evidence would reduce open-world mass), and convergence status. Does NOT write to the database — results are proposals for human or automated review."
    )]
    async fn reconcile_sheaf(
        &self,
        Parameters(params): Parameters<ReconcileSheafParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::sheaf::reconcile_sheaf(self, viewer, params).await
    }

    // ── Embeddings (2 tools) ──

    #[tool(
        description = "Aggregate claim count + similarity stats for the embedding ball around a free-text query. Mirrors POST /api/v1/embeddings/neighborhood-density. Returns n_claims, mean/median cosine similarity, a squashed sparsity score, and breakdowns by level + source_type. Defaults: radius=0.30 (cosine distance), max_sample=500 (clamped to [1, 5000]). Use this to detect dense regions that warrant theme sub-splitting and to drive the nightly theme-maintenance workflow."
    )]
    async fn embedding_neighborhood_density(
        &self,
        Parameters(params): Parameters<
            crate::tools::embeddings::EmbeddingNeighborhoodDensityParams,
        >,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        crate::tools::embeddings::embedding_neighborhood_density(self, viewer, params).await
    }

    #[tool(
        description = "Generate and store the missing claims.embedding vector for current, non-telemetry claims that lack one (the is_current AND embedding IS NULL gap the CLAUDE.md embedding-policy invariant tracks). Server-side, MCP-executable counterpart to the embed_backfill CLI: the embed stage of the decomposition-cycle's decompose→embed→cross-source-match pipeline. Selection is oldest-first so repeated runs drain the backlog monotonically. Params: limit (default 200, clamped 1..=2000), dry_run (default false — count candidates without writing; safe with no OpenAI key). Returns {candidates, embedded, failed, dry_run}. Errors if the server has no OPENAI_API_KEY and dry_run is false. Covers every tenant's claims. A claim sealed or superseded between selection and store is not given a vector and is counted in failed. Requires scope claims:admin over HTTP (it reads and writes across every tenant). Requires this server to have a privileged maintenance connection: start it with MAINTENANCE_DATABASE_URL explicitly set to a role that is a member of epigraph_maintenance; the application DSN is never used for this, even when it could bypass row-level security. Without one the call is refused with nothing written, and the boot log says why; it never reports a successful no-op."
    )]
    async fn backfill_embeddings(
        &self,
        Parameters(params): Parameters<crate::tools::embeddings::BackfillEmbeddingsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        let mut session = crate::maintenance::maintenance_viewer(
            self,
            epigraph_db::visibility::SystemReason::EmbeddingBackfill,
        )
        .await?;
        crate::tools::embeddings::backfill_embeddings(self, &mut session, params).await
    }

    // ── Themes (3 tools) ──

    #[tool(
        description = "READ-ONLY paged inventory of the theme layer: for each theme its id, label, description, live member_count (COUNT(*) of is_current claims actually assigned — authoritative), stored_claim_count (the denormalised claim_themes.claim_count column, which the assignment writers do NOT maintain; reported only so drift is visible), derived centroid_dim (1536 / 3072 / null), created_at and updated_at. Optional label_prefix filter (e.g. \"auto\" for the k-means family). Defaults: limit=50 (clamped 1..=500), offset=0. Response carries total / returned / has_more under the SAME prefix predicate, so a limit/offset walk terminates exactly. Clusters nothing, wipes nothing, writes nothing — use this instead of theme_cluster to answer \"what topics does this graph cover\"."
    )]
    async fn list_themes(
        &self,
        Parameters(params): Parameters<crate::tools::themes::ListThemesParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        crate::tools::themes::list_themes(self, viewer, params).await
    }

    #[tool(
        description = "READ-ONLY detail for ONE theme: its list_themes summary plus a page of member claim IDs (ids + truth_value + created_at — deliberately NOT content, so this is not a second unredacted content surface; resolve ids via get_claim, which redacts). Select with theme_id OR theme_label, never both; a malformed theme_id, a label matching nothing, and a label matching several themes are all REJECTED rather than silently widening the query (claim_themes has no UNIQUE(label) constraint). Members are ordered created_at ASC, id ASC — a total order, so a members_limit/members_offset walk yields each member exactly once. Defaults: members_limit=50 (max 500; 0 = summary only), members_offset=0. Response carries members_total / members_returned / members_has_more."
    )]
    async fn get_theme(
        &self,
        Parameters(params): Parameters<crate::tools::themes::GetThemeParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        crate::tools::themes::get_theme(self, viewer, params).await
    }

    #[tool(
        description = "Trigger server-side theme clustering via k-means over the claim corpus. Mirrors POST /api/v1/themes/build-from-corpus. Defaults: k_min=4, k_max=16, min_claims_per_theme=5, limit=500 (hard-capped at 500 here for OOM safety), label_prefix=\"auto\", centroid_dim=1536. Default `wipe_first=true` ensures clean rebuilds on each call. Pass `false` only for additive runs with a unique `label_prefix` (otherwise duplicate themes accumulate — see backlog: missing UNIQUE constraint on claim_themes.label)."
    )]
    async fn theme_cluster(
        &self,
        Parameters(params): Parameters<crate::tools::themes::ThemeClusterParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        crate::tools::themes::theme_cluster(self, params).await
    }

    // ── RDF Triple Layer (3 tools) ──

    #[tool(
        description = "Query RDF-style triples extracted from claims. Filter by subject entity, predicate pattern, and/or object entity. All filters optional (omit to wildcard). Optional min_confidence threshold (default 0.0, no filtering). Returns triples with source claim references."
    )]
    async fn query_triples(
        &self,
        Parameters(params): Parameters<QueryTriplesParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::rdf::query_triples(self, viewer, params).await
    }

    #[tool(
        description = "Get everything known about an entity — all triples where it appears as subject or object, grouped by predicate. Pass entity name (e.g. 'DNA origami') or UUID."
    )]
    async fn entity_neighborhood(
        &self,
        Parameters(params): Parameters<EntityNeighborhoodParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::rdf::entity_neighborhood(self, viewer, params).await
    }

    #[tool(
        description = "Search triples via natural language. Uses embedding similarity to find relevant claims, then returns their structured triples. Complements query_triples (structured) with fuzzy discovery."
    )]
    async fn search_triples(
        &self,
        Parameters(params): Parameters<SearchTriplesParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::rdf::search_triples(self, viewer, params).await
    }

    // ── Cross-source matching (3 tools) ──

    #[tool(
        description = "Look up existing cross-source matches for a claim. Returns match_candidates rows (any status), any CORROBORATES edges already written, and sweep coverage for the claim: `never_swept: true` means the matcher has not scanned it yet (an empty candidate list says nothing), `last_swept_at` is when it last did. Both coverage fields are omitted entirely for a claim you cannot read. Read-only — to *run* the matcher across new claims, use the `cross_source_sweep` CLI."
    )]
    async fn find_cross_source_matches(
        &self,
        Parameters(params): Parameters<FindCrossSourceMatchesParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::matching::find_cross_source_matches(self, viewer, params).await
    }

    #[tool(
        description = "List match_candidates rows, sorted by score desc. Filter by status (pending|promoted|rejected|stale) or get all. Use this to triage what the matcher has surfaced."
    )]
    async fn list_match_candidates(
        &self,
        Parameters(params): Parameters<ListMatchCandidatesParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::matching::list_match_candidates(self, viewer, params).await
    }

    #[tool(
        description = "Decide a match candidate: 'promote' marks the row promoted and writes the edge its verifier_verdict calls for — CORROBORATES for same/paraphrase/overlapping, contradicts for contradicts, and refused for distinct (no truthful edge exists; reject it instead); 'reject' marks it rejected. To undo a promotion use retire_match_candidate (claims:admin). Honours read-only mode."
    )]
    async fn decide_match_candidate(
        &self,
        Parameters(params): Parameters<DecideMatchCandidateParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        tools::matching::decide_match_candidate(self, viewer, params).await
    }

    #[tool(
        description = "Retire a promoted match candidate: RETRACTS the matcher edge (closes valid_to — the row and its properties.decided_by survive, so the original promoter stays recoverable), deletes the factors/bp_messages/BBAs derived from it, and flips the candidate to stale. Requires claims:admin, unlike promote/reject on decide_match_candidate: retirement withdraws an assertion another principal made, which is the same class of act as supersession. Honours read-only mode."
    )]
    async fn retire_match_candidate(
        &self,
        Parameters(params): Parameters<RetireMatchCandidateParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::matching::retire_match_candidate(self, params).await
    }

    // ── Meta (1 tool) ──

    #[tool(
        description = "List all MCP tools available on this server. Returns the name, description, and full JSON Schema for every registered tool — including tools your client may have DEFERRED (name visible but schema not loaded). Use this for runtime tool discovery and to load the schema of any tool your client could not call directly. The list reflects the live server state, including newly deployed tools not yet stored in the knowledge graph."
    )]
    async fn list_mcp_tools(&self) -> Result<CallToolResult, McpError> {
        // Kernel tools + every federated tool the gateway advertises, matching
        // `ServerHandler::list_tools`. `server_instructions` directs clients here
        // to enumerate every tool with its schema, so the federated tools must be
        // present or a deferred-schema client following that guidance would never
        // discover them.
        let mut tools = self.tool_router.list_all();
        tools.extend(self.federation.list_federated_tools());
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&tools).map_err(crate::errors::internal_error)?,
        )]))
    }
}

impl EpiGraphMcpFull {
    /// Build the `instructions` string surfaced in the MCP `initialize`
    /// payload (`ServerInfo.instructions`).
    ///
    /// This is the ALWAYS-shown, never-deferred handshake text — clients
    /// (including the claude.ai web connector) render it verbatim before
    /// any `tools/list` page-in. We therefore use it to advertise the
    /// deferred-tool / tool-search gate: many clients list a tool's *name*
    /// but defer its *schema*, so a direct call fails with "not loaded
    /// yet / call tool-search first". That is client-side deferral, NOT a
    /// missing server tool — `tools/list` returns every registered tool.
    ///
    /// `tool_count` is derived from the live tool router (`all_tools_json`),
    /// so it can never drift from the registered tool set the way a
    /// hardcoded constant would.
    #[must_use]
    pub fn server_instructions(read_only: bool) -> String {
        let mode = if read_only { "read-only" } else { "full" };
        let tool_count = Self::all_tools_json().as_array().map_or(0, Vec::len);
        format!(
            "EpiGraph {mode} MCP server with {tool_count} epistemic tools. \
             Many EpiGraph tools are DEFERRED by your client — their names may appear but \
             their schemas are not loaded, so a direct call can fail with \
             \"not loaded yet / call tool-search first\". This is NOT a missing tool. \
             Use your client's tool-search mechanism (e.g. tool_search / ToolSearch) to load \
             a tool's schema by name before calling it (the edge-writers submit_claim, \
             link_hierarchical, supersede_claim and the graph reads get_neighborhood, traverse, \
             query_claims are all available this way), or call list_mcp_tools to enumerate every \
             tool with its full schema."
        )
    }
}

// Manual `ServerHandler` impl (in lieu of `#[tool_handler]`) so `call_tool`
// can be wrapped with durable event emission. Mirrors the macro's expansion
// for `list_tools` and `get_tool` verbatim — see
// `rmcp-macros-0.15.0/src/tool_handler.rs` for the canonical body.
//
// `call_tool` is the single chokepoint for every MCP tool invocation. We
// emit one `tool.invoked` event per call (closes #61's tool.invoked
// requirement) and forward to the macro-built dispatcher unchanged. Event
// emission is fire-and-forget; a failed event publish must not break tool
// dispatch.
impl ServerHandler for EpiGraphMcpFull {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(Self::server_instructions(self.read_only)),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }

    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
        // For HTTP requests, the Bearer middleware (`auth::bearer_auth_middleware`)
        // inserts an `AuthContext` into request.extensions; rmcp's
        // `StreamableHttpService` forwards those into `context.extensions` via
        // `http::request::Parts` (see rmcp/src/transport/streamable_http_server/
        // tower.rs:326/384/463). For stdio transport there is no `Parts` attached —
        // the stdio process boundary is the trust gate and no auth check applies.
        let is_http_call;
        let auth_owned: Option<epigraph_auth::AuthContext>;
        // The verbatim caller bearer, present only on the HTTP path (stashed by
        // `auth::bearer_auth_middleware`). Needed to forward to a downstream
        // extension MCP on a federated call.
        let raw_token: Option<String>;
        {
            let http_parts = context.extensions.get::<Parts>();
            is_http_call = http_parts.is_some();
            // Clone the AuthContext out of the borrow so we can both
            // (a) run scope enforcement and (b) reassign `context`
            // below to insert it into rmcp's extensions map.
            auth_owned = http_parts
                .and_then(|p| p.extensions.get::<epigraph_auth::AuthContext>())
                .cloned();
            raw_token = http_parts
                .and_then(|p| p.extensions.get::<crate::auth::RawBearerToken>())
                .map(|t| t.0.clone());
        }

        // FEDERATION BRANCH — only for names the static tool router does NOT own.
        // Must intercept BEFORE the static scope gate below: that gate fails
        // closed for any name absent from `SCOPE_MAP`, and federated tools are
        // deliberately not in `SCOPE_MAP`. Kept outside the `is_http_call` guard
        // so a stdio federated call reaches `enforce_federated_scope` and fails
        // closed there (no `AuthContext`) rather than falling through to a bare
        // "unknown tool" from the router. A genuinely-unknown name (neither
        // static nor federated) is reported as a ROUTING failure at the bottom
        // of this block — see `unknown_tool_error` — rather than borrowing the
        // static gate's authz-shaped "no scope mapping" (backlog ee50d10d).
        if self.tool_router.get(&request.name).is_none() {
            // `route_config` returns an OWNED config and releases the registry
            // lock before returning, so nothing below holds a guard across the
            // downstream `invoke` await.
            if let Some(ext) = self.federation.route_config(&request.name) {
                let ext_name = ext.name;
                let ext_scope = ext.scope;
                // (a) enforce the extension's configured scope against the caller.
                if let Err(err) =
                    Self::enforce_federated_scope(auth_owned.as_ref(), &request.name, &ext_scope)
                {
                    self.emit_tool_invoked(&format!("denied:{}:{}", ext_name, request.name))
                        .await;
                    return Err(err);
                }
                // (b) require the caller's raw bearer to forward downstream.
                let Some(token) = raw_token else {
                    return Err(McpError {
                        code: rmcp::model::ErrorCode::INVALID_REQUEST,
                        message: std::borrow::Cow::Borrowed(
                            "Unauthorized: no Bearer token to forward to the downstream \
                             extension (federated tools are unavailable over stdio)",
                        ),
                        data: None,
                    });
                };
                // (c) durable audit event, namespaced by the owning extension.
                self.emit_tool_invoked(&format!("{}:{}", ext_name, request.name))
                    .await;
                // (d) proxy to the downstream on a fresh caller-token session.
                // `McpError` IS `rmcp::ErrorData`, so `internal_error` yields the
                // handler's error type directly (no further conversion).
                return self
                    .federation
                    .invoke(&request.name, &token, request.arguments)
                    .await
                    .map_err(crate::errors::internal_error);
            }

            // Neither a kernel tool nor a federated route: a ROUTING failure.
            //
            // GATED ON THE CALLER ALREADY BEING AUTHENTICATED ON THE HTTP PATH,
            // and that is not decoration. `main.rs` has a router arm that
            // layers NEITHER auth middleware (given neither `--jwt-secret` nor
            // `--allow-unauthenticated-http` the `/mcp` service is nested
            // bare), so an unauthenticated HTTP call does reach here, and
            // `enforce_tool_scope`'s no-auth branch below is the only thing
            // refusing it — the property
            // `http_calls_cannot_reach_a_tool_without_an_auth_context.rs`
            // locks. Answering "unknown tool" ahead of that branch would turn
            // this into a PRE-AUTH tool-name oracle on exactly that arm. For a
            // caller who IS authenticated nothing new is disclosed: the old
            // "no scope mapping" answer already meant "absent from SCOPE_MAP",
            // and `scope_map_coverage` makes SCOPE_MAP total over kernel tools,
            // so the same name/no-name bit was already readable.
            //
            // stdio (`!is_http_call`) takes this arm too. It previously fell
            // through to the macro dispatcher's bare "unknown tool", so the
            // two transports now give the same, more useful answer.
            if !is_http_call || auth_owned.is_some() {
                return Err(Self::unknown_tool_error(
                    &request.name,
                    &self
                        .federation
                        .unhealthy_extension_candidates(&request.name),
                ));
            }
        }

        if is_http_call {
            if let Err(err) = Self::enforce_tool_scope(auth_owned.as_ref(), &request.name) {
                // Emit a denial audit event so 403s show up alongside successes.
                self.emit_tool_invoked(&format!("denied:{}", request.name))
                    .await;
                return Err(err);
            }
            // An HTTP listener must never serve as an operator-linked signer
            // (migration 107): it authors every caller's claims as this one
            // agent. The startup gate (`operator::refuse_operated_http_signer`)
            // runs once; this re-checks on EVERY call, so a link recorded after
            // startup refuses at once instead of taking effect until the next
            // restart. After the scope gate, so an unauthenticated caller learns
            // nothing about the signer. Federated calls returned above: they are
            // proxied under the caller's own token and never author as this
            // signer.
            if let Err(err) = crate::operator::refuse_linked_http_signer(self).await {
                self.emit_tool_invoked(&format!("denied:{}", request.name))
                    .await;
                return Err(err);
            }
        }

        // Single chokepoint for every MCP tool invocation: emit a durable
        // tool.invoked event before dispatch, then forward to the
        // macro-built dispatcher.
        //
        // **DO NOT remove this line without updating
        // `tests/event_log_wiring_tests.rs::tool_dispatch_emits_tool_invoked_event`.**
        self.emit_tool_invoked(&request.name).await;

        // ── Auth-lineage provenance (OPERATED_BY) ───────────────────────────
        // When the caller authenticated under a user/agent scope, record that
        // THIS MCP agent acted on behalf of that principal
        // (`mcp_agent --OPERATED_BY--> auth.agent_id`, prov:actedOnBehalfOf).
        // `auth.agent_id == None`, or stdio (no `Parts` -> `auth_owned == None`),
        // writes NO edge. Best-effort + per-session memoized inside the helper;
        // borrow `auth_owned` here (it is MOVED just below into `context`).
        self.record_auth_lineage(auth_owned.as_ref().and_then(|a| a.agent_id))
            .await;

        // Propagate the HTTP-side `AuthContext` (set by
        // `auth::bearer_auth_middleware` and forwarded by
        // `StreamableHttpService` through `http::request::Parts`) into
        // rmcp's `RequestContext::extensions` so per-tool handlers can
        // pull it out via the `rmcp::model::Extensions` extractor and
        // run per-row ownership checks (e.g. `resolve_backlog_item`'s
        // owner-or-`claims:admin` gate). For stdio transport there is
        // no `Parts` and no auth to copy; handlers see an empty
        // extensions map and fall back to coarse, signer-agent-based
        // checks.
        let mut context = context;
        if let Some(auth) = auth_owned {
            context.extensions.insert(auth);
        }

        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        self.tool_router.call(tcc).await
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::ErrorData> {
        // Kernel tools first, then every federated tool the gateway currently
        // advertises. Static-first mirrors `call_tool`'s resolution order: a
        // kernel tool always wins a name clash (the operator resolves clashes
        // between an extension and the kernel with a `prefix=`).
        let mut tools = self.tool_router.list_all();
        tools.extend(self.federation.list_federated_tools());
        Ok(rmcp::model::ListToolsResult {
            tools,
            meta: None,
            next_cursor: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<rmcp::model::Tool> {
        // Static router first (kernel tools win name clashes, as in call_tool),
        // then fall back to a federated tool from the routing map.
        self.tool_router.get(name).cloned().or_else(|| {
            self.federation
                .list_federated_tools()
                .into_iter()
                .find(|t| t.name.as_ref() == name)
        })
    }
}

#[cfg(test)]
mod scope_guard_tests {
    use super::*;
    use epigraph_auth::{AuthContext, ClientType};
    use uuid::Uuid;

    fn auth_with_scopes(scopes: &[&str]) -> AuthContext {
        AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: None,
            owner_id: None,
            client_type: ClientType::Service,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: Uuid::new_v4(),
        }
    }

    #[test]
    fn scope_guard_allows_matching_scope() {
        let auth = auth_with_scopes(&["claims:admin"]);
        assert!(EpiGraphMcpFull::enforce_tool_scope(Some(&auth), "mark_duplicate").is_ok());
    }

    #[test]
    fn scope_guard_rejects_missing_scope() {
        let auth = auth_with_scopes(&["claims:read"]);
        let err = EpiGraphMcpFull::enforce_tool_scope(Some(&auth), "mark_duplicate")
            .expect_err("read-only token must NOT be allowed to mark_duplicate");
        // Error message should mention the required scope name so callers can
        // debug a 403 without reading the source.
        assert!(
            err.message.contains("claims:admin"),
            "error should cite the required scope; got: {}",
            err.message
        );
    }

    #[test]
    fn scope_guard_rejects_missing_auth_context() {
        let err = EpiGraphMcpFull::enforce_tool_scope(None, "query_claims")
            .expect_err("no AuthContext must yield 401-style rejection");
        assert!(
            err.message.to_lowercase().contains("auth"),
            "error should mention auth; got: {}",
            err.message
        );
    }

    #[test]
    fn scope_guard_rejects_unmapped_tool_by_default() {
        let auth = auth_with_scopes(&["claims:admin"]);
        let err = EpiGraphMcpFull::enforce_tool_scope(Some(&auth), "tool_that_does_not_exist")
            .expect_err("unmapped tool must fail closed");
        assert!(
            err.message.to_lowercase().contains("not authorized")
                || err.message.to_lowercase().contains("no scope mapping"),
            "error should indicate the tool isn't authorized; got: {}",
            err.message
        );
    }
}

#[cfg(test)]
mod instructions_tests {
    use super::*;

    /// The `initialize` instructions are the only EpiGraph text a client (incl.
    /// the claude.ai web connector) is GUARANTEED to render before any tool
    /// schema is paged in. This guards that the deferred-tool / tool-search
    /// gate guidance is present there, so an agent that sees a tool name but no
    /// schema knows how to load it (rather than reporting the tool "missing").
    ///
    /// No DB: `server_instructions` is a pure function of `read_only` + the
    /// static tool router, so it exercises the real production code path.
    #[test]
    fn instructions_advertise_the_tool_search_gate() {
        let s = EpiGraphMcpFull::server_instructions(false);

        // The gate must name a tool-search mechanism the client can act on.
        assert!(
            s.contains("tool_search") || s.contains("tool-search"),
            "instructions must point at the tool-search gate; got: {s}"
        );
        // ...and the always-available enumerate-every-schema escape hatch.
        assert!(
            s.contains("list_mcp_tools"),
            "instructions must mention list_mcp_tools as the schema-enumeration fallback; got: {s}"
        );
        // It must frame deferral as client-side, NOT a missing server tool —
        // that framing is the whole point (an agent reported tools "absent").
        assert!(
            s.contains("DEFERRED"),
            "instructions must explain tools are DEFERRED (not missing); got: {s}"
        );
    }

    /// The tool count in the instructions must equal the LIVE registered tool
    /// count, computed dynamically here (never a hardcoded literal) — that is
    /// exactly what stops it going stale. If a tool is added/removed and this
    /// substring stops matching, the production string is wrong.
    #[test]
    fn instructions_tool_count_matches_live_router() {
        let n = EpiGraphMcpFull::tool_router().list_all().len();
        let s = EpiGraphMcpFull::server_instructions(false);
        assert!(
            s.contains(&format!("{n} epistemic tools")),
            "instructions must report the live tool count ({n}); got: {s}"
        );
    }

    /// `read_only` only changes the human-readable mode label, not the
    /// registered tool set (read-only is enforced at call time, not
    /// registration), so the count is identical across modes.
    #[test]
    fn instructions_reflect_mode_label() {
        assert!(EpiGraphMcpFull::server_instructions(true).contains("read-only"));
        assert!(EpiGraphMcpFull::server_instructions(false).contains("full"));
    }
}

/// The MCP half of the write-gate wiring ratchet.
///
/// PR-11 installed `epigraph_authz::GroupPolicyGate` at six `AppState`
/// constructors and both `EpiGraphMcpFull` constructors, and pinned the count —
/// but only for the six, in
/// `epigraph-api/src/state.rs::the_default_gate_is_installed_at_every_constructor`.
/// The two here were asserted in prose only, in `locked_decisions.rs`'s module
/// doc.
///
/// PR-14 deletes the tools that were the gate's only MCP-side callers
/// (`assign_ownership`, `update_partition`), so `PolicyGate::authorize` has no
/// production call site on either transport until PR-16 restores one
/// (`D-PR16-reestablish-the-write-gate-call-site-lint`). A dormant mechanism
/// with no lint over it is a mechanism that gets deleted as dead code, and the
/// three call-site lints that would have objected went with the tools. This is
/// the residual: the gate must still be CONSTRUCTED and fail-closed at both
/// entry points when PR-16 comes to consult it.
#[cfg(test)]
mod policy_gate_wiring_tests {
    /// Both `EpiGraphMcpFull` constructors install the fail-closed default.
    ///
    /// Counted from the source rather than from a built server because the
    /// field is `pub(crate)` and `Arc<dyn PolicyGate>` has no equality — there
    /// is nothing to compare two instances with. The needle is split so this
    /// assertion is not itself a third occurrence of the thing it counts.
    #[test]
    fn the_default_gate_is_installed_at_both_mcp_constructors() {
        let src = include_str!("server.rs");
        let needle = concat!(
            "policy_gate: Arc::new(epigraph_authz::",
            "GroupPolicyGate::new())"
        );
        let installs = src.matches(needle).count();
        assert_eq!(
            installs, 2,
            "expected the fail-closed default at both `policy_gate:` assignment \
             sites — `new_with_federation` and `new_shared_with_federation`, \
             which `new` and `new_shared` delegate to, so two assignments cover \
             four public entry points — found {installs}. \
             Since PR-14 the gate has no production caller here — see \
             D-PR16-reestablish-the-write-gate-call-site-lint — so it is this \
             test, and only this test, that stops it being removed as dead \
             code before PR-16 revives it."
        );
    }

    /// `with_policy_gate` is the documented injection seam and must survive the
    /// dormant period: PR-16 needs it, and a deployment that swaps in a
    /// stricter gate needs it now.
    #[test]
    fn the_injection_seam_survives() {
        let src = include_str!("server.rs");
        assert!(
            src.contains("pub fn with_policy_gate("),
            "EpiGraphMcpFull::with_policy_gate is the MCP counterpart of \
             AppState::with_policy_gate; removing it would make the gate \
             unswappable"
        );
    }
}

#[cfg(test)]
mod session_factory_tests {
    //! F1 (`da432f25`): every HTTP session of one listener shares ONE
    //! resolution of the server agent, so `agent_id()`'s provisioning call runs
    //! once per process, not once per session.
    //!
    //! `epigraph-mcp/tests/per_session_agent_resolution.rs` cannot pin this
    //! any more. Since migration 105 the provisioning function refuses a
    //! revoked row by itself, so that file's revoked-server arm also passes
    //! with a fresh cell per session. The batch F review measured this: 3
    //! passed with `SessionFactory::session` giving each session a new cell.
    //! What the shared cell still buys is the removal of the per-session
    //! write, and only this pin can see that.
    //!
    //! No database: the pool is lazy and points at a port nothing listens on,
    //! so any session that tried to resolve through the database would ERROR
    //! instead of answering.
    use super::*;

    fn unreachable_template() -> EpiGraphMcpFull {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(500))
            .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
            .expect("a lazy pool never connects at construction");
        let signer = Arc::new(AgentSigner::from_bytes(&[0x5Eu8; 32]).expect("signer"));
        let embedder = Arc::new(McpEmbedder::new(pool.clone(), None));
        EpiGraphMcpFull::new_shared_with_federation(
            pool,
            signer,
            embedder,
            false,
            crate::federation::SharedFederation::empty(),
            None,
        )
    }

    /// Structural: two sessions of one factory hold the SAME cell.
    #[tokio::test]
    async fn sessions_of_one_factory_share_the_agent_cell() {
        let sessions = SessionFactory::new(unreachable_template());
        let (a, b) = (sessions.session(), sessions.session());
        assert!(
            Arc::ptr_eq(&a.agent_db_id, &b.agent_db_id),
            "every session must share the template's agent_db_id cell"
        );
        assert!(
            !Arc::ptr_eq(&a.seen_auth_lineage, &b.seen_auth_lineage),
            "the OPERATED_BY memo is per-session by contract"
        );
    }

    /// Behavioural: once one session has resolved the agent, a NEW session
    /// answers `agent_id()` from the shared cell without touching the
    /// database. A fresh cell would try the unreachable pool and error.
    #[tokio::test]
    async fn a_new_session_answers_from_the_resolved_cell_without_the_database() {
        let sessions = SessionFactory::new(unreachable_template());
        let resolved = uuid::Uuid::new_v4();
        *sessions.session().agent_db_id.lock().await = Some(resolved);

        let fresh = sessions.session();
        let got = fresh
            .agent_id()
            .await
            .expect("a new session must not re-resolve through the database");
        assert_eq!(got, resolved);
    }
}
