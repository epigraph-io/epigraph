//! MCP federation gateway.
//!
//! The gateway mounts zero or more downstream "extension" MCP servers
//! (e.g. episcience) and exposes their tools alongside the kernel's own,
//! behind the single EpiGraph MCP endpoint. Callers see one flat tool list;
//! the gateway routes each federated `tools/call` to the owning extension.
//!
//! ## Modules
//!
//! - [`config`] — parse `EPIGRAPH_MCP_EXTENSIONS` into [`config::ExtensionConfig`]s.
//!   (Stage 1; no networking.)
//!
//! Stage 2 (networking) adds:
//! - `client` — thin wrapper over rmcp `serve_client` + streamable-HTTP client
//!   transport, with a persistent discovery session (service token) and an
//!   ephemeral per-call invocation session (caller token).
//! - `registry` — [`config::ExtensionConfig`] → mounted extensions with cached
//!   tool lists, a `tool_name -> extension` routing map, collision detection,
//!   health, and a reconnect timer ([`SharedFederation::spawn_reconnect_loop`]).
//!
//! ## Transport (v1)
//!
//! Loopback TCP only: rmcp's reqwest streamable-HTTP client cannot dial Unix
//! sockets. Extensions serve on `127.0.0.1:PORT` (never Caddy-exposed). UDS via
//! a custom hyper connector is a documented fast-follow.

pub mod client;
pub mod config;

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use rmcp::model::{CallToolResult, Tool};

use crate::federation::client::{ExtensionClient, FederationError};
use crate::federation::config::ExtensionConfig;

/// Failure building a [`FederationRegistry`]. The only fatal condition is a tool
/// name COLLISION (two reachable extensions exporting the same effective tool
/// name) — that is an operator misconfiguration the gateway must not paper over,
/// because silent last-writer-wins routing would send calls to the wrong
/// backend. An *unreachable* extension at startup is NOT fatal: it is logged and
/// skipped (see [`FederationRegistry::build`]).
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// Two extensions resolve to the same effective (post-prefix) tool name.
    #[error(
        "federated tool-name collision on `{tool}`: exported by both extension \
         `{first}` and extension `{second}`; set a distinct `prefix=` on one"
    )]
    Collision {
        /// The effective tool name exported by two extensions.
        tool: String,
        /// Name of the first extension to claim the tool.
        first: String,
        /// Name of the second extension that collided.
        second: String,
    },
}

/// One downstream extension mounted into the gateway: its config, a live
/// discovery session (service-token authenticated), the cached tool list, and a
/// health flag. `client` is `None` when the extension was unreachable at build
/// time (or its discovery session later dropped) — it holds no cached tools and
/// routes nothing until a [`reconnect_tick`](SharedFederation::reconnect_tick)
/// re-establishes it.
pub struct MountedExtension {
    /// Parsed config for this extension (name, addr, scope, optional prefix).
    pub config: ExtensionConfig,
    /// Persistent discovery session, or `None` if currently unreachable.
    pub client: Option<ExtensionClient>,
    /// Cached tools with their **effective** (post-prefix) names, exactly as the
    /// gateway advertises them to callers.
    pub tools: Vec<Tool>,
    /// Whether the discovery session is currently believed healthy.
    pub healthy: bool,
}

impl MountedExtension {
    /// Apply the extension's optional prefix to a downstream tool's name,
    /// yielding the effective name the gateway advertises and routes on.
    fn effective_name(prefix: Option<&str>, downstream: &str) -> String {
        match prefix {
            Some(p) => format!("{p}{downstream}"),
            None => downstream.to_string(),
        }
    }
}

/// The federation gateway's routing table over zero or more mounted extensions.
///
/// Holds each [`MountedExtension`] and a `effective_tool_name -> extension_index`
/// map. Lookups ([`route`](Self::route), [`required_scope`](Self::required_scope))
/// are O(1).
///
/// This type is the plain, single-threaded data model; it performs no locking of
/// its own. The server holds it inside a [`SharedFederation`], which owns the
/// lock and drives [`reconnect_tick`](SharedFederation::reconnect_tick).
pub struct FederationRegistry {
    /// Mounted extensions, indexed by position. The routing map's values are
    /// indices into this vector.
    extensions: Vec<MountedExtension>,
    /// `effective_tool_name -> index into `extensions``.
    routes: HashMap<String, usize>,
    /// Discovery token used to (re)establish discovery sessions. Kept so
    /// [`reconnect_tick`](SharedFederation::reconnect_tick) can re-dial dropped
    /// extensions without the caller threading the token back through.
    discovery_token: String,
}

impl FederationRegistry {
    /// An empty registry with no mounted extensions. Used as the default
    /// federation for the plain `EpiGraphMcpFull::new`/`new_shared` constructors
    /// (which keep their pre-federation signatures) and whenever
    /// `EPIGRAPH_MCP_EXTENSIONS` is absent — the gateway then behaves exactly as
    /// it did before federation. Unlike [`build`](Self::build) this is sync and
    /// infallible: no network I/O, no collisions possible.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            extensions: Vec::new(),
            routes: HashMap::new(),
            discovery_token: String::new(),
        }
    }

    /// Build a registry from parsed extension configs, connecting a discovery
    /// session to each and caching its (prefixed) tool list.
    ///
    /// Reachability is best-effort: an extension that fails to connect or list
    /// its tools is logged and mounted **unhealthy** (no client, no tools, no
    /// routes) rather than aborting the whole gateway — a down backend must not
    /// take the kernel's own tools offline. A later
    /// [`reconnect_tick`](SharedFederation::reconnect_tick) brings it up without
    /// a gateway restart.
    ///
    /// # Errors
    /// [`RegistryError::Collision`] if two *reachable* extensions export the
    /// same effective tool name. This is the sole fatal condition: it is an
    /// operator misconfiguration (ambiguous routing) that must fail loudly.
    pub async fn build(
        configs: Vec<ExtensionConfig>,
        discovery_token: &str,
    ) -> Result<Self, RegistryError> {
        let mut extensions: Vec<MountedExtension> = Vec::with_capacity(configs.len());
        let mut routes: HashMap<String, usize> = HashMap::new();

        for config in configs {
            let index = extensions.len();
            let mounted = match client::discovery_session(&config.addr, discovery_token).await {
                Ok(session) => match client::list_all_tools(&session).await {
                    Ok(raw_tools) => {
                        let tools = Self::prefix_tools(&config, raw_tools);
                        // Register routes; a collision on the effective name is
                        // fatal. Detect BEFORE moving `tools` into the mount.
                        for tool in &tools {
                            let name = tool.name.to_string();
                            if let Some(&prior) = routes.get(&name) {
                                return Err(RegistryError::Collision {
                                    tool: name,
                                    first: extensions[prior].config.name.clone(),
                                    second: config.name.clone(),
                                });
                            }
                            routes.insert(name, index);
                        }
                        tracing::info!(
                            extension = %config.name,
                            addr = %config.addr,
                            tool_count = tools.len(),
                            "federation: mounted extension"
                        );
                        MountedExtension {
                            config,
                            client: Some(session),
                            tools,
                            healthy: true,
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            extension = %config.name,
                            addr = %config.addr,
                            error = %e,
                            "federation: extension connected but tools/list failed; \
                             mounting unhealthy (no tools routed)"
                        );
                        MountedExtension {
                            config,
                            client: None,
                            tools: Vec::new(),
                            healthy: false,
                        }
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        extension = %config.name,
                        addr = %config.addr,
                        error = %e,
                        "federation: extension unreachable at startup; \
                         mounting unhealthy (no tools routed)"
                    );
                    MountedExtension {
                        config,
                        client: None,
                        tools: Vec::new(),
                        healthy: false,
                    }
                }
            };
            extensions.push(mounted);
        }

        Ok(Self {
            extensions,
            routes,
            discovery_token: discovery_token.to_string(),
        })
    }

    /// Rewrite each downstream tool's `name` to its effective (prefixed) name.
    /// Everything else (schema, description, annotations) is preserved so
    /// callers see the downstream tool faithfully under the gateway namespace.
    fn prefix_tools(config: &ExtensionConfig, tools: Vec<Tool>) -> Vec<Tool> {
        let prefix = config.prefix.as_deref();
        tools
            .into_iter()
            .map(|mut tool| {
                let effective = MountedExtension::effective_name(prefix, tool.name.as_ref());
                tool.name = std::borrow::Cow::Owned(effective);
                tool
            })
            .collect()
    }

    /// Every federated tool the gateway currently advertises, across all healthy
    /// extensions, with effective (prefixed) names. Order follows extension
    /// mount order then the downstream's own tool order.
    #[must_use]
    pub fn list_federated_tools(&self) -> Vec<Tool> {
        self.extensions
            .iter()
            .flat_map(|ext| ext.tools.iter().cloned())
            .collect()
    }

    /// `true` when no extensions are mounted (env absent/empty), so the caller
    /// can cheaply skip the whole federation branch.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.extensions.is_empty()
    }

    /// Look up the extension config that owns `effective_name`, or `None` if the
    /// name is not a federated tool (caller should fall through to kernel tools).
    #[must_use]
    pub fn route(&self, effective_name: &str) -> Option<&ExtensionConfig> {
        self.routes
            .get(effective_name)
            .map(|&i| &self.extensions[i].config)
    }

    /// The OAuth scope a caller must hold to invoke `effective_name`, or `None`
    /// if it is not a federated tool. This is the SOLE scope gate for federated
    /// tools (they are deliberately absent from the static `SCOPE_MAP`).
    #[must_use]
    pub fn required_scope(&self, effective_name: &str) -> Option<&str> {
        self.route(effective_name).map(|c| c.scope.as_str())
    }

    /// Proxy a federated `tools/call` to the owning extension on a fresh
    /// ephemeral session authenticated with `caller_token`.
    ///
    /// # Errors
    /// [`FederationError::Request`] if `effective_name` is not a federated tool
    /// (the caller should have routed it to the kernel), or any transport /
    /// downstream error from [`client::invoke_once`].
    pub async fn invoke(
        &self,
        effective_name: &str,
        caller_token: &str,
        arguments: Option<rmcp::model::JsonObject>,
    ) -> Result<CallToolResult, FederationError> {
        let Some(config) = self.route(effective_name) else {
            return Err(FederationError::Request(format!(
                "no federated route for tool `{effective_name}`"
            )));
        };
        // Strip the gateway prefix back off before forwarding: the downstream
        // knows the tool by its *bare* name, not the gateway's namespaced one.
        let downstream_name = match config.prefix.as_deref() {
            Some(p) => effective_name.strip_prefix(p).unwrap_or(effective_name),
            None => effective_name,
        };
        client::invoke_once(&config.addr, caller_token, downstream_name, arguments).await
    }

    /// Every extension currently mounted unhealthy, as `(index, config)` pairs,
    /// paired with the discovery token needed to re-dial them.
    ///
    /// This is the **read half** of a reconnect pass. It is deliberately sync
    /// and allocation-owning so [`SharedFederation::reconnect_tick`] can drop
    /// the registry lock before doing any network I/O — see that method for why
    /// holding a lock across the dial would be worse than the bug it fixes.
    #[must_use]
    fn unhealthy_targets(&self) -> Vec<(usize, ExtensionConfig)> {
        self.extensions
            .iter()
            .enumerate()
            .filter(|(_, ext)| !ext.healthy)
            .map(|(index, ext)| (index, ext.config.clone()))
            .collect()
    }

    /// The token used to (re)establish discovery sessions.
    #[must_use]
    fn discovery_token(&self) -> String {
        self.discovery_token.clone()
    }

    /// Promote extension `index` to healthy with `tools` routed to it, using the
    /// freshly-established discovery `session`.
    ///
    /// The **write half** of a reconnect pass: sync, no `.await`, so it runs
    /// entirely under the write lock. A reconnect that would introduce a
    /// tool-name collision with an already-mounted extension is skipped (logged)
    /// rather than errored — reconnect must never take down the running gateway;
    /// the collision is surfaced at the next `build`. Returns `true` when the
    /// extension was actually promoted.
    fn apply_reconnect(
        &mut self,
        index: usize,
        session: ExtensionClient,
        tools: Vec<Tool>,
    ) -> bool {
        // Guard against stealing a route owned by a *different* extension. The
        // snapshot this reconnect was planned from may be stale: another tick
        // (or a concurrent revival) could have claimed the name in between.
        for tool in &tools {
            let name = tool.name.as_ref();
            if let Some(&owner) = self.routes.get(name) {
                if owner != index {
                    tracing::warn!(
                        extension = %self.extensions[index].config.name,
                        tool = %name,
                        "federation: reconnect skipped — tool collides with a mounted extension"
                    );
                    return false;
                }
            }
        }
        for tool in &tools {
            self.routes.insert(tool.name.to_string(), index);
        }
        tracing::info!(
            extension = %self.extensions[index].config.name,
            tool_count = tools.len(),
            "federation: reconnected extension"
        );
        let ext = &mut self.extensions[index];
        ext.client = Some(session);
        ext.tools = tools;
        ext.healthy = true;
        true
    }
}

/// Default period between reconnect attempts for unhealthy extensions.
pub const DEFAULT_RECONNECT_INTERVAL: Duration = Duration::from_secs(30);

/// A shareable handle to the registry. The gateway constructs one
/// [`FederationRegistry`] at boot and clones this handle into every per-session
/// server. The `RwLock` lets the reconnect timer mutate mounts while readers
/// (list/route/invoke) proceed concurrently.
///
/// The lock is a **`std`** `RwLock`, not tokio's, on purpose. Its guards are
/// `!Send`, so the compiler *refuses* to hold one across an `.await` — which is
/// exactly the invariant this type depends on. Every network round-trip
/// (discovery dial, `tools/list`, and the per-call downstream proxy) happens
/// with no lock held; only owned snapshots cross the boundary. Holding a read
/// guard across a downstream call would let one hung extension stall every
/// subsequent reader and take the whole gateway down — strictly worse than the
/// unhealthy-mount bug the reconnect timer exists to fix.
#[derive(Clone)]
pub struct SharedFederation(Arc<RwLock<FederationRegistry>>);

impl SharedFederation {
    /// Wrap an already-built registry in a shareable handle.
    #[must_use]
    pub fn new(registry: FederationRegistry) -> Self {
        Self(Arc::new(RwLock::new(registry)))
    }

    /// A handle around an empty registry (no extensions configured).
    #[must_use]
    pub fn empty() -> Self {
        Self::new(FederationRegistry::empty())
    }

    /// Read guard, recovering from poisoning. A panic in an unrelated reader
    /// must not wedge the gateway's tool list for the rest of the process: the
    /// registry is plain data behind the lock, so the inner value stays usable.
    fn read(&self) -> RwLockReadGuard<'_, FederationRegistry> {
        self.0.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Write guard, recovering from poisoning (see [`Self::read`]).
    fn write(&self) -> RwLockWriteGuard<'_, FederationRegistry> {
        self.0.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// `true` when no extensions are mounted. See
    /// [`FederationRegistry::is_empty`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }

    /// Every federated tool currently advertised. See
    /// [`FederationRegistry::list_federated_tools`].
    #[must_use]
    pub fn list_federated_tools(&self) -> Vec<Tool> {
        self.read().list_federated_tools()
    }

    /// The config of the extension owning `effective_name`, or `None` if the
    /// name is not a federated tool.
    ///
    /// Returns an **owned** clone rather than a borrow: the guard is released
    /// on return, so a reference into the registry could not outlive it.
    #[must_use]
    pub fn route_config(&self, effective_name: &str) -> Option<ExtensionConfig> {
        self.read().route(effective_name).cloned()
    }

    /// Proxy a federated `tools/call` to the owning extension. See
    /// [`FederationRegistry::invoke`].
    ///
    /// # Errors
    /// As [`FederationRegistry::invoke`].
    pub async fn invoke(
        &self,
        effective_name: &str,
        caller_token: &str,
        arguments: Option<rmcp::model::JsonObject>,
    ) -> Result<CallToolResult, FederationError> {
        // Resolve the route to an OWNED config, then drop the guard before the
        // downstream round-trip (the `std` guard is `!Send`, so this is enforced
        // rather than merely intended).
        let Some(config) = self.route_config(effective_name) else {
            return Err(FederationError::Request(format!(
                "no federated route for tool `{effective_name}`"
            )));
        };
        let downstream_name = match config.prefix.as_deref() {
            Some(p) => effective_name.strip_prefix(p).unwrap_or(effective_name),
            None => effective_name,
        };
        client::invoke_once(&config.addr, caller_token, downstream_name, arguments).await
    }

    /// One reconnect pass: re-dial every extension currently mounted unhealthy
    /// and, on success, route its tools. Healthy extensions are untouched.
    ///
    /// Structured as snapshot → (unlocked) network I/O → apply, so no lock is
    /// held across an `.await`.
    pub async fn reconnect_tick(&self) {
        let (targets, token) = {
            let guard = self.read();
            (guard.unhealthy_targets(), guard.discovery_token())
        };
        for (index, config) in targets {
            let session = match client::discovery_session(&config.addr, &token).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(extension = %config.name, error = %e, "federation: reconnect still failing");
                    continue;
                }
            };
            let raw = match client::list_all_tools(&session).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!(extension = %config.name, error = %e, "federation: reconnect tools/list failed");
                    continue;
                }
            };
            let tools = FederationRegistry::prefix_tools(&config, raw);
            self.write().apply_reconnect(index, session, tools);
        }
    }

    /// Spawn the background reconnect timer, returning its handle.
    ///
    /// Without this, an extension that was down at boot stays unroutable for the
    /// lifetime of the process — the gateway would need a restart to pick it up.
    pub fn spawn_reconnect_loop(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                this.reconnect_tick().await;
            }
        })
    }
}
