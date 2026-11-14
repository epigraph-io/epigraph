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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use rmcp::model::{CallToolResult, Tool};

use crate::federation::client::{ExtensionClient, FederationError};
use crate::federation::config::ExtensionConfig;

/// Failure building a [`FederationRegistry`]. The only fatal condition is a tool
/// name COLLISION: a reachable extension exporting an effective tool name that
/// the kernel or another reachable extension already exports. That is an
/// operator misconfiguration the gateway must not paper over, because the
/// clashing name would be listed twice and routed to only one of its owners.
/// An *unreachable* extension at startup is NOT fatal: it is logged and
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

    /// An extension exports an effective tool name the kernel already
    /// registers (backlog 351d3def). `call_tool` tries the kernel router first,
    /// so the extension's tool could never be called, and the manifest would
    /// list the name twice.
    #[error(
        "federated tool-name collision on `{tool}`: extension `{extension}` exports a \
         tool the kernel already registers; set a `prefix=` on the extension"
    )]
    KernelCollision {
        /// The effective tool name the kernel and the extension both export.
        tool: String,
        /// Name of the extension that exported it.
        extension: String,
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
    /// Bumped on every change to this mount (promotion, demotion, a swapped
    /// tool list). A reconnect pass snapshots it before its unlocked network
    /// I/O and applies its result only if it is unchanged, so a stale result
    /// never overwrites a fresher one (see [`SharedFederation::reconnect_tick`]).
    generation: u64,
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
    /// Effective names no extension may route: the kernel's own tools. Kept
    /// so a reconnect applies the same rule `build` refused a clash under.
    reserved: HashSet<String>,
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
            reserved: HashSet::new(),
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
    /// Reserves every kernel tool name
    /// ([`EpiGraphMcpFull::kernel_tool_names`](crate::EpiGraphMcpFull::kernel_tool_names)):
    /// computed here rather than passed in, so no caller can mount extensions
    /// without the kernel's names reserved.
    ///
    /// # Errors
    /// [`RegistryError::KernelCollision`] if a *reachable* extension exports an
    /// effective tool name the kernel registers, and
    /// [`RegistryError::Collision`] if two *reachable* extensions export the
    /// same one. These are the only fatal conditions: each is an operator
    /// misconfiguration (ambiguous routing) that must fail loudly.
    pub async fn build(
        configs: Vec<ExtensionConfig>,
        discovery_token: &str,
    ) -> Result<Self, RegistryError> {
        Self::build_reserving(
            configs,
            discovery_token,
            crate::EpiGraphMcpFull::kernel_tool_names(),
        )
        .await
    }

    /// [`build`](Self::build) with a caller-chosen set of `reserved` effective
    /// names in place of the kernel's: an extension exporting one fails the
    /// build with [`RegistryError::KernelCollision`].
    ///
    /// # Errors
    /// As [`build`](Self::build).
    async fn build_reserving(
        configs: Vec<ExtensionConfig>,
        discovery_token: &str,
        reserved: HashSet<String>,
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
                            if reserved.contains(&name) {
                                return Err(RegistryError::KernelCollision {
                                    tool: name,
                                    extension: config.name.clone(),
                                });
                            }
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
                            generation: 0,
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
                            generation: 0,
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
                        generation: 0,
                    }
                }
            };
            extensions.push(mounted);
        }

        Ok(Self {
            extensions,
            routes,
            discovery_token: discovery_token.to_string(),
            reserved,
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
    /// [`FederationError::NoRoute`] if `effective_name` is not a federated tool
    /// (the caller should have routed it to the kernel), or any transport /
    /// downstream error from [`client::invoke_once`].
    pub async fn invoke(
        &self,
        effective_name: &str,
        caller_token: &str,
        arguments: Option<rmcp::model::JsonObject>,
    ) -> Result<CallToolResult, FederationError> {
        let Some(config) = self.route(effective_name) else {
            return Err(FederationError::NoRoute(effective_name.to_string()));
        };
        // Strip the gateway prefix back off before forwarding: the downstream
        // knows the tool by its *bare* name, not the gateway's namespaced one.
        let downstream_name = match config.prefix.as_deref() {
            Some(p) => effective_name.strip_prefix(p).unwrap_or(effective_name),
            None => effective_name,
        };
        client::invoke_once(
            &config.addr,
            caller_token,
            downstream_name,
            arguments,
            config.call_timeout,
        )
        .await
    }

    /// Every extension currently mounted unhealthy, as `(index, config)` pairs,
    /// paired with the discovery token needed to re-dial them.
    ///
    /// This is the **read half** of a reconnect pass. It is deliberately sync
    /// and allocation-owning so [`SharedFederation::reconnect_tick`] can drop
    /// the registry lock before doing any network I/O — see that method for why
    /// holding a lock across the dial would be worse than the bug it fixes.
    #[must_use]
    fn unhealthy_targets(&self) -> Vec<(usize, ExtensionConfig, u64)> {
        self.extensions
            .iter()
            .enumerate()
            .filter(|(_, ext)| !ext.healthy)
            .map(|(index, ext)| (index, ext.config.clone(), ext.generation))
            .collect()
    }

    /// Every extension currently mounted healthy, each with a clone of its
    /// discovery session's peer and its generation: the **read half** of a
    /// re-list pass, owned so the lock is dropped before the `tools/list`.
    #[must_use]
    fn healthy_targets(&self) -> Vec<RelistTarget> {
        (0..self.extensions.len())
            .filter_map(|index| self.relist_target(index))
            .collect()
    }

    /// [`healthy_targets`](Self::healthy_targets) for one extension, or `None`
    /// when it is not mounted healthy.
    #[must_use]
    fn relist_target(&self, index: usize) -> Option<RelistTarget> {
        let ext = self.extensions.get(index)?;
        let client = ext.client.as_ref().filter(|_| ext.healthy)?;
        Some(RelistTarget {
            index,
            config: ext.config.clone(),
            peer: client.peer().clone(),
            generation: ext.generation,
        })
    }

    /// The **write half** of a re-list of healthy extension `index`
    /// (backlog c19cdae0), applied only if the mount's generation is still the
    /// one the re-list was planned from.
    ///
    /// - The `tools/list` failed: the extension is demoted
    ///   ([`demote`](Self::demote)). Its tools stop being listed and routed
    ///   now, rather than being advertised until the process restarts.
    /// - It answered with a changed list: its routes are swapped for the new
    ///   one in this one write (under the lock, so no reader sees a half-swap),
    ///   through the same [`admit`](Self::admit) rule a reconnect uses.
    /// - It answered with the same list: nothing changes, and nothing is
    ///   logged, so a clash `admit` already reported is not re-reported every
    ///   tick.
    fn apply_relist(
        &mut self,
        index: usize,
        generation: u64,
        listed: Result<Vec<Tool>, FederationError>,
    ) {
        if self.extensions[index].generation != generation || !self.extensions[index].healthy {
            return;
        }
        let tools = match listed {
            Ok(tools) => tools,
            Err(e) => {
                self.demote(index, &e);
                return;
            }
        };
        let (admitted, skipped) = self.partition_admissible(index, tools);
        if admitted == self.extensions[index].tools {
            return;
        }
        self.log_skipped(index, &skipped);
        self.routes.retain(|_, owner| *owner != index);
        for tool in &admitted {
            self.routes.insert(tool.name.to_string(), index);
        }
        let ext = &mut self.extensions[index];
        tracing::info!(
            extension = %ext.config.name,
            tool_count = admitted.len(),
            previous_tool_count = ext.tools.len(),
            "federation: extension's tool list changed; routes swapped"
        );
        ext.tools = admitted;
        ext.generation += 1;
    }

    /// Demote extension `index` to unhealthy: drop its discovery session, its
    /// cached tools and every route it owns. The next
    /// [`reconnect_tick`](SharedFederation::reconnect_tick) re-dials it.
    fn demote(&mut self, index: usize, cause: &dyn std::fmt::Display) {
        self.routes.retain(|_, owner| *owner != index);
        let ext = &mut self.extensions[index];
        tracing::warn!(
            extension = %ext.config.name,
            error = %cause,
            "federation: extension's discovery session failed; demoted unhealthy \
             (its tools are no longer listed or routed until it reconnects)"
        );
        ext.client = None;
        ext.tools = Vec::new();
        ext.healthy = false;
        ext.generation += 1;
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
    /// entirely under the write lock. A tool whose name collides with a kernel
    /// tool or one another mounted extension routes is skipped (logged; see
    /// [`admit`](Self::admit)) rather than errored: reconnect must never take
    /// down the running gateway, and the collision is refused at the next
    /// `build`. The rest of the extension's tools are routed.
    ///
    /// Applied only if the mount is still unhealthy at the `generation` the
    /// reconnect was planned from; otherwise the fresh `session` is dropped.
    fn apply_reconnect(
        &mut self,
        index: usize,
        generation: u64,
        session: ExtensionClient,
        tools: Vec<Tool>,
    ) {
        if self.extensions[index].generation != generation || self.extensions[index].healthy {
            return;
        }
        let tools = self.admit(index, tools);
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
        ext.generation += 1;
    }

    /// The subset of `tools` extension `index` may route at runtime: every one
    /// whose effective name is neither a kernel tool ([`Self::reserved`]) nor
    /// routed to a *different* extension. Each one dropped is logged.
    ///
    /// `build` refuses either clash outright. At runtime the gateway is already
    /// serving, so the clashing name is not routed to this extension and
    /// everything else is: the kernel, or the extension that routed the name
    /// first, keeps it, and no name is ever listed twice. The routes checked
    /// are the live ones, because the snapshot a reconnect was planned from
    /// may be stale.
    fn admit(&self, index: usize, tools: Vec<Tool>) -> Vec<Tool> {
        let (admitted, skipped) = self.partition_admissible(index, tools);
        self.log_skipped(index, &skipped);
        admitted
    }

    /// [`admit`](Self::admit) without the logging: the admitted tools, and
    /// each skipped name with the extension that keeps it (`None`: the
    /// kernel).
    fn partition_admissible(
        &self,
        index: usize,
        tools: Vec<Tool>,
    ) -> (Vec<Tool>, Vec<(String, Option<usize>)>) {
        let mut skipped = Vec::new();
        let admitted = tools
            .into_iter()
            .filter(|tool| {
                let name = tool.name.as_ref();
                if self.reserved.contains(name) {
                    skipped.push((name.to_string(), None));
                    return false;
                }
                match self.routes.get(name) {
                    Some(&owner) if owner != index => {
                        skipped.push((name.to_string(), Some(owner)));
                        false
                    }
                    _ => true,
                }
            })
            .collect();
        (admitted, skipped)
    }

    fn log_skipped(&self, index: usize, skipped: &[(String, Option<usize>)]) {
        let extension = &self.extensions[index].config.name;
        for (name, owner) in skipped {
            match owner {
                None => tracing::warn!(
                    extension = %extension,
                    tool = %name,
                    "federation: tool not routed, the kernel already registers this name; \
                     set a `prefix=` on the extension"
                ),
                Some(owner) => tracing::warn!(
                    extension = %extension,
                    tool = %name,
                    owner = %self.extensions[*owner].config.name,
                    "federation: tool not routed, another mounted extension routes \
                     this name; set a distinct `prefix=`"
                ),
            }
        }
    }
}

/// One healthy extension's discovery peer, snapshotted for a re-list with no
/// lock held. See [`FederationRegistry::healthy_targets`].
struct RelistTarget {
    index: usize,
    config: ExtensionConfig,
    peer: rmcp::Peer<rmcp::RoleClient>,
    generation: u64,
}

/// Default period between reconnect passes: each re-lists the healthy
/// extensions and re-dials the unhealthy ones.
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

    /// Names of configured extensions that are mounted **unhealthy** and could
    /// plausibly own `tool_name`.
    ///
    /// An unhealthy extension has no tool list (that is what unhealthy means),
    /// so the gateway cannot know whether it owns a given name. The configured
    /// `prefix=` is the one piece of evidence that survives the outage: if any
    /// unhealthy extension's prefix matches, those are the only candidates
    /// worth naming. See [`narrow_unhealthy_candidates`] for the rule.
    ///
    /// Exists for `server.rs`'s unknown-tool error, which reports a routing
    /// failure and wants to say *why* a name might be missing. Only names are
    /// returned — never `addr`, which is deployment topology.
    #[must_use]
    pub fn unhealthy_extension_candidates(&self, tool_name: &str) -> Vec<String> {
        let pairs: Vec<(String, Option<String>)> = self
            .read()
            .unhealthy_targets()
            .into_iter()
            .map(|(_, cfg, _)| (cfg.name, cfg.prefix))
            .collect();
        narrow_unhealthy_candidates(&pairs, tool_name)
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
        let Some((index, config)) = self.route_entry(effective_name) else {
            return Err(FederationError::NoRoute(effective_name.to_string()));
        };
        let downstream_name = match config.prefix.as_deref() {
            Some(p) => effective_name.strip_prefix(p).unwrap_or(effective_name),
            None => effective_name,
        };
        let result = client::invoke_once(
            &config.addr,
            caller_token,
            downstream_name,
            arguments,
            config.call_timeout,
        )
        .await;
        // The per-call session could not be opened (backlog c19cdae0). That is
        // not proof the extension is down: the session is opened under the
        // CALLER's token, and a downstream that refuses this one caller's
        // token fails the same way. So check through the gateway's own
        // discovery session, which demotes only if that fails too; one
        // caller's bad token never takes the extension away from the others.
        if matches!(
            result,
            Err(FederationError::Connect { .. } | FederationError::Timeout(..))
        ) {
            self.recheck(index).await;
        }
        result
    }

    /// The `(index, config)` of the extension routing `effective_name`, owned.
    fn route_entry(&self, effective_name: &str) -> Option<(usize, ExtensionConfig)> {
        let guard = self.read();
        let index = *guard.routes.get(effective_name)?;
        Some((index, guard.extensions[index].config.clone()))
    }

    /// Re-list extension `index` through its discovery session now, demoting
    /// it if that fails. A no-op unless it is mounted healthy.
    async fn recheck(&self, index: usize) {
        let Some(target) = self.read().relist_target(index) else {
            return;
        };
        self.relist(target).await;
    }

    /// One re-list: `tools/list` on `target`'s discovery peer with no lock
    /// held, then [`FederationRegistry::apply_relist`] under the write lock.
    async fn relist(&self, target: RelistTarget) {
        let listed = client::list_all_tools_on(&target.peer)
            .await
            .map(|raw| FederationRegistry::prefix_tools(&target.config, raw));
        self.write()
            .apply_relist(target.index, target.generation, listed);
    }

    /// One reconnect pass, in two phases.
    ///
    /// 1. **Re-list every healthy extension** (backlog c19cdae0) through its
    ///    discovery session: a failure demotes it, a changed list swaps its
    ///    routes (see [`FederationRegistry::apply_relist`]). Before this the
    ///    tick touched only unhealthy extensions, so the gateway advertised a
    ///    boot-time tool list for the life of the process: tools the extension
    ///    had dropped stayed listed, tools it had added never appeared, and an
    ///    extension that had gone away stayed listed as if it were up.
    /// 2. **Re-dial every extension mounted unhealthy**, including one phase 1
    ///    just demoted, so an extension that restarted (whose old session the
    ///    new process does not know) is back within the same tick.
    ///
    /// Each phase is snapshot → (unlocked) network I/O → apply, so no lock is
    /// held across an `.await`, and every network step is bounded
    /// ([`client::HANDSHAKE_TIMEOUT`], [`client::LIST_TOOLS_TIMEOUT`]), so one
    /// wedged extension cannot stall the loop for the others.
    pub async fn reconnect_tick(&self) {
        let healthy = self.read().healthy_targets();
        for target in healthy {
            self.relist(target).await;
        }

        let (targets, token) = {
            let guard = self.read();
            (guard.unhealthy_targets(), guard.discovery_token())
        };
        for (index, config, generation) in targets {
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
            self.write()
                .apply_reconnect(index, generation, session, tools);
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

/// Which unhealthy extensions are worth naming in an unknown-tool error.
///
/// `unhealthy` is `(name, configured prefix)` for every extension mounted
/// unhealthy. The rule:
///
/// - If any unhealthy extension carries a `prefix=` that `tool_name` starts
///   with, return **only** those. A prefix match is real evidence of ownership
///   and the unqualified list would bury it.
/// - Otherwise return every unhealthy extension's name: without a prefix the
///   gateway genuinely cannot tell which one (if any) owns the name, and
///   guessing would be worse than listing.
///
/// Pure and separate from [`SharedFederation`] so the rule is testable without
/// standing up a registry, a lock, or a downstream server.
#[must_use]
pub fn narrow_unhealthy_candidates(
    unhealthy: &[(String, Option<String>)],
    tool_name: &str,
) -> Vec<String> {
    let prefix_owners: Vec<String> = unhealthy
        .iter()
        .filter(|(_, prefix)| {
            prefix
                .as_deref()
                .is_some_and(|p| !p.is_empty() && tool_name.starts_with(p))
        })
        .map(|(name, _)| name.clone())
        .collect();
    if prefix_owners.is_empty() {
        unhealthy.iter().map(|(name, _)| name.clone()).collect()
    } else {
        prefix_owners
    }
}

#[cfg(test)]
mod candidate_tests {
    use super::narrow_unhealthy_candidates;

    fn ext(name: &str, prefix: Option<&str>) -> (String, Option<String>) {
        (name.to_string(), prefix.map(str::to_string))
    }

    #[test]
    fn a_prefix_match_wins_over_the_unqualified_list() {
        let unhealthy = vec![
            ext("episcience", Some("es_")),
            ext("otherext", Some("ox_")),
            ext("noprefix", None),
        ];
        assert_eq!(
            narrow_unhealthy_candidates(&unhealthy, "es_attach_blob"),
            vec!["episcience".to_string()],
            "a configured prefix is real ownership evidence and must not be \
             buried under every other down extension"
        );
    }

    #[test]
    fn with_no_prefix_match_every_unhealthy_extension_is_named() {
        let unhealthy = vec![ext("episcience", Some("es_")), ext("noprefix", None)];
        assert_eq!(
            narrow_unhealthy_candidates(&unhealthy, "attach_blob"),
            vec!["episcience".to_string(), "noprefix".to_string()],
            "an unprefixed extension may own any name, so guessing is worse \
             than listing"
        );
    }

    #[test]
    fn nothing_unhealthy_names_nothing() {
        assert!(narrow_unhealthy_candidates(&[], "attach_blob").is_empty());
    }

    /// An empty `prefix=` must not match every tool name. `starts_with("")` is
    /// true for every string, so without the `!p.is_empty()` guard one
    /// misconfigured entry would be reported as the owner of every unknown
    /// tool and suppress every other candidate.
    #[test]
    fn an_empty_prefix_is_not_a_match() {
        let unhealthy = vec![ext("empty", Some("")), ext("other", None)];
        assert_eq!(
            narrow_unhealthy_candidates(&unhealthy, "attach_blob"),
            vec!["empty".to_string(), "other".to_string()],
            "an empty prefix is not evidence of ownership"
        );
    }
}

/// The `generation` guard on [`FederationRegistry::apply_relist`] and
/// [`FederationRegistry::apply_reconnect`].
///
/// A reconnect pass snapshots a mount's generation, drops the lock for its
/// network I/O, and applies its result later. Between the two, another pass
/// (or a failed call's [`SharedFederation::recheck`]) may have demoted and
/// re-promoted the same mount. These tests stage exactly that: the mount is
/// already in the state the stale result's health check would accept, so only
/// the generation comparison can refuse the stale write. Each has a control
/// at the current generation, so a test cannot pass because the write is a
/// no-op for some other reason.
#[cfg(test)]
mod generation_tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::time::Duration;

    use rmcp::model::Tool;
    use rmcp::{ServerHandler, ServiceExt};

    use super::{FederationRegistry, MountedExtension};
    use crate::federation::client::{ExtensionClient, FederationError};
    use crate::federation::config::{ExtensionConfig, DEFAULT_CALL_TIMEOUT};

    fn tool(name: &str) -> Tool {
        Tool::new(
            name.to_string(),
            "test tool",
            Arc::new(serde_json::Map::new()),
        )
    }

    fn config() -> ExtensionConfig {
        ExtensionConfig {
            name: "ext".to_string(),
            addr: "127.0.0.1:1".to_string(),
            scope: "ext:tools".to_string(),
            prefix: None,
            call_timeout: DEFAULT_CALL_TIMEOUT,
        }
    }

    /// One mount at `generation`, routing `tools` when `healthy`.
    ///
    /// `client` is `None` even when `healthy` is true, a state the gateway
    /// never builds. That is sound only for `apply_relist`, which never reads
    /// the session; the reconnect tests pass a real one.
    fn registry(healthy: bool, generation: u64, tools: &[&str]) -> FederationRegistry {
        let tools: Vec<Tool> = if healthy {
            tools.iter().map(|n| tool(n)).collect()
        } else {
            Vec::new()
        };
        let routes: HashMap<String, usize> =
            tools.iter().map(|t| (t.name.to_string(), 0)).collect();
        FederationRegistry {
            extensions: vec![MountedExtension {
                config: config(),
                client: None,
                tools,
                healthy,
                generation,
            }],
            routes,
            discovery_token: String::new(),
            reserved: HashSet::new(),
        }
    }

    fn routed(registry: &FederationRegistry) -> Vec<String> {
        let mut names: Vec<String> = registry.routes.keys().cloned().collect();
        names.sort();
        names
    }

    fn list_failed() -> Result<Vec<Tool>, FederationError> {
        Err(FederationError::ListTimeout(Duration::from_secs(10)))
    }

    /// A downstream with no tools, served over an in-memory pipe, so a test
    /// holds a real discovery session without a socket.
    struct Downstream;
    impl ServerHandler for Downstream {}

    async fn session() -> ExtensionClient {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            if let Ok(running) = Downstream.serve(server_io).await {
                let _ = running.waiting().await;
            }
        });
        match ().serve(client_io).await {
            Ok(client) => client,
            Err(e) => panic!("in-memory MCP handshake failed: {e}"),
        }
    }

    /// A re-list that failed, planned before the mount was demoted and
    /// reconnected, must not demote the freshly reconnected mount.
    #[test]
    fn a_stale_failed_relist_does_not_demote_a_reconnected_mount() {
        let mut stale = registry(true, 2, &["a"]);
        stale.apply_relist(0, 0, list_failed());
        assert!(
            stale.extensions[0].healthy,
            "a stale failure demoted the mount"
        );
        assert_eq!(routed(&stale), vec!["a".to_string()]);

        let mut current = registry(true, 2, &["a"]);
        current.apply_relist(0, 2, list_failed());
        assert!(
            !current.extensions[0].healthy,
            "control: a failure at the current generation must demote"
        );
        assert!(routed(&current).is_empty());
    }

    /// A re-list that answered, planned before a newer change, must not swap
    /// in its older tool list.
    #[test]
    fn a_stale_changed_relist_does_not_swap_routes() {
        let mut stale = registry(true, 2, &["a"]);
        stale.apply_relist(0, 0, Ok(vec![tool("old")]));
        assert_eq!(
            routed(&stale),
            vec!["a".to_string()],
            "a stale tool list replaced the current one"
        );
        assert_eq!(stale.extensions[0].generation, 2);

        let mut current = registry(true, 2, &["a"]);
        current.apply_relist(0, 2, Ok(vec![tool("new")]));
        assert_eq!(
            routed(&current),
            vec!["new".to_string()],
            "control: a changed list at the current generation must be swapped in"
        );
        assert_eq!(current.extensions[0].generation, 3);
    }

    /// A reconnect planned before the mount was promoted and demoted again
    /// must not promote it with its stale session and tool list.
    #[tokio::test]
    async fn a_stale_reconnect_does_not_promote_a_demoted_mount() {
        let mut stale = registry(false, 2, &[]);
        stale.apply_reconnect(0, 0, session().await, vec![tool("old")]);
        assert!(
            !stale.extensions[0].healthy,
            "a stale reconnect promoted the mount"
        );
        assert!(stale.extensions[0].client.is_none());
        assert!(routed(&stale).is_empty());

        let mut current = registry(false, 2, &[]);
        current.apply_reconnect(0, 2, session().await, vec![tool("new")]);
        assert!(
            current.extensions[0].healthy,
            "control: a reconnect at the current generation must promote"
        );
        assert_eq!(routed(&current), vec!["new".to_string()]);
    }
}
