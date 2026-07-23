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
//!   health, and a reconnect timer.
//!
//! ## Transport (v1)
//!
//! Loopback TCP only: rmcp's reqwest streamable-HTTP client cannot dial Unix
//! sockets. Extensions serve on `127.0.0.1:PORT` (never Caddy-exposed). UDS via
//! a custom hyper connector is a documented fast-follow.

pub mod client;
pub mod config;

use std::collections::HashMap;
use std::sync::Arc;

use rmcp::model::{CallToolResult, Tool};
use tokio::sync::RwLock;

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
/// routes nothing until a [`reconnect_tick`](FederationRegistry::reconnect_tick)
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
/// are O(1). The registry is wrapped in the server behind an `Arc`; interior
/// mutability (for [`reconnect_tick`](Self::reconnect_tick)) is confined to the
/// per-extension session via the registry being reconstructed or refreshed —
/// v1 exposes reconnect as a method that mutates in place under `&mut`.
pub struct FederationRegistry {
    /// Mounted extensions, indexed by position. The routing map's values are
    /// indices into this vector.
    extensions: Vec<MountedExtension>,
    /// `effective_tool_name -> index into `extensions``.
    routes: HashMap<String, usize>,
    /// Discovery token used to (re)establish discovery sessions. Kept so
    /// [`reconnect_tick`](Self::reconnect_tick) can re-dial dropped extensions
    /// without the caller threading the token back through.
    discovery_token: String,
}

impl FederationRegistry {
    /// Build a registry from parsed extension configs, connecting a discovery
    /// session to each and caching its (prefixed) tool list.
    ///
    /// Reachability is best-effort: an extension that fails to connect or list
    /// its tools is logged and mounted **unhealthy** (no client, no tools, no
    /// routes) rather than aborting the whole gateway — a down backend must not
    /// take the kernel's own tools offline. A later
    /// [`reconnect_tick`](Self::reconnect_tick) can bring it up.
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

    /// Re-establish discovery sessions for any extension currently mounted
    /// unhealthy, refreshing its cached tool list and routing entries. Healthy
    /// extensions are left untouched.
    ///
    /// Called on a timer by the gateway. A reconnect that would introduce a
    /// tool-name collision with an already-mounted extension is skipped (logged)
    /// rather than errored — reconnect must never take down the running gateway;
    /// the collision is surfaced at the next `build`.
    pub async fn reconnect_tick(&mut self) {
        // Snapshot the currently-routed names owned by *other* healthy
        // extensions so a reviving extension can't silently steal a route.
        for index in 0..self.extensions.len() {
            if self.extensions[index].healthy {
                continue;
            }
            let addr = self.extensions[index].config.addr.clone();
            let name = self.extensions[index].config.name.clone();
            let session = match client::discovery_session(&addr, &self.discovery_token).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(extension = %name, error = %e, "federation: reconnect still failing");
                    continue;
                }
            };
            let raw = match client::list_all_tools(&session).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!(extension = %name, error = %e, "federation: reconnect tools/list failed");
                    continue;
                }
            };
            let tools = Self::prefix_tools(&self.extensions[index].config, raw);
            // Guard against collisions with routes owned by other extensions.
            let mut collides = false;
            for tool in &tools {
                let n = tool.name.as_ref();
                if let Some(&owner) = self.routes.get(n) {
                    if owner != index {
                        tracing::warn!(
                            extension = %name,
                            tool = %n,
                            "federation: reconnect skipped — tool collides with a mounted extension"
                        );
                        collides = true;
                        break;
                    }
                }
            }
            if collides {
                continue;
            }
            for tool in &tools {
                self.routes.insert(tool.name.to_string(), index);
            }
            tracing::info!(extension = %name, tool_count = tools.len(), "federation: reconnected extension");
            let ext = &mut self.extensions[index];
            ext.client = Some(session);
            ext.tools = tools;
            ext.healthy = true;
        }
    }
}

/// A shareable handle to the registry. The gateway constructs one
/// [`FederationRegistry`] at boot and clones this `Arc` into every per-session
/// server. The `RwLock` allows the reconnect timer to mutate mounts while
/// readers (list/route/invoke) proceed concurrently.
pub type SharedRegistry = Arc<RwLock<FederationRegistry>>;
