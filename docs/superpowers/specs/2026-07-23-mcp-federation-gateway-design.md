# EpiGraph MCP Federation Gateway — Design

**Date:** 2026-07-23
**Status:** Implemented (gateway kernel, v1 — loopback TCP transport). Episcience socket
transport + deployment (§B, §C) remain follow-on work.
**Repos touched:** `epigraph-io/epigraph` (gateway — primary), `epigraph-io/episcience` (socket transport for its existing MCP server)

> **v1 note (post-implementation).** The transport shipped as **loopback TCP only**
> (`tcp:127.0.0.1:PORT`), not UDS. rmcp 0.15's reqwest streamable-HTTP client cannot
> dial a Unix socket; a custom `hyper` + `UnixStream` connector is a documented
> **fast-follow**, not v1. Sections below that still say "unix socket" describe the
> eventual UDS design; the shipped kernel uses the loopback-TCP form everywhere
> (config `tcp:host:port`, dial `http://host:port/mcp`). See the **Session model**
> and **Transport (as built)** subsections for what actually landed.

## Problem

Episcience has a complete, 9-tool MCP server (`EpiscienceServer`: `synthesize`,
`recall_synthesis`, `get_synthesis`, `list_syntheses`, `propose_protocol`,
`add_observation`, `countersign`, `list_countersignatures`, `attach_blob`) but it is
**stdio-only and undeployed** — nothing serves it. We want episcience's tools
available to MCP clients (claude.ai, `claude` CLI) alongside epigraph's ~78 tools,
**through the one existing authenticated endpoint** (`https://5-78-124-36.nip.io/mcp`),
without coupling the kernel to episcience.

Piggybacking episcience tools *into* `epigraph-mcp` is rejected: `epigraph-mcp` does
not (and must not) depend on `episcience-db`/`episcience-api` — that reverses the
kernel→downstream dependency. Its tool router and `scope_map` are a closed set with no
extension point.

## Solution: a federation gateway

`epigraph-mcp` becomes a **gateway**: it serves its own tools locally AND mounts
downstream MCP servers over a local socket, proxying their `tools/list` and
`tools/call`. Extensions stay independent processes/deployables. The kernel gains a
generic MCP **client**; it never links extension code.

```
        claude.ai / claude CLI
                │  HTTPS + Bearer
                ▼
   Caddy ─▶ epigraph-mcp  ── ~78 local tools
             (GATEWAY)     ── + federated extensions:
                │
                ├─ unix:/run/epigraph/episcience-mcp.sock ─▶ episcience-mcp (9 tools)
                └─ unix:/run/epigraph/<ext>.sock          ─▶ future extensions
```

### Why this fits the codebase

`epigraph-mcp/src/server.rs` **already hand-writes** `ServerHandler::call_tool` /
`list_tools` / `get_tool` (instead of rmcp's `#[tool_handler]` macro) so it can inject
auth-scope enforcement and `tool.invoked` events. That manual impl is the exact seam:
`list_tools` appends federated tools; `call_tool` falls through to a mounted extension
when the static `tool_router` does not own the requested name.

## Confirmed design decisions

1. **Namespacing:** federated tools mount under their **natural names**. If two mounted
   servers (or a server and the kernel) export the same tool name, the gateway
   **refuses to start** with a loud error. A per-extension prefix (`episcience__`) is
   available in config to resolve a collision without renaming upstream tools.
2. **Federation transport:** **loopback TCP for v1; UDS is a fast-follow.** Downstream
   serves streamable-HTTP on `127.0.0.1:PORT` (never exposed via Caddy); the gateway
   dials it as an rmcp client at `http://127.0.0.1:PORT/mcp`. The de-risking outcome was
   decisive: rmcp 0.15's reqwest `StreamableHttpClientTransport` has **no way to dial a
   Unix socket** — it builds a `reqwest::Client` that only speaks TCP. UDS therefore
   needs a custom `hyper` + `UnixStream` connector, which is deferred to a follow-on and
   is **not** in the v1 kernel. Config uses the `tcp:` scheme
   (`name=tcp:127.0.0.1:8093;scope=…`); a `unix:` scheme is rejected at parse time in v1.

### Transport (as built)

- Config value form (shipped):
  `EPIGRAPH_MCP_EXTENSIONS="episcience=tcp:127.0.0.1:8093;scope=episcience:tools[;prefix=episcience__]"`
  — comma-separated extensions, semicolon-separated fields; first field is
  `name=tcp:host:port`. Absent/empty env → empty registry → gateway behaves exactly as
  pre-federation (backward compatible). A malformed entry is a hard boot error.
- `FederationRegistry::empty()` is the sync, infallible default used by the plain
  `EpiGraphMcpFull::new`/`new_shared` constructors (whose signatures are deliberately
  **unchanged** — mirroring the `claim_from_row` house rule against widening a
  ~30-caller signature). `main` injects the live registry via
  `new_with_federation` / `new_shared_with_federation` on both transport paths.

## Components

### A. Kernel: `epigraph-mcp` gateway (primary work)

- **Federation client module** (`epigraph-mcp/src/federation/`):
  - `MountedExtension` — holds an rmcp client session to one downstream, its cached
    `Vec<Tool>`, its config (name, socket spec, required scope, optional prefix), and
    connection state.
  - `FederationRegistry` — the set of mounted extensions + the aggregate
    `tool_name → extension` routing map. Built at startup from config; collision →
    startup failure.
  - Persistent **discovery** client session per extension, established at startup.
    `reconnect_tick(&mut self)` and the `SharedRegistry = Arc<RwLock<…>>` alias exist for
    a lazy-reconnect timer, but that timer is **defined-but-unwired in v1** (the field is
    a plain `Arc<FederationRegistry>`, no reconnect loop is spawned). Intentional: a
    reviving downstream is a fast-follow; v1 mounts unreachable extensions unhealthy at
    boot and leaves them so until the next process restart.
- **Config parsing:** `EPIGRAPH_MCP_EXTENSIONS` (env). **As shipped (v1, loopback TCP):**
  `episcience=tcp:127.0.0.1:8093;scope=episcience:tools[;prefix=episcience__]`,
  semicolon-separated fields, comma-separated extensions. (The UDS form
  `unix:/run/epigraph/episcience-mcp.sock` is the fast-follow shape; `unix:` is rejected
  in v1.) Absent → gateway behaves exactly as today (pure kernel server), so this is
  backward-compatible.
- **`ServerHandler` integration** (extend the existing manual impl):
  - `list_tools` = `tool_router.list_all()` + every mounted extension's cached tools.
  - `get_tool(name)` consults the routing map after the static router.
  - `call_tool`: static router owns name → dispatch locally (unchanged); else routing
    map → **coarse per-extension scope gate**, then **forward the caller's Bearer token
    verbatim** to the downstream via an rmcp client `call_tool`; else existing
    unknown-tool error. `tool.invoked` still emits at the chokepoint, tagged with the
    extension.
  - `all_tools_json` / `server_instructions` tool-count / `list_mcp_tools` include
    federated tools (dynamic count stays correct).
- **Scope handling:** `enforce_tool_scope` currently fails closed for names not in the
  static `scope_map`. Extend it: a federated tool's required scope comes from its
  extension's config (`scope=…`). The gateway checks the caller has that scope, then
  forwards the token; the downstream does fine-grained enforcement.

### B. Episcience: socket transport for its MCP server

- Add a **streamable-HTTP-on-socket** transport to `episcience-mcp-server` (today
  `serve(stdio())`). Reuse the `unix:`/`host:port` listener pattern from
  `epigraph-mcp::serve_with_listener`. Keep stdio as an option for local dev.
- Episcience validates the forwarded Bearer with the shared **`EPIGRAPH_JWT_SECRET`**
  (its REST server already does) and resolves `agent_id` from claims — no new
  credential, single token across both hops.

### C. Deployment

- New `episcience-mcp.service` (systemd) serving `unix:/run/epigraph/episcience-mcp.sock`
  (`0o660`), sharing the episcience env (DB URL, JWT secret, embed/LLM providers,
  edge-writer client).
- `epigraph-mcp` env gains `EPIGRAPH_MCP_EXTENSIONS=episcience=unix:/run/epigraph/episcience-mcp.sock;scope=episcience:tools`.
- Rebuild + redeploy `epigraph-mcp-*` and add `episcience-mcp.service`. `nip.io/mcp`
  then serves kernel + episcience tools via one endpoint, one token.

## Session model (as built — the critical correction)

rmcp 0.15's `StreamableHttpClientTransportConfig.auth_header` is **per-transport**: it
is set once at transport construction and cloned into every request on that transport.
There is **no per-call token slot**. That forces two distinct session shapes:

- **Discovery** (`federation::client::discovery_session`) — one long-lived client session
  per extension, built with `auth_header =` a gateway **service token** (env
  `EPIGRAPH_MCP_DISCOVERY_TOKEN`, falling back to `EPIGRAPH_SERVICE_TOKEN`). It drives
  `list_all_tools` to populate the routing cache, collision detection, and health. Built
  once at boot inside `FederationRegistry::build`; independent of caller identity and of
  transport (so stdio and HTTP share the same populated registry).
- **Invocation** (`federation::client::invoke_once`) — a **fresh, ephemeral** session per
  federated `tools/call`, built with `auth_header =` the **caller's raw bearer**, so the
  downstream sees the real principal (not the gateway). The session is dropped
  immediately after the call; rmcp's transport worker issues `delete_session` on drop, so
  downstream sessions do not leak.

### Forwarding the raw caller token (`RawBearerToken`)

`auth::bearer_auth_middleware` validates the incoming bearer and normally discards the
raw string, inserting only the decoded `AuthContext`. Invocation needs the **verbatim
signed token** (the downstream re-validates it), so the middleware also inserts
`RawBearerToken(pub String)` into the request extensions alongside `AuthContext`.
`call_tool` pulls it from `context.extensions.get::<http::request::Parts>()` →
`parts.extensions.get::<RawBearerToken>()`. Present only on the HTTP path: **stdio has no
bearer**, so a federated `tools/call` over stdio has no token to forward and is rejected
(federated tools list over stdio, but cannot be invoked).

### Scope gate (federated tools only)

The static `enforce_tool_scope` fails **closed** for any name absent from the
compile-time `SCOPE_MAP`, so federated tools must **not** be added to `SCOPE_MAP` (its
coverage is a static test invariant). Instead a **separate** `enforce_federated_scope`
checks the caller holds the extension's configured `scope=…`. `call_tool` branches to
federation **only after** the static `tool_router` misses the name, so the static gate
never runs for a federated tool and never runs the federated gate for a kernel tool. A
kernel tool always wins a name clash (build-time collision detection only guards clashes
*between extensions*; an extension-vs-kernel clash is the operator's `prefix=`
responsibility).

## Data flow (federated call)

1. Client → `POST /mcp` `tools/call {name: "synthesize", …}` + Bearer.
2. Gateway `auth::bearer_auth_middleware` validates the token → `AuthContext` **and
   stashes `RawBearerToken`**.
3. `call_tool`: `synthesize` not in static `tool_router` → routing map says `episcience`.
4. `enforce_federated_scope`: caller must hold `episcience:tools` (else 403). Require the
   `RawBearerToken` (else 401 — e.g. on stdio). Emit `tool.invoked` tagged `episcience:…`.
5. Gateway opens a **fresh ephemeral session** to the episcience extension with
   `auth_header =` the caller's raw bearer and forwards `tools/call`; the prefix (if any)
   is stripped back to the bare downstream name first.
6. Episcience validates the token, resolves `agent_id`, runs the tool, returns
   `CallToolResult`.
7. Gateway returns it to the client unchanged and drops the ephemeral session
   (`delete_session` downstream).

## Failure handling

- Downstream socket down at startup → its tools are **absent** from `tools/list`
  (logged); gateway serves everything else. Reconnect on a timer; tools reappear.
- Downstream errors mid-call → surfaced as a normal MCP tool error.
- Collision at startup (two servers, same tool name, no prefix) → **refuse to start**.

## Testing

- **Kernel unit:** config parse; routing-map build; collision refusal; federated-tool
  scope gate (fail-closed without the configured scope); `list_tools` aggregation;
  token-forward header present.
- **Kernel integration:** stub downstream MCP on a socket → mount → assert `tools/list`
  includes stub tools and a `tools/call` proxies through and returns the stub's result;
  assert a down socket degrades gracefully (kernel tools still listed).
- **E2E:** real `episcience-mcp` on a socket, mounted by the gateway; call `synthesize`
  through the gateway end-to-end (seeds via the recall fix + `claude -p` compose, emits
  provo edges) — the full stack proven through the single endpoint.

## Non-goals / YAGNI

- No dynamic runtime add/remove of extensions via an API — config at startup only.
- No resource/prompt federation — **tools only** (episcience exposes only tools).
- No cross-extension transactions or fan-out; one tool → one extension.
- No change to how the kernel's own tools are defined or dispatched.

## Risks (retired / updated post-implementation)

- **rmcp streamable-HTTP client over UDS** — *resolved:* confirmed **not supported** in
  rmcp 0.15's reqwest client. v1 shipped loopback TCP; UDS is a fast-follow needing a
  custom `hyper`+`UnixStream` connector. No longer a v1 risk.
- **rmcp client API surface** (0.15.x) — *confirmed:* `serve_client((), transport)` yields
  a session whose `peer()` exposes `list_all_tools()` and `call_tool(...)`. Both are
  exercised by `tests/federation_gateway_test.rs` against a stub streamable-HTTP server.
- **Per-transport `auth_header`** (new, resolved) — there is no per-call token slot, which
  is why discovery (service token, persistent) and invocation (caller token, ephemeral)
  are split. See **Session model**.
- **Reconnect timer unwired in v1** — an extension unreachable at boot stays unhealthy
  until the next `epigraph-mcp` restart. `reconnect_tick` is implemented but not spawned.
