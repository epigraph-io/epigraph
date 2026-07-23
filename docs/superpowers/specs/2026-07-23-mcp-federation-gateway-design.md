# EpiGraph MCP Federation Gateway — Design

**Date:** 2026-07-23
**Status:** Approved (design), pre-implementation
**Repos touched:** `epigraph-io/epigraph` (gateway — primary), `epigraph-io/episcience` (socket transport for its existing MCP server)

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
2. **Federation transport:** **unix domain socket primary**, loopback-TCP fallback.
   Downstream serves streamable-HTTP; the gateway dials it as an rmcp client. UDS is
   `0o660`, local-only. If the streamable-HTTP-over-UDS client connector proves fiddly
   in rmcp, fall back to `127.0.0.1:PORT` (never exposed via Caddy). **De-risk the UDS
   HTTP client on day one.**

## Components

### A. Kernel: `epigraph-mcp` gateway (primary work)

- **Federation client module** (`epigraph-mcp/src/federation/`):
  - `MountedExtension` — holds an rmcp client session to one downstream, its cached
    `Vec<Tool>`, its config (name, socket spec, required scope, optional prefix), and
    connection state.
  - `FederationRegistry` — the set of mounted extensions + the aggregate
    `tool_name → extension` routing map. Built at startup from config; collision →
    startup failure.
  - Persistent client session per extension, established at startup, **lazy reconnect**
    on a timer.
- **Config parsing:** `EPIGRAPH_MCP_EXTENSIONS` (env), e.g.
  `episcience=unix:/run/epigraph/episcience-mcp.sock;scope=episcience:tools[;prefix=episcience__]`,
  semicolon-separated fields, comma-separated extensions. Absent → gateway behaves
  exactly as today (pure kernel server), so this is backward-compatible.
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

## Data flow (federated call)

1. Client → `POST /mcp` `tools/call {name: "synthesize", …}` + Bearer.
2. Gateway `auth::bearer_auth_middleware` validates the token → `AuthContext`.
3. `call_tool`: `synthesize` not in static router → routing map says `episcience`.
4. Scope gate: caller must hold `episcience:tools` (else 403). Emit `tool.invoked`.
5. Gateway forwards `tools/call` to the episcience client session **with the same
   Bearer**.
6. Episcience validates the token, resolves `agent_id`, runs the tool, returns
   `CallToolResult`.
7. Gateway returns it to the client unchanged.

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

## Risks

- **rmcp streamable-HTTP client over UDS** — the one unknown; de-risk first, loopback-TCP
  fallback ready.
- **rmcp client API surface** in the pinned version (0.15.x) — confirm a client session
  supporting `list_tools` + `call_tool` exists before committing to the transport shape.
