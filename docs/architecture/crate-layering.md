# Crate layering: front ends over one service crate

**Status:** Canonical (backlog 6ffcb138 and 93e01896; 2026-11-27)

## 1. The rule

EpiGraph has three front ends: the HTTP API, the MCP server and the operator
CLI. They are peers over one transport-neutral service crate:

- an operation that more than one front end needs lives in **`epigraph-service`**,
  written in terms of the kernel crates (`epigraph-core`, `epigraph-db`,
  `epigraph-crypto`, `epigraph-embeddings`, `epigraph-engine`, ...);
- every front end calls `epigraph-service`, and **no front end depends on
  another**;
- `epigraph-service` never depends on a front end.

This is the option the operator chose for two backlog findings, which have one
ruling: 6ffcb138 (one surface-ownership rule, so that MCP and HTTP share one
implementation and one authorization model) and 93e01896 (no
transport-neutral service layer, with `epigraph-mcp` and `epigraph-cli`
doubling as the shared business-logic crates).

The tree does not follow the rule yet. The 93e01896 wave moves the shared
operations one module at a time, and each module is re-exported from where it
was, so no caller has to change in the same step. Until the wave ends, the
existing edges are allowed and may only shrink (section 5).

Which OAuth scope each operation requires on each transport is a separate
question, decided under backlog 8d5c8d50. This rule settles where the code
lives, not which scopes guard it.

## 2. Which crate is which

| Crate | Role |
|---|---|
| `epigraph-api` | Front end: the HTTP API (`/api/v1/...`, OAuth endpoints) and its server binary. |
| `epigraph-mcp` | Front end: the MCP server (`#[tool_router]` tools, `SCOPE_MAP`). |
| `epigraph-cli` | Front end: the operator binaries under `src/bin/` and the library code only they use. |
| `epigraph-service` | The service crate. The first steps of the 93e01896 wave create it, with the shared error type (`ServiceError`, `HttpClass`) and the tenancy context (`Ctx`). Later steps move the shared operations into it. |

Every other crate (`epigraph-core`, `epigraph-db`, `epigraph-engine`,
`epigraph-events`, `epigraph-jobs`, ...) is a kernel crate. Any crate may
depend on a kernel crate, and a kernel crate depends on no front end and not
on `epigraph-service`.

Today's front-end edges, all due to be removed by the wave:

- `epigraph-api` -> `epigraph-mcp` (optional, the `db` feature);
- `epigraph-api` -> `epigraph-cli` (optional, the `genai` feature);
- `epigraph-cli` -> `epigraph-mcp`;
- `epigraph-cli` -> `epigraph-api` (dev-dependency only).

## 3. Composition targets

A **composition target** is a `[[bin]]` (or a test crate) that links more than
one front end only to wire their servers into one process. It contains no
operation logic of its own. Such a target is the only place where two front
ends may meet, and each one must be named here, with the front ends it links
and why.

There are **none today**. `epigraph-api`'s `server` binary does not name
`epigraph_mcp`, and the MCP server ships as its own binary
(`epigraph-mcp-full`). The CLI binaries that import `epigraph_mcp` are not
composition targets: they call MCP tool functions as shared logic, which is
exactly the coupling the wave removes, and the ratchet counts them.

The one test-only exception is composition in tests. A front end's
`tests/` may build another front end beside its own (the API's tests start an
MCP server beside the router, and the CLI's tests drive the real API
handlers), and the ratchet does not count files under `tests/`. Only the
CLI's edge is a dev-dependency today: the API's tests reach `epigraph-mcp`
through the API's optional normal dependency (the `db` feature), the same
edge section 2 lists. When the wave removes that edge, those tests need an
`epigraph-mcp` dev-dependency in its place; this exception permits that, and
the step that makes the swap lists the dev edge in the ratchet's allowed edges.

## 4. Where new shared logic goes

- Logic that more than one front end needs goes into **`epigraph-service`**,
  or into a kernel crate when it has no transport-facing shape (a repository
  method, an engine computation).
- It **never** goes into `epigraph-mcp`, and never into `epigraph-api` or
  `epigraph-cli` for another front end to import. "The MCP tool already has it"
  is the reason the old layering grew. Move the core to `epigraph-service`
  and have both front ends call it.
- A front end keeps only its own transport concerns: request parsing, scope
  checks, the mapping from `ServiceError` to its own error type
  (`HttpClass` for HTTP, a JSON-RPC error for MCP), and output formatting.
- A new HTTP twin of an MCP tool (or the reverse) calls the same
  `epigraph-service` function on a viewer-stamped connection. It does not
  call the other front end's handler or tool.

## 5. How it is enforced

`crates/epigraph-api/tests/crate_layering_ratchet.rs` arrives in the same
change as the service crate (the first step of the wave, backlog 6ffcb138).
In a tree that has no `crates/epigraph-service` yet, that step has not landed:
the rule still holds, and shared logic goes into a kernel crate or waits for
the service crate, never into a front end. Once it has landed, the ratchet
fails when:

1. **A new dependency edge appears among the three front ends**, or from
   `epigraph-service` to any of them. Every dependency table is read (normal,
   dev, build and `[target.<cfg>]` tables). An allowed edge is keyed on (from,
   to, table, optional), so turning an optional edge into an unconditional
   one, or moving a dev edge into `[dependencies]`, also fails.
2. **A front end's source names another front end's crate more often than its
   per-file ceiling.** Occurrences of `epigraph_mcp::`, `epigraph_cli::` and
   `epigraph_api::` are counted in each `.rs` file under a front end's `src/`
   (comments and `#[cfg(test)]` modules included, files under `tests/`
   excluded). `epigraph-service/src` has a ceiling of zero.
3. **A front-end dependency is renamed, or a front end's crate is aliased in
   source**, which would hide references from the count.

A count below its ceiling prints "lower the ceiling", so the step that removes
a reference lowers the number in the same change. The last step of the wave
takes the allowed edges and the ceilings to zero, except the test-only
exception in section 3.

A pull request that adds shared logic says so in the PR template's checklist
(`.github/pull_request_template.md`).
