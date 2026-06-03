# `link_epistemic` MCP tool — design

- **Date:** 2026-06-03
- **Status:** Approved (design); ready for implementation plan
- **Scope:** one new MCP tool in `crates/epigraph-mcp`; no schema change
- **Owner:** Jeremy Barton

## 1. Context & motivation

Agents can already write **structural** edges between claims via the MCP
`link_hierarchical` tool, but that tool is deliberately *inert*: it accepts only
`decomposes_to`/`section_follows`/`continues_argument` and does **no** Dempster–Shafer
recomputation, **no** factor inserts, **no** `edge.added` event, and **no** provenance
(see `crates/epigraph-mcp/src/tools/link_hierarchical.rs` header comment).

There is **no MCP path to write epistemic edges** (`supports`, `contradicts`, …).
The HTTP route `crates/epigraph-api/src/routes/edges.rs::create_edge` already does this
correctly: it creates the edge, then on first creation calls
`trigger_edge_ds_recomputation` → `auto_wire_edge_if_epistemic`
(`crates/epigraph-engine/src/edge_factor.rs`), which builds a DS mass function from the
source claim's belief interval and **recomputes the target claim's combined belief**, plus
records provenance and emits `edge.added`.

**Goal:** give agents a `link_epistemic` MCP tool with *parity to the HTTP route* — write an
epistemic edge AND wire it into belief propagation — so agents can express supports/contradicts
relationships that actually move belief.

### Key fact that drives the design
A bare `EdgeRepository::create*` writes only a row in the `edges` table. The edge is **inert**
(no BBA, no belief change) until `auto_wire_edge_if_epistemic` runs. Therefore the new tool
**must call the engine wiring fn**, not merely write the edge (the `link_hierarchical` path is
the wrong template; `create_edge` is the right one).

## 2. Goals / non-goals

**Goals**
- New MCP tool `link_epistemic(source_claim_id, target_claim_id, relationship, properties?)`.
- Accept the engine's non-neutral epistemic relationships (below) and wire belief on creation.
- Idempotent on `(source, target, relationship)`, matching the HTTP route and `link_hierarchical`.
- Honor the repo convention: routes and MCP both call the shared repo/engine layer; no duplicated logic.

**Non-goals (explicitly out of scope for v1)**
- `supersedes` edges (see §4 exclusion).
- Edges between non-claim node types (claim↔claim only, like `link_hierarchical`).
- A per-edge strength/weight override knob (the engine's default restriction profile is used;
  a `properties.weight` override is a possible future extension, not v1).
- Any change to `link_hierarchical` (its inert contract stays intact).

## 3. Tool surface

```
link_epistemic(
  source_claim_id: String,   // UUID
  target_claim_id: String,   // UUID
  relationship:    String,   // one of the epistemic set in §4
  properties:      Option<serde_json::Value>,
)
```
Direction convention: **source → target** means "source `relationship` target"
(e.g. a `supports` edge: source is evidence for / strengthens target). This matches
`restriction_kind_with_profile` in `crates/epigraph-engine/src/sheaf.rs`.

**Response** (so the agent can see the effect):
```json
{
  "edge_id": "<uuid>",
  "was_created": true,
  "relationship": "supports",
  "belief_wired": true,
  "target_belief": { "belief": 0.x, "plausibility": 0.x, "pignistic_prob": 0.x }
}
```
- `belief_wired=false` is returned when the edge was created but wiring failed (see §7), or
  when `was_created=false` (idempotent re-hit — no re-wire, consistent with the HTTP route).
- `target_belief` reflects the target claim's combined belief after recompute (best-effort read).

## 4. Allowed relationships

Exposed set = the engine's non-neutral epistemic relations **minus `supersedes`**:

| Direction effect | relationships |
|---|---|
| positive (strengthen target) | `supports`, `corroborates`, `elaborates`, `generalizes`, `specializes` |
| negative (weaken target)     | `contradicts`, `refutes` |

Define these as a constant `EPISTEMIC_RELATIONSHIPS` in the MCP crate (mirror of how
`link_hierarchical` defines `HIERARCHICAL_RELATIONSHIPS`), using the **lowercase canonical**
strings (matching the `epigraph-core::relationships` constants and the engine's internal
`to_ascii_lowercase`). Validation rejects anything else (structural types, unknown strings, and
`supersedes`) with an error that lists the valid set.

> **Case note (resolved):** the MCP tool owns this constant and does **not** route through
> `routes/edges.rs::is_valid_relationship`. That HTTP whitelist (`VALID_RELATIONSHIPS`) stores
> only UPPER-CASE `CONTRADICTS`/`CORROBORATES` and is case-sensitive, whereas the engine
> lowercases internally — so a "must be in `VALID_RELATIONSHIPS`" check would spuriously fail.
> The coverage guard (§8) therefore asserts the **non-Neutral engine mapping only**, which is
> the property that actually governs belief.

### `supersedes` exclusion (deliberate)
The engine treats `supersedes` as a negative restriction, but `supersedes` has dedicated
semantics: the `supersede_claim` tool (scope `claims:admin`) creates the relationship **and**
flips `is_current=false` + nulls the superseded claim's embedding
(`crates/epigraph-db/src/repos/claim.rs::supersede`). Allowing any `claims:write` agent to
write a bare `supersedes` edge here would create an inconsistent state (supersedes edge, both
claims still `is_current`). The repo CLAUDE.md also reserves `supersedes`/`is_current` for
epistemic claim replacement, not generic edges. So `supersedes` stays exclusively with
`supersede_claim`.

## 5. Behavior (mirror of `routes/edges.rs::create_edge`)

1. Parse `source_claim_id`/`target_claim_id` as UUIDs (clear error on failure).
2. Reject self-loop (`source == target`) — matches `link_hierarchical` and core `Edge::new`.
3. Verify both claims exist (matches `link_hierarchical`'s existence check).
4. Reject `relationship ∉ EPISTEMIC_RELATIONSHIPS`.
5. `EdgeRepository::create_if_not_exists(src,"claim",tgt,"claim",&rel,props,None,None)`
   → `(edge_row, was_created)`.
6. If `was_created`:
   - Call the engine wiring (`auto_wire_edge_if_epistemic`, same entry the HTTP route uses via
     `trigger_edge_ds_recomputation`) to build the BBA and recompute the **target** belief.
   - Record provenance from the caller's auth context (as the HTTP route does when authenticated).
   - Emit the `edge.added` event.
7. If `!was_created`: return the existing edge, `belief_wired=false`, no re-wire (idempotent).
8. Read the target claim's `{belief, plausibility, pignistic_prob}` for the response (best-effort).

### Reuse / no duplication
Per repo CLAUDE.md ("HTTP routes and MCP tools both call the repo layer; do not duplicate"):
the MCP tool calls the **same** `EdgeRepository` methods and the **same** engine wiring fn the
HTTP route calls. If `create_edge`'s create→wire→provenance→event sequence is non-trivial to
share, extract a small reusable helper (e.g. `create_and_wire_epistemic_edge`) — placed where
both `epigraph-api` and `epigraph-mcp` can call it (engine or a shared service module) — and
have **both** the HTTP route and the MCP tool delegate to it. Decide extraction granularity in
the plan; the invariant is: one implementation of the create-and-wire logic, two call sites.

## 6. Scope & registration

- Scope: **`claims:write`** (same tier as `link_hierarchical`; no admin needed since
  `supersedes` is excluded). Add `("link_epistemic", "claims:write")` to
  `crates/epigraph-mcp/src/scope_map.rs`; the existing `every_registered_tool_has_a_scope`
  coverage test enforces the mapping.
- Register the `#[tool(...)]` method on `EpiGraphMcpFull` (alongside `link_hierarchical`),
  with a description that states it writes a belief-affecting epistemic edge and lists the
  valid relationships and the direction convention.
- Tool count in `get_info` instructions is derived from `list_all().len()` (post PR #258), so
  it updates automatically.

## 7. Error handling

| Condition | Result |
|---|---|
| bad UUID | `McpError` invalid-params, names which id |
| self-loop | `McpError` invalid-params |
| missing source/target claim | `McpError` not-found, names which |
| relationship not in set | `McpError` invalid-params, lists valid set |
| edge created but wiring fails | **success** with `belief_wired=false` + hint to call `recompute_beliefs` (the edge row is the durable commit; `recompute_beliefs` is idempotent and retry-safe) |

Rationale for the wiring-failure choice: the durable fact (the edge) must not be lost on a
transient recompute error, and the agent gets an explicit signal that belief wasn't updated so
it can re-trigger. (Note: because wiring only runs on `was_created`, a naive retry of
`link_epistemic` would find `was_created=false` and skip re-wire — so the recovery path is
`recompute_beliefs`, not a re-call. The plan may optionally make wiring re-runnable when the
edge exists-but-unwired; v1 relies on `recompute_beliefs`.)

## 8. Testing

- **Coverage guard (most important):** a test asserting **every** `EPISTEMIC_RELATIONSHIPS`
  entry maps to a **non-Neutral** `RestrictionKind` via the engine's
  `restriction_kind_with_profile` (with the default `RestrictionProfile::scientific()`). This
  makes it impossible to expose an inert relationship and catches drift if the engine mapping
  changes. (We do **not** assert membership in `routes/edges.rs::VALID_RELATIONSHIPS` — see the
  case note in §4; the engine mapping, not the HTTP whitelist, is the real invariant.)
- **Validation unit tests:** accept each of the 7 epistemic types; reject `decomposes_to`,
  an unknown string, and `supersedes`; reject self-loop.
- **DB integration** (small DB per CLAUDE.md — `epigraph_db_repo_test` or `#[sqlx::test]`):
  - `supports` edge raises the target's belief (vs. pre-state).
  - `contradicts` edge lowers it.
  - second identical call → `was_created=false`, belief unchanged (no double-application).
  - `properties` round-trips onto the edge row.
- Tests reviewed against the council-of-critics standard (no tautologies, no happy-path-only).

## 9. Code anchors (for the implementation plan)

- Template tool: `crates/epigraph-mcp/src/tools/link_hierarchical.rs` (+ `tools/mod.rs`,
  `server.rs` registration, `types.rs` params, `scope_map.rs`).
- Edge repo: `crates/epigraph-db/src/repos/edge.rs::create_if_not_exists` (returns
  `(EdgeRow, bool)`).
- Engine wiring: `crates/epigraph-engine/src/edge_factor.rs::auto_wire_edge_if_epistemic`
  / `auto_wire_ds_for_edge`; restriction mapping in
  `crates/epigraph-engine/src/sheaf.rs::restriction_kind_with_profile`.
- HTTP reference path: `crates/epigraph-api/src/routes/edges.rs::create_edge`,
  `trigger_edge_ds_recomputation`, `is_valid_relationship`, `VALID_RELATIONSHIPS`.
- Canonical relationship constants: `crates/epigraph-core/src/edge.rs` (`relationships` module).

## 10. Out of scope / future

- Per-edge strength/weight override (`properties.weight` → restriction factor).
- Epistemic edges between non-claim nodes.
- Re-runnable wiring for an exists-but-unwired edge (v1 uses `recompute_beliefs`).
- Exposing `supersedes` (stays with `supersede_claim`).
