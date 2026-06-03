# Perspective-lens reads — design

- **Date:** 2026-06-03
- **Status:** Approved (design); ready for implementation plan
- **Scope:** thread an optional `(frame, perspective)` lens into four MCP read tools; compute-on-read; no storage/combine change
- **Owner:** Jeremy Barton
- **Backlog:** read-side realization of `23472d04` (the default-cache-scoping headline stays a separate, deferred concern — see §10)

## 1. Context & motivation

EpiGraph has a fully-built **per-perspective frame function** (PRs #206/#208/#218): a
perspective carries `source_reliability` (evidence-type → α) and `locality_reliability`
(locality-tag → factor) maps, and `epigraph_engine::belief_query::get_perspective_belief(pool,
claim_id, frame_id, perspective_id)` recomputes a claim's belief **on-read**, re-discounting all
of its BBAs by that perspective's weights (an absent/empty perspective reduces exactly to the
global `get_belief`).

But that machinery is **dormant in normal operation** (verified 2026-06-03): the default combine
is single-global, and the paths through which agents actually **receive belief as context** —
`recall`, `recall_with_context`, `get_claim`, `get_belief` — return only the global
`truth_value`/`pignistic_prob`. There is no way for an agent to receive belief **through a chosen
lens**. Only the explicit `scoped_belief` tool exposes one claim's lensed belief.

**Goal:** let an agent **pick a `(frame, perspective)` lens per call** and have the belief it
receives as context be computed under that lens — reusing the existing compute-on-read engine,
with no write-path or cache change.

## 2. Goals / non-goals

**Goals**
- Optional `lens` input on `recall`, `recall_with_context`, `get_claim`, `get_belief`.
- When a lens is present, attach a per-claim lensed belief computed via `get_perspective_belief`.
- Enrich `list_perspectives` so an agent can discover and meaningfully choose a lens.
- Fully backward-compatible: no lens → byte-identical responses to today.

**Non-goals (out of scope for this spec)**
- Making the **default cache** perspective-scoped (the `23472d04` headline — heavier; see §10).
- Threading the lens into every belief-returning tool (`query_claims`, `get_neighborhood`, …) —
  only the four context-delivery paths above. (`scoped_belief` already lenses single claims.)
- A session-level default lens (a possible thin follow-up layered on this per-call version).
- Any change to write paths, the combine, or storage.

## 3. Lens input

A flat optional pair on each of the four tools' params (mirrors how existing optional params are
modelled in `crates/epigraph-mcp/src/types.rs`):

```
frame_id:       Option<String>   // UUID, from list_frames (binary_truth today)
perspective_id: Option<String>   // UUID, from list_perspectives
```

- Both omitted → today's global behavior (no compute-on-read; no new fields).
- Both present → lens applied (see §5).
- Exactly one present → validation error (a lens needs both a frame and a perspective).
- `perspective_id` is the canonical key (UUID). Name→id resolution is a **future convenience**,
  not v1 (names are not guaranteed unique; resolving here would add ambiguity handling).

> Why both (frame + perspective): per the design decision, the lens unit is `(frame, perspective)`
> so the API future-proofs for non-binary frames even though `binary_truth` is the only live frame
> today. `get_perspective_belief` already takes both.

## 4. Discovery (so agents can choose a lens)

- `list_frames` (exists, `crates/epigraph-mcp/src/tools/ds.rs::list_frames`) — already returns the
  available frames; no change needed beyond confirming it returns `id` + `name`.
- `list_perspectives` (`crates/epigraph-mcp/src/tools/perspectives.rs::list_perspectives`) —
  **enrich** the response so each entry carries `id`, `name`, and the lens maps
  (`source_reliability`, `locality_reliability`) read via `PerspectiveRow::source_reliability()` /
  `locality_reliability()`. An agent picks a perspective by seeing what it up/down-weights.

## 5. Behavior — lensed read

When a valid `(frame_id, perspective_id)` lens is supplied, for **each claim in the response page**
call `epigraph_engine::belief_query::get_perspective_belief(pool, claim_id, frame_id,
perspective_id)` and attach:

```
lensed_belief: {
  frame_id, perspective_id,
  belief, plausibility, pignistic_prob
}
```

- **Additive, not overwriting:** the existing global fields (`truth_value` / belief columns)
  stay as-is so existing consumers don't break and the agent sees global vs. lensed side by side.
  `lensed_belief` is `Option`, present only when a lens was requested.
- `recall` / `recall_with_context`: compute for each returned claim (page already capped by
  `limit` / neighborhood size). `recall`'s ranking/`min_truth` filtering is unchanged — it still
  uses the global value; the lens only annotates the returned set (ranking by lensed belief is a
  possible future option, explicitly not v1).
- `get_claim` / `get_belief`: single claim → one compute. For `get_belief`, the lensed interval is
  returned in `lensed_belief`; the tool's existing global return is preserved.

## 6. Reuse / no new SQL in tool layer

The tool layer calls the engine (`get_perspective_belief`) and the repo (`PerspectiveRepository`)
— no new SQL in `crates/epigraph-mcp` (per CLAUDE.md "MCP tools call the repo/engine layer"). The
bulk `recall` SQL is **unchanged**; the lens is a bounded post-pass over the already-selected page.

## 7. Scope & registration

- All four tools and `list_perspectives` are reads → scope `claims:read` (unchanged;
  `scope_map.rs` already maps them — no new tool, so the coverage test is unaffected).
- No new MCP tool is registered; this extends existing tool params + responses.

## 8. Error handling

| Condition | Result |
|---|---|
| only one of frame_id/perspective_id given | `McpError` invalid-params ("a lens needs both frame_id and perspective_id") |
| frame_id / perspective_id not a UUID | `McpError` invalid-params, names which |
| unknown frame_id or perspective_id | `McpError` not-found, names which |
| claim has no BBAs on the frame / perspective expresses no opinion | `lensed_belief` reduces to the global interval (compute-on-read already does this; documented, not an error) |
| per-claim lensed compute fails for one claim in a recall page | that claim's `lensed_belief` is null + a warn log; the rest of the page is unaffected (a lens annotation must not fail the whole recall) |

## 9. Testing

- **Discriminating test:** a perspective with a populated `source_reliability` map yields a
  `lensed_belief` **different** from the global value for the same claim, via `recall`, `get_claim`,
  and `get_belief`; an **empty/absent** perspective yields `lensed_belief` equal to global (the
  reduce-to-global guarantee). Mirror the engine fixture used by `link_epistemic_smoke`.
- **Back-compat:** no lens → response is byte-identical to current (no `lensed_belief` key, or
  null) — a regression that would catch accidental shape changes.
- **Validation:** only-one-of pair → error; unknown frame/perspective → error; one bad claim in a
  page degrades to null `lensed_belief` not a whole-call failure.
- **Discovery:** `list_perspectives` surfaces the `source_reliability`/`locality_reliability` maps.
- Council-of-critics on tests (no tautologies, prove belief actually differs under the lens).

## 10. Out of scope / future / backlog relationship

- **Default-cache perspective-scoping** (`23472d04` headline): making the default combine compute
  & cache per-perspective beliefs remains a separate, heavier item. This spec is the **read-side**
  realization of the same goal; on landing, `23472d04` should be **re-scoped** (read-side done;
  default-cache-scoping still open) rather than resolved.
- Session-level / agent-default lens (auto-lens every read for a session).
- Lens-aware ranking in `recall` (rank by lensed belief, not just annotate).
- `perspective_id`-by-name resolution.
- Threading the lens into other belief-returning tools (`query_claims`, `get_neighborhood`, …).

## 11. Code anchors (for the plan)

- Engine: `crates/epigraph-engine/src/belief_query.rs::get_perspective_belief(pool, claim_id,
  frame_id, perspective_id)` (+ `get_belief`).
- Read tools: `crates/epigraph-mcp/src/tools/recall.rs` (recall + recall_with_context),
  `crates/epigraph-mcp/src/tools/claims.rs::get_claim`, the `get_belief` tool, params in
  `crates/epigraph-mcp/src/types.rs`.
- Discovery: `crates/epigraph-mcp/src/tools/perspectives.rs::list_perspectives`,
  `crates/epigraph-mcp/src/tools/ds.rs::list_frames`,
  `crates/epigraph-db/src/repos/perspective.rs` (`source_reliability`/`locality_reliability`).
