# Design: EpiGraph belief graphs as short-term memory for the Pi coding harness

**Status:** design / feasibility assessment. No code landed yet.
**Upstream surveyed:** [`earendil-works/pi`](https://github.com/earendil-works/pi) @ `main`, 2026-09-09.

## The proposal

Pi's context management today is *keep-recent + prose-summary*: when context
crosses a threshold, everything older than roughly `keepRecentTokens` is sent to
an LLM and replaced by a single markdown checkpoint. The recent tail survives
verbatim.

The proposal keeps the verbatim tail exactly as it is, and replaces the prose
checkpoint with a **rendered belief graph** — noun-claims, verb-edges, and
Dempster-Shafer beliefs in the EpiGraph sense — as the representation of older
context.

```
  ┌────────┬────────────────────────┬──────────────────────────────────┐
  │ system │  BELIEF GRAPH BLOCK    │  verbatim tail (last N turns)    │
  └────────┴────────────────────────┴──────────────────────────────────┘
                     ▲                              ▲
        older context, structured        unchanged Pi retention
        (claims + edges + BetP)          (firstKeptEntryId onward)
```

## Why this is worth doing

A prose summary is lossy in a specific, damaging way: it is a *point estimate of
the past*. Three failure modes we hit constantly in long coding sessions:

1. **Refuted branches vanish.** The agent tries approach X, it fails, the
   summary says "implemented approach Y". Two compactions later the agent
   proposes X again, because nothing in context says X was tried and refuted.
   A belief graph keeps `X works` as a live claim with *low* BetP and a
   `contradicts` edge to the observed error — cheaper than the prose that would
   be needed to say the same thing, and it survives re-summarization because it
   is a row, not a sentence competing for space.

2. **Superseded facts stay asserted.** "File A has bug B" and "bug B fixed in
   commit C" both end up in the summary, ordered by narrative rather than by
   currency. EpiGraph's `is_current` / `supersedes` machinery already solves
   this: render only current claims, and the contradiction never reaches the
   model.

3. **Re-summarization drift.** Pi's `UPDATE_SUMMARIZATION_PROMPT` asks an LLM to
   preserve the previous summary while folding in new messages. Every
   compaction is another lossy generation on top of a lossy generation. A graph
   is *merged*, not rewritten: new claims are inserted, existing ones get new
   evidence edges, contradicted ones get their mass shifted. The compaction
   LLM call goes from "rewrite this document" to "emit deltas", which is a much
   smaller and more reliable ask.

The uncertainty representation is the part that has no prose equivalent. DST
distinguishes "we believe this at 0.5" from "we have no evidence either way" via
mass on the full frame. In a coding session that is the difference between "the
test is flaky" and "we never ran the test".

## Where Pi lets us hook in

The good news: **no fork is required for a working version.** Pi has
first-class extension points at exactly the three places this needs.

Note that Pi carries two parallel context stacks, and they have different
surfaces:

| Layer | Package | Surface |
|-------|---------|---------|
| CLI + extensions | `packages/coding-agent` | `ExtensionAPI` events (`pi.on(...)`) |
| Harness runtime / SDK | `packages/agent` (`pi-agent-core`) | `HookMap` hooks + `entryProjectors` |

Each has its own `compaction.ts`. An extension targets the coding-agent layer;
an SDK embedder targets the harness layer. The design below is written against
the extension layer, with the harness-layer equivalents noted.

### 1. Replace the summary — `session_before_compact`

`packages/coding-agent/src/core/extensions/types.ts:595`

```ts
interface SessionBeforeCompactEvent {
  preparation: CompactionPreparation;  // messagesToSummarize, turnPrefixMessages,
                                       // firstKeptEntryId, tokensBefore,
                                       // previousSummary, fileOps, settings
  branchEntries: SessionEntry[];
  reason: "manual" | "threshold" | "overflow";
  willRetry: boolean;
  signal: AbortSignal;
}
// returns { cancel? } | { compaction: CompactionResult }
```

and `CompactionResult` (`core/compaction/compaction.ts:88`) carries
`details?: T` — arbitrary extension-owned JSON persisted on the
`CompactionEntry`.

That is the whole integration in one hook: take `messagesToSummarize`, extract
claims and edges, merge into the graph, render the graph to text, return it as
`summary`, and stash the *structured* graph in `details`. `firstKeptEntryId`
passes through untouched, so **the verbatim tail behaviour is unchanged** — the
"keep a few previous turns" half of the ask needs no work at all.

`details` is the load-bearing field: it makes the graph durable across
`/resume`, and the next compaction can read the prior graph back out of
`branchEntries` instead of round-tripping through prose. Upstream's own
`session_before_compact` example (`examples/extensions/custom-compaction.ts`)
is the template.

Harness-layer equivalent: the `before_compaction` hook
(`packages/agent/src/harness/agent-harness.ts:488`), same shape, returning
`{ compaction: CompactResult }` with its own `details`.

### 2. Render into context — `context` (optional, dynamic mode)

`packages/coding-agent/src/core/extensions/types.ts:688`

```ts
interface ContextEvent { messages: AgentMessage[] }  // returns { messages }
```

Fires before every LLM call with a deep copy. This is where a *dynamic* variant
re-renders the graph per turn — running recall against the current turn so the
in-context slice is the relevant subgraph rather than a frozen dump.

Harness-layer equivalent: `transform_context`
(`agent-harness.ts:443`), or more cleanly `entryProjectors` — a custom entry
type (`appendCustomEntry("belief_graph", …)`) with a registered projector that
expands it to messages at context-build time
(`packages/agent/src/harness/session/context.ts:60`).

### 3. Incremental capture — `turn_end` / `tool_execution_end`

Waiting for compaction to extract claims means the extraction LLM sees a large
span at once. Cheaper and higher-fidelity: capture candidate claims at
`turn_end`, so extraction is incremental and compaction becomes a pure
render step. Trade-off is one extra small call per turn; make it configurable.

## What gets extracted

The mapping from a coding session onto EpiGraph's noun/verb split
(`docs/intro/02-concepts.md` §1) is direct. The rule — "does this have stable
identity, or is it an event?" — separates cleanly:

**Noun-claims** (stable identity, dedup key `(content_hash, agent_id)`):

| Kind | Example |
|------|---------|
| Goal / requirement | "User wants belief-graph memory in the Pi harness" |
| Constraint | "Never squash-merge; feature branches only" |
| Codebase fact | "`claim_from_row` has ~20 callers in `repos/claim.rs`" |
| Artifact state | "`compaction.ts` exports `prepareCompaction`" |
| Decision | "Use the extension API rather than forking Pi" |
| Hypothesis | "The test failure is caused by a stale `.sqlx/` cache" |
| Observation | verbatim error text, verbatim command output excerpt |

**Verb-edges** (timestamped events between nouns):

`read`, `edited`, `ran`, `observed`, `decided`, `supports`, `contradicts`,
`depends_on`, `supersedes`.

The hypothesis/observation pair is where the value concentrates. "Stale `.sqlx/`
cache causes the failure" is a *hypothesis* claim; the observed test output that
did or did not go away after `cargo sqlx prepare` is an *observation* claim; and
the `supports`/`contradicts` edge between them is what a prose summary throws
away.

**Fidelity rule:** exact file paths, function names, error strings, and commit
SHAs must survive verbatim. They go in claim `properties`, not in prose content
— content is the assertion, properties are the evidence payload. Pi's default
summarization prompt already carries this instruction ("Preserve exact file
paths, function names, and error messages") for good reason; the structured
form enforces it rather than asking politely.

## Rendering

The in-context block is a budgeted text serialization. Sketch:

```
<belief-graph turns="1-14" claims="23" budget="4200/6000">
## Goals
- [0.95] Belief-graph short-term memory for Pi          (user, turn 1)

## Constraints
- [1.00] Develop on claude/pi-harness-belief-graphs-mzimdw

## Established
- [0.92] Pi exposes session_before_compact with details: T
         ⊢ read core/extensions/types.ts:595
- [0.88] No fork needed for a working version
         ⊢ supported-by: extension API survey

## Open / contested
- [0.30] Dynamic per-turn rendering is worth the cache cost
         ⊣ contradicted-by: prefix cache invalidation measurement (turn 11)

## Refuted — do not retry
- [0.05] epigraph-tools is the MCP extension point
         ⊣ CLAUDE.md: "that is not how tools reach the MCP server"

## Files
read: compaction.ts, context.ts, types.ts
edited: (none)
</belief-graph>
```

Budgeting: sort by BetP × recency × relevance-to-current-turn, fill to the token
budget, drop the tail. "Refuted — do not retry" gets a reserved floor; it is the
cheapest section and prevents the most expensive failure mode.

Note that the rendered block is *derived*. The authoritative graph is the JSON
in `details`, so the renderer can change without a migration.

## Two axes of choice

### Axis A — where the graph lives

**A1 — session-local.** Graph is JSON in the compaction entry's `details` plus
extension state. Zero infrastructure, works offline, ships as a single
`.pi/extensions/` file. DST degrades to a scalar with evidence counts. Memory
is per-session; nothing carries across.

**A2 — EpiGraph-kernel-backed.** Claims and edges are written to a real EpiGraph
instance under a session-scoped perspective, via the MCP tools
(`submit_claim`, `link_epistemic`, `recall_with_context`, `get_belief`,
`supersede_claim`). Real DST with mass functions and conflict/ignorance
tracking. Memory becomes cross-session and cross-agent, and
`consolidate_claims` / `sweep_semantic_duplicates` handle graph bloat.

**Recommendation: build A1 first, behind a `store` interface, then add A2 as a
second implementation.** A1 is a self-contained extension that can be evaluated
on its own; A2's value (persistence, sharing, real DST) is real but it drags in
a server dependency, agent identity, and auth before we know whether the
core idea earns its keep. The extraction and rendering code is identical in
both.

One thing to settle before A2: the harness is short-*term* memory but EpiGraph
is a durable ledger. Writing every session's transient hypotheses into the
kernel will pollute claim state unless they land under a session-scoped
perspective/frame and are marked as such — the same concern the repo already
carries for host telemetry, which is deliberately excluded from embedding.
Session-scoped claims should almost certainly follow that precedent: labelled,
not embedded by default, promoted into the durable graph only on explicit
consolidation.

### Axis B — frozen vs dynamic rendering

**B1 — frozen.** Render once at compaction into the `summary` string. The block
is then a stable prefix. Prompt caching keeps working.

**B2 — dynamic.** Re-render every turn via the `context` hook, with recall
scored against the current turn. Better relevance density per token.

**The cost of B2 is prompt-cache invalidation, and it is not small.** The belief
block sits *before* the verbatim tail, so re-rendering it invalidates the cached
prefix for everything after it, every turn. On a long session that can dominate
the token savings the graph buys. Pi is already careful here — it sets
`cacheRetention: "none"` on summarization calls specifically because those
one-off prompts will not be reused.

**Recommendation: B1 by default, B2 opt-in with a change-gate** — only
re-render when the graph actually changed materially, and hold the block at a
stable position so an unchanged render is byte-identical and the cache survives.

## Risks

| Risk | Mitigation |
|------|------------|
| Prompt-cache invalidation (B2) | B1 default; change-gated re-render |
| Extraction cost/latency per compaction | Reuse Pi's existing budget — it already spends a summarization call here; incremental `turn_end` capture spreads it |
| Structured-output reliability | Schema-constrained extraction; fall back to Pi's default compaction on parse failure (upstream example already models this — return `undefined` and default compaction runs) |
| Graph bloat over a long session | Budgeted render + BetP-ranked eviction; `consolidate_claims` under A2 |
| Verbatim detail loss | Exact strings in claim `properties`, never paraphrased into content |
| Divergence from upstream | Extension API only, no fork — upstream churn risk limited to the three hook signatures |

## Proposed first milestone

A single self-contained Pi extension implementing A1 + B1:

1. `session_before_compact` handler: extract → merge → render → return
   `{ compaction: { summary, firstKeptEntryId, tokensBefore, details: graph } }`.
2. Graph model + merge semantics (insert, evidence-attach, supersede, refute).
3. Budgeted renderer with a reserved "refuted" section.
4. Fall back to default compaction on any extraction failure.
5. `pi.registerCommand("beliefs", …)` to dump the current graph for inspection.

Evaluation: run the same long coding task through default compaction and
through the extension, and measure re-litigation — how often the agent
re-proposes something already refuted before the compaction boundary. That is
the metric the prose summary loses on, so it is the one worth measuring first.

## Source references

Upstream (`earendil-works/pi` @ `main`, surveyed 2026-09-09):

- `packages/coding-agent/src/core/extensions/types.ts:595` — `SessionBeforeCompactEvent`
- `packages/coding-agent/src/core/extensions/types.ts:688` — `ContextEvent`
- `packages/coding-agent/src/core/compaction/compaction.ts:88` — `CompactionResult.details`
- `packages/coding-agent/src/core/compaction/compaction.ts:732` — `CompactionPreparation`
- `packages/coding-agent/docs/compaction.md` — compaction model, cut points, split turns
- `packages/coding-agent/examples/extensions/custom-compaction.ts` — reference handler
- `packages/agent/src/harness/agent-harness.ts:430` — `HookMap` (`before_compaction`, `transform_context`)
- `packages/agent/src/harness/session/context.ts:60` — `entryProjectors`

This repo:

- `docs/intro/02-concepts.md` §1 — noun-claims vs verb-edges
- `docs/intro/02-concepts.md` §3 — beliefs and DST, BetP
- `docs/architecture/noun-claims-and-verb-edges.md`
