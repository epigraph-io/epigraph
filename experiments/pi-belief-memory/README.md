# pi-belief-memory

Belief-graph short-term memory for the [Pi coding agent](https://github.com/earendil-works/pi).

Pi's default compaction replaces older context with a prose checkpoint. This
extension replaces it with a rendered belief graph instead — noun-claims,
verb-edges, and Dempster-Shafer beliefs in the EpiGraph sense — while leaving
the verbatim recent tail exactly as Pi manages it.

Milestone 1 of
[`docs/superpowers/specs/2026-09-09-pi-belief-graph-short-term-memory-design.md`](../../docs/superpowers/specs/2026-09-09-pi-belief-graph-short-term-memory-design.md):
session-local store, frozen render. No fork of Pi — it is an extension.

## What it looks like

Real output from `render()` (see `test/render.test.ts` and `test/cycle.test.ts`):

```
<belief-graph turns="1-7" claims="7/7" budget="170/2000">
This replaces the older conversation. Scores are pignistic probability (BetP):
1.00 = established, 0.00 = doubted. `?` marks high ignorance (never actually
checked, not evidence of a coin flip); `!` marks accumulated conflict.
Refuted entries show refuting mass instead — treat them as settled dead ends
and do not re-propose them without new evidence.
Claims tagged ⟨epigraph:ID⟩ come from long-term memory; fetch the full
record with the EpiGraph `get_claim` tool if the summary line is not enough.

## Goals
- [0.97] Make the migration test suite pass

## Constraints
- [0.97] All SQL stays in crates/epigraph-db/src/repos/

## Established
- [0.97] regenerating .sqlx changed nothing; E0308 persisted
      error=error[E0308]: mismatched types
- [0.96] the SELECT in list_by_labels is missing a column
      ⊢ regenerating .sqlx changed nothing; E0308 persisted
- [0.90] cargo sqlx prepare must be re-run after query changes
      ⟨epigraph:a4aaa487-1c2d-4e5f-9a0b-1c2d3e4f5a6b⟩

## Refuted — do not retry
- [refuted 0.60 !] the failure is a stale sqlx offline cache
      ⊣ regenerating .sqlx changed nothing; E0308 persisted

## Files
read: crates/epigraph-db/src/repos/claim.rs
edited: crates/epigraph-db/src/repos/claim.rs
</belief-graph>
```

The last section is the one a prose summary cannot produce. By the second
compaction, "we tried the stale-cache theory and it was wrong" has been
summarized away — and the agent proposes it again. Here it stays, at low
belief, with the observation that killed it attached.

## How it hooks in

One hook does the work. `session_before_compact` hands over
`CompactionPreparation` and accepts a `CompactionResult` back:

| Field | What we do with it |
|-------|--------------------|
| `messagesToSummarize` + `turnPrefixMessages` | extract claims and edges |
| `firstKeptEntryId` | **passed straight through** — the verbatim tail is Pi's, unchanged |
| `tokensBefore` | passed through |
| `summary` | the rendered belief-graph block |
| `details` | the graph itself, as JSON — durable across `/resume` |

`details` is what makes this a graph rather than a document. The next
compaction restores from it and merges deltas, instead of asking a model to
rewrite a summary it only half remembers.

Every failure path returns `undefined`, which makes Pi run its own default
compaction. A degraded prose summary beats a lost turn.

## Install

```bash
cp -r . ~/.pi/agent/extensions/belief-memory
# or, for a quick test:
pi -e ./src/index.ts
```

Commands:

- `/beliefs` — dump the current graph
- `/beliefs-hydrate <query>` — seed from EpiGraph long-term memory

Environment:

| Variable | Effect |
|----------|--------|
| `PI_BELIEF_BUDGET` | token budget for the rendered block (default: 30% of `keepRecentTokens`, capped at 6000) |
| `EPIGRAPH_API_URL` | enable hydration from an EpiGraph kernel |
| `EPIGRAPH_TOKEN` | bearer token for that kernel |
| `PI_BELIEF_HYDRATE=0` | disable automatic hydration at compaction |

## Hydration from long-term memory

With `EPIGRAPH_API_URL` set, compaction also pulls the relevant slice of the
kernel graph into the session graph, seeded from the session's live goals.

Because both sides use the same representation, this is a graph-into-graph
merge rather than a text splice:

1. `POST /api/v1/search/semantic` — seed claims, each already carrying a belief
   interval `[Bel, Pl]`, mapped back onto a mass function exactly
   (`support = Bel`, `refute = 1 - Pl`).
2. `GET /api/v1/claims/:id/neighborhood?depth=1` — **the epistemic links arrive
   already in place**; supports/contradicts structure is preserved, not
   re-derived.
3. `GET /api/v1/claims/:id` — neighbours not already held.

Every hydrated node keeps a `⟨epigraph:UUID⟩` pointer. That is what keeps the
block honest about its own lossiness: the rendered one-liner summarizes a claim
that has a full record — evidence, provenance chain, mass function, challenges —
sitting behind it, and an agent that needs the real thing calls `get_claim`
instead of treating the summary as the whole story.

Hydrated edges are added with `applyEvidence: false`. The kernel already folded
them into the belief it reported; applying them again would count the same
evidence twice.

A kernel that is down degrades to a session-only graph. Hydration is an
enhancement, never a dependency.

## Reading the numbers

Section membership reads the **mass balance**, not BetP, and this is the
subtlest thing in the code.

Dempster's rule normalizes conflict away by dividing through by `(1 - K)`,
which drags two strongly disagreeing sources back toward the middle. A
hypothesis held at 0.7 and then killed by a direct observation lands near
**BetP 0.40**, not near zero — while its refute mass outweighs its support mass
roughly two to one. Ranking by BetP alone would file every refuted approach
under "open" and lose the one signal this block exists to carry. So
`sectionFor()` tests `refute > support`, and the refuted section prints
refuting mass rather than BetP.

`test/belief.test.ts` pins this behaviour explicitly so a future reader does
not "fix" it.

## Layout

| File | Role |
|------|------|
| `src/belief.ts` | binary-frame DST: mass functions, Dempster combination, discounting, BetP |
| `src/graph.ts` | claims, edges, merge/supersede/prune |
| `src/extract.ts` | conversation span → graph deltas, with lenient parsing |
| `src/render.ts` | budgeted text block |
| `src/hydrate.ts` | EpiGraph HTTP client |
| `src/index.ts` | the Pi extension itself |

## Development

```bash
npm install
npm test        # 81 tests
npm run typecheck
```

Typechecks against the real `@earendil-works/pi-coding-agent` types (0.85.1),
so the hook signatures and return shapes are verified against upstream rather
than assumed.

## Status and what is not done

This is milestone 1 of the design doc. Not yet built:

- **Incremental capture at `turn_end`.** Extraction currently happens only at
  compaction, so it sees a large span at once.
- **Dynamic per-turn rendering** via the `context` hook. Deliberately deferred:
  the block sits *before* the verbatim tail, so re-rendering every turn
  invalidates the prompt cache for everything after it, and on a long session
  that can outweigh the tokens the graph saves.
- **Writing back to the kernel.** Hydration is read-only. Promoting session
  claims into long-term memory needs a session-scoped perspective and the
  not-embedded-by-default treatment host telemetry already gets, or it will
  pollute durable claim state.
- **The evaluation.** The metric worth measuring is re-litigation: how often
  the agent re-proposes something already refuted before the compaction
  boundary. That is what the prose summary loses on.
