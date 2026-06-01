# Workflow Evolution (GEPA) — Design & Status

**Branch:** `feat/workflow-evolution-gepa`. Origin: the 2026-06-01 Hermes-Agent
comparison (`~/hermes-epiclaw-lessons.md`, headlines #1/#2) — Hermes *designed*
the "read traces → propose edit → gate it" reflective loop but never wired it;
we have the richer signal (`behavioral_executions`) and consume it only for
`find_workflow` ranking. This builds the proposer + gate.

**User sign-off (2026-06-01):** the **autonomous statistical gate** — promote a
variant on **behavioral `rolling_success_rate`** (NOT `truth_value`; the
hierarchical workflow-outcome path never updates it), gated on **min-N ≥ 10** of
the variant's own executions AND the variant's **Wilson lower bound beating the
parent's rate**. Variants reuse the `variant_of` edge.

---

## What is built (the DECIDE layer — read-only, this branch)

All TDD'd, committed:

| Piece | Where | Commit |
|-------|-------|--------|
| `recent_executions(workflow_id, limit)` raw-row getter | `epigraph-db` behavioral_execution.rs | `f20ead6` |
| `get_workflow_executions` MCP tool (claims:read) | `epigraph-mcp` | `5d27f54` |
| Pure Wilson gate (`wilson_lower_bound`, `evaluate_workflow_promotion`) | `epigraph-engine` workflow_promotion.rs | `9f23329` |
| `success_stats` + `immediate_variant_parent` DB queries | `epigraph-db` | `4346293` |
| `evaluate_workflow_promotion` MCP tool (claims:read, read-only verdict) | `epigraph-mcp` | `4f6b57d` |

These **decide**; they do not **act**. `evaluate_workflow_promotion` resolves a
variant's immediate parent, compares both sides over the same window with the
Wilson gate, and returns `{promotable, variant_lower_bound, parent_rate, …}` —
safe to merge regardless of which apply-layer is later chosen.

**Note (immediate parent vs lineage root):** the gate compares a variant against
its *immediate* `variant_of` parent. Across many generations this can drift (a
gen-3 variant is judged against gen-2, not the original root). Comparing to the
lineage root (`find_lineage_root`) would avoid that but changes the semantics;
deferred deliberately — not built.

---

## The PROPOSER (a scheduled Claude-CLI job — NOT committable Rust)

The proposer is a prompt run by a `schedules.toml` Claude-CLI session under a
`claims:write` token (Foreman credential-partition; **never** the Anthropic SDK
— OAuth house rule). Its loop, all via existing MCP tools:

1. Pick a workflow lineage with enough executions and a non-trivial failure rate.
2. `get_workflow_executions(workflow_id)` → reflect on `step_beliefs`
   (`deviation_reason`), `tool_pattern`, and per-run `success`/`quality`.
3. Propose a variant via `improve_workflow_hierarchy` / `evolve_step` — these
   already create the `variant_of` lineage edge. (No new edge type.)
4. The variant accrues its own `behavioral_executions` as agents use it and call
   `report_workflow_outcome`.
5. (apply layer, below) once the variant has ≥ min-N runs,
   `evaluate_workflow_promotion` says whether it has earned promotion.

---

## APPLY layer — option (A) chosen and BUILT (stacked branch `feat/workflow-promotion-apply`)

User chose **(A) additive promotable flag** (2026-06-01). Built + TDD'd, stacked on the decide-layer branch:
- `ClaimRepository::merge_properties` + `promotion_flag` (db) — store/read the verdict on `properties.promotion`.
- `refresh_workflow_promotion` MCP tool (`claims:write`) — re-evaluates a variant and writes the verdict to `properties.promotion`, **overwriting every run** (bidirectional: a regressed variant is demoted, not left stale; `evaluated_at` makes staleness auditable). A lineage root is left untouched.
- `find_workflow` surfaces `promotable` (advisory field; still ranks by similarity).

The maintenance pass calls `refresh_workflow_promotion` per candidate variant; `find_workflow` callers see `promotable: true` and may prefer those variants. Reversible. Storage is a claim **property** (not a `workflows` column — variants are claims; not a label — a property carries the full verdict provenance for audit + demotion).

### (historical) the fork that was decided

`find_workflow` orders results by **semantic similarity**;
`behavioral_success_rate` is a *returned field, not a sort key* (verified
2026-06-01). So there is **no existing auto-promotion** — making a verdict
actually change which workflow agents use is a deliberate new behavior. Three
options, materially different blast radius:

- **(A) Additive `promotable` flag, surfaced as metadata.** A maintenance pass
  calls `evaluate_workflow_promotion` and stores the verdict (migration adding
  `workflows.promotable`, or a claim label/property). `find_workflow` returns it
  as a field so the calling agent prefers promoted variants. *Additive, smallest
  blast radius; needs storage + a find_workflow field.* (Closest to the
  sign-off's "maintenance pass sets a flag; find_workflow stays read-only".)
- **(B) Deprecate the loser.** When a variant is promotable, the pass calls the
  existing `deprecate_workflow` on the parent (truth → 0.05, already filtered by
  `find_workflow`'s default `min_truth = 0.3`). *No migration, no find_workflow
  change — but DESTRUCTIVE and not what the additive-flag sign-off implied.*
- **(C) Re-rank `find_workflow` by the flag.** Biggest change; touches the hot
  read path. Not recommended.

**Recommendation: (A).** It matches the sign-off (additive flag, read-only
find_workflow) and is reversible. **Not built — surfaced for an explicit
decision, since it is the one hard-to-walk-back step (a job mutating prod
workflow selection).**

---

## C-6 — the scheduled job (runtime artifact, NOT committed)

A `[[schedule]]` entry in the deployed `/var/lib/epiclaw/data/schedules.toml`
(runtime artifact; reload via `systemctl restart epiclaw`) drives the proposer +
the chosen apply-layer pass. Documented here; the actual entry + prompt are
authored at deploy time, like the existing `graph-integrity` / `system-health`
jobs. Keep cadence conservative at first (e.g. daily) and log every proposal +
verdict.

## Remaining before the loop runs in prod
1. ~~Sign off the apply layer~~ — done (A).
2. ~~Build the apply-layer maintenance pass~~ — done (`refresh_workflow_promotion`, TDD).
3. Author the `schedules.toml` proposer + apply entries (deploy-time).
4. End-to-end dry run on a seeded lineage before enabling in prod.
