# Edge retraction: which reads hide a retracted edge

**Status:** Normative. Every `edges` read belongs to exactly one of the three
tiers below; a new read must pick one and follow its rule.
**Related:** `EDGE_IN_FORCE` / `EDGE_IN_FORCE_UNALIASED`
(`crates/epigraph-db/src/repos/edge.rs`), commits 4331efb6, 7e870b69, a6adf739.

---

## Why this exists

`edges` is bitemporal (`valid_from` / `valid_to`, migration 001). Since
a6adf739, **removing an edge is a retraction everywhere**: `valid_to` is set and
the row survives, so `properties.decided_by`, the signature and the content hash
stay auditable. The retraction writers are:

| Writer | Reached from |
|---|---|
| `EdgeRepository::retract_by_id` | MCP `delete_edge`, `DELETE /api/v1/edges/:id` |
| `EdgeRepository::retract` / `retract_between` | library primitives |
| `MatchCandidateRepo::retire`, `epigraph-cli retire_match_candidates` | match-candidate retirement |
| `PATCH /api/v1/edges/:id` / MCP `patch_edge` with `valid_to` | explicit lifecycle close (may be future-dated) |
| `ClaimRepository::mark_duplicate_with_repair` | the three collapse sites |
| `ClaimRepository` `edges_deduped` sweep | redundant parallel copies |
| `SemanticLinkRepository::retract` | semantic-link removal |

A retracted row is therefore still returned by any read that does not filter
on `valid_to`. The predicate is `EDGE_IN_FORCE`,
`(e.valid_to IS NULL OR e.valid_to > now())`: NULL means ongoing, and a
future-dated `valid_to` is in force until then.

Commit 4331efb6 enforced the predicate on the belief-bearing tier and said the
display and traversal tiers were "follow-on and listed in the docs". This file
is that list.

## The three tiers

### 1. Belief-bearing — always filtered, no opt-in

A retracted edge must stop influencing belief, or retraction silently undoes
itself on the next recompute.

| Read | Where |
|---|---|
| Retraction-cascade selector | `EdgeRepository::list_current_claim_targets` |
| Auto-wire re-derivation guard | `EdgeRepository::is_in_force` |
| Sheaf epistemic scan | `SheafRepository::get_epistemic_edge_pairs` |
| Matcher `graph_overlap` | `epigraph-engine/src/matching/scorer.rs` |
| Frame silence alarm (CONTRADICTS count) | `epigraph-api/src/routes/belief.rs` |

### 2. Display — hidden by default, opt-in where an audit view is useful

These reads render the graph to a person or an agent. Showing a deleted edge as
live makes the delete look like it failed, and an agent re-checking the
neighbourhood re-finds it and may try to delete it again (which now 404s).
The rule is the tenancy rule's twin: **render the graph restricted to the edges
the viewer may read AND that are in force now.** That includes the
`decomposes_to` classification probes of a display projection — a retracted
decomposition stops making its source a compound there — because a view whose
compound and atomic halves disagree is worse than either.

| Read | Where | Opt-in |
|---|---|---|
| Cluster / neighbourhood / compound views, `load_subgraph` edges (`graph_full`, graph-query routes) | every `edges` alias in `GraphViewRepository` (`crates/epigraph-db/src/repos/graph_view.rs`) | none |
| MCP `get_neighborhood`, `traverse` | `EdgeRepository::get_by_{source,target}_in_force` via `crates/epigraph-mcp/src/tools/graph.rs` | `include_retracted: true` — rows flagged `retracted: true` with `valid_to`; `traverse` then also follows them |

The in-force endpoint reads are separate functions, not a flag on
`get_by_source` / `get_by_target`, because those stay the structural read (see
below) and neither default should be flippable by accident. `traverse` chooses
at the READ, so a hidden edge never widens the frontier or changes how
`node_limit` truncates.

### 3. Structural — never filtered

These readers resolve identity or walk document / workflow structure. Retraction
is an *evidential* mechanism; applying it here would sever structure that the
retraction was not about (a6adf739, 7e870b69).

| Read | Why it stays unfiltered |
|---|---|
| `source_key.rs` `paper --asserts--> claim`, `derived_from` | resolves a claim's own source / lineage |
| `scorer.rs` `cites` | bibliographic, never retracted |
| Workflow lineage / `step_follows` walks (`epigraph-mcp/src/tools/workflows.rs`, `workflow_steps.rs`) | a retracted step edge would leave two live paths |
| `ClaimRepository::list_undecomposed`, `latest_in_lineage`, `resolve_steps_to_heads_batched` | global exclusion probes over work queues / lineage heads |
| PROV export (`epigraph-engine/src/export/prov.rs`) | provenance must keep every assertion. It does NOT yet mark a retracted relation (no `prov:invalidatedAtTime`); flagging rather than hiding is the right fix and is an open follow-up |

## Enforcement

* `crates/epigraph-db/tests/edge_in_force_lint.rs` — every `edges` read in a
  display-tier file or function spells `EDGE_IN_FORCE` for its own alias, once
  per read; the spelling is derived from the constant, so it cannot drift.
* `crates/epigraph-db/tests/edge_retraction_display.rs` — behavioural: each
  `GraphViewRepository` projection before/after a retraction, each with an
  in-force sibling so no assertion passes on an empty result.
* `edge_in_force_lint.rs` also pins the exact set of callers of the
  UNFILTERED `EdgeRepository::get_by_source` / `get_by_target`, each with its
  reason, because the neighbourhood walks reach `edges` through those Rust
  calls rather than SQL text.
* `crates/epigraph-mcp/tests/edge_retraction_display.rs` — `get_neighborhood`
  and `traverse` after `delete_edge`, default and opt-in.
* `crates/epigraph-db/tests/edge_retraction_enforcement.rs` — the belief tier.
