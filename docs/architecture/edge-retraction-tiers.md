# Edge retraction: which reads hide a retracted edge

**Status:** Normative for the reads it tables, and NOT YET EXHAUSTIVE. The
intent is that every `edges` read belongs to exactly one of the three tiers
below, and a new read must pick one and follow its rule. That is not true of
the codebase yet: the reads under [Not yet classified](#not-yet-classified)
have no tier and do not filter on `valid_to` today. Treat that list as open
work, not as a fourth tier.
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
| G8 contradiction pre-screen on `POST /api/v1/frames/:id/evidence` | `predict_contradiction` in `epigraph-api/src/routes/belief.rs` (in-force endpoint reads) |

The G8 pre-screen was missed by 7e870b69 and read the unfiltered endpoint
reads until the display-tier pass: a deleted `refutes` edge kept emitting
`contradiction.predicted`.

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
| Cluster / neighbourhood / compound views, and the `load_subgraph` EDGE projection (`graph_full`, `POST /api/v1/graph/query`) | every `edges` alias in `GraphViewRepository` (`crates/epigraph-db/src/repos/graph_view.rs`) | none |
| `POST /api/v1/graph/query` path walk — decides the NODE set that `load_subgraph` then projects | the `WITH RECURSIVE` walk in `execute_graph_query` (`crates/epigraph-api/src/routes/graph_query.rs`) | none |
| MCP `get_neighborhood`, `traverse` | `EdgeRepository::get_by_{source,target}_in_force` via `crates/epigraph-mcp/src/tools/graph.rs` | `include_retracted: true` — rows flagged `retracted: true` with `valid_to`; `traverse` then also follows them |
| `GET /api/v1/claims/:id/neighborhood` (multi-hop BFS) | `neighborhood_hop` in `crates/epigraph-api/src/routes/edges.rs` | `?include_retracted=true` — every edge already carries `valid_to` |
| `GET /api/v1/graph/edges`, `GET /api/v1/graph/full` | `EdgeRepository::list_all_in_force` (renamed from `list_all`) | none |
| `recall_with_context` graph expansion | `ClaimRepository::graph_expand_seeds_since` (in-force endpoint read) | none |
| `recall_with_context` structural context (sections, atoms, siblings, CORROBORATES / epistemic neighbours, `continues_argument`, atom bridges, paper attribution) | all 15 `edges` aliases in `fetch_batched_context` (`crates/epigraph-mcp/src/tools/recall.rs`) | none |
| Semantic-search graph neighbours; RAG `edge_count` (a ranking input) | `ClaimRepository::semantic_graph_neighbors`, `rag_hybrid_context` | none |
| Recall dispute annotation — `is_contested`, `dispute_count`, `contesting_claim_ids`, and the `exclude_contested` filter — on MCP `recall`, `recall_with_context` and engine recall | `ClaimRepository::dispute_batch` | none |
| `recall_with_context` graph rerank degree (`similarity * (1 + 0.1 * degree)`, a ranking input — `edge_count`'s twin) | `ClaimRepository::in_epistemic_degree_batch` | none |
| Precomputed communities and per-theme neighborhoods (`graph_clusters`, `cluster_edges`, `graph_neighborhoods`, `neighborhood_edges`) | every `edges` read in `crates/epigraph-jobs/src/cluster_graph/{runner,neighborhood}.rs`, including the leaf (`decomposes_to`) classification | none |

The `cluster_graph` rows change what the job computes, not only what is shown:
after this rule landed, a retracted edge no longer contributes to Louvain, so
the first run afterwards can move community boundaries and cluster ids compared
with the previous run. That is the intended outcome, not a regression.

The in-force endpoint reads are separate functions, not a flag on
`get_by_source` / `get_by_target`, because those stay the structural read (see
below) and neither default should be flippable by accident. `traverse` chooses
at the READ, so a hidden edge never widens the frontier or changes how
`node_limit` truncates. The same rule holds for every walk in this tier (the
claim-neighbourhood BFS, `graph_expand_seeds_since`, the graph-query path
walk): filtering only the edges a walk RETURNS is not enough, because the
node set is decided by the edges it FOLLOWS — hiding the edge while keeping
the node it reached renders a node with nothing explaining it.

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

## Not yet classified

These `edges` reads have been assigned to NO tier and do not apply
`EDGE_IN_FORCE`, so each one still returns (or counts, or walks through) a
retracted edge. The "likely tier" column is a first reading, not a decision.
Each entry needs one: filter it (belief-bearing / display), or record it under
structural with its reason.

The list was derived mechanically on the valid-to-display-tier branch: every
function under `crates/*/src` whose body reads `FROM`/`JOIN edges` and has no
`valid_to` filter, minus the ones tabled above and the write paths (dedup
probes inside an `INSERT`, the retraction writers' own snapshots). Re-run that
scan before relying on the list being complete.

**Likely belief-bearing (highest priority).** These look like siblings of reads
the belief tier already filters.

| Read | Where | Why it looks belief-bearing |
|---|---|---|
| Sheaf claim-neighbour belief pairs | `SheafRepository::get_claim_neighbor_betp_pairs` (`repos/sheaf.rs`) | sibling of the filtered `get_epistemic_edge_pairs`; feeds sheaf consistency |
| Conflict scan / silence check `CONTRADICTS` counts | `scan_conflicts`, `silence_check` (`epigraph-api/src/routes/conflicts.rs`) | the same frame silence alarm `belief.rs` computes in force |
| Reasoning-engine edge load | `load_edges_from_db` (`epigraph-api/src/routes/reasoning.rs`) | feeds the reasoning endpoints the same way the G8 pre-screen's reads feed Ascent |

**Likely display.**

| Read | Where | Note |
|---|---|---|
| `POST /api/v1/graph/compose` neighbourhood walk | `extract_neighborhood` (`epigraph-api/src/routes/computation.rs`) | a recursive walk, so the follow-vs-return rule above applies. It also has no tenancy predicate |
| Paragraph bridge graph | the `decomposes_to` reads in `build_from_bridges` (`epigraph-api/src/routes/clusters.rs`) | the `cluster_graph` job already treats `decomposes_to` classification as in-force |
| Graph statistics | `StructuralRepository::{edge_counts, degrees, clustering_coefficients}` (`repos/structural.rs`) | "structural" names the statistics here, not this doc's tier |
| Semantic-link reads | `SemanticLinkRepository::{get_by_id, get_by_source, get_by_target, get_between, get_by_type, list, count}` (`repos/semantic_link.rs`) | `SemanticLinkRepository::retract` is one of the retraction writers above, so a removed link is still listed by its own repository |
| Evidence views | `get_evidence`, `build_evidence_chains` (`epigraph-api/src/routes/edges.rs`); `EvidenceRepository::{provided_for_claim_as_of, by_relationship_for_claim}` | |
| `GET /api/v1/edges` (`list_edges`) and the other `EdgeRepository` reads `get_by_relationship`, `get_between` | `repos/edge.rs` | these SELECT `valid_to`, so a caller can see the retraction, but they do not hide it |

**Undecided (attribution / provenance / analytics).**

| Read | Where |
|---|---|
| Propagation genealogy and agent profiles | `PoliticalRepository::{get_claim_genealogy, get_agent_profile_claims, get_agent_evidence_distribution, get_agent_position_timeline, get_originated_claims_with_amplification, get_claim_techniques}` (`repos/political.rs`) |
| Claim lineage walks | `LineageRepository` (`repos/lineage.rs`) — probably structural, on the same argument as workflow lineage, but not recorded as such |
| Attribution | `EdgeRepository::{get_claims_attributed_to, count_claims_attributed_to, count_for_entity}` |
| Grounding and evidence counts | `ClaimRepository::{grounded_neighborhood, count_all_evidence_for_claim, has_grounded_evidence}` |
| Method, analysis, experiment, hypothesis | `MethodRepository` evidence reads, `AnalysisRepository`, `ExperimentRepository::count_completed_with_analysis`, `hypothesis_status` (`epigraph-api/src/routes/hypothesis.rs`) |
| Match-candidate and behavioural reads | `MatchCandidateRepo::corroborates_edges_for_claim`, `behavioral_affinity_lineage`, `corpus_stats::tenant_counts` |
| Operator CLIs | `crates/epigraph-cli/src/bin/*`, `bridge/components.rs`, `rerank/core.rs` |

## Enforcement

* `crates/epigraph-db/tests/edge_in_force_lint.rs` — every `edges` read in a
  display-tier file or function spells `EDGE_IN_FORCE` for its own alias, once
  per read; the spelling is derived from the constant, so it cannot drift. It
  checks only the scopes it LISTS: it cannot notice a read that was never
  classified (see above), so a new display read must be added to it by hand.
* `crates/epigraph-db/tests/edge_retraction_display.rs` — behavioural: each
  `GraphViewRepository` projection, and the recall-side reads
  (`graph_expand_seeds`, `semantic_graph_neighbors`, `rag_hybrid_context`,
  `dispute_batch`, `in_epistemic_degree_batch`), before/after a retraction,
  each with an in-force sibling so no assertion passes on an empty result.
* `edge_in_force_lint.rs` also pins the exact set of callers of the
  UNFILTERED `EdgeRepository::get_by_source` / `get_by_target`, each with its
  reason, because the neighbourhood walks reach `edges` through those Rust
  calls rather than SQL text.
* `crates/epigraph-mcp/tests/edge_retraction_display.rs` — `get_neighborhood`
  and `traverse` after `delete_edge`, default and opt-in; every relation
  of `fetch_batched_context` resting on a retracted edge; and `recall`'s
  dispute annotation and `exclude_contested` after `delete_edge` on the only
  `contradicts` edge (contested asserted first).
* `crates/epigraph-api/tests/edge_retraction_display_http.rs` — the claim
  neighbourhood, `graph/edges`, `graph/full` and the `graph/query` path walk
  after the `DELETE` handler.
* `crates/epigraph-jobs/tests/cluster_graph_retraction_test.rs` — communities
  and neighborhoods before/after a retraction.
* `routes::belief::tests::predict_contradiction_ignores_a_retracted_refutes_edge`
  — the G8 pre-screen.
* `crates/epigraph-db/tests/edge_retraction_enforcement.rs` — the belief tier.
