# Atlas W3: the node set of each leaf group (plan)

Backlog item W3 bd6f0a02 (epic 8fa0282d). Design:
`docs/superpowers/specs/2026-11-12-atlas-nested-groups-and-subgraph-view-design.md`
(§2 "Deepest level", §5 "Visibility", §7 step 3 and "the 100-node cap").

Stacked on W2 (PR #803, migration 210, `AtlasMapRepository`). W3 adds no
migration and does not change 210.

## What this item delivers

Given a candidate leaf (a list of claim ids from the W4 or W5 hierarchy
builder), the map it is built for (a team map or the public map) and a cap
(default 100), W3 returns either:

- **`Fits`**: a deterministic node set made of the leaf's claims, the agents
  that asserted or authored them (one node per agent per leaf), the evidence
  attached to them, and the edges among those nodes. This is the input to the
  W6 layout and the W7 flow weights. Or:
- **`NeedsSplit { reason, counts }`**: claims + agents + evidence exceed the
  cap, so the leaf must split one level further. W3 also provides a
  deterministic fallback split the builders can call. W4 and W5 replace it with
  their own clustering.

It writes nothing: no edge, no level document. W10 assembles the W10a document
from this output plus W6 positions, W7 weights and W8 names.

## Files

| File | What |
|------|------|
| `crates/epigraph-db/src/repos/atlas_leaf.rs` | the DB read (`AtlasLeafRepository::read_leaf_rows`), the pure assembly (`assemble_leaf`), the per-claim cap, the fallback split (`fallback_split`, `resolve_with_fallback`), and unit tests of the pure half |
| `crates/epigraph-db/src/repos/mod.rs`, `src/lib.rs` | module registration and re-exports |
| `crates/epigraph-db/tests/atlas_leaf_repo.rs` | DB tests (a fresh database per test, `remote-cargo --db`) |

## Data model

**Node kinds and edge spellings follow the W10a contract** (PR #801,
`services/explorer/contract/atlas_level/v1/schema.json`): node `kind` is
`claim`, `agent` or `evidence`; an edge's `relationship` is the stored
relationship name, unnormalised. W3 does not depend on the W10a crate.

**The pure input, `LeafRows`**: what the map may draw around the candidate
claims, read once:
- `claims`: the candidate claims the map may draw, each with its filer
  (`claims.agent_id`, when that agent row exists);
- `evidence`: drawable evidence rows reached from those claims, each with its
  `claim_id`;
- `agents`: agents reached through an authorship edge (the `agents` table has no
  tenancy: 077's `agents_identity` is `USING (true)`; the read only drops
  dangling ids, since edges carry no FK);
- `edges`: drawable stored edges whose endpoints are `claim`, `agent` or
  `evidence` nodes in that universe;
- `unreadable_claims`: input ids the map may not draw.

**Membership rules** (who joins the leaf):
- an agent joins through a claim it filed (`claims.agent_id`) or an authorship
  edge: `agent -> claim` with a relationship in
  `claim_ingest::AGENT_SOURCE_AUTHORSHIP`, or `claim -> agent` in
  `AGENT_TARGET_AUTHORSHIP`, both compared lower-cased;
- evidence joins through `evidence.claim_id` or any drawable stored edge
  between it and the claim, in either direction;
- once the node set is fixed, every drawable stored edge whose two endpoints are
  both in it (matched on kind and id) is an edge of the leaf. Edges to claims
  outside the leaf are left to the outgoing-links stage.

**Output, `LeafNodeSet`**: `nodes` (kind + id, sorted), `edges` (source, target,
relationship, origin, sorted), `capped` (per-claim truncations) and `counts`.
- Stored edges repeating one (source, target, relationship) collapse into one
  edge carrying every stored edge id, sorted, so W7 can take the largest weight
  among them (the W10a rule).
- A column link with no stored edge between the same two nodes gets a DERIVED
  edge, so every agent and evidence node has an edge to a claim (a W10a
  invariant): a filer becomes `agent -asserts-> claim` (the stored spelling of
  the same fact), and `evidence.claim_id` becomes `evidence -evidence_for->
  claim`. `evidence_for` is a new name, chosen because `supports` would preset a
  sign that W7 must take from the stored mass. The origin marks it derived, so
  W7 and the view can tell it from a stored edge. This spelling is an open
  question for the operator.
- Everything is built from ordered collections (`BTreeMap`, `BTreeSet`), so the
  output depends on the input set, never on input order or SQL row order.

**Cap and split** (pure, one counting function shared by assembly and split):
1. **Per-claim cap.** A claim whose own attachments do not fit beside it
   (1 + agents + evidence > cap) keeps a deterministic prefix: its filer, then
   its other agents by id, then its evidence by id, `cap - 1` in all. The cut is
   recorded as `CappedClaim { claim, kept_agents, kept_evidence, total_agents,
   total_evidence }`. This is what guarantees termination: every claim alone
   fits, so a split always makes progress.
2. **Count** = |claims| + |distinct agents| + |distinct evidence| over the
   capped attachments. A shared agent or evidence row counts once.
3. Count ≤ cap: `Fits`. Otherwise `NeedsSplit { reason: NodeCap, counts }`.
   No readable claim: `Empty` (W10a requires at least one node; the builder
   drops the leaf). A cap of 0 is refused.
4. **Fallback split** (`fallback_split`): walk the readable claims in id order,
   add each claim with its capped attachments to the current part, and start a
   new part when the next claim would take it over the cap. Each claim keeps its
   evidence; a node shared by claims in two parts appears in both. Every part
   fits, by step 1. `resolve_with_fallback` assembles each part.
5. The W10a document caps a leaf at 1,024 edges. W3 reports the collapsed edge
   count in `counts`; enforcing the edge cap is left to the document assembly
   (W10) and is an open question.

**Scope (tenancy).** The read takes the build's connection (the transaction
`AtlasMapRepository::begin_build_snapshot` opened, so the rows match the
recorded epochs), a `Viewer` and the `AtlasMap`.
- Every statement carries an explicit MAP predicate, because the nightly build
  runs on the maintenance connection with a bypass viewer, where the viewer
  splice renders nothing and RLS is bypassed:
  - claims and evidence: `visibility = 'public' OR (visibility = 'group' AND
    owner_group_id = T)`;
  - edges: the same, and a co-owned edge only when its co-owner is T as well
    (072's intersection: a member of T who is not in the other owner cannot
    read it), so a co-owned edge is never drawn;
  - the public map binds T as NULL, so only public rows pass.
- Every statement is also spliced on the viewer (`VISIBILITY` for claims and
  evidence, `EDGE_VISIBILITY` for edges), so a scoped caller is filtered by its
  own session too. The map predicate still matters then: a viewer in teams A
  and B passes B's rows through the splice, and the map predicate removes them
  from A's map.
- A node reached only through a row the map cannot read is dropped: an agent
  whose only authorship edge is another team's, evidence re-tenanted to another
  team, an edge owned or co-owned by another team.
- No belief column is read (W7 and W10 own belief, behind the role-aware
  belief ratchet).
- Set-based reads (`= ANY($1)`), five statements per leaf whatever its size.

## Tests

**Pure unit tests** (`atlas_leaf::tests`, no database):
- `count_is_claims_plus_distinct_agents_plus_distinct_evidence`: a shared agent
  and shared evidence count once.
- `exactly_at_the_cap_fits_and_one_over_needs_a_split`: the boundary.
- `a_claim_with_more_evidence_than_fits_is_capped_and_recorded`: deterministic
  prefix, recorded totals, and the leaf then fits.
- `fallback_split_partitions_the_claims_and_every_part_fits`: seeded random
  graphs; the parts cover every readable claim exactly once, in id order, every
  part re-assembles to `Fits`, each claim's capped evidence is in its part.
- every agent and evidence node has an edge to a claim, after capping and after
  splitting, derived edges included: not a test of its own but the
  `assert_attached` helper, which the count, cap, split and derived-edge tests
  call on every leaf they assemble.
- `duplicate_stored_edges_collapse_and_keep_every_id`.
- `derived_edges_stand_in_only_where_no_stored_edge_does`.
- `a_zero_cap_is_refused_and_no_drawable_claim_is_empty`.

**DB tests** (`crates/epigraph-db/tests/atlas_leaf_repo.rs`):
- `every_leaf_of_a_test_hierarchy_fits_the_cap`: a team hierarchy of three
  candidate leaves (one that fits, one over the cap through evidence, one claim
  with 150 evidence rows), resolved through `resolve_with_fallback`; every leaf
  has ≤ 100 nodes and the leaves cover the drawable claims.
- `agents_or_evidence_pushing_a_leaf_over_the_cap_trigger_a_resplit`: a leaf of
  40 claims that fits, then evidence rows, and separately authorship edges from
  new agents, push it to 101 nodes; the result turns into `NeedsSplit` with the
  counts, and the fallback parts fit.
- `a_high_degree_agent_appears_once`: one agent files 60 claims and holds an
  `AUTHORED` edge to each; the leaf holds one agent node.
- `another_teams_private_rows_never_appear`: on the BUILD path (superuser
  connection, bypass viewer, inside `begin_build_snapshot`) for team T's map and
  the public map, and once for a scoped viewer who is in T and U: U's claim in
  the input, an evidence row re-tenanted to U on T's claim, a claim-to-claim
  edge owned by U, an authorship edge owned by U that is the only path to its
  agent, an edge co-owned by T and U, and the filer of U's claim never appear.
  T's own rows and public rows do (calibration). The public map's own arms are
  tested by rows of T hung on nodes the public map draws: an edge between two
  public claims, an evidence row on a public claim (migration 110's hidden
  evidence), an edge between a public evidence row and a public filer; all are
  on T's map and none on the public map. A public evidence row of U's claim,
  reached through a public edge, is drawn on both maps and the read carries no
  claim id for it. Seeded by direct inserts and forced tenancy updates on the
  superuser pool; every forced stamp is checked before the reads.
- `retracted_edges_are_never_drawn`: a retracted claim-to-claim edge, a
  retracted authorship edge (and so its author) and a retracted
  evidence-to-agent edge are not drawn; the same leaf built while they are in
  force draws all three (calibration). In force is the predicate of `EDGE_IN_FORCE`
  (`repos/edge.rs`), the repo's one predicate: `valid_to` only, so a future
  `valid_from` is not filtered, as on every other edge read.
- `the_node_set_is_identical_across_runs`: two reads with the claim ids in
  different orders and with duplicates, over rows inserted out of id order,
  give equal results.

**Fail on the old code** (each mutation applied to `atlas_leaf.rs`, both test
targets run, then restored and `touch`ed). Measured on the pushed branch:

| Mutation | Tests that went red |
|---|---|
| cap check on claims only | `exactly_at_the_cap_...`, `fallback_split_...` (unit); `agents_or_evidence_..._resplit`, `every_leaf_..._fits_the_cap` (DB) |
| node count summed per claim (a shared agent counted per claim) | 2 unit; `a_high_degree_agent_appears_once`, the resplit, hierarchy and determinism DB tests |
| claims map predicate removed | `another_teams_private_rows_never_appear` |
| evidence map predicate removed | `another_teams_private_rows_never_appear` |
| claim-edge read: owner clause removed | `another_teams_private_rows_never_appear` |
| claim-edge read: co-owner clause removed | `another_teams_private_rows_never_appear` |
| agent/evidence-edge read: owner clause removed | `another_teams_private_rows_never_appear` (it survived the scope test before that test seeded such edges) |
| agent/evidence-edge read: co-owner clause removed | `another_teams_private_rows_never_appear` |
| per-claim cap removed | `a_claim_with_more_evidence_...`, `fallback_split_...` (unit); `every_leaf_..._fits_the_cap` (DB) |
| collapsed edge ids left unsorted | `duplicate_stored_edges_collapse_and_keep_every_id` (unit only: the read already sorts edges by id, so the DB path cannot see it) |
| fallback split walks input order | `fallback_split_...` (unit); `the_node_set_is_identical_across_runs` (DB) |
| derived edges removed | 4 unit; `another_teams_private_rows_never_appear` |
| public map binds the nil uuid as its team | none: an equivalent mutant (no row is owned by the nil group), recorded, not a gap |
| public map lets team rows in, team map unchanged (claims read) | `another_teams_private_rows_never_appear` (public map nodes) |

Added after review (the public map's own arms, retracted edges, hidden claim
ids), each run alone against the DB target and restored:

| Mutation | Assertion that went red in the DB tests |
|---|---|
| claim-edge read: public map admits any single-owner group edge | `another_teams_private_rows_never_appear`: T's edge between two public claims is on the public map |
| agent/evidence-edge read: the same | `another_teams_private_rows_never_appear`: T's edge between a public evidence row and a public filer is on the public map |
| evidence read: public map admits any group evidence | `another_teams_private_rows_never_appear`: T's evidence on a public claim is on the public map |
| evidence read keeps the raw `claim_id` | `another_teams_private_rows_never_appear`: the read carries U's claim id for the public evidence row |
| claim-edge read: in-force check removed | `retracted_edges_are_never_drawn` |
| agent/evidence-edge read: in-force check removed | `retracted_edges_are_never_drawn` |

Before the scope test seeded rows of T on public nodes, the first three
mutations, applied together, left every test green.

**Lints**: `no_unscoped_pool`, `visibility_lint` (every new function that takes
a connection takes and splices a viewer), `pool_read_lint`, `viewer_ratchet`.
W3 writes no edge, so `edge_writer_signing_ratchet` is not affected.

## "Done when" → proof

| Criterion | Proof |
|---|---|
| every leaf in a test hierarchy has ≤ 100 nodes | `every_leaf_of_a_test_hierarchy_fits_the_cap` (DB), `fallback_split_partitions_the_claims_and_every_part_fits` (unit) |
| a re-split triggers when agents or evidence push a leaf over | `agents_or_evidence_pushing_a_leaf_over_the_cap_trigger_a_resplit` (DB), `exactly_at_the_cap_fits_and_one_over_needs_a_split` (unit) |
| a node from outside the team's readable set never appears | `another_teams_private_rows_never_appear` (DB, team map, public map, multi-team scoped viewer) |
| (brief) a high-degree agent appears once | `a_high_degree_agent_appears_once` (DB) |
| (brief) identical across runs | `the_node_set_is_identical_across_runs` (DB) |

## Needs prod measurement (the orchestrator's)

- The distribution of evidence rows and of agents per claim (how often the
  per-claim cap bites).
- The share of evidence rows with a stored evidence-to-claim edge (how many
  derived `evidence_for` edges a leaf carries).
- The read's timing over a theme of about 2,000 claims.
