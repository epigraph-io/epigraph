# Atlas W5 (+W5b): the "by links" hierarchy (plan)

Backlog items W5 4e02c23f and W5b febb2a77 (epic 8fa0282d), one PR. Design:
`docs/superpowers/specs/2026-11-12-atlas-nested-groups-and-subgraph-view-design.md`
(§2 "Nested groups", "Private data off the host"; §2a "Co-owned edges"; §3 goal 2;
§7 "By links edges").

Stacked on W4 (#810, the "by meaning" hierarchy), and through it on W1 #802,
W2 #803, W3 #805 and W10a #801. No migration.

## What this item delivers

Per map (a team map or the public map), under each theme, the claims the map
draws are grouped by the communities of the claim graph until every leaf fits
W3's 100-node cap, weighted exactly as W4 weighs them (claims + distinct
agents and evidence, a shared one counted once). A claim with no counted link
to another member of its theme goes into a links group that mirrors its "by
meaning" leaf (W5b). Both hierarchies are written into ONE run.

## Decisions (standing authorization: the recommended default, stated)

- **Louvain via networkx, not Leiden.** `leidenalg` (GPL-3) and `igraph`
  (GPL-2+) would be imported by a script in an Apache-2.0 repository;
  networkx is BSD-3, pure Python, and has a seeded `louvain_communities`.
  networkx 3.6.1 (pinned in `tests/requirements-ci.txt`; its
  `leiden_communities` is a dispatch stub with no networkx backend).
- **Members** are W4's: current, drawable on the map, embedded. Unembedded
  members are outside both trees (counted, as W4 counts them), so the two
  hierarchies cover the same claims and the switch always has a target.
- **Counted edges** are read from W3's `read_leaf_rows` (no new SQL): claim to
  claim, both ends members of the theme, `lower(relationship)` in
  {supports, refutes, contradicts, cites, elaborates, corroborates,
  decomposes_to}, not a self-loop. W3's read already carries the map edge
  rule: public, or owned by the team with NO co-owner. So no
  co-owned or other-team edge can reach the graph, and the rule lives in one
  place (W3's module doc asks every later edge read to use it).
- **One run for both hierarchies.** The serving read takes a map's latest
  finished run whatever it holds, and the contract requires a switch at every
  level. A links-only run would hide the meaning levels and leave every switch
  dangling. So `atlas_links apply` takes the meaning result AND the links
  result and, in one snapshot and transaction, resolves the meaning result
  with W4's code, checks the links result against it, and writes both
  (`write_meaning_levels` then `write_links_levels`) into one run. This is the
  brief's "membership from the same run": the DB tests read it back with
  `leaf_membership`. Copying an older run's meaning levels forward was
  rejected for W4's reason (trees checked against an older snapshot).
- **Switch.** The links root's switch is the meaning root (`tree::root_id`),
  and W4's meaning root already points at `root_id(map, links, theme)`. The
  contract requires a switch at every level, so a deeper links level points
  at the meaning group with the largest Jaccard overlap of claims, ties to the
  deeper group, then the smaller id. Plain "largest overlap" always picks the
  meaning root (it holds every claim). Meaning levels keep W4's switch (the
  links root).
- **Off-box export.** Claim ids, per-theme attachment integers (W4's),
  counted links as index pairs, each claim's meaning leaf as an integer
  (numbered per theme in meaning pre-order), and embeddings for LINKED claims
  only. The backlog says "ids and edge structure only"; embeddings are allowed
  off the box by design §2 and are needed only for the dense-community
  fallback, which only ever splits linked claims. Owner-only exactly as W4
  (`prepare_export_dir`, files created 0600).

## Algorithm (`scripts/atlas_links_core.py`, pure)

Input per theme: sorted ids, attachments, link pairs, meaning-leaf index per
claim, embeddings of the linked claims.

1. **Linked / unlinked.** L = claims with a counted link to another member;
   U = the rest.
2. **Root.** If the theme's weight fits the cap, the root is one leaf (the
   meaning root is then one leaf too).
3. **Units (bottom-up).** Decompose L into atomic units that each fit, and
   never cut a unit again: a set that fits is a unit; a disconnected set over
   the cap is cut into its connected components (a component that fits stays
   whole); a connected one into its Louvain communities (seeded, nodes and
   edges inserted in id order); when Louvain returns a single community (a
   dense one that will not split), W4's embedding split
   (`atlas_meaning_core._split`) cuts it instead. Each part is cut again the
   same way.
4. **Packing (top-down).** A set of units whose union fits is a leaf.
   Otherwise the units are packed into bins of target weight
   `T = max(cap, ceil(w / k))`, `k = clamp(ceil(w / cap), 2, 16)`: first the
   linked units are merged, most links first (ties: smaller unit index),
   while the merged bin stays within T, so the parts Louvain cut out of one
   component sit together; then the merged groups are packed first-fit
   decreasing (weight, then smallest id). More than 16 bins: T doubles (while
   below w) and the packing repeats. Every bin is a child: one unit is a leaf,
   a union that fits is a leaf, anything else recurses. Since T < w there are
   always at least two bins, so no level has a single child and recursion
   terminates.
5. **Mirrors (W5b).** For each meaning leaf with unlinked claims, ONE links
   leaf holding exactly those claims (U ∩ meaning leaf). It fits because it
   is a subset of a meaning leaf that fits. Mirror leaves sit directly under
   the root beside L's top-level bins: an intermediate group of mirrors that
   fits would have to be a leaf (merging two meaning leaves' claims), so none
   is made. More than 128 root children is refused.
6. **Ids.** W4's mint with `hierarchy = links`: the root from
   `(map, links, theme)`, every other group from its sorted member claims.

## Box side (`crates/epigraph-cli/src/atlas_links/`)

| File | What |
|---|---|
| `graph.rs` | pure: `counted_links(rows, members)`, the linked set, the mirror check on a resolved tree, the switch targets (Jaccard over the meaning tree) |
| `files.rs` | the links export and result formats; `LinksComputeVersions` (numpy, scikit-learn, umap-learn, networkx, python) |
| `build.rs` | `export_links`, `resolve_links_result`, `write_links_levels` (into a caller-opened run), `apply_hierarchies` (both into one run) |
| `mod.rs` | module docs |
| `src/bin/atlas_links.rs` | operator binary: `export --map M --meaning-from R... --out DIR`, `apply --map M --meaning-from R... --from L... [--apply]`, on `MAINTENANCE_DATABASE_URL` only |

W4 refactors (one commit each, behaviour unchanged): `level_documents` takes
a switch per level (`level_documents_with_switch`); the per-theme resolve is
extracted from `resolve_result` (`resolve_theme`) so a batched links export
can resolve only its themes; `write_owner_only` is exposed.

**Apply checks, in order:** map/hierarchy/cap/versions; the links themes are
exactly the meaning result's themes (which W4 already checks are exactly the
map's); per theme: the live linked set from `LeafRows`; `check_tree(Links)`
(ids minted, every member in exactly one leaf); `resolve_tree` (W3 re-count,
fallback split of a linked leaf over the cap); then the mirror check on the
RESOLVED tree: every leaf holding an unlinked claim u is exactly U ∩ (u's
meaning leaf), except a root that is still a single leaf. A root leaf W3 had
to split, or a drifted link, fails it: export and compute again.

## Tests

**Python** (`tests/theme/test_atlas_links_core.py`, local `python3` 3.12 with
CI's pins: numpy 1.26.4, scikit-learn 1.8.0, umap-learn 0.5.11, networkx 3.6.1):
- `test_every_leaf_weight_is_within_the_cap` (shared agents, evidence);
- `test_a_densely_linked_cluster_stays_in_one_leaf`;
- `test_a_fitting_component_is_never_split_across_leaves`;
- `test_parts_of_one_component_are_packed_together`;
- `test_a_clique_over_the_cap_is_split_by_embedding`;
- `test_an_unlinked_claim_lands_in_its_meaning_leafs_mirror`;
- `test_no_level_has_a_single_child`;
- `test_rerun_reproduces_every_group_id` (shuffled input too);
- `test_many_small_components_keep_the_root_fanout_bounded`;
- `test_a_theme_under_the_cap_is_one_root_leaf`;
- `test_validate_refuses_a_malformed_tree[...]`;
- `test_ids_match_the_golden_vector` (links root, pinned in Rust too);
- `test_committed_fixture_reproduces_the_committed_result`,
  `test_compute_runs_without_db_driver`.

**Rust, pure:** counted-link filter (spellings, kinds, self-loops,
non-members); mirror check refusals; switch selection; the writer reproduces
the committed export bytes; the committed result passes the Rust checks.

**Rust, DB** (`crates/epigraph-cli/tests/atlas_links.rs`, fresh DB):
- `every_leaf_fits_and_unlinked_claims_mirror_their_meaning_leaf`: linked
  clusters arrive as one coarse leaf that W3 resplits; every stored links leaf
  re-counted by W3 fits; every unlinked claim's links leaf equals its
  `leaf_membership` leaf's unlinked claims;
- `no_co_owned_or_other_team_edge_counts_as_a_link`: two team clusters
  bridged only by a co-owned edge and another team's edge; the export's pairs
  never cross, a claim whose only edge is co-owned is exported unlinked, and
  apply refuses a result that groups it with a cluster;
- `the_root_switch_round_trips_between_the_hierarchies` (`level_for_viewer`);
- `stored_documents_of_both_hierarchies_validate`;
- `a_second_apply_reproduces_every_links_group_id`;
- `apply_refuses_a_forged_or_drifted_links_result`;
- `the_binary_refuses_a_bad_map_or_cap_before_connecting` (no DB).

**Fail on old code** (measured on the branch: each mutation applied alone,
the affected targets run, then restored and `touch`ed):

| Mutation | Tests that went red |
|---|---|
| Python: no connected-component cut (Louvain straight away) | `test_a_fitting_component_is_never_split_across_leaves` |
| Python: no embedding fallback (cut a dense community in half by position) | `test_a_clique_over_the_cap_is_split_by_embedding`, the two fixture tests |
| Python: unlinked claims in one bucket | `test_a_theme_with_no_links_mirrors_every_meaning_leaf`, and every test on the realistic theme (it is refused) |
| Python: input not sorted by id | `test_rerun_reproduces_every_group_id` |
| Python: weight summed per claim | `test_every_leaf_weight_is_within_the_cap` and the realistic-theme tests |
| Python: a set of units that fits is not a leaf | `test_many_small_components_keep_the_root_fanout_bounded` and others |
| Python: T never grows (fanout unbounded) | `test_many_small_components_keep_the_root_fanout_bounded`, the fixture tests |
| Python: no affinity merge (first-fit only) | `test_parts_of_one_component_are_packed_together` |
| Python: validate skips the mirror rule | `test_validate_tree_refuses_a_malformed_tree[mirror_split, mirror_with_linked_claim, unlinked_in_linked_leaf]` |
| W3 edge read without `co_owner_group_id IS NULL` | `no_co_owned_or_other_team_edge_counts_as_a_link` and four more DB tests |
| W3 edge read without the owner check | `no_co_owned_or_other_team_edge_counts_as_a_link` |
| `counted_links` without the relationship filter | `only_counted_claim_links_between_members_count` |
| `is_counted` without lower-casing | `only_counted_claim_links_between_members_count` |
| `check_mirrors` a no-op | `mirrors_hold_exactly_their_meaning_leafs_unlinked_claims`, `a_single_root_leaf_needs_no_mirror`, `apply_refuses_a_forged_or_drifted_links_result`, `no_co_owned_or_other_team_edge_counts_as_a_link`, `every_leaf_fits_and_unlinked_claims_mirror_their_meaning_leaf` |
| switch: every level to the meaning root | `switch_targets_pick_the_best_jaccard_meaning_group` |
| switch: no depth tie-break | `a_switch_tie_goes_to_the_deeper_group_then_the_smaller_id` (the first probe survived on uuid luck; the comparator test was added for it) |
| links documents switch to the root's target only | `the_root_switch_round_trips_between_the_hierarchies` |
| apply does not write the meaning levels into the run | `the_root_switch_round_trips_between_the_hierarchies`, `stored_documents_of_both_hierarchies_validate`, `every_leaf_fits_and_unlinked_claims_mirror_their_meaning_leaf` |
| links resolve skips W3's re-check | `every_leaf_fits_and_unlinked_claims_mirror_their_meaning_leaf`, `a_second_apply_reproduces_every_links_group_id` |
| export writes every claim's embedding | `the_writer_reproduces_the_committed_export_bytes`, `no_co_owned_or_other_team_edge_counts_as_a_link` |
| export numbers every meaning leaf 0 | `no_co_owned_or_other_team_edge_counts_as_a_link` |
| apply without the theme-set check | `apply_refuses_a_forged_or_drifted_links_result` |

**Not tested end to end:** a database export computed by the Python core
and applied back (as for W4: the build hosts have no numpy; the halves meet
through the committed fixture, whose export bytes the Rust writer reproduces
and whose result passes the Rust tree and mirror checks).

## "Done when" → proof

| Criterion | Proof |
|---|---|
| W5: a test team map has every leaf ≤ 100 nodes | `every_leaf_fits_and_unlinked_claims_mirror_their_meaning_leaf` (DB); `test_every_leaf_weight_is_within_the_cap` |
| W5: unlinked claims land in their meaning group | same DB test (via `leaf_membership`); `test_an_unlinked_claim_lands_in_its_meaning_leafs_mirror` |
| W5: a rerun reproduces ids | `a_second_apply_reproduces_every_links_group_id`; `test_rerun_reproduces_every_group_id` |
| W5b: unlinked claims in their meaning group inside the links hierarchy, every leaf ≤ 100 | the first DB test (both clauses at once) |
| (brief) no co-owned or other-team edge influences the grouping | `no_co_owned_or_other_team_edge_counts_as_a_link` |
| (brief) the switch round-trips at the root | `the_root_switch_round_trips_between_the_hierarchies` |
| (brief) stored documents validate | `stored_documents_of_both_hierarchies_validate` |
| (brief) dense clusters stay together; no single-child level | `test_a_densely_linked_cluster_stays_in_one_leaf`, `test_no_level_has_a_single_child` |

## Needs prod measurement (the orchestrator's)

- Per theme and map: linked vs unlinked members, and meaning leaves per theme
  (root fanout = top-level link bins + mirror leaves; refused over 128).
- Counted-edge counts per theme, and how many are `decomposes_to`.
- Louvain reproducibility across compute hosts (the result records the
  networkx version; ids persist only while it reproduces).
