# Atlas W9: the incremental nightly refresh (plan)

Backlog item W9 1da9ed16 (epic 8fa0282d). Design:
`docs/superpowers/specs/2026-11-12-atlas-nested-groups-and-subgraph-view-design.md`
(§2 "Freshness", §5 "Invalidation", §7). Stacked on `atlas/wave5-base`
(W1 #802, W2 #803, W3 #805, W4 #810, W5 #812, W6 #808, W7 #809, W8 #811,
W10a #801, W11 #807). No migration. Does not depend on W10 (routes).

This item is the theme-v2 runbook's "rewire the nightly" step: it replaces
the paused theme-maintenance task with a systemd timer that runs one Rust
binary on the maintenance DSN.

## What one night does

```
atlas_nightly [--map M ...] [--apply] [--max-calls N] [--keep-runs K]
```

1. **Session lock.** A new key in `maintenance_lock.rs`. A second copy beside
   the timer prints `{"locked": true}` and exits 0.
2. **Themes.** Assign unthemed embedded claims to their nearest theme
   centroid with the existing `ClaimThemeRepository::assign_unthemed_batch`,
   in its own committed transactions, before any build snapshot. A dry run
   assigns nothing and reports the count. Themes over W1's member cap
   (default 2,000) are REPORTED, not split: the theme split stays W1's
   operator-run, off-box tool.
3. **Per map** (every map with a finished run, or the `--map` list):
   1. **Snapshot** (`begin_build_snapshot`, REPEATABLE READ, first statement):
      the latest finished run and its levels (W8's
      `AtlasNamingRepository::latest_finished_run` / `run_levels`; no new SQL
      for this), then per theme, each inside a SAVEPOINT so one theme's SQL
      error does not abort the others:
      - members (W4's `theme_members`: current, drawable, embedded; the
        unembedded count goes in the summary), W3's `read_leaf_rows`;
      - **meaning tree, incrementally**: the previous run's tree rebuilt from
        the stored rows (parents, children order, leaf claim nodes); claims
        that left are removed; each new claim joins the leaf whose centroid
        (mean of its members' L2-normalised embeddings, on the box, ids and
        embeddings only) is nearest by cosine, ties to the earlier leaf in
        pre-order; empty leaves are dropped and single-child levels
        collapsed; every id re-minted with W4's mint; a theme whose members
        fit one leaf is one root leaf. Then W4's `check_tree` and
        `resolve_tree` (a leaf over the 100-node cap is split on the box by
        W3's fallback split, counted in `resplit_leaves`);
      - **links tree, incrementally, against the RESOLVED meaning tree**:
        each previous leaf keeps its role (a mirror when the previous run's
        `params.mirrors` record lists it; for a run with no record, when at
        least half its surviving claims are unlinked now). An unlinked claim goes to the mirror of its
        meaning leaf, which holds exactly the unlinked claims of that leaf
        (W5b; an existing mirror leaf keyed to that meaning leaf is reused in
        place, a new one goes under the root). A new or newly linked claim
        joins the non-mirror leaf holding most of its counted neighbours,
        repeated until nothing moves; the rest are packed by connected
        component, first fit, into new leaves under the root. Then
        `check_tree`, `resolve_tree`, `check_mirrors`;
      - **switches both ways** with W5's Jaccard rule (`switch_targets`), so a
        deep meaning level points to its overlapping links group, not the
        links root (W5 finding #4; fixed in `apply_hierarchies` too);
      - **level documents** from W4's builder, every leaf then made REAL: W3's
        `assemble_leaf` nodes (claims, agents, evidence) with labels
        (claim text through W4's map-scoped read; agent display names and
        evidence text through a new map-scoped read, never empty, clipped to
        160 characters), W7's `build_leaf_flow_edges` weights;
      - the naming inputs: `plan_samples`, `read_member_texts` (the
        map-scoped text read), `read_previous`.
   2. The snapshot transaction ROLLS BACK (it wrote nothing).
   3. W6's `fill_positions`, warm-started from the previous run, then
      **naming** (`name_levels` under `--max-calls`), both with NO
      transaction open (W8's design).
   4. **Unchanged night:** if every level equals the previous run's
      (compared as parsed contract documents per (hierarchy, group id), the
      `run_id` field set to the previous run's, and the same level set) AND the snapshot epochs equal the
      previous run's, nothing is written (`"unchanged": true`). Documents
      equal but epochs moved: the run IS written, so the map is `current`
      again. (Epochs alone cannot gate the skip: a claim INSERT and a theme
      assignment bump no epoch, W2.)
   5. **Write transaction:** a per-map `pg_advisory_xact_lock` (also taken
      by W8's `name_and_write` now, so the two publishers serialise), the
      latest finished run must still be the one the night built from (else
      nothing is written and the map is reported `superseded`), `write_run`
      with the SNAPSHOT's epochs and params (`layout`, `naming`, counts),
      `put_level` each, `finish_run`, prune, commit. The builder bumps no
      epoch: the epochs belong to the W2 triggers.
4. **Exit:** 0 when every map built, was unchanged or was skipped; 1 when any
   map failed (the timer's `OnFailure=` alert fires). A failed THEME is not a
   failed map.

## Per-theme failure (W4's "one drifted theme refuses the whole apply")

A theme whose update fails (a SQL error inside its savepoint, a tree the
checks refuse, a leaf document the contract refuses, e.g. a leaf with more
than 1,024 edges) does not fail the night:
- **carried**: the previous run's documents of that theme, BOTH hierarchies
  (so switches resolve), `run_id` rewritten and re-validated, IF every node
  and edge of every carried leaf is still in that leaf re-assembled from the
  current rows (a subset check, a leak control: a claim, agent, evidence row
  or edge that left the map's audience is never carried; a skeleton leaf of
  an operator build carries on the first night);
- otherwise **dropped** from the run.
Both are listed per map in the summary with the error text.

A theme new to the map (not in the previous run) that fits one leaf gets two
root leaves; one that does not is `unbuilt` (reported; an operator build
with `atlas_meaning` / `atlas_links` makes it). A map with no finished run
is skipped and reported the same way. No UMAP runs on the box.

**The off-box split hook is deferred.** The item allows the split-only step
to call the off-box compute through a configurable command. This PR ships
"skip splits and report" only: themes over W1's cap, `unbuilt` themes and
`resplit_leaves` are in the summary, and the runbook names the operator
commands.

## Pruning

`AtlasMapRepository::prune_runs(conn, map, keep)`: delete the map's finished
runs older than its newest `keep` (default 3) and its UNfinished runs older
than its newest finished one; runs newer than the newest finished run are
kept (a build in flight). Levels go by `ON DELETE CASCADE`. Scoped by the
map's tenancy columns; never touches another map.

## Guard on a standalone meaning apply

`atlas_meaning apply --apply` refuses when the map's latest finished run
holds links levels (it would hide them). Use `atlas_links apply` with both
results, or let the nightly carry the map.

## Files

| File | What |
|---|---|
| `crates/epigraph-db/src/repos/atlas_map.rs` | `prune_runs`, `lock_map_for_publish`, `lock_map_for_build`/`unlock_map_for_build` (the operator applies' session lock), `maps_with_finished_runs`, `run_hierarchies` |
| `crates/epigraph-db/src/repos/atlas_leaf.rs` | `node_labels` (agents, evidence under the map predicate); the edge limit as a split reason (`ATLAS_LEAF_EDGE_CAP`, `SplitReason::EdgeCap`, an edge-aware `fallback_split`); `map_claim_links` (the map's drawable claim-to-claim edges) |
| `crates/epigraph-db/src/repos/atlas_meaning.rs` | `unthemed_embedded_count`, `themes_over_member_cap`, `unembedded_members_on_map`, `claim_truth_values` (viewer-spliced, no new exemption) |
| `crates/epigraph-cli/src/atlas_nightly/links.rs` | pure: group `bundles` and `targets`, leaf `outgoing`, under the contract caps |
| `crates/epigraph-db/src/repos/maintenance_lock.rs` | `ATLAS_NIGHTLY_LOCK_KEY` |
| `crates/epigraph-cli/src/atlas_nightly/previous.rs` | pure: the previous run's trees from its stored rows |
| `crates/epigraph-cli/src/atlas_nightly/incremental.rs` | pure: the meaning and links updates, collapse, re-mint |
| `crates/epigraph-cli/src/atlas_nightly/leaves.rs` | the real leaf documents (W3 + W7 + labels) |
| `crates/epigraph-cli/src/atlas_nightly/build.rs` | one map's night, the whole night, the summary |
| `crates/epigraph-cli/src/bin/atlas_nightly.rs` | the binary, `MAINTENANCE_DATABASE_URL` only |
| `crates/epigraph-cli/src/atlas_links/build.rs` | meaning levels switch by Jaccard; the build lock around `apply_hierarchies` |
| `crates/epigraph-cli/src/atlas_meaning/build.rs` | the links-hiding guard; the build lock around `apply_result` |
| `crates/epigraph-cli/src/atlas_naming/build.rs` | the publish lock in `name_and_write` |
| `deploy/systemd/epigraph-atlas-nightly.{service,timer}`, `epigraph-atlas-nightly-alert@.service` | the units (templates; not installed) |
| `docs/runbooks/atlas-nightly.md` | dry run, apply, rollback, enabling the timer |
| `crates/epigraph-cli/tests/atlas_nightly.rs` | DB tests (fresh DB, `remote-cargo --db`) |
| `crates/epigraph-cli/tests/atlas_nightly_units.rs` | the unit files: `systemd-analyze verify` when present, a syntax test always |

## "Done when" → proof

| Criterion | Test |
|---|---|
| a run over a synthetic multi-team corpus completes; every stored level validates; both hierarchies; switches resolve; leaves carry real nodes, weights, positions and names (fake backend) | `a_night_over_two_teams_stores_real_validated_levels_in_both_hierarchies` |
| two consecutive runs over unchanged input change nothing (variant: the second night writes NO run, makes 0 model calls, and its built documents equal the stored ones) | `a_second_night_over_unchanged_input_writes_nothing_and_calls_no_model` |
| a run with new claims touches only the affected groups | `a_new_claim_relays_and_renames_only_its_leaf_and_ancestors` |
| a drifted theme does not fail the night | `a_theme_that_fails_is_carried_and_the_night_completes`, `a_theme_that_fails_on_the_first_night_keeps_its_skeleton_levels`, `a_failed_theme_with_a_narrowed_claim_is_dropped_not_carried` (trigger: ONE claim whose own attachments carry 1,090 edges, which no split can fix) |
| a leaf over 1,024 edges is split, not frozen (review) | `a_leaf_over_the_edge_limit_is_split_not_frozen`; W3 unit tests `a_leaf_over_the_edge_limit_needs_a_split_on_edges`, `exactly_at_the_edge_limit_fits_and_one_over_splits`, `the_edge_split_counts_exactly_what_assembly_counts`, `one_claim_over_the_edge_limit_is_one_part_and_reports_its_edges` |
| pruning keeps exactly K finished runs | `pruning_keeps_exactly_k_finished_runs_of_that_map_only` (the repository call), `the_nightly_prunes_its_map_to_keep_runs` (the nightly with `keep_runs = 2`) |
| every run writer takes the publish lock (review) | `a_meaning_only_apply_waits_for_a_publish_and_then_sees_it`, `a_both_hierarchies_apply_waits_for_the_publish_lock` (`atlas_links.rs`), `a_night_that_finds_a_newer_run_at_publish_writes_nothing` |
| unembedded claims counted per map in every theme (review) | `unembedded_members_are_counted_in_every_theme_of_the_map` |
| the label read keeps the map predicate (review) | `node_labels_label_only_the_evidence_the_map_may_draw` (`epigraph-db/tests/atlas_leaf_repo.rs`) |
| the units pass `systemd-analyze verify` / a syntax test | `atlas_nightly_units::*` |
| (hand-off) standalone meaning apply cannot hide links | `a_meaning_only_apply_refuses_to_hide_a_links_run` |
| (hand-off) deep meaning switch to the overlapping links group | `meaning_levels_switch_to_their_best_links_group` (pure) + the night's switch assertions |

## Fail on old code (measured on the branch)

Each mutation applied alone on a lane, the affected target run on a fresh
database, then restored (`.mut/`-style script, not committed):

| Mutation | Tests that went red |
|---|---|
| a theme's error propagates (no carry/drop) | `a_theme_that_fails_is_carried_and_the_night_completes`, `a_failed_theme_with_a_narrowed_claim_is_dropped_not_carried` |
| carry without the re-assembly check | `a_failed_theme_with_a_narrowed_claim_is_dropped_not_carried` |
| carry requires equality, not a subset (the first version) | `a_theme_that_fails_on_the_first_night_keeps_its_skeleton_levels` |
| naming with no previous names | `a_second_night_over_unchanged_input_writes_nothing_and_calls_no_model`, `a_new_claim_relays_and_renames_only_its_leaf_and_ancestors` (after its call bound was added: the first probe left it green) |
| layout fill with no previous run | `a_second_night_...` |
| skip on epochs alone | `a_night_over_two_teams_...`, `a_second_night_...`, `a_new_claim_...`, `a_theme_that_fails_...` |
| never skip | `a_second_night_...`, `a_new_claim_...` |
| nightly meaning switch to the links root | `a_night_over_two_teams_...` |
| skeleton leaves (no W3/W7 fill) | `a_night_over_two_teams_...` and both drift tests |
| no theme assignment | `a_new_claim_...` |
| no new mirror leaves | `a_new_claim_...` |
| prune keeps one run too many | `pruning_keeps_exactly_k_finished_runs_of_that_map_only` |
| prune ranks runs across maps | `pruning_keeps_exactly_k_...` |
| guard a no-op | `a_meaning_only_apply_refuses_to_hide_a_links_run` |
| `apply_hierarchies` meaning switch to the links root | `meaning_levels_switch_to_their_best_links_group` |
| timer `OnCalendar` misspelt | both `atlas_nightly_units` tests |
| service `IOSchedulingClass=idlest` | `systemd_analyze_verifies_the_units` (the lane has systemd-analyze) |
| first leaf instead of the nearest centroid | `a_new_claim_joins_the_leaf_with_the_nearest_centroid_whatever_the_leaf_order` |
| no single-child collapse | `an_emptied_leaf_is_dropped_and_its_single_child_parent_collapses` |
| no neighbour vote | `a_new_unlinked_claim_lands_in_its_meaning_leafs_mirror_and_a_linked_one_by_its_neighbours` |

Added after the review (each applied alone, the target run on a fresh
database, restored):

| Mutation | Tests that went red |
|---|---|
| no `EdgeCap` in W3's assembly (the reviewed code) | `a_leaf_over_the_edge_limit_is_split_not_frozen` and the three W3 edge unit tests |
| `fallback_split` does not cut on edges | the W3 edge unit tests |
| the split ignores derived filer edges | `a_leaf_over_the_edge_limit_needs_a_split_on_edges`, `the_edge_split_counts_exactly_what_assembly_counts` |
| `>=` for `>` in the split, or in the assembly | `exactly_at_the_edge_limit_fits_and_one_over_splits` |
| (re-run on the single-claim trigger) a theme's error propagates | all three drift tests |
| (re-run) carry without the check | `a_failed_theme_with_a_narrowed_claim_is_dropped_not_carried` |
| (re-run) carry requires equality | `a_theme_that_fails_on_the_first_night_keeps_its_skeleton_levels` |
| `apply_result` takes no lock | `a_meaning_only_apply_waits_for_a_publish_and_then_sees_it` |
| `apply_result` takes the lock late, inside its snapshot | `a_meaning_only_apply_waits_for_a_publish_and_then_sees_it` |
| `apply_hierarchies` takes no lock | `a_both_hierarchies_apply_waits_for_the_publish_lock` |
| the nightly skips its newer-run check | `a_night_that_finds_a_newer_run_at_publish_writes_nothing` |
| the nightly does not prune | `the_nightly_prunes_its_map_to_keep_runs` |
| `node_labels` without the map predicate | `node_labels_label_only_the_evidence_the_map_may_draw` |
| the unembedded count summed over built themes (the reviewed code) | `unembedded_members_are_counted_in_every_theme_of_the_map` |

Known limit: ONE claim whose own agents and evidence carry more than 1,024
edges among them cannot be split; its theme is carried or dropped every
night until those edges shrink (an operator build does not clear it).

## Needs prod measurement

Run time per map against the timer window; how long the snapshot transaction
is held; flow reads per leaf; memory to hold a whole map's levels (the unit
sets `MemoryMax`); model calls on the first night (every level is unnamed);
whether the 197 theme-level layout needs a refresh after theme assignment
changes theme sizes.

## Operator rulings 2026-11-13

The operator ruled on what this item had left for later: the nightly builds
the cross-group links, and fills each leaf claim's `truth_value`.

### Cross-group links

Built once per map, in the build snapshot, after every theme is final (built
or carried) and before `fill_positions`, so W6's group layout pulls linked
children together from the sibling bundles (`atlas_nightly::links`).

- **Edge set.** `AtlasLeafRepository::map_claim_links`: claim-to-claim edges
  in force between two claims the run draws, under the same map edge rule as
  W3 and W5 (public, or owned by the team with no co-owner). The read also
  requires both ends to be claims the map may draw (public, or the team's
  own), whatever ids the caller passes. W5's
  `is_counted` decides which relationships are links (the epistemic edges
  plus `decomposes_to`). Rows repeating (source, target, lower-cased
  relationship) are one link. A co-owned edge is never read.
- **Where a link shows**, per hierarchy:
  - same theme: a sibling bundle at the lowest common ancestor, in the stored
    direction; every level below it on the SOURCE side lists the link towards
    the shallowest group outside that level that holds the target (the child
    of the common ancestor on the target's side);
  - another theme: every level on the source's path lists it towards the
    target theme's root in the same hierarchy (depth 0). W11's stub path
    resolves a depth-0 target (it attaches the theme root and selects it).
  - A link is listed from its source end only, as the contract defines a
    bundle ("all links from one child") and an `outgoing` entry ("all links
    leaving the leaf"). The levels on the target's side list nothing for it,
    so a stub reads "this claim links to that group", never the reverse. A
    leaf whose claims are only linked to shows no stub for those links.
- **Count and sign.** `count` is the number of links; `net_sign` the sign of
  the sum of W7's link signs (+1 supporting, -1 opposing, 0 other).
- **Caps.** A group keeps its 160 heaviest outside targets (bundles to a cut
  target go with it), then its 2,048 heaviest bundles (a target left with no
  bundle goes too, and counts as a cut target); a leaf its 64 heaviest
  `outgoing` targets. Ties go to the smaller id. The cuts are counted (no
  ids) under `links` in the night report and the run's `params`; they never
  fail the night. Children stay capped at 128 by the tree.
- **Incremental. A deviation from the ruling's wording, for the operator to
  confirm.** The ruling said to rebuild links only for levels whose members
  or edges changed. This builds a deterministic recompute of every level
  from the snapshot's edges instead. What the ruling protects holds:
  unchanged input gives the same bytes (the second night still writes
  nothing), and a changed link changes only the levels that list it. The
  cost is one map-wide read of the edges among the run's claims each night,
  not yet measured on the largest map. Rebuilding only
  levels whose own members changed would leave a target pointing at a group
  whose member-derived id has moved, and a carried theme's counts must follow
  the map's edge rule as it stands that night.

### Leaf claim `truth_value`

`AtlasMeaningRepository::claim_truth_values` reads it under the map's claim
predicate; `fill_leaf` sets it as the colour value only, after and apart from
W7's weights. A claim the read does not return carries null, never a default.
`claims.truth_value` is NOT NULL, so on a real map every drawn claim has one.
A carried theme keeps the values its stored leaves hold.

### Proofs (fresh database, each mutation applied alone and restored)

| Criterion | Test |
|---|---|
| two themes with links across groups, leaves and themes give the expected bundles, targets and outgoing in both hierarchies, named as their levels | `links_across_groups_leaves_and_themes_fill_bundles_targets_and_outgoing`; unit `links_are_aggregated_at_every_level_towards_the_shallowest_outside_group` |
| a co-owned or other team's edge never contributes; a public one does | `a_co_owned_or_other_teams_edge_never_makes_a_link_but_a_public_one_does`; `map_claim_links_return_only_claim_edges_the_map_may_draw` (epigraph-db) |
| over-cap truncation keeps the heaviest and reports the rest | `a_leaf_over_the_outgoing_cap_keeps_its_heaviest_targets_and_the_night_reports_the_rest`; unit tests for all three caps |
| positions pull linked children together | `the_group_layout_pulls_linked_children_together` (two families of six; linked pairs closer than unlinked ones, and closer than W6 places the same children with no bundles) |
| a second night over unchanged input is byte-identical with 0 model calls; a new link changes only the levels that list it (its bundle's group and its source leaf) | `links_stay_byte_identical_until_a_link_changes_and_then_only_where_it_passes`; unit `the_result_does_not_depend_on_link_order_and_replaces_what_was_there` |
| leaf claim `truth_value` matches the row, null without one | `leaf_claims_carry_their_stored_truth_value`; unit `a_claims_truth_value_is_its_stored_one_and_none_without_one`; `claim_truth_values_read_only_the_claims_the_map_may_draw` (epigraph-db) |

| Mutation | Tests that went red |
|---|---|
| the nightly skips the cross-link fill | `links_across_...`, `a_co_owned_or_other_teams_...`, `links_stay_byte_identical_...`, `the_group_layout_pulls_linked_children_together`, `a_leaf_over_the_outgoing_cap_...` |
| the link read admits a co-owned edge | `map_claim_links_return_only_claim_edges_the_map_may_draw`, `a_co_owned_or_other_teams_...`, `links_across_...` |
| the link read admits another team's edge | the same three |
| a link points at the far leaf, not the shallowest outside group | unit `links_are_aggregated_...`, `links_across_...` |
| an opposing net sign reads as 0 | unit `links_are_aggregated_...`, `links_across_...` |
| a same-theme link is also listed above the common ancestor | unit `links_are_aggregated_...`, `links_across_...`, `links_stay_byte_identical_...` |
| the caps keep the lightest | the three unit cap tests, `a_leaf_over_the_outgoing_cap_...` |
| no outgoing cap | the unit leaf and target cap tests, `a_leaf_over_the_outgoing_cap_...` (the contract refuses the leaf) |
| `outgoing` sources in hash order (not deterministic) | unit `links_are_aggregated_...`, `links_stay_byte_identical_...` |
| leaf `truth_value` left null | unit `a_claims_truth_value_...`, `leaf_claims_carry_their_stored_truth_value` |
| leaf `truth_value` defaults to 0.5 with no stored value | unit `a_claims_truth_value_...` |
| the truth read without the map predicate | `claim_truth_values_read_only_the_claims_the_map_may_draw` |
| a link also listed from its target end (review fix) | unit `links_are_aggregated_...`, `links_across_...`, `a_co_owned_or_other_teams_...`, `links_stay_byte_identical_...` |
| the link read without the endpoint claim rule (review fix) | `map_claim_links_return_only_claim_edges_the_map_may_draw` |
| a target the bundle cap empties not counted as cut (review fix) | unit `a_target_the_bundle_cap_leaves_with_no_bundle_is_reported_as_cut` |

### Needs prod measurement (added)

The size and time of the map-wide claim-to-claim edge read on the largest
map, and how many levels hit a cap (the `links` counts of the first night).

