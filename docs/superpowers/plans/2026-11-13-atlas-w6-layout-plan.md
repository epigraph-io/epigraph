# Atlas W6: precomputed leaf and group layouts (plan)

Backlog item W6 f52fff97 (epic 8fa0282d). Design:
`docs/superpowers/specs/2026-11-12-atlas-nested-groups-and-subgraph-view-design.md`
(§2 "Deepest level" and "Private data off the host", §6 "No client-side force
simulation", §7 step 4). Contract: W10a, schema v1
(`crates/epigraph-atlas-contract`): a leaf node's `x`, `y` and a group child's
`x`, `y`, `r`, in a unit frame (`x`, `y` in [-1, 1], `r` in (0, 1]).

Stacked on `atlas/wave2-base` (W1 #802, W2 #803, W3 #805, W10a #801). W6 adds
no migration and does not change W2's or W3's code.

## What this item delivers

The browser draws the Atlas below a theme from stored positions and never
simulates. W6 computes those positions in the nightly build:

1. **Leaf layout.** Input: a leaf's node ids, node kinds and the edges among
   them (a W3 `LeafNodeSet`, or the nodes and edges of a W10a leaf
   document). Output: `x`, `y` per node. A force-directed layout
   (Fruchterman-Reingold with a gravity term), then collision sweeps, inside
   a disc of radius 0.95, so a leaf drawn inside its parent's child circle
   stays in it.
2. **Group-level layout.** Input: a group's children as (child id, weighted
   size) and the aggregated child-to-child link counts. Output: `x`, `y`, `r`
   per child. Circle sizes have area proportional to size (`r` monotone in
   size). A force layout pulls linked children together and resolves
   collisions, then one uniform scale fits every circle inside the unit disc.
3. **Fill entry point.** Given a run's level documents (W10a
   `LevelDocument`s, the payloads W2 stores) and the previous run's layout
   record and documents, fill every position. A level whose layout inputs
   hash to the value the previous run recorded keeps the previous positions
   (copied by node or child id) and is not laid out again. Every filled
   document must pass `LevelDocument::validate` and `to_stored_json`.

The hierarchies (W4 by meaning, W5 by links) are built in parallel and do not
exist on this branch. W6 depends on neither: the fill reads only the W10a
document, which carries everything a layout needs (leaf nodes and edges, group
children with `claim_count`, and sibling bundles). Whoever assembles the
documents (W9 / W10) calls the fill before `write_run`.

## Determinism and stability

- **Seeded.** Each node's (or child's) starting point is derived from
  SHA-256(seed id ‖ node id) alone: the leaf's or group's stable id, then the
  node's id. Adding a node does not move the others' starting points.
- **Order-free.** Inputs are normalised before anything else: nodes sorted by
  id, edges folded to undirected `(min, max)` pairs, deduplicated, self-loops
  dropped. Group links are folded the same way, with their counts summed.
  Only `BTreeMap`/sorted `Vec`s; no `HashMap` iteration order can leak in.
- **Fixed work.** A fixed iteration count; the collision sweeps stop at the
  first sweep that moves nothing, which is itself deterministic.
- **Portable arithmetic.** Only `+ - * /` and `sqrt`, which IEEE 754 rounds
  correctly on every host, so an off-box lane and the prod box give the same
  bytes. No trigonometry, `exp` or `powf`.
- **Rounded.** Positions are rounded to 1e-4, as `math.rs` does, and every
  quality bound is checked on the rounded output.

## The content hash and where it is stored

`leaf_input_hash` / `group_input_hash`: lower-hex SHA-256 over a canonical
byte encoding of the algorithm tag and version, every layout constant, the
seed id and the normalised input. Labels and every other text never enter it
(the pure functions take no text at all), and neither does edge direction or
relationship name, which the layout does not use. So a W3 `LeafNodeSet`
(stored edge direction) and the matching W10a leaf (belief-flow direction,
W7/W10 re-orient) hash the same.

**Stored in the run's `params`**, under `params.layout`:

```json
{"layout": {"algo": "atlas-w6-v1",
            "hashes": {"meaning/<group id>": "<64 hex>", "links/<group id>": "..."}}}
```

Why `params` and not a column on `atlas_map_levels`:
- `params` is the builder's slot on W2's run row; W2's module treats the level
  payload as opaque, and the W10a document is closed (`deny_unknown_fields`),
  so the hash cannot ride in the payload.
- A column needs a migration and a `LevelDoc` field. W4 and W7 build on the
  same base in parallel and would collide on the struct literal and the
  migration slot.
- Upgrade path: if the record grows too large on the biggest team map, move
  the hashes to a nullable `layout_hash` column on `atlas_map_levels`. Size is
  about 110 bytes per level per hierarchy, to be measured on prod (leaves per
  map).

Consequence for the build order: `write_run` takes `params` when the run is
opened, so the build lays out every level in memory first:
snapshot, read, assemble documents, `fill_positions`, `write_run(params)`,
`put_level` each, `finish_run`.

## Off-box rule

`force.rs` takes `Uuid`s, a three-valued node kind, weights and counts. No
`String` enters it. The fill adapter extracts those from the documents on the
box; the positions it gets back carry no text either, so the pure step can
run on a remote lane on ids and edges only.

## Files

| File | What |
|------|------|
| `crates/epigraph-cli/src/atlas_layout/force.rs` | pure: input normalisation, `layout_leaf`, `layout_group`, the two input hashes, unit tests of quality, determinism and timing |
| `crates/epigraph-cli/src/atlas_layout/fill.rs` | pure over W10a types: inputs from documents, `LayoutRecord` (to / from `params`), `fill_positions` with skip-by-hash, `FillReport`; the `LeafNodeSet` adapter behind the `db` feature |
| `crates/epigraph-cli/src/atlas_layout/mod.rs` | module registration |
| `crates/epigraph-cli/Cargo.toml`, `Cargo.lock` | depend on `epigraph-atlas-contract` (no features) |
| `crates/epigraph-cli/tests/atlas_w6_layout_store.rs` | DB test (`remote-cargo --db`): a synthetic hierarchy filled, stored through W2, read back, validated; a rerun skips through the stored hash |

## Tests and how each "Done when" is proven

| Criterion | Test |
|-----------|------|
| Every leaf in a synthetic hierarchy has stored positions | `atlas_w6_layout_store::every_level_of_a_synthetic_hierarchy_is_stored_with_valid_positions`: documents built with placeholder (0, 0) positions are filled, written with `write_run`/`put_level`/`finish_run`, read back with `level_for_viewer`, parsed with `parse_and_validate`, and checked for the minimum distance and the disc bound. Leaving one leaf unfilled fails it. |
| A rerun over unchanged leaves gives identical positions and skips them through the content hash | `fill::tests::an_unchanged_level_reuses_the_previous_positions_and_is_not_laid_out` (sentinel positions under the right hash come back unchanged, `computed == 0`), `fill::tests::one_changed_leaf_is_the_only_one_laid_out_again` (`computed == 1`), and the DB test's second run over the stored record. Breaking the hash comparison fails each. |
| The per-leaf time bound holds, so the nightly fits its window | `force::tests::a_full_leaf_lays_out_within_the_time_bound`: 100 nodes, dense edges, best of several runs under 50 ms on one core in the test (debug) build. The measured time times the leaf count per night (a prod measurement) gives the nightly's share. |

Quality bounds (all on the rounded output):
- `leaf_nodes_keep_the_minimum_distance` and `leaf_positions_stay_inside_the_disc` (also over a sweep of random graphs);
- `connected_nodes_sit_closer_than_unconnected_ones`;
- `group_radii_are_monotone_in_size`, `group_circles_do_not_overlap_and_stay_inside_the_unit_disc`, `linked_children_sit_closer_than_unlinked_ones`;
- determinism: `the_same_input_gives_byte_identical_positions`, `input_order_does_not_change_the_output`, `a_new_node_does_not_change_the_others_starting_points`, `the_hash_ignores_labels_and_edge_direction`, `the_hash_changes_with_any_layout_input`;
- contract: every filled document passes `validate` and `to_stored_json`.

Each test is shown to fail on broken code: the mutation probes (no collision
sweep, no gravity, no scale-to-fit, r from size inverted, hash comparison
disabled, a leaf left unfilled) are run, seen red, and reverted.

## Build gate (tier 1)

- `cargo test -p epigraph-cli --lib atlas_layout` (new unit tests)
- `cargo test -p epigraph-cli --test atlas_w6_layout_store` under `--db`
- `cargo fmt --check`, `cargo +stable clippy -p epigraph-cli --all-targets --locked -- -D warnings`
- `cargo test -p epigraph-db --test no_unscoped_pool`, `cargo check -p epigraph-api --no-default-features --locked`

No edge writer is added or renamed, so the signing ratchet is not in scope.

## Left for later items

- W9 reads the previous finished run's `params.layout` and its level
  documents, and calls `fill_positions` before `write_run`.
- The off-box shipping itself (serialising inputs to a lane and positions
  back) is W9's orchestration; W6 makes the pure step text-free.
