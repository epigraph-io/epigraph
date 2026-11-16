# Atlas W4: the "by meaning" hierarchy (plan)

Backlog item W4 f9fc052c (epic 8fa0282d). Design:
`docs/superpowers/specs/2026-11-12-atlas-nested-groups-and-subgraph-view-design.md`
(§2 "Nested groups", "Private data off the host"; §3 goal 2; §7 steps 2 and 3).

Stacked on W1 (#802, `theme_cap_core.py`), W2 (#803, migration 210,
`AtlasMapRepository`), W3 (#805, `AtlasLeafRepository`) and W10a (#801, the
`epigraph-atlas-contract` crate). No migration.

## What this item delivers

Per map (a team map or the public map), under each theme, the claims the map
draws are clustered recursively by embedding similarity until every leaf fits
W3's 100-node cap (claims + agents + evidence, a shared agent or evidence row
counted once). The result is stored as `hierarchy = 'meaning'` level documents
in a W2 run.

## Shape: export on the box, compute anywhere, apply on the box

W1's shape, with the box halves in Rust because W3's read, `assemble_leaf` and
the contract types are Rust.

| Step | Where | What crosses |
|---|---|---|
| `atlas_meaning export --map M --out DIR` | box (Rust bin) | writes claim ids, embeddings and each claim's attachment nodes as per-theme integer indices |
| `atlas_meaning_core.py compute --from DIR --out result.json` | anywhere (Python, no DB driver) | reads the export, writes the tree: group ids, parents, depth, leaf member claim ids, child ids |
| `atlas_meaning apply --map M --from result.json [--apply]` | box (Rust bin) | re-reads everything in one snapshot, verifies, writes one run |

**A run is the whole map.** The serving read takes the latest finished run of
a map, so `apply` refuses a result whose themes are not exactly the themes the
map draws with an embedded member in the apply snapshot
(`embedded_theme_ids_on_map`, the same set `export` writes). To keep exports
small, export in `--theme-id` batches into separate directories, compute each,
and apply every batch's result at once with repeated `--from`
(`files::merge_results` refuses batches that differ in map, hierarchy, cap,
seed or library versions, or repeat a theme). Carrying unchanged themes
forward from the previous run was rejected: it would serve trees checked
against an older snapshot.

**The export is owner-only.** Embeddings approximate claim text. `--out` is
created 0700 when it does not exist; an existing directory must be empty with
no group or other bits (it is refused, never chmod-ed); every file is created
new with mode 0600, so no umask exposes it (W1 fixed the same class).

**The result is checked, all of it.** Every id is re-minted, and the
`versions` the compute records are typed (four keys, short version strings or
null) before they go into the run's `params`.

**Undo.** There is no `reverse` subcommand yet (deferred). A standalone
`apply --apply` writes ONE new `atlas_map_runs` row and its levels, and as the
map's latest finished run it is what is served. To undo it, delete that run
row by the `run_id` the apply report prints, as the maintenance login; its
levels go with it (`ON DELETE CASCADE`), and the previous finished run is
served again. Nothing else is written.

**The off-box rule.** The export holds claim ids, embeddings, and for each
claim the list of its attachment nodes (its agents and evidence, after W3's
per-claim cap) as small integers numbered per theme. No agent or evidence id,
no text, no tenancy column leaves the box. The integers let the core count a
shared agent once per group without knowing who it is.

## Files

| File | What |
|---|---|
| `crates/epigraph-db/src/repos/atlas_leaf.rs` | adds `claim_attachments(rows, cap)`: each drawable claim's capped agents and evidence, from the same `claim_nodes` that `assemble_leaf` counts with, so the export and the check cannot count differently |
| `crates/epigraph-db/src/repos/atlas_meaning.rs` | the scoped reads: `theme_ids_on_map`, `theme_members` (current, embedded, drawable, plus the unembedded count), `claim_labels`, and `leaf_membership` (claim to leaf group of one stored run) |
| `crates/epigraph-cli/src/atlas_meaning/tree.rs` | pure: the id mint, the result tree, its validation against the live members, and the W3 re-check that turns a leaf over the cap into a group (`resolve_tree`) |
| `crates/epigraph-cli/src/atlas_meaning/docs.rs` | pure: the level documents, built from `epigraph_atlas_contract` types and stored through `to_stored_json` |
| `crates/epigraph-cli/src/atlas_meaning/files.rs` | the export and result file formats |
| `crates/epigraph-cli/src/atlas_meaning/build.rs` | the DB halves: `export_map` and `apply_result` (and `write_meaning_levels`, which writes into a run the caller opened) |
| `crates/epigraph-cli/src/bin/atlas_meaning.rs` | the operator binary (`export`, `apply`), on `MAINTENANCE_DATABASE_URL` only |
| `scripts/atlas_meaning_core.py` | pure: `build_tree(...)` and `compute`; reuses W1's UMAP reduction and k-means (`theme_cap_core`) |
| `tests/theme/test_atlas_meaning_core.py` | Python tests (synthetic embeddings, no DB) |
| `crates/epigraph-cli/tests/atlas_meaning.rs` | DB tests (fresh DB, `remote-cargo --db`) |
| `crates/epigraph-cli/tests/fixtures/atlas_meaning/` | a small committed export and the result Python computes from it, read by both suites |

## Data model

**Tree.** Each theme's tree has one root at depth 0 (the theme root of the
W10a contract, `parent_group_id` NULL, `level` 0). A group whose weight fits
the cap is a leaf; otherwise it splits into at least two children. A group that
already fits becomes a leaf directly, so there is never a level with one child.
A theme that fits in one leaf has a root that is itself a leaf.

**Weight** = claims + distinct attachment nodes over the group's claims. Each
claim's attachments are W3's per-claim capped list, so every single claim fits
and every split terminates. The core refuses an export where one claim alone is
over the cap.

**Split** (core): L2-normalise, UMAP (W1's settings; skipped at 100 distinct
points or fewer), k-means with `k = clamp(ceil(weight / cap), 2, 16)`, small
clusters merged into the nearest one, larger k tried when that leaves one
group (W1's `_cluster`). Only identical vectors fall back to equal cuts in
claim-id order, counted in `id_chunk_cuts`. Children are ordered by size,
then smallest claim id. Depth is capped at the contract's 16 and children at 128.

**Ids (deterministic, no matching against the previous run).** UUIDv5 in a
fixed namespace:
- root: `"{map}|{hierarchy}|{theme}|root"`;
- other groups: `"{map}|{hierarchy}|{theme}|members|"` + the group's claim ids
  (every claim under it), lowercase and hyphenated, sorted, comma-joined;
- `map` is `public` or `team:<group uuid>`.

So a group whose member set is unchanged keeps its id across runs, and a root
keeps its id while its membership changes. Rust mints them (`tree.rs`) and
`apply` refuses any result id that differs from its own. Python mints the
same strings, and one golden vector is pinned in both suites. The links
hierarchy (W5) must mint its root with the same function: the meaning root's
`switch` points to `root(map, links, theme)`.

**What W4 stores** (`atlas_map_levels`, `hierarchy = 'meaning'`):
- a group document per inner group: children (id, kind, `claim_count`),
  `name` null with `needs_naming: true` (W8), `bundles: []` and `targets: []`
  (W10's outgoing links), breadcrumbs from the root, and the switch above;
- a SKELETON leaf document per leaf: its claim nodes only, each labelled with
  its text cut to 160 characters, `truth_value` null (no belief read),
  `edges: []`, `outgoing: []`. Agents, evidence, edges and flow weights are
  W3/W7's and are drawn when W10 assembles the full leaf. The leaf was still
  checked against the cap with its agents and evidence;
- **positions are placeholders** that the contract allows: children evenly
  spaced on a ring of radius 0.6 with `r` the largest that keeps them apart
  (at most 0.35); leaf nodes on a ring of radius 0.8. W6 replaces them. The run
  params say `"positions": "placeholder"` and `"leaves": "skeleton"`.

**Membership** (claim to leaf group, for W9's incremental assignment) needs no
migration: every leaf document lists its claims as nodes, and
`AtlasMeaningRepository::leaf_membership` reads claim to leaf group for one run
and one hierarchy in one spliced statement.

**Runs.** `level_for_viewer` serves the latest finished run of a map whatever
its hierarchy, so a run holding only meaning levels hides a run holding only
links levels. `write_meaning_levels` writes into a run the caller opened, so
the nightly (W9) can put both hierarchies in one run. The standalone `apply`
opens and finishes its own run and says so in its report.

**Scope.** Every read takes the build's snapshot transaction, a viewer and the
map, splices the viewer and carries W3's map predicate (`visibility = 'public'
OR (visibility = 'group' AND owner_group_id = T)`; T bound NULL on the public
map). Members are `claims.theme_id = theme`, `COALESCE(is_current, true)`,
with an embedding. Current members with no embedding are left out of the tree
and counted in the box-side report (not in the export).

**Apply refuses** (nothing written): a result for another map or hierarchy, a
cap over the apply cap, a theme whose live member set differs from the
result's, any id that does not match the mint, a malformed tree (a member
twice, a group with one child, a depth or parent that does not chain, too
deep, too many children). A leaf that W3's `assemble_leaf` finds over the cap
(attachments that grew since the export) is split on the box with W3's
`fallback_split`, the parts minted like any group; the report counts these.

## Tests

**Python** (`tests/theme/test_atlas_meaning_core.py`):
- `test_every_leaf_weight_is_within_the_cap` (blobs, shared agents, evidence);
- `test_rerun_reproduces_every_group_id` (and input order does not matter);
- `test_a_theme_under_the_cap_is_one_root_leaf` and
  `test_a_child_that_fits_is_a_leaf_with_no_empty_level`;
- `test_a_shared_agent_counts_once_per_group` (60 claims sharing one agent fit
  one leaf of 61; counting per claim would split them);
- `test_ids_match_the_golden_vector`;
- `test_a_claim_over_the_cap_alone_is_refused`;
- `test_identical_vectors_terminate_within_the_cap`;
- `test_compute_runs_without_db_driver` (subprocess, `psycopg2` blocked);
- `test_committed_fixture_reproduces_the_committed_result`.

**Rust, pure** (`atlas_meaning::tree`, `docs`, `files`): the golden id;
validation refusals (each malformed tree); a leaf over the cap is resplit and
minted; documents validate; the committed result fixture parses and
validates; the export writer reproduces the committed export bytes.

**Rust, DB** (`crates/epigraph-cli/tests/atlas_meaning.rs`, fresh DB):
- `every_leaf_of_a_team_map_fits_the_cap_as_w3_counts`: a team theme of
  claims with agents and evidence; a deliberately coarse result (the whole
  theme as one root leaf) forces the on-box resplit; after apply, every stored
  leaf's claim ids are re-read with `read_leaf_rows` and re-assembled with
  `assemble_leaf`: `Fits`, at most 100 nodes;
- `a_second_apply_over_unchanged_input_reproduces_every_group_id`;
- `export_weights_match_what_w3_counts`: the export's per-leaf weight equals
  `assemble_leaf`'s `counts.nodes`;
- `a_team_map_never_holds_another_teams_claim`;
- `the_public_map_holds_only_public_claims`;
- `stored_level_documents_validate_against_the_contract`;
- `leaf_membership_reads_back_every_claim`;
- `apply_refuses_a_result_whose_members_drifted` and
  `apply_refuses_a_forged_group_id`;
- `retired_and_unembedded_claims_are_not_members`.

- `the_binary_refuses_a_bad_map_or_cap_before_connecting` (no DB).

**Fail on old code** (measured on the branch: each mutation applied alone,
the affected targets run, then restored and `touch`ed):

| Mutation | Tests that went red |
|---|---|
| Python: weight summed per claim (a shared node counted per claim) | `test_every_leaf_weight_is_within_the_cap`, `test_a_shared_agent_counts_once_per_group`, `test_committed_fixture_reproduces_the_committed_result`, `test_compute_runs_without_db_driver` |
| Python: members unsorted in the id | `test_a_group_id_depends_only_on_its_members`, `test_ids_match_the_golden_vector` |
| Python: a root under the cap still split | `test_a_theme_under_the_cap_is_one_root_leaf`, `test_a_shared_agent_counts_once_per_group` |
| Python: input not sorted by id | `test_rerun_reproduces_every_group_id` |
| Python: validate skips the id check | `test_validate_tree_refuses_a_malformed_tree[forged_id]` |
| Python: validate allows a single child | `test_validate_tree_refuses_a_malformed_tree[single_child]` |
| `claim_attachments` without the per-claim cap | `claim_attachments_are_what_assembly_counts_for_each_claim` (unit only: no DB fixture has a claim with more than 99 attachments) |
| member read without the map predicate | 8 of 10 DB tests, among them `a_team_map_never_holds_another_teams_claim`, `the_public_map_holds_only_public_claims` |
| member read without `is_current` | `a_team_map_never_holds_another_teams_claim`, `retired_and_unembedded_claims_are_not_members` |
| `leaf_membership` without the map predicate | `leaf_membership_reads_back_every_claim` |
| group id hashed over reversed members | `ids_match_the_golden_vector`, `the_committed_result_passes_the_rust_tree_check` |
| `check_tree` without the id mint check | `check_tree_refuses_each_malformed_tree`, `apply_refuses_a_forged_group_id` |
| `check_tree` allows a single child | `check_tree_refuses_each_malformed_tree` |
| `check_tree` without the member cover check | `check_tree_refuses_each_malformed_tree`, `a_team_map_never_holds_another_teams_claim`, `apply_refuses_a_result_whose_members_drifted` |
| `resolve_tree` skips the W3 re-check | `a_leaf_that_fits_is_left_alone`, `a_leaf_w3_finds_over_the_cap_is_split_into_minted_leaves`, `every_leaf_of_a_team_map_fits_the_cap_as_w3_counts`, `a_second_apply_over_unchanged_input_reproduces_every_group_id` |
| export numbers attachments per claim | `attachments_are_numbered_per_theme_by_kind_then_id`, `export_weights_match_what_w3_counts` |
| the binary's cap check removed | `the_binary_refuses_a_bad_map_or_cap_before_connecting` |
| Python: clustering skipped (every split by claim-id position) | `test_the_tree_follows_the_embeddings` |
| documents stored without `to_stored_json` and a child `r` of 0 | `every_document_validates_and_chains_to_its_parent`, `stored_level_documents_validate_against_the_contract` |
| (review) export files written with `std::fs::write`, directory created with the default mode | `the_binary_export_is_owner_only_under_umask_022`, `export_files_are_created_new_and_owner_only`, `the_export_directory_must_be_owner_only_and_empty` |
| (review) apply without the whole-map theme check | `apply_refuses_a_result_that_lacks_a_theme_the_map_draws` |
| (review) `embedded_theme_ids_on_map` without the map predicate | `apply_refuses_a_result_that_lacks_a_theme_the_map_draws` |
| (review) `ComputeVersions::check` a no-op | `a_result_with_arbitrary_versions_is_refused` |
| (review) `leaf_membership` without the other-schema-version refusal | `leaf_membership_reads_back_every_claim` |
| (review) `atlas_meaning` missing from the help lint's `BINS` | `every_env_backed_arg_hides_its_value` (the review ran it red) |

Not mutation-proved (each asserts a direct property, with no separate code
path to break): `labels_are_cut_to_the_contract_length`,
`placeholder_positions_stay_inside_the_contract_ranges`,
`test_shared_evidence_counts_once_and_unshared_evidence_splits`,
`test_export_reader_refuses_a_truncated_embedding_file`,
`the_writer_reproduces_the_committed_export_bytes`,
`a_tree_for_another_map_or_hierarchy_is_refused`,
`map_keys_round_trip_and_refuse_other_spellings`.

The committed fixture's result is exact k-means output (30 points, no UMAP)
under CI's pins (`tests/requirements-ci.txt`: numpy 1.26.4, scikit-learn
1.8.0, umap-learn 0.5.11), the versions it was generated with.

**Not tested end to end**: an export from a database, computed by the
Python core and applied back. The build hosts have no numpy, and CI's Python
job has a database but no built binary, so the two halves meet through the
committed fixture instead (the Rust writer reproduces the Python export bytes;
the Python result passes the Rust tree check), and
`the_binary_export_is_owner_only_under_umask_022` runs the box's export as the
real binary on a fresh database. The first true compute-on-database run is the
operator's first dry run (`apply` without `--apply`).

**Left for later items.** Current members with no embedding are in no leaf
(counted in the report and the run's `params`; W5's unlinked claims and W9's
incremental assignment must handle them). One drifted theme refuses the whole
apply, and `export` holds one snapshot across every theme it writes (W9's
nightly decides how to retry).

## "Done when" → proof

| Criterion | Proof |
|---|---|
| a test team map has every leaf ≤ 100 nodes | `every_leaf_of_a_team_map_fits_the_cap_as_w3_counts` (DB); `test_every_leaf_weight_is_within_the_cap` (Python) |
| a second run over unchanged input reproduces the same group ids | `a_second_apply_over_unchanged_input_reproduces_every_group_id` (DB); `test_rerun_reproduces_every_group_id`, `test_committed_fixture_reproduces_the_committed_result` (Python) |
| (brief) a group already under the cap becomes a leaf directly | `test_a_theme_under_the_cap_is_one_root_leaf`, `test_a_child_that_fits_is_a_leaf_with_no_empty_level` |
| (brief) shared agents counted once | `test_a_shared_agent_counts_once_per_group`; `export_weights_match_what_w3_counts` |
| (brief) a team map never includes another team's claim; the public map only public claims | `a_team_map_never_holds_another_teams_claim`, `the_public_map_holds_only_public_claims` |
| (brief) stored level documents validate | `stored_level_documents_validate_against_the_contract` |
| off-box: ids, embeddings, numeric weights only | `test_compute_runs_without_db_driver`; the export writer test pins the file contents |

## Needs prod measurement (the orchestrator's)

- Per-theme drawable claim counts per team map, and the unembedded count.
- Attachments per claim (how often W3's per-claim cap bites), and the export
  size per map.
- UMAP reproducibility across the compute hosts: ids persist only if the
  clustering reproduces, so the result records numpy, scikit-learn and
  umap-learn versions.
- `leaf_membership`'s cost on the largest team map.
