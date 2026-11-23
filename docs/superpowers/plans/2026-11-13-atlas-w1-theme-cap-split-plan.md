# Atlas W1: split every theme over the cap (implementation plan)

Backlog item W1 `8c4aefda` (epic `8fa0282d`). Design:
`docs/superpowers/specs/2026-11-12-atlas-nested-groups-and-subgraph-view-design.md` §2, §5, §7.

## Goal

No theme holds more than about 2,000 claims. Every theme over the cap is split by UMAP over
its members' embeddings and then clustering, recursively, until every part is at or under the
cap. The largest part keeps the theme id, and the split can be reversed exactly.

## Files

| File | Role |
|------|------|
| `scripts/theme_cap_core.py` | The pure split: `split_to_cap(ids, embeddings, cap, seed) -> parts`. It also holds the export and result file formats. It imports numpy, scikit-learn and umap-learn only: no DB driver, no `theme_lib`, no text. |
| `scripts/theme_cap_split.py` | The CLI: `plan`, `export`, `compute`, `apply`, `reverse`. The DB helpers are imported lazily, so `compute` runs on a host with no DB driver. |
| `scripts/theme_lib.py` | Docstring only: the new script is added to `not_intake_owned`'s "checked and not routed" list. |
| `tests/theme/test_theme_cap_core.py` | The pure core and the export file format. No DB. |
| `tests/theme/test_theme_cap_split.py` | The CLI: names, the role guards, the off-box `compute` subprocess, and the DB arm on the `tests/theme` fixture DB (a fresh database migrated to head). |

## Split core

1. Sort the input by claim id, so the result does not depend on the order rows arrive in.
2. If `n <= cap`, return one part.
3. L2-normalise the embeddings. UMAP to 16 dimensions (cosine, `n_neighbors=15`, `min_dist=0`,
   `random_state=seed`), using `refine_clusters.auto_refine`'s settings. Small inputs
   (`n <= 100`) skip UMAP and cluster the normalised vectors.
4. Run k-means with `k = max(2, ceil(n / cap))`, `random_state=seed`.
5. Merge any cluster under `min_part` (default `cap // 20`) into its nearest cluster centroid.
   If that leaves one group (a theme just over the cap whose second cluster is a small separated
   subtopic), retry k-means on the same reduction with up to four larger k, which splits the
   dominant cluster by its own geometry and folds the small one in whole. If every k still merges
   to one group, keep the first k's clusters unmerged.
6. Only when the vectors cannot be told apart (identical embeddings) cut into equal chunks by
   claim id. Every such cut is counted (`id_chunk_cuts`, in the result file, the plan report and
   each part's `split_id_chunk_cuts`). Every recursive call is strictly smaller, so this
   terminates.
7. Recurse into every part over the cap.
8. Order the final parts by size, descending, then by smallest claim id. Part 0 is the largest
   and keeps the theme id.

## Off-box round trip

The off-box rule (design §2) allows ids and embeddings only.

- `export --out DIR` writes one `<theme_id>.npz` per over-cap theme, with `claim_ids` as a
  fixed-width unicode array and `embeddings` as float32, plus an `export.json` index of ids and
  counts. Everything loads with `allow_pickle=False`.
- `compute --from DIR --out result.json` needs no DB. It writes the parts as claim ids.
- `apply --from result.json` reads that file.
- `plan` does export and compute in process and writes the same `result.json`. That file is
  the dry run's output and `apply`'s input, so what is applied is exactly what was reviewed.
- The split is deterministic on one host and set of library versions, but not promised across
  hosts or CPU architectures (backlog c7c6e7ce), so an off-box `compute` may not reproduce the
  on-box plan. A plan file is tagged `"source": "plan"` and a compute result
  `"source": "compute"`. Apply takes a plan file as it is. Any other result (a compute result,
  or a file with no `source`) needs `--reviewed-plan PLAN` (the plan the operator reviewed) or
  `--expect-digest HEX` (the `parts_digest` that plan printed): apply recomputes
  `theme_cap_core.parts_digest` of both from the parts and refuses on a mismatch, before
  connecting. `compute` prints its own result's digest, which always matches itself, so it is
  not a review. `--unreviewed` applies such a result unchecked; the output and the manifest
  record which check ran (`review`).

## Apply (one transaction)

1. **Validate the result against the live DB.** For each theme, the union of its parts must be
   exactly the theme's current embedded members, the parts must be disjoint, and each part must
   be at or under the cap. Any drift refuses the whole apply, and nothing is written. The
   result's cap is enforced, and a result whose cap is over `apply --cap` (default 2000) is
   refused before the database is read.
2. **Kept part.** Part 0 keeps the theme id. New parts get new `claim_themes` rows. Members
   move with `AND theme_id = parent`, and the rowcount must match.
3. **Recompute.** `claim_count` and `centroid` are recomputed per part, as in `split_theme.py`.
   `centroid_3072` is recomputed when the parent had one.
4. **Lineage in `properties`.** Each part copies the parent's properties and sets `split_of`,
   `split_part`, `split_run`, `split_method`, `split_cap` and a `split_path`. The `split_path`
   extends the parent's path, so a re-split theme keeps a unique
   `(cluster_run_id, cluster_id, split_path)` key. Earlier `split_of`/`split_part` values are
   kept in `split_history`.
5. **Names.** No name comes from claim text. Each part's label is
   `<parent label> · part <path>`, kept under 60 characters and never starting `auto-` or
   `cluster-`. That keeps `label_themes_llm.is_placeholder_label` false, so the default labeller
   does not rename it from member text (D-PR16). Every part has `needs_naming: true` for W8.
6. **Final check.** Before commit, a live recount of every touched theme, including members with
   no embedding, must be at or under the cap. Otherwise the apply rolls back.
7. **Manifest.** The manifest holds each parent's full row (`to_jsonb`) and each new part's id and
   moved claim ids. It is written and fsynced before commit.

## Reverse (one transaction)

1. For each new part, its current members must equal the manifest's moved ids. Otherwise the
   reverse refuses, unless `--allow-drift`, which moves every current member back to the parent.
2. Move the members back and delete the new rows.
3. Restore the parent row from the snapshot through `jsonb_populate_record`, over the columns
   `information_schema` lists that the snapshot holds. The column list is not hard-coded, and a
   column added after the apply keeps its current value.
4. A manifest whose new rows do not exist (an apply that never committed, or one already
   reversed) is a no-op when the parent row equals its snapshot.

## DB role

`claims` has forced RLS, so an application-role session sees only a subset. The scripts refuse
in two cases:

- a DSN whose user is the application role;
- a session that row security on `claims` applies to: one whose role is not a superuser or
  BYPASSRLS, and for which the DB's own `epigraph_bypass()` is false
  (`test_a_session_under_row_security_is_refused`).

The usage text names `MAINTENANCE_DATABASE_URL`.

## "Done when" → proof

| Criterion | Proven by |
|-----------|-----------|
| A dry run lists every theme over the cap with its proposed parts | `test_plan_lists_every_over_cap_theme_with_part_sizes` (DB) |
| The apply leaves no theme over ~2,000 | `test_blobs_split_under_cap_without_cutting_a_blob`, `test_a_small_separated_cluster_stays_whole_just_over_the_cap`, `test_the_split_follows_umap_structure_not_raw_kmeans` and `test_degenerate_identical_embeddings_terminate_under_cap` (core); `test_apply_leaves_no_theme_over_cap_and_largest_keeps_id`, `test_apply_places_unembedded_members_under_the_cap`, `test_apply_splits_an_over_cap_theme_the_embeddings_cannot` and `test_apply_refuses_a_result_whose_cap_is_over_its_own` (DB); `test_unembedded_slots_fill_parts_in_order_then_chunk` (no DB) |
| Ids stay stable for kept parts | `test_apply_leaves_no_theme_over_cap_and_largest_keeps_id`; `test_split_is_deterministic_and_input_order_free` |
| The split is reversible | `test_apply_then_reverse_is_byte_identical` (every `claim_themes` row in full, plus an md5 of the `(id, theme_id)` projection of `claims`); `test_reverse_refuses_drift_unless_allowed`; `test_reverse_keeps_a_column_added_after_the_apply` |
| Off-box: ids and embeddings only | `test_compute_runs_without_db_driver` (subprocess with `psycopg2` and `theme_lib` blocked); `test_no_claim_text_reaches_any_output` |
| Off-box parts that differ from the reviewed plan are not applied | `test_parts_digest_is_the_parts_and_nothing_else`, `test_apply_refuses_a_result_that_is_not_the_reviewed_plan`, `test_apply_cli_refuses_an_unreviewed_result_before_connecting`, `test_apply_cli_refuses_a_result_nobody_reviewed` (no DB); `test_apply_with_the_reviewed_digest_writes_and_records_it`, and `test_no_claim_text_reaches_any_output` (same-host compute applied against the plan) (DB) |

## Limits

- **`claims.updated_at`.** The `claims_updated_at` trigger bumps `updated_at` on every move, so
  the byte-identity covers the `(id, theme_id)` membership, not whole `claims` rows.
- **Atlas layouts.** `atlas_layout_themes` and `graph_neighborhoods` rows of a split theme are
  stale until rebuilt (W2/W9). Reverse cascades over rows that reference the deleted parts.
- **Current members only.** The cap counts `COALESCE(is_current, true)` members, which is what the
  Atlas draws and what `list_summaries` counts. Superseded and duplicate-marked members keep their
  `theme_id` but have no embedding. They stay in the kept part and do not count
  (`test_the_cap_counts_current_members_only`).
- **Unembedded current members** (backlog 029392cb). The off-box split cannot place them, so
  apply places them on the box (`theme_cap_core.unembedded_slots`): in claim-id order, each part
  in part order (the kept part first) is filled up to the cap, and any remainder becomes extra
  parts of at most the cap. A theme whose embedded members fit in one part, or that has none, is
  therefore still split under the cap, and plan reports the final sizes
  (`part_sizes_with_unembedded`) and `unembedded_only_parts`. Two consequences:
  - A part filled to exactly the cap goes over it at the next nightly assignment to it.
  - A part of unembedded members only has a NULL centroid and a `claim_count` of 0. The Atlas
    builds take only themes with an embedded member, so it is not drawn until its members are
    embedded. Showing unembedded members on the Atlas (a fallback leaf) is still open under
    029392cb.
  Any theme the result names that would still end over the cap refuses the whole apply (a
  safety net). Run plan and apply in small `--theme-id` batches on a large corpus.
