# Re-port the EpigraphV2 Theme-Clustering System — Design

**Date:** 2026-06-03
**Status:** Approved (design); pending spec review → implementation plan
**Branch:** `feat/theme-v2-full-report` (off `origin/main` @ 169a85c)

## Problem

The current `epigraph` theme system tops out at the silhouette-optimal flat
k-means count (k≈8 on this corpus — *fewer* than the existing broken 16, and
0.1% coverage: 500 of 429K claims themed). EpigraphV2 reached ~60–72 themes
not from the base pass but from an **iterative refinement engine** that was
never ported: discover outlier/boundary claims → subcluster the boundaries to
surface "isolated clusters within a previous k-means cluster" → split and
reassign → repeat. The current partial port (`cluster_themes.py` on the stale
`feat/theme-system-overhaul` branch) brought only the base seed→assign→label
path and dropped that engine plus the per-claim boundary signal it runs on.

Two facts shape the work:

1. **The columns already exist.** `claim_clusters` (with `centroid_distance`,
   `second_centroid_dist`, `boundary_ratio`, `silhouette_score`,
   `centroid_distances[]`, `cluster_run_id`), `cluster_centroids`, and
   `cluster_labels` are all present in the live DB; `claim_clusters` holds
   191,891 rows from an old V2 run. This is an **algorithm re-port, not a
   schema build.** (`cluster_labels` is prod-drift — present in the DB, absent
   from `migrations/` — and needs a forward migration.)

2. **`claim_clusters` is read but never written by current code.** It feeds the
   matcher (`scorer.rs` Jaccard cluster-overlap, `CompoundNeighborhoodBlocker`)
   and `find_boundary_claims` / `GET /api/v1/clusters/boundary-claims`, but
   nothing populates it — so those features run on stale 191K-row data while the
   corpus is 429K. Re-running the engine fixes this.

## Goal

Re-port the full V2 embedding-clustering engine — all columns and algorithms —
functioning in the current codebase: base clustering with the rich boundary
signal, outlier discovery, boundary subclustering, refine/split, and LLM
labeling, driven by an orchestrated grow-loop that reaches ~60–72 coherent
themes, with the result projected into the active `claim_themes`/`theme_id`
model so recall/GUI/MCP/matcher all consume it.

## Decisions (locked)

| Decision | Choice |
|---|---|
| Runtime | **Python scripts** (faithful; reuse UMAP/sklearn/logreg; Rust k-means proved to hang) |
| Data model | **Engine writes B (`claim_clusters`/`cluster_centroids`/`cluster_labels`), projects into A (`claim_themes`/`claims.theme_id`)** |
| Refine mode | **Autonomous LLM mode (`--auto`, claude haiku) + keep interactive faithful mode** |
| Orchestration | **Orchestrated grow-loop + each step independently invokable** |
| Run versioning | **One consolidated `cluster_run_id` per grow-cycle** (improves on V2's per-refine fragmentation) |
| Runtime budget | Multi-hour off-hours batch is acceptable; no first-cut sampling cap required |

## Architecture

```
scripts/
  theme_pipeline.py    orchestrator: grow-loop + discrete subcommands + --dry-run
  cluster_base.py      seed → assign → discover   (writes Model B; revives V2 cluster_claims.py)
  subcluster.py        find isolated sub-structure in boundary claims (proposes/writes splits)
  refine.py            split a cluster: --auto (LLM) | interactive (logreg, faithful V2 port)
  project_to_themes.py B → claim_themes + claims.theme_id (true 1536-d centroids)
  label_themes_llm.py  LLM labels clusters/themes (salvage existing port)
  theme_lib.py         shared: memory-safe load, embedding parse, DB + run-id helpers
migrations/
  NNN_formalize_cluster_labels.sql   CREATE TABLE IF NOT EXISTS cluster_labels (matches prod)
```

Each unit has one purpose and a defined interface (CLI args + the DB tables it
reads/writes). `theme_lib.py` removes the load/parse duplication the V2 scripts
each carried.

### Data flow

1. **Base** (`cluster_base.py`): sample atomic-leaf claims (V2 default; sharper
   manifold than all-claims — `--all-claims` to override), fit UMAP(32, cosine)
   + k-means (silhouette pick), persist reducer; assign **all** current+embedded
   claims into the fixed UMAP frame; write per-claim `claim_clusters` rows
   (`cluster_id`, `centroid_distance`, `second_centroid_dist`, `boundary_ratio =
   nearest/second`, `silhouette_score ≈ 1−boundary`, full `centroid_distances[]`)
   and `cluster_centroids`. All keyed by a fresh `cluster_run_id`.
2. **Discover**: flag clusters whose p95 `centroid_distance` or mean
   `boundary_ratio` exceeds a threshold → candidates with hidden sub-structure.
3. **Subcluster/split**: for each flagged cluster, UMAP+k-means on just its
   boundary claims; if silhouette confirms real structure, split it and rewrite
   the affected claims' `cluster_id` **into the same run** (consolidated run).
4. **Repeat** 2–3 until no cluster qualifies, target k reached (~60–72), or
   max-iterations hit. The orchestrator logs the stop reason; no silent cap.
5. **Project** (`project_to_themes.py`): for the final run, upsert one
   `claim_themes` row per cluster (label from `cluster_labels`; `centroid` =
   **true 1536-d mean of member embeddings**, since recall does pgvector search
   on it — *not* the padded 32-d UMAP centroid); set `claims.theme_id`; store the
   `cluster_id ↔ theme_id` map in `claim_themes.properties`.
6. **Label** (`label_themes_llm.py`): claude-haiku names each cluster/theme from
   its nearest-centroid claims.

### Refine modes

- `--auto`: embedding-subcluster the chosen cluster, then claude (haiku)
  proposes sub-labels and confirms the split. Unattended; used by the grow-loop.
- interactive: faithful port — human sub-labels → logistic-regression on
  boundary claims → reassign.

## Robustness (defects observed during the trial run, fixed first-class)

- **`SET statement_timeout`** on the wipe/bulk writes so a killed client cannot
  orphan a multi-minute server-side `UPDATE` (observed: a 23-min orphaned
  `UPDATE claims SET theme_id=NULL` lock-blocked the retry).
- **Targeted wipe** `WHERE theme_id IS NOT NULL` (and run-scoped deletes of
  `claim_clusters`/`cluster_centroids`/`cluster_labels`) instead of rewriting all
  429K rows every run.
- **Memory-safe loading** in `theme_lib.py`: chunked fetch + numpy-direct parse
  to avoid the ~3.5 GB Python-float transient that OOMs at default batch sizes;
  designed to run under a `systemd-run --user --scope -p MemoryMax=…` cap so the
  job, never postgres, is the OOM victim. Output to stdout/log file (never the
  systemd journal, which hid progress during the trial).

## Schema

One forward migration: `CREATE TABLE IF NOT EXISTS cluster_labels (cluster_run_id
uuid, cluster_id int, label text, sample_count int, created_at timestamptz, …,
UNIQUE(cluster_run_id, cluster_id))` matching the live table, plus any indexes the
engine relies on (`claim_clusters(cluster_run_id, cluster_id)`,
`claim_clusters(claim_id)`). No other schema changes — every other column exists.

## Testing

- **Unit (pure functions):** boundary-metric math (`boundary_ratio`,
  `silhouette_score`); LLM refine/label prompt builders + output parsers;
  projection `cluster_id → theme_id` mapping.
- **Integration (small DB, `epigraph_db_repo_test`):** seed→assign leaves 0
  unthemed and writes one `claim_clusters` row per claim; discover flags a
  planted incoherent cluster; split increases k and rewrites only affected
  claims; projection makes `claims.theme_id` consistent with the latest run and
  `claim_themes.centroid` a real 1536-d vector.
- **`--dry-run`** orchestrator path: reports the grow plan (which clusters would
  split, projected k) without writing.
- Tests reviewed against the council-of-critics rule (no tautologies/happy-path-
  only).

## Scope / non-goals

- **Out:** the separate graph-cluster subsystem (Louvain on epistemic edges —
  `graph_clusters`/`graph_neighborhoods`/`claim_cluster_membership`); 3072-d
  centroids (claims embed at 1536 — note as future); any Rust rewrite of the
  engine.
- **Salvage, don't rebuild:** the already-ported `label_themes_llm.py` and the
  memory/wipe lessons from the stale `feat/theme-system-overhaul` branch.

## Source references

- V2 originals: `/home/jeremy/EpigraphV2/scripts/cluster_claims.py`,
  `subcluster_outliers.py`, `refine_clusters.py`.
- Current consumers to keep working (per codebase map): `scorer.rs::compute`,
  `CompoundNeighborhoodBlocker`, `ClaimThemeRepository::{find_boundary_claims,
  claims_in_themes_at_dim, recompute_all_centroids}`, recall MCP,
  `GET /clusters/boundary-claims`, theme HTTP routes.
```
