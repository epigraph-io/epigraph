# theme-v2 prod promotion runbook

Status as of 2026-08-19. Supersedes the "promote theme-v2" backlog claim
`c1b7dd8a-0b0a-4573-a8b5-9b37d3be9585`, which is stale on two points.

Step 1 has been RUN. Step 2 has NOT. See "Current state" below before acting.

## What the backlog claim got wrong

1. **"dev->main promotion PR not done."** It is done. Every theme-v2 artefact is on
   `origin/main` at `7cd5eeef`: `scripts/project_to_themes.py`, `theme_pipeline.py`,
   `cluster_claims.py`, `refine_clusters.py`, `label_themes_llm.py`,
   `maintain_themes.py`, `theme_lib.py`, and `migrations/051_formalize_cluster_labels.sql`.
   It went over in the #280 dev->main promotion. `origin/dev` is currently 2 commits
   ahead of main and contains none of it.
2. **"do NOT apply migration 051 to prod before the binary ships it."** Moot —
   051 is already applied in prod (`_sqlx_migrations` runs through 059).

The "VM has NO active swap" constraint is also stale: 4 GB of swap was added
2026-07-21. The 7.6 GB ceiling itself still stands.

## Current state (measured 2026-08-19, not assumed)

| Thing | Value |
|---|---|
| `claim_themes` rows | **209**, all semantically labelled |
| `auto-NN` labels | **0** |
| `claims.theme_id` populated | **330,529** of 462,923 |
| Claims with an embedding | 330,750 (this is the themable ceiling, not 462k) |
| Embedding dim | 1536 (`claim_themes.centroid`) |
| `claim_themes.centroid` NULL | **0** |
| `claim_themes.centroid_3072` NULL | 209 — benign, see below |
| Largest theme | 7,951 ("Bone anatomy and joint articulation") = **2.41%** of the themed corpus |
| Top-7 share | 13.68% (45,213 claims) |
| Themes >= 8,000 claims | **0** |
| Themes under 2,000 claims | 161, smallest 78 |
| `claim_clusters` | 339,640 rows across TWO runs |
| Current run | `16138781-156b-4e12-9b1d-27f6ae8f9e8b` — 330,530 rows, 210 cluster ids, 2026-08-17 to 2026-08-19 |
| Legacy run | `8ecaa839-b737-4332-bdab-2b18c115866a` — 9,110 rows, 8 clusters, 2026-03-27 |

Two things the earlier version of this file got wrong: `claim_clusters` was never
"191,891 rows all under one run" — the March run is 9,110 rows — and the corpus is no
longer the 500-claim `auto-NN` toy sample.

`centroid_3072` being NULL everywhere is not a hole. `crates/epigraph-api/src/routes/search.rs`
auto-detects centroid dimension from the fraction of themes with `centroid_3072`
populated (>= 50% selects 3072), so it selects the fully-populated 1536-d `centroid`.

The 330,530-vs-330,529 gap is not loss: the run has 210 distinct `cluster_id`s and
`cluster_id = 0` is a singleton that received no theme row. No cluster row in that run
points at a deleted claim.

## Why diverse recall was dead, and is not any more

`recall()` already accepts `diverse: bool` (`crates/epigraph-mcp/src/tools/recall.rs`,
the `pub diverse: Option<bool>` field) and mirrors `POST /api/v1/search/semantic?diverse=true`.
The wiring was always **code-complete**. The REST handler gates on themes existing —
in `crates/epigraph-api/src/routes/search.rs`, search for the comment
`// Only enter diverse mode if themes have been populated` and the `if !themes.is_empty()`
guard immediately under it. With 500 claims themed across 16 generic labels, that
path fell back to flat ANN. The feature was DATA-blocked, never code-blocked.

With 209 populated themes the guard now passes, and `diverse=true` returns results
spread across multiple themes for a query flat search answers from one.

**Populating themes properly was the whole fix.** No code change was required to make
recall-diverse call the themes.

## Step 1 — full-corpus grow (DONE 2026-08-17, re-run 2026-08-19; kept for the next rebuild)

Claude Code's auto-mode classifier refuses both `systemd-run` and the live prod write,
which is the same gate recorded in claim `aabbb75c`. Run this yourself:

```bash
DATABASE_URL="$(sudo sed -n 's/^DATABASE_URL=//p' /etc/epiclaw/epigraph-api.env)" \
systemd-run --user --scope -p MemoryMax=1900M \
  --working-directory=/home/jeremy/epigraph-wt-themev2 \
  python3 scripts/theme_pipeline.py grow --batch-size 2000 --target-k 72 --max-size 8000
```

- `--max-size 8000` is **required**, and requires the fix in PR #393
  (`fix/theme-split-oversized`). Without it the 2026-08-17 run produced six themes
  holding the bulk of the corpus, the largest 51,772 claims (15.7%). See "Why the
  first run failed".
- `--batch-size 2000` is **required**. The default is 20000, which is the value that
  caused a global OOM in the 2026-06 run.
- `MemoryMax=1900M` is required for the same reason: this box also runs
  epigraph-postgres and epigraph-api, and the OOM killer will not pick politely.
- Expect roughly 40 minutes for the base assign (166 batches of 2000), plus the
  split/grow iterations, plus LLM labelling.
- Chain: base k-means (UMAP-32, silhouette-selected k in 8..20) -> split clusters that
  are high-variance **or** at/over `--max-size`, continuing past `target_k` while any
  cluster is oversized -> `project_to_themes.project_run` -> `label_themes_llm.py --relabel-all`.
  The 2026-08-19 run settled at k=209 from a target of 72; that is expected — `target_k`
  is a floor, not a ceiling.

## Why the first run failed (do not re-derive this)

The 2026-08-17 run passed every check in the verify block below and was still unusable.
The oversized clusters reported p95 centroid distance 0.032–0.065 and mean boundary
0.31–0.44, failing **both** arms of the split trigger `p95 >= 0.5 OR mean_boundary >= 0.5`.
Those distances live in UMAP-32 *normalized* space with `min_dist=0.0`, which collapses a
coherent cluster to ~0.03 spread — the 0.5 threshold is structurally unreachable for
exactly the largest, most coherent clusters. Small clusters wedged between neighbours
reported 0.77–0.83 boundary ratios, so the heuristic split crumbs and never giants.
`stop_reason` compounded it by returning "target_k reached" at k=76 against target 72,
ending the loop before any oversized cluster was examined.

PR #393 adds `DEFAULT_MAX_SIZE = 8000` as an absolute second split trigger and makes
`target_k` a floor (`current_k >= target_k and n_oversized == 0`). **Variance-based
splitting alone is not a sufficient gate — always assert on absolute size.**

`project_run` wipes and rebuilds `claim_themes` inside **one transaction** with an
empty-run guard, so a mid-run failure rolls back to the current state rather than
leaving a hole. Note that this rebuilds Model A only — `claim_clusters` (Model B) is
untouched, which is why the 2026-08-18 nightly wipe cost only the projection and the
2026-08-19 re-run could resume from the surviving base run.

If it dies partway through the base assign — or a wipe destroys `claim_themes` — resume
without redoing it:

```bash
python3 scripts/theme_pipeline.py grow --from-run-id <run_id> --batch-size 2000 --max-size 8000
```

### Verify after the run

```sql
-- k is a floor, not a target: 2026-08-19 landed 209 from --target-k 72
SELECT count(*) FROM claim_themes;                                  -- expect >= target_k
SELECT count(*) FILTER (WHERE theme_id IS NOT NULL) FROM claims;    -- expect ~330k
SELECT label, claim_count FROM claim_themes ORDER BY claim_count DESC LIMIT 15;
-- labels must be semantic ("Bacterial Pathogenesis"), NOT auto-NN
SELECT count(*) FROM claim_themes WHERE centroid IS NULL;           -- must be 0

-- THE CHECK THAT THE 2026-08-17 RUN WOULD HAVE FAILED. Do not skip it: every
-- other query above passed on a corpus where six themes held the bulk of it.
SELECT count(*) FROM (
  SELECT theme_id FROM claims WHERE theme_id IS NOT NULL
  GROUP BY theme_id HAVING count(*) >= 8000
) oversized;                                                        -- must be 0

-- and the distribution itself, not just the extremes
SELECT round(100.0 * sum(n) / (SELECT count(*) FROM claims WHERE theme_id IS NOT NULL), 2)
FROM (SELECT count(*) n FROM claims WHERE theme_id IS NOT NULL
      GROUP BY theme_id ORDER BY n DESC LIMIT 7) top7;              -- 2026-08-19: 13.68
```

A NULL centroid breaks pgvector recall, so that check is not optional. Neither is the
oversized check — a passing NULL-centroid check says nothing about whether the themes
are usable.

## Step 2 — rewire the nightly (NOT DONE — the wipe path is still intact)

**This step is outstanding.** On 2026-08-18 11:20 UTC the nightly fired against the
completed 76-theme run and replaced it with 16 `auto-NN` rows over 500 claims. The task
has been PAUSED as a stopgap; it has not been fixed. Re-enabling the cron before both
edits below land will destroy the current 209 themes exactly the same way. A pause is
not a fix.

The 4 AM task is `theme-maintenance` in `/var/lib/epiclaw/data/scheduler.db`
(`scheduled_tasks`), cron `0 0 4 * * *`, model `claude-haiku-4-5`, `context_mode=isolated`.
Its prompt says only "find_workflow(goal: 'Run k-means theme maintenance on knowledge
graph claims'), follow the best-matching workflow steps."

That resolution is the bug. `find_workflow` returns `305050d2` — a *pointer* claim whose
goal is a prose description and whose `steps` array is **empty** — and the runner-up
`d32ee4e8` has literal steps `["step-a","step-b","step-c"]`. With no real steps to
follow, the agent falls back to calling the bare `theme_cluster` MCP tool, which
defaults to `wipe_first=true` on a 500-claim sample with `label_prefix="auto"`. That is
the nightly wipe, and it is what happened on 2026-08-18.

**The nightly must NOT run `theme_pipeline.py grow`.** It executes in an epiclaw
container capped at 1 GB with `EPICLAW_MAX_CONTAINERS=2`; UMAP over 330k embeddings
there would OOM the host.

Correct split:

- **Nightly (4 AM) = `scripts/maintain_themes.py`.** It runs entirely through
  `/api/v1/themes/*` and `/api/v1/clusters/boundary-claims` — no ML, no direct DB, so
  it is container-safe. It assigns unthemed claims to the nearest existing centroid,
  reassigns misplaced ones by boundary_ratio, auto-splits high-variance themes,
  recomputes only affected centroids, and reports new theme candidates. Cumulative
  growth, no wipe. Needs `EPIGRAPH_TOKEN` with `claims:write` (`claims:admin` for
  cross-owner reassign).
- **Periodic full rebuild = `theme_pipeline.py grow`**, on the host, under the memory
  cap, monthly or on demand. Never on the nightly cron.

Both edits are needed, or the old chain stays reachable:

1. Store a workflow whose steps are the real maintain chain, and
2. rewrite the `theme-maintenance` prompt to name that workflow explicitly rather than
   resolving it by semantic search.

Also reconsider `claude-haiku-4-5` for this task now that the chain includes judgement
about split candidates.

## Step 3 — confirm diverse recall lights up (DONE 2026-08-19)

After themes are populated, with no code change:

```
recall(query: "<something broad>", diverse: true, max_themes: 5)
```

should return claims spread across several semantically-named themes. Compare against
`diverse: false` — if the two are identical, the `!themes.is_empty()` guard is still
failing and the projection did not land.

Observed 2026-08-19: same query and limit, flat search returned 8 results from **one**
theme; `diverse=true` returned 8 from **two** ("Evidence-Grounded Agent Memory Systems",
4,250 claims, and "Graph integrity maintenance audits", 2,786). Note the failure mode
this check has: before the size fix, `diverse=true` *also* returned one theme, not
because the guard failed but because the whole subject sat inside a single 51,772-claim
bucket. A one-theme diverse result means either "no themes" or "themes too coarse" —
check the oversized query in the verify block before blaming the guard.
