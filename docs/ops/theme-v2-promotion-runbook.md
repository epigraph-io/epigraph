# theme-v2 prod promotion runbook

Status as of 2026-08-17. Supersedes the "promote theme-v2" backlog claim
`c1b7dd8a-0b0a-4573-a8b5-9b37d3be9585`, which is stale on two points.

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

## Actual prod state (measured, not assumed)

| Thing | Value |
|---|---|
| `claim_themes` rows | 32 (16 distinct labels, each duplicated) |
| Labels | `auto-00`..`auto-15` — generic, no semantic naming |
| `claims.theme_id` populated | **500** of 462,623 |
| Claims with an embedding | 330,527 (this is the themable ceiling, not 462k) |
| Embedding dim | 1536 |
| `claim_clusters` | 191,891 rows, all under ONE run `8ecaa839-b737-4332-bdab-2b18c115866a` |
| That run's date | **2026-03-27** |
| `cluster_centroids` for it | 8 |
| `cluster_labels` for it | 8, and the "labels" are concatenated example sentences, not names |

So Model B is stale and coarse (8 clusters from March), and Model A is the nightly
toy sample. This is **not** a replay of the validated 88-theme clone run — it is a
fresh full-corpus pass.

## Why diverse recall is currently dead

`recall()` already accepts `diverse: bool` (`crates/epigraph-mcp/src/tools/recall.rs`,
the `pub diverse: Option<bool>` field) and mirrors `POST /api/v1/search/semantic?diverse=true`.
The wiring is **code-complete**. But the REST handler gates on themes existing —
in `crates/epigraph-api/src/routes/search.rs`, search for the comment
`// Only enter diverse mode if themes have been populated` and the `if !themes.is_empty()`
guard immediately under it. With 500 claims themed across 16 generic labels, that
path either falls back to flat ANN or selects across meaningless groupings.

**Populating themes properly is the whole fix.** No code change is required to make
recall-diverse call the themes.

## Step 1 — full-corpus grow (BLOCKED, needs a human to run)

Claude Code's auto-mode classifier refuses both `systemd-run` and the live prod write,
which is the same gate recorded in claim `aabbb75c`. Run this yourself:

```bash
DATABASE_URL="$(sudo sed -n 's/^DATABASE_URL=//p' /etc/epiclaw/epigraph-api.env)" \
systemd-run --user --scope -p MemoryMax=1900M \
  --working-directory=/home/jeremy/epigraph-wt-themev2 \
  python3 scripts/theme_pipeline.py grow --batch-size 2000 --target-k 72
```

- `--batch-size 2000` is **required**. The default is 20000, which is the value that
  caused a global OOM in the 2026-06 run.
- `MemoryMax=1900M` is required for the same reason: this box also runs
  epigraph-postgres and epigraph-api, and the OOM killer will not pick politely.
- Expect roughly 40 minutes for the base assign (166 batches of 2000), plus the
  split/grow iterations, plus LLM labelling.
- Chain: base k-means (UMAP-32, silhouette-selected k in 8..20) -> split high-variance
  clusters until k reaches 72 -> `project_to_themes.project_run` -> `label_themes_llm.py --relabel-all`.

`project_run` wipes and rebuilds `claim_themes` inside **one transaction** with an
empty-run guard, so a mid-run failure rolls back to the current state rather than
leaving a hole. The 500 currently-themed claims are the toy sample; nothing of value
is lost.

If it dies partway through the base assign, resume without redoing it:

```bash
python3 scripts/theme_pipeline.py grow --from-run-id <run_id> --batch-size 2000
```

### Verify after the run

```sql
SELECT count(*) FROM claim_themes;                                  -- expect ~72-88
SELECT count(*) FILTER (WHERE theme_id IS NOT NULL) FROM claims;    -- expect ~330k
SELECT label, claim_count FROM claim_themes ORDER BY claim_count DESC LIMIT 15;
-- labels must be semantic ("Bacterial Pathogenesis"), NOT auto-NN
SELECT count(*) FROM claim_themes WHERE centroid IS NULL;           -- must be 0
```

A NULL centroid breaks pgvector recall, so that last check is not optional.

## Step 2 — rewire the nightly

The 4 AM task is `theme-maintenance` in `/var/lib/epiclaw/data/scheduler.db`
(`scheduled_tasks`), cron `0 0 4 * * *`, model `claude-haiku-4-5`, `context_mode=isolated`.
Its prompt says only "find_workflow(goal: 'Run k-means theme maintenance on knowledge
graph claims'), follow the best-matching workflow steps."

That resolution is the bug. `find_workflow` returns `305050d2` — a *pointer* claim whose
goal is a prose description and whose `steps` array is **empty** — and the runner-up
`d32ee4e8` has literal steps `["step-a","step-b","step-c"]`. With no real steps to
follow, the agent falls back to calling the bare `theme_cluster` MCP tool, which
defaults to `wipe_first=true` on a 500-claim sample with `label_prefix="auto"`. That is
the nightly wipe.

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

## Step 3 — confirm diverse recall lights up

After themes are populated, with no code change:

```
recall(query: "<something broad>", diverse: true, max_themes: 5)
```

should return claims spread across several semantically-named themes. Compare against
`diverse: false` — if the two are identical, the `!themes.is_empty()` guard is still
failing and the projection did not land.
