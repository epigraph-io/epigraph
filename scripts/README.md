# scripts/

Operational scripts for the live EpiGraph deployment. Not part of the
build; invoked manually or by maintenance tasks (see `epiclaw-host`'s
`schedules.toml`).

## audit_claims_content_hash_agent.py

Audits the drifted `uq_claims_content_hash_agent` constraint (migration 013)
on a live database: reports whether `_sqlx_migrations` claims 013 applied,
whether the constraint actually exists, and how many rows block each candidate
constraint shape (full `UNIQUE (content_hash, agent_id)` vs partial
`... WHERE is_current`).

Read-only by default. **Never deletes claims** — 14 of the FKs referencing
`claims.id` are `ON DELETE CASCADE` (`evidence`, `reasoning_traces`,
`mass_functions`, `triples`, …), so choosing a survivor per duplicate group is
an owner decision, not a mechanical one.

```bash
python3 scripts/audit_claims_content_hash_agent.py            # report
python3 scripts/audit_claims_content_hash_agent.py --json     # machine-readable

# Adds the constraint; refuses (exit 1) unless zero rows violate it:
python3 scripts/audit_claims_content_hash_agent.py --apply-constraint full
```

This is the **S2 content-hash-keyed** gate referenced below — distinct from
`fuzzy_dedup_claims.py`'s S3 semantic layer.

## fuzzy_dedup_claims.py

Cross-agent **semantic** dedup of the `claims` table, driven by a
precomputed embedding-similarity snapshot from
`epigraph-gui/public/semantic-dedup.json`.

Soft-marks duplicates with the `deduped` label and a `deduped_into`
property pointer to the canonical claim, so the GUI's collapse-equivalents
view stays coherent and any hard-delete sweep can come later.

This is the **S3 fuzzy** layer. It is *not* the S2 content-hash-keyed
backfill that gates migration 107 (`UNIQUE (content_hash, agent_id)`).
Different problems, different keys; both are needed eventually.

```bash
# Inspect what would change against a freshly synced snapshot:
python3 scripts/fuzzy_dedup_claims.py --input /home/jeremy/epigraph-gui/public/semantic-dedup.json --verbose

# Stage a small commit to validate behaviour on production:
python3 scripts/fuzzy_dedup_claims.py --input semantic-dedup.json --execute --limit 50

# Full run:
python3 scripts/fuzzy_dedup_claims.py --input semantic-dedup.json --execute
```

Each cluster runs in its own transaction. A failing cluster is rolled
back and reported in the summary; the rest of the run continues.

## compute_semantic_dedup.py

Regenerates `epigraph-gui/public/semantic-dedup.json` — the offline
embedding-similarity snapshot the GUI uses to collapse semantically
equivalent claims at viz time, and that `fuzzy_dedup_claims.py`
consumes for backend dedup.

Walks every embedded claim, pulls its top-k nearest neighbours via the
`idx_claims_embedding_hnsw_cosine` HNSW index, filters to cosine
similarity ≥ threshold, builds connected components via union-find,
and writes the snapshot atomically.

```bash
# Full refresh (writes to GUI's public/ by default):
python3 scripts/compute_semantic_dedup.py

# Tighter threshold + larger k:
python3 scripts/compute_semantic_dedup.py --threshold 0.92 --top-k 10

# Smoke test on a slice, alternative output:
python3 scripts/compute_semantic_dedup.py --limit 5000 --output /tmp/quick.json
```

Reproduces the exact JSON shape (`threshold`, `top_k`, `computed_at`,
`n_claims`, `n_groups_with_dupes`, `n_dup_claims`, `groups[]`) so
nothing on the consumer side needs to change.

Throughput is ~20 claims/sec at HNSW defaults — full 389k corpus runs
in 5–6 h. Read-only against the database.

## backfill_source_strength.py

One-shot backfill for `mass_functions.source_strength` rows that
predate the evidence-type-weighted writer. The discount path treats
NULL as 1.0 (no discount); under undiscounted Dempster combination
even mid-confidence supporters can drive a target's BetP toward 1.0.

For each NULL row:
- If the claim has ≥1 evidence row: take the **highest** evidence-type
  weight from `calibration.toml` (single source of truth, with the
  DB-vocab aliases applied — and a hardcoded fallback if the alias
  section is absent). Best-evidence wins.
- Otherwise: fall back to the agent-only / `conversational` tier (0.3).

```bash
# Preview the resolved weight distribution:
python3 scripts/backfill_source_strength.py

# Commit:
python3 scripts/backfill_source_strength.py --execute
```

After --execute, run `reconcile_sheaf` (or wait for the next nightly
graph-integrity task) so beliefs re-aggregate against the new
discount weights. Idempotent — re-runs only touch rows still NULL.

## git_ingest_reconciler.py

Server-side git-ingest reconciler (Plan 3). Discovers newly-merged PRs
across configured repos (read-only GitHub access via the `gh` CLI) and
runs `ingest_git --pr-ingest` against the localhost EpiGraph API for
each — continuous, cross-repo, idempotent commit ingestion with no
external CI and no write-token spray. Stdlib-only; idempotent (Plan
2.5) and stateless, so it is safe to run repeatedly on a cron.

**Auth:** set `EPIGRAPH_GIT_INGEST_GITHUB_PAT` to a *read-only* PAT
(injected as `GH_TOKEN` for the `gh` subprocesses), or leave it unset to
fall back to the host's own `gh auth` token. Writes go to the localhost
API, not GitHub — **no GitHub write scope is ever used**.

**Install:**

```bash
# 1. Copy the template into the state dir and edit it (repos, endpoint, bin path):
sudo mkdir -p /var/lib/epiclaw/git-ingest
sudo cp scripts/git_ingest_reconciler.config.example.toml \
        /var/lib/epiclaw/git-ingest/config.toml
sudo $EDITOR /var/lib/epiclaw/git-ingest/config.toml

# 2. Build the ingester this config points at (or use the deployed release path):
cargo build --bin ingest_git   # → .cargo-target/debug/ingest_git

# 3. Dry-run first (no API writes; proves discovery + range + argv end to end):
EPIGRAPH_GIT_INGEST_GITHUB_PAT=ghp_readonly... \
  python3 scripts/git_ingest_reconciler.py \
    --config /var/lib/epiclaw/git-ingest/config.toml --dry-run
```

**Cron** (every 15 min; a `fcntl` lock in `state_dir/.lock` prevents
overlapping runs):

```
*/15 * * * *  EPIGRAPH_GIT_INGEST_GITHUB_PAT=... /usr/bin/python3 /home/jeremy/epigraph/scripts/git_ingest_reconciler.py --config /var/lib/epiclaw/git-ingest/config.toml >> /var/log/git-ingest.log 2>&1
```

**Hard rule — do NOT enable the cron until Plan 2.5 is in prod**
(`dev → main` merge + redeploy of the `ingest_git --pr-ingest`
find-or-create / idempotency path). Until then, run the reconciler
**only with `--dry-run`**. Enabling the live cron against a server that
predates Plan 2.5 risks duplicate or malformed claim writes.


## test_generality_direction.py

Falsification test: **does the geometry of the claim embedding space predict
the direction of `decomposes_to` edges?**

The motivating problem is a mismatch of symmetry. A Riemannian metric is
symmetric (`d(a,b) = d(b,a)`); an ontology is not (`is-a` and `decomposes-to`
have direction). So no learned metric can induce hierarchy unless some
*asymmetric* quantity in the geometry tracks generality. In the full method
that quantity is the volume element `sqrt(det G(z))`, which costs weeks to
train. This script asks the cheap prerequisite: does a **flat-space** proxy,
in the 1536-d space we already have, beat chance at calling which endpoint is
the parent? If it cannot, a learned metric has no signal to sharpen.

A negative result is a successful outcome. The script is built to kill the
idea, not to support it.

Proxies (fitted against a background sample of `is_current` claims):
neighbourhood count at cosine radii 0.20/0.30/0.40, mean k-NN similarity,
proximity to the corpus centroid, and — the headline — the **participation
ratio** `(sum L)^2 / sum L^2` of the local k-NN covariance spectrum, which is
the flat-space analogue of the volume element and so the proxy that actually
forecasts whether the learned-metric version can work. It is reported
separately even when another proxy scores higher.

Read-only: the connection is pinned `default_transaction_read_only = on`, so a
stray write aborts rather than commits.

```bash
DATABASE_URL=postgres://epigraph_ro:epigraph_ro@localhost:5432/epigraph \
    python3 scripts/test_generality_direction.py --verbose

# Smoke test on a slice:
python3 scripts/test_generality_direction.py --limit 500 --background 5000

# Full report as JSON, plus the paired parent/child distribution plot:
python3 scripts/test_generality_direction.py --json out.json --plot out.png

# Validate the harness with no database at all:
python3 scripts/test_generality_direction.py --self-test
```

**Pre-registered decision rule** (fixed before any result was seen; do not
adjust after):

| verdict | condition |
|---------|-----------|
| `PROCEED` | best proxy >= 0.70 **and** >= 10 points over the length baseline **and** the margin survives the within-agent restriction |
| `INCONCLUSIVE` | 0.55 – 0.70, or margin over length < 10 points |
| `DEAD` | <= 0.55, or not separable from the length baseline |

Four confounds are handled, because a naive version of this test returns a
confident wrong answer:

1. **Length.** `len(content)` is scored as a first-class competitor beside
   every proxy, and each proxy is rescored inside length-matched strata.
2. **Agent.** The parent/child `agent_id` contingency is reported, plus
   accuracy restricted to same-agent edges (a proxy may be reading writing
   style, not geometry).
3. **Non-independence.** A parent with 30 children is 30 correlated trials.
   The headline uses a one-child-per-parent subsample (Wilson CI); the
   all-edges figure carries a parent-clustered bootstrap CI.
4. **Temporal / id leakage.** `created_at`, `id` and insertion order are never
   read as features — `created_at` is not even selected. Hierarchical ingest
   creates parents before children, so any time-derived feature would score
   near-perfectly and mean nothing.

Two further guards: a **shuffled-direction control**, which must return ~0.50
or the harness is broken and every other number is suspect; and a **lexical
sanity check** (bag-of-words and length-only pairwise logistic regressions).
If the lexical models match the geometric proxies, a positive result is a
lexical axis in the ambient space — a classifier could recover hierarchy, but
it would say nothing about manifold curvature.

Orientation ("higher = parent" vs "lower = parent") is fitted on a fit split
and scored only on a disjoint test split, with parents split as whole groups.

Offline regression tests (no DB, no network):

```bash
python3 -m unittest scripts.tests.test_generality_direction
```
