# scripts/

Operational scripts for the live EpiGraph deployment. Not part of the
build; invoked manually or by maintenance tasks (see `epiclaw-host`'s
`schedules.toml`).

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
predate the evidence-type-weighted writer (PR #76). The discount
path treats NULL as 1.0 (no discount), which is what produced the
runaway hubs at BetP≈1.0 in bug #6.

For each NULL row:
- If the claim has ≥1 evidence row: take the **highest** evidence-type
  weight from `calibration.toml` (single source of truth, with PR #75's
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
