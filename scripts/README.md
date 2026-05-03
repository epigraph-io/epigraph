# scripts/

Operational scripts for the live EpiGraph deployment. Not part of the
build; invoked by maintenance tasks (see `epiclaw-host`'s `schedules.toml`)
or run manually on the host.

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
