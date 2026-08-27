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


## scan_sensitive_terms.sh

Fails the build if any **tracked** file contains a string from the
sensitive-term list. Runs as the blocking `sensitive-scan` CI job
(`.github/workflows/ci.yml`) and as the first step of `verify.sh`.

The effective list is the **union** of two files:

| File | Committed? | Purpose |
|------|-----------|---------|
| `scripts/sensitive-terms.example.txt` | yes | generic secret markers; the list CI actually uses |
| `scripts/sensitive-terms.txt` | gitignored | org-specific terms (partners, codenames, hosts) |

One fixed string per line; a line whose first non-blank character is `#`
is a comment. Inline comments are **not** supported. Matching is
case-sensitive fixed-string (`git grep -F`) — case-folding short
credential prefixes matches ordinary prose.

Local setup mirrors `providers.toml.example`:

```bash
cp scripts/sensitive-terms.example.txt scripts/sensitive-terms.txt
$EDITOR scripts/sensitive-terms.txt   # add your org-specific terms
```

```bash
./scripts/scan_sensitive_terms.sh                # redacted (CI default)
./scripts/scan_sensitive_terms.sh --show-matches # full lines, local triage only
```

Exit codes: **0** clean · **1** term(s) found · **2** configuration error
(no list, not a git repo, bad argument). Default output prints
`path:match_count` and never the matched line, because CI logs are
themselves a disclosure channel — re-run locally with `--show-matches`
to triage.

Scope is tracked files in the working tree (`git grep` semantics): it
scans full file content, not just the PR diff, and does **not** see
untracked or gitignored files. It is a pre-merge gate, not a
filesystem-wide secret sweep.

Adding a term to the committed list red-lights every open PR if it
matches existing content — scan first. Self-test:
`./scripts/tests/test_scan_sensitive_terms.sh` (pure shell + git, no DB).
