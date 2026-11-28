# scripts/

Operational scripts for the live EpiGraph deployment. Not part of the
build; invoked manually or by the deployment's scheduled maintenance tasks
(a host scheduler of your choice; `docs/deploy.md` step 10 lists the jobs).

## Dependencies and database

The Python packages these scripts import (psycopg2, numpy, scikit-learn,
umap-learn, requests, httpx, networkx) are pinned, with hashes, in
`scripts/requirements.txt`. It is compiled from `scripts/requirements.in`
against `tests/requirements-ci.txt`, the file the CI `python` job installs and
tests them against, so every version and hash in it equals the CI one
(`tests/ci/test_requirements_locked.py` fails otherwise; the `.in` header says
how to recompile). Install it into a virtual environment on the host that runs
them, before the first run:

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes --only-binary :all: -r scripts/requirements.txt
```

No script installs a package at run time: a missing one is an `ImportError`
naming this file.

A script that opens a database connection has no built-in DSN: it connects on
`--database-url`, else `MAINTENANCE_DATABASE_URL`, else `DATABASE_URL`, and
refuses to start with none of them (`scripts/maintenance_dsn.py`). Four
scripts differ:

- `subcluster_outliers.py` is read-only and deliberately stays off the
  maintenance login: `--database-url` or `DATABASE_URL` only. Give it a
  read-only login; nothing enforces that.
- `screen_public_claims.py` is read-only (its session is set read-only) and
  takes `--database-url` only (required; not read from the environment). Give
  it a read-only login, and leave the password out of the DSN: a command line
  is visible to other users of the host and lands in shell history, while
  libpq still reads `~/.pgpass` (or the file `PGPASSFILE` names).
- `lib/tiered_enrichment.py --claim-id` takes `--database-url` only (not from
  the environment), so a privileged `DATABASE_URL` exported for another job is
  never used for it.
- `run_assessment_worker.py` has no `--database-url`: it reads on
  `DATABASE_URL` and writes on `MAINTENANCE_DATABASE_URL`, else
  `DATABASE_ADMIN_URL`, and exits at startup unless both sides are set. Which jobs to schedule, and with what
role and cadence, is in `docs/deploy.md`, "Step 10 — Schedule the maintenance
jobs" (the theme pipeline is there too).

## screen_public_claims.py

Screens every public claim, current or superseded (the guest claim card reads
a claim by id whatever its `is_current`), for text that should not be readable
without a login, before guest reads are turned on: long verbatim text (content
over 300 characters, or a quoted span of more than 40 words), internal
identifiers (full UUIDs, internal host names and private addresses,
home-directory and `*-private/` paths, operator-listed markers and private
group names) and personal data (e-mail addresses, phone numbers, street
addresses). It writes one JSON line per flagged claim (`{"claim_id",
"is_current", "reasons"}`), optionally the flagged ids in the format `epigraph-operator
restrict-claims --claims-file` reads, and per-reason counts on stderr. It never
prints a claim's text, a matched term or the DSN.

The private group names and markers come from files the operator supplies (one
per line, `#` comments); none is built in, because that list is itself private.
Both flags are required (an empty file is allowed): list every private
directory and project name in the markers file, since the built-in path rule
only knows home directories and a `*-private/` directory.

Not screened: credentials or connection strings, IPv6 addresses, UUIDs written
without dashes, and the guest card's `sources` (document key and title).

```bash
python3 scripts/screen_public_claims.py --database-url "$READONLY_DSN" \
    --private-groups groups.txt --private-markers markers.txt \
    --out hits.jsonl --claims-file-out restrict-candidates.txt
```

Review the hits, make the ones that should not be public private with
`restrict-claims`, and only then turn guest reads on.

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

**Marks** each duplicate through the API, `POST /api/v1/claims/{dup}/dedup
{"canonical_id": ...}`, the same act as MCP `mark_duplicate`: the duplicate is
retired (`supersedes = canonical`, `is_current = false`, both embeddings
nulled), gets its `same_as` identity edge carrying `properties.dedup` (so
`unmark_duplicate` can reverse it and `label_dedup_index_view` reads it), and
the administrative cascade moves its evidence, edges and mass functions onto
the canonical with a revert record. The database connection is read-only; it
only picks canonicals and skips retired members.

Until 2026-10 the script marked with its own SQL (a raw `UPDATE claims` plus
lossy re-pointing) and wrote no identity edge (rows carrying
`properties->>'deduped_by' = 'fuzzy_dedup_claims'`). Once an operator's
`backfill_dedup_identity_edges --apply` (epigraph-cli, dry run by default) has
written the edge they are ordinary dedup records: the index view lists them,
and `unmark_duplicate` makes the claim current again and restores nothing (that
SQL kept no repair record; the answer says `legacy_mark`). A legacy mark the
backfill cannot reconstruct is refused with the reason. An un-marked legacy
claim keeps its `deduped` label; the script treats that label as a mark only
while the claim is retired.

`--execute` needs a bearer token (`--token` or `EPIGRAPH_TOKEN`) and refuses to
start without one; `EPIGRAPH_API_BASE` (or `--api-base`) names the API. The
endpoint needs the `claims:write` scope and write authority over both claims,
so a cross-agent cluster needs a token that also carries `claims:admin`. A
refused mark, or a request that got no HTTP answer, is reported with its
status and the run exits 1; the cluster's other marks still count.

A member that is not current, or already carries a `supersedes` pointer, is
never the canonical; as a duplicate it is skipped and reported as
`duplicates_skipped_already_superseded` (also when it is the cluster's only
other member), unless it is already marked onto this cluster's canonical by an
earlier run, which is passed over silently.

This is the **S3 fuzzy** layer. It is *not* the S2 content-hash-keyed
backfill that gates migration 107 (`UNIQUE (content_hash, agent_id)`).
Different problems, different keys; both are needed eventually.

```bash
# Inspect what would change against a freshly synced snapshot:
python3 scripts/fuzzy_dedup_claims.py --input <path-to>/semantic-dedup.json --verbose

# Mark a small batch first:
EPIGRAPH_TOKEN=... python3 scripts/fuzzy_dedup_claims.py --input semantic-dedup.json --execute --limit 50

# Full run:
EPIGRAPH_TOKEN=... python3 scripts/fuzzy_dedup_claims.py --input semantic-dedup.json --execute
```

Each duplicate is one request. A refused one is reported in the summary; the
rest of the run continues.

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
  weight from the calibration file (with the DB-vocab aliases applied —
  and a hardcoded fallback if the alias section is absent). Best-evidence
  wins. The file is `--calibration` if given, else `$CALIBRATION_PATH`
  when set (the file the engine serves), else the repo-root
  `calibration.toml`; the run prints which one it used.
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
2.5), so it is safe to run repeatedly on a cron. Per repo it keeps a
cursor and a retry list in `<state_dir>/<owner>__<repo>.state.json`: a run
scans the PRs merged since `cursor - window_minutes` and re-tries every
PR whose ingest failed (after a backoff of 15 minutes, doubling per failure,
at most a day), so neither an outage longer than the window nor a failed
ingest loses a PR. A rebase-merged PR is ingested commit by commit
(its range is matched against the PR commits API).

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
*/15 * * * *  EPIGRAPH_GIT_INGEST_GITHUB_PAT=... /usr/bin/python3 <checkout>/scripts/git_ingest_reconciler.py --config /var/lib/epiclaw/git-ingest/config.toml >> /var/log/git-ingest.log 2>&1
```

**Hard rule — do NOT enable the cron until Plan 2.5 is in prod**
(`dev → main` merge + redeploy of the `ingest_git --pr-ingest`
find-or-create / idempotency path). Until then, run the reconciler
**only with `--dry-run`**. Enabling the live cron against a server that
predates Plan 2.5 risks duplicate or malformed claim writes.


## check_sensitive.py (pre-commit sensitive-data check)

epigraph is a public repository. The `secrets` CI job (gitleaks) catches
credentials; this check catches the other class of leak: infrastructure
identifiers and organisation-specific names. A `pre-commit` hook (and a
`pre-merge-commit` hook, which git runs instead when `git merge` records a
merge commit) runs `scripts/check_sensitive.py` over the **staged** content and
file paths of each commit and blocks it on:

- AWS resource ids (`i-`, `vol-`, `sg-`, `vpc-`, ... with 8 or 17 hex digits),
  EC2 public/private hostnames (`ec2-A-B-C-D...`, `ip-A-B-C-D...`) and the
  account id inside an ARN or a private ECR registry host. These rules are
  built in and always on. A bare 12-digit account id is NOT matched (too many
  false positives); list account ids in the local file if they must be caught.
- Org-specific terms and regexes from `.check_sensitive_local.yaml` at the
  checkout root. That file is **gitignored** because the list of terms is
  itself sensitive; `.check_sensitive_local.example.yaml` is the committed
  template (placeholders only). Linked worktrees use the main checkout's copy.
  Local entries starting with `example-` are template placeholders and are
  ignored. The template gets no exemption: a real term typed into it blocks
  the commit like anywhere else.

The hooks are opt-in per clone. Install them from a checkout you trust (main):

```bash
bash scripts/install-sensitive-hooks.sh
cp .check_sensitive_local.example.yaml .check_sensitive_local.yaml   # then edit
```

The installer writes both hooks into the clone's own hooks directory
(`.git/hooks`, shared by linked worktrees), outside the working tree, and they
run `scripts/check_sensitive.py` from the blob at a **trusted ref**, never from
the working tree: `refs/remotes/origin/main` by default. To use another branch,
`git config epigraph.sensitiveHookRef <branch>` and re-run the installer, which
expands it to a full refname; the hooks accept only full names under
`refs/remotes/` or `refs/heads/`, because a short name such as `origin/main` can
be shadowed by a tag or branch of that name (fetching a fork's remote brings its
tags). The blob runs under `python3 -I` from a private temp directory, so no
module planted in a shared temp directory or named by `PYTHON*` variables is
imported in its place. A scanner change therefore takes effect once it is
reviewed and merged (and fetched); a missing ref or blob, or a ref that is not
a full branch name, blocks the commit (exit 2). Re-run the installer after
updating it; it never overwrites a hook it did not write.

**Do not use `git config core.hooksPath .githooks`** (the setup this section
used to document), and do not enable any in-tree hooks path in a clone you use
to review contributor branches. With it, git runs whatever `.githooks/` the
CHECKED-OUT branch holds, and those hooks ran that branch's
`scripts/check_sensitive.py`: checking out a contributor's pull request and then
committing or merging there would execute its code with your privileges and
credentials before anyone had reviewed it. The files in `.githooks/` are now
stubs that block every commit with migration instructions, and the installer
removes a `core.hooksPath` set in the clone's config (it stops if one is set
globally, where it cannot). A branch can still ship its own `.githooks/`, so
the stubs are a reminder, not a control: the fix is to unset the option.

Without the local file, or with one that lists no terms or patterns, the hook
warns and applies the generic rules only; a local file it cannot parse blocks
the commit (exit 2). Findings print `path:line` and the rule or entry number,
never the matched text; a path that itself matches is shown as
`<path redacted, blob <id>>` (find it with `git ls-files -s`). Audit the whole
tracked tree with `python3 scripts/check_sensitive.py --all-files`, and clean up
its hits before enabling the hook: it scans whole staged files, so any commit
touching a file that already contains a listed term is blocked.

`scripts/tests/test_check_sensitive.py` drives real `git commit`s through the
installed hooks in throwaway repositories (including a checked-out branch whose
scanner and `.githooks/` try to run their own code), and its last test runs the
`--all-files` audit
over this checkout. It runs in the CI `python` job with the generic rules only
(no local list exists there).
