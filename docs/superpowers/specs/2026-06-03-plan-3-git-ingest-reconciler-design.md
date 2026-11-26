# Plan 3: Server-side git-ingest reconciler (cross-repo, continuous)

**Status:** implemented (`scripts/git_ingest_reconciler.py`); §3.5, §3.6, §4 and §5 revised 2026-11-26 (backlog 39dfef78)
**Repo:** `epigraph` (public) · **Branch base:** `docs/commit-ingestion-spec`
**Depends on:** Plan #2 (`--pr-ingest`, merged to `main` #257) and **Plan 2.5** (server-side idempotency — merged to `dev` #261, **must reach `main`/prod before live enable**). Final subsystem of `docs/superpowers/specs/2026-06-02-commit-ingestion-automation-design.md`.

---

## 1. Motivation

Plan #2 gave us `ingest_git --pr-ingest` (repo→PR→commit hierarchy + resolution links); Plan 2.5 made the server idempotent so re-ingesting is safe. We still need something to **call it continuously, across all our repos**.

The design doc §5 assumed per-repo GitHub Actions calling the API. That is the wrong fit here: CI runs on **external GitHub-hosted `ubuntu-latest`** runners, the prod API is behind the **VPC firewall (Caddy reverse-proxy ingress only)**, and per-repo workflows would **spray a write-capable prod token** across every repo's CI plus require distributing a prebuilt binary. This spec **supersedes §5** with a **server-side reconciler**: a periodic job on the VPC that discovers newly-merged PRs (read-only GitHub token), runs the ingester locally, and POSTs to the API on `localhost` (already authed). No external CI, no per-repo workflow, no write-token spray, no binary distribution. It also **never executes repo/PR code** (it only reads git metadata + commit messages) — a security win over a self-hosted runner.

**Goal:** every merged PR across configured repos becomes a `repo→PR→commit` hierarchy in EpiGraph within one cron interval, idempotently, with zero secrets in external CI.

---

## 2. Architecture

```
system cron (every ~15 min, on the VPC)
   └─ scripts/git_ingest_reconciler.py        (the driver)
        for each configured repo slug:
          1. discover merged PRs (GitHub API, read-only token) within an
             overlapping time window
          2. git -C <mirror> fetch origin        (local mirror clone)
          3. for each merged PR:  ingest_git --pr-ingest … --rev-range M^1..M^2
                                  --endpoint http://127.0.0.1:8080
          4. log per-PR outcome; continue on failure
```

A per-repo cursor and retry list (see §5) bound the scan and carry failed PRs to the next
cycle. Idempotency (2.5) makes the overlap a no-op.

---

## 3. Components

### 3.1 Driver — `scripts/git_ingest_reconciler.py`
Standalone Python (mirrors `scripts/reconcile_backlog_labels.py`), run by system cron. **Not** a `schedules.toml` `claude -p` agent (no LLM needed) and **not** an in-`epigraph-api` Rust cron (keep load off the API process). Responsibilities: load config, resolve auth, loop repos→PRs, invoke the ingester, log. Idempotent and re-entrant; a single lock file prevents overlapping runs.

### 3.2 GitHub auth chain
Read-only access to list PRs + read PR metadata. Resolution order:
1. **PAT** from env `EPIGRAPH_GIT_INGEST_GITHUB_PAT` (fine-grained, `Pull requests: read` + `Contents: read`), if set;
2. else **`gh auth token`** — reuse the host's existing authenticated `gh` CLI bearer.
The driver sets `GH_TOKEN`/`GITHUB_TOKEN` for any `gh`/API call accordingly. No write scope is ever needed (writes go to the localhost API, not GitHub).

### 3.3 Repo config
A small config (TOML/JSON under the state dir, e.g. `/var/lib/epiclaw/git-ingest/config.toml`) listing `owner/repo` slugs and the poll window. **Pilot: `epigraph-io/epigraph` only.** Expand by adding slugs (`epiclaw-host`, `episcience`, `epigraph-gui`, …) once the pilot is validated.

### 3.4 Local mirror clones
One clone per repo under `/var/lib/epiclaw/git-ingest/<owner__repo>` (created on first run via `git clone`; `git fetch origin` each cycle). Needed because the ingester parses **local** `git log`. Read-only use; never checked out to run code.

### 3.5 Merged-PR discovery
Per repo, query the GitHub API for PRs merged since the cutoff, `cursor - window` (`now - window` on a first run; §5):
`gh api -X GET repos/<slug>/pulls --field state=closed --field sort=updated --field direction=desc --field per_page=100 --field page=N`, filter to `merged_at != null && merged_at >= cutoff`. Pages are read one at a time and the scan stops at the first page that is short or whose last row's `updated_at` is before the cutoff: the listing is ordered by `updated_at` and a PR's `updated_at` is never before its `merged_at`. (It must not stop on `merged_at`: a comment on an old PR lifts it to the top.) The listing moves while it is paged: a PR updated mid-scan jumps from an unread page to page 1, already read. Every such PR's `updated_at` is at or after page 1's newest, so after a multi-page scan the driver re-reads the listing down to that mark (normally one page), repeating only while page 1's newest moves, and keeps each PR once. Not covered: a closed, unmerged PR reopened mid-scan leaves the listing and shifts the rows below it up one place, which can skip one row whose `updated_at` did not change. Capture per PR: `number, title, body, merge_commit_sha (M), base.sha, user.login, merged_at`. (Window default ≈ 4× the cron interval, generous overlap; idempotency absorbs it.)

### 3.6 Commit-range computation
For a `--merge` merge commit `M` (two parents): the PR's own commits are **`M^1..M^2`** (base-tip..PR-head). The driver verifies `M` has two parents (`git rev-list --parents -n1 M`); a one-parent `M` is a **squash** or a **rebase** merge. The driver reads the PR commits API (`repos/<slug>/pulls/<n>/commits`, n commits): when the n first-parent commits ending at `M` carry the API commits' author email, author date and first message line, in order (a rebase keeps those and changes the sha), the range is **`M~n..M`**; otherwise it is a squash and the range is the single commit `M~1..M`. Matching on identity rather than the count keeps a squash from claiming other PRs' commits. The API lists at most 250 commits, so a 250-commit answer falls back to `M~1..M` with a warning. The ingester already runs `--no-merges`, so `M` itself is never a claim.

### 3.7 Ingester invocation
```
ingest_git --pr-ingest \
  --repo-slug <owner/repo> --pr-number N \
  --pr-title <title> --pr-body <body> \
  --merge-sha M --merged-at <iso> --pr-author <login> \
  --rev-range M^1..M^2 \
  --repo <mirror path> --endpoint http://127.0.0.1:8080
```
The ingester resolves the orchestrator agent from the `Epigraph-Orchestrator-Id:` trailer (PR body / commits), else `EPIGRAPH_DEFAULT_ORCHESTRATOR_ID` (which **must be a registered agent**); commit children → deterministic git-author agents; the repo-root node → the fixed system agent (Plan 2.5 §9, already on `dev`). The binary is the one built on the VPC from `epigraph` `main` (alongside the existing deploy), so no distribution step.

### 3.8 `--dry-run`
The driver supports `--dry-run`: discover + compute ranges + print the exact `ingest_git` invocations (and pass `--dry-run` through to the ingester) **without** POSTing. Used for validation now (before 2.5 is in prod) and for safe inspection later.

### 3.9 Cron wiring
A crontab entry on the VPC (documented in the spec + a `scripts/` install note), e.g. `*/15 * * * *  /usr/bin/python3 /path/git_ingest_reconciler.py >> /var/log/git-ingest.log 2>&1`. Deploy = place the script + config + token, then add the cron line. **Live enable is the LAST rollout step** (see §7).

---

## 4. Data flow & idempotency
A merged PR is discovered → its commit range computed → ingested. Re-running the same PR (overlapping window, missed cursor, retry) is safe: 2.5 makes repo/PR/commit nodes and author/orchestrator agents find-or-create on `(content_hash, agent_id)` / `public_key`, returning canonical ids. Idempotency alone does not make a time-window driver complete: a PR merged during an outage longer than the window, or one whose ingest failed and aged out of the window, was never ingested. The driver therefore keeps a per-repo cursor and retry list (§5).

---

## 5. Cursor and retry list
*(v1 had no cursor; revised 2026-11-26, backlog 39dfef78.)* Per repo, `<state_dir>/<owner>__<repo>.state.json` (written atomically) holds:
- `cursor`: the start time of the last cycle whose discovery succeeded. The next cycle scans PRs merged since `cursor - window`, so the window is an overlap, not a horizon. A repo-level failure (state, mirror, discovery) keeps the old cursor.
- `retry`: each PR whose ingest failed, with its attempt count and last failure time. Once its backoff has run out (15 minutes after the first failure, doubling after each further one, capped at a day), a cycle fetches it by number (`repos/<slug>/pulls/<n>`) and ingests it, wherever it falls relative to the scan, until it succeeds; a PR found not merged is dropped with a warning. A PR still backing off is neither attempted nor counted as a failure; the cycle logs a warning naming it. This is what makes advancing the cursor past a failed PR safe.
- An unreadable state file fails that repo (no silent restart, which would drop the retry list). A dry run reads the state and writes none.

---

## 6. Error handling
- **Per-PR isolation:** a single PR's ingest failure (non-2xx, parse error) is **logged and put on the retry list** (§5); the batch continues, and later cycles retry it, with a backoff, until it succeeds.
- **Dead-node 409** (from 2.5 §2.5): logged as an operational anomaly (a structural node was superseded — should never happen); does not abort the batch.
- **GitHub/API unreachable:** the cycle logs and exits non-zero; the repo's cursor is kept, so the next cycle catches up.
- **Overlap lock:** a lock file (`flock`) prevents a slow cycle from overlapping the next.
- **Auth failure:** if neither PAT nor `gh auth token` resolves, exit non-zero with a clear message (cron mail / log).

---

## 7. Rollout
1. **Build + unit/integration test** the driver (against a test repo + the API on a test DB). *(Can do now.)*
2. **Dry-run** against `epigraph`'s recent real merged PRs; eyeball the planned invocations + (with `--dry-run` through the ingester) the planned hierarchy. *(Can do now.)*
3. **Gate on 2.5 in prod:** do **not** enable the live cron until Plan 2.5 has been promoted `dev → main` and redeployed (else cross-run find-or-create still 500s). 
4. **Pilot live:** enable the cron for `epigraph` only; watch one interval; verify the repo→PR→commit hierarchy + `resolves` edges + `repo:epigraph-io/epigraph` labels appear and that re-runs don't duplicate.
5. **Expand:** add the other repo slugs to config.
6. **(Optional later)** historical backfill per repo (adjacent task) reuses the same ingester over a full range.

---

## 8. Security
- Read-only GitHub token (PAT or `gh` bearer); **no GitHub write scope**, **no prod write token in any external CI**.
- All graph writes go to `http://127.0.0.1:8080` (localhost, on the VPC) — no public write ingress added.
- The reconciler **reads git metadata + commit messages only**; it never checks out or executes PR code (unlike a self-hosted CI runner) — untrusted-input surface is data, not execution. Commit/PR text fed to the ingester is treated as data.

---

## 9. Testing
- **Unit:** auth-chain resolution (PAT present → PAT; absent → `gh auth token`); merged-PR window filter; **commit-range computation** (2-parent → `M^1..M^2`; 1-parent squash → `M~1..M`); dry-run renders the exact invocation; config parsing; lock behavior.
- **Integration:** point the driver at a throwaway local git repo with a synthetic merged-PR shape + the API on `epigraph_db_repo_test`; assert one ingest call produces the expected `repo→PR→commit` rows and that a second cycle (same window) adds nothing (idempotency end-to-end). 
- **Live dry-run:** against `epigraph` real merged PRs — no writes; inspect planned output.

---

## 10. Open items / dependencies
1. **2.5 → prod** is a hard precondition for live enable (§7.3). 2.5 is on `dev`.
2. `EPIGRAPH_DEFAULT_ORCHESTRATOR_ID` must point to a **registered** agent for PRs lacking the trailer.
3. **Merge strategy:** squash/rebase handling is specified (§3.6) but the pilot (`epigraph`) uses `--merge`; validate other repos' strategies before adding them.
4. Where exactly the driver/config/clones live on the VPC (`/var/lib/epiclaw/git-ingest/…` proposed) is a deploy detail to confirm against the host layout.

---

## 11. Components (for the implementation plan)
1. `scripts/git_ingest_reconciler.py` — config load, auth chain, repo loop, PR discovery, range computation, ingester invocation, logging, lock, `--dry-run`.
2. A config template + a `scripts/` README/install note (cron line, token, state dir).
3. Tests (unit + integration per §9).
4. (Deploy, not code) cron wiring + token provisioning — documented; executed at live-enable after 2.5→prod.
