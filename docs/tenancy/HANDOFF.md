# Multi-user tenancy — implementation handoff

**Branch:** `feat/multi-user-tenancy` · **Base:** `main` @ `3948445`
**Status as of 2026-08-27.** Nothing pushed. No PRs opened. Everything below is local commits.
**The implementation loop was HALTED after PR-04 by request.** PR-05 was never started.
4 of 22 PRs are landed and independently verified; 18 remain.

This document is the durable record for whoever (human or agent) picks this up next.
It assumes no access to this session's scratchpad, which is ephemeral.

---

## 1. The plan

`docs/tenancy/FINAL-PLAN.md` (committed alongside this file) — 4,205 lines, 22 ordered
PRs. Also published, same content:
https://claude.ai/code/artifact/c5f1163b-6ea6-4b54-a8f0-72e736ad1908

Read §7 (work breakdown) for the PR you are about to do, and §0 for the settled
architecture arguments so you do not relitigate them.

**Read the plan for CONTENTS, `migrations/README.md` for NUMBERS.** The plan's §3.1
numbering is pre-shift and is superseded — PR-04 shipped six migrations where §3.1
allocated three, so everything from the plan's printed 064 onward moved +4, and the
series now ends at 084 in a range reserved 060–090. The authoritative
number-to-PR table lives in `migrations/README.md`; the plan carries a banner
saying so. **PR-05 takes 068 and 069.**

**Architecture in one paragraph.** Tenancy lives on the row (`claims.visibility`,
`claims.owner_group_id`, likewise on `evidence` and `edges`), enforced by a `Viewer`
that is a required parameter with no infallible constructor, whose predicate is emitted
inline into retrieval SQL **above `LIMIT`** so a hidden row is absent rather than
blanked. Postgres `FORCE ROW LEVEL SECURITY` under a separate `epigraph_app` role is the
backstop, landing late (PR-17) behind a boot canary and a one-statement kill switch.
Group-scoped encryption (`seal`) is last and deliberately optional.

## 2. Progress

| PR | Title | State |
|----|-------|-------|
| PR-01 | create the group tenancy tables (migration 060) | **landed** `4f32408` — 3453 pass / 0 fail |
| PR-02 | agents.id for every principal; close both registration gates (061) | **landed** `6429097` — 3634 pass / 0 fail |
| PR-03 | anonymous allowlist, RFC 6750 challenge, unforgeable Viewer (D3) | **landed** `8c70e5a` — 3669 pass / 0 fail |
| PR-04 | tenancy columns, world/seed groups, ScopedPool, resolvable Viewer (062–067) | **landed** `1e310bc` — 3723 pass / 0 fail; discharged PR-03's ignore obligation |
| PR-05 | project communities onto groups; de-overload `ownership.encryption_key_id` | not started |
| PR-06 | visibility predicate required on every claim read | not started |
| PR-07 | derive a Viewer on every HTTP read path | not started |
| PR-08 | authenticate + viewer-filter the structural-features endpoint | not started |
| PR-09 | derive a Viewer on every content-reading MCP tool | not started |
| PR-10 | filter webhook fan-out and federation forwarding by tenancy | not started |
| PR-11 | fail-closed, resource-aware write gate (replaces assign_ownership) | not started |
| PR-12 | batched, resumable tenancy backfill with write-side stamping | not started |
| PR-13 | edge co-ownership so the endpoint meet is expressible | not started |
| PR-14 | delete redaction — a non-visible row is absent, not blanked | not started |
| PR-15 | maintenance DSN for every background writer, before FORCE | not started |
| PR-16 | ownership REQUIRED — drop defaults, arm trigger, validate (D1) | not started |
| PR-17 | RLS policies, FORCE, and a canary that proves it | not started |
| PR-18 | privatization plans, preview, restrict-mode apply (D4) | not started |
| PR-19 | client-side content sealing with entity-bound AAD | not started |
| PR-20 | atomic key rotation gated on a recoverable retired epoch | not started |
| PR-21 | seal mode — client-driven subgraph encryption (D4, second half) | not started |
| PR-22 | retire the `ownership` table | not started (deliberately last) |

## 3. Locked decisions — do NOT reopen

Settled by the repository owner. §0 of the plan carries the reasoning.

| # | Decision |
|---|----------|
| D1 | Ownership is **required**. `public` must be explicitly declared; nothing is public by absence, omission, or default-on-error. Enforce at the **database** layer, not just the repo layer. |
| D2 | Legacy backfill sets **explicit `public`**, owner derived from `claims.agent_id`. Those rows were already world-readable, so declaring it is a no-op, not a new disclosure. |
| D3 | `public` means **any authenticated agent**. Unauthenticated callers get **nothing**. There is no anonymous read path. |
| D4 | There must be an **admin surface to privatize a subgraph** (`restrict` mode, and `seal` mode for encryption). |
| Q1 | `/metrics` → separate internal listener. **Done in PR-03** (`EPIGRAPH_METRICS_ADDR`, default `127.0.0.1:9090`). |
| Q2 | Keep the `epigraph_seed` escape hatch for rollout; delete in a follow-up. |
| Q3 | Proceed past community-as-ACL. `POST /communities/:id/members` performs no authorization today, so nothing legitimately depends on it. |
| Q4 | `allow_all_identities` **fails closed**. **Done in PR-02.** |
| Q5 | `pad_to` default 256. |

**Standing policy for this work:** at any remaining open decision, take the plan's own
recommendation and note it. Do not stall.

## 4. Still blocked — needs a production database

None of these can be answered from a development machine. They are **not** optional;
several gate specific PRs.

| # | Question | Gates |
|---|----------|-------|
| M1 | `ownership` row census | before PR-12; blocks PR-22 |
| M3 | prod `_sqlx_migrations` head — confirm nothing at 060+ | **PR-01's W0 gate, still unperformed** |
| M4 | row counts across the 24 tier-A tables, to size DDL windows | before PR-04 |
| M5 | session-GUC probe against the real cluster topology (pgbouncer?) | blocks PR-04, gates PR-17 |
| M6 | OAuth client `agent_id` coverage must be 100 % | gates PR-03 |
| M7 | partition split `f_group` | gates PR-06 acceptance and the `062b` decision |

**M2 is ANSWERED** (2026-08-27): production runs the pgvector **0.8 series**, so
`hnsw.iterative_scan` is available and R1's primary mitigation is live. Residual: the
exact patch level was not given, and local is pinned to 0.8.6 — do not depend on
anything added in 0.8.1–0.8.6 without confirming prod's patch version.

## 5. Deferred obligations

- ~~**PR-04 owes** an un-ignore of
  `no_anonymous_viewer.rs::resolve_unions_in_the_principals_personal_group`~~ —
  **discharged in PR-04.** The `#[ignore]` is gone and the test has a real body.
- **PR-15 owes** two pool repoints, both prerequisites for PR-17:
  `ScopedPool::unscoped_for_maintenance` must draw from `MAINTENANCE_DATABASE_URL`
  rather than the application pool, and the background `job_pool` in
  `bin/server.rs` must be routed through `ScopedPool` so it gets the
  `after_release` tenancy scrub (keeping its `after_connect` statement_timeout
  hook). Both are commented at their call sites and in `docs/deploy.md` §1c.
- **PR-16 owes** `REINDEX INDEX CONCURRENTLY idx_claims_world_owned;` after the
  backfill. That index is corpus-sized when migration 066 builds it, because
  `owner_group_id` defaults to the world group; the backfill empties it without
  reclaiming pages.
- **PR-06 may want** a substitution helper on `Viewer::predicate_fragment`. It
  ships `{alias}` and `$V` placeholders with no helper, so every call site will
  hand-roll `.replace()` and choose its own positional parameter number.
  Deliberately deferred to PR-06, where the first real call sites exist to
  design against.

## 6. Rebuilding the development environment

This machine had **no Docker, no Homebrew, no Postgres and no admin rights**. What
follows is a working recipe; each step exists because the obvious approach fails.

```bash
python3 -m venv venv && ./venv/bin/pip install pgserver          # bundles PostgreSQL 16.2
BIN=$(./venv/bin/python -c "import pgserver,pathlib;p=pathlib.Path(pgserver.__file__).parent;print(list(p.rglob('bin/psql'))[0].parent)")
export PATH="$BIN:$HOME/.cargo/bin:$PATH"
initdb -D <datadir> -U postgres --auth=trust -E UTF8
# TCP-ONLY: a long datadir path exceeds Postgres's 103-byte unix-socket limit
pg_ctl -D <datadir> -o "-p 55432 -c listen_addresses=127.0.0.1 -c unix_socket_directories=''" -l <datadir>/pg.log start
createdb -h 127.0.0.1 -p 55432 -U postgres epigraph_db_repo_test
export DATABASE_URL="postgresql://postgres@127.0.0.1:55432/epigraph_db_repo_test"
cd <repo> && sqlx migrate run --source migrations
```

### The four traps

1. **Unix socket path length.** See the TCP-only flags above. Without them the server
   refuses to start with a message about socket path length.
2. **`pg_config --cppflags` carries a hardcoded `-isysroot`** pointing at the pgserver
   build machine's Xcode, which does not exist locally. Every extension build needs
   `make USE_PGXS=1 CPPFLAGS="-isysroot $(xcrun --show-sdk-path)"`.
3. **The bundle ships no contrib.** `pg_trgm` must be **compiled from matching
   PostgreSQL source** — migration 001 creates gist/gin trigram *indexes*, which need
   real operator classes, so a fake extension does not work.
   `uuid-ossp` **can** be shimmed (functions only, no operator classes).
   Without `pg_trgm`, every `#[sqlx::test]` in the repo fails, because `sqlx::test`
   applies migrations unfiltered.
4. **Apply migrations only with `sqlx migrate run`.** `psql` does not populate
   `_sqlx_migrations`, after which every test calling `sqlx::migrate!` re-applies them
   and fails on duplicate objects. It presents as an unrelated pre-existing failure.

**Fidelity check that the environment is trustworthy:** `cargo sqlx prepare --workspace
-- --tests` must leave `.sqlx/` with **zero** diff. That passed here, which is the proof
the local schema matches the one the committed query cache was built against.

pgvector: **done — local is 0.8.6**, matching production's 0.8 series. Built from source
the same way as `pg_trgm`, then `ALTER EXTENSION vector UPDATE` (the 0.6.2 → 0.8.6
upgrade chain ships with the install, so it is in-place, not a rebuild). `template1`
never carried the extension here, so `#[sqlx::test]` databases pick up 0.8.6 from the
migration's own `CREATE EXTENSION` — but check that assumption on any other machine.
`SET hnsw.iterative_scan = 'relaxed_order'` is verified working locally.

**The bump was verified non-breaking:** the full workspace suite returned identical
numbers before and after (3723 passed / 0 failed / 68 ignored on both 0.6.2 and 0.8.6).
Worth re-checking on any future pgvector move, since a major bump touches operator
classes and index AM behaviour.

## 7. How the work was being driven

A per-PR workflow (`analyze` + `blast-radius` → `implement` → `verify` → `correctness`
and `conformance` critics → `land`), committing **only** when green: fresh-database
migration apply, idempotent re-apply, `cargo check --workspace --all-targets`,
`cargo sqlx prepare`, `cargo test --workspace`, `cargo clippy`, and every acceptance
criterion in the PR's spec. Commit messages follow CLAUDE.md's Epistemic Commit Protocol.

## 8. Verification discipline — read this before trusting any automated step

**A subagent reported PR-01 as green while PR-01's own new test suite failed all five
of its cases.** The cause was environmental rather than a code defect, but it was
reported green regardless. In a sequential loop a single false green propagates into
every later PR.

Re-verify independently after any agent claims success:

```bash
SQLX_OFFLINE=true cargo check --workspace --all-targets
cargo sqlx prepare --workspace -- --tests && git status --porcelain .sqlx   # expect 0
cargo test --workspace
git diff <prev-sha>..HEAD -- '*.rs' | grep -E '^\+\s*#\[ignore'            # expect none, or labelled
```

Compare **per-suite** ignored counts between runs, not just the total: a total can hold
constant while one test is added and another silently disabled. That happened here
legitimately (PR-03 added one labelled obligation while an unrelated conditional skip
began running) — but only a per-suite diff shows it.

## 9. Immediate next steps

1. **Perform M3 before anything merges.** PR-01's W0 gate requires confirming prod's
   `_sqlx_migrations` has nothing at 060 or above. **Eight migrations (060–067) are already
   written against that assumption.** If production holds anything at 060+, all eight need
   renumbering before this branch can merge. This is the single highest-risk open item.
2. Start at **PR-05** (`feat(db): project communities onto groups, de-overload
   ownership.encryption_key_id, and classify every entity type`), spec in the plan's §7.
3. `stash@{0}` holds an abandoned, unverified partial PR-04 from an interrupted run
   (its own migrations 062–068, numbered differently from what actually landed). It is
   superseded and **should be dropped**: `git stash drop`. Inspect first with
   `git stash show -p stash@{0}` if curious.
4. Local pgvector was upgraded 0.6.2 → **0.8.6** to match production's 0.8 series;
   `hnsw.iterative_scan` is available locally and verified working.
