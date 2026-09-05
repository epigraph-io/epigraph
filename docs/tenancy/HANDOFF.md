# Multi-user tenancy — implementation handoff

**Branch:** `feat/multi-user-tenancy` · **Base:** `main` @ `3948445`
**Status as of 2026-08-27.** Nothing pushed. No PRs opened. Everything below is local commits.
**5 of 22 plan PRs are landed and independently verified; 17 remain.** PR-06 is in
progress. A weekly usage limit briefly killed an earlier PR-06 attempt on 2026-08-29
(5 of 7 agents lost mid-run, 228-file partial parked in `stash@{0}`, unverified); the
quota then refreshed and the PR was relaunched from its cached analyze phase.
**Lesson worth keeping:** do not compute a quota block's duration from the reset string
and a clock reading — if the session is executing at all, capacity exists. Just retry.

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
| PR-05 | project communities onto groups; de-overload `ownership.encryption_key_id` (068–069) | **landed** — sha recorded by the next docs pass, as PR-04's row was by `40c04d3`. 3763 pass / 0 fail / 68 ignored (PR-04 baseline 3723). New files: `tenancy_coverage.rs` (16/16) and `community_partition.rs` (10/10); `routes::admin::db_tests` grew to 11/11, `locked_decisions.rs` to 4/4, and `read_path_authz_test.rs` gained the HTTP community case. First-ever coverage of the `community` partition arm, on both the MCP and HTTP surfaces |
| PR-06 | visibility predicate required on every claim read | in progress (relaunched after a transient quota failure) |
| PR-07 | derive a Viewer on every HTTP read path | not started |
| PR-08 | authenticate + viewer-filter the structural-features endpoint | not started |
| PR-09 | derive a Viewer on every content-reading MCP tool | not started |
| PR-10 | filter webhook fan-out and federation forwarding by tenancy | not started |
| PR-11 | fail-closed, resource-aware write gate (replaces assign_ownership) | **done** (`db5dc422`, PR #422). Row corrected by PR-14: it read "not started" while `progress.json` had PR-11 in `prs.done`, and PR-14's own entry describes deleting PR-11's four gated call sites. Note what that leaves: `PolicyGate::authorize` has **no production caller** between PR-14 and PR-16, and the three call-site lints went with the sites — `D-PR16-reestablish-the-write-gate-call-site-lint`. `GroupPolicyGate` is still installed at all six `AppState` and both `EpiGraphMcpFull` constructors, pinned by `state.rs::the_default_gate_is_installed_at_every_constructor` and (added by PR-14) `epigraph-mcp/src/server.rs::the_default_gate_is_installed_at_both_mcp_constructors` |
| PR-12 | batched, resumable tenancy backfill with write-side stamping | **done** (migrations 070/071, `epigraph-tenancy-backfill`) |
| PR-13 | edge co-ownership so the endpoint meet is expressible | **done** (migrations **072/073**, not the plan's 068/069; `Viewer::edge_predicate_fragment` + the `/* {EDGE_VISIBILITY:…} */` marker; `DbError::CheckViolation` → 400). Closes 070 arm (b)'s cross-group `RAISE`, which 071's transcription had made reachable. Residual it does NOT fix: an edge stamped `('group', G, co_owner = NULL)` **before** 072, whose endpoints later diverged into different groups, is not reconciled by 072 and stays visible to all of G — `epigraph-tenancy-backfill verify` now fails on that shape (`D-PR18-stale-cross-group-edges`) |
| PR-14 | delete redaction — a non-visible row is absent, not blanked | **done** (code-only, no migration). Deletes `epigraph-db/src/access_control.rs`, **its `epigraph-api` re-export shim** (which also owned `redact_claim_content` — the plan's *Files* line named only one of the two), `epigraph-mcp/src/tools/redaction.rs` (taking `mcp_requester` with it), `routes/ownership.rs` (4 routes × 2 `create_router` variants) and **three** MCP tools — `assign_ownership`, `update_partition` and `get_ownership`; the plan named two. **Three `edges.rs` handlers were converted BEFORE the deletion, not after**: `get_evidence`, `claim_provenance` and `evidence_by_relationship` read raw viewerless SQL and `check_content_access` was their ONLY control, so deleting it without moving them behind a `Viewer` would have widened access rather than tidied it. All four of `edges.rs`'s counted inline reads now live in the repo layer (`viewer_route_table_lint` `edges.rs` 4 → 0). Ratchets moved: `EXPECTED_TOOLS_WITHOUT_A_VIEWER` 20 → 19, `#[tool(` 86 → 83, `SCOPE_MAP` −3 entries + 1 assertion, `COMPENSATED_INLINE_READS` retired → `TEST_ONLY_INLINE_READS`. Closes `F-access-control-none-full`, `F-coarse-edge-types-reexport-shim`, `F-PR11-ownership-reads-are-an-owner-oracle`; moots `F-PR11-ownership-upsert-is-check-then-act`. **Breaking** (announce with PR-03's RAG revocation): a caller that received `200` + `"[REDACTED]"` now receives an absence. **Deploy prerequisite**: the read path no longer consults `ownership`, so run `epigraph-tenancy-backfill` to completion first (`D-PR14-transcription-is-a-deploy-prerequisite`). **Left dormant for PR-16**: `PolicyGate::authorize` has zero production callers and the three write-gate lint files were deleted — `D-PR16-reestablish-the-write-gate-call-site-lint` |
| PR-15 | maintenance DSN for every background writer, before FORCE | **done** (code-only; `migrations/README.md` reserves no number for it). Corrects the plan on counts: **27** bin files, not 26, and the work list was **23** DB-touching bins, not 14. The scope recon's "Group B — already on the template, DO NOT TOUCH (9)" was wrong at the pool level — all nine bound a bypass `Viewer` from a `ScopedPool` they discarded and then ran every query on a raw `epigraph_cli::db_connect()` pool, i.e. the same privileged-viewer/ordinary-pool hybrid the recon flagged in only two. `epigraph_cli::db_connect` and `maintenance_pool_and_viewer` are **deleted**; `epigraph_cli::MaintenancePool` replaces both. It *improves* the old template's lifetime handling — the `MaintenanceConn` is returned to the caller instead of being dropped inside the constructor, and every converted bin binds it for the whole run — but does **not** discharge the obligation: the `Viewer` is still owned and outlives its lease, so the coupling is a convention, not a type-level guarantee (`D-PR17-maintenance-lease-coupling-is-a-convention`). `SystemReason` is taken by `MaintenancePool::viewer`, not by `connect`, so the twelve bins that need a privileged *connection* and never spend a viewer mint none — which is why `viewer_ratchet.rs`'s monotone bound of 10 was never in play. New lint `crates/epigraph-db/tests/no_unmaintained_dsn.rs`, keyed on pool CONSTRUCTION rather than the plan's `DATABASE_URL` axis (which passes vacuously on the clap-`env=` spelling and on any partial conversion); it cannot see the INJECTED-pool form of the same hybrid (`D-PR17-hybrid-shape-lint`). The boot probe keys on `relrowsecurity OR relforcerowsecurity`, **not FORCE alone**: a policy filters every non-owner without `BYPASSRLS`, and every protected table is owned by the superuser, so ENABLE is the operative arming signal for this fleet — FORCE-only would be disarmed through PR-17's own policies-before-FORCE window and after its `NO FORCE` kill switch. Two *Files*-line deviations, recorded because the plan prescribed files that do not exist: the shared constructor landed in `crates/epigraph-db/src/pool.rs` + `crates/epigraph-cli/src/lib.rs`, **not** the plan's new `crates/epigraph-jobs/src/pool.rs` and `crates/epigraph-cli/src/pool.rs` (`epigraph-jobs` has no binary and no pool constructor, and a second `epigraph-cli` pool module would fork the existing template); and the deploy checklist landed in `docs/deploy.md` §1c-bis/§1c-ter because **no `docs/runbooks/` directory exists** in this tree. Deliberately NOT done: `epigraph-mcp`'s three maintenance tools stay fail-CLOSED — see §5 |
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
| M4 | row counts across the **25** tier-A tables, to size DDL windows | before PR-04 |

> **M4 said 24; it is 25.** Migration 062's `tier_a` array has 25 entries and
> seeds exactly 25 rows into `tenancy_backfill_progress` (verified:
> `SELECT count(*)` = 25). An implementation built against 24 leaves one entity
> permanently `complete = false` and `epigraph-tenancy-backfill verify` fails
> forever. Corrected by PR-12.

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
- ~~**PR-15 owes** two pool repoints~~ — **both discharged in PR-15.**
  `ScopedPool::unscoped_for_maintenance` draws from an attachable maintenance
  pool (`ScopedPool::with_maintenance_pool`), and the `job_pool` is built by the
  new `ScopedPool::connect_with_options` so it keeps both the `after_release`
  scrub and its `after_connect` statement_timeout. See `docs/deploy.md` §1c-bis
  for the operational surface.
- **PR-17 owes** the `epigraph-mcp` maintenance wiring PR-15 deliberately left
  closed. `EpiGraphMcpFull::with_scoped_pool` has zero callers, so
  `sweep_semantic_duplicates`, `recompute_beliefs` and `backfill_embeddings`
  currently fail with a clear error. Attaching a `ScopedPool` alone would make
  it *worse*: the three tools query `self.pool`, so they would mint a privileged
  viewer and spend it on an application connection — the hybrid PR-15 removed
  from eleven CLI binaries — turning a hard error into a silent no-op under
  FORCE. The fix is to move those three tools' queries onto the maintenance
  connection. Reasoned at `crates/epigraph-mcp/src/maintenance.rs` and pinned as
  an exemption in `no_unmaintained_dsn.rs`.
- **PR-17 owes** `GRANT epigraph_maintenance TO epigraph_admin` as a deploy
  runbook step (no migration), **together with the api job path's table
  grants**. `epigraph_maintenance` is NOLOGIN and `epigraph_admin` is not a
  member, so today no non-superuser role both connects and satisfies
  `epigraph_bypass()`. This is also what blocks the two-role form of PR-15's
  acceptance — see the note in
  `crates/epigraph-cli/tests/backfill_idempotence.rs`. The grants half matters
  because PR-15 moved the api's background job pool onto the maintenance DSN and
  `assert_maintenance_privilege` probes bypass and row security but **not**
  table privileges; CI connects as the superuser, so nothing in the suite
  exercises the role switch.
- **PR-17 owes** the type-level coupling of a bypass `Viewer` to its
  `MaintenanceConn` (`D-PR17-maintenance-lease-coupling-is-a-convention`).
  `MaintenancePool::viewer`, `AppState::maintenance_viewer` and
  `epigraph_mcp::maintenance::maintenance_viewer` all return an owned `Viewer`
  whose `MaintenanceLease` drops at return, so a caller can drop the connection
  and keep a predicate-suppressing viewer. Every call site in the tree binds
  both; nothing enforces it.
- **PR-17 owes** a second lint keyed on the HYBRID SHAPE rather than on pool
  construction (`D-PR17-hybrid-shape-lint`). `no_unmaintained_dsn.rs` fires on a
  file that *builds* an unmaintained pool; it is blind to a file that builds
  nothing, mints a bypass viewer, and runs the statement on an injected
  `PgPool`. Calibration cases: `epigraph-jobs/src/db_reputation_service.rs::get_claim_outcomes`
  (still has the shape; no production constructor) and
  `epigraph-api/src/routes/claims.rs::find_claims_needing_embeddings` (had it,
  fixed in PR-15 by making the repo method executor-generic).
- **PR-17 owes** an answer on DERIVED-ROW visibility. `ClusterGraphHandler` and
  `ThemeClusterRebuildHandler` now run on the maintenance DSN with no `Viewer`
  at all, and they persist rows computed over group-private claims. What
  `owner_group_id` / `visibility` migration 067's stamping triggers put on those
  rows, on a bypass connection with no session GUCs, is currently nobody's
  stated decision. "Derived rows inherit the meet of their inputs' visibility"
  is the property that needs a test in `rls_enforcement.rs`; no test in PR-15
  touches it.
- **PR-16 owes** `REINDEX INDEX CONCURRENTLY idx_claims_world_owned;` after the
  backfill. That index is corpus-sized when migration 066 builds it, because
  `owner_group_id` defaults to the world group; the backfill empties it without
  reclaiming pages.
- **PR-17 owes** `security_invoker = true` on `public.alternative_set` and
  `public.alt_set_decisions` in migration 077 — or a `DROP VIEW`. Both are
  `relkind = 'v'` with the option UNSET, so after 079's `FORCE ROW LEVEL
  SECURITY` they execute as the view OWNER and bypass the invoker's policies
  entirely: `alt_set_decisions` returns `belief`, `plausibility` and
  label-derived state for claims the caller cannot read. Discovered in PR-05,
  not in the plan. Recorded in their `tenancy_exempt.residual` text and pinned
  by `tenancy_coverage.rs::the_two_view_exemptions_are_still_security_definer`,
  which INVERTS when PR-17 discharges it. Two in-tree tests already query these
  views (`crates/epigraph-api/tests/alt_set_decisions_view_test.rs`,
  `alternative_set_view_closure.rs`).
- **PR-16 or PR-18 owes** promoting five content-bearing tables to tier A before
  privatization ships. Migration 069 exempts them **under protest**, because
  giving them tenancy columns now would grant coverage that migrations
  070/074/077 do not extend to — worse than a stated exemption. Each carries
  real claim-derived plaintext: `experiments.protocol` /
  `protocol_source`, `counterfactual_scenarios.scenario_a` / `scenario_b`,
  `learning_events.lesson` / `resolution`, `match_candidates.verifier_rationale`
  (whose `(claim_a, claim_b)` pair is itself a near-duplicate oracle over the
  private corpus), and `behavioral_executions.goal_text` / `goal_embedding`.
  This is exactly the failure class the plan's §12 summary names — *"a derived
  table nobody listed keeps the plaintext public after privatization"*. The
  registry CATCHES it; it does not CLOSE it. All twelve `tenancy_exempt` rows
  carry `reviewed_by = 'PENDING'`, which is honest — nothing in PR-05 could
  cause a review — but it means the registry's "named reviewer" property is
  currently unmet for every row. `tenancy_coverage.rs::
  tenancy_exempt_rows_state_a_residual` ratchets that count DOWNWARD (a review
  lowers it; a thirteenth unreviewed exemption fails the build). **Reviewing
  those five is the gate this bullet names.**
- **PR-12 owes** ongoing community→group projection, in BOTH directions.
  **DONE in PR-12** — `CommunityRepository::create` now projects the `groups`
  row (plus its epoch-0 `group_key_epochs` row, and an `admin` membership when a
  creator is known), `add_member` projects a `role='reader'`
  `group_memberships` row, and `remove_member` sets `revoked_at` — guarded by a
  `NOT EXISTS` so removing one of an agent's two perspectives does not cut
  access the other still justifies. Covered by the NEW
  `crates/epigraph-db/tests/community_projection.rs`, which goes through the
  REPOSITORY rather than replaying 068, and so can actually observe the drift.
  The `create` projection is load-bearing rather than tidy — but **not** for the
  reason an earlier revision of this bullet gave. It said migration 071's shim
  "resolves a `community` partition through the projected group" and implied it
  fails if the group is absent. It does not: 071 INSERTs the group on demand,
  replays 068's membership projection, and falls through to the owner's personal
  group when no live membership results. The real reason is that the projection
  is a standing invariant `tenancy_coverage.rs` structurally cannot observe
  (it replays 068 before asserting), so without `create` projecting, the
  invariant breaks on the first `POST /api/v1/communities` and 071 papers over
  it with `created_by_agent_id` NULL — 068's zero-administrator dead end.

  **MEMBERSHIP IS NOW CLOSED, and that is a security fix PR-12 owed because
  PR-12 caused it.** `POST /api/v1/communities/:id/members` had no authorization
  (`F-PR11-community-membership-is-self-service`). Before PR-12 the consequence
  lived only in `check_content_access`'s community arm, which PR-14 deletes;
  projecting the membership moves it into the control plane that SURVIVES PR-14
  and that PR-17 arms, so a stranger could create a perspective, POST it into
  any community, and read that community's private corpus. `add_member` and
  `remove_member` now require the acting agent to hold a live membership in the
  community's projected group (bootstrap exception when the group has none;
  `remove_member` additionally always permits removing your own perspective),
  and the DELETE handler — which previously extracted nothing at all — now takes
  a `ViewerExtractor`. Full route-level authorization is still PR-16's.
  Original description follows.
  Migration 068's projection is a **one-time snapshot**:
  - `CommunityRepository::create` and `add_member`
    (`crates/epigraph-db/src/repos/community.rs:42,110`) still write only
    `communities` / `community_members`, so any membership added through
    `POST /communities/:id/members` after 068 produces no `group_memberships`
    row until PR-12's write-side stamping triggers land. That is the plan's R7.
  - **`remove_member` (`:144`) is the permissive half and is NOT in the plan.**
    It deletes the `community_members` row and does not set `revoked_at` on the
    corresponding `group_memberships` row, so the two membership models drift in
    the direction that GRANTS: an agent removed from a community keeps its
    projected group membership and, at PR-17, keeps read access to the group's
    private corpus. The projection is least-privilege (`role = 'reader'`), which
    bounds the damage, but it does not remove it.

  `tenancy_coverage.rs::every_community_projects_onto_a_group_and_its_members_onto_memberships`
  seeds and then REPLAYS 068 before asserting, so it tests the migration's
  output and is structurally incapable of observing either drift. Its doc
  comment says so; do not read it as coverage of this gap.
- **PR-12 or PR-18 owes** an administrator for every projected community group.
  **PARTIALLY DONE in PR-12** — `CommunityRepository::create` takes an
  `Option<Uuid> created_by_agent_id`, sets `groups.created_by_agent_id` from it
  and gives that agent a live `admin` membership. `POST /api/v1/communities` now takes a
  `ViewerExtractor` and passes `Viewer::principal()`, so a community created
  through the route has a live admin from the moment it exists. (That route is
  already on the PROTECTED router, so the extractor changes who the creator IS,
  not whether the route is reachable, and `community.rs` appears in neither of
  `viewer_route_table_lint.rs`'s registers.) It is **NOT** closed for the
  communities migration 068 already projected — `communities` has no creator
  column to derive one from — so **still open for PR-18** for those.
  Original description follows.
  Migration 068 projects members as `reader` and leaves
  `groups.created_by_agent_id` NULL (`communities` has no creator column to
  derive one from), so a projected group has **zero admins**: `POST
  /groups/:id/members` can never be used on it, and PR-18's "≥2 other live
  admins" precondition is unsatisfiable by construction. Deliberate — inventing
  an admin from `community_members`, which attests read eligibility only, would
  be worse — but it must be discharged before those PRs rely on it.
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
2. Start at **PR-06** (`feat(db): make the visibility predicate a required parameter
   on every claim read`), spec in the plan's §7. PR-05 landed migrations 068–069; the
   live `_sqlx_migrations` head is now **69**, and
   `crates/epigraph-api/tests/migrate_on_startup.rs::MIGRATION_HEAD` was bumped with it.

   **Deploy ordering for PR-05 — MIGRATIONS FIRST. Apply 068 and 069 BEFORE the
   PR-05 binary rolls.** `EPIGRAPH_MIGRATE_ON_BOOT` is default-off (PR-01), so
   this ordering is operator-controlled, not automatic. Both directions have
   teeth, and the binary-first direction is the severe one:

   - **Binary before migrations (DO NOT):** `EntityTypeRepository::list_all`
     now selects `tenancy_tier`, and `AppState::load_entity_type_cache`
     (`crates/epigraph-api/src/state.rs:575`) is `.expect()`ed at
     `crates/epigraph-api/src/bin/server.rs:372`. **The API panics on every
     boot** until 069 lands. That fails closed and loudly, which is the right
     failure, but it is an outage. The MCP server does not load that cache and
     boots fine — and would then hit a missing `ownership.community_id` on
     every read; `check_content_access` was hardened in this PR to REDACT on a
     query error rather than treat it as "no ownership row, therefore public",
     so that window degrades to over-redaction instead of disclosure.
   - **Migrations before binary (the correct order, with one cost):** 069 drops
     `entity_types.tenancy_tier`'s DEFAULT, so any `INSERT INTO entity_types`
     omitting the column raises 23502. `EntityTypeRepository::upsert_non_core`
     is the only in-tree writer and is fixed in the same commit, so the cost is
     that **entity-type registration is broken for the length of the roll** —
     a narrow, recoverable window, unlike the panic above.

   This inverts the code-first-then-migration ordering the plan prescribes for
   PR-16. That is intended here: PR-16's ordering protects a data migration,
   PR-05's protects a startup invariant.

   **Release-note item for PR-05.** `POST /api/v1/admin/entity-types` is now
   strictly more restrictive in two ways at once: `tenancy_tier` is a required
   body field (an existing client omitting it gets 400), and
   `tenancy_tier='columns'` is refused for **every** table until PR-17 lands —
   measured at head 069, `relforcerowsecurity = false` and zero `pg_policy` rows
   on every table in the schema, `claims` included, because RLS is PR-17's
   migrations 077/079. The `columns` tier is therefore write-locked through the
   API for the whole PR-05 → PR-17 window. Intended (the six seeded `columns`
   types are `is_core = true` and the hijack guard 403s them first), but it must
   be stated.

   Two smaller wire changes in the same release. `GET/POST /api/v1/ownership`
   returns a new REQUIRED `community_id` field, and
   `POST /api/v1/admin/entity-types` a new REQUIRED `tenancy_tier` field; the
   DEPRECATED `encryption_key_id` is retained on the `ownership` response (now
   always `null` for anything the handler writes) purely so an existing
   deserializer does not break, and is dropped with the column in 084. The
   wire-compatibility argument is therefore applied to the field being REMOVED
   and not to the fields being ADDED — deliberate, because a strict client
   breaks on an unknown field either way and the added fields are the point of
   the change, but it is an inconsistency worth naming in the release note.

   `PUT /api/v1/ownership/:node_id` also now clears `encryption_key_id`
   alongside `community_id`. On a database still holding a pre-068 non-UUID
   value, the previous behaviour would have raised 23514 from the `NOT VALID`
   `ownership_key_id_is_uuid` CHECK (Postgres re-checks the whole new row
   version even when the constrained column is untouched) and returned a 500.
3. `stash@{0}` holds an abandoned, unverified partial PR-04 from an interrupted run
   (its own migrations 062–068, numbered differently from what actually landed). It is
   superseded and **should be dropped**: `git stash drop`. Inspect first with
   `git stash show -p stash@{0}` if curious.
4. Local pgvector was upgraded 0.6.2 → **0.8.6** to match production's 0.8 series;
   `hnsw.iterative_scan` is available locally and verified working.
