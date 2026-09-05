# Tenancy: what an "undeclared write" means, and what to do about it

This file exists because migration `070_tenancy_triggers.sql` names it in a
`RAISE WARNING` HINT that operators and developers will actually see:

```
WARNING:  epigraph tenancy: undeclared INSERT INTO claims (id=…). This will
          raise 23502 after migration 074. See docs/tenancy.md.
```

Before PR-12 that path pointed at a file that did not exist.

## The one-sentence version

Every row in a tenancy-partitioned ("tier-A") table carries an explicit
`(visibility, owner_group_id)` pair. `visibility` is `public` or `group`;
`owner_group_id` names the group that owns the row. A write that does not
declare them is **undeclared**, and undeclared is on its way to being illegal.

## Why you are seeing the warning

Migration 062 added the columns with transition `DEFAULT`s — `visibility
'public'` and `owner_group_id` = the *world* group, the all-zero UUID. Those
defaults exist so the columns could be added without rewriting 25 tables or
breaking every existing `INSERT` on the same day.

Migration 070 arm (a) is a `BEFORE INSERT` trigger on `claims` that notices when
a row arrives still carrying the world default. It tries, in order:

1. `supersedes` — inherit the predecessor's tenancy. Without this, superseding a
   private claim silently **declassifies** it.
2. `step_lineage_id` — `evolve_step` inserts a successor without setting
   `supersedes`, linking through the lineage id and an edge instead.
3. Otherwise: bump `tenancy_undeclared_writes` for the table, emit the warning
   above, and let the row through with the default.

Step 3 is deliberately loud and deliberately non-fatal. It is an instrument, not
a gate.

## What changes, and when

| Migration | PR | Effect |
|---|---|---|
| **070** | PR-12 | Warns and counts. Nothing fails. |
| **074** | PR-16 | Drops the defaults and replaces arm (a) with the final, `RAISE`-terminated form. An undeclared insert becomes a hard **`23502` not-null violation**. |
| **077 / 079** | PR-17 | RLS policies, then `FORCE ROW LEVEL SECURITY`. A row you cannot see is absent, not blanked. |

The gate between 070 and 074 is plan §9.2 week **11b**: the
`tenancy_undeclared_writes` counter must be **flat at zero for 24 hours across
every tier-A table**. That is what the `epigraph_tenancy_undeclared_writes`
Prometheus gauge exports (scraped from the internal metrics listener,
`EPIGRAPH_METRICS_ADDR`, default `127.0.0.1:9090`).

> §9.2 has no row labelled "W11". PR-12's *Acceptance* line cites one; the real
> instrument row is week 11b, and the only `W`-prefixed gate in the plan is W10
> (§9.4, pre-RLS).

## What you should do about it

**If you are seeing this from application code:** the write path needs to
declare tenancy. PR-16 patched the thirteen production `INSERT INTO claims`
call sites plus the nine on the parentless root tables, so a warning from a
path other than those is a NEW writer that was added without one — see
[Declaring visibility on write](#declaring-visibility-on-write). Report the
table and the code path; do not add a `DEFAULT`.

**If you are seeing this from a test:** most test fixtures insert claims
directly. Migration 074 arm 4 gives them an escape hatch — as the database role
`epigraph_seed`, an undeclared insert succeeds and yields `('public', <seed
group>)`. That is what the seed group is *for*, and it is why ~160 test
statements do not need rewriting.

**What you must not do** is stamp the seed group from application code, or from
the backfill. Seed has no `group_memberships` rows by design, so a
`('group', seed)` row is a black hole nobody — including its author — can read
back. Migration 062 forbids that pairing outright with
`<table>_group_needs_real_group`.

## Where rows actually get their owner

| Case | Owner |
|---|---|
| Pre-existing rows (the one-shot backfill) | the **author's personal group**, `visibility = 'public'` — plan D2. Those rows were already world-readable, so declaring `public` is a no-op, not a new disclosure. |
| A new claim from an authenticated principal | the principal's declared write target |
| A claim-derived row (`evidence`, `triples`, …) | inherited from the parent claim by 070 arm (c), at insert |
| A visibility change on a claim | propagated to 17 derived tables, `harvester_fragments` and `edges` by 070 arm (d), in the same transaction |
| An edge | the **meet** of its two endpoints, 070 arm (b) |
| A row with no derivable owner (`frames`, `contexts`, `perspectives`, `communities`, `harvester_fragments`, `recall_events`) | **must be declared by the writer.** Before 074 these landed on `('public', world)`; after 074 there is no default to land on. See the next section. |

## Declaring visibility on write

This is the section migration 074's error `HINT` points at. If you got here from
a `23502` whose message begins `epigraph tenancy:`, the write path you are on
did not declare tenancy and the database could not derive it.

Every tier-A table carries two columns, both `NOT NULL` and — from migration
074 — both with **no `DEFAULT`**:

| Column | Values |
|---|---|
| `visibility` | `'public'` or `'group'` |
| `owner_group_id` | a real `groups.id` |

`'public'` under D3 means *any authenticated agent*, not *anonymous*. A public
row still carries a real owner group: `visibility` says who may read it,
`owner_group_id` says who owns it. Pairing `'group'` with the `world` or `seed`
group is refused outright (`<table>_group_needs_real_group`) — both are
memberless by design, so such a row is a black hole nobody, including its
author, can read back.

### Three ways a write can satisfy the requirement

**1. Name both columns.** The normal case for a root row.

```sql
INSERT INTO claims (id, content, content_hash, truth_value, agent_id,
                    visibility, owner_group_id)
VALUES ($1, $2, $3, $4, $5, $6, $7);
```

In Rust this is `epigraph_core::TenancyDecl` — `TenancyDecl::public(group)` or
`TenancyDecl::group(group)` — threaded into the repository call. The type has no
`Default` and no zero-argument constructor, for the same reason `Viewer` has
none: a constructor that needs no argument is a decision nobody made.

**2. Bind a parent the database can read the tenancy off.** This is *preferred*
over restating, because restating invites an accidental downgrade.

| Table | Parent column | Trigger arm |
|---|---|---|
| `claims` | `supersedes` | 074 arm 1 |
| `claims` | `step_lineage_id` | 074 arm 2 |
| the 17 claim-derived tables (`evidence`, `triples`, `claim_versions`, …) | `claim_id` | 074's `epigraph_derived_require_tenancy` |
| `edges` | `source_id` / `target_id` | 072's `epigraph_edges_tenancy` (the endpoint meet) |

**Inheritance is checked even when you also declare.** The parent arms run
*before* the "fully declared" arm, so binding `supersedes` to a group-private
claim and declaring `('public', world)` in the same statement raises `42501`,
not a silent declassification. A declaration may narrow or move a row between
groups; it may never widen it past its parent.

**3. Be a member of `epigraph_seed`.** The escape hatch, and it is for test
fixtures only. An undeclared insert by a member of that role yields
`('public', <seed group>)` rather than raising. It is **role membership**, not a
GUC an application can `SET`, it is keyed on `session_user` (so `SET ROLE` does
not reach it — `SET SESSION AUTHORIZATION` does), it is revocable with one
`REVOKE`, and every row it stamps is greppable:

```sql
SELECT count(*) FROM claims
 WHERE owner_group_id = '00000000-0000-0000-0000-00000000dead'::uuid;
```

Production code must never rely on it. At boot the API **logs a warning** when
its connecting role can take the hatch (`AppState::warn_on_privileged_connection`).
It is a warning and not a refusal today, deliberately: the connecting role is
still `epigraph` — a superuser, which satisfies `pg_has_role` for every role —
so refusing would stop the API booting in CI and in development before the
credential split has happened. PR-17 repoints `DATABASE_URL` (plan §9.2 week
11d) and its acceptance line already owns turning this into a refusal.

### The six tables with no parent at all

`frames`, `contexts`, `perspectives`, `communities`, `harvester_fragments` and
`recall_events` have no `claim_id` and no predecessor, so route 2 does not exist
for them. Their writers declare, or the write raises. In this tree that is nine
production statements, in `repos/community.rs`, `repos/context.rs`,
`repos/frame.rs`, `repos/perspective.rs`, `repos/recall_event.rs` and
`bin/dekg.rs`.

### What you must not do

Do not add a `DEFAULT` back. Do not stamp the seed or world group from
application code. Do not "fix" a `23502` by widening the row to `'public'` when
the caller meant `'group'` — a failed write is recoverable, a disclosure is not.

## Running the backfill

```bash
# 070 MUST be applied first — the backfill relies on arm (d) to propagate to the
# 17 claim-derived tables. The binary refuses to start otherwise.
epigraph-tenancy-backfill run --batch-size 5000

# The deploy pre-flight. Exit code is the guard; it prints offending ids.
epigraph-tenancy-backfill verify
```

It is resumable across a `kill -9`: the `tenancy_backfill_progress` cursor is
committed in the same transaction as its batch.

**It is single-operator.** `FOR UPDATE SKIP LOCKED` is on the batch selection so
a batch does not block behind an unrelated application transaction — it does
**not** make two concurrent operators divide the work. Both processes share one
`last_id`, and the cursor advances to the last id *returned*, so rows a peer had
locked are stepped over. Run one.

**Never run it against production without a restored snapshot to rehearse on.**

### What `run` does, in order

1. `preflight` — refuses to start unless migration 070's
   `claims_propagate_tenancy` trigger exists and is enabled.
2. **Phase 0** — mints a personal group, plus a live membership in it, for every
   claim author that lacks one (migration 057 documents ~1,198 orphan agents
   that have never authenticated).
3. The entity arms: `claims`, `communities`, `perspectives`, `recall_events`,
   `harvester_fragments`.
4. **Legacy `ownership` transcription** — migration 071 installs only an
   `AFTER INSERT OR UPDATE` trigger, so rows already in `ownership` when it
   applied were never transcribed. This pass re-fires the trigger over every
   row that has no `tenancy_transcription_log` entry. Without it `verify` fails
   permanently on any database that had `ownership` rows before 071.
5. `settle_remaining`, then `verify`.

### When the backfill leaves rows behind

`verify` fails and names the offending ids. The usual cause is a claim whose
`agent_id` names an agent that does not exist — `claims.agent_id` has **no
foreign key** to `agents`, so a dangling author is possible and phase 0 (which
joins `agents`) cannot mint a group for it. Those claims are deliberately left
`('public', world)` rather than mis-stamped.

`backfill_claims` detects a non-zero residual and **resets `last_id` to NULL**
so a re-run genuinely retries instead of finding nothing past a stale cursor.
To rewind by hand:

```sql
UPDATE tenancy_backfill_progress SET last_id = NULL WHERE entity = 'claims';
```

Fixing the underlying rows means repointing `claims.agent_id` at a real agent
(or creating the missing `agents` row). Do not stamp them by hand.

### If `verify` complains about function ownership

```
FAIL: public.epigraph_node_tenancy is owned by 'epigraph_app', not 'epigraph_maintenance'.
```

Migrations 070 and 071 skip their `ALTER FUNCTION … OWNER TO
epigraph_maintenance` when that role does not exist, because migration 060 only
`RAISE NOTICE`s if the migration role lacks `CREATEROLE`. The migrations still
report success. Provision `epigraph_maintenance` out of band and **re-apply 070
and 071** (both are idempotent). Deploying past this is not safe: 070's bodies
become RLS-filtered at PR-17 and arm (b) then stamps a private endpoint public,
and 071's shim raises 42501 on every `ownership` write.

## The `ownership` table

`ownership` is the pre-tenancy ACL table. Migration 071 demotes it to a
write-through shim: writing an `ownership` row now **reclassifies** the node and
cascades. It is a compatibility surface with a scheduled death — **PR-14 deleted
its API surface entirely** (`POST /api/v1/ownership`,
`PUT /api/v1/ownership/:node_id`, `GET /api/v1/ownership/:node_id`,
`GET /api/v1/agents/:id/owned-nodes`, and the MCP tools `assign_ownership`,
`update_partition` and `get_ownership`) — and the table is dropped in migration
084.

Since PR-14 **nothing on the read path consults `ownership`**: the tenancy
columns on the row are the sole source of truth. Completing the
`epigraph-tenancy-backfill` transcription pass is therefore a prerequisite of
deploying that release rather than a follow-up — see `docs/tenancy/progress.json`
(PR-12's B5, and M1 under `blocked_measurements`, which sizes the pass).

**Nothing replaces the deleted surface, and that is a capability removal, not a
relocation.** Between PR-14 and PR-16 there is no API and no MCP tool that can
reclassify an existing node. Tenancy is stamped at INSERT — 070's inherit
trigger, and 071's write-through shim for anyone still writing `ownership` — and
no code path updates `claims.visibility` or `claims.owner_group_id` afterwards.
`OwnershipRepository` (`crates/epigraph-db/src/repos/ownership.rs`) is retained
deliberately with **zero production callers** — its only remaining users are the
community-partition tests — until migration 084 drops the table. Do not delete
it as dead code, and do not read its survival as evidence that a write path
still exists.

If you are writing new code, do not write `ownership`.
