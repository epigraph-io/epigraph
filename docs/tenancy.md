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
| **080 / 082 / 083** | PR-18a | The D4 privatization schema and the `instance_admins` authority. **These are additional FORCE sources.** 079 is applied and immutable, so each of them `ENABLE`s and `FORCE`s the tables it creates, on the precedent 078 set for `rls_canary`. The FORCE-protected set grows **35 → 39**; see the kill switch below. |

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

## Row-level security, and who may declassify (PR-17)

Migrations 077/078/079 install the RLS policy set, the canary table, and
`FORCE ROW LEVEL SECURITY`.

**Enforcement begins at 077, not at 079.** In PostgreSQL a policy filters every
role except the table's *owner* and holders of `BYPASSRLS`; `FORCE` only
*additionally* subjects the owner. Every protected table is owned by the
superuser `epigraph`, and `epigraph_app`, `epigraph_admin` and
`epigraph_maintenance` are all non-owners without `BYPASSRLS`. So from 077
onward the policies already filter every role the application and the job fleet
connect as. 079 closes the remaining owner hole and is the terminal, gated step.

The corollary is what makes the migrations safe to land ahead of the credential
split: while `DATABASE_URL` still names the owning superuser, **all three
migrations are observably inert**. The risk lives in deploy step 11d, not in
the schema change.

### The kill switch

`ALTER TABLE … NO FORCE ROW LEVEL SECURITY`, scripted at
`docs/runbooks/079-undo.sql`. Instant, no rewrite, no data change; paired with
reverting `DATABASE_URL` to the owner role it is a sub-minute rollback. The
undo script loops the *same array* as `079_rls_force.sql`, because
`AppState::assert_rls_posture` refuses to boot on a **partially** FORCEd set —
a half-applied undo would leave the cluster un-bootable.

**From PR-18a the undo script is LONGER than 079's array, and a stale copy is
unsafe.** 079 could not name the four privatization tables — they did not exist
— so 080/082/083 FORCE their own. The boot assertion counts the **catalog**, not
079, so it now expects **39** protected relations while a pre-18a copy of
`079-undo.sql` un-FORCEs only 35. That leaves `0 < forced < protected`, which is
exactly the partial state `rls_verdict` refuses on: the sub-minute rollback
becomes an outage. Run the copy of the script that ships in the tree you are
rolling back, and use the VERIFY query at the foot of it — it is total over the
protected set and reports a partial flip.

### `epigraph.allow_declassify` — what actually controls it

Migration 074's `epigraph_claims_block_widening` refuses an UPDATE that widens a
claim from `group` to `public` unless the session GUC
`epigraph.allow_declassify` is set. PR-17 owns writing down who may set it, and
the honest answer is **nobody is stopped by the database**:

* `REVOKE SET ON PARAMETER "epigraph.allow_declassify" FROM PUBLIC` returns
  `REVOKE` and **records no `pg_parameter_acl` row** — a silent no-op. Measured
  on PostgreSQL 16.13.
* Even with an explicit `pg_parameter_acl` row granting `SET` to one role, a
  session that has `SET ROLE`d to another still sets it successfully.
  Customized (placeholder) GUCs are `PGC_USERSET`, and parameter ACLs do not
  gate them.
* The `REVOKE EXECUTE` in `074_tenancy_required.sql` applies to the **trigger
  function**, not to the GUC. It is frequently miscredited with restricting the
  GUC; it does not.

So the control on declassification is **not** a `GRANT`. It is:

1. **The trigger itself**, which is unconditional for a *sealed* claim — arm (a)
   refuses `sealed ⇒ public` and the GUC deliberately does not reach it.
2. **Reaching the statement at all.** Under 077 an UPDATE of a claim the session
   cannot see matches zero rows, so declassifying somebody else's private claim
   is not available regardless of the GUC.
3. **`security_events`**, which is append-only by default-deny.

**Treat `epigraph.allow_declassify` as a safety interlock against an accidental
widening, not as an authorization boundary.** A code path that sets it is
asserting "this widening is intended", and the authorization for that decision
has to be made in the repo/route layer above it. PR-18's privatization surface
is where a real approval boundary appears.

#### The same reasoning applies to the three TENANCY GUCs, and that is the more important half

`epigraph.allow_declassify` is the GUC PR-17 was asked to write down, but nothing
above is specific to it. `epigraph.group_ids`, `epigraph.writable_group_ids` and
`epigraph.principal_id` are customized GUCs too, therefore `PGC_USERSET` too,
therefore settable by any session — measured: as `epigraph_app` a session can
`SET epigraph.principal_id` to an arbitrary uuid and `epigraph_principal_id()`
returns it. Since the entire policy set in 077 keys on those three functions,
**the confidentiality of the corpus rests on GUCs that the database does not
protect.**

The control is therefore not a `GRANT` here either. It is that **no code path
interpolates untrusted input into a `SET`**: `apply_session_gucs` is private,
takes the `&Viewer` itself, has exactly two callers (`acquire_as`, `begin_as`),
and binds from `Viewer::resolve`'s output rather than from a request. That is a
structural convention, not a boundary, and it should be read as one.

This is latent rather than live today — nothing in the tree sets those GUCs from
user input, and `acquire_as` has no request-path callers at all — but the natural
reading of the `allow_declassify` conclusion above is that the tenancy GUCs are
different in kind. They are not. Recorded as
`D-PR17-tenancy-gucs-are-pgc-userset`.

## What rotation and member removal actually revoke (PR-20)

Two operations in this system are commonly read as "revoke access", and they do
two different things. Neither does what the phrase implies.

**Removing a member** (`DELETE /api/v1/groups/:id/members/:agent_id`) sets
`group_memberships.revoked_at`. From the removed agent's *next request* onward
they resolve to a `Viewer` without that group, so RLS and the in-query predicate
both stop returning the group's rows to them. Membership is deliberately not in
the JWT, so this is immediate rather than "when the token expires". That half is
strong.

**Rotating the key** (`POST /api/v1/groups/:id/rotate`) retires epoch N, creates
epoch N+1 and re-wraps the new key for every live member, in one transaction. It
does **not** re-encrypt anything. Every `claim_encryption` row stays bound to the
epoch it was sealed under, through `claim_encryption_epoch_fkey`. Retired epochs
are kept, and the revoked member's `group_memberships` row is kept too, with its
`wrapped_key_share` intact.

So, stated plainly, and this is the sentence to quote when someone asks:

> A member removed at epoch N who kept their share can decrypt every claim sealed before the rotation, forever. Rotation gates only future ciphertext.

The same sentence is returned in the body of every successful rotation, and in
the `side_effects.revocation` field of a privatization plan preview. It is one
constant in the source (`epigraph_api::tenancy_disclosure`) with a test asserting
all three copies agree, because a disclosure that drifts is a disclosure that
stops being read.

### What follows from that

A removal therefore leaves a **debt**, and the system records it rather than
pretending otherwise:

- `groups.reseal_required_at` is set on the first unrotated removal. It is not
  reset by later removals — the debt dates from when it was incurred — and it is
  surfaced on `GET /api/v1/groups/:id`. Both removal paths record it:
  `DELETE /api/v1/groups/:id/members/:agent_id` and
  `DELETE /api/v1/communities/:id/members/:perspective_id`, the second of which
  revokes a projected group membership and so leaves exactly the same debt.
- The group's current key epoch moves to `status = 'rotating'`. This is a mark,
  not a shutdown: the group keeps accepting members and sealing new claims under
  that epoch until an admin rotates. That has a forward cost, and it is the
  deliberate trade for not turning every removal into a write outage: content
  written while the mark is outstanding is sealed under the same epoch key the
  removed member may still hold, and a member added during the window is pinned
  to that epoch too. The exposure extends forward in time, not only backward
  over what was already sealed, which is why the window is meant to be short.
- `epigraph_groups_reseal_required` counts groups whose debt is more than seven
  days old. Zero is the healthy value; `-1` means the sampler has not run yet.
  **In this release the series only ever rises.** Nothing clears
  `reseal_required_at` — rotation deliberately does not, and the re-seal handler
  that would is not built — so read it as "groups that have ever incurred an
  unrotated removal older than seven days", not "groups currently owing one". An
  alert wired to it will not clear when an admin remediates.

Nothing re-seals automatically, and that is deliberate. Re-sealing needs the
group key, which the server does not have and by design will never have. The
server can mark the obligation, measure it, and (in a later release) prepare the
manifest; only a key-holding admin can complete it. A job that could only ever
fail would turn a stated, visible gap into a red queue nobody trusts.

### Rotation is refused when the outgoing key is unrecoverable

`POST /api/v1/groups/:id/rotate` answers `409` unless the epoch it is about to
retire is recoverable — either that epoch row already carries a `wrapped_key`, or
the group carries a `properties->>'kms_key_ref'` naming an external escrow.
Retiring an epoch whose key nobody can produce does not hide the content sealed
under it; it destroys it, silently, in an operation that reads like routine
hygiene.

**The request carries no key material of its own, and that is a deliberate
limit.** The server cannot check that a blob offered as "the outgoing group key"
is one, so accepting one would make the gate satisfiable by any value at all —
and the gate is the only thing standing between a routine operation and content
nobody can ever read again. `kms_key_ref` is the production satisfier: under
both custody models in §5.4 of the plan, `group_key_epochs.wrapped_key` stays
`NULL` by design.

The rotation also refuses (`400`) a submission that does not carry a re-wrapped
share for exactly the live roster, and one that names any member twice. A member
skipped by a rotation would hold a share for a retired epoch and be unable to
read anything written afterwards — an accidental removal dressed as a key
change; two shares for one member are two answers to one question, which the
server declines to resolve by picking the last.
