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
| A `harvester_fragments` row whose provenance row arrives later | stamped from the cited claim by **089**, when the `harvester_claim_provenance` row linking them is inserted — but only if the fragment is still unstamped. See the note below the table. |
| An edge | the **meet** of its two endpoints, 070 arm (b); since **120** (operator decision D8) an edge between two public claims (or evidence, or from a `synthesis` source) is owned by its **writer's group** and stays public, and every other public-meet edge (an agent, paper, workflow, trace ... endpoint) stays `('public', world)`. See "Edges between public claims are their writer's (120)" below. |
| A row with no derivable owner (`frames`, `contexts`, `perspectives`, `communities`, `recall_events`) | **must be declared by the writer.** Before 074 these landed on `('public', world)`; after 074 there is no default to land on. See the next section. `harvester_fragments` is in this set too, with one qualification — see below. |

**`harvester_fragments` is the one table in two rows of that table, and the
order of the two writes decides which.** It has no `claim_id`, so it is a
parentless root and its writer must declare tenancy (074) — but it does reach a
claim, through `harvester_claim_provenance`. Until migration 089, a fragment
written *before* that link existed was stamped by nothing: arm (c) has no column
to key on, and arm (d) fires only when a claim's tenancy actually changes. 089
closes that with an AFTER INSERT trigger on the provenance side.

It stamps **only a still-unstamped fragment** — one owned by the world or seed
group, the two sentinels 062's `*_group_needs_real_group` CHECK names as
non-owners. A fragment already owned by a real group keeps that owner when a
second claim cites it, because re-stamping it to the second claim's group would
widen access to the first group's content.

**089 does not relieve the writer of declaring, and is not a substitute for it.**
Its target predicate matches only the two sentinel owners, and under 079's FORCE
`harvester_fragments_tenancy`'s `WITH CHECK` admits a write naming a sentinel
owner only through a bypass disjunct. So the rows 089 reaches are the ones written
by a bypassing or `epigraph_seed`-member session — today's connection regime, and
the `#[sqlx::test]` harness — plus everything already on disk. **Declare both
columns at the fragment's own insert site.** 089 is a backstop for the rows that
predate a declaration, not a default to lean on.

**Since migration 115 the stamp also runs only for a privileged session**
(`epigraph_bypass()`: a maintenance-member or superuser `session_user`). A
provenance INSERT from any other session leaves a sentinel-owned fragment
exactly as it was. Such a session cannot write a sentinel-owned fragment in the
first place (the `WITH CHECK` above), so the only fragments it could have
stamped were somebody else's, and owning one would have let it DELETE the
fragment and, through the FK cascade, every other claim's provenance row for
it. The unstamped fragment was already public and stays so.

One consequence worth knowing before you rely on it: a still-unstamped fragment
cited by **both** a public claim and a group-private one becomes group-private the
moment the private link is inserted, and so leaves the public claim's provenance.
That is intended and fail-closed — it is the same stance
`seal_side_channels.rs::a_shared_source_fragment_is_blanked_for_every_claim_that_cites_it`
already takes for the seal — and it is a second reason to declare a fragment's
tenancy yourself rather than let a later link decide it.

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
| `edges` | `source_id` / `target_id` | 120's `epigraph_edges_tenancy` (the endpoint meet, or the writer's group between two public claims) |

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

**`harvester_fragments` is a partial exception since migration 089, and only
partial.** It still has no `claim_id` and its writer must still declare — nothing
about the `23502` changed. What 089 adds is a *second chance*: the fragment does
reach a claim through `harvester_claim_provenance`, and when that link is
inserted the fragment inherits the claim's tenancy, provided it is still
unstamped. So route 2 exists for it one step removed, keyed on a later write
rather than on its own — and only for rows a bypassing or `epigraph_seed`-member
session wrote, because a sentinel owner is what the predicate matches and the
policy does not admit an application-role write that names one. The other five
have no such path and never will.

### What you must not do

Do not add a `DEFAULT` back. Do not stamp the seed or world group from
application code — the prohibition binds application writers, and it is not
contradicted by 070's and 089's stamping bodies, whose target-side predicates
treat both sentinels as "no owner yet" and may therefore copy a sentinel owner
from a claim. Do not "fix" a `23502` by widening the row to `'public'` when
the caller meant `'group'` — a failed write is recoverable, a disclosure is not.

## Running the backfill

```bash
# 070 MUST be applied first — the backfill relies on arm (d) to propagate to the
# 17 claim-derived tables. The binary refuses to start otherwise.
epigraph-tenancy-backfill run --legacy-owner operator|platform --batch-size 5000

# The deploy pre-flight. Exit code is the guard; it prints offending ids.
epigraph-tenancy-backfill verify [--legacy-owner operator|platform]
```

**`--legacy-owner` is required on `run`**: who owns the legacy corpus is an
operator decision, not a default. `operator`: a world-owned row of an author
linked to a human (live OR retired) goes to that operator's group, an unlinked
author's to its own personal group. `platform`: only rows of authors with a LIVE
link to a registered human operator move (to that operator's group), and a
registered human operator's own rows (to its personal group); rows of
retired-linked and unlinked authors, and their derived rows, stay world-owned as
the platform corpus (the walk itself skips them, so a re-run never revisits
them). In both modes the run re-stamps a world-owned edge that touches a
non-public claim or evidence endpoint to its endpoints' meet (arm (d) repairs
such an edge only when one of its endpoint claims moves, and the platform
corpus never moves). `verify` takes the same flag: without it the check is strict (no
world-owned residue at all); under `platform` it fails only on rows that should
have moved and REPORTS the platform corpus.

It is resumable across a `kill -9`: the `tenancy_backfill_progress` cursor is
committed in the same transaction as its batch.

**Bounded runs.** `--entity claims|communities|perspectives|recall-events|harvester-fragments`
runs one arm alone (no settle, no final verify). `--max-runtime 2h` (or `90m`,
`3600s`) stops cleanly between batches and exits **3**: partial, re-run the same
command to resume. A walk that begins from a cursor an earlier run left (an
aborted run, or one under the other `--legacy-owner`) and finds rows below it
rewinds and walks again in the same run; a walk that covered the table from
the start and still leaves rows (an author that resolves to no group) resets
its cursor, and under `--entity` exits **1**, so `0` always means that arm is
done. Use them to run the claims walk in windows with a `VACUUM`
between (below).

**Cost model (measured on a 5433 `*_test` seed: 200k claims, 400k edges, rows
in all 17 derived tables).** A batch resolves each distinct author's group once
and updates its rows with one join; arm (d) then issues one UPDATE per derived
table and one edges statement per batch (migration 122 made the edges meet
set-based). A 5,000-claim batch of UN-embedded claims takes ~4.5 s (~1,100
claims/s). A claims row that carries an embedding costs ~5 ms more per row,
because every UPDATE of `owner_group_id` is non-HOT and inserts a new entry into
each HNSW index on `claims.embedding` (~30 s per 5,000 embedded claims on the
seed; more on a larger graph). Two ways to run a large corpus:

* keep the HNSW indexes (recall stays fast; the walk takes roughly
  `claims x 6 ms`), in `--max-runtime` windows; or
* in a maintenance window, `DROP` the HNSW indexes on `claims`, run the walk at
  ~1,100 claims/s, then `CREATE INDEX CONCURRENTLY` them again (a build costs
  ~1 ms per vector serially on the seed, ~5x less than the incremental
  inserts; semantic recall is slow until they are back).

Before the walk, `ANALYZE claims` (the backfill's batch selection and the
trigger's joins read its statistics). Each moved claim leaves one dead tuple in
`claims` and in each derived row; public edges are not rewritten. Between
windows: `VACUUM (ANALYZE) claims, evidence, claim_cluster_membership, triples,
entity_mentions, mass_functions;`.

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
4. `settle_remaining`, then `verify`.

A fifth arm, **legacy `ownership` transcription**, ran between (3) and (4) until
PR-22. It re-fired migration 071's write-through trigger over every `ownership`
row with no `tenancy_transcription_log` entry, and `verify` carried two matching
checks. Migration 084 retires the table, and its second pre-flight now holds
that gate: it **refuses to drop `ownership`** while any non-public row lacks a
ledger entry. Run the backfill to completion BEFORE applying 084 — if the
pre-flight fires, that is what it is telling you.

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

Migration 070 skips its `ALTER FUNCTION … OWNER TO epigraph_maintenance` when
that role does not exist, because migration 060 only `RAISE NOTICE`s if the
migration role lacks `CREATEROLE`. The migration still reports success. Provision
`epigraph_maintenance` out of band and **re-apply 070** (it is idempotent).
Deploying past this is not safe: 070's bodies become RLS-filtered at PR-17 and
arm (b) then stamps a private endpoint public. Migration 086's read helper is
subject to the same check; 071's shim was too, until PR-22 retired it.

## Operator binding

**The invariant.** Every writing agent is irrevocably tied to one individual
human account, and there may be many humans. Once a database is ARMED (below),
a claim may be INSERTED only when its author is BOUND, and, when the session's
authenticated principal is not the author, only when that WRITER is bound too
(see "Who is checked" below; the supersede exceptions, restating a retired
claim, are under "A linked agent writes only where its own operator
writes"). `claims.agent_id` of an existing claim is changed
only by a privileged session (since migration 123, not by a platform-custodian
principal on an application session either: "The custodian role" below),
`OPL02` for anyone else, and is then checked like an insert. Bound means:

* (a) a **human operator**: an agent with a live row in the maintenance-only
  registry `human_operators` whose recorded OAuth client (the one client the
  registration was made for) is still an ACTIVE `client_type = 'human'` client
  of that agent. Neither half alone counts: being named as some link's operator
  never makes an agent a human, and a dynamic client registration is typed
  `human` too. Keying on the recorded client means suspending it suspends the
  human: minting a fresh active client for the same agent (the application
  role may register clients, but not update them) does not revive it, and
  neither does the admin approval (`POST /api/v1/admin/clients/:id/approve`,
  which runs on the application role): only a privileged session takes a
  client out of `suspended` or `revoked` (`oauth_clients_reactivation_guard`,
  `42501` otherwise; promoting a `pending` client is unaffected). Register
  and revoke with `epigraph-operator register-human-operator --agent <id>
  --client <oauth client id> --reason <text> [--apply]` /
  `revoke-human-operator --agent <id> --reason <text> [--apply]` (maintenance
  DSN). `--client` is REQUIRED: the operator names the human's own OAuth client
  rather than letting it be inferred, because the application role may insert
  `oauth_clients` rows, so "the agent's one active human client" could be a row
  an application session planted before the human was registered. Register
  refuses a client that is not an active `human` client of that agent, and an
  agent already registered for a different client. Verify the recorded
  `human_operators.client_id` after registering. Match `--client` to an
  out-of-band record of the person's own client (when and how it was created),
  never to a listing of active `human` clients: `oauth_clients` carries no
  provenance column, so a row an application session inserted (with an id,
  name and timestamp of its choosing) looks the same as an administrator's. The registry's rules and its audit live on
  the table itself, so a direct maintenance `INSERT` / `UPDATE` meets the same
  checks and leaves the same `security_events` row as the command; revoke is
  final (a revoked row takes no change at all) and stops every agent
  live-linked to that human at once; or
* (b) the holder of a **live link to a human operator**: an `operator_links`
  row for the agent with `retired = false` whose operator is (a) (recorded by
  `epigraph-operator link`, or by a stdio process's own startup on a
  maintenance DSN). An agent has ONE operator for life: a link to a second
  human is refused, live or retired, and never re-pointed. And a NEW link can
  be recorded only to a registered human operator, armed or not
  (`operator_links_operator_is_human`; link rows are permanent, so a link to a
  non-human could never be corrected); an exact re-link of an existing link is
  never refused by it. Every link row recorded, by any path, writes one
  `operator.link_recorded` `security_events` row.

Anything else is refused with SQLSTATE **`OPL01`**.

**Who is checked.** `claims.agent_id` is a column the writing session supplies
(REST takes it from the request body), so binding it alone would let any
session write as any bound author. The trigger therefore also binds the
session's authenticated PRINCIPAL (the one `ScopedPool` stamps from the
request's viewer) whenever it differs from the author: that writer must be
bound (`OPL01`), must write the owner group (`OPL02`, below), and may name as
author only a bound agent of its OWN human (`OPL01` / `OPL02` otherwise). The
one exception is the author a supersede INHERITS, which is exactly what the
supersede act writes: a new row naming `supersedes` whose predecessor is a
DIFFERENT claim that carries the same author, is owned by the same group, is
already retired (the act retires it first, in the same transaction), and has
no other current successor; and, on an application session, that predecessor
has never been restated by that author before, current or retired (migration
123: before it, "no other CURRENT successor" alone re-admitted a predecessor
whose successor had been retired, so retire-and-restate doubled the current
claims under the identity each round). That author may be a retired agent of
the writer's own human, so a human can supersede its own legacy author's
claims, once per claim, ever, and in the claim's own group; a fresh claim
never names a retired identity, however `supersedes` is posed (at a current
claim, at a claim in another group, as a second successor, at an
already-restated claim, or at the claim itself). A privileged session keeps
the "no other current successor" rule, so a custodial revision of a canonical
claim that retired duplicates point at still works. No claim names ITSELF in
`supersedes`: a statement that sets it to the row's own id is refused
(`OPL02`) on every session, armed or not (migration 123). Nor can an existing claim's lineage be laundered: once
armed, an application session may not clear `claims.supersedes`, nor re-point
it on a claim that stays current (`OPL02`); setting it on a claim that had
none, and re-pointing it while retiring the claim in the same statement (the
dedup and consolidate acts), are unchanged; re-opening such a claim later is
checked as an insert ("Scope" below). With a principal
equal to the author, or a privileged session, the author is the one checked.
An APPLICATION session with NO principal (a write on an unstamped connection)
is an unbound writer: refused `OPL01` once armed, so a path that forgot to
stamp its viewer fails closed instead of writing as the author its request
named (with the valve open, the author is then the one checked). The REST
handlers that take the author from the request (`POST /api/v1/claims`,
`/api/v1/submit/packet`, `/api/v1/hypothesis`, `/api/v1/policy-challenges`)
write on a transaction stamped with the caller's viewer, so the caller is the
writer the trigger binds; any other claim write on an unstamped application
connection (a CLI run on an application DSN, a job with no viewer) is refused
once armed and must be stamped or run on a maintenance DSN. Consequences to
decide before arming: a write whose principal is an identity that can never be
bound (a shared HTTP listener's own agent acting under an admin's borrowed
stamp, or a non-human OAuth client authoring on another agent's behalf, such as
a decomposition tool posting atoms under the parent claim's author) is refused
once armed.

**A linked agent writes only where its own operator writes (`OPL02`).** A claim
written by a live-linked agent must be owned by a group its operator holds a
live `writer`/`admin` membership in: normally the operator's personal group,
never another human's group, and never the agent's own personal group. A claim
written by a human must be owned by a group that human writes (on the claims
path a human is scoped like everyone). The
same rule guards the membership door: a `writer`/`admin` row for a live-linked
agent is refused unless its operator writes that group, so another human
cannot enrol my agent to write evidence, edges or beliefs in their group. Both
refusals are SQLSTATE **`OPL02`**. Only a privileged (maintenance) session
crosses groups and humans. Since migration 123 (operator ruling OQ-1 (b)) a
session whose principal holds `role:platform-custodian` is relieved of
nothing on an application session: the principal is a stamp the application
role sets, and holding the role is not using it. A custodial write is made on
the maintenance DSN with `epigraph-operator custodial-supersede`, which
records a `platform.custodial_act` against the actor's live assignment. The
privileged session is not relieved of `OPL01` either, except for a supersede,
whose successor inherits a retired predecessor's author and group: that
supersede is admitted whatever the author's binding, retired-linked or
unlinked (the platform corpus's edit path, "Existing rows"). A re-open of a
claim, and any change of an existing claim's lineage, on an application
session is checked exactly as that session's insert would be. A consequence: an
agent whose membership in its operator's group was REVOKED writes nothing (its
default declaration falls back to its own personal group, which `OPL02`
refuses); ending an agent's writes is a revoke or a retire. Residual, named: a
writer row that predates the link, or outlives the operator's own membership,
is not revisited by the door; `epigraph-operator link` lists such rows as
`FOREIGN-WRITE` and revokes them with `--revoke-foreign-writes` (it does not
refuse the link, because any application session can enrol an unlinked agent as
a writer in its own group), and the query in "Existing rows" audits them. `OPL02`
holds whenever the database is armed, whatever the valve says. The refusal is a
trigger on `claims` (`claims_require_tenancy_then_operator_binding`, migration
122, named to fire after the tenancy trigger fills an inherited owner), so it
holds for every claim INSERT on every path: REST, MCP over HTTP and stdio, the
CLIs, workflow ingest, default and explicit tenancy declarations, and a raw
`INSERT` on any role (an unstamped application session included, as above).
`ClaimRepository::default_decl_for_author` runs the same check before it
resolves a personal group, so no group is provisioned for a refused author.
Workflow ingest authors every row as ONE shared system agent under that agent's
own stamp, so the database sees only it; its request paths therefore bind their
real CALLER before writing (`OPL01` for an unbound caller, `OPL02` for a caller
whose human does not write the group the system agent's rows land in, and
`OPL02` for a caller that does not belong to the system agent's human, which
holds with the valve open too: the valve never lets an unbound caller write as
the bound system identity). Once the
system agent is live-linked to one human, another human's callers are refused
rather than writing into that human's group; a per-operator system identity is
the follow-up that lets them ingest workflows.

**Scope: claim INSERTs.** The trigger governs claim INSERTs, changes of
`claims.agent_id`, the clearing or re-pointing of an existing
`claims.supersedes` (above), and a claim becoming current again
(`is_current` false to true), which the trigger checks as an INSERT of that
row on every session but a privileged one (a custodian principal included,
since migration 123; before it the instance-admin exemption skipped the
check). The inherited-author rules therefore hold across statements: retiring a successor, adding a second one and re-opening the
first, or re-pointing a successor while retiring it and then re-opening it,
meets the same refusal as the one-statement form. No repository or route
re-opens a claim. Every other claim UPDATE (content, truth value, labels,
retiring a claim, a first `supersedes`, properties, embedding: the retire half
of a supersede, a dedup, a relabel, a re-score) is gated by tenancy row
security alone, not by `OPL01` / `OPL02`. On a schema with only this series' policies
that is the owner-group rule: an update needs the row readable and its owner
group in the session's writable set, so one human's agent cannot update
another human's claim, but an UNBOUND agent can still update claims in a group
it writes (its own). A database that still carries the orphan permissive
`*_privacy` policies (no `WITH CHECK`, `USING` true for every non-sealed row,
OR'd with the tenancy policy) admits ANY claim UPDATE from any application
session, other humans' group-private claims included, and arming does not
change that. So for claims too, do not rely on arming for update isolation
until those policies are removed. Other rows that name an agent (evidence,
challenges, DS mass, edges, perspectives, recall events) are likewise gated by
tenancy (row security and the `OPL02` membership door), not by `OPL01`: an
unbound agent that holds a writer row in a group can still write those rows
there once armed. Extending the binding to updates and to those rows is an
open decision, not an oversight. Surfaces:

| surface | what the caller sees |
|---|---|
| HTTP | `403`, body starts `OPL01:` (and names the fix) or `OPL02:` |
| MCP | `INVALID_REQUEST`, message carries `OPL01` / `OPL02` |
| Rust | `DbError::OperatorLinkRequired` / `DbError::OperatorScopeRefused` (`is_write_authority_refusal()`) |

**The fix** is an operator action on a maintenance DSN:

```bash
EPIGRAPH_OPERATOR_MAINTENANCE_DSN=... \
  epigraph-operator link --agent <agent id> --operator <human operator agent id> [--apply]
# or, for a stdio fleet identity, before its first start:
EPIGRAPH_OPERATOR_MAINTENANCE_DSN=... \
  epigraph-operator link --agent-model <model> --agent-system-prompt-hash <hash> \
    --operator <human operator agent id> [--apply]
```

`link` refuses an operator that is not a human operator, and refuses an agent
that is the principal of an un-revoked OAuth client (see "HTTP principals"
below). It is idempotent; a dry run is the default.

### Arming, and the valve

Applying migration 122 enforces nothing. Enforcement starts when a maintenance
session arms the database, once:

```bash
EPIGRAPH_OPERATOR_MAINTENANCE_DSN=... epigraph-operator arm-operator-binding            # census only
EPIGRAPH_OPERATOR_MAINTENANCE_DSN=... epigraph-operator arm-operator-binding --apply    # arm
```

The census lists every agent that authored claims in the last `--recent-days`
(14) and is not bound; `--apply` refuses while that list is non-empty unless
`--allow-unbound-writers` records that stopping them is the decision. Arming is
**one-way**: there is no disarm function, and the maintenance role holds no
UPDATE or DELETE on `operator_binding_arming`. The api and mcp servers log at
boot whether the database is armed, and REFUSE TO START (exit 1, `ERROR:
refusing to start: ...` on stderr) when their DSN is privileged
(`epigraph_bypass()` is true) on an armed database, whatever the valve says:
on such a DSN the trigger checks the author column alone and relieves the
cross-human scope (operator ruling OQ-7 (b)). `epigraph-mcp` refuses on every
transport, stdio included. An unarmed database is not refused at boot, but a
unit keeps re-reading its posture while it serves
(`EPIGRAPH_REQUEST_UNIT_RECHECK_SECS`, 30 s by default, clamped to 1..300 s)
and exits 1 (`ERROR: stopping: ...`) once it finds itself on a privileged DSN
of an armed database, so arming under a running privileged unit stops it. A
failed re-read is a WARN and the unit keeps serving; only the boot read fails
closed.

The only runtime relief is per process:
`EPIGRAPH_OPERATOR_LINK_ENFORCEMENT=off`. It is read once at boot, logs a WARN
on every boot while set, and makes every connection the process's `ScopedPool`
opens carry the session setting `epigraph.operator_link_enforcement = 'off'`,
which the binding check honours. It relieves `OPL01` ONLY: the cross-human
scope (`OPL02`) keys on arming alone, so no valve lets one human's agent write
into another human's group, and no valve lets an UNBOUND writer, or another
human's agent, name a bound author (a human, any human's agent, or a RETIRED
identity tied to a human): with the valve open an unbound writer may author
only as itself or as another unbound identity. A RETIRED identity stays scoped
by its human too: stamped as itself, or named on an unstamped session, it
writes only into a group its human writes, never into another human's group or
the world group (`OPL02`). What the valve does relieve
inside one human is the binding itself: a fresh claim naming the writer's own
human's retired identity is `OPL01` with the valve closed and admitted with it
open. Any other value, including a typo, leaves
enforcement ON. It reaches only `ScopedPool` connections (every request unit
and operator CLI); any other pool, and a transaction-mode pooler, stay
enforced. The setting is a transport, not an authority boundary: any raw
session can set a custom setting.

**Trust boundary: the principal is a stamp, too.** The session principal the
binding checks (`epigraph.principal_id`, with the group settings) is set by the
application role itself, which is how `ScopedPool` stamps a request, and
tenancy row security trusts the same stamp. A holder of the APPLICATION DSN
that issues raw SQL can therefore stamp any identity it knows the id of (agent
and human ids are not secrets: they author ordinary claims): a bound agent, a
human, or a platform custodian (since migration 123 the last gains it
nothing: no application session is relieved of `OPL02`). The
binding constrains the code paths that stamp from an authenticated viewer; it
is not a defence against a process that holds the application DSN and
misbehaves (a compromised request unit, or any agent container given that
DSN). That boundary is the DSN: who holds it, and a separate maintenance DSN
for every privileged act. Arming is no substitute for it.

### Stdio agents under D9

A request-serving process holds only the application DSN (operator decision
D9), where `epigraph_link_operator` is refused (`42501`). A stdio agent with
`EPIGRAPH_OPERATOR_ID` therefore cannot record its own link. The host records
it first (`epigraph-operator link`, above); the agent's startup reads the actor
record and, when it already names the declared operator, starts without calling
the link function. Without a recorded link the startup exits with a message
naming that command. A fleet identity is derived from the model and a hash of
its stable prompt files, so a changed prompt file is a new, unlinked agent:
run `link` at every spawn.

### HTTP principals

An agent with ANY operator link is refused an OAuth token and a viewer over
HTTP (migration 107: operated agents are stdio-only). So a non-human OAuth
principal (a `service` or `agent` client) that writes over REST can be neither
linked (it would lose HTTP) nor left unlinked once armed (`OPL01`). `link` and
`link-legacy-authors` refuse or skip such agents rather than cut them off, and
the arming census lists them if they wrote recently. Decide how each is bound
before arming.

### Existing rows

* `epigraph-operator link-legacy-authors --operator <human> [--apply]` records
  a RETIRED link to the human for every agent that authored a tier-A row and
  has no link (migration 122's `epigraph_link_legacy_authors`, one
  `security_events` row per call). It skips, and names, humans, OAuth
  principals, holders of write authority in the operator's group, 107's
  shared-signer fingerprint (use `link-retired --attest-shared-signer`),
  agents whose own OPERATED_BY lineage names ANOTHER registered human
  (`operated_by_other_human`),
  `--exclude-agents-file` ids, and agents that authored a claim within
  `--quiet-days` (30; they may still be running and want a live link), and
  agents holding write authority in a group the operator does not write
  (`foreign_write_authority`: they act in someone else's group), and, from
  migration 123, principals still holding an un-ended, un-lapsed role
  assignment (`role_holder`: typically a departed holder whose registration
  was revoked; end the assignment with `end-role-assignment` and re-run, which
  links it then). `--operator`
  is always explicit, and a run ties EVERY untied candidate to that one operator
  (there is no include list): with many humans, scope each run with
  `--exclude-agents-file` listing every agent that is not that human's (a later
  run skips everything an earlier one tied). "Authored" means named in an
  author column (`claims.agent_id`, `evidence.signer_id`,
  `claim_versions.created_by`, `mass_functions.source_agent_id`,
  `challenges.challenger_id`, `challenges.resolved_by`,
  `claim_signature_revocations.revoked_by`, `perspectives.owner_agent_id`,
  `recall_events.agent_id`); the signing-key columns (`edges.signer_id`,
  `claims.signer_id`, `claim_signature_revocations.previous_signer_id`) name a
  key, not a writer, and are excluded.
* **Register every human before tying legacy authors.** The
  `operated_by_other_human` skip consults the REGISTRY: an agent whose
  OPERATED_BY edge names a person who holds an active `human` client but is not
  yet registered is tied to `--operator`, permanently (a link is never
  re-pointed). The skip is deliberately not widened to "any active human
  client", because a dynamic client registration is typed `human` too and such
  a rule would leave an operator's own agents untied. Before `--apply`, list the
  candidates whose lineage names an unregistered human-client agent and decide
  each one (register that person first, or exclude the agent):

  ```sql
  SELECT DISTINCT e.source_id AS agent, e.target_id AS unregistered_human_client_agent
    FROM edges e
    JOIN oauth_clients c ON c.agent_id = e.target_id
                        AND c.client_type = 'human' AND c.status = 'active'
   WHERE e.relationship = 'OPERATED_BY'
     AND NOT public.epigraph_is_human_operator(e.target_id)
     AND NOT EXISTS (SELECT 1 FROM operator_links l WHERE l.agent_id = e.source_id);
  ```
* Audit writer rows that predate a link (the `OPL02` door does not revisit
  them):

  ```sql
  SELECT m.agent_id, m.group_id FROM group_memberships m
    JOIN operator_links l ON l.agent_id = m.agent_id AND NOT l.retired
   WHERE m.revoked_at IS NULL AND m.role IN ('writer', 'admin')
     AND NOT public.epigraph_operator_writes_group(l.operator_id, m.group_id);
  ```
* The backfill (`epigraph-tenancy-backfill run --legacy-owner ...`) stamps a
  world-owned row of a linked author to the operator's group: any link state
  under `operator`, LIVE links only under `platform`, where a registered human
  operator's OWN world-owned rows also go to its personal group (see "Running
  the backfill"). `verify` REPORTS (not a failure) rows still owned by a linked
  author's own personal group.
* **World-owned claims once armed.** Nobody holds a writer row in the world
  group, so once armed a NEW claim owned by it (a supersede's successor
  inherits the world owner) is written only by a privileged session or a
  platform-custodian principal; everyone else, a human included, is refused
  `OPL02`. Under `--legacy-owner platform` the retired-linked and unlinked
  authors' rows STAY world-owned (the platform corpus), to be revised only by
  an elevated act. A privileged (maintenance) session's supersede of such a
  claim carries its predecessor's author whatever that author's binding (the
  successor restates the one retired claim, in the world group); a
  custodian PRINCIPAL supersedes a retired-linked author's claim but not
  an unlinked author's (`OPL01`: a principal stamp is a value an application
  session sets, so it is not relieved of the binding). With the valve closed,
  a fresh claim naming such an author is refused (`OPL01`) on every session,
  maintenance included. The valve relieves that `OPL01` wherever it is set: a
  privileged session or a custodian principal with the valve open can
  mint a fresh world-owned claim under a legacy identity, and only `OPL02`
  (the cross-human scope) still holds for everyone else. So keep the valve
  out of maintenance units, and keep valve windows short. The custodial
  supersede is `epigraph-operator custodial-supersede` (migration 123; "The
  custodian role" below), and a hand-written retire plus INSERT is not one.
  The act also writes the `supersedes` edge from the successor to its
  predecessor, moves the predecessor's strengthening edges to the successor
  (weakening ones stay), records a `platform.custodial_act` naming the
  custodian's assignment, and leaves the successor's embedding to the
  embedding backfill. The "human supersedes its own
  legacy author's claim" admission applies to rows in the human's own group.
  Revising the corpus IN PLACE (an UPDATE of content, truth value, labels, or
  retiring a claim) is not governed by the binding trigger ("Scope" above;
  re-opening a retired claim is, as an insert): with
  this series' policies only a session that writes the world group can do it,
  but a database that still carries the orphan permissive `*_privacy`
  policies admits it from any application session, so arming does not protect
  the corpus from in-place rewrites until those policies are removed.
* `epigraph-operator reown-linked --operator <human> --legacy-owner operator|platform --manifest-out <new path>
  [--apply]` moves those claims into the operator's group through
  `reown-claims`' guarded batches (`--derived follow-claim`; derived rows follow
  through 070's arm (d); `reown-reverse` undoes a manifest). Resumable: a re-run
  selects what is left. Run one instance at a time. Both `reown-linked` and
  `reown-reverse` switch the session to the application role for their
  readability probe (`SET SESSION AUTHORIZATION`), which only a SUPERUSER may
  do: run them on the admin (superuser) DSN, not on a plain maintenance login,
  which they refuse before writing anything.
* What a linked author's OWN personal group still holds afterwards (the
  claims `reown-linked` HOLDS, and anything else `verify` REPORTS) is frozen
  against that author once armed. A supersede of such a claim inherits the
  personal group, and the author's human holds no writer row there, so the act
  is refused `OPL02`, like a fresh claim into that group. Revise those claims
  on a maintenance DSN, or move them before arming.

## The custodian role (migration 123)

**Instance administration is a role, not a flag on an agent.**
`role:platform-custodian` is held by a REGISTERED HUMAN operator through a
timestamped assignment (`role_assignments`: holder, `valid_from`,
`valid_to`, the granting custodian, the database login that wrote it, a
reason, and an end stamp). It replaces `instance_admins` as the source of
admin authority: `epigraph_is_instance_admin` keeps its name, signature and
subject binding and answers "holds role:platform-custodian now", so every
policy that asked it (privatization, the security-event read arm) switched at
once. It no longer relieves `OPL02`: 122's `epigraph_operator_scope_exempt()`
is re-bodied to the privileged session alone (operator ruling OQ-1 (b)), so
the role confers no write authority on an application session. `role:auditor`
reads the platform audit trail and confers nothing else.

* **Agents never hold a role** (`CUS01`): the holder must be a registered human
  (`epigraph_is_human_operator`) that is not itself linked to a human as an
  agent (live or retired), re-checked at read time, so revoking the human's
  registration or suspending its recorded OAuth client ends its authority at
  once. A HOLDER is never linked as an agent: a new `operator_links` row for a
  principal with a live or not-yet-begun assignment is refused `CUS01`, so its
  holding ends through `end-role-assignment` (audited) before the link. A
  grant and a link of one principal running at once see each other: both
  guards take the link writes' advisory lock before they read, so the second
  is refused once the first commits. That holds under READ COMMITTED (the
  default) and SERIALIZABLE (a serialization failure); REPEATABLE READ is
  refused on both sides (`CUS06`), because its snapshot predates the wait.
* **Append-only** (`CUS02`): an assignment is never edited or deleted; its only
  change is its end (`revoked_at` stamped now, by the revoking login, with
  why), and an ended assignment is final. Nothing is back-dated, and the
  provenance columns (`granted_via`, `created_at`) are the database's, never
  the writer's.
* **The grantor rule** (`CUS03`): once any live custodian exists, every grant
  names a live custodian as its grantor, and a holder never extends its own
  assignment while another holder exists. The first grant (no live custodian)
  is the only one without a grantor.
* **Written only on a maintenance DSN**: `epigraph-operator grant-role`,
  `end-role-assignment`, `list-role-assignments`. The application role reads
  only its own assignments. `epigraph-instance-admin grant|revoke` refuse and
  name these.
* **Audited**: every grant and end and every custodial act is one
  `security_events` row whose type starts with `platform.` (any case) and
  whose details name the assignment. No application session writes a
  `platform.` row, and no row is ever edited, deleted or back-dated. The
  trail is NOT proof against a holder of the maintenance DSN: `granted_by`
  and an act's actor are UUIDs that login supplies, checked for a live
  custodian. Since migration 130, once the acting custodian holds a live
  passkey the write must name a PASSKEY-CONFIRMED admin act whose canonical
  arguments are exactly the write's (`ELV10` otherwise; see "Elevation"
  below); before any passkey exists the write is a bootstrap act, audited
  `confirmation = 'none'`.
  A holder of `role:auditor` (or the custodian role) reads the trail through
  `epigraph_platform_audit(since, limit)`.
* **Custodial acts**: privatization plan writes (create, approve, abort,
  apply, revert) and `epigraph-operator custodial-supersede` each record a
  `platform.custodial_act` against the actor's LIVE assignment in the act's
  own transaction (`CUS04`, and nothing written, otherwise).
* **OCCUPIES is a projection**: each assignment also appears in the graph as
  an `OCCUPIES` edge from the holder to the role's node, with the
  assignment's window in the edge's `valid_from` / `valid_to`. It is never
  read for authority (a ratchet test fails if a policy, function or Rust
  source reads it), and, like the governance graph's other OCCUPIES edges,
  it is world-readable: who holds the custodian role is public. An edge of
  the same shape can be written by any writer of the world group, so a
  governance reader joins it to `role_assignments` on
  `properties->>'assignment_id'` before treating it as a holder.
* **`instance_admins` is frozen**: no new row and no edit on any role, except
  a `revoked_at` stamp on the row of a principal holding no live custodian
  assignment (an old `revoke` of a live custodian fails `CUS05`), which ending
  a holder's last custodian assignment, or revoking the human, writes into
  the holder's legacy row (so a rollback that
  restores 083's body resurrects nobody). Migration 123 carried each LIVE row
  of a registered human into an assignment from its `granted_at`, and skipped
  every other live row loudly, naming why (an agent, a human linked as an
  agent, a human whose client is not active).

The role confers no WRITE authority on an application session: every custodial
write is a maintenance act. Its standing READ authority (083's
`security_events_read` arm, the privatization plan, item and audit reads, and
the privatization routes' gate, all keyed on the session's stamped principal,
which any holder of the application DSN sets) follows the admin-scope switch
since migration 129: UNARMED it is as described here; ARMED it needs a live
elevation. Activating the role per session, per-act confirmation and audited
reads are the next section.

## Elevation: time-boxed, passkey-confirmed READ for custodians (migrations 124-132)

**What it is.** A holder of an elevating role (today `role:platform-custodian`)
may, for at most 15 minutes, READ rows of groups it is not a member of. It is
"sudo READ": nothing is written through an elevation except the audit trail
and an admin-act proposal. Every elevated access is recorded where the people
whose rows were read can see it. Migration 132 opens it (125's recorder gate);
before 132 no session is ever live.

**Who may elevate** (operator ruling D2). Only a REGISTERED HUMAN, not linked
as any human's agent, holding a LIVE assignment of an elevating role, with a
live passkey (WebAuthn with user verification, ruling D5), on a live refresh
family of its own human OAuth client. Agents never elevate (they hold no
role, `CUS01`); `instance_admins` and standing flags never qualify. All of
this is re-checked by the database on EVERY statement, so revoking the
assignment, the registration, the client, the family or the confirming
passkey ends the elevation at once.

**How.**

* Passkeys are enrolled on a maintenance-DSN ticket
  (`epigraph-operator passkey-enroll`), completed by the person at
  `/elevate/enroll/<id>` on their own device. A later passkey of a holder
  needs a confirmed `passkey.register` act. The relying party requires a
  verified attestation on a configured allowlist; the test and development
  flag that accepts software (`none` / self) attestation,
  `EPIGRAPH_WEBAUTHN_ALLOW_SOFTWARE_ATTESTATION`, is REFUSED by the API on a
  database armed for operator binding, at boot and while running.
* The CLI / console path (the one served by default): `POST
  /api/v1/elevation/tickets {reason}` with the person's own token opens a
  ticket; the person confirms it with their passkey at `/elevate/<ticket>`
  (only their own passkeys are offered; another person's passkey on the
  ticket is REFUSED and audited); the client then redeems the ticket at
  `/oauth/token` (`urn:epigraph:grant:elevate`) for ONE token: at most the
  session's lifetime, no refresh token, the client's READ scopes that the
  ticket's refresh family was consented for (never a write scope, never a
  standing admin-only one) plus `platform:admin`, naming the session (`elv`).
* MCP `sudo` / `unsudo` (connector mode) exist but `sudo` is served only with
  `EPIGRAPH_MCP_CONNECTOR_ELEVATION` on, which is OFF by default (see the
  limits). `unsudo`, `POST /api/v1/elevation/end` and `epigraph-operator
  end-elevation` end a session early.

**What an elevated request may do.** Read: 126's per-table read arms admit
every row to a live elevated session on the application role; the request's
own query fragment is always-true for an elevated viewer, so the database
decides. Write: nothing. The API refuses every non-GET request from a token
carrying an elevation claim (a named allowlist of read-only POSTs aside, and
the one act-proposal route); the MCP transport refuses every non-read tool
and every federated tool to an elevated request; the database's RESTRICTIVE
policies refuse INSERT, UPDATE and DELETE on every armed table; a pool
connection is scrubbed of the elevation on release; a task detached from an
elevated request runs as the person's ordinary viewer.

**Who sees that it happened.** Every elevated request (REST response or MCP
tool result) is recorded in `elevated_access` BEFORE the response leaves; if
the record cannot be written the response is withheld. A row names the
session, the person, the reason, the surface, the ids and filters (never
content), the row count, and the GROUPS whose non-public rows the response
named; an admin member of such a group reads the row through its row policy,
and a holder of `role:auditor` or an elevated custodian reads all rows through
a definer reader. Attribution is by the ids the response contains, so it errs
toward the subject: a group id merely mentioned (a public row's owner, a
not-found error naming an id) attributes that group, and an aggregate with no
row ids is recorded with no group. No API route or MCP tool shows a subject
their rows yet: they are readable on the database through the policy.

**Operator-hidden (pinned) evidence** is readable to an elevated session that
reads the claims it is for or against, and every such read is recorded for
the evidence row's owning group. This is an INTERIM operator ruling ("for
now"); a later one may restore hiding.

**Admin acts** (migrations 130 and 131). An elevated person PROPOSES an act
(`POST /api/v1/admin/acts`, or MCP `propose_admin_act` listed only to an
elevated request): `role.grant`, `role.end`, `claim.custodial_supersede`, or
`passkey.register`, with its arguments stored in a canonical form and digested.
The same person CONFIRMS that act with their passkey at `/elevate/act/<id>`;
the WebAuthn challenge commits to the act's id, its stored digest and a stored
nonce, so a page cannot show one act while another is confirmed. The
maintenance CLI then EXECUTES it (`epigraph-operator grant-role |
end-role-assignment | custodial-supersede | passkey-enroll ... --act <id>`),
recomputing the digest from its own flags and consuming the act in the same
transaction; the audit row carries `confirmation = passkey`, the act id and
the elevation id. The database's guards enforce this for direct maintenance
statements too (`ELV10`): once the acting custodian holds a passkey, a
custodial write without a confirmed act is refused. `revoke-passkey` is the
break-glass back to the bootstrap path.

**Admin-only scopes** (`claims:admin`, `clients:admin`, `groups:admin`, ...)
pass through one mint chokepoint and one check chokepoint behind a switch that
ships UNARMED. Armed, no grant mints them, a standing one counts for nothing
on an unelevated request, and an elevated request holds the admin READ
scopes; arming is an operator step (`docs/deploy.md`).

**The honest limits, stated rather than left to be found.**

* **Tokens are HS256 until the EdDSA token work.** A holder of the token
  secret can forge an elevation claim and a family; the database still
  requires a live session bound to that principal and family, but the forger
  can ride a LIVE elevation of the person's family while it lasts.
* **Forged confirmations are DETECTABLE, not preventable.** The database
  cannot verify a WebAuthn signature, so a holder of the application DSN can
  record a confirmation through the confirm definers, and a holder of the
  maintenance DSN can write the rows directly. `epigraph-operator
  verify-confirmations` re-verifies every stored confirmation offline (the
  signature against the stored public key, the act binding, a replayed
  evidence object, a session no confirmed ticket opened) and re-runs every
  passkey's stored registration under the API's attestation policy (a
  passkey completed through the application DSN with a key the allowlist
  refuses, or with no registration stored), and records each finding. It
  does not detect: a forged completion with an authenticator of an
  allowlisted model (or any key under the software policy); an assertion
  phished from the person's real passkey over a challenge the forger chose; a maintenance holder editing or
  deleting the ceremony rows or the trail (the append-only guards bind every
  login a superuser has not disabled); a signature counter going back across
  confirmations.
* **Connector-mode family scope is unmeasured.** An MCP `sudo` elevates the
  calling token's refresh family; whether a connector shares one family
  across chats is not measured, so connector mode stays OFF and the CLI path
  is the served one.
* **MCP reads are not widened.** The MCP read tools read on the server's own
  unstamped pool, so an elevated MCP request reads no more than before; its
  calls are still recorded (attributed when the answer names a row). The REST
  surface is widened.
* **Lockdown, group-held assignments, a two-person rule and signed audit
  events are out of scope** for this stack.

## The `ownership` table — RETIRED (PR-22, migration 084)

`ownership` was the pre-tenancy ACL table: one row per node, naming an agent and
a coarse partition (`public` / `community` / `private`). It no longer exists.

The retirement ran in three steps and each is still visible in the tree:

* **Migration 071** demoted it to a write-through shim — writing an `ownership`
  row *reclassified* the node's tenancy columns and cascaded, and left a row in
  `tenancy_transcription_log`.
* **PR-14** deleted its API surface entirely: `POST /api/v1/ownership`,
  `PUT /api/v1/ownership/:node_id`, `GET /api/v1/ownership/:node_id`,
  `GET /api/v1/agents/:id/owned-nodes`, and the MCP tools `assign_ownership`,
  `update_partition` and `get_ownership`.
* **PR-22 / migration 084** dropped the table, the
  `ownership_key_id_quarantine` view, the `ownership_transcribe` trigger and
  `public.epigraph_ownership_transcribe()`, and deleted `OwnershipRepository`.
  Two pre-flights gate the drop and both `RAISE EXCEPTION`: the quarantine view
  must be empty, and every non-public row must already appear in
  `tenancy_transcription_log`.

**The tenancy columns on the row are the sole source of truth, and now they are
the only one that exists.** `tenancy_transcription_log` survives 084 and is the
only surviving record of what the dropped rows declared —
`node_type`, `from_partition`, `to_visibility`, `to_group_id` and
`transcribed_at` per node. `ownership.created_at`, `updated_at`, `community_id`
and `encryption_key_id` are gone. `docs/runbooks/084-undo.sql` recreates the
empty shape and says so plainly; it does not bring the rows back.

**What the endpoint census lost.** `GET /api/v1/structural-features/:owner_id`
broke its node counts down by `ownership.node_type` across six tables. After 084
only two tables name an owning agent — `claims.agent_id` and
`perspectives.owner_agent_id` — so `evidence`, `community`, `context` and
`frame` no longer appear in any count. That is the same fail-closed rule the
endpoint already applied to `agent` rows: a node whose owner cannot be
determined is not counted.

**…and what it gained, which is the larger movement.** The census above is the
narrowing; the *dominant* direction is a **widening**. Nothing ever
auto-populated `ownership` — no migration inserts into it, and its only writers
died with PR-14 — so the old owned set was "nodes with an explicit `ownership`
row", in practice near-empty, and the new one is the agent's **entire authored
corpus**. The `claims` arm also carries no `is_current` filter, so node identity
moves from per-lineage to per-**version**. The direction is certain; the
magnitude is exactly the unmeasured **M1**. Do not assume zero: an operator's
numbers can move from near-zero to full-corpus in one release.

**The new key is an author field, not a credential.** `claims.agent_id` is set
from the request body at write time. This endpoint is now a consumer of it, so a
caller with `claims:write` can inflate another agent's public counts. That is
attribution injection into a caller-facing read, **not** a confidentiality leak
— every statement still `AND`s the viewer predicate — and it is tracked against
`D-PR16-claim-authorship-is-not-a-credential`, owned by the write-gate PR. See
`crates/epigraph-db/src/repos/structural.rs`.

**Nothing replaces the deleted write surface, and that is a capability removal,
not a relocation.** There is still no API and no MCP tool that reclassifies an
existing node. Tenancy is stamped at INSERT by migration 070's triggers and by
074's per-table `_require_tenancy` guards; the write-side predicate is owned by
the write-gate PR and is not shipped.

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

### DELETE and UPDATE of a row you do not own (115, 117)

077's policies are FOR ALL with the READ predicate as their USING, so for DELETE
and UPDATE they admitted what a session could read. Two later migrations narrow
that for a non-privileged session:

* **DELETE is owner-scoped (115, 120)** on every tier-A table: the row's owner
  (on `edges`, the owner or co-owner) must be in the session's writable set.
  115 also admitted, for an edge nobody owned, the writer of its SOURCE node;
  120 removed that arm (operator decision D8), so a non-privileged DELETE is
  strictly owner or co-owner scoped.
* **UPDATE of an edge or of an instance-wide registry row is owner-scoped
  (117).** `edges` (owner or co-owner) and `frames`, `contexts`, `perspectives`,
  `communities` (owner): both the row as it was and the row as it will be,
  after `edges_tenancy` has restamped a re-pointed edge. A row nobody owns (a
  world-owned edge, a shared frame) is therefore not updatable by any
  application session; its retraction, relabelling or re-pointing is a
  privileged act. The other tier-A tables already refuse a non-owner's UPDATE
  through their writable-set WITH CHECK and 115's owner-immutability guard.
  A re-point by a non-privileged session (the owner, or a co-owner moving the
  edge off the owner's endpoint) clears the edge's `signature`, `signer_id` and
  `content_hash`: the signed content named the old endpoints.

### Edges between public claims are their writer's (120)

Operator decision D8. `edges.writer_group_id` records the writing session's
group (`epigraph_writer_group()`: the acting operator's personal group, else the
principal's own) on every INSERT, whatever the caller bound; it is never
recomputed and a non-privileged session cannot change it. When both endpoints
are public AND both are epistemic nodes (`claim` or `evidence`; a `synthesis`
source too), the edge is owned by that group and stays public: its writer
patches, retracts and deletes it, and nobody else does. This applies to a
privileged session that carries a principal too; a session with no principal
(a maintenance login, a backfill) writes a world edge. Every other public-meet
edge stays `('public', world)`. A re-point keeps a public edge's owner (the
administrative cascade re-points other writers' edges, and they stay theirs);
mixed and private endpoints keep the meet; an explicit `('group', G)`
declaration between public endpoints is still kept. A public-to-public owner
change of an endpoint (the operator re-own) no longer rewrites any edge; a
narrowing takes the meet, and the privatization revert restores the writer from
`writer_group_id`.

Edges written before 120 carry no attributable author (`signer_id`, where set,
is a bulk attestation key), so they stay world-owned: administrative. A write
refused on an edge the caller can read answers `not_owner` naming the rule
(another writer's, or administrative), never "not found". When an edge's owner
retracts or deletes it, its own edge-keyed BBAs are deleted in the act and every
other writer's are removed by the maintenance replay (cause `edge_retract`); the
replay also re-derives the belief of the claims the owner's own BBAs lived on,
since the owner cannot write another owner's cache. The deferral definer derives
those claims itself, from the session's own BBA rows keyed on the edge, before
the act deletes them; a caller names none. So the replay re-derives only claims
that carried a BBA keyed on the edge. A re-derivation recomputes a claim's
belief from the rows it has, and clears a cache that no surviving row backs.
Two acts on one edge before one replay are both re-derived: the replay reads the
claims of every open deferral of the edge, not only the oldest one's. A
deferral names only an edge out of force (an act that deletes the row closes
its window first). The owner-only rule is row security: it is enforced for
sessions on the application role, and a privileged session bypasses it.

**The retraction cascade is an administrative act (117).** A supersede, a dedup
or a consolidation is the caller's act, written with the caller's authority on
its own stamped transaction. Since batch OA1 the two claim acts need only
`claims:write` plus write authority over the claim: `admin`/`writer`
membership in its owning group (authorship alone admits nothing; for a dedup
the canonical is judged the same way), or `claims:admin`
(`epigraph_auth::claim_act`, shared by HTTP and MCP). The one exception to
"the caller's own stamp" is a `claims:admin` caller over MCP on a claim it does
not write, which acts with the MCP server agent's stamp, as before OA1. A claim the caller cannot
read is answered like a missing one; a readable one it may not retire is
refused as `not_owner` / `not_claim_writer`. What follows it --
re-pointing and retracting other writers' edges, moving and invalidating their
edge-keyed BBAs, re-deriving belief -- runs on the server's maintenance
connection (`epigraph_engine::admin_cascade`). Each repair commits in ONE
transaction with its `security_events` row (`cascade.admin_applied`) naming the
caller, the cause and what it touched; a failed repair rolls back and is
recorded as `cascade.admin_failed`; the belief re-derivation that follows writes
`cascade.belief_rederived`. **Under operator decision D9 (batch W12a) no
request-serving process holds that connection**: the API `server` and
`epigraph-mcp-full` (every transport) refuse to start when
`MAINTENANCE_DATABASE_URL` is set, and attach no maintenance pool. So on a
request path the act commits and the cascade is ALWAYS reported
(`"cascade": {"status": "deferred"}`) and recorded (`cascade.deferred`) in the
act's own transaction; the replay timer (`epigraph-cascade-replay.timer`,
below) applies it, normally within about two minutes. The in-process applied
arm (`apply_after_*` on a maintenance connection the request path holds)
remains only in test harnesses; the replay runs the same functions.

A match-candidate retirement has no caller's act: its flip to `stale` is
administrative too (migration 118's `match_candidates_stale_guard` refuses it on
a non-privileged session). The flip, the matcher-edge retraction and the
derived-row deletes run together, in one transaction, on the maintenance
connection, with one `cascade.admin_applied` row naming the caller. Without the
connection nothing about the candidate changes: the whole retirement is recorded
as a deferred request, with the candidate's status at that moment, and the
replay carries it out only while the candidate still has that status (a
candidate decided again in between fails loudly and stays pending).

What the caller is told is filtered to what it may read: `cascade.touched` is
counts only, and the belief report keeps only claims the caller's viewer can
read. The ids live in the audit rows.

Two rules keep the administrative repair from carrying a decision the caller
could not make: a dedup onto a non-public canonical requires write authority
over the canonical (the repair would move the duplicate's derived rows into the
canonical's group), and a duplicate bound FALSE on `binary_truth` does not hand
that binding to a canonical the caller cannot write.

Every repair re-verifies the committed act and is idempotent, so the
`replay_deferred_cascades` CLI, run on the maintenance DSN (it refuses the
fallback to `DATABASE_URL`), replays every deferred or failed cascade with no
later `cascade.admin_applied` (or `cascade.retired`) row, naming the original
caller and the deferral. The window takes cascades with fewer failed attempts
first; one that has failed `--max-failures` times (default 5; the timer passes
20, about 30 minutes at its 90-second period) is held out and reported as stuck
(the CLI exits 2) until an operator retires it with
`--retire <event id> --reason <text>`. Under D9 it runs on
`epigraph-cascade-replay.timer` as a non-superuser maintenance login, takes its
own advisory lock (a concurrent run does nothing), and
`--report-only` prints `{"pending","stuck","oldest_age_s"}` read-only for the
staleness alert.

**Maintenance work lives in timers and operator CLIs (D9).** Besides the
replay: the job queue is drained by `drain_jobs` (`epigraph-jobs-drain.timer`);
the corpus-wide sweep, belief recompute and embedding backfill are the
`sweep_semantic_duplicates`, `recompute_claim_belief` and `embed_backfill`
CLIs (their MCP tools answer MOVED, JSON-RPC `-32600`); the embedding worklist
route and the whole privatization lifecycle answer HTTP `501` MOVED. The
sweep CLI collapses each pair through the act and `apply_after_dedup`, so
every collapse has a `cascade.admin_applied` row naming `--acting-agent`
(cause `dedup`). Migration 119 lets no application session enqueue a job and
grants the maintenance role the job handlers' DELETEs; `maintenance_timer_only.rs`
pins both, and `maintenance_surface_register.rs` pins that the request crates
acquire no maintenance authority outside the drain.

The replay acts on `security_events` rows, so 117 makes those rows the
server's: a non-privileged session cannot write any `cascade.*` row itself (a
RESTRICTIVE INSERT policy), and a request path records its deferral through the
definer `epigraph_record_cascade_deferral`, which attributes the row to the
session principal and admits it only for an act that session made (write
authority over the retired claim and its successor for a supersede; over the
duplicate, onto a canonical that is public or written by the session, for a
dedup; over every source for a consolidation; an existing candidate for a
match-candidate retirement request, whose table has no tenancy -- the request
paths gate it on `claims:admin`, and the definer records the candidate's status
as the replay's precondition). A non-privileged
UPDATE may point `claims.supersedes` only at a claim that is public or written
by the session.

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

## `restrict` and `seal`: two privatization modes, one of them irreversible (PR-21)

A D4 privatization plan runs in one of two modes, and the difference is not a
setting — it is a different set of guarantees, a different cost, and a different
answer to "can we undo this".

### `restrict` is the default, and it is fully reversible

`restrict` sets `visibility='group'` and `owner_group_id=<target>` and touches
nothing else. `content` keeps its plaintext, `content_tsv` is untouched, and
**the embedding is retained on purpose**.

That last one looks like an oversight and is not. `content`, `content_tsv` and
`embedding` are three columns of the **same row**, and row-level security is
row-level: the predicate that hides one hides all three, atomically. Retaining
the embedding therefore leaks nothing beyond what retaining `content` already
leaks — and `restrict` retains `content` by definition. Dropping it would cost
the owning group its own semantic recall and buy exactly zero confidentiality.

Because nothing was destroyed, **`POST …/revert` puts everything back.** It
walks the plan's items in the mirror order, restores each row's captured
`before_visibility` / `before_owner_group_id`, and re-runs the boundary-edge
meet. There is no re-derivation, no re-embedding, and no new code path — which
is the single strongest argument for `restrict` being the default, and the
reason it is said out loud here rather than left in a design document.

`restrict` is right for roughly 95% of privatizations. The threat it does not
cover — `pg_dump`, physical and logical replicas, filesystem backups, anyone
with the database role — is a **hosting** problem, and hosting has answers for
it that apply uniformly and cost less than per-row application cryptography.

### `seal` is for data whose confidentiality must survive the operator

`seal` is `restrict` **plus** client-side encryption: regulatory holds, NDA
corpora, cross-tenant SaaS. The server never holds the key, so it can neither
seal nor unseal; a key-holding admin drives the ceremony with
`epigraph-privatize`, and the server stores ciphertext and enforces who may
fetch the row that holds it.

**The whole point of `seal` is that nothing derived from the plaintext is left
behind.** That is a set, not a column, and the set is written out below so that
a future change to any of these tables can be checked against it.

#### The SEAL trusted computing base

| Column | On seal | Restored by unseal |
|---|---|---|
| `claims.content` | → `'[sealed:x<id-without-hyphens>]'`; ciphertext to `claim_encryption.encrypted_content` | yes, from client plaintext |
| `claims.content_hash` | → BLAKE3 over the **ciphertext** | yes, verified against the client plaintext |
| `claims.content_tsv` | follows `content` — `GENERATED ALWAYS`, no code | yes, the same way |
| `claims.embedding` | → `NULL` | via an enqueued `embedding_generation` job, which a registered handler drains — but only on an instance whose embedding provider owns this column; see the gaps below |
| `claims.embedding_3072` | → `NULL` | **not restored** — see the gap below |
| `claims.labels` | → `ARRAY[]::text[]`; ciphertext to `claim_encryption.encrypted_labels` | yes |
| `claims.properties` | → `'{}'::jsonb`; ciphertext to `claim_encryption.encrypted_properties` | yes |
| `claim_versions.content` | → sentinel; ciphertext to `claim_version_encryption` | yes |
| `evidence.raw_content` | → `'[sealed]'`; ciphertext to `evidence_encryption` | yes |
| `evidence.embedding`, `evidence.embedding_3072` | → `NULL` | **not restored** — see the gap below |
| `evidence.properties` | → `'{}'`; ciphertext to `evidence_encryption.encrypted_properties` | yes |
| `triples`, `entity_mentions`, `experiment_entity_mentions`, `reasoning_traces`, `challenges`, `experiment_triples` | rows **DELETED** | **no** — re-extraction is a separate, explicit operation |
| `harvester_fragments.content_text`, `.context_window` | blanked, including a fragment cited by claims outside the plan | **no, and not recoverable** — the fragment text *is* the source |

Deleting the derived extractions rather than encrypting them is deliberate: they
are re-derivable from the plaintext, and encrypting each one would multiply the
key ceremony by a table shape apiece for no confidentiality gain. The preview's
`side_effects` block names every one of them before an admin clicks.

A commit that covers only part of that set is **refused, not partially
applied**. A partial seal is worse than none: it reports success while the
plaintext is one `pg_dump` away.

#### What `seal` costs

- **No semantic recall inside the group.** The vector is gone and the server
  cannot recompute it. This is a real product cost, taken deliberately.
- **The extractions are gone**, and `harvester_fragments` source text is gone
  for good. A fragment is one row and can be cited by several claims, so a
  fragment shared with a claim OUTSIDE the plan is blanked for that claim too.
  The alternative — skipping shared fragments — would leave the sealed claim's
  own source text readable, which is the direction a seal exists to prevent. The
  preview's `unrecoverable` line states the over-reach before the admin clicks.
- **It is not server-reversible.** Only a key holder can unseal, and a `seal`
  plan cannot be reverted to `public` until every one of its items has been
  unsealed. A sealed claim can never be declassified: the database refuses it
  with `42501` and there is no override.
- **Ciphertext length is padded, not hidden.** `pad_to` buckets the stored
  length so a one-byte and a two-hundred-byte plaintext are indistinguishable at
  `pad_to=256`; a nine-kilobyte one is still distinguishable from both.

#### Rotation does not re-seal, and re-sealing is a ceremony

As the previous section says, rotating a group key does not re-encrypt anything.
Every `claim_encryption` row stays bound to the epoch it was sealed under, and
`groups.reseal_required_at` is set on member removal to say so. Clearing it
requires a key holder to run `epigraph-privatize reseal`, which unseals under the
retiring epoch's key and re-seals under the new one. The server marks and
measures; it cannot complete the ceremony, and a job that could only ever fail
is deliberately not built.

#### Three known gaps in what unseal restores, stated rather than left to be found

Unseal enqueues one `embedding_generation` job per restored **claim**. Three
things that does not amount to:

- **The handler is registered CONDITIONALLY.** `crates/epigraph-api/src/bin/server.rs`
  does register a handler for that job type, so the enqueued job is a
  restoration rather than a marker — but only where the configured embedding
  provider is the one that owns `claims.embedding`. Writing another provider's
  vectors into that column would put two incompatible vector spaces in one ANN
  column and degrade recall with no error, so an instance configured for any
  other provider — including the development fallback — registers nothing and
  its queue does not drain. `epigraph-cli reembed` remains the recovery path
  there, and it never selects a sealed row.

  This is also why the CLAUDE.md audit clause that hides an unseal-in-flight
  from `live_missing` is still bounded to 24 hours: without the bound an
  unsealed claim on such an instance would be hidden from the audit forever. A
  non-zero count of `embedding_generation` jobs older than the bound now means
  the instance's embedding provider is not the one that owns the column, which
  is a deployment signal rather than a missing-code one.
- **It does not name an evidence row.** The job payload carries a claim id and
  there is no evidence-shaped variant, so an unsealed evidence row keeps NULL
  vectors until a backfill reaches it.
- **It does not restore `embedding_3072` on either table.** That column is
  written by `epigraph-cli reembed`, which is a separate operation from the job.

All three are functional gaps and none is a confidentiality one — the seal nulled
the vectors, which is the safe direction. An operator who wants full recall back
after an unseal runs `epigraph-cli reembed`.
