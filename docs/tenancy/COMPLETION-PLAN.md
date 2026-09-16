# Tenancy completion plan — from "all 22 sections delivered" to "tenancy is enforced"

Successor to `FINAL-PLAN.md`. Measured against `origin/integration/tenancy` = **`be04aabd`**.

`FINAL-PLAN.md`'s 22 sections are **all delivered** — `prs.done` carries 35 entries,
`current` is null, `halted` is null, `failed` is empty. That plan is finished and this
document does not reopen it.

**But the tenancy system is not in force anywhere.** Production is at migration 59 with
the entire 060–091 series unapplied: 3 tables with RLS enabled, against 40 on the
throwaway. `integration/tenancy` is 188 commits ahead of `main` and has never been merged
there, by design. What exists is a complete, tested, reviewed implementation sitting one
conversion, one FORCE step, and one deploy away from doing anything.

This plan closes that distance, and records honestly what closing it does and does not buy.

---

## §0 — The three registers, deduplicated

Residual work is recorded in three places that overlap in exactly one significant way.

| register | count | note |
|---|---|---|
| `open_findings` | 54 | 42 actionable, 12 `ACCEPTED` and deliberately carried |
| `deferred_obligations` | 48 | **45 not stated as discharged**; 3 carry no `status` field at all |
| `no_unscoped_pool.rs` ratchet | 355 sites / 44 files | the conversion tail |

**This table is a POINT-IN-TIME SNAPSHOT, measured 2026-09-16 at the close of conversion shard 5.**
Every shard so far has had to re-sweep it, and a stale row here has already been raised as a
finding twice. Treat the registers themselves as authoritative: `open_findings` /
`deferred_obligations` in `docs/tenancy/progress.json`, and `HIGH_WATER` / `HIGH_WATER_FILES`
in `crates/epigraph-db/tests/no_unscoped_pool.rs`, which are machine-checked and these numbers
are not.

**The `F-` and `D-` id spaces are disjoint — zero overlap, verified by set intersection.**
They are two registers, not one counted twice.

**The one real duplication:** `D-PR17-request-path-never-stamps-session-gucs` *is* the ratchet's
sites. Its own text says "411 `state.db_pool` line hits across ~50 files under routes/".
It is scheduled once, in §2.1, and nowhere else.

Three obligations have **no `status` field**, so their state is unknown rather than open or
closed: `D-PR14-transcription-is-a-deploy-prerequisite`,
`D-PR17-request-path-never-stamps-session-gucs`,
`D-PR17-current-user-refusal-left-as-a-warning`. §6.1 disposes them first, because two are
deploy gates and planning around an unknown is how a gate gets skipped.

---

## §1 — What step 11d actually buys, measured

**This section exists so that finishing §2 is not mistaken for "tenancy is now enforced."**

Measured on the throwaway at head 91, where `claims` is `relrowsecurity = t` and
`relforcerowsecurity = t`. A session running as the **application role**, holding no
membership in the owning group, was able to read a `'group'`-visibility claim; the same
session reads zero rows before the session state is changed. Method and recipe are
deliberately not restated here — see §9 on redaction — and the underlying property is
already documented in `docs/tenancy.md` beside the `allow_declassify` paragraph.

This is **not a new discovery** — it reproduces `D-PR17-tenancy-gucs-are-pgc-userset`,
which already states it: *"the corpus's confidentiality rests on GUCs the database does not
protect… The control is that no code path interpolates untrusted input into a `SET`.
That is a structural convention, not a boundary."*

**So the enforcement boundary is Rust, not Postgres.** It is `apply_session_gucs` being
private with exactly two callers. FORCE RLS defends the corpus against *other* roles —
`pg_dump` as a non-member, a maintenance operator, a second application — and it does not
defend it against the application role itself.

Two consequences the rest of this plan is built on:

1. **11d is worth doing** and is not sufficient on its own.
2. **The Rust-side boundary deserves the same rigour as the SQL one**, which is
   `D-PR17-maintenance-lease-coupling-is-a-convention` (§2.2.4). Making that structural is
   the highest-value item in this plan that nobody has scheduled.

---

## §2 — Critical path: conversion → FORCE-correctness → 11d → deploy

Strictly ordered. Each stage gates the next.

### 2.1 — Drain the conversion tail

**355 sites across 44 files**, per the ratchet's own measurement — it strips comments and
excludes a separately-reviewed exempt set, so a naive `grep` overcounts.
Quote the ratchet, not the grep. (It read 372 across 46 at the close of conversion shard 4;
shard 5 converted 17 more and emptied two files, which is where 355/44 comes from. The
parenthesised naive-grep figure this line used to carry was NOT re-derived by shard 5 and has
been dropped rather than restated stale.) A smaller number is not a discharged decision:
§9.2 step 11d stays blocked until this reaches zero.

Distribution is heavily skewed, which is what makes sharding cheap:

| file | sites |
|---|---|
| `routes/crud.rs` | 40 |
| `routes/workflows.rs` | 40 |
| `routes/claims.rs` | 25 |
| `routes/experiment_loop.rs` | 20 |
| remaining 40 files | 230 |

Re-measured by conversion shard 5 by reimplementing `measure()` over the tree: 40 + 40 + 25 +
20 + 230 = **355 across 44 files**, which is the ratchet's own number. Two corrections to the
row this table used to carry. `routes/claims.rs` is **25, not 26** — the machine-checked
`UNCONVERTED` entry reads 25 both before and after this shard, so the 26 was already stale and
is not something shard 5 changed. And the roll-up row is now exact rather than a `~` estimate.

**Shape: one shard per file, ratchet steps down each time.** This is the pattern PR-23
through PR-29 already established and proved; do not invent a new one. The three largest files
are 105 of the 355 remaining sites — 30% of the tail in three shards.

**Per-shard acceptance:**
- `HIGH_WATER` and `HIGH_WATER_FILES` decrease, never increase, and the new numbers are
  the measurement rather than a round number.
- A converted read is proven to filter — mutation proof with a counterfactual: the
  pre-conversion form must PASS on the same planted tree, or the proof shows nothing.
- No behaviour change in the anonymous surface (`public_router_allowlist.rs` pins it).

**Do not convert `routes/webhooks.rs` or `routes/events.rs`** — that hold predates this
plan and stands.

### 2.2 — FORCE preconditions

Each of these is latent today and bites the moment 11d runs.

**2.2.1 `D-PR17-read-guards-widen-under-rls` — guards invert under FORCE.**
A `WHERE NOT EXISTS (SELECT 1 FROM t …)` over a protected `t` returns nothing to a
non-bypass role, so a dedup guard silently degrades into an unconditional insert. Already
enumerated and pinned by `rls_enforcement.rs::guard_subquery_sites_are_enumerated`. App-pool
sites: `edge.rs::create_symmetric_if_absent`, `::create_symmetric_if_absent_returning`,
**three** sites in `graph_view.rs` and two in `routes/graph_neighborhood.rs`, all over `edges`.
**None is a read leak**; each is a correctness degradation — duplicate edges, or
already-decomposed claims reappearing as undecomposed.
Two reconciliations with that test, which is the authority here and had already corrected this
line. (1) `graph_view.rs` is **three** `NOT EXISTS` clauses across two functions, not two —
the test recorded that upward correction and this sentence had not been re-swept. (2) The two
`routes/graph_neighborhood.rs` sites are no longer plain app-pool: conversion shard 5 moved
`compound_response`, the only function that reaches them, onto a viewer-stamped `read_as`
connection, so they are the one STAMPED row in that table. The SQL is unchanged and the
disposition is unchanged; only the session moved.
**The fix is real unique constraints, not policy changes.** Claims a migration number.

**2.2.2 `D-PR16-seed-grant-to-the-harness-role`.** The *Files* line item "`epigraph_seed`
granted to the test harness pools" was never implemented — no role-membership `GRANT`
exists anywhere in the tree. Until it does, the harness may be unable to exercise FORCE at
all, which would make every 11d test vacuous. **Do this before 2.2.1's tests, not after.**

**2.2.3 `D-PR17-current-user-refusal-left-as-a-warning`.** PR-17's acceptance says the
process *refuses* if `current_user <> epigraph_app`; it ships as a `WARN`. Five of six
listed refusals are armed. Arm the sixth, or amend the acceptance line to say what ships.

**2.2.4 `D-PR17-maintenance-lease-coupling-is-a-convention`** — see §1. Make the coupling
between a bypass `Viewer` and the maintenance connection structural rather than a call-site
convention. Companion: `D-PR17-hybrid-shape-lint`, a lint for the hybrid shape (minting a
bypass viewer and spending it on a non-maintenance pool).

**2.2.5 Remaining FORCE-correctness obligations**, each small and independently landable:
`D-PR17-creator-arm-outlives-membership`,
`D-PR17-live-memberships-is-parameterised-not-principal-bound`,
`D-PR17-agent-projection-enforced-at-one-call-site`,
`D-PR16-undeclared-write-counter-link-uncovered`,
`D-PR25-guc-independence-arm-has-no-positive-premise`,
`D-PR17-structural-force-mode-test`.

### 2.3 — Run step 11d

Only after 2.1 and 2.2. **§9.2 step 11d must not run before then** — that hold has been in
force all series and this plan does not lift it early; it schedules its lifting.

Acceptance: every tenancy table is `relforcerowsecurity`, the guard sites in 2.2.1 are
constraint-backed, and the harness demonstrates a non-bypass role being refused — not a
superuser standing in for one.

### 2.4 — Deploy

**Gated on 11d plus `D-PR14-transcription-is-a-deploy-prerequisite`:** run
`epigraph-tenancy-backfill` to completion and confirm its verify step reports zero
*before* deploying. This is a prerequisite, not a step.

**The six blocked measurements are deploy preconditions, not work items.** `M1`, `M3`–`M7`
each need production database access: the ownership row census, the prod migration head,
row counts for DDL sizing, a session-GUC probe on the real topology, OAuth client
`agent_id` coverage, and the partition split. They cannot be scheduled — they are answered
on the day, and the deploy runbook must require them rather than assume them.

**Migration 084 drops a table and has no `.down.sql`.** `docs/runbooks/084-undo.sql`
exists and is honest about what it cannot restore. Read it before, not during.

---

## §3 — Parallel track A: security items that must not wait

**These are live on today's corpus and independent of 11d.** Scheduling them behind the
remaining conversions would be the wrong order.

**3.1 `D-PR19-webhook-secret-at-rest`** — `webhook_subscriptions.secret` stores the
HMAC-SHA256 signing secret **in plaintext**. Anyone who can read that table can forge
webhook payloads. Highest-severity item in this plan.

**3.2 `D-PR16-ownership-transfer-is-unguarded`** — `claims_block_widening` is
`BEFORE UPDATE OF visibility`, so an `UPDATE` changing **only** `owner_group_id` fires no
guard, and 070 arm (d) then propagates the new owner to all 17 derived tables.

**3.3 `D-PR16-claim-authorship-is-not-a-credential`** — nothing checks that a caller may
author as the `agent_id` in the request body, and `routes/hypothesis.rs` derives
`owner_group_id` from that field. Its own note says it is **misfiled** onto the write-gate
PR and needs a new owner.

**3.4 `D-PR16-recall-events-are-instance-wide`** — `RecallEventRepository::log` stamps
every row `('public', world)`, so `::list`'s viewer predicate is **vacuous** and every
agent's recall history is readable. A predicate that cannot fail is the failure mode this
series names most often.

**3.5 `D-PR16-claim-provenance-trace-read-unfiltered`** — `routes/edges.rs::claim_provenance`
reads `reasoning_traces` inline with no `Viewer`.

**3.6 `F-089-G`** — migration 089's trigger is in neither boot-time allowlist, so a
database whose stamping trigger has been **dropped** boots and serves with no refusal. A
*disabled* one is refused. One-line fix; the asymmetry is the bug.

---

## §4 — Parallel track B: completeness

Ungated. Order within the track is free.

**4.1 Privatization / seal remainder.** `D-PR18-files-line-remainder` (six MCP
privatization tools and their `SCOPE_MAP` bucket, the `epigraph-privatize` CLI, and
`PATCH /claims/:id`), `D-PR18-drift-write-guard` (sec-F9 ships one of two halves),
`D-PR18-applied-webhook-fanout`, and seven `D-PR21-*` items: the evidence-embedding job,
the **unregistered embedding handler** (`bin/server.rs` registers five handlers and none
drains `embedding_generation`, so the job unseal-commit enqueues is a marker rather than a
restoration — this one makes an advertised capability inert), shared-fragment count,
CLI wire-shape pin, manifest paging, clause-10 positive arm, cross-group ciphertext.

**4.2 Webhooks.** `D-PR-webhook-dispatcher-behavioural-test` (type-checked in both `cfg`
arms, behaviour-checked in neither), `D-PR-bin-server-boot-hydration-test`,
`D-PR-webhook-store-invalidation`.

**4.3 Key rotation.** `D-PR20-A` — an epoch advance must carry a fresh base key and a
re-wrapped share for every live member, in the same transaction.

**4.4 Data reconciliation.** `D-PR18-stale-cross-group-edges` — migration 072 changed what
the stamping arms *write* and reconciled no existing row. Needs a one-off pass, and it is
the only item here that touches existing data.

**4.5 Coverage and hygiene.** `D-PR16-theme-cluster-viewer-scope` (registered as
`tenancy_exempt` with viewer-scoped clustering as its compensating control, never
delivered — so the residual has no compensating control), `D-PR16-mcp-http-parity-suite`,
`D-PR16-per-id-claim-oracles-write-half`, `D-PR19-A`/`D-PR19-B`,
`D-PR25-deferred-definer-doc-understates-its-stake`,
`D-PR27-proven-equivalent-sibling-pairs`, `D-PR27-A`, `D-PR27-B`,
`D-PR27-shared-db-test-isolation` (partly discharged by `tenancy/fix-test-integrity`).

**4.6 The 20 `CONVERSION-TAIL` findings.** Filed as EpiGraph backlog claims and recorded in
`~/ops-private/2026-09-13-tenancy-backlog-epigraph-mapping.md`. Several ride along with
§2.1 shards; the rest are independent.

---

## §5 — Investigations, with stated unknown yield

**Six `EMPTY-NEEDS-RE-DERIVATION` findings cannot be estimated**, because nobody knows what
they contain: `F-PR28-claims-list-projection`, `F-PR28-route-arm-extractor-parity`,
`F-PR18a-B1`, `F-PR20-A`, `F-PR20-B`, `F-PR21-A`.

Each says its detail is held outside the repository and **no such record was ever written**.
They are content-free: a location and a shape, no analysis. Re-derive each from the code and
write the private record *in the same sitting* — the failure that produced them was doing
the redaction half without the recording half.

**Do not size these alongside measured work.** Yield is unknown; one may be nothing and one
may be a §3 item.

---

## §6 — Decisions only the operator can make

### 6.1 Dispose the three status-less obligations
Listed in §0. Two are deploy gates. Do this first — it is minutes of work and it removes an
unknown from the critical path.

### 6.2 The nine standing decisions
In `~/tenancy-pending-decisions.md`, filed as EpiGraph backlog claims labelled
`operator-decision`:

- **the privacy-budget mechanism** — resolves three findings at once
- **the unauthenticated-listener posture**
- **`methods.source_claim_ids`** exposure
- **`F-PR18b-A1`** — response assembly, out of band
- **`F-089-A` / `F-089-C`** — *one question from two sides*; answer the first and the second
  follows
- **`F-089-F`** — the harvester trust model

### 6.3 When to merge to `main` — **DECIDED, 2026-09-14. Do not re-open.**

**`integration/tenancy` remains the integration branch, and every item in this plan targets
it. Nothing merges to `main` until end-to-end tests pass against `integration/tenancy`, and
the promotion to production happens after that — not before.**

So the answer to the question this section used to pose is **neither** of the two options it
offered. It framed the choice as "merge to `main` before 11d or after 11d" and omitted the
one the operator actually wanted: **merge after end-to-end validation on the integration
branch**, which is a gate this plan had not accounted for at all.

An earlier revision of this section described the divergence window as "the smallest it will
ever be," which reads as an argument to merge early. That is a real property and it is not a
reason. A merge to `main` is a promotion, and promotion waits on validation rather than on
the convenience of the diff. **The window widening as §2 lands is expected and is not a
cost worth pre-empting.**

Consequences for everything else in this document:

- Every workflow, shard and batch targets `integration/tenancy`. The merge watcher already
  enforces this for `tenancy/*` branches and refuses to merge that branch to `main` by
  design — that refusal is correct and stays.
- §8's acceptance criteria are evaluated **on `integration/tenancy`**, not on `main`.
- The deploy in §2.4 is gated on end-to-end validation in addition to 11d and
  `D-PR14-transcription-is-a-deploy-prerequisite`.

**Standing e2e gate, not yet specified.** This plan does not define what the end-to-end
suite covers, and that is a gap worth naming rather than assuming: §1 establishes that the
enforcement boundary is Rust rather than Postgres, so an e2e suite that exercises only the
HTTP surface would validate the convention and not the boundary. Specifying it is its own
piece of work and belongs to whoever owns the promotion.

---

## §7 — Deliberately not scheduled

**The 12 `ACCEPTED` findings.** Each is carried with a stated reason and needs no owner.
They are not in this plan and were not filed as backlog items, because a queue containing
work nobody should do is the pollution the disposition register exists to prevent.

**The six blocked measurements** appear in §2.4 as deploy preconditions rather than as
items, for the same reason: they cannot be worked, only answered.

---

## §8 — Acceptance for this plan as a whole

**Every criterion below is evaluated on `integration/tenancy`, not on `main`** (§6.3).
Criterion 3 is the one exception, because it is about a running system rather than a branch,
and it is reached only after the end-to-end gate.

1. `HIGH_WATER` reaches its floor and the register documents what remains exempt and why.
2. Step 11d has run, and a **non-bypass role** is demonstrably refused — not a superuser
   standing in for one.
3. Production is at the series head with the backfill verified at zero.
4. `deferred_obligations` contains no entry that is both undischarged and unowned; every
   one is discharged, scheduled, or dispositioned with a reason.
5. `open_findings` contains no `FIX-SCHEDULED` entry whose batch has shipped, and no
   disposition term outside the declared vocabulary. **Both properties are asserted by a
   test, not declared** — each drifted silently during the cleanup series and nothing
   failed.
6. §1's statement is either still true and documented, or no longer true because the
   Rust-side boundary became structural.

---

## §9 — Working rules carried forward

These were learned the expensive way during the 22-section series and the cleanup batches.

- **A finding is a measurement; a brief is an instruction.** Re-measure every count before
  acting. Numerous briefs in the previous series were wrong about counts, file inventories
  and which crates were affected, while being right about the defect.
- **Mutation proofs need counterfactuals.** The pre-fix check must PASS on the same planted
  tree, or the proof shows only that the plant was detected.
- **When the claim is "this transformation moved no number," substitute an identity
  transform and re-run.** Comparing the numbers is blind to a transform that silently does
  nothing.
- **A closed vocabulary needs an assertion, not a declaration.**
- **Redaction has two halves.** Removing detail from this public repository without writing
  the private record destroys the finding. Cite the private file *by name*; a bare "held
  privately" is unverifiable and indistinguishable from one that was never written.
- **`integration/tenancy` is never merged to `main` by the watcher, by design.**
