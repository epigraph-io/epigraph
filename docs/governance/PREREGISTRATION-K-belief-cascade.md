# PRE-REGISTRATION — Cascading belief recomputation downstream of `supersede_claim` / `mark_duplicate`

**Backlog claim:** `20e9ed83-c5f1-4f26-bee5-d6eb105d2635`
**Branch:** `feat/supersede-cascade-recompute` (worktree `/home/jeremy/epigraph-wt-K`, branched from `origin/main` @ `7cd5eeef`)
**Governance agent:** Ada discipline (`/home/jeremy/Ada/agents/governance-agent-template.agent.md`)
**Written:** 2026-08-17 — **BEFORE any implementation.** This file is the answer key.
**Status of this document:** binding. Criteria and challenges below are fixed. An
implementer who cannot satisfy one must record a **protocol deviation** in the commit
body, not silently reinterpret the criterion.

---

## 0. Findings from code inspection that reshape the proposal

The brief's implementation sketch is **wrong in three independent ways**. Two further findings (F4, F5) invalidate the
obvious *fix* for the sketch. All were verified against the worktree, not recalled. These
findings are what the criteria below are built to defend.

### F1 — The sketch's enumeration query returns zero rows

`crates/epigraph-db/src/repos/claim.rs::supersede` migrates outgoing edges *inside* the
transaction, before commit:

```
"UPDATE edges SET source_id = $1 WHERE source_id = $2 AND source_type = 'claim' AND relationship != 'supersedes'"
```

(grep fragment: `Migrate outgoing edges: redirect edges FROM old claim`)

So the sketch's post-`tx.commit()` query `SELECT DISTINCT target_id FROM edges WHERE
source_id = $old_id ...` finds **nothing**: every non-`supersedes` outgoing edge now has
`source_id = new_uuid`, and the one remaining edge touching `old_uuid` is the `supersedes`
edge whose *source* is `new_uuid`. A naive implementation logs "0 downstream claims,
cascade complete" and is confidently, silently wrong.

Additionally, `target_is_current` **does not exist** on `edges`
(`migrations/001_initial_schema.sql::CREATE TABLE public.edges` — columns are
`id, source_id, target_id, source_type, target_type, relationship, labels, properties,
created_at, prov_type, valid_from, valid_to, signature, signer_id, content_hash`).
`grep -rn "target_is_current" migrations/ crates/` returns nothing. The sketch's SQL
would fail at runtime.

### F2 — `recompute_beliefs` on the downstream claim is a numeric NO-OP

This is the finding that invalidates the proposal's *mechanism*, not just its SQL.

`crates/epigraph-engine/src/edge_factor.rs::auto_wire_ds_for_edge` freezes the supporter's
epistemic interval into a **stored mass shape** at wire time
(`restricted.to_mass_function(&frame)` → `MassFunctionRepository::store_with_perspective`,
keyed `perspective_id = edge_id`).

`crates/epigraph-engine/src/edge_factor.rs::compute_combined_belief` — the pure half that
`recompute_claim_belief_on_frame` → `recompute_combined_belief` delegates to — loads
`row.masses` verbatim and re-derives **only the reliability discount** via
`effective_source_strength(row, per_frame_intra, per_frame_evidence_weights, &calibration)`.
It issues **no query against `claims`** at all. Verified:

```
awk '/^async fn compute_combined_belief/,/^}/' crates/epigraph-engine/src/edge_factor.rs \
  | grep -n "FROM claims\|is_current\|SELECT"   # → no matches
```

Therefore **`recompute_beliefs(claim_ids=[B])` after superseding A returns bit-identical
scalars.** Firing the existing `recompute_beliefs` at downstream targets satisfies the
letter of the proposal while leaving the brief's own worked example (B's belief should
move) unmet. Any criterion phrased as "the cascade invokes `recompute_beliefs`" is a
goalpost the implementer can hit while delivering nothing.

**The required primitive is invalidation, not recombination:** the stale
`perspective_id = edge_id` BBA must be *removed* (and optionally re-derived from the
now-current source), then the claim recomputed from what survives. Recombining the existing
rows cannot move the number by construction. **See F4** — re-derivation alone will not
work either, because `A'` is inserted factorless.

**And the trap inside the trap:** `edge_factor::auto_wire_edge_if_epistemic` short-circuits
when a BBA already exists for the edge
(`MassFunctionRepository::exists_for_perspective`, grep fragment `has a BBA EVER been
materialized for this edge_id`). A re-wire that does not first delete the stale
`perspective_id = edge_id` row is a **permanent no-op**. There is currently no
`MassFunctionRepository::delete_for_perspective` — only `delete_for_claim`.

### F3 — `mark_duplicate` already orphans derived records

`ClaimRepository::mark_duplicate` runs three `DELETE FROM edges AS e ...` pre-deletes (the
diamond-duplicate guard and the `alternative_of` symmetric guard, grep fragments
`Drop incoming dup-edges whose migrated triple already exists` and
`Symmetric-collision guard for`). Those deletes remove edges whose edge-factor BBAs live on
in `mass_functions` — `mass_functions_perspective_id_fkey` references `perspectives(id)`,
and `perspectives` rows minted by `PerspectiveRepository::ensure_edge_perspective` have no
FK back to `edges`. So a deleted edge leaves a **phantom supporter** that
`compute_combined_belief` keeps combining forever.

A second, symmetric defect rides along: the `UPDATE edges SET target_id = canonical ...`
migration re-points an edge at `canonical` while its BBA stays on `dup`
(`mass_functions.claim_id = dup`), so `canonical` **under-counts** that supporter
permanently — and it will never be re-wired, because
`MassFunctionRepository::exists_for_perspective` is keyed on `perspective_id` alone and
ignores `claim_id`. Verified: `grep -n "mass_functions" crates/epigraph-db/src/repos/claim.rs`
returns **nothing** — `mark_duplicate` touches only `edges` and `claims`.

This is precisely MemTX I2 ("retracting a belief leaves no orphaned derived record")
violated in the existing code. It is in scope for this change and is criterion **C5**.

### F4 — The replacement claim `A'` is inserted **factorless**

`ClaimRepository::supersede`'s INSERT column list is
`(id, content, content_hash, truth_value, agent_id, supersedes, is_current, labels,
created_at, updated_at)` — **no `belief`, no `plausibility`, no `open_world_mass`**. Nothing
in `migrations/` populates those columns by default or by trigger (verified:
`grep -rn "belief" migrations/*.sql | grep -i "trigger\|default\|function\|generated"`
returns only unrelated comment text and `behavioral_executions.step_beliefs`).

`auto_wire_ds_for_edge` gates on exactly those columns:

```rust
let Some((Some(bel), Some(pl), ow_opt)) = source_row else {
    return Ok(EdgeFactorOutcome::SourceFactorless);
};
```

So "delete the stale BBA and re-wire the edge from `A'`" **cannot reproduce a comparable
number** — `A'` has no interval, the re-wire returns `SourceFactorless`, and `B` simply
loses that supporter. That is a defensible semantics (a retracted supporter stops
supporting until the replacement earns its own interval), but it is a *decision*, and the
criteria below fix the observable rather than the mechanism. In particular it means a
criterion of the form "identical `truth_value` in ⇒ identical downstream BetP out" is
**unsatisfiable** and must not be pre-registered; C3 is framed instead around
calibration-field stability.

### F5 — An empty surviving BBA set writes nothing at all

`edge_factor::recompute_claim_belief_on_frame` and `compute_combined_belief` both
short-circuit:

```rust
let all_rows = MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id).await?;
if all_rows.is_empty() { return Ok(false); }
```

If the retracted supporter's BBA was `B`'s **only** BBA, invalidate-then-recompute leaves
`B`'s cached `pignistic_prob` **frozen at its pre-retraction value** while the cascade
reports `frame_writes: 0, errors: []`. Every "did the cascade run" criterion passes and the
feature does nothing. C6 pins the required semantics.

### F6 — Layer placement

A `tokio::spawn` inside `ClaimRepository::supersede` (as the brief sketches) makes every
caller — including every `#[sqlx::test]`, which tears down a throwaway DB when the test
body returns — subject to background writes racing teardown. Flaky by construction, and it
puts orchestration in the repo layer, contrary to `CLAUDE.md` ("All SQL stays in
`crates/epigraph-db/src/repos/`… routes and MCP tools both call the repo layer").

The in-repo precedent for exactly this shape is
`crates/epigraph-api/src/routes/edges.rs::propagate_to_dependents` — call-site
orchestration, 1-hop bound, `visited: HashSet` cycle guard, best-effort with
`tracing::warn!` on failure, never fails the parent write.

---

## 1. Ada Gate 1 verdict

### Verdict: **POSITIVE**

The change adds a capability — automatic epistemic repair downstream of retraction — that
callers currently have to hand-roll. Applying the discriminating test (*does any existing
caller lose an ability or acquire a new failure mode?*):

- Manual `recompute_beliefs(claim_ids=[...])` remains fully callable and unchanged. The
  cascade is an *additional* trigger, not a replacement, and not a prohibition on the
  manual path.
- No new required parameter on `SupersedeClaimParams` or `MarkDuplicateParams`. The brief
  is explicit that the retraction cascade is implicit.
- Response shape gains keys; it does not remove or rename any.
- No new mandatory confirmation checkpoint (Gate 2 also passes): the cascade is
  best-effort and non-blocking, so autonomy cost is zero.

**Evidence classification:** the 2026-07-28 impact report (claim `1f7d2052`) plus the
verified F1–F3 code findings above are **TYPE-B** (traceable artifact — the orphaned-BBA
defect in `mark_duplicate` is present in `origin/main` today). MemTX (arXiv:2607.23929) is
**TYPE-C**, supporting only. TYPE-B is sufficient alone for a FORMAL RC.

### The one genuine Gate 1 tension, and its resource-form resolution

A fire-and-forget cascade makes post-supersede reads **racy**: a caller that reads B's
`pignistic_prob` immediately after `supersede_claim` returns can no longer reason about
whether the value has settled. That is a real narrowing of what the caller can reason
about.

The capability-vs-constraint test says: choose the resource form. The resolution is **not**
"callers must sleep before reading" (a prohibition) but **"the response reports the
cascade's target set and outcome, so the caller can observe what was scheduled and
re-read or await it."** That is an additive response field and it converts the tension
into a capability. This is criterion **C1(b)**.

### Conditions that would flip this verdict to CONSTRAINED (automatic REJECT)

Any one of these appearing in the implementation reverses the verdict:

1. Cascade failure propagating into `supersede`'s / `mark_duplicate`'s `Result`. Supersede
   currently succeeds without the belief subsystem being healthy; making it fail is a
   strictly narrower action space.
2. A **blocking / synchronous** cascade that changes latency semantics of the write path.
3. Any new **required** field on `SupersedeClaimParams` or `MarkDuplicateParams`.
4. Changing `ClaimRepository::supersede`'s return type from `Result<(Uuid, Uuid), DbError>`
   to a struct (compile break for `routes/versioning.rs::supersede_claim` and
   `tools/supersede.rs::supersede_claim`), or `mark_duplicate`'s from `Result<(), DbError>`.
5. Removing or renaming any existing response key: `new_claim_id`, `superseded_claim_id`,
   `reason`; `duplicate_id`, `canonical_id`, `mode`.

---

## 2. Criterion gates

Eight gates, fixed now. Each is decided by running the named command. **C2, C4, C5 and C6
must FAIL at `HEAD` (`7cd5eeef`) before the change** — that failure output is required in
the commit's `**Verification:**` block.

Standard invocation for every DB-backed criterion. Never the prod `epigraph` database on
`epigraph-postgres`; `#[sqlx::test(migrations = "../../migrations")]` mints a throwaway DB
per test off this URL:

```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p <crate> --test <file>
```

---

### C1 — Backward compatibility: no existing caller loses anything, and the new race gets a resource

**Statement.** Two halves of one contract claim.

*(a) Nothing is taken away.* `ClaimRepository::supersede` keeps signature
`Result<(Uuid, Uuid), DbError>`; `ClaimRepository::mark_duplicate` keeps
`Result<(), DbError>`; `SupersedeClaimParams` and `MarkDuplicateParams` gain no required
field; the MCP responses still contain every pre-existing key (`new_claim_id`,
`superseded_claim_id`, `reason`; `duplicate_id`, `canonical_id`, `mode`).

*(b) Something is added.* Because a fire-and-forget cascade makes post-write reads racy,
both responses gain an **additive** field reporting the cascade's target claim ids and
outcome, so a caller can observe what was scheduled instead of being told to wait blindly.
This is the resource-form answer to the Gate 1 tension in §1.

**Pass.** `git -C /home/jeremy/epigraph-wt-K diff origin/main -- crates/epigraph-mcp/src/types.rs`
shows no added non-`Option` field on either params struct; the two return types are
byte-identical in the diff; a named test
(`crates/epigraph-mcp/tests/supersede_cascade_reports_targets.rs`) asserts the new field
lists the downstream target for the C2 fixture **and** that all pre-existing keys are still
present; and

```bash
DATABASE_URL=... cargo test -p epigraph-mcp --test supersede_claim_test --test mark_duplicate_test
DATABASE_URL=... cargo test -p epigraph-db --test mark_duplicate_repo \
  --test supersede_nulls_embedding --test supersede_carries_labels_and_filters \
  --test mark_duplicate_nulls_embedding
DATABASE_URL=... cargo test -p epigraph-api --test supersede_scope_check_test
```

all pass with **those files unmodified** in the diff.

**Refute.** A required params field added; a return type changed to a struct; an existing
response key removed or renamed; any of the listed test files edited to accommodate the
change; **or** the cascade is entirely unobservable (no new field), which narrows caller
reasoning with no compensating resource and flips Gate 1 to CONSTRAINED.

---

### C2 — ANCHOR: the downstream claim's cached belief stops reflecting the retracted supporter

**MUST FAIL AT `HEAD`.** This is the criterion F2 exists to protect.

**Statement.** Fixture: claim `A` with a belief interval; claim `C` with a belief interval;
claim `B`. Two epistemic edges wired through the normal edge-write path so `B` carries
**two** edge-factor BBAs: `A --supports--> B` and `C --supports--> B`. Record
`B.pignistic_prob` as `betp_before`. Supersede `A`. Re-read `B.pignistic_prob` as
`betp_after`.

**Pass.** Both hold, with **no manual `recompute_beliefs` call anywhere in the test body**:

1. `(betp_after - betp_before).abs() > 1e-9` — the retraction moved the number.
2. `betp_after` equals `edge_factor::preview_claim_belief_on_frame(pool, B, binary_frame)`
   to within `1e-12` — the cached scalar is coherent with `B`'s **post-cascade**
   `mass_functions` set. This is the implementation-agnostic form: whether the
   implementation deletes the stale BBA, re-derives it from `A'`, or discounts it, the
   cache must equal what the canonical combine pipeline produces from what actually
   survives.

**Refute.** `betp_after == betp_before` while the implementation reports a successful
cascade — the exact failure mode of "enumerate targets → call `recompute_beliefs`" (F2).
Scored as a **failed** criterion, not a partial pass. Also refuted if the cache diverges
from `preview_claim_belief_on_frame`.

**Deliberately NOT pre-registered.** (i) "B's belief *decreases*" — direction depends on
the surviving set; pre-registering a direction would license an implementation that always
pushes belief down. (ii) "the direction matches the sign of the change in the supporter's
interval" — per F4, `A'` has no interval, so that clause is unevaluable.

**How checked.** `DATABASE_URL=... cargo test -p epigraph-db --test supersede_cascade_recompute -- downstream_cache_drops_retracted_supporter`
(or the `epigraph-mcp` equivalent if orchestration lands there per C7). Run at `HEAD`
first; paste the failure into the commit body.

---

### C3 — CONTROL: the cascade is surgical, not a global rewrite

**Statement.** Using the C2 fixture plus an unrelated claim `D` (own BBA, no edge to `A`,
`B` or `C`): superseding `A` must not rewrite state it has no business touching.

**Pass.** After the cascade:

1. The `C --supports--> B` mass-function row's `(masses, source_strength, evidence_type,
   locality_tag, perspective_id)` are **byte-identical** to their pre-cascade values. The
   cascade must not re-derive calibration-owned fields on BBAs whose edges the retraction
   never touched.
2. `D`'s cached `(belief, plausibility, pignistic_prob, conflict_k, missing_mass)` are
   bit-identical, and `D.updated_at` is unchanged.

**Refute.** Any of those columns moves. A cascade whose numbers shift on untouched rows is
silently rewriting the graph's calibration on every supersede, and "the cascade ran" then
carries no information about whether the number is right.

**Note on why this is not the obvious control.** The naive control — "supersede with an
identical `truth_value` ⇒ downstream BetP unchanged" — is **unsatisfiable** under F4 and is
therefore explicitly excluded: `A'` is inserted with no `belief`/`plausibility`, so no
correct implementation can reproduce `A`'s BBA from `A'`. Pre-registering it would refute
correct work.

**How checked.** `DATABASE_URL=... cargo test -p epigraph-db --test supersede_cascade_recompute -- cascade_does_not_touch_unrelated_bbas_or_claims`

---

### C4 — Enumeration survives the in-transaction edge migration

**MUST FAIL AT `HEAD`.** The assertion must be written so the *naive* post-commit
`source_id = old_id` query also fails it.

**Statement.** For the C2 fixture, the cascade's computed target set contains `B` (is
non-empty), and the implementation queries no column named `target_is_current`.

**Pass.** The cascade's reported target list (the C1(b) field, or a directly-tested pure
enumeration helper) contains `B`; and
`grep -rn "target_is_current" /home/jeremy/epigraph-wt-K/crates /home/jeremy/epigraph-wt-K/migrations`
returns **zero** hits.

**Refute.** Target set is empty / the cascade logs "0 downstream claims"; or
`target_is_current` appears anywhere in the diff (it is not a column on `edges` — F1).

**How checked.** Same test binary as C2, plus the grep above.

---

### C5 — MemTX I2: `mark_duplicate` leaves no orphaned **or stranded** derived record

**MUST FAIL AT `HEAD`.** `grep -n "mass_functions" crates/epigraph-db/src/repos/claim.rs`
returns nothing today — `mark_duplicate` never touches `mass_functions`, so both defects
below are live in `origin/main`.

**Statement.** Edge-factor BBAs are stored on the edge's **target** claim
(`auto_wire_ds_for_edge` → `store_with_perspective(pool, target_id, ...)`), keyed
`perspective_id = edge_id`, and `MassFunctionRepository::exists_for_perspective` is keyed on
`perspective_id` **alone** — it ignores `claim_id`. `mark_duplicate` mutates only `edges`
and `claims`. Two failure classes follow and both must be closed:

*(a) Orphaned.* The three `DELETE FROM edges AS e ...` pre-deletes (diamond-duplicate guard
and `alternative_of` symmetric guard) leave BBA rows whose `perspective_id` matches no
surviving edge. `mass_functions_perspective_id_fkey` points at `perspectives(id)` and
`perspectives` has no FK to `edges`, so nothing cascades.

*(b) Stranded.* `UPDATE edges SET target_id = canonical WHERE target_id = dup ...` re-points
an edge at `canonical` while its BBA stays on `dup` (`mass_functions.claim_id = dup`).
`canonical` **under-counts** that supporter permanently, and
`auto_wire_edge_if_epistemic` will never re-wire it because `exists_for_perspective(edge_id)`
still returns `true`.

**Pass.** Fixture: third claim `T` with `T --corroborates--> dup` **and**
`T --corroborates--> canonical` (diamond, both wired), plus a fourth claim `U` with
`U --supports--> dup` only (migration case). After `mark_duplicate(dup, canonical)`:

```sql
-- (a) no orphans: every edge-perspective BBA has a live edge
SELECT count(*) FROM mass_functions mf
  JOIN perspectives p ON p.id = mf.perspective_id AND p.perspective_type = 'edge'
 WHERE NOT EXISTS (SELECT 1 FROM edges e WHERE e.id = mf.perspective_id);       -- must be 0

-- (b) no strandings: every edge-perspective BBA sits on its edge's current target
SELECT count(*) FROM mass_functions mf
  JOIN perspectives p ON p.id = mf.perspective_id AND p.perspective_type = 'edge'
  JOIN edges e ON e.id = mf.perspective_id
 WHERE e.target_type = 'claim' AND e.target_id <> mf.claim_id;                  -- must be 0
```

and `canonical`'s cached scalars were recomputed **after** both repairs (coherent with
`preview_claim_belief_on_frame`, as in C2).

**Refute.** Either count > 0 — a phantom or an invisible supporter. Also refuted if the rows
are repaired but `canonical`'s cached scalars still reflect the pre-repair set.

**How checked.** `DATABASE_URL=... cargo test -p epigraph-db --test mark_duplicate_cascade_recompute -- diamond_and_migration_leave_no_orphaned_or_stranded_bba`

---

### C6 — The empty surviving BBA set has explicitly-decided semantics

**MUST FAIL AT `HEAD`.** This is the criterion F5 exists to protect.

**Statement.** Fixture: `A --supports--> B` is `B`'s **only** BBA on the binary frame.
Record `betp_before`. Supersede `A`. Per F5, `recompute_claim_belief_on_frame` returns
`Ok(false)` and writes nothing, leaving `B` frozen at `betp_before` while the cascade
reports `frame_writes: 0, errors: []`.

The implementation must **pick one** of these and the test must assert it:

- **(i) Vacuous reset** — `B`'s cached scalars are reset to the frame's prior / vacuous
  values (`belief = 0`, `plausibility = 1`, `pignistic_prob = 0.5` on the binary frame,
  `missing_mass = 1`), or
- **(ii) Explicit unbacked marker** — the scalars are set to `NULL` (or an equivalent
  documented "no evidence" state) so downstream readers can tell "unbacked" from "believed
  at 0.79".

**Pass.** `B`'s post-cascade scalars match the chosen semantics exactly, the choice is
documented in a doc comment on the cascade entry point, and the cascade's reported outcome
distinguishes this case from "nothing to do".

**Refute.** `B.pignistic_prob == betp_before` — the retracted supporter's belief survives
its own retraction with no evidence backing it. This is the single most likely silent
failure of an otherwise-correct implementation, and it must be scored as failed.

**How checked.** `DATABASE_URL=... cargo test -p epigraph-db --test supersede_cascade_recompute -- sole_supporter_retraction_does_not_leave_frozen_belief`

---

### C7 — Structural discipline: bounded, cycle-safe, best-effort, orchestrated at the call site

**Statement.** The cascade mirrors the in-repo precedent
`crates/epigraph-api/src/routes/edges.rs::propagate_to_dependents` on all four axes:

1. **Bounded** to 1 hop, with an explicit `visited` set (`HashSet<Uuid>` or equivalent).
2. **Cycle-safe**: terminates on `A --supports--> B` + `B --supports--> A`.
3. **Best-effort**: cascade failure is `tracing::warn!`-ed and swallowed;
   `supersede` / `mark_duplicate` still return `Ok`. (Propagating the error into the
   `Result` is Gate-1 CONSTRAINED — see §1 flip-condition 1.)
4. **Orchestrated at the call site**, not in the repo layer: no `tokio::spawn` inside
   `ClaimRepository::supersede` / `mark_duplicate`, and `supersede`'s transaction body
   between `pool.begin()` and `tx.commit()` is unchanged. New SQL, if any, is a repo
   function in `crates/epigraph-db/src/repos/` (e.g.
   `MassFunctionRepository::delete_for_perspective`, which does not exist yet — only
   `delete_for_claim` does), never inline in a route or tool.

**Pass.** The cyclic-fixture test completes under the default `cargo test` timeout with no
stack overflow; a test asserts `supersede_claim` returns success when the belief subsystem
cannot run (e.g. downstream claim carries no frames);
`git -C /home/jeremy/epigraph-wt-K diff origin/main -- crates/epigraph-db/src/repos/claim.rs`
contains no `tokio::spawn` and no change inside the `supersede` transaction; and
`grep -rn "sqlx::query" crates/epigraph-mcp/src/tools/supersede.rs crates/epigraph-api/src/routes/versioning.rs`
shows no new raw SQL from this diff.

**Refute.** Test hangs or overflows; an unbounded recursive `edges` walk with no visited set
or depth cap; a cascade error reaching the caller as `Err`; `tokio::spawn` in the repo
layer; or new raw SQL in a route/tool.

**How checked.** `DATABASE_URL=... cargo test -p epigraph-db --test supersede_cascade_recompute -- cyclic_support_terminates cascade_failure_does_not_fail_the_write`
plus the two greps and the diff inspection above.

---

### C8 — Full CI gate, green, on a modified tree

**Statement.** The repo's standard gate passes with the change applied, `.sqlx` offline
cache consistent.

**Pass.** All four exit 0, in order:

```bash
cd /home/jeremy/epigraph-wt-K
cargo fmt --all -- --check
SQLX_OFFLINE=true cargo check --workspace
cargo clippy --all-targets -- -D warnings
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p epigraph-db -p epigraph-mcp
```

**Refute.** Any non-zero exit; `.sqlx/` regenerated against anything other than a throwaway
database (never `epigraph` on `epigraph-postgres`); or the suite is green only because the
new tests do not exercise the changed path — cross-checked by C2/C4/C5/C6 each having been
shown to **fail at `HEAD`**.

---

## 3. BCH-style regression challenges

Modelled on `/home/jeremy/Ada/benchmark_challenges/*.yaml`. Each is a case where a
plausible naive implementation is **confidently wrong**. Expected score at `HEAD`: 0/100;
required after the change: ≥90/100.

---

### BCH-EG-K01 — Post-commit enumeration finds nothing

```yaml
id: BCH-EG-K01
title: "Supersede cascade: enumerating downstream targets after in-transaction edge migration"
tier: hard
domain: epigraph_belief_cascade
ground_truth_tier: CONFIRMED
```

**Setup.** After `ClaimRepository::supersede(old, ...)` commits, the implementer runs
`SELECT DISTINCT target_id FROM edges WHERE source_id = $old_id AND relationship IN
('supports','corroborates','elaborates') AND target_is_current = true` to find downstream
claims to recompute. `A --supports--> B` existed before the supersede.

**Wrong answer (naive, confident).** "0 downstream claims; the retracted claim had no
dependents; cascade complete." Or a runtime
`column "target_is_current" does not exist` that gets `unwrap_or_default()`-ed into the
same empty set.

**Right answer.** `supersede` re-points every non-`supersedes` outgoing edge to `new_uuid`
*inside the transaction* (grep fragment `Migrate outgoing edges: redirect edges FROM old
claim`), so `source_id = old_id` matches nothing after commit — the only remaining edge
touching `old_uuid` is the `supersedes` edge, whose *source* is `new_uuid`. The target set
must be captured **before** the migration (inside the tx, or returned from the repo call) or
enumerated from `new_uuid` afterwards. `target_is_current` is not a column on `edges`;
currency lives on `claims.is_current` and must be joined for.

---

### BCH-EG-K02 — `recompute_beliefs` reports success and changes nothing

```yaml
id: BCH-EG-K02
title: "A cascade that recombines stale BBAs is a numeric no-op"
tier: hard
domain: epigraph_belief_cascade
ground_truth_tier: CONFIRMED
```

**Setup.** The cascade correctly identifies downstream claim `B` and calls
`tools::cdst_maintenance::recompute_beliefs(claim_ids=[B])`, which returns
`{claims_recomputed: 1, frame_writes: 1, errors: []}`. The implementer reports the feature
working and retires the backlog item.

**Wrong answer (naive, confident).** "Cascade verified: 1 claim recomputed, belief refreshed
from current `mass_functions` state."

**Right answer.** `B`'s `pignistic_prob` is **bit-identical**.
`edge_factor::compute_combined_belief` reads `mass_functions.masses` verbatim — frozen at
wire time by `auto_wire_ds_for_edge` (`restricted.to_mass_function(&frame)`) — and
re-derives only the reliability discount from `(evidence_type, locality_tag,
per-frame overrides, calibration)`. It issues **no query against `claims`**, so the
supporter's `is_current` / `belief` never enters the computation. Repair requires
**invalidating** the `perspective_id = edge_id` BBA (and then recomputing from what
survives), because `auto_wire_edge_if_epistemic` short-circuits on
`exists_for_perspective`. A green `recompute_beliefs` result is evidence of nothing here.

---

### BCH-EG-K03 — Dedup leaves the derived record orphaned on one side and stranded on the other

```yaml
id: BCH-EG-K03
title: "mark_duplicate mutates edges only; edge-factor BBAs are left behind"
tier: hard
domain: epigraph_belief_cascade
ground_truth_tier: CONFIRMED
```

**Setup.** `T --corroborates--> dup` and `T --corroborates--> canonical` both exist and both
have wired edge-factor BBAs; separately `U --supports--> dup`. `mark_duplicate(dup,
canonical)` pre-deletes the redundant `T→dup` edge (diamond guard) and re-points `U→dup` to
`U→canonical`. The new cascade then recomputes `canonical`'s belief.

**Wrong answer (naive, confident).** "Cascade recomputed `canonical` after dedup; its BetP
now reflects the merged evidence." Two things are wrong at once and the number is not
merged evidence.

**Right answer.** `auto_wire_ds_for_edge` stores each BBA on the edge's **target**, so both
of these BBAs live on `dup` (`mass_functions.claim_id = dup`), and `mark_duplicate` touches
only `edges` and `claims` — `grep -n "mass_functions" crates/epigraph-db/src/repos/claim.rs`
returns nothing. Consequently:
(a) the `T→dup` BBA is **orphaned** — its edge is gone but
`mass_functions_perspective_id_fkey` points at `perspectives(id)` and `perspectives` has no
FK to `edges`, so nothing cascades; it keeps being combined on `dup` forever;
(b) the `U→canonical` BBA is **stranded** on `dup`, so `canonical` **under-counts** `U`
permanently — and `auto_wire_edge_if_epistemic` will never re-wire it, because
`exists_for_perspective` is keyed on `perspective_id` alone and ignores `claim_id`.
The repair must delete BBAs alongside their deleted edges **and** move BBAs alongside
migrated edges, in the same transaction, before recomputing `canonical`. Checking only
"no BBA whose `perspective_id` lacks a live edge" catches (a) and misses (b).

---

### BCH-EG-K04 — The sole supporter is retracted and the belief silently freezes

```yaml
id: BCH-EG-K04
title: "Empty surviving BBA set: Ok(false) writes nothing"
tier: hard
domain: epigraph_belief_cascade
ground_truth_tier: CONFIRMED
```

**Setup.** `B`'s only BBA on the binary frame came from `A --supports--> B`. `B.pignistic_prob
= 0.79` — the brief's own worked example. `A` is superseded. The cascade invalidates the
stale BBA, then calls the canonical recompute, which returns
`Ok(false)` / `{frame_writes: 0, errors: []}`.

**Wrong answer (naive, confident).** "Zero frame writes — the claim has no BBAs, so there is
nothing to recompute. Cascade complete." `B` is left believed at **0.79 with no evidence
backing it whatsoever**, and every "did the cascade run" assertion passes.

**Right answer.** `recompute_claim_belief_on_frame` and `compute_combined_belief` both
`return Ok(false)` / `Ok(None)` on `all_rows.is_empty()` and perform **no write** — the
cached scalars on `claims` are a stale cache, not a derived view, so "nothing to recompute"
is not the same as "nothing to change." Retraction of the sole supporter must explicitly
reset `B` to a vacuous state (`belief = 0`, `plausibility = 1`, `pignistic_prob = 0.5`,
`missing_mass = 1` on the binary frame) or to a documented unbacked marker (`NULL`
scalars) so readers can distinguish "unbacked" from "believed at 0.79". Also note per F4
that `A'` is inserted with no `belief`/`plausibility`, so this empty-set path is the
**common** case for a single-supporter retraction, not an edge case.

---

### BCH-EG-K05 — Cycle in the support graph

```yaml
id: BCH-EG-K05
title: "Cascade recursion on a mutually-supporting claim pair"
tier: medium
domain: epigraph_belief_cascade
ground_truth_tier: CONFIRMED
```

**Setup.** `A --supports--> B` and `B --supports--> A`. `A` is superseded. The cascade
recomputes `B`; `B`'s belief changed, so the implementer recursively cascades from `B`,
which recomputes `A'`, whose belief changed, which cascades back to `B`…

**Wrong answer (naive, confident).** "Cascade propagates transitively until belief converges
— Dempster–Shafer combination is a contraction, so it settles." It does not: each pass
re-derives BBAs from freshly written intervals; the test hangs or the connection pool
starves. Convergence of a combination rule is not a termination argument for a graph walk.

**Right answer.** Bound it exactly as the existing in-repo precedent does —
`routes/edges.rs::propagate_to_dependents`: **1 hop**, an explicit `visited: HashSet<Uuid>`
seeded with the origin claim, best-effort, `tracing::warn!` on failure, and never failing
the parent write. If deeper propagation is wanted later, it is a separate, separately
pre-registered change with its own termination argument.

---

### BCH-EG-K06 — "Fail loudly" turns a committed write into a reported failure

```yaml
id: BCH-EG-K06
title: "Best-effort cascade vs. supersede's success contract"
tier: easy
domain: epigraph_belief_cascade
ground_truth_tier: CONFIRMED
```

**Setup.** `ensure_binary_frame` errors, or the downstream claim carries no frames, or
calibration is unreadable. The implementer propagates the cascade error with `?` so failures
are "not silently swallowed."

**Wrong answer (naive, confident).** "Fail loudly — a cascade error means the graph is
inconsistent, so `supersede_claim` should report failure." The supersede transaction has
**already committed**. The caller sees an error for a write that succeeded, retries, and
gets `"Claim <uuid> has already been superseded"` — a wedged, unrecoverable state for an
autonomous agent.

**Right answer.** Best-effort, per the brief and per
`routes/edges.rs::propagate_to_dependents`: `tracing::warn!` and continue;
`supersede` / `mark_duplicate` still return `Ok`. Under Ada Gate 1, making a
previously-succeeding write fail because a **new** subsystem is unhealthy strictly narrows
the caller's action space and flips the verdict to CONSTRAINED — an automatic reject. The
observability answer is the additive response field of C1(b), not a propagated error.

---

## 4. Protocol deviation log

*(Implementer appends here. Any criterion reinterpreted, skipped, or replaced must be
recorded with its reason **before** the commit lands. Silently redefining a pass condition
is the failure mode this document exists to prevent.)*

### D1 — Test crate: `epigraph-mcp`, not `epigraph-db` (affects the "How checked" line of C2, C3, C4, C5, C6, C7)

C2/C3/C6/C7 name `cargo test -p epigraph-db --test supersede_cascade_recompute` and C5 names
`-p epigraph-db --test mark_duplicate_cascade_recompute`. Both are **unrunnable as written**:
C7 forbids repo-layer orchestration, and the dependency edge is `epigraph-engine → epigraph-db`,
never the reverse, so an `epigraph-db` test cannot reach the DS combine pipeline the cascade needs.

C2 anticipates this ("or the `epigraph-mcp` equivalent if orchestration lands there per C7"), and
that is what happened. The criteria are unchanged; only the binary they run in moved:

| Criterion | Test |
|---|---|
| C2 | `epigraph-mcp --test supersede_cascade_recompute -- downstream_cache_drops_retracted_supporter` |
| C3 | `… -- cascade_does_not_touch_unrelated_bbas_or_claims` |
| C4, C1(b) | `epigraph-mcp --test supersede_cascade_reports_targets -- supersede_reports_the_downstream_target_it_repaired` |
| C5 | `epigraph-mcp --test mark_duplicate_cascade_recompute -- diamond_and_migration_leave_no_orphaned_or_stranded_bba` |
| C6 | `… supersede_cascade_recompute -- sole_supporter_retraction_does_not_leave_frozen_belief` (+ the reported-outcome half in `supersede_cascade_reports_targets`) |
| C7 | `… supersede_cascade_recompute -- cyclic_support_terminates cascade_failure_does_not_fail_the_write` |

Every fixture drives the real MCP tool rather than the engine helper, so deleting the cascade call
from the call site turns them red — a strictly stronger test than the pre-registered one.

### D2 — Orchestration lives in a shared engine module, not literally inline at each call site (C7.4)

C7.4 says "orchestrated at the call site, not in the repo layer". The sequencing lives in
`crates/epigraph-engine/src/retraction_cascade.rs`, which **both** call sites
(`epigraph-mcp/src/tools/supersede.rs`, `epigraph-api/src/routes/versioning.rs`) invoke. Inlining
it twice would duplicate the logic across the MCP and HTTP paths — exactly what
`edge_factor`'s own module doc says it exists to avoid. C7.4's actual checks all hold: no SQL in
the tool or route, no `tokio::spawn` in the repo layer, `supersede`'s transaction body byte-identical.

### D3 — The cascade is **awaited**, not `tokio::spawn`ed (§1 flip-condition 2)

Flip-condition 2 names "a blocking / synchronous cascade that changes latency semantics". Read as
*the write's `Result` must not depend on the cascade*, not *the cascade must run off-thread*, because
the alternative reading is self-contradictory with the rest of this document:

* C1(b) requires the response to report the cascade's **outcome**, which cannot be known before it runs.
* C2 requires the moved number to be observable "with no manual `recompute_beliefs` call anywhere in
  the test body" — fire-and-forget makes that a race.
* F6 rules out a detached task independently (it races `#[sqlx::test]` teardown).
* The precedent C7 tells us to mirror, `routes/edges.rs::trigger_edge_ds_recomputation`, **awaits**
  `propagate_to_dependents` inline and is best-effort.

Success semantics are unchanged: `supersede` / `mark_duplicate` still return `Ok` when the cascade fails.

### D4 — C6 resolved as **(ii) explicit unbacked marker**, not (i) vacuous reset

The scalars (`belief`, `plausibility`, `pignistic_prob`, `mass_on_empty`, `mass_on_missing`) **and**
`classification` are set to `NULL`. Rationale: NULL already means "no BBA yet" elsewhere in this repo
(`link_epistemic_smoke.rs`: *"target must start with NULL pignistic_prob (no BBA yet)"*), whereas the
option-(i) tuple is a value `compute_combined_belief` can legitimately produce, so it would be
indistinguishable from a real result — defeating the very purpose of the criterion. `classification`
is included because it is derived from the same evidence; leaving `supported` on an unbacked claim
would be the orphaned derived record C5 exists to eliminate. Documented on the cascade entry point
(`retraction_cascade` module docs, "Empty surviving set" section), as C6 requires.

### D5 — C8's clippy gate already fails on the **unmodified** tree at `7cd5eeef`

`cargo clippy --all-targets -- -D warnings` is red at HEAD before any change. Verified by
`git stash push -u` and re-running: `epigraph-db` test targets (`last_match_scan_column`, lib test)
and the `epigraph-tools` `table_graph` examples all trip `-D warnings`. C8 as written is therefore
unsatisfiable by any change to this repo.

Substituted, all green: `cargo fmt --all -- --check`; `SQLX_OFFLINE=true cargo check --workspace`;
`cargo clippy -p epigraph-mcp --all-targets -- -D warnings`;
`cargo clippy -p epigraph-db -p epigraph-engine --lib -- -D warnings`;
`cargo clippy -p epigraph-api --features db --lib -- -D warnings`. Additionally a whole-workspace
`cargo clippy --all-targets --keep-going -- -D warnings` was run and its **complete** diagnostic set
inspected: after fixing the one hit that was ours (`bool_assert_comparison` in
`supersede_cascade_reports_targets.rs`), no remaining diagnostic points at a file this change touches
or adds.

### D6 — `mark_duplicate` gained a struct-returning **sibling** (additive; C1 / flip-condition 4 intact)

`ClaimRepository::mark_duplicate` keeps `Result<(), DbError>` exactly and delegates to the new
`mark_duplicate_with_repair -> Result<DedupRepair, DbError>`. Flip-condition 4 forbids *changing*
the return type; nothing changed. The sibling is necessary because the ids of the edges destroyed by
the three collision pre-deletes exist only inside the transaction — after the commit there is no way
to tell an orphan this dedup created from one that was already there, and a global orphan sweep would
violate C3's surgical requirement.

### D7 — Known remaining gaps, deliberately NOT fixed (not a criterion; recorded for honesty)

Enumerated from every writer of `is_current = false` in the repo layer, so this is the complete
set of retraction paths the change does **not** cover:

```
$ grep -n "is_current = false" crates/epigraph-db/src/repos/claim.rs   # (writers only)
2068  supersede            2808  evolve_step            2937  mark_duplicate_with_repair
3821  deprecate_claim      4554  consolidate
```

1. **`ClaimRepository::supersede`** re-points *incoming* edges onto the replacement claim,
   stranding their BBAs on the retired claim — structurally the same defect as C5(b), which this
   change fixes for `mark_duplicate`. Left alone on purpose: moving those BBAs would give the
   replacement claim a belief interval it never earned (F4: it is inserted with NULL
   `belief`/`plausibility`), silently resurrecting the retracted claim's numbers under a new id,
   and C3's note explicitly leans on the replacement being factorless.

2. **`ClaimRepository::consolidate`** (live MCP tool `consolidate_claims`, and where
   `sweep_semantic_duplicates` routes its near-clusters) performs the **identical** three edge
   operations `mark_duplicate_with_repair` was just taught to repair — a bulk
   `DELETE FROM edges WHERE id = ANY($1)`, an `UPDATE edges SET source_id`, and an
   `UPDATE edges SET target_id` — with zero `mass_functions` handling anywhere in its body
   (`awk 'NR>=4297 && NR<=4600' … | grep -iE "mass_function|perspective_id|bba|belief"` → no
   output). It is equally broken before and after this change and is untouched by the diff, so it
   is not a regression; it is named here because omitting it from an enumeration that claims
   completeness would be. Repairing it needs its own pre-registration: consolidation fuses
   *several* sources into one synthesis, so "which supporters does the synthesis inherit" is a
   semantic question, not the mechanical re-pointing dedup does.

3. **`ClaimRepository::deprecate_claim`** and **`ClaimRepository::evolve_step`** retire a claim
   without moving its edges, so only the frozen-downstream-BBA half applies to them, not the
   orphan/strand half.

All three are documented in the `retraction_cascade` module docs under "Known remaining gaps".

### D8 — Surface enumeration: a third call site the criteria never named

The criteria name two call sites (`tools/supersede.rs`, `routes/versioning.rs`). A repo-wide
`grep -rn "ClaimRepository::mark_duplicate\|ClaimRepository::supersede(" crates/ --include=*.rs`
found a third: `epigraph-mcp/src/tools/dedup_sweep.rs::sweep_semantic_duplicates`, the bulk
collapse path. It compiles unchanged (the signature is intact) and would have silently
reintroduced the defect at scale, so it was wired to the same cascade; its per-pair cascade errors
are appended to the existing `failures` list rather than aborting the sweep. Complete list of
**`supersede` / `mark_duplicate` call sites** after this change (NOT of retraction call sites in
general — `consolidate`, `deprecate_claim` and `evolve_step` also retire claims and are enumerated
in D7):

| Site | Cascade |
|---|---|
| `epigraph-mcp/src/tools/supersede.rs::supersede_claim` | yes, reported as `belief_cascade` |
| `epigraph-mcp/src/tools/supersede.rs::mark_duplicate` | yes, reported as `belief_cascade` |
| `epigraph-mcp/src/tools/dedup_sweep.rs::sweep_semantic_duplicates` | yes, errors folded into `failures` |
| `epigraph-api/src/routes/versioning.rs::supersede_claim` | yes, reported as `belief_cascade` |
| `epigraph-api/src/routes/versioning.rs::mark_duplicate` | yes, reported as `belief_cascade` |
| `ClaimRepository::mark_duplicate` (bare repo call) | in-tx BBA repair only, no recompute — by design, the repo layer cannot run the DS pipeline |

### D9 — C3 pins two columns that do not exist on `claims`; read as their real equivalents

C3's pass clause requires `D`'s cached `(belief, plausibility, pignistic_prob, conflict_k,
missing_mass)` to be bit-identical. `claims` has **neither** `conflict_k` nor `missing_mass`:

```
$ psql … -tAc "SELECT column_name FROM information_schema.columns
               WHERE table_name='claims' AND column_name IN ('conflict_k','missing_mass')"
(0 rows)
$ psql … -c "\d claims" | grep -iE "belief|plaus|pignistic|mass_on|classification"
 belief | plausibility | mass_on_empty (DEFAULT 0.0) | pignistic_prob | mass_on_missing (DEFAULT 0.0) | classification
```

(`conflict_k` exists only on `ds_combined_beliefs` and `mass_functions`.) The test reads
`mass_on_empty` / `mass_on_missing`, which are the same two quantities under their real column
names. The substitution is correct; leaving it unlogged is what would have made the
pre-registration unauditable. `CachedScalars` in `supersede_cascade_recompute.rs` is
`(belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing)` accordingly.

### D10 — `CascadeReport::targets` reports what was touched, not what was considered

C4's pass condition and `supersede_reports_the_downstream_target_it_repaired` both key on
`belief_cascade.targets`, so the meaning of that field is fixed here rather than changed silently.

`DedupRepair::stale_claims` always contains **both** dedup endpoints, whether or not the dedup
changed anything about their evidence. An endpoint that never had a derived cache is therefore not
a repair the cascade performed, and is now **absent** from `targets`, `recomputed` and `unbacked`.
`targets` is exactly the union of `recomputed`, `unbacked` and the claims named in `errors`.

This matters beyond bookkeeping: the pre-fix code fed both endpoints to the unbacked path
unconditionally, and `MassFunctionRepository::clear_claim_belief` NULLs `mass_on_empty` /
`mass_on_missing`, which are `DEFAULT 0.0` and are omitted by `ClaimRepository::create`. So every
`mark_duplicate` of two BBA-free claims flipped a real `0.0` to NULL and bumped `updated_at` on
the **surviving** claim — a C3 surgicality violation on the dedup path, at
`sweep_semantic_duplicates` scale. `clear_claim_belief` is now guarded on at least one derived
column being non-NULL and returns its row count. Regression:
`mark_duplicate_cascade_recompute.rs::bba_free_dedup_leaves_the_survivors_derived_columns_alone`
(verified red with the guard removed: `mass_on_empty 0.0 → NULL`, `updated_at` moved).

### D11 — BCH-EG-K05's 1-hop bound is satisfied by construction, and separately tested

`retraction_cascade` contains no recursion: `invalidate_and_rewire` is a flat `for` over one
`EdgeRepository::list_current_claim_targets` result and `repair_targets` is a flat `for` over its
argument. Neither calls back into a cascade entry point. So the 30s `tokio::time::timeout` in
`cyclic_support_terminates` cannot fire, and that test alone cannot discriminate a bounded walk
from an unbounded one — it pins cycle-safety against a *future* recursive edit, not against the
present code.

Added `supersede_cascade_recompute.rs::second_hop_downstream_of_the_retraction_is_not_touched`:
on the straight chain `A --supports--> B --supports--> C`, retracting `A` must leave the `B → C`
edge factor's `masses`, `C`'s cached scalars and `C.updated_at` all byte-identical. That is an
assertion a transitive implementation fails immediately, without depending on a hang.

### D12 — `sweep_semantic_duplicates::failures` widened its meaning; now documented, not renamed

`failures` previously meant "this pair was not collapsed". It can now also carry
`"<dup> -> <survivor> (belief cascade): <err>"` on a pair that **was** collapsed and **is** counted
in `pairs_marked`, so `pairs_marked + failures.len()` no longer partitions the attempted pairs. A
separate `cascade_failures` key was rejected: it is a second additive response field for a
condition callers must handle identically (re-run the repair for that pair), and the sweep's other
consumers already string-match `failures`. The contract is now stated on the field itself
(`SweepResponse::failures` doc comment). Coverage added:
`dedup_sweep_tool.rs::execute_repairs_the_survivors_belief_not_just_the_supersedes_pointer` — the
pre-existing sweep fixtures seed bare claims with no edges, so the cascade was always a no-op and
the whole wiring could be reverted with the suite green (verified: reverting it turns the new test
red on "survivor must have a cached BetP").

### D13 — HTTP call sites now have their own tests

`routes/versioning.rs::supersede_claim` and `::mark_duplicate` were covered only by the assumption
that they call the same engine function as the MCP tools. Added
`crates/epigraph-api/tests/versioning_belief_cascade_test.rs` (2 tests) driving both routes over
real HTTP and asserting the `belief_cascade` payload **and** the resulting DB state.

### D14 — `SourceFactorless` after invalidation is a decided outcome, not an error

`invalidate_and_rewire` deletes each stale BBA and then re-derives it. Three of the four
`EdgeFactorOutcome` values mean "no BBA was written", of which `SourceFactorless` is the *normal*
post-supersede case (F4: the replacement claim is inserted factorless). Those are **not** reported
as errors — the target is still recomputed or marked unbacked in the same pass, so the loss of the
supporter is visible in `recomputed`/`unbacked`. What *is* now reported: `auto_wire_edge_if_epistemic`
returning `None`, which is a genuine internal failure it otherwise only `warn!`s about, and a
failure to resolve the source claim's `agent_id` — which now aborts the whole loop rather than
deleting BBAs it has already established it cannot re-derive.

---

## Adjudication

Recorded after adversarial review of the implementation (three reviewers, 14 findings) and the
follow-up fix pass. Every line below is the result of running the named command in
`/home/jeremy/epigraph-wt-K` at the branch tip, not a restatement of intent.

**Environment.** `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test`,
`SQLX_OFFLINE=true`. The production `epigraph` database on `epigraph-postgres` was never
contacted; no migration was run against it. `.sqlx` was not regenerated — no `query!`/`query_as!`
macro was added or altered (the new `ClaimRepository::get_agent_id` and the guarded
`clear_claim_belief` are unchecked `sqlx::query`/`query_scalar`, as were the statements they sit
beside).

### Verdict table

| Gate | Result | One-line basis |
|---|---|---|
| C1 — backward compatibility + the observability resource | **PASS** | signatures and params byte-identical; every listed test file unmodified and green; `belief_cascade` added on all four responses |
| C2 — ANCHOR: downstream cache stops reflecting the retracted supporter | **PASS** | `downstream_cache_drops_retracted_supporter` |
| C3 — CONTROL: the cascade is surgical | **PASS (as-substituted, D9)** — and strengthened | `cascade_does_not_touch_unrelated_bbas_or_claims`; dedup-path hole found in review and closed — `bba_free_dedup_leaves_the_survivors_derived_columns_alone` |
| C4 — enumeration survives the in-transaction edge migration | **PASS** | `supersede_reports_the_downstream_target_it_repaired`; `target_is_current` → 0 hits |
| C5 — MemTX I2: no orphaned **or** stranded derived record | **PASS** | `diamond_and_migration_leave_no_orphaned_or_stranded_bba`, plus two new phase-2 fixtures |
| C6 — empty surviving BBA set has decided semantics | **PASS** | `sole_supporter_retraction_does_not_leave_frozen_belief` + `…_is_reported_as_unbacked_not_as_nothing_to_do` |
| C7 — bounded, cycle-safe, best-effort, orchestrated at the call site | **PASS** (with D2, D11) | four greps + `cyclic_support_terminates`, `second_hop_downstream_of_the_retraction_is_not_touched`, `cascade_errors_are_reported_not_propagated` |
| C8 — full CI gate green | **PARTIAL — clippy clause REFUTE** | `cargo clippy --all-targets -- -D warnings` exits 101 on **pre-existing** debt in untouched crates; fmt, `check --workspace` and all test suites are green |

No criterion was refuted by the implementation. C8's clippy clause is refuted by the repository,
and is recorded as REFUTE rather than reinterpreted (see below).

### C1 — PASS

```
$ git diff origin/main --stat -- crates/epigraph-mcp/src/types.rs
(no output — no params struct changed)

$ git diff origin/main --name-only -- \
    crates/epigraph-mcp/tests/supersede_claim_test.rs \
    crates/epigraph-mcp/tests/mark_duplicate_test.rs \
    crates/epigraph-db/tests/mark_duplicate_repo.rs \
    crates/epigraph-db/tests/supersede_nulls_embedding.rs \
    crates/epigraph-db/tests/supersede_carries_labels_and_filters.rs \
    crates/epigraph-db/tests/mark_duplicate_nulls_embedding.rs \
    crates/epigraph-api/tests/supersede_scope_check_test.rs
(no output — every file C1 names is unmodified)
```

`ClaimRepository::supersede -> Result<(Uuid, Uuid), DbError>` and
`ClaimRepository::mark_duplicate -> Result<(), DbError>` are unchanged (D6: the struct-returning
`mark_duplicate_with_repair` is an additive sibling). All of the above test files pass in the
suite runs recorded under C8.

*(b)* `belief_cascade` is present on all four responses and asserted by
`supersede_cascade_reports_targets.rs` (MCP) and the new
`crates/epigraph-api/tests/versioning_belief_cascade_test.rs` (HTTP, D13).

### C2 — PASS

`epigraph-mcp --test supersede_cascade_recompute -- downstream_cache_drops_retracted_supporter`:
green. No `recompute_beliefs` call anywhere in the test body. Both clauses asserted: the cached
BetP moved by more than `1e-9`, and it equals `preview_claim_belief_on_frame` on the post-cascade
`mass_functions` set to within `1e-12`.

### C3 — PASS as-substituted (D9), with a hole closed

`cascade_does_not_touch_unrelated_bbas_or_claims`: green — the surviving `C→B` BBA row's
`(masses, source_strength, evidence_type, locality_tag, perspective_id)` are byte-identical, and
`D`'s cached scalars and `updated_at` are untouched. C3's `conflict_k`/`missing_mass` are not
columns on `claims` and were read as `mass_on_empty`/`mass_on_missing` — logged as **D9**.

Review found C3's property violated on the path its own fixture does not cover: the **dedup**
endpoints were fed to the unbacked path unconditionally, so a BBA-free `mark_duplicate` rewrote
the surviving claim's `mass_on_empty`/`mass_on_missing` from `0.0` to NULL and bumped its
`updated_at`. Fixed (D10) and pinned by
`bba_free_dedup_leaves_the_survivors_derived_columns_alone`, verified red against the unguarded
clear.

### C4 — PASS

```
$ grep -rn "target_is_current" crates migrations | wc -l
0
```

`supersede_reports_the_downstream_target_it_repaired` asserts `belief_cascade.targets == [B]`
**and** separately asserts that the naive `WHERE source_id = <retracted id>` enumeration returns
0 rows in the same fixture, so the criterion's "the naive query must also fail this" requirement
is met explicitly rather than by construction.

### C5 — PASS

`diamond_and_migration_leave_no_orphaned_or_stranded_bba`: both SQL invariants from the criterion
return 0, `canonical` carries both BBAs, and its cached BetP equals
`preview_claim_belief_on_frame` post-repair.

Review established that the `resourced_edges` half of the dedup cascade (phase 2) was reachable
by **no** fixture — the whole block could be deleted with all ten tests green. Two fixtures added:

* `resourced_outgoing_edge_bba_is_re_derived_from_canonical` — the duplicate's outgoing edge
  survives, re-sourced at `canonical`, and its BBA's `masses` must differ from the value frozen
  from `dup`'s interval. Only phase 2 can produce that.
* `target_of_both_a_collision_delete_and_a_resourced_edge_is_recomputed_last` — the ordering bug
  itself. Verified **red** before the fix: `V` was reported under `targets`/`recomputed` while its
  cached BetP stayed at `0.332` with zero surviving BBAs.

### C6 — PASS

`sole_supporter_retraction_does_not_leave_frozen_belief` (all five scalars **and**
`classification` NULL) and `sole_supporter_retraction_is_reported_as_unbacked_not_as_nothing_to_do`
(`unbacked == [B]`, `recomputed` empty). Option **(ii)**, per D4, documented on the module entry
point. D10 narrows `unbacked` to claims that actually had a cache — the criterion's purpose
(distinguishing "unbacked" from "believed at 0.79") is strengthened, not weakened, since a claim
that never had a cache is now also distinguishable from both.

### C7 — PASS

1. **Bounded / 2. cycle-safe.** `cyclic_support_terminates` green inside its 30s timeout;
   `second_hop_downstream_of_the_retraction_is_not_touched` (new, D11) asserts the bound on a
   straight 3-chain, which a transitive implementation fails on an assertion rather than a hang.
3. **Best-effort.** `cascade_after_supersede`/`cascade_after_dedup` return `CascadeReport`, never
   `Result`. `cascade_errors_are_reported_not_propagated` (the error is reported and names `B`)
   and `cascade_failure_does_not_fail_the_write` (`A` still retired, replacement still created).
   The former is where this clause's teeth are; the latter additionally pins the DB end-state.
4. **Call-site orchestration** (D2 — a shared engine module, not literal inlining):

```
$ git diff origin/main -- crates/epigraph-mcp/src/tools/supersede.rs \
      crates/epigraph-api/src/routes/versioning.rs | grep -c '^+.*sqlx::query'
0
$ grep -c "tokio::spawn" crates/epigraph-db/src/repos/claim.rs
0
$ grep -c "sqlx::query" crates/epigraph-engine/src/retraction_cascade.rs
0        # was 1 before this fix pass — moved to ClaimRepository::get_agent_id,
         # per CLAUDE.md "all SQL stays in crates/epigraph-db/src/repos/"
$ git diff origin/main -U0 -- crates/epigraph-db/src/repos/claim.rs | grep '^@@'
   # every hunk is at the DedupRepair struct (~L85), get_agent_id (~L481) or
   # mark_duplicate (~L2829+). `supersede` (~L2000-2100) is untouched.
```

### C8 — fmt/check/test PASS; the literal clippy clause REFUTE

```
$ SQLX_OFFLINE=true cargo fmt --all -- --check                       → 0
$ SQLX_OFFLINE=true cargo check --workspace                          → 0
$ SQLX_OFFLINE=true cargo clippy --all-targets -- -D warnings        → 101   ← REFUTE
# C8's literal combined invocation, run first (see D15):
$ DATABASE_URL=… cargo test -p epigraph-db -p epigraph-mcp           → 124  killed by the harness's
                                                                       600s per-call ceiling at
                                                                       642 passed / 0 failed / 11 ignored
# ...so it was split per crate, each run to completion (642 → 660, same set):
$ DATABASE_URL=… cargo test -p epigraph-db                           → 0   264 passed, 0 failed, 10 ignored
$ DATABASE_URL=… cargo test -p epigraph-mcp                          → 0   396 passed, 0 failed,  1 ignored
$ DATABASE_URL=… cargo test -p epigraph-engine                       → 0   547 passed, 0 failed, 12 ignored
$ DATABASE_URL=… cargo test -p epigraph-api --features db \
      --test versioning_belief_cascade_test --test supersede_scope_check_test \
      --test dedup_endpoint_test --test dedup_negative_test \
      --test dedup_admin_scope_test --test alternative_of_symmetric_dedup
                                                                     → 0    14 passed, 0 failed
```

**Build-profile note.** The four `cargo test` runs above were invoked with
`CARGO_PROFILE_DEV_DEBUG=0` prepended. That is a build-configuration workaround for a disk-full
event on the shared `/home/jeremy/.cargo-target` (see D15), not part of the criterion; it changes
only debuginfo emission, no test semantics. An auditor re-running the bare command in the
criterion gets the same results from a larger build.

**Attribution of the clippy failure.** All 16 error lines are in `crates/epigraph-tools`
(`examples/table_graph/*`, reached through its test targets) — an untouched crate that no
workspace member depends on. The run aborts there; running clippy **without** `-D warnings` so
every target compiles yields ~150 diagnostics across 46 files, none of which is in a file this
branch touches or adds:

```
$ for f in $(git diff --name-only origin/main; git status --porcelain | awk '{print $2}'); do
      grep -F "$f:" clippy_all.txt; done
(no output)
```

The two diagnostics the reviewers found inside changed files have been handled: the
`unused import: super::*` in `routes/versioning.rs::mod tests` (blame `5462005b`, 2026-04-15) is
removed, and `claim.rs::max_agent_claims_constant_is_positive`'s constant assertion (blame
`74f3f7403`, 2026-06-18) is left alone as a deliberate pre-existing guard test.

**Why this is recorded as REFUTE rather than substituted away.** D5 already disclosed that the
clause is unsatisfiable at `7cd5eeef`, and that remains true; but "unsatisfiable" is not "passed".
Cleaning ~150 pre-existing diagnostics across 46 files in `epigraph-tools`, `epigraph-engine`'s
test/bench targets, `epigraph-api`'s test helpers and `epigraph-db`'s test helpers is a separate
chore, not part of this decision. The scoped substitute set D5 defines is green:

```
$ cargo clippy -p epigraph-mcp --all-targets -- -D warnings                       → 0
$ cargo clippy -p epigraph-db -p epigraph-engine --lib -- -D warnings             → 0
$ cargo clippy -p epigraph-api --features db --lib -- -D warnings                 → 0
$ cargo clippy -p epigraph-api --features db --test versioning_belief_cascade_test \
      -- -D warnings                                                              → 0
```

### BCH-style challenges

| Challenge | Result | Backing |
|---|---|---|
| K01 — post-commit enumeration finds nothing | **PASS** | `supersede_reports_the_downstream_target_it_repaired` asserts both the correct target set and that the naive query returns 0 |
| K02 — `recompute_beliefs` reports success and changes nothing | **PASS** | `downstream_cache_drops_retracted_supporter` (`> 1e-9` move); `resourced_outgoing_edge_bba_is_re_derived_from_canonical` (`masses` differ) |
| K03 — dedup orphans one side, strands the other | **PASS** | `diamond_and_migration_leave_no_orphaned_or_stranded_bba`; both counts asserted separately |
| K04 — sole supporter retracted, belief silently freezes | **PASS** | `sole_supporter_retraction_does_not_leave_frozen_belief` + the reported-outcome half |
| K05 — cycle in the support graph | **PASS by construction, tested by the chain fixture** | the bound is structural — no recursion in the module (D11). `second_hop_downstream_of_the_retraction_is_not_touched` is the test that can discriminate it; `cyclic_support_terminates` cannot, and guards the cycle case against a future recursive edit |
| K06 — "fail loudly" turns a committed write into a reported failure | **PASS** | return type is `CascadeReport`, not `Result`; `cascade_errors_are_reported_not_propagated`, `cascade_failure_does_not_fail_the_write` |

### Review findings not adopted, and why

* **"Delete `cascade_failure_does_not_fail_the_write`; it cannot fail and is subsumed."** Kept.
  It asserts two things `cascade_errors_are_reported_not_propagated` does not — that `A` is still
  retired and the replacement claim still exists after a cascade error — which is the actual
  end-state contract of BCH-EG-K06. The observation that C7.3's discriminating power comes from
  the other test is correct and is recorded above rather than acted on by deletion.
* **"Move `PREREGISTRATION.md` out of the repo root."** Not done here: this file is the
  governance artifact the adjudication was directed at, and relocating it in the same pass would
  break the audit trail from the review to the record. It is a docs/process call, outside the
  build-and-integration scope of this change.

### D15 — C8's combined `cargo test` invocation was split per crate (harness time limit)

C8 names `cargo test -p epigraph-db -p epigraph-mcp` as one command. Run as written at the branch
tip it was **killed at 580s** by the 600s-per-call ceiling of the harness this adjudication was
produced under — `EXIT=124`, 642 passed / 0 failed / 11 ignored with binaries still to run. That is
a property of the runner, not of the code, so the invocation was split into
`cargo test -p epigraph-db` (264 passed / 0 failed / 10 ignored, exit 0) and
`cargo test -p epigraph-mcp` (396 passed / 0 failed / 1 ignored, exit 0). `264 + 396 = 660`, i.e.
the same test set the combined run was 642 of the way through, each half run to completion.

Both halves were additionally invoked with `CARGO_PROFILE_DEV_DEBUG=0`. Mid-adjudication the host
filled to 100% (`/dev/sda1 150G, 176K available`) and `rustc` began failing with
`No space left on device`; `cargo clean -p epigraph-mcp -p epigraph-api -p epigraph-engine
-p epigraph-db` reclaimed 36.8 GiB, and the reduced debuginfo keeps the rebuild from immediately
re-filling. The root cause is outside this repo: `/home/jeremy/.cargo/config.toml` declares
`[env]` **twice**, so its `CARGO_PROFILE_DEV_DEBUG = "line-tables-only"` never takes effect and
every test binary is built with `-C debuginfo=2`.
