# Noun-Claims and Verb-Edges — S1: Foundation Design

> **Origin:** Ported from `epigraph-internal` (private dev repo) as historical
> design context. The implementation landed on this repo as **#16**. Branch /
> PR-number references below point to the original `epigraph-internal` artifacts.

**Date:** 2026-04-25
**Branch:** `chore/migration-renumber-2026-04-25` (lands in PR #6)
**Status:** Approved for spec → plan → implementation
**Sub-project of:** Noun-Claims and Verb-Edges architecture (S1 of S1–S4)

---

## Why this design exists

While preparing to apply migration 106 (which adds `UNIQUE (content_hash, agent_id)` on `claims`), live-DB probes turned up ~95,214 duplicate `(content_hash, agent_id)` groups covering 262,274 of 389,739 claim rows (67% of the table). 413,380 edges, 95,496 mass functions, and 2,283 evidence rows reference rows in those groups. The dups are not random:

- **Cause 1 — textbook/paper ingest scripts (~173k dup rows, 65%).** `scripts/ingest_textbook_cdst.py` (and its paper sibling) in the deprecated EpigraphV2 repo use `psql` direct INSERT with `ON CONFLICT (id) DO NOTHING`. The PK conflict target catches nothing because each run mints fresh UUIDs. Re-runs on the same source produce fresh duplicate rows. March 2 / March 30 / March 31 spikes (160k rows on March 30 alone) are textbook re-runs.
- **Cause 2 — MCP-driven Claude agent (~72k dup rows, 28%).** Agent `f741ab67…` (display name `did:key:z6MknhYrJfEUVjke4vZDUwYMhVkvSzXfkwmTA7DvqjeGKBZM`, properties `{"model":"claude-agent","source":"epigraph-nano-mcp"}`) submits via the `epigraph-nano-mcp` MCP server during agent runtime. Same agent submits the same content multiple times because the MCP submission path doesn't dedup on `(content_hash, agent_id)`.
- **Cause 3 — host provenance recording (~18 April rows but steady drip).** `EpigraphV2/EpigraphV2/epigraph-nano/src/host/provenance.rs` records lifecycle events as full claim rows where `content_hash = hash(container_name)` for spawn events, `hash(task_id:status)` for executions, etc. Same container spawning twice or same task running on schedule legitimately collides on `(content_hash, agent_id)`. The intuition that this was a "30 ms race" was wrong (advisor caught it): the gaps are 14 seconds to 32 hours apart.

The diagnosis is convergent: migration 106's `UNIQUE` constraint reflects an architectural intent (one claim per `(content_hash, agent_id)`) that the codebase has drifted from. The right fix is not to weaken the constraint or to apply it against a dirty table — it is to restore the architecture and bring the data back to it.

## The architecture

**Two element types, each with its own role:**

- **Noun-claim** — a `claims` row representing an entity or assertion that has stable identity. Its `(content_hash, agent_id)` is the canonical key: there is at most one row per `(content_hash, agent)`. Examples:
  - "Container `epiclaw-tg-7173612411` exists for group `telegram-7173612411`"
  - "Task `epistemic-gaps` is scheduled"
  - The textbook fact "evidence supports H₀ at confidence 0.8"
  - The message body "ok"

- **Verb-edge** — an `edges` row representing a timestamped occurrence or relationship involving one or more noun-claims. The edge's `created_at` (and optional `valid_from` / `valid_to`) carries the event time; `properties` JSONB carries event metadata; `relationship` carries the verb; `signature` / `signer_id` give the same audit guarantee as claim signatures. Examples:
  - `host_agent --[spawned @ 2026-04-25T03:03:59Z, props={group: "epistemic-gaps"}]--> container_claim`
  - `host_agent --[executed @ 2026-04-25T07:43:13Z, props={status: completed, duration_ms: 1342}]--> task_claim`
  - `paper_artifact --[asserts @ 2026-03-30T23:50:03Z, props={extraction_run: "2026-03-30"}]--> textbook_fact_claim`

**Three rules that fall out of this:**

1. **Re-occurrence of the same lifecycle event = new edge, not new claim.** Migration 106's `UNIQUE (content_hash, agent_id)` becomes naturally correct.
2. **Re-ingesting the same source content = new edge from a (per-run) source-artifact noun to the existing fact-claim, not a duplicated fact-claim.**
3. **`provenance_log` (cryptographic audit) is unchanged.** Every claim/edge create still gets a row there. The change is what writers *create*: more edges, fewer duplicate claims.

**Why this fits existing schema:** the `edges` table already carries `created_at`, `valid_from`/`valid_to`, `properties` JSONB, `labels`, `signature`, `signer_id`. The schema was designed for this; the writers drifted. No new columns are required.

## Goals and non-goals

**S1 ships:**

- Pattern documentation that any future writer can follow.
- Idempotent claim creation primitive on the existing API (`if_not_exists` flag).
- Migration 106 in a shape that is applicable to the live DB today.
- Migration 107 holding the deferred `UNIQUE` constraint with the prerequisite documented in the file header.
- Disposition doc, README, PR body all updated to reflect the new sequenced plan.

**S1 explicitly does NOT ship:**

- Backfilling the 95k existing duplicate groups → that's S2.
- Modifying any writer (`epigraph-mcp` submission paths, `epigraph-agent` `submit_claim` builtin, V2 `epigraph-nano/provenance.rs`, V2 ingest scripts) → that's S3 (sub-plans S3a–S3d).
- Applying the `UNIQUE` constraint to the live DB → that's S4 (depends on S2 done).
- A combined "create-claim-and-edge" atomic helper endpoint. The two-call sequence is sufficient until evidence proves otherwise. YAGNI.

## API surface

**One change to the existing claim-create endpoint, three new repo helpers, plus documentation.**

### `POST /api/v1/claims` — add `if_not_exists` field

New optional request body field:

```json
{
  "content": "...",
  "content_hash": "...",
  "agent_id": "...",
  "if_not_exists": true
}
```

Behavior:

- `if_not_exists: false` (default): the request inserts unconditionally (raw INSERT). Pre-107: this writes a row even if `(content_hash, agent_id)` already exists, increasing duplicate count (S2 backfill cleans up). Post-107: a `(content_hash, agent_id)` collision returns a constraint-violation error surfaced as `409 Conflict` to the client.
- `if_not_exists: true`: server checks for an existing row by `(content_hash, agent_id)`; returns the existing claim's id if found; else inserts. Response body adds `was_created: bool` so the caller can tell which branch ran.

**Note on existing dedup.** `ClaimRepository::create()` and `create_with_tx()` today perform an implicit dedup-on-`content_hash`-alone (`crates/epigraph-db/src/repos/claim.rs:70-92` and `:149-170`) that returns the first agent's row regardless of requester — a noun-claim invariant violation. The blast radius of removing this is wide (~44 internal callers across 11 files including `epigraph-mcp` tools and the integration test suite); fixing it as part of S1 would balloon the PR. S1 therefore **adds new helpers** that the API endpoint routes to, and leaves the legacy methods untouched. Internal callers continue using legacy behavior until a follow-up task migrates them. The legacy dedup bug is documented but not fixed here.

Implementation surface (estimated):

- `crates/epigraph-db/src/repos/claim.rs` — three new helpers, all taking `&mut PgConnection` so the caller can compose with edge creation in the same transaction:
  - `find_by_content_hash_and_agent(conn, content_hash, agent_id) -> Option<Claim>` — find-only.
  - `create_or_get(conn, claim) -> (Claim, was_created: bool)` — finds by `(content_hash, agent_id)` then inserts if absent. **Post-107 race handling:** on a unique-violation during the INSERT (a concurrent writer won the race), the helper catches the error, re-runs the find, and returns the resulting row with `was_created: false`. Pre-107, no constraint exists, so the catch path is unreachable and a concurrent race may produce two rows (per the race-window section).
  - `create_strict(conn, claim) -> Claim` — raw INSERT, no dedup. Post-107, surfaces unique-violation; pre-107, inserts a duplicate.
- `crates/epigraph-api/src/routes/claims.rs` — extend the create-claim handler:
  - Branch on `if_not_exists`: `true` → `create_or_get`, `false` → `create_strict`. (The existing path through `create_with_tx` is replaced; legacy `create_with_tx` remains for internal callers.)
  - Add `was_created: bool` to `ClaimResponse`.
  - Map unique-violation errors on the `if_not_exists: false` path to `409 Conflict` (only fires post-107).
- Tests cover:
  - `if_not_exists: true` returns the existing claim with `was_created: false` when `(content_hash, agent_id)` already exists.
  - `if_not_exists: true` inserts and returns `was_created: true` when no existing row matches.
  - `if_not_exists: false` writes a new row pre-107 even when `(content_hash, agent_id)` already exists.
  - Post-107: `if_not_exists: false` collision returns `409 Conflict`.
  - Post-107: two concurrent `if_not_exists: true` calls produce one row — first writer wins; second catches the unique-violation from the constraint and returns the existing row.
  - The pre-107 concurrent-`if_not_exists: true` case (which may produce two rows) is documented as a tolerated transitional state and is **not** added as a passing test, because the test would be inherently racy and would flake. S2 cleans up any rows the race produces.
  - **Test fixture note.** Post-107 assertions only hold against a DB that has migration 107 applied. The post-107 tests apply migration 107 in their fixture setup (e.g., `sqlx::migrate!()` against the test pool, or a per-test SQL execution of the `ALTER TABLE` statement). Tests that exercise pre-107 behavior must run on a fixture without 107 applied — keep these in a separate test module so the migration state is explicit per test.

### `POST /api/v1/edges` — no change

Each call already creates a new edge, which is the correct semantics for verb-edges. `created_at`, `properties`, `valid_from`, `valid_to`, `signature`, `signer_id` already supported. No new fields, no new endpoint.

### `if_not_exists: true` × `privacy_tier`

`if_not_exists: true` is rejected with `400 Bad Request` when `privacy_tier != "public"`. Encrypted claims store ciphertext keyed by group epoch in `claim_encryption`; cross-group dedup on plaintext hash would either leak content equality across groups (privacy violation) or no-op against the `[private]` placeholder content. A coherent dedup design for encrypted claims is an open question deferred to a future spec — until then, encrypted submissions stay on the existing `if_not_exists: false` (raw insert) path.

### `if_not_exists: true` × `properties`, `labels`, `content_hash` override

Today the handler runs `UPDATE claims SET content_hash = COALESCE(...), properties = COALESCE(...) WHERE id = $1` and a separate `UPDATE claims SET labels = $1` after the insert (`claims.rs:417-452`). With `if_not_exists: true`, two concerns arise:

- **Mutating an existing canonical noun-claim from a different caller's request is surprising.** It bypasses ownership/authorisation checks and can clobber metadata that another agent set previously. So when `was_created: false`, the handler skips the `properties` / `labels` UPDATEs entirely. The returned response reflects the existing row's metadata, not the request's. Callers needing metadata changes go through a separate PATCH (existing labels endpoint, future properties endpoint).
- **`content_hash` override + `if_not_exists: true` is rejected with `400 Bad Request`.** The override is a textbook-ingest-script feature (Cause 1) that S3c retires; new callers should not combine override and idempotent-create. When the override is omitted, the server-computed BLAKE3 hash is used for the `(content_hash, agent_id)` lookup. Post-107 the override UPDATE could itself violate the constraint (override sets a hash already used by another row of the same agent); that surfaces as `409 Conflict` from the UPDATE on the `if_not_exists: false` path. New ingestion paths should compute hashes server-side and stop using the override.

### Auto-emitted `AUTHORED` edge

`POST /api/v1/claims` already emits `agent --[AUTHORED]--> claim` after every successful create call (`claims.rs:503-514`). This is preserved unchanged: `if_not_exists: true` returning an existing claim still emits a fresh AUTHORED edge. Each submission is a distinct verb-event — the noun-claim is canonical, the AUTHORED edges are the timestamped occurrences. This is the noun-claim/verb-edge architecture in microcosm and is documented as the canonical pattern in `docs/architecture/noun-claims-and-verb-edges.md`.

### Pre-107 race window (acknowledged, not solved)

Until migration 107 lands, the DB has no `(content_hash, agent_id)` UNIQUE constraint. Two concurrent `if_not_exists: true` requests for the same key can both find no existing row and both insert, producing two rows where `if_not_exists: true` semantically promised one. Once migration 107 is applied, the second insert fails with a constraint violation; the handler catches that error and returns the existing row.

S1 does **not** add advisory-lock serialization in the pre-107 window. Rationale:

- The race window already exists for *every* claim-creation path today; S1 doesn't widen it.
- S2 backfill will deduplicate any additional rows produced during the S1→S4 transition, so the race-window dups are temporary and bounded.
- Adding a per-key advisory lock now adds non-trivial code that would be removed when 107 lands.

This race-window behavior is documented in the architecture doc and in the `if_not_exists` field's API description so callers know that during the S1→S4 transition, two near-simultaneous `if_not_exists: true` calls for the same `(content_hash, agent_id)` may both report `was_created: true` and produce separate rows. Strict-semantics callers can mitigate by serializing per-key in their own writer (the canonical S3a path), or by tolerating the duplicate until S2 backfill collapses it. The handler does not attempt to detect or merge the race itself.

### Recommended call sequence (in the architecture doc)

```
POST /api/v1/claims  {content, content_hash, agent_id, if_not_exists: true}
    → {claim_id, was_created}

POST /api/v1/edges   {source_id: actor_agent_id, source_type: "agent",
                      target_id: claim_id, target_type: "claim",
                      relationship: <verb>, properties: {...}, created_at: <T>}
    → {edge_id}
```

Two calls. Two transactions. Composes cleanly.

### Why two calls instead of an atomic helper

- Both endpoints already exist; one optional flag is a smaller surface than a new route.
- The two operations have different idempotency: claims are dedup'd, edges are appended. A combined endpoint would hide this distinction.
- If composability problems show up later (race window between calls, performance under high event volume), a single-shot helper can wrap both — that wrapper is a thin upgrade, not an architectural redo.

## Migration shape

### Migration 106 (rewritten in place)

Keeps everything except the `UNIQUE` constraint:

1. `CREATE INDEX IF NOT EXISTS idx_edges_source_target_rel ON edges (source_id, target_id, relationship);` — kept.
2. *(documented skip)* — `idx_claims_agent_id` already present from `001_initial_schema.sql`. Skip preserved.
3. `CREATE INDEX IF NOT EXISTS idx_bp_messages_factor_id ON bp_messages (factor_id);` — kept.
4. ~~`ALTER TABLE claims ADD CONSTRAINT uq_claims_content_hash_agent UNIQUE (content_hash, agent_id);`~~ — moved to migration 107.
5. `COMMENT ON COLUMN activities.agent_id IS '...';` — kept.
6. `ALTER TABLE activities ALTER COLUMN agent_id DROP NOT NULL;` — kept.

Header comment in migration 106 gets a paragraph: "The `(content_hash, agent_id)` UNIQUE constraint originally bundled here was extracted to migration 107 because it requires a prerequisite deduplication backfill (see `docs/architecture/noun-claims-and-verb-edges.md`). Every remaining statement in this file is idempotent or a no-op against the live DB and can be applied immediately."

After this rewrite, migration 106 is **applicable to the live DB today**. PR #6 still ships it as `pending`; a subsequent user-authorized `sqlx migrate run` lands it cleanly.

### Migration 107 (new file)

`migrations/107_claims_unique_content_hash_agent.sql`:

```sql
-- Migration 107: enforce noun-claim canonicality
--
-- Adds the (content_hash, agent_id) UNIQUE constraint that was originally
-- drafted in migration 106 and extracted here when the noun-claims-and-
-- verb-edges architecture was formalised (see docs/architecture/
-- noun-claims-and-verb-edges.md).
--
-- PREREQUISITE: this migration will FAIL until the deduplication backfill
-- (sub-project S2) has reduced the 95,000+ existing duplicate (content_hash,
-- agent_id) groups in the claims table to one canonical row per group.
-- Running it on a dirty table produces:
--
--   ERROR:  could not create unique index "uq_claims_content_hash_agent"
--   DETAIL: Key (content_hash, agent_id)=(\x..., ...) is duplicated.
--
-- The migration is intentionally not wrapped with NOT VALID + later
-- VALIDATE: the constraint represents a real architectural invariant; any
-- future apply attempt should refuse on a dirty table rather than silently
-- defer enforcement.

ALTER TABLE claims
  ADD CONSTRAINT uq_claims_content_hash_agent UNIQUE (content_hash, agent_id);
```

After PR #6 merges, `sqlx migrate info` shows `106/pending` and `107/pending`. A user-authorized `sqlx migrate run` lands 106 cleanly. 107 stays pending until S2 completes; trying to run it earlier fails loudly with a clear constraint-violation error pointing back to the disposition doc.

### Why fail loud rather than `CREATE UNIQUE INDEX CONCURRENTLY` + `NOT VALID`

The constraint represents a real architectural invariant. A partially-validated state where existing dups are grandfathered would corrupt the meaning of the constraint going forward — every future query that depends on `(content_hash, agent_id)` uniqueness for correctness would have a silent failure surface against unflagged historical rows. Failing loud forces backfill discipline.

### Why not a partial index conditioned on `is_current`, `labels`, etc.

- `is_current` belongs to the supersession/version mechanism (migrations 035, 081). Reusing it for dedup signaling would conflate two unrelated semantic dimensions.
- `labels @> ARRAY['telemetry']` would push the dedup decision out to every writer's `labels` field — fragile, and lets bugs slip through silently.
- Both options bake assumption into the schema. The clean architecture per this design has *no* legitimate `(content_hash, agent_id)` duplicates by construction. The constraint should reflect that.

## Documentation deliverables

### `docs/architecture/noun-claims-and-verb-edges.md` (new, canonical)

Sections:

- The pattern (noun-claim, verb-edge, definitions and rules).
- Worked examples mapping each of the three causes onto the pattern (host telemetry, MCP submission, ingest scripts).
- Recommended call sequence with the API surface.
- **Atomicity policy.** Writers are responsible for retry/cleanup if the verb-edge call fails after the noun-claim call succeeds. Orphaned noun-claims are tolerated — they have no effect on graph queries that traverse from edges, and S2-style sweeps can collect them. S3 writer plans may add per-writer retry-on-edge-failure if the writer's audit semantics require strict consistency. The auto-emitted `AUTHORED` edge already gives every successful `POST /api/v1/claims` a baseline edge anchor, so total orphans only occur on transaction-commit failure.
- **Boundary with the `activities` audit table.** `activities` rows describe events without graph traversal. Verb-edges replace `activities` for graph-traversable events (where the edge connects two entities and graph queries reach the event). `activities` remains for non-graph audit (bulk operations, system-level events without entity targets). S3d (host provenance porting) is the canonical migration target — host events currently written to `activities` move to verb-edges as part of that work. Migration 106's `ALTER TABLE activities ALTER COLUMN agent_id DROP NOT NULL` predates this architectural pivot and is preserved; it has no bearing on verb-edge semantics.
- **Edge signing.** Schema supports `signature` / `signer_id` on edges (migration 073). S1 does not require edge signing; the existing `EdgeRepository::create` call passes `None` for signature fields. S3 writer plans specify the signing strategy per writer (host_agent has key material; ingest scripts may not). The "same audit guarantee as claim signatures" claim in the pattern definition is therefore aspirational — schema-supported, S3-realised.
- Migration sequence (106 → 107) and the S2 backfill prerequisite.
- Sub-project map (S1 done, S2/S3/S4 to follow with one-line stubs).

### `docs/migration-106-disposition.md` (rewritten)

Replaces the original four-options doc with the sequenced rollout. Sections:

- Context (the dup probe data + three causes, with concrete counts).
- The architectural pivot (link to the canonical architecture doc).
- Migration sequence (106 here, 107 here, both pending; SHA-384 prefixes for both files).
- The four-stage rollout (S1 done in this PR, S2 / S3 / S4 future plans).
- What was rejected and why: `apply-as-is` (now embodied by 107 with the S2 prereq), `mark-applied-without-running` (semantic mismatch), `supersede-with-105` (V2's 105 pre-dates the architectural pivot, so superseding with it would re-import the old model — permanently obsolete), `defer` (rejected because the architecture cleanup is the priority Jeremy named).
- Authorisation status: PR #6 ships S1 with no live-DB writes; applying migrations 106 and 107 to the live DB are separate user-authorized steps.

### `migrations/README.md` slot-gap section update

- Slot 099 still skipped (V2 numbering).
- Slot 105 still skipped — the supersede option is **permanently obsolete** now (record this).
- Slot 107 documented as pending until S2 backfill.
- New-migration advice: "pick the next free slot ≥ 108 (slot 107 is reserved for the deferred constraint enforcement)."

## PR #6 integration

**Branch state:** `chore/migration-renumber-2026-04-25` is at `609111d`, pushed to `origin`, PR #6 open against `main`. Adding S1 means **appending new commits — no force-push**. Branch grows from 10 commits to ~16.

**Proposed commit sequence** (each goes through subagent-driven-development: implementer → spec-reviewer → quality-reviewer):

1. `docs(architecture): introduce noun-claims-and-verb-edges pattern`
   New file `docs/architecture/noun-claims-and-verb-edges.md`. Self-contained — no other code referenced yet.

2. `chore(migrations): split 106 — extract UNIQUE constraint to 107`
   Edits `migrations/106_security_and_hardening.sql`: (a) removes statement 4 (the UNIQUE constraint), (b) updates the header comment from `-- Migration 002: Code review hardening` (a fossil from the original internal draft slot) to `-- Migration 106: Code review hardening (deferred UNIQUE moved to 107)`, (c) adds a paragraph explaining the split and pointing to the architecture doc. Adds `migrations/107_claims_unique_content_hash_agent.sql` with the constraint and the prerequisite-failure header comment. **Side effect:** this changes the SHA-384 of `migrations/106_security_and_hardening.sql`. The disposition doc's recorded hash (added in commit `adef3fa` and used in the `mark-applied-without-running` SQL) becomes stale; commit 5 reconciles it. Implementation step in the plan: compute the new SHA via `sha384sum migrations/106_security_and_hardening.sql` after the edit and embed it verbatim in the disposition doc rewrite.

3. `feat(db): add find_by_content_hash_and_agent / create_or_get / create_strict helpers`
   Three new methods in `crates/epigraph-db/src/repos/claim.rs`, all taking `&mut PgConnection`: a find-only (`find_by_content_hash_and_agent`), a find-or-insert on `(content_hash, agent_id)` (`create_or_get`), and a raw INSERT with no implicit dedup (`create_strict`). Existing `create()` and `create_with_tx()` unchanged — they retain the legacy implicit content-hash dedup, with a doc-comment flagging it as legacy and pointing to the new helpers. No callers wired up yet.

4. `feat(api): add if_not_exists option to POST /api/v1/claims`
   Request struct gets the new field; response gets `was_created`. Handler branches: `if_not_exists: true` → `create_or_get`, `if_not_exists: false` → `create_strict` (replacing the existing `create_with_tx` call site). Adds the `if_not_exists: true` × `privacy_tier`, `if_not_exists: true` × `content_hash` override, and `was_created: false` skip-metadata-UPDATE branches per spec. Maps unique-violation errors on `if_not_exists: false` to `409 Conflict`. Tests cover the cases enumerated in the API surface section. **Behavior change** for callers that did not set `if_not_exists` previously: post-107, duplicate `(content_hash, agent_id)` submissions begin returning `409` instead of silently returning the first agent's row. Pre-107 (between this PR merge and S4), the same callers may produce duplicate rows — S2 cleans them up. Internal Rust callers of `ClaimRepository::create()` / `create_with_tx()` are unaffected.

5. `docs(migrations): rewrite 106 disposition for S1 architectural pivot`
   Replaces the four-options structure with the sequenced rollout. Updates the recorded SHA-384 of migration 106 to its new (post-split) value.

6. `docs(migrations): update README slot-gap for 107`
   Small README edit per the section above.

**PR body addendum** posted via `gh pr edit 6 --body …` after commits land:

> ## Architectural pivot (added 2026-04-25)
>
> While preparing to apply migration 106, live-DB probes uncovered ~95k duplicate `(content_hash, agent_id)` groups. Diagnosis: the codebase had drifted from a "noun-claims and verb-edges" architecture that migration 106's UNIQUE constraint encodes. This PR now also includes S1 of a four-stage rollout to restore that architecture (full design at `docs/superpowers/specs/2026-04-25-noun-claims-and-verb-edges-design.md`):
>
> - **S1 (this PR):** pattern docs, idempotent claim creation primitive (`if_not_exists` flag), migration split (106 stays applicable; 107 holds the deferred constraint).
> - **S2 (next plan):** backfill 95k existing duplicate groups to canonical claim + verb edges.
> - **S3 (writers):** four sub-plans updating MCP, agent harness, ingest, host provenance.
> - **S4 (final):** apply migration 107 once S2 is verified clean.
>
> Title stays "align internal numbering with live DB" — the renumber is still the primary contribution; S1 is a same-PR follow-on because it must edit migration 106 before it lands.

Title remains as currently set.

## Risk and rollback

- **PR #6 size grows.** ~6 additional commits, ~600 additional lines (mostly docs + the architecture file). The reviewer surface is wider but each commit is independent and atomic; rollback of any one is `git revert`.
- **Migration 106's SHA-384 changes.** The disposition doc's recorded hash becomes correct only after commit 5. Between commits 2 and 5 the on-branch state is internally inconsistent — but no live DB has applied either file yet, so the inconsistency is resolved before the merge boundary.
- **API behavior change for default-flag callers.** With `if_not_exists` defaulting to `false`, the API path now routes through `create_strict` (raw INSERT) instead of `create_with_tx` (implicit content-hash dedup). Pre-107: callers who relied on the implicit dedup will see duplicate rows when re-submitting the same content. Post-107: those duplicates surface as `409 Conflict`. The mitigation is documented: callers that want dedup set `if_not_exists: true`. The pre-existing cross-agent collapse bug (Bob's request returning Alice's row) is also fixed for the API path. Internal Rust callers of `ClaimRepository::create()` / `create_with_tx()` are unaffected because those legacy methods are unchanged.
- **No live-DB writes in S1.** Same rollback story as the renumber: `git reset --hard origin/main` undoes everything.

## Sub-project map (after S1)

**Sub-project ordering: S3a → S2 → (S3b–S3d in parallel) → S4.** Writers must be updated first so duplicates stop accumulating. Backfill (S2) cleans existing dups against a stable writer baseline. Constraint enforcement (S4) locks the door. Running S2 before S3a is wasteful — every backfill batch is immediately re-dirtied by the unfixed canonical writer. S3b–S3d (lower-volume writers) can run in parallel with S2 once S3a deploys, because their accretion rate is small relative to the backfill rate.

- **S3a — `epigraph-mcp` submission paths** (Cause 2 in the canonical codebase, plus reaching cleanly into the rest of S3). Highest priority — `epigraph-internal/crates/epigraph-mcp` is the live MCP server, ~72k dup contribution from its V2 cousin tells us the same path will accumulate unless wired to `if_not_exists: true`. Each `epigraph-mcp` tool that calls `ClaimRepository::create()` is migrated to `create_or_get` (or to the API endpoint with `if_not_exists: true`, whichever fits). Future plan.

- **S2 — Backfill duplicate claim groups.** Convert each of 95,214 existing `(content_hash, agent_id)` groups into one canonical claim plus (N-1) timestamped verb-edges using the dups' `created_at` values. Redirect the 413k existing edges, 95k MFs, and 2.3k evidence rows currently pointing at non-canonical rows. API-driven, batchable, reversible. Writes to live DB; gated on its own design + plan + user authorization. Runs after S3a so the canonical writer has stopped emitting new dups. **Additional prerequisite:** V2 ingest scripts are no longer running (either by V2 deprecation or by completing S3c). A live V2 textbook re-run mid-backfill would re-dirty 100k+ rows and force restart. Confirm the V2 host status before scheduling S2. Future spec.

- **S3b–S3d — remaining writers** (parallelisable with S2):
  - **S3b — `epigraph-agent` `submit_claim` builtin tool.** Memory says the next-gen harness is already event-oriented; S3b verifies and aligns.
  - **S3c — Replace V2 ingest scripts** (Cause 1, ~173k dups, V2-resident). May be skipped since V2 is being deprecated.
  - **S3d — V2 `epigraph-nano/provenance.rs`** (Cause 3, ~18 April rows but ongoing). Port to `epigraph-agent` or decommission with the V2 host.

- **S4 — Apply migration 107.** Becomes a one-liner once writers are clean and S2's backfill has settled. User-authorized `sqlx migrate run`.

- **(Out of band)** Migrate the ~44 internal Rust callers of `ClaimRepository::create()` / `create_with_tx()` to `create_or_get` or `create_strict` and remove the legacy implicit content-hash dedup. Independent of S2/S3/S4 (the API endpoint already routes around these legacy methods after S1); priority is low since the legacy callers are mostly tests and the cross-agent collapse bug is rare in practice. Future task.

Each future sub-project gets its own brainstorm → spec → plan cycle.
