# S3a — `epigraph-mcp` Writer Migration Design

> **Origin:** Ported from `epigraph-internal` (private dev repo) as historical
> design context. The implementation landed on this repo as **#17**. Branch /
> PR-number references below point to the original `epigraph-internal` artifacts.

**Date:** 2026-04-26
**Branch:** `feat/s3a-mcp-writer-migration` (created off `chore/migration-renumber-2026-04-25` so S1 helpers are the base); separate PR from #6
**Status:** Approved for spec → plan → implementation
**Sub-project of:** Noun-Claims and Verb-Edges architecture (S3a — first writer migration after S1 foundation)

---

## Why this design exists

S1 of the noun-claims-and-verb-edges architecture shipped on branch `chore/migration-renumber-2026-04-25` (PR #6, currently OPEN — pending merge): `docs/architecture/noun-claims-and-verb-edges.md`, idempotent claim-create primitive `if_not_exists` on `POST /api/v1/claims`, migrations 106/107 split. S3a is a follow-on on a child branch and is queued behind PR #6 in the merge order; PR #6 must land before S3a's PR can be merged. The architecture's sub-project map orders the rollout as **S3a → S2 → (S3b–S3d in parallel) → S4** because writers must stop accumulating new duplicates before the S2 backfill begins — otherwise every backfill batch is immediately re-dirtied.

S3a migrates the canonical-codebase writer that contributed Cause 2's ~72k duplicate rows: `epigraph-internal/crates/epigraph-mcp`, the live MCP server. Five callsites in `crates/epigraph-mcp/src/tools/{claims,memory,workflows,workflows,ingestion}.rs` currently call `ClaimRepository::create()` unconditionally; every same-agent same-content resubmission produces a fresh `claims` row. Once 107 lands (S4), those resubmissions would error with `409 Conflict`. S3a switches the five callsites to the noun-claim-canonical pattern: idempotent create via `create_or_get`, with each submission emitting an AUTHORED verb-edge as the lifecycle event marker.

## Goals and non-goals

**S3a ships:**

- A shared helper `create_claim_idempotent(pool, claim, tool_name)` in `crates/epigraph-mcp/src/claim_helper.rs` that wraps `ClaimRepository::create_or_get` plus AUTHORED edge emission.
- Migration of all 5 callsites in `crates/epigraph-mcp/src/tools/{claims,memory,workflows,ingestion}.rs` to use the helper.
- Per-tool resubmit semantics (Option A or Option B per the table in §"Per-tool migration").
- Tier-1 helper unit tests + Tier-2 integration tests for `submit_claim` and `ingest_paper`.

**S3a explicitly does NOT ship:**

- **No live-DB writes.** Migration 107 is not applied; the S2 backfill is not run.
- **No Layer 2 (embedding near-neighbor) dedup** for `ingest_paper`. Layer 0 (byte-identical content_hash) only. Layer 2's threshold tuning needs labeled pairs from S2 backfill; doing it before S2 means tuning blind.
- **No per-run `paper_artifact` noun-claim** for `ingest_paper`. The architecture doc's worked example uses this pattern for S3c (V2 ingest scripts with source-coordinate dedup); S3a's MCP `ingest_paper` stays agent-direct and emits AUTHORED only.
- **No edge signing for AUTHORED.** Mirrors the API handler at `routes/claims.rs:565` which passes `None` for signature fields. The architecture doc explicitly defers edge signing.
- **No migration of the ~44 internal Rust callers** of legacy `ClaimRepository::create()` / `create_with_tx()` (test files, epigraph-api routes, other crates). Only the 5 epigraph-mcp callers are migrated. Legacy methods stay.
- **No removal of legacy `ClaimRepository::create()` / `create_with_tx()`.** They remain with their cross-agent collapse bug, documented as legacy.

## Architecture

### The shared helper

A new module `crates/epigraph-mcp/src/claim_helper.rs` exposes one function:

```rust
/// Idempotently create a claim by (content_hash, agent_id) and emit an AUTHORED
/// verb-edge marking the submission lifecycle event.
///
/// Mirrors the API handler's pattern at routes/claims.rs:444-576: create_or_get
/// inside a connection scope, then fire-and-forget AUTHORED edge on the pool
/// after the connection is released. AUTHORED failure is logged via tracing::warn!
/// but not propagated — orphan claims are tolerated per the architecture doc's
/// atomicity policy. Each submission emits a distinct AUTHORED edge regardless of
/// `was_created`, because each submission is an authorship verb-event.
pub async fn create_claim_idempotent(
    pool: &PgPool,
    claim: &Claim,
    tool_name: &'static str,
) -> Result<(Claim, bool), McpError> {
    let mut conn = pool.acquire().await.map_err(internal_error)?;
    let (claim, was_created) = ClaimRepository::create_or_get(&mut *conn, claim)
        .await
        .map_err(internal_error)?;
    drop(conn);

    if let Err(e) = EdgeRepository::create(
        pool,
        claim.agent_id.as_uuid(), "agent",
        claim.id.as_uuid(), "claim",
        "AUTHORED",
        Some(json!({"tool": tool_name, "was_created": was_created})),
        None, None,
    ).await {
        tracing::warn!(
            claim_id = %claim.id.as_uuid(),
            tool = tool_name,
            error = %e,
            "AUTHORED verb-edge emit failed; claim row persisted as orphan"
        );
    }

    Ok((claim, was_created))
}
```

**Design choices:**

- **Helper lives in `epigraph-mcp`, not `epigraph-db`.** AUTHORED edge emission is MCP-layer policy. Putting it on `ClaimRepository` would force the AUTHORED emit on every internal caller of `create_or_get` (44 callsites across the workspace, many of which don't want AUTHORED). The dedup primitive stays at the data layer; the verb-edge emission stays at the writer layer.
- **`tool_name: &'static str`** forces compile-time-literal callsite values (`"memorize"`, `"submit_claim"`, etc.) — typo-resistant.
- **Connection-scoped, not transactional.** Mirrors the API handler at `routes/claims.rs:560-576`, which commits the claim INSERT then fires AUTHORED on the pool fire-and-forget. Post-107 race recovery is handled inside `create_or_get` itself; no MCP-side retry needed.
- **AUTHORED `let _` swallowed-or-warned.** Matches API behavior; orphans are tolerated per atomicity policy. One small improvement over the API: emits a `tracing::warn!` on edge failure so observability tooling can flag orphans without grepping fire-and-forget bugs.

## Per-tool migration

| Callsite | Tool | Resubmit semantics | Resubmit branch (`was_created == false`) |
|---|---|---|---|
| `claims.rs:134` | `submit_claim` | **Option B** (preserve evidence) | Create Evidence + ReasoningTrace as standalone noun-claims; emit `claim --[DERIVED_FROM @ T]--> evidence` and `claim --[HAS_TRACE @ T]--> trace` verb-edges (relationship names match the API handler at `routes/claims.rs:587-614`); **skip** `update_trace_id` (canonical claim's `trace_id` is immutable post-creation); skip DS auto-wire (canonical truth was set on first create). |
| `memory.rs:72` | `memorize` | **Option A** (skip everything) | Skip Evidence + Trace + `update_trace_id` + DS auto-wire. AUTHORED edge (already emitted by helper) is the only persisted artifact of the resubmission. |
| `workflows.rs:144` | `store_workflow` | **Option A** | Same as `memorize`. The workflow-definition JSON is canonical; resubmission is a no-op. |
| `workflows.rs:590` | `improve_workflow` | **Option A** + idempotent `variant_of` | Skip Evidence + Trace, `update_trace_id`, and `embed_and_store` (no DS auto-wire exists in this tool today, so there is nothing to skip on that axis); **also skip** the `variant_of` edge creation (the parent→variant relationship is set when the variant is first created; resubmits don't create new sibling-variants). The AUTHORED edge captures "I tried to improve this again." |
| `ingestion.rs:218` | `ingest_paper` (per-claim loop) | **Option B** | Per LLM-extracted claim: if `was_created=true`, full sequence (Evidence + Trace + `update_trace_id` + DS batch entry collection + relationship edges later). If `was_created=false`, create Evidence + Trace as standalone noun-claims linked via `DERIVED_FROM` / `HAS_TRACE` edges; **skip** DS batch entry (would re-wire canonical truth), skip `embed_and_store` (canonical embedding already exists); but **keep** the claim's UUID in `claim_uuids` so post-loop relationship-edge construction still emits inter-claim relationships from this run. **Side effect (intentional):** repeat `ingest_paper` runs over the same source produce duplicate `(source, target, relationship)` rows in `edges` — one per run. This is consistent with architecture rule 1 ("re-occurrence of the same lifecycle event = new edge") and matches what each run is actually saying ("this run asserts that X relates to Y"). Source-coordinate dedup for relationship edges is deferred to S3c (V2 ingest), where source coordinates are first-class; for S3a the relationship-edge multi-emit is the documented behavior. |

**Common shape across all 5 callsites:**

```rust
let (claim, was_created) = create_claim_idempotent(&server.pool, &claim, "<tool_name>").await?;
if was_created {
    // existing post-create logic: Evidence + Trace + update_trace_id + DS + embed + edges
} else {
    // tool-specific resubmit branch (per table above)
}
```

**Per-callsite refactor: re-read `claim.id` after the helper.** Both `claims.rs:92` (`let claim_uuid = claim.id.as_uuid();`) and `memory.rs:38` capture the claim UUID *before* the create call; today that's harmless because every create produces a fresh row. After S3a, on `was_created=false` the helper returns the canonical row whose UUID differs from the locally-generated one. Every downstream use — DS auto-wire's `claim_uuid` arg, `embed_and_store`, `ClaimRepository::update_truth_value`, the response body's `claim_id`, and `ingestion.rs`'s pushes into `claim_ids` / `claim_uuids` / `ds_entries.claim_id` — must read from the shadowed `claim` returned by the helper. Each per-callsite migration commit removes or relocates the early `claim_uuid` capture.

**Truth-value clobber risk** in `claims.rs`: the existing flow updates `truth_value` from DS pignistic after auto-wire. On `was_created=false` with Option B, DS auto-wire is skipped, so no clobber. On `was_created=true` with Option B, the flow is identical to today.

**Truth-value response divergence (related fix).** Today, `submit_claim`'s response `truth_value` field falls back to `raw_truth` (the new submission's `confidence * weight`) when DS is unavailable. On `was_created=false` Option B, that path would report a value never written to the DB — the canonical row carries first-create's truth. The migration must read `claim.truth_value.value()` from the returned canonical row in the `was_created=false` branch. The Tier-2 `submit_claim_resubmit_creates_evidence_trace_via_edges` test asserts response.truth_value matches DB.truth_value across both calls.

## Resubmit semantics rationale

**Why Option A for memorize / store_workflow / improve_workflow:**
- Same content from same agent rarely brings new information. Memorize-it-again is a "noise" event the AUTHORED verb-edge captures cleanly without growing canonical state.
- The workflow-definition JSON is canonical: same JSON content_hash means the user re-stored the same workflow definition, not a new one.

**Why Option B for submit_claim / ingest_paper:**
- Each `submit_claim` call inherently carries a new `evidence_data` value. Discarding that on resubmit loses real information — the user is providing a new piece of evidence supporting an existing claim.
- Each `ingest_paper` call extracts from a (possibly different) paper context. Even with byte-identical extracted text, the supporting passage / DOI / page reference may differ. Preserving these as new Evidence nouns linked to the canonical claim via `DERIVED_FROM` edges is the architecture-doc-faithful way to record multi-source attestation.

**Relationship-naming divergence from API handler.** The API handler emits `HAS_TRACE` / `DERIVED_FROM` only on `was_created=true` (first-create lineage). MCP's Option B reuses the same relationship names but emits them on `was_created=false` resubmits. Rationale: in MCP, agent identity is server-derived and stable, so every resubmit IS an owner-request; the architecture doc's "non-owner mutation" concern doesn't apply. Reusing the relationship names keeps graph queries uniform — "all evidence for claim X" is one query against `DERIVED_FROM` regardless of which writer emitted the edge. The semantic invariant becomes: `HAS_TRACE` / `DERIVED_FROM` accumulate over a claim's lifetime; the canonical `trace_id` column reflects only the original create. Backlog item filed to align the API to the same accumulating semantics later.

**Why standalone noun-claims with verb-edges, not `update_trace_id`:**
- `update_trace_id` mutates the canonical claim's `trace_id` field. Repeated mutation by re-submissions would clobber the canonical claim's primary trace, conflating multiple submissions' traces into one slot.
- Evidence and ReasoningTrace are themselves entities with their own `id`, `agent_id`, `signature`. Each is a noun-claim by the architecture's definition. Linking them via verb-edges preserves their identity and lets graph queries traverse "all evidence for this claim" without ambiguity.

## Failure semantics & error handling

**Helper failure modes:**

1. **`pool.acquire()` failure** — propagates as `McpError::internal_error`.
2. **`create_or_get` failure** — propagates as `McpError::internal_error`. Includes pre-107 race window (architecture-doc-tolerated; S2 cleans up).
3. **AUTHORED edge failure** — logged via `tracing::warn!`, swallowed. Returns `Ok((claim, was_created))`. The `claims` row exists but lacks an AUTHORED anchor.

**Per-tool callsite failure semantics:**

- Each tool's existing post-create logic (Evidence + Trace + DS + embed + relationships) keeps its current `?` propagation. If Evidence creation fails after `create_claim_idempotent` returns Ok, the claim is orphan-with-AUTHORED-but-no-trace — a tolerated state per atomicity policy. S2-style sweeps can collect these.
- Existing `tracing::warn!` patterns in DS auto-wire failure paths are preserved.

**Behavior change for end users of MCP tools:**

After S3a, repeat calls to the 5 tools with the same content from the same MCP agent return the canonical claim's UUID instead of a fresh UUID. Anything downstream that relied on a fresh UUID per call will see the same UUID on resubmits. **Risk surface:** agent code that uses MCP tool return UUIDs as call-deduplication keys. Spot-check epigraph-agent code paths during S3a implementation; flag any reliance on uniqueness-of-returned-UUID-per-call as a separate fix item (logged as an EpiGraph backlog claim).

**Pre-107 race window:** the architecture doc's pre-107 race applies — two concurrent same-agent calls may both report `was_created=true` and produce two rows. S2 cleans up. No MCP-specific mitigation needed.

**Post-107 race recovery:** when migration 107 lands, the (content_hash, agent_id) UNIQUE constraint catches concurrent inserts. `create_or_get` handles the retry path internally per the existing spec.

## Tests

epigraph-mcp has zero tests today. S3a adds the first.

### Tier 1 (mandatory) — Helper unit tests

`crates/epigraph-mcp/tests/claim_helper_tests.rs`. Patterns after `crates/epigraph-db/tests/claim_repo_helpers.rs` — same `try_test_pool` / `test_pool_or_skip!` macro / pre-107 / post-107 fixture toggling.

| Test | Asserts |
|---|---|
| `helper_creates_when_absent` | First call returns `was_created=true`; one row in `claims`; one row in `edges` with `relationship='AUTHORED'`, `properties->>'tool'='test_tool'`, `properties->>'was_created'='true'`. |
| `helper_returns_existing_when_present` | Second call (same content_hash+agent) returns `was_created=false`; only one row in `claims`; **two** AUTHORED edges in `edges` (one per call), the second has `properties->>'was_created'='false'`. |
| `helper_emits_authored_on_both_branches` | Cross-checks: with `was_created=true` AND `was_created=false`, AUTHORED edge always fires. |
| `helper_post_107_race_recovery` | Post-107 fixture; concurrent two-insert race recovers via `create_or_get`'s internal `DbError::DuplicateKey` retry; one row, `was_created=false` for the loser. |
| `helper_pre_107_no_constraint` | Pre-107 fixture; helper still works, second call still returns existing row (find-then-insert path, not race-recovery path). |
| `helper_authored_failure_does_not_propagate` | Use `tracing-test` to capture log output; force AUTHORED failure (e.g., drop edges constraint or use a malformed agent_id reference); confirm helper returns `Ok` and emits a `tracing::warn!`. |

### Tier 2 (high-value subset) — Per-tool integration tests

`crates/epigraph-mcp/tests/tool_resubmit_tests.rs`. Builds an `EpiGraphMcpFull` with a stub signer (deterministic Ed25519 keypair) and the test pool. Tests the trickiest two tools:

| Test | Asserts |
|---|---|
| `submit_claim_resubmit_creates_evidence_trace_via_edges` | Call `submit_claim` twice with same content + different `evidence_data`. After second call: one `claims` row; **two** `evidence` rows; **two** `reasoning_traces` rows; canonical claim's `trace_id` unchanged from first create; second call's evidence + trace linked to claim via `DERIVED_FROM` + `HAS_TRACE` edges. |
| `ingest_paper_resubmit_creates_per_call_evidence_no_dup_claim` | Call `ingest_paper` twice with the same DOI + same extracted-claim text. After second call: one `claims` row per unique LLM-extracted statement; per-call evidence + trace rows preserved via `DERIVED_FROM` / `HAS_TRACE` edges; `embed_and_store` not called again on resubmit (counting embedder stub); `auto_wire_ds_for_claim` not invoked on resubmit. |

### Deferred Tier 2 tests (logged as backlog claims)

memorize, store_workflow, improve_workflow follow Option A (skip-everything-on-resubmit). The helper unit tests already cover the dedup primitive; tool-level Option A tests would mostly assert "didn't call X." Manually verifiable. Logged as a backlog item.

### Test infrastructure invariants

- **`--test-threads=1` mandatory.** Mirrors S1 test policy (the pre-107/post-107 fixture toggling races otherwise).
- **DATABASE_URL must point at a clean test DB**, not the live `epigraph-postgres` docker container (which has 95k duplicate (content_hash, agent_id) groups). The `add_unique_constraint` helper's `DELETE` would attempt to dedup all 95k inline — destructive on the live DB. Either (a) `sqlx database create` a separate DB and point DATABASE_URL there, or (b) spin up a second pgvector container on a different port. The implementation plan's pre-flight findings will document this.
- **Silent-skip detection.** Mirrors S1: scan test output for `Skipping DB test:` after each run. A skip-when-DATABASE_URL-is-set is a vacuous pass.
- **`tracing-test` dev-dep required.** `crates/epigraph-mcp/Cargo.toml` does not yet have `tracing-test` in `[dev-dependencies]`; the helper unit test `helper_authored_failure_does_not_propagate` requires it for `tracing::warn!` capture. Add it as part of commit 1 (the helper module + Tier-1 tests).

## Out of scope (logged as EpiGraph backlog claims)

All deferred items are submitted to EpiGraph via `submit_claim` with labels `["backlog", "high-urgency", "s3a-followup"]` so they're queryable by future planning sessions. Items:

1. **Layer 2 (embedding near-neighbor) dedup for `ingest_paper`.** Threshold tuning needs S2-labeled pairs; revisit after S2 ships.
2. **Per-run `paper_artifact` noun-claim** for `ingest_paper`. The architecture doc's worked-example pattern, deferred to S3c (V2 ingest) where source coordinates make it natural.
3. **Edge signing for AUTHORED edges.** Schema-supported (migration 073); not yet implemented in any writer.
4. **S3b — `epigraph-agent` `submit_claim` builtin migration.** Independent sub-project; same drift exists in the agent harness.
5. **S3c — V2 ingest scripts migration.** May be skipped if V2 deprecates first.
6. **S3d — V2 `epigraph-nano/provenance.rs` migration.** Cause 3 source.
7. **Migrate ~44 internal Rust callers** of legacy `ClaimRepository::create()` / `create_with_tx()` (test files in epigraph-db + epigraph-api integration tests + epigraph-api/routes/{claims,conventions}.rs). Out-of-band cleanup.
8. **Remove legacy `ClaimRepository::create()` / `create_with_tx()`** methods. Gated on (7).
9. **Tier-2 integration tests for memorize, store_workflow, improve_workflow.** Deferred from S3a.
10. **Spot-check epigraph-agent for reliance on per-call MCP-tool UUID uniqueness.** Risk surface from S3a's behavior change.
11. **Align API handler's `HAS_TRACE` / `DERIVED_FROM` emission to accumulating semantics.** S3a's MCP Option B emits these on resubmit; the API handler at `routes/claims.rs:585-614` only emits on first create. Align the API later so query semantics are uniform across writers.

## Risk and rollback

- **Branch on its own PR.** Separate from PR #6. Each of the 6 commits (Approach 2) is independently revertable.
- **No live-DB writes.** Source-only PR; rollback is `git reset --hard origin/main` on the S3a branch.
- **Behavior change for MCP tool callers.** Documented above. Spot-checked during implementation.
- **First tests added to epigraph-mcp.** Test infrastructure (try_test_pool helper, fixtures) is the first of its kind in this crate; pattern is copied from claim_repo_helpers.rs to maximize consistency.
- **Five callsites, six commits.** Each commit is atomic and per-tool (commit 1 = helper module + tests; commits 2–6 = one callsite migration each, with focused tests). Reviewer can validate the helper once and skim the rest.

## Sub-project map (after S3a)

S1 (helpers shipped on `chore/migration-renumber-2026-04-25`; PR #6 OPEN, pending merge) → **S3a (this design)** → S2 → S3b–S3d (parallel) → S4.

- **S3a** unblocks S2 by stopping new dups from accumulating in the canonical codebase's MCP server.
- **S2** can begin once S3a is deployed and the dup count stops growing in canonical-codebase write paths. (V2 writers — Causes 1 and 3 — still need S3c/S3d if V2 stays alive; otherwise V2 deprecation removes the threat.)
- **S3b–S3d** parallelisable with S2 once S3a deploys.
- **S4** applies migration 107 once S2 backfill is verified clean.

Each sub-project gets its own brainstorm → spec → plan cycle.

## PR commit sequence (Approach 2)

1. `feat(mcp): add create_claim_idempotent helper for noun-claim canonical create`
   New file `crates/epigraph-mcp/src/claim_helper.rs`. Helper module + Tier-1 unit tests + a `mod claim_helper;` line in `lib.rs`. No callsite changes yet.

2. `feat(mcp): migrate submit_claim to noun-claim canonical pattern`
   Edits `crates/epigraph-mcp/src/tools/claims.rs:134`. Adds Option B resubmit branch (Evidence + Trace + `DERIVED_FROM` / `HAS_TRACE` edges, skip `update_trace_id`, skip DS auto-wire). One Tier-2 integration test.

3. `feat(mcp): migrate memorize to noun-claim canonical pattern`
   Edits `crates/epigraph-mcp/src/tools/memory.rs:72`. Option A resubmit branch.

4. `feat(mcp): migrate store_workflow to noun-claim canonical pattern`
   Edits `crates/epigraph-mcp/src/tools/workflows.rs:144`. Option A resubmit branch.

5. `feat(mcp): migrate improve_workflow to noun-claim canonical pattern`
   Edits `crates/epigraph-mcp/src/tools/workflows.rs:590`. Option A + idempotent variant_of skip.

6. `feat(mcp): migrate ingest_paper per-claim loop to noun-claim canonical pattern`
   Edits `crates/epigraph-mcp/src/tools/ingestion.rs:218`. Option B per loop iteration. One Tier-2 integration test.

Total: 6 commits, ~400 lines (helper + tests + 5 small callsite branches).
