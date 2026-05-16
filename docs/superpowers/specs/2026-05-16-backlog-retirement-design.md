# Backlog Retirement Convention & Tooling

**Date:** 2026-05-16
**Status:** Design — awaiting review
**Author:** Jeremy Barton (with Claude)

## Problem

Backlog items are filed as claims labelled `["backlog"]`, but the label is never cleared when the underlying issue is resolved. As of 2026-05-16, `query_claims_by_label(["backlog"])` returns 100 items (the MCP cap), but a large fraction are stale — already addressed weeks ago and forgotten.

Three different retirement conventions are in flight, none of which produce a coherent open-backlog view:

1. **Free-text reference** (most common). A new claim is filed with `"Resolves <UUID>: …"` in its content. The original keeps its `["backlog"]` label and stays in every backlog query forever. Example: `4485beac` ("Embedding backfill complete… Resolves 1c31a529") — `1c31a529` still has `["backlog"]`.
2. **`supersedes` column + `is_current` flag** (rare). Raw SQL `UPDATE claims SET supersedes = canonical_id, is_current = false`. Used in the 2026-05-08 dedup of 25 duplicate bug claims. Properly retires the claim at the column level but is invisible to MCP readers because `get_claim` and `query_claims_by_label` don't surface those columns. Example: `6949d004 → ffa446e1`.
3. **Re-label original** (very rare). PATCH labels to add `"resolved"`. Only one observed case (`c4e48078`), and `"backlog"` typically stays present, so the claim still surfaces in label queries unless the query negates `"resolved"`.

Compounding factor: the read-side MCP (`get_claim`, `query_claims_by_label`) returns a 6-field flat record — no `labels`, no `is_current`, no `supersedes`. Even claims that *have* been properly retired at the column level look identical to live ones from the agent's perspective. This is what allowed three conventions to grow without anyone noticing the inconsistency.

Concrete evidence of the mess: claim `1c31a529` ("Embedding backfill gap") has two downstream retirement signals — a "backfill complete" claim (`4485beac`, free-text Resolves convention) AND a "NOT-A-BUG (per Jeremy)" reframe (`6d28afba`, surfaces only via `get_provenance` as a `parent_ids` link). Neither updated the original's labels. The original still reports `truth_value=0.54` with `["backlog"]` intact.

## Goals

1. **One canonical retirement convention** for status tracking (separate from epistemic claim replacement).
2. **Read-side MCP surfaces enough state** that agents and humans can see whether a claim is retired without round-tripping through `get_provenance`.
3. **Convenience write-side primitive** so the convention is one tool call, not two — agents won't skip step 2 if there is no step 2.
4. **Cleanup pass** that retroactively retires the existing ~100 stale backlog items wherever a resolution exists.
5. **Drift safety net** — a recurring reconciler that catches free-text "Resolves <UUID>" claims filed without the proper PATCH and back-fills the label update.

Non-goals: redesigning the epistemic semantics of `supersedes` / `is_current`, changing the `claims` schema, building a backlog UI, automating *which* items get labelled `"backlog"` in the first place.

## Convention

- **Open backlog** = claims where `labels @> ["backlog"]` AND NOT `labels @> ["resolved"]`. Both signals are first-class; the query must check both.
- **Retirement** = PATCH the original claim's labels: `add: ["resolved"]`, keep `"backlog"` so the historical query ("everything ever filed as backlog") still works.
- `supersedes` and `is_current` are reserved for *epistemic* claim replacement — when a newer claim refines or replaces the factual content of an older one. They are NOT the primary signal for "this issue was addressed."
- The resolution claim itself (a separate row) keeps the free-text `"Resolves <UUID>: …"` prose for audit / human readability. Prose is the narrative, label is the signal.
- Existing `supersedes`-based retirements (like `6949d004 → ffa446e1`) are honoured for backward compatibility: the cleanup pass treats `is_current=false` as an additional retirement signal and back-fills the `"resolved"` label.

## Architecture

Five components, each shippable independently:

1. **MCP read-side extension** (epigraph public, Rust)
2. **MCP write-side tool: `resolve_backlog_item`** (epigraph public, Rust)
3. **One-shot cleanup script** (Python, `scripts/`)
4. **Recurring reconciler scheduled task** (workflow + script)
5. **Convention documentation** (CLAUDE.md updates in epigraph + epiclaw)

### Component 1: MCP read-side extension

**Goal:** expose retirement state so agents and humans can tell a live claim from a retired one without `get_provenance`.

Changes:

- **`mcp__epigraph__get_claim`** output schema gains three fields:
  - `labels: string[]`
  - `is_current: bool`
  - `supersedes: UUID | null`
- **`mcp__epigraph__query_claims_by_label`** gains two params and two output fields:
  - Param `exclude_labels: string[]` (default `[]`) — returned claims must NOT contain any of these labels.
  - Param `current_only: bool` (default `false`) — when true, filter to `is_current = true`.
  - Output: every returned claim includes `is_current` and `supersedes` (and `labels`, currently absent).
- The default behaviour of `query_claims_by_label` is unchanged when the new params are omitted, so existing callers don't break.

Implementation: changes to `epigraph-mcp` server tool definitions + corresponding handler in `epigraph-api` if the query is delegated, or direct SQL filter (`NOT (labels && $exclude::text[])` and `is_current = true`) if the MCP server queries the DB directly. The actual implementation path is decided in the implementation plan after reading the current MCP handler code.

### Component 2: MCP write-side tool — `resolve_backlog_item`

**Goal:** single tool call that both submits the resolution claim and PATCHes the original's labels. Agents can't half-apply the convention because there's no half.

Signature:

```
mcp__epigraph__resolve_backlog_item(
  original_id: UUID,           # the backlog claim being retired
  resolution_content: string,  # narrative for the new resolution claim
  methodology: string = "resolution",
  evidence: list[Evidence] = []
) -> { resolution_claim_id: UUID, original_labels: string[] }
```

Semantics:

1. Validate `original_id` exists and currently has `"backlog"` in its labels (warn-only, don't reject — sometimes you resolve something that was never labelled backlog).
2. Submit a new claim with:
   - `content` = `"Resolves <original_id>: <resolution_content>"` (prose convention preserved).
   - `labels = ["resolved"]`.
   - `methodology` and `evidence` passed through.
3. PATCH the original claim's labels: `add: ["resolved"]` (no remove — keep `"backlog"` for historical queries).
4. Return both the new claim's UUID and the updated label list on the original.

Atomicity: best-effort. If step 2 succeeds but step 3 fails, return an error that includes the new resolution claim's UUID so the caller knows what was created. The reconciler (Component 4) will catch and back-fill on its next run.

Implementation: lives in the `epigraph-mcp` server. Calls existing HTTP routes (`POST /api/v1/claims` and `PATCH /api/v1/claims/:id/labels`) rather than touching the DB directly — keeps the audit trail consistent with normal claim submission.

### Component 3: One-shot cleanup script

**Goal:** retroactively retire the existing ~100 stale backlog items wherever a resolution already exists.

Algorithm:

1. Pull all claims with `labels @> ["backlog"]` (page through; `query_claims_by_label` caps at 100, so use offset/limit until exhausted).
2. Pull all claims with `labels @> ["resolved"]` into memory, indexed by every UUID-shaped substring found in their content.
3. Build a set of "supersedes-retired" originals: every claim with `is_current = false` AND a `supersedes` value, OR every claim whose UUID appears as the `supersedes` target of another claim. (Requires Component 1 to be deployed for the MCP path, OR direct DB read for the cleanup — script may use direct DB read since it's one-shot and operator-supervised.)
4. For each backlog item:
   - If already has `"resolved"` label → skip (idempotent).
   - If matched by exactly one resolution claim AND no other downstream conflict → bucket as `auto-patch`.
   - If matched by `supersedes` retirement → bucket as `auto-patch` (and note the superseding UUID in the report).
   - If matched by multiple resolution claims (e.g. `1c31a529` with both `4485beac` "complete" and `6d28afba` "NOT-A-BUG") → bucket as `needs-review`, do NOT auto-patch.
   - If no match found → bucket as `still-open`.
5. Execute the `auto-patch` bucket: PATCH labels via `PATCH /api/v1/claims/:id/labels` with `add: ["resolved"]`.
6. Write a report file `backlog-cleanup-report-2026-05-16.md` listing all three buckets with UUIDs, resolution claim UUIDs, and content summaries for the `needs-review` set.

Safety:

- Dry-run mode by default (`--apply` flag required to actually PATCH).
- Report file written even in dry-run.
- Each PATCH is a separate HTTP call, so partial failure leaves the rest correct.

Location: `scripts/cleanup_backlog_labels.py` in the epigraph repo.

### Component 4: Recurring reconciler

**Goal:** catch future drift if any agent files a free-text "Resolves <UUID>" claim without using `resolve_backlog_item`.

Schedule: daily, low-priority.

Algorithm:

1. Pull `[backlog]` items that are NOT `[resolved]` and are NOT `is_current=false`.
2. For each, search recent claims (created in the past 7 days) for content matching `"Resolves <UUID>"` or `"Supersedes <UUID>"` with that backlog UUID (full or 8-char prefix).
3. Unambiguous match (exactly one resolution claim, no conflicting reframes) → PATCH the original's labels with `add: ["resolved"]`.
4. Ambiguous → record to a `reconciler-needs-review.log` file (not auto-actioned), notify on next operator scan.

Implementation: a new claim-as-workflow stored in EpiGraph + a small Python runner triggered by the existing scheduled-task harness. The workflow content is a sequence of MCP tool calls; the runner is a thin script wrapping it.

Location: workflow stored in EpiGraph via `store_workflow`; runner at `scripts/reconcile_backlog_labels.py`; scheduled-task wiring follows the existing convention (see `epiclaw-host` scheduler config — exact path resolved in implementation plan).

### Component 5: Convention documentation

**Goal:** prevent future agents from filing the old free-text-only convention.

Updates:

- `/home/jeremy/epigraph/CLAUDE.md`: add a section "Retiring backlog items" explaining the canonical convention and the `resolve_backlog_item` tool. Cite this design doc.
- `/home/jeremy/epiclaw-host/CLAUDE.md` (or wherever the EpiClaw agent prompt lives): same convention note, since EpiClaw is the primary agent that files autonomous backlog claims.
- The convention note also explains the *open-backlog query* — `query_claims_by_label(labels=["backlog"], exclude_labels=["resolved"])` — so agents know how to find live items.

## Data flow

**Filing a backlog item (unchanged):**
```
agent → submit_claim(content="…", labels=["backlog"]) → claim row in DB
```

**Resolving a backlog item (new convention):**
```
agent → resolve_backlog_item(original_id, "the bug was fixed in PR #X")
  → POST /api/v1/claims (new resolution claim, labels=["resolved"], content="Resolves <id>: …")
  → PATCH /api/v1/claims/<original_id>/labels (add: ["resolved"])
  → returns { resolution_claim_id, original_labels }
```

**Querying open backlog (new):**
```
agent → query_claims_by_label(labels=["backlog"], exclude_labels=["resolved"], current_only=true)
  → returns claims that are still actually open
```

**Reconciliation (recurring):**
```
scheduler fires daily → reconcile_backlog_labels.py
  → query open backlog
  → for each, search recent claims for "Resolves <id>" prose
  → unambiguous matches: PATCH labels
  → ambiguous: log for human review
```

## Error handling

- **`resolve_backlog_item` partial failure** (claim created, label PATCH failed): return error with the new claim UUID; reconciler will fix on next run.
- **Cleanup script HTTP failures**: per-claim try/except; failures logged to the report; rest of the batch continues.
- **`query_claims_by_label` invalid params**: validate `exclude_labels` is a list of strings; reject otherwise. No silent fallback.
- **Reconciler ambiguity**: never auto-PATCH when multiple resolution claims reference the same backlog UUID with conflicting narratives. Always require human triage for these — they're the cases where the resolution itself is contested.

## Testing

- **MCP read-side**: unit tests that `exclude_labels` correctly filters; `current_only` correctly filters; `is_current`/`supersedes`/`labels` appear in output. Integration test against a seeded DB with mixed live/retired claims.
- **`resolve_backlog_item`**: unit test the happy path; test the partial-failure case (mock the PATCH to fail and assert the resolution claim UUID is returned in the error).
- **Cleanup script**: dry-run against the live DB first, verify the `needs-review` bucket matches expectation (esp. `1c31a529`), then `--apply`.
- **Reconciler**: seed a test DB with a backlog claim and a free-text "Resolves <UUID>" resolution claim, run reconciler, assert the label was patched.

## Open questions resolved during brainstorming

- **Q: keep `"backlog"` after resolution or remove it?** A: keep. Lets the historical "ever was backlog" query still work; the open query negates `"resolved"`.
- **Q: should `supersedes`/`is_current` become the primary signal?** A: no. Those carry strong epistemic semantics (claim replacement). Status tracking is operational and belongs on labels. Hybrid is acceptable for legacy retirements (cleanup pass honours both).
- **Q: scope?** A: C + D — convention + tooling fix (forward-going) PLUS expose `supersedes`/`is_current`/`labels` on the read side PLUS one-shot cleanup of existing stale items.

## Out of scope

- UI for the backlog (this is a data-hygiene fix, not a product feature).
- Automating *which* items get the `"backlog"` label in the first place.
- Migrating the existing `supersedes`-based retirements to the label convention (they continue to work via the cleanup pass; future retirements use the new convention).
- Changing the `claims` table schema.

## Acceptance criteria

1. `mcp__epigraph__query_claims_by_label(labels=["backlog"], exclude_labels=["resolved"])` returns a meaningfully shorter list than the current 100-item query.
2. `mcp__epigraph__get_claim` returns `labels`, `is_current`, and `supersedes` for every claim.
3. `mcp__epigraph__resolve_backlog_item` exists and, in one call, creates a resolution claim and PATCHes the original's labels.
4. The cleanup script has been run once with `--apply` and the cleanup report is committed to the repo for audit.
5. The reconciler runs daily and its log file is empty (or contains only `needs-review` entries) for at least one week.
6. Convention docs are merged to both CLAUDE.md files.
