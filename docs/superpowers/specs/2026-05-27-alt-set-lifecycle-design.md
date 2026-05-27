# Alt-Set Lifecycle Labels (Dev-Pathway Spec A.1 + A.3)

**Date:** 2026-05-27
**Status:** Design — awaiting review
**Author:** Jeremy Barton (with Claude)
**Depends on:** PR #187 (`alternative_of` + max-Pl + `suggest_alternative_sets`)

## Problem

The `alternative_of` edge (#140) and max-Pl combine (#141) give us the *math* for mutually-exclusive supporters of a shared target. They do not give us the *operational lifecycle* a developmental-pathway workflow needs.

Two concrete use cases drive this spec:

1. **Rival hypothesis resolution.** Multiple competing explanations of an observation are held, then new evidence resolves them. Today: alt-set edges persist as historical record; new evidence shifts BetPs. Already supported.
2. **Developmental pathway planning.** Multiple candidate pathways are held during planning, one is chosen and implemented, others are deferred or rejected. Later, a new pathway may emerge that beats the previously-chosen one, requiring reopening. Today: no operational state on alt-set members — readers cannot ask "which pathway did we pick?" or "what was rejected when?". Reopening a decision is invisible.

Use case 1 is content with the current primitive. Use case 2 needs state, but does not yet justify a full Decision-as-claim primitive or a goal-decomposition tree. This spec adds the minimum that makes pathway planning workable.

## Goals

1. Operators (and agents) can mark alt-set members as `alt-chosen`, `alt-deferred`, or `alt-rejected` with no schema change.
2. Lifecycle state is queryable in one shot — "what alt-set decisions have been made" returns in a single query.
3. Optional per-member metadata (timestamp, scorer, multi-dimensional score) lands in `properties.alt_state_meta` without breaking the label-only contract.
4. The candidate-finder MCP tool drops settled alt-set pairs by default and can be flipped to surface reconsideration candidates (rejected member with new higher-BetP rival).
5. Reopening a decision is one label PATCH; no audit trail is added in v1 (file a resolution claim if history matters — existing convention).
6. CDST belief semantics are unchanged. Lifecycle is *operational*, not *epistemic*.

**Non-goals.**

- Decision-as-claim primitive (option B). Filed as backlog with explicit promotion triggers.
- Goal-decomposition tree primitive (option C). Filed as backlog.
- Multi-dimensional scoring as a first-class shape. Lives inside `properties.alt_state_meta` as opaque JSONB; structured scoring is a (B) follow-up.
- Per-alt-set state (a claim with `alt-chosen` in set X but `alt-rejected` in set Y). Documented limitation; resolution is (B)'s scope.
- Engine-side filtering by lifecycle state (e.g., "only combine `alt-chosen`"). Belief reasoning stays separate from operational decisions.

## Architecture

### Labels (A.1)

Three reserved labels on claims that are members of `alternative_of` edges:

- `alt-chosen` — operator/agent has committed to this member as the current choice.
- `alt-rejected` — explicitly ruled out; preserved as graph history.
- `alt-deferred` — held but not implementable yet (resource, prereq, timing).
- (no label) — default "active" state; still in play.

Labels are added/removed via the existing `PATCH /api/v1/claims/:id/labels` route with `add`/`remove` arrays. Authorization mirrors the existing label-PATCH path: claim owner or `claims:admin`.

No new MCP tool, no new HTTP route. The mutation surface is intentionally trivial.

### Properties metadata (A.3)

Optional `properties.alt_state_meta` JSONB on the same claim:

```json
{
  "alt_state_meta": {
    "state": "chosen",
    "transitioned_at": "2026-05-27T20:30:00Z",
    "transitioned_by": "agent_uuid_or_user_email",
    "rationale": "Cheaper to fab; meets all requirements within 2x cost budget.",
    "score": {
      "cost": 0.7,
      "time": 0.5,
      "risk": 0.3,
      "betp": 0.84
    }
  }
}
```

All sub-fields optional. The `state` field is denormalized from the label (cardinal source of truth is still the label) — useful for one-shot reads. `score` is unstructured JSONB so domain-specific scoring schemes can land without engine changes.

Metadata is set via the existing `PATCH /api/v1/claims/:id` route (`patch_claim` at `crates/epigraph-api/src/routes/claims.rs:1321`), which already accepts `properties` updates.

### `alt_set_decisions` view

A read-side SQL view joins `alternative_set` (from migration 042) with claim labels/properties:

```sql
CREATE VIEW alt_set_decisions AS
SELECT
    a.claim_id,
    a.alt_members,
    CASE
        WHEN c.labels @> ARRAY['alt-chosen']   THEN 'chosen'
        WHEN c.labels @> ARRAY['alt-rejected'] THEN 'rejected'
        WHEN c.labels @> ARRAY['alt-deferred'] THEN 'deferred'
        ELSE 'active'
    END AS alt_state,
    c.properties->'alt_state_meta' AS alt_state_meta,
    c.pignistic_prob
FROM alternative_set a
JOIN claims c ON c.id = a.claim_id;
```

Operators query `WHERE alt_state = 'chosen'` to find current picks; agents query `WHERE alt_state = 'active'` to find pending decisions.

### `suggest_alternative_sets` MCP tool extension

Two new optional input params on the existing tool from PR #187:

- `exclude_settled: bool` (default `true`) — drop pairs where either member is `alt-chosen` or `alt-rejected`. Default behavior changes from current to filtered; existing callers that want everything pass `exclude_settled=false`.
- `surface_reconsiderations: bool` (default `false`) — when `true`, surface pairs where one member is `alt-rejected` and the *other* member has BetP at least `min_pair_strength` higher than the rejected member's BetP. Returns the rejected pair as a "reconsider this" candidate.

The two flags compose: with `exclude_settled=true` and `surface_reconsiderations=true`, settled `alt-chosen` pairs are dropped but rejected-with-better-rival pairs are surfaced. The result shape adds `reason` strings like `"alt-rejected member has BetP 0.42; rival has BetP 0.78"`.

### Invariants

- **At most one `alt-chosen` per equivalence class** (soft). Not enforced at DB level. Soft check: the candidate-finder skips classes with an existing `alt-chosen`; a future v2 invariant tool can scan for violations.
- **State is per-claim, not per-set.** A claim in two transitively-collapsed alt-sets shares ONE state. Documented limitation; (B)'s problem to fix.
- **Label transitions are atomic.** PATCH `/labels` is already atomic; no read-modify-write hazard.
- **No state machine enforcement.** Any label can transition to any other (active → chosen → rejected → chosen) at the operator's discretion. v2 may add a transition validator.

## Testing

### Label-only

- PATCH `/labels` adds `alt-chosen` to an alt-set member; subsequent GET returns the label.
- PATCH removes `alt-chosen`; GET no longer returns it.
- `alternative_set` view continues to return correct equivalence classes regardless of any member's labels (state on claim, not edge).

### View

- `alt_set_decisions` returns `alt_state = 'chosen'` for a labelled member; `'active'` for unlabelled.
- A 3-cycle alt-set with one member labelled `alt-chosen` and another `alt-rejected` shows each row's state correctly.
- A member in TWO transitively-collapsed alt-sets shows the same `alt_state` in both contexts (documented limitation).

### Properties metadata

- Setting `properties.alt_state_meta = {state, transitioned_at, score}` round-trips through the view's `alt_state_meta` column.
- A null `alt_state_meta` returns SQL NULL (not an empty object).

### Tool extensions

- `suggest_alternative_sets(exclude_settled=true)` drops candidate pairs with any `alt-chosen` or `alt-rejected` member.
- `suggest_alternative_sets(exclude_settled=false)` returns the pre-change behavior — explicit opt-out.
- `surface_reconsiderations=true` returns pairs where rejected member's BetP is lower than rival's by ≥ `min_pair_strength`.
- `reason` string in the surfaced pair includes BOTH BetPs for operator review.

### Engine no-regression

- The existing alt-set CDST integration test from PR #187 (BetP shifts 0.970 → 0.911 with alt-set wiring) still passes with any combination of `alt-chosen` / `alt-rejected` labels applied to members. Belief is label-agnostic.

## Backlog filings

This spec ships A.1 + A.3 only. Two follow-ons are filed as `["backlog", "alt-set-extension"]` claims via `mcp__epigraph__memorize` (or `submit_claim` with explicit labels):

### (B) Decision-as-claim primitive

**Trigger to develop:** file when ANY of the following becomes true:

- Three or more reopens occur on a single alt-set (label thrashing — `alt-rejected` flipped back to `alt-chosen` repeatedly). Operators want queryable decision history.
- Multi-dimensional scoring (cost / time / risk independent from BetP) becomes operationally needed for ranking. `properties.alt_state_meta.score` becomes overloaded.
- A single claim needs to be `alt-chosen` in one alt-set and `alt-rejected` in another (per-set state). The shared-state limitation breaks operators.

**Sketch:** add a `Decision` claim (label `["decision"]`) representing the choice point. Edges `decides_among → claim` from Decision to each alt-set member, with edge properties `{chosen, rejected_at, deferred_at, score}`. Reopen = new edge to a new candidate; old `chosen=true` becomes `chosen=false` with `superseded_at`.

### (C) Goal-decomposition tree primitive

**Trigger to develop:** file when ANY of the following becomes true:

- A WRHQ / Praxis / EpiClaw consumer requires multi-step pathway planning with sub-step decomposition AND alt-set lifecycle on sub-pathways.
- A single Goal claim has > 5 candidate pathways each with own `decomposes_to` chains (the alt-set across pathways gets unwieldy without a wrapper).
- The existing hierarchical-workflow primitive (`store_workflow`, `add_step`) gets requested to support alternative branches at any step.

**Sketch:** add a `goal` label. `pathway` claims `supports → Goal` with `alternative_of` linking competing pathways. Each pathway has its own `decomposes_to` sub-step chain. Lifecycle state (A.1 labels) applies to the pathway claim; the sub-steps inherit operational state from their parent pathway. Combines with (B) by making the Goal the implicit decision-point claim.

Both backlog items reference this spec for context.

## Acceptance

- [ ] Three reserved labels (`alt-chosen`, `alt-rejected`, `alt-deferred`) are usable without code changes (verified — EpiGraph labels are free-form `text[]` with no allow-list).
- [ ] `alt_set_decisions` view lands in migration `043`. PRs #185 (041) and #187 (042) are merged to `origin/main` as of 2026-05-27; if another migration lands first, renumber per the existing `chore(db): renumber migration NN→MM` pattern (PRs #177, #178).
- [ ] `suggest_alternative_sets` accepts `exclude_settled` and `surface_reconsiderations` params with documented defaults.
- [ ] Tests above all pass against `epigraph_db_repo_test`.
- [ ] Backlog items (B) and (C) filed via `mcp__epigraph__memorize` with the triggers above, labelled `["backlog", "alt-set-extension"]`.
- [ ] CDST engine tests from PR #187 unchanged and still pass.
- [ ] `cargo fmt --check`, `cargo clippy --workspace --lib -- -D warnings` clean.

## Out of scope

- Decision history table (audit log of label transitions). File-as-resolution-claim suffices for v1.
- Engine-side belief filtering by lifecycle state.
- Auto-promotion of suggested reconsiderations to explicit edges.
- A state-transition validator (e.g., "rejected cannot go directly to chosen without first being active"). v1 trusts the operator.

## Related

- PR #187 — `alternative_of` edge type, `alternative_set` view, `combine_alternative_set`, `suggest_alternative_sets` tool. This spec extends.
- `crates/epigraph-api/src/routes/hypothesis.rs:64` — `hypothesis_status` precedent (properties JSONB for single-string status).
- `feedback_pignistic_not_bayesian.md` — BetP is the canonical decision measure; multi-dim scoring in `properties.alt_state_meta.score` keeps BetP authoritative for belief-based ranking.
- `feedback_dedup_admin_only.md` — labels-as-state precedent (`["resolved"]` for backlog retirement).
