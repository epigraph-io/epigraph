# `claims_*_bounds` write-contract clamp (Spec 1)

**Date:** 2026-05-27
**Status:** Design — awaiting review
**Author:** Jeremy Barton (with Claude)
**Closes:** [#139](https://github.com/epigraph-io/epigraph/issues/139)

## Problem

The Postgres CHECK constraint `claims_plausibility_bounds` (`migrations/001_initial_schema.sql:631`) requires `plausibility` to lie in `[0.0, 1.0]`. There is a matching `claims_belief_bounds` constraint on `belief`. Both can be tripped by post-combine values that drift one ULP above 1.0 (or, in pathological combine sequences, by raw values that exceed 1.0 outright).

PR #149 (2026-04-?) added defensive `.clamp(0.0, 1.0)` calls to `epigraph_ds::measures::{belief, plausibility}` to absorb the most common drift. `MassFunctionRepository::update_claim_belief` (`crates/epigraph-db/src/repos/mass_function.rs:282`) clamps again on the write side.

But the write contract is enforced inconsistently. At least one BP write path — `crates/epigraph-api/src/routes/computation.rs:621` — writes raw `bel`, `pl` straight from `result.updated_intervals` without clamping. Any future write site added without this discipline reintroduces the bug.

Issue #139 reports that `update_with_evidence` violates `claims_plausibility_bounds` when a claim is at `plausibility=1.0` and additional evidence is submitted. The issue body guesses at the cause; the audit so far suggests the failure may surface through a write path other than the `auto_wire_ds_update → update_claim_belief` route the issue traces. Reproducing first will pin down the actual culprit; sweeping every write site will prevent the next instance.

## Goals

1. Deterministic reproduction of the #139 failure mode against `epigraph_db_repo_test`.
2. Single source of truth for the `claims_*_bounds` write contract — one helper, used by every write site that touches `belief`, `plausibility`, `pignistic_prob`, `mass_on_empty`, or `mass_on_missing`.
3. Every existing `UPDATE claims SET ...` site that writes those columns is routed through the helper.
4. Per-site unit tests assert that drifted inputs produce in-bounds outputs.
5. An end-to-end regression test that reproduces the original `update_with_evidence` failure and now passes.

**Non-goals.** Changing how belief / plausibility / pignistic probability are *computed*. The combine logic, discounting, and BP message-passing are out of scope — this spec is purely about the write contract.

## Approach

### Step 1 — Reproduce

Add a failing integration test in `crates/epigraph-mcp/tests/` (or `crates/epigraph-api/tests/` if the actual culprit is HTTP-side). The test:

1. Seeds a claim in `epigraph_db_repo_test` with `plausibility = 1.0, belief = 0.4, pignistic_prob = 0.4`.
2. Calls `update_with_evidence` (via the MCP tool entry point) with supporting evidence and a non-trivial strength.
3. Asserts `Ok(_)` from the call.

If the test fails on the current main branch with `claims_plausibility_bounds`, the bug is reproduced. If it passes, drive the input toward known drift cases (multi-evidence sequences where the BBA sum drifts above 1.0) until reproduction is achieved, and note the actual surfacing code path in this spec before continuing.

### Step 2 — Centralized helper

Add to `crates/epigraph-ds/src/measures.rs`:

```rust
/// Clamp the five belief-measure fields written to `claims` to `[0.0, 1.0]`.
///
/// Three of the five — `belief`, `plausibility`, `mass_on_empty` — are enforced
/// at the DB level by `claims_belief_bounds`, `claims_plausibility_bounds`, and
/// `claims_mass_empty_bounds` respectively (see `migrations/001_initial_schema.sql`).
/// `pignistic_prob` and `mass_on_missing` have no CHECK constraint today but are
/// clamped defensively so future constraints can be added without code changes.
///
/// All callers that issue
/// `UPDATE claims SET belief|plausibility|pignistic_prob|mass_on_empty|mass_on_missing ...`
/// MUST route their values through this helper.
#[must_use]
pub fn clamp_claim_belief_measures(
    belief: f64,
    plausibility: f64,
    pignistic_prob: Option<f64>,
    mass_on_empty: f64,
    mass_on_missing: f64,
) -> (f64, f64, Option<f64>, f64, f64) {
    (
        belief.clamp(0.0, 1.0),
        plausibility.clamp(0.0, 1.0),
        pignistic_prob.map(|p| p.clamp(0.0, 1.0)),
        mass_on_empty.clamp(0.0, 1.0),
        mass_on_missing.clamp(0.0, 1.0),
    )
}
```

Constraint names confirmed against `migrations/001_initial_schema.sql`:
`claims_belief_bounds` (line 627), `claims_mass_empty_bounds` (630),
`claims_plausibility_bounds` (631), `claims_truth_value_bounds` (634). No CHECK
exists for `pignistic_prob` or `mass_on_missing` as of 2026-05-27. The helper
clamps all five regardless so a future `ALTER TABLE ... ADD CONSTRAINT ...
pignistic_bounds` lands without surfacing a new bug.

### Step 3 — Audit and sweep

Grep `UPDATE claims SET` across the workspace. Every site that writes any of the five measures is migrated to call the helper before binding. After the sweep:

- `crates/epigraph-db/src/repos/mass_function.rs:282` (inline-clamping today) routes through the helper, dropping the per-field `.clamp` calls.
- `crates/epigraph-api/src/routes/computation.rs:621` routes through the helper.
- Any third site grep turns up routes through the helper.

Plan-stage step: produce the full audit list inline in the plan; this spec does not enumerate beyond the two confirmed.

### Step 4 — Tests

Three tiers, each adversarial enough to satisfy the council-of-critics rule:

1. **Helper unit tests** in `crates/epigraph-ds/src/measures.rs` — drifted-input cases (`1.0 + 1ULP`, `-0.0`, `Option::None`, `1.5`, `-0.5`) → asserts clamped outputs.
2. **Per-site write-path tests.** For each repo / route that writes the five fields, a test that constructs a `MassFunction` whose combine produces drift above 1.0, calls the write path, and asserts the persisted row's `plausibility = 1.0` exactly (not 1.0000000000000002, not 0.97).
3. **End-to-end reproduction test** — the Step 1 test, now passing. This is the "this is the bug from the issue" guardrail.

### Step 5 — Constraint-name doc comment

The helper's doc comment names every constraint it satisfies, with a `// see migration NNN` pointer. Future engineers adding a sixth belief-measure column or a sixth write site can grep for the helper name and find both the contract and the constraint list in one place.

## Out of scope

- Changes to `epigraph-ds` combine logic, discounting, or BP message-passing.
- New belief-measure columns or new CHECK constraints.
- Refactoring the `claim_from_row` read path or widening its signature (forbidden by `CLAUDE.md`).
- Migration to drop or modify the existing `claims_*_bounds` constraints.

## Acceptance

- [ ] Reproduction test exists and fails on current `main`.
- [ ] `clamp_claim_belief_measures` exists in `epigraph-ds` with unit tests covering drift, negative, out-of-range, and `None` cases.
- [ ] Every `UPDATE claims SET ... {belief|plausibility|pignistic_prob|mass_on_empty|mass_on_missing}` site in the workspace calls the helper.
- [ ] Per-site write-path tests assert in-bounds persistence under drifted input.
- [ ] Reproduction test passes after the fix.
- [ ] `cargo sqlx prepare --workspace -- --tests` is re-run if any `query!` macros are touched (per `CLAUDE.md`).
- [ ] `cargo fmt`, `cargo clippy --workspace`, `cargo test --workspace` clean against `epigraph_db_repo_test`.

## Related

- PR #149 — `belief` / `plausibility` clamp in `measures.rs`
- `crates/epigraph-ds/tests/order_independence_smoke.rs` — drift regression for the *compute* side
- `feedback_pignistic_not_bayesian.md` — `pignistic_prob` (BetP) is the canonical decision measure; clamping it matters for downstream ordering
- `feedback_council_of_critics.md` — adversarial-test rule justifies the per-site drift test rather than a "no error thrown" smoke
