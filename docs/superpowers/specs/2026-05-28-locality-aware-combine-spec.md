# Locality-Aware Combine — Phase 2 Design

**Date:** 2026-05-28
**Status:** Design — awaiting review
**Author:** Jeremy Barton (with Claude)
**Issue:** [#197](https://github.com/epigraph-io/epigraph/issues/197)
**Depends on:** Phase 1a (`feat/mass-functions-locality-tag`, schema + write-path tagging) and Phase 1b (one-shot SQL backfill of `locality_tag`).
**Companion plan:** `docs/superpowers/plans/2026-05-28-locality-tag-schema.md`

## Problem

The plan establishes the goal: stop reading `mass_functions.source_strength` as the per-row reliability discount at combine time, and compute it dynamically from `evidence_type + locality_tag + per-frame factor` instead. Once Phase 1a (forward writes tag) and Phase 1b (legacy rows backfilled) are in production, Phase 2 flips the read side. This spec pins down exactly what changes, what stays, and which migration-compat levers the helper needs.

Two non-obvious constraints emerged from the code investigation and shape the design:

1. The edge_factor write path stores `relationship` (e.g. `"supports"`) in the `evidence_type` column (`crates/epigraph-engine/src/edge_factor.rs::auto_wire_ds_for_edge`, the `store_with_perspective` call at the end of the body, fourth-from-last argument). `get_evidence_type_weight("supports")` falls through every alias and returns the `0.5` unknown-type fallback. A naive helper would silently change every edge-supported BBA's effective reliability from `transmission_factor * locality_factor` (`0.7 * 0.3 = 0.21`) to `0.5 * locality_factor` (`0.5 * 0.3 = 0.15`).
2. The only call sites that actually read `row.source_strength` at combine time are in `crates/epigraph-engine/src/edge_factor.rs::recompute_combined_belief` and `crates/epigraph-mcp/src/tools/ds_auto.rs::auto_wire_ds_update`. The HTTP paths in `routes/belief.rs`, `routes/assess.rs`, and the perspective/community/pignistic combine loops in `routes/belief.rs` operate on BBAs that were already discounted at write time (`combination_method = 'discount'`) and do not read `source_strength` from the row. Phase 2 leaves those paths untouched.

## Goals

1. A single helper, `effective_source_strength(row, frame_id, &calibration)`, is the only function that turns a `MassFunctionRow` into a Shafer reliability discount at combine time.
2. `recompute_combined_belief` (the canonical CDST cascade) and `auto_wire_ds_update` (the MCP auto-wire combine) both call the helper instead of reading `row.source_strength` directly.
3. Recalibration (changing `intra_evidence_locality_factor` in `calibration.toml` or via a per-frame override) flows through to combined belief without any DB rewrite. This is the whole point of Phase 2.
4. The deploy-day state — Phase 1a forward-tags new writes, Phase 1b has populated legacy rows, Phase 2 ships — produces combine outputs that are ≈identical to the pre-Phase-2 numerics for the population the legacy backfill has already discounted, modulo the two cohorts called out in § 5.
5. The `source_strength` column remains on the table as a write-through cache (forward writes keep populating it for back-compat and for the legacy fallback) but is no longer the authority for combine-time reliability.

**Non-goals.**

- Changing the BBA mass shape, transmission factor, or restriction semantics. Phase 2 is read-side only; the math through `restrict_epistemic_*` and `combination::discount(&mf, r)` is unchanged.
- Touching the HTTP belief / assess pre-discount-then-store pattern. Those routes already incorporate locality at write time through their own `discount()` call before `store_with_perspective`; Phase 2 does not need to re-discount them.
- Dropping the `source_strength` column. That stays as a denormalized cache (and as the migration-compat lever for legacy null-`evidence_type` rows) until Phase 3 lands an `evidence_id` FK and we have a primary-data path for both locality and reliability.
- Eliminating the per-frame override read at write time in `auto_wire_ds_for_edge`. Keeping the stored `source_strength` populated by the write path costs us nothing and preserves the audit trail; the helper just stops trusting it for the dynamic-computation cohort.

## Approach

### 1. Inventory of `row.source_strength` read sites

Searched the workspace with `grep -rn "source_strength.unwrap_or"` and `grep -rn "row.source_strength"`. Two read sites at combine time:

- `crates/epigraph-engine/src/edge_factor.rs::recompute_combined_belief` — two reads in the single-BBA and multi-BBA branches:
  ```rust
  let reliability = r.source_strength.unwrap_or(1.0).clamp(0.0, 1.0);     // single-BBA branch
  let reliability = row.source_strength.unwrap_or(1.0).clamp(0.0, 1.0);   // multi-BBA loop
  ```
  Called from `recompute_claim_belief_on_frame`, `recompute_claim_belief_binary`, and directly from the end of `auto_wire_ds_for_edge`. This is the canonical CDST cascade.
- `crates/epigraph-mcp/src/tools/ds_auto.rs::auto_wire_ds_update` — same shape, two reads:
  ```rust
  let reliability = all_rows.first().and_then(|r| r.source_strength).unwrap_or(1.0).clamp(0.0, 1.0); // single-BBA
  let reliability = row.source_strength.unwrap_or(1.0).clamp(0.0, 1.0);                              // multi-BBA loop
  ```
  Called from `submit_ds_evidence`, `update_with_evidence`, and `report_workflow_outcome` MCP tools. This is the auto-wire-update path.

Read sites that are **not** combine-time discounts:

- `crates/epigraph-engine/src/edge_factor.rs::auto_wire_ds_for_edge` writes `source_strength = transmission_factor * locality_factor` into the row via the `store_with_perspective` call near the end of the function. This is a write, not a combine-time read; Phase 2 does not modify it (the column still exists; it just stops being the authoritative read at combine time).
- `crates/epigraph-mcp/src/tools/ds_auto.rs::auto_wire_ds_for_claim` and `auto_wire_ds_update` write `Some(weight)` from the calling tool's evidence-type lookup. Same shape — write side, not in scope.
- `crates/epigraph-engine/tests/intra_source_discount_regression.rs` reads `source_strength` to assert on the written value. Phase 2 changes the test's *interpretation* of `source_strength` (see § 6 below).
- `crates/epigraph-mcp/tests/source_strength_tests.rs` asserts on the write contract. Out of scope for Phase 2.

Paths that have their own combine loops but **do not** read `source_strength`:

- `crates/epigraph-api/src/routes/belief.rs` — the `POST /api/v1/belief/...` handler stores BBAs with `combination_method = "discount"` after pre-discounting via `combination::discount(&raw_mass, request.reliability)`. The combine loop near `combine_multiple(&for_combination, request.conflict_threshold)` filters `combination_method == "discount"` rows and does not re-discount.
- The perspective-scoped and community-scoped combine loops further down in `routes/belief.rs` similarly operate on already-discounted BBAs.
- The pignistic-probability handler near the bottom of `routes/belief.rs` is the same pattern.
- `crates/epigraph-api/src/routes/assess.rs` — `submit_evidence` likewise pre-discounts and stores with `combination_method = "discount"`, then combines on the filtered set without re-discounting.

The task hypothesis that `routes/belief.rs` and `routes/ds_auto.rs` "have their own combine loops" reading `source_strength` is correct only for `ds_auto.rs`. The HTTP belief / assess paths are pre-discount-then-store and need no change in Phase 2.

### 2. Helper signature

The plan sketches the helper. The spec's only refinements are around fallback ordering and the calibration-config parameter shape:

```rust
// crates/epigraph-engine/src/edge_factor.rs (or a new
// crates/epigraph-engine/src/locality.rs if it grows)

pub(crate) fn effective_source_strength(
    row: &MassFunctionRow,
    per_frame_intra_factor: Option<f64>,
    calibration: &CalibrationConfig,
) -> f64 { ... }
```

Inputs:
- `row` — the BBA's persisted state. The helper inspects `row.evidence_type`, `row.locality_tag`, and (for the legacy fallback) `row.source_strength`.
- `per_frame_intra_factor` — pre-loaded by the caller via `FrameRepository::get_intra_evidence_locality_factor(pool, frame_id)`. Pre-loading avoids a DB round-trip per row in a multi-BBA combine.
- `calibration` — pre-loaded `&CalibrationConfig` (already the pattern in `auto_wire_ds_for_edge`, which loads it inline). The caller hoists the load above the combine loop.

Output: `f64`, already in `[0.0, 1.0]` (the helper internally clamps; the existing `.clamp(0.0, 1.0)` at the read site disappears).

Fallback chain (the order matters):

1. **`evidence_type IS NULL` AND `source_strength IS NOT NULL`** → return `row.source_strength.unwrap()` clamped. Pure legacy-compat for the pre-Phase-1a population whose `evidence_type` was never set; the column-as-cache path.
2. **`evidence_type IS NOT NULL`** → `base = calibration.get_evidence_type_weight(row.evidence_type)`. Compose with locality:
   - `locality_tag = "intra"` → `base * per_frame_intra_factor.unwrap_or(calibration.evidence_locality.intra_evidence_locality_factor)`
   - `locality_tag = "cross"` or `"unknown"` or unknown-string → `base`
3. **`evidence_type IS NULL` AND `source_strength IS NULL`** → return `0.5` (the existing `get_evidence_type_weight` fallback for unknown-type lookup). This case is the same all-NULL row the old code hit via `source_strength.unwrap_or(1.0)`; Phase 2 changes it from 1.0 to 0.5 (see § 5 — there should be zero rows in this bucket after Phase 1a + 1b deploy).

Two notes on the helper that are non-obvious from the plan body:

- **The 0.5 unknown-evidence-type sentinel is indistinguishable from a real 0.5 weight.** `circumstantial = 0.4` and `conversational = 0.3` are real values; `0.5` could be a real-weight match for some future calibration key. The helper trusts `get_evidence_type_weight`'s output unconditionally for the "evidence_type is set" branch and relies on (1) above to handle null-`evidence_type` legacy rows. This is the source-strength-as-cache lever and the reason we don't drop the column.
- **Per-frame factor lookup is the caller's responsibility.** Loading the per-frame factor inside `effective_source_strength` would either require passing `pool` (turning the helper async) or duplicating the lookup once per row in a multi-BBA combine. The caller already has `frame_id` and is already async; it does one lookup and passes the `Option<f64>` to every per-row call.

### 3. Call-site changes

Two read-side files change:

**`crates/epigraph-engine/src/edge_factor.rs::recompute_combined_belief`**

Above the combine, load the calibration and per-frame factor once:

```rust
let calibration = crate::calibration::CalibrationConfig::from_workspace_root().ok();
let per_frame_intra = FrameRepository::get_intra_evidence_locality_factor(pool, frame_id)
    .await
    .ok()
    .flatten();
```

Replace both `let reliability = r.source_strength.unwrap_or(1.0).clamp(0.0, 1.0)` reads (in the single-BBA and multi-BBA branches) with calls to `effective_source_strength(r, per_frame_intra, &calibration_or_default)`. If `CalibrationConfig::from_workspace_root()` fails, fall back to a static `CalibrationConfig::default_fallback()` that returns the same 0.3 intra factor and the 0.5 unknown-type weight the existing code uses on its failure paths. Per the doc on `from_workspace_root`, calibration I/O failure is recoverable.

**`crates/epigraph-mcp/src/tools/ds_auto.rs::auto_wire_ds_update`**

This path currently has no `CalibrationConfig` load — it trusts the stored `source_strength`. Phase 2 introduces one. Mirror the `edge_factor.rs` change: hoist the calibration + per-frame factor load above the combine loop, replace the two `row.source_strength.unwrap_or(1.0).clamp` reads with helper calls.

`auto_wire_ds_for_claim` (the single-BBA, pre-combine `discount` call) does NOT need to change. It's discounting the just-built BBA before the very first combine; the value used is `confidence`, not `source_strength`, and the local discount is for the cached BetP only. Phase 2 leaves single-BBA initial-write semantics alone.

No other read sites change. The HTTP belief / assess pre-discount paths stay as they are.

### 4. The edge_factor `evidence_type` vocabulary mismatch

`auto_wire_ds_for_edge` writes `Some(relationship)` (e.g. `"supports"`, `"refutes"`, `"corroborates"`) into `evidence_type` via the final argument of `store_with_perspective`. That string is not a key in `[evidence_type_weights]` or `[evidence_type_aliases]` in `calibration.toml`. Naive Phase 2 helper:

- `get_evidence_type_weight("supports")` → 0.5 fallback
- Composed intra: `0.5 * 0.3 = 0.15` (intra) or `0.5` (cross)
- Stored today by the write path: `transmission_factor * locality_factor = 0.7 * 0.3 = 0.21` (intra) or `0.7` (cross)

Every edge-supported BBA — the 19-supporter regression population, every `supports`/`refutes` BBA written since `feat/locality-aware-discounting` landed — silently changes effective reliability. The "fall back to `source_strength` when `evidence_type IS NULL`" mitigation does not catch this because `evidence_type` is `"supports"`, not NULL.

Three resolution paths, in increasing order of code surface:

1. **Treat the calibration 0.5 unknown-type fallback as the sentinel.** When `get_evidence_type_weight(row.evidence_type)` returns 0.5 *and* the input is not a calibrated 0.5 key (we'd need a `has_evidence_type_weight(key) -> bool` accessor on `CalibrationConfig` to disambiguate), fall back to `row.source_strength` if set. This is the minimum-surface fix and keeps the helper's signature stable; it accepts that "unknown evidence_type → trust source_strength" is the migration-compat axis.
2. **Pre-populate the calibration with relationship aliases.** Add `[evidence_type_aliases]` entries: `supports = "logical"`, `refutes = "logical"`, etc. Lets the helper compute weights from relationships natively. Choice of canonical key per relationship is non-trivial; out of scope for Phase 2, but the table to do this lives in one TOML file.
3. **Change the edge_factor write to store a calibrated `evidence_type`** instead of the raw relationship. Requires re-running history on the population edge_factor has already written, plus a downstream decision about what evidence_type a `supports` edge actually represents.

The spec recommends path (1) as the Phase 2 fix and files (2)/(3) as follow-ups. Path (1) means the helper's fallback chain becomes:

1. `evidence_type IS NULL` OR `get_evidence_type_weight(evidence_type) == FALLBACK_SENTINEL` (key absent from both `evidence_type_weights` and `evidence_type_aliases`) → if `source_strength` is set, return it; else return 0.5.
2. Otherwise → `base * locality_factor` as in § 2.

This requires a new `CalibrationConfig::evidence_type_weight_present(key) -> bool` accessor. Trivial. Without it the helper cannot distinguish a real 0.5 calibration entry from the unknown-type fallback.

### 5. Backwards-compatibility analysis

For each combine-time read site, walking the deploy-day population (Phase 1a forward-writes already tagging, Phase 1b legacy rows backfilled, Phase 2 just shipped):

| cohort | `evidence_type` | `locality_tag` | helper output | stored `source_strength` | delta |
|---|---|---|---|---|---|
| Phase 1a forward writes from edge_factor (intra) | `"supports"` etc. | `"intra"` | via § 4 path (1): `source_strength` | `transmission * 0.3` | 0 |
| Phase 1a forward writes from edge_factor (cross) | `"supports"` etc. | `"cross"` | via § 4 path (1): `source_strength` | `transmission * 1.0` | 0 |
| Phase 1a forward writes from auto_wire_ds_update | SciFact key (`"empirical"`, `"logical"`, …) | `"unknown"` (per plan: ds_auto callsites have no locality context) | `weight * 1.0` | `weight` | ≈0 |
| Phase 1b backfill cohort (5202ded population, evidence_type populated, locality intra) | SciFact key | `"intra"` | `weight * 0.3` | `weight` (post-5202ded), un-composed | small negative shift on intra rows that had not yet been composed |
| Phase 1b backfill cohort (locality cross) | SciFact key | `"cross"` | `weight * 1.0` | `weight` | 0 |
| Phase 1b backfill cohort (locality unknown — no evidence row) | NULL | `"unknown"` | via § 2 step (1): `source_strength` | 0.3 (conversational backfill) | 0 |
| Pre-5202ded legacy (both NULL) | NULL | `"unknown"` | via § 2 step (3): 0.5 | NULL | shifts from `unwrap_or(1.0) = 1.0` to 0.5 |

The last row is the problematic case the plan flags. It should be empty after Phase 1b's `UPDATE … SET locality_tag = ...` runs against the 5202ded-populated `source_strength` column, *and* once the 5202ded backfill itself is verified to have populated `evidence_type` along with `source_strength`. **If 5202ded only populated `source_strength`**, this cohort is non-empty and Phase 2 shifts those rows from `1.0` (no discount) to `0.5` (the unknown-evidence-type fallback). That's a per-row reliability change; on a hub claim with multiple such BBAs it could shift combined BetP by 5-15 percentage points.

Verification step before Phase 2 deploy (operator pre-flight):

```sql
SELECT COUNT(*) FROM mass_functions
 WHERE evidence_type IS NULL
   AND source_strength IS NOT NULL;
-- Expected: 0 (5202ded should have populated both). If non-zero, investigate.
```

If non-zero, the § 2 step (1) legacy fallback catches them: `evidence_type IS NULL` AND `source_strength IS NOT NULL` → return `source_strength`. Delta is zero.

Net: with the § 2 step (1) and § 4 path (1) fallbacks, every row the deploy-day population can present has delta ≈ 0, modulo the small intra-shift the Phase 1b backfill is *intended* to produce on rows that hadn't been composed yet.

### 6. Test plan

Tests added or modified in three crates:

**`crates/epigraph-engine` (new file `tests/effective_source_strength_unit.rs`)**

Pure-unit tests of the helper, no DB. Synthetic `MassFunctionRow` instances:

- `evidence_type = Some("empirical")`, `locality_tag = "intra"`, `source_strength = Some(1.0)`, per-frame factor `None` → `1.0 * 0.3 = 0.3`.
- `evidence_type = Some("empirical")`, `locality_tag = "intra"`, per-frame factor `Some(0.5)` → `1.0 * 0.5 = 0.5`. **Critical recalibration test: changing the per-frame factor flows through without DB rewrite.**
- `evidence_type = Some("empirical")`, `locality_tag = "cross"`, any factor → `1.0`.
- `evidence_type = Some("conversational")`, `locality_tag = "unknown"`, any factor → `0.3`.
- `evidence_type = Some("supports")` (unknown-key), `source_strength = Some(0.21)` → § 4 path (1) returns 0.21.
- `evidence_type = None`, `source_strength = Some(0.85)` → § 2 step (1) returns 0.85.
- `evidence_type = None`, `source_strength = None` → § 2 step (3) returns 0.5.
- `evidence_type = Some("empirical")`, `locality_tag = "intra_self_cite"` (forward-compat tag value) → cross behavior (`1.0`). Documents that the helper treats any non-`"intra"` string as cross.

**`crates/epigraph-engine/tests/intra_source_discount_regression.rs` (extend)**

The existing `intra_source_19_supporters_betp_in_band` and `cross_source_19_supporters_keeps_high_betp` tests check that the *stored* `source_strength` lies in expected bands. Phase 2 changes the semantics of `source_strength` from "the value actually used at combine" to "a write-through cache that may or may not match the helper's output." The existing assertions on `source_strength` ranges (lines around 250 and 339) become assertions on the *write-side cache*, which is still populated, so they should continue to pass. **No change** to those assertions; they document the write contract, not the read.

A new assertion is added per test: after `auto_wire_ds_for_edge` returns, the combined BetP on the target is in the expected band ([0.70, 0.85] for intra, > 0.9 for cross). That assertion already exists. The new content is a *recompute-after-recalibration* assertion: change `intra_evidence_locality_factor` via `FrameRepository::set_property`, call `recompute_claim_belief_binary` on the target, and confirm BetP shifts to the new band. This is the canary that Phase 2 actually does what it's supposed to.

**`crates/epigraph-engine/tests/intra_source_discount_regression.rs::per_frame_locality_factor_override_applied` (extend, lines 374-487)**

This test's *documented invariant* — "Per-frame factor is read at write time, not stored on the BBA, so a later override doesn't retroactively change historical rows — backfill script's job" (lines 472-476) — is exactly the invariant Phase 2 inverts. Mechanically the `assert!(primer_ss < 0.30, …)` at the end still passes (we don't rewrite the stored cache). The comment is now wrong.

Phase 2 update: keep the existing `primer_ss < 0.30` write-cache assertion, **rewrite the comment** to say "the stored `source_strength` is a write-through cache; the helper at combine time reads `locality_tag` + per-frame factor and may diverge from the cache." Then add new combine-time assertions:

- After the per-frame override is set and a fresh edge is wired, call `recompute_claim_belief_binary` on the target.
- Read the target's `claims.pignistic_prob`. It should reflect the override-driven combine (primer + override-affected supporter, both intra, both now using the 0.9 factor), not the original write-time-frozen mix.

This is the test that confirms Phase 2 actually flows recalibration through. Without it, Phase 2 ships green but the per-frame override is dead code at combine time.

**`crates/epigraph-mcp/tests` (new test in `auto_wire_update_locality_tag.rs` or extension of `source_strength_tests.rs`)**

Combined-belief assertion through the MCP auto-wire-update path: submit two pieces of evidence on a claim, both intra-source, then change the per-frame factor and call `update_with_evidence` again. The cached BetP after the third call should reflect all three BBAs combined under the new factor, not the original.

This is the equivalent of the engine recalibration test, but exercising the `ds_auto.rs::auto_wire_ds_update` call site of the helper.

**`crates/epigraph-db` (no changes)**

The repo layer is untouched. The helper lives in `epigraph-engine`. The `MassFunctionRow` struct already has `evidence_type` and (after Phase 1a) `locality_tag`.

**Regression scope on existing tests**

- `crates/epigraph-mcp/tests/source_strength_tests.rs::auto_wire_ds_update_stores_weight_as_source_strength` — asserts on the write side (`stored.0 == weight`). Phase 2 does not change the write path; still passes.
- `crates/epigraph-api/tests/bp_apply_plausibility_bounds.rs` — seeds `source_strength = 0.95` and `evidence_type = 'empirical'` directly via SQL. Under Phase 2 the combine path computes `effective_source_strength(empirical, unknown) = 1.0 * 1.0 = 1.0`, not 0.95. **This test's drift behavior changes.** Either update the seed values to use `source_strength = 1.0` (the new effective) or use a different `evidence_type` weight that yields 0.95.
- `crates/epigraph-db/src/repos/mass_function.rs` unit tests (`source_strength: Some(0.9)` round-trip at line 650) — assert on storage, not combine. Unchanged.

### 7. Production rollout sequencing

Operator must follow this order. Phase 2 is not safe to deploy before Phase 1b:

1. **Phase 1a merges + deploys.** Migration 045 lands. New writes from `wire_evidential_edge_factor` tag `locality_tag = "intra"`/`"cross"`; ds_auto / API / CLI tags `"unknown"`. Existing rows default `"unknown"`.
2. **Phase 1b SQL runs against production.** The plan's UPDATE statements populate `locality_tag` on the 279 894 historical rows. Validation queries (per plan § 1b) confirm counts: ~98 836 intra, ~22 612 cross, ~158 446 unknown.
3. **Pre-Phase-2 verification SQL** (operator one-shot):
   ```sql
   -- Should be empty after 5202ded backfill + Phase 1b
   SELECT COUNT(*) FROM mass_functions
    WHERE evidence_type IS NULL AND source_strength IS NULL;
   SELECT COUNT(*) FROM mass_functions
    WHERE locality_tag = 'unknown' AND evidence_type IS NULL AND source_strength IS NOT NULL;
   ```
   The second count is the cohort that will hit the § 2 step (1) legacy fallback; its size determines how many rows skip the dynamic computation. If acceptable, deploy.
4. **Phase 2 deploys.** The combine path switches to `effective_source_strength`. Forward writes continue populating `source_strength` (cache) and `locality_tag` (read authority).
5. **Once Phase 2 is stable**, retire `scripts/backfill_intra_source_evidence_discount.py` as a numeric mutator. The plan suggests rewriting it as a tag-writer (`UPDATE mass_functions SET locality_tag = 'intra' WHERE …`) but that work is *already done* by Phase 1b for the historical population; future intra-source rows are tagged forward by `wire_evidential_edge_factor` at write time. The script is dead. File a backlog claim to delete it once we've confirmed no operator playbook references it.

Operator-facing acceptance gate: do not deploy Phase 2 until Phase 1b SQL has run and the verification counts in step (3) are confirmed.

## Open questions

1. **Helper module location.** Spec proposes putting `effective_source_strength` in `crates/epigraph-engine/src/edge_factor.rs` initially (where its only two callers live, transitively). If a Phase 3 `evidence_id` FK path adds a third caller, factor out to `crates/epigraph-engine/src/locality.rs`. Confirm location preference.
2. **CalibrationConfig load failure behavior.** `from_workspace_root()` returns `Result<_, CalibrationError>`. Existing code in `edge_factor.rs` swallows the error with `.ok()` and falls back to a hardcoded 0.3 intra factor (no fallback for `evidence_type_weights`, though, so an unknown key currently returns 0.5 — see the helper's behavior in § 4). Should the helper require a non-optional `&CalibrationConfig` (caller resolves the load+default elsewhere) or accept `Option<&CalibrationConfig>` and apply its own defaults? Spec assumes the former.
3. **`locality_tag` vocabulary expansion.** The plan defines three values: `intra`, `cross`, `unknown`. The Phase 3 `evidence_id` design might want finer granularity (`intra_self_cite` vs. `intra_methodological_overlap`). Phase 2 should treat any non-`"intra"` value as cross behavior, so a future tag expansion is purely additive on the write side. Confirm we want to defer the expanded vocabulary to Phase 3.
4. **`source_strength` column lifecycle.** The plan implies the column survives Phase 2 as a write-through cache. Spec endorses that and uses it as the § 2 step (1) legacy fallback. Confirm we keep populating it from `wire_evidential_edge_factor` and `auto_wire_ds_*` — it costs nothing and is the migration-compat lever. Drop only when Phase 3 lands an `evidence_id` FK *and* every legacy row has been re-derived.
5. **Evidence-type vocabulary mismatch on edge_factor (§ 4).** Spec recommends path (1) — treat the calibration unknown-fallback as the sentinel — for Phase 2. Confirm we want to file paths (2) and (3) (calibration aliases for relationships; rewriting edge_factor to store a SciFact key) as separate follow-ups rather than blocking Phase 2 on them. The 0.5-vs-real-0.5 disambiguation requires a small `CalibrationConfig::evidence_type_weight_present(key) -> bool` accessor; trivial to add but explicit on the API.
6. **Pre-Phase-2 verification SQL count of legacy null-`evidence_type` rows** (§ 7 step 3, second query). The spec assumes 5202ded populated both `source_strength` and `evidence_type`; the commit message phrasing ("Policy: claims with ≥1 evidence row: take MAX(evidence-type weight)") suggests it only set `source_strength`. If the count is in the tens of thousands, the § 2 step (1) legacy fallback covers them correctly but those rows skip dynamic recalibration. Decide whether a Phase 1c pass populates `evidence_type` from `evidence.evidence_type` before Phase 2 deploys, or whether the legacy-cache cohort is tolerable.
7. **`per_frame_locality_factor_override_applied` test rewrite scope.** The existing test mechanically passes under Phase 2 but its documented intent is inverted (§ 6). Confirm we update the comment + add the recompute-after-override combined-BetP assertions in the same PR as the helper introduction, or whether the test extension lands in a separate PR ahead of the helper to lock in the new invariant first.

## Acceptance

- [ ] `effective_source_strength` exists in `crates/epigraph-engine` with the fallback chain in § 2 and the unknown-evidence-type sentinel from § 4.
- [ ] `CalibrationConfig` gains an `evidence_type_weight_present(key) -> bool` accessor (or equivalent) to disambiguate the 0.5 sentinel from real 0.5 weights.
- [ ] `recompute_combined_belief` and `auto_wire_ds_update` call the helper instead of reading `row.source_strength` at combine time.
- [ ] `tests/effective_source_strength_unit.rs` (new) covers every branch of the fallback chain.
- [ ] `intra_source_discount_regression.rs` is extended with a recompute-after-recalibration assertion (BetP shifts when the per-frame factor changes, no DB rewrite).
- [ ] `per_frame_locality_factor_override_applied` is extended to assert the combined BetP on the target reflects the override, and its outdated comment is rewritten.
- [ ] `crates/epigraph-mcp/tests` has an analogous recalibration test through the `auto_wire_ds_update` MCP entry point.
- [ ] `bp_apply_plausibility_bounds.rs` seed is updated so the drift test continues to drift under the new combine numerics.
- [ ] Pre-deploy verification SQL (§ 7 step 3) has been run against production and counts are confirmed within tolerances.
- [ ] `cargo fmt`, `cargo clippy --workspace`, `cargo test --workspace` clean against `epigraph_db_repo_test`.
- [ ] `cargo sqlx prepare --workspace -- --tests` re-run if any `query!` macros are touched (no expected touches; the change is Rust-side only).

## Related

- Plan: `docs/superpowers/plans/2026-05-28-locality-tag-schema.md` — three-phase fix for #197.
- Phase 1a in-flight: branch `feat/mass-functions-locality-tag` (additive schema, forward-write-path tagging).
- Phase 1b: one-shot SQL described in the plan body (no separate branch; operator-run).
- Spec: `docs/superpowers/specs/2026-05-27-alternative-and-dependency-edges-design.md` § 2 — the locality-aware discounting design that Phase 1a/1b/2 supersede on the typing-vs-weight axis.
- Plan: `docs/superpowers/plans/2026-05-27-locality-aware-discounting.md` — predecessor implementation; introduced `intra_evidence_locality_factor`, `same_source_papers` Postgres function, and the `wire_evidential_edge_factor` composed-strength write path.
- `feedback_pignistic_not_bayesian.md` — BetP is the decision measure; this spec's recalibration tests assert on BetP.
- `feedback_council_of_critics.md` — the recompute-after-recalibration test is adversarial in the sense the council requires (not a happy-path no-op).
