# Per-Frame Evidence-Type Weights — Phase 4 Design

**Date:** 2026-05-28
**Status:** Design — awaiting review
**Author:** Jeremy Barton (with Claude)
**Issue:** [#197](https://github.com/epigraph-io/epigraph/issues/197)
**Depends on:** Phase 1a (`feat/mass-functions-locality-tag`, schema + write-path tagging), Phase 1b (one-shot SQL backfill of `locality_tag`), and Phase 2 (the `effective_source_strength` helper — see companion spec).
**Companion plan:** `docs/superpowers/plans/2026-05-28-locality-tag-schema.md` § Phase 4
**Companion spec (parallel review):** `docs/superpowers/specs/2026-05-28-locality-aware-combine-spec.md` (Phase 2)

## Problem

Phase 2 introduces the helper `effective_source_strength(row, per_frame_intra_factor, &calibration)` that computes a per-row Shafer reliability discount as `evidence_type_weight × locality_factor`. The locality axis already supports per-frame overrides via `frames.properties->>'intra_evidence_locality_factor'` (migration 044, shipped in #193). The **evidence-type axis** still reads a single global `evidence_type_weights` table from `calibration.toml`.

Production has 124 distinct frames, each representing a different epistemic context. A few examples drawn from the live DB:

| frame | claims | epistemic shape |
|---|---|---|
| `research_validity` | 44 999 | empirical methodology evaluation; testimony is methodologically circular |
| `binary_truth` | 25 477 | SciFact-calibrated baseline; the calibration's targeted frame |
| `textbook_veracity_openstax_astronomy-2e` | 4 307 | reference evidence (citing the textbook) IS the assertion-grounding move |
| `textbook_veracity_openstax_anatomy-and-physiology-2e` | 3 628 | same |
| `wrhq_spec_validity` | 976 | spec-conformance frame; document evidence (the spec itself) carries weight by design |
| `nanotech_mechanosynthesis_progress` | (NDI-internal) | observation-heavy; testimony from molecular-machines researchers weighs differently than from generalists |
| `funder_narrative_weight` | (governance) | testimony-heavy; circumstantial/regulatory evidence is the operating mode |

A single global `evidence_type_weights` table cannot fit all of these. `textbook_veracity_*` wants `reference = 1.0` (citing the textbook is the *point*, not circular); `research_validity` wants `testimony ≤ 0.5` (methodology-paper testimonials are circular); `binary_truth` wants the calibrated defaults untouched (it's what the 0.948 SciFact F1 was tuned against). Today every frame shares the same weights.

Phase 4 extends the per-frame override pattern that #193 established on the locality factor to evidence-type weights themselves. The schema lever already exists (`frames.properties` JSONB); the change is purely in the helper's lookup chain and a thin repository accessor.

## Goals

1. Operators can set per-frame evidence-type weights via the existing `FrameRepository::set_property` writer. No new schema, no new migration.
2. The Phase 2 helper's signature gains a `per_frame_evidence_weights: Option<&HashMap<String, f64>>` parameter. When the override is present and contains the BBA's `evidence_type` (case-normalized), it wins; otherwise the existing global lookup (with alias resolution) wins.
3. Recalibration of a per-frame weight via `FrameRepository::set_property` flows through `recompute_claim_belief_on_frame` to combined BetP without any DB rewrite. Same recalibration-without-rewrite property Phase 2 establishes for the locality factor.
4. The legacy population (278 635 of 279 894 rows with `evidence_type IS NULL`) is unaffected. Phase 4's Tier 1 is keyed on `evidence_type` and silently no-ops on null. The Phase 2 legacy-`source_strength` fallback handles those rows unchanged.
5. Phase 4 produces zero behavioural change on the deploy day itself: no frame carries an evidence-type weight override yet (verified — see § 6), so every helper call falls through to the Phase 2 Tier 2 (global calibration) on shipping day. Behavioural change happens *only* when an operator sets an override.

**Non-goals.**

- Per-agent or per-perspective evidence-type weights. Those need a join table, not JSONB on `frames`. See § 10.
- Outcome-driven learning of per-frame weights. Dempster's rule isn't differentiable; learning requires CMA-ES or genetic optimisation over the discrete-weight space and a residual ledger. Separate research track; see § 10.
- A JSON-schema validator on `frames.properties` writes. Operators write via `set_property` or direct SQL today; runtime validation in the repo accessor is the agreed surface.
- HTTP / MCP routes for setting per-frame weights. Operator surface is psql or `FrameRepository::set_property` directly. Adding a route is a separate design pass.
- Changing the BBA mass shape, the discount step, or the combine math. Phase 4 is a lookup-chain extension only.

## Approach

### 1. The existing infrastructure

Read-only inventory of pieces already in place:

- **Migration 044 (`migrations/044_frames_properties.sql`):** `ALTER TABLE frames ADD COLUMN properties JSONB NOT NULL DEFAULT '{}'::jsonb`. The migration's `COMMENT ON COLUMN` already enumerates `intra_evidence_locality_factor` as a conventional key; Phase 4 adds `evidence_type_weights` as a second one.
- **`FrameRepository::get_intra_evidence_locality_factor` (`crates/epigraph-db/src/repos/frame.rs::329-347`):** reads `properties->>'intra_evidence_locality_factor'` as TEXT, parses to `f64`, returns `Ok(None)` on missing-row / missing-key / unparseable. The "parse in Rust so the worst case is None" pattern is the template for Phase 4's new accessor.
- **`FrameRepository::set_property` (`crates/epigraph-db/src/repos/frame.rs::357-376`):** thin JSONB-merge writer: `UPDATE frames SET properties = properties || jsonb_build_object($key, $value) WHERE id = $1`. Already used by `per_frame_locality_factor_override_applied` test. Accepts arbitrary `&serde_json::Value` — no validation. Phase 4 uses it as-is for per-frame weight writes.
- **`CalibrationConfig::evidence_type_weights: HashMap<String, f64>` (`crates/epigraph-engine/src/calibration.rs::38`) + `evidence_type_aliases: HashMap<String, String>` (line 44):** the existing global lookup tables. `get_evidence_type_weight(key)` at line 195 does `.to_lowercase()` then canonical → alias → 0.5-fallback resolution.
- **Phase 2 helper signature (per companion spec, § 2):**
  ```rust
  pub(crate) fn effective_source_strength(
      row: &MassFunctionRow,
      per_frame_intra_factor: Option<f64>,
      calibration: &CalibrationConfig,
  ) -> f64
  ```
  Phase 4 extends this signature with a fourth parameter.
- **`MassFunctionRow.evidence_type: Option<String>` (`crates/epigraph-db/src/repos/mass_function.rs::23`):** the per-row evidence-type tag. Stored case-as-written by the caller; production has mixed-case entries (`CORROBORATES`, `Reference`, `observation`) the case-insensitive lookups must absorb.

Production state (queried 2026-05-27 against `epigraph` DB):

- 124 frames total.
- **0 frames** carry `properties->>'intra_evidence_locality_factor'` today. The Phase-2 per-frame-factor lever ships into a virgin field; Phase 4 ships into the same.
- **0 frames** carry `properties->>'evidence_type_weights'` (expected — no operator could set it without the accessor Phase 4 introduces).
- 13 distinct `evidence_type` values on `mass_functions`: `NULL` (278 635), `document` (380), `empirical` (348), `observation` (113), `reference` (104), `logical` (101), `statistical` (66), `CORROBORATES` (56), `testimony` (56), `testimonial` (37), `circumstantial` (2), `supersedes` (2), `SUPPORTS` (1).

### 2. Helper signature extension

The Phase 2 signature gains a fourth parameter. Recommended shape:

```rust
// crates/epigraph-engine/src/edge_factor.rs (alongside the Phase 2 helper;
// move to crates/epigraph-engine/src/locality.rs if and when Phase 3
// adds a third caller — see Phase 2 spec § 7 open question 1).

pub(crate) fn effective_source_strength(
    row: &MassFunctionRow,
    per_frame_intra_factor: Option<f64>,
    per_frame_evidence_weights: Option<&HashMap<String, f64>>,
    calibration: &CalibrationConfig,
) -> f64 { ... }
```

**Type-shape decision: `Option<&HashMap<String, f64>>`, parsed once at the call site, passed by reference per row.**

Three options were considered:

| shape | trade-off |
|---|---|
| `Option<&serde_json::Value>` (raw JSONB) | Caller does no parsing; helper does `.get(key).and_then(.as_f64())` per row. **Hot-path serde_json parsing inside a multi-BBA combine loop.** Rejected. |
| `Option<&HashMap<String, f64>>` (parsed in repo) | Repo parses once (validates floats, lowercases keys, range-checks); helper does `.get(key)` per row. Mirrors `get_intra_evidence_locality_factor`'s parse-in-Rust pattern. **Recommended.** |
| `Option<&PerFrameEvidenceWeights>` (newtype) | Same as `HashMap` shape with a wrapper. Worth doing only if Phase 4+ accretes invariants beyond "flat string→float". The current scope doesn't justify the indirection. Defer until a second consumer (e.g. CLI introspection) needs the same parse logic. |

The `HashMap<String, f64>` shape symmetrises Phase 4 with Phase 2's locality lever: `get_intra_evidence_locality_factor` returns `Option<f64>` parsed in the repo; `get_per_frame_evidence_type_weights` returns `Option<HashMap<String, f64>>` parsed in the repo. Both are loaded once per `recompute_claim_belief_*` call, above the per-BBA combine loop.

**Case normalisation: keys lowercased at parse time inside the repo accessor.** Production has mixed-case `evidence_type` values (`CORROBORATES`, `Reference`, `observation`). `CalibrationConfig::get_evidence_type_weight` lowercases its lookup key before resolving (calibration.rs:196). The helper's per-frame Tier 1 lookup MUST do the same or operator intent silently misses: an operator who writes `"observation": 1.2` would expect that to hit the 113 `observation`-tagged BBAs *and* the 0 `OBSERVATION`-tagged BBAs uniformly. The repo accessor lowercases both the map keys (at parse) and the lookup performed by the helper (at read).

### 3. Repository extension

Two new `FrameRepository` methods in `crates/epigraph-db/src/repos/frame.rs`. Both mirror the existing `get_intra_evidence_locality_factor` / `set_property` pair.

```rust
/// Read the per-frame `evidence_type_weights` override map, if any.
///
/// Returns `Ok(None)` when:
///   * the frame row doesn't exist,
///   * `properties` does not contain the `evidence_type_weights` key,
///   * the key's value is not a JSON object (operator wrote garbage),
///   * the JSON object is empty after parsing (no usable entries).
///
/// Object entries are parsed:
///   * key normalised to lowercase (matches `CalibrationConfig`),
///   * value coerced via `as_f64()`; non-numeric values are dropped
///     with a `warn!` log (operator misspelled the weight),
///   * values outside `[0.0, 2.0]` are dropped with a `warn!` log
///     (see § 8 open question on range bounds; the soft default is
///     `[0.0, 2.0]` to allow textbook frames to weigh `reference > 1.0`
///     while still bounding obvious typos).
///
/// Callers fall back to `CalibrationConfig::get_evidence_type_weight`
/// when this returns `None` or when the returned map does not contain
/// the BBA's evidence-type key.
///
/// # Errors
/// Returns `DbError::QueryFailed` only on actual DB failure. Missing
/// rows / missing keys / malformed JSON return `Ok(None)`, not an
/// error — the consumer is expected to fall back to the global
/// calibration in that case.
#[instrument(skip(pool))]
pub async fn get_per_frame_evidence_type_weights(
    pool: &PgPool,
    frame_id: Uuid,
) -> Result<Option<HashMap<String, f64>>, DbError> { ... }
```

Implementation sketch (no code; design only): fetch `properties->'evidence_type_weights'` as `Option<serde_json::Value>`, match on `Some(Value::Object(map))`, iterate entries, lowercase keys via `String::to_lowercase()`, coerce values via `.as_f64()`, range-check, collect into `HashMap`. Return `Ok(None)` if the resulting map is empty.

Optional convenience method (recommended for operator ergonomics but not required for Phase 4 acceptance):

```rust
/// Set a single per-frame evidence-type weight. Convenience wrapper
/// over `set_property` for the common single-key write path.
///
/// Reads the existing `evidence_type_weights` object (if any), merges
/// the new key, writes back. The key is NOT normalised on write —
/// readers normalise on read, so `"observation"` and `"OBSERVATION"`
/// in the JSONB resolve to the same effective entry but the JSONB
/// stores what the operator typed (an audit-trail consideration).
///
/// # Errors
/// Returns `DbError::QueryFailed` on actual DB failure. Does NOT
/// validate the evidence_type key against calibration; operators may
/// pre-register weights for evidence types not yet in calibration.toml
/// (see § 8 open question on strict-validation).
pub async fn set_evidence_type_weight(
    pool: &PgPool,
    frame_id: Uuid,
    evidence_type: &str,
    weight: f64,
) -> Result<(), DbError> { ... }
```

The convenience method is a thin read-modify-write around `set_property`; the operator can equally well do the merge in psql. Spec recommends shipping it for symmetry with the documented operator interface in the plan body (`mcp__epigraph__set_frame_property` if it ever becomes a thing).

### 4. Lookup chain — exactly three tiers

The Phase 2 helper's two-tier evidence-type lookup becomes three:

1. **Tier 1 (per-frame override, strict-key):** `per_frame_evidence_weights.and_then(|m| m.get(&row.evidence_type.as_deref()?.to_lowercase()))`. If `Some(weight)`, return `weight`. **No alias resolution at this tier** — see § 5.
2. **Tier 2 (global calibration with aliases):** `calibration.get_evidence_type_weight(row.evidence_type.as_deref()?)`. Already case-normalises; already resolves aliases (`observation → empirical`, etc.); returns the 0.5 unknown-key fallback on miss.
3. **Tier 3 (Phase 2's legacy bridge):** when Tier 2 returns the 0.5 fallback (disambiguated via `CalibrationConfig::evidence_type_weight_present(key) -> bool`, the accessor the Phase 2 spec § 4 introduces) AND `row.source_strength` is set, return `row.source_strength`. Unchanged from Phase 2.

The Tier 1 → Tier 2 → Tier 3 ordering is the only ordering that satisfies all the following constraints:

- Operator wrote a per-frame override → it wins. (Tier 1 first.)
- Operator did NOT write a per-frame override for this evidence type, but the evidence type maps to a calibration alias → global calibration applies. (Tier 2 second; aliases resolved there.)
- Evidence-type is unknown / null AND `source_strength` is set → migration-compat path applies. (Tier 3 last, same as Phase 2.)
- Evidence-type is null AND `source_strength` is null → 0.5 fallback (same as Phase 2 § 2 step 3).

### 5. Alias resolution — strict at Tier 1, lenient at Tier 2

The load-bearing decision: at Tier 1, does `per_frame_evidence_weights.get("observation")` ALSO match BBAs tagged `"empirical"` (because `observation → empirical` is in `calibration.evidence_type_aliases`)?

**Recommendation: strict-key at Tier 1, no alias resolution.** The per-frame map is hand-written operator override; if they write `"observation": 1.2`, that should affect rows literally tagged `"observation"` (case-insensitively), not also `"empirical"` (which they may not have known aliases to `observation`'s canonical key).

Reasoning:

1. Alias resolution at Tier 1 silently expands operator intent. An operator writing a textbook-frame override for `"reference"` would unexpectedly also hit `"document"`-tagged BBAs (both alias to `"logical"`).
2. If the operator *wants* to override both, they write both: `{"observation": 1.2, "empirical": 1.2}`. Explicit > implicit for a configuration knob.
3. The strict policy makes per-frame overrides a "patch" on top of the global vocabulary, not a fork of it. Tier 2 still resolves aliases globally; Tier 1 only patches the specific tags the operator named.

Walk-through of Tier-resolution cases:

| `evidence_type` | per-frame map | calibration | helper output |
|---|---|---|---|
| `"observation"` | `{"observation": 1.2}` | empirical=1.0 (alias `observation`→empirical) | **1.2 (Tier 1)** |
| `"empirical"` | `{"observation": 1.2}` | empirical=1.0 | **1.0 (Tier 2)** — strict-key means override does not transitively apply |
| `"empirical"` | `{"empirical": 1.5}` | empirical=1.0 | **1.5 (Tier 1)** |
| `"Reference"` | `{"reference": 0.6}` | reference→logical=0.85 | **0.6 (Tier 1)** — case normalised on both sides |
| `"reference"` | `{}` (no override) | reference→logical=0.85 | **0.85 (Tier 2)** |
| `"CORROBORATES"` | `{}` | unknown key, fallback 0.5 | Tier 2 returns 0.5 sentinel; helper checks `evidence_type_weight_present`, sees `false`; Tier 3 returns `row.source_strength` if set, else 0.5. |
| `"CORROBORATES"` | `{"corroborates": 0.7}` | unknown key | **0.7 (Tier 1)** — Phase 4 lets operators patch the relationship-vocabulary leak (see § 7) without waiting for Phase 2 path (2) follow-up |
| `"supports"` | `{}` | unknown key (0.5 fallback) | Tier 3 — `row.source_strength` (the Phase 2 § 4 bridge). |
| `"supports"` | `{"supports": 0.7}` | unknown key | **0.7 (Tier 1)** — same |
| `NULL` | `{"empirical": 1.5}` | (no `evidence_type` to look up) | Tier 1 misses (no key); Tier 2 returns 0.5; Tier 3 returns `row.source_strength` if set, else 0.5. Phase 4 is a no-op on null-`evidence_type` rows. |

The third-to-last and second-to-last rows are an interesting side benefit: **Phase 4 gives operators a Tier-1-only escape hatch for the relationship-vocabulary mismatch the Phase 2 spec § 4 flagged.** Without rewriting `edge_factor.rs::auto_wire_ds_for_edge` to store a SciFact-canonical evidence_type, an operator can write `{"supports": 0.7, "corroborates": 0.5, "refutes": 0.7}` into a frame to give Tier 1 hits for the relationship-as-evidence-type cohort. This is documented as a use, not as the *intended fix* (the proper fix is still Phase 2 § 4 path 2 or 3); but Phase 4 doesn't conflict with it and may unblock it.

### 6. Production population assessment

Queries run against the live `epigraph` DB on 2026-05-27 (small queries on indexed columns; no read pressure):

```sql
SELECT COUNT(*) FROM frames;
-- 124

SELECT COUNT(*) FROM frames WHERE properties ? 'intra_evidence_locality_factor';
-- 0

SELECT COUNT(*) FROM frames WHERE properties ? 'evidence_type_weights';
-- 0

SELECT COUNT(*) FROM frames WHERE properties != '{}'::jsonb;
-- 0

SELECT evidence_type, COUNT(*) FROM mass_functions GROUP BY evidence_type
ORDER BY COUNT(*) DESC LIMIT 30;
-- NULL: 278 635
-- document: 380, empirical: 348, observation: 113, reference: 104,
-- logical: 101, statistical: 66, CORROBORATES: 56, testimony: 56,
-- testimonial: 37, circumstantial: 2, supersedes: 2, SUPPORTS: 1.
```

Inferences for Phase 4 deploy-day behaviour:

1. **Zero frames carry any property override today.** Phase 4 ships into a virgin field. No backfill, no migration, no rewrite. The repo accessor returns `Ok(None)` for every frame on the day of deploy; every helper call falls through to Tier 2 (global calibration). Behavioural identity with Phase 2 is by construction.
2. **278 635 of 279 894 mass_functions have `evidence_type IS NULL`.** Phase 4's Tier 1 lookup keys on `evidence_type`; null → no key → Tier 1 silently no-ops. These rows hit Phase 2's Tier 3 bridge (`source_strength` cache) and are unaffected by Phase 4 regardless of what operators write into `frames.properties`.
3. **Realistic per-frame override candidates (by claim count and frame semantics):**
   - `research_validity` (45 K claims): plausible candidate. Methodology testimony is circular here; `{"testimonial": 0.4, "testimony": 0.4, "expert_elicitation": 0.4}` (with all three names because aliases don't auto-expand at Tier 1) is a defensible operator move.
   - `textbook_veracity_openstax_*` family (8 frames, 769–4 307 claims each): the textbook-citing case. `{"reference": 1.2, "document": 1.2}` reflects "citing the textbook *is* the evidence." Per-frame override is exactly the right tool.
   - `wrhq_spec_validity` (976 claims): similar to textbook frames; the spec is the assertion-grounding artifact.
   - `binary_truth` (25 K claims): **explicitly NOT a candidate.** SciFact-calibrated baseline; the 0.948 F1 was tuned against these weights. Document this in the operator playbook as "don't override binary_truth."
   - `nanotech_mechanosynthesis_progress` and `funder_narrative_weight`: NDI / governance frames Jeremy maintains; per-frame overrides are appropriate as the program matures.
4. **The relationship-vocabulary leak (Phase 2 § 4).** Production carries 56 + 1 + 2 = 59 BBAs with `CORROBORATES` / `SUPPORTS` / `supersedes` (no calibration match). Under Phase 2 these hit the Tier 3 `source_strength` bridge. Under Phase 4, an operator who cares about a specific frame can patch them via `{"corroborates": ..., "supports": ...}`. This is the side benefit called out in § 5; it doesn't unblock Phase 2 § 4's broader follow-ups but it does relieve specific frames.

Verification SQL (operator pre-flight before considering an override):

```sql
-- Distribution of evidence_type on the target frame (helps the operator
-- pick which keys to override and what magnitude).
SELECT mf.evidence_type, COUNT(*)
  FROM mass_functions mf
  JOIN claim_frames cf ON cf.claim_id = mf.claim_id
  WHERE cf.frame_id = $1
  GROUP BY mf.evidence_type
  ORDER BY COUNT(*) DESC;
```

### 7. Test plan

New and modified tests across two crates. Spec recommends extending the existing Phase 2 test file rather than introducing a Phase-4-only one — the helper's unit-test surface should live in one place.

**`crates/epigraph-engine/tests/effective_source_strength_unit.rs` (extend the Phase 2 unit test file)**

Pure-unit tests of the helper, no DB. Synthetic `MassFunctionRow` instances + synthetic `CalibrationConfig` + synthetic `HashMap<String, f64>` for the per-frame map. New cases on top of the Phase 2 set:

- Per-frame override present + matches canonical key: `evidence_type = "empirical"`, per-frame `{"empirical": 1.5}` → 1.5 (Tier 1 wins over global 1.0).
- Per-frame override present + matches alias of canonical: `evidence_type = "observation"`, per-frame `{"observation": 1.2}`, calibration alias `observation → empirical` → 1.2 (Tier 1 wins, strict-key, no transitive override of `empirical`).
- Per-frame override present + matches alias but operator wrote the canonical instead of the alias: `evidence_type = "observation"`, per-frame `{"empirical": 1.5}` → Tier 1 misses (strict-key, no reverse alias resolution); Tier 2 returns 1.0 via alias. Documents the strict-key contract.
- Per-frame override present + case mismatch: `evidence_type = "Reference"`, per-frame `{"reference": 0.6}` → 0.6 (both sides lowercased).
- Per-frame override present + relationship-vocab key: `evidence_type = "CORROBORATES"`, per-frame `{"corroborates": 0.7}` → 0.7 (Tier 1; documents the side-benefit § 5 lists for the Phase 2 § 4 leak).
- Per-frame override present + key absent + global hits: `evidence_type = "logical"`, per-frame `{"empirical": 1.5}` (no logical entry) → 0.85 (Tier 2).
- Per-frame override present + key absent + global misses + `source_strength` set: `evidence_type = "supports"`, per-frame `{"empirical": 1.5}`, `source_strength = Some(0.21)` → 0.21 (Tier 3, unchanged from Phase 2).
- Per-frame override is `None` (operator never set it): falls through to Phase 2 behaviour identically. Sanity check that Phase 4 is a strict superset.
- Per-frame override is `Some({})` (empty map): same as `None`. The repo accessor returns `Ok(None)` on empty (see § 3); the helper still handles `Some({})` defensively.
- Per-frame override on null `evidence_type`: `evidence_type = None`, per-frame `{"empirical": 1.5}` → Tier 1 misses (no key to look up); Tier 2 returns 0.5; Tier 3 returns `source_strength` if set, else 0.5. Documents that Phase 4 is a no-op on the 278 K-row legacy bulk.

**`crates/epigraph-engine/tests/intra_source_discount_regression.rs` (extend)**

Add a new test (or extend `per_frame_locality_factor_override_applied`) that exercises the **recalibration-flows-through-via-`recompute_claim_belief_*`** invariant for the evidence-type axis. This is the Phase-4 analogue of the Phase 2 spec's recalibration assertion on the locality axis:

`per_frame_evidence_type_weight_override_applied` (new sqlx::test):

1. Seed: a target claim on `binary_truth`, two supporters each with explicit `evidence_type = "empirical"`, both intra-source. Auto-wire both. Combine via `recompute_claim_belief_binary`.
2. Read `claims.pignistic_prob` for the target — record as the "baseline BetP" (calibration's `empirical = 1.0` weight in effect).
3. Set `frames.properties = jsonb_build_object('evidence_type_weights', jsonb_build_object('empirical', 0.5))` via `FrameRepository::set_property`.
4. Call `recompute_claim_belief_binary` again on the same target.
5. Assert BetP has shifted downward (the override halved the per-row reliability discount, so each supporter contributes less; combined BetP moves toward 0.5). Concrete assertion: `new_betp < baseline_betp - 0.05` (5 percentage points; tolerance picked to be larger than combination-noise but smaller than the expected shift).
6. Set the override to `1.5`. Recompute. Assert BetP shifts upward versus the 0.5-override baseline by a comparable margin.
7. Remove the override: `UPDATE frames SET properties = properties - 'evidence_type_weights'`. Recompute. Assert BetP returns to the original baseline (within float tolerance).

This is the canary that Phase 4 actually does what it's supposed to. Without it, Phase 4 ships green but the per-frame override is dead code at combine time.

**`crates/epigraph-db/tests/frame_repository_properties.rs` (new or extend existing test file)**

Repository-layer round-trip tests for `get_per_frame_evidence_type_weights` and `set_evidence_type_weight`:

- Round-trip: `set_evidence_type_weight(pool, frame_id, "empirical", 1.5)`, then `get_per_frame_evidence_type_weights` returns `Some(map)` with `map["empirical"] == 1.5`.
- Case normalisation on read: write `{"Empirical": 1.5}` via raw `set_property`, then `get_per_frame_evidence_type_weights` returns `Some(map)` with `map["empirical"] == 1.5` (lowercased on read).
- Malformed JSON value: write `{"evidence_type_weights": "not-an-object"}` via `set_property`, then `get_per_frame_evidence_type_weights` returns `Ok(None)` (no panic, no error).
- Non-numeric weight in an otherwise-valid map: write `{"empirical": "string", "logical": 0.85}`, then `get_per_frame_evidence_type_weights` returns `Some({"logical": 0.85})` (drops the malformed entry, keeps the valid one).
- Out-of-range weight: write `{"empirical": 5.0}` (above the [0.0, 2.0] soft bound — see § 8), then the accessor drops it with a warn-log and returns `Ok(None)` if it was the only entry, or `Some(map)` excluding it otherwise.
- Missing key: write `{"intra_evidence_locality_factor": 0.5}` (Phase 2's key only), then `get_per_frame_evidence_type_weights` returns `Ok(None)`.
- Missing frame: `get_per_frame_evidence_type_weights(pool, Uuid::new_v4())` returns `Ok(None)`.

**`crates/epigraph-mcp/tests` (no new tests required)**

Phase 4 doesn't change MCP-facing behaviour beyond what the engine recalibration test already verifies. The MCP `auto_wire_ds_update` path picks up the helper through the Phase 2 change; Phase 4's per-frame parameter is loaded by the same caller. No new MCP-specific test surface.

**`crates/epigraph-api/tests` (no new tests required)**

Same reasoning. API combine paths don't read `source_strength` at combine time (see Phase 2 spec § 1). Phase 4's per-frame override is invisible to them.

**Regression on existing tests**

- `per_frame_locality_factor_override_applied` (lines 374-487 of `intra_source_discount_regression.rs`) — unchanged by Phase 4. Phase 4's helper signature widens but the test exercises the locality axis only and passes `None` for the per-frame evidence-weights parameter (or whatever the Phase 2 callsite passes, since Phase 4 lands as a follow-up to Phase 2 and the helper-signature change happens once).
- `intra_source_19_supporters_betp_in_band` and `cross_source_19_supporters_keeps_high_betp` — unchanged. They don't set per-frame overrides; Tier 1 silently no-ops.
- `calibration.rs::tests::*` — unchanged. Phase 4 doesn't modify `CalibrationConfig` or its accessors.

### 8. Open questions

1. **Strict validation of evidence-type keys on write.** Should `set_property` (or the convenience `set_evidence_type_weight`) reject writes where the key is not in `calibration.evidence_type_weights` ∪ `calibration.evidence_type_aliases` ∪ a known-leakage allow-list (relationship vocab: `supports`, `corroborates`, `supersedes`, etc.)?
   - **Tighter:** prevents typos; an operator typo'ing `"emperical"` would error immediately rather than silently no-op at read time.
   - **Looser (recommended):** lets operators experiment with new evidence types before they're added to `calibration.toml`. Aligns with `set_property`'s current "thin JSONB merge with no validation" semantics. Operators retain responsibility for spelling.
   - Suggested compromise: no validation in `set_property` (stays thin); a warn-log in `get_per_frame_evidence_type_weights` if a key isn't in calibration's canonical-or-alias vocabulary. This surfaces typos in operational logs without rejecting the write.

2. **Alias resolution at Tier 1.** § 5 recommends strict-key (no alias resolution at Tier 1). The looser alternative — Tier 1 also resolves aliases — has the user-affordance argument: an operator writing `"observation": 1.2` and expecting `empirical` BBAs to follow is a defensible reading. Spec recommends strict-key; **confirm** before code.

3. **Range validation.** The spec recommends `[0.0, 2.0]` (allows textbook frames to weight `reference > 1.0`; bounds obvious typos). Alternatives:
   - `[0.0, 1.0]` matches Shafer's reliability semantics strictly (a discount, not an amplification). Rules out the textbook-frame use case. **Rejected.**
   - Unbounded above: allows "this evidence is super-strong" but invites operator errors like a stray decimal place. **Soft-reject; range-check at read time, not write.**
   - The recommended `[0.0, 2.0]` is conservative; if textbook-frame experiments demonstrate higher weights are wanted, widen.

4. **Should `frames.properties` get a JSON Schema?** Today the column is a free-form JSONB bag. Adding a schema (either as a Postgres CHECK constraint with a `jsonb_matches_schema` extension function, or as Rust-side validation in `set_property`) catches operator errors earlier.
   - **Pro:** typos rejected at write time; well-typed audit trail.
   - **Con:** the column is intentionally a free-form bag for *forward* operator experimentation. Locking it down via a schema now constrains future per-frame keys we haven't designed yet (e.g. a future per-frame BetP-decision-threshold override).
   - **Recommendation:** stay free-form, validate per-key in the repo accessors. The accessor's defensive parsing is the schema-in-Rust equivalent.

5. **Where does the helper live?** Phase 2 spec puts it in `crates/epigraph-engine/src/edge_factor.rs`. Phase 4 doesn't change that. The signature widens, but the helper still has only two transitive callers (the two combine paths). If a Phase 3 `evidence_id` FK path adds a third, factor out to `crates/epigraph-engine/src/locality.rs` then. Confirm.

6. **MCP / HTTP surface.** Should `set_evidence_type_weight` (or `set_property` generally) get an MCP tool and/or HTTP route? Operators currently set per-frame properties via psql + direct SQL. The convenience-method recommendation in § 3 is a pure Rust addition; promoting it to MCP / HTTP is a separate API design decision. **Defer to a follow-up issue.** Out of scope for Phase 4 per the task's § 10 (UI / API surface deferred).

7. **Multi-frame claim handling.** Some claims are assigned to multiple frames (`claim_frames` is M:N). The combine helper is called per (claim, frame) pair via `recompute_claim_belief_on_frame`; per-frame overrides flow naturally because the override is keyed on `frame_id`. No special handling needed, but worth confirming the operator mental model: a claim's combined belief is per-frame, and per-frame overrides apply to the per-frame combine independently. **No action;** documenting for the reviewer.

### 9. Production rollout sequencing

Phase 4 has no schema migration. Pure-Rust deploy.

Strict dependency ordering:

1. **Phase 1a merges + deploys.** `045_mass_functions_locality_tag.sql` lands; forward writes carry `locality_tag`.
2. **Phase 1b SQL runs against production.** Historical 279 K rows get `locality_tag` populated.
3. **Phase 2 merges + deploys.** `effective_source_strength` helper exists, combine path reads it. Behaviour-identical to pre-Phase-2 for the deploy-day population (per Phase 2 spec § 5 backwards-compat analysis).
4. **Phase 4 merges + deploys.** Helper signature widens with the fourth parameter; callers pass `Option<&HashMap<String, f64>>` from a new repo lookup. Until any operator sets an override, behaviour is identical to Phase 2: the new parameter is `None` for every frame, Tier 1 silently no-ops, Tier 2 takes over (the same Tier 2 Phase 2 already runs).
5. **Operators start setting per-frame overrides.** Via `FrameRepository::set_property`, the convenience method, or psql. Each override-write affects only future `recompute_claim_belief_on_frame` calls; the helper reads the override at combine time, not at BBA write time. Recalibration is dynamic.
6. **Idempotency / rollback:**
   - Removing a per-frame override is `UPDATE frames SET properties = properties - 'evidence_type_weights' WHERE id = $1;`. Trivial.
   - Removing a single weight from an existing override: read-modify-write via psql or the convenience method.
   - Reverting a per-frame override and recomputing: `UPDATE ...; recompute_claim_belief_on_frame(claim_id, frame_id);` for each affected claim. The `recompute_combined_belief` cascade picks up the absence and falls back to global Tier 2.

**Acceptance gate:** do not deploy Phase 4 until Phase 2 is stable in production for at least one full reconciler cycle (≥24h) and the Phase 2 backwards-compat counts (Phase 2 spec § 7 step 3) are confirmed.

### 10. Out of scope

Forwarded to separate design passes:

- **Per-agent / per-perspective evidence-type weights.** "Operator A's prior on testimonial evidence is lower than the calibration default." Needs a join table (`agent_evidence_type_weights`, `perspective_evidence_type_weights`) keyed on `(agent_id, evidence_type)` or `(perspective_id, evidence_type)`. JSONB on `agents` / `perspectives` is the wrong shape because the cardinality is large and the lookup pattern is per-row at combine time. **Separate design pass; no current consumer.**
- **Outcome-driven learning of weights.** Predicted-vs-realised-BetP residuals as a loss signal; CMA-ES or genetic optimisation over discrete weight space (Dempster's rule isn't differentiable so backprop doesn't drop in). The Phase 4 substrate (per-frame JSONB carrying weight overrides) is the right write-target for an eventual optimiser, but the optimiser itself is its own project. **Separate research track.**
- **UI / API surface for setting per-frame weights.** psql + `FrameRepository::set_property` is the operator surface today. An MCP `set_frame_property` tool or HTTP `PATCH /api/v1/frames/{id}/properties` route is a sensible follow-up but is its own design pass (auth, audit, validation surface). **Separate issue.**
- **Per-frame BetP decision thresholds** (NEI, support, conflict thresholds — the `[classifier_thresholds]` table). The pattern is identical to evidence-type weights but a different axis. Likely a Phase 5 if it becomes a real need. **Out of scope for Phase 4.**
- **Per-frame methodology profiles** (the `[methodology_profiles]` table). Same pattern, different axis. Same disposition as above.

## Open conflicts with Phase 2 spec

None expected. Phase 4 widens the Phase 2 helper signature additively; the third parameter (`per_frame_evidence_weights`) is `Option<_>` and silently no-ops when absent. Phase 4 lands strictly after Phase 2.

One ordering note for review: the helper signature gets its final shape only once. If Phase 4's PR lands *before* Phase 2's, Phase 4 has to introduce the helper itself rather than widening an existing one. Spec assumes Phase 2 first; **confirm sequencing in review** so reviewers don't land Phase 4 without Phase 2.

## Acceptance

- [ ] `FrameRepository::get_per_frame_evidence_type_weights(pool, frame_id) -> Result<Option<HashMap<String, f64>>, DbError>` exists in `crates/epigraph-db/src/repos/frame.rs`, lowercases keys at parse time, coerces values, range-checks `[0.0, 2.0]`, returns `Ok(None)` on missing-frame / missing-key / malformed-JSON / empty-after-parse.
- [ ] `FrameRepository::set_evidence_type_weight(pool, frame_id, evidence_type, weight)` (convenience read-modify-write over `set_property`) exists. Optional but recommended.
- [ ] `effective_source_strength` (Phase 2 helper) gains the `per_frame_evidence_weights: Option<&HashMap<String, f64>>` parameter.
- [ ] Lookup chain implemented per § 4: Tier 1 strict-key + lowercased per-frame override, Tier 2 unchanged global calibration with aliases, Tier 3 unchanged Phase 2 `source_strength` bridge.
- [ ] Phase 2 callers (`recompute_combined_belief`, `auto_wire_ds_update`) load the per-frame weights via the new repo accessor above the combine loop and pass `Option<&HashMap<String, f64>>` to every per-row helper call.
- [ ] `effective_source_strength_unit.rs` (Phase 2 unit test file) extended with the Phase 4 cases enumerated in § 7.
- [ ] `intra_source_discount_regression.rs` gets the `per_frame_evidence_type_weight_override_applied` test (or equivalent name) exercising the BetP-shifts-when-override-set invariant via `recompute_claim_belief_binary`.
- [ ] `frame_repository_properties.rs` (new or extended) covers the repo round-trip + malformed-input cases in § 7.
- [ ] `cargo fmt`, `cargo clippy --workspace`, `cargo test --workspace` clean against `epigraph_db_repo_test`.
- [ ] No new `sqlx::query!` / `query_as!` macros introduced (the new accessor uses `sqlx::query_as` with `query_as`, mirroring `get_intra_evidence_locality_factor`); `cargo sqlx prepare` does not need to re-run unless an unrelated macro is touched.

## Related

- Plan: `docs/superpowers/plans/2026-05-28-locality-tag-schema.md` § Phase 4 (sketch this spec deepens).
- Spec: `docs/superpowers/specs/2026-05-28-locality-aware-combine-spec.md` (Phase 2 — companion; this spec extends its helper).
- Migration: `migrations/044_frames_properties.sql` (shipped in #193 — JSONB column, COMMENT enumerating conventional keys including the one Phase 4 adds).
- `FrameRepository::get_intra_evidence_locality_factor` / `set_property` (#193 / `crates/epigraph-db/src/repos/frame.rs`) — the parse-in-Rust + JSONB-merge-writer pattern Phase 4 mirrors.
- `CalibrationConfig::get_evidence_type_weight` / `evidence_type_aliases` (`crates/epigraph-engine/src/calibration.rs`) — Tier 2 of the lookup chain.
- `feedback_pignistic_not_bayesian.md` — BetP is the decision measure; the recalibration test asserts on BetP.
- `feedback_council_of_critics.md` — the recompute-after-override test is adversarial per the council's requirements (not a happy-path no-op; the BetP shift must be larger than combination-noise).
