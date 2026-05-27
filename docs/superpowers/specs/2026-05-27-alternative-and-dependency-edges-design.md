# Alternative & Dependency Edges (Spec 2)

**Date:** 2026-05-27
**Status:** Design — awaiting review
**Author:** Jeremy Barton (with Claude)
**Closes:** [#140](https://github.com/epigraph-io/epigraph/issues/140), [#141](https://github.com/epigraph-io/epigraph/issues/141), [#142](https://github.com/epigraph-io/epigraph/issues/142)

## Problem

Three separate issues describe symptoms of the same underlying defect: the Dempster product-rule combine treats every supporter as an independent observation. Three failure modes:

1. **Intra-source supporter inflation (#142).** A paper that decomposes one synthesis claim into 19 atomic sub-claims, all `supports`-linked to the synthesis, produces 19 BBAs that combine as if from 19 independent sources. NEMS claim BetPs land at 0.997 / 0.970 — well above any individual supporter (mean ~0.68).
2. **Competing-hypothesis over-combination (#141).** Two mutually-exclusive supporters {A1, A2} of a shared target T (e.g., competing mechanistic hypotheses) get product-combined as if their evidence stacked. Real semantics: T's belief should be bounded by the most permissive single alternative, not the conjunctive product.
3. **No vocabulary for the alternative-set relation (#140).** No edge type exists to mark two claims as alt-set members, so the engine cannot distinguish "independent supporters" from "competing alternatives".

The original #142 proposal — retype every intra-source `supports` to `decomposes_to` — was rejected during brainstorming because it conflates two genuinely different cases inside one paper:

- **Decomposition.** Paper claims X. Extractor emits X₁..Xₙ as sub-claims with `supports` edges to X. These aren't N observations; they're one assertion with N parts. (This is the inflation source.)
- **Intra-source evidence.** Paper claims Y. Paper *also* reports experiment Z (within the same paper) supporting Y. Z genuinely supports Y — cherry-picked maybe, but still evidence. Negative versions ("paper notes contradicting result W") are exactly what we want surfaced and weighted, not zeroed out.

Blanket retyping collapses case 2 onto zero. The correct treatment is **discounted** evidence: intra-source is non-zero but the independence assumption is suspect, so the Shafer reliability factor lands somewhere below cross-source. Same paper ≠ no evidence.

## Goals

1. Intra-source supporters contribute discounted (not zero) mass to their targets; NEMS-style inflation drops into the 0.7–0.85 BetP range matching the supporter mean.
2. New `alternative_of` edge type expresses mutually-exclusive supporters of a shared target. Symmetric. SQL view exposes the equivalence class under transitive closure.
3. CDST BP detects alternative sets among the supporters of a target and reduces them via max-Bel / max-Pl ("least restrictive alternative") before Dempster-combining with non-alt supporters.
4. Candidate-finder tool surfaces likely-alternative pairs from the existing graph as operator suggestions, no auto-promotion.
5. Operator-runnable backfill recomputes `source_strength` on existing intra-source BBAs to the new discount and re-runs `reconcile_sheaf`. No edge data is rewritten.

**Non-goals.**

- Retroactive `supports → decomposes_to` retyping. Replaced by locality-aware discounting.
- Auto-promoting suggested alt pairs into explicit edges. Operator-mediated.
- Alt-set semantics on `refutes`/`contradicts` edges. Symmetric case is a follow-up if it surfaces.
- Replacing CDST as the primary BP engine.
- Scope expansion to the four evidential relationships beyond what locality-discount already does (which is all four).

## Architecture

### 1. Edge vocabulary

`crates/epigraph-api/src/routes/edges.rs:65` — `VALID_RELATIONSHIPS` gains:

- `"alternative_of"` — claim ↔ claim, symmetric, mutually-exclusive supporters of a shared target.

Symmetric uniqueness via a partial unique index on the canonicalized endpoint pair:

```sql
CREATE UNIQUE INDEX edges_alternative_of_symmetric_uniq
  ON edges (LEAST(source_id, target_id), GREATEST(source_id, target_id))
  WHERE relationship = 'alternative_of';
```

A view exposes the equivalence class under transitive closure:

```sql
CREATE VIEW alternative_set AS
WITH RECURSIVE pairs AS (
  SELECT source_id AS a, target_id AS b
    FROM edges WHERE relationship = 'alternative_of'
  UNION
  SELECT target_id, source_id
    FROM edges WHERE relationship = 'alternative_of'
), closure AS (
  SELECT a, b FROM pairs
  UNION
  SELECT c.a, p.b FROM closure c JOIN pairs p ON c.b = p.a
)
SELECT a AS claim_id, array_agg(DISTINCT b ORDER BY b) AS alt_members
  FROM closure GROUP BY a;
```

A new migration (next-numbered slot in `migrations/`) lands the index and view. No alteration of existing edge-CHECK constraints — `alternative_of` is added to the application-level allow-list, and the DB enforces nothing about the relationship string today (per current schema, the column is free-form `text`).

### 2. Locality-aware discounting

**Predicate.** `same_source_papers(a UUID, b UUID) RETURNS BOOLEAN` — Postgres function that returns true iff `a` and `b` share a transitive closure under edges of relationship `{asserts, same_source, section_follows, continues_argument, decomposes_to}`. Implementation: recursive CTE rooted at the smaller of `(a, b)`, expanded across the five relationship types, returning true if the larger appears in the closure. Materialized as a function so callers (engine + backfill) share one definition.

**Engine integration.** `trigger_edge_ds_recomputation` (`crates/epigraph-api/src/routes/edges.rs:156`) consults the predicate at edge-create time and writes the BBA with:

- `source_strength = config.cross_source_support_strength` (default `1.0`) when endpoints are cross-source.
- `source_strength = config.intra_source_support_strength` (default `0.3`, tunable) when same-source.

The existing CDST combine already discounts each BBA by its stored `source_strength` (`crates/epigraph-mcp/src/tools/ds_auto.rs:295-307`). Locality only adjusts the per-BBA reliability — no combine-rule change.

**Calibration.** Two new keys in `config/calibration.toml`:

```toml
[evidence_locality]
intra_source_support_strength = 0.3
cross_source_support_strength = 1.0
```

Defaults are starting points, tuned against the NEMS regression and a synthetic 19-supporter test until the BetP lands in 0.7–0.85.

**Backfill.** Operator-run script `scripts/backfill_intra_source_discount.py`. Single SQL pass:

```sql
UPDATE mass_functions mf
SET source_strength = $1   -- bound from config.evidence_locality.intra_source_support_strength
FROM edges e
WHERE mf.source_agent_id = e.source_id
  AND mf.claim_id        = e.target_id
  AND e.relationship IN ('supports','refutes','corroborates','contradicts')
  AND same_source_papers(e.source_id, e.target_id)
RETURNING mf.claim_id;
```

The script loads `intra_source_support_strength` from `config/calibration.toml`, binds it as `$1`, and POSTs the distinct returned `claim_id` set to `/api/v1/graph/reconcile_sheaf`. A `--dry-run` mode reports the row count without writing. Not application code; one-time hygiene pass run by an operator after the engine-side change ships.

### 3. `alternative_of` combine rule

`crates/epigraph-ds/src/combination.rs` gains:

```rust
/// Reduce a set of mutually-exclusive supporter BBAs to a single representative
/// BBA via max-Bel/max-Pl on the projected belief interval toward `target`.
///
/// Used by CDST BP for alternative-set members: independence has failed, so
/// product-rule (Dempster) over-combines. Max-Pl is the "least restrictive
/// alternative" rule from regulatory/legal reasoning. Members are passed
/// post-discount (the caller applies source_strength discount first).
pub fn combine_alternative_set(
    bbas: &[MassFunction],
    target: &FocalElement,
) -> Result<MassFunction, DsError>;
```

Semantics: for each member i, compute `Bel_i = belief(m_i, target)`, `Pl_i = plausibility(m_i, target)`. Take `max_Bel = max_i Bel_i`, `max_Pl = max_i Pl_i`. Construct a fresh BBA on the same frame with:

- `m({target}) = max_Bel`
- `m(target ∪ complement(target)) = max_Pl − max_Bel`  (ignorance band)
- `m(complement(target)) = 1.0 − max_Pl`

Singletons (one-element groups) return the single member unchanged.

### 4. Engine integration

In `crates/epigraph-engine/src/cdst_bp.rs`, before combining the supporters of a target T:

1. Group T's incoming `supports` BBAs by `alternative_set` membership. The view's `alt_members` array drives membership. Unaffiliated supporters form singleton groups.
2. For each multi-member group, call `combine_alternative_set(group, target=T)` to reduce it to one BBA.
3. Dempster-combine the resulting per-group BBAs as today.

Overlapping alt sets resolve through the equivalence-class view's transitive closure — they collapse into one group. No special handling required.

### 5. Candidate-finder tool

MCP tool `mcp__epigraph__suggest_alternative_sets` and HTTP route `GET /api/v1/alternative_sets/suggest`:

- **Input:** optional `target_claim_id` filter, optional `min_pair_strength` (default 0.5).
- **Output:** ordered list of `(claim_a, claim_b, score, reason)` candidate pairs.
- **Heuristic v1:** A and B both `supports`-link to the same T, and `contradicts(A, B)` exists. `score = min(BetP_A, BetP_B)`. `reason = "contradicts edge between supporters of <T_id>"`.
- **No auto-creation.** Operator reviews and promotes by submitting an explicit `alternative_of` edge.

Tool exists in `crates/epigraph-mcp/src/tools/` and is wired into the scope map (`scope_map`) under `claims:read`.

## Testing

### Locality-discount

- **Unit.** `same_source_papers` on a synthetic two-paper four-claim graph. Truth table: same-paper pairs → true (regardless of which traversal path), cross-paper pairs → false, self-pairs → true.
- **Integration.** 19-supporter synthetic claim mirroring the NEMS shape. Each supporter has a BBA with `betp ≈ 0.68`. After locality-aware combine, target BetP lands in `[0.7, 0.85]`. Mirror setup with cross-source supporters keeps BetP near current (un-discounted) behavior. Both assertions adversarial — fails if defaults are tuned wrong, not just if the code is wrong.
- **Calibration canary.** `cargo test -p epigraph-engine intra_source_discount_calibration` reads the calibration values and asserts they're within the documented band. Trips if a future change moves the defaults without re-tuning the synthetic NEMS regression.

### `alternative_of` and max-Pl

- **`combine_alternative_set` unit tests** covering the three #141 regression cases:
  - Single-member set → returns input unchanged.
  - Two disjoint sets, two members each → each set combined separately, then product-aggregated with the others.
  - Mixed alt + independent supporters → `dempster(maxPl({A1,A2}), A3)` ≠ `dempster(A1,A2,A3)` (asserts the rule is actually being applied, not silently dropped to Dempster).
- **DB symmetric uniqueness.** Insert `alternative_of(A, B)` succeeds; inserting `alternative_of(B, A)` afterward returns a dedup hit (existing edge_id, `created=false`), not a duplicate row.
- **View transitive closure.** 3-cycle `(A↔B, B↔C)` produces `{A, B, C}` in each member's `alt_members`.
- **Engine.** Factor graph with alt set `{A1, A2}` both supporting T, plus independent A3 supporting T. Combined T BetP equals `dempster(maxPl({A1,A2}), A3)`, *not* `dempster(A1,A2,A3)`. Numeric tolerance via `(actual − expected).abs() < 1e-9`.

### Candidate-finder

- **Integration.** Three supporters of T; two linked by `contradicts`. Tool returns exactly one pair, with `score = min(BetP_A, BetP_B)`. No false positives for the third supporter.

## Out of scope

- Retroactive `supports → decomposes_to` retyping (the original #142 mechanism).
- Auto-promotion of suggested pairs to explicit edges.
- Alt-set semantics on `refutes`/`contradicts` (symmetric case follow-up).
- New BP engine.
- Locality discount on non-evidential edges (`derived_from`, `cites`, etc.) — those don't write BBAs today.

## Acceptance

- [ ] `alternative_of` accepted by `is_valid_relationship` and `POST /api/v1/edges`.
- [ ] Symmetric uniqueness index lands; duplicate-direction insert dedupes.
- [ ] `alternative_set` view returns transitive-closure equivalence classes.
- [ ] `same_source_papers(a, b)` Postgres function exists and passes its truth-table tests.
- [ ] `trigger_edge_ds_recomputation` writes locality-aware `source_strength` per the calibration values.
- [ ] `combine_alternative_set` lives in `epigraph-ds` with the three regression-case unit tests passing.
- [ ] CDST BP routes alt-set members through `combine_alternative_set` before Dempster, per integration test.
- [ ] `mcp__epigraph__suggest_alternative_sets` returns scored candidate pairs.
- [ ] Operator backfill script exists at `scripts/backfill_intra_source_discount.py`, dry-run mode reports the count of BBAs that would be updated.
- [ ] 19-supporter synthetic regression: locality-aware BetP lands in `[0.7, 0.85]`.
- [ ] `cargo sqlx prepare --workspace -- --tests` re-run if any `query!` macros change.
- [ ] `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` clean against `epigraph_db_repo_test`.

## Related

- `feedback_pignistic_not_bayesian.md` — `pignistic_prob` is the canonical decision measure
- `project_bp_cdst_primary.md` — CDST is the primary BP engine
- Spec 1 (`docs/superpowers/specs/2026-05-27-claims-belief-bounds-clamp-design.md`) — write-contract clamp, ships independently; this spec assumes that contract is honored
- Episcience `EdgeType` design — separates `Supports` (cross-source corroboration) from dependency edges; the locality-discount approach generalizes that distinction to a continuous reliability dial rather than a binary type swap
- `feedback_council_of_critics.md` — adversarial-test rule justifies the calibration-canary and the engine integration test asserting the rule is actually applied
