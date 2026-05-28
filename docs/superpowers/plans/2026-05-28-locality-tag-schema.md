# Plan: BBA locality tagging — stop inferring BBA typing from source_strength

Status: draft / in-flight
Issue: #197
Date: 2026-05-28
Supersedes nothing; complements the locality work in #185 / #192 / #193 / #195 / #196.

## The bug we're fixing

`mass_functions.source_strength` is doing double duty as both the
Shafer reliability discount weight AND an implicit label for what
kind of BBA this is (conversational / logical / empirical / ...).
The backfill script
(`scripts/backfill_intra_source_evidence_discount.py`) infers the
"kind" from the value-set: `{0.85, 0.75, 1.0, 0.6, 0.3}` is the
pre-composition tier list, post-composition is the same set times
the global `intra_evidence_locality_factor = 0.3`.

That works **except at tier 1.0**: `1.0 × 0.3 = 0.3`, and 0.3 is also
the conversational tier. After tonight's `--scope all --execute`,
310 BBAs moved from 1.0 → 0.3; a second `--scope all` dry-run can't
tell them apart from the 160 982 originally-conversational BBAs at
0.3 and would compose them again to 0.09. Over-discount on rerun.

Other collisions arise as soon as `intra_evidence_locality_factor`
shifts from 0.3 (e.g. a per-frame override): `0.6 × 0.5 = 0.3` would
collide. The general problem: a value-based identity for "what kind
of BBA is this" can never be stable under recalibration.

## The fix: store typing explicitly, compute weight dynamically

Stop mutating `source_strength`. Store BBA typing in dedicated
columns and compute the effective reliability at combine-time:

```
effective_source_strength(bba) =
    evidence_type_weight(bba.evidence_type)   ← calibration.toml
  * locality_factor(bba.locality_tag, bba.frame_id)  ← per-frame or global
```

Re-runs become trivially idempotent (tag either matches or doesn't);
recalibration is cheap (no DB rewrite); the conceptual model is
clean (typing vs weight).

## Phasing

### Phase 1a — additive schema + forward write path

**Goal:** new column exists, forward writes populate it, script becomes idempotent without changing combine semantics.

**Files to change:**
- `migrations/045_mass_functions_locality_tag.sql` (NEW)
  ```sql
  ALTER TABLE mass_functions
      ADD COLUMN locality_tag varchar(20) NOT NULL DEFAULT 'unknown';
  CREATE INDEX idx_mass_functions_locality_tag ON mass_functions(locality_tag);
  COMMENT ON COLUMN mass_functions.locality_tag IS
    'Locality classification of this BBA''s underlying evidence relative '
    'to its claim''s asserting paper. Values: intra (evidence cites the '
    'same paper that asserts the claim), cross (evidence is from a '
    'different paper), unknown (no evidence row attached, or pre-locality '
    'classification). Read at combine-time with evidence_type to compute '
    'effective source_strength dynamically. See issue #197.';
  ```
- `crates/epigraph-db/src/repos/mass_function.rs`:
  - `MassFunctionRow.locality_tag: String` field
  - All 8 `SELECT` lists in this file widened to include `locality_tag`
  - `store_with_perspective` signature gains `locality_tag: &str` parameter (default callers pass `"unknown"`)
- `crates/epigraph-engine/src/edge_factor.rs::wire_evidential_edge_factor`:
  - Already computes `is_intra`; pass `if is_intra { "intra" } else { "cross" }` to `store_with_perspective`
- `crates/epigraph-mcp/src/tools/ds_auto.rs` and `crates/epigraph-mcp/src/tools/ds.rs`:
  - Update the 4 `store_with_perspective` callsites to pass `"unknown"` (these paths don't have locality context)
- `crates/epigraph-api/src/routes/{assess.rs, belief.rs, experiment_loop.rs, hypothesis.rs}`:
  - Same — pass `"unknown"` for now
- `crates/epigraph-cli/src/bin/{hypothesis.rs, experiment.rs}`:
  - Same

**Tests:**
- `intra_source_discount_regression.rs` — assertions add: `locality_tag = 'intra'` on the 19 intra-supporter BBAs, `locality_tag = 'cross'` on the cross-source ones.
- `per_frame_locality_factor_override_applied.rs` — same assertion shape on the per-frame override fixture.
- New tiny test: `mass_function_locality_tag_roundtrip.rs` exercising `store_with_perspective("intra") → get_for_claim_frame → row.locality_tag == "intra"`.

**Out of scope for 1a:**
- Backfilling locality_tag for existing 280k rows (that's 1b)
- Changing the combine math to compute effective source_strength from tag (that's Phase 2)
- Script changes (also Phase 2)

### Phase 1b — backfill `locality_tag` for existing rows

**Goal:** populate the column for the 279 894 historical BBAs using
the same intra-source heuristic the discount script uses.

**One-shot SQL (operator):**
```sql
-- Mark as intra: BBA's claim has ≥1 evidence row whose doi matches
-- the paper asserting the claim.
UPDATE mass_functions mf
   SET locality_tag = 'intra'
 WHERE mf.locality_tag = 'unknown'
   AND EXISTS (
     SELECT 1 FROM evidence e
     JOIN edges ed ON ed.target_id = e.claim_id
                   AND ed.relationship = 'asserts'
                   AND ed.source_type = 'paper'
     JOIN papers p ON p.id = ed.source_id AND p.doi = e.properties->>'doi'
     WHERE e.claim_id = mf.claim_id AND e.properties ? 'doi'
   );

-- Mark as cross: BBA's claim has evidence rows but none intra-source.
UPDATE mass_functions mf
   SET locality_tag = 'cross'
 WHERE mf.locality_tag = 'unknown'
   AND EXISTS (SELECT 1 FROM evidence e WHERE e.claim_id = mf.claim_id);

-- Everything else stays 'unknown' (no evidence at all).
```

This recovers per-claim locality. Per-BBA (which would distinguish
the case where a claim has both intra and cross evidence and we
want to tag each BBA correctly) requires Phase 3.

**Validation:** counts should agree with current backfill audit —
intra ≈ {98 836 already-discounted + the ones that would have been
caught at scope all}, cross ≈ {pre-composition tiers with evidence
but no intra evidence}, unknown ≈ conversational tier.

### Phase 2 — switch combine to compute from tag

**Goal:** the combine path computes effective_source_strength from
`evidence_type + locality_tag + per-frame override`, not from the
stored `source_strength`.

**Files:**
- `crates/epigraph-engine/src/edge_factor.rs::recompute_combined_belief`:
  - Change `let reliability = row.source_strength.unwrap_or(1.0)`
    to `let reliability = effective_source_strength(&row, frame_id, &calibration)`
- New helper:
  ```rust
  fn effective_source_strength(
      row: &MassFunctionRow,
      frame_id: Uuid,
      calibration: &CalibrationConfig,
  ) -> f64 {
      let base = calibration
          .get_evidence_type_weight(row.evidence_type.as_deref().unwrap_or(""));
      let intra_factor = /* per-frame override or calibration global */;
      let locality_factor = match row.locality_tag.as_str() {
          "intra" => intra_factor,
          _ => 1.0,
      };
      base * locality_factor
  }
  ```
- `MassFunctionRepository::update_claim_belief` callsites — unchanged
  signature, but the values they compute use the new effective_source_strength.

**Backwards-compat concern:** existing 279 894 BBAs have `evidence_type IS NULL` for 278 633 of them. `get_evidence_type_weight("")` returns the fallback `0.5`. So switching the combine path naively would mean every legacy BBA uses 0.5 instead of its currently-stored `source_strength`. That's a behavior change for the 5202ded-era backfill.

**Mitigation:** the effective_source_strength helper should fall back to `row.source_strength.unwrap_or(weight)` when `evidence_type` is null AND `source_strength` is non-null. That preserves the historical-data semantics while letting newly-tagged rows use the dynamic computation.

After this, the script becomes a tag-writer:
```sql
UPDATE mass_functions SET locality_tag = 'intra' WHERE locality_tag = 'unknown' AND <intra predicate>;
```
No numeric mutation. Idempotency is trivial: `WHERE locality_tag = 'unknown'`.

### Phase 3 — `mass_functions.evidence_id` FK

**Goal:** locality fact becomes derivable from primary data — the
evidence row's `properties->>'doi'` vs the claim's asserting paper.
Stop denormalizing into `locality_tag`.

**Files:**
- `migrations/046_mass_functions_evidence_id.sql` — `ALTER TABLE
  mass_functions ADD COLUMN evidence_id uuid NULL REFERENCES
  evidence(id) ON DELETE SET NULL;`
- Forward write path: every BBA written from an evidence row (the
  `auto_wire_ds_update` path in `ds_auto.rs` and similar) sets
  `evidence_id`.
- Linking script (best-effort): for legacy BBAs, find the evidence
  row whose `evidence_type_weight` matches the BBA's stored
  `source_strength`. Tie-break on `created_at`. Ambiguous matches
  stay NULL.
- Combine path: when `evidence_id` is set, locality is derived from
  the evidence row's DOI vs claim's asserting paper. `locality_tag`
  remains as a cache for query performance and for BBAs where the
  link isn't recoverable.

**Independent of Phase 1/2** — could happen in either order. But the
linking heuristic is most useful AFTER Phase 1b has tagged
per-claim locality, because we can validate the per-evidence-row
linkage against the per-claim aggregate ("if claim is fully
intra-source, every linked evidence row should be intra-source").

### Phase 4 — per-frame `evidence_type_weights` override

**Goal:** let frames override individual evidence-type weights, not
just the locality factor. The Phase 2 helper currently does
`calibration.get_evidence_type_weight(row.evidence_type)` — a single
global lookup. Operators can already override `intra_evidence_locality_factor`
per frame via `frames.properties` (shipped in #193); Phase 4 extends
that pattern to evidence-type weights so e.g. a textbook frame can
say "observation evidence weighs 1.2 here, reference evidence weighs
0.6" while binary_truth keeps the SciFact calibration defaults.

**Schema:** no change. `frames.properties` JSONB (migration 044)
already carries the data; convention adds a key
`evidence_type_weights: { "<key>": <float>, ... }`.

**Helper change:** the Phase 2 `effective_source_strength` signature
gains a `per_frame_evidence_type_weights: Option<&serde_json::Value>`
parameter (or equivalent typed map). Lookup order for evidence-type
weight:

1. `frame.properties->>'evidence_type_weights'->>(row.evidence_type)`
   if the frame override is set for this key.
2. `calibration.get_evidence_type_weight(row.evidence_type)` (the
   existing global lookup, including alias resolution).
3. The 0.5 unknown-key fallback (which Phase 2 already routes
   through `source_strength` as the migration-compat axis — same
   behaviour applies in Phase 4).

**Operator interface:** `FrameRepository::set_property` (also
shipped in #193) suffices for write; readers use the new lookup
chain. Example:

```rust
FrameRepository::set_property(
    pool, textbook_frame_id, "evidence_type_weights",
    &json!({ "observation": 1.2, "reference": 0.6 }),
).await?;
```

**Test plan:**
- Unit test on the lookup chain: a frame with an override for
  `"observation"` returns the override; a frame without one returns
  the global; an unknown evidence_type falls through to legacy
  fallback.
- Integration test: an intra-source observation BBA on a frame
  whose `evidence_type_weights["observation"] = 1.5` gets effective
  source_strength `1.5 × intra_factor` instead of
  `1.0 × intra_factor`. Recalibration in either dimension flows
  through dynamically (same property as Phase 2 — no DB rewrite).

**Scope boundary:** Phase 4 is per-frame, NOT per-agent or
per-perspective. Per-agent overrides ("my prior on testimonial
evidence is lower than calibration default") and per-perspective
overrides would need a join table (`agent_evidence_type_weights`,
`perspective_evidence_type_weights`), not a JSONB override on
`frames`. Defer that to a separate design pass — the schema
question is real and shouldn't be folded into Phase 4 without
explicit demand.

**Out of scope (deferred as separate research track):** outcome-
driven recalibration. Learning the weights from later-validated
claim outcomes needs a loss signal (predicted vs realized BetP),
a residual ledger, and an optimizer (CMA-ES or genetic over the
discrete weight space — Dempster's rule is non-differentiable so
backprop doesn't drop in cleanly). That's a separate project; the
extension hook this plan creates (per-frame JSONB carrying weight
overrides) is the right substrate for an optimizer to eventually
write to, but the optimizer itself is its own design.

**Sequencing:** depends on Phase 2 (uses the helper extension
point). Independent of Phase 3 (locality detection from
`evidence_id` doesn't change weight resolution).

## Production state to track through the phases

| metric | now | after 1a | after 1b | after 2 | after 3 |
|---|---|---|---|---|---|
| `mass_functions` total | 279 894 | 279 894 | 279 894 | 279 894 | 279 894 |
| with `locality_tag = 'intra'` | n/a | (small, only new writes) | ~98 836 + scope-all candidates | same | same |
| with `locality_tag = 'cross'` | n/a | (small) | ~22 612 (the 0.85/1.0 remaining + others with non-intra evidence) | same | same |
| with `locality_tag = 'unknown'` | n/a (all) | 279 894 - new writes | ~158 446 (conversational) | same | same |
| with `evidence_id` set | n/a | n/a | n/a | n/a | best-effort heuristic |

## Dispatch order

1. **Phase 1a (in flight)** — schema + write path + tests. Subagent dispatched.
2. After 1a merges + deploys: run Phase 1b backfill SQL. ~1 hour total elapsed including review.
3. Phase 2 design review with you before code work begins — the
   evidence_type null-fallback + per-frame factor lookup integration
   has enough surface to deserve its own design pass.
4. Phase 3 deferred until Phase 2 lands.
5. Phase 4 depends on Phase 2 (extends the helper's lookup chain).
   Spec'd in a separate doc; design parallel-pass with Phase 2 review.
   Code lands after Phase 2.

## Tests for the in-flight phase 1a

- `intra_source_discount_regression.rs` — extend with locality_tag assertions
- `per_frame_locality_factor_override_applied.rs` — same
- `mass_function_locality_tag_roundtrip.rs` (NEW) — round-trip the column through `store_with_perspective` and `get_for_claim_frame`
- Existing tests for `recompute_claim_belief_binary` and friends — must continue to pass (math doesn't change in 1a; just data widens)
