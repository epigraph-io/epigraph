# Provenance BBA Migration — sequencing plan

**Status: NOT RUN. Dry-run only until every gate below is signed off.**

Companion script: `scripts/migrate_provenance_bba.py`.

## What this migrates and why

Ingested claims carry a source-class confidence in `claims.truth_value` alone,
produced by `epigraph_engine::bayesian::calculate_initial_truth`:

```rust
let truth = 0.5 + base + diversity_bonus;
TruthValue::clamped(truth.min(0.85))   // Never start above 0.85
```

Textbook-ingested claims sit at exactly **0.85** (the cap) and raw pipeline output
at exactly **0.5** (zero evidence weight, zero count). That number is a bare
scalar: it has no representation in the DS layer at all. Sampled claims return
`source: "no_bbas"` in the canonical frame.

A bare scalar conflates two different statements — "85% likely true" and "credible
source, incomplete evidence". Dempster-Shafer separates them:

```
m({supported}) = 0.85      <- what the source asserts
m(Θ)           = 0.15      <- "high but not 1.0" IS the ignorance mass
```

Migrating provenance into a BBA buys four things:

1. **The default epistemic lens becomes meaningful.** Today it would be a no-op
   for most of the corpus, because most claims have no BBA to read.
2. **The 0.85 cap becomes principled.** It stops being a magic ceiling and becomes
   an ignorance floor: `m(Θ) >= 0.15` for any provenance-only claim. Nothing is
   ever certain from provenance alone.
3. **Edges combine instead of compete.** Today a `refutes` edge writes DS columns
   while provenance owns `truth_value` in a different column — backlog 14b98adc.
   As BBAs they combine under Dempster in one frame.
4. **It respects the existing appeal-to-authority guard.** `calculate_initial_truth`
   documents "Initial truth is based ONLY on evidence quality, NOT agent
   reputation." Source *class* (textbook vs blog) is evidence quality, which
   `effective_source_strength` already models. Agent reputation stays excluded.

## HARD GATES — none of this may run until all are satisfied

| # | Gate | Why | Status |
|---|------|-----|--------|
| G1 | `0183a294` deployed (BetP bounds) | The lens writes BetP into `truth_value` corpus-wide. An out-of-bounds BetP would be persisted for 476k claims. | merged in PR #462, **NOT deployed** |
| G2 | `696d3a1c` deployed (one frame owns the cache) | Until it lands, ANY recompute over a multi-frame claim reverts edge-derived belief. This migration CREATES a second frame for many claims, so running it first would *widen* that bug's blast radius. | fixed in `51780ce4`, **NOT merged, NOT deployed** |
| G3 | ~~Frame choice ratified~~ | DISSOLVED 2026-09-18 — multi-frame is intended, so the unit is a (claim, frame) pair and the operator names contexts via `--frame-ids`. | **closed** |
| G4 | Perspective library exists with non-null `source_reliability` | 100+ perspectives currently exist, every one with `source_reliability: null`, auto-minted per call. A null reliability makes the lens re-weighting a no-op, so migrating into it produces BBAs that no lens can discriminate. | **OPEN** |
| G5 | Dry-run reviewed on prod-sized counts | Population sizing must be read before writing, not after. | pending |
| G6 | Rehearsed on a restored snapshot | 476k rows; the rollback path must be exercised, not assumed. | pending |

**G2 is the one most likely to be skipped and most damaging if it is.** This
migration gives previously single-frame claims a second frame. Before `51780ce4`,
`recompute_beliefs` wrote the shared `claims.*` cache once per frame and let the
alphabetically last win — and `binary_truth` sorts first. Running this migration
on an unfixed deployment converts a latent bug into a corpus-wide one.

## G3 — DISSOLVED (2026-09-18)

This gate asked "which ONE frame gets the provenance BBA." Under multi-frame that
question is malformed, and the schema already said so: `claim_frames` is keyed
`PRIMARY KEY (claim_id, frame_id)`, and 3 claims in the corpus already carry more
than one frame.

A claim applies in many contexts, and a provenance prior is a statement about the
claim *in each of them*. So the unit of work is a **(claim, frame) pair**, not a
claim, and the operator names the contexts via `--frame-ids`.

Three consequences, all now implemented:

1. **The binary-only guard was wrong and is gone.** It refused any frame with
   `len(hypotheses) != 2`, justified as "mapping onto three hypotheses requires
   inventing a position on the third." That reasoning was incorrect — Θ *is* that
   position. `m({asserted}) = tv, m(Θ) = 1 - tv` generalizes to any arity, with Θ
   the full hypothesis set, so the residual stays ignorance rather than being spread
   across the other hypotheses as if the source had an opinion on them. Verified:
   a 2-hypothesis frame yields `{"0": 0.5, "0,1": 0.5}` and a 3-hypothesis frame
   `{"0": 0.5, "0,1,2": 0.5}`.

   What replaced it is the check that actually matters: the asserted index must
   EXIST in the frame. Writing mass against an index the frame does not define
   produces a BBA no reader can interpret.

2. **The hypothesis index is read from the claim's own assignment.**
   `claim_frames.hypothesis_index` is what the framed `get_belief` path resolves via
   `FrameRepository::get_claim_assignment`. Writing mass against any other index
   would produce a BBA the engine interprets as being about a different hypothesis.
   `--default-hypothesis-index` applies only where no assignment exists.

3. **The migration may create `claim_frames` rows**, and the rollback removes them —
   but only those it created, and only where no other writer's BBA has since come to
   depend on the assignment. Verified by constructing that race.

## G4 — the perspective problem

`list_perspectives` returns 100+ rows, every one named `edge_factor` or
`evidence_grounded`, every one with `source_reliability: null` and
`locality_reliability: null`, auto-minted seconds apart per agent per call.

`scoped_belief` re-weights BBAs by `source_reliability`. With it null everywhere,
the perspective half of the lens is an identity function.

This migration must NOT mint a perspective per claim — that would add hundreds of
thousands of junk rows and make the problem permanent. It requires ONE resolved
perspective per source class, with calibrated `source_reliability`, created before
the run and passed in by id. The script refuses to run without `--perspective-id`
and validates that its `source_reliability` is non-null.

This is also why the migration writes via SQL rather than `submit_ds_evidence`:
the tool's own path is what mints the junk perspectives.

## Phases

Each phase gates the next. Do not compress them.

**Phase 0 — census (read-only).**
`--dry-run` with no `--limit`. Produces population counts by source class and
truth_value band, the count already carrying a BBA in the target frame (which will
be skipped), and the count with `truth_value IS NULL`. Nothing is written.
*Exit criterion:* the numbers are understood and the skip population is explicable.

**Phase 1 — rehearsal on a restored snapshot.**
Run Phase 2 and Phase 4 end to end against a restored copy, never prod. Confirm the
rollback returns the corpus bit-identical.
*Exit criterion:* `--rollback` verified to restore exactly, with a row count match.

**Phase 2 — batched apply.**
`--execute --limit N --offset M`, smallest source class first. Every run appends to
a manifest JSONL. Stop after the first batch and re-read the census before
continuing.
*Exit criterion:* manifest line count equals reported writes for every batch.

**Phase 3 — recompute, ONLY after G2 is deployed.**
`recompute_beliefs` over the migrated population so the cached scalars reflect the
new BBAs. This is the step that is actively destructive on an unfixed deployment.
*Exit criterion:* spot-check that a claim with both a provenance BBA and a
`refutes` edge shows combined belief, not one or the other.

**Phase 4 — rollback drill on prod (rehearsed, not hypothetical).**
Confirm the manifest can still drive a rollback after Phase 3, or record explicitly
that Phase 3 makes rollback lossy and why that is acceptable.

## Rollback

Every written row is tagged `combination_method = 'provenance_migration_v1'`, which
no other writer uses. Rollback is therefore a scoped delete, and the manifest
records the exact `mass_functions.id` of each insert plus the claim's prior
`truth_value` / DS columns.

Rollback does NOT restore the cached DS scalars if Phase 3 has run — a recompute is
one-way. That is the reason Phase 3 is sequenced last and gated separately.

## What this migration deliberately does NOT do

- It does not write `claims.truth_value`. The existing provenance number is the
  INPUT, and is left untouched, so the migration is additive and the corpus reads
  identically until a recompute runs.
- It does not touch claims that already have a BBA in the target frame. Real
  evidence outranks a synthesized prior.
- It does not touch `is_current = false` claims, or host telemetry (per the
  embedding-policy carve-out in CLAUDE.md, telemetry claims are not semantic
  content).
- It does not create frames or perspectives. Both must pre-exist and be passed by
  id.
