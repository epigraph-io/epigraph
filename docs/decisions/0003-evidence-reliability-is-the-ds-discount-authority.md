# 0003: Evidence-type reliability, not agent confidence, sets the Dempster-Shafer discount

- **Decided:** 2026-05-03 (stored value), 2026-05-28 (computed at combine time)
- **Recorded:** 2026-11-27 (retrospective)
- **Sources:**
  - commit 119e83d8a, `fix(ds): store evidence-type weight as
    source_strength, not agent confidence`, which is pull request #76
    (merged 2026-05-04). It is piece 2 of 3:
    - piece 1 is pull request #75, `feat(calibration): bridge DB evidence-type
      vocab to SciFact-calibrated weights`;
    - piece 3 is pull request #77, commit 5202deddc, `feat(scripts): backfill
      source_strength for legacy mass_function rows`.
  - commit 91153b66f, `feat(engine): effective_source_strength dynamic
    combine path (Phase 2 of #197)`, which is pull request #205 (merged
    2026-05-28);
  - spec `docs/superpowers/specs/2026-05-28-locality-aware-combine-spec.md`;
  - commit 7ed9d8a5d, `feat(belief): config-based two-tier reliability with
    per-perspective overrides`, which is pull request #208.

## Rule it grounds

No `CLAUDE.md` section states this rule. The code states it:

- `crates/epigraph-engine/src/edge_factor.rs`:
  `effective_source_strength` / `effective_source_strength_profiled`;
- the comments in `crates/epigraph-mcp/src/tools/ds_auto.rs` on the
  initial-cache writers: "Unify onto the SAME discount authority
  (`effective_source_strength`)", "the same discount authority every other
  writer uses" and "The shared invariant is the discount AUTHORITY";
- the module comment in `ds_auto.rs`: "Each BBA is Shafer-discounted by its
  `source_strength` before combination to prevent runaway confirmation (C2)
  and dilution attacks (C3)."

## Decision

- Before Dempster combination, each BBA's mass is discounted (Shafer's
  reliability discount).
- The reliability used for that discount comes from the evidence. It is the
  calibrated weight of the evidence type, later also the locality tag, a
  per-frame factor and the belief profile.
- It never comes from the confidence the agent expressed in the claim. That
  confidence is already in the shape of the BBA.

## Context

- Commit 119e83d8a and pull request #76: the auto-wire writers stored the
  caller's `confidence` as the BBA's `source_strength`. That mixed two
  quantities: how strongly the agent holds the proposition, and how reliable
  the class of evidence source is.
- A gap made things worse: when a legacy row had no `source_strength`, the
  combine step used a reliability of 1.0. With no discount, several
  mid-confidence supporters of a claim combined to a pignistic probability
  near 1. That was the "sheaf stuck" defect, bug #6.

## Reasoning (from the sources)

- **No double discount.** "The agent's confidence is already encoded in the
  BBA mass shape (`mass = confidence * weight`, clamped). Storing it again as
  source_strength caused the discount step to re-multiply by it,
  double-discounting low-confidence agents while leaving the intended
  evidence-type reliability unenforced." (commit 119e83d8a)
- **Fix the past rows too, not just new writes.** The three pull requests
  were one fix:
  - #75 mapped the database's evidence-type names onto the calibrated
    weights;
  - #76 corrected new writes;
  - #77 back-filled legacy rows that had no value.
  - Rows with evidence took the highest calibrated weight of their evidence
    types. Rows with none took an agent-only tier of 0.3 (commit 5202deddc).
- **Compute the discount, don't trust the stored value.** Pull request #205
  stopped reading the stored `source_strength` at combine time. It derives
  the discount from `evidence_type`, `locality_tag`, the per-frame factor and
  the calibration, so that "Recalibration (global or per-frame) now flows
  through to combined BetP with no DB rewrite."
  - The column was kept as a write-through cache and a fallback for legacy
    rows (spec, Goal 5; decision Q4 in #205).
- **One chain for both read paths.** Commit 7ed9d8a5d made framed
  `get_belief` and the perspective reads go through the same chain:
  - evidence-type weight times locality;
  - per-perspective overrides on top, with global calibration as the base.
  - Reason given: so that "a compute-on-read belief reproduces the recompute
    path".

## Not recorded

- Why Shafer's reliability discount, rather than another way to weight
  sources? None of these sources compare methods. The `discount` function
  has been in `epigraph-ds` since the initial public release (2026-04-15),
  so the choice is older than all of them.
- The calibrated weights themselves (`calibration.toml`) are justified by
  the SciFact calibration named in #75's title. The weights are not
  re-derived here.

## Later changes

- Commit 0627350b5 (2026-06-01, after the protocol) routed the two writers
  that build a new claim's initial cache through `effective_source_strength`.
  - Before that, one of them used no discount and the other discounted by
    `confidence`. The first `update_with_evidence` on an ingested claim
    therefore looked like a drop in belief.
  - This is the commit that names the helper "one discount authority".
- Commit 3db16f202 (2026-10-23) folds every stored BBA under a resolved
  `BeliefProfile`. `effective_source_strength_profiled` is the current
  entry point.
