# Locality-aware backfill redesign

Status: draft / planning
Supersedes: Task 7 of `2026-05-27-locality-aware-discounting.md`
Date: 2026-05-27

## Why this exists

PR #185 shipped a working **forward** path for locality-aware
`source_strength` on evidential edges (`edge_factor::wire_evidential_edge_factor`
+ `same_source_papers` migration + `evidence_locality` calibration block +
regression test). New evidential BBAs written by that path carry the
calibrated intra/cross value automatically.

PR #185 also shipped a **backfill** script
(`scripts/backfill_intra_source_discount.py`) intended to discount the
historical population. **That script does not work against production**:

1. It joins `mass_functions` → `edges` via
   `mf.source_agent_id = e.source_id`. `mass_functions.source_agent_id`
   is FK to `agents.id`; for the claim→claim evidential edges that
   actually need discounting, `edges.source_id` is a claim UUID. The
   comparison is between two different entity domains and never matches.
2. PR #188 (the join fix) routed the join through
   `mf.perspective_id = e.id` filtered by `evidence_type = 'edge_factor'`.
   That join is correct for BBAs *written by the new `edge_factor` path*
   — but in production there are **zero** such BBAs at the moment, and
   the population we actually want to backfill (≈25k-100k BBAs depending
   on scope) is the **pre-`edge_factor`** historical population, which
   has no `perspective_id = edge_id` linkage at all.
3. The pre-#185 backfill that DID work in this codebase
   (`scripts/backfill_source_strength.py`, commit `5202ded`, 2026-05-03)
   joined `mass_functions` → **`evidence`** on `claim_id`. That is the
   schema bridge historical BBAs actually have. The locality script
   reached for `edges` instead — a vibe-coded mismatch with how the
   bulk-ingested data is shaped.

`scripts/backfill_intra_source_discount.py` is reverted in this branch.

## What still ships from #185 (do NOT revert)

- `migrations/041_same_source_papers_function.sql` — the
  `same_source_papers(uuid, uuid)` Postgres function. The new backfill
  will still use it; the forward write path already uses it.
- `calibration.toml` `[evidence_locality]` block.
- `crates/epigraph-engine/src/edge_factor.rs` locality-aware
  `source_strength` write logic and `intra_source_discount_regression`
  test.
- `crates/epigraph-db/tests/same_source_papers_truth_table.rs`.

These pieces are correctness-positive on their own — new evidential
edges get the right `source_strength`, and the discounting math is
validated by the 19-supporter regression. The only broken artifact was
the backfill script.

## Production population (snapshot 2026-05-27)

```
mass_functions total:                279 894
source_strength distribution:
  0.30    160 982   (5202ded backfill: "no evidence row" conversational tier)
  0.85     80 417   (5202ded backfill: reference / document / logical tier)
  0.75     14 848   (5202ded backfill: testimonial tier)
  1.00     10 714   (5202ded backfill: empirical tier OR original NULL→1.0)
  0.50      5 161
  ...
evidence rows total:                  75 303
  reference     51 054   (≈98% carry doi in properties)
  observation   15 547   (source = "epigraph-nano-mcp"; no doi)
  document       6 788
  testimony      1 530
  computation      384
intra-source signal:
  49 119 evidence rows carry properties->>'doi'
  48 144 of those (≈98%) match the asserting paper's doi on their claim
edge_factor BBAs:                            0   (new write path not exercised yet)
BBAs with perspective_id matching an edge:  59
```

## The actual schema bridge for historical BBAs

The pre-`edge_factor` population is keyed `mass_functions.claim_id →
evidence.claim_id`. To classify a historical BBA as intra-source we
need to look at the **claim's evidence rows**, not at any edge.

The strongest available intra-source signal is:

```
evidence.properties->>'doi'  ==  (the doi of the paper that asserts evidence.claim_id)
```

i.e. an evidence row whose cited paper IS the same paper that the
target claim was asserted from. ≈48k of ≈49k evidence rows with doi
satisfy this — papers nearly always cite themselves in their own
extracted-claim evidence rows. That is the signal `5202ded` had to
work with, and it is the signal the locality redesign should use.

## Predicate options (need a decision before writing the script)

Let `intra_signal(mf)` :=
`EXISTS (SELECT 1 FROM evidence e JOIN edges ed ON ed.target_id = e.claim_id AND
ed.relationship='asserts' AND ed.source_type='paper' JOIN papers p ON
p.id = ed.source_id AND p.doi = e.properties->>'doi' WHERE e.claim_id =
mf.claim_id AND e.properties ? 'doi')`.

| Predicate | BBAs | Notes |
|---|---|---|
| A — any intra-source evidence on claim, BBA ≠ 0.25 | 99 231 | over-discounts mixed-source claims |
| B — only intra-source evidence rows (no cross-source evidence on claim) | TBD | undercounts when claim has any cross-source citation |
| C — A AND BBA `source_strength = 0.85` only | 74 711 | scopes to the "reference/document/logical" tier — most numerous and most plausibly self-cited |
| D — A AND BBA `source_strength = 1.0` only | ~310 | scopes to "empirical" tier; tiny |
| E — A AND BBA `source_strength != 0.3` (skip already-conversational tier) | ~97k | most of A |
| F — per-evidence-row scoring: each BBA gets `min(evidence_type_weight)` over its intra-source evidence rows | needs schema change | requires `mass_function_evidence` join table or a `mass_functions.evidence_id` column |

A naïve `5202ded`-style heuristic doesn't preserve the "discount only
when intra-source" guarantee. Option F is the only one that truly
honors per-row provenance, and it requires a schema migration so each
BBA can point to its originating evidence row.

## Recommendation

**Option C** as the operator one-shot, with a follow-up design for
**Option F** if intra-source discounting is going to be a recurring
operation.

Rationale: Option C targets the `0.85` tier — these BBAs were written
by `5202ded` for `reference`/`document`/`logical` evidence types, and
those are the evidence types most likely to carry `properties->>'doi'`
self-references. Restricting to that tier avoids molesting the
`conversational` 0.3 population (which by construction has no
evidence anyway) and the `observation`/`empirical` populations
(which generally lack `doi`, so Option A's count is dominated by
the 0.85 tier regardless).

74 711 BBAs is more than the user's recalled ≈25k. The remaining gap
(≈25k vs ≈75k) is unexplained — either the user's number is from a
different snapshot, an earlier dry-run of a different predicate, or
intuition. Worth asking the user to confirm before committing to a
discount of this magnitude — it's a third of the 0.85 population and
will visibly move BetP on those claims.

## Implementation tasks (when the predicate is signed off)

1. **Write `scripts/backfill_intra_source_evidence_discount.py`**
   - Mirror `5202ded`'s structure (preview / `--execute` modes,
     evidence-table join, idempotent via `IS DISTINCT FROM intra`).
   - Predicate selectable via `--scope {all|0.85|1.0|...}` flag.
   - Collect affected `claim_id`s and POST to
     `/api/v1/graph/reconcile_sheaf` like the merged script did.

2. **Document scope limits in script docstring**: this is heuristic,
   not provenance-exact. It approximates "discount the per-paper
   self-citation tier" by joining on doi match. BBAs derived from
   evidence rows without doi (observation, computation) are NOT in
   scope.

3. **(Future) Schema track for Option F**: open a backlog claim for
   adding `mass_functions.evidence_id` (nullable FK to `evidence.id`)
   or a join table. Lets each BBA carry exact provenance so future
   re-calibrations can be applied per-row without heuristics. Mention
   in the script: "Re-running this is safe but cannot fix wrong
   discounts produced by mixed-source claims — see the schema-track
   backlog item for the long-term fix."

4. **Update `docs/superpowers/plans/2026-05-27-locality-aware-discounting.md`**
   to point at this redesign for Task 7. Don't rewrite the plan doc
   itself — it's the historical record of how #185 was developed.

## Open question for the user

- Confirm Option C is the right scope, or pick a different one.
- Is the recalled ≈25k a memory of running an earlier predicate, or
  estimated from intuition? If the former, can you point at the
  predicate so we can match it?
- Want the schema track (Option F prerequisite) opened as a backlog
  claim now, or defer?
