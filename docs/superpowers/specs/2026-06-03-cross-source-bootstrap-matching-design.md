# Cross-source matcher: renormalize the score by fired features

**Date:** 2026-06-03
**Status:** Design — approved, pending implementation plan
**Branch:** `feat/matcher-renormalize-fired-features`
**Backlog:** resolves `9b50c331` (score dilution); partially addresses `27bc9754` (provisional bands; final sweep → #239)

## Problem

The cross-source matcher's pair scorer (`scorer::score_pair`,
`crates/epigraph-engine/src/matching/scorer.rs`) computes a normalized weighted
average `score = Σ wᵢ·vᵢ / Σ wᵢ` over nine features, where the denominator sums
**all nine weights unconditionally**. For cross-source pairs the structural
features are ~0 by construction, so they dilute the score below the verifier
band and genuine restatements can never reach the LLM verifier.

### Evidence (2026-06-02 / 2026-06-03 live validation on the canonical `epigraph` DB)

- `match_candidates` holds 12,006 historical rows — **all** `status='rejected'`;
  0 ever `pending`, 0 ever `promoted`.
- Score distribution over those rows: min 0.202 / avg 0.310 / p95 0.450 /
  **max 0.502** — strictly below the deployed `mid = 0.60` band. The queue is
  structurally dead.
- A perfect-cosine cross-source pair (`embed_cosine = 1.0`, all structurals 0,
  neutral 0.5 belief/theme fallbacks) scores `raw = 0.35·1.0 + 0.10·0.5 +
  0.05·0.5 = 0.425` over `denom = 1.0` → **~0.425**. It mathematically cannot
  clear `mid`.

### Why this is the right scale to fix (data, not assumption)

Measured on real candidate claims (2026-06-03):

- **The `triples` table is globally empty** — 0 rows across 432,213 current
  claims. So `triple_overlap`, `entity_jaccard`, and `method_match` (uses
  `properties->>'method_id'`) are **always** zero / empty-union for every pair
  in production.
- On 170 *substantive* (len > 40, non-telemetry) high-cosine cross-source pairs:
  `nbhd_overlap` (clusters) and `citation_overlap` (cites edges) have **empty
  union** (0/170 — these candidate claims are unclustered / uncited);
  `graph_overlap` is positive on only 15/170; `belief_alignment` fires on
  22/170 (13%); `theme_proximity` fires on 0/170 (theme overhaul in progress).

So for cross-source pairs today, the only feature carrying signal is
`embed_cosine` (plus `belief_alignment` on ~13%). The other eight contribute ~0
to the numerator while still dividing it.

## Decision

Change the combiner to a **weighted average over only the features that produced
a real signal** ("fired"), renormalizing the denominator to the applicable
features. Apply it unconditionally to the single production scoring path
(`run_pipeline`, which is source-filtered → 100% cross-source today). No
separate `--bootstrap` flag.

### Goal (scoped)

**Unblock the verifier queue.** Get genuine cross-source pairs to actually reach
the LLM verifier (`status = pending`). The LLM verifier is the precision gate;
over-admitting at the scorer is acceptable. Rigorous band recalibration is
deferred to the #239 conformal-calibration owner. This is the smallest change
that makes the matcher observably work.

## Applicability semantics

`score = Σ (wᵢ · vᵢ)  for applicable i   /   Σ wᵢ  for applicable i`

"Applicable" is defined **per feature by its natural no-data / no-signal
sentinel** — deliberately *not* a blanket "drop all zeros", which would conflate
a genuine zero-overlap negative with missing data.

| Feature | Applicable when | On today's data |
|---|---|---|
| `embed_cosine` | **always** (`0.0`-on-NULL retained as deliberate suppression) | ~always carries signal |
| `triple_overlap` | Jaccard **union** non-empty | never (`triples` empty) → drops |
| `entity_jaccard` | Jaccard **union** non-empty | never (`triples` empty) → drops |
| `nbhd_overlap` | cluster union non-empty | ~never on candidate claims → drops |
| `citation_overlap` | cites-edge union non-empty | ~never on candidate claims → drops |
| `graph_overlap` | ≥1 common neighbor (value > 0) | 15/170 → mostly drops |
| `method_match` | both claims have a `method_id` | never → drops |
| `belief_alignment` | both claims have a mass function | ~13% → fires, can pull score down |
| `theme_proximity` | both claims themed | 0% now → drops |

**Why union-non-empty for the Jaccards, but value > 0 for `graph_overlap`:**
A Jaccard with a non-empty union but empty intersection (both claims have
triples, no shared ones) is a *genuine negative* and must stay in the
denominator — so applicability keys on the union, not the value. This preserves
"structurals-as-negatives" for a future intra-source path once `triples` is
populated. `graph_overlap` is different: it is not a Jaccard-with-explicit-union
but an Adamic-Adar similarity whose `0.0` *is* its "no shared neighbor"
sentinel, so value > 0 is the correct applicability test there.

On today's data both rules coincide for the structural features (all drop),
yielding cross-source `score ≈ embed_cosine` — exactly the bootstrap intent.

**`embed_cosine` is always applicable.** Its `0.0`-on-NULL is a *deliberate
suppression* (per the origin/main docstring — distinct from the neutral 0.5
fallbacks of `belief_alignment`/`theme_proximity`): a missing embedding on an
`is_current` non-telemetry claim violates the embedding invariant, so similarity
is suppressed rather than guessed. Keeping it always-in-denominator preserves
that intent — a NULL-embedding pair that happens to have a fired
`belief_alignment` still scores `belief·w / (w_embed + w_belief)`, which is low
(suppressed), rather than scoring on belief alone. Because its weight is always
present, `denom ≥ w_embed > 0` always holds.

**Guard (defensive):** `denom` can never be 0 given the above, but the combiner
still guards `denom == 0 → score = 0.0` rather than dividing by zero.

### Simulated result (170 substantive high-cosine pairs)

| | old | renormalized |
|---|---|---|
| avg score | 0.417 | **0.887** |
| max score | 0.502 | 1.000 |
| min score | — | 0.779 |
| clears `mid = 0.60` | **0** | 170 |
| clears `mid = 0.80` | 0 | 164 |

`new_min = 0.779` reflects `belief_alignment` correctly pulling down the ~13% of
pairs where stance data fired — the precision feature still works.

## Band reset (provisional, in-scope)

Renormalizing lifts the score scale (cross-source ≈ cosine), so the old
`mid = 0.60 / high = 0.85` now gate the wrong scale and **must** move with this
change. Set in `calibration.toml [matcher.bands]`:

- `mid = 0.80`
- `high = 1.01` (unreachable), with `auto_promote = off` → **100% of candidates
  route to the LLM verifier**; nothing auto-promotes blindly.

`mid = 0.80` is **grounded, not hand-picked**: resolved item `4a715300`
established "real corroboration clusters > 0.85 cosine; 0.70–0.79 is topical
noise." Since `score ≈ cosine` post-renormalization, `mid = 0.80` pre-filters
topical noise and routes the ≥0.80 band to the verifier. Validated: 164/170
genuine pairs clear it; topical 0.70–0.79 pairs fall below.

This is explicitly a **provisional bootstrap band**, a single knob. The rigorous
precision/recall sweep (item `27bc9754`) stays deferred to the #239 owner, who
re-derives `mid` on a labelled set via split-conformal recalibration.

## Implementation shape

The five SQL queries in `score_pair` already mostly compute the needed values;
the change is to **stop hiding "no data" behind `COALESCE(..., 0.0)`** and
surface it as `NULL` → `Option<f32>` / `Option<bool>` in Rust:

- **Query 1** (`embed_cosine`, `method_match`): leave `embed_cosine` unchanged
  (keep `COALESCE(..., 0.0)` — always applicable, deliberate suppression);
  return `NULL` `method_match` when either `method_id` is absent (vs `false` for
  present-but-unequal).
- **Query 2** (Jaccards): drop the outer `COALESCE(..., 0.0)` so an empty union
  (the `NULLIF(union_count, 0)` already produces `NULL`) surfaces as `NULL`
  (= not applicable). A non-empty union with empty intersection stays `0.0`
  (= applicable negative).
- **Query 3** (`graph_overlap`): `NULL` when the common-neighbor set is empty
  (drop the `COALESCE(..., 0.0)`); a positive Adamic-Adar value otherwise.
- **Query 4** (`belief_alignment`) and **Query 5** (`theme_proximity`):
  applicability is **already detectable** — the `(Some, Some)` arm and
  `tp_opt.is_some()` respectively. Keep the neutral 0.5 only for the reported
  feature value; exclude from scoring when not in the data-present arm.

`MatchFeatures` keeps reporting the raw feature values (for telemetry /
`match_candidates.features`); a parallel per-feature **applicable mask** drives
the combiner. No change to the blocker, verifier, policy, or pipeline control
flow.

## Scope & blast radius

`run_pipeline` (source-filtered) is the only production caller of `score_pair`;
the change touches the cross-source sweep alone.

**Latent tension (documented, not solved):** dropping structural zeros weakens
"structurals-as-negatives" for a *future* intra-source dedup path. This is
latent today because the structural tables are empty/sparse. The union-non-empty
rule for the Jaccards preserves the negative signal for when `triples` is
populated. Revisit when an intra-source profile with populated triples exists
(e.g. gate the zero-drop to cross-source pairs, or add a per-pair-class weight
profile).

## Testing

- **Unit** (`crates/epigraph-engine/tests/scorer_features.rs`):
  - cosine-only pair (no structure, no mass function, unthemed) → `score ≈
    embed_cosine`.
  - a fired structural (non-empty Jaccard union, even with 0 intersection)
    correctly re-enters the denominator and lowers the score.
  - opposite-stance `belief_alignment` (both mass functions, divergent BetP)
    pulls the score down.
  - NULL-embedding pair → `embed_cosine = 0.0` stays in the denominator →
    score is suppressed (≈0), never promotes — even if another feature fires.
- **Integration** (`pipeline`):
  - a synthetic cross-source restatement pair lands in `[mid, high)` and reaches
    the verifier.
  - a topical ~0.72-cosine pair stays below `mid` (dropped).

All new tests pass the council-of-critics bar (no tautologies, no mock-shaped
assertions). Pre-commit CI gate: `cargo fmt --check` + `cargo clippy
--workspace --locked -- -D warnings` + `cargo test`. If any `sqlx::query!`
macro changes, run `cargo sqlx prepare --workspace -- --tests` and commit
`.sqlx/`. (The current queries are dynamic `sqlx::query(...)`, not the macro
form, so offline prep may be unaffected — verify during implementation.)

## Backlog outcome

- `9b50c331` (score dilution) — **resolved** by this change.
- `27bc9754` (band starvation) — **partially**: provisional reachable bands set
  here; the final calibrated precision/recall sweep stays with #239.
- `4a715300` (resolved) — its cosine prior is now the band's evidence base.

Retire via `mcp__epigraph__resolve_backlog_item` per repo convention when the
PR merges and a sweep confirms a non-empty `pending` queue on live data.
