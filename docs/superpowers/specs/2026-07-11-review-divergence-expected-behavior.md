# Review-Divergence: Documenting Expected Behavior (2026-07-11)

## Status

Design note / policy documentation. No code change. Written to close backlog Part 10 Task 10.3
(the review-divergence cluster) per the plan's own recommendation: **document, don't backfill.**

## Problem

The `assessment-worker` scheduled task periodically flags claims where the global cached
Bayesian `pignistic_prob`/`truth_value` (accumulated via repeated `update_with_evidence` calls)
diverges by more than 0.15 from the same claim's frame-scoped Dempster-Shafer belief (computed via
`submit_ds_evidence` + `compare_methods`/`get_divergence`, usually under the `claim_validity` frame
with a named perspective like `preprint-computational` or `peer-reviewed-empirical`). As of
2026-07-09, 10 such `review-divergence`-labeled claims are open in the backlog.

## Finding: one root cause, not ten independent defects

Every one of the 10 flagged claims shares the identical mechanical cause: the Bayesian
`truth_value` track and the per-frame DS belief track are **two independently-weighted evidence
accumulators that are not required to converge**, and in every flagged case, one track has
accumulated substantially more evidentiary weight than the other at the time of the scan:

- The Bayesian side had typically absorbed **2-3+ rounds** of `update_with_evidence`
  (empirical/statistical/testimonial corroboration passes, e.g. citing arXiv sources), each of
  which nudges `truth_value` upward.
- The DS side, in the flagged cases, had absorbed only a **single `submit_ds_evidence` call**
  producing one BBA with substantial residual ignorance mass (often reliability 0.58-0.8, meaning
  0.2-0.42 mass stays on the full frame Θ rather than committing to a hypothesis). A single BBA
  with wide ignorance necessarily pulls its own pignistic probability toward 0.5, regardless of
  how confident the Bayesian side has become.

Sample (from the 2026-07-02 through 2026-07-08 scan batch; representative, not exhaustive):

| Claim | Global BetP (Bayesian) | Frame-scoped BetP (single DS BBA) | Delta |
|---|---|---|---|
| a7282fb8 (working memory) | 0.9225 | 0.4542 | 0.468 |
| b89edc07 (graph memory) | 0.9258 | 0.4583 | 0.4675 |
| f71e2ae5 (Zep temporal retrieval) | 0.9258 | 0.4583 | 0.4675 |
| 1ef3602e (Cs quasi-spin) | 0.9513 | 0.5363 | 0.415 |
| ad6467ef (graph structures necessity) | 0.852 | 0.496 | 0.356 |

`compare_methods` on several of these confirms the 6 standard combination methods agree closely
*with each other* (spread of ~0.05) but all diverge sharply from the plain Bayesian update path —
i.e. this is not a bug in any one combination method, it is a genuine two-track-weight mismatch.

## Decision: this divergence is EXPECTED on freshly-enriched claims, not a defect

Per this note, going forward:

1. **Bayesian `truth_value` and per-frame DS belief are two independent, intentionally separate
   tracks.** `truth_value` accumulates classical evidence-weighted updates (`update_with_evidence`);
   the frame-scoped DS belief accumulates typed Dempster-Shafer mass functions
   (`submit_ds_evidence`) scoped to a `(frame, perspective)` lens. There is no architectural
   requirement, and no code path, that keeps them numerically equal — see
   `docs/superpowers/specs/2026-06-03-perspective-lens-reads-design.md` §10, which explicitly
   scopes "making the default combine compute & cache per-perspective beliefs" as a separate,
   heavier, still-open item (tracked as Task 4.4 in the 2026-07-09 backlog plan; NOT resolved by
   this note).
2. **The >0.15 review-divergence threshold is a triage signal, not an error signal.** It correctly
   flags "these two tracks currently disagree" so a human or the assessment-worker can decide
   whether to (a) submit additional DS mass entries mirroring each `update_with_evidence` pass (to
   bring the DS side's evidentiary weight up to par), or (b) leave it — the disagreement is
   informative in itself (it shows how much the frame-scoped/perspective view still depends on a
   single evidence submission).
3. **Backfilling matching DS evidence for every future review-divergence hit does not scale.** Every
   claim enriched via both pathways will show this gap until the DS side independently accumulates
   comparable evidentiary weight through its own natural evidence-gathering process. Treating each
   occurrence as a bug to fix by force-backfilling DS mass would just be manufacturing DS evidence
   to make numbers match, which is worse than leaving the honest gap visible.

## Disposition of the 10 flagged claims (2026-07-09 batch)

- **f80f3ceb, 3fdb8a16** — both reference the now-superseded/refuted target `f8cf28d0` ("Belief
  propagation lag" claim). Per Task 10.3 Step 2: resolve as "divergence-mechanism evidence, target
  claim already retired" — do not reopen work on `f8cf28d0` itself.
- **The remaining 8** (531809cb, f57e5c9a, b071f0c7, 913ab001, aa5d4398, 4a822cef, 9aa2fd47,
  f97ed169) — resolve with the documented-divergence rationale in this note: the gap is expected
  given each claim's current DS-side evidentiary weight, not a defect requiring backfill.

All 10 resolutions are QUEUED (`resolve_backlog_item` is classifier-blocked this orchestrator
session; see `PENDING_RETIREMENTS.md` in the operator scratchpad) rather than fired directly.

## Non-goals

- This note does not change any combination math, any threshold, or any tool behavior.
- This note does not resolve Task 4.4 (default perspective-scoped belief) — that remains a
  separate, heavier, explicitly-deferred design question.
- Future review-divergence hits should still be scanned and individually assessed (a large delta
  can still occasionally indicate a genuine contradiction rather than a weight mismatch — e.g. if
  `compare_methods` shows the 6 DS combination methods themselves disagree sharply, that is a
  different, genuine-conflict signal, not the expected-divergence pattern described here).
