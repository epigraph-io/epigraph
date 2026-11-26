# Belief readers: which belief value each reader uses

**Status:** Canonical (backlog 3c4ddac0, 2026-11-25)

A claim carries two independent belief stores:

- **`claims.truth_value`**: an authored scalar in `[0, 1]`, `NOT NULL`. `submit_claim` and
  `update_with_evidence` seed it from BetP, but `patch_claim`, `POST /api/v1/claims` and other
  writers set it directly. No Dempster-Shafer (DS) write path refreshes it.
- **The DS cache**: `claims.{belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing}`.
  These columns are `NULL` until a DS write (an evidence BBA, an epistemic edge, `recompute_beliefs`)
  combines a BBA onto the claim. The recompute writes them and leaves `truth_value` alone.

The two disagree once the first epistemic edge is wired. Each reader therefore has to choose one
of them, and the table below records that choice. Functions are cited as `path::function` so the
citations survive line drift.

## The no-DS fallback is a real BBA

When a reader needs an *interval* for a claim with no DS state, it uses the interval of the
**least-committed binary BBA whose pignistic probability is `truth_value`**. That BBA is the one
`epigraph-ds` `MassFunction::from_pignistic_prior` builds, which is also the shape `ds_auto` seeds
from `truth_value`:

| `t = truth_value` | BBA on {true, false} | Bel | Pl | BetP |
|---|---|---|---|---|
| `t > ½` | m(true) = 2t−1, m(Θ) = 2−2t | 2t−1 | 1 | t |
| `t = ½` | vacuous, m(Θ) = 1 | 0 | 1 | ½ |
| `t < ½` | m(false) = 1−2t, m(Θ) = 2t | 0 | 2t | t |
| `t = 1` | m(true) = 1 (dogmatic) | 1 | 1 | 1 |
| `t = 0` | m(false) = 1 (dogmatic) | 0 | 0 | 0 |

This is `crates/epigraph-engine/src/belief_query.rs::BeliefInterval::cached_from_truth`.

Before backlog 3c4ddac0 this fallback returned `{belief: t, plausibility: 1, pignistic_prob: t}`.
No BBA has that interval: on a binary frame BetP = Bel + (Pl − Bel)/2, so Bel = t with Pl = 1
implies BetP = (1+t)/2. The corrected fallback keeps **BetP = t** and **lowers Bel and Pl** for
every `t < 1`. For example, `t = 0.73` used to read `[0.73, 1]` and now reads `[0.46, 1]`, and
`t = 0.3` used to read `[0.3, 1]` and now reads `[0, 0.6]`.

Unlike the `ds_auto` seed, the read does not cap `t` to the profile's truth-seed bounds. That cap
exists so that a *stored* BBA does not absorb later evidence under Dempster's rule. Nothing is
combined on a read, and a cap would move BetP away from the `truth_value` the gates below compare.

## Who reads what

"Effective score" means `crates/epigraph-db/src/repos/claim.rs::EFFECTIVE_BELIEF_SCORE_SQL`:
`pignistic_prob` (else `belief`) when both `belief` and `plausibility` are non-NULL, else
`truth_value`. Because the no-DS fallback above has BetP = `truth_value`, every reader that
reports a BetP for a no-DS claim agrees with the effective score.

| Reader | Value used | No DS state |
|---|---|---|
| MCP `get_belief` with no `frame_id` (`epigraph-engine` `belief_query::get_belief_conn`, unframed branch) | the DS cache: Bel, Pl and BetP (BetP falls back to `belief` on old rows) | the least-committed interval above, still `source: "cached"` |
| MCP `get_belief` with `frame_id` (`belief_query::framed_belief`) | live Dempster combination of the frame's stored BBAs, each discounted by the resolved belief profile | `source: "no_bbas"`: Bel 0, Pl 1, BetP 1/n |
| MCP `get_belief` with a perspective lens (the `lensed_belief` response field of `epigraph-mcp` `tools/ds.rs::get_belief_in_mode`), and MCP `scoped_belief` with `scope_type: perspective` and a `frame_id` (`belief_query::get_perspective_belief_conn`) | the same combination re-discounted from the perspective | `no_bbas` interval, as above |
| MCP `scoped_belief` otherwise, REST `GET /api/v1/claims/:id/belief/scoped` (`ScopedBeliefRepository::get`) | the cached `scoped_beliefs` row for that scope | no row: MCP returns an error, REST returns `null` |
| REST `GET /api/v1/claims/:id/belief` (`epigraph-api` `routes/belief.rs::get_claim_belief`) | the raw DS cache columns (`ClaimRepository::get_belief_columns`) | every interval field `null`; **no** `truth_value` fallback |
| REST `GET /api/v1/claims/:id/pignistic` (`routes/belief.rs::get_pignistic`) | live combination over one frame | uniform `1/n` per hypothesis, Bel 0, Pl 1 |
| REST `GET /api/v1/claims/by-belief` (`ClaimRepository::list_by_belief_bounds`) | raw `belief >= min` and `plausibility <= max` | excluded (NULL compares false) |
| MCP `recall` `min_truth` gate (`epigraph-mcp` `tools/memory.rs::recall_post_embed`, through `ClaimRepository::effective_belief_batch`) | effective score | `truth_value` |
| MCP `recall_with_context` `min_truth` gate and per-hit / context-atom `belief_score` (`tools/recall.rs::recall_with_context_core`) | effective score | `truth_value` |
| MCP `traverse` `min_truth` gate (`tools/graph.rs::traverse`) | effective score | `truth_value` |
| engine recall (`epigraph-engine` `recall.rs::effective_beliefs`) | effective score | `truth_value` |
| MCP `query_claims` `min_truth` / `max_truth` filter and projection (`ClaimRepository::list_by_belief_range`) | effective score | `truth_value` |
| REST `POST /api/v1/reasoning/analyze` claim inputs (`routes/reasoning.rs::analyze`) | effective score | `truth_value` |
| method evidence strength (`epigraph-db` `repos/method.rs::MethodRepository::get_evidence_strength`, `avg_belief`) | `COALESCE(pignistic_prob, truth_value)` | `truth_value` |

## Known inconsistencies (not fixed here)

- **REST and MCP shape the no-DS claim differently.** `GET /api/v1/claims/:id/belief` returns
  `null` intervals, while the MCP unframed `get_belief` returns the reconstructed least-committed
  interval. Both are documented behaviour. A client that needs "has this claim been assessed by
  DS?" should use the REST nulls, or `mass_function_count`.
- **`MethodRepository::get_evidence_strength` has no both-columns guard.** It uses `COALESCE(pignistic_prob, truth_value)`
  instead of the effective score. A half-written DS row with `pignistic_prob` set but `belief` or
  `plausibility` NULL is therefore authoritative there and not in the gates.
