# Atlas W7: flow weights for the leaf view (plan)

Backlog item W7 7a03f5e4 (epic 8fa0282d). Design:
`docs/superpowers/specs/2026-11-12-atlas-nested-groups-and-subgraph-view-design.md`
(§7 "flow weights"). Contract: the W10a level schema v1
(`crates/epigraph-atlas-contract`, `FlowBasis`, `Edge`).

Stacked on W3 (the leaf node sets, `AtlasLeafRepository`), which already
carries W2, plus W1 and W10a. W7 adds no migration.

## Operator rulings that shape this item

- **A claim-to-claim weight is the link's strength times its sign, and
  nothing else.** No belief value of either claim (BetP, belief,
  plausibility, `truth_value`, a BBA or a belief fold) enters it, so a served
  weight can never be divided back into a belief. This overrides the design
  doc's and the backlog text's "link strength × the source claim's BetP".
- **An evidence-to-claim weight is the exact stored mass.**
- **Leaves draw stored evidence-to-claim edges only** (no derived evidence
  edge); `supports`/`SUPPORTS` and `refutes`/`REFUTES` are both stored.
- **A map draws an edge only when its whole audience may read the edge row**
  (W3 applies this; a co-owned edge is on no single-team map).

## What this item delivers

A build-time function over W3's `LeafNodeSet` that returns the contract's
edge list (`epigraph_atlas_contract::Edge`), each edge with `sign`,
`flow_weight` and `flow_basis`. W10 assembles the level document from it.

## Files

| File | What |
|------|------|
| `crates/epigraph-db/src/repos/atlas_flow.rs` | the DB read, `AtlasFlowRepository::read_flow_inputs`: stored link strengths of the leaf's claim-to-claim edge rows, and the evidence-keyed mass rows behind its evidence-to-claim edges, both under the map's audience; the plain input type `FlowInputs` |
| `crates/epigraph-engine/src/atlas_flow.rs` | the pure weighting, `weigh_leaf_edges(&LeafNodeSet, &FlowInputs) -> Vec<Edge>`, the sign table, the strength fallback, the mass reading, and `build_leaf_flow_edges` (read then weigh); unit tests of the pure half |
| `crates/epigraph-engine/Cargo.toml` | depends on `epigraph-atlas-contract` (types and `validate`); the tests build the level envelope by hand, so no `check` feature is needed |
| `crates/epigraph-engine/tests/atlas_flow.rs` | DB tests, a fresh database per test (`#[sqlx::test]`, `remote-cargo --db`) |

The pure half lives in `epigraph-engine` because the strength fallback is the
belief engine's own per-relationship factor (`sheaf::restriction_kind`), and
`epigraph-db` cannot depend on the engine (the engine depends on it). All SQL
stays in `epigraph-db/src/repos`.

## Data model

### Sign (one explicit table, by the lower-cased relationship)

| sign | relationships |
|---|---|
| +1 | `supports`, `corroborates`, `elaborates`, `generalizes`, `specializes` |
| -1 | `contradicts`, `refutes` |
| 0 | everything else: `cites`, `qualifies`, the structural kinds (`decomposes_to`, `supersedes`, `derived_from`, authorship, ...) |

The table is NOT derived from `restriction_kind`: that function also maps
`informs` (positive) and `frame_validates` (frame evidence), which the item's
sign list does not name. `informs` stays at sign 0 here; whether it should
carry +1 is an operator question (see the report).

### Claim to claim (`flow_basis` = `proxy`)

`flow_weight = strength × |sign|`, where the strength of ONE stored edge row
is:

1. the row's own stored strength, `edges.properties.strength`, when it is a
   finite JSON number in [0, 1] (several writers store it: the git ingester,
   the workflow ingester, the reranker);
2. otherwise the belief engine's per-relationship transmission factor,
   `sheaf::restriction_kind(relationship)` (the scientific profile, which is
   what the edge-factor wire uses): `Positive(f)` and `Negative(f)` give `f`
   (supports and corroborates 0.80, elaborates and specializes 0.60,
   generalizes 0.50, refutes 0.80, contradicts 0.90). Any other kind has
   sign 0, so its strength never shows.

Not used: the SQL `edge_to_factor_type` (it gives contradicts and refutes a
forward strength of 0, a mutual-exclusion encoding, not a strength), the
`cdst_bel`/`cdst_pl` edge properties, and anything read from a claim or a
BBA. The read selects no claim column and no `mass_functions` row for a
claim-to-claim edge.

Several stored rows with one (source, target, relationship) were collapsed by
W3 after its audience filter; W7 takes the largest weight among their ids.
The strength read applies the same map edge predicate again, and a set edge
id the read does not return is an error, not a silent fallback.

### Evidence to claim (`flow_basis` = `exact`)

An evidence-to-claim edge is `exact` when BOTH hold:
- its lower-cased relationship is `supports` or `refutes`;
- at least one USABLE mass row exists: a `mass_functions` row with
  `evidence_id` = the evidence node and `claim_id` = the claim node, not
  retracted, readable by the map's audience, on a frame with exactly two
  hypotheses (the evidence BBA writer files on `binary_truth` or a
  two-hypothesis frame, and the belief fold reads exactly those frames).

**The exact mass of one row** is the row's stored mass on the singleton the
edge names: with `h` = the claim's hypothesis index on that frame
(`claim_frames.hypothesis_index` through `edge_factor::resolve_hypothesis_index`,
0 when absent), `m({h})` for `supports` and `m({1 − h})` for `refutes`. It is
the raw stored mass, with no `source_strength` discount (that discount is
computed at fold time, not stored). A mass value within 1e-9 of [0, 1] (the
tolerance `epigraph_ds::mass` allows a BBA's sum) is float residue: it reads
clamped into [0, 1], so a Θ of `-1e-17` does not void the row and a singleton
of `1 + 1e-12` serves as exactly 1. A value further out, or not a finite
number, makes the row unusable.

**Several rows from one evidence row on one claim** (another agent, a copy of
the BBA on a second frame) aggregate by the largest mass: a copy is not more
support, and a sum could leave [0, 1].

**Sign** is +1 for `supports`, -1 for `refutes`.

**No usable mass row, or another relationship:** `flow_basis` = `none`,
weight 0, sign 0. The contract FORBIDS this today: `FlowBasis::for_kinds`
(evidence, claim) is `exact`, and `validate_leaf`'s flow-basis check
(`crates/epigraph-atlas-contract/src/lib.rs`) rejects any other basis; the
schema's `flow_basis` description says the same. W7 does not fake a mass.
Reported to the operator; a test pins the exact violation.

This is not only legacy rows: the convention learn and forget routes write a
stored `evidence -SUPPORTS-> claim` / `-REFUTES->` edge and no evidence-keyed
mass row, and the leaf draws evidence-to-claim edges of every relationship.

**Recommended rule change (the contract's, not W7's):** the leaf validation
accepts `none` as well as `exact` for an evidence-to-claim edge, still with
weight 0 and sign 0 (the existing "no flow" check), and the schema's
`flow_basis` text says so. The alternative, W10 dropping such edges, does not
work on its own: the leaf validation counts an evidence node as anchored only
through an edge to a claim, so an evidence node whose only claim edge has no
mass would become an orphan and the leaf would still fail; dropping the node
as well hides evidence the audience may read. When the rule changes,
`an_evidence_edge_with_no_readable_mass_is_none_and_the_contract_refuses_it`
is the test that flips.

### Every other edge (`flow_basis` = `none`)

Weight 0, sign 0: authorship, the derived filer edge, evidence to agent, and
a stored `claim -> evidence` row (`derived_from` / `DERIVED_FROM`
provenance). Such a row is NOT re-oriented: it is a provenance link, and the
leaf draws stored evidence-to-claim edges only.

### Spelling and collapse

The served relationship is the stored name lower-cased. W3 collapsed on the
exact stored spelling, so `supports` and `SUPPORTS` between one pair are two
W3 edges; W7 collapses them again into one edge with the largest weight
(contract: one edge per (source, target, relationship)). Output is sorted by
(source, target, relationship).

### Audience (tenancy)

`mass_functions` rows carry their own `visibility` and `owner_group_id`
(inherited from the claim, or the writer's group for a row attached to a
public claim its writer could not write). The mass read applies the map
predicate to `mass_functions`, `frames` and `claim_frames` (`visibility =
'public' OR (visibility = 'group' AND owner_group_id = T)`, T NULL on the
public map) and splices the viewer on each, so the build on the maintenance
connection with a bypass viewer and a member's own session agree. A mass row
the audience cannot read never contributes; if it was the only one, the edge
is `none`.

The read runs on the build's snapshot transaction
(`AtlasMapRepository::begin_build_snapshot`).

## Tests

**Pure unit tests** (`atlas_flow::tests`, no database):
- the sign table, both spellings;
- the strength fallback equals `restriction_kind`'s factor and not
  `edge_to_factor_type`'s;
- a stored strength wins over the fallback; an out-of-range or non-number
  strength falls back;
- the largest weight among collapsed ids wins; lower-casing re-collapses;
- the exact mass: `h` = 1 on a binary frame, max over rows, a bad mass value
  is unusable;
- float residue within 1e-9 of [0, 1] is clamped, not a bad row; a value
  1e-6 out is still a bad row;
- no usable row and a non-supports/refutes evidence edge are `none`.

**DB tests** (`crates/epigraph-engine/tests/atlas_flow.rs`, fresh DB):
- `proxy_weights_do_not_move_when_any_belief_moves` (THE INVARIANCE TEST): a
  leaf with non-zero proxy weights from a stored strength and from the
  fallback, sign +1 and -1, built on the build snapshot. Then, on both
  endpoints of every proxy edge: the cached `belief`, `plausibility`,
  `pignistic_prob`, `truth_value` and `open_world_mass`, every claim BBA, and
  the edge-keyed BBA on the target (`perspective_id` = the edge id) with its
  `source_strength`, all changed. Rebuilt: the sorted proxy edges are equal
  bit for bit (`f64::to_bits`). Calibration: one evidence BBA was changed
  too, and its exact weight did move, so the rebuild re-read the rows.
- `exact_masses_on_a_fixture_with_known_bbas`;
- `a_mass_row_the_audience_cannot_read_does_not_contribute`;
- `every_weighted_edge_passes_contract_validation`;
- `contradicts_and_refutes_carry_negative_sign_and_the_engine_factor`;
- `cites_weighs_zero_even_with_a_stored_strength`;
- `both_spellings_collapse_into_one_lower_cased_edge`;
- `an_evidence_edge_with_no_readable_mass_is_none_and_the_contract_refuses_it`;
- `a_frame_or_hypothesis_index_the_audience_cannot_read_is_not_used` (added
  after the first probe run showed nothing seeded another team's frame or
  index row);
- `a_claim_link_row_the_map_cannot_read_is_an_error_not_a_strength` (added
  after review): the strength read on its own, handed a W3 leaf plus one
  extra claim-to-claim row id the map cannot read (another team's row, a row
  the map's team owns with a co-owner, a team's row on the public map). Each
  is `DbError::InvalidData`; the unmodified leaf and a readable extra id read.

**Fail on the old code.** Each mutation applied to the committed tree, the
unit tests and the DB target run (`--no-fail-fast`), then restored and
`touch`ed. 23 probes before review, 4 after (the last four rows), measured
on the branch:

| Mutation | Tests that went red |
|---|---|
| strength read × (0.5 + 0.5·source BetP) (never 0) | `proxy_weights_do_not_move_when_any_belief_moves`, `cites_weighs_zero_...` |
| the same, with the invariance test's calibration asserts deleted | `proxy_weights_do_not_move_...` at "a proxy weight moved with a belief" |
| × (0.5 + 0.5·target BetP), with and without calibration | the same two; without calibration, the invariance assertion |
| × source `truth_value` / 0.5 (exactly 1 on the fixture), with and without calibration | `proxy_weights_do_not_move_...` at the invariance assertion only |
| × (0.5 + 0.5·source belief) / 0.625 (exactly 1 on the fixture) | `proxy_weights_do_not_move_...` |
| × the edge-keyed BBA's `source_strength` / 0.5 | `proxy_weights_do_not_move_...`, `both_spellings_collapse_...` |
| `× |sign|` dropped | unit `a_proxy_weight_is_strength_times_abs_sign_...`; `cites_weighs_zero_...` |
| fallback gives opposing links 0 (the SQL factor table's value) | 3 unit; `contradicts_and_refutes_...`, `proxy_weights_do_not_move_...` |
| opposing links get sign +1 | 2 unit; `contradicts_and_refutes_...`, `proxy_weights_do_not_move_...` |
| mass read: `mass_functions` map predicate removed | `a_mass_row_the_audience_cannot_read_does_not_contribute` |
| mass read: `frames` map predicate removed | `a_frame_or_hypothesis_index_...` |
| mass read: `claim_frames` map predicate removed | `a_frame_or_hypothesis_index_...` |
| mass read: `retracted_at IS NULL` removed | `exact_masses_on_a_fixture_with_known_bbas` |
| frames of any size read (`< 2` instead of `!= 2`) | 2 unit; `exact_masses_...` |
| the claim's hypothesis index ignored | unit `the_exact_mass_reads_...`; `exact_masses_...` |
| several rows aggregate by min, not max | unit `evidence_edges_take_...`; `exact_masses_...`, `a_frame_or_hypothesis_index_...` |
| relationship not lower-cased | 3 unit; 4 DB tests incl. `every_weighted_edge_passes_contract_validation` |
| a re-collapse keeps the first edge, not the largest | `both_spellings_collapse_into_one_lower_cased_edge` |
| no usable mass gives `exact` with weight 0 (an invented mass) | unit `evidence_edges_take_...`; `a_mass_row_...`, `an_evidence_edge_with_no_readable_mass_...` |
| the stored strength ignored (fallback always) | 2 unit; `both_spellings_collapse_...`, `proxy_weights_do_not_move_...` |
| strength read: `co_owner_group_id IS NULL` dropped | before review: none (equivalent end to end, since W3 only hands the read ids it already filtered). After review: `a_claim_link_row_the_map_cannot_read_...` at the co-owned case |
| strength read: the whole edge predicate dropped | `a_claim_link_row_the_map_cannot_read_...` |
| exact mass: the old strict [0, 1] check (no residue tolerance) | unit `float_residue_is_a_mass_...` (residue on Θ voids the row) |
| exact mass: residue tolerated but not clamped | unit `float_residue_is_a_mass_...` (`1 + 1e-12` served) |

**Lints**: `no_unscoped_pool`, `visibility_lint`, `bba_retract_read_lint`,
`pool_read_lint`, `viewer_ratchet`, `no_role_blind_belief_reads`. W7 writes
no edge, so `edge_writer_signing_ratchet` is not affected.

## "Done when" → proof

| Criterion | Proof |
|---|---|
| every leaf edge carries a weight and an exact-or-proxy flag | **Blocked** for an evidence-to-claim edge with no usable mass (it is `none`, which the v1 contract refuses; see "Evidence to claim" for the rule to change). Met for every other edge: `every_weighted_edge_passes_contract_validation` (DB) seeds a mass for every evidence edge, so it does not cover the blocked case; `an_evidence_edge_with_no_readable_mass_is_none_and_the_contract_refuses_it` pins it |
| tests on a fixture with known masses | `exact_masses_on_a_fixture_with_known_bbas` (DB), the mass unit tests |
| contradicting and refuting links carry negative sign | `contradicts_and_refutes_carry_negative_sign_and_the_engine_factor` (DB) |
| (ruling) no belief factor in a proxy weight | `proxy_weights_do_not_move_when_any_belief_moves` (DB) and its mutation probes |
| (brief) a mass row the audience cannot read does not contribute | `a_mass_row_the_audience_cannot_read_does_not_contribute`, `a_frame_or_hypothesis_index_the_audience_cannot_read_is_not_used` (DB) |
| (brief) `cites` weighs 0 | `cites_weighs_zero_even_with_a_stored_strength` (DB) |

## Needs prod measurement (the orchestrator's)

- The share of evidence-to-claim edges with a readable, live, evidence-keyed
  BBA on a two-hypothesis frame (how many leaf evidence edges come out
  `none`).
- Whether any evidence-keyed BBA sits on a frame of three or more hypotheses.
- The range of `edges.properties.strength` on claim-to-claim edges, and which
  writers set it.
- The count of evidence-to-claim edges outside supports/refutes, and of
  `informs` and `challenges` claim-to-claim edges (both sign 0 today: not on
  the item's lists).
- The count of convention evidence edges (no evidence-keyed mass row).
- The count of evidence-keyed mass rows with any value more than 1e-9
  outside [0, 1] (each voids its row).
- The count of evidence-to-claim edges whose relationship disagrees with the
  singleton the BBA puts its mass on (served as `exact` weight near 0 with
  the edge's sign).
