# Atlas W10a: the nested-level payload contract and fixtures (plan)

Backlog item W10a (8921ce49), epic 8fa0282d. Design:
`2026-11-12-atlas-nested-groups-and-subgraph-view-design.md` (§2, §6, §7).

W10a fixes the JSON document that one Atlas level serves, below a theme, so the
front end (W11) and the latency harness (W12) can be built before the backend
(W2, W4 to W10). It adds no route and no front-end code.

## 1. Where it lives, and why

| Piece | Path |
|---|---|
| JSON Schema v1 (the contract) | `services/explorer/contract/atlas_level/v1/schema.json` |
| Fixtures | `services/explorer/contract/atlas_level/v1/fixtures/*.json` |
| Kernel serde types, invariants, validator, generator | `crates/epigraph-atlas-contract` (new workspace member) |
| Explorer mirror types | `services/explorer/src/upstream/atlas_level.rs` |
| Explorer schema-test helper | `services/explorer/tests/common/atlas_contract.rs` |

- **One copy of the schema and the fixtures, under `services/explorer`.** The Explorer
  is a standalone crate. Its Docker build context and its local gate see only
  `services/explorer`, while the kernel's CI and builds see the whole tree. So the only
  place both sides can read without a copy is inside `services/explorer`. The files sit
  outside `static/`, so `build.rs` does not embed them in the binary.
- **Kernel types in a new small crate.** The W2 builder, the API routes (W10) and the
  CLI all need the document type, and none of them needs a JSON Schema validator. The
  crate always compiles the types, the invariant checks (`validate`), the producer's
  storage path that also measures the gzip budget (`to_stored_json`, hence `flate2`
  always) and the per-viewer filter (`for_viewer`). The JSON Schema validator
  (`jsonschema`) compiles only under the `check` feature or in the crate's own tests. The new crate also keeps W10a off W2's files (`epigraph-db`,
  `migrations/`).
- **The Explorer mirrors the types** (it cannot depend on a kernel crate). The two
  sides are tied together as follows:
  - The kernel generator writes the fixtures.
  - A kernel test fails if the committed fixtures differ from what the generator
    writes now.
  - The fixtures live under `services/explorer/**`, so any change to them triggers
    the Explorer CI.
  - In the Explorer, a round-trip test fails if the mirror drops or renames a field.

## 2. Data model (schema v1)

Every level document is a closed JSON object (no extra keys anywhere). Serialised
compact (`to_stored_json`), it is what W2 stores as `jsonb` next to a `schema_version`
column.

**Served filtered for the viewer** (design §5: "the serving path still filters by the
viewer (RLS)"). The kernel route reads the stored document and serves
`for_viewer(readable)`, where `readable` says which node ids the viewer's own session
can read (claims, agents and evidence; evidence has its own row security). From a
leaf it drops:
1. every unreadable node;
2. every edge with a dropped end;
3. every agent or evidence node left with no edge to a kept claim, since an isolated
   one would show where a hidden claim was;
4. dropped nodes from `outgoing[].sources`, and any `outgoing` entry left with none.

Counts and signs pass through as stored. With no claim left the answer is the
not-found body. Group levels carry no claim rows and are served as stored. Their
counts and names change only at the next rebuild, which the per-team epoch of
design §5 triggers. The BFF serves the kernel's answer as it comes.

**Assembled on the box.** The document holds claim text (`label`) and LLM names, so
it is assembled on the prod box. Off-box stages (design §2) produce only ids,
positions and weights.

**Envelope (both kinds):**
- `schema_version` (const `1`), `kind` (`group` | `leaf`).
- The map: `map_scope` (`team` | `public`) and `map_group_id`. The id is set for a
  team map and null for the public map.
- `hierarchy` (`meaning` | `links`), `theme_id`, `run_id`, `level_id`, `depth`.
- `name` (null until named) and `needs_naming`.
- `breadcrumbs`: the ancestors from the theme root down to the parent, each with its
  id, name and depth.
- `switch`: `{hierarchy, level_id}`, the counterpart level in the other hierarchy for
  the same theme. Which level that is (the best overlap, or the other hierarchy's root)
  is the builder's choice. The contract only requires that the other hierarchy differs
  from this level's.

**Group level** (`kind: "group"`):
- `children[]`: id, kind (`group` | `leaf`), name, needs_naming, `claim_count`, and a
  precomputed position `x, y, r` in the parent's unit circle.
- `bundles[]`: aggregated cross-group links, each with `source` (a child id), `target`
  (a level id), `count` and `net_sign` (-1, 0 or 1).
- `targets[]`: each target outside this group, listed once with its theme id, level id,
  name and depth.

**Leaf level** (`kind: "leaf"`):
- `nodes[]` (at most 100): `claim` (`truth_value`, and no belief value), `agent` or
  `evidence`.
  Each has an id, a label (at most 160 characters) and a precomputed `x, y` in
  [-1, 1].
- Every agent and evidence node has an edge to a claim of the leaf (design §7 step 3).
- `edges[]`: `source`, `target`, `relationship`, `sign`, `flow_weight` in [0, 1] and
  `flow_basis`. The endpoint kinds limit the basis (`FlowBasis::allows`), so a
  producer cannot drop a claim-to-claim flow by marking it `none`:
  - `exact`: an evidence-to-claim edge with a mass row the map's audience can read,
    from the stored mass;
  - `proxy`: every claim-to-claim edge, the link's strength × its sign and nothing
    else, which the view labels an estimate. `flow_weight` is strength × |sign| and
    `sign` the direction, so a `cites` edge (sign 0) weighs 0, and both the schema and
    `validate` reject a sign-0 proxy edge with any other weight. No belief factor of any
    kind enters it (see "No belief value" below);
  - `none`: no belief flow, so weight 0 and sign 0 whatever the relationship. Every
    other pair, such as an agent's authorship, and an evidence-to-claim edge that
    carries no mass the audience can read: no mass row the audience can read (the
    common case; §5), or a relationship with no belief direction (anything but
    `supports` or `refutes`, lower-cased). That evidence node still counts as
    attached to the claim. A claim-to-claim edge is never `none`, and evidence to
    claim never `proxy`.
- `sign` is the direction of the flow, so a `none` edge has sign 0 even when its
  relationship is `refutes`. The direction of evidence with no readable mass is in
  its relationship name only; the view reads it from there, not from `sign`.
- `relationship` matches `^[A-Za-z][A-Za-z0-9_]*$`, at most 32 characters. The
  `edges` table uses both casings (`AUTHORED` and `authored`, `SUPPORTS` and
  `supports`); builders serve the stored name lower-cased and collapse repeated rows
  on the lower-cased name. The pattern still admits upper case (some fixtures keep it
  on purpose), so the view compares names case-insensitively.
- The builder draws only edge rows the map's whole audience can read. An edge row has
  its own visibility and owner and co-owner groups, apart from its endpoints. The
  public map draws public rows only; a team map draws public rows and the rows that
  team owns with no co-owner. A co-owned row is readable only by members of both
  groups, so it is never drawn on a single team's map (a joint view for such viewers
  is later work). Two readable
  endpoints do not make a row readable, and a served edge carries no row id or
  visibility, so `for_viewer` cannot check this: it is a builder (W8) invariant, and
  no test in this crate can prove it.
- The `edges` table keeps one row per submission (migration 018), so a stored
  (source, target, relationship) can repeat. After the audience filter, the builder
  collapses rows sharing (source, target, lower-cased relationship) into one edge with the largest `flow_weight`: a resubmission is
  not more support. Filtering first matters, or an unreadable row's larger weight
  would win the collapse.
- `outgoing[]`: links leaving the leaf, aggregated by target group. Each has the
  target, `count`, `net_sign`, and the leaf nodes they leave from.

**Not found (non-member)**: one closed body per side, identical for "absent",
"unreadable" and "not a member":
- kernel: `{"error":"NotFound","message":"atlas_level with ID <id> not found","details":{"entity":"atlas_level","id":"<id>"}}`
- BFF: `{"error":"not_found","message":"We could not find that atlas level."}`

**No belief value in the payload:**
- The region and theme Atlas routes carry no belief key; colour comes from
  `truth_value`. The nested levels follow the same rule: a leaf claim node carries
  `truth_value` and no `betp`. Every object is closed, so a leaf carrying `betp`
  (a number or null) fails validation as an unknown key, on the schema and on the
  kernel types. (The Explorer mirror ignores unknown keys by its own rule, so on the
  BFF side the schema check in `check_level_body` is what rejects it.) The Explorer's banned-key list (`BELIEF_KEYS`, shared by
  `assert_no_belief_keys` on the existing routes and the contract tests) covers both.
- Proxy flow weights carry no belief either. A claim-to-claim `flow_weight` is the
  link's strength × its sign, with no BetP, belief, plausibility or `truth_value`
  factor of either claim, so a served weight can never be divided back into a belief.
  W7 reads no belief to compute it: the strength comes from the link's own edge row,
  never from a BBA or a belief fold. What keeps a weight to the map's audience is the
  W8 edge-row filter (only rows the audience can read are drawn, before the collapse),
  not a scoped belief read.
- `truth_value` stays, as the colour value only, so colour means the same at every
  level. It is not purely authored: writers that fold evidence also persist
  `truth_value = clamped(pignistic_prob)` as a mirror of the cache at write time
  (`crates/epigraph-cli/src/truth_mirror.rs`). The region and theme routes already
  serve it, so a leaf serving it adds no key and no value a member does not already
  see. The view never sorts, compares or folds it, and no flow weight is computed
  from it.

## 3. Budget

- Each level is at most 150,000 bytes as compact JSON, gzip-compressed (flate2 default
  level).
- The array and string caps in the schema keep the worst document they allow inside
  the budget when its text compresses at least as well as random Latin, Greek,
  Cyrillic and CJK characters. That document has every array at `maxItems` and every
  string at `maxLength` (`worst_case_multiscript_documents_are_in_budget`: leaf
  126,505 and group 115,056 gzip bytes, after the leaf lost `betp`).
- The caps do not guarantee the budget. The same leaf with random astral-plane text is
  valid by schema and types and is over budget
  (`astral_text_can_exceed_the_budget_and_storage_refuses_it`). A JSON Schema
  `maxLength` counts code points, so a byte cap in `validate` alone would split the
  contract. Instead the producer stores through `to_stored_json`, which measures, and
  `check_level_body` measures every served body.

## 4. Tests: how each "Done when" criterion is proven

| Criterion | Proof |
|---|---|
| A versioned schema | `schema.json` with `$id` `urn:epigraph:atlas-level:v1` and `schema_version` const 1. Test: `schema_is_versioned_and_self_valid`. |
| Fixtures for team, public and non-member | `team_theme_root`, `team_group_deep`, `team_leaf_dense`, `public_leaf`, `team_leaf_sparse_mass`, `non_member_kernel` and `non_member_bff`, from a seeded generator (SplitMix64, synthetic words and ids, no real data). Tests: `fixtures_are_current`, `every_fixture_validates`, `fixtures_cover_the_cases` (kernel); `every_fixture_passes_the_helper`, `the_fixtures_cover_team_and_public_maps_and_every_flow_basis` (explorer). |
| ≤ 150 KB compressed per level | `every_level_fixture_is_in_budget`, `worst_case_multiscript_documents_are_in_budget`, `a_document_over_budget_is_rejected`, `astral_text_can_exceed_the_budget_and_storage_refuses_it`, `stored_json_is_the_compact_fixture` (kernel); `the_fixtures_fit_the_budget`, `the_helper_rejects_a_body_over_budget` (explorer). |
| A schema test W10's real responses must pass | `epigraph_atlas_contract::check::{check_level_body, check_not_found, assert_indistinguishable}` (kernel, `check` feature), and the same functions in `tests/common/atlas_contract.rs` (explorer). `check_level_body` takes the request's `Expected` map and level, so a body for another map or level fails (`the_body_must_be_the_map_and_level_requested`, `the_helper_ties_the_body_to_the_request`). The Explorer helper ports every kernel invariant (`the_helper_enforces_every_kernel_invariant`) and compares numbers by value (`an_integer_float_passes_the_helper`). W10 calls them on the route bodies. |
| Served filtered for the viewer | `every_leaf_filtered_for_a_viewer_is_valid` (96 seeded readable subsets of the two leaves), `for_viewer_drops_what_would_show_a_hidden_claim` (kernel). |
| serde types ↔ schema | `schema_and_types_agree_on_every_mutation`: in small probe documents cut from the fixtures (both level kinds, both map scopes, every node kind and flow basis), at every key, drop it, add an unknown key beside it, and replace its value 7 ways; the schema's verdict must equal the strict serde and invariant verdict. Also `fixtures_round_trip_through_the_types` (kernel) and `the_mirror_round_trips_every_fixture` (explorer). |
| No belief value | `the_contract_carries_no_belief_value`, `a_leaf_claim_node_carrying_betp_is_rejected` (kernel); `no_schema_or_fixture_key_carries_belief`, `the_helper_rejects_betp_on_a_leaf_claim` (explorer). |
| No belief factor in proxy weights | `invariants_enforce_the_schema_rules` (a sign-0 proxy edge weighs 0, kernel and schema); `proxy_weights_are_link_strength_times_sign_only`, `proxy_weights_ignore_every_claim_value` (kernel, on the generator; §5). The builder-side invariance test belongs to W7. |
| Evidence with no readable mass | `an_evidence_edge_with_no_readable_mass_is_none` (every evidence edge of both leaves flipped to `none`: valid on the schema, the types and the served-body check, and `for_viewer` keeps exactly the readable evidence with a readable claim), `a_none_evidence_edge_with_a_weight_or_sign_is_rejected`, `fixtures_cover_the_cases` on `team_leaf_sparse_mass` (kernel); `the_helper_accepts_an_evidence_edge_with_no_readable_mass`, `a_fixture_has_evidence_with_no_readable_mass` (explorer). §5. |
| Negative cases | `extra_private_field_is_rejected`, `missing_flow_basis_is_rejected`, `non_member_body_leaks_no_shape`, `the_kernel_not_found_message_names_the_requested_id`, `invariants_catch_what_the_schema_cannot`, `invariants_enforce_the_schema_rules`, `flow_basis_is_limited_by_the_endpoint_kinds`, `a_none_evidence_edge_with_a_weight_or_sign_is_rejected`, `an_agent_or_evidence_node_with_no_claim_edge_is_rejected`, `relationship_names_in_both_casings_are_accepted` (kernel); `the_helper_rejects_an_extra_private_field`, `the_helper_rejects_an_edge_without_its_exact_or_proxy_flag`, `the_helper_rejects_a_dangling_reference`, `the_not_found_answer_leaks_no_shape` (explorer). |

Each new test is shown to fail on a mutated contract:
- a schema with no `additionalProperties: false`;
- `flow_basis` dropped from `required`;
- a kernel field added without regenerating the fixtures;
- a field dropped from the Explorer mirror;
- a cap raised past the budget.

## 5. Operator rulings 2026-11-13

- **No BetP on leaf claims until their evidence is filed.** A v1 leaf is drawn before
  the evidence behind each claim is filed as stored evidence-to-claim edges, so a
  served BetP would rest on evidence the leaf cannot show. Leaf claim nodes carry no
  `betp`, and a document carrying one fails validation. Adding it back is a later
  schema version, after the evidence-edge backfill lands. `schema_version` stays 1:
  this PR is unmerged, so v1 was never published.
- **Proxy flow weights carry no belief factor.** A claim-to-claim `flow_weight` is
  the link's strength × its sign only: no BetP, belief or `truth_value` of either
  claim, so a served weight can never be divided back into a belief. With the sign in
  its own field, `flow_weight` is strength × |sign|, so a `cites` link weighs 0.
  Evidence-to-claim edges keep their exact stored mass (`flow_basis` `exact`). This
  replaces design §2's "link strength × the source claim's BetP" and the same words in
  W7's backlog text. It also settles the question an earlier revision left open (a
  weight built as strength × BetP could be divided back into the BetP): there is no
  BetP in the weight to recover. The fixture generator follows the rule, and these
  contract checks pin it:
  - `validate` and the schema reject a proxy edge with sign 0 and a non-zero weight,
    so no document can serve a `cites` link carrying a value such as its source's
    belief (`invariants_enforce_the_schema_rules`).
  - `proxy_weights_are_link_strength_times_sign_only`: over the committed leaves and
    32 seeded ones, every proxy edge's sign matches its relationship, a `cites` link
    weighs exactly 0, and every other one a strength in (0, 1]. This pins the shape of
    the rule only: a belief factor that never reaches 0 (a missing belief defaulted to
    0.5, say) passes it.
  - `proxy_weights_ignore_every_claim_value`: the generator keeps a belief per claim
    that the leaf never serves (the value a builder could fold from the claim's BBAs).
    Two seeded leaves identical except for every claim's belief, or except for every
    claim's `truth_value`, have identical edges. Each value is set to 1 for every
    claim and to none for every claim, which moves both a factor such as
    `0.5 + 0.5 × belief` and one that defaults a missing belief.
  These see only what the generator holds per claim: a factor drawn from anywhere
  else passes them, and none of them can see a builder's source. No contract test
  can prove a real builder reads no belief, so W7 must carry the real invariance
  test: changing a source claim's BBAs, or its cached BetP, leaves its proxy weights
  unchanged.
- **Evidence draws only stored edges** (a ruling on the storage items, recorded here
  because the `exact` basis rests on it). There is no derived `evidence_for` edge: a
  leaf's evidence nodes and their edges come from stored evidence→claim edges. Making
  every evidence write path name a claim and write that edge, and backfilling existing
  evidence, is separate backlog (2d60f619). Most of those edges have no mass row keyed
  by their evidence, which the next ruling covers.
- **An evidence-to-claim edge with no readable mass is `none`** (a build decision taken
  under the operator's standing authorization, on W7's report in #809). W7 serves an
  evidence edge `exact` only when the map's audience can read a mass row keyed by that
  evidence on that claim, and `none` (weight 0, sign 0) otherwise; v1 refused the whole
  leaf for the second. Only a minority of today's evidence edges have such a row, and
  the evidence-edge backfill adds many with none, so this is the common case. The
  contract now accepts `exact` or `none` for evidence to claim (`FlowBasis::allows`;
  `for_kinds` keeps its signature and gives the basis when belief flows, which W7
  matches on). `none` still needs weight 0 and sign 0, claim to claim is still only
  `proxy`, and every other rule stands. The evidence node still counts as attached, in
  `validate` and in `for_viewer`. The Explorer helper (`basis_allowed`) and mirror
  follow. What the contract can no longer see: a builder that drops a readable mass
  and serves `none`. W7's known-mass test is that guard. The existing fixtures are
  unchanged; the tests flip their evidence edges in a copy. `schema_version` stays 1.
- **A `none` edge's sign is 0 whatever its relationship** (from #801's review). So a
  `refutes` evidence edge with no readable mass is served with sign 0, like a
  `supports` one, and its direction is only in the relationship name. The sign, basis
  and edge docs (kernel, schema, mirror) say so, and also give both reasons an
  evidence edge is `none`: no readable mass row, or a relationship with no belief
  direction (W7 serves the second as `none` too). Keeping a sign on such edges would
  need a new ruling.
- **A committed fixture with evidence served `none`**: `team_leaf_sparse_mass`, a new
  team leaf (40 claims, 6 agents, 16 evidence nodes). Every evidence edge is `none`
  except those of every fourth evidence node, which keep their exact mass: 38 `none`
  (31 `supports`, 7 `refutes`) against 12 `exact`. Some evidence is attached to its
  claims only through `none` edges. It is built from the same generator and then
  rewritten, so every other fixture is byte-identical. The view's tests (W11, W12)
  can load the common case from disk.
- **Two stale doc points fixed** (also from #809). Builders serve relationship names
  lower-cased and collapse on the lower-cased name; the pattern still admits upper
  case, so readers compare case-insensitively (§2). A co-owned edge row is readable
  only by members of both groups, so it is never drawn on a single team's map; a team
  map draws public rows and rows the team owns with no co-owner (§2).

How the first is proven: §4, row "No belief value". All four tests failed on the
contract before this change. Three mutation probes of the new code also go red:
- the Explorer mirror given `betp` back: `the_mirror_round_trips_every_fixture` and
  four other helper tests;
- the kernel claim node opened to unknown keys: `a_leaf_claim_node_carrying_betp_is_rejected`,
  `extra_private_field_is_rejected` and `schema_and_types_agree_on_every_mutation`;
- the schema given an optional `betp` property: all four new tests.

How the proxy-weight rule is proven (each probe restored afterwards):
- `proxy_weights_are_link_strength_times_sign_only` failed against the fixtures
  committed before this change (`team_leaf_dense /edges/124 (cites): a link with no
  direction weighs 0`).
- The generator's old formula put back (strength × a per-claim belief): the same
  test fails on the seeded leaves, on a `cites` link. A belief factor on directed
  links only fails it too (`weight 0 is not a strength in (0, 1]`, from a claim with
  no belief). Strength alone, sign ignored, fails it on a `cites` link.
- The weight multiplied by the source claim's `truth_value`:
  `proxy_weights_ignore_every_claim_value` fails (`/edges/70`).
- The weight multiplied by the source claim's belief with a non-zero default
  (`belief.unwrap_or(0.5)`), or by `0.5 + 0.5 × belief`: the rule test passes, and
  `proxy_weights_ignore_every_claim_value` fails on the belief variants. The old
  formula (`belief.unwrap_or(0.0)`) fails both. A factor drawn from outside the claim
  (a fresh random draw per link) passes both, as stated above.
- The `validate` rule for sign-0 proxy edges switched off, and separately the
  schema's matching clause: `invariants_enforce_the_schema_rules` fails each time.
- Keeping the per-claim belief draws where they were leaves every fixture
  byte-identical (`fixtures_are_current`).
- The regenerated fixtures equal the old ones, compared as parsed JSON, except for
  the `flow_weight` of proxy edges (421 in `team_leaf_dense`, 127 in `public_leaf`);
  the group and not-found fixtures are byte-identical.

How the evidence-edge rule is proven (each probe restored and touched afterwards):
- On the code before this change, all five new or changed tests fail: kernel
  `an_evidence_edge_with_no_readable_mass_is_none` (the types refuse the leaf),
  `a_none_evidence_edge_with_a_weight_or_sign_is_rejected` (a second, basis
  violation), `flow_basis_is_limited_by_the_endpoint_kinds` (no `Exact or None`);
  Explorer `the_helper_accepts_an_evidence_edge_with_no_readable_mass` and
  `the_helper_enforces_every_kernel_invariant`.
- Mutation probes on the new code, all red:
  - `allows` taking `none` for any pair: `flow_basis_is_limited_by_the_endpoint_kinds`
    (claim to claim `none` accepted) and `invariants_catch_what_the_schema_cannot`;
  - the `none` weight/sign check off in `validate`:
    `a_none_evidence_edge_with_a_weight_or_sign_is_rejected` and two older tests;
  - the schema's `none` clause off: the same kernel test and the Explorer accept test;
  - `validate` not counting a `none` evidence edge as attaching:
    `an_evidence_edge_with_no_readable_mass_is_none`;
  - `for_viewer` not counting it: the same test (its kept-iff-attached assertion);
  - the Explorer helper on the old rule, taking `none` for any pair, or not counting a
    `none` evidence edge as attaching: its accept test or invariant table, each time.
- The claim-to-claim and agent cases pass on the old code by design; the too-permissive
  `allows` probe is what proves them.

How the sparse-mass fixture is proven (each probe restored and touched afterwards):
- On the contract before the evidence-edge rule (kernel, schema, helper and mirror
  reverted, the new fixture kept), `every_fixture_validates`,
  `stored_json_is_the_compact_fixture`, `every_fixture_passes_the_helper` and
  `a_fixture_has_evidence_with_no_readable_mass` fail on it.
- Generator probes, each re-blessed in a scratch copy: no edge flipped (`0 none, 50
  exact`); `refutes` edges left `exact`; one `exact` edge kept on every evidence node.
  Each one fails `fixtures_cover_the_cases` and `a_fixture_has_evidence_with_no_readable_mass`.
