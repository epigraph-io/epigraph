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
  crate always compiles the types and the invariant checks. The validator and the gzip
  budget check (`jsonschema`, `flate2`) compile only under the `check` feature or in the
  crate's own tests. The new crate also keeps W10a off W2's files (`epigraph-db`,
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
compact, it is what W2 stores as `jsonb` next to a `schema_version` column, and what
W10 serves.

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
- `nodes[]` (at most 100): `claim` (`truth_value`, `betp`), `agent` or `evidence`.
  Each has an id, a label (at most 160 characters) and a precomputed `x, y` in
  [-1, 1].
- `edges[]`: `source`, `target`, `relationship`, `sign`, `flow_weight` in [0, 1] and
  `flow_basis`:
  - `exact`: evidence to claim, from the stored mass;
  - `proxy`: claim to claim, strength × source BetP, which the view labels an
    estimate;
  - `none`: no belief flow, such as an agent's authorship, so weight 0 and sign 0.
- `outgoing[]`: links leaving the leaf, aggregated by target group. Each has the
  target, `count`, `net_sign`, and the leaf nodes they leave from.

**Not found (non-member)**: one closed body per side, identical for "absent",
"unreadable" and "not a member":
- kernel: `{"error":"NotFound","message":"atlas_level with ID <id> not found","details":{"entity":"atlas_level","id":"<id>"}}`
- BFF: `{"error":"not_found","message":"We could not find that atlas level."}`

**Belief in the payload (a deliberate departure, for the operator to check):**
- The P3a Atlas routes carry no belief key; colour comes from `truth_value`.
- Leaf claim nodes keep `truth_value`, so colour means the same thing at every
  level. They also carry `betp`, because design §2 and §4 compute the proxy flow
  from the source claim's BetP.

## 3. Budget

- Each level is at most 150,000 bytes as compact JSON, gzip-compressed (flate2 default
  level).
- The array and string caps in the schema are set so that the worst document they
  allow still fits. That document has every array at `maxItems` and every string at
  `maxLength`, filled with high-entropy text. So any document that passes the schema
  is in budget: the budget is checked, not assumed.

## 4. Tests: how each "Done when" criterion is proven

| Criterion | Proof |
|---|---|
| A versioned schema | `schema.json` with `$id` `urn:epigraph:atlas-level:v1` and `schema_version` const 1. Test: `schema_is_versioned_and_self_valid`. |
| Fixtures for team, public and non-member | `team_theme_root`, `team_group_deep`, `team_leaf_dense`, `public_leaf`, `non_member_kernel` and `non_member_bff`, from a seeded generator (SplitMix64, synthetic words and ids, no real data). Tests: `fixtures_are_current`, `every_fixture_validates`. |
| ≤ 150 KB compressed per level | `every_level_fixture_is_in_budget`, `worst_case_documents_the_schema_allows_are_in_budget` (kernel); `fixtures_fit_the_budget` (explorer). |
| A schema test W10's real responses must pass | `epigraph_atlas_contract::check::{check_level_body, check_not_found}` (kernel, `check` feature), and `tests/common/atlas_contract.rs` (explorer). W10 calls them on the route bodies. |
| serde types ↔ schema | `schema_and_types_agree_on_every_mutation`: in each fixture, at every object, drop each key and add one unknown key; the schema's verdict must equal the strict serde and invariant verdict. Also `fixtures_round_trip_through_the_types` in both crates. |
| Negative cases | `extra_private_field_is_rejected`, `missing_flow_basis_is_rejected`, `non_member_body_leaks_no_shape`, plus invariant tests (dangling edge endpoints, `exact` from a non-evidence node, a switch to the same hierarchy, 101 nodes). |

Each new test is shown to fail on a mutated contract:
- a schema with no `additionalProperties: false`;
- `flow_basis` dropped from `required`;
- a kernel field added without regenerating the fixtures;
- a field dropped from the Explorer mirror;
- a cap raised past the budget.
