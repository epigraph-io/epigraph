# Atlas W11: the front end for the nested levels (plan)

Backlog item W11 (abfeb2e3), epic 8fa0282d. Design:
`2026-11-12-atlas-nested-groups-and-subgraph-view-design.md` (§2, §2a, §6). Built
against W10a's contract (`services/explorer/contract/atlas_level/v1/`), stacked on
`feat/atlas-w10a`. The real level routes (W10) do not exist yet, so this item also
adds an opt-in **fixture preview** that serves the nested levels from committed,
synthetic documents with no database and no kernel.

## 1. Files

| Piece | Path |
|---|---|
| Pure rendering rules (no DOM, loads under `node:test`) | `services/explorer/static/atlas_nested.js` |
| Canvas integration (levels, leaf graph, flows, switch, map picker, stubs) | `services/explorer/static/atlas.js`, `atlas.css`, `templates/atlas/atlas.html` |
| Preview page | `services/explorer/templates/atlas/preview.html` |
| Preview server (flag, loopback check, router, embedded store) | `services/explorer/src/atlas_preview.rs`, `src/main.rs` |
| Preview hierarchy generator | `crates/epigraph-atlas-contract/src/preview.rs` |
| Preview data (synthetic, not contract fixtures) | `services/explorer/contract/atlas_level/v1/preview/{manifest.json,levels.jsonl}` |
| JS tests | `services/explorer/js-tests/atlas_nested.test.cjs` (outside `static/`, which `build.rs` embeds and serves), run by `node --test` in `explorer.yml` |
| Rust tests | `services/explorer/tests/atlas_preview.rs`; kernel `src/tests.rs` (preview section) |

The v1 contract fixtures (`fixtures/`) are untouched; `fixtures_are_current` keeps
them byte-stable.

## 2. Data model

**Level documents** are the v1 contract, as served. The client keeps each document
as fetched (never trimmed or rewritten) in a bounded cache keyed by map and level id,
and derives scene nodes from it.

**What the contract does not define** (W10's hand-off): how a viewer lists the maps
they may pick, which level is a theme's root in each hierarchy, and where a level is
fetched from. The page takes all three from one shell attribute, `data-atlas-maps`,
now its own small contract, `services/explorer/contract/atlas_maps/v1/schema.json`
(Rust types `src/atlas_maps.rs`, checker `tests/common/atlas_maps.rs`):

```json
{"schema_version": 1,
 "maps": [{"key": "team", "scope": "team", "group_id": "<uuid>", "label": "…",
           "level_url": "/bff/…/team/",
           "themes": [{"theme_id": "<uuid>", "label": "… or null", "claim_count": 120,
                       "roots": {"meaning": "<level uuid>", "links": "<level uuid>"}}]}]}
```

A level is `GET <level_url><hierarchy>/<level id>`: the map, the hierarchy and the
level, because W2 stores a level per (run, hierarchy, group id) and finds the run by
map, and a group id need not be unique across maps or hierarchies. (The first
version had one page-wide `data-level-prefix` and fetched by id alone; review
finding 1.) The hierarchy is also in the client's cache key and in `levelProblem`.
The real `/atlas` page does not carry the attribute yet, so its regions and themes
behave exactly as today. The preview page builds it at render time. The client
fetches nothing else.

With a map list the picked map sets each theme's name and count, and a theme off the
map shows "Not on this map" and opens onto nothing, never the viewer's claim list
(`themeOnMap`, `themeOpens`). Geometry stays the layout's (`layoutValue`).

**Scene.** Nested levels live in the Atlas's one world, inside their theme's circle:
- a group child is a circle at `parent + (x, y) · parent.r`, radius `r · parent.r`;
- a leaf node sits at `leaf + (x, y) · 0.7 · leaf.r`, so the unit square fits the
  circle, and its position is used as served: no simulation, no settle.

A nested node loads its own document when it fills a third of the view, as regions
and themes already do (design §6). The zoom ceiling follows the smallest attached
nested node, so a deep leaf can be framed.

**Encoding** (`atlas_nested.js`, from `sign`, `flow_basis` and `flow_weight`,
never from the relationship name, except a `none` evidence edge's tone: see §5):
- width grows with `flow_weight`;
- `proxy` is dashed and listed in the legend as an estimate, while `exact` is solid;
- the sign sets the colour (support accent, opposing critical) and the particle
  direction (+1 source to target, -1 back out of the target, 0 none);
- a zero-weight edge (`cites`, authorship) is a hairline with no particles;
- claim fill is still `truth_value`; agents and evidence are outline shapes with no
  belief colour;
- `needs_naming` shows the neutral placeholder "Not yet named".

**Navigation.**
- Breadcrumbs come from the scene's parent chain: region, theme, groups, leaf.
- The switch goes to `switch.level_id`. The client fetches it and its breadcrumb
  ancestors in parallel, attaches the chain under the theme in the other hierarchy,
  and frames it.
- Clicking a sibling bundle flies to that child. Clicking a stub (a group bundle to an
  outside target, or a leaf's `outgoing`) does the same chain-attach for
  `{theme_id, level_id}`, in this or another theme, and flies there.
- The map picker resets the nested levels, renames and recounts the themes, and
  checks every fetched document's `map_scope`, `map_group_id` and `hierarchy`
  against the request.
- A search hit or `#c-` link into a nested theme lands on its leaf when that leaf
  has been fetched (`findClaimLeaf`), else frames the theme and says so; no
  stand-in node. A claim-to-leaf lookup is a W10 hand-off.

**Preview.**
- Start it with `epigraph-explorer --atlas-fixture-preview <port | loopback-ip:port>`.
- It refuses any address that is not an IP-literal loopback, it is off without the
  flag, and it logs a loud warning at start.
- It builds its own minimal router: health, static, the `/atlas/preview` page with a
  banner, and `/bff/atlas/preview/maps/{map}/{hierarchy}/{id}` (a level only under
  its own map and hierarchy). It mounts no upstream route, and its
  API URL points at a dead port.
- The data is embedded in the binary and served byte for byte. An unknown or
  malformed id gets the contract's BFF not-found body.
- The preview top level is one synthetic region holding the picked map's themes.

**Preview hierarchy** (kernel generator, seeded):
- Maps:
  - a team map (`FIXTURE_TEAM_GROUP_ID`) with two themes;
  - the public map with one of those themes.
- Each (map, theme, hierarchy) gets one tree of the same shape:
  - the theme root has 2 groups and 2 leaves;
  - each group has 1 subgroup and 1 leaf;
  - each subgroup has 2 leaves.
- One team leaf is a dense 100-node leaf.
- The switch pairs each level with its structural twin in the other hierarchy.
- Bundle targets and outgoing targets are real levels of the same map and hierarchy,
  including some in the other theme.

## 3. Tests

- **JS (`node:test`):**
  - weight to width is monotonic, and weight 0 gives the hairline;
  - proxy is dashed and exact is solid;
  - the four proxy/exact × support/oppose styles are distinguishable;
  - the sign sets the particle direction;
  - `cites` (sign 0, weight 0) draws no particles;
  - the switch target is the other hierarchy, and a same-hierarchy switch is refused;
  - placeholder naming;
  - leaf positions pass through unchanged;
  - the load threshold;
  - the map check;
  - the zoom ceiling covers the smallest node.
- **Rust preview (`tests/atlas_preview.rs`):**
  - off by default: `build_app` 404s the same id the preview router serves, and no
    flag gives no preview;
  - non-loopback binds are refused (`0.0.0.0`, `::`, a LAN IP, a hostname, port 0);
  - every manifest-reachable level is served byte-identical and passes
    `check_level_body` for its map;
  - an unknown id or a malformed id gets the contract's BFF not-found body;
  - the page carries the banner, the scripts with no inline script, and no upstream
    call.
- **Kernel:**
  - `preview_files_are_current` (blessed like the fixtures);
  - every preview document passes `check_level_body`, `validate()` and the budget;
  - every link resolves: breadcrumbs equal the real parent chain, each switch exists
    in the other hierarchy of the same map and theme, and every bundle, target and
    outgoing level exists in the same map.
- **Static safety:** the `tests/atlas.rs` bans (`innerHTML`, `.style.`, `.belief`, …)
  are extended to `atlas_nested.js`.

## 4. "Done when", and how each part is proven

| Criterion | Proof |
|---|---|
| Zoom from a region to a leaf and back | Preview: synthetic region, then theme, group, subgroup, leaf. The navigability tests plus the screenshot pass. In the real `/atlas`: **not provable until W10** supplies the maps and roots attribute and the level route. |
| Flip the switch | `switchTarget` JS tests and kernel `preview_links_resolve` (each switch lands on its twin in the other hierarchy) |
| Follow a cross-group link | JS stub tests and kernel `preview_links_resolve` (every target is a served level) |
| No client layout beyond a ≤ 300 ms settle | No settle at all: `leafPositions` passes positions through (JS test), and the leaf path never calls the force collide |
| Proxy marked estimate, opposing style, exact solid | JS style tests and the legend |
| Colour still means belief; regions and themes unchanged | Existing `tests/atlas.rs` pass unchanged; the real page has no `data-atlas-maps` |
| Preview impossible to enable by accident | Preview Rust tests (off by default, loopback only, banner) |

## 5. Operator rulings 2026-11-13

The level contract changed under this item, and the change was merged into this branch:

- Evidence with no readable mass is served on its evidence-to-claim edge as `flow_basis`
  `none`, with weight 0 and sign 0, whatever it says about the claim. That is the common case.
- Because its sign is 0, a reader takes such an edge's direction from its `relationship`.
- The contract adds a committed fixture, `team_leaf_sparse_mass`. Most of its evidence
  edges are `none`, among them 7 that refute and 31 that support.

What this item does about it:

- **Edge style.** For every exact or proxy edge, `flow_basis`, `sign` and `flow_weight`
  still drive the style. A `none` edge that `supports` takes the supporting tone, and one
  that `refutes` or `contradicts` (either casing) takes the opposing tone. It is drawn as a
  thin solid line with no particles and no arrow (`NO_MASS_WIDTH`, wider than a hairline so
  the colour reads, thinner than any flow), set apart from exact flows and dashed estimates.
  Any other `none` edge (an agent's authorship) stays a neutral hairline. `edgeStyle`
  carries the stroke alpha as well, so what a viewer sees is decided, and tested, in one place.
- **Legend.** The leaf legend gains "evidence, no stored mass". The side panel lists such an
  edge with "no stored mass" where a flow shows its weight.
- **Tests.** The node tests read the `none` edges from the committed `team_leaf_sparse_mass`
  fixture:
  - a refuting edge gets the opposing tone and no flow;
  - a supporting edge (including one spelled `SUPPORTS`) gets the supporting tone and no flow;
  - the massless line differs from exact flows (including an exact edge stored with weight 0)
    and from dashed estimates;
  - an exact edge is unchanged, and still follows its sign when its name disagrees.
  A Rust page test checks the legend entry and its stylesheet class.
- **Preview.** No preview leaf had a `none` evidence edge, so the generator now serves one
  team leaf (the second theme, the root's second leaf, and its twin in the other hierarchy)
  with the fixture's rule. Every evidence edge there is `none` except those of every fourth
  evidence node. The rule draws nothing from the seeded generator, so the other 76 preview
  levels and the v1 contract fixtures stay byte-identical. A contract test asserts that
  the preview holds such a leaf in each hierarchy, with supporting and refuting `none`
  edges among them. The existing tests still validate every preview payload.
