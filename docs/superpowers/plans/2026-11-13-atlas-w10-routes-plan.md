# Atlas W10: the nested-level routes (kernel and Explorer BFF)

Backlog W10 083c97b9 (epic 8fa0282d). Stacked on `atlas/wave4-base` (W1 #802,
W2 #803, W3 #805, W10a #801, W4 #810, W6 #808, W7 #809, W8 #811, W11 #807).
Design: `docs/superpowers/specs/2026-11-12-atlas-nested-groups-and-subgraph-view-design.md`
(sections 5 and 6). No migration.

## What this item delivers

The serving half of the nested Atlas: kernel routes that read the PRECOMPUTED
level documents W2 stores (`atlas_map_levels`) on the viewer's stamped
connection, and Explorer BFF routes that proxy them with compression and cache
validators, plus the `/atlas` page's `data-atlas-maps` attribute, which
replaces the fixture preview's role for real data.

Not in scope, and said so in the PR:

- **Assembling full leaves.** The W6 and W7 plans name "W9/W10" as the caller
  that assembles a leaf from W3's node set, W7's edges and W6's positions.
  W10 serves what is stored; the stored leaves are W4's skeletons
  (`edges: []`, `outgoing: []`) until the nightly (W9) assembles them before
  `write_run`. Operator check: that hand-off is W9's.
- **Both hierarchies in one run.** `level_for_viewer` serves the latest
  finished run of a map whatever it holds, and W5 (links) is not in the base,
  so on prod a switch target 404s until a run carries both hierarchies. The
  tests seed both in one run.
- **Front-end use of the claim-to-leaf lookup.** The page renders its URL;
  `atlas.js` (W11) does not call it yet. A follow-up wires `findClaimLeaf`.

## Routes

Map segment `{map}`: `public`, or a team group's hyphenated id. Hierarchy:
`meaning` or `links`.

| Kernel (`epigraph-api`, `routes/atlas_maps.rs`) | What |
|---|---|
| `GET /api/v1/atlas/maps` | the maps the viewer can see: every map whose latest finished run its session can read (their team and community maps, and the public map), each with its label (the group's display name, or "Public map") |
| `GET /api/v1/atlas/maps/:map/themes` | each theme's per-map name, claim count and root level in each hierarchy, from the run's level-0 documents (`atlas_map_levels_theme_roots_idx`) |
| `GET /api/v1/atlas/maps/:map/:hierarchy/levels/:id` | one level: `AtlasMapRepository::level_for_viewer` (one indexed read), then `LevelDocument::for_viewer` with what the session can read |
| `GET /api/v1/atlas/maps/:map/:hierarchy/claims/:claim_id/leaf` | the leaf holding a claim the viewer can read, in the latest run (contract `atlas_claim_leaf` v1) |

| BFF (`services/explorer`, `bff/atlas_nested.rs`) | What |
|---|---|
| `GET /bff/atlas/maps/{key}/{hierarchy}/{id}` | the level proxy; `{key}` is the map's `data-atlas-maps` key (`public` or `team-<32 hex>`), so `level_url` is `/bff/atlas/maps/<key>/` |
| `GET /bff/atlas/claim-leaf/{key}/{hierarchy}/{claim_id}` | the claim-to-leaf proxy |
| `GET /atlas` | now renders `data-atlas-maps` (when the kernel lists at least one map) and `data-atlas-claim-leaf-url` |

## Rules

**Reads.** Every kernel read is on `AppState::read_as(&viewer)` with
`ViewerExtractor`, every statement spliced on the viewer, all SQL in a new
`epigraph-db` repo (`repos/atlas_serve.rs`, `AtlasServeRepository`), beside
W2's `AtlasMapRepository` (unchanged).

**Per-viewer filter.** A leaf is served through `for_viewer(readable)`, where
`readable` is one statement over the leaf's node ids by kind: claims and
evidence spliced on the viewer (their own row security), agents by existence
(the `agents` row is universally readable, migration 077). A group level is
served as stored.

**Staleness** (the standing authorization's default): a run whose
`nothing_left` is true is served even when `current` is false; a run where
something left the map is refused with the not-found body; no counter is
exposed (no epoch, no flag, in any body).

**One not-found body.** Every refusal of a level is
`ApiError::NotFound { entity: "atlas_level", id: <requested id> }`: an unknown
id, a non-member, a map or hierarchy segment that names nothing, a run where
something left, a stored document that is not v1 or names another map, level
or hierarchy (a builder fault: logged at error, answered as absent), and a leaf
with no claim left after `for_viewer`. The BFF answers each with the contract's
`bff_not_found` body. The map and theme routes answer absent and unreadable
maps with one `atlas_map` not-found body.

**Claim to leaf.** Narrowed by the claim's current theme within the run:
`claims.theme_id` (spliced, so an unreadable claim finds nothing), then the
run's leaves of that hierarchy and theme whose claim nodes contain the claim
(a primary-key prefix scan of the run's levels, filtered on `theme_id`, then a
containment test on that theme's leaves only). The route then serves the leaf
through the level path and answers only when the claim survives `for_viewer`.
No index is added; the scan needs prod measurement. A claim re-themed since the
run answers not-found until the next build.

**BFF caching and compression.**
- `Cache-Control: private, no-cache`, `Vary: Cookie`; never a shared cache.
- `ETag: W/"<run id>.<level id>.<16 hex of SHA-256 of the served bytes>"`:
  keyed on the run and the group as asked, plus a digest because `for_viewer`
  makes the bytes per viewer. Weak, because the encoding varies.
- A 304 comes only AFTER the kernel answered 200 for this viewer, so a revoked
  member gets the not-found body, never a 304.
- `tower_http::compression::CompressionLayer` (gzip and br) on the nested-level
  routes only. gzip at flate2's default level (the level the budget is measured
  at), br at a moderate quality, not 11.
- The kernel's bytes are served unchanged; the BFF decodes them with the mirror
  types only to check map, hierarchy and level against the request.

## The claim-to-leaf contract (v1)

`services/explorer/contract/atlas_claim_leaf/v1/schema.json`, mirroring
`atlas_maps`: `{schema_version: 1, claim_id, map_scope, map_group_id,
hierarchy, theme_id, level_id}`, closed; the kernel and BFF not-found bodies
as `$defs`. Rust: `epigraph_atlas_contract::ClaimLeaf` (producer) and
`check::check_claim_leaf_body`; the Explorer mirror in
`src/atlas_maps.rs` and checker `tests/common/atlas_claim_leaf.rs`. Request:
`GET <data-atlas-claim-leaf-url><map key>/<hierarchy>/<claim id>`.

## Tests

Kernel, `crates/epigraph-api/tests/atlas_maps_route_test.rs`
(`#[sqlx::test]`, fresh DB, `remote-cargo --db`). World: team A with member M
and stranger S (no team); team-A claims, public claims, an agent and evidence;
a team-A run with both hierarchies of one theme and the public run.

| Test | Proves | Mutation that must turn it red |
|---|---|---|
| `a_member_gets_the_team_level_and_it_passes_the_contract` | team case; `check_level_body` | serve another map's row |
| `a_non_member_gets_the_body_of_an_unknown_id` | non-member case; `check_not_found` + `assert_indistinguishable` | answer 403 for a non-member |
| `the_public_map_is_served_to_a_viewer_with_no_team` | public case | (route absent) |
| `the_switch_leads_to_the_other_hierarchy_of_the_same_theme` | the switch | (route ignores hierarchy) |
| `a_stale_run_with_nothing_left_is_served` | staleness default, arrival | serve only when `current` |
| `a_run_a_claim_left_is_refused_with_the_not_found_body` | staleness default, departure | drop the `nothing_left` refusal |
| `a_leaf_node_the_session_cannot_read_is_not_served` | `for_viewer` applied | skip `for_viewer` |
| `claim_to_leaf_returns_only_leaves_the_viewer_can_read` | claim to leaf | skip the claim-readability check |
| `the_largest_documents_are_served_within_budget` | payload sizes (`worst_case_group` re-scoped, a 100-node leaf of real rows) | (budget measured) |
| `maps_and_themes_list_only_what_the_viewer_reads` | maps and theme roots | list runs on the raw pool |

Explorer, `services/explorer/tests/atlas_nested.rs` (wiremock kernel):

| Test | Proves | Mutation |
|---|---|---|
| `the_atlas_page_carries_a_valid_map_list` | `check_atlas_maps_attr` on the rendered page; team maps first, public last | |
| `the_atlas_page_omits_the_map_list_when_the_kernel_lists_none` | today's behaviour when no run exists | |
| `the_level_proxy_serves_the_kernel_bytes_and_passes_the_contract` | `check_level_body`, bytes unchanged | |
| `a_level_is_compressed_within_budget_when_gzip_is_accepted` | `Content-Encoding: gzip`, received bytes <= 150,000, decoded body passes the contract | remove the layer |
| `a_level_is_private_and_revalidated_by_etag` | `private, no-cache`, 304 on a matching `If-None-Match` | |
| `a_revoked_member_gets_not_found_not_304` | 304 only after the kernel's 200 | answer 304 before the upstream call |
| `two_viewers_with_different_bodies_get_different_etags` | digest in the ETag | drop the digest |
| `a_kernel_not_found_is_the_bff_not_found_body_even_compressed` | `check_not_found(Bff)` with gzip accepted | |
| `a_body_for_another_level_is_refused` | the mirror check | |
| `claim_leaf_proxy_passes_its_contract` | `check_claim_leaf_body` | |

Each mutation is applied, the test run red, and the code restored; the results
go in the PR body.

## "Done when" (backlog 083c97b9)

- **Route tests cover the team, public and non-member cases:** kernel
  `a_member_gets_the_team_level...`, `the_public_map_is_served...`,
  `a_non_member_gets_the_body_of_an_unknown_id`; BFF level proxy tests.
- **Payload sizes stay in budget:** kernel `the_largest_documents_are_served_within_budget`
  (`check_level_body` measures gzip of the served bytes) and BFF
  `a_level_is_compressed_within_budget_when_gzip_is_accepted` (bytes on the wire).
- **The switch returns the other hierarchy's level for the same theme:** kernel
  `the_switch_leads_to_the_other_hierarchy_of_the_same_theme`.

## Cleanup

Remove the unused `futures` from `crates/epigraph-db/Cargo.toml` and the unused
`csv` from `crates/epigraph-cli/Cargo.toml`; `Cargo.lock` regenerated and
proven with `--locked`.

## Needs prod measurement

- The theme-roots read detoasts every level-0 document of a run (two per
  theme) to read its name, switch and child counts, once per `/atlas` load.
- The claim-to-leaf scan (the run's level keys, then one theme's leaves).
- Compressed sizes of real assembled leaves once W9 writes them.
