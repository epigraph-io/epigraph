# Atlas W2: per-team layout storage and staleness (plan)

Backlog item W2 77f4bf09 (epic 8fa0282d). Design:
`docs/superpowers/specs/2026-11-12-atlas-nested-groups-and-subgraph-view-design.md`
(§2 "one layout per team", §5 "Invalidation", §7 "the storage shape").

## What this item delivers

Storage for the nested Atlas levels, one map per team group plus the public
map, with a per-map staleness epoch. It does not build the hierarchies (W4,
W5), lay out leaves (W6) or serve routes (W10). The level payload is an opaque
`jsonb` document whose schema W10a owns and versions; W2 stores
`schema_version` beside it and indexes only on the key columns.

## Files

| File | What |
|------|------|
| `migrations/210_atlas_team_layout.sql` | three tables, tenancy, RLS, the staleness trigger |
| `crates/epigraph-db/src/repos/atlas_map.rs` | `AtlasMapRepository`: write a run, put a level, finish a run, read a level for a viewer, read the epochs |
| `crates/epigraph-db/tests/atlas_map_repo.rs` | DB tests (fresh database per test) |
| the tier-A ratchets in `crates/epigraph-db/tests/` and `epigraph_api::state::FORCE_PROTECTED_SET`, `docs/runbooks/079-undo.sql` | the three new tables counted where every tier-A table is counted |

## Data model (migration 210)

A *map* is `(owner_group_id, visibility)`. A team map is `('group', T)` with T
a team or community group, which is 206's definition of a TEAM. The public map is
`('public', world group)`. Frames, contexts, perspectives and communities already
use the world group as the owner of instance-wide rows.

- `atlas_map_epochs (owner_group_id PK, visibility, n)`: the staleness counter
  of one map. Rows are created by the trigger on the first bump.
- `atlas_map_runs (id, owner_group_id, visibility, created_at, finished_at,
  algo, params, map_epoch, public_epoch, level_count)`: one nightly build of
  one map.
  - `map_epoch` and `public_epoch` are the two epochs the builder read in its
    snapshot.
  - A run is unfinished (`finished_at IS NULL`) while its levels are written.
    Readers take only finished runs, so a half-written run is never served.
- `atlas_map_levels (run_id, owner_group_id, visibility, hierarchy, group_id,
  parent_group_id, theme_id, level, schema_version, payload)`: one level
  document.
  - Primary key `(run_id, hierarchy, group_id)`: a level is one index probe.
  - The tenancy columns are pinned to the run's by a composite FK on
    `(run_id, owner_group_id, visibility)`.
  - `hierarchy IN ('meaning','links')`; `level >= 0`; parent is NULL exactly at
    level 0; `payload` is a JSON object.

All three tables carry 062's tier-A shape:
- `visibility IN ('public','group')`, an FK to groups, and `group_needs_real_group`;
- NOT NULL with no default, and 074's require-tenancy trigger;
- 115's owner-immutable guard plus a visibility guard;
- ENABLEd and FORCEd row security with the standard `<table>_tenancy` policy
  (read = public, or the owner group is in the session's read set), plus 115's
  restrictive `<table>_delete_owner`.

The application role holds SELECT only. The nightly writes on the maintenance
connection, and the trigger writes the epochs as a maintenance-owned definer.

## Staleness

A map's *readable set*:
- team T: the claims with `('group', T)`, plus public claims;
- public map: the public claims.

A team run is current while both the team's epoch and the public epoch equal
what the run recorded. Each epoch therefore tracks one half of the readable set.

A statement-level `AFTER UPDATE` trigger on `claims` uses transition tables,
beside 070's `claims_propagate_tenancy`; PostgreSQL shares the transition
tuplestore between the two.
- **Firing gate first.** It returns at once unless some row's signature changed.
  The signature is `'public'`, or `('group', owner)`.
- **Keys.** It collects the map keys of the old and new signatures of the
  changed rows: world for public, the owner for group.
- **Filter.** It keeps world plus team and community groups (personal and seed
  groups have no map). It upserts `n = n + 1` once per key, in key order.

So:
- **Moves.** A→B bumps A and B. P→A bumps A. A→P bumps A.
- **Publicize.** A claim of B going public bumps B and the public map.
- **Narrowing.** public→A bumps the public map and A.
- **Re-owned public row.** An owner change on a public row bumps nothing, since
  no readable set changed.
- **Bulk moves.** A bulk move is one bump per key per statement.

Out of scope, recorded for the operator:
- **Claim INSERT and DELETE** do not bump. New claims appear the next night
  (design §2, "Freshness").
- **Edges and evidence tenancy changes** do not bump. Edges follow their
  endpoint claims through 070's cascade in the same statement, whose claim keys
  bump. A direct edge re-tenancy is a residual.
- **Co-owners.** Claims have no co-owner. An edge co-owner narrows reading (an
  intersection), so the task's "if co-owners grant reading" does not apply.

197's `atlas_layout_epoch` and its triggers are untouched.

## Repo layer (`repos/atlas_map.rs`, all SQL there, non-macro `sqlx::query`)

- `map_epochs(conn, viewer, map) -> MapEpochs { map, public }`: one spliced
  statement. The builder makes it the first read of its REPEATABLE READ
  snapshot.
- `write_run(conn, &NewMapRun) -> run_id`: inserts an unfinished run. It refuses
  a team map whose group is not a team or community group.
- `put_level(conn, run_id, &LevelDoc)`: upserts one level into an unfinished
  run. It refuses on a finished or unknown run.
- `finish_run(conn, run_id)`: stamps `finished_at` and `level_count`.
- `level_for_viewer(conn, viewer, map, hierarchy, group_id) -> Option<MapLevel>`:
  - one statement on the caller's stamped connection, over the latest finished
    run of the map;
  - spliced on runs and levels, with RLS beneath;
  - carries `current` (both epochs unchanged).

## Tests (fresh database per test, `remote-cargo --db`)

| Done-when criterion / brief case | Test |
|------|------|
| migration + RLS: a non-member reads nothing of a team map | `a_non_member_reads_no_row_of_a_team_map` (app role, stamped `read_as`; raw table reads and the repo read) |
| public map stays readable (A1) | `the_public_map_is_read_by_an_unstamped_session` (downgraded `epigraph_app`, no GUCs) |
| a group move bumps exactly that team's epoch | `moving_a_claim_into_a_team_bumps_that_team_only`, `moving_a_claim_out_of_a_team_bumps_that_team_only`, `moving_a_claim_between_teams_bumps_both_and_no_other` |
| publicize | `publicize_bumps_the_source_team_and_the_public_map` (through `epigraph_publicize_claims` on a stamped admin transaction) |
| bulk | `a_thousand_row_move_bumps_each_epoch_once` (one UPDATE statement) |
| no false bumps | `a_tenancy_free_update_and_a_public_reowning_bump_nothing` |
| serving | `a_level_is_served_only_from_a_finished_run_and_goes_stale_on_a_move` |

The proof that each test fails on old code is a mutation table run once and
recorded in the PR:

| Mutation | Must fail |
|------|------|
| drop the trigger | the move tests |
| per-row bump | the 1,000-row test |
| new keys only | the out-of-A test |
| bump every map | the "no other" assertions |
| tenancy policy `USING (true)` | the non-member test |

The repo tests also run against the migration-210-less tree (all red).

Lints: `no_unscoped_pool`, `visibility_lint`, the tier-A ratchets
(`tenancy_required`, `tenancy_migration_shape`, `tenancy_coverage`,
`rls_enforcement`, `locked_decisions`, `owner_scoped_delete`,
`owner_scoped_update`, `elevation_arms_census`, `elevated_access`,
`app_role_table_lockdown`, `definer_search_path_ratchet`, `schema_contract`),
`atlas_layout_repo` (197 still works), `cargo check -p epigraph-api
--no-default-features --locked`, fmt, and clippy `-D warnings`.
