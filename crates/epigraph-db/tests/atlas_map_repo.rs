//! Per-team Atlas maps (migration 210, Atlas W2, backlog 77f4bf09): a
//! non-member's session reads nothing of a team map, the public map stays
//! readable by an unstamped session, and the staleness epochs move exactly for
//! the maps whose readable set a claim entered or left, once per statement.
//!
//! Every read that is about row security runs as `epigraph_app` (a stamped
//! `ScopedPool` or a downgraded pool with no GUCs): the `#[sqlx::test]` pool is
//! a BYPASSRLS superuser, on which no policy filters anything. Viewers are
//! resolved on the superuser pool first (`viewer_fixture::downgraded_pool`).
//! Moves that are not themselves under test run on the superuser pool as one
//! statement each, which is what the per-statement rule is about.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::BTreeMap;

use epigraph_db::repos::atlas_map::{
    AtlasHierarchy, AtlasMap, LevelDoc, MapEpochs, MapLevel, NewMapRun,
};
use epigraph_db::{
    AtlasMapRepository, ClaimRepository, DbError, ScopedPool, SessionGucMode, Viewer,
};
use sqlx::PgPool;
use uuid::Uuid;

const WORLD: Uuid = Uuid::nil();

/// A keyed TEAM group with no members.
async fn team(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, $2, 'did:epigraph:test-team:' || $1::text, $3, 'team')",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed team");
    id
}

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

async fn seed_theme(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ('atlas map theme') RETURNING id")
        .fetch_one(pool)
        .await
        .expect("seed theme")
}

/// Every epoch row, `owner_group_id -> n`, read on the superuser pool.
async fn epochs(pool: &PgPool) -> BTreeMap<Uuid, i64> {
    sqlx::query_as::<_, (Uuid, i64)>("SELECT owner_group_id, n FROM atlas_map_epochs")
        .fetch_all(pool)
        .await
        .expect("read epochs")
        .into_iter()
        .collect()
}

/// The maps whose epoch moved between two snapshots, and by how much (a row
/// that did not exist before counts from 0).
fn moved(before: &BTreeMap<Uuid, i64>, after: &BTreeMap<Uuid, i64>) -> BTreeMap<Uuid, i64> {
    after
        .iter()
        .filter_map(|(k, n)| {
            let d = n - before.get(k).copied().unwrap_or(0);
            (d != 0).then_some((*k, d))
        })
        .collect()
}

/// Re-tenant `ids` in ONE statement, on the superuser pool. A widening to
/// public is a fixture step here (the publicize test drives the real act), so
/// 074's declassification guard is opened for this transaction only.
async fn retenant(pool: &PgPool, ids: &[Uuid], visibility: &str, owner: Uuid) {
    let mut tx = pool.begin().await.expect("tx");
    sqlx::query("SELECT set_config('epigraph.allow_declassify', 'yes', true)")
        .execute(&mut *tx)
        .await
        .expect("open the declassification guard");
    let n =
        sqlx::query("UPDATE claims SET visibility = $2, owner_group_id = $3 WHERE id = ANY($1)")
            .bind(ids)
            .bind(visibility)
            .bind(owner)
            .execute(&mut *tx)
            .await
            .expect("re-tenant claims")
            .rows_affected();
    tx.commit().await.expect("commit");
    assert_eq!(n, ids.len() as u64, "every claim moved");
}

async fn app_scoped(pool: &PgPool) -> ScopedPool {
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

fn doc(theme: Uuid, group_id: Uuid, payload: serde_json::Value) -> LevelDoc {
    LevelDoc {
        hierarchy: AtlasHierarchy::Meaning,
        group_id,
        parent_group_id: None,
        theme_id: theme,
        level: 0,
        schema_version: 1,
        payload,
    }
}

/// Build and finish one run of `map` holding one level-0 document for
/// `group_id`, on the superuser pool (the nightly's maintenance stand-in), at
/// the epochs a build snapshot reads now. Returns the run id.
async fn build_map(pool: &PgPool, map: AtlasMap, theme: Uuid, group_id: Uuid) -> Uuid {
    let (_scoped, system) = fixture::bypass(pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let epochs = AtlasMapRepository::map_epochs(&mut conn, &system, map)
        .await
        .expect("map_epochs");
    let run = AtlasMapRepository::write_run(
        &mut conn,
        &NewMapRun {
            map,
            algo: "test-v1".into(),
            params: serde_json::json!({}),
            epochs,
        },
    )
    .await
    .expect("write_run");
    AtlasMapRepository::put_level(
        &mut conn,
        run,
        &doc(
            theme,
            group_id,
            serde_json::json!({"children": [], "map": format!("{map:?}")}),
        ),
    )
    .await
    .expect("put_level");
    AtlasMapRepository::finish_run(&mut conn, run)
        .await
        .expect("finish_run");
    run
}

async fn team_level(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    team: Uuid,
    hierarchy: AtlasHierarchy,
    group_id: Uuid,
) -> Option<MapLevel> {
    AtlasMapRepository::level_for_viewer(conn, viewer, AtlasMap::Team(team), hierarchy, group_id)
        .await
        .expect("level_for_viewer")
}

// ===========================================================================
// Reads: a team map is its members'; the public map is everyone's (A1)
// ===========================================================================

/// Two teams' maps and the public map; `m` is a member of A, `s` of nothing.
/// On `s`'s stamped `epigraph_app` session no row of A's map exists, through
/// the repo read or through raw SQL on any of the three tables, while `m`
/// reads it and both read the public map.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_reads_no_row_of_a_team_map(pool: PgPool) {
    let a = team(&pool, "team-a").await;
    let (m, m_home) = fixture::seed_agent_with_group(&pool, "map-member").await;
    let (s, _) = fixture::seed_agent_with_group(&pool, "map-stranger").await;
    add_member(&pool, a, m, "writer").await;
    // A bump creates A's epoch row, so the epochs table has an A row to hide.
    let c = fixture::seed_group_claim(&pool, m, m_home, "a draft").await;
    retenant(&pool, &[c], "group", a).await;
    assert!(
        epochs(&pool).await.contains_key(&a),
        "calibration: A has an epoch row"
    );

    let theme = seed_theme(&pool).await;
    let ga = Uuid::new_v4();
    let gp = Uuid::new_v4();
    build_map(&pool, AtlasMap::Team(a), theme, ga).await;
    build_map(&pool, AtlasMap::Public, theme, gp).await;

    let scoped = app_scoped(&pool).await;
    let mv = Viewer::resolve(&pool, m).await.expect("member viewer");
    let sv = Viewer::resolve(&pool, s).await.expect("stranger viewer");

    for (v, member) in [(&mv, true), (&sv, false)] {
        let mut read = scoped.read_as(v).await.expect("stamped read");
        for table in ["atlas_map_runs", "atlas_map_levels", "atlas_map_epochs"] {
            let n: i64 = sqlx::query_scalar(&format!(
                "SELECT count(*) FROM {table} WHERE owner_group_id = $1"
            ))
            .bind(a)
            .fetch_one(&mut *read)
            .await
            .expect("raw read");
            assert_eq!(
                n > 0,
                member,
                "{table}: member={member} reads {n} rows of A's map"
            );
        }
        let team_level = AtlasMapRepository::level_for_viewer(
            &mut read,
            v,
            AtlasMap::Team(a),
            AtlasHierarchy::Meaning,
            ga,
        )
        .await
        .expect("level_for_viewer");
        assert_eq!(
            team_level.is_some(),
            member,
            "repo read of A's level, member={member}"
        );
        let public_level = AtlasMapRepository::level_for_viewer(
            &mut read,
            v,
            AtlasMap::Public,
            AtlasHierarchy::Meaning,
            gp,
        )
        .await
        .expect("level_for_viewer public");
        assert!(public_level.is_some(), "everyone reads the public map");
        let ep = AtlasMapRepository::map_epochs(&mut read, v, AtlasMap::Team(a))
            .await
            .expect("map_epochs");
        assert_eq!(ep.map > 0, member, "A's epoch is A's members' to read");
        read.commit().await.expect("close read");
    }
}

/// Rule A1: an `epigraph_app` session with no GUCs at all reads the public
/// map's rows and none of a team's.
#[sqlx::test(migrations = "../../migrations")]
async fn the_public_map_is_read_by_an_unstamped_session(pool: PgPool) {
    let a = team(&pool, "team-a").await;
    let theme = seed_theme(&pool).await;
    let gp = Uuid::new_v4();
    let public_run = build_map(&pool, AtlasMap::Public, theme, gp).await;
    let team_run = build_map(&pool, AtlasMap::Team(a), theme, Uuid::new_v4()).await;

    let plain = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let runs: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM atlas_map_runs ORDER BY id")
        .fetch_all(&plain)
        .await
        .expect("unstamped runs");
    assert_eq!(
        runs,
        vec![public_run],
        "unstamped: the public run only, not {team_run}"
    );
    let levels: Vec<Uuid> = sqlx::query_scalar("SELECT run_id FROM atlas_map_levels")
        .fetch_all(&plain)
        .await
        .expect("unstamped levels");
    assert_eq!(levels, vec![public_run]);

    let public_viewer = fixture::public_viewer(&pool).await;
    let mut conn = plain.acquire().await.expect("acquire");
    let level = AtlasMapRepository::level_for_viewer(
        &mut conn,
        &public_viewer,
        AtlasMap::Public,
        AtlasHierarchy::Meaning,
        gp,
    )
    .await
    .expect("level_for_viewer")
    .expect("the public level is served unstamped");
    assert_eq!(level.run_id, public_run);
    assert!(level.current, "nothing moved since the build");
}

// ===========================================================================
// Staleness: exactly the maps whose readable set changed, once per statement
// ===========================================================================

/// Into A through the real path (migration 206's share-with-team, on the
/// member's stamped application session): A's epoch moves, and no other row
/// moves or appears (the source is a personal group, which has no map).
#[sqlx::test(migrations = "../../migrations")]
async fn moving_a_claim_into_a_team_bumps_that_team_only(pool: PgPool) {
    let a = team(&pool, "team-a").await;
    let b = team(&pool, "team-b").await;
    let (m, home) = fixture::seed_agent_with_group(&pool, "map-sharer").await;
    add_member(&pool, a, m, "writer").await;
    add_member(&pool, b, m, "writer").await;
    // Give B and the public map epoch rows, so "nobody else" is measurable.
    let pb = fixture::seed_group_claim(&pool, m, b, "b's claim").await;
    retenant(&pool, &[pb], "public", b).await;
    let c = fixture::seed_group_claim(&pool, m, home, "a draft").await;
    let before = epochs(&pool).await;
    assert!(
        before.contains_key(&b) && before.contains_key(&WORLD),
        "calibration"
    );

    let scoped = app_scoped(&pool).await;
    let v = Viewer::resolve(&pool, m).await.expect("viewer");
    let mut tx = scoped.begin_as(&v).await.expect("stamped tx");
    ClaimRepository::share_with_team_conn(&mut tx, &[c], a, "share the draft")
        .await
        .expect("shared into A");
    tx.commit().await.expect("commit");

    assert_eq!(
        moved(&before, &epochs(&pool).await),
        BTreeMap::from([(a, 1)])
    );
}

/// Out of A into a personal group: A's epoch moves and nothing else.
#[sqlx::test(migrations = "../../migrations")]
async fn moving_a_claim_out_of_a_team_bumps_that_team_only(pool: PgPool) {
    let a = team(&pool, "team-a").await;
    let b = team(&pool, "team-b").await;
    let (m, home) = fixture::seed_agent_with_group(&pool, "map-mover").await;
    let c = fixture::seed_group_claim(&pool, m, a, "a's claim").await;
    let other = fixture::seed_group_claim(&pool, m, home, "other").await;
    retenant(&pool, &[other], "group", b).await;
    let before = epochs(&pool).await;
    assert!(
        before.contains_key(&b),
        "calibration: B has a row that must not move"
    );

    retenant(&pool, &[c], "group", home).await;
    let after = epochs(&pool).await;
    assert_eq!(moved(&before, &after), BTreeMap::from([(a, 1)]));
    assert!(
        !after.contains_key(&home),
        "a personal group has no map and no epoch"
    );
}

/// A -> B: both move once, the public map and a third team C do not.
/// Then narrowing a public claim into A moves the public map and A.
#[sqlx::test(migrations = "../../migrations")]
async fn moving_a_claim_between_teams_bumps_both_and_no_other(pool: PgPool) {
    let a = team(&pool, "team-a").await;
    let b = team(&pool, "team-b").await;
    let cc = team(&pool, "team-c").await;
    let (m, _) = fixture::seed_agent_with_group(&pool, "map-mover").await;
    let c = fixture::seed_group_claim(&pool, m, a, "a's claim").await;
    let p = fixture::seed_group_claim(&pool, m, cc, "c's claim").await;
    retenant(&pool, &[p], "public", cc).await;
    let before = epochs(&pool).await;
    assert!(
        before.contains_key(&cc) && before.contains_key(&WORLD),
        "calibration"
    );

    retenant(&pool, &[c], "group", b).await;
    let mid = epochs(&pool).await;
    assert_eq!(moved(&before, &mid), BTreeMap::from([(a, 1), (b, 1)]));

    // Narrowing: a public claim into A.
    retenant(&pool, &[p], "group", a).await;
    assert_eq!(
        moved(&mid, &epochs(&pool).await),
        BTreeMap::from([(WORLD, 1), (a, 1)])
    );
}

/// Publicize through migration 206's definer, by B's admin on a stamped
/// application session: B's private half lost the claim and the public half
/// gained it, so B and the public map move; A does not.
#[sqlx::test(migrations = "../../migrations")]
async fn publicize_bumps_the_source_team_and_the_public_map(pool: PgPool) {
    let a = team(&pool, "team-a").await;
    let b = team(&pool, "team-b").await;
    let (admin, _) = fixture::seed_agent_with_group(&pool, "map-admin").await;
    add_member(&pool, b, admin, "admin").await;
    let c = fixture::seed_group_claim(&pool, admin, b, "b's finding").await;
    let other = fixture::seed_group_claim(&pool, admin, b, "elsewhere").await;
    retenant(&pool, &[other], "group", a).await;
    let before = epochs(&pool).await;
    assert!(
        before.contains_key(&a),
        "calibration: A has a row that must not move"
    );

    let scoped = app_scoped(&pool).await;
    let v = Viewer::resolve(&pool, admin).await.expect("viewer");
    let mut tx = scoped.begin_as(&v).await.expect("stamped tx");
    ClaimRepository::publicize_conn(&mut tx, &[c], "release it")
        .await
        .expect("publicized");
    tx.commit().await.expect("commit");

    assert_eq!(
        moved(&before, &epochs(&pool).await),
        BTreeMap::from([(WORLD, 1), (b, 1)])
    );
}

/// One UPDATE moves 1,000 claims from A to B: each epoch moves by exactly one,
/// not by a thousand.
#[sqlx::test(migrations = "../../migrations")]
async fn a_thousand_row_move_bumps_each_epoch_once(pool: PgPool) {
    let a = team(&pool, "team-a").await;
    let b = team(&pool, "team-b").await;
    let (m, _) = fixture::seed_agent_with_group(&pool, "map-bulk").await;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         SELECT gen_random_uuid(), 'bulk claim ' || i, \
                decode(md5('a' || i) || md5('b' || i), 'hex'), 0.8, $1, true, 'group', $2 \
           FROM generate_series(1, 1000) AS i \
         RETURNING id",
    )
    .bind(m)
    .bind(a)
    .fetch_all(&pool)
    .await
    .expect("seed 1,000 claims");
    assert_eq!(ids.len(), 1000);
    let before = epochs(&pool).await;

    retenant(&pool, &ids, "group", b).await;
    assert_eq!(
        moved(&before, &epochs(&pool).await),
        BTreeMap::from([(a, 1), (b, 1)])
    );
}

/// An UPDATE that changes no tenancy, re-owning a PUBLIC claim (owner A -> B,
/// still public: no readable set changed) and inserting a new claim move no
/// epoch.
#[sqlx::test(migrations = "../../migrations")]
async fn a_tenancy_free_update_and_a_public_reowning_bump_nothing(pool: PgPool) {
    let a = team(&pool, "team-a").await;
    let b = team(&pool, "team-b").await;
    let (m, _) = fixture::seed_agent_with_group(&pool, "map-quiet").await;
    let c = fixture::seed_group_claim(&pool, m, a, "a's claim").await;
    let p = fixture::seed_group_claim(&pool, m, a, "to publish").await;
    retenant(&pool, &[p], "public", a).await;
    let before = epochs(&pool).await;
    assert!(
        before.contains_key(&a) && before.contains_key(&WORLD),
        "calibration"
    );

    sqlx::query("UPDATE claims SET truth_value = 0.4 WHERE id = ANY($1)")
        .bind(vec![c, p])
        .execute(&pool)
        .await
        .expect("tenancy-free update");
    retenant(&pool, &[p], "public", b).await;
    fixture::seed_group_claim(&pool, m, a, "a new claim").await;

    assert_eq!(moved(&before, &epochs(&pool).await), BTreeMap::new());
}

// ===========================================================================
// Runs: unfinished runs are not served; a move makes a served run stale
// ===========================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn a_level_is_served_only_from_a_finished_run_and_goes_stale_on_a_move(pool: PgPool) {
    let a = team(&pool, "team-a").await;
    let (m, home) = fixture::seed_agent_with_group(&pool, "map-reader").await;
    add_member(&pool, a, m, "reader").await;
    let theme = seed_theme(&pool).await;
    let g = Uuid::new_v4();
    let child = Uuid::new_v4();
    let (_scoped, system) = fixture::bypass(&pool).await;
    let mv = Viewer::resolve(&pool, m).await.expect("viewer");

    let mut conn = pool.acquire().await.expect("acquire");
    let epochs0 = AtlasMapRepository::map_epochs(&mut conn, &system, AtlasMap::Team(a))
        .await
        .expect("epochs");
    assert_eq!(epochs0, MapEpochs { map: 0, public: 0 });
    let run = AtlasMapRepository::write_run(
        &mut conn,
        &NewMapRun {
            map: AtlasMap::Team(a),
            algo: "test-v1".into(),
            params: serde_json::json!({"k": 3}),
            epochs: epochs0,
        },
    )
    .await
    .expect("write_run");
    AtlasMapRepository::put_level(&mut conn, run, &doc(theme, g, serde_json::json!({"v": 1})))
        .await
        .expect("put");
    // A replacement of the same key, and a nested level.
    AtlasMapRepository::put_level(&mut conn, run, &doc(theme, g, serde_json::json!({"v": 2})))
        .await
        .expect("put again");
    let nested = LevelDoc {
        hierarchy: AtlasHierarchy::Links,
        group_id: child,
        parent_group_id: Some(g),
        theme_id: theme,
        level: 1,
        schema_version: 1,
        payload: serde_json::json!({"leaf": true}),
    };
    AtlasMapRepository::put_level(&mut conn, run, &nested)
        .await
        .expect("nested");

    assert!(
        team_level(&mut conn, &mv, a, AtlasHierarchy::Meaning, g)
            .await
            .is_none(),
        "an unfinished run is not served"
    );
    AtlasMapRepository::finish_run(&mut conn, run)
        .await
        .expect("finish");
    let level = team_level(&mut conn, &mv, a, AtlasHierarchy::Meaning, g)
        .await
        .expect("served once finished");
    assert_eq!(level.run_id, run);
    assert_eq!(level.payload, serde_json::json!({"v": 2}));
    assert!(level.current);
    assert!(
        team_level(&mut conn, &mv, a, AtlasHierarchy::Links, g)
            .await
            .is_none(),
        "the other hierarchy is a different key"
    );
    let leaf = team_level(&mut conn, &mv, a, AtlasHierarchy::Links, child)
        .await
        .expect("nested level");
    assert_eq!((leaf.level, leaf.parent_group_id), (1, Some(g)));
    let count: Option<i32> =
        sqlx::query_scalar("SELECT level_count FROM atlas_map_runs WHERE id = $1")
            .bind(run)
            .fetch_one(&mut *conn)
            .await
            .expect("count");
    assert_eq!(count, Some(2));

    match AtlasMapRepository::put_level(
        &mut conn,
        run,
        &doc(theme, Uuid::new_v4(), serde_json::json!({})),
    )
    .await
    {
        Err(DbError::NotFound { .. }) => {}
        other => panic!("a finished run takes no more levels: {other:?}"),
    }

    // A claim leaves A: the stored run is stale (still served, flagged).
    let c = fixture::seed_group_claim(&pool, m, a, "a's claim").await;
    retenant(&pool, &[c], "group", home).await;
    let stale = team_level(&mut conn, &mv, a, AtlasHierarchy::Meaning, g)
        .await
        .expect("still served");
    assert!(!stale.current, "a claim left A after the build");

    // A personal group has no map, so no run of one may exist.
    match AtlasMapRepository::write_run(
        &mut conn,
        &NewMapRun {
            map: AtlasMap::Team(home),
            algo: "test-v1".into(),
            params: serde_json::json!({}),
            epochs: epochs0,
        },
    )
    .await
    {
        Err(DbError::InvalidData { .. }) => {}
        other => panic!("a personal group's map is refused: {other:?}"),
    }
}
