//! The cycle guard of the workflow references walks every in-force edge, not
//! only the edges the writing session reads (backlog 7149132e, migration 254).
//!
//! `EdgeRepository::reaches_in_force_conn` is MCP `link_hierarchical`'s cycle
//! guard for `invokes`, `executes` and `depends_on`. It ran its recursive walk
//! inline on the writer's STAMPED application session, where row security
//! filters `edges`, so a cycle closed through an edge that session cannot read
//! was not seen and the closing edge was written. Migration 254 decides
//! reachability with definer rights (`public.epigraph_edges_reach`).
//!
//! What is pinned here:
//!
//! * on an `epigraph_app` session stamped for a caller who cannot read the
//!   middle of a path (two edges private to another group), the walk reaches
//!   the far end. Calibrated in the same session: the old inline walk does not
//!   (the session really hides the path), the session reads none of the two
//!   edges, and a retired hidden edge is not followed;
//! * the definer walks only the workflow references: any other relationship,
//!   an empty set or a NULL element is refused 22023;
//! * the definer's catalog shape: SECURITY DEFINER, owned by
//!   `epigraph_maintenance`, STABLE, path `pg_catalog, pg_temp`, no PUBLIC
//!   EXECUTE, EXECUTE for the application role;
//! * the check-then-insert serialization: two sessions checking the two
//!   directions of one 2-cycle. The second blocks on the advisory lock until
//!   the first commits its edge, then its walk sees that edge. Run on the
//!   `depends_on` key between two harness sessions, and on the `invokes` /
//!   `executes` key with the waiting writer on a stamped `epigraph_app`
//!   transaction, the path `link_hierarchical` runs.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{EdgeRepository, ScopedPool, SessionGucMode};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

/// The definer's signature.
const DEFINER: &str = "public.epigraph_edges_reach(uuid, uuid, text[])";

/// What `link_hierarchical` walks for a new `invokes` or `executes` edge.
const INVOKES_WALK: &[&str] = &["invokes", "executes"];

/// A current claim with explicit tenancy, standing in for a graph node.
async fn node(pool: &PgPool, author: Uuid, group: Uuid, visibility: &str, what: &str) -> Uuid {
    let content = format!("7149132e {what} {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, true, $3, $4) RETURNING id",
    )
    .bind(&content)
    .bind(author)
    .bind(visibility)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// An in-force `source -relationship-> target` edge, its tenancy left to the
/// edges trigger (the meet of its endpoints), on the harness connection.
async fn edge<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    source: Uuid,
    target: Uuid,
    relationship: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .fetch_one(executor)
    .await
    .expect("seed edge")
}

/// The walk `reaches_in_force_conn` ran inline before 254, verbatim.
async fn inline_reaches(
    conn: &mut sqlx::PgConnection,
    from: Uuid,
    to: Uuid,
    relationships: &[&str],
) -> bool {
    let rels: Vec<String> = relationships.iter().map(|r| (*r).to_string()).collect();
    sqlx::query_scalar(&format!(
        "WITH RECURSIVE reach(node) AS ( \
             SELECT $1::uuid \
           UNION \
             SELECT e.target_id FROM reach r \
               JOIN edges e ON e.source_id = r.node \
              WHERE e.relationship = ANY($3) AND {} \
         ) \
         SELECT EXISTS (SELECT 1 FROM reach WHERE node = $2)",
        epigraph_db::repos::edge::EDGE_IN_FORCE
    ))
    .bind(from)
    .bind(to)
    .bind(&rels)
    .fetch_one(conn)
    .await
    .expect("inline walk")
}

async fn app_scoped_pool(pool: &PgPool) -> ScopedPool {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: the hidden arm is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

/// The red test of 7149132e at the repository: `w1 -executes-> s -invokes->
/// w2` where `s` (and so both edges) is private to a group the caller is not
/// in. On the caller's stamped application session `w1` reaches `w2`, so a
/// caller's `w2 -invokes-> w1` is seen to close a cycle.
#[sqlx::test(migrations = "../../migrations")]
async fn on_an_app_session_a_path_through_unreadable_edges_is_walked(pool: PgPool) {
    let (caller, mine) = fixture::seed_agent_with_group(&pool, "7149132e-caller").await;
    let (other, theirs) = fixture::seed_agent_with_group(&pool, "7149132e-other").await;
    let w1 = node(&pool, caller, mine, "public", "w1").await;
    let w2 = node(&pool, caller, mine, "public", "w2").await;
    let s = node(&pool, other, theirs, "group", "private step").await;
    let hidden_exec = edge(&pool, w1, s, "executes").await;
    let hidden_inv = edge(&pool, s, w2, "invokes").await;
    let lone = node(&pool, caller, mine, "public", "unconnected").await;

    // Calibration on the superuser connection: the trigger made both edges
    // private to the other group, and structurally w1 reaches w2.
    for id in [hidden_exec, hidden_inv] {
        let (vis, owner): (String, Uuid) =
            sqlx::query_as("SELECT visibility, owner_group_id FROM edges WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("read edge tenancy");
        assert_eq!(
            (vis.as_str(), owner),
            ("group", theirs),
            "calibration: edge {id} takes the private step's tenancy"
        );
    }
    let mut su = pool.acquire().await.expect("acquire");
    assert!(
        inline_reaches(&mut su, w1, w2, INVOKES_WALK).await,
        "calibration: structurally, w1 reaches w2"
    );
    drop(su);

    let viewer = Viewer::resolve(&pool, caller)
        .await
        .expect("resolve caller");
    let scoped = app_scoped_pool(&pool).await;
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped transaction");
    let who: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&mut *tx)
        .await
        .expect("session_user");
    assert_eq!(who, "epigraph_app", "the session is the application role");
    let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM edges WHERE id = ANY($1)")
        .bind(vec![hidden_exec, hidden_inv])
        .fetch_one(&mut *tx)
        .await
        .expect("count readable edges");
    assert_eq!(
        seen, 0,
        "calibration: the caller's session reads neither edge"
    );
    assert!(
        !inline_reaches(&mut tx, w1, w2, INVOKES_WALK).await,
        "calibration: the pre-254 inline walk, on this session, does not reach w2"
    );

    assert!(
        EdgeRepository::reaches_in_force_conn(&mut tx, w1, w2, INVOKES_WALK)
            .await
            .expect("reaches_in_force_conn on an app session"),
        "7149132e: the cycle guard must walk edges the caller cannot read"
    );
    assert!(
        !EdgeRepository::reaches_in_force_conn(&mut tx, w1, lone, INVOKES_WALK)
            .await
            .expect("reaches_in_force_conn"),
        "an unconnected node is not reached"
    );
    assert!(
        !EdgeRepository::reaches_in_force_conn(&mut tx, w1, w2, &["depends_on"])
            .await
            .expect("reaches_in_force_conn"),
        "only the named relationships are walked"
    );
    tx.rollback().await.expect("rollback");

    // A retired hidden edge is not followed.
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 second' WHERE id = $1")
        .bind(hidden_exec)
        .execute(&pool)
        .await
        .expect("retire the hidden executes edge");
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped transaction");
    assert!(
        !EdgeRepository::reaches_in_force_conn(&mut tx, w1, w2, INVOKES_WALK)
            .await
            .expect("reaches_in_force_conn"),
        "a retired edge is not in force and is not walked"
    );
    tx.rollback().await.expect("rollback");
}

/// The definer walks the workflow references only: any other relationship,
/// an empty set, a NULL set or a NULL element is refused 22023, so it is not
/// a reachability oracle over the rest of the graph.
#[sqlx::test(migrations = "../../migrations")]
async fn the_definer_walks_only_the_workflow_references(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "7149132e-rels").await;
    let a = node(&pool, agent, group, "public", "a").await;
    let b = node(&pool, agent, group, "public", "b").await;
    edge(&pool, a, b, "supports").await;

    let refused: [Option<Vec<Option<String>>>; 5] = [
        Some(vec![Some("supports".to_string())]),
        Some(vec![
            Some("invokes".to_string()),
            Some("decomposes_to".to_string()),
        ]),
        Some(vec![]),
        Some(vec![Some("invokes".to_string()), None]),
        None,
    ];
    for rels in refused {
        let err = sqlx::query_scalar::<_, bool>("SELECT public.epigraph_edges_reach($1, $2, $3)")
            .bind(a)
            .bind(b)
            .bind(&rels)
            .fetch_one(&pool)
            .await
            .expect_err("a relationship set outside the workflow references is refused");
        let code = err
            .as_database_error()
            .and_then(|d| d.code())
            .map(|c| c.to_string());
        assert_eq!(code.as_deref(), Some("22023"), "{rels:?}: {err}");
    }
    // Calibration: the same call over the admitted set answers (a reaches b
    // only along `supports`, which it does not walk).
    let reached: bool = sqlx::query_scalar("SELECT public.epigraph_edges_reach($1, $2, $3)")
        .bind(a)
        .bind(b)
        .bind(vec!["invokes", "executes", "depends_on"])
        .fetch_one(&pool)
        .await
        .expect("an admitted set is walked");
    assert!(!reached);
    let reached: bool = sqlx::query_scalar("SELECT public.epigraph_edges_reach($1, $1, $2)")
        .bind(a)
        .bind(vec!["depends_on"])
        .fetch_one(&pool)
        .await
        .expect("an admitted set is walked");
    assert!(reached, "a node reaches itself");
}

/// Migration 254's definer, as the catalog holds it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_definer_is_maintenance_owned_pinned_and_executable_by_the_app_role(pool: PgPool) {
    let (secdef, owner, volatile, config): (bool, String, String, Option<Vec<String>>) =
        sqlx::query_as(
            "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, p.provolatile::text, \
                    p.proconfig \
               FROM pg_proc p WHERE p.oid = $1::regprocedure",
        )
        .bind(DEFINER)
        .fetch_one(&pool)
        .await
        .expect("the definer exists");
    assert!(secdef, "{DEFINER} must be SECURITY DEFINER");
    assert_eq!(owner, "epigraph_maintenance", "{DEFINER} owner");
    assert_eq!(volatile, "s", "{DEFINER} is STABLE");
    assert_eq!(
        config.unwrap_or_default(),
        vec!["search_path=pg_catalog, pg_temp".to_string()],
        "{DEFINER} pins 172's path"
    );
    for (role, expected) in [
        ("public", false),
        ("epigraph_app", true),
        ("epigraph_maintenance", true),
    ] {
        let can: bool =
            sqlx::query_scalar("SELECT has_function_privilege($1, $2::regprocedure, 'EXECUTE')")
                .bind(role)
                .bind(DEFINER)
                .fetch_one(&pool)
                .await
                .expect("has_function_privilege");
        assert_eq!(can, expected, "EXECUTE on {DEFINER} for {role}");
    }
}

/// Whether backend `pid` is waiting on an advisory lock it has not been
/// granted.
async fn waits_on_advisory_lock(pool: &PgPool, pid: i32) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_locks \
                         WHERE locktype = 'advisory' AND NOT granted AND pid = $1)",
    )
    .bind(pid)
    .fetch_one(pool)
    .await
    .expect("read pg_locks")
}

/// The barrier: returns once backend `pid` (writer 2, running in `second`) is
/// waiting on an ungranted advisory lock. Fails if `second` finishes first:
/// writer 2 then answered without waiting for writer 1.
async fn wait_until_blocked(pool: &PgPool, pid: i32, second: &tokio::task::JoinHandle<bool>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if waits_on_advisory_lock(pool, pid).await {
            break;
        }
        assert!(
            !second.is_finished(),
            "writer 2 finished its check without waiting for writer 1's lock: the \
             check-then-insert is not serialized"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "writer 2 never waited on an advisory lock"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!second.is_finished(), "writer 2 is still blocked");
}

/// The race the advisory lock closes. Writer 1 is about to add `a -> b` and
/// writer 2 `b -> a` (both `depends_on`); each first asks whether its target
/// reaches its source. Writer 1 checks (no path) and holds the lock. Writer 2's
/// check must WAIT (barrier: `pg_locks` shows its backend waiting on an
/// ungranted advisory lock), and once writer 1 commits `a -> b`, writer 2's
/// walk runs on a fresh snapshot and sees it: the 2-cycle is refused. Without
/// the lock writer 2 answers at once, from a snapshot without `a -> b`, and
/// both edges would be written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_concurrent_check_waits_for_the_first_writer_and_sees_its_edge(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "7149132e-race").await;
    let a = node(&pool, agent, group, "public", "race a").await;
    let b = node(&pool, agent, group, "public", "race b").await;
    const WALK: &[&str] = &["depends_on"];

    let mut writer1 = pool.begin().await.expect("writer 1");
    assert!(
        !EdgeRepository::reaches_in_force_conn(&mut writer1, b, a, WALK)
            .await
            .expect("writer 1 checks"),
        "no path yet: writer 1 may add a -> b"
    );

    let mut writer2 = pool.begin().await.expect("writer 2");
    let pid2: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer2)
        .await
        .expect("writer 2 pid");
    let second = tokio::spawn(async move {
        let reached = EdgeRepository::reaches_in_force_conn(&mut writer2, a, b, WALK)
            .await
            .expect("writer 2 checks");
        writer2.rollback().await.expect("rollback writer 2");
        reached
    });

    // Barrier: writer 2 is blocked on the lock writer 1 holds.
    wait_until_blocked(&pool, pid2, &second).await;

    edge(&mut *writer1, a, b, "depends_on").await;
    writer1.commit().await.expect("writer 1 commits a -> b");

    let reached = tokio::time::timeout(Duration::from_secs(15), second)
        .await
        .expect("writer 2 resumes once writer 1 commits")
        .expect("writer 2 task");
    assert!(
        reached,
        "writer 2's walk runs after writer 1's commit and sees a -> b, so b -> a is refused"
    );
}

/// The same race on the path `link_hierarchical` actually runs: writer 2 is a
/// STAMPED `epigraph_app` transaction (`begin_as`), and the key is the
/// `invokes` / `executes` walk rather than `depends_on`. Writer 1 checks and
/// adds `a -invokes-> b`; writer 2's check for `b -invokes-> a` must wait for
/// writer 1's commit and then, on its stamped session, see `a -invokes-> b`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stamped_app_check_on_the_invokes_walk_waits_and_sees_the_edge(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "7149132e-race-app").await;
    let a = node(&pool, agent, group, "public", "race app a").await;
    let b = node(&pool, agent, group, "public", "race app b").await;

    let mut writer1 = pool.begin().await.expect("writer 1");
    assert!(
        !EdgeRepository::reaches_in_force_conn(&mut writer1, b, a, INVOKES_WALK)
            .await
            .expect("writer 1 checks"),
        "no path yet: writer 1 may add a -invokes-> b"
    );

    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve agent");
    let scoped = app_scoped_pool(&pool).await;
    let (pid_tx, pid_rx) = tokio::sync::oneshot::channel::<i32>();
    let second = tokio::spawn(async move {
        let mut writer2 = scoped.begin_as(&viewer).await.expect("stamped writer 2");
        let (who, pid): (String, i32) =
            sqlx::query_as("SELECT session_user::text, pg_backend_pid()")
                .fetch_one(&mut *writer2)
                .await
                .expect("writer 2 session");
        assert_eq!(who, "epigraph_app", "writer 2 is the application role");
        pid_tx.send(pid).expect("send writer 2 pid");
        let reached = EdgeRepository::reaches_in_force_conn(&mut writer2, a, b, INVOKES_WALK)
            .await
            .expect("writer 2 checks");
        writer2.rollback().await.expect("rollback writer 2");
        reached
    });
    let pid2 = tokio::time::timeout(Duration::from_secs(15), pid_rx)
        .await
        .expect("writer 2 starts")
        .expect("writer 2 pid");

    wait_until_blocked(&pool, pid2, &second).await;

    edge(&mut *writer1, a, b, "invokes").await;
    writer1
        .commit()
        .await
        .expect("writer 1 commits a -invokes-> b");

    let reached = tokio::time::timeout(Duration::from_secs(15), second)
        .await
        .expect("writer 2 resumes once writer 1 commits")
        .expect("writer 2 task");
    assert!(
        reached,
        "writer 2's stamped walk runs after writer 1's commit and sees a -invokes-> b, \
         so b -invokes-> a is refused"
    );
}
