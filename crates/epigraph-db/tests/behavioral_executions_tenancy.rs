//! Migration 240 (backlog 88cf603b): `behavioral_executions` carries the
//! tenancy of the workflow it records a run of, under FORCEd row security,
//! measured AS the application role under real stamps.
//!
//! A run's row holds the goal text, its embedding, the step beliefs and the
//! tool pattern of one run. Before 240 the table had no tenancy and no row
//! security (069 ledgered it in `tenancy_exempt`), so ANY application
//! session read every run of every workflow, group-private ones included; only
//! the first-party readers' own parent filters stood between a new reader (or a
//! raw query on the application DSN) and a private plan's run history.
//!
//! * A non-member, stamped or unstamped, reads no run of a group workflow,
//!   hierarchical (`workflows` row) or flat (a workflow claim); a member reads
//!   them; everyone reads the runs of a public workflow.
//! * A run follows its workflow: narrowing the `workflows` row (the
//!   privatization batch, `reown-workflows`) or the flat workflow claim hides
//!   its runs from a non-member, and restoring the row shows them again.
//! * The row's pair is the workflow's, whatever the writer declared, and a
//!   run of no workflow is refused.
//! * A session records a run only of a workflow it reads (a reader of a
//!   PUBLIC workflow outside its owner group included), and no application
//!   session edits or deletes one.
//!
//! # Verified to fail
//!
//! The first two tests name no column 240 adds, so they run on a pre-240
//! schema. With `migrations/240_behavioral_executions_tenancy.sql` moved out
//! of the directory, `a_non_member_reads_no_run_of_a_group_workflow` fails on
//! the unstamped session's read (it reads all four runs),
//! `a_run_follows_its_workflow_when_the_workflow_is_narrowed` on the first
//! post-narrowing read, and `a_session_records_a_run_only_of_a_workflow_it_reads`
//! on the stranger's insert (`Ok(1)`, not 42501). With the two follow triggers
//! dropped, the narrowing test fails the same way. With the BEFORE INSERT
//! stamp dropped, every test fails on the NOT NULL violation (23502) of its
//! first run insert.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;

struct World {
    scoped: ScopedPool,
    /// An UNSTAMPED `epigraph_app` session: the raw application DSN.
    plain: PgPool,
    member: Viewer,
    stranger: Viewer,
    group: Uuid,
    /// Hierarchical workflows (`workflows` rows).
    wf_private: Uuid,
    wf_public: Uuid,
    /// Flat workflows (workflow claims).
    flat_private: Uuid,
    flat_public: Uuid,
}

async fn workflow_row(pool: &PgPool, name: &str, visibility: &str, owner: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal, visibility, owner_group_id) \
         VALUES ($1, $2, 'a goal', $3, $4)",
    )
    .bind(id)
    .bind(format!("{name}-{id}"))
    .bind(visibility)
    .bind(owner)
    .execute(pool)
    .await
    .expect("declared workflow row");
    id
}

/// One run of `workflow`, written on the harness superuser with no tenancy
/// columns named (the shape every writer in the tree uses).
async fn seeded_run(pool: &PgPool, workflow: Uuid, goal: &str) {
    sqlx::query(
        "INSERT INTO behavioral_executions (workflow_id, goal_text, success) \
         VALUES ($1, $2, true)",
    )
    .bind(workflow)
    .bind(goal)
    .execute(pool)
    .await
    .expect("seed run");
}

async fn world(pool: &PgPool) -> World {
    let (m, g) = fixture::seed_agent_with_group(pool, "bex-member").await;
    let (s, _) = fixture::seed_agent_with_group(pool, "bex-stranger").await;
    let wf_private = workflow_row(pool, "bex-private", "group", g).await;
    let wf_public = workflow_row(pool, "bex-public", "public", g).await;
    let flat_private = fixture::seed_group_claim(pool, m, g, "bex flat private workflow").await;
    let flat_public = fixture::seed_public_claim(pool, m, "bex flat public workflow").await;
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    World {
        scoped,
        plain: fixture::downgraded_pool(pool, "epigraph_app").await,
        member: Viewer::resolve(pool, m).await.expect("member viewer"),
        stranger: Viewer::resolve(pool, s).await.expect("stranger viewer"),
        group: g,
        wf_private,
        wf_public,
        flat_private,
        flat_public,
    }
}

/// The goal texts of every run `viewer`'s stamped session reads, sorted.
async fn goals_as(w: &World, viewer: &Viewer) -> Vec<String> {
    let mut read = w.scoped.read_as(viewer).await.expect("stamped read");
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT goal_text FROM behavioral_executions ORDER BY goal_text")
            .fetch_all(&mut *read)
            .await
            .expect("stamped read of behavioral_executions");
    read.commit().await.expect("close read");
    rows
}

/// The goal texts of every run an UNSTAMPED application session reads, sorted.
async fn goals_unstamped(w: &World) -> Vec<String> {
    sqlx::query_scalar("SELECT goal_text FROM behavioral_executions ORDER BY goal_text")
        .fetch_all(&w.plain)
        .await
        .expect("unstamped read of behavioral_executions")
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

/// `Err(SQLSTATE)` or `Ok(rows affected)` of `sql` (binding `id`) on a
/// transaction stamped from `viewer`, rolled back.
async fn write_as(w: &World, viewer: &Viewer, sql: &str, id: Uuid) -> Result<u64, String> {
    let mut tx = w.scoped.begin_as(viewer).await.expect("stamped tx");
    let r = sqlx::query(sql)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| {
            e.as_database_error()
                .and_then(|d| d.code().map(|c| c.to_string()))
                .unwrap_or_else(|| e.to_string())
        });
    drop(tx);
    r
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_reads_no_run_of_a_group_workflow(pool: PgPool) {
    let w = world(&pool).await;
    seeded_run(&pool, w.wf_private, "b hierarchical private run").await;
    seeded_run(&pool, w.wf_public, "a hierarchical public run").await;
    seeded_run(&pool, w.flat_private, "d flat private run").await;
    seeded_run(&pool, w.flat_public, "c flat public run").await;

    let public = strings(&["a hierarchical public run", "c flat public run"]);
    assert_eq!(
        goals_unstamped(&w).await,
        public,
        "an unstamped application session (the raw application DSN) must read the runs of \
         public workflows only, never a group workflow's run history"
    );
    assert_eq!(
        goals_as(&w, &w.stranger).await,
        public,
        "a stamped non-member must read no run of a group workflow"
    );
    assert_eq!(
        goals_as(&w, &w.member).await,
        strings(&[
            "a hierarchical public run",
            "b hierarchical private run",
            "c flat public run",
            "d flat private run",
        ]),
        "a member of the owner group reads its group's runs and every public run"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_run_follows_its_workflow_when_the_workflow_is_narrowed(pool: PgPool) {
    let w = world(&pool).await;
    seeded_run(&pool, w.wf_public, "a hierarchical run").await;
    seeded_run(&pool, w.flat_public, "b flat run").await;
    let both = strings(&["a hierarchical run", "b flat run"]);
    assert_eq!(goals_as(&w, &w.stranger).await, both, "both public before");

    // The privatization batch / reown-workflows narrowing of a `workflows`
    // row, and restrict-claims' narrowing of a flat workflow claim: both are
    // maintenance writes on the PARENT; nothing touches the runs directly.
    sqlx::query("UPDATE workflows SET visibility = 'group' WHERE id = $1")
        .bind(w.wf_public)
        .execute(&pool)
        .await
        .expect("narrow the workflow row");
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(w.flat_public)
        .bind(w.group)
        .execute(&pool)
        .await
        .expect("narrow the flat workflow claim");

    assert!(
        goals_unstamped(&w).await.is_empty(),
        "after its workflow is narrowed, a run must not stay readable to an unstamped session"
    );
    assert!(
        goals_as(&w, &w.stranger).await.is_empty(),
        "after its workflow is narrowed, a run must not stay readable to a non-member"
    );
    assert_eq!(
        goals_as(&w, &w.member).await,
        both,
        "the member still reads both"
    );

    // The privatization RESTORE: the workflow row goes public again, and so
    // does its run (and only its run: the flat claim stays narrowed).
    sqlx::query("UPDATE workflows SET visibility = 'public' WHERE id = $1")
        .bind(w.wf_public)
        .execute(&pool)
        .await
        .expect("restore the workflow row");
    assert_eq!(
        goals_as(&w, &w.stranger).await,
        strings(&["a hierarchical run"]),
        "a restored workflow's run is public again; the narrowed flat claim's is not"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_session_records_a_run_only_of_a_workflow_it_reads(pool: PgPool) {
    let w = world(&pool).await;
    let insert = "INSERT INTO behavioral_executions (workflow_id, goal_text, success) \
                  VALUES ($1, 'a run', true)";
    assert_eq!(
        write_as(&w, &w.member, insert, w.wf_private).await,
        Ok(1),
        "a member records a run of its group's workflow"
    );
    assert_eq!(
        write_as(&w, &w.member, insert, w.flat_private).await,
        Ok(1),
        "a member records a run of its group's flat workflow"
    );
    assert_eq!(
        write_as(&w, &w.stranger, insert, w.wf_private).await,
        Err("42501".into()),
        "a stranger cannot record a run of a workflow it does not read"
    );
    assert_eq!(
        write_as(&w, &w.stranger, insert, w.flat_private).await,
        Err("42501".into()),
        "a stranger cannot record a run of a flat workflow it does not read"
    );
    assert_eq!(
        write_as(&w, &w.stranger, insert, w.wf_public).await,
        Ok(1),
        "a reader of a PUBLIC workflow records a run of it without writing its owner group"
    );
    assert_eq!(
        write_as(&w, &w.stranger, insert, w.flat_public).await,
        Ok(1),
        "a reader of a public flat workflow records a run of it"
    );

    seeded_run(&pool, w.wf_private, "seeded").await;
    for sql in [
        "UPDATE behavioral_executions SET goal_text = 'x' WHERE workflow_id = $1",
        "DELETE FROM behavioral_executions WHERE workflow_id = $1",
    ] {
        assert_eq!(
            write_as(&w, &w.member, sql, w.wf_private).await,
            Err("42501".into()),
            "no application session edits or deletes a run: {sql}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamp_is_the_workflow_pair_and_an_orphan_is_refused(pool: PgPool) {
    let w = world(&pool).await;
    let world_group = fixture::world_group(&pool).await;
    // A writer that DECLARES ('public', world) on a group workflow's run gets
    // the workflow's pair, never its declaration.
    for parent in [w.wf_private, w.flat_private] {
        let (vis, owner): (String, Uuid) = sqlx::query_as(
            "INSERT INTO behavioral_executions \
                 (workflow_id, goal_text, success, visibility, owner_group_id) \
             VALUES ($1, 'declared public', true, 'public', $2) \
             RETURNING visibility::text, owner_group_id",
        )
        .bind(parent)
        .bind(world_group)
        .fetch_one(&pool)
        .await
        .expect("stamped insert");
        assert_eq!(
            (vis.as_str(), owner),
            ("group", w.group),
            "the run takes its workflow's pair over the writer's declaration"
        );
    }

    let orphan = sqlx::query(
        "INSERT INTO behavioral_executions (workflow_id, goal_text, success) \
         VALUES ($1, 'no workflow', true)",
    )
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .expect_err("a run of no workflow must be refused");
    assert_eq!(
        orphan
            .as_database_error()
            .and_then(|d| d.code().map(|c| c.to_string())),
        Some("23503".to_string()),
        "a run of no workflow is a dangling reference: {orphan}"
    );
}

/// `docs/runbooks/240-undo.sql` puts the table back exactly as 069 left it:
/// no tenancy columns, no row security, no 240 trigger or function, and 069's
/// `tenancy_exempt` row; the runs themselves survive.
#[sqlx::test(migrations = "../../migrations")]
async fn the_undo_restores_the_pre_240_posture(pool: PgPool) {
    let w = world(&pool).await;
    seeded_run(&pool, w.wf_private, "a private run").await;
    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/240-undo.sql"),
    )
    .expect("240-undo.sql");
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("run 240's undo");

    let (rls, force): (bool, bool) = sqlx::query_as(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
          WHERE oid = 'public.behavioral_executions'::regclass",
    )
    .fetch_one(&pool)
    .await
    .expect("pg_class");
    assert_eq!((rls, force), (false, false), "row security is off again");
    let columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'behavioral_executions' \
            AND column_name IN ('owner_group_id', 'visibility')",
    )
    .fetch_one(&pool)
    .await
    .expect("columns");
    assert_eq!(columns, 0, "both tenancy columns are gone");
    let left: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM pg_trigger WHERE tgname LIKE '%behavioral_executions%' \
                   AND NOT tgisinternal AND tgname <> 'role_agent_write_check') \
              + (SELECT count(*) FROM pg_proc WHERE proname IN ( \
                   'epigraph_behavioral_execution_inherit_tenancy', \
                   'epigraph_workflow_behavioral_executions_follow', \
                   'epigraph_claim_behavioral_executions_follow'))",
    )
    .fetch_one(&pool)
    .await
    .expect("triggers and functions");
    assert_eq!(left, 0, "no 240 trigger or function is left");
    let exempt: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM tenancy_exempt WHERE table_name = 'behavioral_executions'",
    )
    .fetch_one(&pool)
    .await
    .expect("registry");
    assert_eq!(exempt, 1, "069's registry row is back");
    assert_eq!(
        goals_unstamped(&w).await,
        strings(&["a private run"]),
        "the run survives, readable to every session as before 240"
    );
}
