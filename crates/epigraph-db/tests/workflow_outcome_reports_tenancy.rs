//! Migration 221 (backlog 9928b61f): `workflow_outcome_reports` inherits its
//! workflow row's tenancy, measured AS the application role under real stamps.
//!
//! * A report on a group-private workflow, with its `outcome_details`, is read
//!   only by a session that reads the workflow row; an unstamped application
//!   session reads reports on public workflows only.
//! * A stranger cannot write a report on a workflow it does not read; a reader
//!   can.
//! * No application session updates or deletes a report.
//! * The idempotency key is unique per (workflow, reporter, key), a NULL
//!   reporter included, and unkeyed reports never collide.
//! * Through the repository: a stranger's key lookup on a private workflow is
//!   `NotFound` (it learns nothing about keys), and a reader's retry is
//!   `Replayed` with the stored result.
//!
//! # Verified to fail
//!
//! With the two `EXISTS` policies replaced by `USING (true)` / `WITH CHECK
//! (true)`, `a_report_is_read_and_written_only_through_its_workflow_row` fails
//! on the stranger's read and insert. With the unique index dropped,
//! `the_key_is_unique_per_workflow_and_reporter` fails on the duplicate insert.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{
    HierarchicalOutcomeCounters, HierarchicalOutcomeRecord, HierarchicalOutcomeResult,
    NewHierarchicalOutcomeReport, ScopedPool, SessionGucMode, WorkflowRepository,
};
use sqlx::PgPool;
use uuid::Uuid;

struct World {
    scoped: ScopedPool,
    plain: PgPool,
    member: Viewer,
    stranger: Viewer,
    public: Uuid,
    private: Uuid,
}

async fn declared_row(pool: &PgPool, name: &str, visibility: &str, owner: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal, visibility, owner_group_id) \
         VALUES ($1, $2, 'a goal', $3, $4)",
    )
    .bind(id)
    .bind(name)
    .bind(visibility)
    .bind(owner)
    .execute(pool)
    .await
    .expect("declared workflow row");
    id
}

/// A level-2 step claim of `owner`'s group, linked by an `executes` edge, so
/// `viewer_reads_plan_structure` admits the group's members.
async fn private_step(pool: &PgPool, agent: Uuid, owner: Uuid, workflow: Uuid) {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, properties) \
         VALUES ($1, $2, $3, 0.8, $4, true, 'group', $5, '{\"level\": 2}'::jsonb)",
    )
    .bind(id)
    .bind(format!("outcome report step {id}"))
    .bind(id.as_bytes().repeat(2))
    .bind(agent)
    .bind(owner)
    .execute(pool)
    .await
    .expect("step claim");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'workflow', $2, 'claim', 'executes')",
    )
    .bind(workflow)
    .bind(id)
    .execute(pool)
    .await
    .expect("executes edge");
}

/// A report row written on the harness superuser.
async fn seeded_report(pool: &PgPool, workflow: Uuid, details: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO workflow_outcome_reports (workflow_id, success, outcome_details, result) \
         VALUES ($1, true, $2, '{}'::jsonb) RETURNING id",
    )
    .bind(workflow)
    .bind(details)
    .fetch_one(pool)
    .await
    .expect("seed report")
}

async fn world(pool: &PgPool) -> World {
    let (m, g) = fixture::seed_agent_with_group(pool, "wor-member").await;
    let (s, _) = fixture::seed_agent_with_group(pool, "wor-stranger").await;
    let public = declared_row(pool, "wor-public", "public", g).await;
    let private = declared_row(pool, "wor-private", "group", g).await;
    private_step(pool, m, g, private).await;
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
        public,
        private,
    }
}

/// The `outcome_details` of every report on `workflow` that `viewer`'s
/// stamped session reads.
async fn readable_details(w: &World, viewer: &Viewer, workflow: Uuid) -> Vec<String> {
    let mut read = w.scoped.read_as(viewer).await.expect("stamped read");
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT outcome_details FROM workflow_outcome_reports WHERE workflow_id = $1",
    )
    .bind(workflow)
    .fetch_all(&mut *read)
    .await
    .expect("policy read");
    read.commit().await.expect("close read");
    rows
}

/// `Err(SQLSTATE)` or `Ok(rows affected)` of `sql` (binding `id`) on a
/// transaction stamped from `viewer`, rolled back.
async fn write(w: &World, viewer: &Viewer, sql: &str, id: Uuid) -> Result<u64, String> {
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
async fn a_report_is_read_and_written_only_through_its_workflow_row(pool: PgPool) {
    let w = world(&pool).await;
    seeded_report(&pool, w.private, "private details").await;
    seeded_report(&pool, w.public, "public details").await;

    assert_eq!(
        readable_details(&w, &w.member, w.private).await,
        vec!["private details".to_string()]
    );
    assert!(
        readable_details(&w, &w.stranger, w.private)
            .await
            .is_empty(),
        "a stranger must not read a report on a workflow it does not read"
    );
    assert_eq!(
        readable_details(&w, &w.stranger, w.public).await,
        vec!["public details".to_string()]
    );
    let unstamped: Vec<String> =
        sqlx::query_scalar("SELECT outcome_details FROM workflow_outcome_reports")
            .fetch_all(&w.plain)
            .await
            .expect("unstamped read");
    assert_eq!(
        unstamped,
        vec!["public details".to_string()],
        "an unstamped application session reads reports on public workflows only"
    );

    let insert = "INSERT INTO workflow_outcome_reports (workflow_id, success, result) \
                  VALUES ($1, true, '{}'::jsonb)";
    assert_eq!(write(&w, &w.member, insert, w.private).await, Ok(1));
    assert_eq!(
        write(&w, &w.stranger, insert, w.private).await,
        Err("42501".into()),
        "a stranger cannot write a report on a workflow it does not read"
    );
    assert_eq!(
        write(
            &w,
            &w.member,
            "UPDATE workflow_outcome_reports SET outcome_details = 'x' WHERE workflow_id = $1",
            w.private
        )
        .await,
        Err("42501".into()),
        "no application session edits a report"
    );
    assert_eq!(
        write(
            &w,
            &w.member,
            "DELETE FROM workflow_outcome_reports WHERE workflow_id = $1",
            w.private
        )
        .await,
        Err("42501".into()),
        "no application session deletes a report"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_key_is_unique_per_workflow_and_reporter(pool: PgPool) {
    let w = world(&pool).await;
    let insert = |reporter: Option<Uuid>, key: Option<&'static str>| {
        let pool = pool.clone();
        let wf = w.public;
        async move {
            sqlx::query(
                "INSERT INTO workflow_outcome_reports \
                     (workflow_id, reporter_id, idempotency_key, success, result) \
                 VALUES ($1, $2, $3, true, '{}'::jsonb)",
            )
            .bind(wf)
            .bind(reporter)
            .bind(key)
            .execute(&pool)
            .await
            .map(|_| ())
            .map_err(|e| {
                e.as_database_error()
                    .and_then(|d| d.code().map(|c| c.to_string()))
                    .unwrap_or_default()
            })
        }
    };
    let a = Some(Uuid::new_v4());
    let b = Some(Uuid::new_v4());
    assert_eq!(insert(a, Some("k")).await, Ok(()));
    assert_eq!(insert(a, Some("k")).await, Err("23505".into()));
    assert_eq!(insert(b, Some("k")).await, Ok(()), "another reporter's key");
    assert_eq!(insert(None, Some("k")).await, Ok(()));
    assert_eq!(
        insert(None, Some("k")).await,
        Err("23505".into()),
        "a principal-less reporter's keys are unique too"
    );
    assert_eq!(insert(a, None).await, Ok(()));
    assert_eq!(
        insert(a, None).await,
        Ok(()),
        "unkeyed reports never collide"
    );
    assert_eq!(insert(a, Some("")).await, Err("23514".into()), "blank key");
}

/// Through the repository on the application role: the member's report is
/// stored and its retry replays; the stranger's lookup with the member's key
/// is `NotFound`, exactly like an unknown id, and moves nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retry_replays_for_the_reporter_and_a_stranger_learns_nothing(pool: PgPool) {
    let w = world(&pool).await;
    let mut tx = w.scoped.begin_as(&w.member).await.expect("member tx");
    let HierarchicalOutcomeRecord::Recorded(counters) =
        WorkflowRepository::record_hierarchical_outcome(
            &mut tx,
            &w.member,
            w.private,
            true,
            0.0,
            Some("k-1"),
        )
        .await
        .expect("record")
    else {
        panic!("a first report must be recorded");
    };
    let result = HierarchicalOutcomeResult {
        counters,
        variance: 0.0,
        step_executions_written: 0,
        unresolved_step_indices: vec![],
    };
    let report_id = WorkflowRepository::insert_hierarchical_outcome_report(
        &mut tx,
        &w.member,
        NewHierarchicalOutcomeReport {
            workflow_id: w.private,
            idempotency_key: Some("k-1"),
            success: true,
            quality: Some(1.0),
            run_label: None,
            outcome_details: "member run",
            result: &result,
        },
    )
    .await
    .expect("insert report");
    tx.commit().await.expect("commit");

    let mut tx = w.scoped.begin_as(&w.member).await.expect("member retry tx");
    let again = WorkflowRepository::record_hierarchical_outcome(
        &mut tx,
        &w.member,
        w.private,
        true,
        0.0,
        Some("k-1"),
    )
    .await
    .expect("retry");
    tx.commit().await.expect("commit retry");
    assert_eq!(
        again,
        HierarchicalOutcomeRecord::Replayed {
            report_id,
            result: result.clone(),
        }
    );

    let mut tx = w.scoped.begin_as(&w.stranger).await.expect("stranger tx");
    let theirs = WorkflowRepository::record_hierarchical_outcome(
        &mut tx,
        &w.stranger,
        w.private,
        true,
        0.0,
        Some("k-1"),
    )
    .await
    .expect("stranger lookup");
    tx.commit().await.expect("commit stranger");
    assert_eq!(theirs, HierarchicalOutcomeRecord::NotFound);

    let use_count: Option<i64> =
        sqlx::query_scalar("SELECT (metadata->>'use_count')::bigint FROM workflows WHERE id = $1")
            .bind(w.private)
            .fetch_one(&pool)
            .await
            .expect("counters");
    assert_eq!(
        use_count,
        Some(1),
        "neither the retry nor the stranger moved the counters"
    );
    assert_eq!(
        counters,
        HierarchicalOutcomeCounters {
            use_count: 1,
            success_count: 1,
            failure_count: 0,
            avg_variance: 0.0,
        }
    );
}
