//! Migration 119 (batch W12a, operator decision D9): the job queue is a
//! privileged timer's, so an application session enqueues nothing, and the
//! maintenance role can run every job handler's DELETE.
//!
//! # Why every arm switches role
//!
//! `#[sqlx::test]` connects as the superuser `epigraph`, for whom every policy
//! and every grant is bypassed. Each arm therefore runs inside a transaction
//! under `SET LOCAL SESSION AUTHORIZATION`: `epigraph_app` for the refusals,
//! `epigraph_maintenance` for the admissions. `epigraph_bypass()` keys on
//! `session_user`, so the maintenance arm is privileged exactly as a
//! non-superuser LOGIN in `epigraph_maintenance` (the drain timer's login) is,
//! and the application arm is not.
//!
//! # Why the refusal is asserted by MESSAGE, not only by SQLSTATE
//!
//! A missing grant and a row-level-security WITH CHECK violation are both
//! `42501`. The application role HOLDS the INSERT grant on `jobs` (asserted
//! first, as calibration), so a `42501` here can only be the policy; the
//! message is asserted as well so a future REVOKE cannot make these arms pass
//! for the wrong reason.

use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

/// The job types the drain timer runs today, one privatization type, and one
/// no handler knows. 077's denylist admitted the first and the last from an
/// application session.
const JOB_TYPES: &[&str] = &[
    "cluster_graph",
    "theme_cluster_rebuild",
    "privatization_apply",
    "no_such_job_type",
];

/// The tables a job handler names in a DELETE, which 119 grants.
const HANDLER_DELETE_TABLES: &[&str] = &[
    "jobs",
    "graph_cluster_runs",
    "graph_clusters",
    "cluster_edges",
    "claim_cluster_membership",
    "claim_themes",
];

async fn insert_job(conn: &mut PgConnection, job_type: &str) -> Result<u64, (String, String)> {
    sqlx::query(
        "INSERT INTO jobs (id, job_type, payload, state, retry_count, max_retries, \
                           created_at, updated_at) \
         VALUES ($1, $2, '{}'::jsonb, 'pending', 0, 3, now(), now())",
    )
    .bind(Uuid::new_v4())
    .bind(job_type)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
    .map_err(|e| {
        let code = e
            .as_database_error()
            .and_then(|d| d.code())
            .map(|c| c.to_string())
            .unwrap_or_default();
        (code, e.to_string())
    })
}

async fn job_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(pool)
        .await
        .expect("count jobs")
}

/// The application role enqueues NO job type, known, privatization or unknown.
/// Before 119 the first, second and fourth were admitted: any application
/// session could schedule work that the maintenance timer then runs with
/// maintenance authority.
#[sqlx::test(migrations = "../../migrations")]
async fn an_application_session_enqueues_no_job_type(pool: PgPool) {
    let (bypassrls, may_insert): (bool, bool) = sqlx::query_as(
        "SELECT rolbypassrls, has_table_privilege('epigraph_app', 'public.jobs', 'INSERT') \
           FROM pg_roles WHERE rolname = 'epigraph_app'",
    )
    .fetch_one(&pool)
    .await
    .expect("read epigraph_app's posture");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS, so every refusal below is vacuous"
    );
    assert!(
        may_insert,
        "epigraph_app lacks the INSERT GRANT on jobs, so a 42501 below would be the grant and \
         not 119's policy; this test would pass for the wrong reason"
    );

    let before = job_count(&pool).await;
    for job_type in JOB_TYPES {
        let mut tx = pool.begin().await.expect("begin");
        sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_app")
            .execute(&mut *tx)
            .await
            .expect("become epigraph_app");
        let err = insert_job(&mut tx, job_type).await.expect_err(&format!(
            "an application session enqueued a `{job_type}` job; after D9 the queue is run \
                 by a privileged timer, so this is application-scheduled maintenance work"
        ));
        assert_eq!(err.0, "42501", "`{job_type}`: {}", err.1);
        assert!(
            err.1.contains("row-level security policy"),
            "`{job_type}` was refused, but not by jobs_app's WITH CHECK: {}",
            err.1
        );
        tx.rollback().await.expect("rollback");
    }
    assert_eq!(
        job_count(&pool).await,
        before,
        "a refused enqueue left a row"
    );
}

/// The positive control, and the grant half: the maintenance role enqueues
/// (so the refusal above is about the session, not the table), and it may
/// DELETE from every table a job handler deletes from. The privilege check on
/// a DELETE happens whether or not a row matches, so `WHERE false` exercises
/// the grant without needing fixture rows. The sealed-content table is NOT
/// granted: deleting ciphertext belongs to the privatization lifecycle.
#[sqlx::test(migrations = "../../migrations")]
async fn the_maintenance_role_enqueues_and_runs_every_handler_delete(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_maintenance")
        .execute(&mut *tx)
        .await
        .expect("become epigraph_maintenance");
    let (is_super, bypass): (bool, bool) = sqlx::query_as(
        "SELECT r.rolsuper, public.epigraph_bypass() FROM pg_roles r \
          WHERE r.rolname = session_user",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("read the maintenance session's posture");
    assert!(
        !is_super,
        "the maintenance arm runs as a superuser, so it proves nothing about the grants"
    );
    assert!(
        bypass,
        "epigraph_bypass() is false for epigraph_maintenance; the drain could not run"
    );

    for job_type in JOB_TYPES {
        assert_eq!(
            insert_job(&mut tx, job_type).await,
            Ok(1),
            "the maintenance role could not enqueue `{job_type}`"
        );
    }
    for table in HANDLER_DELETE_TABLES {
        let r = sqlx::query(&format!("DELETE FROM public.{table} WHERE false"))
            .execute(&mut *tx)
            .await;
        assert!(
            r.is_ok(),
            "epigraph_maintenance cannot DELETE from {table}; the drain timer's handler that \
             deletes there fails at its first run: {:?}",
            r.err()
        );
    }
    // Committed nothing that matters: roll the whole arm back.
    tx.rollback().await.expect("rollback");

    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_maintenance")
        .execute(&mut *tx)
        .await
        .expect("become epigraph_maintenance");
    let err = sqlx::query("DELETE FROM public.claim_encryption WHERE false")
        .execute(&mut *tx)
        .await
        .expect_err(
            "epigraph_maintenance may DELETE sealed ciphertext; 119 must not grant that (it is \
             the privatization lifecycle's decision)",
        );
    assert_eq!(
        err.as_database_error()
            .and_then(|d| d.code())
            .map(|c| c.to_string())
            .as_deref(),
        Some("42501"),
        "{err}"
    );
    tx.rollback().await.expect("rollback");
}

/// The catalog form of the rule, so a later migration that re-adds an arm is
/// caught even if it happens to admit none of `JOB_TYPES`: `jobs_app`'s WITH
/// CHECK names only the two session predicates.
#[sqlx::test(migrations = "../../migrations")]
async fn jobs_app_admits_only_privileged_sessions(pool: PgPool) {
    let (using, check): (String, String) = sqlx::query_as(
        "SELECT pg_get_expr(p.polqual, p.polrelid), pg_get_expr(p.polwithcheck, p.polrelid) \
           FROM pg_policy p WHERE p.polname = 'jobs_app' AND p.polrelid = 'public.jobs'::regclass",
    )
    .fetch_one(&pool)
    .await
    .expect("jobs_app exists");
    for (name, expr) in [("USING", &using), ("WITH CHECK", &check)] {
        let stripped: String = expr.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(
            stripped,
            "((SELECTepigraph_bypass()ASepigraph_bypass)OR(SELECTepigraph_definer_bypass()ASepigraph_definer_bypass))",
            "jobs_app's {name} admits more than a privileged session: {expr}"
        );
    }
}
