//! Migration 237 (backlog 524f89c1): a hierarchical outcome report moves a
//! `workflows` row's counters through two definers, as the application role.
//!
//! * `epigraph_workflow_outcome_lock` locks a row the session READS (183's
//!   `workflows_read`) and answers whether it did; a row it cannot read is
//!   answered `false` and stays unlocked.
//! * `epigraph_workflow_record_outcome` computes the four counters from the
//!   stored ones exactly as `HierarchicalOutcomeCounters::after_report` does
//!   (pinned on odd stored shapes), writes only those four keys, and refuses a
//!   row the session cannot read (42501) and a variance outside [0, 1] (22023).
//!
//! Every write runs on `epigraph_app` under a real stamp
//! (`ScopedPool::connect_downgraded_for_tests`); fixtures are seeded and read
//! back on the superuser pool.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{HierarchicalOutcomeCounters, ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;

struct World {
    scoped: ScopedPool,
    /// Writer (admin) of `g`.
    member: Viewer,
    /// A reader of `g`, writer of its own personal group only.
    reader: Viewer,
    /// In no group of `g`'s.
    stranger: Viewer,
    g: Uuid,
    /// `('public', g)`.
    public: Uuid,
    /// `('group', g)`.
    private: Uuid,
}

async fn declared_row(pool: &PgPool, name: &str, visibility: &str, owner: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal, visibility, owner_group_id, metadata) \
         VALUES ($1, $2, 'a goal', $3, $4, \
                 jsonb_build_object('epigraph_submitted_by', $5::text, 'note', 'keep me'))",
    )
    .bind(id)
    .bind(format!("{name}-{id}"))
    .bind(visibility)
    .bind(owner)
    .bind(Uuid::new_v4().to_string())
    .execute(pool)
    .await
    .expect("declared workflow row");
    id
}

async fn world(pool: &PgPool) -> World {
    let (m, g) = fixture::seed_agent_with_group(pool, "wf237-member").await;
    let (r, _) = fixture::seed_agent_with_group(pool, "wf237-reader").await;
    let (s, _) = fixture::seed_agent_with_group(pool, "wf237-stranger").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(g)
    .bind(r)
    .execute(pool)
    .await
    .expect("reader membership");
    let public = declared_row(pool, "wf237-public", "public", g).await;
    let private = declared_row(pool, "wf237-private", "group", g).await;
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let bypass: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypass,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let reader = Viewer::resolve(pool, r).await.expect("reader viewer");
    assert!(
        reader.group_bind().is_some_and(|gs| gs.contains(&g))
            && !reader.writable_groups().contains(&g),
        "fixture: the reader reads g and does not write it"
    );
    World {
        scoped,
        member: Viewer::resolve(pool, m).await.expect("member viewer"),
        reader,
        stranger: Viewer::resolve(pool, s).await.expect("stranger viewer"),
        g,
        public,
        private,
    }
}

/// `Ok(value)` or `Err(SQLSTATE)` of a one-value query on a transaction
/// stamped from `viewer`, committed when it succeeds.
async fn scalar<T>(w: &World, viewer: &Viewer, sql: &str, binds: Binds) -> Result<T, String>
where
    T: for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Send + Unpin,
{
    let mut tx = w.scoped.begin_as(viewer).await.expect("stamped tx");
    let mut q = sqlx::query_scalar::<_, T>(sql).bind(binds.id);
    if let Some(b) = binds.success {
        q = q.bind(b);
    }
    if let Some(v) = binds.variance {
        q = q.bind(v);
    }
    let r = q.fetch_one(&mut *tx).await.map_err(|e| {
        e.as_database_error()
            .and_then(|d| d.code().map(|c| c.to_string()))
            .unwrap_or_else(|| e.to_string())
    });
    if r.is_ok() {
        tx.commit().await.expect("commit");
    }
    r
}

#[derive(Clone, Copy)]
struct Binds {
    id: Uuid,
    success: Option<bool>,
    variance: Option<f64>,
}

async fn lock(w: &World, viewer: &Viewer, id: Uuid) -> Result<bool, String> {
    scalar(
        w,
        viewer,
        "SELECT public.epigraph_workflow_outcome_lock($1)",
        Binds {
            id,
            success: None,
            variance: None,
        },
    )
    .await
}

async fn record(
    w: &World,
    viewer: &Viewer,
    id: Uuid,
    success: bool,
    variance: f64,
) -> Result<serde_json::Value, String> {
    scalar(
        w,
        viewer,
        "SELECT public.epigraph_workflow_record_outcome($1, $2, $3)",
        Binds {
            id,
            success: Some(success),
            variance: Some(variance),
        },
    )
    .await
}

async fn row(pool: &PgPool, id: Uuid) -> (serde_json::Value, f64) {
    sqlx::query_as("SELECT metadata, truth_value FROM workflows WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("workflow row")
}

fn counters(v: &serde_json::Value) -> HierarchicalOutcomeCounters {
    serde_json::from_value(v.clone()).expect("counters decode")
}

/// A non-member of a PUBLIC row and a reader of a GROUP row each lock the row
/// and move its counters through the definer, which writes the four counter
/// keys and nothing else (the submitter key, another key and `truth_value`
/// are as they were).
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_moves_only_the_four_counters(pool: PgPool) {
    let w = world(&pool).await;
    for (viewer, id) in [(&w.stranger, w.public), (&w.reader, w.private)] {
        let (before, truth_before) = row(&pool, id).await;
        assert_eq!(lock(&w, viewer, id).await, Ok(true));
        let first = record(&w, viewer, id, true, 0.5)
            .await
            .expect("first report");
        assert_eq!(
            counters(&first),
            HierarchicalOutcomeCounters {
                use_count: 1,
                success_count: 1,
                failure_count: 0,
                avg_variance: 0.5,
            }
        );
        let second = record(&w, viewer, id, false, 0.0)
            .await
            .expect("second report");
        assert_eq!(
            counters(&second),
            HierarchicalOutcomeCounters {
                use_count: 2,
                success_count: 1,
                failure_count: 1,
                avg_variance: 0.25,
            }
        );
        let (after, truth_after) = row(&pool, id).await;
        assert_eq!(truth_after, truth_before, "truth_value untouched");
        let mut expected = before.clone();
        counters(&second).write_into(&mut expected);
        for k in ["use_count", "success_count", "failure_count"] {
            assert_eq!(after[k].as_i64(), expected[k].as_i64(), "{k}: {after}");
        }
        assert_eq!(after["avg_variance"].as_f64(), Some(0.25), "{after}");
        assert_eq!(
            after["epigraph_submitted_by"], before["epigraph_submitted_by"],
            "the submitter key is untouched: {after}"
        );
        assert_eq!(after["note"], serde_json::json!("keep me"), "{after}");
        assert_eq!(
            after.as_object().map(serde_json::Map::len),
            Some(6),
            "exactly the two seeded keys and the four counters: {after}"
        );
    }
    // The member (a writer) is admitted the same way.
    assert_eq!(lock(&w, &w.member, w.private).await, Ok(true));
}

/// The definer's arithmetic is `after_report`'s on every stored shape the
/// Rust rule treats specially: a non-object `metadata`, a counter that is a
/// string, a float, out of i64 range or negative, and an `avg_variance` that
/// is not a number.
#[sqlx::test(migrations = "../../migrations")]
async fn the_counters_follow_after_report_on_odd_stored_shapes(pool: PgPool) {
    let w = world(&pool).await;
    let shapes = [
        "null",
        "[1, 2]",
        "\"text\"",
        "{}",
        r#"{"use_count": "3", "success_count": 2, "avg_variance": "x"}"#,
        r#"{"use_count": 1, "avg_variance": "0.5"}"#,
        r#"{"use_count": 2.0, "success_count": 2.5, "failure_count": 1}"#,
        r#"{"use_count": 9999999999999999999, "failure_count": -9999999999999999999}"#,
        r#"{"use_count": 18446744073709551615, "avg_variance": 0.75}"#,
        r#"{"use_count": -2, "success_count": -1, "avg_variance": 0.5}"#,
        r#"{"use_count": 1e2, "success_count": 40, "failure_count": 60, "avg_variance": 0.125}"#,
        r#"{"use_count": 7, "success_count": 3, "failure_count": 4, "avg_variance": 0.3, "k": [1]}"#,
    ];
    for (i, shape) in shapes.iter().enumerate() {
        for (success, variance) in [(true, 0.0), (false, 1.0), (true, 1.0 / 3.0)] {
            sqlx::query("UPDATE workflows SET metadata = $2::jsonb WHERE id = $1")
                .bind(w.public)
                .bind(shape)
                .execute(&pool)
                .await
                .expect("seed the shape");
            let (stored, _) = row(&pool, w.public).await;
            let expected = HierarchicalOutcomeCounters::after_report(&stored, success, variance);
            let got = record(&w, &w.stranger, w.public, success, variance)
                .await
                .unwrap_or_else(|e| panic!("shape {i} {shape}: {e}"));
            assert_eq!(
                counters(&got),
                expected,
                "shape {i} {shape}, success {success}, variance {variance}"
            );
            let mut want = stored.clone();
            expected.write_into(&mut want);
            let (after, _) = row(&pool, w.public).await;
            let want = want
                .as_object()
                .expect("write_into leaves an object")
                .clone();
            let after = after
                .as_object()
                .expect("an object after the report")
                .clone();
            assert_eq!(
                after.keys().collect::<Vec<_>>(),
                want.keys().collect::<Vec<_>>(),
                "shape {i} {shape}: the same keys as write_into"
            );
            for (k, v) in &want {
                if v.is_number() {
                    assert_eq!(after[k].as_f64(), v.as_f64(), "shape {i} {shape}: {k}");
                } else {
                    assert_eq!(&after[k], v, "shape {i} {shape}: {k}");
                }
            }
        }
    }
}

/// A row the session cannot read is not locked (`false`) and its counters
/// are refused (42501), with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_row_the_session_cannot_read_is_neither_locked_nor_counted(pool: PgPool) {
    let w = world(&pool).await;
    let (before, _) = row(&pool, w.private).await;
    assert_eq!(lock(&w, &w.stranger, w.private).await, Ok(false));
    assert_eq!(
        record(&w, &w.stranger, w.private, true, 0.0).await,
        Err("42501".into())
    );
    assert_eq!(
        lock(&w, &w.stranger, Uuid::new_v4()).await,
        Ok(false),
        "an unknown id is answered like an unreadable one"
    );
    assert_eq!(row(&pool, w.private).await.0, before, "nothing written");
    let _ = w.g;
}

/// A variance outside [0, 1], NaN or infinite is refused (22023) before any
/// write, so a direct caller cannot poison the mean.
#[sqlx::test(migrations = "../../migrations")]
async fn a_variance_outside_the_unit_interval_is_refused(pool: PgPool) {
    let w = world(&pool).await;
    let (before, _) = row(&pool, w.public).await;
    for bad in [1.5, -0.1, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            record(&w, &w.stranger, w.public, true, bad).await,
            Err("22023".into()),
            "variance {bad}"
        );
    }
    assert_eq!(row(&pool, w.public).await.0, before, "nothing written");
    // The boundary values land.
    record(&w, &w.stranger, w.public, true, 0.0)
        .await
        .expect("0 lands");
    record(&w, &w.stranger, w.public, true, 1.0)
        .await
        .expect("1 lands");
}
