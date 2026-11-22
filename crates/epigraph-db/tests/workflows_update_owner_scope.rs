//! Migration 237 (backlog 524f89c1), as the application role: a hierarchical
//! outcome report moves a `workflows` row's counters through two definers, an
//! UPDATE is owner-scoped, and the recorded submitter is write-once.
//!
//! * `epigraph_workflow_lock_readable` locks a row the session READS (183's
//!   `workflows_read`) and answers whether it did; a row it cannot read is
//!   answered `false` and stays unlocked.
//! * `epigraph_workflow_record_outcome` computes the four counters from the
//!   stored ones exactly as `HierarchicalOutcomeCounters::after_report` does
//!   (pinned on odd stored shapes), writes only those four keys, and refuses a
//!   row the session cannot read (42501) and a variance outside [0, 1] (22023).
//!
//! * `workflows_update_owner`: a direct UPDATE (or row lock) reaches a row
//!   only for a writer of its owner group or a maintenance session; a
//!   non-member of a public row and a reader of a group row reach none.
//! * `workflows_submitter_immutable`: a writer may not change or remove the
//!   recorded submitter; recording a first one, and a maintenance
//!   correction, are admitted.
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
        "SELECT public.epigraph_workflow_lock_readable($1)",
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

/// The definer's arithmetic is `after_report`'s on the stored shapes the
/// rule treats specially: a non-object `metadata`, a counter that is a
/// string, a float, out of i64 range, negative (-1 divided by zero before the
/// rule refused negatives) or at the i64 maximum (it overflowed), and an
/// `avg_variance` that is not a number or is outside [0, 1] (1e308 overflowed
/// the multiply).
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
        r#"{"use_count": -1, "avg_variance": 0.5}"#,
        r#"{"use_count": 9223372036854775807, "success_count": 9223372036854775807, "failure_count": 9223372036854775807, "avg_variance": 0.25}"#,
        r#"{"use_count": 3, "avg_variance": 1e308}"#,
        r#"{"use_count": 3, "avg_variance": -0.5}"#,
        r#"{"use_count": 3, "avg_variance": 1.5}"#,
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

    // A stored mean beyond the float8 range (serde cannot even read it back,
    // so it is outside the parity loop): counted as 0, never cast.
    sqlx::query(
        "UPDATE workflows SET metadata = '{\"use_count\": 1, \"avg_variance\": 1e400}'::jsonb \
          WHERE id = $1",
    )
    .bind(w.public)
    .execute(&pool)
    .await
    .expect("seed the shape");
    let got = record(&w, &w.stranger, w.public, true, 0.5)
        .await
        .expect("a mean beyond float8 counts as 0");
    let c = counters(&got);
    assert_eq!(c.use_count, 2);
    assert!((c.avg_variance - 0.25).abs() < 1e-12, "{c:?}");
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

// ===================================================================
// The policy (237 section 4): an UPDATE, or a row lock, reaches a row only
// for a writer of its owner group, or a maintenance session.
// ===================================================================

/// `Ok(rows)` or `Err(SQLSTATE)` of `sql` (binding the row id, then the
/// viewer's principal as text) on a transaction stamped from `viewer`, rolled
/// back.
async fn write(w: &World, viewer: &Viewer, sql: &str, id: Uuid) -> Result<u64, String> {
    let mut tx = w.scoped.begin_as(viewer).await.expect("stamped tx");
    let r = sqlx::query(sql)
        .bind(id)
        .bind(viewer.principal().map(|p| p.to_string()))
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

const DEPRECATE: &str =
    "UPDATE workflows SET truth_value = 0.05 WHERE id = $1 AND $2::text IS NOT NULL";
const TAKE_OVER: &str = "UPDATE workflows \
     SET metadata = jsonb_set(metadata, '{epigraph_submitted_by}', to_jsonb($2::text)) \
     WHERE id = $1";
const COUNTERS: &str = "UPDATE workflows SET metadata = metadata || '{\"use_count\": 99}' \
     WHERE id = $1 AND $2::text IS NOT NULL";
const LOCK: &str = "SELECT id FROM workflows WHERE id = $1 AND $2::text IS NOT NULL FOR UPDATE";

/// THE DEFECT. A non-member of a PUBLIC row, and a READER of a group row (on
/// that row and on the group's public row), reach neither with a direct
/// UPDATE of `truth_value` (deprecation), of `epigraph_submitted_by` (taking
/// the row over through the entry points' submitter arm) or of the counters,
/// nor with a row lock. Below 237 each statement here wrote 1 row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_writer_updates_no_workflow_row(pool: PgPool) {
    let w = world(&pool).await;
    for (who, viewer, id) in [
        ("non-member on a public row", &w.stranger, w.public),
        ("reader on its group's row", &w.reader, w.private),
        ("reader on its group's public row", &w.reader, w.public),
    ] {
        let before = row(&pool, id).await;
        for (what, sql) in [
            ("deprecate", DEPRECATE),
            ("take over", TAKE_OVER),
            ("counters", COUNTERS),
            ("row lock", LOCK),
        ] {
            assert_eq!(
                write(&w, viewer, sql, id).await,
                Ok(0),
                "{who}: {what} must reach no row"
            );
        }
        assert_eq!(row(&pool, id).await, before, "{who}: the row is unchanged");
        // It still READS the row (183's read rule is untouched).
        let mut read = w.scoped.read_as(viewer).await.expect("stamped read");
        let seen: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM workflows WHERE id = $1)")
                .bind(id)
                .fetch_one(&mut *read)
                .await
                .expect("read");
        read.commit().await.expect("close read");
        assert!(seen, "{who}: the row stays readable");
    }
}

/// The positive control: a writer of the owner group still updates and locks
/// its public and its group row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_writer_of_the_owner_group_still_updates_its_rows(pool: PgPool) {
    let w = world(&pool).await;
    for id in [w.public, w.private] {
        for (what, sql) in [
            ("deprecate", DEPRECATE),
            ("counters", COUNTERS),
            ("row lock", LOCK),
        ] {
            assert_eq!(write(&w, &w.member, sql, id).await, Ok(1), "{what}");
        }
    }
}

/// The carve-out: a maintenance session updates any row (077's bypass arm),
/// as the privatization, re-own and submitter verbs do.
#[sqlx::test(migrations = "../../migrations")]
async fn a_maintenance_session_still_updates_any_row(pool: PgPool) {
    let w = world(&pool).await;
    let ids = vec![w.public, w.private];
    let r: Result<u64, String> =
        fixture::as_role(&pool, "epigraph_maintenance", move |mut conn| async move {
            let r = sqlx::query("UPDATE workflows SET truth_value = 0.05 WHERE id = ANY($1)")
                .bind(ids)
                .execute(&mut *conn)
                .await
                .map(|r| r.rows_affected())
                .map_err(|e| e.to_string());
            (conn, r)
        })
        .await;
    assert_eq!(r, Ok(2));
    assert_eq!(row(&pool, w.public).await.1, 0.05);
    assert_eq!(row(&pool, w.private).await.1, 0.05);
}

// ===================================================================
// The recorded submitter is write-once to an ordinary session (237 section 5).
// ===================================================================

/// A WRITER of the owner group may update the row, but not re-name its
/// recorded submitter (which would hand another agent the entry points'
/// submitter arm over the row): changing, removing or wiping the key is
/// refused 42501. Editing another key, and recording a submitter on a row
/// that has none (`record_submitter`), are admitted; a maintenance session
/// corrects one.
#[sqlx::test(migrations = "../../migrations")]
async fn the_recorded_submitter_is_write_once(pool: PgPool) {
    let w = world(&pool).await;
    let (before, _) = row(&pool, w.private).await;
    for (what, sql) in [
        ("re-name", TAKE_OVER),
        (
            "remove",
            "UPDATE workflows SET metadata = metadata - 'epigraph_submitted_by' \
             WHERE id = $1 AND $2::text IS NOT NULL",
        ),
        (
            "wipe",
            "UPDATE workflows SET metadata = '{}'::jsonb WHERE id = $1 AND $2::text IS NOT NULL",
        ),
        (
            "non-object",
            "UPDATE workflows SET metadata = 'null'::jsonb WHERE id = $1 AND $2::text IS NOT NULL",
        ),
    ] {
        assert_eq!(
            write(&w, &w.member, sql, w.private).await,
            Err("42501".into()),
            "a writer may not {what} the recorded submitter"
        );
    }
    assert_eq!(row(&pool, w.private).await.0, before, "nothing written");
    assert_eq!(
        write(&w, &w.member, COUNTERS, w.private).await,
        Ok(1),
        "another key is still the writer's to edit"
    );

    // A row with no recorded submitter: recording one is admitted, once.
    sqlx::query("UPDATE workflows SET metadata = metadata - 'epigraph_submitted_by' WHERE id = $1")
        .bind(w.public)
        .execute(&pool)
        .await
        .expect("forget the submitter (harness)");
    let me = w.member.principal().expect("member principal");
    let mut tx = w.scoped.begin_as(&w.member).await.expect("stamped tx");
    let recorded = epigraph_db::WorkflowRepository::record_submitter(&mut *tx, w.public, me)
        .await
        .expect("record_submitter");
    tx.commit().await.expect("commit");
    assert!(recorded, "a writer records the first submitter");
    assert_eq!(
        row(&pool, w.public).await.0["epigraph_submitted_by"],
        serde_json::json!(me.to_string())
    );

    // The maintenance correction (`set-workflow-submitter`).
    let id = w.private;
    let r: Result<u64, String> =
        fixture::as_role(&pool, "epigraph_maintenance", move |mut conn| async move {
            let r = sqlx::query(
                "UPDATE workflows \
                 SET metadata = jsonb_set(metadata, '{epigraph_submitted_by}', '\"corrected\"') \
                 WHERE id = $1",
            )
            .bind(id)
            .execute(&mut *conn)
            .await
            .map(|r| r.rows_affected())
            .map_err(|e| e.to_string());
            (conn, r)
        })
        .await;
    assert_eq!(r, Ok(1));
    assert_eq!(
        row(&pool, w.private).await.0["epigraph_submitted_by"],
        serde_json::json!("corrected")
    );
}

// ===================================================================
// add_step's plan lock (`WorkflowRepository::lock_for_plan_edit`).
// ===================================================================

/// `add_step` serializes concurrent appends to one plan by locking its
/// `workflows` row, and the entry points admit callers that do not write the
/// row's owner group (the submitter, its operator, a delegate, the audited
/// admin) to a PUBLIC plan. Such a caller's lock still takes the row: it is
/// held (a second locker gets 55P03 under NOWAIT) until the caller's
/// transaction ends. A row the caller cannot read is answered `false`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_plan_edit_lock_holds_a_readable_row_the_caller_does_not_write(pool: PgPool) {
    let w = world(&pool).await;
    let mut tx = w.scoped.begin_as(&w.stranger).await.expect("stamped tx");
    let locked = epigraph_db::WorkflowRepository::lock_for_plan_edit(&mut *tx, w.public)
        .await
        .expect("lock_for_plan_edit");
    assert!(locked, "a reader of the public row locks it");
    let held = sqlx::query("SELECT 1 FROM workflows WHERE id = $1 FOR UPDATE NOWAIT")
        .bind(w.public)
        .execute(&pool)
        .await
        .map_err(|e| {
            e.as_database_error()
                .and_then(|d| d.code().map(|c| c.to_string()))
                .unwrap_or_default()
        });
    assert_eq!(held.map(|_| ()), Err("55P03".into()), "the row is held");
    let unreadable = epigraph_db::WorkflowRepository::lock_for_plan_edit(&mut *tx, w.private)
        .await
        .expect("lock_for_plan_edit");
    assert!(!unreadable, "a row the caller cannot read is not locked");
    tx.rollback().await.expect("rollback");
    sqlx::query("SELECT 1 FROM workflows WHERE id = $1 FOR UPDATE NOWAIT")
        .bind(w.public)
        .execute(&pool)
        .await
        .expect("released with the transaction");
}

// ===================================================================
// A deprecation's lineage lock
// (`WorkflowRepository::lock_lineages_for_deprecation`).
// ===================================================================

/// Generation `generation` of lineage `name`, `visibility` in group `owner`.
async fn lineage_row(
    pool: &PgPool,
    name: &str,
    generation: i32,
    visibility: &str,
    owner: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 'a goal', $4, $5)",
    )
    .bind(id)
    .bind(name)
    .bind(generation)
    .bind(visibility)
    .bind(owner)
    .execute(pool)
    .await
    .expect("lineage row");
    id
}

/// Whether another session finds `id` row-locked (`55P03` under NOWAIT).
async fn held_elsewhere(pool: &PgPool, id: Uuid) -> bool {
    match sqlx::query("SELECT 1 FROM workflows WHERE id = $1 FOR UPDATE NOWAIT")
        .bind(id)
        .execute(pool)
        .await
    {
        Ok(_) => false,
        Err(e) => {
            let code = e
                .as_database_error()
                .and_then(|d| d.code().map(|c| c.to_string()));
            assert_eq!(code.as_deref(), Some("55P03"), "unexpected error: {e}");
            true
        }
    }
}

/// Two deprecations of one lineage serialize on its rows (U017's write-skew
/// guard), and a PUBLIC lineage may hold generations in different owner
/// groups (a new generation of a public lineage the caller does not write
/// lands in the caller's own group). So the lock takes EVERY generation the
/// caller reads, including one in a group it does not write; a lock on the
/// stamp takes only the rows the caller writes since 237 and leaves gen1 free,
/// and then two concurrent deprecations of gen0 and gen1 would each keep the
/// step they share. A generation the caller cannot read is not locked.
#[sqlx::test(migrations = "../../migrations")]
async fn the_lineage_lock_holds_every_readable_generation_across_owner_groups(pool: PgPool) {
    let w = world(&pool).await;
    let (_, other) = fixture::seed_agent_with_group(&pool, "wf237-other-writer").await;
    assert!(
        !w.member.writable_groups().contains(&other),
        "fixture: the member does not write the other group"
    );
    let name = format!("wf237-lineage-{}", Uuid::new_v4());
    let gen0 = lineage_row(&pool, &name, 0, "public", w.g).await;
    let gen1 = lineage_row(&pool, &name, 1, "public", other).await;
    let gen2 = lineage_row(&pool, &name, 2, "group", other).await;
    let unrelated = lineage_row(&pool, &format!("{name}-x"), 0, "public", w.g).await;

    let mut tx = w.scoped.begin_as(&w.member).await.expect("stamped tx");
    epigraph_db::WorkflowRepository::lock_lineages_for_deprecation(&mut tx, &[gen0])
        .await
        .expect("lock the lineage");
    assert!(held_elsewhere(&pool, gen0).await, "the target's own row");
    assert!(
        held_elsewhere(&pool, gen1).await,
        "a public generation in a group the caller does not write is locked too"
    );
    assert!(
        !held_elsewhere(&pool, gen2).await,
        "a generation the caller cannot read is not locked"
    );
    assert!(
        !held_elsewhere(&pool, unrelated).await,
        "another lineage is not locked"
    );
    tx.rollback().await.expect("rollback");
    assert!(
        !held_elsewhere(&pool, gen1).await,
        "released with the transaction"
    );
}

// ===================================================================
// The audited admin deprecation of a row
// (`epigraph_admin_deprecate_workflow_row`).
// ===================================================================

async fn admin_client(pool: &PgPool, agent: Uuid, scopes: &[&str], status: &str) -> Uuid {
    let id = Uuid::new_v4();
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id) \
         VALUES ($1, $2, 'wf237 admin', 'human', $3, $3, $4, $5)",
    )
    .bind(id)
    .bind(format!("wf237-admin-{id}"))
    .bind(&scopes)
    .bind(status)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed the admin's client");
    id
}

/// `Ok(rows changed)` or `Err(SQLSTATE)` of the admin definer, on a
/// transaction stamped from `viewer`, committed when it succeeds.
async fn admin_deprecate(
    w: &World,
    viewer: &Viewer,
    client: Uuid,
    id: Uuid,
    details: serde_json::Value,
) -> Result<u64, String> {
    let mut tx = w.scoped.begin_as(viewer).await.expect("stamped tx");
    let r = epigraph_db::WorkflowRepository::admin_deprecate_row(
        &mut tx,
        client,
        Uuid::new_v4(),
        id,
        &details,
    )
    .await
    .map_err(|e| {
        e.as_database_error()
            .and_then(|d| d.code().map(|c| c.to_string()))
            .unwrap_or_else(|| e.to_string())
    });
    if r.is_ok() {
        tx.commit().await.expect("commit");
    }
    r
}

/// The audit rows the admin definer wrote for `agent`, oldest first.
async fn admin_audits(pool: &PgPool, agent: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details FROM security_events \
          WHERE event_type = 'workflows.admin_write' AND agent_id = $1 ORDER BY created_at, id",
    )
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("audit rows")
}

/// 237's carve-out for the audited admin path. A caller that writes none of
/// the row's groups (here a stranger to a group row it cannot even read, and
/// to a public row) deprecates it only through the definer, and only with a
/// live `claims:admin` grant through its client: no client, a de-scoped one
/// and a revoked one are refused (42501) with nothing written and no audit
/// row. With the grant it sets `truth_value` to 0.05 (and only that), and
/// writes one `workflows.admin_write` row naming the admin, the client and
/// the row before and after, under which the caller's own details sit; a
/// clash is decided by the definer's facts. A re-run changes nothing and says
/// so. A direct UPDATE by the same session still reaches no row.
#[sqlx::test(migrations = "../../migrations")]
async fn the_admin_deprecation_rechecks_the_live_grant_and_audits(pool: PgPool) {
    let w = world(&pool).await;
    let admin = w.stranger.principal().expect("the stranger's principal");
    let details = serde_json::json!({"reason": "obsolete", "workflow_id": "forged"});

    // No live grant: refused, nothing written, nothing audited.
    let none = Uuid::new_v4();
    let descoped = admin_client(&pool, admin, &["claims:write"], "active").await;
    let revoked = admin_client(&pool, admin, &["claims:admin"], "revoked").await;
    let others = admin_client(
        &pool,
        w.member.principal().expect("member"),
        &["claims:admin"],
        "active",
    )
    .await;
    for (label, client) in [
        ("no client", none),
        ("de-scoped", descoped),
        ("revoked", revoked),
        ("another agent's client", others),
    ] {
        assert_eq!(
            admin_deprecate(&w, &w.stranger, client, w.private, details.clone()).await,
            Err("42501".into()),
            "{label}"
        );
    }
    assert!(
        (row(&pool, w.private).await.1 - 1.0).abs() < 1e-12,
        "row untouched"
    );
    assert!(
        admin_audits(&pool, admin).await.is_empty(),
        "nothing audited"
    );

    // Details that are not an object are refused.
    let granted = admin_client(&pool, admin, &["claims:admin"], "active").await;
    assert_eq!(
        admin_deprecate(&w, &w.stranger, granted, w.private, serde_json::json!([1])).await,
        Err("22023".into())
    );

    // CALIBRATION: the same session's direct UPDATE reaches no row.
    assert_eq!(write(&w, &w.stranger, DEPRECATE, w.public).await, Ok(0));

    // With a live grant: deprecated, audited, only `truth_value` moved.
    let (meta_before, _) = row(&pool, w.public).await;
    assert_eq!(
        admin_deprecate(&w, &w.stranger, granted, w.public, details.clone()).await,
        Ok(1)
    );
    let (meta_after, truth) = row(&pool, w.public).await;
    assert!((truth - 0.05).abs() < 1e-12, "deprecated: {truth}");
    assert_eq!(meta_after, meta_before, "metadata untouched");
    let audits = admin_audits(&pool, admin).await;
    assert_eq!(audits.len(), 1, "{audits:?}");
    let a = &audits[0];
    assert_eq!(a["reason"], "obsolete", "the caller's details are kept");
    assert_eq!(
        a["workflow_id"],
        serde_json::json!(w.public.to_string()),
        "the definer's facts win"
    );
    assert_eq!(a["admin_agent_id"], serde_json::json!(admin.to_string()));
    assert_eq!(a["client_id"], serde_json::json!(granted.to_string()));
    assert_eq!(
        a["workflow_row"]["owner_group_id"],
        serde_json::json!(w.g.to_string())
    );
    assert_eq!(a["workflow_row"]["truth_value_before"].as_f64(), Some(1.0));
    assert_eq!(a["workflow_row"]["changed"], serde_json::json!(true));

    // A re-run changes nothing, and its audit row says so.
    assert_eq!(
        admin_deprecate(&w, &w.stranger, granted, w.public, details.clone()).await,
        Ok(0)
    );
    let audits = admin_audits(&pool, admin).await;
    assert_eq!(audits.len(), 2);
    assert_eq!(
        audits[1]["workflow_row"]["changed"],
        serde_json::json!(false)
    );

    // An unknown row: P0002, nothing audited.
    assert_eq!(
        admin_deprecate(&w, &w.stranger, granted, Uuid::new_v4(), details).await,
        Err("P0002".into())
    );
    assert_eq!(admin_audits(&pool, admin).await.len(), 2);
}

/// The definer reads the admin from the SESSION principal, never from an
/// argument: an application session with no principal stamped is refused
/// (42501), whatever client it names.
#[sqlx::test(migrations = "../../migrations")]
async fn the_admin_deprecation_needs_the_session_principal(pool: PgPool) {
    let w = world(&pool).await;
    let admin = w.stranger.principal().expect("the stranger's principal");
    let granted = admin_client(&pool, admin, &["claims:admin"], "active").await;
    let public = w.public;
    let r = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r = sqlx::query_scalar::<_, i64>(
            "SELECT public.epigraph_admin_deprecate_workflow_row($1, $2, $3, '{}'::jsonb)",
        )
        .bind(granted)
        .bind(Uuid::new_v4())
        .bind(public)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| {
            e.as_database_error()
                .map(|d| (d.code().map(|c| c.to_string()), d.message().to_string()))
                .unwrap_or_default()
        });
        (conn, r)
    })
    .await;
    let (code, message) = r.expect_err("no principal, no deprecation");
    assert_eq!(code.as_deref(), Some("42501"));
    assert!(
        message.contains("ADM01"),
        "refused for the missing principal, not the grant: {message}"
    );
    assert!(
        (row(&pool, w.public).await.1 - 1.0).abs() < 1e-12,
        "row untouched"
    );
}

// ===================================================================
// The undo (`docs/runbooks/237-undo.sql`).
// ===================================================================

/// `(policy, trigger, guard, lock definer, counter definer, admin
/// deprecation definer)` present.
async fn objects_237(pool: &PgPool) -> (bool, bool, bool, bool, bool, bool) {
    sqlx::query_as(
        "SELECT \
           EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' \
                     AND tablename = 'workflows' AND policyname = 'workflows_update_owner'), \
           EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'public.workflows'::regclass \
                     AND tgname = 'workflows_submitter_immutable'), \
           to_regprocedure('public.epigraph_workflows_submitter_guard()') IS NOT NULL, \
           to_regprocedure('public.epigraph_workflow_lock_readable(uuid)') IS NOT NULL, \
           to_regprocedure('public.epigraph_workflow_record_outcome(uuid, boolean, \
                                                                    double precision)') \
             IS NOT NULL, \
           to_regprocedure('public.epigraph_admin_deprecate_workflow_row(uuid, uuid, uuid, \
                                                                         jsonb)') \
             IS NOT NULL",
    )
    .fetch_one(pool)
    .await
    .expect("catalog")
}

/// The undo removes exactly 237's objects, twice without error, and a
/// non-member's direct UPDATE of a public row reaches it again (the rule 237
/// replaced), while 183's policies stay.
#[sqlx::test(migrations = "../../migrations")]
async fn the_237_undo_returns_the_table_to_below_237(pool: PgPool) {
    let w = world(&pool).await;
    assert_eq!(
        objects_237(&pool).await,
        (true, true, true, true, true, true)
    );
    let undo = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/runbooks/237-undo.sql"
    ))
    .expect("read the undo");
    for run in 1..=2 {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("undo run {run}: {e}"));
        assert_eq!(
            objects_237(&pool).await,
            (false, false, false, false, false, false),
            "after undo run {run}"
        );
    }
    let kept: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_policies WHERE schemaname = 'public' AND tablename = 'workflows' \
           AND policyname IN ('workflows_read', 'workflows_insert', 'workflows_update', \
                              'workflows_delete_owner')",
    )
    .fetch_one(&pool)
    .await
    .expect("183's policies");
    assert_eq!(kept, 4, "183's policies are untouched");
    assert_eq!(
        write(&w, &w.stranger, DEPRECATE, w.public).await,
        Ok(1),
        "below 237 a non-member's UPDATE reaches a public row"
    );
}
