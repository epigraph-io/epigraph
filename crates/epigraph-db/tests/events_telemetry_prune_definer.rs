//! Migration 250, part 1: the maintenance role prunes `events` only through a
//! telemetry-only definer and no longer holds table-wide DELETE or UPDATE on
//! `events` (backlog 062d7767).
//!
//! # What was wrong, measured on the base
//!
//! Migration 186 granted `epigraph_maintenance` DELETE on `events` so the
//! retention job could prune telemetry, and 070 had already granted it UPDATE.
//! 189 closed `events` to the application role only. So any session acting as
//! the maintenance role could delete or rewrite any `events` row, provenance
//! events such as `claim.created` included, not only expired telemetry: the
//! type and age filters were the job's, in Rust. With UPDATE alone it could
//! also re-type a provenance row to `tool.invoked` and let the job prune it.
//!
//! # What is pinned
//!
//! * a maintenance session's DELETE of a `claim.created` row, and its UPDATE
//!   of that row's type or payload, are refused with 42501 and the row is
//!   unchanged (red on the base: the DELETE removes the row);
//! * `RecallEventRepository::prune_telemetry_events` on a maintenance session
//!   deletes exactly the expired telemetry row, through the definer, and the
//!   INVOKER cascade (`events_cascade_edges`) still removes an edge naming it;
//! * the application role cannot execute the definer;
//! * the definer's type list is exactly `PRUNABLE_EVENT_TYPES`, and the
//!   dry-run count reads the same list;
//! * the definer's shape: SECURITY DEFINER, owned by the owner of `events`
//!   (never the maintenance role, which no longer holds DELETE there), EXECUTE
//!   granted to the maintenance role only.
//!
//! The end-to-end run of the real binary on a non-superuser maintenance LOGIN
//! is `epigraph-cli/tests/prune_recall_events_maintenance.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{RecallEventRepository, PRUNABLE_EVENT_TYPES};
use sqlx::PgPool;
use uuid::Uuid;

/// A pool whose connections are `SET SESSION AUTHORIZATION <role>` (a
/// test-local literal), so `session_user` and `current_user` are both `role`.
async fn role_pool(pool: &PgPool, role: &'static str) -> PgPool {
    use sqlx::Executor;
    let url = fixture::database_url_for(pool).await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                conn.execute(format!("SET SESSION AUTHORIZATION {role}").as_str())
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("role pool")
}

fn sqlstate<T: std::fmt::Debug>(r: Result<T, sqlx::Error>) -> Option<String> {
    match r {
        Ok(v) => panic!("expected a database error, got Ok({v:?})"),
        Err(e) => e
            .as_database_error()
            .and_then(|d| d.code().map(|c| c.to_string())),
    }
}

async fn seed_event(pool: &PgPool, event_type: &str, age_days: i32) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO events (event_type, payload, graph_version, created_at) \
         VALUES ($1, '{\"k\": 1}'::jsonb, 0, now() - make_interval(days => $2)) RETURNING id",
    )
    .bind(event_type)
    .bind(age_days)
    .fetch_one(pool)
    .await
    .expect("seed an event")
}

async fn exists(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM events WHERE id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read back")
}

/// The red test for 062d7767. On the base the DELETE removes the provenance
/// row (186's grant) and the UPDATE re-types it (070's grant).
#[sqlx::test(migrations = "../../migrations")]
async fn a_maintenance_session_cannot_delete_or_rewrite_a_provenance_event(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "t62-prov").await;
    let provenance = seed_event(&pool, "claim.created", 400).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'event', $2, 'agent', 'TEST_EDGE')",
    )
    .bind(provenance)
    .bind(agent)
    .execute(&pool)
    .await
    .expect("an edge naming the provenance event");

    let maint = role_pool(&pool, "epigraph_maintenance").await;
    let deleted = sqlx::query("DELETE FROM events WHERE id = $1")
        .bind(provenance)
        .execute(&maint)
        .await
        .map(|r| r.rows_affected());
    let retyped = sqlx::query("UPDATE events SET event_type = 'tool.invoked' WHERE id = $1")
        .bind(provenance)
        .execute(&maint)
        .await
        .map(|r| r.rows_affected());
    let rewritten = sqlx::query("UPDATE events SET payload = '{}'::jsonb WHERE id = $1")
        .bind(provenance)
        .execute(&maint)
        .await
        .map(|r| r.rows_affected());
    let truncated = sqlx::query("TRUNCATE events")
        .execute(&maint)
        .await
        .map(|r| r.rows_affected());
    // The definer itself never selects a provenance row, whatever the window.
    let pruned: Result<i64, _> =
        sqlx::query_scalar("SELECT public.epigraph_prune_telemetry_events(1)")
            .fetch_one(&maint)
            .await;
    maint.close().await;

    let (event_type, payload, edges): (String, serde_json::Value, i64) = sqlx::query_as(
        "SELECT e.event_type, e.payload, \
                (SELECT count(*) FROM edges WHERE source_id = e.id) \
           FROM events e WHERE e.id = $1",
    )
    .bind(provenance)
    .fetch_one(&pool)
    .await
    .expect("the provenance event is still there");
    assert_eq!(sqlstate(deleted).as_deref(), Some("42501"), "DELETE events");
    assert_eq!(sqlstate(retyped).as_deref(), Some("42501"), "UPDATE type");
    assert_eq!(
        sqlstate(rewritten).as_deref(),
        Some("42501"),
        "UPDATE payload"
    );
    assert_eq!(sqlstate(truncated).as_deref(), Some("42501"), "TRUNCATE");
    assert_eq!(
        pruned.expect("the definer runs"),
        0,
        "no telemetry to prune"
    );
    assert_eq!(
        (event_type.as_str(), payload, edges),
        ("claim.created", serde_json::json!({"k": 1}), 1),
        "the provenance event, its payload and the edge naming it are unchanged"
    );

    let grants: (bool, bool, bool) = sqlx::query_as(
        "SELECT has_table_privilege('epigraph_maintenance', 'public.events', 'DELETE'), \
                has_table_privilege('epigraph_maintenance', 'public.events', 'UPDATE'), \
                has_table_privilege('epigraph_maintenance', 'public.events', 'TRUNCATE')",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog");
    assert_eq!(grants, (false, false, false), "(DELETE, UPDATE, TRUNCATE)");
}

/// The retention job's call on a maintenance session prunes exactly the
/// expired telemetry row, through the definer, and the INVOKER cascade still
/// removes an edge naming it (the definer's path keeps `public` for that
/// cascade's unqualified `DELETE FROM edges`).
#[sqlx::test(migrations = "../../migrations")]
async fn the_retention_job_prunes_only_expired_telemetry_through_the_definer(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "t62-prune").await;
    let expired = seed_event(&pool, "tool.invoked", 200).await;
    let fresh = seed_event(&pool, "tool.invoked", 1).await;
    let near_miss = seed_event(&pool, "Tool.Invoked", 200).await;
    let provenance = seed_event(&pool, "claim.created", 200).await;
    let assessed = seed_event(&pool, "claim.assessed", 200).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'event', $2, 'agent', 'TEST_EDGE')",
    )
    .bind(expired)
    .bind(agent)
    .execute(&pool)
    .await
    .expect("an edge naming the expired telemetry event");

    let maint = role_pool(&pool, "epigraph_maintenance").await;
    let would = RecallEventRepository::count_prunable_events(&maint, 90)
        .await
        .expect("the dry-run count on a maintenance session");
    let deleted = RecallEventRepository::prune_telemetry_events(&maint, 90)
        .await
        .expect("the prune on a maintenance session");
    maint.close().await;

    assert_eq!((would, deleted), (1, 1), "(dry-run count, deleted)");
    assert!(
        !exists(&pool, expired).await,
        "the expired telemetry row is pruned"
    );
    for (id, why) in [
        (fresh, "a fresh telemetry row"),
        (near_miss, "a near-miss spelling of the telemetry type"),
        (provenance, "an expired provenance row"),
        (assessed, "an expired assessment record"),
    ] {
        assert!(exists(&pool, id).await, "{why} survives");
    }
    let edges: i64 = sqlx::query_scalar("SELECT count(*) FROM edges WHERE source_id = $1")
        .bind(expired)
        .fetch_one(&pool)
        .await
        .expect("edges");
    assert_eq!(
        edges, 0,
        "the cascade removed the edge naming the pruned row"
    );
}

/// The application role cannot run the prune, and the definer's shape.
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_maintenance_role_executes_the_prune_definer(pool: PgPool) {
    let expired = seed_event(&pool, "tool.invoked", 200).await;
    let app = role_pool(&pool, "epigraph_app").await;
    let r: Result<i64, _> = sqlx::query_scalar("SELECT public.epigraph_prune_telemetry_events(90)")
        .fetch_one(&app)
        .await;
    app.close().await;
    assert_eq!(sqlstate(r).as_deref(), Some("42501"), "the app role");
    assert!(exists(&pool, expired).await, "nothing was pruned");

    let (definer, owner, events_owner, app_exec, maint_exec, public_exec): (
        bool,
        String,
        String,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, \
                (SELECT pg_get_userbyid(c.relowner)::text FROM pg_class c \
                  WHERE c.oid = 'public.events'::regclass), \
                has_function_privilege('epigraph_app', p.oid, 'EXECUTE'), \
                has_function_privilege('epigraph_maintenance', p.oid, 'EXECUTE'), \
                EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl, \
                                                acldefault('f', p.proowner))) a \
                         WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') \
           FROM pg_proc p \
          WHERE p.oid = 'public.epigraph_prune_telemetry_events(integer)'::regprocedure",
    )
    .fetch_one(&pool)
    .await
    .expect("the definer exists");
    assert!(definer, "SECURITY DEFINER");
    assert_eq!(owner, events_owner, "owned by the owner of `events`");
    assert_ne!(owner, "epigraph_maintenance", "never the maintenance role");
    assert_eq!(
        (app_exec, maint_exec, public_exec),
        (false, true, false),
        "(app EXECUTE, maintenance EXECUTE, PUBLIC EXECUTE)"
    );
}

/// The database's prunable list is the Rust allowlist, so the binary's docs
/// and the definer cannot drift apart unnoticed.
#[sqlx::test(migrations = "../../migrations")]
async fn the_definers_type_list_is_prunable_event_types(pool: PgPool) {
    let mut db: Vec<String> =
        sqlx::query_scalar("SELECT unnest(public.epigraph_prunable_event_types())")
            .fetch_all(&pool)
            .await
            .expect("the list");
    db.sort();
    let mut rust: Vec<String> = PRUNABLE_EVENT_TYPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    rust.sort();
    assert_eq!(db, rust);
}

/// `docs/runbooks/250-undo.sql` restores the posture before 250 (the
/// maintenance role's UPDATE and DELETE on `events`, no prune definer, no
/// `claim.assessed` guard, no masses-write table, triggers or function), and
/// can be run twice.
#[sqlx::test(migrations = "../../migrations")]
async fn the_250_undo_restores_the_maintenance_grants(pool: PgPool) {
    let undo = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/runbooks/250-undo.sql"
    ))
    .expect("read the undo");
    for run in 0..2 {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("apply the undo (run {run}): {e}"));
    }
    let state: (bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT has_table_privilege('epigraph_maintenance', 'public.events', 'DELETE'), \
                has_table_privilege('epigraph_maintenance', 'public.events', 'UPDATE'), \
                to_regprocedure('public.epigraph_prune_telemetry_events(integer)') IS NULL, \
                to_regprocedure('public.epigraph_prunable_event_types()') IS NULL, \
                to_regprocedure('public.epigraph_events_assessment_guard()') IS NULL, \
                NOT EXISTS (SELECT 1 FROM pg_trigger \
                             WHERE tgrelid = 'public.events'::regclass \
                               AND tgname = 'events_assessment_guard')",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog");
    assert_eq!(
        state,
        (true, true, true, true, true, true),
        "(maintenance DELETE, maintenance UPDATE, prune definer gone, type list gone, \
         assessment guard function gone, its trigger gone)"
    );
    let stamp: (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT to_regprocedure('public.epigraph_mass_function_masses_written()') IS NULL, \
                to_regprocedure('public.epigraph_event_type_norm(text)') IS NULL, \
                NOT EXISTS (SELECT 1 FROM pg_trigger \
                             WHERE tgrelid = 'public.mass_functions'::regclass \
                               AND tgname LIKE 'mass_functions_masses_written_%'), \
                to_regclass('public.mass_function_masses_writes') IS NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog");
    assert_eq!(
        stamp,
        (true, true, true, true),
        "(stamp function gone, type normaliser gone, stamp triggers gone, table gone)"
    );
}
