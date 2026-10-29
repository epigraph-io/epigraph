//! Migration 183 (ruling R-74, backlog c0ab097a (2)): a `workflows` row
//! carries the tenancy of its plan.
//!
//! * The backfill takes each existing row's tenancy from its plan: a row whose
//!   thesis/phase/step `executes` targets include a group-private claim is the
//!   group's (the group owning most of them), level-3 operation atoms do not
//!   count, and every other row is public with a real, non-world owner.
//! * The columns have 062's tier-A shape, the row security is ENABLEd and
//!   FORCEd, and a write must declare its tenancy.
//! * As the application role under real stamps: a group row is read only by a
//!   reader of the group (an unstamped session reads public rows only), only a
//!   writer of the owner group inserts a row, a reader may update a row's
//!   mutable columns but nobody but a maintenance session changes its
//!   tenancy, and no application session deletes one.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode, WorkflowRepository};
use sqlx::PgPool;
use uuid::Uuid;

const SEED: Uuid = Uuid::from_u128(0xdead);
const WORLD: Uuid = Uuid::nil();

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

fn up_to(max: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= max)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

/// Run `migrator` on one connection and reset it: 001's pg_dump header leaves
/// session-level SETs behind.
async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

/// A claim at `level` with the given tenancy (harness superuser).
async fn claim(pool: &PgPool, agent: Uuid, level: i32, visibility: &str, owner: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, properties) \
         VALUES ($1, $2, $3, 0.8, $4, true, $5, $6, jsonb_build_object('level', $7::int))",
    )
    .bind(id)
    .bind(format!("workflow tenancy fixture {id}"))
    .bind(id.as_bytes().repeat(2))
    .bind(agent)
    .bind(visibility)
    .bind(owner)
    .bind(level)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// A `workflows` row as a pre-183 schema holds it (no tenancy columns).
async fn legacy_workflow(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO workflows (id, canonical_name, goal) VALUES ($1, $2, 'a goal')")
        .bind(id)
        .bind(name)
        .execute(pool)
        .await
        .expect("legacy workflow row");
    id
}

async fn executes(pool: &PgPool, workflow: Uuid, claim: Uuid) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'workflow', $2, 'claim', 'executes')",
    )
    .bind(workflow)
    .bind(claim)
    .execute(pool)
    .await
    .expect("executes edge");
}

async fn tenancy(pool: &PgPool, workflow: Uuid) -> (String, Uuid) {
    sqlx::query_as("SELECT visibility::text, owner_group_id FROM workflows WHERE id = $1")
        .bind(workflow)
        .fetch_one(pool)
        .await
        .expect("row tenancy")
}

/// The backfill, on rows written before 183, decides each row from its plan.
#[sqlx::test(migrations = false)]
async fn migration_183_takes_each_rows_tenancy_from_its_plan(pool: PgPool) {
    migrate(&pool, &up_to(182)).await;
    let (a, g) = fixture::seed_agent_with_group(&pool, "wf-tenancy-a").await;
    let (b, h) = fixture::seed_agent_with_group(&pool, "wf-tenancy-b").await;

    // Public steps owned by G: public, owned by G.
    let public = legacy_workflow(&pool, "wf-public").await;
    for _ in 0..2 {
        executes(&pool, public, claim(&pool, a, 2, "public", g).await).await;
    }
    // A public thesis and a public step shared with another generation, plus
    // a step of its own private to G: the plan is G's.
    let private = legacy_workflow(&pool, "wf-private").await;
    executes(&pool, private, claim(&pool, a, 0, "public", g).await).await;
    executes(&pool, private, claim(&pool, a, 2, "public", g).await).await;
    executes(&pool, private, claim(&pool, a, 2, "group", g).await).await;
    // Steps in two groups: the group owning most of them.
    let split = legacy_workflow(&pool, "wf-split").await;
    executes(&pool, split, claim(&pool, b, 2, "group", h).await).await;
    executes(&pool, split, claim(&pool, b, 1, "group", h).await).await;
    executes(&pool, split, claim(&pool, a, 2, "group", g).await).await;
    // A public plan that executes an operation atom private to H: atoms are
    // shared across documents and do not make the plan H's.
    let atom = legacy_workflow(&pool, "wf-private-atom").await;
    executes(&pool, atom, claim(&pool, a, 2, "public", g).await).await;
    executes(&pool, atom, claim(&pool, b, 3, "group", h).await).await;
    // No plan at all, and a plan whose only target is world-owned: public,
    // owned by the seed group (never world).
    let stepless = legacy_workflow(&pool, "wf-stepless").await;
    let world_only = legacy_workflow(&pool, "wf-world-only").await;
    executes(&pool, world_only, claim(&pool, a, 2, "public", WORLD).await).await;

    migrate(&pool, &MIGRATOR).await;

    assert_eq!(tenancy(&pool, public).await, ("public".into(), g));
    assert_eq!(tenancy(&pool, private).await, ("group".into(), g));
    assert_eq!(tenancy(&pool, split).await, ("group".into(), h));
    assert_eq!(tenancy(&pool, atom).await, ("public".into(), g));
    assert_eq!(tenancy(&pool, stepless).await, ("public".into(), SEED));
    assert_eq!(tenancy(&pool, world_only).await, ("public".into(), SEED));
    let unset: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workflows WHERE owner_group_id = $1 OR visibility IS NULL",
    )
    .bind(WORLD)
    .fetch_one(&pool)
    .await
    .expect("world-owned rows");
    assert_eq!(unset, 0, "no row is world-owned or undecided");
}

/// The columns have 062's tier-A shape (NOT NULL, no default, the three
/// validated constraints), row security is ENABLEd and FORCEd, and the
/// declare-or-refuse trigger is armed.
#[sqlx::test(migrations = "../../migrations")]
async fn workflow_rows_carry_the_tier_a_shape(pool: PgPool) {
    let cols: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT column_name::text, data_type::text, is_nullable::text, column_default::text \
           FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'workflows' \
            AND column_name IN ('owner_group_id', 'visibility') ORDER BY column_name",
    )
    .fetch_all(&pool)
    .await
    .expect("columns");
    assert_eq!(
        cols,
        vec![
            ("owner_group_id".into(), "uuid".into(), "NO".into(), None),
            (
                "visibility".into(),
                "character varying".into(),
                "NO".into(),
                None
            ),
        ]
    );
    for suffix in [
        "_visibility_check",
        "_owner_group_fkey",
        "_group_needs_real_group",
    ] {
        let validated: Option<bool> = sqlx::query_scalar(
            "SELECT convalidated FROM pg_constraint \
              WHERE conrelid = 'public.workflows'::regclass AND conname = $1",
        )
        .bind(format!("workflows{suffix}"))
        .fetch_optional(&pool)
        .await
        .expect("constraint");
        assert_eq!(validated, Some(true), "workflows{suffix}");
    }
    let (rls, force): (bool, bool) = sqlx::query_as(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
          WHERE oid = 'public.workflows'::regclass",
    )
    .fetch_one(&pool)
    .await
    .expect("pg_class");
    assert!(rls && force, "row security ENABLEd and FORCEd");
    let armed: Vec<String> = sqlx::query_scalar(
        "SELECT tgname::text FROM pg_trigger \
          WHERE tgrelid = 'public.workflows'::regclass AND NOT tgisinternal \
            AND tgenabled = 'O' AND tgname IN ('workflows_require_tenancy', \
                'workflows_owner_immutable', 'workflows_visibility_immutable') \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("triggers");
    assert_eq!(
        armed,
        [
            "workflows_owner_immutable",
            "workflows_require_tenancy",
            "workflows_visibility_immutable"
        ]
    );
}

/// The application-role world: a member `m` of `g` (its personal group, which
/// it writes), a stranger `s`, a public row and a row declared into `g`.
struct AppWorld {
    scoped: ScopedPool,
    plain: PgPool,
    m: Viewer,
    s: Viewer,
    g: Uuid,
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

async fn app_world(pool: &PgPool) -> AppWorld {
    let (m, g) = fixture::seed_agent_with_group(pool, "wf-app-member").await;
    let (s, _) = fixture::seed_agent_with_group(pool, "wf-app-stranger").await;
    let public = declared_row(pool, "wf-app-public", "public", g).await;
    let private = declared_row(pool, "wf-app-private", "group", g).await;
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    AppWorld {
        scoped,
        plain: fixture::downgraded_pool(pool, "epigraph_app").await,
        m: Viewer::resolve(pool, m).await.expect("member viewer"),
        s: Viewer::resolve(pool, s).await.expect("stranger viewer"),
        g,
        public,
        private,
    }
}

/// `(row visible by the policy alone, viewer_reads_row, row_as_viewer)` for
/// `viewer` on `id`, on one stamped read.
async fn reads(w: &AppWorld, viewer: &Viewer, id: Uuid) -> (bool, bool, bool) {
    let mut read = w.scoped.read_as(viewer).await.expect("stamped read");
    let policy: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM workflows WHERE id = $1)")
        .bind(id)
        .fetch_one(&mut *read)
        .await
        .expect("policy read");
    let predicate = WorkflowRepository::viewer_reads_row(&mut read, viewer, id)
        .await
        .expect("viewer_reads_row");
    let row = WorkflowRepository::row_as_viewer(&mut read, viewer, id)
        .await
        .expect("row_as_viewer")
        .is_some();
    read.commit().await.expect("close read");
    (policy, predicate, row)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_group_row_is_read_only_by_a_reader_of_its_group(pool: PgPool) {
    let w = app_world(&pool).await;
    assert_eq!(reads(&w, &w.m, w.private).await, (true, true, true));
    assert_eq!(reads(&w, &w.s, w.private).await, (false, false, false));
    assert_eq!(reads(&w, &w.s, w.public).await, (true, true, true));
    let unstamped: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM workflows WHERE id = ANY($1)")
        .bind(vec![w.public, w.private])
        .fetch_all(&w.plain)
        .await
        .expect("unstamped read");
    assert_eq!(
        unstamped,
        vec![w.public],
        "an unstamped application session reads public rows only"
    );
}

/// `Err(SQLSTATE)` or `Ok(rows affected)` of `sql` (binding `id`, then `g`)
/// on a transaction stamped from `viewer`, rolled back.
async fn write(w: &AppWorld, viewer: &Viewer, sql: &str, id: Uuid) -> Result<u64, String> {
    let mut tx = w.scoped.begin_as(viewer).await.expect("stamped tx");
    let r = sqlx::query(sql)
        .bind(id)
        .bind(w.g)
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
async fn only_a_writer_inserts_and_nobody_retenants_a_row(pool: PgPool) {
    let w = app_world(&pool).await;
    let insert = "INSERT INTO workflows (id, canonical_name, goal, visibility, owner_group_id) \
                  VALUES ($1, 'wf-app-new-' || $1::text, 'a goal', 'group', $2)";
    assert_eq!(write(&w, &w.m, insert, Uuid::new_v4()).await, Ok(1));
    assert_eq!(
        write(&w, &w.s, insert, Uuid::new_v4()).await,
        Err("42501".into()),
        "a stranger cannot write a row into a group it does not write"
    );
    assert_eq!(
        write(
            &w,
            &w.m,
            "INSERT INTO workflows (id, canonical_name, goal) \
             VALUES ($1, 'wf-app-undeclared-' || $1::text, 'a goal') \
             ON CONFLICT DO NOTHING RETURNING $2::uuid",
            Uuid::new_v4(),
        )
        .await,
        Err("23502".into()),
        "an undeclared row is refused, never defaulted"
    );

    let counters = "UPDATE workflows SET metadata = jsonb_build_object('use_count', 1) \
                    WHERE id = $1 AND $2::uuid IS NOT NULL";
    assert_eq!(write(&w, &w.m, counters, w.private).await, Ok(1));
    assert_eq!(
        write(&w, &w.s, counters, w.private).await,
        Ok(0),
        "a stranger's UPDATE does not reach the group row"
    );
    assert_eq!(
        write(&w, &w.s, counters, w.public).await,
        Ok(1),
        "a reader of a public row moves its counters, as before"
    );
    assert_eq!(
        write(
            &w,
            &w.m,
            "UPDATE workflows SET visibility = 'public' WHERE id = $1 AND $2::uuid IS NOT NULL",
            w.private
        )
        .await,
        Err("42501".into()),
        "a member cannot publish its group's row"
    );
    // Re-owning a public row into another agent's group (which the member
    // neither reads nor writes).
    let (_, other) = fixture::seed_agent_with_group(&pool, "wf-app-other").await;
    let mut tx = w.scoped.begin_as(&w.m).await.expect("stamped tx");
    let reown = sqlx::query("UPDATE workflows SET owner_group_id = $2 WHERE id = $1")
        .bind(w.public)
        .bind(other)
        .execute(&mut *tx)
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| {
            e.as_database_error()
                .and_then(|d| d.code().map(|c| c.to_string()))
                .unwrap_or_default()
        });
    drop(tx);
    assert_eq!(reown, Err("42501".into()), "a reader cannot re-own a row");
    assert_eq!(
        write(
            &w,
            &w.m,
            "DELETE FROM workflows WHERE id = $1 AND $2::uuid IS NOT NULL",
            w.private
        )
        .await,
        Ok(0),
        "no application session deletes a workflow row"
    );
    assert_eq!(
        tenancy(&pool, w.private).await,
        ("group".into(), w.g),
        "nothing above changed the row's tenancy"
    );
}

/// `(visibility, owner group)` of each row, as the backfill decides it, for
/// the shapes the first backfill test does not reach:
///
/// * a group step whose `executes` edge is RETRACTED still makes the plan the
///   group's (a plan that was ever declared private stays private);
/// * two groups owning one group target each: the lowest group id;
/// * a level stored as text the readers accept (`"+02"`, `" 2"`) counts as a
///   step;
/// * a public plan is owned by the group owning its EARLIEST public target,
///   by edge creation time (inserted here in the other order, with the later
///   edge holding the lower id).
#[sqlx::test(migrations = false)]
async fn migration_183_backfill_counts_retracted_edges_and_breaks_ties_by_rule(pool: PgPool) {
    migrate(&pool, &up_to(182)).await;
    let (a, g) = fixture::seed_agent_with_group(&pool, "wf-rule-a").await;
    let (b, h) = fixture::seed_agent_with_group(&pool, "wf-rule-b").await;

    let retracted = legacy_workflow(&pool, "wf-retracted").await;
    executes(&pool, retracted, claim(&pool, a, 2, "public", g).await).await;
    let private_step = claim(&pool, a, 2, "group", g).await;
    executes(&pool, retracted, private_step).await;
    let n = sqlx::query(
        "UPDATE edges SET valid_to = now() \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'executes'",
    )
    .bind(retracted)
    .bind(private_step)
    .execute(&pool)
    .await
    .expect("retract the private step's edge")
    .rows_affected();
    assert_eq!(n, 1, "fixture: the private step's edge is retracted");

    let tie = legacy_workflow(&pool, "wf-tie").await;
    executes(&pool, tie, claim(&pool, a, 2, "group", g).await).await;
    executes(&pool, tie, claim(&pool, b, 2, "group", h).await).await;

    let mut text_levels = Vec::new();
    for (i, level) in ["\"+02\"", "\" 2\""].into_iter().enumerate() {
        let wf = legacy_workflow(&pool, &format!("wf-text-level-{i}")).await;
        executes(&pool, wf, claim(&pool, a, 2, "public", g).await).await;
        executes(
            &pool,
            wf,
            claim_with_level(&pool, a, level, "group", g).await,
        )
        .await;
        text_levels.push(wf);
    }

    let earliest = legacy_workflow(&pool, "wf-earliest").await;
    let later = claim(&pool, a, 2, "public", g).await;
    let older = claim(&pool, b, 2, "public", h).await;
    executes_with(&pool, Uuid::from_u128(1), earliest, later, 0).await;
    executes_with(&pool, Uuid::from_u128(2), earliest, older, 600).await;

    migrate(&pool, &MIGRATOR).await;

    // One comparison, so a run that breaks several rules shows each of them.
    let group = |g: Uuid| ("group".to_string(), g);
    assert_eq!(
        (
            tenancy(&pool, retracted).await,
            tenancy(&pool, tie).await,
            tenancy(&pool, text_levels[0]).await,
            tenancy(&pool, text_levels[1]).await,
            tenancy(&pool, earliest).await,
        ),
        (
            group(g),
            group(g.min(h)),
            group(g),
            group(g),
            ("public".to_string(), h),
        ),
        "(retracted private step -> group; tie -> lowest group id; level \"+02\" and \" 2\" \
         count as steps; public plan -> its earliest target's group)"
    );
}

/// A claim whose `properties.level` is the JSON value `level_json`.
async fn claim_with_level(
    pool: &PgPool,
    agent: Uuid,
    level_json: &str,
    visibility: &str,
    owner: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, properties) \
         VALUES ($1, $2, $3, 0.8, $4, true, $5, $6, jsonb_build_object('level', $7::jsonb))",
    )
    .bind(id)
    .bind(format!("workflow tenancy fixture {id}"))
    .bind(id.as_bytes().repeat(2))
    .bind(agent)
    .bind(visibility)
    .bind(owner)
    .bind(level_json)
    .execute(pool)
    .await
    .expect("seed claim with a text level");
    id
}

/// An `executes` edge with id `id`, created `age_secs` seconds ago.
async fn executes_with(pool: &PgPool, id: Uuid, workflow: Uuid, claim: Uuid, age_secs: i64) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            created_at) \
         VALUES ($1, $2, 'workflow', $3, 'claim', 'executes', \
                 now() - make_interval(secs => $4::float8))",
    )
    .bind(id)
    .bind(workflow)
    .bind(claim)
    .bind(age_secs as f64)
    .execute(pool)
    .await
    .expect("executes edge with id and age");
}

/// 183's backfill reads `claims` and `edges` under FORCEd row security, so it
/// is correct only on a session that reads every row. Run by a table owner
/// that is neither a superuser, nor BYPASSRLS, nor a maintenance session, the
/// migration refuses before the backfill instead of making a private plan
/// public; the same owner run as a maintenance session migrates and backfills
/// the plan as its group's.
#[sqlx::test(migrations = false)]
async fn migration_183_refuses_a_session_that_cannot_read_every_row(pool: PgPool) {
    use sqlx::{Connection, Executor};
    migrate(&pool, &up_to(182)).await;
    let (a, g) = fixture::seed_agent_with_group(&pool, "wf-guard").await;
    let private = legacy_workflow(&pool, "wf-guard-private").await;
    executes(&pool, private, claim(&pool, a, 2, "group", g).await).await;

    for stmt in [
        "CREATE ROLE wf183_owner NOLOGIN NOSUPERUSER NOBYPASSRLS",
        "ALTER TABLE public.workflows OWNER TO wf183_owner",
        "GRANT USAGE, CREATE ON SCHEMA public TO wf183_owner",
        "GRANT SELECT ON public.claims, public.edges TO wf183_owner",
        "GRANT SELECT, REFERENCES ON public.groups TO wf183_owner",
        "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO wf183_owner",
    ] {
        sqlx::query(stmt)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("{stmt}: {e}"));
    }
    const M183: &str = include_str!("../../../migrations/183_workflows_tenancy.sql");

    let mut conn = pool.acquire().await.expect("acquire");
    let refused = {
        let mut tx = conn.begin().await.expect("begin");
        tx.execute("SET SESSION AUTHORIZATION wf183_owner")
            .await
            .expect("become the owner");
        let r = sqlx::raw_sql(M183).execute(&mut *tx).await.map(|_| ());
        let tenancy: Option<(String, Uuid)> = if r.is_ok() {
            sqlx::query_as("SELECT visibility::text, owner_group_id FROM workflows WHERE id = $1")
                .bind(private)
                .fetch_optional(&mut *tx)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        drop(tx);
        r.map(|()| tenancy)
    };
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    match refused {
        Err(e) => assert!(
            e.to_string().contains("183: run as the maintenance role"),
            "refused for the guard's reason: {e}"
        ),
        Ok(t) => panic!(
            "183 ran on a session that cannot read every row; the private plan's row became \
             {t:?}"
        ),
    }

    sqlx::query("GRANT epigraph_maintenance TO wf183_owner")
        .execute(&pool)
        .await
        .expect("make the owner a maintenance session");
    let mut tx = conn.begin().await.expect("begin");
    tx.execute("SET SESSION AUTHORIZATION wf183_owner")
        .await
        .expect("become the owner");
    sqlx::raw_sql(M183)
        .execute(&mut *tx)
        .await
        .expect("a maintenance session migrates");
    tx.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    let t: (String, Uuid) =
        sqlx::query_as("SELECT visibility::text, owner_group_id FROM workflows WHERE id = $1")
            .bind(private)
            .fetch_one(&mut *tx)
            .await
            .expect("row tenancy");
    assert_eq!(
        t,
        ("group".into(), g),
        "the maintenance run backfills the plan"
    );
    drop(tx);
}

/// The tenancy guard's positive control: a maintenance session re-tenants a
/// row (publishes a group row, and re-owns it), which no application session
/// can do (`only_a_writer_inserts_and_nobody_retenants_a_row`).
#[sqlx::test(migrations = "../../migrations")]
async fn a_maintenance_session_re_tenants_a_row(pool: PgPool) {
    let w = app_world(&pool).await;
    let (_, other) = fixture::seed_agent_with_group(&pool, "wf-app-retenant").await;
    let private = w.private;
    let r: Result<u64, String> =
        fixture::as_role(&pool, "epigraph_maintenance", move |mut conn| async move {
            let r = sqlx::query(
                "UPDATE workflows SET visibility = 'public', owner_group_id = $2 WHERE id = $1",
            )
            .bind(private)
            .bind(other)
            .execute(&mut *conn)
            .await
            .map(|r| r.rows_affected())
            .map_err(|e| e.to_string());
            (conn, r)
        })
        .await;
    assert_eq!(r, Ok(1), "a maintenance session re-tenants the row");
    assert_eq!(tenancy(&pool, private).await, ("public".into(), other));
}
