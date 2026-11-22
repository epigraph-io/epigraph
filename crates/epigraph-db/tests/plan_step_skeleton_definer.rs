//! Migration 259's `epigraph_plan_step_skeleton` (backlog a1474e22): the
//! definer the outcome reports order a plan through.
//!
//! * [`the_skeleton_definer_is_owned_and_granted_as_registered`]: it is
//!   `SECURITY DEFINER`, owned by `epigraph_maintenance` (whose reads of the
//!   FORCEd `edges` and `claims` the definer bypass admits; under another
//!   owner it would read only the caller's rows and the fix would be void),
//!   not EXECUTE-able by PUBLIC, and EXECUTE-able by `epigraph_app`.
//! * [`the_skeleton_masks_every_claim_the_caller_did_not_name`]: a claim not in
//!   `visible` comes back as a token only, while its level, ordinal and chain
//!   position are there.
//! * [`the_259_undo_returns_the_catalog_below_259`]: the runbook drops exactly
//!   what 259 added, and a second run changes nothing.
//!
//! The end-to-end behaviour (a stranger's report is not shifted by a hidden
//! unindexed chain member, on the application role) is pinned in
//! `epigraph-mcp/tests/hierarchical_outcome_stamped_reads.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;

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

async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

const SIG: &str = "public.epigraph_plan_step_skeleton(uuid, uuid[])";

/// `(slot, token, claim_id, level, plan_index, successors)`.
type SkeletonRow = (
    i32,
    i32,
    Option<Uuid>,
    Option<String>,
    Option<i32>,
    Vec<i32>,
);

#[sqlx::test(migrations = "../../migrations")]
async fn the_skeleton_definer_is_owned_and_granted_as_registered(pool: PgPool) {
    let (secdef, owner): (bool, String) = sqlx::query_as(
        "SELECT p.prosecdef, p.proowner::regrole::text FROM pg_proc p WHERE p.oid = $1::regprocedure",
    )
    .bind(SIG)
    .fetch_one(&pool)
    .await
    .expect("the definer exists");
    assert!(
        secdef,
        "it must stay SECURITY DEFINER: it reads past row security"
    );
    assert_eq!(owner, "epigraph_maintenance", "owner");
    let public_exec: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_proc p, aclexplode(p.proacl) a \
          WHERE p.oid = $1::regprocedure AND a.grantee = 0 AND a.privilege_type = 'EXECUTE')",
    )
    .bind(SIG)
    .fetch_one(&pool)
    .await
    .expect("acl");
    assert!(!public_exec, "PUBLIC must not EXECUTE it");
    let app_exec: bool =
        sqlx::query_scalar("SELECT has_function_privilege('epigraph_app', $1, 'EXECUTE')")
            .bind(SIG)
            .fetch_one(&pool)
            .await
            .expect("app privilege");
    assert!(app_exec, "the request DSN's role must EXECUTE it");
}

async fn claim(pool: &PgPool, agent: Uuid, level: i32) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, &format!("skeleton probe {}", Uuid::new_v4()))
        .await;
    sqlx::query(
        "UPDATE claims SET properties = jsonb_build_object('level', $2::int) WHERE id = $1",
    )
    .bind(id)
    .bind(level)
    .execute(pool)
    .await
    .expect("level");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_skeleton_masks_every_claim_the_caller_did_not_name(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "skeleton-probe").await;
    let workflow = Uuid::new_v4();
    epigraph_db::WorkflowRepository::insert_root(
        &pool,
        workflow,
        "skeleton-probe",
        0,
        "A plan for the skeleton definer.",
        None,
        serde_json::json!({}),
        epigraph_core::TenancyDecl::inherited(),
    )
    .await
    .expect("insert workflow root");
    let a = claim(&pool, agent, 2).await;
    let b = claim(&pool, agent, 2).await;
    let x = claim(&pool, agent, 2).await;
    for (c, pi) in [(a, Some(0)), (b, Some(1)), (x, None)] {
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
             VALUES ($1, 'workflow', $2, 'claim', 'executes', \
                     CASE WHEN $3::int IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('plan_index', $3::int) END)",
        )
        .bind(workflow)
        .bind(c)
        .bind(pi)
        .execute(&pool)
        .await
        .expect("executes");
    }
    for (s, t) in [(a, x), (x, b)] {
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'claim', $2, 'claim', 'step_follows')",
        )
        .bind(s)
        .bind(t)
        .execute(&pool)
        .await
        .expect("step_follows");
    }

    let rows: Vec<SkeletonRow> = sqlx::query_as(
        "SELECT slot, token, claim_id, level, plan_index, successors \
             FROM public.epigraph_plan_step_skeleton($1, $2) ORDER BY slot",
    )
    .bind(workflow)
    .bind(vec![a, b])
    .fetch_all(&pool)
    .await
    .expect("skeleton");
    assert_eq!(
        rows,
        vec![
            (1, 1, Some(a), Some("2".into()), Some(0), vec![3]),
            (2, 2, Some(b), Some("2".into()), Some(1), vec![]),
            (3, 3, None, Some("2".into()), None, vec![2]),
        ],
        "the unnamed step is a token in its place in the chain, never its id"
    );
}

async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || CASE WHEN p.prokind IN ('f', 'p') THEN md5(pg_get_functiondef(p.oid)) \
                        ELSE md5(p.prosrc) END \
                || ' ' || p.proowner::regrole::text || ' ' || COALESCE(p.proacl::text, '-') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'pol ' || c.relname || '.' || pol.polname \
           FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'trg ' || c.relname || '.' || t.tgname \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

#[sqlx::test(migrations = false)]
async fn the_259_undo_returns_the_catalog_below_259(pool: PgPool) {
    migrate(&pool, &up_to(258)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(259)).await;
    let through = catalog(&pool).await;
    let added: Vec<&String> = through.difference(&before).collect();
    assert_eq!(
        added.len(),
        1,
        "CALIBRATION: 259 adds one function: {added:?}"
    );
    assert!(
        added[0].starts_with("fn epigraph_plan_step_skeleton("),
        "{added:?}"
    );
    assert!(before.is_subset(&through), "259 changes nothing else");

    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/259-undo.sql"),
    )
    .expect("259-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        assert_eq!(
            catalog(&pool).await,
            before,
            "after the {run} run the catalog is exactly the one below 259"
        );
    }
}
