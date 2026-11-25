//! Migration 311 (backlog 9a9d6850): the application role moves no factor
//! between frames itself. A promotion moves its hypothesis's factors through
//! `epigraph_promote_hypothesis_factors`, and that definer moves nothing else.
//!
//! Every call under test runs on a pool whose connections are
//! `SET SESSION AUTHORIZATION epigraph_app`, stamped as `ScopedPool::begin_as`
//! stamps a request; fixtures are seeded and read back on the superuser pool.
//!
//! * [`the_writer_of_a_promoted_hypothesis_moves_its_factors_and_nothing_else`]:
//!   the move takes exactly the `hypothesis_assessment` factors that name the
//!   claim to `research_validity`; a factor in that frame over other claims,
//!   and a factor over the claim in a third frame, stay.
//! * [`a_session_that_does_not_write_the_claim_is_refused`]: a reader of the
//!   claim's group and a stranger are refused BPF01 (42501), on a promoted, an
//!   unpromoted and an absent claim alike, and nothing moves.
//! * [`an_unpromoted_hypothesis_keeps_its_factors`]: its writer is refused
//!   BPF02 (55000); a NULL claim is 22004; a missing frame is BPF03.
//! * [`the_definer_is_a_pinned_maintenance_owned_app_executable_function`]
//!   pins the catalog.
//! * [`the_311_undo_returns_the_catalog_below_311`]: the runbook.
//!
//! # Verified to fail
//!
//! * Migration 311 removed (the tree before this change): every call is 42883
//!   (no such function), so each test above fails on its first call; the
//!   undo test's calibration fails (no difference across 311).
//! * The BPF01 writes check removed from the body: fails
//!   `a_session_that_does_not_write_the_claim_is_refused` (the stranger's call
//!   on the promoted claim moves its factor).
//! * The BPF02 status check removed: fails
//!   `an_unpromoted_hypothesis_keeps_its_factors` (the writer moves the
//!   unpromoted hypothesis's factor).
//! * `GRANT EXECUTE .. TO PUBLIC` added: fails the catalog test.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use sqlx::{Executor, PgPool};
use std::collections::BTreeSet;
use uuid::Uuid;

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// A pool of `epigraph_app` connections stamped for `agent` (group ids,
/// writable group ids and principal), as `factors_write_posture.rs` builds it.
async fn stamped_app_pool(pool: &PgPool, agent: Uuid) -> PgPool {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());
    let url = fixture::database_url_for(pool).await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |conn, _meta| {
            let (groups, writable) = (groups.clone(), writable.clone());
            Box::pin(async move {
                conn.execute("SET SESSION AUTHORIZATION epigraph_app")
                    .await?;
                sqlx::query(
                    "SELECT set_config('epigraph.group_ids', $1, false), \
                            set_config('epigraph.writable_group_ids', $2, false), \
                            set_config('epigraph.principal_id', $3, false)",
                )
                .bind(groups)
                .bind(writable)
                .bind(agent.to_string())
                .execute(&mut *conn)
                .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("stamped app pool")
}

async fn ensure_frame(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['true','false']::text[]) \
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {name} frame: {e}"))
}

async fn seed_factor(pool: &PgPool, frame: Uuid, a: Uuid, b: Uuid) -> Uuid {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    sqlx::query_scalar(
        "INSERT INTO factors (factor_type, variable_ids, potential, frame_id) \
         VALUES ('evidential_support', $1, '{\"strength\": 0.8}', $2) RETURNING id",
    )
    .bind(vec![lo, hi])
    .bind(frame)
    .fetch_one(pool)
    .await
    .expect("seed factor")
}

async fn frame_of(pool: &PgPool, factor: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT frame_id FROM factors WHERE id = $1")
        .bind(factor)
        .fetch_one(pool)
        .await
        .expect("read factor frame")
}

async fn set_status(pool: &PgPool, claim: Uuid, status: &str) {
    sqlx::query(
        "UPDATE claims SET properties = properties || jsonb_build_object('hypothesis_status', $2::text) \
          WHERE id = $1",
    )
    .bind(claim)
    .bind(status)
    .execute(pool)
    .await
    .expect("set hypothesis status");
}

/// `(sqlstate, message)` of a refused call; panics on success.
async fn refused(app: &PgPool, claim: Option<Uuid>, what: &str) -> (String, String) {
    match sqlx::query_scalar::<_, i64>("SELECT public.epigraph_promote_hypothesis_factors($1)")
        .bind(claim)
        .fetch_one(app)
        .await
    {
        Ok(n) => panic!("{what}: the definer moved {n} factor(s)"),
        Err(e) => {
            let d = e
                .as_database_error()
                .unwrap_or_else(|| panic!("{what}: not a database error: {e}"));
            (
                d.code().map(|c| c.to_string()).unwrap_or_default(),
                d.message().to_string(),
            )
        }
    }
}

async fn moved(app: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT public.epigraph_promote_hypothesis_factors($1)")
        .bind(claim)
        .fetch_one(app)
        .await
        .expect("the definer runs")
}

struct World {
    writer: Uuid,
    reader: Uuid,
    stranger: Uuid,
    hyp: Uuid,
    rv: Uuid,
    other_frame: Uuid,
    /// Promoted, in the writer's group.
    claim: Uuid,
    /// In the writer's group, status `active`.
    unpromoted: Uuid,
    /// `hypothesis_assessment`, over `claim` and a partner.
    f_claim: Uuid,
    /// `hypothesis_assessment`, over two other claims.
    f_bystander: Uuid,
    /// A third frame, over `claim`.
    f_elsewhere: Uuid,
    /// `hypothesis_assessment`, over `unpromoted`.
    f_unpromoted: Uuid,
}

async fn world(pool: &PgPool, label: &str) -> World {
    let hyp = ensure_frame(pool, "hypothesis_assessment").await;
    let rv = ensure_frame(pool, "research_validity").await;
    let other_frame = ensure_frame(pool, &format!("f311 other {}", Uuid::new_v4())).await;
    let (writer, group) = fixture::seed_agent_with_group(pool, &format!("{label}-writer")).await;
    let (reader, _) = fixture::seed_agent_with_group(pool, &format!("{label}-reader")).await;
    let (stranger, _) = fixture::seed_agent_with_group(pool, &format!("{label}-stranger")).await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(group)
    .bind(reader)
    .execute(pool)
    .await
    .expect("reader membership");
    let claim_in = |tag: &'static str| {
        let pool = pool.clone();
        async move {
            fixture::seed_group_claim(
                &pool,
                writer,
                group,
                &format!("f311 {tag} {}", Uuid::new_v4()),
            )
            .await
        }
    };
    let (claim, unpromoted, partner, p, q) = (
        claim_in("claim").await,
        claim_in("unpromoted").await,
        claim_in("partner").await,
        claim_in("p").await,
        claim_in("q").await,
    );
    set_status(pool, claim, "promoted").await;
    set_status(pool, unpromoted, "active").await;
    World {
        writer,
        reader,
        stranger,
        hyp,
        rv,
        other_frame,
        claim,
        unpromoted,
        f_claim: seed_factor(pool, hyp, claim, partner).await,
        f_bystander: seed_factor(pool, hyp, p, q).await,
        f_elsewhere: seed_factor(pool, other_frame, claim, partner).await,
        f_unpromoted: seed_factor(pool, hyp, unpromoted, partner).await,
    }
}

async fn assert_unmoved(pool: &PgPool, w: &World, what: &str) {
    assert_eq!(
        frame_of(pool, w.f_claim).await,
        Some(w.hyp),
        "{what}: f_claim"
    );
    assert_eq!(
        frame_of(pool, w.f_bystander).await,
        Some(w.hyp),
        "{what}: f_bystander"
    );
    assert_eq!(
        frame_of(pool, w.f_elsewhere).await,
        Some(w.other_frame),
        "{what}: f_elsewhere"
    );
    assert_eq!(
        frame_of(pool, w.f_unpromoted).await,
        Some(w.hyp),
        "{what}: f_unpromoted"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_writer_of_a_promoted_hypothesis_moves_its_factors_and_nothing_else(pool: PgPool) {
    let w = world(&pool, "f311-move").await;
    let app = stamped_app_pool(&pool, w.writer).await;
    assert_eq!(
        moved(&app, w.claim).await,
        1,
        "one factor names the claim in the frame"
    );
    assert_eq!(
        frame_of(&pool, w.f_claim).await,
        Some(w.rv),
        "f_claim moved"
    );
    assert_eq!(
        frame_of(&pool, w.f_bystander).await,
        Some(w.hyp),
        "bystander stays"
    );
    assert_eq!(
        frame_of(&pool, w.f_elsewhere).await,
        Some(w.other_frame),
        "a factor over the claim in another frame stays"
    );
    assert_eq!(
        frame_of(&pool, w.f_unpromoted).await,
        Some(w.hyp),
        "another hypothesis's factor stays"
    );
    assert_eq!(
        moved(&app, w.claim).await,
        0,
        "a second call finds nothing to move"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_session_that_does_not_write_the_claim_is_refused(pool: PgPool) {
    let w = world(&pool, "f311-refuse").await;
    for (who, agent) in [("reader", w.reader), ("stranger", w.stranger)] {
        let app = stamped_app_pool(&pool, agent).await;
        for (arm, claim) in [
            ("promoted", w.claim),
            ("unpromoted", w.unpromoted),
            ("absent", Uuid::new_v4()),
        ] {
            let (code, msg) = refused(&app, Some(claim), &format!("{who} on {arm}")).await;
            assert_eq!(code, "42501", "{who} on {arm}: {msg}");
            assert!(msg.starts_with("BPF01:"), "{who} on {arm}: {msg}");
        }
        assert_unmoved(&pool, &w, who).await;
    }
    // The unstamped application role (no writable group) is refused too.
    let bare = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let (code, msg) = refused(&bare, Some(w.claim), "unstamped app session").await;
    assert_eq!(code, "42501", "{msg}");
    assert_unmoved(&pool, &w, "unstamped").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unpromoted_hypothesis_keeps_its_factors(pool: PgPool) {
    let w = world(&pool, "f311-unpromoted").await;
    let app = stamped_app_pool(&pool, w.writer).await;
    let (code, msg) = refused(&app, Some(w.unpromoted), "writer on unpromoted").await;
    assert_eq!(code, "55000", "{msg}");
    assert!(msg.starts_with("BPF02:"), "{msg}");
    let (code, msg) = refused(&app, None, "NULL claim").await;
    assert_eq!(code, "22004", "{msg}");
    assert_unmoved(&pool, &w, "writer refused").await;

    // A missing frame: nothing to move to, so nothing moves.
    sqlx::query("UPDATE frames SET name = name || ' (renamed)' WHERE id = $1")
        .bind(w.rv)
        .execute(&pool)
        .await
        .expect("rename research_validity");
    let (code, msg) = refused(&app, Some(w.claim), "missing frame").await;
    assert_eq!(code, "P0002", "{msg}");
    assert!(msg.starts_with("BPF03:"), "{msg}");
    assert_unmoved(&pool, &w, "missing frame").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_definer_is_a_pinned_maintenance_owned_app_executable_function(pool: PgPool) {
    let (secdef, owner, config, public_exec, app_exec, maint_exec): (
        bool,
        String,
        Vec<String>,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT p.prosecdef, p.proowner::regrole::text, COALESCE(p.proconfig, '{}'), \
                EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a \
                         WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'), \
                has_function_privilege('epigraph_app', p.oid, 'EXECUTE'), \
                has_function_privilege('epigraph_maintenance', p.oid, 'EXECUTE') \
           FROM pg_proc p \
          WHERE p.oid = 'public.epigraph_promote_hypothesis_factors(uuid)'::regprocedure",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog");
    assert!(secdef, "SECURITY DEFINER");
    assert_eq!(owner, "epigraph_maintenance");
    assert_eq!(config, vec!["search_path=pg_catalog, pg_temp".to_string()]);
    assert!(!public_exec, "no PUBLIC EXECUTE");
    assert!(app_exec, "the request DSN calls it");
    assert!(maint_exec);
}

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

/// Every `public` function (definition, owner and ACL) and the table and
/// column ACLs of `factors` and `bp_messages`, ACLs as sets of entries (a
/// NULL ACL read as its default, an empty column ACL as none).
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || CASE WHEN p.prokind IN ('f', 'p') THEN md5(pg_get_functiondef(p.oid)) \
                        ELSE md5(p.prosrc) END \
                || ' ' || p.proowner::regrole::text || ' ' \
                || COALESCE((SELECT string_agg(x::text, ',' ORDER BY x::text) \
                               FROM unnest(COALESCE(p.proacl, acldefault('f', p.proowner))) x), \
                            '-') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'acl ' || c.relname || ' ' \
                || COALESCE((SELECT string_agg(x::text, ',' ORDER BY x::text) \
                               FROM unnest(COALESCE(c.relacl, acldefault('r', c.relowner))) x), \
                            '-') \
           FROM pg_class c \
          WHERE c.oid IN ('public.factors'::regclass, 'public.bp_messages'::regclass) \
         UNION ALL \
         SELECT 'colacl ' || a.attrelid::regclass::text || '.' || a.attname || ' ' \
                || (SELECT string_agg(x::text, ',' ORDER BY x::text) FROM unnest(a.attacl) x) \
           FROM pg_attribute a \
          WHERE a.attrelid IN ('public.factors'::regclass, 'public.bp_messages'::regclass) \
            AND a.attnum > 0 AND NOT a.attisdropped AND cardinality(a.attacl) > 0",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

/// The undo returns the catalog to what it was below 311, and is idempotent.
/// Mutation: the undo's `bp_messages` re-grant dropped, or its column
/// re-grant -> the ACL entries differ from the ones below 311.
#[sqlx::test(migrations = false)]
async fn the_311_undo_returns_the_catalog_below_311(pool: PgPool) {
    migrate(&pool, &up_to(310)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(311)).await;
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    let removed: BTreeSet<&String> = before.difference(&through).collect();
    assert_eq!(
        added.len(),
        2,
        "CALIBRATION: 311 adds the definer and narrows the bp_messages ACL: {added:?}"
    );
    assert_eq!(
        removed.len(),
        2,
        "CALIBRATION: 311 narrows the bp_messages ACL and drops the frame_id column grant: \
         {removed:?}"
    );
    assert!(
        removed
            .iter()
            .any(|e| e.starts_with("colacl factors.frame_id epigraph_app=w/")),
        "CALIBRATION: 311 revokes epigraph_app UPDATE on frame_id: {removed:?}"
    );

    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/311-undo.sql"),
    )
    .expect("read the 311 undo runbook");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 311"
        );
    }
}
