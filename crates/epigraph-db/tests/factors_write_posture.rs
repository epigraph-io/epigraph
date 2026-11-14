//! Migration 217 (backlog a2c5f714): belief-propagation factors are written
//! by the database's own triggers, never by an application statement.
//!
//! Every write under test runs on a pool whose connections are
//! `SET SESSION AUTHORIZATION epigraph_app` (non-bypassing), stamped as a
//! writer the way `ScopedPool::begin_as` stamps a request; fixtures are seeded
//! and read back on the superuser pool.
//!
//! * [`an_app_session_cannot_forge_rewrite_or_drop_a_factor`] pins the attack
//!   the item names. A stamped session that owns nothing in the graph cannot
//!   INSERT a factor over another writer's edge, cannot rewrite an existing
//!   factor's pair or potential, and cannot DELETE or TRUNCATE one; the
//!   catalog leaves the application role UPDATE on `frame_id` alone.
//! * [`the_legitimate_writers_still_work_on_the_app_role`]. The writer's own
//!   edge INSERT still mints 038's factor (the matcher-score override
//!   included, a superseded endpoint still skipped), the promote route's
//!   `frame_id` move still runs, and retiring a claim still clears its
//!   factors.
//! * [`no_session_can_attach_the_factor_definers_to_its_own_table`] and
//!   [`the_factor_definers_refuse_any_table_but_their_own`]. The two definers
//!   cannot be borrowed. An application session cannot attach either to a
//!   temporary table (no EXECUTE), and a session that can (a superuser here)
//!   is refused by the body's `TG_RELID` guard.
//! * [`the_factor_triggers_are_maintenance_owned_pinned_definers`] pins the
//!   catalog.
//!
//! # Verified to fail
//!
//! * Migration 217 removed (the tree before this change): fails the four
//!   attack and catalog tests (the forged INSERT, the potential rewrite and
//!   the DELETE succeed; CREATE TRIGGER succeeds on the temporary table and
//!   the superuser's fake row mints a factor; the functions are invokers).
//!   `the_legitimate_writers_still_work_on_the_app_role` passes there: it is
//!   the preservation half, and fails under the next mutation.
//! * 217's mint left SECURITY INVOKER (grants still revoked): fails
//!   `the_legitimate_writers_still_work_on_the_app_role` (the writer's own
//!   edge INSERT is refused 42501) and the catalog test.
//! * 217 with `GRANT EXECUTE .. TO PUBLIC` re-issued on the mint: fails
//!   `no_session_can_attach_the_factor_definers_to_its_own_table` and the
//!   catalog test.
//! * 217's `TG_RELID` guard removed from the mint: fails
//!   `the_factor_definers_refuse_any_table_but_their_own` (the temporary
//!   table's row mints a factor as the maintenance role).
//! * 217 keeping table-level UPDATE: fails
//!   `an_app_session_cannot_forge_rewrite_or_drop_a_factor` (the rewrite and
//!   the column set).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use sqlx::{Executor, PgPool};
use uuid::Uuid;

const PERMISSION_DENIED: &str = "42501";

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// A pool of `epigraph_app` connections stamped for `agent` (group ids,
/// writable group ids and principal, as `ScopedPool::begin_as` stamps them).
/// The viewer is resolved on the superuser pool first: resolved on a
/// downgraded session it would read no memberships.
async fn stamped_app_pool(pool: &PgPool, agent: Uuid) -> PgPool {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());
    assert!(!writable.is_empty(), "a writer with no writable group");
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

fn code(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|d| d.code().map(|c| c.to_string()))
}

fn assert_denied<T: std::fmt::Debug>(r: Result<T, sqlx::Error>, what: &str) {
    match r {
        Ok(v) => panic!("{what}: the application role was allowed (got {v:?})"),
        Err(e) => assert_eq!(
            code(&e).as_deref(),
            Some(PERMISSION_DENIED),
            "{what}: want 42501, got {e}"
        ),
    }
}

/// `(factor_type, variable_ids, potential, properties)` of a factor.
type FactorShape = (String, Vec<Uuid>, serde_json::Value, serde_json::Value);

async fn factor_by_edge(pool: &PgPool, edge: Uuid) -> Option<(Uuid, FactorShape)> {
    sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            Vec<Uuid>,
            serde_json::Value,
            serde_json::Value,
        ),
    >(
        "SELECT id, factor_type::text, variable_ids, potential, properties FROM factors \
          WHERE properties->>'source_edge_id' = $1::text",
    )
    .bind(edge)
    .fetch_optional(pool)
    .await
    .expect("read factor")
    .map(|(id, t, v, p, props)| (id, (t, v, p, props)))
}

async fn factor_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM factors")
        .fetch_one(pool)
        .await
        .expect("count factors")
}

/// An application session cannot write `factors` itself: not a forged factor
/// over another writer's edge, not a rewrite, not a removal.
#[sqlx::test(migrations = "../../migrations")]
async fn an_app_session_cannot_forge_rewrite_or_drop_a_factor(pool: PgPool) {
    use epigraph_db::FactorRepository;
    let (victim, _) = fixture::seed_agent_with_group(&pool, "f217-victim").await;
    let (attacker, _) = fixture::seed_agent_with_group(&pool, "f217-attacker").await;
    let a = fixture::seed_public_claim(&pool, victim, &format!("f217 a {}", Uuid::new_v4())).await;
    let b = fixture::seed_public_claim(&pool, victim, &format!("f217 b {}", Uuid::new_v4())).await;
    let edge = fixture::seed_edge(&pool, a, b).await;
    let (factor, shape) = factor_by_edge(&pool, edge)
        .await
        .expect("CALIBRATION: the victim's edge minted its factor");
    let pair = shape.1.clone();
    let before = factor_count(&pool).await;

    let app = stamped_app_pool(&pool, attacker).await;
    let who: (String, bool) =
        sqlx::query_as("SELECT session_user::text, public.epigraph_lockdown_privileged()")
            .fetch_one(&app)
            .await
            .expect("whoami");
    assert_eq!(
        who,
        ("epigraph_app".to_string(), false),
        "CALIBRATION: a non-privileged application session"
    );

    // The forged factor: the victim's pair, as if minted from its edge, under
    // a factor type that slot does not hold yet, at full strength.
    assert_denied(
        sqlx::query(
            "INSERT INTO factors (factor_type, variable_ids, potential, description, properties) \
             VALUES ('evidential_support', $1, '{\"strength\": 1.0}', 'forged', \
                     jsonb_build_object('source_edge_id', $2::text))",
        )
        .bind(&pair)
        .bind(edge)
        .execute(&app)
        .await,
        "INSERT a factor over another writer's edge",
    );
    match FactorRepository::insert(
        &app,
        "mutual_exclusion",
        &pair,
        &serde_json::json!({}),
        Some("forged through the repository"),
        None,
    )
    .await
    {
        Ok(id) => panic!("FactorRepository::insert on the application role minted {id}"),
        Err(epigraph_db::DbError::QueryFailed { source }) => assert_eq!(
            code(&source).as_deref(),
            Some(PERMISSION_DENIED),
            "FactorRepository::insert: {source}"
        ),
        Err(other) => panic!("FactorRepository::insert: want 42501, got {other:?}"),
    }
    assert_denied(
        sqlx::query("UPDATE factors SET potential = '{\"strength\": 1.0}' WHERE id = $1")
            .bind(factor)
            .execute(&app)
            .await,
        "UPDATE an existing factor's potential",
    );
    assert_denied(
        sqlx::query("UPDATE factors SET variable_ids = $2 WHERE id = $1")
            .bind(factor)
            .bind(vec![a, Uuid::new_v4()])
            .execute(&app)
            .await,
        "UPDATE an existing factor's pair",
    );
    assert_denied(
        sqlx::query("DELETE FROM factors WHERE id = $1")
            .bind(factor)
            .execute(&app)
            .await,
        "DELETE a factor",
    );
    assert_denied(
        sqlx::query("TRUNCATE factors CASCADE").execute(&app).await,
        "TRUNCATE factors",
    );

    assert_eq!(factor_count(&pool).await, before, "no factor was written");
    assert_eq!(
        factor_by_edge(&pool, edge).await,
        Some((factor, shape)),
        "the victim's factor is exactly as minted"
    );

    // The catalog: no INSERT on any column, no DELETE or TRUNCATE, and UPDATE
    // on `frame_id` alone (the hypothesis promote route).
    let (insert, delete, truncate): (bool, bool, bool) = sqlx::query_as(
        "SELECT has_any_column_privilege('epigraph_app', 'public.factors', 'INSERT'), \
                has_table_privilege('epigraph_app', 'public.factors', 'DELETE'), \
                has_table_privilege('epigraph_app', 'public.factors', 'TRUNCATE')",
    )
    .fetch_one(&pool)
    .await
    .expect("table privileges");
    assert_eq!(
        (insert, delete, truncate),
        (false, false, false),
        "epigraph_app holds INSERT / DELETE / TRUNCATE on factors"
    );
    let updatable: Vec<String> = sqlx::query_scalar(
        "SELECT a.attname::text FROM pg_attribute a \
          WHERE a.attrelid = 'public.factors'::regclass AND a.attnum > 0 \
            AND NOT a.attisdropped \
            AND has_column_privilege('epigraph_app', a.attrelid, a.attnum, 'UPDATE') \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("column privileges");
    assert_eq!(updatable, vec!["frame_id".to_string()]);
}

/// The writers 217 keeps: the edge trigger on the session's own edge, the
/// promote route's frame move, and the retirement trigger.
#[sqlx::test(migrations = "../../migrations")]
async fn the_legitimate_writers_still_work_on_the_app_role(pool: PgPool) {
    let (writer, group) = fixture::seed_agent_with_group(&pool, "f217-writer").await;
    let claim = |tag: &'static str| {
        let pool = pool.clone();
        async move {
            fixture::seed_group_claim(
                &pool,
                writer,
                group,
                &format!("f217 {tag} {}", Uuid::new_v4()),
            )
            .await
        }
    };
    let (a, b, c, d, gone) = (
        claim("a").await,
        claim("b").await,
        claim("c").await,
        claim("d").await,
        claim("gone").await,
    );
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(gone)
        .execute(&pool)
        .await
        .expect("retire the superseded endpoint");
    let app = stamped_app_pool(&pool, writer).await;

    let insert_edge = |src: Uuid, tgt: Uuid, rel: &'static str, props: serde_json::Value| {
        let app = app.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO edges (source_id, source_type, target_id, target_type, \
                                    relationship, properties) \
                 VALUES ($1, 'claim', $2, 'claim', $3, $4) RETURNING id",
            )
            .bind(src)
            .bind(tgt)
            .bind(rel)
            .bind(props)
            .fetch_one(&app)
            .await
            .unwrap_or_else(|e| panic!("the writer inserts its own {rel} edge: {e}"))
        }
    };
    let lo_hi = |x: Uuid, y: Uuid| if x < y { vec![x, y] } else { vec![y, x] };

    // 038's directional mint, as the trigger always wrote it.
    let supports = insert_edge(a, b, "supports", serde_json::json!({})).await;
    let (_, got) = factor_by_edge(&pool, supports)
        .await
        .expect("the writer's own edge minted its factor on the application role");
    assert_eq!(
        got,
        (
            "directional_support".to_string(),
            lo_hi(a, b),
            serde_json::json!({
                "forward_strength": 0.7, "reverse_strength": 0.15,
                "source_var": a.to_string()
            }),
            serde_json::json!({
                "source_edge_id": supports, "relationship": "supports",
                "edge_source_id": a, "edge_target_id": b
            }),
        )
    );
    let description: String = sqlx::query_scalar(
        "SELECT description FROM factors WHERE properties->>'source_edge_id' = $1::text",
    )
    .bind(supports)
    .fetch_one(&pool)
    .await
    .expect("description");
    assert_eq!(
        description,
        format!("Auto-generated from supports edge {supports}")
    );

    // 038's matcher-score override, clamped.
    let matched = insert_edge(
        c,
        d,
        "CORROBORATES",
        serde_json::json!({"source": "cross_source_matcher", "score": 0.42}),
    )
    .await;
    let (_, got) = factor_by_edge(&pool, matched)
        .await
        .expect("the matcher edge minted its factor");
    assert_eq!(got.0, "evidential_support");
    assert_eq!(got.2, serde_json::json!({"strength": 0.42}));

    // 090's superseded-endpoint skip.
    let to_gone = insert_edge(a, gone, "supports", serde_json::json!({})).await;
    assert_eq!(
        factor_by_edge(&pool, to_gone).await,
        None,
        "an edge to a superseded claim mints no factor"
    );

    // The hypothesis promote route's move, as it is written there.
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['true', 'false']) RETURNING id",
    )
    .bind(format!("f217 frame {}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");
    let moved = sqlx::query(
        "UPDATE factors SET frame_id = $2 WHERE frame_id IS NOT DISTINCT FROM $1 \
           AND $3 = ANY(variable_ids)",
    )
    .bind(None::<Uuid>)
    .bind(frame)
    .bind(c)
    .execute(&app)
    .await
    .expect("the frame move runs on the application role")
    .rows_affected();
    assert_eq!(moved, 1, "the matcher factor moved frames");

    // The retirement trigger clears the retired claim's factors.
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(b)
        .execute(&app)
        .await
        .expect("the writer retires its own claim on the application role");
    assert_eq!(
        factor_by_edge(&pool, supports).await,
        None,
        "retiring an endpoint deleted its factor"
    );
    assert!(
        factor_by_edge(&pool, matched).await.is_some(),
        "an unrelated factor is kept"
    );
}

/// An application session can create a temporary table shaped like `edges`
/// (or `claims`), but cannot attach either factor definer to it.
#[sqlx::test(migrations = "../../migrations")]
async fn no_session_can_attach_the_factor_definers_to_its_own_table(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "f217-borrow").await;
    let app = stamped_app_pool(&pool, agent).await;
    let mut conn = app.acquire().await.expect("acquire");
    for (table, like, func) in [
        (
            "f217_fake_edges",
            "public.edges",
            "public.auto_create_factor_from_edge()",
        ),
        (
            "f217_fake_claims",
            "public.claims",
            "public.deactivate_superseded_factors()",
        ),
    ] {
        conn.execute(format!("CREATE TEMP TABLE {table} (LIKE {like})").as_str())
            .await
            .unwrap_or_else(|e| {
                panic!("CALIBRATION: the application session creates {table}: {e}")
            });
        let r = conn
            .execute(
                format!(
                    "CREATE TRIGGER f217_borrowed AFTER INSERT OR UPDATE ON {table} \
                     FOR EACH ROW EXECUTE FUNCTION {func}"
                )
                .as_str(),
            )
            .await;
        assert_denied(r, &format!("attach {func} to a temporary table"));
    }
}

/// A session that may attach them (a superuser) is refused by each body.
#[sqlx::test(migrations = "../../migrations")]
async fn the_factor_definers_refuse_any_table_but_their_own(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "f217-guard").await;
    let a = fixture::seed_public_claim(&pool, agent, &format!("f217 g a {}", Uuid::new_v4())).await;
    let b = fixture::seed_public_claim(&pool, agent, &format!("f217 g b {}", Uuid::new_v4())).await;
    let before = factor_count(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute(
        "CREATE TEMP TABLE f217_fake_edges AS SELECT * FROM public.edges WITH NO DATA; \
         CREATE TRIGGER f217_borrowed AFTER INSERT ON f217_fake_edges \
           FOR EACH ROW EXECUTE FUNCTION public.auto_create_factor_from_edge(); \
         CREATE TEMP TABLE f217_fake_claims AS SELECT * FROM public.claims WITH NO DATA; \
         CREATE TRIGGER f217_borrowed AFTER UPDATE ON f217_fake_claims \
           FOR EACH ROW EXECUTE FUNCTION public.deactivate_superseded_factors();",
    )
    .await
    .expect("the superuser attaches both definers to temporary tables");

    let err = sqlx::query(
        "INSERT INTO f217_fake_edges (id, source_id, source_type, target_id, target_type, \
                                      relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'supports')",
    )
    .bind(a)
    .bind(b)
    .execute(&mut *conn)
    .await
    .expect_err("the mint refuses a row from any table but public.edges");
    assert_eq!(code(&err).as_deref(), Some(PERMISSION_DENIED), "{err}");
    assert!(err.to_string().contains("FCT01"), "{err}");
    assert_eq!(factor_count(&pool).await, before, "nothing was minted");

    sqlx::query("INSERT INTO f217_fake_claims SELECT * FROM public.claims WHERE id = $1")
        .bind(a)
        .execute(&mut *conn)
        .await
        .expect("copy a claim row");
    let err = sqlx::query("UPDATE f217_fake_claims SET is_current = false WHERE id = $1")
        .bind(a)
        .execute(&mut *conn)
        .await
        .expect_err("the clear refuses a row from any table but public.claims");
    assert_eq!(code(&err).as_deref(), Some(PERMISSION_DENIED), "{err}");
    assert!(err.to_string().contains("FCT01"), "{err}");
}

/// Both trigger bodies are SECURITY DEFINER, owned by the maintenance role,
/// on 172's pinned path, and executable by neither PUBLIC nor the
/// application role.
#[sqlx::test(migrations = "../../migrations")]
async fn the_factor_triggers_are_maintenance_owned_pinned_definers(pool: PgPool) {
    for sig in [
        "public.auto_create_factor_from_edge()",
        "public.deactivate_superseded_factors()",
    ] {
        let (definer, owner, config, public_exec, app_exec): (bool, String, String, bool, bool) =
            sqlx::query_as(
                "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, \
                        coalesce(array_to_string(p.proconfig, ';'), ''), \
                        has_function_privilege('public', p.oid, 'EXECUTE'), \
                        has_function_privilege('epigraph_app', p.oid, 'EXECUTE') \
                   FROM pg_proc p WHERE p.oid = $1::regprocedure",
            )
            .bind(sig)
            .fetch_one(&pool)
            .await
            .expect("catalog");
        assert!(definer, "{sig}: SECURITY DEFINER");
        assert_eq!(owner, "epigraph_maintenance", "{sig}: owner");
        assert_eq!(
            config, "search_path=pg_catalog, pg_temp",
            "{sig}: 172's path"
        );
        assert!(!public_exec, "{sig}: PUBLIC executes it");
        assert!(!app_exec, "{sig}: epigraph_app executes it");
    }
    // The two real triggers still name them.
    let triggers: Vec<(String, String)> = sqlx::query_as(
        "SELECT t.tgname::text, t.tgfoid::regprocedure::text FROM pg_trigger t \
          WHERE t.tgname IN ('edges_auto_factor', 'claims_deactivate_factors') \
            AND NOT t.tgisinternal ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("triggers");
    assert_eq!(
        triggers,
        vec![
            (
                "claims_deactivate_factors".to_string(),
                "deactivate_superseded_factors()".to_string()
            ),
            (
                "edges_auto_factor".to_string(),
                "auto_create_factor_from_edge()".to_string()
            ),
        ]
    );
}
