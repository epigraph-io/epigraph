//! The compound guard of the cached-belief owner lookup holds CLOSED on a
//! row-security-filtered connection (backlog 0dc20fad, migration 193).
//!
//! `MassFunctionRepository::cache_owner_frame_for_claim` gives a compound no
//! owner, so no recompute that resolves its owner there refolds the BBAs that
//! sit on it into its cache. The per-request refreshes (`routes::assess`, REST
//! and MCP BBA retract / un-retract) run it on the CALLER's application
//! session, where row security filters `edges` and `claims`. The inline
//! `IS_COMPOUND_SQL` read there found no compound when the caller could see
//! none of the decomposition, so the guard failed open. Migration 193 decides
//! the role with definer rights (`public.epigraph_claim_is_compound`).
//!
//! What is pinned here:
//!
//! * on an `epigraph_app` session stamped for a caller who cannot read the
//!   compound's only child (private to another group), the compound has no
//!   cache owner. Calibrated in the same session: the old inline predicate
//!   finds no compound there (the session really hides the decomposition), a
//!   standalone twin holding the same BBA HAS an owner (the session reads the
//!   BBA rows), and a compound with a public child has none;
//! * the definer's catalog shape: SECURITY DEFINER, owned by
//!   `epigraph_maintenance`, path `pg_catalog, pg_temp`, no PUBLIC EXECUTE,
//!   EXECUTE for the application role;
//! * ONE spelling: its body is `IS_COMPOUND_SQL`, schema-qualified, and
//!   nothing else (the behavioural agreement over the role fixtures is
//!   `claim_role.rs::assert_one_spelling`).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::claim_role;
use epigraph_db::visibility::Viewer;
use epigraph_db::{MassFunctionRepository, ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;

/// The definer's signature.
const DEFINER: &str = "public.epigraph_claim_is_compound(uuid)";

/// A claim with explicit tenancy.
async fn claim(pool: &PgPool, author: Uuid, group: Uuid, visibility: &str, what: &str) -> Uuid {
    let content = format!("0dc20fad {what} {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, true, $3, $4) RETURNING id",
    )
    .bind(&content)
    .bind(author)
    .bind(visibility)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// An in-force `parent -decomposes_to-> child` edge, its own tenancy forced
/// to `(visibility, group)` (the trigger fires only on endpoint changes, so
/// the UPDATE sticks).
async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid, visibility: &str, group: Uuid) {
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_from) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
                 now() - interval '1 day') RETURNING id",
    )
    .bind(parent)
    .bind(child)
    .fetch_one(pool)
    .await
    .expect("seed decomposes_to");
    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(edge)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("force edge tenancy");
}

async fn frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("0dc20fad-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

/// One plain (non-template, non-combination) BBA of `agent` on `claim`.
async fn bba(pool: &PgPool, agent: Uuid, claim: Uuid, frame: Uuid) {
    let perspective: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("0dc20fad-{}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed perspective");
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, perspective_id, \
                                     masses, source_strength) \
         VALUES ($1, $2, $3, $4, $5, 1.0)",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(perspective)
    .bind(serde_json::json!({"0": 0.7, "0,1": 0.3}))
    .execute(pool)
    .await
    .expect("seed BBA");
}

/// The inline `IS_COMPOUND_SQL` (the pre-193 guard's predicate) over `id`.
async fn inline_is_compound(conn: &mut sqlx::PgConnection, id: Uuid) -> bool {
    let sql = format!(
        "SELECT EXISTS (SELECT 1 FROM claims c WHERE c.id = $1 AND {})",
        claim_role::is_compound_sql("c")
    );
    sqlx::query_scalar(&sql)
        .bind(id)
        .fetch_one(conn)
        .await
        .expect("inline IS_COMPOUND_SQL")
}

/// What the caller's application session sees for each claim:
/// `(cache owner, inline IS_COMPOUND_SQL, the definer)`, on an
/// `epigraph_app` transaction stamped from `viewer` exactly as the request
/// path stamps it (`ScopedPool::begin_as`).
async fn on_app_session(
    pool: &PgPool,
    viewer: &Viewer,
    ids: &[Uuid],
) -> Vec<(Option<Uuid>, bool, bool)> {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let mut tx = scoped.begin_as(viewer).await.expect("stamped transaction");
    let who: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&mut *tx)
        .await
        .expect("session_user");
    assert_eq!(
        who, "epigraph_app",
        "the session must be the application role"
    );
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let owner = MassFunctionRepository::cache_owner_frame_for_claim(&mut *tx, viewer, *id)
            .await
            .expect("cache_owner_frame_for_claim on an app session");
        let inline = inline_is_compound(&mut tx, *id).await;
        let definer: bool = sqlx::query_scalar("SELECT public.epigraph_claim_is_compound($1)")
            .bind(*id)
            .fetch_one(&mut *tx)
            .await
            .expect("the definer is EXECUTE-able by the app role");
        out.push((owner, inline, definer));
    }
    tx.rollback().await.expect("rollback");
    out
}

/// The red test of 0dc20fad. The caller writes into its own group, which
/// owns the public compound `hidden`; `hidden`'s only child, and the edge to
/// it, are private to another group. On the caller's stamped application
/// session `hidden` has NO cache owner, so no owner-resolving refresh refolds
/// its BBA into its cache.
#[sqlx::test(migrations = "../../migrations")]
async fn on_an_app_session_a_compound_with_a_private_decomposition_has_no_cache_owner(
    pool: PgPool,
) {
    let (caller, mine) = fixture::seed_agent_with_group(&pool, "0dc20fad-caller").await;
    let (other, theirs) = fixture::seed_agent_with_group(&pool, "0dc20fad-other").await;
    let f = frame(&pool).await;

    let hidden = claim(
        &pool,
        caller,
        mine,
        "public",
        "compound, private decomposition",
    )
    .await;
    let child = claim(&pool, other, theirs, "group", "private only child").await;
    decomposes_to(&pool, hidden, child, "group", theirs).await;
    let standalone = claim(&pool, caller, mine, "public", "standalone twin").await;
    let open = claim(
        &pool,
        caller,
        mine,
        "public",
        "compound, public decomposition",
    )
    .await;
    let open_child = claim(&pool, caller, mine, "public", "public child").await;
    decomposes_to(&pool, open, open_child, "public", mine).await;
    for c in [hidden, standalone, open] {
        bba(&pool, caller, c, f).await;
    }

    // On the superuser (bypass) connection `hidden` is a compound.
    let mut su = pool.acquire().await.expect("acquire");
    assert!(
        inline_is_compound(&mut su, hidden).await,
        "calibration: structurally, the fixture is a compound"
    );
    drop(su);

    let viewer = Viewer::resolve(&pool, caller)
        .await
        .expect("resolve caller");
    let got = on_app_session(&pool, &viewer, &[hidden, standalone, open]).await;
    let (hidden_owner, hidden_inline, hidden_definer) = got[0];
    let (standalone_owner, _, standalone_definer) = got[1];
    let (open_owner, open_inline, open_definer) = got[2];

    assert!(
        !hidden_inline,
        "calibration: the caller's session cannot see the private decomposition, so the \
         inline predicate (the pre-193 guard) finds no compound"
    );
    assert_eq!(
        standalone_owner,
        Some(f),
        "calibration: the session reads the BBA rows, so a standalone claim has an owner"
    );
    assert!(!standalone_definer, "a standalone claim is not a compound");
    assert!(
        open_inline && open_definer,
        "calibration: a visible compound"
    );
    assert_eq!(open_owner, None, "a visible compound has no owner");
    assert!(
        hidden_definer,
        "the definer decides the role on the whole graph, whatever the session sees"
    );
    assert_eq!(
        hidden_owner, None,
        "0dc20fad: a compound whose decomposition the caller's row security hides must \
         still have no cache owner (it had {hidden_owner:?})"
    );
}

/// Migration 193's definer, as the catalog holds it: maintenance-owned
/// SECURITY DEFINER, STABLE, pinned to `pg_catalog, pg_temp` (172's form; no
/// `public` on the path, `pg_temp` last), not EXECUTE-able by PUBLIC, and
/// EXECUTE-able by the application and maintenance roles.
#[sqlx::test(migrations = "../../migrations")]
async fn the_definer_is_maintenance_owned_pinned_and_executable_by_the_app_role(pool: PgPool) {
    let (secdef, owner, volatile, config): (bool, String, String, Option<Vec<String>>) =
        sqlx::query_as(
            "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, p.provolatile::text, \
                    p.proconfig \
               FROM pg_proc p WHERE p.oid = $1::regprocedure",
        )
        .bind(DEFINER)
        .fetch_one(&pool)
        .await
        .expect("the definer exists");
    assert!(secdef, "{DEFINER} must be SECURITY DEFINER");
    assert_eq!(owner, "epigraph_maintenance", "{DEFINER} owner");
    assert_eq!(volatile, "s", "{DEFINER} is STABLE");
    assert_eq!(
        config.unwrap_or_default(),
        vec!["search_path=pg_catalog, pg_temp".to_string()],
        "{DEFINER} pins 172's path"
    );
    for (role, expected) in [
        ("public", false),
        ("epigraph_app", true),
        ("epigraph_maintenance", true),
    ] {
        let can: bool =
            sqlx::query_scalar("SELECT has_function_privilege($1, $2::regprocedure, 'EXECUTE')")
                .bind(role)
                .bind(DEFINER)
                .fetch_one(&pool)
                .await
                .expect("has_function_privilege");
        assert_eq!(can, expected, "EXECUTE on {DEFINER} for {role}");
    }
}

/// [`claim_role::IS_COMPOUND_SQL`] over `alias` as migration 193 states it:
/// every relation it names schema-qualified to `public` and `now()` as
/// `pg_catalog.now()`. Panics if a `FROM` / `JOIN` is left naming an
/// unqualified relation other than the template's own CTE, so a template
/// change that adds a table cannot slip through unqualified.
fn qualified_is_compound(alias: &str) -> String {
    let mut sql = claim_role::is_compound_sql(alias);
    for (from, to) in [
        ("FROM edges ", "FROM public.edges "),
        ("JOIN edges ", "JOIN public.edges "),
        ("FROM claims ", "FROM public.claims "),
        ("JOIN claims ", "JOIN public.claims "),
        ("FROM system_agents ", "FROM public.system_agents "),
        ("now()", "pg_catalog.now()"),
    ] {
        sql = sql.replace(from, to);
    }
    let tokens: Vec<&str> = sql.split_whitespace().collect();
    for pair in tokens.windows(2) {
        if matches!(pair[0], "FROM" | "JOIN") {
            let rel = pair[1];
            assert!(
                rel.starts_with("public.") || rel == "role_up",
                "IS_COMPOUND_SQL names the relation {rel:?}, which this qualifier does not \
                 qualify; extend it and re-state the definer in a new migration"
            );
        }
    }
    sql
}

fn without_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// ONE spelling: the definer's body is `IS_COMPOUND_SQL` (schema-qualified)
/// over the claims row `c` bound to the argument, and nothing else. A change
/// to the Rust template without a migration that re-states the body fails
/// here. Whitespace is not compared (the migration is formatted for reading).
#[sqlx::test(migrations = "../../migrations")]
async fn the_definer_body_is_the_one_spelling_of_is_compound(pool: PgPool) {
    let prosrc: String =
        sqlx::query_scalar("SELECT p.prosrc FROM pg_proc p WHERE p.oid = $1::regprocedure")
            .bind(DEFINER)
            .fetch_one(&pool)
            .await
            .expect("the definer's body");
    let expected = format!(
        "SELECT EXISTS (SELECT 1 FROM public.claims c WHERE c.id = p_claim_id AND {})",
        qualified_is_compound("c")
    );
    assert_eq!(
        without_whitespace(&prosrc),
        without_whitespace(&expected),
        "{DEFINER}'s body has drifted from claim_role::IS_COMPOUND_SQL.\n\
         expected (whitespace aside):\n{expected}\n\ncatalog:\n{prosrc}"
    );
}

/// The guard is `AND NOT (SELECT <definer>)`, so a NULL from the definer
/// would turn it into `AND NULL` and silently drop EVERY owner row. The
/// definer is documented "never NULL": an id that names no claim, and a
/// parent whose only child has been superseded (no in-force decomposition
/// left), both answer FALSE. Decoded as `Option<bool>`, so a NULL fails the
/// assertion rather than the decode.
#[sqlx::test(migrations = "../../migrations")]
async fn the_definer_answers_false_never_null_for_an_unknown_or_no_longer_compound_claim(
    pool: PgPool,
) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "0dc20fad-null").await;
    let parent = claim(&pool, agent, group, "public", "parent").await;
    let child = claim(&pool, agent, group, "public", "only child").await;
    decomposes_to(&pool, parent, child, "public", group).await;
    let call = "SELECT public.epigraph_claim_is_compound($1)";
    let live: Option<bool> = sqlx::query_scalar(call)
        .bind(parent)
        .fetch_one(&pool)
        .await
        .expect("definer on the live compound");
    assert_eq!(live, Some(true), "calibration: the parent is a compound");
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(child)
        .execute(&pool)
        .await
        .expect("supersede the only child");

    for (what, id) in [
        ("unknown id", Uuid::new_v4()),
        ("parent whose only child is superseded", parent),
    ] {
        let got: Option<bool> = sqlx::query_scalar(call)
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("definer call");
        assert_eq!(
            got,
            Some(false),
            "{what}: the definer must answer FALSE, never NULL"
        );
    }
}

/// `routes::assess` runs the refresh on a plain `db_pool` connection, which
/// carries no viewer stamp (row security then admits public rows only), not
/// on a `ScopedPool::begin_as` transaction. The guard must hold on that
/// connection state too: on an UNSTAMPED `epigraph_app` session the compound
/// whose only child is private has no owner, while its standalone twin (same
/// BBA, public) does. The viewer is resolved on the superuser pool BEFORE the
/// downgrade, as `viewer_fixture::downgraded_pool` requires.
#[sqlx::test(migrations = "../../migrations")]
async fn on_an_unstamped_app_session_a_compound_with_a_private_decomposition_has_no_cache_owner(
    pool: PgPool,
) {
    let (caller, mine) = fixture::seed_agent_with_group(&pool, "0dc20fad-unstamped").await;
    let (other, theirs) = fixture::seed_agent_with_group(&pool, "0dc20fad-unstamped-o").await;
    let f = frame(&pool).await;
    let hidden = claim(&pool, caller, mine, "public", "compound, private child").await;
    let child = claim(&pool, other, theirs, "group", "private only child").await;
    decomposes_to(&pool, hidden, child, "group", theirs).await;
    let standalone = claim(&pool, caller, mine, "public", "standalone twin").await;
    for c in [hidden, standalone] {
        bba(&pool, caller, c, f).await;
    }
    let viewer = Viewer::resolve(&pool, caller)
        .await
        .expect("resolve caller");

    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let mut conn = app.acquire().await.expect("app-role connection");
    let who: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&mut *conn)
        .await
        .expect("current_user");
    assert_eq!(
        who, "epigraph_app",
        "the session must be the application role"
    );
    assert!(
        !inline_is_compound(&mut conn, hidden).await,
        "calibration: the unstamped session cannot see the private decomposition"
    );
    let twin = MassFunctionRepository::cache_owner_frame_for_claim(&mut *conn, &viewer, standalone)
        .await
        .expect("owner lookup of the twin");
    assert_eq!(
        twin,
        Some(f),
        "calibration: the unstamped session reads the public BBA rows"
    );
    let owner = MassFunctionRepository::cache_owner_frame_for_claim(&mut *conn, &viewer, hidden)
        .await
        .expect("owner lookup of the compound");
    assert_eq!(
        owner, None,
        "0dc20fad: on an unstamped app session a compound whose decomposition is hidden must \
         have no cache owner (it had {owner:?})"
    );
}
