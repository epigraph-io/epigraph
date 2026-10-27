//! Migration 181 (backlog 323773fe, ruling R-56): the narrow definer through
//! which a group ADMIN marks the group's re-key obligation,
//! `public.epigraph_mark_group_reseal_required(p_group uuid)`.
//!
//! Each behavioural arm calls the function DIRECTLY on a connection whose
//! `session_user` is `epigraph_app` (no BYPASSRLS, `groups` FORCEd), stamped
//! with a principal, which is the shape the member-removal route reaches it
//! in. Fixtures are seeded and read back on the superuser `#[sqlx::test]`
//! pool.
//!
//! What is pinned: an admin who did NOT create the group marks it, and the
//! call changes `reseal_required_at` and nothing else (`updated_at` is the
//! `groups_updated_at` trigger's); an existing mark keeps its first timestamp;
//! a writer, a stranger, an unstamped session and an admin of ANOTHER group
//! are refused with 42501 / `GRA01` and change nothing; and the catalog shape
//! (definer, owner, pinned path, grants) at head.

use sqlx::PgPool;
use uuid::Uuid;

const SIGNATURE: &str = "public.epigraph_mark_group_reseal_required(uuid)";
const CALL: &str = "SELECT public.epigraph_mark_group_reseal_required($1)";
/// The world group every migrated database seeds: a bystander no test here
/// marks.
const WORLD_GROUP: Uuid = Uuid::nil();

async fn seed_agent(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(id.as_bytes());
    key.extend_from_slice(id.as_bytes());
    sqlx::query_scalar("INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id")
        .bind(key)
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("seed agent")
}

/// A keyed team group created by `creator` (its first admin), on the
/// superuser pool.
async fn seed_group(pool: &PgPool, creator: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(id.as_bytes());
    key.extend_from_slice(id.as_bytes());
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id, \
                             properties) \
         VALUES ($1, $2, 'did:key:reseal-mark-' || $1::text, $3, 'team', $4, \
                 '{\"probe\": \"untouched\"}'::jsonb)",
    )
    .bind(id)
    .bind(format!("reseal mark {id}"))
    .bind(key)
    .bind(creator)
    .execute(pool)
    .await
    .expect("seed group");
    seed_member(pool, id, creator, "admin").await;
    id
}

async fn seed_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

/// The whole `groups` row as JSON, read on the superuser pool.
async fn row(pool: &PgPool, group: Uuid) -> serde_json::Value {
    sqlx::query_scalar("SELECT to_jsonb(g) FROM groups g WHERE g.id = $1")
        .bind(group)
        .fetch_one(pool)
        .await
        .expect("group row")
}

/// [`row`] without the column the function writes and the column the
/// `groups_updated_at` trigger maintains.
fn other_columns(mut v: serde_json::Value) -> serde_json::Value {
    let o = v.as_object_mut().expect("row is an object");
    o.remove("reseal_required_at");
    o.remove("updated_at");
    v
}

/// Call the function once on a fresh connection downgraded to `epigraph_app`
/// and stamped with `principal` (or with no principal at all), then hand the
/// connection back reset.
async fn call_as_app(
    pool: &PgPool,
    principal: Option<Uuid>,
    group: Uuid,
) -> Result<(), sqlx::Error> {
    use sqlx::Executor;
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade to the application role");
    if let Some(p) = principal {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(p.to_string())
            .execute(&mut *conn)
            .await
            .expect("stamp the principal");
    }
    let r = sqlx::query(CALL)
        .bind(group)
        .execute(&mut *conn)
        .await
        .map(|_| ());
    conn.execute("RESET SESSION AUTHORIZATION; RESET epigraph.principal_id")
        .await
        .expect("reset the connection");
    r
}

fn assert_refused(r: Result<(), sqlx::Error>, who: &str) {
    let err = r.expect_err(&format!("{who}: the mark must be refused"));
    let db = err
        .as_database_error()
        .unwrap_or_else(|| panic!("{who}: not a database error: {err}"));
    assert_eq!(db.code().as_deref(), Some("42501"), "{who}: {db}");
    assert!(
        db.message().starts_with("GRA01:"),
        "{who}: {}",
        db.message()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_creator_admin_marks_only_reseal_required_at(pool: PgPool) {
    let creator = seed_agent(&pool, "181-creator").await;
    let admin = seed_agent(&pool, "181-admin").await;
    let group = seed_group(&pool, creator).await;
    seed_member(&pool, group, admin, "admin").await;
    let before = row(&pool, group).await;
    assert!(before["reseal_required_at"].is_null(), "fixture: unmarked");

    call_as_app(&pool, Some(admin), group)
        .await
        .expect("a live admin who did not create the group marks it");

    let after = row(&pool, group).await;
    assert!(
        after["reseal_required_at"].is_string(),
        "the obligation is marked: {after}"
    );
    assert_eq!(
        other_columns(after),
        other_columns(before),
        "no other column of the group changed"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_existing_mark_keeps_its_first_timestamp(pool: PgPool) {
    let creator = seed_agent(&pool, "181-first-creator").await;
    let admin = seed_agent(&pool, "181-first-admin").await;
    let group = seed_group(&pool, creator).await;
    seed_member(&pool, group, admin, "admin").await;
    sqlx::query("UPDATE groups SET reseal_required_at = now() - interval '3 days' WHERE id = $1")
        .bind(group)
        .execute(&pool)
        .await
        .expect("an earlier unrotated removal");
    let first = row(&pool, group).await["reseal_required_at"].clone();

    call_as_app(&pool, Some(admin), group)
        .await
        .expect("an admin marks an already-marked group");

    assert_eq!(
        row(&pool, group).await["reseal_required_at"],
        first,
        "the obligation dates from the FIRST unrotated removal"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_admin_cannot_mark_and_nothing_changes(pool: PgPool) {
    let creator = seed_agent(&pool, "181-refuse-creator").await;
    let writer = seed_agent(&pool, "181-refuse-writer").await;
    let reader = seed_agent(&pool, "181-refuse-reader").await;
    let stranger = seed_agent(&pool, "181-refuse-stranger").await;
    let group = seed_group(&pool, creator).await;
    seed_member(&pool, group, writer, "writer").await;
    seed_member(&pool, group, reader, "reader").await;
    let before = row(&pool, group).await;

    for (principal, who) in [
        (Some(writer), "a writer"),
        (Some(reader), "a reader"),
        (Some(stranger), "a stranger"),
        (None, "an unstamped application session"),
    ] {
        assert_refused(call_as_app(&pool, principal, group).await, who);
    }
    assert_eq!(
        row(&pool, group).await,
        before,
        "the group row is unchanged"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_of_one_group_cannot_mark_another(pool: PgPool) {
    let a_admin = seed_agent(&pool, "181-a-admin").await;
    let b_admin = seed_agent(&pool, "181-b-admin").await;
    let group_a = seed_group(&pool, a_admin).await;
    let group_b = seed_group(&pool, b_admin).await;
    // A is also a plain member of B: membership is not admin.
    seed_member(&pool, group_b, a_admin, "writer").await;
    let before_b = row(&pool, group_b).await;

    assert_refused(
        call_as_app(&pool, Some(a_admin), group_b).await,
        "an admin of A on B",
    );
    assert_eq!(row(&pool, group_b).await, before_b, "B is unchanged");

    let world_before = row(&pool, WORLD_GROUP).await;
    assert!(
        world_before["reseal_required_at"].is_null(),
        "fixture: the migration-seeded world group is unmarked"
    );

    call_as_app(&pool, Some(a_admin), group_a)
        .await
        .expect("CONTROL: the same principal marks its own group");
    assert!(row(&pool, group_a).await["reseal_required_at"].is_string());

    // The mark is ONE group's. Inside the definer's frame `current_user` is the
    // maintenance owner, which `groups_tenancy` admits on every row, so only
    // the function's own `WHERE` keeps a successful mark off the bystanders.
    assert_eq!(
        row(&pool, group_b).await,
        before_b,
        "marking A leaves B's whole row unchanged"
    );
    assert_eq!(
        row(&pool, WORLD_GROUP).await,
        world_before,
        "marking A leaves the world group's whole row unchanged"
    );
}

/// `(prosecdef, owner, proacl, proconfig, prosrc)` of one function.
type CatalogRow = (bool, String, Option<String>, Option<Vec<String>>, String);

/// The catalog at head: a maintenance-owned definer with 172's pinned path,
/// executable by the application role and not by PUBLIC. Pinned here because
/// the harness migrates as a superuser, so a silently no-opped guarded
/// `OWNER TO` or `GRANT` would pass every behavioural arm above.
#[sqlx::test(migrations = "../../migrations")]
async fn the_mark_is_a_maintenance_owned_definer_the_app_role_executes(pool: PgPool) {
    let row: Option<CatalogRow> = sqlx::query_as(
        "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, p.proacl::text, \
                p.proconfig, p.prosrc \
           FROM pg_proc p WHERE p.oid = to_regprocedure($1)",
    )
    .bind(SIGNATURE)
    .fetch_optional(&pool)
    .await
    .expect("catalog read");
    let Some((secdef, owner, acl, config, src)) = row else {
        panic!("{SIGNATURE} does not exist");
    };
    assert!(secdef, "SECURITY DEFINER");
    assert_eq!(owner, "epigraph_maintenance");
    assert_eq!(
        config.unwrap_or_default(),
        vec!["search_path=pg_catalog, pg_temp".to_string()],
        "172's pinned path"
    );
    let acl = acl.expect("an explicit ACL");
    assert!(
        acl.contains("epigraph_app=X/"),
        "the app role executes: {acl}"
    );
    assert!(src.contains("pg_catalog.now()"), "built-ins qualified");
    assert!(
        !src.replace("pg_catalog.now()", "").contains("now()"),
        "no unqualified now(): {src}"
    );

    // `has_function_privilege('public', ...)` rather than scanning `proacl`
    // text for PUBLIC's empty grantee, as schema_contract.rs asks it.
    let can: (bool, bool, bool) = sqlx::query_as(
        "SELECT has_function_privilege('public', $1, 'EXECUTE'), \
                has_function_privilege('epigraph_app', $1, 'EXECUTE'), \
                has_function_privilege('epigraph_maintenance', $1, 'EXECUTE')",
    )
    .bind(SIGNATURE)
    .fetch_one(&pool)
    .await
    .expect("privilege read");
    assert_eq!(
        can,
        (false, true, true),
        "(PUBLIC, epigraph_app, epigraph_maintenance) EXECUTE"
    );
}
