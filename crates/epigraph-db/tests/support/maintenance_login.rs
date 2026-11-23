//! REAL logins: a `LOGIN NOSUPERUSER NOBYPASSRLS INHERIT` role that is a
//! member of `epigraph_maintenance` (as `docs/deploy.md` step 5 provisions the
//! one in `MAINTENANCE_DATABASE_URL`) or of `epigraph_app` (step 4), and of
//! nothing else, connected to with its own password. Its `session_user` and
//! `current_user` are the login itself (not the group role, which is what a
//! `SET SESSION AUTHORIZATION epigraph_maintenance` fixture gives), so a guard
//! that tests "the statement runs as the maintenance role" sees exactly what
//! production sees.
//!
//! Roles are cluster-wide: each login gets a unique name, and the caller
//! drops it with [`drop_login`] (a panicking test leaks one memberless login,
//! as the other login fixtures in this workspace do).

#![allow(dead_code)]

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

/// Create the login and return `(role, pool)`; the pool's connections are the
/// login's own.
pub async fn maintenance_login(pool: &PgPool, tag: &str) -> (String, PgPool) {
    let (role, login) = login_in(pool, tag, "maint", "epigraph_maintenance").await;

    let (session, current, superuser, bypass, maint_member): (String, String, bool, bool, bool) =
        sqlx::query_as(
            "SELECT session_user::text, current_user::text, r.rolsuper, \
                    public.epigraph_bypass(), \
                    pg_has_role(current_user, 'epigraph_maintenance', 'USAGE') \
               FROM pg_roles r WHERE r.rolname = current_user",
        )
        .fetch_one(&login)
        .await
        .expect("read the login's identity");
    assert_eq!(session, role, "fixture: the session is the login itself");
    assert_eq!(current, role, "fixture: and so is current_user");
    assert!(!superuser, "fixture: the login is not a superuser");
    assert!(bypass, "fixture: the login is privileged (epigraph_bypass)");
    assert!(
        maint_member,
        "fixture: the login inherits epigraph_maintenance"
    );
    (role, login)
}

/// A REAL application login, made as `docs/deploy.md` step 4 makes the API's:
/// a `LOGIN NOSUPERUSER NOBYPASSRLS INHERIT` role that is a member of
/// `epigraph_app` and nothing else, connected with its own password.
pub async fn app_login(pool: &PgPool, tag: &str) -> (String, PgPool) {
    let (role, login) = login_in(pool, tag, "app", "epigraph_app").await;
    let (session, superuser, bypass, app_member): (String, bool, bool, bool) = sqlx::query_as(
        "SELECT session_user::text, r.rolsuper, public.epigraph_bypass(), \
                pg_has_role(current_user, 'epigraph_app', 'USAGE') \
           FROM pg_roles r WHERE r.rolname = current_user",
    )
    .fetch_one(&login)
    .await
    .expect("read the app login's identity");
    assert_eq!(session, role, "fixture: the session is the login itself");
    assert!(!superuser, "fixture: the login is not a superuser");
    assert!(!bypass, "fixture: the app login is not privileged");
    assert!(app_member, "fixture: the login inherits epigraph_app");
    (role, login)
}

/// `CREATE ROLE <tag>_<kind>_<uuid> LOGIN ... IN ROLE <member_of>` and a pool
/// of the login's own connections.
async fn login_in(pool: &PgPool, tag: &str, kind: &str, member_of: &str) -> (String, PgPool) {
    let role = format!("{tag}_{kind}_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB INHERIT \
         PASSWORD 'probe-only' IN ROLE {member_of}"
    ))
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("create the {kind} login: {e}"));

    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("current_database()");
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let (scheme, rest) = base.split_once("://").expect("DATABASE_URL scheme");
    let (_, host_and_path) = rest.split_once('@').expect("DATABASE_URL credentials");
    let host = host_and_path
        .split_once('/')
        .map_or(host_and_path, |(h, _)| h);
    let query = base.split_once('?').map(|(_, q)| format!("?{q}"));
    let dsn = format!(
        "{scheme}://{role}:probe-only@{host}/{db}{}",
        query.unwrap_or_default()
    );
    let login = PgPoolOptions::new()
        .max_connections(2)
        .connect(&dsn)
        .await
        .unwrap_or_else(|e| panic!("connect as the {kind} login: {e}"));

    (role, login)
}

/// Close the login's pool and drop the role.
pub async fn drop_login(pool: &PgPool, role: &str, login: PgPool) {
    login.close().await;
    sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("drop the login {role}: {e}"));
}
