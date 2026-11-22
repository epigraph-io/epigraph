//! A REAL maintenance login: a `LOGIN NOSUPERUSER NOBYPASSRLS INHERIT` role
//! that is a member of `epigraph_maintenance` and nothing else, connected to
//! with its own password, as `docs/deploy.md` step 5 provisions the one in
//! `MAINTENANCE_DATABASE_URL`. Its `session_user` and `current_user` are the
//! login itself (not `epigraph_maintenance`, which is what a `SET SESSION
//! AUTHORIZATION epigraph_maintenance` fixture gives), so a guard that tests
//! "the statement runs as the maintenance role" sees exactly what production
//! sees.
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
    let role = format!("{tag}_maint_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB INHERIT \
         PASSWORD 'probe-only' IN ROLE epigraph_maintenance"
    ))
    .execute(pool)
    .await
    .expect("create the maintenance login");

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
        .expect("connect as the maintenance login");

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

/// Close the login's pool and drop the role.
pub async fn drop_login(pool: &PgPool, role: &str, login: PgPool) {
    login.close().await;
    sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("drop the maintenance login {role}: {e}"));
}
