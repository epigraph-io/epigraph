//! Migration 231 (backlog bb200b7b): `epigraph_app` is NOLOGIN after
//! migrating, whatever the cluster held before.
//!
//! # The scenario CI never sees
//!
//! Migration 060 creates `epigraph_app` NOLOGIN only `IF NOT EXISTS`. CI's
//! Postgres starts empty, so 060 always takes the CREATE branch and the role
//! is always NOLOGIN there. A cluster where `epigraph_app` already existed
//! WITH LOGIN (a production database armed by the old docs/deploy.md step 4)
//! kept LOGIN for ever. Every test below starts from that cluster: it gives
//! `epigraph_app` LOGIN before the migration under test runs.
//!
//! # Why these tests take a lock, and commit role changes
//!
//! Roles are CLUSTER-global, and a real second login needs a COMMITTED
//! `LOGIN` (a new connection cannot see an uncommitted `ALTER ROLE`). Every
//! test in this file flips `epigraph_app`'s LOGIN and some open a session
//! logged in as it, which migration 231 refuses cluster-wide, so the tests
//! here are serialized on [`SERIAL`] and each runs its own migrations
//! (`migrations = false`) under that lock. This file is its own test binary,
//! and `cargo test` runs binaries one after another, so no other binary's
//! migrations overlap these sessions. Each test leaves `epigraph_app` NOLOGIN
//! with no password, which is the state migration 231 establishes anyway.

use sqlx::migrate::{MigrateError, Migrator};
use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use uuid::Uuid;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// Every migration below the one under test. 230 is another change's slot
/// (it may or may not be on this tree); `up_to` takes whatever exists at or
/// below it.
const HEAD_BEFORE_231: i64 = 230;

/// Serializes every test in this binary; see the module docs. An async
/// mutex: each `#[sqlx::test]` runs on its own runtime, and the guard is held
/// across awaits. It is released on unwind, so one failing test does not
/// wedge the rest.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn up_to(max: i64) -> Migrator {
    Migrator {
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

/// Which migration set this binary embeds, printed so a run shows whether it
/// ran with or without 231 (`sqlx::migrate!` embeds at compile time).
fn report_embedded_head() {
    let head = MIGRATOR.migrations.iter().map(|m| m.version).max();
    println!("embedded migration head: {head:?}");
}

async fn migrate(pool: &PgPool, migrator: &Migrator) -> Result<(), MigrateError> {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = migrator.run(&mut *conn).await;
    // A failed `run` returns before releasing sqlx's session-level migration
    // lock, and this connection goes back to the pool; release it here so the
    // next run (on whichever connection) does not wait on it for ever.
    conn.execute("SELECT pg_advisory_unlock_all()")
        .await
        .expect("release the migration lock");
    conn.execute("RESET ALL").await.expect("RESET ALL");
    out
}

async fn app_can_login(pool: &PgPool) -> bool {
    sqlx::query_scalar("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'epigraph_app'")
        .fetch_one(pool)
        .await
        .expect("epigraph_app exists")
}

/// Give `epigraph_app` LOGIN (creating it with LOGIN when the cluster has no
/// such role yet), and a password when one is given: the armed state the old
/// deploy docs produced.
async fn arm_app_login(pool: &PgPool, password: Option<&str>) {
    let pw = password
        .map(|p| format!(" PASSWORD '{p}'"))
        .unwrap_or_default();
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app')")
            .fetch_one(pool)
            .await
            .unwrap();
    let verb = if exists { "ALTER" } else { "CREATE" };
    pool.execute(format!("{verb} ROLE epigraph_app LOGIN{pw}").as_str())
        .await
        .unwrap_or_else(|e| panic!("{verb} ROLE epigraph_app LOGIN: {e}"));
    assert!(
        app_can_login(pool).await,
        "CALIBRATION: epigraph_app must log in before the migration under test"
    );
}

/// Leave the cluster in 231's end state, password removed.
async fn disarm_app_login(pool: &PgPool) {
    pool.execute("ALTER ROLE epigraph_app NOLOGIN PASSWORD NULL")
        .await
        .expect("disarm epigraph_app");
}

fn login_options(pool: &PgPool, user: &str, password: &str) -> PgConnectOptions {
    (*pool.connect_options())
        .clone()
        .username(user)
        .password(password)
        .application_name("app_role_nologin_test")
}

async fn sessions_logged_in_as(pool: &PgPool, user: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// A backend exits asynchronously after its client disconnects.
async fn wait_until_no_session_as(pool: &PgPool, user: &str) {
    for _ in 0..100 {
        if sessions_logged_in_as(pool, user).await == 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("a session logged in as {user} is still in pg_stat_activity after 5 s");
}

async fn applied_successfully(pool: &PgPool, version: i64) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = $1 AND success)",
    )
    .bind(version)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// `(current_user, session_user)` on `conn`. Not a cached prepared
/// statement: `DISCARD ALL` below deallocates those.
async fn identity(conn: &mut PgConnection) -> (String, String) {
    sqlx::query_as("SELECT current_user::text, session_user::text")
        .persistent(false)
        .fetch_one(&mut *conn)
        .await
        .expect("identity")
}

/// The bug itself: a cluster whose `epigraph_app` already had LOGIN before
/// 060 ran. 060 skips the existing role, and before 231 nothing ever took the
/// login away.
#[sqlx::test(migrations = false)]
async fn a_pre_existing_login_app_role_is_nologin_after_migrating(pool: PgPool) {
    let _serial = SERIAL.lock().await;
    report_embedded_head();

    arm_app_login(&pool, None).await;
    migrate(&pool, &MIGRATOR)
        .await
        .expect("migrate 001 -> head");

    assert!(
        !app_can_login(&pool).await,
        "epigraph_app had LOGIN before migrating and still has it after: 060 keeps an existing \
         role as it is, so the end state must be asserted by a later migration (231)"
    );
    // Only LOGIN changes: the role keeps the posture the contract asserts.
    let (superuser, bypassrls, createrole, createdb): (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb \
           FROM pg_roles WHERE rolname = 'epigraph_app'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (superuser, bypassrls, createrole, createdb),
        (false, false, false, false)
    );

    disarm_app_login(&pool).await;
}

/// A service logged in as `epigraph_app` while the deploy migrates: 231
/// refuses, changes nothing, and the operator sees a message that names the
/// fix. Once the session is gone, the same run succeeds.
#[sqlx::test(migrations = false)]
async fn the_migration_refuses_while_a_session_is_logged_in_as_the_app_role(pool: PgPool) {
    let _serial = SERIAL.lock().await;
    report_embedded_head();

    migrate(&pool, &up_to(HEAD_BEFORE_231))
        .await
        .expect("migrate to just below 231");
    let password = format!("pw-{}", Uuid::new_v4().simple());
    arm_app_login(&pool, Some(&password)).await;

    let mut live = PgConnection::connect_with(&login_options(&pool, "epigraph_app", &password))
        .await
        .expect("CALIBRATION: an armed epigraph_app must accept a login");
    assert_eq!(
        identity(&mut live).await,
        ("epigraph_app".to_string(), "epigraph_app".to_string())
    );
    assert!(sessions_logged_in_as(&pool, "epigraph_app").await >= 1);

    let err = migrate(&pool, &MIGRATOR)
        .await
        .expect_err("231 must refuse while a session is logged in as epigraph_app");
    // What `epigraph-migrate` prints after `migrations: FAILED: sqlx::migrate failed: `.
    let shown = err.to_string();
    println!("operator sees: {shown}");
    assert!(
        shown.starts_with("while executing migration 231: ")
            && shown.contains("231 refuses: 1 session(s) are logged in as epigraph_app")
            && shown.contains("app_role_nologin_test")
            // The guide is named by its directory and file separately: a whole
            // `docs/deploy.md` literal reads to the CI shard planner as a file this
            // test opens, so every docs-only change would run its shard.
            && shown.contains(concat!("docs", "/deploy.md"))
            && shown.contains("re-run epigraph-migrate"),
        "{shown}"
    );
    match &err {
        MigrateError::ExecuteMigration(e, 231) => assert_eq!(
            e.as_database_error().and_then(|d| d.code()).as_deref(),
            Some("55000"),
            "{e}"
        ),
        other => panic!("expected ExecuteMigration(_, 231), got {other:?}"),
    }
    assert!(app_can_login(&pool).await, "a refusal must change nothing");
    assert!(
        !applied_successfully(&pool, 231).await,
        "a refusal must record nothing"
    );

    // The live session is untouched by the refusal.
    assert_eq!(identity(&mut live).await.1, "epigraph_app");
    live.close().await.expect("close");
    wait_until_no_session_as(&pool, "epigraph_app").await;

    migrate(&pool, &MIGRATOR)
        .await
        .expect("with the session gone, the same run applies 231");
    assert!(applied_successfully(&pool, 231).await);
    assert!(!app_can_login(&pool).await);
    let refused = PgConnection::connect_with(&login_options(&pool, "epigraph_app", &password))
        .await
        .expect_err("NOLOGIN refuses the next connection");
    assert!(
        refused.to_string().contains("not permitted to log in"),
        "{refused}"
    );

    disarm_app_login(&pool).await;
}

/// The runbook's central claim. With the service moved to its own login (a
/// member of `epigraph_app` whose default is `SET role = 'epigraph_app'`),
/// 231 applies while that login's session is open, the session keeps
/// working, new connections as that login still succeed with `current_user =
/// epigraph_app` (what the API's posture check keys on), and only direct
/// `epigraph_app` logins are refused. A superuser session that has merely
/// switched to `epigraph_app` (what the test fixtures do) does not block it
/// either.
#[sqlx::test(migrations = false)]
async fn a_member_login_with_the_app_role_default_keeps_working_and_does_not_block(pool: PgPool) {
    let _serial = SERIAL.lock().await;
    report_embedded_head();

    migrate(&pool, &up_to(HEAD_BEFORE_231))
        .await
        .expect("migrate to just below 231");
    let app_password = format!("pw-{}", Uuid::new_v4().simple());
    arm_app_login(&pool, Some(&app_password)).await;

    let login = format!("api_login_{}", Uuid::new_v4().simple());
    let password = format!("pw-{}", Uuid::new_v4().simple());
    pool.execute(
        format!(
            "CREATE ROLE {login} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE \
             NOREPLICATION INHERIT PASSWORD '{password}' IN ROLE epigraph_app"
        )
        .as_str(),
    )
    .await
    .expect("create the member login");
    pool.execute(format!("ALTER ROLE {login} SET role = 'epigraph_app'").as_str())
        .await
        .expect("default the member login to the app role");

    let mut api = PgConnection::connect_with(&login_options(&pool, &login, &password))
        .await
        .expect("connect as the member login");
    assert_eq!(
        identity(&mut api).await,
        ("epigraph_app".to_string(), login.clone()),
        "the member login must act as epigraph_app from its first statement"
    );
    // A pool's reset statements return to the role default, not to the login.
    api.execute("RESET ALL").await.unwrap();
    assert_eq!(
        identity(&mut api).await.0,
        "epigraph_app",
        "after RESET ALL"
    );
    api.execute("DISCARD ALL").await.unwrap();
    assert_eq!(
        identity(&mut api).await.0,
        "epigraph_app",
        "after DISCARD ALL"
    );

    // A superuser connection downgraded the way the test fixtures do it.
    let mut downgraded = pool.acquire().await.expect("acquire");
    downgraded
        .execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .unwrap();
    assert_eq!(identity(&mut downgraded).await.1, "epigraph_app");
    assert_eq!(
        sessions_logged_in_as(&pool, "epigraph_app").await,
        0,
        "CALIBRATION: neither session authenticated as epigraph_app"
    );

    migrate(&pool, &MIGRATOR)
        .await
        .expect("231 applies while only member logins and downgraded sessions are open");
    assert!(!app_can_login(&pool).await);

    assert_eq!(
        identity(&mut api).await,
        ("epigraph_app".to_string(), login.clone()),
        "the open member-login session keeps working"
    );
    let mut next = PgConnection::connect_with(&login_options(&pool, &login, &password))
        .await
        .expect("a NEW connection as the member login still succeeds after 231");
    assert_eq!(
        identity(&mut next).await,
        ("epigraph_app".to_string(), login.clone())
    );
    let refused = PgConnection::connect_with(&login_options(&pool, "epigraph_app", &app_password))
        .await
        .expect_err("a direct epigraph_app login is refused after 231");
    assert!(
        refused.to_string().contains("not permitted to log in"),
        "{refused}"
    );

    downgraded
        .execute("RESET SESSION AUTHORIZATION")
        .await
        .unwrap();
    drop(downgraded);
    api.close().await.unwrap();
    next.close().await.unwrap();
    wait_until_no_session_as(&pool, &login).await;
    pool.execute(format!("DROP ROLE {login}").as_str())
        .await
        .expect("drop the member login");
    disarm_app_login(&pool).await;
}
