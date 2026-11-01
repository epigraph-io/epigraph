//! `prune_recall_events` driven as a real process on real LOGIN roles
//! (migration 186).
//!
//! The retention job connects through `epigraph_cli::MaintenancePool`, which
//! refuses any session that does not satisfy `epigraph_bypass()`: on an
//! application connection `recall_events` (FORCE row security) would match
//! zero rows and the job would exit 0 having enforced nothing. Its two DELETEs
//! (`RecallEventRepository::prune_older_than` on `recall_events`,
//! `RecallEventRepository::prune_telemetry_events` on `events`) therefore run
//! as a non-superuser login in `epigraph_maintenance`. Migration 070 gave that
//! role SELECT, INSERT and UPDATE on every table and no DELETE, so before 186
//! the dry run (a count) succeeded and the real run stopped at its first
//! statement with `permission denied for table recall_events`.
//!
//! What is pinned:
//!
//! * a maintenance login deletes exactly the expired `recall_events` row and
//!   the expired TELEMETRY `events` row; the fresh rows and the expired
//!   provenance event (`claim.created`, not in `PRUNABLE_EVENT_TYPES`) stay;
//! * an application login is refused by the binary before it deletes
//!   anything, and the application role's own DELETE on `recall_events`
//!   (which it holds as a grant) matches no row under FORCE row security.
//!   Only `recall_events` is asserted for that: `events` has no row security,
//!   and the application role's DELETE there is a separate, allowlisted
//!   posture (`app_role_table_lockdown.rs`, `OPERATIONAL`).
//!
//! The logins are created per test (roles are cluster-global, so each name is
//! unique) and dropped at the end; neither is a superuser. The superuser
//! fixture pool only seeds rows and reads results.
//!
//! # Verified to fail
//!
//! Without migration 186 the first test fails: the binary exits 1 with
//! `permission denied for table recall_events` and every seeded row is still
//! present.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::process::Command;

use epigraph_db::RecallEventRepository;
use sqlx::PgPool;
use uuid::Uuid;

const PRUNE: &str = env!("CARGO_BIN_EXE_prune_recall_events");
const WORLD: Uuid = Uuid::nil();
const RETENTION_DAYS: &str = "90";

async fn create_login(pool: &PgPool, parent: &str) -> (String, String) {
    let role = format!("m186_{}_{}", parent, Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}' IN ROLE {parent}"
    ))
    .execute(pool)
    .await
    .expect("create the login");
    let base = viewer_fixture::database_url_for(pool).await;
    let scheme_end = base.find("://").expect("a scheme") + 3;
    let host_path = &base[base.find('@').expect("credentials in the DSN") + 1..];
    let url = format!("{}{role}:{password}@{host_path}", &base[..scheme_end]);
    (role, url)
}

async fn drop_login(pool: &PgPool, role: &str) {
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(pool)
        .await;
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(database_url: &str, maintenance_url: Option<&str>) -> Run {
    let mut cmd = Command::new(PRUNE);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", database_url)
        .env("RUST_LOG", "warn")
        .args(["--retention-days", RETENTION_DAYS])
        .current_dir(std::env::temp_dir());
    if let Some(m) = maintenance_url {
        cmd.env("MAINTENANCE_DATABASE_URL", m);
    }
    let out = cmd.output().expect("run prune_recall_events");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// One row on each side of every line the job draws.
struct Seeded {
    recall_expired: Uuid,
    recall_fresh: Uuid,
    telemetry_expired: Uuid,
    telemetry_fresh: Uuid,
    provenance_expired: Uuid,
}

async fn seed_recall(pool: &PgPool, age_days: i32) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO recall_events (tool, query_text, owner_group_id, visibility, created_at) \
         VALUES ('recall', 'm186', $1, 'public', now() - make_interval(days => $2)) \
         RETURNING id",
    )
    .bind(WORLD)
    .bind(age_days)
    .fetch_one(pool)
    .await
    .expect("seed recall_events")
}

async fn seed_event(pool: &PgPool, event_type: &str, age_days: i32) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO events (event_type, payload, graph_version, created_at) \
         VALUES ($1, '{}'::jsonb, 0, now() - make_interval(days => $2)) RETURNING id",
    )
    .bind(event_type)
    .bind(age_days)
    .fetch_one(pool)
    .await
    .expect("seed events")
}

async fn seed(pool: &PgPool) -> Seeded {
    Seeded {
        recall_expired: seed_recall(pool, 200).await,
        recall_fresh: seed_recall(pool, 1).await,
        telemetry_expired: seed_event(pool, "tool.invoked", 200).await,
        telemetry_fresh: seed_event(pool, "tool.invoked", 1).await,
        provenance_expired: seed_event(pool, "claim.created", 200).await,
    }
}

async fn present(pool: &PgPool, table: &str, id: Uuid) -> bool {
    sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM public.{table} WHERE id = $1)"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read {table}: {e}"))
}

async fn assert_all_present(pool: &PgPool, s: &Seeded, why: &str) {
    for (table, id, what) in [
        ("recall_events", s.recall_expired, "the expired recall row"),
        ("recall_events", s.recall_fresh, "the fresh recall row"),
        ("events", s.telemetry_expired, "the expired telemetry event"),
        ("events", s.telemetry_fresh, "the fresh telemetry event"),
        (
            "events",
            s.provenance_expired,
            "the expired provenance event",
        ),
    ] {
        assert!(present(pool, table, id).await, "{why}: {what} is gone");
    }
}

/// The retention pass on a maintenance login removes what is past the window
/// and nothing else. Before 186 the binary stopped at its first DELETE.
#[sqlx::test(migrations = "../../migrations")]
async fn a_maintenance_login_prunes_expired_recall_and_telemetry_rows(pool: PgPool) {
    let s = seed(&pool).await;
    let (maint_role, maint_url) = create_login(&pool, "epigraph_maintenance").await;
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;

    // The deployed shape: DATABASE_URL is the application login and the
    // maintenance login is supplied separately.
    let r = run(&app_url, Some(&maint_url));
    let outcome = (
        r.code,
        present(&pool, "recall_events", s.recall_expired).await,
        present(&pool, "recall_events", s.recall_fresh).await,
        present(&pool, "events", s.telemetry_expired).await,
        present(&pool, "events", s.telemetry_fresh).await,
        present(&pool, "events", s.provenance_expired).await,
    );
    drop_login(&pool, &maint_role).await;
    drop_login(&pool, &app_role).await;

    assert_eq!(
        r.code,
        Some(0),
        "the retention pass failed on a maintenance login\nstdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    assert!(
        r.stdout.contains(&format!(
            "deleted 1 recall_events + 1 telemetry events older than {RETENTION_DAYS} days"
        )),
        "the pass deleted something other than the one expired row of each kind: {}",
        r.stdout
    );
    assert_eq!(
        outcome,
        (Some(0), false, true, false, true, true),
        "(exit, expired recall, fresh recall, expired telemetry, fresh telemetry, expired \
         provenance): only the two expired retention rows may go"
    );
}

/// The application role prunes nothing: the binary refuses its login before
/// any DELETE, and the role's own DELETE on `recall_events` (a grant it holds)
/// matches no row under FORCE row security, which is why the job needs the
/// maintenance login at all.
#[sqlx::test(migrations = "../../migrations")]
async fn the_application_role_prunes_no_recall_row(pool: PgPool) {
    let (app_may_delete, forced): (bool, bool) = sqlx::query_as(
        "SELECT has_table_privilege('epigraph_app', 'public.recall_events', 'DELETE'), \
                c.relforcerowsecurity \
           FROM pg_class c WHERE c.oid = 'public.recall_events'::regclass",
    )
    .fetch_one(&pool)
    .await
    .expect("read recall_events' posture");
    assert!(
        app_may_delete,
        "CALIBRATION: epigraph_app lacks the DELETE grant on recall_events, so the zero below \
         would be the grant and not row security"
    );
    assert!(
        forced,
        "CALIBRATION: recall_events is not FORCE row security"
    );

    let s = seed(&pool).await;
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;

    let refused = run(&app_url, None);
    let after_refusal_ok = (
        present(&pool, "recall_events", s.recall_expired).await,
        present(&pool, "events", s.telemetry_expired).await,
    );

    let app_pool = PgPool::connect(&app_url).await.expect("app login pool");
    let deleted = RecallEventRepository::prune_older_than(&app_pool, 90).await;
    app_pool.close().await;
    drop_login(&pool, &app_role).await;

    assert_ne!(
        refused.code,
        Some(0),
        "prune_recall_events ran on an application login\nstdout: {}\nstderr: {}",
        refused.stdout,
        refused.stderr
    );
    assert!(
        refused.stderr.contains("epigraph_bypass()"),
        "the application login was not refused by the maintenance check: {}",
        refused.stderr
    );
    assert_eq!(
        after_refusal_ok,
        (true, true),
        "a refused run deleted a row"
    );
    assert_eq!(
        deleted.expect("the application role's DELETE is a grant it holds"),
        0,
        "the application role deleted recall_events rows it does not own"
    );
    assert_all_present(&pool, &s, "after the application role's attempts").await;
}
