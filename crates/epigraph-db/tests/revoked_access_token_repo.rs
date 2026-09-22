//! `RevokedAccessTokenRepository`: the shared access-token revocation list.
//!
//! The table is created by a PENDING migration whose body lives in
//! `tests/fixtures/pending_migration_revoked_access_tokens.sql` (see that
//! file's header for why it is not in `migrations/`). Every test here applies
//! it on top of the real migration set, exactly as a deploy would once it is
//! promoted.
//!
//! The app-role tests run on `viewer_fixture::downgraded_pool`, NOT on the
//! `epigraph` superuser the harness connects as: that role owns the table and
//! bypasses row security, so a posture assertion made on it passes vacuously.

mod viewer_fixture;
use viewer_fixture as fixture;

use chrono::{Duration, Utc};
use epigraph_db::{DbError, RevocationStoreStatus, RevokedAccessTokenRepository};
use sqlx::PgPool;
use uuid::Uuid;

const PENDING_DDL: &str = include_str!("fixtures/pending_migration_revoked_access_tokens.sql");

async fn apply_pending_ddl(pool: &PgPool) {
    sqlx::raw_sql(PENDING_DDL)
        .execute(pool)
        .await
        .expect("apply the pending revoked_access_tokens DDL");
}

#[sqlx::test(migrations = "../../migrations")]
async fn probe_reports_absent_before_the_table_exists_and_ready_after(pool: PgPool) {
    assert_eq!(
        RevokedAccessTokenRepository::probe(&pool)
            .await
            .expect("probe on a schema without the table must not error"),
        RevocationStoreStatus::Absent,
        "no table must read as Absent (log and keep the old behaviour), not as an error that \
         would stop every pre-migration deploy from booting"
    );

    apply_pending_ddl(&pool).await;
    // Idempotent: promoting the body to a real migration leaves both in force
    // for a while, and the second application must be a no-op.
    apply_pending_ddl(&pool).await;

    assert_eq!(
        RevokedAccessTokenRepository::probe(&pool)
            .await
            .expect("probe"),
        RevocationStoreStatus::Ready
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_jti_is_reported_and_an_unrevoked_one_is_not(pool: PgPool) {
    apply_pending_ddl(&pool).await;
    let revoked = Uuid::new_v4();
    let other = Uuid::new_v4();
    let exp = Utc::now() + Duration::minutes(15);

    assert!(!RevokedAccessTokenRepository::is_revoked(&pool, revoked)
        .await
        .unwrap());

    RevokedAccessTokenRepository::revoke(&pool, revoked, exp)
        .await
        .expect("revoke");
    // A second revocation of the same token is a no-op, not a conflict error.
    RevokedAccessTokenRepository::revoke(&pool, revoked, exp)
        .await
        .expect("revoke is idempotent");

    assert!(RevokedAccessTokenRepository::is_revoked(&pool, revoked)
        .await
        .unwrap());
    assert!(
        !RevokedAccessTokenRepository::is_revoked(&pool, other)
            .await
            .unwrap(),
        "revoking one jti must not revoke another"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn prune_waits_out_the_grace_window_and_lookup_ignores_expiry(pool: PgPool) {
    apply_pending_ddl(&pool).await;
    let just_expired = Uuid::new_v4();
    let long_expired = Uuid::new_v4();
    let live = Uuid::new_v4();

    RevokedAccessTokenRepository::revoke(&pool, just_expired, Utc::now() - Duration::seconds(10))
        .await
        .unwrap();
    RevokedAccessTokenRepository::revoke(&pool, long_expired, Utc::now() - Duration::hours(2))
        .await
        .unwrap();
    RevokedAccessTokenRepository::revoke(&pool, live, Utc::now() + Duration::hours(1))
        .await
        .unwrap();

    // A row past its token's exp still answers "revoked" until it is pruned:
    // the lookup must not depend on the database clock agreeing with the
    // validating process's clock.
    assert!(
        RevokedAccessTokenRepository::is_revoked(&pool, just_expired)
            .await
            .unwrap()
    );

    let pruned = RevokedAccessTokenRepository::prune_expired(&pool)
        .await
        .expect("prune");
    assert_eq!(
        pruned, 1,
        "only the row expired beyond the grace window goes"
    );

    assert!(
        !RevokedAccessTokenRepository::is_revoked(&pool, long_expired)
            .await
            .unwrap()
    );
    assert!(
        RevokedAccessTokenRepository::is_revoked(&pool, just_expired)
            .await
            .unwrap(),
        "a row inside the {}s grace window must survive the prune",
        epigraph_db::repos::revoked_access_token::PRUNE_GRACE_SECONDS
    );
    assert!(RevokedAccessTokenRepository::is_revoked(&pool, live)
        .await
        .unwrap());
}

/// The API and MCP pools run as `epigraph_app` once plan §9.2 step 11d
/// repoints `DATABASE_URL`, so every operation the two processes perform is
/// exercised on that role here — probe included, since the probe is what
/// decides whether revocation is enforced at all.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_can_probe_revoke_look_up_and_prune(pool: PgPool) {
    apply_pending_ddl(&pool).await;
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;

    // CALIBRATION: the pool really is the app role, so the assertions below
    // are not the owner's.
    let who: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&app)
        .await
        .unwrap();
    assert_eq!(who, "epigraph_app");

    assert_eq!(
        RevokedAccessTokenRepository::probe(&app)
            .await
            .expect("probe as app"),
        RevocationStoreStatus::Ready
    );

    let jti = Uuid::new_v4();
    RevokedAccessTokenRepository::revoke(&app, jti, Utc::now() + Duration::minutes(5))
        .await
        .expect("revoke as app");
    assert!(RevokedAccessTokenRepository::is_revoked(&app, jti)
        .await
        .expect("look up as app"));

    // A revocation written by one process is seen by another: the owner pool
    // stands in for the second process here.
    assert!(RevokedAccessTokenRepository::is_revoked(&pool, jti)
        .await
        .unwrap());

    RevokedAccessTokenRepository::prune_expired(&app)
        .await
        .expect("prune as app");
}

/// Row security on this table is the fail-OPEN trap: with ENABLE and no
/// policy, a non-owner's lookup of a revoked jti answers `false`. The probe
/// must refuse that posture rather than report the store ready.
#[sqlx::test(migrations = "../../migrations")]
async fn probe_refuses_a_table_with_row_security_enabled(pool: PgPool) {
    apply_pending_ddl(&pool).await;
    let jti = Uuid::new_v4();
    RevokedAccessTokenRepository::revoke(&pool, jti, Utc::now() + Duration::minutes(5))
        .await
        .unwrap();

    sqlx::query("ALTER TABLE public.revoked_access_tokens ENABLE ROW LEVEL SECURITY")
        .execute(&pool)
        .await
        .unwrap();

    // CALIBRATION: the hazard is real. As the app role the revoked jti is
    // invisible, so an unguarded check would admit the token.
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    assert!(
        !RevokedAccessTokenRepository::is_revoked(&app, jti)
            .await
            .expect("lookup under RLS returns rows, not an error"),
        "under ENABLE with no policy the app role must see nothing — if it does see the row, \
         this calibration no longer demonstrates the trap the probe guards"
    );

    for p in [&pool, &app] {
        match RevokedAccessTokenRepository::probe(p).await {
            Err(DbError::InvalidData { reason }) => assert!(
                reason.contains("row level security"),
                "unexpected refusal text: {reason}"
            ),
            other => panic!("probe must refuse a row-secured table, got {other:?}"),
        }
    }
}
