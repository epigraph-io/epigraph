//! Migration 216 (backlog 0512ca33) on the API side: the two boot posture
//! probes, EXECUTED, and `epigraph-migrate`'s test-harness seed grant.
//!
//! # The probes
//!
//! `AppState::probe_rls_posture` and `AppState::warn_on_privileged_connection`
//! are composed at runtime around
//! `epigraph_db::repos::seed_posture::SESSION_IS_SEED_SQL`, and the only
//! caller of either is `bin/server.rs` at boot.
//! `seed_escape_explicit_membership.rs::the_boot_probe_asks_the_seed_question_the_triggers_ask`
//! tests the EXPRESSION; this runs the two statements that embed it (column
//! order, tuple decode, the `$1` bind). That matters in one direction:
//! `assert_rls_posture` treats a failure to READ the posture as a logged
//! error, not a refusal, so a statement that no longer parsed would silently
//! switch off the armed boot refusals.
//!
//! What it does not pin: a swap of two same-typed columns whose values
//! coincide on the harness (a superuser with BYPASSRLS that holds the seed
//! grant, so all three booleans are true) decodes cleanly. A swap across
//! types fails the decode and is caught.
//!
//! # The grant
//!
//! Since 216 the superuser harness needs an explicit grant of
//! `epigraph_seed`; `epigraph-migrate` issues it when
//! `EPIGRAPH_MIGRATE_GRANT_SEED_TO_SELF` is set. The test runs the grant as a
//! throwaway superuser created inside a transaction that is rolled back, so
//! the cluster is left exactly as it was (roles and grants are cluster-wide).

use epigraph_api::{ApiConfig, AppState};
use sqlx::{Executor, PgPool};

#[sqlx::test(migrations = "../../migrations")]
async fn the_boot_posture_probes_execute_and_report_the_trigger_seed_answer(pool: PgPool) {
    let state = AppState::with_db(pool.clone(), ApiConfig::default());

    let posture = state.probe_rls_posture().await.expect(
        "probe_rls_posture must execute at head. A failure here at boot is logged, not \
         refused, so a malformed statement would silently disarm every armed boot refusal",
    );
    state
        .warn_on_privileged_connection()
        .await
        .expect("warn_on_privileged_connection must execute at head");

    let (current_user, is_super, bypass, is_seed): (String, bool, bool, bool) = sqlx::query_as(
        "SELECT current_user::text, \
                (SELECT rolsuper FROM pg_roles WHERE rolname = session_user), \
                (SELECT rolbypassrls FROM pg_roles WHERE rolname = session_user), \
                public.epigraph_session_is_seed()",
    )
    .fetch_one(&pool)
    .await
    .expect("read the session's own facts");

    assert_eq!(posture.current_user, current_user);
    assert_eq!(posture.is_superuser, is_super);
    assert_eq!(posture.has_bypassrls, bypass);
    assert_eq!(
        posture.is_seed_member, is_seed,
        "the boot probe's seed column must be what epigraph_session_is_seed() says, the \
         question the *_require_tenancy triggers ask since migration 216"
    );
    assert!(
        posture.protected_count > 0 && posture.forced_count == posture.protected_count,
        "at head every protected relation is FORCEd: {posture:?}"
    );
}

/// A superuser with no grant is not a seed (216); after
/// `grant_seed_to_session_user` it is, the grant names that role, and a
/// second call is a harmless no-op.
#[sqlx::test(migrations = "../../migrations")]
async fn the_harness_seed_grant_makes_the_migrating_role_an_explicit_seed(pool: PgPool) {
    const ROLE: &str = "seedg_harness_superuser";
    let mut tx = pool.begin().await.expect("begin");
    tx.execute(format!("CREATE ROLE {ROLE} NOLOGIN SUPERUSER").as_str())
        .await
        .unwrap_or_else(|e| {
            panic!(
                "CREATE ROLE {ROLE}: {e}. If it already exists it was committed by something \
                 else: DROP ROLE {ROLE}"
            )
        });
    tx.execute(format!("SET SESSION AUTHORIZATION {ROLE}").as_str())
        .await
        .expect("become the throwaway superuser");

    let before: bool = sqlx::query_scalar("SELECT public.epigraph_session_is_seed()")
        .fetch_one(&mut *tx)
        .await
        .expect("seed probe before");
    assert!(
        !before,
        "precondition: a superuser with no grant is not a seed since migration 216"
    );

    let who = epigraph_api::migrate::grant_seed_to_session_user(&mut tx)
        .await
        .expect("the grant must succeed for a superuser");
    assert_eq!(who.as_deref(), Some(ROLE));
    let after: bool = sqlx::query_scalar("SELECT public.epigraph_session_is_seed()")
        .fetch_one(&mut *tx)
        .await
        .expect("seed probe after");
    assert!(
        after,
        "after the grant {ROLE} must take the seed escape hatch"
    );

    let again = epigraph_api::migrate::grant_seed_to_session_user(&mut tx)
        .await
        .expect("granting a role already held is a NOTICE, not an error");
    assert_eq!(again.as_deref(), Some(ROLE));

    tx.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    tx.rollback()
        .await
        .expect("rollback removes the role and its grant");
}
