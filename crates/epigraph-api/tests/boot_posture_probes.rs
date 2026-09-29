//! The two boot posture probes, EXECUTED: `AppState::probe_rls_posture` and
//! `AppState::warn_on_privileged_connection`.
//!
//! # Why this file exists
//!
//! Both statements are composed at runtime around
//! `epigraph_db::repos::seed_posture::SESSION_IS_SEED_SQL` (migration 113's
//! seed question), and the only caller of either is `bin/server.rs` at boot.
//! `tenancy_required.rs::the_boot_probe_asks_the_seed_question_the_triggers_ask`
//! tests the EXPRESSION; nothing ran the two statements that embed it: their
//! column order, their tuple decode, their `$1` bind.
//!
//! That gap is dangerous in one specific direction. `assert_rls_posture`
//! treats a failure to READ the posture as a logged error, not a refusal (its
//! doc says why), so a statement that no longer parses or decodes would
//! silently switch off the armed boot refusals (superuser, BYPASSRLS, seed
//! member, visible canary) and nothing would be red. This pins that both
//! statements execute on a database at head and that the seed column is the
//! answer the triggers give.
//!
//! # What it does not pin
//!
//! A swap of two columns of the SAME type whose values coincide on the harness
//! (the CI harness is a superuser with BYPASSRLS that CI grants
//! `epigraph_seed`, so all three booleans are true there) decodes cleanly and
//! is not caught by value. A swap across types (a boolean with a count, the
//! user name with anything) fails the decode and is caught.

use epigraph_api::{ApiConfig, AppState};
use sqlx::PgPool;

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
         question the *_require_tenancy triggers ask since migration 113"
    );
    assert!(
        posture.protected_count > 0 && posture.forced_count == posture.protected_count,
        "at head every protected relation is FORCEd: {posture:?}"
    );
}
