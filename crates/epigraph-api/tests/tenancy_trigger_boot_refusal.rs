#![cfg(feature = "db")]
//! `AppState::assert_tenancy_triggers_armed` refuses a database whose migration
//! 089 stamping trigger has been removed — finding `F-089-G`.
//!
//! Until now the boot assertion was asymmetric: a *disabled* 089 trigger was
//! refused (the `disabled` half of the check is built from the LIKE-matched
//! catalog rows, which its name matches), while a *dropped* one was not,
//! because 089's trigger appeared in no required list. Absence therefore
//! reverted to the pre-089 status quo with nothing said about it.
//!
//! # These three cases are one test each, and the third is the point
//!
//! A required-set entry is easy to get wrong in the direction of refusing a
//! database that is legitimately behind — which is the outage the staged design
//! exists to prevent, not a safe default. So:
//!
//! 1. a database at head boots (over-refusal is silent and total);
//! 2. trigger dropped, 089's function still present → refuses;
//! 3. trigger AND function dropped → boots.
//!
//! Case 3 is what discriminates a marker-gated tier from an unconditional
//! entry. An unconditional entry in `TENANCY_TRIGGERS_070` passes cases 1 and 2
//! and fails case 3 — and a database that never ran 089 is exactly the
//! population that entry would have refused.

use epigraph_api::{ApiConfig, AppState};
use sqlx::PgPool;

/// 089's trigger, and the function it is gated on. Spelled here rather than
/// imported: the constants under test are private to `state.rs`, and a test
/// that shares its subject's spelling cannot detect a typo in it.
const TRIGGER: &str = "harvester_claim_provenance_fragment_inherit_tenancy";
const MARKER_FN: &str = "epigraph_inherit_fragment_tenancy_stmt";

async fn drop_trigger(pool: &PgPool) {
    sqlx::query(&format!(
        "DROP TRIGGER {TRIGGER} ON public.harvester_claim_provenance"
    ))
    .execute(pool)
    .await
    .expect("drop 089 trigger");
}

async fn drop_marker_fn(pool: &PgPool) {
    sqlx::query(&format!("DROP FUNCTION public.{MARKER_FN}()"))
        .execute(pool)
        .await
        .expect("drop 089 marker function");
}

/// Positive direction. A fix that refuses every database passes any negative
/// test, so this one runs first.
#[sqlx::test(migrations = "../../migrations")]
async fn a_database_at_head_boots(pool: PgPool) {
    let state = AppState::with_db(pool, ApiConfig::default());
    assert!(
        state.assert_tenancy_triggers_armed().await.is_ok(),
        "a database migrated to head must boot"
    );
}

/// The finding. Assert the EFFECT — the refusal names the missing trigger —
/// rather than merely that an error came back.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dropped_089_trigger_is_refused(pool: PgPool) {
    drop_trigger(&pool).await;

    let state = AppState::with_db(pool, ApiConfig::default());
    let err = state
        .assert_tenancy_triggers_armed()
        .await
        .expect_err("a database at 089 with the stamping trigger removed must not serve");
    let msg = err.to_string();
    assert!(
        msg.contains(TRIGGER),
        "the refusal must name the trigger an operator has to restore; got: {msg}"
    );
}

/// The discriminator. A database that never ran 089 — or one reverted by 089's
/// own documented reversal, which drops the trigger and then the function — is
/// behind, not broken, and must still boot.
#[sqlx::test(migrations = "../../migrations")]
async fn a_database_without_089_at_all_still_boots(pool: PgPool) {
    drop_trigger(&pool).await;
    drop_marker_fn(&pool).await;

    let state = AppState::with_db(pool, ApiConfig::default());
    assert!(
        state.assert_tenancy_triggers_armed().await.is_ok(),
        "089's trigger must be required only where 089's marker says 089 ran; requiring it \
         unconditionally refuses every database that has not reached 089 yet, which is the \
         staged-deploy outage the tier split exists to prevent"
    );
}

// ===========================================================================
// Migration 173's tier: the harvester neighbours' stamping triggers
// ===========================================================================
//
// The same three cases for 173. Its triggers keep `harvester_sources` and
// `harvester_audit_reports` no more readable than their fragments; losing the
// follow trigger in particular re-opens the audit of a narrowed fragment
// without any error. 173 installs two functions, and either one present means
// 173 ran: a revert that drops one trigger with its own function still leaves
// the other behind.

/// 173's triggers as `(relation, trigger)`, spelled here for the same reason as
/// [`TRIGGER`].
const TRIGGERS_173: &[(&str, &str)] = &[
    ("harvester_sources", "harvester_sources_require_tenancy"),
    (
        "harvester_audit_reports",
        "harvester_audit_reports_inherit_tenancy",
    ),
    (
        "harvester_fragments",
        "harvester_fragments_audit_reports_inherit_tenancy",
    ),
];
const STAMP_FN_173: &str = "epigraph_audit_report_inherit_tenancy";
const FOLLOW_FN_173: &str = "epigraph_fragment_audit_reports_follow";

async fn drop_173_triggers(pool: &PgPool) {
    for (rel, tg) in TRIGGERS_173 {
        sqlx::query(&format!("DROP TRIGGER {tg} ON public.{rel}"))
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("drop 173 trigger {tg}: {e}"));
    }
}

async fn drop_173_fn(pool: &PgPool, name: &str) {
    sqlx::query(&format!("DROP FUNCTION public.{name}()"))
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("drop 173 function {name}: {e}"));
}

/// The finding: dropped 173 triggers are refused, each one named. The follow
/// function is dropped too, so the refusal also holds when only one of 173's
/// two functions is left to say that 173 ran.
#[sqlx::test(migrations = "../../migrations")]
async fn dropped_173_triggers_are_refused(pool: PgPool) {
    drop_173_triggers(&pool).await;
    drop_173_fn(&pool, FOLLOW_FN_173).await;

    let state = AppState::with_db(pool, ApiConfig::default());
    let err = state
        .assert_tenancy_triggers_armed()
        .await
        .expect_err("a database at 173 with its stamping triggers removed must not serve");
    let msg = err.to_string();
    for (rel, tg) in TRIGGERS_173 {
        assert!(
            msg.contains(&format!("{rel}.{tg}")),
            "the refusal must name {rel}.{tg}; got: {msg}"
        );
    }
}

/// The discriminator: a database without 173 (both functions gone, as 173's
/// documented undo leaves it) is behind, not broken, and boots.
#[sqlx::test(migrations = "../../migrations")]
async fn a_database_without_173_at_all_still_boots(pool: PgPool) {
    drop_173_triggers(&pool).await;
    drop_173_fn(&pool, FOLLOW_FN_173).await;
    drop_173_fn(&pool, STAMP_FN_173).await;

    let state = AppState::with_db(pool, ApiConfig::default());
    assert!(
        state.assert_tenancy_triggers_armed().await.is_ok(),
        "173's triggers must be required only where one of 173's functions says 173 ran"
    );
}
