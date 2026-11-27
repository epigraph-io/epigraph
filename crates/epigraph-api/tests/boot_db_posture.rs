#![cfg(feature = "db")]
//! `epigraph_api::boot::check_db_posture` (backlog 2cb020af): the
//! database-posture gates `bin/server.rs::main` runs, as one library call on a
//! bare pool, before any `AppState` exists.
//!
//! The positive case runs first: an implementation that refuses every
//! database passes every negative test. The negative cases each assert the
//! VARIANT and the named subject, so a refusal for the wrong reason (say, an
//! earlier gate tripping) does not pass.

use epigraph_api::boot::{check_db_posture, BootRefusal, DbPostureOptions};
use sqlx::PgPool;

const OPTS: DbPostureOptions<'static> = DbPostureOptions {
    unit: "boot-db-posture-test",
    allows_software_attestation: false,
};

/// A trigger of migration 070's first tier, spelled here rather than imported
/// (the constants are private to `state.rs`, and a test sharing its
/// subject's spelling cannot catch a typo in it).
const TRIGGER: &str = "claims_require_tenancy";

#[sqlx::test(migrations = "../../migrations")]
async fn a_database_at_head_passes(pool: PgPool) {
    check_db_posture(&pool, OPTS)
        .await
        .expect("a database migrated to head must pass every posture gate");
}

/// The item's acceptance case: a pool whose tenancy triggers are not armed is
/// refused, and the refusal names the trigger an operator has to re-enable.
#[sqlx::test(migrations = "../../migrations")]
async fn a_disabled_tenancy_trigger_is_refused(pool: PgPool) {
    sqlx::query(&format!(
        "ALTER TABLE public.claims DISABLE TRIGGER {TRIGGER}"
    ))
    .execute(&pool)
    .await
    .expect("disable the trigger");

    let refusal = check_db_posture(&pool, OPTS)
        .await
        .expect_err("a database with a disabled tenancy trigger must not serve");
    assert!(
        matches!(refusal, BootRefusal::TenancyTriggers(_)),
        "refused for the wrong reason: {refusal:?}"
    );
    let line = refusal.to_string();
    assert!(
        line.starts_with("refusing to serve: tenancy triggers are not armed")
            && line.contains(&format!("claims.{TRIGGER}=D")),
        "the refusal must say what is wrong and name the trigger; got: {line}"
    );
}

/// A dropped trigger is refused too (the `missing` half of the assertion).
#[sqlx::test(migrations = "../../migrations")]
async fn a_dropped_tenancy_trigger_is_refused(pool: PgPool) {
    sqlx::query(&format!("DROP TRIGGER {TRIGGER} ON public.claims"))
        .execute(&pool)
        .await
        .expect("drop the trigger");

    let refusal = check_db_posture(&pool, OPTS)
        .await
        .expect_err("a database with a dropped tenancy trigger must not serve");
    assert!(
        matches!(refusal, BootRefusal::TenancyTriggers(_)),
        "refused for the wrong reason: {refusal:?}"
    );
    assert!(
        refusal.to_string().contains(&format!("claims.{TRIGGER}")),
        "the refusal must name the trigger; got: {refusal}"
    );
}

/// The pgvector floor is the first gate: an unmigrated database (no `vector`
/// extension) is refused by it, before any tenancy read could fail instead.
#[sqlx::test(migrations = false)]
async fn a_database_without_pgvector_is_refused_first(pool: PgPool) {
    let refusal = check_db_posture(&pool, OPTS)
        .await
        .expect_err("an unmigrated database must not serve");
    assert!(
        matches!(refusal, BootRefusal::Pgvector(_)),
        "the pgvector floor must refuse first: {refusal:?}"
    );
    assert!(
        refusal.to_string().starts_with("refusing to serve: "),
        "{refusal}"
    );
}

/// The last gate: the RLS posture verdict. A half-applied FORCE (some
/// protected tables FORCEd, some not) is refused whatever role connects, so
/// it reaches the refusal on a test pool too. The precondition is checked
/// first: at head every protected table is FORCEd, so un-FORCEing one leaves
/// a strict subset.
#[sqlx::test(migrations = "../../migrations")]
async fn a_half_applied_force_is_refused_by_the_rls_gate(pool: PgPool) {
    let before = epigraph_api::state::AppState::probe_rls_posture_on(&pool)
        .await
        .expect("read the RLS posture");
    assert!(
        before.protected_count > 1 && before.forced_count == before.protected_count,
        "precondition: every protected table is FORCEd at head; got {} of {}",
        before.forced_count,
        before.protected_count
    );

    sqlx::query("ALTER TABLE public.claims NO FORCE ROW LEVEL SECURITY")
        .execute(&pool)
        .await
        .expect("un-FORCE one protected table");

    let refusal = check_db_posture(&pool, OPTS)
        .await
        .expect_err("a half-applied FORCE must not serve");
    assert!(
        matches!(refusal, BootRefusal::RlsPosture(_)),
        "refused for the wrong reason: {refusal:?}"
    );
    let line = refusal.to_string();
    assert!(
        line.starts_with("refusing to serve: RLS posture assertion failed")
            && line.contains("FORCE ROW LEVEL SECURITY is applied to"),
        "the refusal must say what is wrong; got: {line}"
    );
}
