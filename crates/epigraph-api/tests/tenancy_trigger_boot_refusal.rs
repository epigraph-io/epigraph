#![cfg(feature = "db")]
//! `AppState::assert_tenancy_triggers_armed` refuses a database whose
//! marker-gated stamping triggers have been removed, and boots one that is
//! legitimately behind.
//!
//! # Each tier is three cases, and the third is the point
//!
//! A required-set entry is easy to get wrong in the direction of refusing a
//! database that is legitimately behind — which is the outage the staged design
//! exists to prevent, not a safe default. So, per tier:
//!
//! 1. a database at head boots (over-refusal is silent and total);
//! 2. trigger dropped, the migration's marker function still present → refuses;
//! 3. trigger AND marker functions dropped → boots.
//!
//! Case 3 is what discriminates a marker-gated tier from an unconditional
//! entry. An unconditional entry in `TENANCY_TRIGGERS_070` passes cases 1 and 2
//! and fails case 3 — and a database that never ran the migration is exactly
//! the population that entry would have refused.
//!
//! The 089 and 173 tiers (the harvester tables' stamping triggers, finding
//! `F-089-G`) and their cases left with those tables in migration 354. A
//! database below 354 still carries them, and the binary boots there too
//! ([`a_database_below_354_boots`]): the binary deploys before the migration.

use epigraph_api::{ApiConfig, AppState};
use sqlx::migrate::Migrator;
use sqlx::PgPool;
use std::borrow::Cow;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

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

/// Deploy order: this binary goes out BEFORE migration 354 drops the harvester
/// tables, so it must boot on a database that still has them and their
/// stamping triggers.
#[sqlx::test(migrations = false)]
async fn a_database_below_354_boots(pool: PgPool) {
    let below = Migrator {
        migrations: Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < 354)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    below.run(&pool).await.expect("migrate below 354");
    let still_there: bool =
        sqlx::query_scalar("SELECT to_regclass('public.harvester_fragments') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .expect("probe");
    assert!(still_there, "CALIBRATION: below 354 the tables exist");
    let state = AppState::with_db(pool, ApiConfig::default());
    assert!(
        state.assert_tenancy_triggers_armed().await.is_ok(),
        "a database below 354 must boot: the binary deploys before the migration"
    );
}

// ---------------------------------------------------------------------------
// Migration 210's tier: the Atlas map tables' root triggers and the three
// staleness triggers
// ---------------------------------------------------------------------------
//
// A dropped or disabled staleness trigger errors nowhere: a row leaves a map's
// readable set, no epoch moves, and a stored map keeps reporting itself
// current. 210 has three functions, and any one present means 210 ran.

/// 210's staleness triggers. Spelled here rather than imported: the constants
/// under test are private to `state.rs`, and a test that shares its subject's
/// spelling cannot detect a typo in it.
const STALE_TRIGGERS_210: &[(&str, &str)] = &[
    ("claims", "claims_atlas_map_stale"),
    ("edges", "edges_atlas_map_stale"),
    ("evidence", "evidence_atlas_map_stale"),
];

/// Dropped 210 staleness triggers are refused, each one named, even with one
/// of 210's three functions dropped alongside.
#[sqlx::test(migrations = "../../migrations")]
async fn dropped_210_staleness_triggers_are_refused(pool: PgPool) {
    for (rel, tg) in STALE_TRIGGERS_210 {
        sqlx::query(&format!("DROP TRIGGER {tg} ON public.{rel}"))
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("drop 210 trigger {tg}: {e}"));
    }
    sqlx::query("DROP FUNCTION public.epigraph_atlas_map_stale()")
        .execute(&pool)
        .await
        .expect("drop one 210 function");

    let state = AppState::with_db(pool, ApiConfig::default());
    let msg = state
        .assert_tenancy_triggers_armed()
        .await
        .expect_err("a database at 210 without its staleness triggers must not serve")
        .to_string();
    for (rel, tg) in STALE_TRIGGERS_210 {
        assert!(
            msg.contains(&format!("{rel}.{tg}")),
            "the refusal must name {rel}.{tg}; got: {msg}"
        );
    }
}

/// A disabled staleness trigger is refused too.
#[sqlx::test(migrations = "../../migrations")]
async fn a_disabled_210_staleness_trigger_is_refused(pool: PgPool) {
    sqlx::query("ALTER TABLE public.claims DISABLE TRIGGER claims_atlas_map_stale")
        .execute(&pool)
        .await
        .expect("disable");
    let state = AppState::with_db(pool, ApiConfig::default());
    let msg = state
        .assert_tenancy_triggers_armed()
        .await
        .expect_err("a disabled staleness trigger must not serve")
        .to_string();
    assert!(
        msg.contains("claims.claims_atlas_map_stale"),
        "the refusal must name the disabled trigger; got: {msg}"
    );
}

/// The discriminator: a database with 210 undone by its documented runbook is
/// behind, not broken, and boots.
#[sqlx::test(migrations = "../../migrations")]
async fn a_database_with_210_undone_still_boots(pool: PgPool) {
    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/210-undo.sql"),
    )
    .expect("210-undo.sql");
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("run 210's undo");
    let state = AppState::with_db(pool, ApiConfig::default());
    assert!(
        state.assert_tenancy_triggers_armed().await.is_ok(),
        "210's triggers must be required only where one of 210's functions says 210 ran"
    );
}

// ---------------------------------------------------------------------------
// Migration 240's tier: a workflow's runs take, and follow, its tenancy
// ---------------------------------------------------------------------------
//
// A dropped follow trigger errors nowhere: a workflow is narrowed and its
// recorded runs stay readable to its old readers. 240 has three functions,
// and any one present means 240 ran.

/// 240's triggers, spelled here for the same reason as [`STALE_TRIGGERS_210`].
const TRIGGERS_240: &[(&str, &str)] = &[
    (
        "behavioral_executions",
        "behavioral_executions_inherit_tenancy",
    ),
    (
        "workflows",
        "workflows_behavioral_executions_inherit_tenancy",
    ),
    ("claims", "claims_behavioral_executions_inherit_tenancy"),
];

/// Dropped 240 triggers are refused, each one named, even with one of 240's
/// three functions dropped alongside.
#[sqlx::test(migrations = "../../migrations")]
async fn dropped_240_triggers_are_refused(pool: PgPool) {
    for (rel, tg) in TRIGGERS_240 {
        sqlx::query(&format!("DROP TRIGGER {tg} ON public.{rel}"))
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("drop 240 trigger {tg}: {e}"));
    }
    sqlx::query("DROP FUNCTION public.epigraph_claim_behavioral_executions_follow()")
        .execute(&pool)
        .await
        .expect("drop one 240 function");

    let state = AppState::with_db(pool, ApiConfig::default());
    let msg = state
        .assert_tenancy_triggers_armed()
        .await
        .expect_err("a database at 240 without its tenancy triggers must not serve")
        .to_string();
    for (rel, tg) in TRIGGERS_240 {
        assert!(
            msg.contains(&format!("{rel}.{tg}")),
            "the refusal must name {rel}.{tg}; got: {msg}"
        );
    }
}

/// The discriminator: a database with 240 undone by its documented runbook is
/// behind, not broken, and boots.
#[sqlx::test(migrations = "../../migrations")]
async fn a_database_with_240_undone_still_boots(pool: PgPool) {
    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/240-undo.sql"),
    )
    .expect("240-undo.sql");
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("run 240's undo");
    let state = AppState::with_db(pool, ApiConfig::default());
    assert!(
        state.assert_tenancy_triggers_armed().await.is_ok(),
        "240's triggers must be required only where one of 240's functions says 240 ran"
    );
}
