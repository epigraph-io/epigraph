pub mod embedding_restore;
pub mod errors;
pub mod extractors;
pub mod metrics;
pub mod middleware;
#[cfg(feature = "db")]
pub mod migrate;
pub mod oauth;
pub mod openapi;
#[cfg(feature = "db")]
pub mod query_parser;
pub mod routes;
pub mod security;
pub mod services;
pub mod state;
pub mod tenancy_disclosure;
#[cfg(feature = "db")]
pub mod tenancy_gauge;
pub mod tls;
pub mod webhook_bridge;

pub use errors::ApiError;
pub use routes::create_router;
pub use security::{
    AgentKey, AgentRateLimiter, KeyError, KeyRevocationRequest, KeyRotationRequest, KeyStatus,
    KeyType, RateLimitConfig, RateLimitError, SecurityAuditLog, SecurityEvent, SecurityEventFilter,
};
pub use services::{SubmissionService, ValidationService};
pub use state::{
    ApiConfig, AppState, ClaimStore, SharedAuditLog, SharedChallengeService,
    SharedEmbeddingService, SharedEventBus,
};

/// Test-only re-export of the module-level event store.
///
/// Returns a clone of the `Arc<EventStore>` singleton so integration tests can
/// drain or inspect events without going through the HTTP API.
#[doc(hidden)]
pub fn _test_event_store() -> std::sync::Arc<crate::routes::events::EventStore> {
    crate::routes::events::global_event_store().clone()
}

/// Apply all pending SQL migrations from the workspace `migrations/` directory,
/// then verify the database reached this binary's embedded head.
///
/// Migrations are embedded into the binary at compile time by `sqlx::migrate!()`,
/// so a binary knows only the migrations that existed when it was built. The
/// schema-head checks that make that safe — and why `set_ignore_missing(true)`
/// is kept — live in [`migrate`] (issue #492): a database AHEAD of the binary
/// is refused before anything is applied unless `opts.allow_db_ahead`, and
/// after running every embedded migration must be recorded as applied. The
/// returned [`migrate::MigrationReport`] names both heads.
///
/// `bin/epigraph-migrate.rs` is the supported deploy path and calls this
/// unconditionally. `bin/server.rs` calls it only when `EPIGRAPH_MIGRATE_ON_BOOT`
/// is `1`/`true`/`yes`, because migrations 074/075/084 are designed to `RAISE`
/// when their tenancy preconditions do not hold and the server call site
/// `.expect()`s — an unattended boot-time apply turns a precondition failure
/// into a crash loop. See `docs/deploy.md`.
#[cfg(feature = "db")]
pub use migrate::run_migrations;

/// Should `bin/server.rs` apply migrations at boot? Reads the raw
/// `EPIGRAPH_MIGRATE_ON_BOOT` value; `None` means unset.
///
/// Lives here rather than in `bin/server.rs` so it is testable — an integration
/// test cannot import a binary's private items.
///
/// Trimmed and case-folded on purpose. `docs/deploy.md` promises `1`/`true`/`yes`,
/// and an operator who writes `TRUE`, `True` or picks up a leading space from
/// YAML quoting must not silently get the *skip* branch: that yields a server
/// that boots happily against a stale schema, the worst failure available here.
pub fn should_migrate_on_boot(raw: Option<&str>) -> bool {
    env_flag_enabled(raw)
}

/// The boolean-environment-variable rule shared by `EPIGRAPH_MIGRATE_ON_BOOT`
/// and `EPIGRAPH_MIGRATE_ALLOW_DB_AHEAD`: `1`/`true`/`yes`, trimmed and
/// case-folded. Anything else — including unset and the empty string — is
/// false.
pub fn env_flag_enabled(raw: Option<&str>) -> bool {
    matches!(
        raw.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// Build the test router.
///
/// # Why this goes through `ScopedPool` and not `PgPoolOptions`
///
/// Conversion shard 4 is the first shard whose converted handlers have real
/// HTTP coverage, and a handler on [`state::AppState::read_as`] REFUSES when
/// `AppState.scoped` is `None` — deliberately, rather than falling back to the
/// raw pool. Built through `with_db` this fixture left `scoped` at `None`, so
/// every converted route would answer 500 here for a reason that has nothing to
/// do with the route.
///
/// # What this is NOT
///
/// It is not the filtered HTTP fixture recorded as owed in
/// `epigraph-api/tests/lineage_scoped_read.rs`, and it must not be cited as
/// closing it. [`state::AppState::with_scoped_pool`] sets
/// `db_pool = scoped.inner().clone()`, so on this fixture the converted and
/// unconverted arms are the SAME POOL: reverting a converted site to
/// `&state.db_pool` changes not one observable row, and a mutation proof built
/// on it reports a false pass. That gap was re-specified to "give the api test
/// fixture a FILTERED pool" for exactly this reason and is still open. The
/// instrument that can see the difference is `viewer_fixture::downgraded_pool`,
/// used by the direct-invocation proofs — `belief_computation_scoped_read.rs`
/// is this shard's.
///
/// Sizing is pinned to the 4 connections this fixture used before rather than
/// `ScopedPoolOptions::default()`'s 10: a `--workspace --no-fail-fast` run
/// spawns many of these at once, and raising the per-app ceiling 2.5× would
/// surface as "too many clients" in binaries unrelated to whatever changed.
#[cfg(feature = "db")]
pub async fn build_app_for_tests(database_url: &str) -> Result<axum::Router, sqlx::Error> {
    let scoped = epigraph_db::ScopedPool::connect_with_options(
        database_url,
        epigraph_db::SessionGucMode::Session,
        epigraph_db::ScopedPoolOptions {
            max_connections: 4,
            ..Default::default()
        },
    )
    .await
    .map_err(|e| sqlx::Error::Configuration(Box::new(e)))?;
    let state =
        crate::state::AppState::with_scoped_pool(scoped, crate::state::ApiConfig::default());
    Ok(crate::routes::create_router(state))
}

#[cfg(test)]
mod migrate_on_boot_gate_tests {
    use super::should_migrate_on_boot;

    #[test]
    fn unset_does_not_migrate() {
        assert!(!should_migrate_on_boot(None));
    }

    #[test]
    fn documented_truthy_values_migrate() {
        for v in ["1", "true", "yes"] {
            assert!(should_migrate_on_boot(Some(v)), "{v} should enable");
        }
    }

    #[test]
    fn case_and_whitespace_variants_migrate() {
        for v in ["TRUE", "True", "YES", " 1", "true\n", "  Yes  "] {
            assert!(should_migrate_on_boot(Some(v)), "{v:?} should enable");
        }
    }

    #[test]
    fn falsey_and_junk_values_do_not_migrate() {
        for v in ["", "0", "false", "no", "off", "maybe", "y"] {
            assert!(!should_migrate_on_boot(Some(v)), "{v:?} should not enable");
        }
    }
}
