pub mod errors;
pub mod extractors;
pub mod metrics;
pub mod middleware;
pub mod oauth;
pub mod openapi;
#[cfg(feature = "db")]
pub mod query_parser;
pub mod routes;
pub mod security;
pub mod services;
pub mod state;
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

/// Apply all pending SQL migrations from the workspace `migrations/` directory.
///
/// Migrations are embedded into the binary at compile time by `sqlx::migrate!()`.
///
/// `bin/epigraph-migrate.rs` is the supported deploy path and calls this
/// unconditionally. `bin/server.rs` calls it only when `EPIGRAPH_MIGRATE_ON_BOOT`
/// is `1`/`true`/`yes`, because migrations 074/075/084 are designed to `RAISE`
/// when their tenancy preconditions do not hold and the server call site
/// `.expect()`s — an unattended boot-time apply turns a precondition failure
/// into a crash loop. See `docs/deploy.md`.
///
/// `ignore_missing(true)` is required because `epigraph-internal` shares the
/// same `_sqlx_migrations` table and applies its own migrations (currently
/// versions 35–37). Without this flag, the public binary would panic on
/// restart with "migration N was previously applied but is missing in the
/// resolved migrations". See `migrations/README.md` for the version-range
/// reservation.
#[cfg(feature = "db")]
pub async fn run_migrations(pool: &epigraph_db::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    let mut migrator = sqlx::migrate!("../../migrations");
    migrator.set_ignore_missing(true);
    migrator.run(pool).await
}

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
    matches!(
        raw.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

#[cfg(feature = "db")]
pub async fn build_app_for_tests(database_url: &str) -> Result<axum::Router, sqlx::Error> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(database_url)
        .await?;
    let state = crate::state::AppState::with_db(pool, crate::state::ApiConfig::default());
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
