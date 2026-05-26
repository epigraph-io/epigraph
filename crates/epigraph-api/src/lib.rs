pub mod access_control;
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
/// Calling this in `bin/server.rs` (and `bin/epigraph-migrate.rs`) before the
/// HTTP listener binds ensures fresh deploys never serve traffic against a
/// stale schema.
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

#[cfg(feature = "db")]
pub async fn build_app_for_tests(database_url: &str) -> Result<axum::Router, sqlx::Error> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(database_url)
        .await?;
    let state = crate::state::AppState::with_db(pool, crate::state::ApiConfig::default());
    Ok(crate::routes::create_router(state))
}
