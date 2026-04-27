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

#[cfg(feature = "db")]
pub async fn build_app_for_tests(database_url: &str) -> Result<axum::Router, sqlx::Error> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(database_url)
        .await?;
    let state = crate::state::AppState::with_db(pool, crate::state::ApiConfig::default());
    Ok(crate::routes::create_router(state))
}
