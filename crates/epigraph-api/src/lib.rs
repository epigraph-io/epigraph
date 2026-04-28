pub mod access_control;
pub mod auth;
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
pub use routes::{create_router, create_router_with_extensions};
pub use security::{
    AgentKey, AgentRateLimiter, KeyError, KeyRevocationRequest, KeyRotationRequest, KeyStatus,
    KeyType, RateLimitConfig, RateLimitError, SecurityAuditLog, SecurityEvent, SecurityEventFilter,
};
pub use services::{SubmissionService, ValidationService};
pub use state::{
    ApiConfig, AppState, ClaimStore, SharedAuditLog, SharedChallengeService,
    SharedEmbeddingService, SharedEventBus,
};
