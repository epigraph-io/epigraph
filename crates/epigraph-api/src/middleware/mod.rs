pub mod auth;
pub mod bearer;
#[cfg(feature = "db")]
pub mod group_authz;
#[cfg(feature = "db")]
pub mod provenance;
pub mod rate_limit;
pub mod scopes;

// Re-export common types for convenience
pub use auth::{
    signature_verification_middleware, SignatureError, SignatureVerificationState, VerifiedAgent,
    PUBLIC_KEY_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER,
};

// Re-export rate limiting middleware
pub use rate_limit::{rate_limit_middleware, RateLimitResponse};

// Re-export OAuth2 middleware
pub use bearer::{bearer_auth_middleware, optional_bearer_auth_middleware, AuthContext};
pub use epigraph_auth::ClientType;
#[cfg(feature = "db")]
pub use group_authz::require_group_admin;
#[cfg(feature = "db")]
pub use provenance::record_provenance;
pub use scopes::check_scopes;

// Legacy export (deprecated)
#[allow(deprecated)]
pub use auth::signature_verification_layer;

// ---------------------------------------------------------------------------
// `require_signature` was DELETED in PR-03.
//
// It layered Ed25519 *request* signing (X-Signature / X-Public-Key /
// X-Timestamp headers over the raw body) on the `protected` router whenever
// `ApiConfig::require_signatures` was set. It had been unreachable through
// either `create_router` variant: the branch that installed it also short-
// circuited on any request carrying an `AuthContext`, and bearer auth ran
// first, so every authenticated request skipped it and every unauthenticated
// one was rejected earlier.
//
// Two knock-on effects, recorded here rather than left to be discovered:
//
//   * It was the only writer of `SecurityEvent::signature_verification` and
//     `SecurityEvent::auth_attempt` rows into `security_events`. Those event
//     types now have no producer. Nothing live is lost — the path was already
//     unreachable — but a dashboard reading them will read empty forever.
//   * It was the only production caller of `signature_verification_middleware`,
//     which is what inserts `VerifiedAgent` into request extensions. The
//     `VerifiedAgent` branch in `rate_limit.rs` is consequently dead; see the
//     note there.
//
// `signature_verification_middleware`, `VerifiedAgent` and the header
// constants remain exported above: the middleware tests build their own
// routers around them, and PAYLOAD-level packet signatures
// (`ApiConfig::require_packet_signatures` -> `routes/submit.rs`) are a
// separate, live mechanism that this deletion does not touch.
// ---------------------------------------------------------------------------
