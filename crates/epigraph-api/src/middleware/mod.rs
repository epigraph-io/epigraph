pub mod bearer;
#[cfg(feature = "db")]
pub mod elevated_access;
#[cfg(feature = "db")]
pub mod group_authz;
#[cfg(feature = "db")]
pub mod instance_authz;
#[cfg(feature = "db")]
pub mod provenance;
pub mod rate_limit;
pub mod scopes;

// Re-export rate limiting middleware
#[cfg(feature = "db")]
pub use rate_limit::guest_rate_limit_middleware;
pub use rate_limit::{address_rate_limit_middleware, rate_limit_middleware, RateLimitResponse};

// Re-export OAuth2 middleware
pub use bearer::{bearer_auth_middleware, optional_bearer_auth_middleware, AuthContext};
pub use epigraph_auth::ClientType;
#[cfg(feature = "db")]
pub use group_authz::require_group_admin_conn;
#[cfg(feature = "db")]
pub use instance_authz::require_instance_admin_for_group;
#[cfg(feature = "db")]
pub use provenance::record_provenance;
pub use scopes::check_scopes;

// ---------------------------------------------------------------------------
// Ed25519 *request* signing (X-Signature / X-Public-Key / X-Timestamp headers
// over the raw body) is gone.
//
// PR-03 deleted `require_signature`, the only production installer of the
// request-signing middleware: it had been unreachable through either
// `create_router` variant (bearer auth ran first and short-circuited it). It
// was also the only writer of `SecurityEvent::signature_verification` and
// `SecurityEvent::auth_attempt` rows, so those event types have no producer
// (see docs/deploy.md).
//
// Backlog 67f71b76 then deleted what PR-03 had left behind with no production
// caller: the middleware itself (`middleware/auth.rs`, with its state type,
// error type, verified-agent extension and header constants), its deprecated
// layer shim, the signed-request body extractor, the in-memory key manager
// and the `AppState` field and constructors that carried the middleware's
// state. Their tests built their own routers around them and went with them.
//
// PAYLOAD-level packet signatures (`ApiConfig::require_packet_signatures` ->
// `routes/submit.rs`) are a separate, live mechanism and are untouched.
// ---------------------------------------------------------------------------
