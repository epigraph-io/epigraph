//! `auth_chain_middleware` — runs the registered `AuthProvider` chain.
//!
//! Behavior (see spec D1, D2):
//! - Empty providers ⇒ pass-through (dormant kernel default).
//! - First provider returning `Ok(Some(identity))` ⇒ resolve via
//!   `IdentityResolver`, set `AuthContext`, run handler.
//! - All providers `Ok(None)` ⇒ pass-through; bearer middleware runs.
//! - Any provider `Err(_)` ⇒ short-circuit with 401.
//!
//! Per review B3: `AuthError::ProviderUnavailable` is collapsed onto 401
//! alongside `AuthError::InvalidCredential` for v1 simplicity. A future
//! revision may route `ProviderUnavailable` to 503; the variant is preserved
//! at the trait level to keep that option open without a breaking change.

use axum::{
    extract::State,
    http::Request,
    middleware::Next,
    response::Response,
};

use crate::errors::ApiError;
use crate::state::AppState;

pub async fn auth_chain_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    if state.auth_providers.is_empty() {
        return Ok(next.run(request).await);
    }

    let (parts, body) = request.into_parts();

    for provider in &state.auth_providers {
        match provider.try_authenticate(&parts).await {
            Ok(Some(identity)) => {
                #[cfg(feature = "db")]
                {
                    let auth_ctx = state
                        .identity_resolver
                        .resolve_or_provision(&identity)
                        .await?;
                    let mut req = Request::from_parts(parts, body);
                    req.extensions_mut().insert(auth_ctx);
                    return Ok(next.run(req).await);
                }
                #[cfg(not(feature = "db"))]
                {
                    let _ = identity;
                    return Err(ApiError::InternalError {
                        message: "auth_chain requires the `db` feature".into(),
                    });
                }
            }
            Ok(None) => continue,
            Err(e) => {
                return Err(ApiError::Unauthorized {
                    reason: format!("auth provider {} rejected: {e}", provider.name()),
                });
            }
        }
    }

    let req = Request::from_parts(parts, body);
    Ok(next.run(req).await)
}

#[cfg(all(test, feature = "db"))]
mod tests_db {
    // Full middleware integration tests live in tests/middleware/auth_chain_tests.rs
    // (they need to mount the middleware on a test router and use a live DB pool
    // for the resolver path). The test file gating is `#[cfg(feature = "db")]`
    // for the resolve-success path and `#[cfg(not(feature = "db"))]` for the
    // pass-through paths — see Task 1.9.
}
