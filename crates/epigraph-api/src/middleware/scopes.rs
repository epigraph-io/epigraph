//! Scope enforcement middleware.
//!
//! Usage: wrap route groups with `require_scope` or call `check_scopes`
//! directly from handlers.

use axum::{extract::Request, middleware::Next, response::Response};

use crate::errors::ApiError;
use crate::middleware::bearer::AuthContext;

/// Check that the request's AuthContext has all required scopes.
/// Call this from route handlers as a guard.
pub fn check_scopes(auth: &AuthContext, required: &[&str]) -> Result<(), ApiError> {
    for scope in required {
        if !auth.has_scope(scope) {
            return Err(ApiError::Forbidden {
                reason: format!("Missing required scope: {scope}"),
            });
        }
    }
    Ok(())
}

/// Middleware: check that the request has a specific scope.
/// Use with `axum::middleware::from_fn`.
pub async fn require_scope(
    required_scope: &'static str,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let auth = request
        .extensions()
        .get::<AuthContext>()
        .ok_or(ApiError::Unauthorized {
            reason: "No auth context".to_string(),
        })?;

    if !auth.has_scope(required_scope) {
        return Err(ApiError::Forbidden {
            reason: format!("Missing required scope: {required_scope}"),
        });
    }

    Ok(next.run(request).await)
}
