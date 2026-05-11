//! Bearer token extraction and JWT validation middleware.
//!
//! Extracts JWT from `Authorization: Bearer <token>` header,
//! validates it, checks revocation, and injects AuthContext
//! into request extensions.

use axum::{extract::State, http::Request, middleware::Next, response::Response};

use crate::errors::ApiError;
use crate::state::AppState;

pub use epigraph_auth::AuthContext;

/// Middleware: extract Bearer token, validate JWT, inject AuthContext.
///
/// Requests without a valid Bearer token are rejected with 401 Unauthorized.
pub async fn bearer_auth_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match auth_header.as_deref() {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];

            // Check revocation set
            if state.is_token_revoked(token) {
                return Err(ApiError::Unauthorized {
                    reason: "Token has been revoked".to_string(),
                });
            }

            // Validate JWT
            let claims =
                state
                    .jwt_config
                    .validate_token(token)
                    .map_err(|e| ApiError::Unauthorized {
                        reason: format!("Invalid token: {e}"),
                    })?;

            // Build AuthContext
            let auth_ctx: AuthContext = claims.into();

            request.extensions_mut().insert(auth_ctx);
            Ok(next.run(request).await)
        }
        _ => Err(ApiError::Unauthorized {
            reason: "Missing Authorization header".to_string(),
        }),
    }
}

/// Scope-aware `FromRequestParts` extractors.
///
/// These run BEFORE any `FromRequest` body-consuming extractor (e.g., `Json`),
/// so a wrong-scope request is rejected with 403 *before* the body is parsed.
/// This prevents the 422-instead-of-403 bug described in issue #128.
///
/// In axum, all `FromRequestParts` extractors run before any `FromRequest`
/// extractor regardless of their order in the handler signature. So a handler
/// that uses one of these extractors gets the scope check enforced at extractor
/// time, ahead of `Json<...>` parsing the body.
macro_rules! require_scope_extractor {
    ($name:ident, $scope:expr) => {
        /// Extracts `AuthContext` from request extensions and verifies the
        /// caller has the required scope. Returns 401 if no `AuthContext` is
        /// present (i.e., bearer middleware did not run / inject one), 403 if
        /// the context is present but lacks the scope.
        pub struct $name(pub AuthContext);

        #[axum::async_trait]
        impl<S: Send + Sync> axum::extract::FromRequestParts<S> for $name {
            type Rejection = ApiError;

            async fn from_request_parts(
                parts: &mut axum::http::request::Parts,
                _state: &S,
            ) -> Result<Self, Self::Rejection> {
                let auth = parts.extensions.get::<AuthContext>().cloned().ok_or(
                    ApiError::Unauthorized {
                        reason: "authentication required".into(),
                    },
                )?;
                if !auth.has_scope($scope) {
                    return Err(ApiError::Forbidden {
                        reason: format!("Missing required scope: {}", $scope),
                    });
                }
                Ok(Self(auth))
            }
        }
    };
}

require_scope_extractor!(RequireScopeAdmin, "claims:admin");
require_scope_extractor!(RequireScopeWrite, "claims:write");
require_scope_extractor!(RequireScopeWebhooksWrite, "webhooks:write");

#[cfg(test)]
mod require_scope_tests {
    use super::*;
    use axum::extract::FromRequestParts;
    use axum::http::Request;

    fn parts_with_scopes(scopes: &[&str]) -> axum::http::request::Parts {
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();
        parts.extensions.insert(AuthContext {
            client_id: uuid::Uuid::nil(),
            agent_id: None,
            owner_id: None,
            client_type: ClientType::Service,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: uuid::Uuid::nil(),
        });
        parts
    }

    #[tokio::test]
    async fn require_scope_admin_missing_context_returns_401() {
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();
        let r: Result<RequireScopeAdmin, _> =
            RequireScopeAdmin::from_request_parts(&mut parts, &()).await;
        assert!(matches!(r, Err(ApiError::Unauthorized { .. })));
    }

    #[tokio::test]
    async fn require_scope_admin_wrong_scope_returns_403() {
        let mut parts = parts_with_scopes(&["claims:read"]);
        let r: Result<RequireScopeAdmin, _> =
            RequireScopeAdmin::from_request_parts(&mut parts, &()).await;
        assert!(matches!(r, Err(ApiError::Forbidden { .. })));
    }

    #[tokio::test]
    async fn require_scope_admin_with_scope_succeeds() {
        let mut parts = parts_with_scopes(&["claims:admin"]);
        let r = RequireScopeAdmin::from_request_parts(&mut parts, &())
            .await
            .expect("should succeed");
        assert!(r.0.has_scope("claims:admin"));
    }

    #[tokio::test]
    async fn require_scope_write_wrong_scope_returns_403() {
        let mut parts = parts_with_scopes(&["claims:read"]);
        let r: Result<RequireScopeWrite, _> =
            RequireScopeWrite::from_request_parts(&mut parts, &()).await;
        assert!(matches!(r, Err(ApiError::Forbidden { .. })));
    }

    #[tokio::test]
    async fn require_scope_webhooks_write_wrong_scope_returns_403() {
        let mut parts = parts_with_scopes(&["claims:read"]);
        let r: Result<RequireScopeWebhooksWrite, _> =
            RequireScopeWebhooksWrite::from_request_parts(&mut parts, &()).await;
        assert!(matches!(r, Err(ApiError::Forbidden { .. })));
    }
}
