//! Bearer token extraction and JWT validation middleware.
//!
//! Extracts JWT from `Authorization: Bearer <token>` header,
//! validates it, checks revocation, and injects AuthContext
//! into request extensions.

use axum::{extract::State, http::Request, middleware::Next, response::Response};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;

/// Authorization context injected into request extensions.
/// Replaces `VerifiedAgent` for OAuth2-authenticated requests.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub client_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub client_type: ClientType,
    pub scopes: Vec<String>,
    pub jti: Uuid,
}

// Canonical home is `epigraph_interfaces::auth::ClientType` (D12).
// Re-exported here for back-compat. Will be removed in a future major.
#[deprecated(
    since = "0.4.0",
    note = "Import ClientType from epigraph_interfaces::auth (or via epigraph_interfaces::ClientType)"
)]
pub use epigraph_interfaces::ClientType;

impl AuthContext {
    /// Check if the context has a specific scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// Middleware: extract Bearer token, validate JWT, inject AuthContext.
///
/// Also supports legacy Ed25519 fallback: if no Bearer token is present
/// but X-Signature headers are, falls through to the legacy middleware.
pub async fn bearer_auth_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    // Early-return if a chained AuthProvider already set AuthContext.
    // Mirrors how `require_signature` short-circuits at middleware/mod.rs:114.
    if request.extensions().get::<AuthContext>().is_some() {
        return Ok(next.run(request).await);
    }

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
            #[allow(deprecated)]
            let client_type = match claims.client_type.as_str() {
                "agent" => ClientType::Agent,
                "human" => ClientType::Human,
                "service" => ClientType::Service,
                _ => ClientType::Service,
            };

            let auth_ctx = AuthContext {
                client_id: claims.sub,
                agent_id: claims.agent_id,
                owner_id: claims.owner_id,
                client_type,
                scopes: claims.scopes,
                jti: claims.jti,
            };

            request.extensions_mut().insert(auth_ctx);
            Ok(next.run(request).await)
        }
        _ => {
            // No Bearer token — check for legacy X-Signature headers
            if request.headers().contains_key("x-signature") {
                Ok(next.run(request).await)
            } else {
                Err(ApiError::Unauthorized {
                    reason: "Missing Authorization header".to_string(),
                })
            }
        }
    }
}

#[cfg(test)]
mod early_return_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;
    use uuid::Uuid;

    // Sentinel handler that records whether it ran.
    async fn ok_handler() -> &'static str { "ok" }

    // Construct a no-db AppState we can attach to the middleware. We use the
    // non-db `AppState::new` constructor so we don't need a live DB pool.
    #[cfg(not(feature = "db"))]
    fn test_state() -> crate::state::AppState {
        crate::state::AppState::new(crate::state::ApiConfig::default())
    }

    #[cfg(not(feature = "db"))]
    #[tokio::test]
    async fn bearer_early_returns_when_authcontext_already_set() {
        let state = test_state();
        let app = Router::new()
            .route("/probe", get(ok_handler))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                bearer_auth_middleware,
            ))
            .with_state(state);

        let mut req = Request::builder().uri("/probe").body(Body::empty()).unwrap();
        #[allow(deprecated)]
        let ctx = AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: None,
            owner_id: None,
            client_type: ClientType::Human,
            scopes: vec!["claims:read".into()],
            jti: Uuid::new_v4(),
        };
        req.extensions_mut().insert(ctx);

        // Despite no Authorization header, bearer should pass through because
        // AuthContext is already set in the request extensions.
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[cfg(not(feature = "db"))]
    #[tokio::test]
    async fn bearer_rejects_when_authcontext_missing_and_no_auth_header() {
        let state = test_state();
        let app = Router::new()
            .route("/probe", get(ok_handler))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                bearer_auth_middleware,
            ))
            .with_state(state);

        let req = Request::builder().uri("/probe").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Pre-existing behavior: 401 when neither AuthContext nor Authorization
        // header nor x-signature is present.
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
