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

#[derive(Debug, Clone, PartialEq)]
pub enum ClientType {
    Agent,
    Human,
    Service,
}

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
