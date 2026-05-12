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
    epigraph_auth::check_scopes(auth, required).map_err(|reason| ApiError::Forbidden { reason })
}

/// Returns `Ok(())` if either:
/// - `auth` has the `claims:admin` scope, OR
/// - `auth.owner_id` (or `auth.client_id` when `owner_id` is `None`) matches `target_owner_id`.
///
/// Used to gate per-row mutations: admins can edit any row; others can
/// only edit rows they authored/own.
pub fn require_owner_or_admin(
    auth: &AuthContext,
    target_owner_id: uuid::Uuid,
) -> Result<(), ApiError> {
    if auth.has_scope("claims:admin") {
        return Ok(());
    }
    let principal = auth.owner_id.unwrap_or(auth.client_id);
    if principal == target_owner_id {
        return Ok(());
    }
    Err(ApiError::Forbidden {
        reason: "row is owned by another principal and caller lacks claims:admin".into(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::ClientType;
    use uuid::Uuid;

    fn make_auth(scopes: &[&str], client_id: Uuid, owner_id: Option<Uuid>) -> AuthContext {
        AuthContext {
            client_id,
            agent_id: None,
            owner_id,
            client_type: ClientType::Service,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: Uuid::new_v4(),
        }
    }

    #[test]
    fn admin_scope_passes_regardless_of_owner() {
        let auth = make_auth(&["claims:admin"], Uuid::new_v4(), None);
        let target = Uuid::new_v4(); // completely different
        assert!(require_owner_or_admin(&auth, target).is_ok());
    }

    #[test]
    fn matching_owner_passes_without_admin() {
        let owner_id = Uuid::new_v4();
        let auth = make_auth(&["claims:write"], Uuid::new_v4(), Some(owner_id));
        assert!(require_owner_or_admin(&auth, owner_id).is_ok());
    }

    #[test]
    fn matching_client_id_passes_when_no_owner_id() {
        let client_id = Uuid::new_v4();
        let auth = make_auth(&["claims:write"], client_id, None);
        assert!(require_owner_or_admin(&auth, client_id).is_ok());
    }

    #[test]
    fn non_matching_no_admin_fails() {
        let auth = make_auth(&["claims:write"], Uuid::new_v4(), None);
        let target = Uuid::new_v4(); // different from client_id
        assert!(require_owner_or_admin(&auth, target).is_err());
    }
}
