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
/// - `auth.agent_id` (the request's `agents.id` principal) is `target_author`,
///   the row's `claims.agent_id`.
///
/// Used to gate per-row mutations of a claim (`PUT`, `PATCH` and
/// `PATCH .../labels` on `/api/v1/claims/:id`): admins can edit any row they
/// can read; others only rows they authored.
///
/// There is deliberately no arm comparing the token's `owner_id` or
/// `client_id` with the author (backlog a2d3e945). Those are
/// `oauth_clients.id` values and `claims.agent_id` is an `agents.id`, which
/// every real token's principal gets from `AgentRepository::ensure_for_client`
/// at mint, so the two never coincide: the old comparison refused every
/// non-admin author of their own claim, and could only ever admit by an id
/// collision. Nor does this gate carry the MCP gate's operator or delegate
/// arms; how far those reach over HTTP is an open ruling (backlog d405f801).
/// A delegated run token is admitted here only as its own principal, i.e. for
/// the claims that principal authored.
pub fn require_owner_or_admin(
    auth: &AuthContext,
    target_author: uuid::Uuid,
) -> Result<(), ApiError> {
    if auth.has_scope("claims:admin") {
        return Ok(());
    }
    if auth.agent_id == Some(target_author) {
        return Ok(());
    }
    Err(ApiError::Forbidden {
        reason: "claim is authored by another agent and caller lacks claims:admin".into(),
    })
}

/// The authority gate for a claim-retiring ACT, `supersede` and
/// `mark_duplicate` (batch OA1, operator decision D1; the rule itself is
/// [`epigraph_auth::claim_act::claim_act_arm`], shared with MCP).
///
/// The caller must already have read `target` THROUGH ITS OWN VIEWER and
/// answered a claim it cannot read with 404; this gate is only ever asked about
/// a claim the caller can see. `viewer_principal` and `writable_groups` are
/// that viewer's. A refusal is [`ApiError::ClaimNotWritable`] (`403`,
/// `not_owner`, rule `not_claim_writer`).
///
/// # Errors
/// [`ApiError::ClaimNotWritable`] when no arm admits the caller.
pub fn require_claim_act_authority(
    auth: &AuthContext,
    viewer_principal: Option<uuid::Uuid>,
    writable_groups: &[uuid::Uuid],
    target: epigraph_auth::claim_act::ClaimActTarget,
    claim_id: uuid::Uuid,
    action: &str,
) -> Result<epigraph_auth::claim_act::ClaimActArm, ApiError> {
    epigraph_auth::claim_act::claim_act_arm(auth, viewer_principal, writable_groups, target)
        .ok_or_else(|| ApiError::ClaimNotWritable {
            claim_id,
            message: epigraph_auth::claim_act::not_claim_writer_message(claim_id, action),
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

    fn make_auth(
        scopes: &[&str],
        client_id: Uuid,
        owner_id: Option<Uuid>,
        agent_id: Option<Uuid>,
    ) -> AuthContext {
        AuthContext {
            client_id,
            agent_id,
            owner_id,
            client_type: ClientType::Service,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: Uuid::new_v4(),
            family_id: None,
            elevation_claim: None,
            elevation: None,
            admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
            delegated_by: None,
        }
    }

    #[test]
    fn admin_scope_passes_regardless_of_owner() {
        let auth = make_auth(
            &["claims:admin"],
            Uuid::new_v4(),
            None,
            Some(Uuid::new_v4()),
        );
        let target = Uuid::new_v4(); // completely different
        assert!(require_owner_or_admin(&auth, target).is_ok());
    }

    /// The author arm: the token's `agents.id` principal wrote the claim.
    /// Verified to fail on the pre-a2d3e945 gate, which compared only
    /// `owner_id` / `client_id` (both different ids here, as on every real
    /// token).
    #[test]
    fn the_author_passes_without_admin() {
        let author = Uuid::new_v4();
        let auth = make_auth(
            &["claims:write"],
            Uuid::new_v4(),
            Some(Uuid::new_v4()),
            Some(author),
        );
        assert!(require_owner_or_admin(&auth, author).is_ok());
    }

    /// An `oauth_clients.id` (`owner_id`, or `client_id` without one) equal
    /// to the claim's author admits nothing: it names a client row, not an
    /// agent. Both passed on the pre-a2d3e945 gate.
    #[test]
    fn an_owner_or_client_id_equal_to_the_author_is_refused() {
        let author = Uuid::new_v4();
        let by_owner = make_auth(
            &["claims:write"],
            Uuid::new_v4(),
            Some(author),
            Some(Uuid::new_v4()),
        );
        assert!(require_owner_or_admin(&by_owner, author).is_err());
        let by_client = make_auth(&["claims:write"], author, None, Some(Uuid::new_v4()));
        assert!(require_owner_or_admin(&by_client, author).is_err());
    }

    /// A token naming no principal owns nothing.
    #[test]
    fn no_principal_no_admin_fails() {
        let auth = make_auth(&["claims:write"], Uuid::new_v4(), None, None);
        assert!(require_owner_or_admin(&auth, Uuid::new_v4()).is_err());
    }

    #[test]
    fn non_matching_no_admin_fails() {
        let auth = make_auth(
            &["claims:write"],
            Uuid::new_v4(),
            None,
            Some(Uuid::new_v4()),
        );
        let target = Uuid::new_v4(); // different from every id the token carries
        assert!(require_owner_or_admin(&auth, target).is_err());
    }
}
