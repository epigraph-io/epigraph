//! Per-transport requester derivation for read-path content redaction (A3 §7.5).
use uuid::Uuid;

/// The agent identity to evaluate `check_content_access` against.
///
/// HTTP transport: the bearer's own identity. We MUST branch on the presence
/// of an `AuthContext` rather than flattening, because an authenticated caller
/// whose `agent_id` is `None` (a Service/Human client presenting a read scope
/// like `claims:read`) is still a *caller* — it must be scoped to its own
/// `client_id`, NEVER elevated to the server's signer identity. Flattening with
/// `and_then(..).or(server)` is a confused-deputy elevation: it would grant
/// that agentless caller `ContentAccess::Full` over any `private` row the
/// server agent happens to own. This mirrors the audited HTTP convention in
/// `epigraph-api/src/routes/claims.rs::get_claim`
/// (`ctx.agent_id.or(Some(ctx.client_id))` — caller's `client_id`, never a
/// shared elevated identity).
///
/// stdio transport: there is no `AuthContext` (single-tenant local agent), so
/// the requester is the server's own signer identity (`server.agent_id()`),
/// keeping stdio agents self-scoped.
pub fn mcp_requester(
    auth: Option<&epigraph_auth::AuthContext>,
    server_agent_id: Uuid,
) -> Option<Uuid> {
    match auth {
        Some(a) => a.agent_id.or(Some(a.client_id)),
        None => Some(server_agent_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_auth::{AuthContext, ClientType};

    /// Minimal AuthContext builder — mirrors server.rs tests `auth_with_scopes`.
    fn test_ctx() -> AuthContext {
        AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: None,
            owner_id: None,
            client_type: ClientType::Service,
            scopes: vec![],
            jti: Uuid::new_v4(),
        }
    }

    #[test]
    fn http_auth_with_agent_wins() {
        let a = AuthContext {
            agent_id: Some(Uuid::from_u128(7)),
            ..test_ctx()
        };
        assert_eq!(
            mcp_requester(Some(&a), Uuid::from_u128(1)),
            Some(Uuid::from_u128(7))
        );
    }

    #[test]
    fn stdio_falls_back_to_server_identity() {
        assert_eq!(
            mcp_requester(None, Uuid::from_u128(1)),
            Some(Uuid::from_u128(1))
        );
    }

    /// Confused-deputy regression: an authenticated caller with no `agent_id`
    /// (Service/Human client presenting a read scope) must be scoped to its OWN
    /// `client_id`, NEVER elevated to the server's signer identity. The
    /// `client_id` (5) is deliberately distinct from `server_agent_id` (1) so
    /// the old `and_then(..).or(server)` flatten — which would return Some(1) —
    /// fails this assertion.
    #[test]
    fn http_auth_without_agent_uses_client_id_not_server() {
        let a = AuthContext {
            agent_id: None,
            client_id: Uuid::from_u128(5),
            ..test_ctx()
        };
        let requester = mcp_requester(Some(&a), Uuid::from_u128(1));
        assert_eq!(
            requester,
            Some(Uuid::from_u128(5)),
            "agentless HTTP caller must be scoped to its own client_id"
        );
        assert_ne!(
            requester,
            Some(Uuid::from_u128(1)),
            "agentless HTTP caller must NOT be elevated to the server identity"
        );
    }
}
