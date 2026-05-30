//! Per-transport requester derivation for read-path content redaction (A3 §7.5).
use uuid::Uuid;

/// The agent identity to evaluate `check_content_access` against.
/// HTTP transport: the bearer's `AuthContext.agent_id` (the GUI/user).
/// stdio transport: no AuthContext → the server's own signer identity
/// (`server.agent_id()`), so single-tenant stdio agents are self-scoped.
pub fn mcp_requester(
    auth: Option<&epigraph_auth::AuthContext>,
    server_agent_id: Uuid,
) -> Option<Uuid> {
    auth.and_then(|a| a.agent_id).or(Some(server_agent_id))
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
        assert_eq!(mcp_requester(None, Uuid::from_u128(1)), Some(Uuid::from_u128(1)));
    }
}
