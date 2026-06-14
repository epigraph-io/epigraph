//! Per-transport requester derivation for read-path content redaction (A3 §7.5).
use epigraph_crypto::ContentHasher;
use epigraph_db::access_control::ContentAccess;
use uuid::Uuid;

/// The placeholder substituted for a claim's `content` when the requester is
/// not allowed to read it. Kept as a single source of truth so the read tools
/// and their regression tests agree on the exact string.
pub const REDACTED: &str = "[REDACTED]";

/// Compute the `(content, content_hash)` pair to put on a `ClaimResponse`,
/// applying redaction in lockstep.
///
/// `content_hash` is an unsalted `BLAKE3(content)` — a *deterministic function
/// of the exact field we redact*. Returning the real hash for a redacted claim
/// is a confirmation oracle: a stranger could compute `BLAKE3(guess)` and
/// compare to confirm any guessable/low-entropy private claim, leaking the
/// redacted `content` through a sibling field. (The HTTP `ClaimResponse` has no
/// `content_hash` field at all, so this is an MCP-only exposure with no HTTP
/// parity to preserve.) We therefore blank the hash in the *same* branch as the
/// content, never separately — keeping the oracle closed wherever a tool
/// redacts.
///
/// Centralizing this in one helper (called by every MCP read tool) eliminates
/// the copy-paste-inversion surface of hand-writing the `if Full { .. } else {
/// REDACTED }` branch at each of the ~6 response-construction sites.
pub fn redact_content(
    access: ContentAccess,
    content: &str,
    content_hash: &[u8; 32],
) -> (String, String) {
    match access {
        ContentAccess::Full => (content.to_string(), ContentHasher::to_hex(content_hash)),
        ContentAccess::Redacted => (REDACTED.to_string(), String::new()),
    }
}

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

    /// `redact_content` must return the real content AND real hash on `Full`,
    /// and blank BOTH on `Redacted`. The hash assertion is the discriminating
    /// one: the content_hash is `BLAKE3(content)`, so returning it for a
    /// redacted claim re-leaks the redacted field through a confirmation
    /// oracle. This fails if the hash is blanked in a separate branch from the
    /// content (drift) or returned unconditionally.
    #[test]
    fn redact_content_blanks_hash_in_lockstep_with_content() {
        let content = "low-entropy private secret";
        let hash = ContentHasher::hash(content.as_bytes());
        let real_hex = ContentHasher::to_hex(&hash);

        let (full_content, full_hash) = redact_content(ContentAccess::Full, content, &hash);
        assert_eq!(full_content, content, "Full must return the real content");
        assert_eq!(full_hash, real_hex, "Full must return the real hash");

        let (red_content, red_hash) = redact_content(ContentAccess::Redacted, content, &hash);
        assert_eq!(red_content, REDACTED, "Redacted must blank the content");
        assert!(
            red_hash.is_empty(),
            "Redacted must blank the hash too — content_hash = BLAKE3(content) \
             is a confirmation oracle for the redacted field"
        );
        assert_ne!(
            red_hash, real_hex,
            "the redacted hash must NOT equal BLAKE3(content)"
        );
    }
}
