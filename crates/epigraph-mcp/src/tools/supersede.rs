use rmcp::model::{CallToolResult, Content};

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{MarkDuplicateParams, SupersedeClaimParams};
use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::ClaimRepository;

pub async fn supersede_claim(
    server: &EpiGraphMcpFull,
    params: SupersedeClaimParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let old = parse_uuid(&params.claim_id)?;
    let old_claim_id = ClaimId::from_uuid(old);

    // Per-resource ownership check: only the claim's author or a
    // claims:admin token holder may supersede it.
    let existing = ClaimRepository::get_by_id(&server.pool, old_claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {} not found", old)))?;
    crate::tools::claims::require_owner_or_admin(server, auth, existing.agent_id.as_uuid()).await?;

    let truth = TruthValue::clamped(params.truth_value);
    let (new_id, old_id) = ClaimRepository::supersede(
        &server.pool,
        old_claim_id,
        &params.content,
        truth,
        &params.reason,
    )
    .await
    .map_err(internal_error)?;
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "new_claim_id": new_id,
            "superseded_claim_id": old_id,
            "reason": params.reason,
        }))
        .map_err(internal_error)?,
    )]))
}

pub async fn mark_duplicate(
    server: &EpiGraphMcpFull,
    params: MarkDuplicateParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let dup = parse_uuid(&params.claim_id)?;
    let canon = parse_uuid(&params.canonical_id)?;
    let dup_claim_id = ClaimId::from_uuid(dup);

    // Per-resource ownership check: only the duplicate claim's author or a
    // claims:admin token holder may mark it as a duplicate.
    let dup_claim = ClaimRepository::get_by_id(&server.pool, dup_claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {} not found", dup)))?;
    crate::tools::claims::require_owner_or_admin(server, auth, dup_claim.agent_id.as_uuid())
        .await?;

    ClaimRepository::mark_duplicate(&server.pool, dup_claim_id, ClaimId::from_uuid(canon))
        .await
        .map_err(internal_error)?;
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "duplicate_id": dup,
            "canonical_id": canon,
            "mode": "mark_duplicate",
        }))
        .map_err(internal_error)?,
    )]))
}

#[cfg(test)]
mod tests {
    use epigraph_auth::{AuthContext, ClientType};
    use uuid::Uuid;

    fn make_auth(caller_id: Uuid, scopes: &[&str]) -> AuthContext {
        AuthContext {
            client_id: caller_id,
            agent_id: None,
            owner_id: Some(caller_id),
            client_type: ClientType::Service,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: Uuid::new_v4(),
        }
    }

    /// Mirrors the ownership gate used by `supersede_claim` and `mark_duplicate`.
    ///
    /// We cannot spin up a pool here; tests exercise the auth-branch logic
    /// (auth = Some(_)) which never touches the pool.
    fn check_ownership(auth: &AuthContext, claim_agent_id: Uuid) -> Result<(), String> {
        if auth.has_scope("claims:admin") {
            return Ok(());
        }
        let principal = auth.owner_id.unwrap_or(auth.client_id);
        if principal == claim_agent_id {
            Ok(())
        } else {
            Err(format!(
                "claim owned by {claim_agent_id}; caller {principal} denied"
            ))
        }
    }

    #[test]
    fn non_owner_without_admin_is_rejected() {
        let claim_agent_id = Uuid::new_v4();
        let caller_id = Uuid::new_v4(); // different from claim owner
        let auth = make_auth(caller_id, &["claims:write"]);
        assert!(
            check_ownership(&auth, claim_agent_id).is_err(),
            "non-owner without claims:admin must be rejected"
        );
    }

    #[test]
    fn admin_scope_allows_cross_agent_supersede() {
        let claim_agent_id = Uuid::new_v4();
        let caller_id = Uuid::new_v4(); // different from claim owner
        let auth = make_auth(caller_id, &["claims:admin", "claims:write"]);
        assert!(
            check_ownership(&auth, claim_agent_id).is_ok(),
            "claims:admin holder must be allowed regardless of ownership"
        );
    }

    #[test]
    fn owner_without_admin_is_allowed() {
        let claim_agent_id = Uuid::new_v4();
        let auth = make_auth(claim_agent_id, &["claims:write"]); // caller IS the owner
        assert!(
            check_ownership(&auth, claim_agent_id).is_ok(),
            "the claim's own author must always be allowed"
        );
    }
}
