use rmcp::model::{CallToolResult, Content};

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{MarkDuplicateParams, SupersedeClaimParams};
use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::ClaimRepository;
use epigraph_engine::admin_cascade::{
    self, CascadeCause, CascadeStatus, CascadeTrigger, OauthPrincipal,
};
use epigraph_engine::retraction_cascade::CascadeReport;

/// The OAuth principal behind an authenticated call, for the cascade's audit row.
pub(crate) fn oauth_principal(auth: Option<&epigraph_auth::AuthContext>) -> Option<OauthPrincipal> {
    auth.map(|a| OauthPrincipal {
        client_id: Some(a.client_id),
        owner_id: a.owner_id,
        agent_id: a.agent_id,
    })
}

pub async fn supersede_claim(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: SupersedeClaimParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let old = parse_uuid(&params.claim_id)?;
    let old_claim_id = ClaimId::from_uuid(old);
    let author = server.agent_id().await?;

    // ONE TRANSACTION, STAMPED FROM THE MCP SERVER'S OWN AGENT, for the gate read
    // and the supersession's own act, the same construction as `patch_claim` and
    // `update_labels`.
    //
    // This was `get_by_id(&server.pool, ..)` then `supersede(&server.pool, ..)`:
    // unstamped, so on a schema without the orphan `*_privacy` policies (config
    // A) the server agent's OWN public claim was refused with 42501 and its own
    // group-private claim read as "not found" (MEASURED, batch H-a review). The
    // stamp admits the population this process writes, claims owned by the
    // server agent's groups. A claim in a group it cannot write is refused
    // loudly, and nothing commits. Whether an authenticated caller should
    // supersede under ITS OWN stamp rather than the server agent's is the
    // authenticated-MCP stamping question recorded as an R3 blocker in
    // scripts/e2e/README.md, not this conversion's.
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, author, "supersede_claim").await?;

    // Per-resource ownership check: only the claim's author or a
    // claims:admin token holder may supersede it. The read is the CALLER's,
    // through its viewer, on the same transaction.
    let existing = ClaimRepository::get_by_id(&mut *tx, viewer, old_claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {} not found", old)))?;
    crate::tools::claims::require_owner_or_admin(server, auth, existing.agent_id.as_uuid()).await?;

    // THE ACT (migration 117): retire the claim, insert the replacement and the
    // `supersedes` edge. It does NOT migrate the old claim's other edges: an
    // incoming edge is its source writer's assertion, and re-pointing another
    // writer's edge is the administrative cascade's job below.
    let truth = TruthValue::clamped(params.truth_value);
    let (new_id, old_id) = ClaimRepository::supersede_act_conn(
        &mut tx,
        old_claim_id,
        &params.content,
        truth,
        &params.reason,
    )
    .await
    .map_err(internal_error)?;

    let trigger = CascadeTrigger {
        cause: CascadeCause::Supersede,
        agent_id: Some(author),
        oauth: oauth_principal(auth),
        subject_id: old_id,
        object_id: Some(new_id),
    };
    // No administrative connection: the deferral is recorded in the act's own
    // transaction, attributed to the principal it is stamped with, so the act
    // and its audit row commit together (or neither does).
    let deferred = if crate::maintenance::admin_cascade_configured(server) {
        None
    } else {
        Some(
            admin_cascade::record_deferral(
                &mut *tx,
                &trigger,
                admin_cascade::REASON_NOT_CONFIGURED,
            )
            .await
            .map_err(internal_error)?,
        )
    };
    tx.commit().await.map_err(internal_error)?;

    // THE CASCADE (backlog 20e9ed83; migration 117): migrate the retired
    // claim's edges onto the replacement, then invalidate the BBAs its
    // supporters froze from ITS interval and re-derive them. It runs with
    // ADMINISTRATIVE authority, on the server's maintenance connection and its
    // bypass viewer, because the edges and BBAs it rewrites belong to other
    // writers; it writes one `security_events` row naming this caller.
    // Best-effort by construction: the act has committed, and failing the call
    // here would hand the caller an error for a write that succeeded (the retry
    // then hits "already been superseded"). Reported, so a caller reading a
    // downstream claim straight after this call can see what was repaired.
    let (cascade, belief_cascade) = match deferred {
        Some(status) => (status, CascadeReport::default()),
        None => match crate::maintenance::admin_cascade_session(server).await {
            Ok(mut session) => {
                let (conn, v) = session.split();
                admin_cascade::apply_after_supersede(conn, v, &trigger, old_id, new_id).await
            }
            Err(reason) => (
                record_deferral_after_commit(server, &trigger, &reason).await,
                CascadeReport::default(),
            ),
        },
    };

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "new_claim_id": new_id,
            "superseded_claim_id": old_id,
            "reason": params.reason,
            "cascade": cascade,
            "belief_cascade": belief_cascade,
        }))
        .map_err(internal_error)?,
    )]))
}

/// Record a deferral AFTER the act committed (the administrative connection was
/// configured but could not be used). Best-effort: the act has committed, so a
/// failure to write the row is reported in the result rather than raised.
pub(crate) async fn record_deferral_after_commit(
    server: &EpiGraphMcpFull,
    trigger: &CascadeTrigger,
    reason: &str,
) -> CascadeStatus {
    let author = match trigger.agent_id {
        Some(a) => a,
        None => {
            return CascadeStatus::deferred_unaudited(reason, "no principal to attribute it to")
        }
    };
    match crate::claim_helper::begin_author_stamped_tx(server, author, "admin_cascade_deferral")
        .await
    {
        Ok(mut tx) => match admin_cascade::record_deferral(&mut *tx, trigger, reason).await {
            Ok(status) => match tx.commit().await {
                Ok(()) => status,
                Err(e) => CascadeStatus::deferred_unaudited(reason, e),
            },
            Err(e) => CascadeStatus::deferred_unaudited(reason, e),
        },
        Err(e) => CascadeStatus::deferred_unaudited(reason, e.message),
    }
}

pub async fn mark_duplicate(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: MarkDuplicateParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let dup = parse_uuid(&params.claim_id)?;
    let canon = parse_uuid(&params.canonical_id)?;
    let dup_claim_id = ClaimId::from_uuid(dup);
    let author = server.agent_id().await?;

    // THE ACT, on ONE transaction STAMPED FROM THE MCP SERVER'S OWN AGENT, the
    // same authority `supersede_claim` above writes with: the ownership read,
    // then marking the duplicate. On an unstamped connection the duplicate's
    // `claims` row is refused by `claims_tenancy` on the application role, so
    // the tool could not dedup even the server agent's own claim. A duplicate
    // in a group the stamp cannot write is refused and nothing commits.
    // `begin_as` stamps a transaction in either GUC mode, so there is no
    // transaction-mode-pooler fallback any more.
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, author, "mark_duplicate").await?;

    // Per-resource ownership check: only the duplicate claim's author or a
    // claims:admin token holder may mark it as a duplicate.
    let dup_claim = ClaimRepository::get_by_id(&mut *tx, viewer, dup_claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {} not found", dup)))?;
    crate::tools::claims::require_owner_or_admin(server, auth, dup_claim.agent_id.as_uuid())
        .await?;

    ClaimRepository::mark_duplicate_act_conn(&mut tx, dup_claim_id, ClaimId::from_uuid(canon))
        .await
        .map_err(internal_error)?;

    let trigger = CascadeTrigger {
        cause: CascadeCause::Dedup,
        agent_id: Some(author),
        oauth: oauth_principal(auth),
        subject_id: dup,
        object_id: Some(canon),
    };
    let deferred = if crate::maintenance::admin_cascade_configured(server) {
        None
    } else {
        Some(
            admin_cascade::record_deferral(
                &mut *tx,
                &trigger,
                admin_cascade::REASON_NOT_CONFIGURED,
            )
            .await
            .map_err(internal_error)?,
        )
    };
    tx.commit().await.map_err(internal_error)?;

    // THE CASCADE (migration 117), with administrative authority on the
    // maintenance connection: retract the duplicate's colliding edges and drop
    // their BBAs, re-point every other edge onto the canonical, move the BBAs
    // that follow them, and re-derive what changed. Same best-effort contract
    // as supersede: the act's own failure is an error, the cascade's is
    // reported.
    let (cascade, belief_cascade) = match deferred {
        Some(status) => (status, CascadeReport::default()),
        None => match crate::maintenance::admin_cascade_session(server).await {
            Ok(mut session) => {
                let (conn, v) = session.split();
                admin_cascade::apply_after_dedup(conn, v, &trigger, dup, canon).await
            }
            Err(reason) => (
                record_deferral_after_commit(server, &trigger, &reason).await,
                CascadeReport::default(),
            ),
        },
    };

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "duplicate_id": dup,
            "canonical_id": canon,
            "mode": "mark_duplicate",
            "cascade": cascade,
            "belief_cascade": belief_cascade,
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
