use rmcp::model::{CallToolResult, Content};

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{MarkDuplicateParams, SupersedeClaimParams};
use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::ClaimRepository;

pub async fn supersede_claim(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: SupersedeClaimParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let old = parse_uuid(&params.claim_id)?;
    let old_claim_id = ClaimId::from_uuid(old);

    // ONE TRANSACTION, STAMPED FROM THE WRITE IDENTITY (the caller over HTTP,
    // the server's own agent on stdio; batch H-b D1), for the gate read and the
    // supersession, the same construction as `patch_claim` and `update_labels`.
    //
    // This was `get_by_id(&server.pool, ..)` then `supersede(&server.pool, ..)`:
    // unstamped, so on a schema without the orphan `*_privacy` policies (config
    // A) the server agent's OWN public claim was refused with 42501 and its own
    // group-private claim read as "not found" (MEASURED, batch H-a review). The
    // stamp admits the claims the CALLER's groups own — for an operated stdio
    // agent that includes its operator's group, which is where a same-operator
    // sibling's claims live (#503, backlog 6d42f494). A claim in a group the
    // caller cannot write is refused loudly, and nothing commits: a
    // `claims:admin` caller superseding into a group it cannot write is NOT
    // lent anyone's stamp (the audited admin path covers labels and patches,
    // not supersession; see `tools::admin_write`).
    let caller = server.write_identity(auth, viewer).await?;
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, caller, "supersede_claim").await?;

    // Per-resource ownership check: only the claim's author or a
    // claims:admin token holder may supersede it. The read is the CALLER's,
    // through its viewer, on the same transaction.
    let existing = ClaimRepository::get_by_id(&mut *tx, viewer, old_claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {} not found", old)))?;
    crate::tools::claims::require_owner_or_admin(server, auth, caller, existing.agent_id.as_uuid())
        .await?;

    let truth = TruthValue::clamped(params.truth_value);
    let (new_id, old_id) = ClaimRepository::supersede_conn(
        &mut tx,
        old_claim_id,
        &params.content,
        truth,
        &params.reason,
    )
    .await
    .map_err(internal_error)?;
    tx.commit().await.map_err(internal_error)?;

    // Retraction cascade (backlog 20e9ed83): the supporters this claim was
    // feeding hold BBAs frozen from ITS interval at wire time, so without an
    // explicit invalidation pass they keep believing a retracted claim
    // forever. Best-effort by construction — the supersede transaction has
    // already committed, and failing the call here would hand the caller an
    // error for a write that succeeded (the retry then hits "already been
    // superseded"). Enumerated from the REPLACEMENT id: supersede re-points
    // outgoing edges onto it inside the transaction.
    //
    // Reported rather than silent so a caller reading a downstream claim
    // straight after this call can see exactly what was repaired.
    //
    // STAMPED FROM THE CALLER (batch H-b). It ran on the unstamped pool, where a
    // clean schema (config A) refuses every downstream write, so the cascade
    // repaired nothing there and reported errors for every target. The walk's
    // targets are owned by arbitrary groups, so no single stamp covers all of
    // them — which is why it runs on ONE transaction stamped with the authority
    // that performed the retraction, and the engine takes a SAVEPOINT per edge
    // and per target: a target the caller cannot write fails ALONE, is rolled
    // back (its stale BBA is kept, not deleted with no re-derivation), and is
    // named in `belief_cascade.errors`, while every target the caller can
    // write is repaired. A downstream owner that is not the caller keeps the
    // retracted supporter until it, or an admin, re-asserts the edge.
    let cascade = supersede_cascade_stamped(server, viewer, caller, new_id).await;

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "new_claim_id": new_id,
            "superseded_claim_id": old_id,
            "reason": params.reason,
            "belief_cascade": cascade,
        }))
        .map_err(internal_error)?,
    )]))
}

/// Run [`epigraph_engine::retraction_cascade::cascade_after_supersede`] on ONE
/// transaction stamped from `caller`, committing what it repaired.
///
/// Never fails, as the cascade never does: a stamp or commit failure is
/// reported in the returned report's `errors`, because the supersession it
/// follows has already committed.
async fn supersede_cascade_stamped(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    caller: crate::write_identity::WriteIdentity,
    new_id: uuid::Uuid,
) -> epigraph_engine::retraction_cascade::CascadeReport {
    let mut tx = match crate::claim_helper::begin_author_stamped_tx(
        server,
        caller,
        "supersede_claim_cascade",
    )
    .await
    {
        Ok(tx) => tx,
        Err(e) => {
            let mut report = epigraph_engine::retraction_cascade::CascadeReport::default();
            report.errors.push(format!(
                "could not stamp the retraction cascade: {}",
                e.message
            ));
            return report;
        }
    };
    let mut report =
        epigraph_engine::retraction_cascade::cascade_after_supersede(&mut tx, viewer, new_id).await;
    if let Err(e) = tx.commit().await {
        report.errors.push(format!(
            "the retraction cascade could not commit, so none of its repairs landed: {e}"
        ));
    }
    report
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
    let caller = server.write_identity(auth, viewer).await?;

    // ONE TRANSACTION, STAMPED FROM THE CALLER (batch H-b): the gate read, the
    // dedup and its cascade. The dedup used to run on the unstamped pool, where
    // a clean schema (config A) read the caller's own group-private duplicate as
    // "not found" and refused its own public one with 42501.
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, caller, "mark_duplicate").await?;

    // Per-resource ownership check: the duplicate's author, an agent acting for
    // its operator, or a claims:admin token holder may mark it as a duplicate.
    let dup_claim = ClaimRepository::get_by_id(&mut *tx, viewer, dup_claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {} not found", dup)))?;
    crate::tools::claims::require_owner_or_admin(
        server,
        auth,
        caller,
        dup_claim.agent_id.as_uuid(),
    )
    .await?;

    // Dedup repairs the derived-record layer (orphaned + stranded edge-factor
    // BBAs) and hands back what still has to be re-derived through the DS
    // pipeline. Same best-effort contract as supersede: the dedup's own failure
    // is an error and rolls everything back; the cascade's is reported, one
    // savepoint per edge and per target (see `supersede_claim`).
    let cascade = epigraph_engine::retraction_cascade::mark_duplicate_with_cascade(
        &mut tx,
        viewer,
        dup_claim_id.into(),
        canon,
    )
    .await
    .map_err(internal_error)?;
    tx.commit().await.map_err(internal_error)?;

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "duplicate_id": dup,
            "canonical_id": canon,
            "mode": "mark_duplicate",
            "belief_cascade": cascade,
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
