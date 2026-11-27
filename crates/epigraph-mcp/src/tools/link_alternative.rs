//! `link_alternative` — promote two claims into a mutually-exclusive
//! `alternative_of` pair, or mark two rival workflows reaching the same goal.
//!
//! Closes the loop `suggest_alternative_sets` documents: it proposes candidate
//! pairs and its own docstring says *"operator promotes by submitting an
//! explicit alternative_of edge"*, but no other MCP tool could write one —
//! `link_epistemic` rejects the relationship (its allow-list is the seven
//! belief-affecting relations) and `link_hierarchical` only takes structural
//! types. This tool writes the symmetric edge directly through the repo layer.
//!
//! Contract:
//! - both endpoints are of one type: two existing claims (the default), or,
//!   with `source_type`/`target_type` both `"workflow"`, two rival workflows
//!   (backlog 41d7b27a). Any other pair is refused,
//! - a workflow pair is held to `link_hierarchical`'s workflow-reference
//!   rules: both workflows readable and PUBLIC (the edges trigger takes no
//!   tenancy from a workflow end, so the edge would be stored public and name
//!   a private workflow to every reader), and authority over BOTH workflows
//!   (`require_workflow_authority`, the gate `add_step` and a
//!   `link_hierarchical` workflow source take), recorded as that gate's writes
//!   are: the pair is listed as `mutual` on each workflow's readers, so it is
//!   a statement about both, and neither owner's workflow is marked a rival by
//!   someone without a say over it. A `target_claim_id` on a workflow pair
//!   must be a PUBLIC claim, since the edge carrying it is stored public.
//!   CDST BP's alternative sets read claim-to-claim edges only
//!   (`FactorRepository::bp_alternative_sets`), so a workflow pair moves no
//!   belief,
//! - the edge is **symmetric**: `{claim_a, claim_b}` is one edge regardless of
//!   order (migration 042's `edges_alternative_of_symmetric_uniq`, which has no
//!   endpoint-type conjunct and so covers a workflow pair too), so the call
//!   is idempotent on the unordered pair,
//! - deliberately inert like `link_hierarchical`: no DS re-wire, no factor
//!   inserts, no `edge.added` event. The belief effect of an alternative set is
//!   realized later by CDST BP's max-plausibility combine over the
//!   `alternative_set` view (see `crates/epigraph-engine/src/cdst_bp.rs`), not
//!   at write time.

use rmcp::model::*;
use serde_json::{Map, Value};

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{LinkAlternativeParams, LinkAlternativeResponse};
use crate::write_identity::WriteIdentity;

use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, EdgeRepository};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

pub async fn link_alternative(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: LinkAlternativeParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    do_link_alternative(server, viewer, params, auth).await
}

/// Core wiring logic factored out so integration tests can call it directly
/// without round-tripping through the rmcp dispatch layer. Mirrors the
/// `do_link_hierarchical` factoring in `tools/link_hierarchical.rs`.
pub async fn do_link_alternative(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: LinkAlternativeParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let a = parse_uuid(&params.claim_a)?;
    let b = parse_uuid(&params.claim_b)?;
    let source_type = params.source_type.as_deref().unwrap_or("claim");
    let target_type = params.target_type.as_deref().unwrap_or("claim");
    let endpoint_type = match (source_type, target_type) {
        ("claim", "claim") => "claim",
        ("workflow", "workflow") => "workflow",
        (s, t) => {
            return Err(invalid_params(format!(
                "alternative_of links claim <-> claim or workflow <-> workflow, not {s} <-> {t}"
            )))
        }
    };

    // No self-loops — a claim cannot be its own alternative, and equal UUIDs
    // would also trip the symmetric index's LEAST==GREATEST degenerate key.
    if a == b {
        return Err(invalid_params(
            "self-loops are not allowed (claim_a and claim_b are the same claim)",
        ));
    }

    // ONE TRANSACTION, STAMPED FROM THE WRITE IDENTITY (the caller over HTTP, the server's own agent on stdio; batch H-b D1). Every read and
    // the INSERT run on it. Same reasoning as `link_hierarchical`: the INSERT on
    // the unstamped pool was admitted only for a world-owned edge (two public
    // endpoints), and the READS on it could not see a group-private endpoint at
    // all. So both have to move for a group-owned `alternative_of` edge to be
    // writable. An endpoint in another agent's private group is refused loudly
    // with nothing written (#374 owns whether it should be).
    let actor = server.write_identity(auth, viewer).await?;
    // This server's key attests the edge at INSERT. Resolved BEFORE the
    // transaction, as `link_hierarchical` resolves it: its first resolution
    // reads the pool, and a second pool connection taken while the write's
    // transaction holds one is the hold-and-wait shape (backlog bdc96181).
    let edge_key = server.edge_signing_key().await?;
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, actor, "link_alternative").await?;

    // Verify both endpoints exist via the repo layer (SQL stays in epigraph-db
    // per CLAUDE.md). Disambiguate which side is missing so the caller can fix
    // the right end of the pair.
    let mut grants = Vec::new();
    if endpoint_type == "workflow" {
        grants = rival_workflows_gate(server, &mut tx, viewer, auth, actor, a, b).await?;
    } else {
        if ClaimRepository::get_by_id(&mut *tx, viewer, ClaimId::from_uuid(a))
            .await
            .map_err(internal_error)?
            .is_none()
        {
            return Err(invalid_params(format!("claim_a {a} not found")));
        }
        if ClaimRepository::get_by_id(&mut *tx, viewer, ClaimId::from_uuid(b))
            .await
            .map_err(internal_error)?
            .is_none()
        {
            return Err(invalid_params(format!("claim_b {b} not found")));
        }
    }

    // Fold the optional context into the edge properties. Validate a supplied
    // target_claim_id so a typo'd UUID surfaces here rather than being silently
    // persisted on the edge.
    let mut props = Map::new();
    if let Some(t) = &params.target_claim_id {
        let tid = parse_uuid(t)?;
        if ClaimRepository::get_by_id(&mut *tx, viewer, ClaimId::from_uuid(tid))
            .await
            .map_err(internal_error)?
            .is_none()
        {
            return Err(invalid_params(format!("target_claim_id {tid} not found")));
        }
        // A workflow pair's edge is stored public (no claim endpoint gives it
        // tenancy), so the claim id it carries must be public too, or the
        // edge would hand a private claim's id to every reader.
        if endpoint_type == "workflow" {
            let tenancy = ClaimRepository::tenancy_of_conn(&mut tx, viewer, &[tid])
                .await
                .map_err(internal_error)?;
            if !tenancy.iter().any(|(_, v, _)| v == "public") {
                return Err(invalid_params(format!(
                    "refused: target_claim_id {tid} is not public. An alternative_of edge \
                     between two workflows is stored public, so the claim it names must be \
                     public too. Nothing was written."
                )));
            }
        }
        props.insert(
            "target_claim_id".to_string(),
            Value::String(tid.to_string()),
        );
    }
    if let Some(r) = &params.rationale {
        props.insert("rationale".to_string(), Value::String(r.clone()));
    }

    // Attested at INSERT by this server's key (R-49/R-50); a dedup hit
    // returns the existing edge unchanged.
    let (edge_id, created) = EdgeRepository::create_symmetric_if_absent_returning_signed_conn(
        &mut tx,
        Some(edge_key),
        a,
        b,
        endpoint_type,
        "alternative_of",
        Value::Object(props),
    )
    .await
    .map_err(internal_error)?;
    for (workflow_id, grant) in grants {
        crate::tools::workflow_authority::record_workflow_write(
            &mut tx,
            auth,
            actor,
            "link_alternative",
            workflow_id,
            grant,
            serde_json::json!({
                "edge_id": edge_id,
                "workflow_a": a,
                "workflow_b": b,
                "relationship": "alternative_of",
                "created": created,
            }),
        )
        .await?;
    }
    tx.commit().await.map_err(internal_error)?;

    success_json(&LinkAlternativeResponse {
        edge_id: edge_id.to_string(),
        created,
    })
}

/// The workflow pair's gate, on the write transaction, before anything is
/// written: both workflows readable (an unreadable one reports not found),
/// both PUBLIC, and authority over BOTH workflows, the rule
/// `link_hierarchical` applies to a symmetric `related_to`. Returns each
/// workflow's grant, for the write record.
async fn rival_workflows_gate(
    server: &EpiGraphMcpFull,
    tx: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    actor: WriteIdentity,
    a: uuid::Uuid,
    b: uuid::Uuid,
) -> Result<Vec<(uuid::Uuid, crate::tools::workflow_authority::WorkflowGrant)>, McpError> {
    for (side, id) in [("claim_a", a), ("claim_b", b)] {
        if !epigraph_db::WorkflowRepository::viewer_reads_row(&mut *tx, viewer, id)
            .await
            .map_err(internal_error)?
        {
            return Err(invalid_params(format!(
                "{side} {id} not found (no readable workflow has that id)"
            )));
        }
    }
    for (side, id) in [("claim_a", a), ("claim_b", b)] {
        let tenancy = epigraph_db::WorkflowRepository::tenancy_as_viewer(&mut *tx, viewer, id)
            .await
            .map_err(internal_error)?;
        if !matches!(tenancy.as_ref().map(|(v, _)| v.as_str()), Some("public")) {
            return Err(invalid_params(format!(
                "refused: the {side} workflow {id} is not public. An alternative_of edge takes \
                 its tenancy from claim endpoints only, so it would be stored public; rival \
                 workflows must both be public. Nothing was written."
            )));
        }
    }
    let mut grants = Vec::with_capacity(2);
    for (side, id) in [("claim_a", a), ("claim_b", b)] {
        let not_found = move || invalid_params(format!("{side} workflow {id} not found"));
        let grant = crate::tools::workflow_authority::require_workflow_authority(
            server,
            &mut *tx,
            auth,
            actor,
            viewer,
            id,
            "link_alternative",
            &not_found,
        )
        .await?;
        grants.push((id, grant));
    }
    Ok(grants)
}
