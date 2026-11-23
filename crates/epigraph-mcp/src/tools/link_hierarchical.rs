//! `link_hierarchical` — cross-tier structural edge creation between claims.
//!
//! Counterpart to the new `POST /api/v1/edges/hierarchical` HTTP endpoint.
//! Bypasses HTTP and goes directly through `EdgeRepository::create_if_not_exists`
//! so per-chapter ingest wiring (e.g. chapter thesis → book thesis,
//! chapter[N] → chapter[N+1]) can continue from a Claude Code session even
//! when the API binary is unavailable.
//!
//! Tight contract — narrower than the generic `POST /api/v1/edges` route:
//! - `relationship` must be one of `HIERARCHICAL_RELATIONSHIPS` (claim to
//!   claim), `WORKFLOW_REFERENCE_RELATIONSHIPS` (backlogs 03d87e3a and
//!   41d7b27a: `executes` workflow -> claim, `invokes` workflow|claim ->
//!   workflow, `depends_on` workflow -> workflow) or
//!   `AGENT_ATTRIBUTION_RELATIONSHIPS` (backlog c6949159: `asserts` agent ->
//!   claim),
//! - both endpoints must exist and be readable; their types default to
//!   `"claim"`, are validated against the `entity_types` registry, and must be
//!   a pair the relationship admits ([`endpoint_types_for`]),
//! - a workflow SOURCE requires authority over that workflow
//!   (`require_workflow_authority`, the gate `add_step` uses), and the write
//!   is recorded as that gate's writes are. A step-claim source of `invokes`
//!   requires that authority over every workflow executing the step, and a
//!   claim no workflow executes is refused,
//! - `executes` writes from the HEAD generation of a lineage only (as
//!   `add_step` does), so a frozen older generation's plan is not extended;
//!   its target is a claim of the plan's own lineage (any level: the repair
//!   path), or a workflow STEP the caller or the submitter wrote
//!   (`WorkflowRepository::is_step_shaped`, backlog 298317a7),
//! - `invokes` and `depends_on` refuse a NON-PUBLIC workflow endpoint: the
//!   edges trigger derives an edge's tenancy from its claim endpoints only
//!   (a workflow endpoint counts as public), so such an edge would be stored
//!   public and name the private workflow to every reader,
//! - `asserts` credits its source agent with the claim, so only that agent or
//!   the human operating it through a live binding may write it
//!   (`AgentRepository::speaks_for`, the HTTP route's rule, no admin arm); an
//!   agent's edge onto a public claim is world-owned, like the HTTP route's,
//!   so `owned_by_caller` is false and its writer cannot retract it,
//! - `invokes`, `depends_on` and `executes` refuse an edge that would close a
//!   cycle through `invokes` / `executes` (or `depends_on`) edges the caller
//!   reads; the check and the insert are serialized per relationship set,
//! - `properties` may not carry a reserved key
//!   (`epigraph_db::RESERVED_EDGE_PROPERTIES`), refused with the HTTP edges
//!   route's text (`epigraph_db::reserved_edge_property_refusal`),
//! - the call is idempotent on `(source, target, relationship)`.
//!
//! Intentionally side-effect-free vs the generic POST: no DS recomputation,
//! no factor inserts, no `edge.added` event, no provenance. These structural
//! edges carry no evidential semantics and the matching `ingest_document`
//! flow treats them the same way.
//!
//! Residual, stated: a reference between two public workflows (or from a
//! public step claim to one) is outside `epigraph_edge_writer_scope`, so it is
//! world-owned like the `executes` edges `store_workflow` writes, and
//! `owned_by_caller` is false: its writer cannot patch or retract it, which
//! takes maintenance. Widening that scope to workflow endpoints is a
//! migration.

use rmcp::model::*;

use crate::errors::{internal_error, internal_error_logged, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{LinkHierarchicalParams, LinkHierarchicalResponse};

use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, EdgeRepository};

/// Allowed relationship strings — mirror of
/// `epigraph_api::routes::edges::HIERARCHICAL_RELATIONSHIPS`. Kept as a local
/// constant so the MCP crate does not take a code dep on the API crate.
pub const HIERARCHICAL_RELATIONSHIPS: &[&str] =
    &["decomposes_to", "section_follows", "continues_argument"];

/// The workflow references (backlogs 03d87e3a, 41d7b27a), all structural and
/// belief-neutral. Kept apart from [`HIERARCHICAL_RELATIONSHIPS`], which
/// mirrors the HTTP hierarchical route's claim-only list.
pub const WORKFLOW_REFERENCE_RELATIONSHIPS: &[&str] = &["executes", "invokes", "depends_on"];

/// The agent attribution this tool writes (backlog c6949159): `asserts`,
/// agent -> claim, the edge that attributes a claim to the agent asserting it.
/// It credits the agent with the claim's content, so only that agent or the
/// human operating it through a live binding may write it
/// (`epigraph_db::credited_agent_end`, `AgentRepository::speaks_for`: the rule
/// `POST /api/v1/edges` applies).
pub const AGENT_ATTRIBUTION_RELATIONSHIPS: &[&str] = &["asserts"];

/// The `(source_type, target_type)` pairs `relationship` admits; empty for a
/// relationship this tool does not write.
///
/// - the document-structure relationships stay claim to claim;
/// - `executes`: a workflow runs a step claim (the edge `store_workflow` and
///   `add_step` write; this is its repair path);
/// - `invokes`: a sub-workflow reference, from a workflow or from one of its
///   step claims;
/// - `depends_on`: a prerequisite workflow;
/// - `asserts`: an agent asserts a claim (its attribution).
#[must_use]
pub fn endpoint_types_for(relationship: &str) -> &'static [(&'static str, &'static str)] {
    match relationship {
        "decomposes_to" | "section_follows" | "continues_argument" => &[("claim", "claim")],
        "executes" => &[("workflow", "claim")],
        "invokes" => &[("workflow", "workflow"), ("claim", "workflow")],
        "depends_on" => &[("workflow", "workflow")],
        "asserts" => &[("agent", "claim")],
        _ => &[],
    }
}

/// The relationships a cycle through a new `relationship` edge is walked
/// along, or `None` when the relationship is not cycle-checked.
///
/// `invokes` walks `executes` too: a step claim's `invokes` belongs to the
/// workflow that executes the step, so `W1 -executes-> S1 -invokes-> W2`
/// followed by `W2 -invokes-> W1` is a cycle. `executes` walks the same
/// pair: `W -executes-> S` closes a loop when `S` already invokes back to `W`.
#[must_use]
pub fn cycle_walk_for(relationship: &str) -> Option<&'static [&'static str]> {
    match relationship {
        "invokes" | "executes" => Some(&["invokes", "executes"]),
        "depends_on" => Some(&["depends_on"]),
        _ => None,
    }
}

/// Whether `relationship`'s edges must not touch a non-public workflow: the
/// workflow-to-workflow and claim-to-workflow references, whose tenancy the
/// edges trigger cannot derive from the workflow end (`executes` takes its
/// step claim's tenancy, as `add_step`'s edges do).
#[must_use]
pub fn requires_public_workflow_endpoints(relationship: &str) -> bool {
    matches!(relationship, "invokes" | "depends_on")
}

fn is_hierarchical_relationship(s: &str) -> bool {
    HIERARCHICAL_RELATIONSHIPS.contains(&s)
        || WORKFLOW_REFERENCE_RELATIONSHIPS.contains(&s)
        || AGENT_ATTRIBUTION_RELATIONSHIPS.contains(&s)
}

/// Whether the `(id, entity_type)` endpoint exists for `viewer`, on the
/// stamped transaction. Only the types [`endpoint_types_for`] names reach
/// here.
async fn endpoint_exists(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    id: uuid::Uuid,
    entity_type: &str,
) -> Result<bool, McpError> {
    match entity_type {
        "claim" => Ok(
            ClaimRepository::get_by_id(&mut *conn, viewer, ClaimId::from_uuid(id))
                .await
                .map_err(internal_error)?
                .is_some(),
        ),
        "workflow" => epigraph_db::WorkflowRepository::viewer_reads_row(&mut *conn, viewer, id)
            .await
            .map_err(internal_error),
        // Agent rows are universally readable (their public key renders
        // authorship), so existence needs no viewer.
        "agent" => Ok(epigraph_db::AgentRepository::get_by_id(
            &mut *conn,
            epigraph_core::AgentId::from_uuid(id),
        )
        .await
        .map_err(internal_error)?
        .is_some()),
        other => Err(internal_error_logged(
            "link_hierarchical: no existence check for this entity type",
            format!("entity type '{other}'"),
        )),
    }
}

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

pub async fn link_hierarchical(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: LinkHierarchicalParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    do_link_hierarchical(server, viewer, params, auth).await
}

/// Core wiring logic factored out so integration tests can call it directly
/// without round-tripping through the rmcp dispatch layer. Mirrors the
/// `do_ingest_document` factoring in `tools/ingestion.rs`.
pub async fn do_link_hierarchical(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: LinkHierarchicalParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let source_id = parse_uuid(&params.source_claim_id)?;
    let target_id = parse_uuid(&params.target_claim_id)?;
    let source_type = params.source_type.as_deref().unwrap_or("claim");
    let target_type = params.target_type.as_deref().unwrap_or("claim");

    // Tight allow-list — narrower than VALID_RELATIONSHIPS on purpose. New
    // entries must come from `HIERARCHICAL_RELATIONSHIPS` or
    // `WORKFLOW_REFERENCE_RELATIONSHIPS`.
    if !is_hierarchical_relationship(&params.relationship) {
        return Err(invalid_params(format!(
            "invalid relationship '{}'. Valid hierarchical types: {}. Valid workflow references: \
             {}. Valid agent attribution: {}",
            params.relationship,
            HIERARCHICAL_RELATIONSHIPS.join(", "),
            WORKFLOW_REFERENCE_RELATIONSHIPS.join(", "),
            AGENT_ATTRIBUTION_RELATIONSHIPS.join(", "),
        )));
    }

    // No self-loops: equal UUIDs always loop (ids are unique across tables).
    if source_id == target_id {
        return Err(invalid_params(
            "self-loops are not allowed (source and target are the same entity)",
        ));
    }
    // The keys only an act or the document ingest writes (backlog 3676c459),
    // checked on the caller's own `properties` before `at_step` is merged in:
    // refused with the HTTP edges route's text, as `patch_edge` refuses them.
    if let Some(reason) = params
        .properties
        .as_ref()
        .and_then(epigraph_db::reserved_edge_property_refusal)
    {
        return Err(invalid_params(reason));
    }
    if params.at_step.is_some() && params.relationship != "invokes" {
        return Err(invalid_params(format!(
            "at_step is only meaningful for invokes, not '{}'",
            params.relationship
        )));
    }

    // ONE TRANSACTION, STAMPED FROM THE WRITE IDENTITY (the caller over HTTP, the server's own agent on stdio; batch H-b D1). The two
    // existence reads and the INSERT all run on it.
    //
    // The INSERT used to run on the unstamped pool. `edges_tenancy`'s WITH CHECK
    // then admitted only what its static arm admits: an edge between two PUBLIC
    // claims, which 070's BEFORE trigger makes world-owned. An edge touching a
    // group-private claim is owned by that claim's group, and on a
    // cleanly-migrated schema it was refused. Production admitted it only through
    // the orphan `edges_privacy` policy that R3 drops.
    //
    // The READS move too, and they are what make the stamp able to succeed. On
    // an unstamped session `claims_tenancy`'s USING admits only public rows, so a
    // group-private endpoint read "not found" before the INSERT was reached.
    // Converting only the INSERT would have been a conversion its own target
    // population could never reach.
    //
    // THE STAMP IS THE WRITE IDENTITY's (`EpiGraphMcpFull::write_identity`), as for every other MCP write: the edge
    // is owned by an endpoint's group, and the population this admits is the
    // server agent's own claims. An endpoint in another agent's private group is
    // refused loudly by the WITH CHECK (or, for a co-owned edge, by RETURNING's
    // intersection read) and nothing is written. Whether a caller should carry
    // write authority into a group this process cannot write is the cross-agent
    // ownership question (#374), not a stamping one.
    let actor = server.write_identity(auth, viewer).await?;
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, actor, "link_hierarchical").await?;

    // Endpoint types: registered (the `entity_types` registry, as the HTTP
    // edges route validates them), then a pair this relationship admits.
    for (side, ty) in [("source_type", source_type), ("target_type", target_type)] {
        if epigraph_db::EntityTypeRepository::get_by_name_conn(&mut tx, ty)
            .await
            .map_err(internal_error)?
            .is_none()
        {
            return Err(invalid_params(format!(
                "{side} '{ty}' is not a registered entity type"
            )));
        }
    }
    let admitted = endpoint_types_for(&params.relationship);
    if !admitted.contains(&(source_type, target_type)) {
        let pairs: Vec<String> = admitted
            .iter()
            .map(|(s, t)| format!("{s} -> {t}"))
            .collect();
        return Err(invalid_params(format!(
            "'{}' does not link {source_type} -> {target_type}. It links: {}",
            params.relationship,
            pairs.join(", "),
        )));
    }

    // Verify both endpoints exist via the repo layer (per CLAUDE.md, SQL stays
    // in epigraph-db). Disambiguate which side is missing so the caller can
    // fix the right end of the link.
    if !endpoint_exists(&mut tx, viewer, source_id, source_type).await? {
        return Err(invalid_params(format!(
            "source_claim_id {source_id} not found (no readable {source_type} has that id)"
        )));
    }
    if !endpoint_exists(&mut tx, viewer, target_id, target_type).await? {
        return Err(invalid_params(format!(
            "target_claim_id {target_id} not found (no readable {target_type} has that id)"
        )));
    }

    // An edge that credits an agent with content (`asserts` from it, backlog
    // c6949159) puts words in that agent's mouth: only the agent itself, or
    // the human operating it through a binding in force, may write it. The
    // HTTP edges route's rule and refusal text, and like it no admin arm.
    if let Some(end) =
        epigraph_db::credited_agent_end(source_type, target_type, &params.relationship)
    {
        let credited = match end {
            epigraph_db::CreditedEnd::Source => source_id,
            epigraph_db::CreditedEnd::Target => target_id,
        };
        let speaks =
            epigraph_db::AgentRepository::speaks_for(&mut *tx, actor.agent_id(), &[credited])
                .await
                .map_err(internal_error)?
                .contains_key(&credited);
        if !speaks {
            return Err(invalid_params(epigraph_db::AGENT_ATTRIBUTION_REFUSAL));
        }
    }

    // A reference touching a non-public workflow would be stored public
    // (`epigraph_node_tenancy` treats a workflow endpoint as tenancy-less), so
    // it is refused before anything is written. Both endpoints were read
    // through the caller's viewer above, so this names nothing it cannot read.
    if requires_public_workflow_endpoints(&params.relationship) {
        for (side, id, ty) in [
            ("source", source_id, source_type),
            ("target", target_id, target_type),
        ] {
            if ty != "workflow" {
                continue;
            }
            let tenancy = epigraph_db::WorkflowRepository::tenancy_as_viewer(&mut tx, viewer, id)
                .await
                .map_err(internal_error)?;
            if !matches!(tenancy.as_ref().map(|(v, _)| v.as_str()), Some("public")) {
                return Err(invalid_params(format!(
                    "refused: the {side} workflow {id} is not public. A '{}' edge takes its \
                     tenancy from claim endpoints only, so it would be stored public; references \
                     to a non-public workflow are not supported yet. Nothing was written.",
                    params.relationship
                )));
            }
        }
    }

    // A workflow SOURCE changes what that workflow runs or references, so it
    // takes the authority `add_step` takes over it (backlog 03d87e3a: "under
    // the same authority checks"), decided before anything is written. A
    // step-claim source of `invokes` is that step's workflows' reference
    // ([`cycle_walk_for`]), so it takes the same authority over EVERY
    // workflow that executes the step's lineage; a claim no workflow executes
    // is not a step and is refused.
    let governed: Vec<uuid::Uuid> = if source_type == "workflow" {
        vec![source_id]
    } else if params.relationship == "invokes" {
        let executing =
            epigraph_db::WorkflowRepository::workflows_executing_step_lineage(&mut tx, source_id)
                .await
                .map_err(internal_error)?;
        if executing.is_empty() {
            return Err(invalid_params(format!(
                "refused: claim {source_id} is not a step of any workflow (nothing executes it). \
                 An invokes from a claim belongs to the workflow running that step. Nothing was \
                 written."
            )));
        }
        executing
    } else {
        Vec::new()
    };
    let mut grants = Vec::with_capacity(governed.len());
    for workflow_id in governed {
        let not_found = move || invalid_params(format!("workflow {workflow_id} not found"));
        let grant = crate::tools::workflow_authority::require_workflow_authority(
            server,
            &mut tx,
            auth,
            actor,
            viewer,
            workflow_id,
            "link_hierarchical",
            &not_found,
        )
        .await?;
        grants.push((workflow_id, grant));
    }

    // `executes` extends a plan, which `add_step` does only on the head of a
    // lineage: an older generation is frozen (a pinned generation is verified
    // against exactly its `executes` edges), so its plan is not repaired here.
    if params.relationship == "executes" {
        let names = epigraph_db::WorkflowRepository::canonical_names_of(&mut *tx, &[source_id])
            .await
            .map_err(internal_error)?;
        let head = match names.first() {
            Some(name) => epigraph_db::WorkflowRepository::head_by_canonical(&mut *tx, name)
                .await
                .map_err(internal_error)?,
            None => None,
        };
        if head != Some(source_id) {
            return Err(invalid_params(format!(
                "refused: workflow {source_id} is not the head generation of its lineage; \
                 executes is written to the head only (an older generation's plan is frozen). \
                 Nothing was written."
            )));
        }

        // The target must already be THIS plan's step: a claim whose step
        // lineage a generation of this lineage executes (the repair of a
        // dropped edge; retracted edges count), or one written by the caller
        // or by the workflow's submitter. Otherwise any workflow owner could
        // adopt another agent's public claim as a step, and every gate that
        // takes authority over "the workflows executing this step"
        // (`evolve_step`, a step-claim `invokes`) would then answer to them.
        let lineage_name = names.first().cloned().unwrap_or_default();
        let executing =
            epigraph_db::WorkflowRepository::workflows_executing_step_lineage(&mut tx, target_id)
                .await
                .map_err(internal_error)?;
        let executing_names =
            epigraph_db::WorkflowRepository::canonical_names_of(&mut *tx, &executing)
                .await
                .map_err(internal_error)?;
        let in_lineage = executing_names.contains(&lineage_name);
        if !in_lineage {
            let author =
                ClaimRepository::get_by_id(&mut *tx, viewer, ClaimId::from_uuid(target_id))
                    .await
                    .map_err(internal_error)?
                    .map(|c| c.agent_id.as_uuid());
            let submitter = epigraph_db::WorkflowRepository::submitter_of(&mut *tx, source_id)
                .await
                .map_err(internal_error)?;
            let own = author.is_some_and(|a| a == actor.agent_id() || Some(a) == submitter);
            if !own {
                return Err(invalid_params(format!(
                    "refused: claim {target_id} is not a step of this workflow's lineage, and \
                     neither the caller nor the workflow's submitter wrote it. executes repairs \
                     or extends this plan with its own steps; it does not adopt another agent's \
                     claim. Nothing was written."
                )));
            }
            // An own claim is adopted only when it is a STEP (backlog
            // 298317a7): plan readers and the outcome reports take every
            // level-2 `executes` target as one, so an ordinary claim (or a
            // level-2 paragraph, which has no step lineage) is refused. The
            // in-lineage branch above repairs every level, as the executor
            // writes `executes` to the thesis and phases too.
            if !epigraph_db::WorkflowRepository::is_step_shaped(&mut tx, viewer, target_id)
                .await
                .map_err(internal_error)?
            {
                return Err(invalid_params(format!(
                    "refused: claim {target_id} is not a step of this workflow's lineage, and it \
                     is not a workflow step (a plan level-2 claim with a step lineage, as \
                     store_workflow, add_step and evolve_step write). executes adopts only a \
                     step; add_step writes a new one. Nothing was written."
                )));
            }
        }

        // A workflow endpoint has no tenancy of its own in the edges trigger
        // (070), so the edge takes the claim's. From a non-public workflow
        // that would name the plan in an edge readable more widely than the
        // plan itself: the target claim must carry the plan's own tenancy,
        // as the steps `add_step` writes do.
        let plan = epigraph_db::WorkflowRepository::tenancy_as_viewer(&mut tx, viewer, source_id)
            .await
            .map_err(internal_error)?;
        if let Some((plan_vis, plan_owner)) = plan.filter(|(v, _)| v != "public") {
            let claim = ClaimRepository::tenancy_of_conn(&mut tx, viewer, &[target_id])
                .await
                .map_err(internal_error)?;
            let matches = claim
                .first()
                .is_some_and(|(_, v, g)| *v == plan_vis && *g == plan_owner);
            if !matches {
                return Err(invalid_params(format!(
                    "refused: workflow {source_id} is not public, and claim {target_id} does not \
                     carry its tenancy. The executes edge would take the claim's tenancy and name \
                     the plan more widely than the plan itself is readable. Nothing was written."
                )));
            }
        }
    }

    // Cycle refusal (backlog 41d7b27a): `source -rel-> target` closes a cycle
    // exactly when `target` already reaches `source`.
    if let Some(walk) = cycle_walk_for(&params.relationship) {
        if EdgeRepository::reaches_in_force_conn(&mut tx, target_id, source_id, walk)
            .await
            .map_err(internal_error)?
        {
            return Err(invalid_params(format!(
                "refused: {source_type} {source_id} {} {target_type} {target_id} would close a \
                 cycle ({target_id} already reaches {source_id} through {}). Nothing was written.",
                params.relationship,
                walk.join(" / "),
            )));
        }
    }

    let mut properties = params.properties.clone();
    if let Some(step) = params.at_step {
        let mut obj = match properties.take() {
            None => serde_json::Map::new(),
            Some(serde_json::Value::Object(m)) => m,
            Some(_) => {
                return Err(invalid_params(
                    "properties must be a JSON object when at_step is given",
                ))
            }
        };
        obj.insert("at_step".to_string(), serde_json::json!(step));
        properties = Some(serde_json::Value::Object(obj));
    }

    // Attested at INSERT by this server's key (R-49/R-50); a dedup hit
    // returns the existing edge unchanged.
    let (edge_row, was_created) = EdgeRepository::create_if_not_exists_signed_conn(
        &mut tx,
        Some(server.edge_signing_key().await?),
        source_id,
        source_type,
        target_id,
        target_type,
        &params.relationship,
        properties,
        None,
        None,
    )
    .await
    .map_err(internal_error)?;
    for (workflow_id, grant) in grants {
        crate::tools::workflow_authority::record_workflow_write(
            &mut tx,
            auth,
            actor,
            "link_hierarchical",
            workflow_id,
            grant,
            serde_json::json!({
                "edge_id": edge_row.id,
                "source_id": source_id,
                "source_type": source_type,
                "relationship": params.relationship,
                "target_id": target_id,
                "target_type": target_type,
                "created": was_created,
            }),
        )
        .await?;
    }
    let owned_by_caller = EdgeRepository::owned_by_session(&mut *tx, edge_row.id)
        .await
        .map_err(internal_error)?;
    tx.commit().await.map_err(internal_error)?;

    success_json(&LinkHierarchicalResponse {
        edge_id: edge_row.id.to_string(),
        created: was_created,
        owned_by_caller,
    })
}
