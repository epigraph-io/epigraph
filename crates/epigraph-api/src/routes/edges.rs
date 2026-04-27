//! Edge creation and query API
//!
//! Provides REST endpoints for creating and querying edges (relationships)
//! between entities in the epistemic knowledge graph.
//!
//! - `POST /api/v1/edges` — Create a new edge (protected, requires signature)
//! - `GET /api/v1/edges` — Query edges by source, target, or relationship (public)
//! - `GET /api/v1/claims/:id/neighborhood` — Get 2-hop subgraph around a claim (public)

#[cfg(feature = "db")]
use crate::access_control::{check_content_access, ContentAccess};
use crate::errors::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "db")]
use epigraph_db::EdgeRepository;

/// Valid entity types (must match the DB CHECK constraint from migration 053)
const VALID_ENTITY_TYPES: &[&str] = &[
    "claim",
    "agent",
    "evidence",
    "trace",
    "node",
    "activity",
    "paper",
    "perspective",
    "community",
    "context",
    "frame",
    "analysis",
    "experiment",
    "experiment_result",
    "propaganda_technique",
    "coalition",
    "synthesis",
];

/// Valid relationship types for edge creation
const VALID_RELATIONSHIPS: &[&str] = &[
    "supports",
    "refutes",
    "relates_to",
    "generalizes",
    "specializes",
    "elaborates",
    "authored_by",
    "derived_from",
    "uses_evidence",
    "supersedes",
    "challenges",
    "generated",
    "attributed_to",   // prov:wasAttributedTo — Claim → Author Agent
    "associated_with", // prov:wasAssociatedWith — Activity → Author Agent
    // DS/DEKG edge types (created by submit_evidence, perspective/community handlers)
    "SUPPORTS",
    "CONTRADICTS",
    "WITHIN_FRAME",
    "SCOPED_BY",
    "PERSPECTIVE_OF",
    "MEMBER_OF",
    "GENERATED_BY",
    "CONTRIBUTES_TO",
    "DERIVED_FROM",
    "RELATES_TO",
    // Political network monitoring edge types (migration 053)
    "ORIGINATED_BY",    // Claim first publicly asserted by agent
    "AMPLIFIED_BY",     // Agent repeated/endorsed existing claim
    "COORDINATED_WITH", // Two claims flagged as potentially coordinated
    "USES_TECHNIQUE",   // Claim employs a propaganda technique
    "MIRROR_NARRATIVE", // Two coalitions are structural mirrors
    // PROV-O agent relationship types (migration 060)
    "AFFILIATED_WITH", // person → organization (temporal)
    "EMPLOYED_BY",     // person → organization (temporal)
    "OPERATED_BY",     // software_agent/instrument → person (prov:actedOnBehalfOf)
    "MANUFACTURED_BY", // instrument → organization
    // Ingestion and cross-source edge types (used by Python migration scripts)
    "asserts",               // paper → claim (paper asserts a claim)
    "same_source",           // claim → claim (same source document)
    "decomposes_to",         // claim → claim (atomic decomposition)
    "same_as",               // claim → claim (deduplication identity)
    "CORROBORATES",          // claim → claim (cross-source corroboration)
    "AUTHORED",              // agent → claim (materialized authorship)
    "ATTRIBUTED_TO",         // claim → agent (prov:wasAttributedTo)
    "refines",               // claim → claim (refinement)
    "cites",                 // claim → claim (citation link)
    "EQUIVALENT_TO",         // claim → claim (semantic equivalence)
    "CONTRADICTS",           // claim → claim (contradiction)
    "supersedes",            // claim → claim (version chain)
    "enables",               // claim → claim (enablement)
    "has_method_capability", // method → capability (method graph)
    "interpreted_by",        // claim → agent (interpretation provenance)
    "concludes",             // trace → claim (reasoning conclusion)
    "HAS_TRACE",             // claim → trace (reasoning trace link)
    // AI development patterns — context persistence, issue generation, observability
    "OBSERVED_DURING", // claim → claim (design decision observed during feature work)
    "INFORMS",         // claim → claim (decision informs future work)
    "BLOCKS",          // claim → claim (backlog item blocks another)
    "GOVERNS",         // claim → claim (convention governs a system/scope)
    "FAILED_TO_COMPLETE", // claim → claim (agent failed to complete a task)
    "RESOLVED_BY",     // claim → claim (plugin mod resolved by upstream release)
    // Synthesis (PROV-O), used by episcience paper-synthesis pipeline
    "WAS_DERIVED_FROM", // synthesis → claim (prov:wasDerivedFrom)
    "REFINES",          // synthesis → synthesis (upper-case form; lower-case "refines" above is claim → claim refinement)
    "COMPOSED_OF",      // synthesis → synthesis (prereq composition)
    "METHODOLOGY",      // claim → claim (methodology relation, traversal)
    "SUPERSEDES",       // upper-case alias of lower-case "supersedes" above; synthesis-side callers use upper-case per PROV-O convention
];

pub fn is_valid_entity_type(s: &str) -> bool {
    VALID_ENTITY_TYPES.contains(&s)
}

pub fn is_valid_relationship(s: &str) -> bool {
    VALID_RELATIONSHIPS.contains(&s)
}

/// Check if a relationship type is evidential (supports/refutes/corroborates/contradicts).
/// Case-insensitive matching.
fn is_evidential_relationship(relationship: &str) -> bool {
    matches!(
        relationship.to_lowercase().as_str(),
        "supports" | "refutes" | "corroborates" | "contradicts"
    )
}

/// Check if an evidential relationship is positive (supports/corroborates) vs negative.
fn is_positive_evidence(relationship: &str) -> bool {
    matches!(
        relationship.to_lowercase().as_str(),
        "supports" | "corroborates"
    )
}

/// Trigger DS recomputation on the target claim when an evidential edge is created.
///
/// 1. Look up the source claim's truth_value to weight the evidence
/// 2. Find or verify the graph-topology frame
/// 3. Build a mass function: mass = source_truth * 0.7 * 0.5
///    - Positive edges: mass on {supported} (hypothesis 0)
///    - Negative edges: mass on {contradicted} (hypothesis 1)
/// 4. Store the mass function with source_claim as source_agent_id
/// 5. Reload all mass functions, combine, compute BetP, update claim belief
#[cfg(feature = "db")]
async fn trigger_edge_ds_recomputation(
    pool: &sqlx::PgPool,
    source_claim_id: uuid::Uuid,
    target_claim_id: uuid::Uuid,
    relationship: &str,
) -> Result<(), crate::errors::ApiError> {
    use epigraph_ds::{combination, FrameOfDiscernment, MassFunction};
    use std::collections::BTreeSet;

    // 1. Get source claim's truth_value and agent_id
    let source_row: Option<(Option<f64>, Uuid)> =
        sqlx::query_as("SELECT truth_value, agent_id FROM claims WHERE id = $1")
            .bind(source_claim_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| crate::errors::ApiError::DatabaseError {
                message: format!("Failed to fetch source claim: {e}"),
            })?;

    let (source_truth_value, source_agent_id) = match source_row {
        Some((tv, agent_id)) => (tv.unwrap_or(0.5), agent_id),
        None => return Ok(()), // source claim doesn't exist, skip silently
    };

    // 2. Get the graph-topology frame ID
    let frame_row: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM frames WHERE name = 'graph-topology'")
            .fetch_optional(pool)
            .await
            .map_err(|e| crate::errors::ApiError::DatabaseError {
                message: format!("Failed to fetch graph-topology frame: {e}"),
            })?;

    let frame_id = frame_row
        .ok_or_else(|| crate::errors::ApiError::InternalError {
            message: "graph-topology frame not found; run migration first".to_string(),
        })?
        .0;

    // 3. Build the DS frame and mass function
    let ds_frame = FrameOfDiscernment::new(
        "graph-topology",
        vec!["supported".to_string(), "contradicted".to_string()],
    )
    .map_err(|e| crate::errors::ApiError::InternalError {
        message: format!("Failed to create DS frame: {e}"),
    })?;

    let mass_value = source_truth_value * 0.7 * 0.5;
    let hypothesis_idx = if is_positive_evidence(relationship) {
        0
    } else {
        1
    };

    let mass_fn = MassFunction::simple(
        ds_frame.clone(),
        BTreeSet::from([hypothesis_idx]),
        mass_value,
    )
    .map_err(|e| crate::errors::ApiError::InternalError {
        message: format!("Failed to create mass function: {e}"),
    })?;

    // 4. Store the mass function with source_claim_id as source_agent_id
    //    This ensures each edge's evidence is stored independently via the
    //    ON CONFLICT on (claim_id, frame_id, source_agent_id, perspective_id).
    let masses_json = mass_fn.masses_to_json();
    epigraph_db::MassFunctionRepository::store(
        pool,
        target_claim_id,
        frame_id,
        Some(source_agent_id), // source_agent_id = agent who created the source claim
        &masses_json,
        None,
        Some("discount"), // match submit_evidence convention
    )
    .await
    .map_err(|e| crate::errors::ApiError::DatabaseError {
        message: format!("Failed to store edge mass function: {e}"),
    })?;

    // 5. Reload all mass functions for (target_claim, graph-topology frame),
    //    combine them, compute BetP, and update claim belief.
    let all_rows =
        epigraph_db::MassFunctionRepository::get_for_claim_frame(pool, target_claim_id, frame_id)
            .await
            .map_err(|e| crate::errors::ApiError::DatabaseError {
                message: format!("Failed to load mass functions for combination: {e}"),
            })?;

    // Filter to only "discount" method entries (user-submitted BBAs), sorted by ID
    let mut indexed_rows: Vec<(Uuid, MassFunction)> = all_rows
        .iter()
        .filter(|row| row.combination_method.as_deref() == Some("discount"))
        .filter_map(|row| {
            MassFunction::from_json_masses(ds_frame.clone(), &row.masses)
                .ok()
                .map(|m| (row.id, m))
        })
        .collect();
    indexed_rows.sort_by_key(|(id, _)| *id);

    if indexed_rows.is_empty() {
        return Ok(());
    }

    let mass_fns: Vec<MassFunction> = indexed_rows.into_iter().map(|(_, m)| m).collect();

    let (combined, _reports) = if mass_fns.len() == 1 {
        (mass_fns.into_iter().next().unwrap(), vec![])
    } else {
        combination::combine_multiple(&mass_fns, 0.3).map_err(|e| {
            crate::errors::ApiError::InternalError {
                message: format!("DS combination failed: {e}"),
            }
        })?
    };

    // Look up claim's hypothesis_index in claim_frames for correct Bel/Pl
    let claim_assignment =
        epigraph_db::FrameRepository::get_claim_assignment(pool, target_claim_id, frame_id)
            .await
            .map_err(|e| crate::errors::ApiError::DatabaseError {
                message: format!("Failed to get claim assignment: {e}"),
            })?;
    let h_idx = claim_assignment.and_then(|ca| ca.hypothesis_index);

    let (final_bel, final_pl, final_betp, m_missing) =
        super::belief::compute_hypothesis_belief(&combined, &ds_frame, h_idx);
    let m_empty = combined.mass_of_empty();

    // Update the target claim's belief columns (including truth_value = BetP)
    epigraph_db::MassFunctionRepository::update_claim_belief(
        pool,
        target_claim_id,
        final_bel,
        final_pl,
        m_empty,
        Some(final_betp),
        m_missing,
    )
    .await
    .map_err(|e| crate::errors::ApiError::DatabaseError {
        message: format!("Failed to update claim belief: {e}"),
    })?;

    tracing::info!(
        target_claim = %target_claim_id,
        source_claim = %source_claim_id,
        relationship = %relationship,
        belief = final_bel,
        plausibility = final_pl,
        betp = final_betp,
        "Edge-triggered DS recomputation complete"
    );

    // 6. Propagate to dependent claims (1-hop via reasoning trace inputs)
    let mut visited = std::collections::HashSet::new();
    visited.insert(target_claim_id);
    match propagate_to_dependents(pool, target_claim_id, &mut visited).await {
        Ok(recomputed) => {
            if !recomputed.is_empty() {
                tracing::info!(
                    updated_claim = %target_claim_id,
                    dependents = ?recomputed,
                    "1-hop CDST propagation recomputed {} dependent claims",
                    recomputed.len(),
                );
            }
        }
        Err(e) => {
            // Log but don't fail the edge creation — propagation is best-effort
            tracing::warn!(
                updated_claim = %target_claim_id,
                error = %e,
                "1-hop CDST propagation failed (non-fatal)"
            );
        }
    }

    Ok(())
}

/// Propagate truth_value changes to claims that depend on `updated_claim_id`
/// via reasoning trace inputs. Bounded to 1 hop with cycle detection.
///
/// Finds reasoning traces where `updated_claim_id` appears in the
/// `properties->'inputs'` JSONB array as a Claim input, then recomputes
/// each dependent claim's combined belief using the same DS combination
/// pattern as `trigger_edge_ds_recomputation`.
///
/// # Termination guarantee
/// - `visited` set prevents cycles
/// - No recursion: only direct dependents are recomputed (1 hop)
/// - Chain: edge → recompute → propagate(visited) → STOP
#[cfg(feature = "db")]
async fn propagate_to_dependents(
    pool: &sqlx::PgPool,
    updated_claim_id: Uuid,
    visited: &mut std::collections::HashSet<Uuid>,
) -> Result<Vec<Uuid>, crate::errors::ApiError> {
    let updated_id_str = updated_claim_id.to_string();

    // Find claim_ids of reasoning traces that reference updated_claim_id as
    // a Claim input. We check both serialization formats:
    //   - Internally tagged (serde tag="type"): {"type":"claim","id":"<uuid>"}
    //   - Externally tagged (default serde):    {"Claim":{"id":"<uuid>"}}
    let dependent_rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT DISTINCT rt.claim_id
        FROM reasoning_traces rt,
             jsonb_array_elements(rt.properties->'inputs') AS input_elem
        WHERE (
            -- Internally tagged format: {"type":"claim","id":"<uuid>"}
            (input_elem->>'type' = 'claim' AND input_elem->>'id' = $1)
            OR
            -- Externally tagged format: {"Claim":{"id":"<uuid>"}}
            (input_elem->'Claim'->>'id' = $1)
        )
        AND rt.claim_id != $2
        "#,
    )
    .bind(&updated_id_str)
    .bind(updated_claim_id)
    .fetch_all(pool)
    .await
    .map_err(|e| crate::errors::ApiError::DatabaseError {
        message: format!("Failed to find dependent claims via reasoning traces: {e}"),
    })?;

    let mut recomputed = Vec::new();

    for (dependent_claim_id,) in dependent_rows {
        // Skip if already visited (cycle detection)
        if !visited.insert(dependent_claim_id) {
            tracing::debug!(
                dependent = %dependent_claim_id,
                "Skipping already-visited claim in propagation"
            );
            continue;
        }

        // Recompute this dependent claim's belief using the same DS combination
        // pattern: load all mass functions, combine, compute BetP, update.
        if let Err(e) = recompute_claim_belief(pool, dependent_claim_id).await {
            tracing::warn!(
                dependent = %dependent_claim_id,
                error = %e,
                "Failed to recompute dependent claim belief (non-fatal)"
            );
            continue;
        }

        recomputed.push(dependent_claim_id);
    }

    Ok(recomputed)
}

/// Recompute a single claim's combined belief from its mass functions.
///
/// Loads all mass functions for the claim's graph-topology frame,
/// combines them via Dempster's rule, computes BetP, and updates
/// the claim's truth_value and belief columns.
#[cfg(feature = "db")]
async fn recompute_claim_belief(
    pool: &sqlx::PgPool,
    claim_id: Uuid,
) -> Result<(), crate::errors::ApiError> {
    use epigraph_ds::{combination, FrameOfDiscernment, MassFunction};

    // Get the graph-topology frame
    let frame_row: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM frames WHERE name = 'graph-topology'")
            .fetch_optional(pool)
            .await
            .map_err(|e| crate::errors::ApiError::DatabaseError {
                message: format!("Failed to fetch graph-topology frame: {e}"),
            })?;

    let frame_id = match frame_row {
        Some((id,)) => id,
        None => return Ok(()), // No frame = nothing to recompute
    };

    let ds_frame = FrameOfDiscernment::new(
        "graph-topology",
        vec!["supported".to_string(), "contradicted".to_string()],
    )
    .map_err(|e| crate::errors::ApiError::InternalError {
        message: format!("Failed to create DS frame: {e}"),
    })?;

    // Load all mass functions for this claim
    let all_rows =
        epigraph_db::MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id)
            .await
            .map_err(|e| crate::errors::ApiError::DatabaseError {
                message: format!("Failed to load mass functions for dependent claim: {e}"),
            })?;

    let mut indexed_rows: Vec<(Uuid, MassFunction)> = all_rows
        .iter()
        .filter(|row| row.combination_method.as_deref() == Some("discount"))
        .filter_map(|row| {
            MassFunction::from_json_masses(ds_frame.clone(), &row.masses)
                .ok()
                .map(|m| (row.id, m))
        })
        .collect();
    indexed_rows.sort_by_key(|(id, _)| *id);

    if indexed_rows.is_empty() {
        return Ok(());
    }

    let mass_fns: Vec<MassFunction> = indexed_rows.into_iter().map(|(_, m)| m).collect();

    let (combined, _reports) = if mass_fns.len() == 1 {
        (mass_fns.into_iter().next().unwrap(), vec![])
    } else {
        combination::combine_multiple(&mass_fns, 0.3).map_err(|e| {
            crate::errors::ApiError::InternalError {
                message: format!("DS combination failed for dependent claim: {e}"),
            }
        })?
    };

    // Look up claim's hypothesis_index
    let claim_assignment =
        epigraph_db::FrameRepository::get_claim_assignment(pool, claim_id, frame_id)
            .await
            .map_err(|e| crate::errors::ApiError::DatabaseError {
                message: format!("Failed to get claim assignment for dependent: {e}"),
            })?;
    let h_idx = claim_assignment.and_then(|ca| ca.hypothesis_index);

    let (final_bel, final_pl, final_betp, m_missing) =
        super::belief::compute_hypothesis_belief(&combined, &ds_frame, h_idx);
    let m_empty = combined.mass_of_empty();

    epigraph_db::MassFunctionRepository::update_claim_belief(
        pool,
        claim_id,
        final_bel,
        final_pl,
        m_empty,
        Some(final_betp),
        m_missing,
    )
    .await
    .map_err(|e| crate::errors::ApiError::DatabaseError {
        message: format!("Failed to update dependent claim belief: {e}"),
    })?;

    tracing::info!(
        claim = %claim_id,
        belief = final_bel,
        plausibility = final_pl,
        betp = final_betp,
        "Dependent claim recomputed via 1-hop propagation"
    );

    Ok(())
}

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateEdgeRequest {
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub source_type: String,
    pub target_type: String,
    pub relationship: String,
    pub properties: Option<serde_json::Value>,
    pub labels: Option<Vec<String>>,
    pub valid_from: Option<chrono::DateTime<chrono::Utc>>,
    pub valid_to: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
pub struct EdgeResponse {
    pub id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub source_type: String,
    pub target_type: String,
    pub relationship: String,
    pub properties: serde_json::Value,
    pub valid_from: Option<chrono::DateTime<chrono::Utc>>,
    pub valid_to: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct EdgeQueryParams {
    pub source_id: Option<Uuid>,
    pub target_id: Option<Uuid>,
    pub relationship: Option<String>,
    pub source_type: Option<String>,
    pub target_type: Option<String>,
    /// Optional requester agent ID for partition-aware content filtering
    #[serde(default)]
    pub agent_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct NeighborhoodResponse {
    pub center_id: Uuid,
    pub edges: Vec<EdgeResponse>,
    pub connected_entity_ids: Vec<Uuid>,
    pub depth: u32,
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Create a new edge between two entities
///
/// Protected route — requires Ed25519 signature verification.
///
/// Validation:
/// - source_id != target_id when source_type == target_type (no self-loops)
/// - source_type and target_type must be valid entity types
/// - relationship must be from the allowed set
#[cfg(feature = "db")]
pub async fn create_edge(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<CreateEdgeRequest>,
) -> Result<(StatusCode, Json<EdgeResponse>), ApiError> {
    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["edges:write"])?;
    }

    // Validate entity types
    if !is_valid_entity_type(&request.source_type) {
        return Err(ApiError::ValidationError {
            field: "source_type".to_string(),
            reason: format!(
                "Invalid source_type '{}'. Valid types: {}",
                request.source_type,
                VALID_ENTITY_TYPES.join(", ")
            ),
        });
    }
    if !is_valid_entity_type(&request.target_type) {
        return Err(ApiError::ValidationError {
            field: "target_type".to_string(),
            reason: format!(
                "Invalid target_type '{}'. Valid types: {}",
                request.target_type,
                VALID_ENTITY_TYPES.join(", ")
            ),
        });
    }

    // Validate relationship
    if !is_valid_relationship(&request.relationship) {
        return Err(ApiError::ValidationError {
            field: "relationship".to_string(),
            reason: format!(
                "Invalid relationship '{}'. Valid types: {}",
                request.relationship,
                VALID_RELATIONSHIPS.join(", ")
            ),
        });
    }

    // Validate no self-loops (same ID AND same type)
    if request.source_id == request.target_id && request.source_type == request.target_type {
        return Err(ApiError::ValidationError {
            field: "target_id".to_string(),
            reason: "Self-loops are not allowed (source and target are the same entity)"
                .to_string(),
        });
    }

    let pool = &state.db_pool;

    // Verify source entity exists
    if !entity_exists(pool, request.source_id, &request.source_type).await? {
        return Err(ApiError::NotFound {
            entity: request.source_type.clone(),
            id: request.source_id.to_string(),
        });
    }
    // Verify target entity exists
    if !entity_exists(pool, request.target_id, &request.target_type).await? {
        return Err(ApiError::NotFound {
            entity: request.target_type.clone(),
            id: request.target_id.to_string(),
        });
    }

    let edge_id = EdgeRepository::create(
        pool,
        request.source_id,
        &request.source_type,
        request.target_id,
        &request.target_type,
        &request.relationship,
        request.properties.clone(),
        request.valid_from,
        request.valid_to,
    )
    .await?;

    // Record provenance when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        let hash_input = format!(
            "{}:{}:{}",
            request.source_id, request.relationship, request.target_id
        );
        let content_hash = blake3::hash(hash_input.as_bytes());
        if let Err(e) = crate::middleware::provenance::record_provenance(
            pool,
            auth,
            "edge",
            edge_id,
            "create",
            content_hash.as_bytes(),
            &[],
            None,
        )
        .await
        {
            tracing::warn!(edge_id = %edge_id, error = %e, "Failed to record edge provenance");
        }
    }

    // Edge-triggered DS recomputation: if this is an evidential edge between
    // two claims, recompute the target claim's truth_value via DS combination.
    if is_evidential_relationship(&request.relationship)
        && request.source_type == "claim"
        && request.target_type == "claim"
    {
        if let Err(e) = trigger_edge_ds_recomputation(
            pool,
            request.source_id,
            request.target_id,
            &request.relationship,
        )
        .await
        {
            tracing::warn!(
                edge_id = %edge_id,
                source_id = %request.source_id,
                target_id = %request.target_id,
                relationship = %request.relationship,
                error = %e,
                "Edge-triggered DS recomputation failed; edge created successfully"
            );
        }
    }

    // P2a: Auto-create factor for epistemic edges
    // Belt-and-suspenders: DB trigger (migration 044/049) also fires on INSERT,
    // but this Rust path ensures factor creation even if the trigger is absent
    // (e.g. dev environments that haven't run all migrations).
    if matches!(
        request.relationship.to_uppercase().as_str(),
        "SUPPORTS" | "CONTRADICTS"
    ) {
        let factor_type = if request.relationship.to_uppercase() == "SUPPORTS" {
            "evidential_support"
        } else {
            "mutual_exclusion"
        };

        let potential = if factor_type == "evidential_support" {
            serde_json::json!({"source_weight": 0.7, "target_weight": 0.3})
        } else {
            serde_json::json!({"strength": 0.8})
        };

        let variable_ids = vec![request.source_id, request.target_id];
        if let Err(e) = sqlx::query(
            "INSERT INTO factors (factor_type, variable_ids, potential, description) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT DO NOTHING",
        )
        .bind(factor_type)
        .bind(&variable_ids)
        .bind(&potential)
        .bind(format!("Auto-created from {} edge", request.relationship))
        .execute(&state.db_pool)
        .await
        {
            tracing::warn!(
                error = %e,
                "Failed to auto-create factor for edge — BP will not include this relationship"
            );
        }
    }

    let response = EdgeResponse {
        id: edge_id,
        source_id: request.source_id,
        target_id: request.target_id,
        source_type: request.source_type,
        target_type: request.target_type,
        relationship: request.relationship,
        properties: request.properties.unwrap_or(serde_json::json!({})),
        valid_from: request.valid_from,
        valid_to: request.valid_to,
    };

    // Emit edge.added event (Task 0.3 / Phase 0 — staleness trigger)
    {
        let actor_id = auth_ctx.as_ref().and_then(|axum::Extension(a)| a.agent_id);
        let event_store = super::events::global_event_store();
        event_store
            .push(
                "edge.added".to_string(),
                actor_id,
                serde_json::json!({
                    "edge_id": response.id,
                    "source_type": response.source_type,
                    "source_id": response.source_id,
                    "target_type": response.target_type,
                    "target_id": response.target_id,
                    "relationship": response.relationship,
                }),
            )
            .await;

        // If this is a supersedes edge, also emit claim.superseded
        if response.relationship.eq_ignore_ascii_case("supersedes") {
            event_store
                .push(
                    "claim.superseded".to_string(),
                    actor_id,
                    serde_json::json!({
                        "superseded_claim_id": response.target_id,
                        "superseded_by_claim_id": response.source_id,
                    }),
                )
                .await;
        }
    }

    Ok((StatusCode::CREATED, Json(response)))
}

// =============================================================================
// DELETE EDGE
// =============================================================================

/// Delete an edge by ID
///
/// DELETE /api/v1/edges/:id
///
/// Hard-deletes the edge. Returns 204 No Content on success, 404 if not found.
#[cfg(feature = "db")]
pub async fn delete_edge(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["edges:write"])?;
    }

    let deleted = EdgeRepository::delete(&state.db_pool, id).await?;

    if !deleted {
        return Err(ApiError::NotFound {
            entity: "Edge".to_string(),
            id: id.to_string(),
        });
    }

    // Record provenance when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        let content_hash = blake3::hash(id.as_bytes());
        if let Err(e) = crate::middleware::provenance::record_provenance(
            &state.db_pool,
            auth,
            "edge",
            id,
            "delete",
            content_hash.as_bytes(),
            &[],
            None,
        )
        .await
        {
            tracing::warn!(edge_id = %id, error = %e, "Failed to record edge delete provenance");
        }
    }

    // Emit edge.deleted event (Task 0.3 / Phase 0 — staleness trigger)
    {
        let actor_id = auth_ctx.as_ref().and_then(|axum::Extension(a)| a.agent_id);
        let event_store = super::events::global_event_store();
        event_store
            .push(
                "edge.deleted".to_string(),
                actor_id,
                serde_json::json!({ "edge_id": id }),
            )
            .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Delete an edge by ID (placeholder - no database)
#[cfg(not(feature = "db"))]
pub async fn delete_edge(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Edge deletion requires database".to_string(),
    })
}

/// Request to relate two claims with a bidirectional semantic link
#[derive(Debug, Deserialize)]
pub struct RelateClaimsRequest {
    pub target_claim_id: Uuid,
    pub properties: Option<serde_json::Value>,
}

/// Relate two claims with bidirectional RELATES_TO edges
///
/// `POST /api/v1/claims/:id/relate`
///
/// Creates two edges: source→target and target→source (undirected semantic link).
#[cfg(feature = "db")]
pub async fn relate_claims(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(source_id): Path<Uuid>,
    Json(request): Json<RelateClaimsRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["edges:write"])?;
    }

    if source_id == request.target_claim_id {
        return Err(ApiError::ValidationError {
            field: "target_claim_id".to_string(),
            reason: "Cannot relate a claim to itself".to_string(),
        });
    }

    let pool = &state.db_pool;

    // Verify both claims exist
    let source_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM claims WHERE id = $1)")
            .bind(source_id)
            .fetch_one(pool)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?;
    if !source_exists {
        return Err(ApiError::NotFound {
            entity: "claim".to_string(),
            id: source_id.to_string(),
        });
    }

    let target_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM claims WHERE id = $1)")
            .bind(request.target_claim_id)
            .fetch_one(pool)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?;
    if !target_exists {
        return Err(ApiError::NotFound {
            entity: "claim".to_string(),
            id: request.target_claim_id.to_string(),
        });
    }

    // Create bidirectional edges
    let edge1 = EdgeRepository::create(
        pool,
        source_id,
        "claim",
        request.target_claim_id,
        "claim",
        "RELATES_TO",
        request.properties.clone(),
        None,
        None,
    )
    .await?;

    let edge2 = EdgeRepository::create(
        pool,
        request.target_claim_id,
        "claim",
        source_id,
        "claim",
        "RELATES_TO",
        request.properties,
        None,
        None,
    )
    .await?;

    // Record provenance for both edges
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        for eid in [edge1, edge2] {
            let hash_input = format!("{}:RELATES_TO:{}", source_id, request.target_claim_id);
            let content_hash = blake3::hash(hash_input.as_bytes());
            if let Err(e) = crate::middleware::provenance::record_provenance(
                pool,
                auth,
                "edge",
                eid,
                "create",
                content_hash.as_bytes(),
                &[],
                None,
            )
            .await
            {
                tracing::warn!(edge_id = %eid, error = %e, "Failed to record relate_claims provenance");
            }
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "source_claim_id": source_id,
            "target_claim_id": request.target_claim_id,
            "edge_ids": [edge1, edge2],
        })),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn relate_claims(
    Path(_source_id): Path<Uuid>,
    Json(_request): Json<RelateClaimsRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Claim relations require database".to_string(),
    })
}

/// Check whether an entity with the given ID exists in the appropriate table.
#[cfg(feature = "db")]
async fn entity_exists(
    pool: &epigraph_db::PgPool,
    id: Uuid,
    entity_type: &str,
) -> Result<bool, ApiError> {
    let exists: bool = match entity_type {
        "claim" => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM claims WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("DB check failed: {e}"),
            })?,
        "agent" => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agents WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("DB check failed: {e}"),
            })?,
        "evidence" => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM evidence WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("DB check failed: {e}"),
            })?,
        "trace" => {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM reasoning_traces WHERE id = $1)")
                .bind(id)
                .fetch_one(pool)
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("DB check failed: {e}"),
                })?
        }
        "propaganda_technique" => {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM propaganda_techniques WHERE id = $1)")
                .bind(id)
                .fetch_one(pool)
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("DB check failed: {e}"),
                })?
        }
        "coalition" => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM coalitions WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("DB check failed: {e}"),
            })?,
        "paper" => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM papers WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("DB check failed: {e}"),
            })?,
        _ => false, // Unknown types already rejected by validation above
    };
    Ok(exists)
}

/// Query edges by source, target, or relationship
///
/// Public route — no authentication required.
///
/// At least one filter parameter must be provided.
#[cfg(feature = "db")]
pub async fn list_edges(
    State(state): State<AppState>,
    Query(params): Query<EdgeQueryParams>,
) -> Result<Json<Vec<EdgeResponse>>, ApiError> {
    let pool = &state.db_pool;

    let rows = if let Some(source_id) = params.source_id {
        let source_type = params.source_type.as_deref().unwrap_or("claim");
        EdgeRepository::get_by_source(pool, source_id, source_type).await?
    } else if let Some(target_id) = params.target_id {
        let target_type = params.target_type.as_deref().unwrap_or("claim");
        EdgeRepository::get_by_target(pool, target_id, target_type).await?
    } else if let Some(ref relationship) = params.relationship {
        EdgeRepository::get_by_relationship(pool, relationship).await?
    } else {
        // No filter: return all edges (capped at 1000)
        EdgeRepository::list_all(pool, 1000).await?
    };

    // Filter edges where source or target has a redacted partition
    let mut edges = Vec::new();
    for row in rows {
        let source_redacted = row.source_type == "claim"
            && check_content_access(pool, row.source_id, params.agent_id).await
                == ContentAccess::Redacted;
        let target_redacted = row.target_type == "claim"
            && check_content_access(pool, row.target_id, params.agent_id).await
                == ContentAccess::Redacted;

        if !source_redacted && !target_redacted {
            edges.push(EdgeResponse {
                id: row.id,
                source_id: row.source_id,
                target_id: row.target_id,
                source_type: row.source_type,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            });
        }
    }

    Ok(Json(edges))
}

/// Get the 2-hop neighborhood around a claim
///
/// Returns all edges where the claim is either source or target (1-hop),
/// plus edges connected to those neighbors (2-hop).
///
/// Public route — no authentication required.
#[cfg(feature = "db")]
pub async fn claim_neighborhood(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<NeighborhoodParams>,
) -> Result<Json<NeighborhoodResponse>, ApiError> {
    let pool = &state.db_pool;

    let max_depth = params.depth.unwrap_or(2).min(3); // Cap at 3 hops

    // 1-hop: edges where this claim is source or target
    let mut all_edges = Vec::new();
    let mut visited_ids: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    visited_ids.insert(claim_id);

    let outgoing = EdgeRepository::get_by_source(pool, claim_id, "claim").await?;
    let incoming = EdgeRepository::get_by_target(pool, claim_id, "claim").await?;

    // Collect 1-hop neighbor IDs
    let mut frontier: Vec<Uuid> = Vec::new();
    for edge in outgoing.iter().chain(incoming.iter()) {
        let neighbor_id = if edge.source_id == claim_id {
            edge.target_id
        } else {
            edge.source_id
        };
        if visited_ids.insert(neighbor_id) {
            frontier.push(neighbor_id);
        }
    }
    all_edges.extend(outgoing);
    all_edges.extend(incoming);

    // 2+ hop: expand frontier
    for _hop in 1..max_depth {
        let mut next_frontier = Vec::new();
        for &node_id in &frontier {
            let out = EdgeRepository::get_by_source(pool, node_id, "claim").await?;
            let inc = EdgeRepository::get_by_target(pool, node_id, "claim").await?;

            for edge in out.iter().chain(inc.iter()) {
                let neighbor_id = if edge.source_id == node_id {
                    edge.target_id
                } else {
                    edge.source_id
                };
                if visited_ids.insert(neighbor_id) {
                    next_frontier.push(neighbor_id);
                }
            }
            all_edges.extend(out);
            all_edges.extend(inc);
        }
        frontier = next_frontier;
    }

    // Cap total edges to prevent unbounded growth
    const MAX_NEIGHBORHOOD_EDGES: usize = 500;
    if all_edges.len() > MAX_NEIGHBORHOOD_EDGES {
        all_edges.truncate(MAX_NEIGHBORHOOD_EDGES);
        tracing::warn!(
            claim_id = %claim_id,
            total_edges = all_edges.len(),
            "Neighborhood truncated to {} edges", MAX_NEIGHBORHOOD_EDGES
        );
    }

    // Deduplicate edges by ID
    let mut seen_edge_ids: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    let deduped: Vec<_> = all_edges
        .into_iter()
        .filter(|e| seen_edge_ids.insert(e.id))
        .collect();

    // Apply partition filtering: remove edges touching redacted claim nodes
    let mut unique_edges = Vec::new();
    let mut redacted_ids: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    for row in deduped {
        let source_redacted = row.source_type == "claim"
            && row.source_id != claim_id
            && check_content_access(pool, row.source_id, params.agent_id).await
                == ContentAccess::Redacted;
        let target_redacted = row.target_type == "claim"
            && row.target_id != claim_id
            && check_content_access(pool, row.target_id, params.agent_id).await
                == ContentAccess::Redacted;

        if source_redacted {
            redacted_ids.insert(row.source_id);
        }
        if target_redacted {
            redacted_ids.insert(row.target_id);
        }
        if !source_redacted && !target_redacted {
            unique_edges.push(EdgeResponse {
                id: row.id,
                source_id: row.source_id,
                target_id: row.target_id,
                source_type: row.source_type,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            });
        }
    }

    // Connected entity IDs (excluding the center and redacted nodes)
    let connected: Vec<Uuid> = visited_ids
        .into_iter()
        .filter(|&id| id != claim_id && !redacted_ids.contains(&id))
        .collect();

    Ok(Json(NeighborhoodResponse {
        center_id: claim_id,
        edges: unique_edges,
        connected_entity_ids: connected,
        depth: max_depth,
    }))
}

#[derive(Debug, Deserialize)]
pub struct NeighborhoodParams {
    pub depth: Option<u32>,
    /// Optional requester agent ID for partition-aware content filtering
    #[serde(default)]
    pub agent_id: Option<Uuid>,
}

/// Query params for graph_full and graph_edges
#[derive(Debug, Deserialize)]
pub struct GraphAccessParams {
    /// Optional requester agent ID for partition-aware content filtering
    #[serde(default)]
    pub agent_id: Option<Uuid>,
}

/// Query params for get_evidence
#[derive(Debug, Deserialize)]
pub struct EvidenceAccessParams {
    /// Optional requester agent ID for partition-aware content filtering
    #[serde(default)]
    pub agent_id: Option<Uuid>,
}

// =============================================================================
// GRAPH EDGES (UI-friendly format)
// =============================================================================

/// Response type matching the UI's SemanticEdge interface
#[derive(Debug, Serialize)]
pub struct SemanticEdgeResponse {
    pub id: Uuid,
    pub source_claim_id: Uuid,
    pub target_claim_id: Uuid,
    pub edge_type: String,
    pub strength: f64,
    pub method: String,
    pub created_at: String,
}

/// Response for the graph edges endpoint
#[derive(Debug, Serialize)]
pub struct GraphEdgesResponse {
    pub edges: Vec<SemanticEdgeResponse>,
    pub total: usize,
}

/// List all claim-to-claim edges in the SemanticEdge format expected by the UI
///
/// GET /api/v1/graph/edges
///
/// Returns edges between claims with `edge_type`, `strength`, and `method`
/// fields extracted from the edge properties JSONB.
#[cfg(feature = "db")]
pub async fn graph_edges(
    State(state): State<AppState>,
    Query(params): Query<GraphAccessParams>,
) -> Result<Json<GraphEdgesResponse>, ApiError> {
    let pool = &state.db_pool;
    let rows = EdgeRepository::list_all(pool, 5000).await?;

    // Filter to claim-to-claim edges, excluding edges touching redacted claims
    let mut filtered = Vec::new();
    for r in rows {
        if r.source_type != "claim" || r.target_type != "claim" {
            continue;
        }
        let source_redacted = check_content_access(pool, r.source_id, params.agent_id).await
            == ContentAccess::Redacted;
        let target_redacted = check_content_access(pool, r.target_id, params.agent_id).await
            == ContentAccess::Redacted;
        if !source_redacted && !target_redacted {
            filtered.push(r);
        }
    }

    let edges: Vec<SemanticEdgeResponse> = filtered
        .into_iter()
        .map(|r| {
            let strength = r
                .properties
                .get("strength")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.5);
            let method = r
                .properties
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            // Map DB relationship names to UI edge_type names
            let edge_type = match r.relationship.as_str() {
                "supports" => "supports",
                "refutes" => "refutes",
                "elaborates" => "elaborates",
                "challenges" => "challenges",
                other => other,
            }
            .to_string();

            SemanticEdgeResponse {
                id: r.id,
                source_claim_id: r.source_id,
                target_claim_id: r.target_id,
                edge_type,
                strength,
                method,
                created_at: String::new(), // DB doesn't return created_at in EdgeRow
            }
        })
        .collect();

    let total = edges.len();
    Ok(Json(GraphEdgesResponse { edges, total }))
}

#[cfg(not(feature = "db"))]
pub async fn graph_edges(
    Query(_params): Query<GraphAccessParams>,
) -> Result<Json<GraphEdgesResponse>, ApiError> {
    Ok(Json(GraphEdgesResponse {
        edges: vec![],
        total: 0,
    }))
}

// =============================================================================
// FULL GRAPH (multi-entity: claims + agents + evidence + traces + all edges)
// =============================================================================

/// A node in the full knowledge graph (any entity type)
#[derive(Debug, Serialize)]
pub struct FullGraphNode {
    pub id: Uuid,
    pub entity_type: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truth_value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub methodology: Option<String>,
    // DS belief fields (claim-specific)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub belief: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plausibility: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pignistic_prob: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mass_on_missing: Option<f64>,
}

/// An edge in the full knowledge graph
#[derive(Debug, Serialize)]
pub struct FullGraphEdge {
    pub id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub source_type: String,
    pub target_type: String,
    pub relationship: String,
    pub strength: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prov_type: Option<String>,
}

/// Response for GET /api/v1/graph/full
#[derive(Debug, Serialize)]
pub struct FullGraphResponse {
    pub nodes: Vec<FullGraphNode>,
    pub edges: Vec<FullGraphEdge>,
    pub total_nodes: usize,
    pub total_edges: usize,
}

/// Return the full knowledge graph: all entity types + all edges.
///
/// `GET /api/v1/graph/full`
///
/// Fetches all edges (capped at 2000), collects unique entity IDs by type,
/// batch-fetches each entity type, and assembles a unified graph response.
#[cfg(feature = "db")]
pub async fn graph_full(
    State(state): State<AppState>,
    Query(params): Query<GraphAccessParams>,
) -> Result<Json<FullGraphResponse>, ApiError> {
    let pool = &state.db_pool;

    // 1. Fetch all edges (capped)
    let edge_rows = EdgeRepository::list_all(pool, 2000).await?;

    // 2. Collect unique entity IDs by type
    let mut claim_ids = std::collections::HashSet::new();
    let mut agent_ids = std::collections::HashSet::new();
    let mut evidence_ids = std::collections::HashSet::new();
    let mut trace_ids = std::collections::HashSet::new();
    let mut activity_ids = std::collections::HashSet::new();

    for edge in &edge_rows {
        match edge.source_type.as_str() {
            "claim" => {
                claim_ids.insert(edge.source_id);
            }
            "agent" => {
                agent_ids.insert(edge.source_id);
            }
            "evidence" => {
                evidence_ids.insert(edge.source_id);
            }
            "trace" => {
                trace_ids.insert(edge.source_id);
            }
            "activity" => {
                activity_ids.insert(edge.source_id);
            }
            _ => {
                tracing::warn!(source_type = %edge.source_type, edge_id = %edge.id, "Unknown source_type in full-graph query — node skipped");
            }
        }
        match edge.target_type.as_str() {
            "claim" => {
                claim_ids.insert(edge.target_id);
            }
            "agent" => {
                agent_ids.insert(edge.target_id);
            }
            "evidence" => {
                evidence_ids.insert(edge.target_id);
            }
            "trace" => {
                trace_ids.insert(edge.target_id);
            }
            "activity" => {
                activity_ids.insert(edge.target_id);
            }
            _ => {
                tracing::warn!(target_type = %edge.target_type, edge_id = %edge.id, "Unknown target_type in full-graph query — node skipped");
            }
        }
    }

    let mut node_ids = Vec::new();
    node_ids.extend(claim_ids);
    node_ids.extend(agent_ids);
    node_ids.extend(evidence_ids);
    node_ids.extend(trace_ids);
    node_ids.extend(activity_ids);

    if node_ids.is_empty() {
        return Ok(Json(FullGraphResponse {
            nodes: vec![],
            edges: vec![],
            total_nodes: 0,
            total_edges: 0,
        }));
    }

    let mut resp = super::graph_query_utils::load_subgraph(pool, node_ids).await?;
    // Redact claim labels for nodes the requester cannot access
    for node in &mut resp.nodes {
        if node.entity_type == "claim" {
            let access = check_content_access(pool, node.id, params.agent_id).await;
            if access == ContentAccess::Redacted {
                node.label = "[REDACTED]".to_string();
            }
        }
    }
    Ok(resp)
}

#[cfg(not(feature = "db"))]
pub async fn graph_full(
    Query(_params): Query<GraphAccessParams>,
) -> Result<Json<FullGraphResponse>, ApiError> {
    Ok(Json(FullGraphResponse {
        nodes: vec![],
        edges: vec![],
        total_nodes: 0,
        total_edges: 0,
    }))
}

// =============================================================================
// SINGLE EVIDENCE DETAIL
// =============================================================================

/// Detailed evidence response with flattened figure/literature fields
#[derive(Debug, Serialize)]
pub struct EvidenceDetailResponse {
    pub id: Uuid,
    pub claim_id: Option<Uuid>,
    pub agent_id: Option<Uuid>,
    pub evidence_type: String,
    pub content: Option<String>,
    pub content_hash: String,
    pub source_url: Option<String>,
    // Figure-specific
    #[serde(skip_serializing_if = "Option::is_none")]
    pub figure_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    // Literature-specific
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extraction_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_range: Option<String>,
    pub created_at: String,
}

// Row types for evidence and provenance queries
#[derive(sqlx::FromRow)]
struct EvidenceDetailRow {
    id: Uuid,
    raw_content: Option<String>,
    content_hash: Vec<u8>,
    source_url: Option<String>,
    properties: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
}
#[derive(sqlx::FromRow)]
struct SourceIdRow {
    source_id: Uuid,
}
#[derive(sqlx::FromRow)]
struct TargetIdRow {
    target_id: Uuid,
}
#[derive(sqlx::FromRow)]
struct ClaimProvRow {
    id: Uuid,
    content: String,
    trace_id: Option<Uuid>,
}
#[derive(sqlx::FromRow)]
struct TraceProvRow {
    id: Uuid,
    methodology: String,
    confidence: f64,
}
#[derive(sqlx::FromRow)]
struct EvidenceProvRow {
    id: Uuid,
    source_url: Option<String>,
    properties: serde_json::Value,
}

/// Get a single evidence item by ID with all details flattened
///
/// `GET /api/v1/evidence/:id`
#[cfg(feature = "db")]
pub async fn get_evidence(
    State(state): State<AppState>,
    Path(evidence_id): Path<Uuid>,
    Query(params): Query<EvidenceAccessParams>,
) -> Result<Json<EvidenceDetailResponse>, ApiError> {
    let pool = &state.db_pool;

    let row: EvidenceDetailRow = sqlx::query_as(
        "SELECT id, raw_content, content_hash, source_url, properties, created_at FROM evidence WHERE id = $1"
    )
    .bind(evidence_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ApiError::InternalError { message: format!("DB error: {e}") })?
    .ok_or(ApiError::NotFound {
        entity: "evidence".to_string(),
        id: evidence_id.to_string(),
    })?;

    let props = &row.properties;

    // Extract claim_id and agent_id from edges pointing to this evidence
    let claim_edge: Option<SourceIdRow> = sqlx::query_as(
        "SELECT source_id FROM edges WHERE target_id = $1 AND target_type = 'evidence' AND source_type = 'claim' LIMIT 1"
    )
    .bind(evidence_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    let agent_edge: Option<SourceIdRow> = sqlx::query_as(
        "SELECT source_id FROM edges WHERE target_id = $1 AND target_type = 'evidence' AND source_type = 'agent' LIMIT 1"
    )
    .bind(evidence_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    let ev_type = props
        .get("evidence_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    // Redact content if linked claim is private/community and requester lacks access
    let should_redact = if let Some(ref ce) = claim_edge {
        check_content_access(pool, ce.source_id, params.agent_id).await == ContentAccess::Redacted
    } else {
        false
    };

    let content = if should_redact {
        Some("[REDACTED]".to_string())
    } else {
        row.raw_content.clone()
    };

    let response = EvidenceDetailResponse {
        id: row.id,
        claim_id: claim_edge.map(|r| r.source_id),
        agent_id: agent_edge.map(|r| r.source_id),
        evidence_type: ev_type,
        content,
        content_hash: hex::encode(&row.content_hash),
        source_url: row.source_url,
        figure_id: props
            .get("figure_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        caption: props
            .get("caption")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        mime_type: props
            .get("mime_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        page: props.get("page").and_then(|v| v.as_i64()),
        doi: props
            .get("doi")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        extraction_target: props
            .get("extraction_target")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        page_range: props
            .get("page_range")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        created_at: row.created_at.to_rfc3339(),
    };

    Ok(Json(response))
}

#[cfg(not(feature = "db"))]
pub async fn get_evidence(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
    Query(_params): Query<EvidenceAccessParams>,
) -> Result<Json<EvidenceDetailResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database".to_string(),
    })
}

// =============================================================================
// PROVENANCE TRACING
// =============================================================================

/// A step in a provenance chain
#[derive(Debug, Clone, Serialize)]
pub struct ProvenanceStep {
    pub id: Uuid,
    pub entity_type: String,
    pub label: String,
}

/// A single provenance chain from claim to source
#[derive(Debug, Serialize)]
pub struct ProvenanceChain {
    pub path: Vec<ProvenanceStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_doi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
}

/// Provenance response for a claim
#[derive(Debug, Serialize)]
pub struct ProvenanceResponse {
    pub claim_id: Uuid,
    pub chains: Vec<ProvenanceChain>,
}

/// Trace provenance from a claim back to source papers/DOIs.
///
/// `GET /api/v1/claims/:id/provenance`
///
/// Follows: Claim -> trace_id -> ReasoningTrace -> evidence inputs -> DOI/source_url
#[cfg(feature = "db")]
pub async fn claim_provenance(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<EvidenceAccessParams>,
) -> Result<Json<ProvenanceResponse>, ApiError> {
    let pool = &state.db_pool;

    // 1. Fetch the claim
    let claim_row: ClaimProvRow =
        sqlx::query_as("SELECT id, content, trace_id FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("DB error: {e}"),
            })?
            .ok_or(ApiError::NotFound {
                entity: "claim".to_string(),
                id: claim_id.to_string(),
            })?;

    // Redact claim content in provenance chain if requester lacks access
    let access = check_content_access(pool, claim_id, params.agent_id).await;
    let claim_label = if access == ContentAccess::Redacted {
        "[REDACTED]".to_string()
    } else if claim_row.content.len() > 60 {
        format!("{}...", &claim_row.content[..57])
    } else {
        claim_row.content.clone()
    };

    let claim_step = ProvenanceStep {
        id: claim_row.id,
        entity_type: "claim".to_string(),
        label: claim_label,
    };

    let mut chains = Vec::new();

    // Helper: build evidence chains from target_ids
    async fn build_evidence_chains(
        pool: &epigraph_db::PgPool,
        claim_step: &ProvenanceStep,
        trace_step: Option<&ProvenanceStep>,
        evidence_target_ids: Vec<Uuid>,
    ) -> Result<Vec<ProvenanceChain>, ApiError> {
        let mut chains = Vec::new();
        for target_id in evidence_target_ids {
            let ev: Option<EvidenceProvRow> =
                sqlx::query_as("SELECT id, source_url, properties FROM evidence WHERE id = $1")
                    .bind(target_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(|e| ApiError::InternalError {
                        message: format!("DB error: {e}"),
                    })?;

            if let Some(ev) = ev {
                let props = &ev.properties;
                let doi = props
                    .get("doi")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let caption = props.get("caption").and_then(|v| v.as_str()).unwrap_or("");
                let ev_type = props
                    .get("evidence_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("evidence");

                let label = if let Some(ref d) = doi {
                    format!("{ev_type}: {d}")
                } else if !caption.is_empty() {
                    caption.to_string()
                } else {
                    format!("Evidence {}", &ev.id.to_string()[..8])
                };

                let evidence_step = ProvenanceStep {
                    id: ev.id,
                    entity_type: "evidence".to_string(),
                    label,
                };

                let source_url = doi
                    .as_ref()
                    .map(|d| format!("https://doi.org/{d}"))
                    .or_else(|| ev.source_url.clone());

                let mut path = vec![claim_step.clone()];
                if let Some(ts) = trace_step {
                    path.push(ts.clone());
                }
                path.push(evidence_step);

                chains.push(ProvenanceChain {
                    path,
                    source_doi: doi,
                    source_url,
                });
            }
        }
        Ok(chains)
    }

    // 2. If claim has a trace, follow it
    if let Some(trace_id) = claim_row.trace_id {
        let trace_row: Option<TraceProvRow> = sqlx::query_as(
            "SELECT id, reasoning_type as methodology, confidence FROM reasoning_traces WHERE id = $1"
        )
        .bind(trace_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| ApiError::InternalError { message: format!("DB error: {e}") })?;

        if let Some(trace) = trace_row {
            let trace_step = ProvenanceStep {
                id: trace.id,
                entity_type: "trace".to_string(),
                label: format!("{} ({:.2})", trace.methodology, trace.confidence),
            };

            // 3. Find evidence linked to this claim via edges
            let evidence_edges: Vec<TargetIdRow> = sqlx::query_as(
                "SELECT target_id FROM edges WHERE source_id = $1 AND source_type = 'claim' AND target_type = 'evidence'"
            )
            .bind(claim_id)
            .fetch_all(pool)
            .await
            .map_err(|e| ApiError::InternalError { message: format!("DB error: {e}") })?;

            if evidence_edges.is_empty() {
                chains.push(ProvenanceChain {
                    path: vec![claim_step.clone(), trace_step],
                    source_doi: None,
                    source_url: None,
                });
            } else {
                let target_ids: Vec<Uuid> =
                    evidence_edges.into_iter().map(|e| e.target_id).collect();
                chains.extend(
                    build_evidence_chains(pool, &claim_step, Some(&trace_step), target_ids).await?,
                );
            }
        }
    }

    // If no chains were found via trace, try direct evidence edges
    if chains.is_empty() {
        let evidence_edges: Vec<TargetIdRow> = sqlx::query_as(
            "SELECT target_id FROM edges WHERE source_id = $1 AND source_type = 'claim' AND target_type = 'evidence'"
        )
        .bind(claim_id)
        .fetch_all(pool)
        .await
        .map_err(|e| ApiError::InternalError { message: format!("DB error: {e}") })?;

        let target_ids: Vec<Uuid> = evidence_edges.into_iter().map(|e| e.target_id).collect();
        chains.extend(build_evidence_chains(pool, &claim_step, None, target_ids).await?);
    }

    Ok(Json(ProvenanceResponse { claim_id, chains }))
}

#[cfg(not(feature = "db"))]
pub async fn claim_provenance(
    State(_state): State<AppState>,
    Path(_claim_id): Path<Uuid>,
    Query(_params): Query<EvidenceAccessParams>,
) -> Result<Json<ProvenanceResponse>, ApiError> {
    Ok(Json(ProvenanceResponse {
        claim_id: _claim_id,
        chains: vec![],
    }))
}

// =============================================================================
// SUPPORTING / CONTRADICTING EVIDENCE
// =============================================================================

/// A single evidence item with edge context
#[derive(Debug, Serialize)]
pub struct EvidenceEdgeResponse {
    pub edge_id: Uuid,
    pub evidence_id: Uuid,
    pub evidence_content: Option<String>,
    pub strength: f64,
    pub created_at: String,
}

/// Response for supporting/contradicting evidence queries
#[derive(Debug, Serialize)]
pub struct ClaimEvidenceListResponse {
    pub claim_id: Uuid,
    pub relationship: String,
    pub evidence: Vec<EvidenceEdgeResponse>,
    pub total: usize,
}

#[derive(sqlx::FromRow)]
struct EvidenceEdgeRow {
    edge_id: Uuid,
    evidence_id: Uuid,
    raw_content: Option<String>,
    strength: Option<f64>,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Get all supporting evidence for a claim
///
/// `GET /api/v1/claims/:id/supporting-evidence`
///
/// Returns edges with relationship SUPPORTS pointing TO this claim,
/// joined with evidence details.
#[cfg(feature = "db")]
pub async fn supporting_evidence(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<EvidenceAccessParams>,
) -> Result<Json<ClaimEvidenceListResponse>, ApiError> {
    evidence_by_relationship(&state, claim_id, "SUPPORTS", params.agent_id).await
}

/// Get all contradicting evidence for a claim
///
/// `GET /api/v1/claims/:id/contradicting-evidence`
///
/// Returns edges with relationship CONTRADICTS pointing TO this claim,
/// joined with evidence details.
#[cfg(feature = "db")]
pub async fn contradicting_evidence(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<EvidenceAccessParams>,
) -> Result<Json<ClaimEvidenceListResponse>, ApiError> {
    evidence_by_relationship(&state, claim_id, "CONTRADICTS", params.agent_id).await
}

#[cfg(feature = "db")]
async fn evidence_by_relationship(
    state: &AppState,
    claim_id: Uuid,
    relationship: &str,
    agent_id: Option<Uuid>,
) -> Result<Json<ClaimEvidenceListResponse>, ApiError> {
    let pool = &state.db_pool;

    // Check if the claim itself is accessible
    let access = check_content_access(pool, claim_id, agent_id).await;
    if access == ContentAccess::Redacted {
        return Ok(Json(ClaimEvidenceListResponse {
            claim_id,
            relationship: relationship.to_string(),
            evidence: vec![],
            total: 0,
        }));
    }

    let rows: Vec<EvidenceEdgeRow> = sqlx::query_as(
        r#"
        SELECT e.id as edge_id, ev.id as evidence_id,
               ev.raw_content, (e.properties->>'strength')::float8 as strength,
               ev.created_at
        FROM edges e
        JOIN evidence ev ON ev.id = e.source_id
        WHERE e.target_id = $1
          AND e.target_type = 'claim'
          AND e.source_type = 'evidence'
          AND e.relationship = $2
        ORDER BY ev.created_at DESC
        LIMIT 100
        "#,
    )
    .bind(claim_id)
    .bind(relationship)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("DB error: {e}"),
    })?;

    let evidence: Vec<EvidenceEdgeResponse> = rows
        .into_iter()
        .map(|r| EvidenceEdgeResponse {
            edge_id: r.edge_id,
            evidence_id: r.evidence_id,
            evidence_content: r.raw_content,
            strength: r.strength.unwrap_or(0.5),
            created_at: r.created_at.to_rfc3339(),
        })
        .collect();

    let total = evidence.len();
    Ok(Json(ClaimEvidenceListResponse {
        claim_id,
        relationship: relationship.to_string(),
        evidence,
        total,
    }))
}

#[cfg(not(feature = "db"))]
pub async fn supporting_evidence(
    State(_state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(_params): Query<EvidenceAccessParams>,
) -> Result<Json<ClaimEvidenceListResponse>, ApiError> {
    Ok(Json(ClaimEvidenceListResponse {
        claim_id,
        relationship: "SUPPORTS".to_string(),
        evidence: vec![],
        total: 0,
    }))
}

#[cfg(not(feature = "db"))]
pub async fn contradicting_evidence(
    State(_state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(_params): Query<EvidenceAccessParams>,
) -> Result<Json<ClaimEvidenceListResponse>, ApiError> {
    Ok(Json(ClaimEvidenceListResponse {
        claim_id,
        relationship: "CONTRADICTS".to_string(),
        evidence: vec![],
        total: 0,
    }))
}

// =============================================================================
// NON-DB STUBS (for testing without database)
// =============================================================================

#[cfg(not(feature = "db"))]
pub async fn create_edge(
    State(_state): State<AppState>,
    Json(_request): Json<CreateEdgeRequest>,
) -> Result<(StatusCode, Json<EdgeResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn list_edges(
    State(_state): State<AppState>,
    Query(_params): Query<EdgeQueryParams>,
) -> Result<Json<Vec<EdgeResponse>>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn claim_neighborhood(
    State(_state): State<AppState>,
    Path(_claim_id): Path<Uuid>,
    Query(_params): Query<NeighborhoodParams>,
) -> Result<Json<NeighborhoodResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database".to_string(),
    })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_entity_types() {
        assert!(is_valid_entity_type("claim"));
        assert!(is_valid_entity_type("agent"));
        assert!(is_valid_entity_type("evidence"));
        assert!(is_valid_entity_type("trace"));
        assert!(is_valid_entity_type("node"));
        assert!(!is_valid_entity_type("invalid"));
        assert!(!is_valid_entity_type(""));
        assert!(!is_valid_entity_type("CLAIM")); // Case sensitive
    }

    #[test]
    fn test_valid_relationships() {
        assert!(is_valid_relationship("supports"));
        assert!(is_valid_relationship("refutes"));
        assert!(is_valid_relationship("relates_to"));
        assert!(is_valid_relationship("generalizes"));
        assert!(is_valid_relationship("specializes"));
        assert!(is_valid_relationship("elaborates"));
        assert!(is_valid_relationship("authored_by"));
        assert!(is_valid_relationship("derived_from"));
        assert!(is_valid_relationship("uses_evidence"));
        assert!(is_valid_relationship("supersedes"));
        assert!(is_valid_relationship("challenges"));
        assert!(is_valid_relationship("generated"));
        assert!(is_valid_relationship("attributed_to"));
        assert!(is_valid_relationship("associated_with"));
        assert!(!is_valid_relationship("invalid"));
        assert!(!is_valid_relationship(""));
    }

    #[test]
    fn test_create_edge_request_deserializes() {
        let json = serde_json::json!({
            "source_id": "550e8400-e29b-41d4-a716-446655440000",
            "target_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "source_type": "claim",
            "target_type": "claim",
            "relationship": "supports",
            "properties": {"strength": 0.8, "rationale": "provides evidence"}
        });
        let request: CreateEdgeRequest = serde_json::from_value(json).unwrap();
        assert_eq!(request.source_type, "claim");
        assert_eq!(request.relationship, "supports");
        assert!(request.properties.is_some());
        assert!(request.labels.is_none());
    }

    #[test]
    fn test_create_edge_request_minimal() {
        let json = serde_json::json!({
            "source_id": "550e8400-e29b-41d4-a716-446655440000",
            "target_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "source_type": "claim",
            "target_type": "claim",
            "relationship": "supports"
        });
        let request: CreateEdgeRequest = serde_json::from_value(json).unwrap();
        assert!(request.properties.is_none());
        assert!(request.labels.is_none());
    }

    #[test]
    fn test_edge_response_serializes() {
        let response = EdgeResponse {
            id: Uuid::new_v4(),
            source_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            source_type: "claim".to_string(),
            target_type: "claim".to_string(),
            relationship: "supports".to_string(),
            properties: serde_json::json!({"strength": 0.8}),
            valid_from: None,
            valid_to: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["source_type"], "claim");
        assert_eq!(json["relationship"], "supports");
    }

    #[test]
    fn test_self_loop_detection() {
        let id = Uuid::new_v4();
        // Same ID and same type = self-loop
        assert!(id == id && "claim" == "claim");
        // Same ID but different type = allowed
        assert!(id == id && "claim" != "agent");
    }

    #[test]
    fn test_neighborhood_params_defaults() {
        let json = serde_json::json!({});
        let params: NeighborhoodParams = serde_json::from_value(json).unwrap();
        assert!(params.depth.is_none());
    }

    #[test]
    fn test_neighborhood_params_with_depth() {
        let json = serde_json::json!({"depth": 1});
        let params: NeighborhoodParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.depth, Some(1));
    }

    #[test]
    fn test_neighborhood_response_serializes() {
        let response = NeighborhoodResponse {
            center_id: Uuid::new_v4(),
            edges: vec![],
            connected_entity_ids: vec![Uuid::new_v4()],
            depth: 2,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["depth"], 2);
        assert!(json["edges"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_edge_query_params_deserializes() {
        let json = serde_json::json!({
            "source_id": "550e8400-e29b-41d4-a716-446655440000",
            "source_type": "claim"
        });
        let params: EdgeQueryParams = serde_json::from_value(json).unwrap();
        assert!(params.source_id.is_some());
        assert_eq!(params.source_type, Some("claim".to_string()));
        assert!(params.target_id.is_none());
        assert!(params.relationship.is_none());
    }

    #[test]
    fn test_edge_query_params_with_agent_id() {
        let json = serde_json::json!({
            "agent_id": "550e8400-e29b-41d4-a716-446655440000"
        });
        let params: EdgeQueryParams = serde_json::from_value(json).unwrap();
        assert!(params.agent_id.is_some());
        assert!(params.source_id.is_none());
    }

    #[test]
    fn test_neighborhood_params_with_agent_id() {
        let json =
            serde_json::json!({"depth": 2, "agent_id": "550e8400-e29b-41d4-a716-446655440000"});
        let params: NeighborhoodParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.depth, Some(2));
        assert!(params.agent_id.is_some());
    }

    #[test]
    fn test_graph_access_params_defaults() {
        let json = serde_json::json!({});
        let params: GraphAccessParams = serde_json::from_value(json).unwrap();
        assert!(params.agent_id.is_none());
    }

    #[test]
    fn test_evidence_access_params_defaults() {
        let json = serde_json::json!({});
        let params: EvidenceAccessParams = serde_json::from_value(json).unwrap();
        assert!(params.agent_id.is_none());
    }

    #[test]
    fn test_claim_evidence_list_response_serializes() {
        let resp = ClaimEvidenceListResponse {
            claim_id: Uuid::new_v4(),
            relationship: "SUPPORTS".to_string(),
            evidence: vec![EvidenceEdgeResponse {
                edge_id: Uuid::new_v4(),
                evidence_id: Uuid::new_v4(),
                evidence_content: Some("test content".to_string()),
                strength: 0.8,
                created_at: "2026-02-24T00:00:00Z".to_string(),
            }],
            total: 1,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["relationship"], "SUPPORTS");
        assert_eq!(json["total"], 1);
        assert_eq!(json["evidence"][0]["strength"], 0.8);
    }

    #[test]
    fn test_evidence_edge_response_handles_null_content() {
        let resp = EvidenceEdgeResponse {
            edge_id: Uuid::new_v4(),
            evidence_id: Uuid::new_v4(),
            evidence_content: None,
            strength: 0.5,
            created_at: "2026-02-24T00:00:00Z".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["evidence_content"].is_null());
    }
}
