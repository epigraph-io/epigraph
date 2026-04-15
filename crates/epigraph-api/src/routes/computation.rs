//! Computation endpoints for epistemic math operations.
//!
//! ## Endpoints
//!
//! - `GET  /api/v1/sheaf/consistency`     - Check sheaf consistency across claims
//! - `GET  /api/v1/sheaf/cohomology`      - Compute sheaf cohomology (global inconsistency)
//! - `POST /api/v1/sheaf/reconcile`       - Reconcile sheaf obstructions via interval BP
//! - `POST /api/v1/bp/propagate`          - Run loopy belief propagation
//! - `POST /api/v1/graph/compose`         - Compose two subgraphs via decorated cospans
//! - `GET  /api/v1/claims/:id/belief-at`  - Reconstruct belief at a past timestamp

#[cfg(feature = "db")]
use axum::{
    extract::{Path, Query, State},
    Json,
};
#[cfg(feature = "db")]
use serde::Deserialize;
#[cfg(feature = "db")]
use std::collections::HashMap;
#[cfg(feature = "db")]
use uuid::Uuid;

#[cfg(feature = "db")]
use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;

// ── Request / Response types ──

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct SheafConsistencyQuery {
    pub min_radius: Option<f64>,
    pub limit: Option<i64>,
    pub frame_id: Option<Uuid>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct SheafCohomologyQuery {
    pub threshold: Option<f64>,
    pub frame_id: Option<Uuid>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct ReconcileRequest {
    pub min_inconsistency: Option<f64>,
    pub max_depth: Option<usize>,
    pub profile: Option<String>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct PropagateRequest {
    pub frame_id: Option<Uuid>,
    pub max_iterations: Option<usize>,
    pub convergence_threshold: Option<f64>,
    pub damping: Option<f64>,
    pub apply_updates: Option<bool>,
    pub mode: Option<String>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct ComposeRequest {
    pub center_a: Uuid,
    pub center_b: Uuid,
    pub max_depth: Option<i32>,
    pub consistency_threshold: Option<f64>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct BeliefAtQuery {
    pub as_of: chrono::DateTime<chrono::Utc>,
}

// ── Handlers ──

/// GET /api/v1/sheaf/consistency - Check sheaf consistency across claims.
#[cfg(feature = "db")]
pub async fn sheaf_consistency(
    State(state): State<AppState>,
    Query(params): Query<SheafConsistencyQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let min_radius = params.min_radius.unwrap_or(0.1);
    let limit = params.limit.unwrap_or(50).clamp(1, 200);

    let rows = epigraph_db::SheafRepository::get_claim_neighbor_betp_pairs(
        &state.db_pool,
        params.frame_id,
        limit * 10, // fetch more rows since multiple neighbors per claim
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch sheaf data: {e}"),
    })?;

    // Group rows by claim_id → (local_interval, neighbors)
    // neighbor entry: (EpistemicInterval, RestrictionKind)
    let mut neighbor_map: HashMap<
        Uuid,
        (
            epigraph_engine::EpistemicInterval,
            Vec<(
                epigraph_engine::EpistemicInterval,
                epigraph_engine::RestrictionKind,
            )>,
        ),
    > = HashMap::new();

    for row in &rows {
        let claim_betp = match row.claim_betp {
            Some(v) => v,
            None => continue,
        };
        let neighbor_betp = match row.neighbor_betp {
            Some(v) => v,
            None => continue,
        };

        // Build the local interval for this claim.
        let local_iv = epigraph_engine::EpistemicInterval::from_scalar(
            claim_betp,
            row.claim_belief.unwrap_or(claim_betp),
            row.claim_plausibility.unwrap_or(claim_betp),
        );
        // Override open_world if the DB has a measured value.
        let local_iv = epigraph_engine::EpistemicInterval::new(
            local_iv.bel,
            local_iv.pl,
            row.claim_open_world.unwrap_or(local_iv.open_world),
        );

        // Build the neighbor interval. The consistency query only returns a
        // scalar neighbor_betp + optional open_world_mass. Use the scalar as
        // both bel and pl (width=0, i.e. no closed-world ignorance data), then
        // override open_world from the DB column if present.
        let neighbor_iv = {
            let base = epigraph_engine::EpistemicInterval::from_scalar(
                neighbor_betp,
                neighbor_betp,
                neighbor_betp,
            );
            epigraph_engine::EpistemicInterval::new(
                base.bel,
                base.pl,
                row.neighbor_open_world.unwrap_or(base.open_world),
            )
        };

        let rk = epigraph_engine::restriction_kind(&row.relationship);
        let entry = neighbor_map
            .entry(row.claim_id)
            .or_insert_with(|| (local_iv, Vec::new()));
        // Always use the first-seen local_iv (consistent per claim_id).
        entry.1.push((neighbor_iv, rk));
    }

    // Compute CDST sections.
    let mut sections: Vec<serde_json::Value> = neighbor_map
        .into_iter()
        .map(|(claim_id, (local_interval, neighbors))| {
            let section =
                epigraph_engine::compute_cdst_section(claim_id, local_interval, &neighbors);
            serde_json::json!({
                "node_id": section.node_id,
                "local_betp": section.local_betp,
                "expected_betp": section.expected_betp,
                "consistency_radius": section.consistency_radius,
                "neighbor_count": section.neighbor_count,
                "local_belief": section.local_interval.bel,
                "local_plausibility": section.local_interval.pl,
                "open_world_local": section.open_world_local,
                "open_world_expected": section.open_world_expected,
                "interval_inconsistency": section.interval_inconsistency,
                "ignorance_inconsistency": section.ignorance_inconsistency,
            })
        })
        .filter(|s| {
            s["consistency_radius"]
                .as_f64()
                .is_some_and(|r| r >= min_radius)
        })
        .collect();

    // Sort by consistency_radius descending (worst first).
    sections.sort_by(|a, b| {
        let ra = a["consistency_radius"].as_f64().unwrap_or(0.0);
        let rb = b["consistency_radius"].as_f64().unwrap_or(0.0);
        rb.partial_cmp(&ra).unwrap_or(std::cmp::Ordering::Equal)
    });
    sections.truncate(limit as usize);

    let max_radius = sections
        .first()
        .and_then(|s| s["consistency_radius"].as_f64())
        .unwrap_or(0.0);

    Ok(Json(serde_json::json!({
        "sections": sections,
        "count": sections.len(),
        "min_radius_threshold": min_radius,
        "max_radius": max_radius,
    })))
}

/// GET /api/v1/sheaf/cohomology - Compute sheaf cohomology (global inconsistency).
#[cfg(feature = "db")]
pub async fn sheaf_cohomology(
    State(state): State<AppState>,
    Query(params): Query<SheafCohomologyQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let threshold = params.threshold.unwrap_or(0.05);

    let edge_pairs =
        epigraph_db::SheafRepository::get_epistemic_edge_pairs(&state.db_pool, params.frame_id)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to fetch edge pairs: {e}"),
            })?;

    let profile = epigraph_engine::sheaf::RestrictionProfile::scientific();

    // Build CdstSheafObstruction for every edge with known beliefs.
    let cdst_obstructions: Vec<epigraph_engine::CdstSheafObstruction> = edge_pairs
        .iter()
        .filter_map(|ep| {
            let source_betp = ep.source_betp?;
            let target_betp = ep.target_betp?;

            let source_iv = epigraph_engine::EpistemicInterval::from_scalar(
                source_betp,
                ep.source_belief.unwrap_or(source_betp),
                ep.source_plausibility.unwrap_or(source_betp),
            );
            let source_iv = epigraph_engine::EpistemicInterval::new(
                source_iv.bel,
                source_iv.pl,
                ep.source_open_world.unwrap_or(source_iv.open_world),
            );

            let target_iv = epigraph_engine::EpistemicInterval::from_scalar(
                target_betp,
                ep.target_belief.unwrap_or(target_betp),
                ep.target_plausibility.unwrap_or(target_betp),
            );
            let target_iv = epigraph_engine::EpistemicInterval::new(
                target_iv.bel,
                target_iv.pl,
                ep.target_open_world.unwrap_or(target_iv.open_world),
            );

            Some(epigraph_engine::compute_cdst_edge_inconsistency(
                ep.source_id,
                ep.target_id,
                source_iv,
                target_iv,
                &ep.relationship,
                &profile,
            ))
        })
        .collect();

    let cohomology = epigraph_engine::compute_cdst_cohomology(cdst_obstructions, threshold);

    // Serialize top obstructions (limit to 50).
    let top_obstructions: Vec<serde_json::Value> = cohomology
        .obstructions
        .iter()
        .take(50)
        .map(|o| {
            serde_json::json!({
                "source_id": o.source_id,
                "target_id": o.target_id,
                "relationship": o.relationship,
                "source_betp": o.source_interval.betp(),
                "target_betp": o.target_interval.betp(),
                "expected_target_betp": o.expected_interval.betp(),
                "edge_inconsistency": o.interval_inconsistency,
                "obstruction_kind": format!("{:?}", o.obstruction_kind),
                "conflict_component": o.conflict_component,
                "ignorance_component": o.ignorance_component,
                "open_world_component": o.open_world_component,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "h0": cohomology.h0,
        "h1": cohomology.h1,
        "h1_normalized": cohomology.h1_normalized,
        "edge_count": cohomology.edge_count,
        "consistency_threshold": threshold,
        "conflict_h1": cohomology.conflict_h1,
        "ignorance_h1": cohomology.ignorance_h1,
        "open_world_h1": cohomology.open_world_h1,
        "belief_conflict_count": cohomology.belief_conflict_count,
        "open_world_spread_count": cohomology.open_world_spread_count,
        "frame_closure_count": cohomology.frame_closure_count,
        "ignorance_drift_count": cohomology.ignorance_drift_count,
        "obstructions": top_obstructions,
        "obstruction_count": cohomology.obstructions.len(),
    })))
}

/// POST /api/v1/sheaf/reconcile - Reconcile sheaf obstructions via interval BP.
#[cfg(feature = "db")]
pub async fn sheaf_reconcile(
    State(state): State<AppState>,
    Json(request): Json<ReconcileRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let threshold = 0.05_f64; // Use default cohomology threshold to discover obstructions.

    // Step 1: fetch all epistemic edges and build CDST obstructions.
    let edge_pairs = epigraph_db::SheafRepository::get_epistemic_edge_pairs(&state.db_pool, None)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to fetch edge pairs for reconciliation: {e}"),
        })?;

    let profile = match request.profile.as_deref() {
        Some("regulatory") => epigraph_engine::sheaf::RestrictionProfile::regulatory(),
        _ => epigraph_engine::sheaf::RestrictionProfile::scientific(),
    };

    let cdst_obstructions: Vec<epigraph_engine::CdstSheafObstruction> = edge_pairs
        .iter()
        .filter_map(|ep| {
            let source_betp = ep.source_betp?;
            let target_betp = ep.target_betp?;

            let source_iv = epigraph_engine::EpistemicInterval::from_scalar(
                source_betp,
                ep.source_belief.unwrap_or(source_betp),
                ep.source_plausibility.unwrap_or(source_betp),
            );
            let source_iv = epigraph_engine::EpistemicInterval::new(
                source_iv.bel,
                source_iv.pl,
                ep.source_open_world.unwrap_or(source_iv.open_world),
            );

            let target_iv = epigraph_engine::EpistemicInterval::from_scalar(
                target_betp,
                ep.target_belief.unwrap_or(target_betp),
                ep.target_plausibility.unwrap_or(target_betp),
            );
            let target_iv = epigraph_engine::EpistemicInterval::new(
                target_iv.bel,
                target_iv.pl,
                ep.target_open_world.unwrap_or(target_iv.open_world),
            );

            Some(epigraph_engine::compute_cdst_edge_inconsistency(
                ep.source_id,
                ep.target_id,
                source_iv,
                target_iv,
                &ep.relationship,
                &profile,
            ))
        })
        .collect();

    // Step 2: build interval map from all nodes seen in edge_pairs.
    let mut all_intervals: HashMap<Uuid, epigraph_engine::EpistemicInterval> = HashMap::new();
    for ep in &edge_pairs {
        if let Some(source_betp) = ep.source_betp {
            let source_iv = epigraph_engine::EpistemicInterval::from_scalar(
                source_betp,
                ep.source_belief.unwrap_or(source_betp),
                ep.source_plausibility.unwrap_or(source_betp),
            );
            let source_iv = epigraph_engine::EpistemicInterval::new(
                source_iv.bel,
                source_iv.pl,
                ep.source_open_world.unwrap_or(source_iv.open_world),
            );
            all_intervals.entry(ep.source_id).or_insert(source_iv);
        }
        if let Some(target_betp) = ep.target_betp {
            let target_iv = epigraph_engine::EpistemicInterval::from_scalar(
                target_betp,
                ep.target_belief.unwrap_or(target_betp),
                ep.target_plausibility.unwrap_or(target_betp),
            );
            let target_iv = epigraph_engine::EpistemicInterval::new(
                target_iv.bel,
                target_iv.pl,
                ep.target_open_world.unwrap_or(target_iv.open_world),
            );
            all_intervals.entry(ep.target_id).or_insert(target_iv);
        }
    }

    // Step 3: build reconciliation config from request params.
    let recon_config = epigraph_engine::ReconciliationConfig {
        min_inconsistency: request.min_inconsistency.unwrap_or(0.15),
        max_depth: request.max_depth.unwrap_or(3),
        ..epigraph_engine::ReconciliationConfig::default()
    };

    // Step 4: run reconciliation (no DB-sourced factors — use empty list).
    let result = epigraph_engine::reconcile(cdst_obstructions, &all_intervals, &[], &recon_config);

    // Serialize updated intervals (limit to 200 for response size).
    let updated: Vec<serde_json::Value> = result
        .updated_intervals
        .iter()
        .take(200)
        .map(|(id, iv)| {
            serde_json::json!({
                "node_id": id,
                "bel": iv.bel,
                "pl": iv.pl,
                "betp": iv.betp(),
                "open_world": iv.open_world,
            })
        })
        .collect();

    let oversized: Vec<serde_json::Value> = result
        .oversized_clusters
        .iter()
        .map(|c| {
            serde_json::json!({
                "node_count": c.node_count,
                "obstruction_count": c.obstruction_count,
                "max_inconsistency": c.max_inconsistency,
            })
        })
        .collect();

    let proposals: Vec<serde_json::Value> = result
        .frame_evidence_proposals
        .iter()
        .take(50)
        .map(|p| {
            serde_json::json!({
                "target_claim_id": p.target_claim_id,
                "evidence_source_id": p.evidence_source_id,
                "proposed_reduction": p.proposed_reduction,
                "confidence": p.confidence,
                "scope_description": p.scope_description,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "clusters_processed": result.clusters_processed,
        "converged": result.converged,
        "total_iterations": result.total_iterations,
        "updated_count": result.updated_intervals.len(),
        "updated_intervals": updated,
        "frame_evidence_proposals": proposals,
        "oversized_clusters": oversized,
        "min_inconsistency": recon_config.min_inconsistency,
        "max_depth": recon_config.max_depth,
        "cohomology_threshold": threshold,
    })))
}

/// POST /api/v1/bp/propagate - Run loopy belief propagation.
#[cfg(feature = "db")]
pub async fn propagate_beliefs(
    State(state): State<AppState>,
    Json(request): Json<PropagateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let config = epigraph_engine::BpConfig {
        max_iterations: request.max_iterations.unwrap_or(20),
        convergence_threshold: request.convergence_threshold.unwrap_or(0.01),
        damping: request.damping.unwrap_or(0.5),
    };
    let apply = request.apply_updates.unwrap_or(false);

    // Load factors from DB
    let factors: Vec<FactorRow> = sqlx::query_as(
        "SELECT id, factor_type, variable_ids, potential, description \
         FROM factors \
         WHERE ($1::uuid IS NULL OR frame_id = $1) \
         ORDER BY created_at",
    )
    .bind(request.frame_id)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to load factors: {e}"),
    })?;

    if factors.is_empty() {
        return Ok(Json(serde_json::json!({
            "iterations": 0,
            "converged": true,
            "max_change": 0.0,
            "messages_sent": 0,
            "factors_count": 0,
            "variables_count": 0,
            "applied": false,
            "updated_beliefs": [],
        })));
    }

    // Collect all variable IDs and load their current beliefs
    let all_var_ids: Vec<Uuid> = factors
        .iter()
        .flat_map(|f| f.variable_ids.iter().copied())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let belief_rows: Vec<(Uuid, Option<f64>)> =
        sqlx::query_as("SELECT id, pignistic_prob FROM claims WHERE id = ANY($1)")
            .bind(&all_var_ids)
            .fetch_all(&state.db_pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to load beliefs: {e}"),
            })?;

    let initial_beliefs: HashMap<Uuid, f64> = belief_rows
        .into_iter()
        .filter_map(|(id, betp)| betp.map(|v| (id, v)))
        .collect();

    // Parse factors into engine format: (factor_id, potential, variable_ids)
    let engine_factors: Vec<(Uuid, epigraph_engine::FactorPotential, Vec<Uuid>)> = factors
        .iter()
        .filter_map(|f| {
            let potential =
                epigraph_engine::FactorPotential::from_db(&f.factor_type, &f.potential)?;
            Some((f.id, potential, f.variable_ids.clone()))
        })
        .collect();

    // -- CDST branch: decide mode, load mass functions if needed ---------------
    let mode = request.mode.as_deref().unwrap_or("auto");

    // Only load mass functions when CDST might be used (skip for explicit scalar/interval)
    let use_cdst = match mode {
        "cdst" => true,
        "scalar" | "interval" => false,
        _ => {
            // Auto: load mass functions and check coverage
            let mf_rows =
                epigraph_db::MassFunctionRepository::get_for_claims(&state.db_pool, &all_var_ids)
                    .await
                    .unwrap_or_default();
            let claims_with_mf: std::collections::HashSet<Uuid> =
                mf_rows.iter().map(|r| r.claim_id).collect();
            !all_var_ids.is_empty() && claims_with_mf.len() * 2 > all_var_ids.len()
        }
    };

    if use_cdst {
        let mf_rows =
            epigraph_db::MassFunctionRepository::get_for_claims(&state.db_pool, &all_var_ids)
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("Failed to load mass functions: {e}"),
                })?;

        // Combine multiple mass functions per claim via adaptive combination
        // (a claim may have evidence from multiple sources/agents)
        let mut evidence: HashMap<Uuid, epigraph_ds::MassFunction> = HashMap::new();
        for row in &mf_rows {
            if let Ok(mf) = epigraph_engine::cdst_bp::parse_mass_function_row(&row.masses) {
                evidence
                    .entry(row.claim_id)
                    .and_modify(|existing| {
                        if let Ok((combined, _)) =
                            epigraph_ds::combination::adaptive_combine(existing, &mf, 0.3)
                        {
                            *existing = combined;
                        }
                    })
                    .or_insert(mf);
            }
        }

        // Build initial beliefs: evidence where available, vacuous otherwise
        let initial: HashMap<Uuid, epigraph_ds::MassFunction> = all_var_ids
            .iter()
            .map(|id| {
                (
                    *id,
                    evidence
                        .get(id)
                        .cloned()
                        .unwrap_or_else(epigraph_engine::cdst_bp::vacuous),
                )
            })
            .collect();

        let cdst_config = epigraph_engine::cdst_bp::CdstBpConfig {
            max_iterations: config.max_iterations,
            convergence_threshold: config.convergence_threshold,
            damping: config.damping,
            ..epigraph_engine::cdst_bp::CdstBpConfig::default()
        };

        let result = epigraph_engine::cdst_bp::run_cdst_bp(
            &engine_factors,
            &initial,
            &evidence,
            &cdst_config,
        );

        // Apply updates: write pignistic_prob, belief, plausibility to claims
        let mut apply_failures = 0_usize;
        if apply {
            for (claim_id, betp) in &result.updated_betps {
                let iv = result
                    .updated_intervals
                    .iter()
                    .find(|(id, _)| id == claim_id)
                    .map(|(_, iv)| iv);
                let (bel, pl) = iv.map(|i| (i.bel, i.pl)).unwrap_or((0.0, 1.0));
                if sqlx::query(
                    "UPDATE claims SET pignistic_prob = $1, belief = $2, plausibility = $3, updated_at = NOW() WHERE id = $4",
                )
                .bind(betp).bind(bel).bind(pl).bind(claim_id)
                .execute(&state.db_pool)
                .await
                .is_err() {
                    apply_failures += 1;
                }
            }
        }

        return Ok(Json(serde_json::json!({
            "mode": "cdst",
            "iterations": result.iterations,
            "converged": result.converged,
            "max_change": result.max_change,
            "max_conflict": result.max_conflict,
            "messages_sent": result.messages_sent,
            "factors_count": engine_factors.len(),
            "variables_count": all_var_ids.len(),
            "applied": apply,
            "apply_failures": apply_failures,
            "updated_beliefs": result.updated_betps.iter()
                .map(|(id, betp)| serde_json::json!({"claim_id": id, "betp": betp}))
                .collect::<Vec<_>>(),
        })));
    }

    // -- Scalar BP fallback ---------------------------------------------------
    let result = epigraph_engine::run_bp(&engine_factors, &initial_beliefs, &config);

    if apply && !result.updated_beliefs.is_empty() {
        for (claim_id, new_betp) in &result.updated_beliefs {
            let _ = sqlx::query("UPDATE claims SET pignistic_prob = $1 WHERE id = $2")
                .bind(new_betp)
                .bind(claim_id)
                .execute(&state.db_pool)
                .await;
        }
    }

    let updated: Vec<serde_json::Value> = result
        .updated_beliefs
        .iter()
        .map(|(id, betp)| serde_json::json!({"claim_id": id, "betp": betp}))
        .collect();

    Ok(Json(serde_json::json!({
        "mode": "scalar",
        "iterations": result.iterations,
        "converged": result.converged,
        "max_change": result.max_change,
        "messages_sent": result.messages_sent,
        "factors_count": engine_factors.len(),
        "variables_count": all_var_ids.len(),
        "applied": apply,
        "updated_beliefs": updated,
    })))
}

/// POST /api/v1/graph/compose - Compose two subgraphs via decorated cospans.
#[cfg(feature = "db")]
pub async fn compose_subgraphs(
    State(state): State<AppState>,
    Json(request): Json<ComposeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let max_depth = request.max_depth.unwrap_or(2).clamp(1, 4);
    let threshold = request.consistency_threshold.unwrap_or(0.2);

    // Extract neighborhoods via recursive CTE
    let left_nodes = extract_neighborhood(&state.db_pool, request.center_a, max_depth).await?;
    let right_nodes = extract_neighborhood(&state.db_pool, request.center_b, max_depth).await?;

    // Determine boundary (shared nodes)
    let left_set: std::collections::HashSet<Uuid> = left_nodes.iter().copied().collect();
    let right_set: std::collections::HashSet<Uuid> = right_nodes.iter().copied().collect();
    let boundary: Vec<Uuid> = left_set.intersection(&right_set).copied().collect();

    let left_interior: Vec<Uuid> = left_set.difference(&right_set).copied().collect();
    let right_interior: Vec<Uuid> = right_set.difference(&left_set).copied().collect();

    // Load beliefs for all nodes
    let all_ids: Vec<Uuid> = left_nodes
        .iter()
        .chain(right_nodes.iter())
        .copied()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let belief_rows: Vec<(Uuid, Option<f64>)> =
        sqlx::query_as("SELECT id, pignistic_prob FROM claims WHERE id = ANY($1)")
            .bind(&all_ids)
            .fetch_all(&state.db_pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to load beliefs: {e}"),
            })?;

    let beliefs: HashMap<Uuid, f64> = belief_rows
        .into_iter()
        .filter_map(|(id, betp)| betp.map(|v| (id, v)))
        .collect();

    let left_beliefs: HashMap<Uuid, f64> = left_nodes
        .iter()
        .filter_map(|id| beliefs.get(id).map(|v| (*id, *v)))
        .collect();

    let right_beliefs: HashMap<Uuid, f64> = right_nodes
        .iter()
        .filter_map(|id| beliefs.get(id).map(|v| (*id, *v)))
        .collect();

    let left_cospan = epigraph_engine::DecoratedCospan {
        interior_ids: left_interior.clone(),
        boundary_ids: boundary.clone(),
        beliefs: left_beliefs,
    };

    let right_cospan = epigraph_engine::DecoratedCospan {
        interior_ids: right_interior.clone(),
        boundary_ids: boundary.clone(),
        beliefs: right_beliefs,
    };

    let result = epigraph_engine::compose_cospans(&left_cospan, &right_cospan, threshold);

    Ok(Json(serde_json::json!({
        "center_a": request.center_a,
        "center_b": request.center_b,
        "max_depth": max_depth,
        "left_interior": left_interior.len(),
        "left_boundary": boundary.len(),
        "right_interior": right_interior.len(),
        "right_boundary": boundary.len(),
        "shared_boundary_size": result.boundary_size,
        "boundary_inconsistency": result.boundary_inconsistency,
        "consistent": result.consistent,
        "total_nodes": all_ids.len(),
    })))
}

/// GET /api/v1/claims/:id/belief-at - Reconstruct belief at a past timestamp.
#[cfg(feature = "db")]
pub async fn belief_at_time(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<BeliefAtQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Verify claim exists
    let _claim = epigraph_db::ClaimRepository::get_by_id(&state.db_pool, claim_id.into())
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to fetch claim: {e}"),
        })?
        .ok_or(ApiError::NotFound {
            entity: "claim".into(),
            id: claim_id.to_string(),
        })?;

    // Fetch all evidence up to the given timestamp
    let evidence_rows: Vec<EvidenceAtRow> = sqlx::query_as(
        "SELECT e.id, e.evidence_type, e.properties, e.created_at \
         FROM evidence e \
         JOIN edges ed ON ed.source_id = e.id AND ed.target_type = 'claim' AND ed.target_id = $1 \
         WHERE e.created_at <= $2 \
         ORDER BY e.created_at ASC",
    )
    .bind(claim_id)
    .bind(params.as_of)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch evidence: {e}"),
    })?;

    // Replay evidence through Bayesian updater
    // TODO: migrate to CDST pignistic probability (BayesianUpdater is deprecated)
    #[allow(deprecated)]
    let updater = epigraph_engine::BayesianUpdater::new();
    let mut truth = epigraph_core::TruthValue::new(0.5).unwrap(); // Start at maximum uncertainty

    for ev in &evidence_rows {
        let confidence = ev
            .properties
            .as_ref()
            .and_then(|p| p.get("confidence"))
            .and_then(|c| c.as_f64())
            .unwrap_or(0.5);

        let supports = ev
            .properties
            .as_ref()
            .and_then(|p| p.get("supports"))
            .and_then(|s| s.as_bool())
            .unwrap_or(true);

        let result = if supports {
            updater.update_with_support(truth, confidence)
        } else {
            updater.update_with_refutation(truth, confidence)
        };

        if let Ok(new_truth) = result {
            truth = new_truth;
        }
    }

    let truth_val = truth.value();

    Ok(Json(serde_json::json!({
        "claim_id": claim_id,
        "as_of": params.as_of.to_rfc3339(),
        "evidence_count": evidence_rows.len(),
        "epistemic_state": {
            "truth_value": truth_val,
        },
    })))
}

// ── Internal types ──

#[cfg(feature = "db")]
#[derive(sqlx::FromRow)]
struct FactorRow {
    #[allow(dead_code)]
    id: Uuid,
    factor_type: String,
    variable_ids: Vec<Uuid>,
    potential: serde_json::Value,
    #[allow(dead_code)]
    description: Option<String>,
}

#[cfg(feature = "db")]
#[derive(sqlx::FromRow)]
struct EvidenceAtRow {
    #[allow(dead_code)]
    id: Uuid,
    #[allow(dead_code)]
    evidence_type: String,
    properties: Option<serde_json::Value>,
    #[allow(dead_code)]
    created_at: chrono::DateTime<chrono::Utc>,
}

// ── Internal helpers ──

/// Extract the neighborhood of a node via recursive CTE.
#[cfg(feature = "db")]
async fn extract_neighborhood(
    pool: &sqlx::PgPool,
    center: Uuid,
    max_depth: i32,
) -> Result<Vec<Uuid>, ApiError> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "WITH RECURSIVE neighborhood AS ( \
            SELECT $1::uuid AS node_id, 0 AS depth \
            UNION \
            SELECT CASE WHEN e.source_id = n.node_id THEN e.target_id ELSE e.source_id END, \
                   n.depth + 1 \
            FROM neighborhood n \
            JOIN edges e ON ( \
                (e.source_id = n.node_id AND e.source_type = 'claim' AND e.target_type = 'claim') \
                OR (e.target_id = n.node_id AND e.source_type = 'claim' AND e.target_type = 'claim') \
            ) \
            WHERE n.depth < $2 \
              AND e.relationship IN ('supports', 'refutes', 'contradicts', 'corroborates', 'elaborates', 'specializes', 'generalizes') \
        ) \
        SELECT DISTINCT node_id FROM neighborhood",
    )
    .bind(center)
    .bind(max_depth)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to extract neighborhood: {e}"),
    })?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}
