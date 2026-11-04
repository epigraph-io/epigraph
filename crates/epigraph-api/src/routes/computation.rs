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
//!
//! # Tenancy: 5 of this file's 15 raw-pool sites are converted, and 10 are not
//!
//! Conversion shard 4 against `D-PR17-request-path-never-stamps-session-gucs`
//! (`epigraph-db/tests/no_unscoped_pool.rs`). Unlike `routes/belief.rs`, the
//! sites here are PER-STATEMENT rather than one alias per handler, so the file
//! can end in a state `belief.rs` cannot: a partially-converted handler. It does
//! not, and the reasons are recorded rather than left to inference.
//!
//! Converted (four read-only handlers, five sites): `sheaf_consistency`,
//! `sheaf_cohomology`, `sheaf_reconcile` and `belief_at_time` each acquire ONE
//! viewer-stamped connection through [`AppState::read_as`] and run every
//! statement on it. `sheaf_reconcile` is a POST and is still a read — it returns
//! computed proposals and persists nothing.
//!
//! Not converted, and NOT merely deferred:
//!
//! * `propagate_beliefs` (4 sites, all reads; its apply writes on a
//!   `write_as` transaction since the batch H-a review). Converting only
//!   its reads is the shape no shard in this series has reviewed — every prior
//!   shard converted whole handlers — and a half-converted handler here would
//!   change its own output silently and with a 200, so it is whole-handler work
//!   or none. ONE statement is the deliberate exception: the factor load runs
//!   on [`AppState::read_as`] because atom-level belief's `decomposes_to`
//!   exclusion (SPEC §6.2) decides its legacy arm by reading `edges`, and that
//!   read must see the caller's own private edges. `factors` has no row
//!   security and the load splices no viewer, so the stamp changes nothing
//!   else it returns. Converting the writes too is worse — `read_as` is
//!   documented read-only, `ScopedRead::commit` is not called by `Drop`, and
//!   under `SessionGucMode::Transaction` a write routed through it is rolled
//!   back while still type-checking, because `ScopedRead` is
//!   `DerefMut<Target = PgConnection>`. Its write side belongs to
//!   `ScopedPool::begin_as` plus 16b's `Viewer::splice_write`, as a whole-handler
//!   change with its own evidence. A separate question raised while classifying
//!   this handler is registered as `F-SHARD4-A2`; analysis held outside this
//!   repository, and its owner is NOT the conversion-shard series — see the
//!   entry's `assigned` field.
//! * `compose_subgraphs` (3 sites) is registered as `F-SHARD4-A1`; analysis
//!   held outside this repository. Owner: the conversion-shard series. Two of
//!   its three sites reach the database through [`extract_neighborhood`], which
//!   takes a `&PgPool` PARAMETER — a shape `no_unscoped_pool.rs` already
//!   enumerates as invisible to its `.db_pool` needle — so a change that moved
//!   this file's counter would not by itself settle the entry.

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
use crate::middleware::bearer::ViewerExtractor;
#[cfg(feature = "db")]
use crate::state::AppState;

// ── Request / Response types ──

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct SheafConsistencyQuery {
    pub min_radius: Option<f64>,
    pub limit: Option<i64>,
    pub frame_id: Option<Uuid>,
    /// Restriction profile: `regulatory`, or `scientific` (the default), as
    /// for the MCP `check_sheaf_consistency` and `POST /api/v1/sheaf/reconcile`.
    pub profile: Option<String>,
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

/// A claim's belief interval from its cached scalars: `[bel, pl]` around
/// BetP, falling back to the point interval at BetP when Bel / Pl are NULL,
/// with the measured open-world mass when there is one.
#[cfg(feature = "db")]
fn sheaf_interval(
    betp: f64,
    belief: Option<f64>,
    plausibility: Option<f64>,
    open_world: Option<f64>,
) -> epigraph_engine::EpistemicInterval {
    let base = epigraph_engine::EpistemicInterval::from_scalar(
        betp,
        belief.unwrap_or(betp),
        plausibility.unwrap_or(betp),
    );
    epigraph_engine::EpistemicInterval::new(
        base.bel,
        base.pl,
        open_world.unwrap_or(base.open_world),
    )
}

/// GET /api/v1/sheaf/consistency - Check sheaf consistency across claims.
///
/// Reads every visible claim's whole in-force neighbourhood (relationships
/// matched case-insensitively) and scores it with
/// `epigraph_engine::build_cdst_sections`, as the MCP `check_sheaf_consistency`
/// does: a directional positive edge constrains only its target, and
/// `profile` picks the restriction factors. `limit` truncates the OUTPUT
/// (worst first), never the scan.
#[cfg(feature = "db")]
pub async fn sheaf_consistency(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Query(params): Query<SheafConsistencyQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let min_radius = params.min_radius.unwrap_or(0.1);
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let profile = match params.profile.as_deref() {
        Some("regulatory") => epigraph_engine::sheaf::RestrictionProfile::regulatory(),
        _ => epigraph_engine::sheaf::RestrictionProfile::scientific(),
    };

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "sheaf_consistency",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let rows = epigraph_db::SheafRepository::get_claim_neighbor_betp_pairs(
        &mut *read,
        &viewer,
        params.frame_id,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch sheaf data: {e}"),
    })?;

    crate::routes::finish_scoped_read(read, "sheaf_consistency").await?;

    let neighbor_rows: Vec<epigraph_engine::NeighborRow> = rows
        .iter()
        .filter_map(|row| {
            Some(epigraph_engine::NeighborRow {
                claim_id: row.claim_id,
                local: sheaf_interval(
                    row.claim_betp?,
                    row.claim_belief,
                    row.claim_plausibility,
                    row.claim_open_world,
                ),
                neighbor: sheaf_interval(
                    row.neighbor_betp?,
                    row.neighbor_belief,
                    row.neighbor_plausibility,
                    row.neighbor_open_world,
                ),
                relationship: row.relationship.clone(),
                outgoing: row.direction == "outgoing",
            })
        })
        .collect();

    let mut sections: Vec<serde_json::Value> =
        epigraph_engine::build_cdst_sections(&neighbor_rows, &profile)
            .into_iter()
            .map(|section| {
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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Query(params): Query<SheafCohomologyQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let threshold = params.threshold.unwrap_or(0.05);

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "sheaf_cohomology",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let edge_pairs = epigraph_db::SheafRepository::get_epistemic_edge_pairs(
        &mut *read,
        &viewer,
        params.frame_id,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch edge pairs: {e}"),
    })?;

    crate::routes::finish_scoped_read(read, "sheaf_cohomology").await?;

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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Json(request): Json<ReconcileRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let threshold = 0.05_f64; // Use default cohomology threshold to discover obstructions.

    // Step 1: fetch all epistemic edges and build CDST obstructions.
    //
    // A POST that writes nothing: reconciliation is computed in
    // `epigraph_engine::reconcile` and returned as proposals, so this handler's
    // one statement is a read and `read_as` is the right mechanism for it.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "sheaf_reconcile",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let edge_pairs =
        epigraph_db::SheafRepository::get_epistemic_edge_pairs(&mut *read, &viewer, None)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to fetch edge pairs for reconciliation: {e}"),
            })?;

    crate::routes::finish_scoped_read(read, "sheaf_reconcile").await?;

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

/// One BP result to write: `(claim, betp, Some((belief, plausibility)))` for the
/// CDST branch, `(claim, betp, None)` for the scalar branch.
#[cfg(feature = "db")]
type BpUpdate = (Uuid, f64, Option<(f64, f64)>);

/// Write a BP run's results to `claims`, ALL OR NOTHING, on one transaction
/// stamped with the caller's viewer.
///
/// Each entry is `(claim, betp, Some((belief, plausibility)))` for the CDST
/// branch, or `(claim, betp, None)` for the scalar branch, which writes only
/// `pignistic_prob` as it always has.
///
/// # Why this replaced two loops over the raw pool
///
/// The scalar branch ran `let _ = UPDATE ... .execute(&state.db_pool)`, and the
/// CDST branch counted only `is_err()`. Neither saw an UPDATE that matched ZERO
/// rows, which is what row security does to a row the session may not see: no
/// error, nothing written. On a schema without the orphan `*_privacy` policies
/// (config A) the route therefore answered `applied: true` with a list of
/// `updated_beliefs` and wrote nothing (MEASURED, batch H-a review: 0 rows on A,
/// 13-17 on B). Now a refusal (`42501`, 403) or a zero-row UPDATE (409) fails
/// the request, and the transaction is never committed.
///
/// # A BP variable that is not a claim the caller can see is SKIPPED, and counted
///
/// `factors.variable_ids` has no foreign key to `claims`, so a factor can name
/// an id that is no longer (or never was) a claim. MEASURED on a long-lived
/// test database: 149 of 151 factors named at least one such id, and failing
/// the whole apply over it turned a working `apply_updates` on production's
/// schema into a 409. So the visible claim ids are read FIRST, on the same
/// stamped transaction; an id outside that set is skipped and reported in
/// `skipped_not_visible` rather than written or failed on. That also covers a
/// real claim the caller cannot READ, which is the correct answer for it: its
/// belief is not the caller's to write, and the response says it was not
/// written. A claim the caller can see but not WRITE is still refused (403),
/// and the whole apply is rolled back.
///
/// # A COMPOUND is never written (SPEC §1.3 D4)
///
/// Under atom-level belief a compound (a claim with an in-force
/// `decomposes_to` out-edge, `compound_ids_among_sql`) is a query over its
/// atoms and has no cache of its own; BP may still compute a value for one
/// (read-only diagnostics keep the `evidential_support` / `mutual_exclusion`
/// factors that name compounds), but apply skips it and counts it in
/// `skipped_compounds`. The role is read on the same stamped transaction, so
/// it is decided over the edges the caller can see, not structurally; see
/// `compound_ids_among_sql` for the residual that leaves.
///
/// # A claim BP could have informed from a LESS READABLE one is SKIPPED
///
/// Ruling R-22 (generalised by the security review): a claim's cached belief
/// is derived only from sources at least as widely readable as the claim.
/// BP messages travel along factors, so a claim's result can carry the belief
/// of any claim in its connected component of the run's factor graph
/// (`factor_variables`). A claim whose component holds a claim less readable
/// than itself (for a public claim, any non-public one; for a group claim,
/// another group's; and any id that is no claim the caller can read) is
/// skipped and counted in `skipped_less_readable_inputs`.
///
/// Returns `(written, skipped_not_visible, skipped_compounds,
/// skipped_less_readable_inputs)`.
#[cfg(feature = "db")]
async fn apply_bp_updates(
    state: &AppState,
    viewer: &epigraph_db::visibility::Viewer,
    updates: &[BpUpdate],
    factor_variables: &[&[Uuid]],
) -> Result<(usize, usize, usize, usize), ApiError> {
    let mut tx = state.write_as(viewer, "propagate_beliefs").await?;
    let all_variables: Vec<Uuid> = factor_variables
        .iter()
        .flat_map(|v| v.iter().copied())
        .collect();
    let tenancy =
        epigraph_db::repos::derivation_scope::DerivationScopeRepository::claim_tenancy_among(
            &mut *tx,
            viewer,
            &all_variables,
        )
        .await?;
    let informed_by_narrower = claims_informed_by_less_readable(factor_variables, &tenancy);
    let ids: Vec<Uuid> = updates.iter().map(|(id, _, _)| *id).collect();
    let visible: std::collections::HashSet<Uuid> =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM claims WHERE id = ANY($1)")
            .bind(&ids)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to read the BP variables' claims: {e}"),
            })?
            .into_iter()
            .collect();
    let compounds: std::collections::HashSet<Uuid> =
        sqlx::query_scalar::<_, Uuid>(&epigraph_db::repos::factor::compound_ids_among_sql())
            .bind(&ids)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to read the BP variables' roles: {e}"),
            })?
            .into_iter()
            .collect();
    let mut written = 0_usize;
    let mut skipped = 0_usize;
    let mut skipped_compounds = 0_usize;
    let mut skipped_less_readable = 0_usize;
    for (claim_id, betp, interval) in updates {
        if !visible.contains(claim_id) {
            skipped += 1;
            continue;
        }
        if compounds.contains(claim_id) {
            skipped_compounds += 1;
            continue;
        }
        if informed_by_narrower.contains(claim_id) {
            skipped_less_readable += 1;
            continue;
        }
        let result = match interval {
            Some((bel, pl)) => {
                sqlx::query(
                    "UPDATE claims SET pignistic_prob = $1, belief = $2, plausibility = $3, \
                     updated_at = NOW() WHERE id = $4",
                )
                .bind(betp)
                .bind(bel)
                .bind(pl)
                .bind(claim_id)
                .execute(&mut *tx)
                .await
            }
            None => {
                sqlx::query("UPDATE claims SET pignistic_prob = $1 WHERE id = $2")
                    .bind(betp)
                    .bind(claim_id)
                    .execute(&mut *tx)
                    .await
            }
        };
        let done = result.map_err(|e| {
            if crate::errors::is_insufficient_privilege(&e) {
                tracing::warn!(
                    target: "tenancy.scoped_write",
                    handler = "propagate_beliefs",
                    claim = %claim_id,
                    error = %e,
                    "the database refused a belief write"
                );
                crate::errors::write_refused("claim")
            } else {
                ApiError::InternalError {
                    message: format!("Failed to apply the belief for claim {claim_id}: {e}"),
                }
            }
        })?;
        if done.rows_affected() != 1 {
            return Err(ApiError::Conflict {
                reason: format!(
                    "the belief for claim {claim_id} could not be applied (no row updated); \
                     nothing was written"
                ),
            });
        }
        written += 1;
    }
    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit the belief updates: {e}"),
    })?;
    Ok((written, skipped, skipped_compounds, skipped_less_readable))
}

/// The stored BBAs that seed a CDST BP run, with each row's source (writing
/// agent, its owner, its same-source key), read on one viewer-stamped
/// connection.
///
/// Ruling R-22: a run that writes caches (`apply`) seeds each claim with the
/// BBAs its own recompute may fold (every source at least as widely readable
/// as the claim); a read-only run SERVES its values to the caller, so it seeds
/// with the BBAs whose every source the caller can read
/// (`derivation_scope::retain_for_viewer`). A row on a public claim is public
/// whatever it was derived from, so without either filter a stranger's BP
/// value moved with evidence narrowed to a group.
#[cfg(feature = "db")]
async fn bp_seed_rows(
    state: &AppState,
    viewer: &epigraph_db::visibility::Viewer,
    claim_ids: &[Uuid],
    apply: bool,
) -> Result<
    Vec<(
        epigraph_db::MassFunctionRow,
        epigraph_engine::source_dependence::BbaSource,
    )>,
    ApiError,
> {
    let rows =
        epigraph_db::MassFunctionRepository::get_for_claims(&state.db_pool, viewer, claim_ids)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to load mass functions: {e}"),
            })?;
    let mut read = state.read_as(viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "propagate_beliefs",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;
    let rows = if apply {
        epigraph_engine::derivation_scope::retain_for_cache(&mut read, rows).await?
    } else {
        epigraph_engine::derivation_scope::retain_for_viewer(&mut *read, viewer, rows).await?
    };
    let sources =
        epigraph_engine::source_dependence::bba_sources_for_rows(&mut read, viewer, &rows).await?;
    crate::routes::finish_scoped_read(read, "propagate_beliefs").await?;
    Ok(rows.into_iter().zip(sources).collect())
}

/// The claims of a BP run whose connected component in the factor graph
/// (`factor_variables`, one variable list per factor) holds a variable less
/// readable than the claim: one absent from `tenancy` (no claim the caller can
/// read), or a non-public one that is not the claim's own group's (for a
/// public claim, every non-public one). `tenancy` maps a claim to (`is
/// public`, owner group).
#[cfg(feature = "db")]
fn claims_informed_by_less_readable(
    factor_variables: &[&[Uuid]],
    tenancy: &std::collections::HashMap<Uuid, (bool, Uuid)>,
) -> std::collections::HashSet<Uuid> {
    use std::collections::{HashMap, HashSet};
    fn find(parent: &mut [usize], x: usize) -> usize {
        let mut root = x;
        while parent[root] != root {
            root = parent[root];
        }
        let mut cur = x;
        while parent[cur] != root {
            let next = parent[cur];
            parent[cur] = root;
            cur = next;
        }
        root
    }
    let mut index: HashMap<Uuid, usize> = HashMap::new();
    let mut parent: Vec<usize> = Vec::new();
    for vars in factor_variables {
        let mut first: Option<usize> = None;
        for v in vars.iter() {
            let i = *index.entry(*v).or_insert_with(|| {
                parent.push(parent.len());
                parent.len() - 1
            });
            match first {
                None => first = Some(i),
                Some(f) => {
                    let (a, b) = (find(&mut parent, f), find(&mut parent, i));
                    parent[a] = b;
                }
            }
        }
    }
    let mut components: HashMap<usize, Vec<Uuid>> = HashMap::new();
    let vars: Vec<(Uuid, usize)> = index.iter().map(|(v, i)| (*v, *i)).collect();
    for (v, i) in vars {
        components.entry(find(&mut parent, i)).or_default().push(v);
    }
    let mut out: HashSet<Uuid> = HashSet::new();
    for members in components.values() {
        for target in members {
            let Some(&(t_public, t_owner)) = tenancy.get(target) else {
                continue;
            };
            let narrower = members.iter().any(|v| match tenancy.get(v) {
                None => true,
                Some(&(public, owner)) => !public && (t_public || owner != t_owner),
            });
            if narrower {
                out.insert(*target);
            }
        }
    }
    out
}

/// POST /api/v1/bp/propagate - Run loopy belief propagation.
///
/// BP apply is retired: `apply_updates: true` answers 409 and writes nothing
/// unless the server runs with `EPIGRAPH_BP_APPLY=on` ([`crate::state::BpApply`]).
/// When it is on, the results are written all-or-nothing on a
/// transaction stamped with the caller's viewer (`apply_bp_updates`): a claim
/// the caller can see but not write fails the request (403) and nothing is
/// written. A BP variable that is not a claim the caller can see (a stale
/// factor id, or another group's private claim) is skipped. `applied_count` is
/// the number of claims written, `skipped_not_visible` the number skipped as
/// not visible and `skipped_compounds` the number skipped as compounds (D4);
/// `updated_beliefs` lists what BP computed, which is not the same list.
#[cfg(feature = "db")]
pub async fn propagate_beliefs(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Json(request): Json<PropagateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let config = epigraph_engine::BpConfig {
        max_iterations: request.max_iterations.unwrap_or(20),
        convergence_threshold: request.convergence_threshold.unwrap_or(0.01),
        damping: request.damping.unwrap_or(0.5),
    };
    let apply = request.apply_updates.unwrap_or(false);

    // BP apply is retired (SPEC §6.2, hazard H4): refused before anything is
    // loaded or computed, so no path below (the empty-factor early return, the
    // scalar branch's empty-result skip) can answer a write request with a 200.
    // Read-only runs are unaffected.
    if apply && state.bp_apply != crate::state::BpApply::On {
        return Err(ApiError::Conflict {
            reason: format!(
                "BP apply is retired: apply_updates:true is refused unless the server runs with \
                 {}=on. Run with apply_updates:false for a read-only BP diagnostic",
                crate::state::BP_APPLY_ENV
            ),
        });
    }

    // Load factors from DB. This is the one loader that feeds the BP engines
    // (`run_cdst_bp`, `run_bp`; interval mode runs the scalar track here), so
    // the `decomposes_to` exclusion (SPEC §6.2, D3) is applied here, once.
    //
    // On the caller's viewer-stamped connection, not the raw pool: the
    // exclusion's legacy arm matches a factor to its `decomposes_to` edge by
    // reading `edges`, which row security filters. Unstamped, that read sees
    // only public edges, so a legacy factor on a decomposition private to the
    // caller's own group would be loaded. `factors` itself has no row security.
    // The rest of this handler's reads stay where they were.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "propagate_beliefs",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;
    let factors: Vec<FactorRow> = sqlx::query_as(&format!(
        "SELECT f.id, f.factor_type, f.variable_ids, f.potential, f.description \
         FROM factors f \
         WHERE ($1::uuid IS NULL OR f.frame_id = $1) \
           AND {} \
         ORDER BY f.created_at",
        epigraph_db::repos::factor::bp_readable_factor_sql()
    ))
    .bind(request.frame_id)
    .fetch_all(&mut *read)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to load factors: {e}"),
    })?;
    crate::routes::finish_scoped_read(read, "propagate_beliefs").await?;

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

    // The run's factor graph, for apply's R-22 guard (`apply_bp_updates`).
    let factor_variables: Vec<&[Uuid]> =
        factors.iter().map(|f| f.variable_ids.as_slice()).collect();

    // -- CDST branch: decide mode, load mass functions if needed ---------------
    let mode = request.mode.as_deref().unwrap_or("auto");

    // Only load mass functions when CDST might be used (skip for explicit
    // scalar/interval). The seed rows are the ones `bp_seed_rows` admits
    // (rulings R-22 and R-36), for the coverage check too, so a BBA the
    // caller may not see a fold of cannot flip the mode either.
    let (use_cdst, seed_rows) = match mode {
        "cdst" => (
            true,
            bp_seed_rows(&state, &viewer, &all_var_ids, apply).await?,
        ),
        "scalar" | "interval" => (false, Vec::new()),
        _ => {
            // Auto: load mass functions and check coverage (a failed load
            // reads as no coverage, as before).
            let rows = bp_seed_rows(&state, &viewer, &all_var_ids, apply)
                .await
                .unwrap_or_default();
            let claims_with_mf: std::collections::HashSet<Uuid> =
                rows.iter().map(|(r, _)| r.claim_id).collect();
            let use_cdst = !all_var_ids.is_empty() && claims_with_mf.len() * 2 > all_var_ids.len();
            (use_cdst, rows)
        }
    };

    if use_cdst {
        // Combine multiple mass functions per claim via adaptive combination
        // (a claim may have evidence from multiple sources/agents). Ruling
        // R-36: agreeing BBAs of sibling agents of one human never multiply,
        // so each claim's sibling groups are first reduced by the cautious
        // rule (`reduce_same_owner_siblings`); a claim with no siblings
        // combines exactly as before.
        let mut per_claim: HashMap<
            Uuid,
            Vec<(
                epigraph_engine::source_dependence::BbaSource,
                epigraph_ds::MassFunction,
            )>,
        > = HashMap::new();
        for (row, source) in seed_rows {
            if let Ok(mf) = epigraph_engine::cdst_bp::parse_mass_function_row(&row.masses) {
                per_claim
                    .entry(row.claim_id)
                    .or_default()
                    .push((source, mf));
            }
        }
        let mut evidence: HashMap<Uuid, epigraph_ds::MassFunction> = HashMap::new();
        for (claim_id, items) in per_claim {
            let fallback: Vec<epigraph_ds::MassFunction> =
                items.iter().map(|(_, m)| m.clone()).collect();
            let inputs = epigraph_engine::source_dependence::reduce_same_owner_siblings(items, 0.3)
                .unwrap_or_else(|e| {
                    tracing::warn!(
                        %claim_id,
                        error = %e,
                        "BP seed: same-human reduction failed; combining as independent"
                    );
                    fallback
                });
            let mut inputs = inputs.into_iter();
            let Some(first) = inputs.next() else {
                continue;
            };
            let seed = inputs.fold(first, |existing, mf| {
                epigraph_ds::combination::adaptive_combine(&existing, &mf, 0.3)
                    .map(|(combined, _)| combined)
                    .unwrap_or(existing)
            });
            evidence.insert(claim_id, seed);
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

        // Load the alternative-set equivalence class for every claim from the
        // `alternative_set` view (migration 042). Empty on a fresh graph —
        // BP must not fail in that case, so we tolerate query failures and
        // proceed with an empty map (== legacy pure-Dempster behavior).
        let alt_set_rows: Vec<(Uuid, Vec<Uuid>)> =
            sqlx::query_as("SELECT claim_id, alt_members FROM alternative_set")
                .fetch_all(&state.db_pool)
                .await
                .unwrap_or_default();

        let mut alt_set_membership: epigraph_engine::cdst_bp::AltSetMembership = HashMap::new();
        for (claim_id, members) in alt_set_rows {
            alt_set_membership.insert(claim_id, members);
        }

        let cdst_config = epigraph_engine::cdst_bp::CdstBpConfig {
            max_iterations: config.max_iterations,
            convergence_threshold: config.convergence_threshold,
            damping: config.damping,
            alt_set_membership,
            ..epigraph_engine::cdst_bp::CdstBpConfig::default()
        };

        let result = epigraph_engine::cdst_bp::run_cdst_bp(
            &engine_factors,
            &initial,
            &evidence,
            &cdst_config,
        );

        // Apply updates: write pignistic_prob, belief, plausibility to claims,
        // all-or-nothing on one transaction stamped with the caller's viewer
        // (see `apply_bp_updates`). `apply_failures` stays in the response for
        // its existing readers and is now always 0: a failed apply is an error
        // with nothing written, not a count beside a 200.
        let apply_failures = 0_usize;
        let (mut written, mut skipped, mut skipped_compounds, mut skipped_less_readable) =
            (0_usize, 0_usize, 0_usize, 0_usize);
        if apply {
            let updates: Vec<BpUpdate> = result
                .updated_betps
                .iter()
                .map(|(claim_id, betp)| {
                    let (bel, pl) = result
                        .updated_intervals
                        .iter()
                        .find(|(id, _)| id == claim_id)
                        .map(|(_, iv)| (iv.bel, iv.pl))
                        .unwrap_or((0.0, 1.0));
                    (*claim_id, *betp, Some((bel, pl)))
                })
                .collect();
            (written, skipped, skipped_compounds, skipped_less_readable) =
                apply_bp_updates(&state, &viewer, &updates, &factor_variables).await?;
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
            "applied_count": written,
            "skipped_not_visible": skipped,
            "skipped_compounds": skipped_compounds,
            "skipped_less_readable_inputs": skipped_less_readable,
            "apply_failures": apply_failures,
            "updated_beliefs": result.updated_betps.iter()
                .map(|(id, betp)| serde_json::json!({"claim_id": id, "betp": betp}))
                .collect::<Vec<_>>(),
        })));
    }

    // -- Scalar BP fallback ---------------------------------------------------
    let result = epigraph_engine::run_bp(&engine_factors, &initial_beliefs, &config);

    let (mut written, mut skipped, mut skipped_compounds, mut skipped_less_readable) =
        (0_usize, 0_usize, 0_usize, 0_usize);
    if apply && !result.updated_beliefs.is_empty() {
        let updates: Vec<BpUpdate> = result
            .updated_beliefs
            .iter()
            .map(|(claim_id, new_betp)| (*claim_id, *new_betp, None))
            .collect();
        (written, skipped, skipped_compounds, skipped_less_readable) =
            apply_bp_updates(&state, &viewer, &updates, &factor_variables).await?;
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
        "applied_count": written,
        "skipped_not_visible": skipped,
        "skipped_compounds": skipped_compounds,
        "skipped_less_readable_inputs": skipped_less_readable,
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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<BeliefAtQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "belief_at_time",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // Verify claim exists
    let _claim = epigraph_db::ClaimRepository::get_by_id(&mut *read, &viewer, claim_id.into())
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to fetch claim: {e}"),
        })?
        .ok_or(ApiError::NotFound {
            entity: "claim".into(),
            id: claim_id.to_string(),
        })?;

    // Fetch all evidence up to the given timestamp.
    //
    // PR-07 follow-up: this ran inline and unfiltered while the handler held a
    // Viewer it had already spent on the existence check above. `evidence` and
    // `edges` are both tier_a in migration 062, so both are filterable; the
    // repo function now splices a predicate onto each. The exposure was an
    // inference oracle rather than raw text — `evidence_count` plus a truth
    // value replayed from `properties->confidence` — but it was gated only by
    // the parent claim's visibility, not the evidence's own.
    let evidence_rows = epigraph_db::EvidenceRepository::provided_for_claim_as_of(
        &mut *read,
        &viewer,
        claim_id,
        params.as_of,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch evidence: {e}"),
    })?;

    crate::routes::finish_scoped_read(read, "belief_at_time").await?;

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

// `EvidenceAtRow` was deleted with the inline evidence read in
// `belief_at_time`; its replacement is `epigraph_db::EvidenceAtTimeRow`, whose
// query carries `/* {VISIBILITY:e} */` and `/* {VISIBILITY:ed} */`.

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

#[cfg(all(test, feature = "db"))]
mod less_readable_tests {
    use super::claims_informed_by_less_readable;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn a_variable_that_is_no_readable_claim_counts_as_narrower() {
        // Factor (1, 2) and factor (2, 3); 3 is absent from the tenancy map
        // (a stale factor id, or a claim the caller cannot read), so every
        // claim in that component is informed by something less readable.
        let (a, b, c) = (id(1), id(2), id(3));
        let world = id(100);
        let tenancy: HashMap<Uuid, (bool, Uuid)> = [(a, (true, world)), (b, (true, world))]
            .into_iter()
            .collect();
        let f1 = [a, b];
        let f2 = [b, c];
        let out = claims_informed_by_less_readable(&[&f1, &f2], &tenancy);
        assert!(out.contains(&a) && out.contains(&b), "{out:?}");
        assert!(
            !out.contains(&c),
            "an unreadable id is not itself a claim to skip"
        );
        // Without the unreadable variable, the all-public component is clean.
        let out = claims_informed_by_less_readable(&[&f1], &tenancy);
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn a_narrower_claim_may_be_informed_by_a_more_readable_one() {
        let (public_claim, group_claim, other_group_claim) = (id(1), id(2), id(3));
        let (g, h, world) = (id(200), id(201), id(100));
        let tenancy: HashMap<Uuid, (bool, Uuid)> = [
            (public_claim, (true, world)),
            (group_claim, (false, g)),
            (other_group_claim, (false, h)),
        ]
        .into_iter()
        .collect();
        let pair = [public_claim, group_claim];
        let out = claims_informed_by_less_readable(&[&pair], &tenancy);
        assert!(out.contains(&public_claim), "{out:?}");
        assert!(!out.contains(&group_claim), "{out:?}");
        let groups = [group_claim, other_group_claim];
        let out = claims_informed_by_less_readable(&[&groups], &tenancy);
        assert!(
            out.contains(&group_claim) && out.contains(&other_group_claim),
            "{out:?}"
        );
    }
}
