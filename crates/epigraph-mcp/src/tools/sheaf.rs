#![allow(clippy::wildcard_imports)]

use std::collections::HashMap;

use rmcp::model::*;
use uuid::Uuid;

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::SheafRepository;

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

/// GET-equivalent: compute CDST sheaf sections for all claims.
pub async fn check_sheaf_consistency(
    server: &EpiGraphMcpFull,
    params: CheckSheafConsistencyParams,
) -> Result<CallToolResult, McpError> {
    let min_radius = params.min_radius.unwrap_or(0.1);
    let limit = params.limit.unwrap_or(50).clamp(1, 200);

    let rows = SheafRepository::get_claim_neighbor_betp_pairs(
        &server.pool,
        None,
        limit * 10, // fetch more rows since multiple neighbors per claim
    )
    .await
    .map_err(internal_error)?;

    // Group rows by claim_id → (local_interval, neighbors)
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

        let local_iv = epigraph_engine::EpistemicInterval::from_scalar(
            claim_betp,
            row.claim_belief.unwrap_or(claim_betp),
            row.claim_plausibility.unwrap_or(claim_betp),
        );
        let local_iv = epigraph_engine::EpistemicInterval::new(
            local_iv.bel,
            local_iv.pl,
            row.claim_open_world.unwrap_or(local_iv.open_world),
        );

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
        entry.1.push((neighbor_iv, rk));
    }

    // Compute CDST sections.
    let mut sections: Vec<SheafSectionEntry> = neighbor_map
        .into_iter()
        .map(|(claim_id, (local_interval, neighbors))| {
            let section =
                epigraph_engine::compute_cdst_section(claim_id, local_interval, &neighbors);
            SheafSectionEntry {
                node_id: section.node_id.to_string(),
                local_betp: section.local_betp,
                expected_betp: section.expected_betp,
                consistency_radius: section.consistency_radius,
                neighbor_count: section.neighbor_count,
                local_belief: section.local_interval.bel,
                local_plausibility: section.local_interval.pl,
                open_world_local: section.open_world_local,
                open_world_expected: section.open_world_expected,
                interval_inconsistency: section.interval_inconsistency,
                ignorance_inconsistency: section.ignorance_inconsistency,
            }
        })
        .filter(|s| s.consistency_radius >= min_radius)
        .collect();

    // Sort by consistency_radius descending (worst first).
    sections.sort_by(|a, b| {
        b.consistency_radius
            .partial_cmp(&a.consistency_radius)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    sections.truncate(limit as usize);

    let max_radius = sections
        .first()
        .map(|s| s.consistency_radius)
        .unwrap_or(0.0);

    success_json(&CheckSheafConsistencyResponse {
        sections,
        min_radius_threshold: min_radius,
        max_radius,
    })
}

/// Compute sheaf cohomology — global inconsistency measure with decomposed H¹.
pub async fn sheaf_cohomology(
    server: &EpiGraphMcpFull,
    params: SheafCohomologyParams,
) -> Result<CallToolResult, McpError> {
    let threshold = params.threshold.unwrap_or(0.05);

    let edge_pairs = SheafRepository::get_epistemic_edge_pairs(&server.pool, None)
        .await
        .map_err(internal_error)?;

    let profile = epigraph_engine::sheaf::RestrictionProfile::scientific();

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

    let top_obstructions: Vec<CdstObstructionEntry> = cohomology
        .obstructions
        .iter()
        .take(50)
        .map(|o| CdstObstructionEntry {
            source_id: o.source_id.to_string(),
            target_id: o.target_id.to_string(),
            relationship: o.relationship.clone(),
            source_betp: o.source_interval.betp(),
            target_betp: o.target_interval.betp(),
            expected_target_betp: o.expected_interval.betp(),
            edge_inconsistency: o.interval_inconsistency,
            obstruction_kind: format!("{:?}", o.obstruction_kind),
            conflict_component: o.conflict_component,
            ignorance_component: o.ignorance_component,
            open_world_component: o.open_world_component,
        })
        .collect();

    success_json(&SheafCohomologyResponse {
        h0: cohomology.h0,
        h1: cohomology.h1,
        h1_normalized: cohomology.h1_normalized,
        edge_count: cohomology.edge_count,
        consistency_threshold: threshold,
        conflict_h1: cohomology.conflict_h1,
        ignorance_h1: cohomology.ignorance_h1,
        open_world_h1: cohomology.open_world_h1,
        belief_conflict_count: cohomology.belief_conflict_count,
        open_world_spread_count: cohomology.open_world_spread_count,
        frame_closure_count: cohomology.frame_closure_count,
        ignorance_drift_count: cohomology.ignorance_drift_count,
        obstructions: top_obstructions,
        obstruction_count: cohomology.obstructions.len(),
    })
}

/// Phase 2: reconcile sheaf obstructions via interval belief propagation.
pub async fn reconcile_sheaf(
    server: &EpiGraphMcpFull,
    params: ReconcileSheafParams,
) -> Result<CallToolResult, McpError> {
    let edge_pairs = SheafRepository::get_epistemic_edge_pairs(&server.pool, None)
        .await
        .map_err(internal_error)?;

    let profile = match params.profile.as_deref() {
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

    // Build interval map from all nodes seen in edge_pairs.
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

    let recon_config = epigraph_engine::ReconciliationConfig {
        min_inconsistency: params.min_inconsistency.unwrap_or(0.15),
        max_depth: params.max_depth.unwrap_or(3),
        ..epigraph_engine::ReconciliationConfig::default()
    };

    let result = epigraph_engine::reconcile(cdst_obstructions, &all_intervals, &[], &recon_config);

    let updated_intervals: Vec<UpdatedIntervalEntry> = result
        .updated_intervals
        .iter()
        .take(200)
        .map(|(id, iv)| UpdatedIntervalEntry {
            node_id: id.to_string(),
            bel: iv.bel,
            pl: iv.pl,
            betp: iv.betp(),
            open_world: iv.open_world,
        })
        .collect();

    let frame_evidence_proposals: Vec<FrameEvidenceProposalEntry> = result
        .frame_evidence_proposals
        .iter()
        .take(50)
        .map(|p| FrameEvidenceProposalEntry {
            target_claim_id: p.target_claim_id.to_string(),
            evidence_source_id: p.evidence_source_id.to_string(),
            proposed_reduction: p.proposed_reduction,
            confidence: p.confidence,
            scope_description: p.scope_description.clone(),
        })
        .collect();

    let oversized_clusters: Vec<OversizedClusterEntry> = result
        .oversized_clusters
        .iter()
        .map(|c| OversizedClusterEntry {
            node_count: c.node_count,
            obstruction_count: c.obstruction_count,
            max_inconsistency: c.max_inconsistency,
        })
        .collect();

    success_json(&ReconcileSheafResponse {
        clusters_processed: result.clusters_processed,
        converged: result.converged,
        total_iterations: result.total_iterations,
        updated_count: result.updated_intervals.len(),
        updated_intervals,
        frame_evidence_proposals,
        oversized_clusters,
        min_inconsistency: recon_config.min_inconsistency,
        max_depth: recon_config.max_depth,
    })
}
