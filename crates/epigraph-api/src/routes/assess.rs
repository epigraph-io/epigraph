//! Single-call claim assessment endpoint.
//!
//! `POST /api/v1/claims/:id/assess` — computes a BBA from human-readable
//! parameters, finds or creates a DS frame, submits the evidence through
//! the standard combination pipeline, optionally generates an embedding,
//! and returns the full belief update in one response.

use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;
#[cfg(feature = "db")]
use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

fn default_open_world() -> f64 {
    0.05
}

/// Request body for `POST /api/v1/claims/:id/assess`.
#[derive(Debug, Deserialize)]
pub struct AssessClaimRequest {
    /// Evidence type key (e.g. "empirical", "statistical").
    pub evidence_type: String,
    /// Methodology key (e.g. "instrumental", "deductive_logic").
    pub methodology: String,
    /// Extraction/evidence confidence in [0, 1].
    pub confidence: f64,
    /// Whether the evidence supports the claim.
    pub supports: bool,
    /// Optional section tier for discount (e.g. "results", "methods").
    #[serde(default)]
    pub section: Option<String>,
    /// Optional journal name for reliability lookup.
    #[serde(default)]
    pub journal: Option<String>,
    /// Optional source URL for auto frame scoping.
    #[serde(default)]
    pub source_url: Option<String>,
    /// Optional supporting text stored as evidence context.
    #[serde(default)]
    pub supporting_text: Option<String>,
    /// Optional uncertainty text parsed for uncertainty discount.
    #[serde(default)]
    pub uncertainty_text: Option<String>,
    /// Explicit frame ID, or auto-create if absent.
    #[serde(default)]
    pub frame_id: Option<Uuid>,
    /// Fraction of total mass allocated to open-world ignorance, in [0, 0.5].
    #[serde(default = "default_open_world")]
    pub open_world_fraction: f64,
}

/// Response body for `POST /api/v1/claims/:id/assess`.
#[derive(Debug, Serialize)]
pub struct AssessClaimResponse {
    pub claim_id: Uuid,
    pub mass_function_id: Uuid,
    pub frame_id: Uuid,
    pub bba: BTreeMap<String, f64>,
    pub updated_belief: Option<f64>,
    pub updated_plausibility: Option<f64>,
    pub pignistic_prob: Option<f64>,
    pub mass_on_conflict: Option<f64>,
    pub embedded: bool,
    pub combination_reports: Vec<serde_json::Value>,
}

// =============================================================================
// HANDLER
// =============================================================================

/// Assess a claim: compute BBA, submit evidence, combine, update belief,
/// and optionally generate embedding — all in one call.
///
/// `POST /api/v1/claims/:id/assess`
#[cfg(feature = "db")]
pub async fn assess_claim(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Json(request): Json<AssessClaimRequest>,
) -> Result<Json<AssessClaimResponse>, ApiError> {
    use epigraph_ds::{combination, FrameOfDiscernment, MassFunction};
    use epigraph_engine::bba::{build_bba_directed, BbaParams};
    use epigraph_engine::calibration::CalibrationConfig;
    use epigraph_engine::uncertainty::parse_uncertainty;

    let pool = &state.db_pool;

    // ── 1. Load claim ────────────────────────────────────────────────────
    let claim_row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, content FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?;

    let (_, claim_content) = claim_row.ok_or(ApiError::NotFound {
        entity: "claim".to_string(),
        id: claim_id.to_string(),
    })?;

    // ── 2. Load calibration config ───────────────────────────────────────
    let calibration_config = CalibrationConfig::load(std::path::Path::new("calibration.toml"))
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to load calibration.toml: {e}"),
        })?;

    // ── 3. Parse uncertainty ─────────────────────────────────────────────
    let uncertainty = request
        .uncertainty_text
        .as_deref()
        .and_then(parse_uncertainty);

    // ── 4. Journal reliability lookup ────────────────────────────────────
    let journal_reliability = request
        .journal
        .as_deref()
        .map(|j| calibration_config.get_journal_reliability(j));

    // ── 5. Build BBA ─────────────────────────────────────────────────────
    let bba_params = BbaParams {
        evidence_type: request.evidence_type.clone(),
        methodology: request.methodology.clone(),
        confidence: request.confidence,
        supports: request.supports,
        section_tier: request.section.clone(),
        journal_reliability,
        open_world_fraction: request.open_world_fraction,
        uncertainty,
    };

    let mass_function = build_bba_directed(&bba_params, &calibration_config).map_err(|e| {
        ApiError::ValidationError {
            field: "bba_params".to_string(),
            reason: e.to_string(),
        }
    })?;

    // ── 6. Find or create frame ──────────────────────────────────────────
    let frame_id = if let Some(fid) = request.frame_id {
        // Verify it exists
        let _ = epigraph_db::FrameRepository::get_by_id(pool, fid)
            .await?
            .ok_or(ApiError::NotFound {
                entity: "frame".to_string(),
                id: fid.to_string(),
            })?;
        fid
    } else {
        let frame_name = if let Some(ref url) = request.source_url {
            let slug: String = url
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '_' })
                .collect::<String>()
                .to_lowercase();
            // Truncate to reasonable length
            let slug = if slug.len() > 80 { &slug[..80] } else { &slug };
            format!("paper_validity_{slug}")
        } else {
            "research_validity".to_string()
        };

        match epigraph_db::FrameRepository::get_by_name(pool, &frame_name).await? {
            Some(existing) => existing.id,
            None => {
                let hypotheses = vec!["supported".to_string(), "unsupported".to_string()];
                let new_frame = epigraph_db::FrameRepository::create(
                    pool,
                    &frame_name,
                    Some("Auto-created frame for claim assessment"),
                    &hypotheses,
                )
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("Failed to create frame '{frame_name}': {e}"),
                })?;
                new_frame.id
            }
        }
    };

    // Load the frame row for DS operations
    let frame_row = epigraph_db::FrameRepository::get_by_id(pool, frame_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        })?;

    let ds_frame =
        FrameOfDiscernment::new(&frame_row.name, frame_row.hypotheses.clone()).map_err(|e| {
            ApiError::InternalError {
                message: format!("Invalid frame in DB: {e}"),
            }
        })?;

    // ── 7. Convert BBA to masses map (BTreeMap<String, f64>) ─────────────
    let bba_json = mass_function.masses_to_json();
    let bba_map: BTreeMap<String, f64> =
        serde_json::from_value(bba_json.clone()).unwrap_or_default();

    // ── 8. Submit evidence through the combination pipeline ──────────────
    // Store the mass function in DB
    let mf_id = epigraph_db::MassFunctionRepository::store_with_perspective(
        pool,
        claim_id,
        frame_id,
        None, // no agent_id for assess endpoint
        None, // no perspective_id
        &bba_json,
        None,
        Some("discount"),
        None,
        None,
    )
    .await?;

    // Ensure claim is assigned to frame + create WITHIN_FRAME edge
    let _ = sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(claim_id)
    .bind(frame_id)
    .execute(pool)
    .await;
    let _ = epigraph_db::EdgeRepository::create(
        pool,
        claim_id,
        "claim",
        frame_id,
        "frame",
        "WITHIN_FRAME",
        None,
        None,
        None,
    )
    .await;

    // Retrieve all user-submitted BBAs for this (claim, frame)
    let all_rows =
        epigraph_db::MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id).await?;

    let mut indexed_rows: Vec<(Uuid, Option<Uuid>, MassFunction)> = all_rows
        .iter()
        .filter(|row| row.combination_method.as_deref() == Some("discount"))
        .filter_map(|row| {
            MassFunction::from_json_masses(ds_frame.clone(), &row.masses)
                .ok()
                .map(|m| (row.id, row.source_agent_id, m))
        })
        .collect();
    indexed_rows.sort_by_key(|(id, _, _)| *id);

    // Independence analysis
    let analysis = if indexed_rows.len() <= 1 {
        super::independence::IndependenceAnalysis::all_independent(
            indexed_rows.iter().map(|(_, _, m)| m.clone()).collect(),
        )
    } else {
        super::independence::analyze_independence(pool, &indexed_rows, 5).await?
    };

    // Cautious-combine within each dependent group
    let mut group_results = Vec::new();
    for group in &analysis.dependent_groups {
        if group.is_empty() {
            continue;
        }
        let combined_group = group
            .iter()
            .skip(1)
            .try_fold(group[0].clone(), |acc, m| {
                combination::cautious_combine(&acc, m)
            })
            .map_err(|e| ApiError::InternalError {
                message: format!("Cautious combine failed: {e}"),
            })?;
        group_results.push(combined_group);
    }

    // Merge independent BBAs + group results
    let mut for_combination: Vec<MassFunction> = analysis.independent.clone();
    for_combination.extend(group_results);

    // Standard adaptive combination
    let default_conflict_threshold = 0.3;
    let (combined, reports) = if for_combination.len() <= 1 {
        (
            for_combination
                .into_iter()
                .next()
                .unwrap_or_else(|| indexed_rows[0].2.clone()),
            vec![],
        )
    } else {
        combination::combine_multiple(&for_combination, default_conflict_threshold).map_err(
            |e| ApiError::InternalError {
                message: format!("Combination failed: {e}"),
            },
        )?
    };

    // Compute belief/plausibility for the claim's hypothesis
    let claim_assignment =
        epigraph_db::FrameRepository::get_claim_assignment(pool, claim_id, frame_id).await?;
    let h_idx = claim_assignment.and_then(|ca| ca.hypothesis_index);

    let (final_bel, final_pl, final_betp, m_missing) =
        super::belief::compute_hypothesis_belief(&combined, &ds_frame, h_idx);
    let m_empty = combined.mass_of_empty();

    // Update claim's belief, plausibility, and pignistic probability
    epigraph_db::MassFunctionRepository::update_claim_belief(
        pool,
        claim_id,
        final_bel,
        final_pl,
        m_empty,
        Some(final_betp),
        m_missing,
    )
    .await?;

    // Store the combined result as a system mass function
    let final_k = reports.last().map(|r| r.conflict_k);
    let used_cautious = !analysis.dependent_groups.is_empty();
    let final_method_str = if used_cautious {
        let adaptive = reports
            .last()
            .map(|r| format!("{:?}", r.method_used))
            .unwrap_or_else(|| "none".to_string());
        Some(format!("cautious+{adaptive}"))
    } else {
        reports.last().map(|r| format!("{:?}", r.method_used))
    };
    let final_method = final_method_str.as_deref();

    let combined_json = combined.masses_to_json();
    let _ = epigraph_db::MassFunctionRepository::store(
        pool,
        claim_id,
        frame_id,
        None, // system-generated combined result
        &combined_json,
        final_k,
        final_method,
    )
    .await;

    // Store global scoped belief cache
    let _ = epigraph_db::ScopedBeliefRepository::upsert(
        pool,
        frame_id,
        claim_id,
        "global",
        None,
        final_bel,
        final_pl,
        m_empty,
        m_missing,
        final_k,
        final_method,
        Some(final_betp),
    )
    .await;

    // Create edges reflecting DS relationships
    if final_bel > 0.5 {
        let _ = epigraph_db::EdgeRepository::create(
            pool,
            mf_id,
            "evidence",
            claim_id,
            "claim",
            "SUPPORTS",
            Some(serde_json::json!({"belief": final_bel})),
            None,
            None,
        )
        .await;
    } else if final_bel < 0.3 {
        let _ = epigraph_db::EdgeRepository::create(
            pool,
            mf_id,
            "evidence",
            claim_id,
            "claim",
            "CONTRADICTS",
            Some(serde_json::json!({"belief": final_bel})),
            None,
            None,
        )
        .await;
    }

    // ── 9. Generate embedding ────────────────────────────────────────────
    let embedded = if let Some(ref embedding_service) = state.embedding_service {
        match embedding_service.generate_query(&claim_content).await {
            Ok(embedding) => {
                let pgvector_str = format!(
                    "[{}]",
                    embedding
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );
                let store_result =
                    sqlx::query("UPDATE claims SET embedding = $1::vector WHERE id = $2")
                        .bind(&pgvector_str)
                        .bind(claim_id)
                        .execute(pool)
                        .await;
                if let Err(e) = store_result {
                    tracing::warn!(claim_id = %claim_id, error = %e, "Failed to store embedding");
                    false
                } else {
                    true
                }
            }
            Err(e) => {
                tracing::warn!(claim_id = %claim_id, error = %e, "Embedding generation failed");
                false
            }
        }
    } else {
        false
    };

    // ── 10. Build response ───────────────────────────────────────────────
    let combination_reports: Vec<serde_json::Value> = reports
        .iter()
        .map(|r| {
            serde_json::json!({
                "method_used": format!("{:?}", r.method_used),
                "conflict_k": r.conflict_k,
                "mass_on_conflict": r.mass_on_conflict,
                "mass_on_missing": r.mass_on_missing,
            })
        })
        .collect();

    Ok(Json(AssessClaimResponse {
        claim_id,
        mass_function_id: mf_id,
        frame_id,
        bba: bba_map,
        updated_belief: Some(final_bel),
        updated_plausibility: Some(final_pl),
        pignistic_prob: Some(final_betp),
        mass_on_conflict: Some(m_empty),
        embedded,
        combination_reports,
    }))
}

// Non-db stub to keep the crate compilable without the db feature
#[cfg(not(feature = "db"))]
pub async fn assess_claim() -> Result<Json<AssessClaimResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database".to_string(),
    })
}
