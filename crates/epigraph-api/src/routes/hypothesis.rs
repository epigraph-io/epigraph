//! Hypothesis lifecycle endpoints.
//!
//! - POST /api/v1/hypothesis — Create hypothesis claim with VOI
//! - GET  /api/v1/hypothesis/:id/status — Belief, evidence chains, promotion readiness
//! - POST /api/v1/hypothesis/:id/promote — Promote to research_validity

#[cfg(feature = "db")]
use axum::{
    extract::{Path, State},
    Json,
};
#[cfg(feature = "db")]
use serde::Deserialize;
#[cfg(feature = "db")]
use uuid::Uuid;

#[cfg(feature = "db")]
use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct CreateHypothesisRequest {
    pub statement: String,
    pub research_question: Option<String>,
    pub search_radius: Option<f64>,
    pub agent_id: Uuid,
}

/// POST /api/v1/hypothesis — Create a hypothesis claim with VOI assessment.
#[cfg(feature = "db")]
pub async fn create_hypothesis(
    State(state): State<AppState>,
    Json(request): Json<CreateHypothesisRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let search_radius = request.search_radius.unwrap_or(0.3);

    // 1. Embed the hypothesis
    let embedder = state.embedding_service().ok_or(ApiError::InternalError {
        message: "Embedding service not configured".into(),
    })?;
    let embedding =
        embedder
            .generate(&request.statement)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to embed hypothesis: {e}"),
            })?;

    // 2. Create claim with hypothesis labels and properties
    let content_hash = epigraph_crypto::ContentHasher::hash(request.statement.as_bytes());
    let claim_id: (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties, embedding)
        VALUES ($1, $2, $3, 0.5, ARRAY['hypothesis'], $4, $5::vector)
        RETURNING id
        "#,
    )
    .bind(&request.statement)
    .bind(content_hash.as_slice())
    .bind(request.agent_id)
    .bind(serde_json::json!({
        "hypothesis_status": "active",
        "research_question": request.research_question,
        "search_radius": search_radius,
    }))
    .bind(format_embedding(&embedding))
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to create hypothesis claim: {e}"),
    })?;

    // 3. Add to hypothesis_assessment frame
    let frame_id: (Uuid,) =
        sqlx::query_as("SELECT id FROM frames WHERE name = 'hypothesis_assessment'")
            .fetch_one(&state.db_pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("hypothesis_assessment frame not found: {e}"),
            })?;

    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0)",
    )
    .bind(claim_id.0)
    .bind(frame_id.0)
    .execute(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to bind claim to frame: {e}"),
    })?;

    // 4. Compute VOI from neighborhood — only grounded claims count.
    //    A grounded claim has at least one non-claim provenance chain
    //    (paper, evidence, or analysis source). Claim-to-claim propagation
    //    alone is not grounded evidence and is excluded from the neighborhood.
    let neighbors: Vec<NeighborRow> = sqlx::query_as(
        r#"
        SELECT c.id, c.belief, c.plausibility,
               1 - (c.embedding <=> $1::vector) AS similarity
        FROM claims c
        WHERE c.embedding IS NOT NULL
          AND c.id != $2
          AND 1 - (c.embedding <=> $1::vector) >= $3
          AND EXISTS (
              SELECT 1 FROM edges e
              WHERE e.target_id = c.id
                AND e.target_type = 'claim'
                AND e.source_type IN ('paper', 'evidence', 'analysis')
                AND e.relationship IN ('asserts', 'SUPPORTS', 'concludes', 'provides_evidence')
          )
        ORDER BY similarity DESC
        LIMIT 50
        "#,
    )
    .bind(format_embedding(&embedding))
    .bind(claim_id.0)
    .bind(search_radius)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to query neighborhood: {e}"),
    })?;

    let voi_neighbors: Vec<epigraph_engine::Neighbor> = neighbors
        .iter()
        .map(|n| epigraph_engine::Neighbor {
            belief: n.belief.unwrap_or(0.0),
            plausibility: n.plausibility.unwrap_or(1.0),
            similarity: n.similarity.unwrap_or(0.0),
        })
        .collect();

    let voi = epigraph_engine::compute_voi(&voi_neighbors);

    // 5. Cache VOI score on claim
    sqlx::query("UPDATE claims SET properties = properties || $2 WHERE id = $1")
        .bind(claim_id.0)
        .bind(serde_json::json!({"voi_score": voi.score}))
        .execute(&state.db_pool)
        .await
        .ok();

    // 6. Submit vacuous mass function as prior (m(Theta) = 1.0)
    let vacuous_masses = serde_json::json!({"0,1": 1.0});
    epigraph_db::MassFunctionRepository::store(
        &state.db_pool,
        claim_id.0,
        frame_id.0,
        Some(request.agent_id),
        &vacuous_masses,
        None,
        Some("prior"),
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to store prior mass function: {e}"),
    })?;

    Ok(Json(serde_json::json!({
        "hypothesis_id": claim_id.0,
        "frame_id": frame_id.0,
        "voi": {
            "score": voi.score,
            "neighbor_count": voi.neighbor_count,
            "avg_belief_gap": voi.avg_belief_gap,
        },
        "neighborhood_size": neighbors.len(),
    })))
}

/// GET /api/v1/hypothesis/:id/status — Hypothesis status with promotion readiness.
#[cfg(feature = "db")]
pub async fn hypothesis_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Get claim
    let claim: ClaimRow = sqlx::query_as(
        "SELECT id, content, truth_value, belief, plausibility, labels, properties FROM claims WHERE id = $1"
    )
    .bind(id)
    .fetch_one(&state.db_pool)
    .await
    .map_err(|_| ApiError::NotFound { entity: "hypothesis".into(), id: id.to_string() })?;

    // Get experiments
    let experiments = epigraph_db::ExperimentRepository::get_for_hypothesis(&state.db_pool, id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("{e}"),
        })?;

    // Get mass functions in hypothesis_assessment frame
    let frame_id: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM frames WHERE name = 'hypothesis_assessment'")
            .fetch_optional(&state.db_pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("{e}"),
            })?;

    let (bel_supported, bel_unsupported) = if let Some((fid,)) = frame_id {
        let mass_rows =
            epigraph_db::MassFunctionRepository::get_for_claim_frame(&state.db_pool, id, fid)
                .await
                .unwrap_or_default();

        // Use the most recent mass function's masses for belief
        if let Some(latest) = mass_rows.last() {
            let m_supported = latest
                .masses
                .get("0")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let m_unsupported = latest
                .masses
                .get("1")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            (m_supported, m_unsupported)
        } else {
            (0.0, 0.0)
        }
    } else {
        (0.0, 0.0)
    };

    // Count completed experiments with analysis
    let completed_with_analysis =
        epigraph_db::ExperimentRepository::count_completed_with_analysis(&state.db_pool, id)
            .await
            .unwrap_or(0);

    // Check scope: find analyses that provide_evidence to this hypothesis with scope_limitations
    let has_scope: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM analyses a
            JOIN edges e ON e.source_id = a.id
                        AND e.source_type = 'analysis'
                        AND e.target_id = $1
                        AND e.target_type = 'claim'
                        AND e.relationship = 'provides_evidence'
            WHERE a.properties->>'scope_limitations' IS NOT NULL
              AND a.properties->'scope_limitations' != '[]'::jsonb
        )
        "#,
    )
    .bind(id)
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or((false,));

    let promotion_input = epigraph_engine::PromotionInput {
        bel_supported,
        bel_unsupported,
        completed_experiments_with_analysis: completed_with_analysis as usize,
        has_explicit_scope: has_scope.0,
    };
    let promotion = epigraph_engine::evaluate_promotion(&promotion_input);

    Ok(Json(serde_json::json!({
        "hypothesis_id": id,
        "content": claim.content,
        "status": claim.properties.get("hypothesis_status"),
        "belief": {
            "supported": bel_supported,
            "unsupported": bel_unsupported,
        },
        "experiments": experiments.len(),
        "completed_with_analysis": completed_with_analysis,
        "promotion": {
            "ready": promotion.ready,
            "failures": promotion.failures.iter().map(|f| format!("{f:?}")).collect::<Vec<_>>(),
        },
    })))
}

/// POST /api/v1/hypothesis/:id/promote — Promote hypothesis to research_validity.
#[cfg(feature = "db")]
pub async fn promote_hypothesis(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Re-check promotion gate
    let status_response = hypothesis_status(State(state.clone()), Path(id)).await?;
    let status_json = status_response.0;

    let ready = status_json["promotion"]["ready"].as_bool().unwrap_or(false);
    if !ready {
        return Err(ApiError::BadRequest {
            message: format!(
                "Hypothesis not ready for promotion: {:?}",
                status_json["promotion"]["failures"]
            ),
        });
    }

    // Get frame IDs
    let hyp_frame: (Uuid,) =
        sqlx::query_as("SELECT id FROM frames WHERE name = 'hypothesis_assessment'")
            .fetch_one(&state.db_pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("hypothesis_assessment frame not found: {e}"),
            })?;

    let rv_frame: (Uuid,) =
        sqlx::query_as("SELECT id FROM frames WHERE name = 'research_validity'")
            .fetch_one(&state.db_pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("research_validity frame not found: {e}"),
            })?;

    // Execute promotion as a transaction — all-or-nothing
    let mut tx = state
        .db_pool
        .begin()
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to begin transaction: {e}"),
        })?;

    // 1. Copy the most recent mass function from hypothesis_assessment to research_validity
    let mass_rows =
        epigraph_db::MassFunctionRepository::get_for_claim_frame(&state.db_pool, id, hyp_frame.0)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("{e}"),
            })?;

    if let Some(latest) = mass_rows.last() {
        sqlx::query(
            r#"
            INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses, conflict_k, combination_method)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (claim_id, frame_id, source_agent_id, perspective_id) DO UPDATE
            SET masses = EXCLUDED.masses, conflict_k = EXCLUDED.conflict_k, created_at = NOW()
            "#,
        )
        .bind(id)
        .bind(rv_frame.0)
        .bind(latest.source_agent_id)
        .bind(&latest.masses)
        .bind(latest.conflict_k)
        .bind(latest.combination_method.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::InternalError { message: format!("Failed to copy mass function: {e}") })?;
    }

    // 2. Add to research_validity frame
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0) ON CONFLICT DO NOTHING"
    )
    .bind(id)
    .bind(rv_frame.0)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::InternalError { message: format!("Failed to add to frame: {e}") })?;

    // 3. Update factors: move from hypothesis_assessment to research_validity
    sqlx::query(
        r#"
        UPDATE factors
        SET frame_id = $3
        WHERE frame_id = $1
          AND $2 = ANY(variable_ids)
        "#,
    )
    .bind(hyp_frame.0)
    .bind(id)
    .bind(rv_frame.0)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to update factors: {e}"),
    })?;

    // 4. Update hypothesis status
    sqlx::query(
        "UPDATE claims SET properties = properties || '{\"hypothesis_status\": \"promoted\"}' WHERE id = $1"
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::InternalError { message: format!("Failed to update status: {e}") })?;

    tx.commit().await.map_err(|e| ApiError::InternalError {
        message: format!("Promotion transaction failed: {e}"),
    })?;

    Ok(Json(serde_json::json!({
        "hypothesis_id": id,
        "promoted": true,
        "research_validity_frame_id": rv_frame.0,
    })))
}

// ── Internal types ──

#[cfg(feature = "db")]
fn format_embedding(embedding: &[f32]) -> String {
    format!(
        "[{}]",
        embedding
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

#[cfg(feature = "db")]
#[derive(sqlx::FromRow)]
struct NeighborRow {
    #[allow(dead_code)]
    id: Uuid,
    belief: Option<f64>,
    plausibility: Option<f64>,
    similarity: Option<f64>,
}

#[cfg(feature = "db")]
#[derive(sqlx::FromRow)]
struct ClaimRow {
    #[allow(dead_code)]
    id: Uuid,
    content: String,
    #[allow(dead_code)]
    truth_value: Option<f64>,
    #[allow(dead_code)]
    belief: Option<f64>,
    #[allow(dead_code)]
    plausibility: Option<f64>,
    #[allow(dead_code)]
    labels: Option<Vec<String>>,
    properties: serde_json::Value,
}
