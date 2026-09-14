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
use crate::middleware::bearer::ViewerExtractor;
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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Json(request): Json<CreateHypothesisRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // ONE EXTRACTOR, NOT TWO, AND IT IS THE VIEWER.
    //
    // The first revision of this change took `RequirePrincipal`, arguing that
    // "the derivation needs a principal id, not a visibility predicate". That
    // is inverted for this handler: step 4 below is a corpus-wide read whose
    // aggregates go into the response, so it needs the predicate too — and
    // `RequirePrincipal` would have guaranteed no lint ever noticed, because
    // the registers key on which extractor a handler holds. `ViewerExtractor`
    // supplies BOTH: `viewer.principal()` is the same uuid, and the viewer is
    // spent on the neighborhood read rather than left unspent.
    //
    // Identical 401 posture either way — both extractors refuse a missing
    // `AuthContext` and a token whose `agent_id` is `None`, in that order.
    //
    // `None` here is a bypass viewer, which `ViewerExtractor` never produces;
    // it is refused rather than defaulted, because the alternative is deriving
    // a row's owner from nothing.
    let principal = viewer.principal().ok_or_else(|| ApiError::Unauthorized {
        reason: "a hypothesis must be owned by a principal".into(),
    })?;
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
    //
    // Tenancy declaration. This statement binds no parent, so migration 074 has
    // nothing to inherit from and the write must name both columns.
    //
    // THE OWNER COMES FROM THE AUTHENTICATED PRINCIPAL, not from the body.
    // `routes/claims.rs::create_claim` made this move already and this handler
    // could not, for a stated reason that no longer holds: it had no principal
    // at all. `ViewerExtractor` supplies one, so the divergence closes. The
    // argument is the same one recorded there: `owner_group_id` decides whose
    // group a later privatization acts on, and deriving it from an
    // unauthenticated body field lets a caller place rows into a group it is
    // not a member of.
    //
    // AUTHORSHIP IS A SEPARATE QUESTION AND IS STILL OPEN. `claims.agent_id`
    // continues to come from the body; nothing here checks that the caller may
    // author as it, and this handler deliberately does not invent that check --
    // see `routes/claims.rs::create_claim`, which documents the same decoupling
    // and the in-repo consumer that constrains any answer. Tracked as
    // `D-PR16-claim-authorship-is-not-a-credential` in
    // `docs/tenancy/progress.json`, with an owner.
    let content_hash = epigraph_crypto::ContentHasher::hash(request.statement.as_bytes());
    let decl =
        epigraph_db::ClaimRepository::default_decl_for_author_pool(&state.db_pool, principal)
            .await?;
    let claim_id: (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties, embedding, visibility, owner_group_id)
        VALUES ($1, $2, $3, 0.5, ARRAY['hypothesis'], $4, $5::vector, $6, $7)
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
    .bind(decl.visibility_bind())
    .bind(decl.owner_group_bind())
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
    //
    //    READ THROUGH THE VIEWER. This was an inline, pool-level `SELECT ...
    //    FROM claims c` in the route layer, and every number in the `voi`
    //    object below — plus `neighborhood_size` — is an aggregate over its
    //    rows. `statement` and `search_radius` are both caller-supplied, so an
    //    unfiltered scan makes the response a function of claims the caller may
    //    not read. Inert while the corpus is entirely public; not inert once
    //    `routes/privatization.rs` has run, which it can today.
    //
    //    Moved to `ClaimRepository::grounded_neighborhood`, where CLAUDE.md
    //    says the SQL belongs, and where BOTH relations are marked — see that
    //    function for why the grounding subquery's `edges` needs the predicate
    //    as much as `claims` does.
    //
    //    BEHAVIOUR: on a wholly public corpus the result set is byte-identical
    //    (`visibility = 'public'` is the leading disjunct of both fragments).
    //    Where private claims exist, a caller outside their groups now gets a
    //    smaller neighborhood and therefore a different VOI score — which is
    //    the intended effect, and is written up in `docs/deploy.md`.
    let neighbors = epigraph_db::ClaimRepository::grounded_neighborhood(
        &state.db_pool,
        &viewer,
        &format_embedding(&embedding),
        claim_id.0,
        search_radius,
        50,
    )
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
        "unknown", // vacuous prior; no evidence yet (issue #197)
        None,      // vacuous prior — no evidence row (issue #197 Phase 3)
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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Get claim.
    //
    // PR-07 follow-up: this ran `SELECT id, content, truth_value, belief,
    // plausibility, labels, properties FROM claims WHERE id = $1` inline, with
    // no viewer — while the handler held one and spent it only on two scalar
    // reads below. A viewer-invisible claim now 404s here instead of having its
    // content, belief and properties returned.
    let (claim_content, claim_properties) =
        epigraph_db::ClaimRepository::content_and_properties(&state.db_pool, &viewer, id)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to fetch hypothesis: {e}"),
            })?
            .ok_or(ApiError::NotFound {
                entity: "hypothesis".into(),
                id: id.to_string(),
            })?;

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
        let mass_rows = epigraph_db::MassFunctionRepository::get_for_claim_frame(
            &state.db_pool,
            &viewer,
            id,
            fid,
        )
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
    let completed_with_analysis = epigraph_db::ExperimentRepository::count_completed_with_analysis(
        &state.db_pool,
        &viewer,
        id,
    )
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
        "content": claim_content,
        "status": claim_properties.get("hypothesis_status"),
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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Re-check promotion gate
    let status_response = hypothesis_status(
        ViewerExtractor(viewer.clone()),
        State(state.clone()),
        Path(id),
    )
    .await?;
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
    let mass_rows = epigraph_db::MassFunctionRepository::get_for_claim_frame(
        &state.db_pool,
        &viewer,
        id,
        hyp_frame.0,
    )
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

// `ClaimRow` was deleted with the inline claim-content read in
// `hypothesis_status`. Its replacement is
// `ClaimRepository::content_and_properties`, whose row type lives in the repo
// layer where the `/* {VISIBILITY:c} */` marker convention applies.
//
// `NeighborRow` went the same way, with the VOI neighborhood scan: its
// replacement is `epigraph_db::GroundedNeighbor`. A row type in the route layer
// is where an unfiltered read hides, so both are deliberately absent rather
// than kept "in case".
