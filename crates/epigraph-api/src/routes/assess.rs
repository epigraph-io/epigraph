//! Single-call claim assessment endpoint.
//!
//! `POST /api/v1/claims/:id/assess` — computes a BBA from human-readable
//! parameters, stores it on the canonical `claim_validity` frame (or an
//! explicit `frame_id`), combines it with the claim's earlier assessments on
//! that frame, refreshes the claim's cached belief under the
//! one-frame-owns-the-cache rule, optionally generates an embedding, and
//! returns the framed belief update in one response.

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
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
    /// Optional source URL. Context only: it no longer selects or names a frame
    /// (U027 retired the per-source `paper_validity_<slug>` frames).
    #[serde(default)]
    pub source_url: Option<String>,
    /// Optional supporting text stored as evidence context.
    #[serde(default)]
    pub supporting_text: Option<String>,
    /// Optional uncertainty text parsed for uncertainty discount.
    #[serde(default)]
    pub uncertainty_text: Option<String>,
    /// Explicit frame ID. Defaults to the canonical `claim_validity` frame
    /// (`["supported", "refuted", "uncertain"]`), resolved by its fixed id
    /// (`edge_factor::CLAIM_VALIDITY_FRAME_ID`, seeded by migration 154) and
    /// never created at request time.
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
    /// The identity this assessment is recorded under (ruling Q-U027F-2): the
    /// caller's human (its operator, or the human its client is allowlisted
    /// to), or the caller itself when bound to none. One assessment per
    /// (claim, frame, owner).
    pub owner_agent_id: Option<Uuid>,
    /// The agent that made this call (the row records the owner).
    pub assessed_by: Option<Uuid>,
    /// The owner's earlier assessment this call replaced in place (the slot row
    /// keeps its id, `mass_function_id` above). Empty when the owner had none.
    pub replaced_assessments: Vec<ReplacedAssessment>,
}

/// The owner's earlier assessment a call replaced.
#[derive(Debug, Serialize)]
pub struct ReplacedAssessment {
    /// The slot row (now holding this call's masses).
    pub mass_function_id: Uuid,
    /// The owner it was recorded under.
    pub source_agent_id: Option<Uuid>,
    /// Its BetP on the claim's hypothesis, alone, before this call replaced it.
    pub prior_pignistic_prob: Option<f64>,
    /// Whether it pointed the other way (more belief against the claim's
    /// hypothesis than for it, or the reverse): the new assessment contests it.
    pub contested: bool,
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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Json(request): Json<AssessClaimRequest>,
) -> Result<Json<AssessClaimResponse>, ApiError> {
    use epigraph_ds::{combination, FrameOfDiscernment, MassFunction};
    use epigraph_engine::bba::{build_bba_directed, remap_binary_bba_to_frame, BbaParams};
    use epigraph_engine::calibration::CalibrationConfig;
    use epigraph_engine::uncertainty::parse_uncertainty;

    let pool = &state.db_pool;

    // ── 1. Load claim ────────────────────────────────────────────────────
    //
    // PR-07: this was a bare `SELECT id, content FROM claims WHERE id = $1`
    // even though the handler holds a `Viewer` and threads it through every
    // downstream repo call. Two things were wrong with that. It made the
    // endpoint an existence-and-content oracle over arbitrary claim ids — the
    // 404 branch distinguished "does not exist" from "exists but is another
    // tenant's", and `claim_content` feeds the BBA build, so the response's
    // belief numbers were derived from content the caller may not read. And
    // because nothing between the path id and the write checked visibility, an
    // authenticated stranger could attach evidence to and mutate the belief of
    // another tenant's claim.
    //
    // `get_by_id` is viewer-filtered, so an invisible claim now takes the same
    // `None` branch as a nonexistent one and both render as 404.
    //
    // This is the READ half only. Gating the subsequent write on
    // `viewer.writable_bind()` (member-with-write-role, not merely
    // member-who-can-read) is PR-16's scope; the read fix belongs here because
    // the viewer was already in hand.
    let claim = epigraph_db::ClaimRepository::get_by_id(pool, &viewer, claim_id.into())
        .await?
        .ok_or(ApiError::NotFound {
            entity: "claim".to_string(),
            id: claim_id.to_string(),
        })?;
    let claim_content = claim.content;

    // ── 2. Load calibration config ───────────────────────────────────────
    //
    // Resolved like every other DS path (`CALIBRATION_PATH`, then the
    // workspace root), not cwd-relative: `Path::new("calibration.toml")` only
    // worked when the server happened to start in the repo root.
    let calibration_config =
        CalibrationConfig::from_workspace_root().map_err(|e| ApiError::InternalError {
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

    // ── 6. Resolve the frame ─────────────────────────────────────────────
    //
    // U027: with no explicit frame this is ALWAYS the canonical
    // `claim_validity` frame. It used to find-or-create
    // `paper_validity_<slug of source_url>` (or `research_validity`), minting a
    // 2-hypothesis frame per source (74 on prod by 2026-10-05) and panicking
    // when a multi-byte char straddled the slug's 80-byte cut.
    //
    // U027F: resolved by its fixed id, never by name and never created here.
    // A by-name get-or-create let whoever first named a frame
    // `claim_validity` (frames.name is UNIQUE) refuse every later call or
    // receive its evidence. A missing or non-canonical row refuses the call
    // before anything is written.
    let frame_id = if let Some(fid) = request.frame_id {
        // Verify it exists
        let _ = epigraph_db::FrameRepository::get_by_id(pool, &viewer, fid)
            .await?
            .ok_or(ApiError::NotFound {
                entity: "frame".to_string(),
                id: fid.to_string(),
            })?;
        fid
    } else {
        let mut conn = pool.acquire().await.map_err(|e| ApiError::InternalError {
            message: format!("acquire connection: {e}"),
        })?;
        epigraph_engine::edge_factor::resolve_claim_validity_frame(&mut conn, &viewer)
            .await
            .map_err(|message| ApiError::InternalError { message })?
    };

    // Load the frame row for DS operations
    let frame_row = epigraph_db::FrameRepository::get_by_id(pool, &viewer, frame_id)
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

    // ── 7. Re-express the BBA on the frame, then as a masses map ─────────
    //
    // `build_bba_directed` builds on its own 2-way frame. Its ignorance key
    // `"0,1"` read on a 3-way frame would mean {supported, refuted}, so the
    // remap moves it onto the target's Theta.
    let mass_function = remap_binary_bba_to_frame(&mass_function, &ds_frame).map_err(|e| {
        ApiError::ValidationError {
            field: "frame_id".to_string(),
            reason: e.to_string(),
        }
    })?;
    let bba_json = mass_function.masses_to_json();
    let bba_map: BTreeMap<String, f64> =
        serde_json::from_value(bba_json.clone()).unwrap_or_default();

    // ── 8. Store under the owner's ONE assessment slot ───────────────────
    //
    // Ruling Q-U027F-2 (operator, 2026-10-22): one assessment per (claim,
    // frame, owner). The owner is the calling agent's human operator, or the
    // agent itself when it has none. A repeat by ANY agent of that owner
    // REPLACES the owner's earlier assessment (reported, and flagged when it
    // reverses the verdict: a contest), and only different owners' assessments
    // combine as independent evidence. U027F's per-call perspective let one
    // caller stack: ten identical calls took BetP 0.61 -> 0.997.
    //
    // The row is keyed (claim, frame, OWNER, the owner's slot perspective), so
    // the slot is the table's own `UNIQUE NULLS NOT DISTINCT` key: every agent
    // of one human upserts the same row, atomically, with no delete authority
    // needed over a sibling's row and no race between two siblings, and no
    // other writer's row can share the key (`assessment_slot_perspective`).
    // `source_agent_id` names the owner, the identity whose one assessment
    // this is.
    //
    // The owner is the caller's HUMAN, by migration 149's `epigraph_human_of`
    // (live bindings only): the caller itself when it is a human, its live
    // operator link, or the human its sole client is allowlisted to; the
    // caller itself when bound to no human. A caller whose ONLY binding is a
    // retired link is refused: falling back to its own slot would let one
    // human assess twice through it. A principal-less viewer has one
    // anonymous slot.
    let caller = viewer.principal();
    let owner = match caller {
        Some(agent) => {
            let mut conn = pool.acquire().await.map_err(|e| ApiError::InternalError {
                message: format!("acquire connection: {e}"),
            })?;
            match epigraph_db::AgentRepository::human_of(&mut conn, agent, true).await? {
                Some(human) => Some(human),
                None if epigraph_db::AgentRepository::human_of(&mut conn, agent, false)
                    .await?
                    .is_some() =>
                {
                    return Err(ApiError::Forbidden {
                        reason: "this agent's link to its human is retired, so it cannot \
                                 assess on that human's behalf; nothing was written"
                            .to_string(),
                    });
                }
                None => Some(agent),
            }
        }
        None => None,
    };
    let slot = epigraph_db::repos::mass_function::assessment_slot_perspective(owner);
    epigraph_db::PerspectiveRepository::ensure_evidence_perspective(pool, slot, owner).await?;
    // The slot read and the slot upsert are ONE unit per (claim, frame, slot):
    // a transaction holding a transaction-scoped advisory lock on that key.
    // Unserialized, two concurrent calls by one owner could both read "no
    // row" before either upsert landed and both report nothing replaced
    // (backlog 4a7f90f8). The key is hashed in SQL so every server process
    // derives the same lock. READ COMMITTED (the default) gives the read
    // below a snapshot taken AFTER the lock is granted, so it sees the
    // previous holder's committed row. The transaction commits before the
    // fold below, which reads on other connections.
    let mut slot_tx = pool.begin().await.map_err(|e| ApiError::InternalError {
        message: format!("begin assessment slot transaction: {e}"),
    })?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended( \
             'epigraph/assess-slot/' || $1::text || '/' || $2::text || '/' || $3::text, 0))",
    )
    .bind(claim_id)
    .bind(frame_id)
    .bind(slot)
    .execute(&mut *slot_tx)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("lock assessment slot: {e}"),
    })?;
    // The owner's assessment this call replaces: exactly the row the upsert
    // below overwrites.
    let replaced_rows: Vec<(Uuid, Option<Uuid>, serde_json::Value)> =
        epigraph_db::MassFunctionRepository::get_for_claim_frame(
            &mut *slot_tx,
            &viewer,
            claim_id,
            frame_id,
        )
        .await?
        .into_iter()
        .filter(|row| row.source_agent_id == owner && row.perspective_id == Some(slot))
        .map(|row| (row.id, row.source_agent_id, row.masses))
        .collect();
    let mf_id = epigraph_db::MassFunctionRepository::store_with_perspective(
        &mut *slot_tx,
        claim_id,
        frame_id,
        owner,
        Some(slot),
        &bba_json,
        None,
        Some("discount"),
        None,
        // Untyped on purpose (bc06ec6f). `build_bba_directed` already sized
        // these masses with the request's type weight, so a typed row would be
        // discounted by it a second time on any later fold.
        None,
        "unknown", // assess endpoint lacks the source/target paper context (issue #197)
        None,      // assess endpoint has no evidence row in scope (issue #197 Phase 3)
    )
    .await?;
    slot_tx
        .commit()
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("commit assessment slot: {e}"),
        })?;

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

    // Retrieve all user-submitted BBAs for this (claim, frame). This fold is
    // stored as the claim's global scoped belief and returned as its updated
    // belief, so on a public claim it takes only the public-derived BBAs
    // (ruling R-22), as the cache refresh below does.
    let all_rows =
        epigraph_db::MassFunctionRepository::get_for_claim_frame(pool, &viewer, claim_id, frame_id)
            .await?;
    let all_rows = {
        let mut conn = pool.acquire().await.map_err(|e| ApiError::InternalError {
            message: format!("acquire connection: {e}"),
        })?;
        epigraph_engine::derivation_scope::retain_for_cache(&mut conn, claim_id, all_rows).await?
    };

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
        super::independence::analyze_independence(pool, &indexed_rows).await?
    };

    // Reduce each dependent group (sibling agents of one owner, ruling R-36)
    // by Denoeux's cautious rule, the reduction the engine fold applies
    // (`source_dependence::cautious_reduce`), so this response and the cache
    // agree on what siblings are worth. The min-commonality
    // `combination::cautious_combine` used here before drops open-world mass,
    // which every default-shaped assessment carries. A group the rule is not
    // defined on folds as independent, as before.
    let mut for_combination: Vec<MassFunction> = analysis.independent.clone();
    let mut used_cautious = false;
    for group in &analysis.dependent_groups {
        match epigraph_engine::source_dependence::cautious_reduce(group).map_err(|e| {
            ApiError::InternalError {
                message: format!("Cautious combine failed: {e}"),
            }
        })? {
            Some((reduced, _)) => {
                used_cautious = true;
                for_combination.push(reduced);
            }
            None => for_combination.extend(group.iter().cloned()),
        }
    }

    // Dempster fold (`combine_multiple`, U025); conflict via `fold_conflict`
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
        epigraph_db::FrameRepository::get_claim_assignment(pool, &viewer, claim_id, frame_id)
            .await?;
    let h_idx = claim_assignment.and_then(|ca| ca.hypothesis_index);

    let (final_bel, final_pl, final_betp, m_missing) =
        super::belief::compute_hypothesis_belief(&combined, &ds_frame, h_idx);

    // Each replaced assessment, and whether this call reverses its direction:
    // Bel(h) against Bel(not h) = 1 - Pl(h), so the sign does not depend on
    // the frame's size (a 0.5 BetP threshold misreads a 3-way frame).
    let direction = |m: &MassFunction| {
        let (bel, pl, _, _) = super::belief::compute_hypothesis_belief(m, &ds_frame, h_idx);
        bel - (1.0 - pl)
    };
    let new_direction = direction(&mass_function);
    let replaced_assessments: Vec<ReplacedAssessment> = replaced_rows
        .iter()
        .map(|(id, source, masses)| {
            let old = MassFunction::from_json_masses(ds_frame.clone(), masses).ok();
            ReplacedAssessment {
                mass_function_id: *id,
                source_agent_id: *source,
                prior_pignistic_prob: old
                    .as_ref()
                    .map(|m| super::belief::compute_hypothesis_belief(m, &ds_frame, h_idx).2),
                contested: old
                    .as_ref()
                    .is_some_and(|m| direction(m) * new_direction < 0.0),
            }
        })
        .collect();
    // Conflict the fold saw (U025: Dempster normalises it out of `combined`).
    let m_empty = combination::fold_conflict(&combined, &reports);

    // Refresh the claim's cached belief under the one-frame-owns-the-cache
    // rule. This used to write the numbers above straight into the cache with
    // `belief_frame_id: None`, NULLing the frame reference and clobbering a
    // `binary_truth`-owned cache with this one frame's combination. Now
    // `binary_truth` keeps the cache when the claim has a BBA there; otherwise
    // the last frame by name owns it (legacy `paper_validity_*` and
    // `research_validity` frames sort after `claim_validity`). The response
    // still reports THIS frame's numbers, which may legitimately differ from
    // the cache: the cache owner's recompute folds every row on its frame.
    {
        let mut conn = pool.acquire().await.map_err(|e| ApiError::InternalError {
            message: format!("acquire connection: {e}"),
        })?;
        epigraph_engine::edge_factor::recompute_claim_cached_belief(&mut conn, &viewer, claim_id)
            .await
            .map_err(|message| ApiError::InternalError { message })?;
    }

    // Conflict/method summary of this frame's fold, for the scoped-belief
    // cache below (no combined mass_functions row is stored).
    let final_k = reports.last().map(|r| r.conflict_k);

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

    // No "combined result" mass_functions row is stored any more: it sat on the
    // input BBA's key and overwrote it, and a recompute must never re-combine a
    // combined row. The per-frame result is cached by the upsert below.
    // So no cached row can ever sit over an agent-less input (backlog
    // b5cb3efb): the input is keyed by its owner's assessment slot
    // perspective, and nothing is stored on the (claim, frame, NULL, NULL)
    // slot.

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
        owner_agent_id: owner,
        assessed_by: caller,
        replaced_assessments,
    }))
}

// Non-db stub to keep the crate compilable without the db feature
#[cfg(not(feature = "db"))]
pub async fn assess_claim() -> Result<Json<AssessClaimResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database".to_string(),
    })
}
