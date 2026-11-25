//! Single-call claim assessment endpoint.
//!
//! `POST /api/v1/claims/:id/assess` — computes a BBA from human-readable
//! parameters, stores it on the canonical `claim_validity` frame (or an
//! explicit `frame_id`), combines it with the claim's earlier assessments on
//! that frame, refreshes the claim's cached belief under the
//! one-frame-owns-the-cache rule, optionally generates an embedding (stored
//! only on a claim the caller may write that is current and not sealed), and
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

/// The `events.event_type` of the durable record each assess call writes
/// (backlog 4a7f90f8): the calling agent as `actor_id`, and a payload of
/// `claim_id`, `frame_id`, `mass_function_id`, `owner_agent_id`,
/// `assessed_by`, `replaced` and `contested`.
///
/// The slot row names only its OWNER, so this record is the one durable place
/// that says which agent wrote it. The writer of masses a call replaced is
/// the `actor_id` of the previous record with the same `mass_function_id`,
/// ordered by `graph_version` (drawn under the slot lock, so it is that slot's
/// write order; `created_at` is not commit-ordered). Rows written before this
/// record existed have no recoverable writer.
///
/// The payload carries ids and booleans only, never masses or BetP. Its
/// `claim_id` is what lets the event list hide the record from a viewer who
/// cannot read the claim.
///
/// The type is reserved (`EventRepository::RESERVED_EVENT_TYPES`): both
/// caller-typed publish paths, `POST /api/v1/events` and the MCP
/// `publish_event` tool, refuse it, so through the API only this route's
/// assessment transaction writes it. The database holds the same line (migration
/// 250's `events_assessment_guard`): outside a maintenance session a row of
/// this type is admitted only when the SAME transaction wrote the masses of
/// the slot row it names (`mass_function_masses_writes`, written only by a
/// trigger and only when `masses` changes), for its claim, frame and
/// owner, with `actor_id` equal to `assessed_by`. That is why the record is
/// written on the assessment's own stamped transaction, the one that writes
/// the masses (a savepoint there is fine: the stamp is the top-level
/// transaction's), and why a call that re-writes the masses the
/// slot already holds files no record: it wrote no masses, and the slot's
/// last record still names the writer of the masses it holds.
///
/// It binds the record to a write of the masses, not to an identity. The
/// tenancy GUCs are session-settable, so any holder of an application DSN can
/// genuinely rewrite a slot row's masses and hold a true record of that
/// write; the record is the server's account of a write, not a cryptographic
/// proof of authorship. Before the reservation the REST path accepted this
/// type, so a row of it older than the reservation may have been filed by a
/// caller rather than by this route.
pub const ASSESSMENT_EVENT_TYPE: &str = epigraph_db::EventRepository::ASSESSMENT_EVENT_TYPE;

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
    /// The agent that made this call. The slot row records the owner; this
    /// agent is recorded durably as the `actor_id` of the call's
    /// [`ASSESSMENT_EVENT_TYPE`] event.
    pub assessed_by: Option<Uuid>,
    /// The owner's earlier assessment this call replaced in place (the slot row
    /// keeps its id, `mass_function_id` above). Empty when the owner had none.
    pub replaced_assessments: Vec<ReplacedAssessment>,
    /// Set when the claim is a COMPOUND and the server runs
    /// `EPIGRAPH_COMPOUND_WRITE_GUARD=warn` (backlog 7435772c, SPEC §4.1 W3):
    /// the assessment was stored, but a compound's belief is derived from its
    /// atoms, so it is never folded into the compound's cached belief (the
    /// derived compound view reads its refutation mass, as for every compound
    /// row). `visible_atoms` lists the atoms the caller can see (`{id, content}`, at most 50;
    /// `visible_atom_count` is the full count): assess those instead. Under
    /// `refuse` the request is refused with 422 (`compound_target`). Omitted
    /// for a claim that is not a compound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated_compound_target: Option<epigraph_engine::compound_write_guard::CompoundTarget>,
}

/// The owner's earlier assessment a call replaced.
#[derive(Debug, Serialize)]
pub struct ReplacedAssessment {
    /// The slot row (now holding this call's masses), or, when `retired`, the
    /// separate row this call retracted.
    pub mass_function_id: Uuid,
    /// The owner it was recorded under.
    pub source_agent_id: Option<Uuid>,
    /// Its BetP on the claim's hypothesis, alone, before this call replaced it.
    pub prior_pignistic_prob: Option<f64>,
    /// Whether it pointed the other way (more belief against the claim's
    /// hypothesis than for it, or the reverse): the new assessment contests it.
    pub contested: bool,
    /// `true` when this was not the owner's slot row but the assessment the
    /// CALLING agent recorded under itself while it was bound to no human
    /// (backlog 840bc5ed): once the agent is linked, its human owns the slot,
    /// so this call retracted that row (audited, `mass_functions.retract`)
    /// instead of leaving the human with two assessments. `false` for the
    /// slot row overwritten in place.
    pub retired: bool,
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
    // `claims:write`, checked before the body is parsed (backlog f00d75ab).
    _scope: crate::middleware::bearer::RequireScopeWrite,
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Json(request): Json<AssessClaimRequest>,
) -> Result<Json<AssessClaimResponse>, ApiError> {
    use epigraph_ds::{combination, FrameOfDiscernment, MassFunction};
    use epigraph_engine::bba::{build_bba_directed, remap_binary_bba_to_frame, BbaParams};
    use epigraph_engine::calibration::CalibrationConfig;
    use epigraph_engine::uncertainty::parse_uncertainty;

    // ── 0. ONE transaction stamped with the caller's viewer ──────────────
    //
    // Backlog 74feb76b. Every read and write below runs on this transaction,
    // which the caller's tenancy context stamps (`AppState::write_as`), and
    // commits before the embedding. The handler used to run on the raw
    // `state.db_pool`, which on a server is the application pool UNSTAMPED
    // (`AppState::with_scoped_pool` aliases it to `ScopedPool::inner`): under
    // FORCE row security the slot upsert was refused ("new row violates
    // row-level security policy for table mass_functions") and the call
    // answered an opaque 500 DatabaseError, a standalone claim's included
    // (measured on the application-role harness, `assess_app_role.rs`). The
    // other assess tests run on the superuser harness, which bypasses row
    // security, so none of them could see it.
    let mut tx = state.write_as(&viewer, "assess_claim").await?;

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
    let claim = epigraph_db::ClaimRepository::get_by_id(&mut *tx, &viewer, claim_id.into())
        .await?
        .ok_or(ApiError::NotFound {
            entity: "claim".to_string(),
            id: claim_id.to_string(),
        })?;
    let claim_content = claim.content;

    // ── 1b. EPIGRAPH_COMPOUND_WRITE_GUARD (backlog 7435772c, SPEC §4.1 W3) ─
    //
    // An assessment's masses carry no evidence text, so on a COMPOUND they
    // could never be attributed to its atoms. The role is decided by
    // structure (migration 193's definer), as the caller, before anything is
    // written (the slot perspective below is the first write). `refuse`
    // answers 422 with the atoms the caller can see; `warn` goes ahead (the
    // row is inert: a compound has no cache-owner frame, so the cache
    // refresh below and every later owner-rule recompute leave its cache
    // alone), reports the atoms and, once the slot row commits, logs the caller.
    let deprecated_compound_target = {
        use epigraph_engine::compound_write_guard::{decide, GuardDecision};
        match decide(
            &mut tx,
            &viewer,
            claim_id,
            state.compound_write_guard,
            "assess",
            viewer.principal(),
        )
        .await?
        {
            GuardDecision::NotCompound => None,
            GuardDecision::Accept(target) => Some(target),
            GuardDecision::Refuse(target) => {
                return Err(ApiError::CompoundTarget {
                    message: target.refusal(),
                    data: target.refusal_data(),
                });
            }
        }
    };

    // ── 2. Load calibration config ───────────────────────────────────────
    //
    // Resolved like every other DS path (`CALIBRATION_PATH`, else the
    // compiled-in workspace calibration.toml), not cwd-relative:
    // `Path::new("calibration.toml")` only worked when the server happened to
    // start in the repo root.
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
        let _ = epigraph_db::FrameRepository::get_by_id(&mut *tx, &viewer, fid)
            .await?
            .ok_or(ApiError::NotFound {
                entity: "frame".to_string(),
                id: fid.to_string(),
            })?;
        fid
    } else {
        epigraph_engine::edge_factor::resolve_claim_validity_frame(&mut tx, &viewer)
            .await
            .map_err(|message| ApiError::InternalError { message })?
    };

    // Load the frame row for DS operations
    let frame_row = epigraph_db::FrameRepository::get_by_id(&mut *tx, &viewer, frame_id)
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
    // The row is keyed (claim, frame, OWNER, the owner's assessment slot:
    // `BbaSlot::Assessment`, migration 267), so
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
        Some(agent) => match epigraph_db::AgentRepository::human_of(&mut tx, agent, true).await? {
            Some(human) => Some(human),
            None if epigraph_db::AgentRepository::human_of(&mut tx, agent, false)
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
        },
        None => None,
    };
    let slot = epigraph_db::repos::mass_function::assessment_slot_perspective(owner);

    // The claim's hypothesis on this frame, read before the slot transaction:
    // whether this call contests the assessment it replaces is decided once,
    // inside that transaction, and the durable record and the response both
    // take that one value. The `claim_frames` insert below only ever creates
    // a missing link, at index 0, which is what a missing index already
    // resolves to (`edge_factor::resolve_hypothesis_index`), so reading it
    // here gives the same values as a read after the write.
    let claim_assignment =
        epigraph_db::FrameRepository::get_claim_assignment(&mut *tx, &viewer, claim_id, frame_id)
            .await?;
    let h_idx = claim_assignment.and_then(|ca| ca.hypothesis_index);
    // Each replaced assessment, and whether this call reverses its direction:
    // Bel(h) against Bel(not h) = 1 - Pl(h), so the sign does not depend on
    // the frame's size (a 0.5 BetP threshold misreads a 3-way frame).
    let direction = |m: &MassFunction| {
        let (bel, pl, _, _) = super::belief::compute_hypothesis_belief(m, &ds_frame, h_idx);
        bel - (1.0 - pl)
    };
    let new_direction = direction(&mass_function);

    // The slot read and the slot upsert are ONE unit per (claim, frame, slot):
    // the transaction holds a transaction-scoped advisory lock on that key
    // until it commits. Unserialized, two concurrent calls by one owner could
    // both read "no row" before either upsert landed and both report nothing
    // replaced (backlog 4a7f90f8). The key is hashed in SQL so every server
    // process derives the same lock. READ COMMITTED (the default) takes each
    // statement's snapshot when it starts, so the read below, which starts
    // AFTER the lock is granted, sees the previous holder's committed row.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended( \
             'epigraph/assess-slot/' || $1::text || '/' || $2::text || '/' || $3::text, 0))",
    )
    .bind(claim_id)
    .bind(frame_id)
    .bind(slot)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("lock assessment slot: {e}"),
    })?;
    let replaced = |row: &epigraph_db::MassFunctionRow, retired: bool| {
        let old = MassFunction::from_json_masses(ds_frame.clone(), &row.masses).ok();
        ReplacedAssessment {
            mass_function_id: row.id,
            source_agent_id: row.source_agent_id,
            prior_pignistic_prob: old
                .as_ref()
                .map(|m| super::belief::compute_hypothesis_belief(m, &ds_frame, h_idx).2),
            contested: old
                .as_ref()
                .is_some_and(|m| direction(m) * new_direction < 0.0),
            retired,
        }
    };
    let rows_before = epigraph_db::MassFunctionRepository::get_for_claim_frame(
        &mut *tx, &viewer, claim_id, frame_id,
    )
    .await?;
    // The owner's assessment this call replaces: exactly the row the upsert
    // below overwrites.
    let mut replaced_assessments: Vec<ReplacedAssessment> = rows_before
        .iter()
        .filter(|row| {
            row.source_agent_id == owner
                && row.slot() == Some(epigraph_db::BbaSlot::Assessment(slot))
        })
        .map(|row| replaced(row, false))
        .collect();
    // And the calling agent's OWN earlier assessment, when the agent now
    // assesses for a human (backlog 840bc5ed). Written while the agent was
    // bound to no human, it is keyed on the agent's slot, not the human's,
    // so the upsert below does not reach it, and the human would hold two
    // assessments that combine as independent evidence (the slot rule above:
    // one per claim, frame and owner). It is retracted (migration 184: kept
    // for audit, a `mass_functions.retract` security event, out of every
    // fold) on this transaction, under the owner's slot lock, and reported.
    // Retracted rather than re-keyed: a retracted row holds its key, so the
    // agent's old slot cannot be refilled, and the history stays readable.
    // Best-effort, under a SAVEPOINT: a refusal (the agent no longer writes
    // the row's owning group) leaves the row as it was, logged, rather than
    // refusing the assessment. Only the CALLER's own row is handled; a
    // sibling agent's pre-link row is retired when that sibling assesses.
    if let Some(agent) = caller.filter(|a| owner != Some(*a)) {
        let own_slot = epigraph_db::repos::mass_function::assessment_slot_perspective(Some(agent));
        for row in rows_before.iter().filter(|r| {
            r.source_agent_id == Some(agent)
                && r.slot() == Some(epigraph_db::BbaSlot::Assessment(own_slot))
        }) {
            use sqlx::Acquire as _;
            let mut sp = tx.begin().await.map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to open a savepoint: {e}"),
            })?;
            let retracted = epigraph_db::MassFunctionRepository::retract_conn(
                &mut sp,
                row.id,
                "assessment superseded by the agent's human's assessment slot: the agent \
                 assessed this claim before it was linked to its human",
                None,
            )
            .await;
            let close = |e: sqlx::Error| ApiError::DatabaseError {
                message: format!("Failed to close a savepoint: {e}"),
            };
            match retracted {
                Ok(_) => {
                    sp.commit().await.map_err(close)?;
                    replaced_assessments.push(replaced(row, true));
                }
                Err(e) => {
                    tracing::warn!(
                        mass_function_id = %row.id,
                        "assess_claim: the caller's pre-link assessment was not retracted: {e}"
                    );
                    sp.rollback().await.map_err(close)?;
                }
            }
        }
    }
    // Whether the slot already holds exactly these masses (the slot lock
    // above holds until `tx` ends). An upsert of identical masses writes no
    // masses, so migration 250's `events_assessment_guard` refuses a record of it:
    // the record is filed only for a write that changes the slot's masses,
    // and the slot's last record keeps naming the writer of the masses it
    // holds. A plain jsonb comparison, so it answers the same before 250.
    let masses_unchanged = match owner {
        Some(o) => {
            epigraph_db::MassFunctionRepository::slot_holds_masses(
                &mut *tx, &viewer, claim_id, frame_id, o, slot, &bba_json,
            )
            .await?
        }
        None => false,
    };
    let mf_id = epigraph_db::MassFunctionRepository::store_in_slot(
        &mut *tx,
        claim_id,
        frame_id,
        owner,
        epigraph_db::BbaSlot::Assessment(slot),
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
    .await
    // Row security refuses the slot row (42501) when its stamped owner is a
    // group the caller cannot write: a non-public claim's row belongs to the
    // claim's group, so a member who may only READ that group is refused
    // here. The transaction is aborted and nothing commits, so answer 403
    // rather than an opaque 500. Mapped at the write rather than checked up
    // front: on a public claim the row is the writer's own, so a check of the
    // claim's group would refuse a legitimate cross-group assessment.
    .map_err(|e| {
        if crate::errors::db_is_insufficient_privilege(&e) {
            crate::errors::write_refused("claim's assessment")
        } else {
            ApiError::from(e)
        }
    })?;
    // The durable record of who wrote this assessment, and whether it replaced
    // and contested the owner's earlier one (backlog 4a7f90f8): in the
    // assessment's transaction, so it commits exactly when the write does, and strict (a
    // failed insert refuses the call) because a record that can silently go
    // missing leaves the write untraced, the defect it exists to close. The
    // challenge event's savepoint-wrapped `publish_or_log_conn` is the wrong
    // contract here for that reason. None when the call re-wrote the masses
    // the slot already held (above).
    if !masses_unchanged {
        epigraph_db::EventRepository::insert_on(
            &mut *tx,
            ASSESSMENT_EVENT_TYPE,
            caller,
            &serde_json::json!({
                "claim_id": claim_id,
                "frame_id": frame_id,
                "mass_function_id": mf_id,
                "owner_agent_id": owner,
                "assessed_by": caller,
                "replaced": !replaced_assessments.is_empty(),
                "contested": replaced_assessments.iter().any(|r| r.contested),
            }),
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("record the assessment's writer: {e}"),
        })?;
    }

    // Ensure the claim is assigned to the frame (best-effort, under a
    // SAVEPOINT: a non-owner's assignment is refused by row security
    // (migration 114), and unsavepointed that refusal would abort the
    // transaction and roll the assessment back at the COMMIT).
    //
    // A NEW link names hypothesis 0, as `POST /frames/:id/evidence` links one
    // (49a0ab1af): it is the index every belief read resolves a missing one
    // to, so the values this handler serves do not change. Linked with a NULL
    // index, every later Beta update on this frame counted nothing (the
    // evidence route's own `ON CONFLICT DO NOTHING` keeps the NULL), so the
    // claim's track never left Beta(1, 1) and no divergence row was ever
    // recorded for it (backlog 7e8202bb, the residual of 1ce62137). An
    // existing link, NULL or not, is left as it is.
    {
        use sqlx::Acquire as _;
        let mut sp = tx.begin().await.map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to open a savepoint: {e}"),
        })?;
        let assigned = sqlx::query(
            "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0) \
             ON CONFLICT DO NOTHING",
        )
        .bind(claim_id)
        .bind(frame_id)
        .execute(&mut *sp)
        .await;
        match assigned {
            Ok(_) => sp.commit().await,
            Err(e) => {
                tracing::warn!("assess_claim: claim_frames assignment refused: {e}");
                sp.rollback().await
            }
        }
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to close a savepoint: {e}"),
        })?;
    }
    super::belief::create_edge_under_savepoint(
        &mut tx,
        state.edge_signing_key(),
        claim_id,
        "claim",
        frame_id,
        "frame",
        "WITHIN_FRAME",
        None,
    )
    .await?;

    // Refresh the claim's cached belief under the one-frame-owns-the-cache
    // rule: `binary_truth` keeps the cache when the claim has a BBA there;
    // otherwise `claim_validity`, then the frame the cache records, then the
    // first writer (`MassFunctionRepository::cache_owner_frame_for_claim`).
    //
    // Then THIS frame's fold, by the same pipeline (backlog 735df6d7):
    // `preview_claim_belief_on_frame` runs exactly the fold the cache refresh
    // writes (each row discounted by its effective reliability, each agent's
    // own rows folded first, same-human sibling agents reduced by the
    // cautious rule, only the rows the derivation scope admits to the cache).
    // So when this frame owns the cache, the response IS the
    // cached value; on another frame it is this frame's fold, as the framed
    // `get_belief` serves it. One exception: a compound claim's cache is not
    // refolded from its own BBAs (the refresh above writes nothing for it),
    // while this preview still folds them, so for a compound the response is
    // that fold and the cache keeps whatever its decomposition derived.
    // The handler used to fold the raw masses of its
    // `'discount'` rows itself: with no reliability discount (so it disagreed
    // with the cache even for one assessment), without the edge-factor rows
    // the cache folds, and with all of a sibling group's rows in one cautious
    // reduction where the engine first folds each agent's own rows.
    epigraph_engine::edge_factor::recompute_claim_cached_belief(&mut tx, &viewer, claim_id)
        .await
        .map_err(|message| ApiError::InternalError { message })?;
    let preview = epigraph_engine::edge_factor::preview_claim_belief_on_frame(
        &mut tx, &viewer, claim_id, frame_id,
    )
    .await
    .map_err(|message| ApiError::InternalError { message })?;
    // The rows that fold combined: the combine-input reader, narrowed by the
    // derivation scope as the fold narrows it.
    let total_sources = {
        let rows = epigraph_db::MassFunctionRepository::get_for_claim_frame(
            &mut *tx, &viewer, claim_id, frame_id,
        )
        .await?;
        epigraph_engine::derivation_scope::retain_for_cache(&mut tx, rows)
            .await?
            .len()
    };

    // `None`: the derivation scope admits none of the frame's rows and there
    // is no cache to vacate (e.g. the claim's visibility changed between the
    // write and this read). Report this call's own assessment, as before.
    let (final_bel, final_pl, final_betp, m_missing, m_empty) = match &preview {
        Some(p) => (
            p.belief,
            p.plausibility,
            p.pignistic_prob,
            p.missing_mass,
            p.conflict_k,
        ),
        None => {
            let (bel, pl, betp, missing) =
                super::belief::compute_hypothesis_belief(&mass_function, &ds_frame, h_idx);
            (
                bel,
                pl,
                betp,
                missing,
                combination::fold_conflict(&mass_function, &[]),
            )
        }
    };

    // Every combine step is Dempster since U025; a single BBA is not folded,
    // so it has no combination step to report (`submit_evidence`'s shape).
    let folded = preview.is_some() && total_sources > 1;
    let final_k = folded.then_some(m_empty);
    let final_method = folded.then_some("Dempster");
    let reports: Vec<serde_json::Value> = if folded {
        vec![serde_json::json!({
            "method_used": "Dempster",
            "conflict_k": m_empty,
            "mass_on_conflict": m_empty,
            "mass_on_missing": m_missing,
        })]
    } else {
        vec![]
    };

    // No "combined result" mass_functions row is stored any more: it sat on the
    // input BBA's key and overwrote it, and a recompute must never re-combine a
    // combined row. The per-frame result is cached by the upsert below.
    // So no cached row can ever sit over an agent-less input (backlog
    // b5cb3efb): the input is keyed by its owner's assessment slot, and
    // nothing is stored on the (claim, frame, NULL, NULL) key.

    // Store the global scoped belief cache (best-effort, under a SAVEPOINT,
    // as `submit_evidence` does).
    {
        use sqlx::Acquire as _;
        let mut sp = tx.begin().await.map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to open a savepoint: {e}"),
        })?;
        let stored = epigraph_db::ScopedBeliefRepository::upsert(
            &mut *sp,
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
        match stored {
            Ok(_) => sp.commit().await,
            Err(e) => {
                tracing::warn!("assess_claim: global scoped belief refused: {e}");
                sp.rollback().await
            }
        }
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to close a savepoint: {e}"),
        })?;
    }

    // No `evidence -> claim` SUPPORTS / CONTRADICTS edge is written. The
    // handler used to write one from the slot row's id typed `evidence`, which
    // is a `mass_functions` id: `edges_validate_refs` refuses every such row,
    // and `let _` swallowed the refusal, so no edge ever landed
    // (`unstamped_http_edge_writes.rs` recorded both as dead writes). On this
    // transaction each would only be a refused savepoint per call.

    // Every write above commits together. The embedding below runs on its own
    // stamped transaction and must not start before this one releases the
    // claim row the cache refresh updated.
    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit the assessment: {e}"),
    })?;
    // The compound assessment has landed: only now does it count in the
    // guard's journal (a request refused above added no line).
    if let Some(target) = &deprecated_compound_target {
        target.log_accepted("assess", caller);
    }

    // ── 9. Generate embedding ────────────────────────────────────────────
    let embedded = if let Some(ref embedding_service) = state.embedding_service {
        match embedding_service.generate_query(&claim_content).await {
            Ok(embedding) => {
                let pgvector_str = epigraph_db::pgvector_literal(&embedding);
                // The shared writer on the caller's stamped transaction
                // (backlog f78526ad): it locks the row, then refuses a sealed
                // or superseded claim and one the caller cannot write. The
                // bare `UPDATE claims SET embedding` this replaced carried
                // none of that, so assessing a sealed claim put a
                // plaintext-derived vector back on it.
                match state
                    .store_claim_embedding_as(&viewer, claim_id, &pgvector_str, "assess_claim")
                    .await
                {
                    Ok(stored) => {
                        if !stored {
                            tracing::debug!(
                                claim_id = %claim_id,
                                "embedding not stored: claim sealed, superseded or not writable"
                            );
                        }
                        stored
                    }
                    Err(e) => {
                        tracing::warn!(claim_id = %claim_id, error = %e, "Failed to store embedding");
                        false
                    }
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
    let combination_reports = reports;

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
        deprecated_compound_target,
    }))
}

// Non-db stub to keep the crate compilable without the db feature
#[cfg(not(feature = "db"))]
pub async fn assess_claim() -> Result<Json<AssessClaimResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database".to_string(),
    })
}
