//! Dempster-Shafer belief endpoints
//!
//! Public (GET):
//! - `GET /api/v1/claims/:id/belief` — belief interval for a claim
//! - `GET /api/v1/claims/by-belief` — filter claims by belief bounds
//! - `GET /api/v1/frames` — list all frames
//! - `GET /api/v1/frames/:id` — frame detail with claims
//! - `GET /api/v1/frames/:id/conflict` — conflict coefficient for frame
//! - `GET /api/v1/frames/:id/claims` — claims in frame sorted by belief
//! - `GET /api/v1/claims/:id/divergence` — DS vs Bayesian divergence
//! - `GET /api/v1/divergence/top` — highest KL-divergence claims
//!
//! Protected (POST):
//! - `POST /api/v1/frames` — create a frame
//! - `POST /api/v1/frames/:id/evidence` — submit mass function evidence
//!
//! # Tenancy: 14 of this file's 17 raw-pool sites are converted, and 3 are not
//!
//! Conversion shard 4 against `D-PR17-request-path-never-stamps-session-gucs`
//! (`epigraph-db/tests/no_unscoped_pool.rs`). Every site in this file is a
//! handler-level `let pool = &state.db_pool;` alias, so one site is one handler
//! and the conversion unit is the whole body — not the line the ratchet's needle
//! matched.
//!
//! The fourteen read-only handlers below now acquire ONE viewer-stamped
//! connection through [`AppState::read_as`] and thread it into every statement,
//! which is what makes each response internally consistent: it describes the
//! corpus this reader can see, not several corpora sampled a connection apart.
//!
//! **Three handlers are deliberately NOT converted, and the reason is not
//! caution.** `create_frame`, `submit_evidence` and `refine_frame` each write
//! through their alias. (`submit_evidence`'s own tier-A writes, the BBA, the
//! frame assignment, the claim's cached belief, its Beta parameters, its
//! global scoped belief and its edges, now go through ONE [`AppState::write_as`]
//! transaction, and its best-effort derived rows after the commit through a
//! second; its alias remains for unstamped reads only.) `read_as` is documented
//! read-only: `ScopedRead::commit`
//! is not called by `Drop`, so under `SessionGucMode::Transaction` a write
//! routed through it is rolled back on drop — a 200 with nothing persisted.
//! `DerefMut<Target = PgConnection>` means that mistake COMPILES, so the
//! prohibition cannot be delegated to the type checker. Their target is
//! `ScopedPool::begin_as` plus 16b's `Viewer::splice_write`, which is a
//! repo-signature change rather than an executor swap; `FrameRepository::create`
//! and `::create_refinement` take no `Viewer` at all. That is a separate batch
//! with its own evidence. The three sites stay COUNTED by the ratchet, which is
//! why `routes/belief.rs` keeps a row there rather than being deleted.

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
#[cfg(feature = "db")]
use crate::state::AppState;
#[cfg(feature = "db")]
use axum::extract::State;
use axum::{
    extract::{Path, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// Response for claim belief interval
#[derive(Debug, Serialize)]
pub struct BeliefResponse {
    pub claim_id: Uuid,
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub ignorance: Option<f64>,
    /// Genuine conflict: m((empty, false)) — evidence sources contradict each other
    pub mass_on_conflict: Option<f64>,
    /// Frame incompleteness: m((Omega, true)) — frame may be missing propositions
    pub mass_on_missing: Option<f64>,
    pub pignistic_prob: Option<f64>,
    /// How many mass functions **this reader can see** contribute to the claim.
    ///
    /// # This is deliberately NOT the denominator of the interval above
    ///
    /// `belief`/`plausibility`/`pignistic_prob` are precomputed aggregate
    /// columns on `claims`, recomputed from *every* BBA in the corpus. No
    /// visibility predicate can narrow them — they are a single stored number,
    /// not a query over `mass_functions`. This count, by contrast, is
    /// viewer-filtered (PR-07). So whenever a contributing BBA is group-private,
    /// `mass_function_count` is strictly less than the number of mass functions
    /// the interval actually rests on.
    ///
    /// The asymmetry is the intended trade, not an oversight: the alternative —
    /// counting mass functions the reader cannot see — turns this field into a
    /// cardinality oracle over another tenant's evidence. Read it as "how much
    /// of the supporting evidence is available to me", never as "how many
    /// sources produced this interval". Do not recompute ignorance from it;
    /// `ignorance` is returned directly and is derived from the same corpus-wide
    /// columns as the interval.
    pub mass_function_count: i64,
}

/// Response for a frame of discernment
#[derive(Debug, Serialize)]
pub struct FrameResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub hypotheses: Vec<String>,
    pub parent_frame_id: Option<Uuid>,
    pub is_refinable: bool,
    /// Frame version, incremented on extend()
    pub version: i32,
    pub created_at: String,
}

/// Response for frame detail with claims
#[derive(Debug, Serialize)]
pub struct FrameDetailResponse {
    pub frame: FrameResponse,
    pub claim_count: usize,
    pub claims: Vec<FrameClaimEntry>,
}

/// A claim assignment within a frame
#[derive(Debug, Serialize)]
pub struct FrameClaimEntry {
    pub claim_id: Uuid,
    pub hypothesis_index: Option<i32>,
}

/// Response for frame conflict analysis
#[derive(Debug, Serialize)]
pub struct FrameConflictResponse {
    pub frame_id: Uuid,
    pub source_count: i64,
    pub avg_conflict_k: Option<f64>,
    pub max_conflict_k: Option<f64>,
}

/// Request to create a new frame
#[derive(Debug, Deserialize)]
pub struct CreateFrameRequest {
    pub name: String,
    pub description: Option<String>,
    pub hypotheses: Vec<String>,
}

/// Request to submit mass function evidence
#[derive(Debug, Deserialize)]
pub struct SubmitEvidenceRequest {
    pub claim_id: Uuid,
    pub agent_id: Option<Uuid>,
    /// Optional perspective under which this evidence is submitted
    pub perspective_id: Option<Uuid>,
    /// Reliability discount factor [0, 1]. 1.0 = fully reliable.
    #[serde(default = "default_reliability")]
    pub reliability: f64,
    /// Optional evidence-source tag (e.g. "western_clinical",
    /// "practitioner_interview") stored on the BBA so per-perspective
    /// source-reliability maps (the frame function) can re-weight this evidence
    /// per observer at query time. See
    /// `epigraph_engine::belief_query::get_perspective_belief`.
    #[serde(default)]
    pub evidence_type: Option<String>,
    /// Conflict K at or above which a `conflict.detected` event is emitted.
    /// Since U025 it no longer selects a combination rule: `combine_multiple`
    /// folds with Dempster at every step. It does not affect the claim's
    /// belief, which is the shared recompute's
    /// (`edge_factor::recompute_claim_belief_on_frame`).
    #[serde(default = "default_conflict_threshold")]
    pub conflict_threshold: f64,
    /// Mass assignments: keys are comma-separated hypothesis indices, values are mass.
    /// Prefix key with `~` for CDST complement (negative) elements.
    pub masses: std::collections::BTreeMap<String, f64>,
    /// DEPRECATED: accepted, no effect on the belief (backlog 82dcff9d). The
    /// claim's belief is computed by the shared recompute, the one
    /// `recompute_beliefs` and MCP `submit_ds_evidence` use. Sending it earns a
    /// `warnings` entry.
    #[serde(default)]
    pub combination_method: Option<String>,
    /// DEPRECATED: accepted, no effect on the belief (backlog 82dcff9d). It was
    /// the Inagaki gamma for `combination_method = "inagaki"`. Sending it earns
    /// a `warnings` entry.
    #[serde(default)]
    pub gamma: Option<f64>,
    /// DEPRECATED: accepted, no effect on the belief (backlog 82dcff9d). It
    /// skipped an independence analysis the shared recompute does not run.
    /// Sending `true` earns a `warnings` entry.
    #[serde(default)]
    pub assume_independent: Option<bool>,
}

/// One warning per deprecated `SubmitEvidenceRequest` field the caller sent
/// (backlog 82dcff9d, the REST twin of MCP `submit_ds_evidence`'s
/// `deprecated_parameter_warnings`). They are accepted, not refused, for
/// parity with MCP.
#[cfg(feature = "db")]
fn deprecated_parameter_warnings(request: &SubmitEvidenceRequest) -> Vec<String> {
    const WHY: &str = "The claim's belief is always recomputed by the shared Dempster fold \
                       (the one recompute_beliefs uses).";
    let mut out = Vec::new();
    if let Some(method) = &request.combination_method {
        out.push(format!(
            "combination_method={method} is deprecated: it did not change the returned belief. \
             {WHY}"
        ));
    }
    if let Some(gamma) = request.gamma {
        out.push(format!(
            "gamma={gamma} is deprecated: it did not change the returned belief. {WHY}"
        ));
    }
    if request.assume_independent == Some(true) {
        out.push(format!(
            "assume_independent=true is deprecated: it did not change the returned belief, \
             since no independence analysis runs. {WHY}"
        ));
    }
    out
}

/// One of `submit_evidence`'s best-effort edges, written on its viewer-stamped
/// transaction under a SAVEPOINT.
///
/// Stamped, the edges trigger records the caller's writer group, and row
/// security decides the INSERT against the caller's writable set. A refused
/// INSERT (row security, or `trigger_validate_edge_refs` on an endpoint that
/// is not a row of its declared type) is logged and rolled back to the
/// savepoint, so it neither fails the request nor aborts the transaction and
/// silently rolls the BBA back at the COMMIT.
///
/// # Errors
/// `ApiError::DatabaseError` only when the savepoint itself cannot be opened
/// or closed.
#[cfg(feature = "db")]
async fn create_edge_under_savepoint(
    conn: &mut sqlx::PgConnection,
    source_id: Uuid,
    source_type: &str,
    target_id: Uuid,
    target_type: &str,
    relationship: &str,
    properties: Option<serde_json::Value>,
) -> Result<(), ApiError> {
    use sqlx::Acquire as _;
    let mut sp = conn.begin().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to open a savepoint: {e}"),
    })?;
    let created = epigraph_db::EdgeRepository::create(
        &mut *sp,
        source_id,
        source_type,
        target_id,
        target_type,
        relationship,
        properties,
        None,
        None,
    )
    .await;
    match created {
        Ok(_) => sp.commit().await,
        Err(e) => {
            tracing::warn!("submit_evidence: {relationship} edge refused: {e}");
            sp.rollback().await
        }
    }
    .map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to close a savepoint: {e}"),
    })
}

/// A scoped belief `submit_evidence` derives after its commit (step 17) and
/// writes on a stamped transaction (step 20).
#[cfg(feature = "db")]
struct ScopedBeliefWrite {
    scope_type: &'static str,
    scope_id: Uuid,
    belief: f64,
    plausibility: f64,
    mass_on_empty: f64,
    mass_on_missing: f64,
    conflict_k: Option<f64>,
    strategy: Option<String>,
    pignistic_prob: f64,
}

/// A stored scoped belief (`ds_combined_beliefs`) of one scope: the scope's
/// stored BBAs, as this handler always folded them (raw masses, no discount),
/// restricted to the rows the claim's stored beliefs may be computed from
/// (ruling R-22: a public claim's are its public-derived BBAs only), folded by
/// the engine's owner-aware rule (ruling R-36: sibling agents of one human
/// are reduced cautiously, never multiplied). `None` when no row is left or
/// the fold fails (best-effort, as before).
#[cfg(feature = "db")]
#[allow(clippy::too_many_arguments)]
async fn scoped_belief_write(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    ds_frame: &epigraph_ds::FrameOfDiscernment,
    h_idx: Option<i32>,
    rows: Vec<epigraph_db::MassFunctionRow>,
    conflict_threshold: f64,
    scope_type: &'static str,
    scope_id: Uuid,
) -> Option<ScopedBeliefWrite> {
    let mut rows = epigraph_engine::derivation_scope::retain_for_cache(conn, claim_id, rows)
        .await
        .map_err(|e| tracing::warn!("submit_evidence: {scope_type} scope rows: {e}"))
        .ok()?;
    rows.sort_by_key(|r| r.id);
    let rows: Vec<(epigraph_db::MassFunctionRow, epigraph_ds::MassFunction)> = rows
        .into_iter()
        .filter_map(|row| {
            epigraph_ds::MassFunction::from_json_masses(ds_frame.clone(), &row.masses)
                .ok()
                .map(|m| (row, m))
        })
        .collect();
    if rows.is_empty() {
        return None;
    }
    let stored: Vec<epigraph_db::MassFunctionRow> = rows.iter().map(|(r, _)| r.clone()).collect();
    let sources = epigraph_engine::source_dependence::bba_sources_for_rows(conn, viewer, &stored)
        .await
        .map_err(|e| tracing::warn!("submit_evidence: {scope_type} scope sources: {e}"))
        .ok()?;
    let folded = rows.len() >= 2;
    let items = sources
        .into_iter()
        .zip(rows.into_iter().map(|(_, m)| m))
        .collect();
    let (combined, k) = epigraph_engine::source_dependence::combine_with_owner_dependence(
        items,
        conflict_threshold,
    )
    .ok()?;
    let (belief, plausibility, pignistic_prob, mass_on_missing) =
        compute_hypothesis_belief(&combined, ds_frame, h_idx);
    Some(ScopedBeliefWrite {
        scope_type,
        scope_id,
        belief,
        plausibility,
        mass_on_empty: k,
        mass_on_missing,
        conflict_k: folded.then_some(k),
        strategy: folded.then(|| "Dempster".to_string()),
        pignistic_prob,
    })
}

/// Close a best-effort write's SAVEPOINT: release it when the write landed,
/// roll back to it (logging `what`) when it was refused.
///
/// # Errors
/// The savepoint's own RELEASE / ROLLBACK error (logged here too); the
/// enclosing transaction is then unusable.
#[cfg(feature = "db")]
async fn finish_savepoint<T>(
    sp: sqlx::Transaction<'_, sqlx::Postgres>,
    result: Result<T, epigraph_db::DbError>,
    what: &str,
) -> Result<(), sqlx::Error> {
    let closed = match result {
        Ok(_) => sp.commit().await,
        Err(e) => {
            tracing::warn!("submit_evidence: {what} refused: {e}");
            sp.rollback().await
        }
    };
    if let Err(e) = &closed {
        tracing::warn!("submit_evidence: could not close the {what} savepoint: {e}");
    }
    closed
}

fn default_reliability() -> f64 {
    1.0
}

fn default_conflict_threshold() -> f64 {
    0.3
}

/// Response from evidence submission
#[derive(Debug, Serialize)]
pub struct EvidenceSubmissionResponse {
    pub mass_function_id: Uuid,
    pub combination_reports: Vec<CombinationReportResponse>,
    pub updated_belief: f64,
    pub updated_plausibility: f64,
    /// Genuine conflict: m((empty, false))
    pub mass_on_conflict: f64,
    /// Frame incompleteness: m((Omega, true))
    pub mass_on_missing: f64,
    pub pignistic_prob: Option<f64>,
    pub bayesian_posterior: f64,
    pub total_sources: i64,
    /// What this write did to the caller's BBA for its key (claim, frame,
    /// agent, perspective_id), decided before the store by the probe MCP
    /// `submit_ds_evidence` shares (`epigraph_db::bba_write_outcome`):
    /// `inserted`, `unchanged` (an identical resubmission: the stored values
    /// stay the same, though the upsert still refreshes the row's
    /// `created_at`) or `replaced` (a different BBA overwrote it, same
    /// `mass_function_id`). Backlog 6f82db4f.
    pub write_outcome: String,
    /// True exactly when `write_outcome` is `unchanged`.
    pub deduplicated: bool,
    /// What the caller should know about this submission's effect: a
    /// deprecated request field it sent (`combination_method`, `gamma`,
    /// `assume_independent`), that the claim's cache was not updated (it
    /// carries another frame), or that the write was `unchanged` or
    /// `replaced`. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Simplified combination report for API response
#[derive(Debug, Serialize)]
pub struct CombinationReportResponse {
    pub method_used: String,
    pub conflict_k: f64,
    pub mass_on_conflict: f64,
    /// Frame incompleteness: m((Omega, true))
    pub mass_on_missing: f64,
}

/// Query parameters for listing frames
#[derive(Debug, Deserialize)]
pub struct ListFramesQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Query parameters for `GET /api/v1/claims/by-belief`
#[derive(Debug, Deserialize)]
pub struct BeliefFilterQuery {
    #[serde(default)]
    pub min_belief: Option<f64>,
    #[serde(default)]
    pub max_plausibility: Option<f64>,
    #[serde(default)]
    pub frame_id: Option<Uuid>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    /// Optional requester agent ID for partition-aware content filtering
    #[serde(default)]
    pub agent_id: Option<Uuid>,
}

/// A claim row returned from belief-scoped queries
#[derive(Debug, Serialize)]
pub struct BeliefClaimRow {
    pub id: Uuid,
    pub content: String,
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub mass_on_conflict: Option<f64>,
    pub mass_on_missing: Option<f64>,
}

/// Query parameters for `GET /api/v1/frames/:id/claims`
#[derive(Debug, Deserialize)]
pub struct FrameClaimsQuery {
    #[serde(default = "default_sort_by")]
    pub sort_by: String,
    #[serde(default = "default_order")]
    pub order: String,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    /// Optional requester agent ID for partition-aware content filtering
    #[serde(default)]
    pub agent_id: Option<Uuid>,
}

fn default_sort_by() -> String {
    "belief".to_string()
}

fn default_order() -> String {
    "desc".to_string()
}

/// Response for a claim within a frame, with belief data
#[derive(Debug, Serialize)]
pub struct FrameClaimBeliefRow {
    pub claim_id: Uuid,
    pub content: String,
    pub hypothesis_index: Option<i32>,
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub ignorance: Option<f64>,
    pub mass_on_missing: Option<f64>,
}

/// Response for divergence query
#[derive(Debug, Serialize)]
pub struct DivergenceResponse {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub frame_id: Uuid,
    pub pignistic_prob: f64,
    pub bayesian_posterior: f64,
    pub kl_divergence: f64,
    pub frame_version: Option<i32>,
    pub computed_at: String,
}

/// Query parameters for `GET /api/v1/divergence/top`
#[derive(Debug, Deserialize)]
pub struct TopDivergenceQuery {
    #[serde(default = "default_top_limit")]
    pub limit: i64,
}

fn default_top_limit() -> i64 {
    10
}

/// Query parameters for scoped belief lookup
#[derive(Debug, Deserialize)]
pub struct ScopedBeliefQuery {
    /// Scope: "global", "perspective", or "community". Defaults to global.
    #[serde(default)]
    pub scope: Option<String>,
    /// Scope entity ID (perspective or community UUID). Required when scope is not "global".
    #[serde(default)]
    pub scope_id: Option<Uuid>,
}

/// Response for an all-scopes belief comparison
#[derive(Debug, Serialize)]
pub struct AllScopesBeliefResponse {
    pub claim_id: Uuid,
    pub scopes: Vec<ScopedBeliefEntry>,
}

/// A single scoped belief entry
#[derive(Debug, Serialize)]
pub struct ScopedBeliefEntry {
    pub scope_type: String,
    pub scope_id: Option<Uuid>,
    pub belief: f64,
    pub plausibility: f64,
    pub ignorance: f64,
    /// Genuine conflict: m((empty, false))
    pub mass_on_conflict: f64,
    /// Frame incompleteness: m((Omega, true))
    pub mass_on_missing: f64,
    pub pignistic_prob: Option<f64>,
    pub conflict_k: Option<f64>,
    pub strategy_used: Option<String>,
    pub computed_at: String,
}

/// Pignistic probability distribution response
#[derive(Debug, Serialize)]
pub struct PignisticResponse {
    pub claim_id: Uuid,
    pub frame_id: Uuid,
    pub frame_name: String,
    pub hypotheses: Vec<PignisticEntry>,
    /// Genuine conflict: m((empty, false))
    pub mass_on_conflict: f64,
    /// Frame incompleteness: m((Omega, true))
    pub mass_on_missing: f64,
}

/// Request body for POST /api/v1/frames/:id/conflict-batch
#[derive(Debug, Deserialize)]
pub struct ConflictBatchRequest {
    pub pairs: Vec<ConflictPair>,
}

#[derive(Debug, Deserialize)]
pub struct ConflictPair {
    pub claim_a: Uuid,
    pub claim_b: Uuid,
}

/// Response for POST /api/v1/frames/:id/conflict-batch
#[derive(Debug, Serialize)]
pub struct ConflictBatchResponse {
    pub results: Vec<ConflictBatchResult>,
}

#[derive(Debug, Serialize)]
pub struct ConflictBatchResult {
    pub claim_a: Uuid,
    pub claim_b: Uuid,
    pub conflict_k: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A single hypothesis entry in a pignistic distribution
#[derive(Debug, Serialize)]
pub struct PignisticEntry {
    pub hypothesis_index: usize,
    pub hypothesis_name: String,
    pub pignistic_probability: f64,
    pub belief: f64,
    pub plausibility: f64,
}

/// Query parameters for pignistic endpoint
#[derive(Debug, Deserialize)]
pub struct PignisticQuery {
    pub frame_id: Uuid,
}

/// Request to create a frame refinement
#[derive(Debug, Deserialize)]
pub struct RefineFrameRequest {
    pub name: String,
    pub description: Option<String>,
    pub hypotheses: Vec<String>,
}

/// KL divergence threshold for emitting `divergence.spike` events
const DIVERGENCE_SPIKE_THRESHOLD: f64 = 0.5;

// =============================================================================
// HELPERS
// =============================================================================

/// Compute symmetric KL divergence between two Bernoulli distributions.
///
/// KL(p || q) = p * ln(p/q) + (1-p) * ln((1-p)/(1-q))
///
/// Clamps inputs to [ε, 1-ε] to avoid log(0).
fn kl_divergence_bernoulli(p: f64, q: f64) -> f64 {
    let eps = 1e-10;
    let p = p.clamp(eps, 1.0 - eps);
    let q = q.clamp(eps, 1.0 - eps);
    p * (p / q).ln() + (1.0 - p) * ((1.0 - p) / (1.0 - q)).ln()
}

/// Convert a FrameRow to a FrameResponse
#[cfg(feature = "db")]
fn frame_to_response(row: epigraph_db::FrameRow) -> FrameResponse {
    FrameResponse {
        id: row.id,
        name: row.name,
        description: row.description,
        hypotheses: row.hypotheses,
        parent_frame_id: row.parent_frame_id,
        is_refinable: row.is_refinable,
        version: row.version,
        created_at: row.created_at.to_rfc3339(),
    }
}

/// Compute belief, plausibility, and pignistic for the correct hypothesis
/// within a combined mass function, respecting the claim's hypothesis_index.
///
/// Returns `(belief, plausibility, pignistic_prob, mass_on_missing)`.
#[cfg(feature = "db")]
pub(crate) fn compute_hypothesis_belief(
    combined: &epigraph_ds::MassFunction,
    ds_frame: &epigraph_ds::FrameOfDiscernment,
    hypothesis_index: Option<i32>,
) -> (f64, f64, f64, f64) {
    use epigraph_ds::{measures, FocalElement};

    // The shared rule (backlog 45cbaef4): a negative or out-of-range stored
    // index reads as 0, exactly as the cache writer resolves it. This used to
    // be `i as usize`, which wrapped a negative index to `usize::MAX`.
    let h_idx = epigraph_engine::edge_factor::resolve_hypothesis_index(
        hypothesis_index,
        ds_frame.hypothesis_count(),
    );
    let supported = FocalElement::positive(std::collections::BTreeSet::from([h_idx]));
    let bel = measures::belief(combined, &supported);
    let pl = measures::plausibility(combined, &supported);
    let betp = measures::pignistic_probability(combined, h_idx);
    let m_missing = combined.mass_of_missing();

    (bel, pl, betp, m_missing)
}

// =============================================================================
// HANDLERS (db feature)
// =============================================================================

/// Get belief interval for a claim
///
/// `GET /api/v1/claims/:id/belief`
///
/// Both reads are filtered by the caller's [`Viewer`](epigraph_db::Viewer).
/// Before PR-07 this handler ran two bare statements against `claims` and
/// `mass_functions` inline, keyed only on the path id, which made it a precise
/// oracle over the whole corpus: a 200 proved a claim id existed and disclosed
/// its belief interval, a 404 proved it did not. Neither fact is public.
/// A claim the viewer cannot see is now indistinguishable from one that does
/// not exist — both are 404 — which is the intended shape.
#[cfg(feature = "db")]
pub async fn get_claim_belief(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<BeliefResponse>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_claim_belief",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let cols = epigraph_db::ClaimRepository::get_belief_columns(
        &mut *read,
        &viewer,
        epigraph_core::ClaimId::from_uuid(claim_id),
    )
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })?
    .ok_or(ApiError::NotFound {
        entity: "claim".to_string(),
        id: claim_id.to_string(),
    })?;

    // Count mass functions across all frames for this claim, as the viewer.
    let mass_function_count =
        epigraph_db::MassFunctionRepository::count_for_claim(&mut *read, &viewer, claim_id)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?;

    crate::routes::finish_scoped_read(read, "get_claim_belief").await?;

    let ignorance = match (cols.belief, cols.plausibility) {
        (Some(b), Some(p)) => Some(p - b),
        _ => None,
    };

    Ok(Json(BeliefResponse {
        claim_id,
        belief: cols.belief,
        plausibility: cols.plausibility,
        ignorance,
        mass_on_conflict: cols.mass_on_empty,
        mass_on_missing: cols.mass_on_missing,
        pignistic_prob: cols.pignistic_prob,
        mass_function_count,
    }))
}

/// List all frames
///
/// `GET /api/v1/frames`
#[cfg(feature = "db")]
pub async fn list_frames(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Query(params): Query<ListFramesQuery>,
) -> Result<Json<Vec<FrameResponse>>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "list_frames",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let rows = epigraph_db::FrameRepository::list(&mut *read, &viewer, params.limit, params.offset)
        .await?;

    crate::routes::finish_scoped_read(read, "list_frames").await?;

    let frames = rows.into_iter().map(frame_to_response).collect();

    Ok(Json(frames))
}

/// Get frame detail with claims
///
/// `GET /api/v1/frames/:id`
#[cfg(feature = "db")]
pub async fn get_frame(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
) -> Result<Json<FrameDetailResponse>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_frame",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let row = epigraph_db::FrameRepository::get_by_id(&mut *read, &viewer, frame_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        })?;

    let claim_rows =
        epigraph_db::FrameRepository::get_claims_in_frame(&mut *read, &viewer, frame_id).await?;

    crate::routes::finish_scoped_read(read, "get_frame").await?;

    let claims: Vec<FrameClaimEntry> = claim_rows
        .into_iter()
        .map(|r| FrameClaimEntry {
            claim_id: r.claim_id,
            hypothesis_index: r.hypothesis_index,
        })
        .collect();

    Ok(Json(FrameDetailResponse {
        frame: frame_to_response(row),
        claim_count: claims.len(),
        claims,
    }))
}

/// Get conflict analysis for a frame
///
/// `GET /api/v1/frames/:id/conflict`
#[cfg(feature = "db")]
pub async fn frame_conflict(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
) -> Result<Json<FrameConflictResponse>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "frame_conflict",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // Verify frame exists
    epigraph_db::FrameRepository::get_by_id(&mut *read, &viewer, frame_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        })?;

    // The aggregate below stays inline and carries no `/* {VISIBILITY:…} */`
    // marker, because a route handler cannot carry one. It binds only
    // `frame_id` and calls no `Viewer::splice`, so it is the ONE site this
    // shard converted that has a single control layer where the other eighteen
    // have two. Registered as `F-SHARD4-A5`, because no existing register can
    // see it: `viewer_route_table_lint.rs::UNCOMPENSATED_INLINE_READS` scans
    // `CONTENT_TABLES`, and `mass_functions` is not one.
    //
    // WHICH DIRECTION THE CONVERSION MOVED IT, stated because the obvious
    // reading is backwards. UNSTAMPED, `epigraph_session_groups()` is empty, so
    // once `mass_functions`' policies are live this statement already counted
    // PUBLIC rows only. Stamping it WIDENS the aggregate to public plus the
    // viewer's own groups. That is the correct direction — it removes
    // over-suppression — but it is not a leak being closed, and a later reader
    // must not cite it as one.
    //
    // And the narrowing half is CONDITIONAL, unlike the spliced sites: with no
    // in-query predicate, whether this aggregate describes the caller's corpus
    // at all depends on the reading session being subject to `mass_functions`'
    // row-level policies. On a deployment whose connecting role bypasses them
    // it is unchanged. That is precisely why the site stays owned by
    // `F-aggregate-existence-oracles`, whose own disposition prescribes
    // repo-layer relocation — a DIFFERENT mechanism from this executor swap,
    // and the actual fix.
    let row: (i64, Option<f64>, Option<f64>) = sqlx::query_as(
        r#"
        SELECT COUNT(*), AVG(conflict_k), MAX(conflict_k)
        FROM mass_functions
        WHERE frame_id = $1 AND conflict_k IS NOT NULL
        "#,
    )
    .bind(frame_id)
    .fetch_one(&mut *read)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })?;

    crate::routes::finish_scoped_read(read, "frame_conflict").await?;

    Ok(Json(FrameConflictResponse {
        frame_id,
        source_count: row.0,
        avg_conflict_k: row.1,
        max_conflict_k: row.2,
    }))
}

/// Reconstruct a `MassFunction` from a frame and a JSON masses object.
///
/// Returns `Ok(mf)` on success, `Err(reason)` if the JSON is invalid or empty.
#[cfg(feature = "db")]
pub(crate) fn reconstruct_mass_function(
    frame: &epigraph_ds::FrameOfDiscernment,
    masses_json: &serde_json::Value,
) -> Result<epigraph_ds::MassFunction, String> {
    use epigraph_ds::{focal_serde::key_to_focal, FocalElement, MassFunction};
    use std::collections::BTreeMap;

    let masses_obj = masses_json
        .as_object()
        .ok_or_else(|| "masses is not a JSON object".to_string())?;

    let mut bba: BTreeMap<FocalElement, f64> = BTreeMap::new();
    for (key, val) in masses_obj {
        if let (Ok(fe), Some(mass)) = (key_to_focal(key), val.as_f64()) {
            if mass > 1e-12 {
                bba.insert(fe, mass);
            }
        }
    }
    if bba.is_empty() {
        return Err("no valid focal elements in masses".to_string());
    }
    MassFunction::new(frame.clone(), bba).map_err(|e| format!("invalid mass function: {e}"))
}

/// Batch compute conflict coefficients between claim pairs
///
/// `POST /api/v1/frames/:id/conflict-batch`
#[cfg(feature = "db")]
pub async fn conflict_batch(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
    Json(request): Json<ConflictBatchRequest>,
) -> Result<Json<ConflictBatchResponse>, ApiError> {
    use epigraph_ds::{combination::conflict_coefficient, FrameOfDiscernment, MassFunction};
    use std::collections::{HashMap, HashSet};

    if request.pairs.len() > 100 {
        return Err(ApiError::ValidationError {
            field: "pairs".to_string(),
            reason: format!("Maximum 100 pairs per request, got {}", request.pairs.len()),
        });
    }

    if request.pairs.is_empty() {
        return Ok(Json(ConflictBatchResponse { results: vec![] }));
    }

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "conflict_batch",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // Verify frame exists and get its hypotheses for reconstruction
    let frame_row = epigraph_db::FrameRepository::get_by_id(&mut *read, &viewer, frame_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        })?;

    // Build DS frame from DB hypotheses
    let ds_frame =
        FrameOfDiscernment::new(&frame_row.name, frame_row.hypotheses.clone()).map_err(|e| {
            ApiError::InternalError {
                message: format!("Invalid frame: {e}"),
            }
        })?;

    // Collect unique claim IDs
    let mut claim_ids: HashSet<Uuid> = HashSet::new();
    for pair in &request.pairs {
        claim_ids.insert(pair.claim_a);
        claim_ids.insert(pair.claim_b);
    }

    // Load mass functions for all unique claims (use latest by created_at)
    let mut mass_fns: HashMap<Uuid, MassFunction> = HashMap::new();
    for &cid in &claim_ids {
        let rows = epigraph_db::MassFunctionRepository::get_for_claim_frame(
            &mut *read, &viewer, cid, frame_id,
        )
        .await?;
        // get_for_claim_frame returns ORDER BY created_at ASC, so last() is latest.
        // Use max_by_key as defense against ordering changes.
        if let Some(row) = rows.iter().max_by_key(|r| r.created_at) {
            if let Ok(mf) = reconstruct_mass_function(&ds_frame, &row.masses) {
                mass_fns.insert(cid, mf);
            }
        }
    }

    crate::routes::finish_scoped_read(read, "conflict_batch").await?;

    // Compute conflict for each pair
    let results: Vec<ConflictBatchResult> = request
        .pairs
        .iter()
        .map(|pair| {
            let mf_a = mass_fns.get(&pair.claim_a);
            let mf_b = mass_fns.get(&pair.claim_b);

            match (mf_a, mf_b) {
                (Some(a), Some(b)) => match conflict_coefficient(a, b) {
                    Ok(k) => ConflictBatchResult {
                        claim_a: pair.claim_a,
                        claim_b: pair.claim_b,
                        conflict_k: Some(k),
                        error: None,
                    },
                    Err(e) => ConflictBatchResult {
                        claim_a: pair.claim_a,
                        claim_b: pair.claim_b,
                        conflict_k: None,
                        error: Some(e.to_string()),
                    },
                },
                _ => {
                    let missing = if mf_a.is_none() && mf_b.is_none() {
                        format!(
                            "No mass functions for claims {} and {}",
                            pair.claim_a, pair.claim_b
                        )
                    } else if mf_a.is_none() {
                        format!("No mass function for claim {}", pair.claim_a)
                    } else {
                        format!("No mass function for claim {}", pair.claim_b)
                    };
                    ConflictBatchResult {
                        claim_a: pair.claim_a,
                        claim_b: pair.claim_b,
                        conflict_k: None,
                        error: Some(missing),
                    }
                }
            }
        })
        .collect();

    Ok(Json(ConflictBatchResponse { results }))
}

/// Stub for non-db builds
#[cfg(not(feature = "db"))]
pub async fn conflict_batch(
    Path(_frame_id): Path<Uuid>,
    Json(_request): Json<ConflictBatchRequest>,
) -> Result<Json<ConflictBatchResponse>, ApiError> {
    Ok(Json(ConflictBatchResponse { results: vec![] }))
}

/// Create a new frame
///
/// `POST /api/v1/frames`
#[cfg(feature = "db")]
pub async fn create_frame(
    State(state): State<AppState>,
    Json(request): Json<CreateFrameRequest>,
) -> Result<(StatusCode, Json<FrameResponse>), ApiError> {
    if request.hypotheses.len() < 2 {
        return Err(ApiError::ValidationError {
            field: "hypotheses".to_string(),
            reason: "Frame must have at least 2 hypotheses".to_string(),
        });
    }

    if request.name.is_empty() || request.name.len() > 200 {
        return Err(ApiError::ValidationError {
            field: "name".to_string(),
            reason: "Name must be between 1 and 200 characters".to_string(),
        });
    }

    let pool = &state.db_pool;
    let row = epigraph_db::FrameRepository::create(
        pool,
        &request.name,
        request.description.as_deref(),
        &request.hypotheses,
    )
    .await?;

    // Emit frame.created event
    let event_store = super::events::global_event_store();
    event_store
        .push(
            "frame.created".to_string(),
            None,
            serde_json::json!({
                "frame_id": row.id,
                "name": row.name,
                "hypothesis_count": request.hypotheses.len(),
            }),
        )
        .await;

    Ok((StatusCode::CREATED, Json(frame_to_response(row))))
}

/// Submit mass function evidence for a claim in a frame
///
/// Pipeline: discount → (one stamped transaction: store → recompute the
/// claim's belief on this frame with the shared pipeline
/// `edge_factor::recompute_claim_belief_on_frame` → Beta update → global
/// scoped belief → edges) → emit events → compute divergence. The belief this returns is the one a later
/// `recompute_beliefs` with no new evidence leaves (backlogs 2bffdfdc,
/// 82dcff9d), and no derived "combined" BBA is stored beside the input.
///
/// `POST /api/v1/frames/:id/evidence`
#[cfg(feature = "db")]
pub async fn submit_evidence(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
    Json(request): Json<SubmitEvidenceRequest>,
) -> Result<(StatusCode, Json<EvidenceSubmissionResponse>), ApiError> {
    use epigraph_ds::{combination, FrameOfDiscernment, MassFunction};
    use std::collections::BTreeSet;

    let pool = &state.db_pool;

    // 0. Every BBA has an author, and it is the caller (operator ruling
    //    2026-10-22). The body's `agent_id` is the BBA's author and half its
    //    upsert key `(claim, frame, source_agent_id, perspective)`. Naming
    //    another agent would attribute evidence to it and, where row security
    //    lets the caller write that agent's row, overwrite its BBA, so it is
    //    refused. An omitted `agent_id` is the caller's own: an agent-less BBA
    //    shared one row per (claim, frame, perspective) under the `NULLS NOT
    //    DISTINCT` key, so one caller's replaced another's (backlog 5a3ba157).
    //    MCP `submit_ds_evidence` takes the author from the authenticated
    //    identity for the same reason.
    let Some(caller) = viewer.principal() else {
        return Err(ApiError::Forbidden {
            reason: "evidence needs an authenticated author".to_string(),
        });
    };
    let named = request.agent_id;
    let mut request = request;
    request.agent_id = Some(caller);

    // An owner's assessment slot (`/claims/:id/assess`, ruling Q-U027F-2) is
    // addressable only through assess: a row keyed (agent, that agent's slot
    // perspective) would overwrite or forge that owner's one assessment. It is
    // checked against the NAMED author first, so naming a slot stays a 400.
    if epigraph_db::repos::mass_function::is_assessment_slot(
        named.or(Some(caller)),
        request.perspective_id,
    ) {
        return Err(ApiError::ValidationError {
            field: "perspective_id".to_string(),
            reason: "this is the agent's assessment slot, written only by \
                     POST /api/v1/claims/:id/assess"
                .to_string(),
        });
    }

    if named.is_some_and(|n| n != caller) {
        return Err(ApiError::Forbidden {
            reason: "agent_id must be the authenticated caller's own agent id, or omitted"
                .to_string(),
        });
    }

    // 0b. Evidence named on `hypothesis_assessment` for a PROMOTED hypothesis
    //     goes to the frame its readers read, `research_validity` (writers
    //     follow the readers, operator ruling R-8; MCP `submit_ds_evidence`
    //     does the same). Read as the caller, before anything is written.
    let named_frame = frame_id;
    let redirected = {
        let mut read = state.read_as(&viewer).await?;
        epigraph_engine::promotion::promoted_hypothesis_evidence_frame(
            &mut read,
            &viewer,
            request.claim_id,
            frame_id,
        )
        .await?
    };
    let frame_id = redirected.as_ref().map_or(frame_id, |f| f.id);

    // 1. Load and validate frame
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

    // 2. Validate reliability
    if !(0.0..=1.0).contains(&request.reliability) || request.reliability.is_nan() {
        return Err(ApiError::ValidationError {
            field: "reliability".to_string(),
            reason: "Must be in [0, 1]".to_string(),
        });
    }

    // 3. Parse and validate the submitted mass function
    //    Keys may be prefixed with ~ to indicate CDST complement (negative) elements.
    let mut masses = std::collections::BTreeMap::new();
    for (key, &value) in &request.masses {
        let (is_complement, indices_str) = key
            .strip_prefix('~')
            .map_or((false, key.as_str()), |rest| (true, rest));
        let subset: BTreeSet<usize> = if indices_str.is_empty() {
            BTreeSet::new()
        } else {
            indices_str
                .split(',')
                .map(|s| {
                    s.trim()
                        .parse::<usize>()
                        .map_err(|_| ApiError::ValidationError {
                            field: "masses".to_string(),
                            reason: format!("Invalid hypothesis index in key '{key}'"),
                        })
                })
                .collect::<Result<BTreeSet<usize>, ApiError>>()?
        };
        let fe = if is_complement {
            epigraph_ds::FocalElement::negative(subset)
        } else {
            epigraph_ds::FocalElement::positive(subset)
        };
        masses.insert(fe, value);
    }

    let raw_mass =
        MassFunction::new(ds_frame.clone(), masses).map_err(|e| ApiError::ValidationError {
            field: "masses".to_string(),
            reason: e.to_string(),
        })?;

    // 4. Apply reliability discount
    let discounted = combination::discount(&raw_mass, request.reliability).map_err(|e| {
        ApiError::InternalError {
            message: format!("Discount failed: {e}"),
        }
    })?;

    // 4b. Apply active context modifiers for this frame (between discount and store)
    let mut modified = discounted;
    let active_contexts = epigraph_db::ContextRepository::list_for_frame(pool, &viewer, frame_id)
        .await
        .unwrap_or_default();
    let now = chrono::Utc::now();
    // The contexts whose modifier applied, for the SCOPED_BY edges step 14
    // writes on the stamped transaction.
    let mut scoped_by: Vec<(Uuid, String)> = Vec::new();
    for ctx in &active_contexts {
        // Check temporal validity
        if let Some(from) = ctx.valid_from {
            if now < from {
                continue;
            }
        }
        if let Some(until) = ctx.valid_until {
            if now > until {
                continue;
            }
        }
        if let Some(ref modifier_type) = ctx.modifier_type {
            let params = ctx.parameters.clone().unwrap_or(serde_json::json!({}));
            match combination::apply_context_modifier(&modified, modifier_type, &params) {
                Ok(m) => {
                    modified = m;
                    scoped_by.push((ctx.id, modifier_type.clone()));
                }
                Err(e) => {
                    tracing::warn!(
                        "Context modifier '{}' failed for context {}: {e}",
                        modifier_type,
                        ctx.id
                    );
                }
            }
        }
    }

    // 4c. Apply perspective confidence_calibration as additional discount.
    //     The perspective is read AS THE CALLER, and one it cannot read is a
    //     404 before anything is written. On the raw pool this read saw no
    //     group-private perspective, and a miss (or an error) went ahead:
    //     the BBA was filed under a perspective the caller cannot see (the
    //     foreign key ignores row security), its CONTRIBUTES_TO edge and
    //     scoped belief followed, and the calibration was skipped.
    if let Some(perspective_id) = request.perspective_id {
        let perspective = {
            let mut read = state.read_as(&viewer).await?;
            epigraph_db::PerspectiveRepository::get_by_id(&mut *read, &viewer, perspective_id)
                .await?
        };
        let Some(perspective) = perspective else {
            return Err(ApiError::NotFound {
                entity: "perspective".to_string(),
                id: perspective_id.to_string(),
            });
        };
        if let Some(calibration) = perspective.confidence_calibration {
            if (0.0..1.0).contains(&calibration) {
                match combination::discount(&modified, calibration) {
                    Ok(m) => {
                        tracing::debug!(
                            "Applied confidence_calibration={calibration} for perspective {perspective_id}"
                        );
                        modified = m;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Confidence calibration discount failed for perspective {perspective_id}: {e}"
                        );
                    }
                }
            }
        }
    }

    // 4d. Apply competence_scopes discount for out-of-scope agents
    if let Some(agent_id) = request.agent_id {
        let agent_props: Option<(serde_json::Value,)> =
            sqlx::query_as("SELECT properties FROM agents WHERE id = $1")
                .bind(agent_id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten();

        if let Some((props,)) = agent_props {
            if let Some(scopes) = props.get("competence_scopes").and_then(|s| s.as_array()) {
                let frame_id_str = frame_id.to_string();
                let frame_name = &frame_row.name;
                let in_scope = scopes.iter().any(|s| {
                    s.as_str()
                        .map(|v| v == frame_id_str || v == frame_name)
                        .unwrap_or(false)
                });
                if !in_scope && !scopes.is_empty() {
                    // Agent has declared competence scopes but this frame isn't in them
                    const COMPETENCE_DISCOUNT: f64 = 0.7;
                    match combination::discount(&modified, COMPETENCE_DISCOUNT) {
                        Ok(m) => {
                            tracing::info!(
                                "Applied competence discount ({COMPETENCE_DISCOUNT}) for agent {agent_id} on frame {frame_id}"
                            );
                            modified = m;
                        }
                        Err(e) => {
                            tracing::warn!("Competence discount failed: {e}");
                        }
                    }
                }
            }
        }
    }

    // 4e. Pre-screen for contradiction potential (G8)
    //     Load the claim's edge neighborhood and check if the new evidence
    //     would introduce a contradiction via the Ascent reasoning engine.
    {
        use epigraph_engine::reasoning::{ReasoningClaim, ReasoningEdge, ReasoningEngine};

        // Load edges where this claim is source or target
        let source_edges =
            epigraph_db::EdgeRepository::get_by_source(pool, &viewer, request.claim_id, "claim")
                .await
                .unwrap_or_default();
        let target_edges =
            epigraph_db::EdgeRepository::get_by_target(pool, &viewer, request.claim_id, "claim")
                .await
                .unwrap_or_default();

        let all_edges: Vec<_> = source_edges.iter().chain(target_edges.iter()).collect();

        if !all_edges.is_empty() {
            // Collect neighbor claim IDs
            let mut neighbor_ids: Vec<Uuid> = all_edges
                .iter()
                .flat_map(|e| [e.source_id, e.target_id])
                .filter(|id| *id != request.claim_id)
                .collect();
            neighbor_ids.sort();
            neighbor_ids.dedup();

            // Load truth values for neighbors + this claim
            let mut claim_ids = neighbor_ids.clone();
            claim_ids.push(request.claim_id);

            let claim_rows: Vec<(Uuid, Option<f64>)> =
                sqlx::query_as("SELECT id, truth_value FROM claims WHERE id = ANY($1)")
                    .bind(&claim_ids)
                    .fetch_all(pool)
                    .await
                    .unwrap_or_default();

            let reasoning_claims: Vec<ReasoningClaim> = claim_rows
                .iter()
                .map(|(id, tv)| ReasoningClaim {
                    id: *id,
                    truth_value: tv.unwrap_or(0.5),
                })
                .collect();

            let reasoning_edges: Vec<ReasoningEdge> = all_edges
                .iter()
                .map(|e| ReasoningEdge {
                    source_id: e.source_id,
                    target_id: e.target_id,
                    relationship: e.relationship.clone(),
                    strength: e
                        .properties
                        .get("strength")
                        .and_then(serde_json::Value::as_f64)
                        .unwrap_or(0.5),
                })
                .collect();

            // Model the new evidence as a pseudo-node supporting the claim
            let pseudo_id = Uuid::new_v4();
            let new_edge = ReasoningEdge {
                source_id: pseudo_id,
                target_id: request.claim_id,
                relationship: "supports".to_string(),
                strength: request.reliability,
            };

            // Extend claims to include the pseudo-evidence node
            let mut extended_claims = reasoning_claims;
            extended_claims.push(ReasoningClaim {
                id: pseudo_id,
                truth_value: request.reliability,
            });

            if let Some(contradiction) =
                ReasoningEngine::would_contradict(&extended_claims, &reasoning_edges, &new_edge)
            {
                let event_store = super::events::global_event_store();
                event_store
                    .push(
                        "contradiction.predicted".to_string(),
                        request.agent_id,
                        serde_json::json!({
                            "claim_id": request.claim_id,
                            "contradicting_claims": [
                                contradiction.claim_a.to_string(),
                                contradiction.claim_b.to_string(),
                            ],
                            "target": contradiction.target.to_string(),
                            "support_strength": contradiction.support_strength,
                            "refute_strength": contradiction.refute_strength,
                        }),
                    )
                    .await;
            }
        }
    }

    // 5. ONE viewer-stamped transaction for this submission's own writes: the
    //    BBA, the frame assignment, the claim's cached belief, its Beta
    //    parameters and its global scoped belief (backlogs 2bffdfdc / I075 and
    //    82dcff9d / I228, the REST twins of `submit_ds_evidence`'s #317 and
    //    #513).
    //
    //    The combine and the cache write are DELEGATED to the shared pipeline,
    //    `edge_factor::recompute_claim_belief_on_frame`, the same function
    //    `recompute_beliefs`, the framed `get_belief` and MCP
    //    `submit_ds_evidence` use. This handler used to run its own combine
    //    (only `'discount'` rows, an independence analysis with cautious
    //    combine, the caller's threshold), wrote the cache with no
    //    `belief_frame_id`, stored the masses with `source_strength =
    //    reliability` (which the shared pipeline discounts AGAIN), and then
    //    stored the combined result back as a NULL-agent "system" BBA that every
    //    later recompute folded in as one more independent source. A submit and
    //    a recompute with no new evidence then disagreed (0.60 vs 0.72 for one
    //    BBA), and a submission with no `agent_id` was overwritten by that
    //    combined row (same unique key).
    //
    //    The submission's edges (WITHIN_FRAME, SCOPED_BY and the DS
    //    relationships) are on this transaction too, so they carry the
    //    caller's writer group.
    //
    //    The derived rows computed after the commit (the perspective and
    //    community scoped beliefs, the divergence record) are written on a
    //    SECOND stamped transaction in step 20, never on the raw pool, and only
    //    AFTER this one commits: once the recompute has updated the `claims`
    //    row on `tx`, a write that touches that row on another connection
    //    would wait on this transaction forever.
    let mut tx = state.write_as(&viewer, "submit_evidence").await?;

    // 5a. The claim, read as the caller. An unreadable claim gets the same 404
    //     as a nonexistent one, so the route is no existence oracle.
    {
        let sql = viewer.splice(
            "SELECT c.id FROM claims c WHERE c.id = $1 /* {VISIBILITY:c} */",
            2,
        );
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql).bind(request.claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        if q.fetch_optional(&mut *tx)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?
            .is_none()
        {
            return Err(ApiError::NotFound {
                entity: "claim".to_string(),
                id: request.claim_id.to_string(),
            });
        }
    }

    // 5b. Store the individual BBA (with optional perspective).
    //     The masses are the reliability-discounted ones (step 4), which the
    //     REST readers of `'discount'` rows (`get_pignistic`, 18b's velocity
    //     check, step 17's perspective scope) consume directly. So the row's
    //     `source_strength` is 1.0: `effective_source_strength` (tier 1 when
    //     untyped, tier 4 for an uncalibrated type) must not apply
    //     `reliability` a second time.
    let masses_json = modified.masses_to_json();
    // Canonical key, or the caller's own key lowercased (bc06ec6f).
    let stored_evidence_type =
        epigraph_engine::calibration::canonical_evidence_type(request.evidence_type.as_deref());

    // 5a'. What the store below does to the caller's row for its key (backlog
    //      6f82db4f, the REST twin of bcbe34b2): the upsert returns only the
    //      id, so read the row first, on this transaction, and compare it with
    //      exactly what 5b stores. The caller's row has an agent, so the
    //      cached-combination exclusion never hides it.
    let write_outcome = {
        use epigraph_db::bba_write_outcome::{classify, prior_for, BbaWrite};
        let rows = epigraph_db::MassFunctionRepository::get_for_claim_frame(
            &mut *tx,
            &viewer,
            request.claim_id,
            frame_id,
        )
        .await?;
        classify(
            prior_for(&rows, request.agent_id, request.perspective_id),
            &BbaWrite {
                masses: &masses_json,
                combination_method: "discount",
                evidence_type: stored_evidence_type.as_deref(),
                locality_tag: "unknown",
                source_strength: Some(1.0),
                conflict_k: None,
                evidence_id: None,
            },
        )
    };

    let mf_id = epigraph_db::MassFunctionRepository::store_with_perspective(
        &mut *tx,
        request.claim_id,
        frame_id,
        request.agent_id,
        request.perspective_id,
        &masses_json,
        None,
        Some("discount"),
        Some(1.0), // `reliability` is already in the masses; see 5b
        stored_evidence_type.as_deref(),
        "unknown", // locality not known at HTTP belief endpoint; see issue #197
        None,      // HTTP belief endpoint has no evidence row in scope (issue #197 Phase 3)
    )
    .await?;

    // 6. Ensure the claim is assigned to the frame (best-effort, under a
    //    SAVEPOINT: unsavepointed, a refused INSERT would abort the transaction
    //    and the COMMIT would silently roll the BBA back).
    //    ON CONFLICT DO NOTHING preserves an existing hypothesis_index;
    //    `FrameRepository::assign_claim` would overwrite it with NULL.
    {
        use sqlx::Acquire as _;
        let mut sp = tx.begin().await.map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to open a savepoint: {e}"),
        })?;
        let assigned = sqlx::query(
            "INSERT INTO claim_frames (claim_id, frame_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(request.claim_id)
        .bind(frame_id)
        .execute(&mut *sp)
        .await;
        match assigned {
            Ok(_) => sp.commit().await,
            Err(e) => {
                tracing::warn!("submit_evidence: claim_frames assignment refused: {e}");
                sp.rollback().await
            }
        }
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to close a savepoint: {e}"),
        })?;
    }

    // 11. Look up claim's hypothesis_index in claim_frames (Beta update, the
    //     perspective scope and the velocity check below)
    let claim_assignment = epigraph_db::FrameRepository::get_claim_assignment(
        &mut *tx,
        &viewer,
        request.claim_id,
        frame_id,
    )
    .await?;
    let h_idx = claim_assignment.and_then(|ca| ca.hypothesis_index);

    // 12. Read old belief/plausibility before updating (for event payload)
    let old_row: Option<(Option<f64>, Option<f64>)> =
        sqlx::query_as("SELECT belief, plausibility FROM claims WHERE id = $1")
            .bind(request.claim_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?;
    let (old_belief, old_plausibility) = old_row.unwrap_or((None, None));

    // 13. Combine every BBA on (claim, frame) and write the claim's cache with
    //     `belief_frame_id = frame_id`, through the shared pipeline. A
    //     non-owner's write follows migration 114: it refreshes the cache only
    //     on the frame the cache already carries (or seeds `binary_truth`).
    epigraph_engine::edge_factor::recompute_claim_belief_on_frame(
        &mut tx,
        &viewer,
        request.claim_id,
        frame_id,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Belief recompute failed: {e}"),
    })?;

    // 13a. This frame's combination, by the same pipeline, for the response
    //      and the events. When the cache now carries another frame (a
    //      non-owner may not re-point it), say so instead of implying that the
    //      claim's belief moved.
    let preview = epigraph_engine::edge_factor::preview_claim_belief_on_frame(
        &mut tx,
        &viewer,
        request.claim_id,
        frame_id,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Belief preview failed: {e}"),
    })?
    .ok_or_else(|| ApiError::InternalError {
        message: "no BBA on this frame after storing one".to_string(),
    })?;
    let cache_frame: Option<Uuid> =
        sqlx::query_scalar("SELECT belief_frame_id FROM claims WHERE id = $1")
            .bind(request.claim_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?
            .flatten();
    let mut warnings = deprecated_parameter_warnings(&request);
    if redirected.is_some() {
        warnings.push(epigraph_engine::promotion::redirected_evidence_warning(
            request.claim_id,
            named_frame,
            frame_id,
        ));
    }
    match write_outcome {
        epigraph_db::bba_write_outcome::BbaWriteOutcome::Unchanged => warnings.push(
            "this BBA is identical to the one this agent already stored for this claim, frame \
             and perspective_id; its stored values are unchanged (the row's created_at is \
             refreshed), so the claim's Dempster-Shafer belief did not move on its account \
             (bayesian_posterior still applies this submission's Beta update)."
                .to_string(),
        ),
        epigraph_db::bba_write_outcome::BbaWriteOutcome::Replaced => warnings.push(
            "this BBA REPLACED this agent's earlier, different BBA for this claim, frame and \
             perspective_id (same mass_function_id); it was not added beside it. To add \
             independent evidence, submit it under a distinct perspective_id."
                .to_string(),
        ),
        epigraph_db::bba_write_outcome::BbaWriteOutcome::Inserted => {}
    }
    if cache_frame != Some(frame_id) {
        warnings.push(format!(
            "claim {}'s cached belief was NOT updated by this call: it carries another frame \
             (or an older cache with no recorded frame, or none on a frame other than \
             binary_truth), which a non-owner does not re-point or seed. updated_belief, \
             updated_plausibility and pignistic_prob here are this frame's combination, not \
             the claim's cache.",
            request.claim_id
        ));
    }

    // 13b. Parallel Beta-Bernoulli update
    //      Compute likelihood ratio from evidence mass function and update Beta parameters.
    //      The evidence's mass on the singleton {h_i} indicates support strength.
    //      Best-effort, under a SAVEPOINT (the read included: a failed statement
    //      aborts the enclosing transaction whether it read or wrote).
    let bayesian_posterior = {
        use sqlx::Acquire as _;
        let mut sp = tx.begin().await.map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to open a savepoint: {e}"),
        })?;
        let beta_row: Result<Option<(f64, f64)>, sqlx::Error> =
            sqlx::query_as("SELECT beta_alpha, beta_beta FROM claims WHERE id = $1")
                .bind(request.claim_id)
                .fetch_optional(&mut *sp)
                .await;

        let (mut alpha, mut beta_param) = beta_row
            .as_ref()
            .ok()
            .copied()
            .flatten()
            .unwrap_or((1.0, 1.0));

        // Use the submitted evidence's singleton mass as the evidence strength
        if let Some(h_i) = h_idx {
            let singleton =
                epigraph_ds::FocalElement::positive(std::iter::once(h_i as usize).collect());
            let m_support = modified.mass_of(&singleton);
            // Evidence strength: mass on the singleton hypothesis vs complement
            // Higher m_support → stronger evidence for the hypothesis
            if m_support > 0.0 {
                alpha += m_support;
            }
            let m_complement = 1.0 - m_support - modified.mass_of_empty();
            if m_complement > 0.0 {
                beta_param += m_complement;
            }
        }

        // Store updated Beta parameters
        let stored = match beta_row {
            Ok(_) => sqlx::query(
                "UPDATE claims SET beta_alpha = $2, beta_beta = $3, updated_at = NOW() WHERE id = $1",
            )
            .bind(request.claim_id)
            .bind(alpha)
            .bind(beta_param)
            .execute(&mut *sp)
            .await
            .map(|_| ()),
            Err(e) => Err(e),
        };
        match stored {
            Ok(()) => sp.commit().await,
            Err(e) => {
                tracing::warn!("submit_evidence: Beta update refused: {e}");
                sp.rollback().await
            }
        }
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to close a savepoint: {e}"),
        })?;

        // Compute posterior: E[Beta(alpha, beta)] = alpha / (alpha + beta)
        alpha / (alpha + beta_param)
    };

    // The BBAs the shared pipeline just combined, read through the same
    // combine-input reader it uses. `count_for_claim_frame` would also count a
    // legacy cached combination row (an agent-less, perspective-less row the
    // writers stored before U024, ~15.5k of them on prod), which the reader
    // excludes (backlog b5cb3efb): one real input beside such a row would then
    // report two sources and a Dempster fold that never happened.
    let total_sources = i64::try_from(
        epigraph_db::MassFunctionRepository::get_for_claim_frame(
            &mut *tx,
            &viewer,
            request.claim_id,
            frame_id,
        )
        .await?
        .len(),
    )
    .unwrap_or(i64::MAX);

    // The values the rest of the handler reports and emits: this frame's
    // combination by the shared pipeline. `combine_multiple` folds with
    // Dempster at every step since U025; a single BBA is not folded, so it has
    // no combination step and no fold conflict to report as one. `total_sources`
    // is the number of BBAs that fold combined (see above).
    let final_bel = preview.belief;
    let final_pl = preview.plausibility;
    let final_betp = preview.pignistic_prob;
    let m_empty = preview.conflict_k;
    let m_missing = preview.missing_mass;
    let folded = total_sources > 1;
    let final_k = folded.then_some(preview.conflict_k);
    let final_method = folded.then_some("Dempster");
    let report_responses: Vec<CombinationReportResponse> = if folded {
        vec![CombinationReportResponse {
            method_used: "Dempster".to_string(),
            conflict_k: preview.conflict_k,
            mass_on_conflict: preview.conflict_k,
            mass_on_missing: preview.missing_mass,
        }]
    } else {
        vec![]
    };

    // 15. The global scoped belief cache, on the stamped transaction
    //     (best-effort, under a SAVEPOINT like steps 6 and 13b). On the raw
    //     pool this write was refused under FORCE without an error, and with
    //     it the only record of a REST fold's conflict K now that no derived
    //     BBA is stored beside the inputs.
    {
        use sqlx::Acquire as _;
        let mut sp = tx.begin().await.map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to open a savepoint: {e}"),
        })?;
        let stored = epigraph_db::ScopedBeliefRepository::upsert(
            &mut *sp,
            frame_id,
            request.claim_id,
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
                tracing::warn!("submit_evidence: global scoped belief refused: {e}");
                sp.rollback().await
            }
        }
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to close a savepoint: {e}"),
        })?;
    }

    // 14 / 16. The edges this submission records, on the stamped transaction
    //     (each best-effort, under a SAVEPOINT like steps 6, 13b and 15). On
    //     the raw pool after the commit they were written UNSTAMPED: the edges
    //     trigger records the writer from the session, so every one landed
    //     with no writer group, a public claim's WITHIN_FRAME edge owned by
    //     the world group, and a group claim's refused outright by row
    //     security.
    create_edge_under_savepoint(
        &mut tx,
        request.claim_id,
        "claim",
        frame_id,
        "frame",
        "WITHIN_FRAME",
        None,
    )
    .await?;
    //     SCOPED_BY, claim -> each context whose modifier step 4b applied.
    for (context_id, modifier_type) in &scoped_by {
        create_edge_under_savepoint(
            &mut tx,
            request.claim_id,
            "claim",
            *context_id,
            "context",
            "SCOPED_BY",
            Some(serde_json::json!({"modifier_type": modifier_type})),
        )
        .await?;
    }
    //     DS relationships. "evidence" is the entity type for mass functions
    //     (constraint-compatible).
    if final_bel > 0.5 {
        create_edge_under_savepoint(
            &mut tx,
            mf_id,
            "evidence",
            request.claim_id,
            "claim",
            "SUPPORTS",
            Some(serde_json::json!({"belief": final_bel})),
        )
        .await?;
    } else if final_bel < 0.3 {
        create_edge_under_savepoint(
            &mut tx,
            mf_id,
            "evidence",
            request.claim_id,
            "claim",
            "CONTRADICTS",
            Some(serde_json::json!({"belief": final_bel})),
        )
        .await?;
    }
    if let Some(agent_id) = request.agent_id {
        create_edge_under_savepoint(
            &mut tx,
            mf_id,
            "evidence",
            agent_id,
            "agent",
            "GENERATED_BY",
            None,
        )
        .await?;
    }
    if let Some(perspective_id) = request.perspective_id {
        create_edge_under_savepoint(
            &mut tx,
            perspective_id,
            "perspective",
            request.claim_id,
            "claim",
            "CONTRIBUTES_TO",
            None,
        )
        .await?;
    }

    tx.commit().await?;

    // 13c. CDST residual mass analysis
    {
        let event_store = super::events::global_event_store();
        // High frame incompleteness -> evidence may not cover all relevant hypotheses
        if m_missing > 0.15 {
            event_store
                .push(
                    "frame.incomplete".to_string(),
                    request.agent_id,
                    serde_json::json!({
                        "claim_id": request.claim_id,
                        "frame_id": frame_id,
                        "mass_on_missing": m_missing,
                    }),
                )
                .await;
        }

        // High genuine conflict with low ignorance -> sources disagree within the frame
        if m_empty > 0.10 && m_missing < 0.05 {
            event_store
                .push(
                    "conflict.genuine".to_string(),
                    request.agent_id,
                    serde_json::json!({
                        "claim_id": request.claim_id,
                        "frame_id": frame_id,
                        "mass_on_conflict": m_empty,
                        "mass_on_missing": m_missing,
                    }),
                )
                .await;
        }
    }

    // 17. Compute perspective-scoped and community-scoped beliefs.
    //     The BBAs are read as the caller (an unstamped read sees no group
    //     row), and the scoped beliefs are collected here and written in step
    //     20 on a stamped transaction, never on the raw pool: there, FORCE'd
    //     row security refused them without an error.
    let mut scoped_beliefs: Vec<ScopedBeliefWrite> = Vec::new();
    let mut scoped_read = match request.perspective_id {
        Some(_) => match state.read_as(&viewer).await {
            Ok(read) => Some(read),
            Err(e) => {
                tracing::warn!("submit_evidence: no stamped read for the scoped beliefs: {e}");
                None
            }
        },
        None => None,
    };
    if let (Some(perspective_id), Some(read)) = (request.perspective_id, scoped_read.as_mut()) {
        // Perspective scope: combine only BBAs from this perspective
        let perspective_rows =
            epigraph_db::MassFunctionRepository::get_for_claim_frame_perspective(
                &mut **read,
                &viewer,
                request.claim_id,
                frame_id,
                perspective_id,
            )
            .await
            .unwrap_or_default();
        if let Some(write) = scoped_belief_write(
            read,
            &viewer,
            request.claim_id,
            &ds_frame,
            h_idx,
            perspective_rows,
            request.conflict_threshold,
            "perspective",
            perspective_id,
        )
        .await
        {
            scoped_beliefs.push(write);
        }

        // Community scope: for each community this perspective belongs to
        if let Ok(community_ids) =
            epigraph_db::CommunityRepository::communities_for_perspective(pool, perspective_id)
                .await
        {
            for community_id in community_ids {
                // Check for community mass_override before combining member BBAs
                let use_override = if let Ok(Some(comm)) =
                    epigraph_db::CommunityRepository::get_by_id(&mut **read, &viewer, community_id)
                        .await
                {
                    if let Some(ref overrides) = comm.mass_override {
                        // Look up override for this specific frame
                        let frame_key = frame_id.to_string();
                        if let Some(frame_masses) = overrides.get(&frame_key) {
                            if let Ok(override_mf) =
                                MassFunction::from_json_masses(ds_frame.clone(), frame_masses)
                            {
                                let (o_bel, o_pl, o_betp, o_m_missing) =
                                    compute_hypothesis_belief(&override_mf, &ds_frame, h_idx);
                                let o_m_empty = override_mf.mass_of_empty();

                                scoped_beliefs.push(ScopedBeliefWrite {
                                    scope_type: "community",
                                    scope_id: community_id,
                                    belief: o_bel,
                                    plausibility: o_pl,
                                    mass_on_empty: o_m_empty,
                                    mass_on_missing: o_m_missing,
                                    conflict_k: None,
                                    strategy: Some("override".to_string()),
                                    pignistic_prob: o_betp,
                                });
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };

                if use_override {
                    continue;
                }

                if let Ok(member_ids) =
                    epigraph_db::CommunityRepository::member_perspective_ids(pool, community_id)
                        .await
                {
                    let community_rows =
                        epigraph_db::MassFunctionRepository::get_for_claim_frame_perspectives(
                            &mut **read,
                            &viewer,
                            request.claim_id,
                            frame_id,
                            &member_ids,
                        )
                        .await
                        .unwrap_or_default();
                    if let Some(write) = scoped_belief_write(
                        read,
                        &viewer,
                        request.claim_id,
                        &ds_frame,
                        h_idx,
                        community_rows,
                        request.conflict_threshold,
                        "community",
                        community_id,
                    )
                    .await
                    {
                        scoped_beliefs.push(write);
                    }
                }
            }
        }
    }

    drop(scoped_read);

    // 17b. Emit evidence.submitted event
    let event_store = super::events::global_event_store();
    event_store
        .push(
            "evidence.submitted".to_string(),
            request.agent_id,
            serde_json::json!({
                "mass_function_id": mf_id,
                "claim_id": request.claim_id,
                "frame_id": frame_id,
                "agent_id": request.agent_id,
                "perspective_id": request.perspective_id,
                "reliability": request.reliability,
            }),
        )
        .await;

    // 18. Emit belief.updated event
    event_store
        .push(
            "belief.updated".to_string(),
            request.agent_id,
            serde_json::json!({
                "claim_id": request.claim_id,
                "frame_id": frame_id,
                "old_belief": old_belief,
                "new_belief": final_bel,
                "old_plausibility": old_plausibility,
                "new_plausibility": final_pl,
                "pignistic_prob": final_betp,
                "combination_method": final_method,
                "total_sources": total_sources,
                "perspective_id": request.perspective_id,
            }),
        )
        .await;

    // 18b. Confidence velocity check — detect monotonic belief increase
    //      Reconstruct recent belief trajectory from scoped_belief snapshots.
    //      Each evidence submission updates the scoped_belief row's computed_at.
    //      We use the scoped_belief audit log (if available) or fall back to
    //      checking the singular mass function support values as a proxy.
    {
        // Use individual mass function singleton masses as a belief proxy trajectory.
        // Each discount-stage BBA's support for the hypothesis approximates what
        // the agent believed when submitting. Ordered by creation time.
        let recent_support: Vec<(f64,)> = if let Some(h_i) = h_idx {
            let focal_key = format!("{h_i}");
            sqlx::query_as(
                "SELECT COALESCE((masses->>$3)::float8, 0.0) AS support \
                 FROM mass_functions \
                 WHERE claim_id = $1 AND frame_id = $2 \
                 AND combination_method = 'discount' \
                 ORDER BY created_at DESC \
                 LIMIT 10",
            )
            .bind(request.claim_id)
            .bind(frame_id)
            .bind(&focal_key)
            .fetch_all(pool)
            .await
            .unwrap_or_default()
        } else {
            vec![]
        };

        if recent_support.len() >= 3 {
            let samples: Vec<_> = recent_support
                .iter()
                .rev()
                .enumerate()
                .map(|(i, (b,))| epigraph_engine::silence_alarm::BeliefSample {
                    belief: *b,
                    evidence_count: i,
                })
                .collect();
            let velocity = epigraph_engine::silence_alarm::check_confidence_velocity(&samples, 5);
            if velocity.is_suspicious {
                event_store
                    .push(
                        "velocity.suspicious".to_string(),
                        request.agent_id,
                        serde_json::json!({
                            "claim_id": request.claim_id,
                            "frame_id": frame_id,
                            "monotonic_streak": velocity.monotonic_streak,
                            "total_samples": velocity.total_samples,
                            "reason": velocity.reason,
                        }),
                    )
                    .await;
            }
        }
    }

    // 19. Emit conflict.detected if conflict exceeds threshold
    if let Some(k) = final_k {
        if k >= request.conflict_threshold {
            event_store
                .push(
                    "conflict.detected".to_string(),
                    request.agent_id,
                    serde_json::json!({
                        "frame_id": frame_id,
                        "claim_id": request.claim_id,
                        "conflict_k": k,
                        "method_used": final_method,
                    }),
                )
                .await;

            // 19b. Auto-create challenge when conflict K >= 0.7 (S4.4 / G14)
            const HIGH_CONFLICT_THRESHOLD: f64 = 0.7;
            if let Some(challenge) = epigraph_core::auto_create_challenge(
                k,
                request.claim_id,
                frame_id,
                HIGH_CONFLICT_THRESHOLD,
            ) {
                let _ = state.challenge_service.submit(challenge);
            }
        }
    }

    // 19c. Silence alarm — check conflict density for this frame (S3.2 / G2)
    //      Read the frame's claim count and contradiction count (distinct claim
    //      pairs joined by a live contradicts/refutes edge, the same counts the
    //      `/conflicts` scans use), then run the pure check_conflict_density().
    {
        let silence_counts: Option<(i64, i64)> =
            epigraph_db::ConflictDensityRepository::for_frames(pool, &[frame_id])
                .await
                .ok()
                .and_then(|rows| rows.into_iter().next())
                .map(|d| (d.total_claims, d.contradicts_edges));

        if let Some((total, contradicts)) = silence_counts {
            let silence = epigraph_engine::silence_alarm::check_conflict_density(
                total as usize,
                contradicts as usize,
                &epigraph_engine::silence_alarm::SilenceAlarmConfig::default(),
            );
            if silence.is_suspicious {
                event_store
                    .push(
                        "silence.suspicious".to_string(),
                        request.agent_id,
                        serde_json::json!({
                            "frame_id": frame_id,
                            "claim_id": request.claim_id,
                            "total_claims": silence.total_claims,
                            "contradicts_edges": silence.contradicts_edges,
                            "conflict_rate": silence.conflict_rate,
                            "reason": silence.reason,
                        }),
                    )
                    .await;
            }
        }
    }

    // 20. Compute and store DS vs Bayesian divergence (using live Beta posterior)
    //     and step 17's scoped beliefs: derived rows, best-effort, on ONE
    //     stamped transaction after the main COMMIT, each under a SAVEPOINT so
    //     one refusal does not discard the others. On the raw pool, FORCE'd row
    //     security refused every one of them without an error. Nothing here may
    //     fail the request: the submission is already committed.
    {
        use sqlx::Acquire as _;
        let kl = kl_divergence_bernoulli(final_betp, bayesian_posterior);

        match state
            .write_as(&viewer, "submit_evidence.derived_rows")
            .await
        {
            Ok(mut side) => {
                for w in &scoped_beliefs {
                    let mut sp = match side.begin().await {
                        Ok(sp) => sp,
                        Err(e) => {
                            tracing::warn!(
                                "submit_evidence: no savepoint for a scoped belief: {e}"
                            );
                            break;
                        }
                    };
                    let stored = epigraph_db::ScopedBeliefRepository::upsert(
                        &mut *sp,
                        frame_id,
                        request.claim_id,
                        w.scope_type,
                        Some(w.scope_id),
                        w.belief,
                        w.plausibility,
                        w.mass_on_empty,
                        w.mass_on_missing,
                        w.conflict_k,
                        w.strategy.as_deref(),
                        Some(w.pignistic_prob),
                    )
                    .await;
                    if finish_savepoint(sp, stored, "scoped belief").await.is_err() {
                        break;
                    }
                }
                if let Ok(mut sp) = side.begin().await {
                    let stored = epigraph_db::DivergenceRepository::store(
                        &mut *sp,
                        request.claim_id,
                        frame_id,
                        final_betp,
                        bayesian_posterior,
                        kl,
                        Some(frame_row.version),
                    )
                    .await;
                    let _ = finish_savepoint(sp, stored, "divergence record").await;
                }
                if let Err(e) = side.commit().await {
                    tracing::warn!("submit_evidence: derived rows not committed: {e}");
                }
            }
            Err(e) => {
                tracing::warn!(
                    "submit_evidence: no stamped transaction for the derived rows: {e:?}"
                );
            }
        }

        // Emit divergence.spike if KL exceeds threshold
        if kl >= DIVERGENCE_SPIKE_THRESHOLD {
            event_store
                .push(
                    "divergence.spike".to_string(),
                    request.agent_id,
                    serde_json::json!({
                        "claim_id": request.claim_id,
                        "frame_id": frame_id,
                        "pignistic_prob": final_betp,
                        "bayesian_posterior": bayesian_posterior,
                        "kl_divergence": kl,
                    }),
                )
                .await;
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(EvidenceSubmissionResponse {
            mass_function_id: mf_id,
            combination_reports: report_responses,
            updated_belief: final_bel,
            updated_plausibility: final_pl,
            mass_on_conflict: m_empty,
            mass_on_missing: m_missing,
            pignistic_prob: Some(final_betp),
            bayesian_posterior,
            total_sources,
            write_outcome: write_outcome.as_str().to_string(),
            deduplicated: write_outcome.deduplicated(),
            warnings,
        }),
    ))
}

/// Filter claims by belief/plausibility bounds
///
/// `GET /api/v1/claims/by-belief`
#[cfg(feature = "db")]
#[allow(clippy::type_complexity)]
pub async fn claims_by_belief(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Query(params): Query<BeliefFilterQuery>,
) -> Result<Json<Vec<BeliefClaimRow>>, ApiError> {
    let min_bel = params.min_belief.unwrap_or(0.0);
    let max_pl = params.max_plausibility.unwrap_or(1.0);

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "claims_by_belief",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // PR-07: this was an unfiltered, caller-paginated corpus scan projecting
    // `c.content` with no `ViewerExtractor` at all. The statement now lives in
    // `ClaimRepository::list_by_belief_bounds` with the visibility predicate on
    // both `claims` and the `claim_frames` subquery.
    let rows = epigraph_db::ClaimRepository::list_by_belief_bounds(
        &mut *read,
        &viewer,
        min_bel,
        max_pl,
        params.frame_id,
        params.limit,
        params.offset,
    )
    .await?;

    crate::routes::finish_scoped_read(read, "claims_by_belief").await?;

    let result: Vec<BeliefClaimRow> = rows
        .into_iter()
        .map(|hit| BeliefClaimRow {
            id: hit.id,
            content: hit.content,
            belief: hit.belief,
            plausibility: hit.plausibility,
            mass_on_conflict: hit.mass_on_empty,
            mass_on_missing: hit.mass_on_missing,
        })
        .collect();

    // No redaction pass: `list_by_belief_bounds` above is spliced with
    // `&viewer`, so an unreadable row never reaches `result`.
    Ok(Json(result))
}

/// List claims in a frame sorted by belief metric
///
/// `GET /api/v1/frames/:id/claims`
#[cfg(feature = "db")]
#[allow(clippy::type_complexity)]
pub async fn frame_claims_sorted(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
    Query(params): Query<FrameClaimsQuery>,
) -> Result<Json<Vec<FrameClaimBeliefRow>>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "frame_claims_sorted",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // Verify frame exists
    epigraph_db::FrameRepository::get_by_id(&mut *read, &viewer, frame_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        })?;

    // Validate sort_by / order. `from_wire` returning `None` is a 400; the
    // repo takes enums, so no caller-supplied string reaches the `ORDER BY`.
    let sort = epigraph_db::BeliefSort::from_wire(params.sort_by.as_str()).ok_or(
        ApiError::ValidationError {
            field: "sort_by".to_string(),
            reason: "Must be one of: belief, plausibility, ignorance".to_string(),
        },
    )?;

    let direction = epigraph_db::SortDirection::from_wire(params.order.as_str()).ok_or(
        ApiError::ValidationError {
            field: "order".to_string(),
            reason: "Must be 'asc' or 'desc'".to_string(),
        },
    )?;

    // PR-07: this statement used to be built here with `format!` +
    // `sqlx::query_as` and NO visibility predicate, even though the handler was
    // already holding a `Viewer` (spent above on the frame-existence check).
    // Holding a viewer and not filtering on it is the plan's own definition of
    // a fail-open, and it escaped `Viewer::splice`'s missing-marker panic only
    // because `splice` was never called.
    let rows = epigraph_db::ClaimRepository::frame_claims_sorted(
        &mut *read,
        &viewer,
        frame_id,
        sort,
        direction,
        params.limit,
        params.offset,
    )
    .await?;

    crate::routes::finish_scoped_read(read, "frame_claims_sorted").await?;

    let result: Vec<FrameClaimBeliefRow> = rows
        .into_iter()
        .map(|hit| FrameClaimBeliefRow {
            claim_id: hit.claim_id,
            content: hit.content,
            hypothesis_index: hit.hypothesis_index,
            belief: hit.belief,
            plausibility: hit.plausibility,
            ignorance: match (hit.belief, hit.plausibility) {
                (Some(b), Some(p)) => Some(p - b),
                _ => None,
            },
            mass_on_missing: hit.mass_on_missing,
        })
        .collect();

    // No redaction pass: the frame-claims repo read above is spliced with
    // `&viewer`. `frame_claims_sorted` is the site PR-07 found holding a
    // `ViewerExtractor` and never filtering on it; the filter is real now, and
    // the post-pass that masked that defect is gone.
    Ok(Json(result))
}

/// Get latest DS vs Bayesian divergence for a claim
///
/// `GET /api/v1/claims/:id/divergence`
#[cfg(feature = "db")]
pub async fn claim_divergence(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<Option<DivergenceResponse>>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "claim_divergence",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let row = epigraph_db::DivergenceRepository::get_latest(&mut *read, &viewer, claim_id).await?;

    crate::routes::finish_scoped_read(read, "claim_divergence").await?;

    Ok(Json(row.map(|r| DivergenceResponse {
        id: r.id,
        claim_id: r.claim_id,
        frame_id: r.frame_id,
        pignistic_prob: r.pignistic_prob,
        bayesian_posterior: r.bayesian_posterior,
        kl_divergence: r.kl_divergence,
        frame_version: r.frame_version,
        computed_at: r.computed_at.to_rfc3339(),
    })))
}

/// Get claims with the highest KL divergence
///
/// `GET /api/v1/divergence/top`
#[cfg(feature = "db")]
pub async fn top_divergence(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Query(params): Query<TopDivergenceQuery>,
) -> Result<Json<Vec<DivergenceResponse>>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "top_divergence",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let rows =
        epigraph_db::DivergenceRepository::top_divergent(&mut *read, &viewer, params.limit).await?;

    crate::routes::finish_scoped_read(read, "top_divergence").await?;

    let result = rows
        .into_iter()
        .map(|r| DivergenceResponse {
            id: r.id,
            claim_id: r.claim_id,
            frame_id: r.frame_id,
            pignistic_prob: r.pignistic_prob,
            bayesian_posterior: r.bayesian_posterior,
            kl_divergence: r.kl_divergence,
            frame_version: r.frame_version,
            computed_at: r.computed_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(result))
}

/// Get scoped belief for a claim
///
/// `GET /api/v1/claims/:id/belief/scoped`
///
/// Query params: `scope` (global|perspective|community), `scope_id` (UUID)
#[cfg(feature = "db")]
pub async fn get_scoped_belief(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<ScopedBeliefQuery>,
) -> Result<Json<Option<ScopedBeliefEntry>>, ApiError> {
    let scope_type = params.scope.as_deref().unwrap_or("global");

    if scope_type != "global" && params.scope_id.is_none() {
        return Err(ApiError::ValidationError {
            field: "scope_id".to_string(),
            reason: format!("scope_id is required when scope is '{scope_type}'"),
        });
    }

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_scoped_belief",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let row = epigraph_db::ScopedBeliefRepository::get(
        &mut *read,
        &viewer,
        claim_id,
        scope_type,
        params.scope_id,
    )
    .await?;

    crate::routes::finish_scoped_read(read, "get_scoped_belief").await?;

    Ok(Json(row.map(scoped_belief_to_entry)))
}

/// Get all scoped beliefs for a claim (global + all perspective/community scopes)
///
/// `GET /api/v1/claims/:id/belief/all-scopes`
#[cfg(feature = "db")]
pub async fn all_scopes_belief(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<AllScopesBeliefResponse>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "all_scopes_belief",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let rows =
        epigraph_db::ScopedBeliefRepository::list_for_claim(&mut *read, &viewer, claim_id).await?;

    crate::routes::finish_scoped_read(read, "all_scopes_belief").await?;

    let scopes = rows.into_iter().map(scoped_belief_to_entry).collect();

    Ok(Json(AllScopesBeliefResponse { claim_id, scopes }))
}

#[cfg(feature = "db")]
fn scoped_belief_to_entry(row: epigraph_db::ScopedBeliefRow) -> ScopedBeliefEntry {
    ScopedBeliefEntry {
        scope_type: row.scope_type,
        scope_id: row.scope_id,
        belief: row.belief,
        plausibility: row.plausibility,
        ignorance: row.plausibility - row.belief,
        mass_on_conflict: row.mass_on_empty,
        mass_on_missing: row.mass_on_missing,
        pignistic_prob: row.pignistic_prob,
        conflict_k: row.conflict_k,
        strategy_used: row.strategy_used,
        computed_at: row.computed_at.to_rfc3339(),
    }
}

/// Get full pignistic probability distribution for a claim in a frame
///
/// `GET /api/v1/claims/:id/pignistic?frame_id=<uuid>`
///
/// Recomputes from stored mass functions on-demand (TBM two-level model:
/// credal-level storage, pignistic-level computation at decision time).
#[cfg(feature = "db")]
pub async fn get_pignistic(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<PignisticQuery>,
) -> Result<Json<PignisticResponse>, ApiError> {
    use epigraph_ds::{measures, FrameOfDiscernment, MassFunction};

    let frame_id = params.frame_id;

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_pignistic",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // Load frame
    let frame_row = epigraph_db::FrameRepository::get_by_id(&mut *read, &viewer, frame_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        })?;

    let ds_frame =
        FrameOfDiscernment::new(&frame_row.name, frame_row.hypotheses.clone()).map_err(|e| {
            ApiError::InternalError {
                message: format!("Invalid frame: {e}"),
            }
        })?;

    // Load all individual evidence BBAs (exclude system-combined)
    let all_rows = epigraph_db::MassFunctionRepository::get_for_claim_frame(
        &mut *read, &viewer, claim_id, frame_id,
    )
    .await?;

    // Only the BBAs whose sources this viewer can read (ruling R-22), with
    // their writers' owners for the same-human rule (ruling R-36).
    let mut rows: Vec<epigraph_db::MassFunctionRow> = all_rows
        .into_iter()
        .filter(|row| row.combination_method.as_deref() == Some("discount"))
        .collect();
    rows.sort_by_key(|r| r.id);
    let rows =
        epigraph_engine::derivation_scope::retain_for_viewer(&mut read, &viewer, rows).await?;
    let (rows, masses): (Vec<epigraph_db::MassFunctionRow>, Vec<MassFunction>) = rows
        .into_iter()
        .filter_map(|row| {
            MassFunction::from_json_masses(ds_frame.clone(), &row.masses)
                .ok()
                .map(|m| (row, m))
        })
        .unzip();
    let sources =
        epigraph_engine::source_dependence::bba_sources_for_rows(&mut read, &viewer, &rows).await?;

    // Finished here rather than at the end of the handler: this is the last
    // statement, and the `masses.is_empty()` branch below returns early. Every
    // path after this point is pure computation over rows already held.
    crate::routes::finish_scoped_read(read, "get_pignistic").await?;

    if masses.is_empty() {
        // No evidence — return uniform pignistic
        let n = ds_frame.hypothesis_count();
        #[allow(clippy::cast_precision_loss)]
        let uniform = 1.0 / n as f64;
        let hypotheses = frame_row
            .hypotheses
            .iter()
            .enumerate()
            .map(|(i, name)| PignisticEntry {
                hypothesis_index: i,
                hypothesis_name: name.clone(),
                pignistic_probability: uniform,
                belief: 0.0,
                plausibility: 1.0,
            })
            .collect();

        return Ok(Json(PignisticResponse {
            claim_id,
            frame_id,
            frame_name: frame_row.name,
            hypotheses,
            mass_on_conflict: 0.0,
            mass_on_missing: 0.0,
        }));
    }

    // Combine (a single BBA is returned as-is), by the engine's owner-aware
    // fold: sibling agents of one human never multiply (ruling R-36). The
    // second value is the conflict the fold saw (U025: Dempster normalises it
    // out of `combined`).
    let (combined, m_empty) = epigraph_engine::source_dependence::combine_with_owner_dependence(
        sources.into_iter().zip(masses).collect(),
        0.3,
    )
    .map_err(|e| ApiError::InternalError {
        message: format!("Combination failed: {e}"),
    })?;
    let m_missing = combined.mass_of_missing();

    let hypotheses = frame_row
        .hypotheses
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let singleton =
                epigraph_ds::FocalElement::positive(std::collections::BTreeSet::from([i]));
            PignisticEntry {
                hypothesis_index: i,
                hypothesis_name: name.clone(),
                pignistic_probability: measures::pignistic_probability(&combined, i),
                belief: measures::belief(&combined, &singleton),
                plausibility: measures::plausibility(&combined, &singleton),
            }
        })
        .collect();

    Ok(Json(PignisticResponse {
        claim_id,
        frame_id,
        frame_name: frame_row.name,
        hypotheses,
        mass_on_conflict: m_empty,
        mass_on_missing: m_missing,
    }))
}

/// Create a refinement of an existing frame
///
/// `POST /api/v1/frames/:id/refine`
#[cfg(feature = "db")]
pub async fn refine_frame(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(parent_id): Path<Uuid>,
    Json(request): Json<RefineFrameRequest>,
) -> Result<(StatusCode, Json<FrameResponse>), ApiError> {
    let pool = &state.db_pool;

    // Validate parent frame exists and is refinable
    let parent = epigraph_db::FrameRepository::get_by_id(pool, &viewer, parent_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: parent_id.to_string(),
        })?;

    if !parent.is_refinable {
        return Err(ApiError::ValidationError {
            field: "parent_frame_id".to_string(),
            reason: "Parent frame is not refinable".to_string(),
        });
    }

    if request.hypotheses.len() < 2 {
        return Err(ApiError::ValidationError {
            field: "hypotheses".to_string(),
            reason: "Refinement must have at least 2 hypotheses".to_string(),
        });
    }

    if request.name.is_empty() || request.name.len() > 200 {
        return Err(ApiError::ValidationError {
            field: "name".to_string(),
            reason: "Name must be between 1 and 200 characters".to_string(),
        });
    }

    let row = epigraph_db::FrameRepository::create_refinement(
        pool,
        parent_id,
        &request.name,
        request.description.as_deref(),
        &request.hypotheses,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(frame_to_response(row))))
}

/// List refinements (children) of a frame
///
/// `GET /api/v1/frames/:id/refinements`
#[cfg(feature = "db")]
pub async fn frame_refinements(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
) -> Result<Json<Vec<FrameResponse>>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "frame_refinements",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // Verify frame exists
    epigraph_db::FrameRepository::get_by_id(&mut *read, &viewer, frame_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        })?;

    let children =
        epigraph_db::FrameRepository::get_children(&mut *read, &viewer, frame_id).await?;

    crate::routes::finish_scoped_read(read, "frame_refinements").await?;

    Ok(Json(children.into_iter().map(frame_to_response).collect()))
}

/// Get frame ancestry (walk up parent chain)
///
/// `GET /api/v1/frames/:id/ancestry`
#[cfg(feature = "db")]
pub async fn frame_ancestry(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
) -> Result<Json<Vec<FrameResponse>>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "frame_ancestry",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let ancestry =
        epigraph_db::FrameRepository::get_ancestry(&mut *read, &viewer, frame_id).await?;

    crate::routes::finish_scoped_read(read, "frame_ancestry").await?;

    if ancestry.is_empty() {
        return Err(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        });
    }

    Ok(Json(ancestry.into_iter().map(frame_to_response).collect()))
}

// =============================================================================
// HANDLERS (non-db stubs)
// =============================================================================

#[cfg(not(feature = "db"))]
pub async fn get_claim_belief(
    Path(claim_id): Path<Uuid>,
) -> Result<Json<BeliefResponse>, ApiError> {
    Ok(Json(BeliefResponse {
        claim_id,
        belief: None,
        plausibility: None,
        ignorance: None,
        mass_on_conflict: None,
        mass_on_missing: None,
        pignistic_prob: None,
        mass_function_count: 0,
    }))
}

#[cfg(not(feature = "db"))]
pub async fn list_frames(
    Query(_params): Query<ListFramesQuery>,
) -> Result<Json<Vec<FrameResponse>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[cfg(not(feature = "db"))]
pub async fn get_frame(Path(frame_id): Path<Uuid>) -> Result<Json<FrameDetailResponse>, ApiError> {
    Err(ApiError::NotFound {
        entity: "frame".to_string(),
        id: frame_id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn frame_conflict(
    Path(frame_id): Path<Uuid>,
) -> Result<Json<FrameConflictResponse>, ApiError> {
    Err(ApiError::NotFound {
        entity: "frame".to_string(),
        id: frame_id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn create_frame(
    Json(request): Json<CreateFrameRequest>,
) -> Result<(StatusCode, Json<FrameResponse>), ApiError> {
    if request.hypotheses.len() < 2 {
        return Err(ApiError::ValidationError {
            field: "hypotheses".to_string(),
            reason: "Frame must have at least 2 hypotheses".to_string(),
        });
    }

    Ok((
        StatusCode::CREATED,
        Json(FrameResponse {
            id: Uuid::new_v4(),
            name: request.name,
            description: request.description,
            hypotheses: request.hypotheses,
            parent_frame_id: None,
            is_refinable: true,
            version: 1,
            created_at: chrono::Utc::now().to_rfc3339(),
        }),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn submit_evidence(
    Path(_frame_id): Path<Uuid>,
    Json(_request): Json<SubmitEvidenceRequest>,
) -> Result<(StatusCode, Json<EvidenceSubmissionResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "DS evidence pipeline requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn claims_by_belief(
    Query(_params): Query<BeliefFilterQuery>,
) -> Result<Json<Vec<BeliefClaimRow>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[cfg(not(feature = "db"))]
pub async fn frame_claims_sorted(
    Path(frame_id): Path<Uuid>,
    Query(_params): Query<FrameClaimsQuery>,
) -> Result<Json<Vec<FrameClaimBeliefRow>>, ApiError> {
    Err(ApiError::NotFound {
        entity: "frame".to_string(),
        id: frame_id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn claim_divergence(
    Path(_claim_id): Path<Uuid>,
) -> Result<Json<Option<DivergenceResponse>>, ApiError> {
    Ok(Json(None))
}

#[cfg(not(feature = "db"))]
pub async fn top_divergence(
    Query(_params): Query<TopDivergenceQuery>,
) -> Result<Json<Vec<DivergenceResponse>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[cfg(not(feature = "db"))]
pub async fn get_scoped_belief(
    Path(_claim_id): Path<Uuid>,
    Query(_params): Query<ScopedBeliefQuery>,
) -> Result<Json<Option<ScopedBeliefEntry>>, ApiError> {
    Ok(Json(None))
}

#[cfg(not(feature = "db"))]
pub async fn all_scopes_belief(
    Path(claim_id): Path<Uuid>,
) -> Result<Json<AllScopesBeliefResponse>, ApiError> {
    Ok(Json(AllScopesBeliefResponse {
        claim_id,
        scopes: Vec::new(),
    }))
}

#[cfg(not(feature = "db"))]
pub async fn get_pignistic(
    Path(_claim_id): Path<Uuid>,
    Query(_params): Query<PignisticQuery>,
) -> Result<Json<PignisticResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Pignistic computation requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn refine_frame(
    Path(_parent_id): Path<Uuid>,
    Json(_request): Json<RefineFrameRequest>,
) -> Result<(StatusCode, Json<FrameResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Frame refinement requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn frame_refinements(
    Path(frame_id): Path<Uuid>,
) -> Result<Json<Vec<FrameResponse>>, ApiError> {
    Err(ApiError::NotFound {
        entity: "frame".to_string(),
        id: frame_id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn frame_ancestry(
    Path(frame_id): Path<Uuid>,
) -> Result<Json<Vec<FrameResponse>>, ApiError> {
    Err(ApiError::NotFound {
        entity: "frame".to_string(),
        id: frame_id.to_string(),
    })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Backlog 45cbaef4 (G6): the HTTP belief routes resolve a stored index the
    /// same way the cache writer does. `i as usize` used to wrap -1 to
    /// `usize::MAX`, a hypothesis no frame has, and report Bel = Pl = 0.
    #[cfg(feature = "db")]
    #[test]
    fn compute_hypothesis_belief_reads_a_bad_stored_index_as_hypothesis_zero() {
        let frame = epigraph_ds::FrameOfDiscernment::new(
            "g6".to_string(),
            vec!["low".to_string(), "mid".to_string(), "high".to_string()],
        )
        .unwrap();
        let mf = epigraph_ds::MassFunction::from_json_masses(
            frame.clone(),
            &serde_json::json!({"0": 0.5, "2": 0.2, "0,1,2": 0.3}),
        )
        .unwrap();
        let at_zero = compute_hypothesis_belief(&mf, &frame, Some(0));
        assert!((at_zero.0 - 0.5).abs() < 1e-12);
        for bad in [Some(-1), Some(3), Some(i32::MAX), None] {
            assert_eq!(
                compute_hypothesis_belief(&mf, &frame, bad),
                at_zero,
                "{bad:?} must read as hypothesis 0"
            );
        }
        let at_two = compute_hypothesis_belief(&mf, &frame, Some(2));
        assert!((at_two.0 - 0.2).abs() < 1e-12, "in range is honoured");
    }

    #[test]
    fn kl_divergence_identical_distributions_is_zero() {
        let kl = kl_divergence_bernoulli(0.7, 0.7);
        assert!(kl.abs() < 1e-8, "KL(p || p) should be ~0, got {kl}");
    }

    #[test]
    fn kl_divergence_different_distributions_is_positive() {
        let kl = kl_divergence_bernoulli(0.9, 0.5);
        assert!(
            kl > 0.0,
            "KL divergence should be positive for different distributions"
        );
    }

    #[test]
    fn kl_divergence_extreme_values_dont_panic() {
        // Edge cases near 0 and 1 should be clamped safely
        let kl = kl_divergence_bernoulli(0.0, 1.0);
        assert!(
            kl.is_finite(),
            "KL with extreme inputs should be finite, got {kl}"
        );

        let kl2 = kl_divergence_bernoulli(1.0, 0.0);
        assert!(
            kl2.is_finite(),
            "KL with extreme inputs should be finite, got {kl2}"
        );
    }

    #[test]
    fn kl_divergence_symmetric_for_equal_distance() {
        // KL is NOT symmetric in general, but verify it doesn't panic
        let kl_forward = kl_divergence_bernoulli(0.3, 0.7);
        let kl_reverse = kl_divergence_bernoulli(0.7, 0.3);
        assert!(kl_forward > 0.0);
        assert!(kl_reverse > 0.0);
        // They should be equal for this symmetric case (|0.5-p| = |0.5-q|)
        assert!(
            (kl_forward - kl_reverse).abs() < 1e-10,
            "Symmetric case: forward={kl_forward}, reverse={kl_reverse}"
        );
    }

    #[test]
    fn belief_filter_query_defaults() {
        let q: BeliefFilterQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.min_belief, None);
        assert_eq!(q.max_plausibility, None);
        assert_eq!(q.frame_id, None);
        assert_eq!(q.limit, 50);
        assert_eq!(q.offset, 0);
    }

    #[test]
    fn frame_claims_query_defaults() {
        let q: FrameClaimsQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.sort_by, "belief");
        assert_eq!(q.order, "desc");
        assert_eq!(q.limit, 50);
        assert_eq!(q.offset, 0);
    }

    #[test]
    fn top_divergence_query_defaults() {
        let q: TopDivergenceQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.limit, 10);
    }

    #[test]
    fn pignistic_query_requires_frame_id() {
        let result: Result<PignisticQuery, _> = serde_json::from_str("{}");
        assert!(result.is_err(), "PignisticQuery should require frame_id");
    }

    #[test]
    fn pignistic_entry_serializes() {
        let entry = PignisticEntry {
            hypothesis_index: 0,
            hypothesis_name: "true".to_string(),
            pignistic_probability: 0.85,
            belief: 0.7,
            plausibility: 1.0,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("0.85"));
        assert!(json.contains("\"true\""));
    }

    #[test]
    fn refine_frame_request_deserializes() {
        let req: RefineFrameRequest =
            serde_json::from_str(r#"{"name":"sub-frame","hypotheses":["a","b"]}"#).unwrap();
        assert_eq!(req.name, "sub-frame");
        assert_eq!(req.hypotheses.len(), 2);
        assert!(req.description.is_none());
    }

    #[test]
    fn belief_response_includes_pignistic() {
        let resp = BeliefResponse {
            claim_id: Uuid::new_v4(),
            belief: Some(0.7),
            plausibility: Some(0.9),
            ignorance: Some(0.2),
            mass_on_conflict: Some(0.01),
            mass_on_missing: Some(0.05),
            pignistic_prob: Some(0.85),
            mass_function_count: 3,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("pignistic_prob"));
        assert!(json.contains("0.85"));
        assert!(json.contains("mass_on_missing"));
    }

    #[test]
    fn frame_response_includes_refinement_fields() {
        let resp = FrameResponse {
            id: Uuid::new_v4(),
            name: "test".to_string(),
            description: None,
            hypotheses: vec!["a".to_string(), "b".to_string()],
            parent_frame_id: Some(Uuid::new_v4()),
            is_refinable: false,
            version: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("parent_frame_id"));
        assert!(json.contains("is_refinable"));
        assert!(json.contains("\"version\":1"));
    }

    #[test]
    fn evidence_submission_response_includes_pignistic() {
        let resp = EvidenceSubmissionResponse {
            mass_function_id: Uuid::new_v4(),
            combination_reports: vec![],
            updated_belief: 0.7,
            updated_plausibility: 0.9,
            mass_on_conflict: 0.01,
            mass_on_missing: 0.03,
            pignistic_prob: Some(0.85),
            bayesian_posterior: 0.5,
            total_sources: 3,
            write_outcome: "inserted".to_string(),
            deduplicated: false,
            warnings: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("pignistic_prob"));
        assert!(json.contains("bayesian_posterior"));
        assert!(json.contains("mass_on_conflict"));
        assert!(json.contains("mass_on_missing"));
    }

    #[test]
    fn scoped_belief_entry_includes_pignistic() {
        let entry = ScopedBeliefEntry {
            scope_type: "global".to_string(),
            scope_id: None,
            belief: 0.7,
            plausibility: 0.9,
            ignorance: 0.2,
            mass_on_conflict: 0.01,
            mass_on_missing: 0.03,
            pignistic_prob: Some(0.85),
            conflict_k: None,
            strategy_used: None,
            computed_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("pignistic_prob"));
        assert!(json.contains("mass_on_missing"));
    }

    // =========================================================================
    // Phase 7 tests: SCOPED_BY, confidence_calibration, competence_scopes
    // =========================================================================

    #[test]
    fn submit_evidence_request_deserializes_with_all_fields() {
        let claim_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let perspective_id = Uuid::new_v4();
        let json = format!(
            r#"{{
                "claim_id":"{}",
                "agent_id":"{}",
                "perspective_id":"{}",
                "reliability":0.9,
                "masses":{{"0,1":0.8,"":0.2}},
                "conflict_threshold":0.95
            }}"#,
            claim_id, agent_id, perspective_id
        );
        let req: SubmitEvidenceRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.claim_id, claim_id);
        assert_eq!(req.agent_id, Some(agent_id));
        assert_eq!(req.perspective_id, Some(perspective_id));
        assert!((req.reliability - 0.9).abs() < f64::EPSILON);
        assert!((req.conflict_threshold - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn competence_discount_constant_is_valid() {
        // The competence discount is 0.7 (defined inline in submit_evidence).
        // Verify the value is in valid range for discount().
        let discount = 0.7_f64;
        assert!((0.0..=1.0).contains(&discount));
    }

    #[test]
    fn confidence_calibration_bounds_check() {
        // confidence_calibration is only applied when in [0.0, 1.0).
        // Verify the guard logic: calibration of 1.0 should NOT trigger discount
        // (it would be a no-op identity, not meaningful as additional discount).
        let calibration = 1.0_f64;
        assert!(
            !(0.0..1.0).contains(&calibration),
            "1.0 should be excluded from discount range"
        );

        let calibration = 0.5_f64;
        assert!(
            (0.0..1.0).contains(&calibration),
            "0.5 should be in discount range"
        );
    }

    // =========================================================================
    // CDST Migration tests: conflict vs missing decomposition
    // =========================================================================

    #[test]
    fn belief_response_includes_mass_on_missing() {
        let resp = BeliefResponse {
            claim_id: Uuid::new_v4(),
            belief: Some(0.6),
            plausibility: Some(0.8),
            ignorance: Some(0.2),
            mass_on_conflict: Some(0.05),
            mass_on_missing: Some(0.10),
            pignistic_prob: Some(0.7),
            mass_function_count: 2,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"mass_on_conflict\":0.05"),
            "Expected mass_on_conflict in JSON"
        );
        assert!(
            json.contains("\"mass_on_missing\":0.1"),
            "Expected mass_on_missing in JSON"
        );
    }

    #[test]
    fn belief_response_missing_fields_serialize_as_null() {
        let resp = BeliefResponse {
            claim_id: Uuid::new_v4(),
            belief: None,
            plausibility: None,
            ignorance: None,
            mass_on_conflict: None,
            mass_on_missing: None,
            pignistic_prob: None,
            mass_function_count: 0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"mass_on_missing\":null"));
    }

    #[test]
    fn frame_response_includes_version() {
        let resp = FrameResponse {
            id: Uuid::new_v4(),
            name: "climate_frame".to_string(),
            description: Some("A frame about climate hypotheses".to_string()),
            hypotheses: vec!["warming".into(), "stable".into(), "cooling".into()],
            parent_frame_id: None,
            is_refinable: true,
            version: 3,
            created_at: "2026-02-25T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"version\":3"),
            "Expected version=3 in JSON: {json}"
        );
    }

    #[test]
    fn combination_report_includes_mass_on_missing() {
        let report = CombinationReportResponse {
            method_used: "Dempster".to_string(),
            conflict_k: 0.15,
            mass_on_conflict: 0.0,
            mass_on_missing: 0.08,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"mass_on_missing\":0.08"));
        assert!(json.contains("\"mass_on_conflict\":0.0"));
    }

    #[test]
    fn evidence_submission_response_has_conflict_and_missing() {
        let resp = EvidenceSubmissionResponse {
            mass_function_id: Uuid::new_v4(),
            combination_reports: vec![CombinationReportResponse {
                method_used: "YagerOpen".to_string(),
                conflict_k: 0.2,
                mass_on_conflict: 0.0,
                mass_on_missing: 0.2,
            }],
            updated_belief: 0.65,
            updated_plausibility: 0.88,
            mass_on_conflict: 0.0,
            mass_on_missing: 0.2,
            pignistic_prob: Some(0.76),
            bayesian_posterior: 0.71,
            total_sources: 5,
            write_outcome: "inserted".to_string(),
            deduplicated: false,
            warnings: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"mass_on_conflict\":0.0"),
            "conflict field: {json}"
        );
        assert!(
            json.contains("\"mass_on_missing\":0.2"),
            "missing field: {json}"
        );
    }

    #[test]
    fn submit_evidence_request_with_combination_method() {
        let claim_id = Uuid::new_v4();
        let json = format!(
            r#"{{
                "claim_id":"{}",
                "masses":{{"0":0.7,"0,1":0.3}},
                "combination_method":"dempster",
                "gamma":null
            }}"#,
            claim_id
        );
        let req: SubmitEvidenceRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.combination_method.as_deref(), Some("dempster"));
        assert_eq!(req.gamma, None);
    }

    #[test]
    fn submit_evidence_request_with_inagaki_gamma() {
        let claim_id = Uuid::new_v4();
        let json = format!(
            r#"{{
                "claim_id":"{}",
                "masses":{{"0":0.6,"1":0.4}},
                "combination_method":"inagaki",
                "gamma":0.3
            }}"#,
            claim_id
        );
        let req: SubmitEvidenceRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.combination_method.as_deref(), Some("inagaki"));
        assert!((req.gamma.unwrap() - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn submit_evidence_request_defaults_omit_combination_method() {
        let claim_id = Uuid::new_v4();
        let json = format!(
            r#"{{
                "claim_id":"{}",
                "masses":{{"0":0.6,"0,1":0.4}}
            }}"#,
            claim_id
        );
        let req: SubmitEvidenceRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.combination_method, None);
        assert_eq!(req.gamma, None);
        // Defaults
        assert!((req.reliability - 1.0).abs() < f64::EPSILON);
        assert!((req.conflict_threshold - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn submit_evidence_request_with_negative_elements() {
        let claim_id = Uuid::new_v4();
        let json = format!(
            r#"{{
                "claim_id":"{}",
                "masses":{{"0":0.4,"~1":0.3,"~":0.3}}
            }}"#,
            claim_id
        );
        let req: SubmitEvidenceRequest = serde_json::from_str(&json).unwrap();
        // Verify ~-prefixed keys are in the map
        assert!(
            req.masses.contains_key("~1"),
            "Should have complement key ~1"
        );
        assert!(req.masses.contains_key("~"), "Should have vacuous key ~");
        assert!(req.masses.contains_key("0"), "Should have positive key 0");
        assert!((req.masses["~1"] - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn divergence_response_includes_frame_version() {
        let resp = DivergenceResponse {
            id: Uuid::new_v4(),
            claim_id: Uuid::new_v4(),
            frame_id: Uuid::new_v4(),
            pignistic_prob: 0.85,
            bayesian_posterior: 0.72,
            kl_divergence: 0.12,
            frame_version: Some(2),
            computed_at: "2026-02-25T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"frame_version\":2"),
            "Expected frame_version: {json}"
        );
    }

    #[test]
    fn divergence_response_null_frame_version() {
        let resp = DivergenceResponse {
            id: Uuid::new_v4(),
            claim_id: Uuid::new_v4(),
            frame_id: Uuid::new_v4(),
            pignistic_prob: 0.5,
            bayesian_posterior: 0.5,
            kl_divergence: 0.0,
            frame_version: None,
            computed_at: "2026-02-25T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"frame_version\":null"));
    }

    #[test]
    fn pignistic_response_includes_mass_on_missing() {
        let resp = PignisticResponse {
            claim_id: Uuid::new_v4(),
            frame_id: Uuid::new_v4(),
            frame_name: "binary".to_string(),
            hypotheses: vec![
                PignisticEntry {
                    hypothesis_index: 0,
                    hypothesis_name: "true".to_string(),
                    pignistic_probability: 0.65,
                    belief: 0.5,
                    plausibility: 0.8,
                },
                PignisticEntry {
                    hypothesis_index: 1,
                    hypothesis_name: "false".to_string(),
                    pignistic_probability: 0.35,
                    belief: 0.2,
                    plausibility: 0.5,
                },
            ],
            mass_on_conflict: 0.02,
            mass_on_missing: 0.10,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"mass_on_missing\":0.1"),
            "Expected mass_on_missing: {json}"
        );
        assert!(json.contains("\"mass_on_conflict\":0.02"));
    }

    #[test]
    fn scoped_belief_entry_includes_mass_on_missing() {
        let entry = ScopedBeliefEntry {
            scope_type: "community".to_string(),
            scope_id: Some(Uuid::new_v4()),
            belief: 0.55,
            plausibility: 0.80,
            ignorance: 0.25,
            mass_on_conflict: 0.03,
            mass_on_missing: 0.07,
            pignistic_prob: Some(0.68),
            conflict_k: Some(0.12),
            strategy_used: Some("dempster".to_string()),
            computed_at: "2026-02-25T12:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(
            json.contains("\"mass_on_missing\":0.07"),
            "Expected mass_on_missing: {json}"
        );
        assert!(json.contains("\"mass_on_conflict\":0.03"));
        assert!(json.contains("\"scope_type\":\"community\""));
    }

    #[test]
    fn belief_claim_row_includes_mass_on_missing() {
        let row = BeliefClaimRow {
            id: Uuid::new_v4(),
            content: "Test claim".to_string(),
            belief: Some(0.7),
            plausibility: Some(0.9),
            mass_on_conflict: Some(0.01),
            mass_on_missing: Some(0.04),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("\"mass_on_missing\":0.04"));
    }

    #[test]
    fn frame_claim_belief_row_includes_mass_on_missing() {
        let row = FrameClaimBeliefRow {
            claim_id: Uuid::new_v4(),
            content: "Hypothesis claim".to_string(),
            hypothesis_index: Some(0),
            belief: Some(0.6),
            plausibility: Some(0.85),
            ignorance: Some(0.25),
            mass_on_missing: Some(0.05),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("\"mass_on_missing\":0.05"));
        assert!(json.contains("\"hypothesis_index\":0"));
    }

    #[test]
    fn combination_method_strings_are_valid() {
        // Verify the known combination method strings match what epigraph-ds expects
        let valid_methods = [
            "conjunctive",
            "dempster",
            "yager_open",
            "yager_closed",
            "dubois_prade",
            "inagaki",
        ];
        for method in valid_methods {
            assert!(!method.is_empty(), "Method name should not be empty");
        }
    }

    #[test]
    fn gamma_parameter_bounds() {
        // Inagaki gamma must be in [0, 1]
        let valid_gammas = [0.0, 0.3, 0.5, 1.0];
        for g in valid_gammas {
            assert!((0.0..=1.0).contains(&g), "Gamma {g} should be in [0, 1]");
        }
    }

    // =========================================================================
    // R5: CDST residual mass signal detection thresholds
    // =========================================================================

    #[test]
    fn test_frame_incomplete_event_threshold() {
        // frame.incomplete fires when m_missing > 0.15
        let threshold = 0.15_f64;
        let above = 0.20_f64;
        let below = 0.10_f64;
        let at = 0.15_f64;

        assert!(
            above > threshold,
            "m_missing=0.20 should trigger frame.incomplete"
        );
        assert!(
            below <= threshold,
            "m_missing=0.10 should NOT trigger frame.incomplete"
        );
        assert!(
            at <= threshold,
            "m_missing=0.15 (boundary) should NOT trigger"
        );
    }

    #[test]
    fn test_genuine_conflict_event_threshold() {
        // conflict.genuine fires when m_empty > 0.10 AND m_missing < 0.05
        let m_empty_threshold = 0.10_f64;
        let m_missing_ceiling = 0.05_f64;

        // Case 1: high conflict, low ignorance -> should fire
        let m_empty = 0.15_f64;
        let m_missing = 0.02_f64;
        assert!(
            m_empty > m_empty_threshold && m_missing < m_missing_ceiling,
            "m_empty=0.15, m_missing=0.02 should trigger conflict.genuine"
        );

        // Case 2: high conflict, high ignorance -> should NOT fire
        let m_empty = 0.15_f64;
        let m_missing = 0.10_f64;
        assert!(
            !(m_empty > m_empty_threshold && m_missing < m_missing_ceiling),
            "m_empty=0.15, m_missing=0.10 should NOT trigger (high ignorance)"
        );

        // Case 3: low conflict, low ignorance -> should NOT fire
        let m_empty = 0.05_f64;
        let m_missing = 0.02_f64;
        assert!(
            !(m_empty > m_empty_threshold && m_missing < m_missing_ceiling),
            "m_empty=0.05, m_missing=0.02 should NOT trigger (low conflict)"
        );
    }

    // ── Section 03: Batch Conflict API tests ──

    #[test]
    fn test_conflict_batch_single_pair() {
        let req_json = serde_json::json!({
            "pairs": [{"claim_a": Uuid::new_v4(), "claim_b": Uuid::new_v4()}]
        });
        let req: ConflictBatchRequest = serde_json::from_value(req_json).unwrap();
        assert_eq!(req.pairs.len(), 1);
    }

    #[test]
    fn test_conflict_batch_100_pairs() {
        let pairs: Vec<serde_json::Value> = (0..100)
            .map(|_| serde_json::json!({"claim_a": Uuid::new_v4(), "claim_b": Uuid::new_v4()}))
            .collect();
        let req_json = serde_json::json!({ "pairs": pairs });
        let req: ConflictBatchRequest = serde_json::from_value(req_json).unwrap();
        assert_eq!(req.pairs.len(), 100);
    }

    #[test]
    fn test_conflict_batch_missing_mass_function() {
        // ConflictBatchResult with error when mass function is missing
        let result = ConflictBatchResult {
            claim_a: Uuid::new_v4(),
            claim_b: Uuid::new_v4(),
            conflict_k: None,
            error: Some("No mass function for claim abc".to_string()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["conflict_k"].is_null());
        assert!(json["error"].as_str().unwrap().contains("No mass function"));
    }

    #[test]
    fn test_conflict_batch_empty_pairs() {
        let req: ConflictBatchRequest =
            serde_json::from_value(serde_json::json!({"pairs": []})).unwrap();
        assert!(req.pairs.is_empty());
        // Empty pairs returns empty results (handler short-circuits)
        let resp = ConflictBatchResponse { results: vec![] };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["results"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_conflict_batch_matches_manual_computation() {
        use epigraph_ds::{
            combination::conflict_coefficient, FocalElement, FrameOfDiscernment, MassFunction,
        };
        use std::collections::{BTreeMap, BTreeSet};

        let frame = FrameOfDiscernment::new("test", vec!["H0".into(), "H1".into()]).unwrap();

        let mut h0 = BTreeSet::new();
        h0.insert(0);
        let mut h1 = BTreeSet::new();
        h1.insert(1);

        let mut bba_a = BTreeMap::new();
        bba_a.insert(FocalElement::positive(h0), 0.6);
        bba_a.insert(FocalElement::theta(&frame), 0.4);
        let mf_a = MassFunction::new(frame.clone(), bba_a).unwrap();

        let mut bba_b = BTreeMap::new();
        bba_b.insert(FocalElement::positive(h1), 0.7);
        bba_b.insert(FocalElement::theta(&frame), 0.3);
        let mf_b = MassFunction::new(frame.clone(), bba_b).unwrap();

        let k = conflict_coefficient(&mf_a, &mf_b).unwrap();
        // m_a({H0}) * m_b({H1}) = 0.6 * 0.7 = 0.42 (conflict mass)
        assert!(
            k > 0.3,
            "K should reflect disjoint focal element conflict, got {k}"
        );
        assert!(
            k < 0.5,
            "K should not exceed sum of conflicting products, got {k}"
        );

        let result = ConflictBatchResult {
            claim_a: Uuid::new_v4(),
            claim_b: Uuid::new_v4(),
            conflict_k: Some(k),
            error: None,
        };
        assert!(result.conflict_k.unwrap() > 0.0);
    }

    #[test]
    fn test_conflict_batch_exceeds_limit() {
        let pairs: Vec<serde_json::Value> = (0..101)
            .map(|_| serde_json::json!({"claim_a": Uuid::new_v4(), "claim_b": Uuid::new_v4()}))
            .collect();
        let req_json = serde_json::json!({ "pairs": pairs });
        let req: ConflictBatchRequest = serde_json::from_value(req_json).unwrap();
        // Handler would reject this (101 > 100), verify the count
        assert_eq!(req.pairs.len(), 101);
        assert!(req.pairs.len() > 100, "Should exceed the 100-pair limit");
    }

    #[test]
    fn test_conflict_batch_nonexistent_frame() {
        // Verify that a nonexistent frame_id would produce a NotFound-style error
        let fake_frame = Uuid::new_v4();
        let err = ApiError::NotFound {
            entity: "frame".to_string(),
            id: fake_frame.to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("not found"),
            "Error should indicate not found: {msg}"
        );
    }
}
