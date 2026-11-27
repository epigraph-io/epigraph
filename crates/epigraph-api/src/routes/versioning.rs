//! Claim versioning and supersession endpoints
//!
//! POST /api/v1/claims/:id/supersede - Create a new claim that supersedes an existing one
//! GET  /api/v1/claims/:id/history   - Get the full version history for a claim
//!
//! Supersession is the mechanism by which claims evolve over time. Rather than
//! mutating a claim in-place (which would break cryptographic integrity), a new
//! claim is created that explicitly supersedes the old one. This preserves the
//! full epistemic history: every version of a belief is recorded and traceable.
//!
//! # Tenancy: one raw-pool site remains
//!
//! `claim_history` reads on a viewer-stamped connection from
//! [`AppState::read_as`]. `supersede_claim` and `mark_duplicate` read their
//! authority target on a stamped connection, run their act on a transaction
//! stamped with the caller's viewer (`AppState::write_as`), and run their
//! administrative cascade on the maintenance connection.
//!
//! The one site left on `state.db_pool` is `mark_duplicate`'s best-effort
//! provenance append (`crates/epigraph-db/tests/no_unscoped_pool.rs` counts
//! it). `supersede_claim`'s detached factor-query spawn, which only logged how
//! many factors referenced the replacement, was deleted (backlog 79e1f75d):
//! the administrative cascade's belief re-derivation is what repairs them.
//!
//! [`AppState::read_as`]: crate::AppState::read_as

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "db")]
use sqlx;
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
use crate::state::AppState;
use epigraph_core::{AgentId, ClaimId, TruthValue};
#[cfg(feature = "db")]
use epigraph_db::ClaimRepository;
use epigraph_events::EpiGraphEvent;

// =============================================================================
// DEDUP TYPES
// =============================================================================

/// Request body for marking a claim as a duplicate.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct DedupRequest {
    pub canonical_id: Uuid,
    pub reason: Option<String>,
}

/// Response for a successful dedup operation.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DedupResponse {
    pub duplicate_id: Uuid,
    pub canonical_id: Uuid,
    pub mode: &'static str,
    /// The administrative cascade that follows the dedup (migration 117):
    /// `status` is `applied`, `deferred` (no maintenance connection; the dedup
    /// itself committed) or `failed`, with its `security_events` row id.
    #[schema(value_type = Object)]
    pub cascade: epigraph_engine::admin_cascade::CascadeStatus,
    /// What the downstream belief cascade repaired (backlog 20e9ed83).
    /// Additive and best-effort: an empty report means there was nothing
    /// downstream (or the cascade was deferred), never that the dedup failed.
    #[schema(value_type = Object)]
    pub belief_cascade: epigraph_engine::retraction_cascade::CascadeReport,
}

/// Response for a successful un-mark (`POST /api/v1/claims/{id}/undedup`).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UndedupResponse {
    pub duplicate_id: Uuid,
    /// The claim it had been marked a duplicate of.
    pub canonical_id: Uuid,
    /// The claim it was restored against: `canonical_id`, or the claim that
    /// replaced it since (supersession or consolidation, followed to the
    /// current one).
    pub current_canonical_id: Uuid,
    pub mode: &'static str,
    /// Whether the claim got its embedding back (best-effort; a backfill
    /// restores it otherwise).
    pub embedded: bool,
    /// The administrative reversal (cause `undedup`), counts only.
    #[schema(value_type = Object)]
    pub cascade: epigraph_engine::admin_cascade::CascadeStatus,
    /// The belief re-derivation that followed it.
    #[schema(value_type = Object)]
    pub belief_cascade: epigraph_engine::retraction_cascade::CascadeReport,
}

// =============================================================================
// SECURITY CONSTANTS
// =============================================================================

/// Maximum length of supersession reason in bytes.
/// Prevents memory exhaustion from excessively large explanations.
const MAX_REASON_LENGTH: usize = 32_768;

/// Maximum length of new claim content in bytes.
/// Matches the MAX_CLAIM_CONTENT_LENGTH in submit.rs (64KB).
const MAX_CONTENT_LENGTH: usize = 65_536;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// Request body for superseding a claim
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SupersedeRequest {
    /// New claim content
    pub content: String,
    /// New truth value [0.0, 1.0]
    pub truth_value: f64,
    /// Why the claim is being superseded
    pub reason: String,
}

/// Response for a successful supersession
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SupersessionResponse {
    /// The ID of the newly created claim
    pub new_claim_id: Uuid,
    /// The ID of the claim that was superseded
    pub superseded_claim_id: Uuid,
    /// The truth value of the new claim
    pub new_truth_value: f64,
    /// Version number in the supersession chain
    pub version: u32,
    /// When the new claim was created
    pub created_at: DateTime<Utc>,
    /// The administrative cascade that follows the supersession (migration
    /// 117): `status` is `applied`, `deferred` (no maintenance connection; the
    /// supersession itself committed) or `failed`, with its `security_events`
    /// row id. `#[serde(default)]` so older payloads still deserialize.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub cascade: epigraph_engine::admin_cascade::CascadeStatus,
    /// What the downstream belief cascade repaired (backlog 20e9ed83).
    /// Additive and best-effort: `#[serde(default)]` so payloads written
    /// before this field existed still deserialize.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub belief_cascade: epigraph_engine::retraction_cascade::CascadeReport,
    /// Whether the replacement got its embedding (best-effort, post-commit; a
    /// backfill covers a `false`). `#[serde(default)]` as for the two above.
    #[serde(default)]
    pub embedded: bool,
}

/// A single version entry in a claim's history
#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimVersion {
    /// The claim ID for this version
    pub claim_id: Uuid,
    /// The claim content at this version
    pub content: String,
    /// The truth value at this version
    pub truth_value: f64,
    /// The version number (1-indexed, oldest first)
    pub version: u32,
    /// Whether this is the current (latest) version
    pub is_current: bool,
    /// When this version was created
    pub created_at: DateTime<Utc>,
    /// The ID of the claim that superseded this one (forward link)
    pub superseded_by: Option<Uuid>,
}

/// Response for a version history query
#[derive(Debug, Serialize, Deserialize)]
pub struct VersionHistoryResponse {
    /// The claim ID that was queried
    pub claim_id: Uuid,
    /// All versions in chronological order (oldest first)
    pub versions: Vec<ClaimVersion>,
    /// Total number of versions in the chain
    pub total_versions: usize,
    /// The version number of the current (latest) version
    pub current_version: u32,
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Supersede an existing claim with a new version
///
/// POST /api/v1/claims/:id/supersede
///
/// Creates a new Claim that supersedes the given claim. The old claim
/// is marked as non-current (`is_current = false`) and the new claim
/// is linked via `supersedes = Some(old_id)`.
///
/// # Validation
///
/// - truth_value must be in [0.0, 1.0]
/// - content must be non-empty
/// - reason must be non-empty
/// - The target claim must exist
/// - The target claim must be current (cannot supersede an already-superseded claim)
///
/// # Errors
///
/// - 400 Bad Request: Validation failures
/// - 403 Forbidden: the token lacks `claims:write`; or `not_owner` (rule
///   `not_claim_writer`): the caller can read the claim but does not write its
///   owning group (authorship alone is not enough) and lacks `claims:admin`
/// - 404 Not Found: Claim does not exist, or the caller cannot read it (the two
///   are indistinguishable)
/// - 409 Conflict: the claim is already superseded (operator ruling R-55)
/// - 201 Created: New claim created successfully
#[cfg(feature = "db")]
#[utoipa::path(
    post,
    path = "/api/v1/claims/{id}/supersede",
    params(("id" = uuid::Uuid, Path, description = "UUID of the claim to supersede")),
    request_body = SupersedeRequest,
    responses(
        (status = 201, body = SupersessionResponse),
        (status = 400),
        (status = 401),
        (status = 403),
        (status = 404),
        (status = 409),
    ),
    security(("ed25519_signature" = [])),
    tag = "claims"
)]
pub async fn supersede_claim(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(claim_id): Path<Uuid>,
    Json(request): Json<SupersedeRequest>,
) -> Result<(StatusCode, Json<SupersessionResponse>), ApiError> {
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "supersede requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])?;

    // 1. Validate content is not empty
    if request.content.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "content".to_string(),
            reason: "Content cannot be empty".to_string(),
        });
    }

    // 2. Validate content length (DoS prevention)
    if request.content.len() > MAX_CONTENT_LENGTH {
        return Err(ApiError::ValidationError {
            field: "content".to_string(),
            reason: format!(
                "Content too long: {} bytes, maximum is {} bytes",
                request.content.len(),
                MAX_CONTENT_LENGTH
            ),
        });
    }

    // 3. Validate reason is not empty
    if request.reason.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "reason".to_string(),
            reason: "Reason cannot be empty".to_string(),
        });
    }

    // 4. Validate reason length (DoS prevention)
    if request.reason.len() > MAX_REASON_LENGTH {
        return Err(ApiError::ValidationError {
            field: "reason".to_string(),
            reason: format!(
                "Reason too long: {} bytes, maximum is {} bytes",
                request.reason.len(),
                MAX_REASON_LENGTH
            ),
        });
    }

    // 5. Validate truth value bounds
    if !request.truth_value.is_finite() || !(0.0..=1.0).contains(&request.truth_value) {
        return Err(ApiError::ValidationError {
            field: "truth_value".to_string(),
            reason: "Truth value must be between 0.0 and 1.0".to_string(),
        });
    }

    let truth_value =
        TruthValue::new(request.truth_value).map_err(|_| ApiError::ValidationError {
            field: "truth_value".to_string(),
            reason: "Truth value must be between 0.0 and 1.0".to_string(),
        })?;

    // 6. The claim's author and owning group, which the authority gate below
    //    decides on, read through the CALLER's viewer on a viewer-stamped
    //    connection (`ClaimRepository::write_target_of`).
    //
    //    This was `SELECT agent_id FROM claims WHERE id = $1` on the raw pool,
    //    unfiltered while the handler held a Viewer (F-write-authz-reads-unfiltered,
    //    backlog 30c29c52). A `claims:admin` principal could therefore supersede
    //    a claim it cannot READ, because the gate asked only whose it was. A claim
    //    the caller cannot see is 404, exactly like one that does not exist, so
    //    the refusal in 6b below is only ever about a claim the caller can see.
    //
    //    READ authority, `{VISIBILITY:c}`, and deliberately not the write gate
    //    `{WRITABLE:c}`: the read decides 404 (can the caller see it at all),
    //    6b decides who may ASK, and the DATABASE decides the write itself,
    //    because it runs on a transaction stamped with the caller's viewer and
    //    `claims_tenancy`'s `WITH CHECK` refuses a row whose owner group the
    //    caller cannot write (answered 403, nothing written).
    let (agent_uuid, owner_group): (Uuid, Uuid) = {
        let mut read = state.read_as(&viewer).await.map_err(|e| {
            tracing::error!(
                target: "tenancy.scoped_read",
                error = %e,
                handler = "supersede_claim",
                "could not acquire a viewer-stamped connection"
            );
            ApiError::InternalError {
                message: "Failed to acquire a scoped connection".to_string(),
            }
        })?;
        ClaimRepository::write_target_of(&mut *read, &viewer, claim_id)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("DB error: {e}"),
            })?
            .ok_or_else(|| ApiError::NotFound {
                entity: "Claim".to_string(),
                id: claim_id.to_string(),
            })?
    };

    // 6b. The ACT's authority (batch OA1, operator decision D1): write
    //     authority over the claim's owning group (the same test as
    //     `claims_tenancy`'s WITH CHECK, so the refusal is named instead of a
    //     generic row-security 403), or a `claims:admin` holder.
    //     `claims:write` above is the scope; this is the per-claim rule, shared
    //     with MCP (`epigraph_auth::claim_act`). The cascade that follows is
    //     administrative and never runs with the caller's authority.
    let arm = crate::middleware::scopes::require_claim_act_authority(
        &auth,
        viewer.principal(),
        viewer.writable_groups(),
        epigraph_auth::claim_act::ClaimActTarget {
            author: agent_uuid,
            owner_group,
        },
        claim_id,
        "supersede",
    )?;
    tracing::info!(
        handler = "supersede_claim",
        claim = %claim_id,
        arm = arm.as_str(),
        "claim act admitted"
    );

    // 7. Perform supersession on ONE transaction stamped with the CALLER's
    //    viewer.
    //
    //    This was `ClaimRepository::supersede(&state.db_pool, ..)`: atomic, but
    //    unstamped, so on a schema without the orphan `*_privacy` policies
    //    (config A, what production becomes at R3) `claims_tenancy` refused it
    //    for EVERY caller. MEASURED (batch H-a review): owner / own-public 500
    //    "new row violates row-level security policy", owner / own-group 404,
    //    because the unstamped session could not even see the owner's own row.
    //    Stamped, the owner's supersede commits, and a caller whose writable set
    //    lacks the claim's owner group gets 403 with nothing written.
    let old_claim_id = ClaimId::from_uuid(claim_id);
    // The ACTING agent, recorded as the replacement's `AUTHORED` edge (backlog
    // 73085534, ruling R-23): the replacement keeps the retired claim's author,
    // so this edge is the only record in the graph of who restated it.
    // `ViewerExtractor` already refuses an agentless token, so a principal-less
    // viewer does not reach here; it is refused rather than recorded as nobody.
    let Some(acting_agent) = viewer.principal() else {
        return Err(ApiError::Unauthorized {
            reason: "supersede requires an authenticated principal".into(),
        });
    };
    let mut tx = state.write_as(&viewer, "supersede_claim").await?;
    //
    //    Migration 117: this is the supersession's ACT only (retire, insert the
    //    replacement and the `supersedes` edge). Re-pointing the old claim's
    //    other edges belongs to whoever asserted them and runs below as the
    //    administrative cascade.
    //    Its two edges are attested at INSERT with the API's own key (backlog
    //    dae795f8), `None` when this API has none configured.
    let (new_uuid, _old_uuid) = ClaimRepository::supersede_act_conn(
        &mut tx,
        state.edge_signing_key(),
        old_claim_id,
        &request.content,
        truth_value,
        &request.reason,
        epigraph_db::SupersedeActor::new(acting_agent, epigraph_db::SupersedeTool::SupersedeClaim),
    )
    .await
    .map_err(|e| supersede_refusal(claim_id, e))?;

    let now = Utc::now();
    let new_claim_id = ClaimId::from_uuid(new_uuid);

    // 8. Record version history for the new claim, on the same transaction and
    //    under a SAVEPOINT. Supplementary: a failure is logged and rolled back
    //    to the savepoint, and the supersession still commits. The savepoint is
    //    what makes "supplementary" true inside a transaction; unsavepointed, a
    //    refused INSERT would abort the transaction and PostgreSQL would answer
    //    the COMMIT with a silent ROLLBACK. It used to run on the raw pool after
    //    the commit, where `claim_versions`' row security refused it on config A
    //    and the 201 went out with no version row.
    #[cfg(feature = "db")]
    {
        use epigraph_db::repos::claim_version::ClaimVersionRow;
        use epigraph_db::ClaimVersionRepository;
        use sqlx::Acquire as _;

        // BOTH statements under the savepoint, the read included: a failed
        // statement aborts the enclosing transaction whether it read or wrote.
        let mut sp = tx.begin().await.map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to open a savepoint: {e}"),
        })?;
        let recorded = match ClaimVersionRepository::latest_version_number(
            &mut *sp, &viewer, claim_id,
        )
        .await
        {
            Ok(latest) => {
                // The version was created by the agent that performed the
                // act, not by the author the replacement inherits (backlog
                // 1a54283d, ruling R-85).
                let version_row = ClaimVersionRow {
                    id: uuid::Uuid::new_v4(),
                    claim_id: new_uuid,
                    version_number: latest + 1,
                    content: request.content.clone(),
                    truth_value: request.truth_value,
                    created_by: Some(acting_agent),
                    created_at: now,
                };
                ClaimVersionRepository::create(&mut *sp, &version_row).await
            }
            Err(e) => Err(e),
        };
        match recorded {
            Ok(_) => sp.commit().await.map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to release the savepoint: {e}"),
            })?,
            Err(e) => {
                tracing::warn!("Failed to record claim version: {e}");
                sp.rollback().await.map_err(|e| ApiError::DatabaseError {
                    message: format!("Failed to roll back the savepoint: {e}"),
                })?;
            }
        }
    }

    // The administrative cascade's trigger, and its administrative session,
    // acquired BEFORE the act commits. With none (not configured, or not
    // usable) the deferral is recorded in the act's own transaction under the
    // principal it is stamped with, so the supersession and its audit row
    // commit together.
    #[cfg(feature = "db")]
    let trigger = epigraph_engine::admin_cascade::CascadeTrigger::new(
        epigraph_engine::admin_cascade::CascadeCause::Supersede,
        viewer.principal(),
        Some(oauth_principal(&auth)),
        claim_id,
        Some(new_uuid),
    );
    #[cfg(feature = "db")]
    let (mut session, deferred) = supersede_session_or_deferral(&state, &mut tx, &trigger).await?;

    // 8b. The staleness event a supersession emits (supersede SPEC K12d,
    // SF-26), with the same payload keys `POST /api/v1/edges` used for a
    // `supersedes` edge before K12a made that relationship the act's alone.
    // Attributed to the acting agent. Persisted on the act's OWN transaction
    // (backlog 8fcc36a0: it used to be pushed after the commit to an
    // in-process store nothing persisted), so it commits or rolls back with
    // the supersession; SAVEPOINT-wrapped inside `publish_or_log_conn`, so a
    // refused event cannot abort the act.
    let _ = epigraph_db::EventRepository::publish_or_log_conn(
        &mut tx,
        "claim.superseded",
        Some(acting_agent),
        &serde_json::json!({
            "superseded_claim_id": claim_id,
            "superseded_by_claim_id": new_uuid,
        }),
    )
    .await;

    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit the supersession: {e}"),
    })?;

    // 9. Publish ClaimSubmitted event for the new claim (fire-and-forget)
    let _ = state
        .event_bus
        .publish(EpiGraphEvent::ClaimSubmitted {
            claim_id: new_claim_id,
            agent_id: AgentId::from_uuid(agent_uuid),
            initial_truth: truth_value,
        })
        .await;

    // 9a. The `claim.superseded` event is on the act's transaction (8b).

    // 9a'. Embed the replacement: a current claim with new text and no vector
    // (the act copies none on purpose). Post-commit and best-effort, on the
    // caller's stamp, which just wrote the row (CLAUDE.md "Embedding policy";
    // backlog 7628ab2c). Without it the claim that replaced a recallable one
    // was invisible to dense recall until a backfill ran.
    let embedded = state
        .embed_claim_as(&viewer, new_uuid, &request.content, "supersede_claim.embed")
        .await;

    // 9b. The administrative cascade (backlog 20e9ed83; migration 117): migrate
    // the retired claim's edges onto the replacement, then invalidate the
    // edge-factor BBAs frozen from ITS interval and re-derive them. Those edges
    // and BBAs belong to other writers, so this runs with ADMINISTRATIVE
    // authority -- the maintenance connection and its bypass viewer, never the
    // caller's stamp -- and writes one `security_events` row naming the
    // caller. Best-effort: the act has committed, so a cascade failure must
    // not turn a successful write into a reported error (the retry would hit
    // "already been superseded").
    let (cascade, belief_cascade) = match (session.as_mut(), deferred) {
        (Some(session), _) => {
            let (conn, admin_viewer) = session.split();
            epigraph_engine::admin_cascade::apply_after_supersede(
                conn,
                admin_viewer,
                &viewer,
                &trigger,
                claim_id,
                new_uuid,
            )
            .await
        }
        (None, status) => (status, Default::default()),
    };

    Ok((
        StatusCode::CREATED,
        Json(SupersessionResponse {
            new_claim_id: new_uuid,
            superseded_claim_id: claim_id,
            new_truth_value: request.truth_value,
            version: 0, // version counting now handled by DB chain walk
            created_at: now,
            cascade,
            belief_cascade,
            embedded,
        }),
    ))
}

/// The OAuth principal behind an authenticated request, for the cascade audit.
#[cfg(feature = "db")]
pub(crate) fn oauth_principal(
    auth: &crate::middleware::bearer::AuthContext,
) -> epigraph_engine::admin_cascade::OauthPrincipal {
    epigraph_engine::admin_cascade::OauthPrincipal {
        client_id: Some(auth.client_id),
        owner_id: auth.owner_id,
        agent_id: auth.agent_id,
    }
}

/// The answer `supersede_claim` gives when the database refuses its act on
/// `claim_id` (`supersede_act_conn`) (supersede SPEC K5). The refusal's KIND
/// is decided once, for both transports, by
/// `epigraph_engine::admin_cascade::supersede_act_refusal`
/// (`epigraph_auth::claim_act::ClaimActRefusal::of_act`); this only answers
/// each kind as an `ApiError` ([`claim_act_refusal`]). A denial is 403 with
/// its code in the reason, and nothing was written (the act and its deferral
/// share one transaction):
///
/// 1. `Cx03`: the session does not write the claim's group
///    ([`epigraph_auth::claim_act::supersede_not_recorded_message`]), the same
///    text as a refused deferral's CX03 ([`supersede_deferral_refusal`]);
/// 2. `NotWriter`, row security's uncoded `42501`: the group-write refusal;
/// 3. `CodedDenial`, a coded `42501`: a reviewed caller-refusal code
///    (`epigraph_db::caller_refusal_code`) keeps its code through
///    `From<DbError>`; an UNLISTED one is the group-write refusal, because its
///    text is unreviewed and `From` would redact it to a 500;
/// 4. `Other`: a reviewed code on another SQLSTATE through `From`;
///    `WriteRefused`, a repo `Refused`, "not found"; and everything else
///    through `From<DbError> for ApiError`, which answers OPL01 / OPL02 /
///    ROL01 as 403 with their codes and a fault as a 500.
#[cfg(feature = "db")]
pub fn supersede_refusal(claim_id: Uuid, e: epigraph_db::DbError) -> ApiError {
    let kind = epigraph_engine::admin_cascade::supersede_act_refusal(&e);
    claim_act_refusal(kind, claim_id, e)
}

/// The answer to a failed supersede DEFERRAL
/// (`epigraph_engine::admin_cascade::cascade_deferral_refusal`): CX03 is the
/// caller's 403 ([`supersede_refusal`]'s first arm, the same text); anything
/// else is a `DeployFault`, the 500 [`admin_session_or_deferral`] gives the
/// other claim acts. An uncoded `42501` here is a missing EXECUTE grant on the
/// definer, not row security refusing the caller, so it must not read as the
/// group-write 403.
#[cfg(feature = "db")]
pub fn supersede_deferral_refusal(claim_id: Uuid, e: epigraph_db::DbError) -> ApiError {
    let kind = epigraph_engine::admin_cascade::cascade_deferral_refusal(&e);
    claim_act_refusal(kind, claim_id, e)
}

/// A claim act's refusal of kind `kind` (classified by `epigraph-auth`, once
/// for both transports) as this transport's error. The MCP twin maps the same
/// kinds onto `McpError`.
#[cfg(feature = "db")]
fn claim_act_refusal(
    kind: epigraph_auth::claim_act::ClaimActRefusal,
    claim_id: Uuid,
    e: epigraph_db::DbError,
) -> ApiError {
    use epigraph_auth::claim_act::ClaimActRefusal;
    let group_write_refused = |e: &epigraph_db::DbError| {
        tracing::warn!(
            target: "tenancy.scoped_write",
            handler = "supersede_claim",
            claim = %claim_id,
            error = %e,
            "the database refused the supersession"
        );
        crate::errors::write_refused("claim")
    };
    match kind {
        ClaimActRefusal::Cx03 => {
            tracing::warn!(
                target: "tenancy.scoped_write",
                handler = "supersede_claim",
                claim = %claim_id,
                error = %e,
                "the cascade deferral refused the supersession"
            );
            ApiError::Forbidden {
                reason: epigraph_auth::claim_act::supersede_not_recorded_message(claim_id),
            }
        }
        ClaimActRefusal::NotWriter => group_write_refused(&e),
        ClaimActRefusal::CodedDenial if has_reviewed_code(&e) => ApiError::from(e),
        ClaimActRefusal::CodedDenial => group_write_refused(&e),
        ClaimActRefusal::DeployFault => deferral_failed(e),
        ClaimActRefusal::Other => other_act_refusal(claim_id, e),
    }
}

/// Whether a database refusal opens with a reviewed caller-refusal code
/// (`epigraph_db::caller_refusal_code`): `From<DbError>` then answers it with
/// the database's reviewed text and its code, as the MCP twin's
/// `db_caller_error` keeps it.
#[cfg(feature = "db")]
fn has_reviewed_code(e: &epigraph_db::DbError) -> bool {
    matches!(
        e,
        epigraph_db::DbError::QueryFailed {
            source: sqlx::Error::Database(d),
        } if epigraph_db::caller_refusal_code(d.message()).is_some()
    )
}

/// [`claim_act_refusal`]'s `Other` arm: an act refusal that is neither CX03
/// nor a `42501`.
#[cfg(feature = "db")]
fn other_act_refusal(claim_id: Uuid, e: epigraph_db::DbError) -> ApiError {
    // A reviewed caller-refusal code on another SQLSTATE keeps its code.
    if has_reviewed_code(&e) {
        return ApiError::from(e);
    }
    // The session reads the claim as current but its retirement matched
    // no row (an UPDATE policy that hides it): a denial, and the act wrote
    // nothing. `From<DbError>` answers it 403.
    if matches!(e, epigraph_db::DbError::WriteRefused { .. }) {
        tracing::warn!(
            target: "tenancy.scoped_write",
            handler = "supersede_claim",
            claim = %claim_id,
            error = %e,
            "the database refused to retire the claim"
        );
        return ApiError::from(e);
    }
    // A repo-authored refusal (e.g. the claim is already superseded) is
    // answered by its kind (operator ruling R-55), not by its text.
    if matches!(e, epigraph_db::DbError::Refused { .. }) {
        return ApiError::from(e);
    }
    if e.to_string().contains("not found") {
        return ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        };
    }
    // The operator binding's OPL01 / OPL02 and 166's ROL01 are 403 with their
    // codes there; a fault stays a redacted 500.
    ApiError::from(e)
}

/// [`admin_session_or_deferral`] for `supersede_claim`: the deferral's own
/// refusal is answered by [`supersede_deferral_refusal`] for the trigger's
/// subject (the retired claim): CX03 as the caller's 403, anything else as a
/// fault. The other claim acts keep [`admin_session_or_deferral`].
///
/// # Errors
/// The deferral INSERT's error, mapped: nothing commits.
#[cfg(feature = "db")]
pub async fn supersede_session_or_deferral<'s>(
    state: &'s AppState,
    tx: &mut sqlx::PgConnection,
    trigger: &epigraph_engine::admin_cascade::CascadeTrigger,
) -> Result<
    (
        Option<epigraph_db::MaintenanceSession<'s>>,
        epigraph_engine::admin_cascade::CascadeStatus,
    ),
    ApiError,
> {
    let claim_id = trigger.subject_id;
    epigraph_engine::admin_cascade::session_or_record_deferral(
        state.admin_cascade_session().await,
        tx,
        trigger,
    )
    .await
    .map_err(|e| supersede_deferral_refusal(claim_id, e))
}

/// Acquire the administrative (maintenance) session BEFORE the caller's act
/// commits. When there is none -- not configured, or not usable -- record the
/// deferral inside the act's own transaction `tx` (stamped with the caller's
/// viewer, so `security_events_append` admits the row) and return that status:
/// the act and its audit row then commit together. The core is
/// `epigraph_engine::admin_cascade::session_or_record_deferral`, shared with
/// the MCP tools; this answers its error as a `DeployFault`: a database error.
///
/// # Errors
/// The deferral INSERT's error, as a database error: nothing commits.
#[cfg(feature = "db")]
pub(crate) async fn admin_session_or_deferral<'s>(
    state: &'s AppState,
    tx: &mut sqlx::PgConnection,
    trigger: &epigraph_engine::admin_cascade::CascadeTrigger,
) -> Result<
    (
        Option<epigraph_db::MaintenanceSession<'s>>,
        epigraph_engine::admin_cascade::CascadeStatus,
    ),
    ApiError,
> {
    let claim_id = trigger.subject_id;
    epigraph_engine::admin_cascade::session_or_record_deferral(
        state.admin_cascade_session().await,
        tx,
        trigger,
    )
    .await
    .map_err(|e| {
        claim_act_refusal(
            epigraph_auth::claim_act::ClaimActRefusal::DeployFault,
            claim_id,
            e,
        )
    })
}

/// The generic answer to a failed deferral INSERT: a database error.
#[cfg(feature = "db")]
fn deferral_failed(e: epigraph_db::DbError) -> ApiError {
    ApiError::DatabaseError {
        message: format!("Failed to record the deferred cascade: {e}"),
    }
}

/// Supersession requires a database; without the `db` feature this reports 503.
#[cfg(not(feature = "db"))]
pub async fn supersede_claim(
    State(_state): State<AppState>,
    _auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(_claim_id): Path<Uuid>,
    Json(_request): Json<SupersedeRequest>,
) -> Result<(StatusCode, Json<SupersessionResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Claim supersession requires database".to_string(),
    })
}

/// Mark a claim as a duplicate of a canonical claim without creating a new claim.
///
/// POST /api/v1/claims/:id/dedup
///
/// Sets `supersedes = canonical_id` and `is_current = false` on the duplicate claim.
/// The canonical claim is left untouched. Writes best-effort provenance.
///
/// # Errors
///
/// - 400 Bad Request: duplicate_id == canonical_id
/// - 401 Unauthorized: no bearer token
/// - 403 Forbidden: the token lacks `claims:write`; or `not_owner` (rule
///   `not_claim_writer`): the caller can read the duplicate (or the canonical)
///   but does not write its owning group (authorship alone is not enough) and
///   lacks `claims:admin`; `claim_id` names the claim refused; or the act's
///   own authority refusal (FA04/FA07), with its reason
/// - 404 Not Found: the claim or the canonical does not exist, or the caller
///   cannot read it (the two are indistinguishable)
/// - 409 Conflict: the duplicate is already superseded, or the canonical is
///   not current (operator ruling R-55: a state refusal, with its reason)
/// - 500: the database failed (a lock timeout, a lost connection); nothing was
///   written, and the detail is in the server log
/// - 200 OK: duplicate marked successfully
#[cfg(feature = "db")]
#[utoipa::path(
    post,
    path = "/api/v1/claims/{id}/dedup",
    params(("id" = uuid::Uuid, Path, description = "UUID of the duplicate claim")),
    request_body = DedupRequest,
    responses(
        (status = 200, body = DedupResponse),
        (status = 400),
        (status = 401),
        (status = 403),
        (status = 404),
        (status = 409),
        (status = 500),
    ),
    security(("ed25519_signature" = [])),
    tag = "claims"
)]
pub async fn mark_duplicate(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(dup_id): Path<Uuid>,
    Json(req): Json<DedupRequest>,
) -> Result<Json<DedupResponse>, ApiError> {
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "dedup requires authentication".into(),
        })?
        .0;
    // `claims:write`, not `claims:admin` (batch OA1, operator decision D1):
    // marking a claim a duplicate is the caller's own write to that claim; the
    // cascade that re-points OTHER writers' edges is administrative, runs on the
    // maintenance connection and is deferred to the replay timer. Who may ask is
    // the per-claim rule below.
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])?;

    let principal = auth.owner_id.unwrap_or(auth.client_id);
    tracing::info!(
        principal = %principal,
        dup_id = %dup_id,
        canonical_id = %req.canonical_id,
        reason = req.reason.as_deref().unwrap_or(""),
        "mark_duplicate"
    );

    if dup_id == req.canonical_id {
        return Err(ApiError::BadRequest {
            message: "canonical_id cannot equal duplicate id".into(),
        });
    }

    // Both claims, read through the CALLER's viewer: one it cannot read is 404,
    // exactly like a missing one, whichever of the two it is. Only then is
    // authority decided, first over the duplicate and then over the canonical,
    // so a refusal below concerns a claim the caller can see. The canonical
    // needs the same write authority as the duplicate (batch OA1, brief (a):
    // "the caller may write the target claim(s)"): the act writes the
    // duplicate's row alone, but the cascade then re-points OTHER writers'
    // edges and BBAs onto the canonical with administrative authority, so a
    // `claims:write` caller may only pick a canonical it could write itself.
    let (dup_target, canonical_target) = {
        let mut read = state.read_as(&viewer).await.map_err(|e| {
            tracing::error!(
                target: "tenancy.scoped_read",
                error = %e,
                handler = "mark_duplicate",
                "could not acquire a viewer-stamped connection"
            );
            ApiError::InternalError {
                message: "Failed to acquire a scoped connection".to_string(),
            }
        })?;
        let not_found = |id: Uuid| ApiError::NotFound {
            entity: "Claim".to_string(),
            id: id.to_string(),
        };
        let db = |e: epigraph_db::DbError| ApiError::InternalError {
            message: format!("DB error: {e}"),
        };
        let dup = ClaimRepository::write_target_of(&mut *read, &viewer, dup_id)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found(dup_id))?;
        let canonical = ClaimRepository::write_target_of(&mut *read, &viewer, req.canonical_id)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found(req.canonical_id))?;
        (dup, canonical)
    };
    let arm = crate::middleware::scopes::require_claim_act_authority(
        &auth,
        viewer.principal(),
        viewer.writable_groups(),
        epigraph_auth::claim_act::ClaimActTarget {
            author: dup_target.0,
            owner_group: dup_target.1,
        },
        dup_id,
        "mark as a duplicate",
    )?;
    crate::middleware::scopes::require_claim_act_authority(
        &auth,
        viewer.principal(),
        viewer.writable_groups(),
        epigraph_auth::claim_act::ClaimActTarget {
            author: canonical_target.0,
            owner_group: canonical_target.1,
        },
        req.canonical_id,
        "mark a duplicate onto",
    )?;
    tracing::info!(
        handler = "mark_duplicate",
        claim = %dup_id,
        arm = arm.as_str(),
        "claim act admitted"
    );

    // THE ACT (migration 117), on ONE transaction stamped with the CALLER's
    // viewer: mark the duplicate. The database decides write authority, so a
    // caller may dedup only a claim it may write (a duplicate in a group its
    // writable set lacks is refused with nothing written). It used to run
    // unstamped on the raw pool, where the application role refused even the
    // caller's own duplicate. Only the act's failure is an error.
    let mut tx = state.write_as(&viewer, "mark_duplicate").await?;
    let provenance = epigraph_db::DuplicateProvenance::new(
        "http:mark_duplicate",
        epigraph_db::DuplicateProvenance::RULE_CALLER_ASSERTED,
    )
    .marked_by(viewer.principal())
    .reason(req.reason.as_deref());
    // The identity edge is attested at INSERT with the API's own key (backlog
    // dae795f8), `None` when this API has none configured.
    ClaimRepository::mark_duplicate_act_attributed_conn(
        &mut tx,
        state.edge_signing_key(),
        ClaimId::from_uuid(dup_id),
        ClaimId::from_uuid(req.canonical_id),
        &provenance,
    )
    .await
    .map_err(|e| mark_duplicate_act_error(e, dup_id))?;
    let trigger = epigraph_engine::admin_cascade::CascadeTrigger::new(
        epigraph_engine::admin_cascade::CascadeCause::Dedup,
        viewer.principal(),
        Some(oauth_principal(&auth)),
        dup_id,
        Some(req.canonical_id),
    );
    let (mut session, deferred) = admin_session_or_deferral(&state, &mut tx, &trigger).await?;
    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit the dedup: {e}"),
    })?;

    // THE CASCADE, with administrative authority on the maintenance connection
    // (migration 117): retract the duplicate's colliding edges and drop their
    // BBAs, re-point every other edge onto the canonical, move the BBAs that
    // follow them, and rebuild the affected beliefs (backlog 20e9ed83).
    // Best-effort and audited; see the supersede handler.
    let (cascade, belief_cascade) = match (session.as_mut(), deferred) {
        (Some(session), _) => {
            let (conn, admin_viewer) = session.split();
            epigraph_engine::admin_cascade::apply_after_dedup(
                conn,
                admin_viewer,
                &viewer,
                &trigger,
                dup_id,
                req.canonical_id,
            )
            .await
        }
        (None, status) => (status, Default::default()),
    };

    // Provenance: best-effort (.ok() swallow). content_hash is zero-bytes for mark_duplicate.
    if let Ok(mut tx) = state.db_pool.begin().await {
        let _ = epigraph_db::ProvenanceRepository::append_conn(
            &mut tx,
            "claim",
            dup_id,
            "mark_duplicate",
            auth.client_id,
            principal,
            &[epigraph_db::repos::provenance::AUTO_POLICY_AUTHORIZER_ID],
            "auto_policy",
            &[0u8; 32],
            &[],
            auth.jti,
            &auth.scopes,
            Some(&serde_json::json!({
                "canonical_id": req.canonical_id,
                "mode": "mark_duplicate",
                "reason": req.reason.clone().unwrap_or_default(),
            })),
        )
        .await;
        let _ = tx.commit().await;
    }

    Ok(Json(DedupResponse {
        duplicate_id: dup_id,
        canonical_id: req.canonical_id,
        mode: "mark_duplicate",
        cascade,
        belief_cascade,
    }))
}

/// The answer `mark_duplicate` gives when the dedup's act fails:
///
/// - row security refused the write (42501): the group-write 403;
/// - a claim is missing or unreadable: 404;
/// - the act's designed refusal by its kind (FA04/FA07 are 403, a retired
///   canonical or an already-superseded duplicate 409), a reviewed coded
///   refusal with its code, and the coded denials (OPL01, OPL02, ROL01, the
///   personal-group and elevation denials, a row-security write refusal) as
///   `From<DbError>` answers them;
/// - every other error, including an uncoded `QueryFailed` (a lock timeout, a
///   lost connection) and the variants `From<DbError>` would answer as the
///   caller's 400/409 (`InvalidData`, a constraint violation, a duplicate key,
///   `Conflict`): the redacted 500. None of those is the caller's error on
///   this path, where both claims were already resolved; their text is a
///   server diagnostic and stays in the log.
///
/// An uncoded `QueryFailed` used to be answered 409 "claim already superseded
/// or invalid input", from before the act's refusals had their own variant
/// (backlog dca9ed56). The list is an allow-list, so a new `DbError` variant
/// defaults to the redacted 500.
#[cfg(feature = "db")]
fn mark_duplicate_act_error(e: epigraph_db::DbError, dup_id: Uuid) -> ApiError {
    use epigraph_db::DbError;
    match e {
        e if crate::errors::db_is_insufficient_privilege(&e) => {
            tracing::warn!(
                target: "tenancy.scoped_write",
                handler = "mark_duplicate",
                claim = %dup_id,
                error = %e,
                "the database refused the dedup"
            );
            crate::errors::write_refused("claim")
        }
        DbError::NotFound { id, .. } => ApiError::NotFound {
            entity: "Claim".into(),
            id: id.to_string(),
        },
        e @ (DbError::Refused { .. }
        | DbError::QueryFailed { .. }
        | DbError::WriteRefused { .. }
        | DbError::ElevatedReadOnly
        | DbError::MembershipRevoked { .. }
        | DbError::PersonalGroupNotOwned { .. }
        | DbError::OperatorLinkRequired { .. }
        | DbError::OperatorScopeRefused { .. }
        | DbError::RoleHolderRequired { .. }) => ApiError::from(e),
        other => ApiError::DatabaseError {
            message: other.to_string(),
        },
    }
}

/// The answer `unmark_duplicate` gives when the administrative un-mark
/// changed nothing ([`epigraph_engine::admin_cascade::UnmarkRefusal`]):
///
/// - the act's designed refusal by its kind, as any repo refusal is answered
///   (`From<DbError>`: input 400, authority 403, state 409), its text the
///   reason;
/// - no record to reverse the mark from: 409, with the reason;
/// - a failure: 500, its text in the server log only.
#[cfg(feature = "db")]
#[must_use]
pub fn unmark_refusal(e: epigraph_engine::admin_cascade::UnmarkRefusal) -> ApiError {
    use epigraph_engine::admin_cascade::UnmarkRefusal;
    match e {
        UnmarkRefusal::Act { kind, message } => {
            ApiError::from(epigraph_db::DbError::Refused { kind, message })
        }
        e @ UnmarkRefusal::NoRecord => ApiError::Conflict {
            reason: e.to_string(),
        },
        e @ UnmarkRefusal::Failed(_) => ApiError::InternalError {
            message: e.to_string(),
        },
    }
}

/// Un-mark a duplicate: reverse `POST /api/v1/claims/{id}/dedup`.
///
/// POST /api/v1/claims/{id}/undedup
///
/// The claim is current again (re-embedded best-effort), its `same_as`
/// identity edge is retracted, and the dedup's repair is reversed from the
/// record it kept; both claims' belief is re-derived. A canonical superseded or
/// consolidated since the mark is followed to its current replacement
/// (`current_canonical_id`), and the duplicate is restored against it. Same
/// authority as the dedup (`claims:write` plus write authority over the
/// duplicate and the canonical, and every claim that replaced the canonical,
/// or `claims:admin`), proved on a transaction stamped with the
/// caller and rolled back; the act and the reversal then commit together on
/// the maintenance connection (`admin_cascade::apply_unmark`), because an
/// un-mark cannot be deferred. A server without that connection answers 409
/// with nothing written.
#[utoipa::path(
    post,
    path = "/api/v1/claims/{id}/undedup",
    params(("id" = uuid::Uuid, Path, description = "UUID of the marked duplicate")),
    responses(
        (status = 200, body = UndedupResponse),
        (status = 400),
        (status = 401),
        (status = 403),
        (status = 404),
        (status = 409),
        (status = 500),
    ),
    security(("ed25519_signature" = [])),
    tag = "claims"
)]
#[cfg(feature = "db")]
pub async fn unmark_duplicate(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(dup_id): Path<Uuid>,
) -> Result<Json<UndedupResponse>, ApiError> {
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "undedup requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])?;

    let db = |e: epigraph_db::DbError| ApiError::InternalError {
        message: format!("DB error: {e}"),
    };
    let not_found = |id: Uuid| ApiError::NotFound {
        entity: "Claim".to_string(),
        id: id.to_string(),
    };
    // The duplicate (and from it the canonical, and the claims that replaced
    // the canonical since), read through the CALLER.
    let (canonical_id, content, dup_target, canonical_target, chain, replacement_targets) = {
        let mut read = state.read_as(&viewer).await.map_err(db)?;
        let claim = ClaimRepository::get_by_id(&mut *read, &viewer, ClaimId::from_uuid(dup_id))
            .await
            .map_err(db)?
            .ok_or_else(|| not_found(dup_id))?;
        let canonical_id: Uuid = claim
            .supersedes
            .ok_or_else(|| ApiError::Conflict {
                reason: format!("claim {dup_id} is not a marked duplicate"),
            })?
            .into();
        let dup_target = ClaimRepository::write_target_of(&mut *read, &viewer, dup_id)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found(dup_id))?;
        let canonical_target = ClaimRepository::write_target_of(&mut *read, &viewer, canonical_id)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found(canonical_id))?;
        // A canonical superseded or consolidated since is followed to its
        // current replacement, and the reversal acts on every claim of that
        // chain (operator ruling R-11), so the caller's authority is checked
        // over each of them below as over the canonical. A mark with no
        // identity edge is refused first, with its reason (R-7); either
        // refusal is answered only after the caller's authority over the
        // duplicate and the canonical is checked.
        let chain = ClaimRepository::unmark_chain_conn(&mut read, &viewer, dup_id, canonical_id)
            .await
            .map_err(db)?;
        let mut replacement_targets = Vec::new();
        for id in chain.iter().flatten().skip(1) {
            let target = ClaimRepository::write_target_of(&mut *read, &viewer, *id)
                .await
                .map_err(db)?
                .ok_or_else(|| not_found(*id))?;
            replacement_targets.push((*id, target));
        }
        (
            canonical_id,
            claim.content.clone(),
            dup_target,
            canonical_target,
            chain,
            replacement_targets,
        )
    };
    crate::middleware::scopes::require_claim_act_authority(
        &auth,
        viewer.principal(),
        viewer.writable_groups(),
        epigraph_auth::claim_act::ClaimActTarget {
            author: dup_target.0,
            owner_group: dup_target.1,
        },
        dup_id,
        "un-mark as a duplicate",
    )?;
    crate::middleware::scopes::require_claim_act_authority(
        &auth,
        viewer.principal(),
        viewer.writable_groups(),
        epigraph_auth::claim_act::ClaimActTarget {
            author: canonical_target.0,
            owner_group: canonical_target.1,
        },
        canonical_id,
        "un-mark a duplicate of",
    )?;
    let chain = chain.map_err(|why| ApiError::Conflict {
        reason: format!("claim {dup_id} {why}; nothing was written"),
    })?;
    for (id, (author, owner_group)) in &replacement_targets {
        crate::middleware::scopes::require_claim_act_authority(
            &auth,
            viewer.principal(),
            viewer.writable_groups(),
            epigraph_auth::claim_act::ClaimActTarget {
                author: *author,
                owner_group: *owner_group,
            },
            *id,
            "un-mark a duplicate onto",
        )?;
    }

    // No administrative connection: refuse before anything is written.
    let mut session = state
        .admin_cascade_session()
        .await
        .map_err(|reason| ApiError::Conflict {
            reason: format!(
                "an un-mark needs this server's administrative (maintenance) connection and \
                 cannot be deferred; nothing was written ({reason}). An operator runs it as \
                 the `unmark_duplicate` CLI on the maintenance DSN"
            ),
        })?;

    // The caller's authority, decided by the database's write predicate on the
    // caller's stamped transaction. Not a rehearsal of the act: once operator
    // binding is armed an application session may not clear a `supersedes`
    // (migration 153); the act commits with the reversal on the maintenance
    // connection.
    let mut tx = state.write_as(&viewer, "unmark_duplicate").await?;
    let mut may = true;
    for id in &chain {
        may &= ClaimRepository::session_may_unmark_conn(
            &mut tx,
            ClaimId::from_uuid(dup_id),
            ClaimId::from_uuid(*id),
        )
        .await
        .map_err(db)?;
    }
    tx.rollback().await.map_err(db)?;
    if !may {
        return Err(crate::errors::write_refused("claim"));
    }

    let trigger = epigraph_engine::admin_cascade::CascadeTrigger::new(
        epigraph_engine::admin_cascade::CascadeCause::Undedup,
        viewer.principal(),
        Some(oauth_principal(&auth)),
        dup_id,
        Some(canonical_id),
    );
    let (conn, admin_viewer) = session.split();
    let (outcome, belief_cascade) = epigraph_engine::admin_cascade::apply_unmark_authorized(
        conn,
        admin_viewer,
        &viewer,
        &trigger,
        dup_id,
        canonical_id,
        Some(&chain),
    )
    .await
    .map_err(unmark_refusal)?;

    // Current again: embed post-commit, best-effort (CLAUDE.md's write-path
    // rule). Stored only if the claim is still current and unsealed.
    let mut embedded = false;
    if let Some(embedder) = state.storing_embedding_service() {
        match embedder.generate(&content).await {
            Ok(v) => {
                let pgvec = epigraph_db::pgvector_literal(&v);
                let (conn, admin_viewer) = session.split();
                match ClaimRepository::store_embedding_if_unsealed(
                    conn,
                    admin_viewer,
                    dup_id,
                    &pgvec,
                )
                .await
                {
                    Ok(stored) => embedded = stored,
                    Err(e) => {
                        tracing::warn!(claim = %dup_id, error = %e, "undedup: embedding not stored")
                    }
                }
            }
            Err(e) => tracing::warn!(claim = %dup_id, error = %e, "undedup: embedding failed"),
        }
    }

    Ok(Json(UndedupResponse {
        duplicate_id: dup_id,
        canonical_id: outcome.canonical_id,
        current_canonical_id: outcome.current_canonical_id,
        mode: "unmark_duplicate",
        embedded,
        cascade: outcome.cascade,
        belief_cascade,
    }))
}

/// Get the full version history for a claim
///
/// GET /api/v1/claims/:id/history
///
/// Walks the supersession chain in both directions to build a complete
/// version history. Returns all versions sorted by creation time (oldest first).
///
/// # Errors
///
/// - 404 Not Found: Claim does not exist
/// - 200 OK: Version history returned
///
/// The whole chain is read as the caller's `Viewer`
/// (`ClaimRepository::version_history`). A claim the viewer cannot see is
/// reported as 404, identically to one that does not exist: before PR-07 this
/// handler walked `claims` with three unfiltered inline statements and returned
/// every revision's `content`, so it disclosed not only other tenants' claim
/// text but the full edit history behind it.
#[cfg(feature = "db")]
pub async fn claim_history(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<VersionHistoryResponse>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "claim_history",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let hits = epigraph_db::ClaimRepository::version_history(&mut *read, &viewer, claim_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("DB error: {e}"),
        })?;

    if hits.is_empty() {
        return Err(ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        });
    }

    // `superseded_by` comes from `claims.supersedes` (see
    // `ClaimVersionHit::superseded_by`), NOT from the position of the next row.
    // Positional inference is wrong on a forked chain — `mark_duplicate` points
    // every duplicate at the same canonical claim, so a claim with two marked
    // duplicates has two successors and "the next row" names an arbitrary one
    // of them. `version` is still positional, but the repo's
    // `ORDER BY depth, id` is a total order, so it is at least stable across
    // identical requests.
    let mut current_version: u32 = 1;
    let versions: Vec<ClaimVersion> = hits
        .iter()
        .enumerate()
        .map(|(idx, hit)| {
            let version = (idx as u32) + 1;
            if hit.is_current {
                current_version = version;
            }
            ClaimVersion {
                claim_id: hit.id,
                content: hit.content.clone(),
                truth_value: hit.truth_value,
                version,
                is_current: hit.is_current,
                created_at: hit.created_at,
                superseded_by: hit.superseded_by,
            }
        })
        .collect();

    let total_versions = versions.len();

    Ok(Json(VersionHistoryResponse {
        claim_id,
        versions,
        total_versions,
        current_version,
    }))
}

/// Version history requires a database; without the `db` feature this reports 503.
#[cfg(not(feature = "db"))]
pub async fn claim_history(
    State(_state): State<AppState>,
    Path(_claim_id): Path<Uuid>,
) -> Result<Json<VersionHistoryResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Claim history requires database".to_string(),
    })
}

// =============================================================================
// TESTS
// =============================================================================
// Supersession and version history are served only by the `db` arm
// (`ClaimRepository::supersede` and the version-chain walk). Parts of that
// behaviour have database integration tests under `tests/`: refusal codes
// and 409 (`supersede_refusal_codes_http.rs`, `refusal_kinds_http.rs`),
// `ClaimSuperseded` emission (`supersede_emits_claim_superseded_http.rs`),
// history walks (`claim_history_cycle_test.rs`), viewer-filtered 404s
// (`write_gate_reads_are_viewer_filtered.rs`) and ownership
// (`own_claim_authority_http.rs`).
//
// NOT YET TESTED in the db arm: the request-validation 400s of the db
// `supersede_claim` (empty or whitespace `content` or `reason`, the
// content and reason length caps, a `truth_value` outside [0, 1] or not
// finite) and its `ClaimSubmitted` publish. These still need db integration
// tests.
//
// The `not(db)` arm keeps only the two 503 stubs above. The in-memory
// supersession tests that used to live here asserted behaviour those stubs
// do not have, so every one of them failed at runtime once the not(db)
// lib-test target was run. They were deleted rather than rewritten: their
// subject no longer exists in this arm. What the not(db) arm DOES promise is
// pinned below.

#[cfg(all(test, not(feature = "db")))]
mod nodb_stub_tests {
    use super::*;
    use crate::middleware::bearer::test_auth_with_scopes;
    use crate::state::{ApiConfig, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::{get, post};
    use axum::Router;
    use epigraph_core::Claim;
    use tower::ServiceExt;

    /// A state holding one claim in the in-memory store, and that claim's id.
    async fn state_with_claim() -> (AppState, Uuid) {
        let state = AppState::new(ApiConfig {
            require_packet_signatures: false,
            ..ApiConfig::default()
        });
        let claim_id = Uuid::new_v4();
        let claim = Claim {
            id: ClaimId::from_uuid(claim_id),
            ..Claim::new(
                "Original claim content".to_string(),
                epigraph_core::AgentId::new(),
                [0u8; 32],
                TruthValue::new(0.7).unwrap(),
            )
        };
        state.claim_store.write().await.insert(claim_id, claim);
        (state, claim_id)
    }

    /// The routes as the bearer middleware would reach them: with a
    /// `claims:write` caller, so a 503 here is the stub's own answer and not
    /// an authentication refusal.
    fn router(state: AppState) -> Router {
        Router::new()
            .route("/api/v1/claims/:id/supersede", post(supersede_claim))
            .route("/api/v1/claims/:id/history", get(claim_history))
            .layer(axum::Extension(test_auth_with_scopes(&["claims:write"])))
            .with_state(state)
    }

    /// A well-formed supersession of an existing claim is refused with 503,
    /// and nothing is written: no successor in the store, the original left
    /// as it was, and no `ClaimSubmitted` event published.
    #[tokio::test]
    async fn supersede_without_a_database_is_503_and_writes_nothing() {
        let (state, claim_id) = state_with_claim().await;

        let body = serde_json::json!({
            "content": "Updated claim via supersession",
            "truth_value": 0.85,
            "reason": "New evidence discovered"
        });
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/claims/{claim_id}/supersede"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = router(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        assert_eq!(
            state.event_bus.history_size(),
            0,
            "no event may be published"
        );
        let store = state.claim_store.read().await;
        assert_eq!(store.len(), 1, "no successor claim may be created");
        let original = store.get(&claim_id).expect("the original claim stays");
        assert_eq!(original.content, "Original claim content");
    }

    /// History of an existing claim is refused with 503, not answered from
    /// the in-memory store as a one-version chain.
    #[tokio::test]
    async fn history_without_a_database_is_503() {
        let (state, claim_id) = state_with_claim().await;

        let request = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/claims/{claim_id}/history"))
            .body(Body::empty())
            .unwrap();

        let response = router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Test that superseding a claim without signature headers returns 401
    /// when the request goes through the full create_router middleware stack.
    ///
    /// This is a true integration test: it uses the production router
    /// (including the bearer_auth_middleware layer) rather than a
    /// bare handler router, proving that unauthenticated writes are rejected.
    #[tokio::test]
    async fn test_supersede_without_signature_returns_401() {
        let claim_id = Uuid::new_v4();
        let state = AppState::new(ApiConfig {
            require_packet_signatures: false, // irrelevant; middleware always checks headers
            ..ApiConfig::default()
        });

        // Pre-populate a claim so we know the 401 comes from auth, not 404
        {
            let claim = epigraph_core::Claim::new(
                "Original claim".to_string(),
                epigraph_core::AgentId::new(),
                [0u8; 32],
                TruthValue::new(0.7).unwrap(),
            );
            let claim = epigraph_core::Claim {
                id: epigraph_core::ClaimId::from_uuid(claim_id),
                ..claim
            };
            let mut store = state.claim_store.write().await;
            store.insert(claim_id, claim);
        }

        // Use the full production router with middleware
        let router = crate::routes::create_router(state);

        let body = serde_json::json!({
            "content": "Updated claim content",
            "truth_value": 0.85,
            "reason": "New evidence discovered"
        });

        // POST without any signature headers -> middleware rejects with 401
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/claims/{claim_id}/supersede"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Supersede without signature headers must return 401"
        );
    }

    /// PR-03 INVERSION. This asserted that `GET /api/v1/claims/:id/history`
    /// answered 200 with no credential, "because the history endpoint is on
    /// the public router". It is not on the public router any more: version
    /// history is claim content over time, which is strictly more than
    /// `GET /api/v1/claims/:id` exposes.
    #[tokio::test]
    async fn test_history_is_401_without_a_token() {
        let claim_id = Uuid::new_v4();
        let state = AppState::new(ApiConfig::default());

        // Pre-populate a claim
        {
            let claim = epigraph_core::Claim::new(
                "A claim".to_string(),
                epigraph_core::AgentId::new(),
                [0u8; 32],
                TruthValue::new(0.5).unwrap(),
            );
            let claim = epigraph_core::Claim {
                id: epigraph_core::ClaimId::from_uuid(claim_id),
                ..claim
            };
            let mut store = state.claim_store.write().await;
            store.insert(claim_id, claim);
        }

        // Use the full production router (with middleware)
        let router = crate::routes::create_router(state);

        // GET with no Authorization header -> 401 with the RFC 6750
        // challenge, before the handler (a 503 stub in this arm) runs.
        let request = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/claims/{claim_id}/history"))
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "claim version history is no longer anonymously readable"
        );
        let challenge = response
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .expect("401 carries an RFC 6750 challenge")
            .to_str()
            .unwrap();
        assert!(
            challenge.contains(r#"error="invalid_token""#),
            "got: {challenge}"
        );
    }
}

#[cfg(all(test, feature = "db"))]
mod unmark_refusal_tests {
    use super::unmark_refusal;
    use axum::response::IntoResponse;
    use epigraph_db::RefusalKind;
    use epigraph_engine::admin_cascade::UnmarkRefusal;

    fn status(e: UnmarkRefusal) -> u16 {
        unmark_refusal(e).into_response().status().as_u16()
    }

    /// An un-mark's act refusal is answered by its kind, as every repo refusal
    /// is (backlog dca9ed56): an authority refusal is 403, not the 409 every
    /// act refusal used to be; a failure is a 500 whose text stays in the log.
    #[test]
    fn an_unmark_refusal_is_answered_by_its_kind() {
        let act = |kind| UnmarkRefusal::Act {
            kind,
            message: "unmark_duplicate: refused".into(),
        };
        assert_eq!(status(act(RefusalKind::Input)), 400);
        assert_eq!(status(act(RefusalKind::Authority)), 403);
        assert_eq!(status(act(RefusalKind::State)), 409);
        assert_eq!(status(UnmarkRefusal::NoRecord), 409);
        let failed = unmark_refusal(UnmarkRefusal::Failed(
            "Query failed: canceling statement due to lock timeout".into(),
        ));
        assert!(
            matches!(failed, crate::errors::ApiError::InternalError { .. }),
            "{failed:?}"
        );
        assert_eq!(failed.into_response().status().as_u16(), 500);
    }

    /// The status and the whole body of `mark_duplicate`'s answer to `e`.
    async fn dedup_answer(e: epigraph_db::DbError) -> (u16, String) {
        use http_body_util::BodyExt;
        let response = super::mark_duplicate_act_error(e, uuid::Uuid::new_v4()).into_response();
        let status = response.status().as_u16();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("an in-memory body")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// A dedup act's error is the caller's only when it is a designed
    /// refusal or a coded denial (backlog dca9ed56): every other error is a
    /// server fault on this path, where both claims were already resolved, so
    /// it is the redacted 500 and its text stays in the log, not a 400/409
    /// carrying a server diagnostic as the caller's reason.
    #[tokio::test]
    async fn a_dedup_act_error_is_the_callers_only_when_it_is_a_designed_refusal() {
        use epigraph_db::DbError;
        const DIAGNOSTIC: &str = "edge properties do not recompute to the digest signed over them";
        let faults = [
            DbError::InvalidData {
                reason: DIAGNOSTIC.into(),
            },
            DbError::Conflict {
                reason: DIAGNOSTIC.into(),
            },
            DbError::CheckViolation {
                constraint: DIAGNOSTIC.into(),
                message: DIAGNOSTIC.into(),
            },
            DbError::ForeignKeyViolation {
                constraint: DIAGNOSTIC.into(),
            },
            DbError::DuplicateKey {
                entity: DIAGNOSTIC.into(),
            },
            DbError::QueryFailed {
                source: sqlx::Error::Protocol(DIAGNOSTIC.into()),
            },
        ];
        for fault in faults {
            let label = format!("{fault:?}");
            let (status, body) = dedup_answer(fault).await;
            assert_eq!(status, 500, "{label}: {body}");
            assert!(!body.contains(DIAGNOSTIC), "{label} leaked: {body}");
        }
        // The designed refusals and the coded denials keep their answers.
        let refused = |kind| DbError::Refused {
            kind,
            message: "mark_duplicate: refused".into(),
        };
        assert_eq!(dedup_answer(refused(RefusalKind::Input)).await.0, 400);
        assert_eq!(dedup_answer(refused(RefusalKind::Authority)).await.0, 403);
        assert_eq!(dedup_answer(refused(RefusalKind::State)).await.0, 409);
        let missing = DbError::NotFound {
            entity: "Claim".into(),
            id: uuid::Uuid::new_v4(),
        };
        assert_eq!(dedup_answer(missing).await.0, 404);
        let role = DbError::RoleHolderRequired {
            message: "ROL01: refused".into(),
        };
        let (status, body) = dedup_answer(role).await;
        assert_eq!(status, 403, "{body}");
        assert!(body.contains("ROL01"), "{body}");
    }
}

/// The supersede refusal mappers, pinned byte for byte by refusal kind
/// (`epigraph_auth::claim_act::ClaimActRefusal`): each row is a database
/// error as the driver raises it and the exact `ApiError` (variant and text)
/// the caller gets.
#[cfg(all(test, feature = "db"))]
mod refusal_table {
    use super::{supersede_deferral_refusal, supersede_refusal};
    use crate::errors::ApiError;
    use std::borrow::Cow;
    use uuid::Uuid;

    #[derive(Debug)]
    struct FakeDbError {
        code: &'static str,
        message: String,
    }
    impl std::fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.message)
        }
    }
    impl std::error::Error for FakeDbError {}
    impl sqlx::error::DatabaseError for FakeDbError {
        fn message(&self) -> &str {
            &self.message
        }
        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.code))
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    fn db(code: &'static str, message: &str) -> epigraph_db::DbError {
        epigraph_db::DbError::QueryFailed {
            source: sqlx::Error::Database(Box::new(FakeDbError {
                code,
                message: message.to_string(),
            })),
        }
    }

    const RLS: &str = "new row violates row-level security policy for table \"claims\"";
    const NO_EXECUTE: &str = "permission denied for function epigraph_record_cascade_deferral";

    fn forbidden(reason: impl Into<String>) -> ApiError {
        ApiError::Forbidden {
            reason: reason.into(),
        }
    }

    fn group_write() -> ApiError {
        forbidden("no write authority over the group that owns this claim; nothing was written")
    }

    fn not_recorded(claim: Uuid) -> ApiError {
        forbidden(format!(
            "CX03: the supersession of claim {claim} cannot be recorded: the session acting on \
             it does not write the group that owns the claim; nothing was written"
        ))
    }

    fn redacted_500() -> ApiError {
        ApiError::DatabaseError {
            message: "A database error occurred".to_string(),
        }
    }

    /// `ApiError` has no `PartialEq`; its `Debug` names the variant and every
    /// field, which is what the response is rendered from.
    fn same(got: &ApiError, want: &ApiError, row: &str) {
        assert_eq!(format!("{got:?}"), format!("{want:?}"), "{row}");
    }

    /// The ACT: CX03, row security's uncoded 42501 (not writer), a coded
    /// 42501 (reviewed, then unlisted), a reviewed code on another SQLSTATE,
    /// CX03's text on another SQLSTATE, and the repo-layer arms.
    #[test]
    fn every_act_refusal_kind_maps_to_its_exact_answer() {
        let c = Uuid::new_v4();
        let rows: Vec<(&str, epigraph_db::DbError, ApiError)> = vec![
            (
                "cx03",
                db("42501", "CX03: not recorded as one this session made"),
                not_recorded(c),
            ),
            ("not writer: row security", db("42501", RLS), group_write()),
            (
                "not writer: uncoded engine 42501",
                db("42501", "permission denied for table claims"),
                group_write(),
            ),
            (
                "coded denial, reviewed: keeps its code, 403",
                db("42501", "TEN01: a reviewed refusal"),
                forbidden("TEN01: a reviewed refusal"),
            ),
            (
                "coded denial, unlisted: the group-write 403, the text withheld",
                db("42501", "ZZ99: a probe refusal"),
                group_write(),
            ),
            (
                "other: a reviewed code on another SQLSTATE keeps its code, 400",
                db("P0001", "GRM05: a reviewed refusal"),
                ApiError::BadRequest {
                    message: "GRM05: a reviewed refusal".to_string(),
                },
            ),
            (
                "other: CX03's text on another SQLSTATE is a redacted fault",
                db("P0001", "CX03: raised elsewhere"),
                redacted_500(),
            ),
            (
                "other: an uncoded fault",
                db("XX000", "internal driver detail"),
                redacted_500(),
            ),
            (
                "other: a write row security hid",
                epigraph_db::DbError::WriteRefused {
                    entity: "claim".into(),
                    id: c,
                    action: "supersede".into(),
                },
                forbidden(format!(
                    "supersede of claim {c} was refused: this session may read it but not \
                     supersede it; nothing was changed"
                )),
            ),
            (
                "other: a repo refusal by its kind",
                epigraph_db::DbError::Refused {
                    kind: epigraph_db::RefusalKind::State,
                    message: "already superseded".into(),
                },
                ApiError::Conflict {
                    reason: "already superseded".to_string(),
                },
            ),
            (
                "other: not found names the claim",
                epigraph_db::DbError::NotFound {
                    entity: "claims".into(),
                    id: Uuid::nil(),
                },
                ApiError::NotFound {
                    entity: "Claim".to_string(),
                    id: c.to_string(),
                },
            ),
        ];
        for (row, e, want) in rows {
            same(&supersede_refusal(c, e), &want, row);
        }
    }

    /// The DEFERRAL: CX03 is the act's own 403, byte for byte; any other
    /// refusal (the missing EXECUTE grant's uncoded 42501 included) is the
    /// deferral's 500 with the error, never the group-write 403.
    #[test]
    fn every_deferral_refusal_kind_maps_to_its_exact_answer() {
        let c = Uuid::new_v4();
        same(
            &supersede_deferral_refusal(c, db("42501", "CX03: not recorded")),
            &not_recorded(c),
            "cx03",
        );
        for (row, e) in [
            ("deploy fault: missing EXECUTE", db("42501", NO_EXECUTE)),
            ("deploy fault: coded", db("42501", "ZZ99: a probe refusal")),
            (
                "deploy fault: uncoded",
                db("XX000", "internal driver detail"),
            ),
        ] {
            let want = ApiError::DatabaseError {
                message: format!("Failed to record the deferred cascade: {e}"),
            };
            same(&supersede_deferral_refusal(c, e), &want, row);
        }
    }
}
