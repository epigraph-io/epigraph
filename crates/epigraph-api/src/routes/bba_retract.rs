//! `POST /api/v1/mass-functions/:id/retract`: retract ONE mass function (BBA)
//! (operator ruling R-79, migration 184).
//!
//! A retracted BBA is excluded from every fold and belief read and kept, with
//! its retractor, time and reason, for audit. The database decides who may
//! retract it, through `epigraph_retract_mass_function` (see
//! `MassFunctionRepository::retract_conn`): a writer of the BBA's owning
//! group, or a caller whose token carries `claims:admin` and whose client
//! record still holds that grant. The transaction is stamped from the
//! CALLER's own viewer, so the retractor recorded is always the caller.
//!
//! * 404 for a BBA that does not exist or that the caller cannot read (one
//!   answer for both);
//! * 403 for a readable BBA the caller may not retract, and for a token
//!   without `claims:write`;
//! * 400 for an empty or over-long reason;
//! * 200 with `status: "retracted"` on the first retraction (one
//!   `security_events` row, `mass_functions.retract`), and with
//!   `status: "already_retracted"` on a repeat, which writes nothing.
//!
//! After a first retraction the claim's cached belief is recomputed on the
//! same transaction from the BBAs that remain (`belief_recomputed` says
//! whether a cache was written); when none remains, the cache becomes the
//! explicit vacuous value (ruling R-80, `belief_vacated`;
//! `epigraph_engine::bba_retract`). The stored scoped beliefs that folded the
//! BBA are deleted as stale (`scoped_beliefs_cleared`). The MCP twin is
//! `retract_bba` (`epigraph-mcp/src/tools/bba_retract.rs`).
//!
//! A retracted BBA keeps its key (ruling R-103): a write to the same claim,
//! frame, source agent and perspective is refused with 409 (RT07). It becomes
//! live again only through `POST /api/v1/mass-functions/:id/unretract`
//! ([`unretract_bba`]), audited, MCP twin `unretract_bba`.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;
use epigraph_db::repos::mass_function::{BbaRetractError, BbaRetractStatus, BbaUnretractStatus};
use epigraph_db::MassFunctionRepository;

/// Body of `POST /api/v1/mass-functions/:id/retract`.
#[derive(Debug, Deserialize)]
pub struct RetractBbaRequest {
    /// Why the BBA is retracted (1 to 2000 characters after trimming).
    pub reason: String,
}

/// What the retraction did.
#[derive(Debug, Serialize, Deserialize)]
pub struct RetractBbaResponse {
    pub mass_function_id: Uuid,
    pub claim_id: Uuid,
    pub frame_id: Uuid,
    /// `retracted` or `already_retracted`.
    pub status: String,
    /// `owner` or `admin`: which authority admitted the call.
    pub arm: String,
    pub retracted_at: chrono::DateTime<chrono::Utc>,
    pub retracted_by: Uuid,
    pub retract_reason: String,
    /// Whether the claim's cached belief was rewritten from the BBAs that
    /// remain. `false` on a repeat, and when no remaining BBA owns the cache.
    pub belief_recomputed: bool,
    /// Whether the claim's cache was set to the explicit vacuous value
    /// (Bel 0, Pl 1, BetP 0.5, `not_enough_info`) because no BBA remained to
    /// fold (ruling R-80). `false` on a repeat.
    pub belief_vacated: bool,
    /// Stored scoped beliefs of the BBA's (claim, frame) deleted as stale
    /// (they folded the retracted BBA); 0 on a repeat.
    pub scoped_beliefs_cleared: i64,
}

/// `POST /api/v1/mass-functions/:id/retract`. See the module doc.
///
/// # Errors
/// 401 without authentication; 403 without `claims:write` or without the
/// authority to retract; 404 for a missing or unreadable BBA; 400 for a bad
/// reason; 500 on a database failure (nothing is written).
pub async fn retract_bba(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(body): Json<RetractBbaRequest>,
) -> Result<Json<RetractBbaResponse>, ApiError> {
    let auth = auth_ctx
        .ok_or_else(|| ApiError::Unauthorized {
            reason: "POST /api/v1/mass-functions/:id/retract requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])?;
    // The definer re-checks the grant against the token's client record; the
    // scope alone admits nothing.
    let admin = auth
        .has_scope(epigraph_core::canonical_scopes::CLAIMS_ADMIN)
        .then_some(epigraph_db::AdminToken {
            client_id: auth.client_id,
            jti: auth.jti,
        });

    let mut tx = state.write_as(&viewer, "retract_bba").await?;
    let before = epigraph_engine::bba_retract::RetractCacheBefore::read(&mut tx, &viewer, id)
        .await
        .map_err(|message| ApiError::InternalError {
            message: format!("read before retraction: {message}"),
        })?;
    let out = MassFunctionRepository::retract_conn(&mut tx, id, &body.reason, admin)
        .await
        .map_err(|e| match e {
            BbaRetractError::NotFound(_) => ApiError::NotFound {
                entity: "MassFunction".to_string(),
                id: id.to_string(),
            },
            BbaRetractError::Forbidden(reason) => ApiError::Forbidden { reason },
            BbaRetractError::InvalidReason(reason) => ApiError::ValidationError {
                field: "reason".to_string(),
                reason,
            },
            BbaRetractError::Db(e) => ApiError::DatabaseError {
                message: e.to_string(),
            },
        })?;
    let cache = if out.status == BbaRetractStatus::Retracted {
        epigraph_engine::bba_retract::refresh_cache_after_retract(
            &mut tx,
            &viewer,
            out.claim_id,
            before,
        )
        .await
        .map_err(|message| ApiError::InternalError {
            message: format!("recompute after retraction: {message}"),
        })?
    } else {
        epigraph_engine::bba_retract::RetractCacheOutcome::default()
    };
    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit transaction: {e}"),
    })?;

    Ok(Json(RetractBbaResponse {
        mass_function_id: out.mass_function_id,
        claim_id: out.claim_id,
        frame_id: out.frame_id,
        status: out.status.as_str().to_string(),
        arm: out.arm.as_str().to_string(),
        retracted_at: out.retracted_at,
        retracted_by: out.retracted_by,
        retract_reason: out.retract_reason,
        belief_recomputed: cache.recomputed,
        belief_vacated: cache.vacated,
        scoped_beliefs_cleared: out.scoped_beliefs_cleared,
    }))
}

/// What the un-retraction did.
#[derive(Debug, Serialize, Deserialize)]
pub struct UnretractBbaResponse {
    pub mass_function_id: Uuid,
    pub claim_id: Uuid,
    pub frame_id: Uuid,
    /// `unretracted` or `not_retracted`.
    pub status: String,
    /// `owner` or `admin`: which authority admitted the call.
    pub arm: String,
    /// The caller, recorded as the un-retractor.
    pub unretracted_by: Uuid,
    pub reason: String,
    /// The retraction this call undid; `null` when nothing was retracted.
    pub previously_retracted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub previously_retracted_by: Option<Uuid>,
    pub previous_retract_reason: Option<String>,
    /// Whether the claim's cached belief was rewritten from the live BBAs,
    /// the un-retracted one included. `false` when nothing was retracted.
    pub belief_recomputed: bool,
    /// Stored scoped beliefs of the BBA's (claim, frame) deleted as stale
    /// (they did not fold the BBA, which folds again); 0 when nothing was
    /// retracted.
    pub scoped_beliefs_cleared: i64,
}

/// `POST /api/v1/mass-functions/:id/unretract`: make ONE retracted mass
/// function live again (operator ruling R-103), the only way back: a write to
/// a retracted BBA's key is refused (RT07). Same authority and the same
/// answers as the retraction (404 missing or unreadable, 403 not the caller's
/// to un-retract or no `claims:write`, 400 bad reason); 200 with `status:
/// "unretracted"` (one `security_events` row, `mass_functions.unretract`,
/// with the reason) or `"not_retracted"`, which writes nothing. The BBA folds
/// again with the masses it was retracted with; the claim's cached belief is
/// recomputed on the same transaction, and the stored scoped beliefs that
/// will fold it again are deleted as stale. The MCP twin is `unretract_bba`.
///
/// # Errors
/// As [`retract_bba`].
pub async fn unretract_bba(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(body): Json<RetractBbaRequest>,
) -> Result<Json<UnretractBbaResponse>, ApiError> {
    let auth = auth_ctx
        .ok_or_else(|| ApiError::Unauthorized {
            reason: "POST /api/v1/mass-functions/:id/unretract requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])?;
    // The definer re-checks the grant against the token's client record.
    let admin = auth
        .has_scope(epigraph_core::canonical_scopes::CLAIMS_ADMIN)
        .then_some(epigraph_db::AdminToken {
            client_id: auth.client_id,
            jti: auth.jti,
        });

    let mut tx = state.write_as(&viewer, "unretract_bba").await?;
    let out = MassFunctionRepository::unretract_conn(&mut tx, id, &body.reason, admin)
        .await
        .map_err(|e| match e {
            BbaRetractError::NotFound(_) => ApiError::NotFound {
                entity: "MassFunction".to_string(),
                id: id.to_string(),
            },
            BbaRetractError::Forbidden(reason) => ApiError::Forbidden { reason },
            BbaRetractError::InvalidReason(reason) => ApiError::ValidationError {
                field: "reason".to_string(),
                reason,
            },
            BbaRetractError::Db(e) => ApiError::DatabaseError {
                message: e.to_string(),
            },
        })?;
    let belief_recomputed = if out.status == BbaUnretractStatus::Unretracted {
        epigraph_engine::bba_retract::refresh_cache_after_unretract(&mut tx, &viewer, out.claim_id)
            .await
            .map_err(|message| ApiError::InternalError {
                message: format!("recompute after un-retraction: {message}"),
            })?
    } else {
        false
    };
    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit transaction: {e}"),
    })?;

    Ok(Json(UnretractBbaResponse {
        mass_function_id: out.mass_function_id,
        claim_id: out.claim_id,
        frame_id: out.frame_id,
        status: out.status.as_str().to_string(),
        arm: out.arm.as_str().to_string(),
        unretracted_by: out.unretracted_by,
        reason: out.reason,
        previously_retracted_at: out.previously_retracted_at,
        previously_retracted_by: out.previously_retracted_by,
        previous_retract_reason: out.previous_retract_reason,
        belief_recomputed,
        scoped_beliefs_cleared: out.scoped_beliefs_cleared,
    }))
}
