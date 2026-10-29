//! `retract_bba`: retract ONE mass function (BBA) (operator ruling R-79,
//! migration 184). The MCP twin of
//! `POST /api/v1/mass-functions/:id/retract`
//! (`epigraph-api/src/routes/bba_retract.rs`); both call
//! `MassFunctionRepository::retract_conn` and refresh the claim's cached
//! belief on the same transaction (`epigraph_engine::bba_retract`: refolded
//! from the BBAs that remain, or the explicit vacuous value when none does,
//! ruling R-80).
//!
//! The transaction is stamped from the calling agent's own write identity
//! (`EpiGraphMcpFull::write_identity`: the caller's OAuth agent over HTTP,
//! this server's own agent on stdio), so the retractor the database records is
//! always the caller. The database decides who may retract: a writer of the
//! BBA's owning group, or a caller whose token carries `claims:admin` and
//! whose client record still holds that grant (re-checked by the definer). A
//! BBA the caller cannot read is "not found", like a random id.
//!
//! `unretract_bba` (ruling R-103) is the only way a retracted BBA becomes live
//! again: a write to its key is refused (RT07). Same authority, audited
//! (`mass_functions.unretract`), HTTP twin
//! `POST /api/v1/mass-functions/:id/unretract`.

use rmcp::model::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use epigraph_db::repos::mass_function::{BbaRetractError, BbaRetractStatus, BbaUnretractStatus};
use epigraph_db::MassFunctionRepository;

/// Parameters of `retract_bba`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RetractBbaParams {
    #[schemars(description = "UUID of the mass function (BBA) row to retract")]
    pub mass_function_id: String,

    #[schemars(
        description = "Why the BBA is retracted (1 to 2000 characters after trimming); \
                       recorded on the row and in its audit record"
    )]
    pub reason: String,
}

/// What `retract_bba` did.
#[derive(Debug, Serialize)]
pub struct RetractBbaResponse {
    pub mass_function_id: uuid::Uuid,
    pub claim_id: uuid::Uuid,
    pub frame_id: uuid::Uuid,
    /// `retracted` or `already_retracted`.
    pub status: &'static str,
    /// `owner` or `admin`.
    pub arm: &'static str,
    pub retracted_at: chrono::DateTime<chrono::Utc>,
    pub retracted_by: uuid::Uuid,
    pub retract_reason: String,
    /// Whether the claim's cached belief was rewritten from the BBAs that
    /// remain.
    pub belief_recomputed: bool,
    /// Whether the claim's cache was set to the explicit vacuous value
    /// because no BBA remained to fold (ruling R-80).
    pub belief_vacated: bool,
    /// Stored scoped beliefs of the BBA's (claim, frame) deleted as stale
    /// (they folded the retracted BBA); 0 on a repeat.
    pub scoped_beliefs_cleared: i64,
}

/// Retract one BBA. See the module doc.
///
/// # Errors
/// invalid-params for a malformed id, a missing or unreadable BBA ("not
/// found"), a caller that may not retract it, or a bad reason (nothing is
/// written in any of these); internal for a database failure.
pub async fn retract_bba(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: RetractBbaParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.mass_function_id)?;
    let admin = auth
        .filter(|a| a.has_scope(crate::scope_map::CLAIMS_ADMIN))
        .map(|a| epigraph_db::AdminToken {
            client_id: a.client_id,
            jti: a.jti,
        });
    let author = server.write_identity(auth, viewer).await?;
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, author, "retract_bba").await?;
    let before = epigraph_engine::bba_retract::RetractCacheBefore::read(&mut tx, viewer, id)
        .await
        .map_err(internal_error)?;
    let out = MassFunctionRepository::retract_conn(&mut tx, id, &params.reason, admin)
        .await
        .map_err(|e| match e {
            BbaRetractError::NotFound(_) => invalid_params(format!("mass function {id} not found")),
            BbaRetractError::Forbidden(reason) => {
                invalid_params(format!("mass function {id}: {reason}"))
            }
            BbaRetractError::InvalidReason(reason) => invalid_params(reason),
            BbaRetractError::Db(e) => internal_error(e),
        })?;
    let cache = if out.status == BbaRetractStatus::Retracted {
        epigraph_engine::bba_retract::refresh_cache_after_retract(
            &mut tx,
            viewer,
            out.claim_id,
            before,
        )
        .await
        .map_err(internal_error)?
    } else {
        epigraph_engine::bba_retract::RetractCacheOutcome::default()
    };
    tx.commit().await.map_err(internal_error)?;

    let body = RetractBbaResponse {
        mass_function_id: out.mass_function_id,
        claim_id: out.claim_id,
        frame_id: out.frame_id,
        status: out.status.as_str(),
        arm: out.arm.as_str(),
        retracted_at: out.retracted_at,
        retracted_by: out.retracted_by,
        retract_reason: out.retract_reason,
        belief_recomputed: cache.recomputed,
        belief_vacated: cache.vacated,
        scoped_beliefs_cleared: out.scoped_beliefs_cleared,
    };
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&body).map_err(internal_error)?,
    )]))
}

/// Parameters of `unretract_bba`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UnretractBbaParams {
    #[schemars(description = "UUID of the retracted mass function (BBA) row to make live again")]
    pub mass_function_id: String,

    #[schemars(
        description = "Why the BBA is un-retracted (1 to 2000 characters after trimming); \
                       recorded in its audit record"
    )]
    pub reason: String,
}

/// What `unretract_bba` did.
#[derive(Debug, Serialize)]
pub struct UnretractBbaResponse {
    pub mass_function_id: uuid::Uuid,
    pub claim_id: uuid::Uuid,
    pub frame_id: uuid::Uuid,
    /// `unretracted` or `not_retracted`.
    pub status: &'static str,
    /// `owner` or `admin`.
    pub arm: &'static str,
    pub unretracted_by: uuid::Uuid,
    pub reason: String,
    /// The retraction this call undid; `null` when nothing was retracted.
    pub previously_retracted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub previously_retracted_by: Option<uuid::Uuid>,
    pub previous_retract_reason: Option<String>,
    /// Whether the claim's cached belief was rewritten from the live BBAs,
    /// the un-retracted one included.
    pub belief_recomputed: bool,
    /// Stored scoped beliefs of the BBA's (claim, frame) deleted as stale; 0
    /// when nothing was retracted.
    pub scoped_beliefs_cleared: i64,
}

/// Un-retract one BBA (operator ruling R-103): the MCP twin of
/// `POST /api/v1/mass-functions/:id/unretract`. Same write identity, same
/// authority and the same refusals as [`retract_bba`]; the claim's cached
/// belief is recomputed on the same transaction
/// (`epigraph_engine::bba_retract::refresh_cache_after_unretract`).
///
/// # Errors
/// As [`retract_bba`].
pub async fn unretract_bba(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: UnretractBbaParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.mass_function_id)?;
    let admin = auth
        .filter(|a| a.has_scope(crate::scope_map::CLAIMS_ADMIN))
        .map(|a| epigraph_db::AdminToken {
            client_id: a.client_id,
            jti: a.jti,
        });
    let author = server.write_identity(auth, viewer).await?;
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, author, "unretract_bba").await?;
    let out = MassFunctionRepository::unretract_conn(&mut tx, id, &params.reason, admin)
        .await
        .map_err(|e| match e {
            BbaRetractError::NotFound(_) => invalid_params(format!("mass function {id} not found")),
            BbaRetractError::Forbidden(reason) => {
                invalid_params(format!("mass function {id}: {reason}"))
            }
            BbaRetractError::InvalidReason(reason) => invalid_params(reason),
            BbaRetractError::Db(e) => internal_error(e),
        })?;
    let belief_recomputed = if out.status == BbaUnretractStatus::Unretracted {
        epigraph_engine::bba_retract::refresh_cache_after_unretract(&mut tx, viewer, out.claim_id)
            .await
            .map_err(internal_error)?
    } else {
        false
    };
    tx.commit().await.map_err(internal_error)?;

    let body = UnretractBbaResponse {
        mass_function_id: out.mass_function_id,
        claim_id: out.claim_id,
        frame_id: out.frame_id,
        status: out.status.as_str(),
        arm: out.arm.as_str(),
        unretracted_by: out.unretracted_by,
        reason: out.reason,
        previously_retracted_at: out.previously_retracted_at,
        previously_retracted_by: out.previously_retracted_by,
        previous_retract_reason: out.previous_retract_reason,
        belief_recomputed,
        scoped_beliefs_cleared: out.scoped_beliefs_cleared,
    };
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&body).map_err(internal_error)?,
    )]))
}
