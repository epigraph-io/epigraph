//! Proposing admin acts and listing one's own (elevation plan EL-12b;
//! operator rulings D2, D5 and OQ-1 (b)).
//!
//! # The life of an act
//!
//! 1. **Propose** (`POST /api/v1/admin/acts`, this module): an ELEVATED
//!    request names the act's kind, its args and a reason. Migration 130's
//!    `epigraph_propose_admin_act` refuses a connection that is not elevated
//!    (ELV07), canonicalizes the args, stores their SHA-256 and binds the act
//!    to the proposer's live elevation. The response is the act id and its
//!    confirmation page.
//! 2. **Confirm** (`/elevate/act/:id`, `routes/elevate.rs`): the proposer
//!    opens the page on the device that holds the passkey; the WebAuthn
//!    challenge commits to the act's id and stored args digest, and only a
//!    live passkey of the proposer confirms it.
//! 3. **Execute** (operator ruling OQ-1 (b)): the maintenance CLI's verb with
//!    `--act <id>` (`grant-role`, `end-role-assignment`,
//!    `custodial-supersede`, `passkey-enroll`) recomputes the args from its own
//!    flags, writes on the maintenance DSN and consumes the act inside the
//!    write. Nothing here executes an act.
//!
//! # Why the proposal is the one write an elevated token makes through a route
//!
//! An elevated request is read-only (`middleware::elevated_access`): every
//! non-GET request whose token carries an elevation claim is refused unless
//! it is on `ELEVATED_NON_GET_ALLOWLIST`. `POST /api/v1/admin/acts` is on it,
//! and is the only entry there that writes: through 130's elevation-gated
//! definer only, into `pending_admin_acts`, a table migration 126 does not
//! arm, and only an authority record that asks for a passkey confirmation
//! (`epigraph_db::ScopedPool::propose_admin_act`). It IS resolved as elevated
//! and recorded in the per-access log like every other elevated request.
//!
//! # Listing (`GET /api/v1/admin/acts?mine`)
//!
//! Migration 131's principal-bound reader: the caller's OWN acts, newest
//! first, elevated or not; never anyone else's, and never the ceremony state
//! or the assertion evidence.
//!
//! # Not configured
//!
//! With no WebAuthn relying party configured no act could ever be confirmed,
//! so proposing answers 503 (fail closed). Listing is always served.

use std::collections::HashMap;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::{AuthContext, ViewerExtractor};
use crate::state::AppState;

/// The longest reason accepted, in characters (the elevation ticket's bound):
/// it is shown on the confirmation page and kept in the audit trail.
pub const MAX_REASON_CHARS: usize = 500;

/// `POST /api/v1/admin/acts` request.
#[derive(Debug, Deserialize)]
pub struct ProposeRequest {
    /// `role.grant`, `role.end`, `claim.custodial_supersede` or
    /// `passkey.register` (migration 130's closed list; the database refuses
    /// anything else).
    pub kind: String,
    /// The act's args (migration 130 names each kind's exact keys).
    pub args: serde_json::Value,
    /// Why: shown on the confirmation page and kept on the act.
    pub reason: String,
}

/// `POST /api/v1/admin/acts` response.
#[derive(Debug, Serialize)]
pub struct ProposeResponse {
    /// The act.
    pub act_id: Uuid,
    /// Its confirmation page's path.
    pub path: String,
    /// Its confirmation page on this relying party's origin: open it on the
    /// device that holds your passkey.
    pub url: String,
}

/// One listed act, with its confirmation page's path.
#[derive(Debug, Serialize)]
pub struct ListedAct {
    /// The act as its proposer sees it.
    #[serde(flatten)]
    pub act: epigraph_db::ProposedAct,
    /// Its confirmation page's path (live only while it is unasserted and
    /// unexpired).
    pub path: String,
}

/// `GET /api/v1/admin/acts` response.
#[derive(Debug, Serialize)]
pub struct ListResponse {
    /// The caller's own acts, newest first.
    pub acts: Vec<ListedAct>,
}

/// The confirmation page's path for `act`.
#[must_use]
pub fn act_path(act: Uuid) -> String {
    format!("/elevate/act/{act}")
}

/// The SQLSTATE a definer raised, and its message, when the error carries one.
fn db_refusal(e: &epigraph_db::DbError) -> Option<(String, String)> {
    match e {
        epigraph_db::DbError::QueryFailed { source } => source
            .as_database_error()
            .and_then(|d| d.code().map(|c| (c.to_string(), d.message().to_string()))),
        _ => None,
    }
}

fn internal(handler: &'static str, what: &str, e: &dyn std::fmt::Display) -> ApiError {
    tracing::error!(target: "elevation.act", handler, error = %e, "{what}");
    ApiError::InternalError {
        message: format!("admin acts: could not {what}"),
    }
}

/// `POST /api/v1/admin/acts`: propose an admin act, as the elevated caller.
///
/// # Errors
/// 503 with no relying party configured; 400 for a missing or overlong
/// reason, or args the kind does not take (22023); 403 when the request is
/// not elevated (ELV07).
pub async fn propose_act(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    ViewerExtractor(viewer): ViewerExtractor,
    Json(req): Json<ProposeRequest>,
) -> Result<(StatusCode, Json<ProposeResponse>), ApiError> {
    let Some(rp) = state.passkeys.as_ref() else {
        return Err(ApiError::ServiceUnavailable {
            service: "admin acts: this server has no WebAuthn relying party configured, so no \
                      act could be confirmed"
                .into(),
        });
    };
    let reason = req.reason.trim();
    if reason.is_empty() {
        return Err(ApiError::BadRequest {
            message: "a reason is required".into(),
        });
    }
    if reason.chars().count() > MAX_REASON_CHARS {
        return Err(ApiError::BadRequest {
            message: format!("the reason is longer than {MAX_REASON_CHARS} characters"),
        });
    }
    let scoped = state.scoped.as_ref().ok_or_else(|| {
        internal(
            "admin_acts::propose_act",
            "find a tenancy-aware pool",
            &"this process was not built from a ScopedPool",
        )
    })?;
    let jti = auth.jti.to_string();
    let act = match scoped
        .propose_admin_act(&viewer, &req.kind, &req.args, reason, Some(&jti))
        .await
    {
        Ok(id) => id,
        Err(e) => {
            return Err(match db_refusal(&e) {
                Some((code, _)) if code == "ELV07" => {
                    tracing::info!(
                        target: "elevation.act",
                        principal = ?auth.agent_id,
                        "admin act refused: the request is not elevated (ELV07)"
                    );
                    ApiError::Forbidden {
                        reason: "an admin act is proposed only by an ELEVATED request: open \
                                 an elevation ticket (POST /api/v1/elevation/tickets), confirm \
                                 it with your passkey, redeem it at /oauth/token, and propose \
                                 with that token"
                            .into(),
                    }
                }
                Some((code, message)) if code == "22023" || code == "22004" => {
                    ApiError::BadRequest { message }
                }
                _ => internal("admin_acts::propose_act", "propose the act", &e),
            })
        }
    };
    let path = act_path(act);
    tracing::info!(
        target: "elevation.act",
        act = %act,
        kind = %req.kind,
        principal = ?auth.agent_id,
        "admin act proposed"
    );
    Ok((
        StatusCode::CREATED,
        Json(ProposeResponse {
            act_id: act,
            url: format!(
                "{}{path}",
                rp.config().origin.as_str().trim_end_matches('/')
            ),
            path,
        }),
    ))
}

/// `GET /api/v1/admin/acts?mine`: the caller's own acts, newest first
/// (`limit`, 1..=200, default 50). Only the caller's own are ever listed:
/// `mine` may be given (`?mine`, `?mine=true`) and anything else for it is
/// refused.
///
/// # Errors
/// 400 for `mine` other than true, or a `limit` that is not a number.
pub async fn list_acts(
    State(state): State<AppState>,
    ViewerExtractor(viewer): ViewerExtractor,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<ListResponse>, ApiError> {
    if let Some(mine) = query.get("mine") {
        if !matches!(mine.as_str(), "" | "true" | "1") {
            return Err(ApiError::BadRequest {
                message: "only your own acts are listed (`?mine`)".into(),
            });
        }
    }
    let limit = match query.get("limit") {
        None => None,
        Some(l) => Some(l.parse::<i32>().map_err(|_| ApiError::BadRequest {
            message: "limit must be a number".into(),
        })?),
    };
    let mut read = state
        .read_as(&viewer)
        .await
        .map_err(|e| internal("admin_acts::list_acts", "acquire a stamped connection", &e))?;
    let acts = epigraph_db::AdminActCeremony::list_mine(&mut read, limit)
        .await
        .map_err(|e| internal("admin_acts::list_acts", "list the acts", &e))?;
    read.commit()
        .await
        .map_err(|e| internal("admin_acts::list_acts", "finish the read", &e))?;
    Ok(Json(ListResponse {
        acts: acts
            .into_iter()
            .map(|act| ListedAct {
                path: act_path(act.id),
                act,
            })
            .collect(),
    }))
}
