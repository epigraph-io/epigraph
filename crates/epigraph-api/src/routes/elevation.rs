//! The authenticated half of elevation (elevation plan EL-5; operator rulings
//! D2 and D5): asking for an elevation ticket, and ending an elevation.
//!
//! # Who may ask (D2)
//!
//! `POST /api/v1/elevation/tickets` takes a HUMAN token that names its refresh
//! family (`fam`, minted by every grant that issues a human a refresh token).
//! It calls migration 125's principal-bound `epigraph_create_elevation_ticket`
//! on a connection stamped with the caller's viewer, so the ticket is always
//! the CALLER's, and the database refuses (ELV02) anyone who is not a
//! registered human holding a LIVE assignment of an elevating role, with a
//! live passkey, on a live family of its own human client. `instance_admins`
//! is never consulted; an agent never holds a role, so it never gets a ticket.
//! This module adds no rule of its own beyond "the token names a family".
//!
//! # What the caller gets
//!
//! A GRANT-mode ticket (MCP's connector mode is `sudo`'s, a later batch): the
//! ceremony page's path, which the human opens on the device that holds the
//! passkey, and a redeem secret shown ONCE (the database keeps its SHA-256).
//! The caller then polls the token endpoint with
//! `grant_type=urn:epigraph:grant:elevate`, the ticket id, the secret and its
//! `client_id` (returned here, because a per-user client's identifier is not
//! otherwise in a CLI's hands): `authorization_pending` until the ceremony
//! lands, then one short, refreshless, elevated access token.
//!
//! # Not configured
//!
//! With no WebAuthn relying party configured (`AppState::passkeys` is `None`)
//! no ceremony could ever complete, so ticket creation answers 503: fail
//! closed. Ending an elevation is always served.

use axum::{body::Bytes, extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::{AuthContext, ViewerExtractor};
use crate::state::AppState;

/// The token endpoint's grant type that redeems a confirmed grant-mode ticket.
pub use crate::oauth::token::ELEVATE_GRANT_TYPE;

/// The longest reason accepted, in characters. It is shown on the ceremony
/// page and kept in the audit trail; a paragraph is plenty.
pub const MAX_REASON_CHARS: usize = 500;

/// How long a ticket stays live (migration 125: `elevation_tickets_ttl`).
const TICKET_TTL_SECS: i64 = 300;

/// `POST /api/v1/elevation/tickets` request.
#[derive(Debug, Deserialize)]
pub struct CreateTicketRequest {
    /// Why the caller wants to elevate: shown on the ceremony page and kept on
    /// the ticket, the session and their audit rows.
    pub reason: String,
}

/// `POST /api/v1/elevation/tickets` response. The redeem secret is shown here
/// once and never again.
#[derive(Serialize)]
pub struct CreateTicketResponse {
    /// The ticket.
    pub ticket_id: Uuid,
    /// The ceremony page, relative to this server's public origin.
    pub path: String,
    /// The secret the token endpoint's elevate grant takes (hex).
    pub redeem_secret: String,
    /// The `client_id` to present with it: the caller's own client.
    pub client_id: String,
    /// The grant type to redeem with.
    pub grant_type: &'static str,
    /// Seconds until the ticket stops being live if no ceremony lands.
    pub expires_in: i64,
}

impl std::fmt::Debug for CreateTicketResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateTicketResponse")
            .field("ticket_id", &self.ticket_id)
            .field("path", &self.path)
            .field("redeem_secret", &"<redacted>")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// `POST /api/v1/elevation/end` request: which session to end. Absent, the
/// session the presenting token names (`elv`).
#[derive(Debug, Default, Deserialize)]
pub struct EndRequest {
    /// The session to end.
    pub elevation_id: Option<Uuid>,
}

/// `POST /api/v1/elevation/end` response.
#[derive(Debug, Serialize)]
pub struct EndResponse {
    /// Whether a live session of the caller's was ended. `false` for an
    /// unknown session, someone else's, or one already ended: no oracle.
    pub ended: bool,
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

fn scoped<'a>(
    state: &'a AppState,
    handler: &'static str,
) -> Result<&'a epigraph_db::ScopedPool, ApiError> {
    state.scoped.as_ref().ok_or_else(|| {
        tracing::error!(
            target: "tenancy.scoped_write",
            handler,
            "refused: this process was not built from a ScopedPool"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped transaction".to_string(),
        }
    })
}

/// The caller's PLAIN scoped viewer, for the two routes that act on the
/// caller's elevation (EL-6). An elevated request gets no write transaction,
/// and these routes write: asking for a ticket and ending a session are the
/// principal's acts, not the elevation's (both definers are bound to the
/// stamped principal only), so they stamp the principal's own scoped viewer.
/// That is what lets an elevated token end its own session.
fn as_principal(viewer: &epigraph_db::Viewer) -> Result<epigraph_db::Viewer, ApiError> {
    viewer.detach_scoped().ok_or_else(|| ApiError::Forbidden {
        reason: "elevation: this request has no principal to act as".into(),
    })
}

fn internal(handler: &'static str, what: &str, e: &dyn std::fmt::Display) -> ApiError {
    tracing::error!(target: "elevation", handler, error = %e, "{what}");
    ApiError::InternalError {
        message: format!("elevation: could not {what}"),
    }
}

/// `POST /api/v1/elevation/tickets`: open a grant-mode elevation ticket for
/// the caller.
///
/// # Errors
/// 503 with no relying party configured; 403 for a token that names no
/// refresh family, and for a principal the database refuses (ELV02); 400 for
/// a missing or overlong reason; 409 when the family is already elevated
/// (ELV06).
pub async fn create_ticket(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    ViewerExtractor(viewer): ViewerExtractor,
    Json(req): Json<CreateTicketRequest>,
) -> Result<(StatusCode, Json<CreateTicketResponse>), ApiError> {
    use sha2::Digest;

    if state.passkeys.is_none() {
        return Err(ApiError::ServiceUnavailable {
            service: "elevation: this server has no WebAuthn relying party configured".into(),
        });
    }
    let family = auth.family_id.ok_or_else(|| ApiError::Forbidden {
        reason: "this token names no refresh family: elevation needs a human token minted \
                 together with a refresh token (code exchange, external sign-in or refresh)"
            .into(),
    })?;
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

    let secret: [u8; 32] = rand::random();
    let redeem_hash: [u8; 32] = sha2::Sha256::digest(secret).into();

    let mut tx = scoped(&state, "elevation::create_ticket")?
        .begin_as(&as_principal(&viewer)?)
        .await
        .map_err(|e| {
            internal(
                "elevation::create_ticket",
                "begin a stamped transaction",
                &e,
            )
        })?;
    let client = epigraph_db::OAuthClientRepository::get_by_id_conn(&mut tx, auth.client_id)
        .await
        .map_err(|e| internal("elevation::create_ticket", "read the caller's client", &e))?
        .ok_or_else(|| ApiError::Forbidden {
            reason: "the token's client no longer exists".into(),
        })?;
    let ticket = match epigraph_db::ElevationCeremony::create_ticket(
        &mut tx,
        auth.client_id,
        family,
        reason,
        epigraph_db::TicketMode::Grant { redeem_hash },
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            return Err(match db_refusal(&e) {
                Some((code, message)) if code == "ELV02" => {
                    tracing::info!(
                        target: "elevation",
                        principal = ?auth.agent_id,
                        client = %auth.client_id,
                        "elevation ticket refused (ELV02)"
                    );
                    ApiError::Forbidden {
                        reason: format!("elevation refused: {message}"),
                    }
                }
                Some((code, _)) if code == "ELV06" => ApiError::Conflict {
                    reason: "this refresh family is already elevated; end it first \
                             (POST /api/v1/elevation/end)"
                        .into(),
                },
                Some((code, message)) if code == "22004" => ApiError::BadRequest { message },
                _ => internal("elevation::create_ticket", "open the ticket", &e),
            })
        }
    };
    tx.commit()
        .await
        .map_err(|e| internal("elevation::create_ticket", "commit the ticket", &e))?;
    tracing::info!(
        target: "elevation",
        ticket = %ticket,
        principal = ?auth.agent_id,
        client = %auth.client_id,
        "elevation ticket opened (grant mode)"
    );
    Ok((
        StatusCode::CREATED,
        Json(CreateTicketResponse {
            ticket_id: ticket,
            path: format!("/elevate/{ticket}"),
            redeem_secret: hex::encode(secret),
            client_id: client.client_id,
            grant_type: ELEVATE_GRANT_TYPE,
            expires_in: TICKET_TTL_SECS,
        }),
    ))
}

/// `POST /api/v1/elevation/end`: end one of the caller's elevations now. The
/// body may name the session (`{"elevation_id": ...}`); with no body, the
/// session the presenting token names (`elv`). The database ends only the
/// stamped principal's own live session.
///
/// # Errors
/// 400 when neither the body nor the token names a session.
pub async fn end_elevation(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    ViewerExtractor(viewer): ViewerExtractor,
    body: Bytes,
) -> Result<Json<EndResponse>, ApiError> {
    let req: EndRequest = if body.iter().all(u8::is_ascii_whitespace) {
        EndRequest::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| ApiError::BadRequest {
            message: format!("invalid JSON body: {e}"),
        })?
    };
    let session =
        req.elevation_id
            .or(auth.elevation_claim)
            .ok_or_else(|| ApiError::BadRequest {
                message: "name the elevation to end (elevation_id), or present the elevated token"
                    .into(),
            })?;
    let mut tx = scoped(&state, "elevation::end_elevation")?
        .begin_as(&as_principal(&viewer)?)
        .await
        .map_err(|e| {
            internal(
                "elevation::end_elevation",
                "begin a stamped transaction",
                &e,
            )
        })?;
    let ended =
        epigraph_db::ElevationCeremony::end(&mut tx, session, epigraph_db::EndReason::Ended)
            .await
            .map_err(|e| internal("elevation::end_elevation", "end the elevation", &e))?;
    tx.commit()
        .await
        .map_err(|e| internal("elevation::end_elevation", "commit the end", &e))?;
    tracing::info!(
        target: "elevation",
        session = %session,
        principal = ?auth.agent_id,
        ended,
        "elevation end requested"
    );
    Ok(Json(EndResponse { ended }))
}
