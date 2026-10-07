//! The two passkey ceremonies served by the API itself: registering a passkey
//! (elevation plan EL-3; operator ruling D5) and confirming an elevation with
//! one (EL-5; ruling D2).
//!
//! # Enrollment: `/elevate/enroll/:id`
//!
//! `epigraph-operator passkey-enroll` opens an enrollment ticket on the
//! maintenance DSN and prints its path, `/elevate/enroll/<id>`. The operator
//! opens that page on the device that holds the authenticator; the page asks
//! the browser to create a credential (user verification required) and posts
//! it back; this module verifies it with `epigraph-passkey` and records it
//! through migration 124's completion definer.
//!
//! # Elevation: `/elevate/:ticket`
//!
//! `POST /api/v1/elevation/tickets` (`routes/elevation.rs`) opens a ticket for
//! a human holding a live elevating-role assignment. Its page shows what is
//! being confirmed (the reason, the client, the refresh family, the expiry);
//! the challenge allows only the TICKET person's live passkeys, with user
//! verification required; the assertion is verified with the library against
//! those passkeys and handed to migration 125's confirm definer, which opens
//! the session (at most 15 minutes) or RETURNS an audited refusal. The
//! signature counter is the definer's to check (under its row lock, with an
//! audit row), not the library's: the challenge is started with
//! `Passkeys::start_authentication_deferring_counter`.
//!
//! An assertion naming a credential that is NOT one of the ticket person's
//! live passkeys (unknown, another person's: the confused deputy, or revoked)
//! cannot be verified here (no key is served for it), and is still handed to
//! the definer so the refusal is audited (`platform.elevation_refused`) and the
//! ticket burned: its evidence is marked unverified (the offline verifier
//! flags it by design), and it runs in a transaction that is ROLLED BACK if the
//! definer would ever confirm it, so an unverified assertion never opens a
//! session. A malformed body, or an assertion by a live credential the library
//! refuses (signature, origin, user verification), is a 400 that leaves the
//! ticket live for a retry.
//!
//! # Admin acts: `/elevate/act/:id` (EL-12b)
//!
//! `POST /api/v1/admin/acts` (`routes/admin_acts.rs`) records an act an
//! elevated person proposed. Its page shows the act's kind, its STORED
//! canonical args, their digest, the reason and the verb that will execute
//! it. The challenge COMMITS TO THE ACT (elevation plan §1.6):
//! `epigraph_passkey::act_challenge(act id, stored args digest, server
//! nonce)`, the nonce stored beside the library's state. At the assertion the
//! handler recomputes that challenge from the act id, the digest the act
//! definer returns and the stored nonce, and refuses (409
//! `challenge_not_bound`, the act left live) a stored state whose challenge
//! is anything else, BEFORE it looks at the assertion: a state copied from
//! another act's ceremony (the application DSN can write it) cannot carry a
//! confirmation over. Only the PROPOSER's live passkeys are allowed; the rest
//! is the ticket assertion's rules, through migration 130's act definers.
//! Confirming executes nothing: the maintenance CLI's `--act` does.
//!
//! # Unauthenticated by design
//!
//! These routes are on the PUBLIC router (`tests/public_router_allowlist.rs`
//! names each with its reason). The page has no bearer token to present: the
//! id in its URL (a random UUID, live for at most 15 minutes for an
//! enrollment and 5 for a ticket, used once) and the authenticator are its
//! credentials (an act's: at most 30 minutes, asserted once). Every handler
//! reads through the ceremony definers, keyed by that id, on an UNSTAMPED
//! application connection; none enumerates anything.
//!
//! # What the pages are careful about
//!
//! * Every string from the database (the reason, the label, the client name)
//!   is HTML-escaped.
//! * A strict Content-Security-Policy ([`CSP`]): no inline script or style, no
//!   framing, no form posts; the scripts and stylesheet are served from this
//!   binary (`include_str!`).
//! * The URL carries the capability, so every response says
//!   `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
//!
//! # Not configured
//!
//! With no relying party configured (`AppState::passkeys` is `None`), every
//! route here answers 503: fail closed, never a default rp id.

// UNSCOPED-POOL-EXEMPT: Pre-authentication. The ceremony pages are anonymous by
// design (the enrollment or ticket id and the authenticator are their
// credentials), so no principal exists to stamp a connection from; each site
// calls one of migration 124's, 125's or 130's ceremony definers keyed by that
// id, which need no stamp.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use epigraph_db::{
    ActConfirmation, AdminActCeremony, AssertedCredential, CeremonyAct, CeremonyEnrollment,
    CeremonyTicket, Confirmation, DbError, ElevationCeremony, PasskeyCeremony, VerifiedPasskey,
};
use epigraph_passkey::{
    act_challenge as act_challenge_of, AuthenticationState, PasskeyError, Passkeys,
    RegistrationState, StoredPasskey, ACT_NONCE_LEN,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::state::AppState;

/// The ceremony pages' Content-Security-Policy.
///
/// The elevation plan's policy (§1.3) plus two directives: `style-src 'self'`
/// (the stylesheet is served from this binary; with `default-src 'none'` it
/// would otherwise be blocked) and `form-action 'none'` (the page has no form).
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
     connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

/// The enrollment page's script, served at [`ENROLL_JS_PATH`].
pub const ENROLL_JS: &str = include_str!("elevate/enroll.js");
/// The elevation page's script, served at [`ELEVATE_JS_PATH`].
pub const ELEVATE_JS: &str = include_str!("elevate/elevate.js");
/// The ceremony pages' stylesheet, served at [`CSS_PATH`].
pub const CSS: &str = include_str!("elevate/elevate.css");
/// Where the enrollment script is served.
pub const ENROLL_JS_PATH: &str = "/elevate/assets/enroll.js";
/// Where the elevation script is served.
pub const ELEVATE_JS_PATH: &str = "/elevate/assets/elevate.js";
/// Where the stylesheet is served.
pub const CSS_PATH: &str = "/elevate/assets/elevate.css";

/// `s` escaped for HTML text and double-quoted attribute values.
#[must_use]
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// The headers every ceremony response carries.
fn harden(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    resp
}

fn json_error(status: StatusCode, error: &str, detail: impl Into<String>) -> Response {
    harden(
        (
            status,
            Json(json!({ "error": error, "detail": detail.into() })),
        )
            .into_response(),
    )
}

fn not_configured() -> Response {
    json_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "passkeys_not_configured",
        "this server has no WebAuthn relying party configured",
    )
}

fn not_live() -> Response {
    json_error(
        StatusCode::NOT_FOUND,
        "enrollment_not_live",
        "no live enrollment with this id: it is unknown, expired or already used; ask the \
         operator for a new one",
    )
}

fn internal(what: &str, e: &dyn std::fmt::Display) -> Response {
    tracing::error!(target: "elevate.enroll", error = %e, "{what}");
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "the enrollment could not be processed",
    )
}

/// The SQLSTATE a definer raised, when the error carries one.
fn sqlstate(e: &DbError) -> Option<String> {
    match e {
        DbError::QueryFailed { source } => source
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .map(|c| c.to_string()),
        _ => None,
    }
}

fn passkeys(state: &AppState) -> Option<Arc<Passkeys>> {
    state.passkeys.clone()
}

/// Read the live enrollment `id` on an unstamped application connection. The
/// refusal is the response to send, boxed (a `Response` is large).
async fn live(state: &AppState, id: Uuid) -> Result<CeremonyEnrollment, Box<Response>> {
    let mut conn = state
        .db_pool
        .acquire()
        .await
        .map_err(|e| Box::new(internal("acquire", &e)))?;
    match PasskeyCeremony::live_enrollment(&mut conn, id).await {
        Ok(Some(e)) => Ok(e),
        Ok(None) => Err(Box::new(not_live())),
        Err(e) => Err(Box::new(internal("read the enrollment", &e))),
    }
}

/// The name an authenticator shows for the credential.
fn user_name(e: &CeremonyEnrollment) -> String {
    e.label
        .as_deref()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map_or_else(|| "EpiGraph operator".to_string(), str::to_string)
}

/// The enrollment page.
fn render_page(id: Uuid, e: &CeremonyEnrollment) -> String {
    let label = e
        .label
        .as_deref()
        .map_or_else(|| "(none)".to_string(), html_escape);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Register a passkey</title>
<link rel="stylesheet" href="{css}">
</head>
<body>
<main id="ceremony" data-enrollment="{id}">
<h1>Register a passkey</h1>
<p>An operator opened this enrollment. Registering adds a passkey for the
principal below, which elevation and administrative confirmations will ask
for. Your authenticator will ask you to verify yourself (PIN or biometric).</p>
<dl>
<dt>Principal</dt><dd><code>{person}</code></dd>
<dt>Reason</dt><dd id="reason">{reason}</dd>
<dt>Passkey name</dt><dd>{label}</dd>
<dt>Expires</dt><dd>{expires}</dd>
</dl>
<p>Only continue if you expected this, on the device that holds your
authenticator.</p>
<button id="register" type="button">Register passkey</button>
<p id="status" role="status" aria-live="polite"></p>
</main>
<script src="{js}"></script>
</body>
</html>
"#,
        css = CSS_PATH,
        js = ENROLL_JS_PATH,
        id = id,
        person = e.person_agent_id,
        reason = html_escape(&e.reason),
        label = label,
        expires = e.expires_at.format("%Y-%m-%d %H:%M:%S UTC"),
    )
}

/// `GET /elevate/enroll/:id`: the enrollment page.
pub async fn enroll_page(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    if passkeys(&state).is_none() {
        return not_configured();
    }
    let e = match live(&state, id).await {
        Ok(e) => e,
        Err(resp) => return *resp,
    };
    let mut resp = (StatusCode::OK, render_page(id, &e)).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    harden(resp)
}

/// `POST /elevate/enroll/:id/challenge`: start (or restart) the ceremony.
pub async fn enroll_challenge(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    let Some(rp) = passkeys(&state) else {
        return not_configured();
    };
    let e = match live(&state, id).await {
        Ok(e) => e,
        Err(resp) => return *resp,
    };
    let name = user_name(&e);
    let (options, ceremony) = match rp.start_registration(e.person_agent_id, &name, &name) {
        Ok(v) => v,
        Err(err) => return internal("start the registration", &err),
    };
    let mut conn = match state.db_pool.acquire().await {
        Ok(c) => c,
        Err(err) => return internal("acquire", &err),
    };
    match PasskeyCeremony::store_challenge(&mut conn, id, &ceremony.to_json()).await {
        Ok(()) => harden((StatusCode::OK, Json(options)).into_response()),
        Err(err) if sqlstate(&err).as_deref() == Some("ELV04") => not_live(),
        Err(err) => internal("store the challenge", &err),
    }
}

/// `POST /elevate/enroll/:id/finish`: verify the authenticator's response and
/// record the passkey.
pub async fn enroll_finish(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    let Some(rp) = passkeys(&state) else {
        return not_configured();
    };
    let e = match live(&state, id).await {
        Ok(e) => e,
        Err(resp) => return *resp,
    };
    let Some(stored) = e.challenge_state.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            "no_ceremony_started",
            "request a challenge for this enrollment first",
        );
    };
    let response: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "malformed_response",
                err.to_string(),
            )
        }
    };
    let registered = match rp.finish_registration(&response, &RegistrationState::from_json(stored))
    {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(
                target: "elevate.enroll",
                enrollment = %id,
                error = %err,
                "passkey registration refused"
            );
            let code = match err {
                PasskeyError::UserNotVerified => "user_not_verified",
                PasskeyError::State(_) => "ceremony_state_unusable",
                PasskeyError::Malformed { .. } => "malformed_response",
                _ => "registration_refused",
            };
            return json_error(StatusCode::BAD_REQUEST, code, err.to_string());
        }
    };
    let mut conn = match state.db_pool.acquire().await {
        Ok(c) => c,
        Err(err) => return internal("acquire", &err),
    };
    let verified = VerifiedPasskey {
        credential_id: &registered.credential_id,
        passkey: &registered.passkey,
        aaguid: registered.aaguid,
        attestation_format: &registered.attestation_format,
        user_verified: registered.user_verified,
        backup_eligible: registered.backup_eligible,
    };
    match PasskeyCeremony::complete(&mut conn, id, verified).await {
        Ok(passkey_id) => {
            tracing::info!(
                target: "elevate.enroll",
                enrollment = %id,
                passkey = %passkey_id,
                aaguid = %registered.aaguid,
                format = %registered.attestation_format,
                "passkey registered"
            );
            harden(
                (
                    StatusCode::OK,
                    Json(json!({
                        "passkey_id": passkey_id,
                        "aaguid": registered.aaguid,
                        "attestation_format": registered.attestation_format,
                    })),
                )
                    .into_response(),
            )
        }
        Err(DbError::DuplicateKey { .. }) => json_error(
            StatusCode::CONFLICT,
            "credential_already_registered",
            "this authenticator credential is already registered",
        ),
        Err(err) => match sqlstate(&err).as_deref() {
            Some("ELV04") => not_live(),
            Some("ELV01") => json_error(
                StatusCode::FORBIDDEN,
                "subject_not_eligible",
                "the principal of this enrollment may no longer hold a passkey",
            ),
            _ => internal("record the passkey", &err),
        },
    }
}

// =====================================================================
// The elevation ceremony (EL-5): `/elevate/:ticket`
// =====================================================================

fn ticket_not_live() -> Response {
    json_error(
        StatusCode::NOT_FOUND,
        "ticket_not_live",
        "no live elevation ticket with this id: it is unknown, expired or already used; ask \
         for a new one",
    )
}

/// An unstamped application connection for a ceremony definer.
async fn ceremony_conn(
    state: &AppState,
) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>, Box<Response>> {
    state
        .db_pool
        .acquire()
        .await
        .map_err(|e| Box::new(internal("acquire", &e)))
}

/// Read the live ticket `id`. The refusal is the response to send, boxed.
async fn live_ticket(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
) -> Result<CeremonyTicket, Box<Response>> {
    match ElevationCeremony::live_ticket(conn, id).await {
        Ok(Some(t)) => Ok(t),
        Ok(None) => Err(Box::new(ticket_not_live())),
        Err(e) => Err(Box::new(internal("read the ticket", &e))),
    }
}

/// What a confirmed ticket means for whoever asked for it.
fn mode_text(mode: &str) -> &'static str {
    if mode == "connector" {
        "this connector's conversations on the session family below"
    } else {
        "one token for the command line or console that asked, redeemed once"
    }
}

/// The elevation page.
fn render_ticket_page(id: Uuid, t: &CeremonyTicket) -> String {
    let family = t.family_id.simple().to_string();
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Confirm an elevation</title>
<link rel="stylesheet" href="{css}">
</head>
<body>
<main id="ceremony" data-ticket="{id}">
<h1>Confirm an elevation</h1>
<p>A session signed in as the principal below asked to ELEVATE: for at most 15
minutes it may READ every group's data on this instance (it cannot write while
elevated), and every elevated read is logged for the people whose data it
reads. Confirming asks your passkey to verify you (PIN or biometric).</p>
<dl>
<dt>Principal</dt><dd><code>{person}</code></dd>
<dt>Reason</dt><dd id="reason">{reason}</dd>
<dt>Client</dt><dd id="client">{client}</dd>
<dt>Session family</dt><dd><code>{family_short}</code></dd>
<dt>Elevates</dt><dd>{mode}</dd>
<dt>Ticket expires</dt><dd>{expires}</dd>
</dl>
<p>Only confirm if you asked for this yourself, just now.</p>
<button id="confirm" type="button">Confirm with passkey</button>
<p id="status" role="status" aria-live="polite"></p>
</main>
<script src="{js}"></script>
</body>
</html>
"#,
        css = CSS_PATH,
        js = ELEVATE_JS_PATH,
        id = id,
        person = t.person_agent_id,
        reason = html_escape(&t.reason),
        client = html_escape(&t.client_name),
        family_short = &family[..8],
        mode = mode_text(&t.mode),
        expires = t.expires_at.format("%Y-%m-%d %H:%M:%S UTC"),
    )
}

/// `GET /elevate/:ticket`: the elevation page.
pub async fn ticket_page(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    if passkeys(&state).is_none() {
        return not_configured();
    }
    let mut conn = match ceremony_conn(&state).await {
        Ok(c) => c,
        Err(resp) => return *resp,
    };
    let t = match live_ticket(&mut conn, id).await {
        Ok(t) => t,
        Err(resp) => return *resp,
    };
    let mut resp = (StatusCode::OK, render_ticket_page(id, &t)).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    harden(resp)
}

/// `POST /elevate/:ticket/challenge`: start (or restart) the assertion. Only
/// the ticket person's live passkeys are allowed; user verification is
/// required; the counter is left to the confirm definer.
pub async fn ticket_challenge(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    let Some(rp) = passkeys(&state) else {
        return not_configured();
    };
    let mut conn = match ceremony_conn(&state).await {
        Ok(c) => c,
        Err(resp) => return *resp,
    };
    if let Err(resp) = live_ticket(&mut conn, id).await {
        return *resp;
    }
    let keys = match ElevationCeremony::passkeys(&mut conn, id).await {
        Ok(k) => k,
        Err(e) => return internal("read the ticket's passkeys", &e),
    };
    if keys.is_empty() {
        return json_error(
            StatusCode::CONFLICT,
            "no_live_passkey",
            "the person this ticket is for has no live passkey",
        );
    }
    // The counter overlay is irrelevant here (the deferring start takes every
    // counter as 0); the confirm definer compares the asserted counter with
    // the stored one under its row lock.
    let stored: Vec<StoredPasskey> = keys
        .into_iter()
        .map(|k| StoredPasskey {
            passkey: k.passkey,
            sign_count: 0,
        })
        .collect();
    let (options, ceremony) = match rp.start_authentication_deferring_counter(&stored, None) {
        Ok(v) => v,
        Err(e) => return internal("start the assertion", &e),
    };
    match ElevationCeremony::store_challenge(&mut conn, id, &ceremony.to_json()).await {
        Ok(()) => harden((StatusCode::OK, Json(options)).into_response()),
        Err(e) if sqlstate(&e).as_deref() == Some("ELV06") => ticket_not_live(),
        Err(e) => internal("store the challenge", &e),
    }
}

/// The response to a confirm definer's answer.
fn confirmation_response(id: Uuid, mode: &str, c: &Confirmation) -> Response {
    if c.outcome == "confirmed" {
        tracing::info!(
            target: "elevate.ticket",
            ticket = %id,
            session = ?c.session_id,
            "elevation confirmed"
        );
        let next = if mode == "connector" {
            "Elevated. Return to your conversation."
        } else {
            "Elevated. Return to the command line: its waiting token request completes now."
        };
        harden(
            (
                StatusCode::OK,
                Json(json!({
                    "outcome": "confirmed",
                    "expires_at": c.expires_at,
                    "detail": next,
                })),
            )
                .into_response(),
        )
    } else {
        tracing::warn!(
            target: "elevate.ticket",
            ticket = %id,
            refusal = ?c.refusal,
            code = ?c.code,
            "elevation refused"
        );
        harden(
            (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "elevation_refused",
                    "refusal": c.refusal,
                    "code": c.code,
                    "detail": "the elevation was refused and this ticket is used up",
                })),
            )
                .into_response(),
        )
    }
}

/// A confirm definer's raised refusal (ELV06: the ticket stopped being live,
/// or its family is already elevated), or a failure.
fn confirm_failed(e: &DbError) -> Response {
    if sqlstate(e).as_deref() == Some("ELV06") {
        json_error(
            StatusCode::CONFLICT,
            "elevation_not_possible",
            "the ticket is no longer live, or its session family is already elevated",
        )
    } else {
        internal("record the assertion", e)
    }
}

/// `POST /elevate/:ticket/assert`: verify the authenticator's response and
/// record it (module docs: what is verified, what is only audited).
pub async fn ticket_assert(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    let Some(rp) = passkeys(&state) else {
        return not_configured();
    };
    let mut conn = match ceremony_conn(&state).await {
        Ok(c) => c,
        Err(resp) => return *resp,
    };
    let t = match live_ticket(&mut conn, id).await {
        Ok(t) => t,
        Err(resp) => return *resp,
    };
    let Some(stored) = t.challenge_state.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            "no_ceremony_started",
            "request a challenge for this ticket first",
        );
    };
    let response: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "malformed_response",
                err.to_string(),
            )
        }
    };
    let Some(raw_id) = response
        .get("rawId")
        .and_then(Value::as_str)
        .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
        .filter(|id| !id.is_empty())
    else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "malformed_response",
            "the response names no credential (rawId)",
        );
    };
    let keys = match ElevationCeremony::passkeys(&mut conn, id).await {
        Ok(k) => k,
        Err(e) => return internal("read the ticket's passkeys", &e),
    };
    let ceremony = AuthenticationState::from_json(stored);

    if keys.iter().any(|k| k.credential_id == raw_id) {
        // One of the ticket person's live passkeys: the library verifies it,
        // and a refusal leaves the ticket live.
        let a = match rp.finish_authentication(&response, &ceremony) {
            Ok(a) => a,
            Err(err) => {
                tracing::warn!(
                    target: "elevate.ticket",
                    ticket = %id,
                    error = %err,
                    "assertion refused by the WebAuthn library"
                );
                let code = match err {
                    PasskeyError::UserNotVerified => "user_not_verified",
                    PasskeyError::State(_) => "ceremony_state_unusable",
                    PasskeyError::Malformed { .. } => "malformed_response",
                    _ => "assertion_refused",
                };
                return json_error(StatusCode::BAD_REQUEST, code, err.to_string());
            }
        };
        let asserted = AssertedCredential {
            credential_id: &a.credential_id,
            counter: i64::from(a.counter),
            backup_eligible: a.backup_eligible,
            evidence: &a.evidence,
        };
        return match ElevationCeremony::confirm(&mut conn, id, asserted).await {
            Ok(c) => confirmation_response(id, &t.mode, &c),
            Err(e) => confirm_failed(&e),
        };
    }

    // Not one of the ticket person's live passkeys: nothing to verify it with.
    // Handed to the definer so the refusal is audited and the ticket burned,
    // in a transaction rolled back should the definer ever confirm it.
    let evidence = json!({
        "v": 1,
        "challenge": ceremony.challenge().ok().map(|c| URL_SAFE_NO_PAD.encode(c)),
        "response": response,
        "verified": false,
        "unverified_reason": "the credential is not one of the ticket person's live passkeys; \
                              the server held no key to verify it with",
    });
    let asserted = AssertedCredential {
        credential_id: &raw_id,
        counter: 0,
        backup_eligible: false,
        evidence: &evidence,
    };
    let mut tx = match sqlx::Connection::begin(&mut *conn).await {
        Ok(tx) => tx,
        Err(e) => return internal("begin", &e),
    };
    let c = match ElevationCeremony::confirm(&mut tx, id, asserted).await {
        Ok(c) => c,
        Err(e) => return confirm_failed(&e),
    };
    if c.outcome != "refused" {
        // Never commit an unverified confirmation (a passkey registered between
        // the read above and the definer's lock).
        let _ = tx.rollback().await;
        tracing::error!(
            target: "elevate.ticket",
            ticket = %id,
            "an unverified assertion would have been confirmed; rolled back"
        );
        return json_error(
            StatusCode::CONFLICT,
            "retry",
            "the ticket's passkeys changed during the ceremony; request a new challenge",
        );
    }
    if let Err(e) = tx.commit().await {
        return internal("commit the refusal", &e);
    }
    confirmation_response(id, &t.mode, &c)
}

// =====================================================================
// The admin-act confirmation (EL-12b): `/elevate/act/:id`
// =====================================================================

/// The maintenance verb that executes an act of `kind` (`--act <id>`).
fn executing_verb(kind: &str) -> &'static str {
    match kind {
        "role.grant" => "grant-role",
        "role.end" => "end-role-assignment",
        "claim.custodial_supersede" => "custodial-supersede",
        "passkey.register" => "passkey-enroll",
        _ => "the matching verb",
    }
}

fn act_not_live() -> Response {
    json_error(
        StatusCode::NOT_FOUND,
        "act_not_live",
        "no live admin act with this id: it is unknown, expired, or already confirmed or \
         refused; propose it again",
    )
}

/// Read the live act `id`. The refusal is the response to send, boxed.
async fn live_act(conn: &mut sqlx::PgConnection, id: Uuid) -> Result<CeremonyAct, Box<Response>> {
    match AdminActCeremony::live_act(conn, id).await {
        Ok(Some(a)) => Ok(a),
        Ok(None) => Err(Box::new(act_not_live())),
        Err(e) => Err(Box::new(internal("read the act", &e))),
    }
}

/// The stored args digest as the fixed-length value the challenge commits to.
fn digest_of(act: &CeremonyAct) -> Result<[u8; 32], Box<Response>> {
    act.args_digest
        .as_slice()
        .try_into()
        .map_err(|_| Box::new(internal("read the act's digest", &"not 32 bytes")))
}

/// One stored arg, for the page: a string as itself, null as "(none)",
/// anything else as its JSON text. Escaped by the caller.
fn arg_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "(none)".to_string(),
        other => other.to_string(),
    }
}

/// The confirmation page, rendered from the STORED canonical args.
fn render_act_page(id: Uuid, act: &CeremonyAct) -> String {
    let args = act.args.as_object().map_or_else(String::new, |m| {
        m.iter()
            .map(|(k, v)| {
                format!(
                    "<dt>{}</dt><dd><code>{}</code></dd>\n",
                    html_escape(k),
                    html_escape(&arg_text(v))
                )
            })
            .collect::<String>()
    });
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Confirm an admin act</title>
<link rel="stylesheet" href="{css}">
</head>
<body>
<main id="ceremony" data-base="/elevate/act/{id}" data-noun="act">
<h1>Confirm an admin act</h1>
<p>An elevated session signed in as the principal below PROPOSED the
administrative act shown here. Confirming asks your passkey to verify you (PIN
or biometric) and signs over exactly these arguments: the act can then be
executed once, by the maintenance command line, within its expiry. Nothing is
executed by this page.</p>
<dl>
<dt>Proposed by</dt><dd><code>{person}</code></dd>
<dt>Act</dt><dd id="kind"><code>{kind}</code></dd>
<dt>Reason</dt><dd id="reason">{reason}</dd>
</dl>
<h2>Arguments</h2>
<dl id="args">
{args}</dl>
<dl>
<dt>Arguments digest (SHA-256)</dt><dd><code>{digest}</code></dd>
<dt>Expires</dt><dd>{expires}</dd>
<dt>Executed by</dt><dd><code>epigraph-operator {verb} --act {id}</code></dd>
</dl>
<p>Only confirm if you proposed this yourself, just now, with these arguments.</p>
<button id="confirm" type="button">Confirm with passkey</button>
<p id="status" role="status" aria-live="polite"></p>
</main>
<script src="{js}"></script>
</body>
</html>
"#,
        css = CSS_PATH,
        js = ELEVATE_JS_PATH,
        id = id,
        person = act.proposed_by,
        kind = html_escape(&act.kind),
        reason = html_escape(&act.reason),
        args = args,
        digest = hex::encode(&act.args_digest),
        expires = act.expires_at.format("%Y-%m-%d %H:%M:%S UTC"),
        verb = executing_verb(&act.kind),
    )
}

/// `GET /elevate/act/:id`: the confirmation page.
pub async fn act_page(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    if passkeys(&state).is_none() {
        return not_configured();
    }
    let mut conn = match ceremony_conn(&state).await {
        Ok(c) => c,
        Err(resp) => return *resp,
    };
    let act = match live_act(&mut conn, id).await {
        Ok(a) => a,
        Err(resp) => return *resp,
    };
    let mut resp = (StatusCode::OK, render_act_page(id, &act)).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    harden(resp)
}

/// `POST /elevate/act/:id/challenge`: start (or restart) the confirmation.
/// The challenge COMMITS TO THE ACT: `epigraph_passkey::act_challenge` over
/// the act id, its stored args digest and a fresh server nonce, which is
/// stored with the library's state so the assertion (and the offline
/// verifier) can recompute it. Only the PROPOSER's live passkeys are allowed;
/// user verification is required; the counter is the confirm definer's.
pub async fn act_challenge(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    let Some(rp) = passkeys(&state) else {
        return not_configured();
    };
    let mut conn = match ceremony_conn(&state).await {
        Ok(c) => c,
        Err(resp) => return *resp,
    };
    let act = match live_act(&mut conn, id).await {
        Ok(a) => a,
        Err(resp) => return *resp,
    };
    let digest = match digest_of(&act) {
        Ok(d) => d,
        Err(resp) => return *resp,
    };
    let keys = match AdminActCeremony::passkeys(&mut conn, id).await {
        Ok(k) => k,
        Err(e) => return internal("read the act's passkeys", &e),
    };
    if keys.is_empty() {
        return json_error(
            StatusCode::CONFLICT,
            "no_live_passkey",
            "the person who proposed this act has no live passkey",
        );
    }
    let stored: Vec<StoredPasskey> = keys
        .into_iter()
        .map(|k| StoredPasskey {
            passkey: k.passkey,
            sign_count: 0,
        })
        .collect();
    let nonce: [u8; ACT_NONCE_LEN] = rand::random();
    let challenge = act_challenge_of(id, &digest, &nonce);
    let (options, ceremony) =
        match rp.start_authentication_deferring_counter(&stored, Some(&challenge)) {
            Ok(v) => v,
            Err(e) => return internal("start the assertion", &e),
        };
    let state_json = json!({
        "v": 1,
        "ceremony": ceremony.to_json(),
        "nonce": URL_SAFE_NO_PAD.encode(nonce),
    });
    match AdminActCeremony::store_challenge(&mut conn, id, &state_json).await {
        Ok(()) => harden((StatusCode::OK, Json(options)).into_response()),
        Err(e) if matches!(sqlstate(&e).as_deref(), Some("ELV08" | "ELV03")) => act_not_live(),
        Err(e) => internal("store the challenge", &e),
    }
}

/// The stored ceremony of an act, CHECKED to commit to that act: its library
/// state's challenge must be `act_challenge(id, stored digest, stored
/// nonce)`. Anything else (a state written for another act, a random
/// challenge, a malformed row) is refused before any assertion is looked at.
fn bound_ceremony(
    id: Uuid,
    digest: &[u8; 32],
    stored: &Value,
) -> Result<AuthenticationState, Box<Response>> {
    let unbound = || {
        tracing::warn!(
            target: "elevate.act",
            act = %id,
            "the stored confirmation ceremony does not commit to this act; refused"
        );
        Box::new(json_error(
            StatusCode::CONFLICT,
            "challenge_not_bound",
            "the stored confirmation ceremony does not commit to this act; request a new \
             challenge",
        ))
    };
    let nonce: [u8; ACT_NONCE_LEN] = stored
        .get("nonce")
        .and_then(Value::as_str)
        .and_then(|n| URL_SAFE_NO_PAD.decode(n).ok())
        .and_then(|n| n.try_into().ok())
        .ok_or_else(unbound)?;
    let ceremony =
        AuthenticationState::from_json(stored.get("ceremony").cloned().ok_or_else(unbound)?);
    match ceremony.challenge() {
        Ok(c) if c.as_slice() == act_challenge_of(id, digest, &nonce).as_slice() => Ok(ceremony),
        _ => Err(unbound()),
    }
}

/// The response to a confirm definer's answer for an act.
fn act_confirmation_response(id: Uuid, kind: &str, c: &ActConfirmation) -> Response {
    if c.outcome == "confirmed" {
        tracing::info!(target: "elevate.act", act = %id, "admin act confirmed");
        harden(
            (
                StatusCode::OK,
                Json(json!({
                    "outcome": "confirmed",
                    "detail": format!(
                        "Confirmed. Execute it on the maintenance command line before it \
                         expires: epigraph-operator {} --act {id} (with the act's arguments)",
                        executing_verb(kind)
                    ),
                })),
            )
                .into_response(),
        )
    } else {
        tracing::warn!(
            target: "elevate.act",
            act = %id,
            refusal = ?c.refusal,
            code = ?c.code,
            "admin act refused"
        );
        harden(
            (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "act_refused",
                    "refusal": c.refusal,
                    "code": c.code,
                    "detail": "the confirmation was refused, and a refused act is final; \
                               propose it again",
                })),
            )
                .into_response(),
        )
    }
}

/// An act confirm definer's raised refusal (ELV08: the act stopped being
/// live), or a failure.
fn act_confirm_failed(e: &DbError) -> Response {
    if sqlstate(e).as_deref() == Some("ELV08") {
        json_error(
            StatusCode::CONFLICT,
            "act_not_confirmable",
            "the act is no longer live and started",
        )
    } else {
        internal("record the act's assertion", e)
    }
}

/// `POST /elevate/act/:id/assert`: check that the stored ceremony commits to
/// THIS act, verify the authenticator's response against the proposer's
/// passkeys, and record it (the ticket assertion's rules otherwise: an
/// assertion by a credential that is not one of the proposer's live passkeys
/// is recorded as an audited refusal, in a transaction rolled back should the
/// definer ever confirm it).
pub async fn act_assert(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    let Some(rp) = passkeys(&state) else {
        return not_configured();
    };
    let mut conn = match ceremony_conn(&state).await {
        Ok(c) => c,
        Err(resp) => return *resp,
    };
    let act = match live_act(&mut conn, id).await {
        Ok(a) => a,
        Err(resp) => return *resp,
    };
    let Some(stored) = act.challenge_state.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            "no_ceremony_started",
            "request a challenge for this act first",
        );
    };
    let digest = match digest_of(&act) {
        Ok(d) => d,
        Err(resp) => return *resp,
    };
    // THE CONTENT BINDING, before anything else is looked at.
    let ceremony = match bound_ceremony(id, &digest, &stored) {
        Ok(c) => c,
        Err(resp) => return *resp,
    };
    let response: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "malformed_response",
                err.to_string(),
            )
        }
    };
    let Some(raw_id) = response
        .get("rawId")
        .and_then(Value::as_str)
        .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
        .filter(|id| !id.is_empty())
    else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "malformed_response",
            "the response names no credential (rawId)",
        );
    };
    let keys = match AdminActCeremony::passkeys(&mut conn, id).await {
        Ok(k) => k,
        Err(e) => return internal("read the act's passkeys", &e),
    };

    if keys.iter().any(|k| k.credential_id == raw_id) {
        let a = match rp.finish_authentication(&response, &ceremony) {
            Ok(a) => a,
            Err(err) => {
                tracing::warn!(
                    target: "elevate.act",
                    act = %id,
                    error = %err,
                    "act assertion refused by the WebAuthn library"
                );
                let code = match err {
                    PasskeyError::UserNotVerified => "user_not_verified",
                    PasskeyError::State(_) => "ceremony_state_unusable",
                    PasskeyError::Malformed { .. } => "malformed_response",
                    _ => "assertion_refused",
                };
                return json_error(StatusCode::BAD_REQUEST, code, err.to_string());
            }
        };
        let asserted = AssertedCredential {
            credential_id: &a.credential_id,
            counter: i64::from(a.counter),
            backup_eligible: a.backup_eligible,
            evidence: &a.evidence,
        };
        return match AdminActCeremony::confirm(&mut conn, id, asserted).await {
            Ok(c) => act_confirmation_response(id, &act.kind, &c),
            Err(e) => act_confirm_failed(&e),
        };
    }

    // Not one of the proposer's live passkeys: nothing to verify it with.
    let evidence = json!({
        "v": 1,
        "challenge": ceremony.challenge().ok().map(|c| URL_SAFE_NO_PAD.encode(c)),
        "response": response,
        "verified": false,
        "unverified_reason": "the credential is not one of the proposer's live passkeys; the \
                              server held no key to verify it with",
    });
    let asserted = AssertedCredential {
        credential_id: &raw_id,
        counter: 0,
        backup_eligible: false,
        evidence: &evidence,
    };
    let mut tx = match sqlx::Connection::begin(&mut *conn).await {
        Ok(tx) => tx,
        Err(e) => return internal("begin", &e),
    };
    let c = match AdminActCeremony::confirm(&mut tx, id, asserted).await {
        Ok(c) => c,
        Err(e) => return act_confirm_failed(&e),
    };
    if c.outcome != "refused" {
        let _ = tx.rollback().await;
        tracing::error!(
            target: "elevate.act",
            act = %id,
            "an unverified act assertion would have been confirmed; rolled back"
        );
        return json_error(
            StatusCode::CONFLICT,
            "retry",
            "the proposer's passkeys changed during the ceremony; request a new challenge",
        );
    }
    if let Err(e) = tx.commit().await {
        return internal("commit the refusal", &e);
    }
    act_confirmation_response(id, &act.kind, &c)
}

/// `GET /elevate/assets/elevate.js`.
pub async fn elevate_js() -> Response {
    let mut resp = (StatusCode::OK, ELEVATE_JS).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/javascript; charset=utf-8"),
    );
    harden(resp)
}

/// `GET /elevate/assets/enroll.js`.
pub async fn enroll_js() -> Response {
    let mut resp = (StatusCode::OK, ENROLL_JS).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/javascript; charset=utf-8"),
    );
    harden(resp)
}

/// `GET /elevate/assets/elevate.css`.
pub async fn elevate_css() -> Response {
    let mut resp = (StatusCode::OK, CSS).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    harden(resp)
}

#[cfg(test)]
mod tests {
    use super::html_escape;

    /// Mutation: one of the five arms dropped -> its character survives.
    #[test]
    fn every_html_metacharacter_is_escaped() {
        assert_eq!(
            html_escape(r#"<a href="x" onclick='y'>&</a>"#),
            "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;"
        );
        assert_eq!(html_escape("plain text"), "plain text");
    }
}
