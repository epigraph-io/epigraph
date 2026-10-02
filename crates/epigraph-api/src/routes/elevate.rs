//! The passkey enrollment ceremony (elevation plan EL-3; operator ruling D5).
//!
//! `epigraph-operator passkey-enroll` opens an enrollment ticket on the
//! maintenance DSN and prints its path, `/elevate/enroll/<id>`. The operator
//! opens that page on the device that holds the authenticator; the page asks
//! the browser to create a credential (user verification required) and posts
//! it back; this module verifies it with `epigraph-passkey` and records it
//! through migration 124's completion definer.
//!
//! # Unauthenticated by design
//!
//! These routes are on the PUBLIC router (`tests/public_router_allowlist.rs`
//! names each with its reason). The page has no bearer token to present: the
//! enrollment id (a random UUID, live for at most 15 minutes, consumed once)
//! and the authenticator are its credentials. Every handler reads the
//! enrollment through the ceremony definers, keyed by that id, on an
//! UNSTAMPED application connection; none enumerates anything.
//!
//! # What the page is careful about
//!
//! * Every string from the database (the reason, the label) is HTML-escaped.
//! * A strict Content-Security-Policy ([`CSP`]): no inline script or style, no
//!   framing, no form posts; the script and stylesheet are served from this
//!   binary (`include_str!`).
//! * The URL carries the capability, so every response says
//!   `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
//!
//! # Not configured
//!
//! With no relying party configured (`AppState::passkeys` is `None`), every
//! route here answers 503: fail closed, never a default rp id.

// UNSCOPED-POOL-EXEMPT: Pre-authentication. The enrollment page is anonymous by
// design (the enrollment id and the authenticator are its credentials), so no
// principal exists to stamp a connection from; each site calls one of
// migration 124's ceremony definers keyed by that id, which need no stamp.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use epigraph_db::{CeremonyEnrollment, DbError, PasskeyCeremony, VerifiedPasskey};
use epigraph_passkey::{PasskeyError, Passkeys, RegistrationState};
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
/// The ceremony pages' stylesheet, served at [`CSS_PATH`].
pub const CSS: &str = include_str!("elevate/elevate.css");
/// Where the script is served.
pub const ENROLL_JS_PATH: &str = "/elevate/assets/enroll.js";
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

/// Read the live enrollment `id` on an unstamped application connection.
async fn live(state: &AppState, id: Uuid) -> Result<CeremonyEnrollment, Response> {
    let mut conn = state
        .db_pool
        .acquire()
        .await
        .map_err(|e| internal("acquire", &e))?;
    match PasskeyCeremony::live_enrollment(&mut conn, id).await {
        Ok(Some(e)) => Ok(e),
        Ok(None) => Err(not_live()),
        Err(e) => Err(internal("read the enrollment", &e)),
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
        Err(resp) => return resp,
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
        Err(resp) => return resp,
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
        Err(resp) => return resp,
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
