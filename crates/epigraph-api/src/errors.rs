use axum::{
    http::{header::WWW_AUTHENTICATE, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
#[cfg(feature = "db")]
use epigraph_db::DbError;
use serde::Serialize;
use std::sync::OnceLock;
use thiserror::Error;

/// RFC 6750 §3.1 error code. Every 401 this crate emits is `invalid_token`:
/// the credential is missing, malformed, expired, or structurally deficient
/// (e.g. a JWT carrying no `agent_id`), and in every one of those cases the
/// remedy is the same — re-mint the token. `insufficient_scope` belongs on 403
/// responses, which this crate raises as `ApiError::Forbidden`.
///
/// # A deliberate deviation from RFC 6750 §3.1
///
/// The RFC says a server *SHOULD NOT* include an `error` code when the request
/// carried no authentication information at all — a bare `Bearer` (optionally
/// with `realm`) is the conforming challenge for "you sent nothing". This crate
/// emits `error="invalid_token"` there too.
///
/// That is a choice, not an oversight. The alternative makes the challenge
/// depend on whether an `Authorization` header was present, and a client
/// looking at two different challenge strings has to decide which of two code
/// paths produced it before it can act — while the action is identical in both
/// cases (obtain a token, retry). PR-03 turned 105 routes into 401s at once;
/// one challenge shape across all of them is what makes
/// `public_router_allowlist.rs`'s exhaustive probe a single assertion instead
/// of a case analysis, and what lets an operator grep one string out of a
/// client's logs. The parameter is advisory in RFC 6750's own terms
/// ("SHOULD NOT", not "MUST NOT"), and no interoperability failure follows: a
/// conforming client treats an unrecognised or unexpected `error` on a 401 the
/// same way it treats its absence.
const INVALID_TOKEN: &str = "invalid_token";

/// The RFC 9728 protected-resource-metadata URL advertised in the
/// `WWW-Authenticate` challenge.
///
/// # Why a process-global
///
/// `IntoResponse::into_response(self)` takes only `self`. There is no
/// `AppState`, no `ApiConfig`, and no request in scope, so the URL cannot be
/// read from configuration at response time. The two alternatives are (a) widen
/// `ApiError::Unauthorized`, `::InvalidSignature` and `::SignatureError` to
/// carry the URL at every one of their ~100 construction sites, or (b) attach
/// the challenge in a response-mapping middleware, which then has to
/// re-classify status codes it did not produce. A `OnceLock` written once
/// during boot is the smaller mechanism.
///
/// Unset means the challenge degrades to the bare `Bearer error="invalid_token"`
/// form, which is RFC 6750-valid — just not RFC 9728-discoverable. That is the
/// shape every integration test sees, because tests build routers through
/// `build_app_for_tests` / `spawn_app` and never boot `bin/server.rs`.
static RESOURCE_METADATA_URL: OnceLock<Option<String>> = OnceLock::new();

/// Install the resource-metadata URL advertised on 401s. Called once from
/// `bin/server.rs`, before the listener binds.
///
/// Idempotent-by-ignoring: a second call is a no-op rather than a panic, so a
/// test binary that initialises it cannot poison a later one. Validate the URL
/// with [`validate_resource_metadata_url`] first — this function does not.
pub fn init_resource_metadata_url(url: Option<String>) {
    let _ = RESOURCE_METADATA_URL.set(url);
}

/// The configured resource-metadata URL, if any.
fn resource_metadata_url() -> Option<&'static str> {
    RESOURCE_METADATA_URL.get().and_then(|opt| opt.as_deref())
}

/// Build the RFC 9728 `WWW-Authenticate` challenge value.
///
/// Ported verbatim from `crates/epigraph-mcp/src/auth.rs:132-140` so the HTTP
/// API and the MCP server emit byte-identical challenges. It is not *shared*
/// with that module because `epigraph-mcp` is an optional dependency of this
/// crate and `challenge_header` there is private; a shared copy belongs in
/// `epigraph-auth` (a hard dependency of both) if a third caller appears.
///
/// Returns `None` when the interpolated URL produces a value `HeaderValue`
/// rejects (control characters / non-ASCII). This is the single source of the
/// challenge format, shared by [`IntoResponse`] (per-request) and
/// [`validate_resource_metadata_url`] (boot-time fail-fast) so the two cannot
/// drift.
fn challenge_header(resource_metadata_url: Option<&str>, error: &str) -> Option<HeaderValue> {
    let challenge = match resource_metadata_url {
        Some(url) => format!("Bearer resource_metadata=\"{url}\", error=\"{error}\""),
        None => format!("Bearer error=\"{error}\""),
    };
    challenge.parse().ok()
}

/// Validate an operator-supplied resource-metadata URL at startup.
///
/// A URL that cannot be embedded in a header would otherwise make every 401
/// silently drop the challenge; failing fast at boot surfaces the
/// misconfiguration before the listener accepts traffic. Mirrors
/// `epigraph_mcp::auth::validate_resource_metadata_url`.
///
/// # Why this is not just a `challenge_header` round trip
///
/// It used to be, and the round trip does not check what this function claims
/// to check. `HeaderValue::from_str`'s predicate (`http` 1.4.0,
/// `src/header/value.rs`) is `b >= 32 && b != 127 || b == b'\t'` — it rejects
/// control characters, and **accepts every byte >= 0x80**. So
/// `https://exämple.test/...` passed, booted, and produced a non-ASCII
/// `WWW-Authenticate` value that strict clients reject and `.to_str()` cannot
/// decode: precisely the silent degradation the fail-fast exists to prevent.
/// An empty string passed too, advertising `resource_metadata=""`, and a bare
/// TAB passed and produced a malformed challenge.
///
/// The four checks below run before the round trip, which is retained as the
/// backstop for control characters and CR/LF header injection.
///
/// # Errors
/// Returns a human-readable message naming which rule the URL broke.
pub fn validate_resource_metadata_url(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err("EPIGRAPH_RESOURCE_METADATA_URL is set but empty; unset it \
                    to fall back to EPIGRAPH_PUBLIC_BASE_URL, or give it a URL"
            .to_string());
    }
    if !url.is_ascii() {
        return Err(format!(
            "EPIGRAPH_RESOURCE_METADATA_URL contains non-ASCII bytes ({url:?}). \
             HeaderValue accepts them but the resulting WWW-Authenticate value \
             is not decodable as a str and strict clients reject it; percent-encode \
             the host and path (IDNA/punycode for the host)"
        ));
    }
    if url.contains('\t') {
        return Err("EPIGRAPH_RESOURCE_METADATA_URL contains a TAB, which is a \
                    legal header byte but not a legal URL character"
            .to_string());
    }
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(format!(
            "EPIGRAPH_RESOURCE_METADATA_URL must be an absolute http(s) URL; got {url:?}. \
             A client reads it out of the challenge and fetches it directly, so a \
             relative or scheme-less value is unfetchable"
        ));
    }
    challenge_header(Some(url), INVALID_TOKEN)
        .map(|_| ())
        .ok_or_else(|| {
            "EPIGRAPH_RESOURCE_METADATA_URL is not a valid HTTP header value \
             (control characters, or an embedded CR/LF?)"
                .to_string()
        })
}

/// API error types with HTTP status code mapping
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Bad request: {message}")]
    BadRequest { message: String },

    #[error("{entity} with ID {id} not found")]
    NotFound { entity: String, id: String },

    #[error("Unauthorized: {reason}")]
    Unauthorized { reason: String },

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Signature error: {reason}")]
    SignatureError { reason: String },

    #[error("Internal error: {message}")]
    InternalError { message: String },

    #[error("Validation error on field '{field}': {reason}")]
    ValidationError { field: String, reason: String },

    #[error("Integrity error on field '{field}': expected {expected}, got {actual}")]
    IntegrityError {
        field: String,
        expected: String,
        actual: String,
    },

    #[error("Database error: {message}")]
    DatabaseError { message: String },

    #[error("Service unavailable: {service}")]
    ServiceUnavailable { service: String },

    #[error("Forbidden: {reason}")]
    Forbidden { reason: String },

    #[error("Conflict: {reason}")]
    Conflict { reason: String },

    #[error("Bad gateway: {reason}")]
    BadGateway { reason: String },
}

/// JSON error response structure
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_type, details) = match &self {
            ApiError::BadRequest { message } => (
                StatusCode::BAD_REQUEST,
                "BadRequest",
                Some(serde_json::json!({ "message": message })),
            ),
            ApiError::NotFound { entity, id } => (
                StatusCode::NOT_FOUND,
                "NotFound",
                Some(serde_json::json!({ "entity": entity, "id": id })),
            ),
            ApiError::Unauthorized { reason } => (
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                Some(serde_json::json!({ "reason": reason })),
            ),
            ApiError::InvalidSignature => (StatusCode::UNAUTHORIZED, "InvalidSignature", None),
            ApiError::SignatureError { reason } => (
                StatusCode::UNAUTHORIZED,
                "SignatureError",
                Some(serde_json::json!({ "reason": reason })),
            ),
            ApiError::InternalError { message } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                Some(serde_json::json!({ "message": message })),
            ),
            ApiError::ValidationError { field, reason } => (
                StatusCode::BAD_REQUEST,
                "ValidationError",
                Some(serde_json::json!({ "field": field, "reason": reason })),
            ),
            ApiError::IntegrityError {
                field,
                expected,
                actual,
            } => (
                StatusCode::BAD_REQUEST,
                "IntegrityError",
                Some(serde_json::json!({
                    "field": field,
                    "expected": expected,
                    "actual": actual
                })),
            ),
            ApiError::DatabaseError { message } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DatabaseError",
                Some(serde_json::json!({ "message": message })),
            ),
            ApiError::ServiceUnavailable { service } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                Some(serde_json::json!({ "service": service })),
            ),
            ApiError::Forbidden { reason } => (
                StatusCode::FORBIDDEN,
                "Forbidden",
                Some(serde_json::json!({ "reason": reason })),
            ),
            ApiError::Conflict { reason } => (
                StatusCode::CONFLICT,
                "Conflict",
                Some(serde_json::json!({ "reason": reason })),
            ),
            ApiError::BadGateway { reason } => (
                StatusCode::BAD_GATEWAY,
                "BadGateway",
                Some(serde_json::json!({ "reason": reason })),
            ),
        };

        // RFC 6750 §3 REQUIRES a `WWW-Authenticate` challenge on a 401 from a
        // protected resource. Without it, a client that gets a 401 has no
        // machine-readable way to learn *which* authorization server to talk to
        // — the failure is undiscoverable. That was tolerable while almost
        // nothing returned 401; it is not tolerable now that the router
        // defaults to authenticated.
        //
        // Attached to the three variants that mean "your credential did not
        // work": Unauthorized, InvalidSignature, SignatureError. Deliberately
        // NOT attached to Forbidden — a 403 means the credential was accepted
        // and the answer is still no, and a challenge there tells the client to
        // retry an authentication that already succeeded.
        let needs_challenge = matches!(
            self,
            ApiError::Unauthorized { .. }
                | ApiError::InvalidSignature
                | ApiError::SignatureError { .. }
        );

        let body = ErrorResponse {
            error: error_type.to_string(),
            message: self.to_string(),
            details,
        };

        let mut response = (status, Json(body)).into_response();

        if needs_challenge {
            // The `Some` URL is validated at boot
            // (`validate_resource_metadata_url`) and the `None` branch is a
            // static valid string, so this is expected to succeed. If it
            // somehow does not, drop the header rather than panicking on every
            // request.
            if let Some(value) = challenge_header(resource_metadata_url(), INVALID_TOKEN) {
                response.headers_mut().insert(WWW_AUTHENTICATE, value);
            }
        }

        response
    }
}

#[cfg(feature = "db")]
impl From<DbError> for ApiError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::NotFound { entity, id } => ApiError::NotFound {
                entity,
                id: id.to_string(),
            },
            DbError::DuplicateKey { entity } => ApiError::BadRequest {
                message: format!("{} already exists", entity),
            },
            DbError::Conflict { reason } => ApiError::Conflict { reason },
            DbError::InvalidData { reason } => ApiError::ValidationError {
                field: "data".to_string(),
                reason,
            },
            // 23503 — the request named a parent row that does not exist. A
            // client error; the default 500 hid it. Routes that can say
            // something more specific (e.g. `create_group` → 403 when the
            // token's agent principal is unknown) match on it before this.
            DbError::ForeignKeyViolation { constraint } => ApiError::BadRequest {
                message: format!(
                    "request references a row that does not exist (constraint {constraint})"
                ),
            },
            // 23514 — the row the request asked for is not one this schema can
            // hold. A client error, mapped to 400 (PR-13). Before this arm it
            // fell through to `QueryFailed` and surfaced as a bare 500 reading
            // "A database error occurred", which is what migration 070's own
            // comment predicted and asked PR-13 to fix.
            //
            // The constraint NAME is included for the same reason the FK arm
            // includes it — it is the only thing that tells a caller which of
            // several CHECKs it tripped — and it is safe to disclose: these are
            // schema identifiers, not row contents.
            //
            // Mapped onto the EXISTING `BadRequest` variant on purpose. Adding
            // an `ApiError` variant would be a wider change than the mapping
            // needs: `ApiError` itself is compiled without the `db` feature
            // while this `impl` is `#[cfg(feature = "db")]`, so a new variant
            // lands in the no-db build with no arm that constructs it.
            // LOGGED, like the `QueryFailed` arm beside it. The response body
            // deliberately carries the constraint NAME only, but the driver's
            // message must not vanish from the server too: a plpgsql
            // `RAISE ... USING ERRCODE = '23514'` reports no constraint name,
            // so for migration 071's memberless-group refusal the name alone is
            // `<unnamed>` and the log line is the entire diagnostic.
            DbError::CheckViolation {
                constraint,
                message,
            } => {
                tracing::warn!(
                    constraint = %constraint,
                    detail = %message,
                    "CHECK constraint violated"
                );
                ApiError::BadRequest {
                    message: format!(
                        "request violates a database constraint (constraint {constraint})"
                    ),
                }
            }
            DbError::ConnectionFailed { source } => {
                tracing::error!(error = %source, "Database connection failed");
                ApiError::DatabaseError {
                    message: "Database connection error".to_string(),
                }
            }
            DbError::QueryFailed { source } => {
                tracing::error!(error = %source, "Database query failed");
                ApiError::DatabaseError {
                    message: "A database error occurred".to_string(),
                }
            }
            DbError::MigrationFailed { source } => {
                tracing::error!(error = %source, "Database migration failed");
                ApiError::DatabaseError {
                    message: "Database migration error".to_string(),
                }
            }
            DbError::JsonError { source } => {
                tracing::error!(error = %source, "JSON serialization failed");
                ApiError::DatabaseError {
                    message: "Data serialization error".to_string(),
                }
            }
            DbError::CoreError { source } => ApiError::ValidationError {
                field: "value".to_string(),
                reason: source.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bad_request_status_code() {
        let error = ApiError::BadRequest {
            message: "Invalid input".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// A CHECK violation reaches the client as **400**, not 500 (PR-13).
    ///
    /// Migration 070 asked for this in its own comment — it raises
    /// `ERRCODE = '23514'` "so the API/MCP layer can map it to a 4xx instead of
    /// surfacing a bare 500" — and before PR-13 nothing did the mapping:
    /// `From<sqlx::Error> for DbError` classified only 23505 and 23503, so
    /// 23514 became `QueryFailed` → `ApiError::DatabaseError` → 500.
    ///
    /// `#[cfg(feature = "db")]`, because `DbError` is only nameable when
    /// `epigraph-db` is compiled in. Without the gate this test breaks
    /// `cargo check -p epigraph-api --no-default-features`, which
    /// `--workspace --all-targets` never exercises.
    ///
    /// The constraint NAME must survive into the message: it is the only thing
    /// that tells a caller which of several CHECKs it tripped.
    #[cfg(feature = "db")]
    #[test]
    fn a_check_violation_is_a_client_error_carrying_its_constraint_name() {
        let api = ApiError::from(DbError::CheckViolation {
            constraint: "edges_co_owner_shape".to_string(),
            message: "new row for relation \"edges\" violates check constraint".to_string(),
        });
        match &api {
            ApiError::BadRequest { message } => {
                assert!(
                    message.contains("edges_co_owner_shape"),
                    "the constraint name must reach the caller: {message}"
                );
                // And the driver's message must NOT. It is server state — for
                // migration 071's 23514 it names a group and its membership —
                // so it goes to `tracing::warn!` and not to the HTTP body. The
                // `DbError` `Display` still carries it, which is what
                // `epigraph-mcp`'s operator-facing surface renders.
                assert!(
                    !message.contains("violates check constraint"),
                    "the driver message must stay server-side: {message}"
                );
            }
            other => panic!("23514 must not be a DatabaseError: {other:?}"),
        }
        assert_eq!(api.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_not_found_status_code() {
        let error = ApiError::NotFound {
            entity: "Claim".to_string(),
            id: "123".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_unauthorized_status_code() {
        let error = ApiError::Unauthorized {
            reason: "Invalid token".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_invalid_signature_status_code() {
        let error = ApiError::InvalidSignature;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_internal_error_status_code() {
        let error = ApiError::InternalError {
            message: "Database connection failed".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_validation_error_status_code() {
        let error = ApiError::ValidationError {
            field: "truth_value".to_string(),
            reason: "Must be between 0 and 1".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_forbidden_status_code() {
        let error = ApiError::Forbidden {
            reason: "Admin role required".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_database_error_does_not_leak_details() {
        let error = ApiError::DatabaseError {
            message: "A database error occurred".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ---- RFC 6750 / RFC 9728 challenge -----------------------------------
    //
    // These assert on the `error="invalid_token"` parameter only, never on
    // `resource_metadata=`. RESOURCE_METADATA_URL is a process-global OnceLock:
    // whether it is set depends on whether some *other* test in this same
    // binary happened to set it first, which would make any assertion about the
    // URL order-dependent. The URL's own formatting is covered by
    // `challenge_header_shapes` below, which calls the pure function directly.

    fn challenge_of(error: ApiError) -> String {
        let response = error.into_response();
        response
            .headers()
            .get(WWW_AUTHENTICATE)
            .unwrap_or_else(|| panic!("401 response carries no WWW-Authenticate header"))
            .to_str()
            .expect("challenge is ASCII")
            .to_string()
    }

    #[test]
    fn unauthorized_carries_the_bearer_challenge() {
        let challenge = challenge_of(ApiError::Unauthorized {
            reason: "no credential".to_string(),
        });
        assert!(challenge.starts_with("Bearer "), "got: {challenge}");
        assert!(
            challenge.contains(r#"error="invalid_token""#),
            "got: {challenge}"
        );
    }

    #[test]
    fn invalid_signature_carries_the_bearer_challenge() {
        let challenge = challenge_of(ApiError::InvalidSignature);
        assert!(
            challenge.contains(r#"error="invalid_token""#),
            "got: {challenge}"
        );
    }

    #[test]
    fn signature_error_carries_the_bearer_challenge() {
        let challenge = challenge_of(ApiError::SignatureError {
            reason: "malformed".to_string(),
        });
        assert!(
            challenge.contains(r#"error="invalid_token""#),
            "got: {challenge}"
        );
    }

    #[test]
    fn non_401_errors_carry_no_challenge() {
        // A 403 in particular: the credential was accepted and the answer is
        // still no. Challenging there tells the client to retry an
        // authentication that already worked.
        for error in [
            ApiError::Forbidden {
                reason: "scope".to_string(),
            },
            ApiError::NotFound {
                entity: "Claim".to_string(),
                id: "x".to_string(),
            },
            ApiError::BadRequest {
                message: "nope".to_string(),
            },
        ] {
            let rendered = format!("{error}");
            let response = error.into_response();
            assert!(
                response.headers().get(WWW_AUTHENTICATE).is_none(),
                "unexpected challenge on non-401: {rendered}"
            );
        }
    }

    #[test]
    fn challenge_header_shapes() {
        let with_url = challenge_header(Some("https://api.example/.well-known/x"), INVALID_TOKEN)
            .expect("valid url builds a header");
        assert_eq!(
            with_url.to_str().unwrap(),
            r#"Bearer resource_metadata="https://api.example/.well-known/x", error="invalid_token""#
        );

        let without_url = challenge_header(None, INVALID_TOKEN).expect("bare form is always valid");
        assert_eq!(
            without_url.to_str().unwrap(),
            r#"Bearer error="invalid_token""#
        );
    }

    #[test]
    fn validate_resource_metadata_url_rejects_unheaderable_values() {
        assert!(validate_resource_metadata_url("https://api.example/.well-known/x").is_ok());
        assert!(validate_resource_metadata_url("http://127.0.0.1:8080/.well-known/x").is_ok());
        // A newline would let an operator inject a second header.
        assert!(validate_resource_metadata_url("https://api.example/\r\nX-Evil: 1").is_err());
        assert!(validate_resource_metadata_url("https://api.example/\u{7f}").is_err());
    }

    /// The cases `HeaderValue::from_str` alone lets through. Each of these
    /// booted successfully before the explicit checks were added, and each
    /// produced a challenge a client cannot use.
    #[test]
    fn validate_resource_metadata_url_rejects_what_headervalue_accepts() {
        // Every byte >= 0x80 satisfies HeaderValue's predicate, so an IDN host
        // built a header that `.to_str()` cannot decode.
        assert!(
            validate_resource_metadata_url("https://exämple.test/.well-known/x").is_err(),
            "non-ASCII must be refused at boot, not turned into an undecodable header"
        );
        // Set-but-empty produced `Bearer resource_metadata="", error="..."`.
        assert!(validate_resource_metadata_url("").is_err());
        // TAB is a legal header byte and an illegal URL character.
        assert!(validate_resource_metadata_url("https://api.example/\tx").is_err());
        // Scheme-less and relative values are unfetchable by the client that
        // reads them out of the challenge.
        assert!(validate_resource_metadata_url("api.example/.well-known/x").is_err());
        assert!(validate_resource_metadata_url("/.well-known/x").is_err());
        assert!(validate_resource_metadata_url("ftp://api.example/x").is_err());
    }
}
