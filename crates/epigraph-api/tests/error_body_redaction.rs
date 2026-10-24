//! The 500 body is redacted, and the detail it no longer carries reaches the
//! server log instead (`docs/tenancy/progress.json`,
//! F-route-error-text-remainder).
//!
//! `errors.rs`'s unit tests pin the body half. This binary pins the log half,
//! and is its own binary because `tracing_test::traced_test` installs a GLOBAL
//! subscriber and a process-wide buffer: a scoped subscriber in the large lib
//! test binary was measured to miss the event under parallel tests (`tracing`
//! caches per-callsite interest process-wide), which is a flake, not a check.

use axum::response::IntoResponse;
use epigraph_api::errors::ApiError;
use tracing_test::traced_test;

/// Both redacted variants log the message the body withholds, under the
/// `api.internal_error` target, so an operator can still read what failed.
#[traced_test]
#[test]
fn redacted_internal_error_detail_reaches_the_server_log() {
    let internal = ApiError::InternalError {
        message: "query failed: internal-detail-7f3a".to_string(),
    }
    .into_response();
    let database = ApiError::DatabaseError {
        message: "Failed to insert claim: database-detail-91c2".to_string(),
    }
    .into_response();
    assert_eq!(internal.status(), 500);
    assert_eq!(database.status(), 500);

    assert!(logs_contain("api.internal_error"));
    assert!(logs_contain("internal-detail-7f3a"));
    assert!(logs_contain("database-detail-91c2"));
}

/// The designed-text variant is answered verbatim, so it has nothing to log
/// under the redaction target: a log line there would mean its literal was
/// treated as a withheld detail.
#[traced_test]
#[test]
fn internal_error_static_is_not_logged_as_a_withheld_detail() {
    // The capture works in THIS span: a redacted variant rendered here is seen,
    // so the absence below is not a capture that never fired.
    let redacted = ApiError::InternalError {
        message: "redacted-control-a8d4".to_string(),
    }
    .into_response();
    assert_eq!(redacted.status(), 500);
    assert!(logs_contain("redacted-control-a8d4"));

    let response = ApiError::InternalErrorStatic {
        message: "static-literal-5be0",
    }
    .into_response();
    assert_eq!(response.status(), 500);
    assert!(!logs_contain("static-literal-5be0"));
}
