//! The RFC 9728 half of the 401 challenge, end to end.
//!
//! # Why this is its own test binary
//!
//! `errors::RESOURCE_METADATA_URL` is a process-global `OnceLock`. It has to
//! be: `IntoResponse::into_response(self)` takes only `self`, so there is no
//! config in scope at response time. A `OnceLock` is write-once *per process*,
//! which means a test that installs a URL and a test that expects the bare
//! challenge cannot coexist in one binary — whichever runs first decides for
//! the other. Cargo gives each integration-test file its own process, so one
//! file with one URL-installing test is the isolation mechanism.
//!
//! # What was missing without it
//!
//! Every other test sees the bare `Bearer error="invalid_token"` form, because
//! only `bin/server.rs` calls `init_resource_metadata_url` and no test boots
//! `bin/server.rs`. Deleting that call therefore broke nothing observable: the
//! sole symptom was that production 401s silently lost the discovery URL —
//! which is the exact failure the port from `epigraph-mcp` exists to prevent.
//! `public_router_allowlist.rs` says so in a comment and declines to assert it.
//! This file asserts it.

#![cfg(feature = "db")]

mod common;

const SERVER_BIN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/server.rs");

/// The wiring half: `bin/server.rs` must actually install the URL.
///
/// Same technique as `public_router_allowlist.rs::require_signature_middleware_is_gone`
/// — a source assertion is the only way to cover a `main` no test executes.
#[test]
fn server_main_installs_the_resource_metadata_url() {
    let src = std::fs::read_to_string(SERVER_BIN)
        .unwrap_or_else(|e| panic!("cannot read {SERVER_BIN}: {e}"));

    assert!(
        src.contains("init_resource_metadata_url("),
        "bin/server.rs no longer calls errors::init_resource_metadata_url. \
         Nothing else calls it, so every production 401 would carry the bare \
         `Bearer error=\"invalid_token\"` challenge and no client could \
         discover the authorization server. The behavioural test below cannot \
         catch this: it installs the URL itself."
    );
    assert!(
        src.contains("validate_resource_metadata_url("),
        "bin/server.rs no longer validates the resource-metadata URL before \
         installing it. The validation is what turns an operator typo into a \
         refused boot instead of 401s that silently drop the challenge."
    );
    // Ordering matters: validate, then install. Installing first would make the
    // exit(1) pointless for the request that arrives between the two.
    let validate_at = src
        .find("validate_resource_metadata_url(")
        .expect("checked above");
    let init_at = src
        .find("init_resource_metadata_url(")
        .expect("checked above");
    assert!(
        validate_at < init_at,
        "bin/server.rs must validate the resource-metadata URL BEFORE \
         installing it"
    );
}

/// The behavioural half: with a URL installed, a real 401 from a real router
/// carries the full RFC 9728 challenge.
#[tokio::test(flavor = "multi_thread")]
async fn a_401_advertises_the_resource_metadata_url() {
    const URL: &str = "https://api.test.invalid/.well-known/oauth-protected-resource";

    // The value an operator would supply must survive the boot-time check.
    epigraph_api::errors::validate_resource_metadata_url(URL)
        .expect("the URL used here must be one bin/server.rs would accept");
    // Before spawn_app, and before any request: OnceLock is write-once.
    epigraph_api::errors::init_resource_metadata_url(Some(URL.to_string()));

    let db = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&db).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/claims"))
        .send()
        .await
        .expect("GET /api/v1/claims");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a protected route with no credential is 401"
    );
    let challenge = resp
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .expect("401 carries a challenge")
        .to_str()
        .expect("the challenge is ASCII — validate_resource_metadata_url guarantees it");

    assert_eq!(
        challenge,
        format!(r#"Bearer resource_metadata="{URL}", error="invalid_token""#),
        "the full RFC 9728 challenge is what an OAuth client follows to find \
         the authorization server; the bare RFC 6750 form is only the \
         degraded fallback for a deployment that configured no URL"
    );
}
