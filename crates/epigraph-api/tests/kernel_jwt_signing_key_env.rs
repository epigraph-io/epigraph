//! Backlog 7b834860: the API state signs kernel tokens with the Ed25519 key in
//! `EPIGRAPH_JWT_SIGNING_KEY`, not with a shared secret.
//!
//! The boot gate (`epigraph_auth::check_kernel_jwt_keys`) reads the variable
//! on its own, and the JWKS route tests inject a `JwtConfig` directly, so
//! without this test a refactor that stopped `AppState::default_jwt_config`
//! from reading the key would still pass every other test, and the server
//! would quietly sign HS256 with the public dev literal.
//!
//! This file holds ONE test on purpose: it changes the process environment,
//! and every test in the same binary would race it.

use epigraph_api::{ApiConfig, AppState};
use epigraph_auth::{AccessTokenBinding, JwtConfig, DEV_JWT_SECRET, JWT_SIGNING_KEY_VAR};
use jsonwebtoken::Algorithm;
use uuid::Uuid;

/// RFC 8037 appendix A.1: the Ed25519 private key `d`.
const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/// A secret that passes the strength check, used as the HS256 accept window.
const WINDOW_SECRET: &str = "a-window-secret-that-is-at-least-32-bytes";

/// The constructor the server binary reaches (`with_scoped_pool` ->
/// `with_db`), on a pool that never connects.
fn state_from_env() -> AppState {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool");
    AppState::with_db(pool, ApiConfig::default())
}

fn mint(cfg: &JwtConfig) -> String {
    cfg.issue_access_token(
        Uuid::new_v4(),
        vec!["claims:read".to_string()],
        "agent",
        None,
        Some(Uuid::new_v4()),
        chrono::Duration::minutes(5),
        AccessTokenBinding::NONE,
    )
    .expect("a signing config mints")
    .0
}

#[tokio::test]
async fn the_api_state_signs_with_the_signing_key_from_the_environment() {
    // Final migration state: signing key only, shared secret removed.
    std::env::set_var(JWT_SIGNING_KEY_VAR, SEED_HEX);
    std::env::remove_var("EPIGRAPH_JWT_SECRET");
    let state = state_from_env();
    let cfg = &state.jwt_config;

    assert_eq!(
        cfg.signing_algorithm(),
        Some(Algorithm::EdDSA),
        "with {JWT_SIGNING_KEY_VAR} set the API must sign EdDSA"
    );
    assert!(
        !cfg.accepts_hs256(),
        "with no secret set there is no HS256 window (the dev literal is never one)"
    );
    let jwks = cfg.jwks();
    assert_eq!(jwks.keys.len(), 1, "the API publishes its one public key");

    let token = mint(cfg);
    assert_eq!(
        jsonwebtoken::decode_header(&token).expect("header").alg,
        Algorithm::EdDSA
    );
    // An extension holding only the published JWK Set admits the token ...
    let verifier = JwtConfig::verifier_from_jwks(&serde_json::to_string(&jwks).unwrap())
        .expect("the published JWKS builds a verifier");
    verifier
        .validate_token(&token)
        .expect("a verifier built from the JWKS admits the API's token");
    // ... and nothing signed with the public dev literal is what the API minted.
    assert!(
        JwtConfig::from_secret(DEV_JWT_SECRET)
            .validate_token(&token)
            .is_err(),
        "the API must not sign with the dev secret when a signing key is set"
    );

    // Migration window: the secret stays accept-only, the signer stays EdDSA.
    std::env::set_var("EPIGRAPH_JWT_SECRET", WINDOW_SECRET);
    let state = state_from_env();
    let cfg = &state.jwt_config;
    assert_eq!(
        cfg.signing_algorithm(),
        Some(Algorithm::EdDSA),
        "the shared secret must never become the signer beside a signing key"
    );
    assert!(
        cfg.accepts_hs256(),
        "during the window the API still admits HS256 tokens minted before the switch"
    );
    let token = mint(cfg);
    assert!(
        JwtConfig::from_secret(WINDOW_SECRET.as_bytes())
            .validate_token(&token)
            .is_err(),
        "a token minted during the window is not verifiable with the shared secret"
    );

    std::env::remove_var(JWT_SIGNING_KEY_VAR);
    std::env::remove_var("EPIGRAPH_JWT_SECRET");
}
