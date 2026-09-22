//! Access-token revocation is shared, durable, and seen by MCP.
//!
//! Before this, `POST /oauth/revoke` put the raw token string into a
//! per-process `HashSet` in `AppState`. MCP never saw it, so a revoked token
//! kept its full scopes on MCP HTTP until `exp`. A restart emptied it, and a
//! second API replica never had it. The endpoint recorded whatever string it
//! was sent, unverified, on an anonymous route.
//!
//! The shared list is `revoked_access_tokens`, keyed by `jti`. Its DDL is a
//! PENDING migration kept as a test fixture in `epigraph-db` (see that file's
//! header). Every test that needs the table applies it on top of the real
//! migration set.
//!
//! The MCP half is MCP's real `bearer_auth_middleware` (axum 0.8, hence the
//! `axum-mcp` dev-dependency) in front of a probe route. rmcp is not needed to
//! see what that middleware admits.

#![cfg(feature = "db")]

use std::sync::Arc;

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    routing::get,
    Router,
};
use chrono::Duration;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use epigraph_api::oauth::JwtConfig;
use epigraph_api::{create_router, ApiConfig, AppState};

const SECRET: &[u8] = b"access-token-revocation-test-secret-32bytes!";
const PENDING_DDL: &str =
    include_str!("../../epigraph-db/tests/fixtures/pending_migration_revoked_access_tokens.sql");

async fn apply_pending_ddl(pool: &PgPool) {
    sqlx::raw_sql(PENDING_DDL)
        .execute(pool)
        .await
        .expect("apply the pending revoked_access_tokens DDL");
}

fn config() -> ApiConfig {
    ApiConfig {
        require_packet_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "https://test.example".to_string(),
        allow_all_identities: true,
    }
}

/// An `AppState` as `bin/server.rs` builds it. `shared` is what the boot
/// probe decides.
fn api_state(pool: &PgPool, shared: bool) -> AppState {
    let mut state = AppState::with_db(pool.clone(), config());
    state.jwt_config = Arc::new(JwtConfig::from_secret(SECRET));
    if shared {
        state = state.with_shared_token_revocation(pool.clone());
    }
    assert_eq!(state.shares_token_revocation(), shared);
    state
}

fn mint() -> String {
    JwtConfig::from_secret(SECRET)
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:read".to_string(), "claims:write".to_string()],
            "service",
            None,
            None,
            Duration::minutes(15),
        )
        .expect("mint")
        .0
}

async fn post_json(app: &Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn revoke(app: &Router, token: &str) -> StatusCode {
    post_json(
        app,
        "/oauth/revoke",
        json!({ "token": token, "token_type_hint": "access_token" }),
    )
    .await
    .0
}

/// The status, and the body's `active` field when there is one.
async fn introspect(app: &Router, token: &str) -> (StatusCode, Option<bool>) {
    let (status, body) = post_json(app, "/oauth/introspect", json!({ "token": token })).await;
    (status, body.get("active").and_then(Value::as_bool))
}

async fn get_with_bearer(app: &Router, uri: &str, token: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::get(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// The API's MANDATORY bearer middleware, exactly as `create_router` layers it
/// on the protected surface, in front of a probe route.
fn api_protected_probe(state: AppState) -> Router {
    Router::new()
        .route("/probe", get(|| async { "admitted" }))
        .layer(axum::middleware::from_fn_with_state(
            state,
            epigraph_api::middleware::bearer_auth_middleware,
        ))
}

/// MCP's bearer middleware as `epigraph-mcp`'s `main.rs` builds it when the
/// boot probe finds the shared list: same secret, same database.
fn mcp_router(pool: &PgPool) -> axum_mcp::Router {
    let state = epigraph_mcp::auth::McpAuthState {
        jwt_config: Arc::new(JwtConfig::from_secret(SECRET)),
        resource_metadata_url: None,
        revocation: Some(pool.clone()),
    };
    axum_mcp::Router::new()
        .route("/mcp", axum_mcp::routing::post(|| async { "admitted" }))
        .layer(axum_mcp::middleware::from_fn_with_state(
            state,
            epigraph_mcp::auth::bearer_auth_middleware,
        ))
}

async fn mcp_call(mcp: &axum_mcp::Router, token: &str) -> (StatusCode, Option<String>) {
    let resp = mcp
        .clone()
        .oneshot(
            axum_mcp::http::Request::post("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .body(axum_mcp::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .map(|v| v.to_str().unwrap().to_string());
    (
        StatusCode::from_u16(resp.status().as_u16()).unwrap(),
        challenge,
    )
}

/// The done-state: revoked through the API's own endpoint, rejected by MCP.
#[sqlx::test(migrations = "../../migrations")]
async fn a_token_revoked_through_the_api_is_rejected_by_mcp(pool: PgPool) {
    apply_pending_ddl(&pool).await;
    let state = api_state(&pool, true);
    let api = create_router(state.clone());
    let mcp = mcp_router(&pool);
    let token = mint();

    // CALIBRATION: the token is good everywhere before it is revoked, so each
    // rejection below is the revocation's doing.
    assert_eq!(mcp_call(&mcp, &token).await.0, StatusCode::OK);
    assert_eq!(introspect(&api, &token).await, (StatusCode::OK, Some(true)));
    assert_eq!(
        get_with_bearer(&api_protected_probe(state.clone()), "/probe", &token).await,
        StatusCode::OK
    );

    assert_eq!(revoke(&api, &token).await, StatusCode::OK);

    let (status, challenge) = mcp_call(&mcp, &token).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "MCP must reject a token the API revoked"
    );
    assert_eq!(challenge.as_deref(), Some("Bearer error=\"invalid_token\""));

    assert_eq!(
        get_with_bearer(&api_protected_probe(state), "/probe", &token).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        introspect(&api, &token).await,
        (StatusCode::OK, Some(false)),
        "introspection must agree with enforcement"
    );
}

/// The revocation lives in the database, so a new process sees it. That covers
/// an API restart and a second replica alike.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revocation_survives_an_api_restart(pool: PgPool) {
    apply_pending_ddl(&pool).await;
    let revoked = mint();
    let untouched = mint();

    let before = create_router(api_state(&pool, true));
    assert_eq!(revoke(&before, &revoked).await, StatusCode::OK);
    drop(before);

    // A fresh AppState is a fresh process-local list.
    let after = api_state(&pool, true);
    assert_eq!(
        get_with_bearer(&api_protected_probe(after.clone()), "/probe", &revoked).await,
        StatusCode::UNAUTHORIZED,
        "a restarted API must still reject a token revoked before the restart"
    );
    assert_eq!(
        introspect(&create_router(after.clone()), &revoked).await,
        (StatusCode::OK, Some(false))
    );
    assert_eq!(
        get_with_bearer(&api_protected_probe(after), "/probe", &untouched).await,
        StatusCode::OK,
        "only the revoked token is refused"
    );

    // CALIBRATION: a process WITHOUT the shared list does not know. This is the
    // exact failure the shared list removes, and the posture a deploy has
    // until the pending migration runs.
    assert_eq!(
        get_with_bearer(
            &api_protected_probe(api_state(&pool, false)),
            "/probe",
            &revoked
        )
        .await,
        StatusCode::OK
    );
}

/// `/oauth/revoke` is anonymous. Only a token whose signature verifies may
/// reach the list. Otherwise anyone could fill the table with forged far-future
/// rows. Every such request is still a 200 (RFC 7009 §2.2).
#[sqlx::test(migrations = "../../migrations")]
async fn an_unverifiable_token_is_not_recorded(pool: PgPool) {
    apply_pending_ddl(&pool).await;
    let api = create_router(api_state(&pool, true));

    let forged = JwtConfig::from_secret(b"not-the-server-secret-but-32-bytes-long!!")
        .issue_access_token(
            Uuid::new_v4(),
            vec![],
            "service",
            None,
            None,
            Duration::days(3650),
        )
        .unwrap()
        .0;
    for junk in [forged.as_str(), "not-a-jwt", ""] {
        assert_eq!(revoke(&api, junk).await, StatusCode::OK);
    }

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM revoked_access_tokens")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0, "no unverified token may be recorded");

    // CALIBRATION: a real token IS recorded through the same path.
    assert_eq!(revoke(&api, &mint()).await, StatusCode::OK);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM revoked_access_tokens")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
}

/// The optional-bearer layer on the anonymous allowlist must refuse a revoked
/// token. Letting it fall through to anonymous would let a revoked credential
/// read whatever an allowlisted route shows a caller it can identify.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_token_is_refused_on_the_anonymous_allowlist_too(pool: PgPool) {
    apply_pending_ddl(&pool).await;
    let api = create_router(api_state(&pool, true));
    let token = mint();

    assert_eq!(
        get_with_bearer(&api, "/health", &token).await,
        StatusCode::OK
    );
    assert_eq!(revoke(&api, &token).await, StatusCode::OK);
    assert_eq!(
        get_with_bearer(&api, "/health", &token).await,
        StatusCode::UNAUTHORIZED
    );
}

/// A lookup or write that cannot be answered is a 503 everywhere, never an
/// admit and never a 200 that claims a revocation nobody else saw.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failing_shared_list_is_a_503_not_an_admit(pool: PgPool) {
    apply_pending_ddl(&pool).await;
    let state = api_state(&pool, true);
    let api = create_router(state.clone());
    let token = mint();

    // CALIBRATION: admitted while the list works.
    assert_eq!(
        get_with_bearer(&api_protected_probe(state.clone()), "/probe", &token).await,
        StatusCode::OK
    );

    sqlx::query("DROP TABLE public.revoked_access_tokens")
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(
        get_with_bearer(&api_protected_probe(state), "/probe", &token).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        get_with_bearer(&api, "/health", &token).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "the optional layer must not fall through to anonymous on a lookup error"
    );
    assert_eq!(
        introspect(&api, &token).await.0,
        StatusCode::SERVICE_UNAVAILABLE,
        "introspection must not answer active=true when it cannot check"
    );
    assert_eq!(
        revoke(&api, &token).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "a revocation other processes will never see must not be acknowledged"
    );
}

/// Without the shared list, which is the posture until the pending migration
/// runs, revocation still works inside the process that received it. That is
/// the pre-existing behaviour, now keyed on the verified jti.
#[sqlx::test(migrations = "../../migrations")]
async fn without_the_shared_list_revocation_is_process_local(pool: PgPool) {
    // No DDL: the table does not exist, and nothing may touch it.
    let state = api_state(&pool, false);
    let api = create_router(state.clone());
    let token = mint();

    assert_eq!(
        get_with_bearer(&api_protected_probe(state.clone()), "/probe", &token).await,
        StatusCode::OK
    );
    assert_eq!(revoke(&api, &token).await, StatusCode::OK);
    assert_eq!(
        get_with_bearer(&api_protected_probe(state), "/probe", &token).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        introspect(&api, &token).await,
        (StatusCode::OK, Some(false))
    );
}
