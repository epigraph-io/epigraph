//! The MCP HTTP bearer middleware consults the shared access-token revocation
//! list (`revoked_access_tokens`, keyed by `jti`).
//!
//! Before this, `bearer_auth_middleware` admitted any token whose signature and
//! `exp` checked out, so a token revoked through the API's `POST /oauth/revoke`
//! kept its full scopes here until it expired (up to an hour).
//!
//! The table's DDL is a PENDING migration kept as a test fixture in
//! `epigraph-db` (see that file's header); each test applies it on top of the
//! real migration set. The router is the real middleware in front of a trivial
//! handler — rmcp is not needed to observe what the middleware admits.
//!
//! The end-to-end case — revoked through the API's own endpoint, rejected here
//! — lives in `epigraph-api/tests/access_token_revocation.rs`, the one crate
//! that can build both routers.

use std::sync::Arc;

use axum::{body::Body, http::Request, http::StatusCode, routing::post, Router};
use chrono::{Duration, TimeZone, Utc};
use epigraph_auth::JwtConfig;
use epigraph_db::RevokedAccessTokenRepository;
use epigraph_mcp::auth::{bearer_auth_middleware, McpAuthState};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const SECRET: &[u8] = b"this-secret-is-at-least-32-bytes-long!!";
const PENDING_DDL: &str =
    include_str!("../../epigraph-db/tests/fixtures/pending_migration_revoked_access_tokens.sql");

async fn apply_pending_ddl(pool: &PgPool) {
    sqlx::raw_sql(PENDING_DDL)
        .execute(pool)
        .await
        .expect("apply the pending revoked_access_tokens DDL");
}

/// A signed token and the (jti, exp) the revocation list keys on.
fn mint() -> (String, Uuid, chrono::DateTime<Utc>) {
    let cfg = JwtConfig::from_secret(SECRET);
    let (token, jti) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:read".to_string()],
            "service",
            None,
            None,
            Duration::minutes(15),
        )
        .expect("mint");
    let exp = cfg.validate_token(&token).expect("round-trip").exp;
    (token, jti, Utc.timestamp_opt(exp, 0).unwrap())
}

fn router(revocation: Option<PgPool>) -> Router {
    let state = McpAuthState {
        jwt_config: Arc::new(JwtConfig::from_secret(SECRET)),
        resource_metadata_url: None,
        revocation,
    };
    Router::new()
        .route("/mcp", post(|| async { "admitted" }))
        .layer(axum::middleware::from_fn_with_state(
            state,
            bearer_auth_middleware,
        ))
}

async fn call(router: &Router, token: &str) -> (StatusCode, Option<String>) {
    let resp = router
        .clone()
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let challenge = resp
        .headers()
        .get(http::header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap().to_string());
    (resp.status(), challenge)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_token_is_rejected_with_invalid_token(pool: PgPool) {
    apply_pending_ddl(&pool).await;
    let app = router(Some(pool.clone()));
    let (token, jti, exp) = mint();

    // CALIBRATION: the same token is admitted before it is revoked, so the 401
    // below is caused by the revocation and not by anything else.
    assert_eq!(call(&app, &token).await.0, StatusCode::OK);

    RevokedAccessTokenRepository::revoke(&pool, jti, exp)
        .await
        .expect("revoke");

    let (status, challenge) = call(&app, &token).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a revoked token must not pass"
    );
    assert_eq!(
        challenge.as_deref(),
        Some("Bearer error=\"invalid_token\""),
        "revocation must be indistinguishable on the wire from every other rejection"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn revoking_one_token_leaves_another_admitted(pool: PgPool) {
    apply_pending_ddl(&pool).await;
    let app = router(Some(pool.clone()));
    let (revoked, jti, exp) = mint();
    let (other, _, _) = mint();

    RevokedAccessTokenRepository::revoke(&pool, jti, exp)
        .await
        .unwrap();

    assert_eq!(call(&app, &revoked).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        call(&app, &other).await.0,
        StatusCode::OK,
        "the check must be per-jti, not a blanket refusal"
    );
}

/// A lookup that cannot be answered refuses the request. Admitting on error
/// would make revocation exactly as strong as the database's uptime.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_revocation_lookup_refuses_rather_than_admits(pool: PgPool) {
    apply_pending_ddl(&pool).await;
    let (token, _, _) = mint();

    // CALIBRATION: this token is admitted while the lookup works.
    assert_eq!(
        call(&router(Some(pool.clone())), &token).await.0,
        StatusCode::OK
    );

    // Same shape, lookup made to fail: the table is gone from under the pool.
    sqlx::query("DROP TABLE public.revoked_access_tokens")
        .execute(&pool)
        .await
        .unwrap();
    let (status, challenge) = call(&router(Some(pool.clone())), &token).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a revocation lookup error must fail closed"
    );
    assert!(
        challenge.is_none(),
        "an outage is not a credential problem; a 401 challenge would send the client to \
         mint another token the same outage cannot check"
    );

    // And a pool that cannot reach the database at all.
    pool.close().await;
    assert_eq!(
        call(&router(Some(pool)), &token).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

/// A token that fails validation is rejected without a database round trip:
/// the list is keyed on the VERIFIED jti, and an unverified token has none.
#[sqlx::test(migrations = "../../migrations")]
async fn an_invalid_token_is_rejected_before_the_lookup(pool: PgPool) {
    // No DDL applied: a lookup here would error and turn into a 503.
    let app = router(Some(pool));
    let forged = JwtConfig::from_secret(b"a-completely-different-32-byte-key!!xx")
        .issue_access_token(
            Uuid::new_v4(),
            vec![],
            "service",
            None,
            None,
            Duration::minutes(5),
        )
        .unwrap()
        .0;
    assert_eq!(call(&app, &forged).await.0, StatusCode::UNAUTHORIZED);
}
