//! `POST /oauth/revoke` against RFC 7009, end to end on the application role.
//!
//! Section 2.1: the request is `application/x-www-form-urlencoded`, and
//! `token_type_hint` is a hint the server "MAY ignore"; when the token is not
//! found under the hint the server "MUST extend its search across all of its
//! supported token types". Section 2.2: an invalid token, and an unknown hint,
//! are answered 200.
//!
//! Each test checks the token's EFFECT after the revoke (the refresh grant, or
//! a bearer request), not only the revoke's status: the endpoint used to
//! answer 200 for a refresh token sent under `token_type_hint=access_token`
//! while revoking nothing.
//!
//! Fixtures are seeded on the superuser pool; every request the router serves
//! runs as `epigraph_app`.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use base64::Engine as _;
use chrono::{Duration, Utc};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::repos::authorization_code::AuthorizationCodeRepository;
use epigraph_db::repos::oauth_client::OAuthClientRepository;
use http_body_util::BodyExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const REDIRECT_URI: &str = "https://claude.ai/api/mcp/auth_callback";
const VERIFIER: &str = "rfc7009-fixed-pkce-code-verifier-of-adequate-length-0123456789";
const FORM: &str = "application/x-www-form-urlencoded";

fn config() -> ApiConfig {
    ApiConfig {
        require_packet_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "https://test.example".to_string(),
        allow_all_identities: true,
    }
}

async fn url_for(pool: &PgPool) -> String {
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("current_database()");
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let prefix = base
        .split_once('?')
        .map_or(base.as_str(), |(a, _)| a)
        .trim_end_matches('/')
        .rsplit_once('/')
        .expect("DATABASE_URL must carry a database path")
        .0
        .to_string();
    format!("{prefix}/{db}")
}

/// The router, serving on a pool whose every connection is `epigraph_app`.
async fn app_router(pool: &PgPool) -> axum::Router {
    use sqlx::Executor;
    let app_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute("SET SESSION AUTHORIZATION epigraph_app")
                    .await?;
                Ok(())
            })
        })
        .connect(&url_for(pool).await)
        .await
        .expect("application-role pool");
    create_router(AppState::with_db(app_pool, config()))
}

/// An active human client plus one authorization code for it.
async fn seed_code(pool: &PgPool) -> (String, Uuid, String) {
    let scopes = vec!["claims:read".to_string()];
    let unique = Uuid::new_v4().simple().to_string();
    let client_id = format!("rfc7009_{unique}");
    let id = OAuthClientRepository::create(
        pool,
        &client_id,
        None,
        "rfc7009 connector",
        "human",
        &scopes,
        &scopes,
        "active",
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("seed client");
    let code = format!("code_{unique}");
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(VERIFIER.as_bytes()));
    AuthorizationCodeRepository::create(
        pool,
        blake3::hash(code.as_bytes()).as_bytes(),
        &client_id,
        id,
        REDIRECT_URI,
        &challenge,
        &scopes,
        None,
        Utc::now() + Duration::minutes(5),
    )
    .await
    .expect("seed code");
    (client_id, id, code)
}

async fn post_token(app: axum::Router, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Redeem a fresh code: `(access_token, refresh_token, client row id)`.
async fn issue_tokens(pool: &PgPool, app: &axum::Router) -> (String, String, Uuid) {
    let (client_id, client, code) = seed_code(pool).await;
    let (status, body) = post_token(
        app.clone(),
        serde_json::json!({
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": VERIFIER,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    (
        body["access_token"].as_str().expect("access").to_string(),
        body["refresh_token"].as_str().expect("refresh").to_string(),
        client,
    )
}

/// POST `/oauth/revoke` with `content_type` and a raw `body`.
async fn revoke(app: axum::Router, content_type: &str, body: String) -> (StatusCode, String) {
    revoke_with(app, Some(content_type), body).await
}

/// POST `/oauth/revoke` with a raw `body` and, when given, a `Content-Type`.
async fn revoke_with(
    app: axum::Router,
    content_type: Option<&str>,
    body: String,
) -> (StatusCode, String) {
    let mut req = Request::builder().method(Method::POST).uri("/oauth/revoke");
    if let Some(ct) = content_type {
        req = req.header(header::CONTENT_TYPE, ct);
    }
    let req = req.body(Body::from(body)).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// A form body (RFC 7009 section 2.1) for `token` and an optional hint.
fn form(token: &str, hint: Option<&str>) -> String {
    let mut pairs = vec![("token", token)];
    if let Some(h) = hint {
        pairs.push(("token_type_hint", h));
    }
    serde_urlencoded::to_string(pairs).unwrap()
}

/// The refresh grant's status for `token`.
async fn refresh_status(app: axum::Router, token: &str) -> StatusCode {
    post_token(
        app,
        serde_json::json!({ "grant_type": "refresh_token", "refresh_token": token }),
    )
    .await
    .0
}

/// `GET /api/v1/webhooks` with `token` as bearer: behind the REST bearer
/// middleware and answered from the principal alone.
async fn bearer_status(app: axum::Router, token: &str) -> StatusCode {
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/webhooks")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

async fn revoked_reason(pool: &PgPool, client: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT revoked_reason FROM refresh_tokens WHERE client_id = $1")
        .bind(client)
        .fetch_one(pool)
        .await
        .expect("exactly one refresh token for the client")
}

/// (a)+(c): a refresh token sent form-encoded under the WRONG hint is revoked.
/// The server must extend its search past the hint (section 2.1).
#[sqlx::test(migrations = "../../migrations")]
async fn a_refresh_token_under_the_access_token_hint_is_revoked(pool: PgPool) {
    let app = app_router(&pool).await;
    let (_access, refresh, client) = issue_tokens(&pool, &app).await;

    let (status, body) = revoke(app.clone(), FORM, form(&refresh, Some("access_token"))).await;
    assert_eq!(status, StatusCode::OK, "form-encoded revoke: {body}");

    assert_eq!(
        revoked_reason(&pool, client).await.as_deref(),
        Some("revoked"),
        "the refresh token row is revoked although the hint said access_token"
    );
    assert_eq!(
        refresh_status(app, &refresh).await,
        StatusCode::UNAUTHORIZED,
        "a revoked refresh token no longer rotates"
    );
}

/// (b): an access token with NO hint is revoked (it used to be routed to the
/// refresh arm and refused 400 "Invalid token format"), and the REST bearer
/// middleware then refuses it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hintless_access_token_is_revoked(pool: PgPool) {
    let app = app_router(&pool).await;
    let (access, refresh, _client) = issue_tokens(&pool, &app).await;

    // CONTROL: the token is admitted before the revoke, so the 401 below is
    // the revocation's.
    assert_eq!(bearer_status(app.clone(), &access).await, StatusCode::OK);

    let (status, body) = revoke(app.clone(), FORM, form(&access, None)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "hintless access-token revoke: {body}"
    );
    assert_eq!(
        bearer_status(app.clone(), &access).await,
        StatusCode::UNAUTHORIZED,
        "a revoked access token is refused by the bearer middleware"
    );
    // Revoking the access token does not touch the refresh chain.
    assert_eq!(refresh_status(app, &refresh).await, StatusCode::OK);
}

/// (d): the hint is advisory, so an unknown value is answered 200 and the
/// token is still revoked, for either token type.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_hint_still_revokes(pool: PgPool) {
    let app = app_router(&pool).await;
    let (access, refresh, client) = issue_tokens(&pool, &app).await;

    let (status, body) = revoke(app.clone(), FORM, form(&refresh, Some("id_token"))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unknown hint, refresh token: {body}"
    );
    assert_eq!(
        revoked_reason(&pool, client).await.as_deref(),
        Some("revoked")
    );
    assert_eq!(
        refresh_status(app.clone(), &refresh).await,
        StatusCode::UNAUTHORIZED
    );

    assert_eq!(bearer_status(app.clone(), &access).await, StatusCode::OK);
    let (status, body) = revoke(app.clone(), FORM, form(&access, Some("bogus"))).await;
    assert_eq!(status, StatusCode::OK, "unknown hint, access token: {body}");
    assert_eq!(bearer_status(app, &access).await, StatusCode::UNAUTHORIZED);
}

/// The JSON body with an explicit, correct hint keeps working (deployed
/// clients send exactly this), and a token that is neither a JWT this server
/// signed nor a hex refresh token is answered 200 (section 2.2). A body
/// without `token` is still a 400, so the endpoint did not become "accept
/// anything".
#[sqlx::test(migrations = "../../migrations")]
async fn json_bodies_unrecognised_tokens_and_a_missing_token(pool: PgPool) {
    let app = app_router(&pool).await;
    let (_access, refresh, client) = issue_tokens(&pool, &app).await;

    let (status, body) = revoke(
        app.clone(),
        "application/json",
        serde_json::json!({ "token": refresh, "token_type_hint": "refresh_token" }).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "JSON revoke: {body}");
    assert_eq!(
        revoked_reason(&pool, client).await.as_deref(),
        Some("revoked")
    );

    for hint in [None, Some("refresh_token"), Some("access_token")] {
        let (status, body) = revoke(app.clone(), FORM, form("not-a-token!", hint)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an unrecognised token is answered 200 (hint {hint:?}): {body}"
        );
    }

    let (status, body) = revoke(app.clone(), FORM, "token_type_hint=refresh_token".into()).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a request without `token` is invalid: {body}"
    );
}

/// A request with NO `Content-Type` is parsed as a form (the section 2.1
/// encoding), and the hint is ignored on a JSON body too: a refresh token sent
/// as JSON under `token_type_hint=access_token` is revoked.
#[sqlx::test(migrations = "../../migrations")]
async fn a_bare_form_body_and_a_mis_hinted_json_body_both_revoke(pool: PgPool) {
    let app = app_router(&pool).await;

    let (_access, refresh, client) = issue_tokens(&pool, &app).await;
    let (status, body) = revoke_with(app.clone(), None, form(&refresh, None)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "revoke without Content-Type: {body}"
    );
    assert_eq!(
        revoked_reason(&pool, client).await.as_deref(),
        Some("revoked"),
        "a form body without Content-Type is parsed and the token revoked"
    );
    assert_eq!(
        refresh_status(app.clone(), &refresh).await,
        StatusCode::UNAUTHORIZED
    );

    let (_access, refresh, client) = issue_tokens(&pool, &app).await;
    let (status, body) = revoke(
        app.clone(),
        "application/json",
        serde_json::json!({ "token": refresh, "token_type_hint": "access_token" }).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mis-hinted JSON revoke: {body}");
    assert_eq!(
        revoked_reason(&pool, client).await.as_deref(),
        Some("revoked"),
        "the JSON hint is ignored like the form one"
    );
    assert_eq!(
        refresh_status(app, &refresh).await,
        StatusCode::UNAUTHORIZED
    );
}
