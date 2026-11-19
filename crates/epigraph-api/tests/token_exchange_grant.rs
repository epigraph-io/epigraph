#![cfg(feature = "db")]
//! `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693) at
//! `POST /oauth/token`, end to end on the application role (backlog c9b82fae).
//!
//! The federation gateway exchanges each caller's kernel token here and
//! forwards only the result to a mounted extension. What these tests pin:
//!
//! * an exchanged token is REFUSED on a kernel route (it names the
//!   extension's audience), while its subject is admitted there;
//! * it names the same principal, no wider scopes, and lives at most five
//!   minutes;
//! * the grant refuses an unknown audience, the kernel's own audience, a wider
//!   scope, a revoked subject, a subject whose client is suspended, and an
//!   already-exchanged token as subject.
//!
//! Every subject token is a real one, minted by the authorization-code grant
//! on the same router. Fixtures are seeded on the superuser pool; every
//! request the router serves runs as `epigraph_app`.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use base64::Engine as _;
use chrono::{Duration, Utc};
use epigraph_api::oauth::token_exchange::TokenExchangeAudiences;
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
const VERIFIER: &str = "token-exchange-fixed-pkce-code-verifier-of-adequate-length-01234";
const GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
/// The one extension this server is configured to exchange for.
const EXT: &str = "episcience";
/// The scopes the subject's client is granted.
const SUBJECT_SCOPES: &[&str] = &["claims:read", "edges:read"];

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

/// The router on an `epigraph_app` pool, configured to exchange for [`EXT`]
/// only, and the JWT config it signs with.
async fn app(pool: &PgPool) -> (axum::Router, std::sync::Arc<epigraph_api::oauth::JwtConfig>) {
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
    let state = AppState::with_db(app_pool, config())
        .with_token_exchange_audiences(TokenExchangeAudiences::parse(Some(EXT)));
    let jwt = state.jwt_config.clone();
    (create_router(state), jwt)
}

/// A real kernel access token from the authorization-code grant, for a fresh
/// active human client holding [`SUBJECT_SCOPES`]: `(token, client row id)`.
async fn subject(pool: &PgPool, app: &axum::Router) -> (String, Uuid) {
    let scopes: Vec<String> = SUBJECT_SCOPES.iter().map(|s| (*s).to_string()).collect();
    let unique = Uuid::new_v4().simple().to_string();
    let client_id = format!("tx_{unique}");
    let id = OAuthClientRepository::create(
        pool,
        &client_id,
        None,
        "token exchange connector",
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
        id,
    )
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

/// The exchange as the gateway sends it: FORM-encoded (RFC 8693 section 2.1),
/// with `scope` added when given.
async fn exchange(
    app: &axum::Router,
    subject: &str,
    audience: &str,
    scope: Option<&str>,
) -> (StatusCode, Value) {
    let mut pairs = vec![
        ("grant_type", GRANT),
        ("subject_token", subject),
        ("subject_token_type", ACCESS),
        ("requested_token_type", ACCESS),
        ("audience", audience),
    ];
    if let Some(s) = scope {
        pairs.push(("scope", s));
    }
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(serde_urlencoded::to_string(pairs).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// `GET /api/v1/webhooks` with `token` as bearer: a kernel route behind the
/// REST bearer middleware, answered from the principal alone.
async fn kernel_route_status(app: &axum::Router, token: &str) -> StatusCode {
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/webhooks")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

/// THE PROPERTY: the subject is admitted on a kernel route and the token
/// exchanged for it is not, although both are signed by the same key for the
/// same principal. The exchanged token is for the extension (its validator
/// admits it), names the subject's principal, carries the subject's scopes,
/// lives at most five minutes, and is answered with RFC 8693's
/// `issued_token_type` and no refresh token.
///
/// Fails on the pre-fix code: there is no such grant (`Unsupported
/// grant_type`, 400), so no extension-audience token exists to refuse.
#[sqlx::test(migrations = "../../migrations")]
async fn an_exchanged_token_is_for_the_extension_and_refused_on_kernel_routes(pool: PgPool) {
    let (app, jwt) = app(&pool).await;
    let (raw, client) = subject(&pool, &app).await;
    assert_eq!(
        kernel_route_status(&app, &raw).await,
        StatusCode::OK,
        "CONTROL: the subject token is admitted on the kernel route"
    );

    let (status, body) = exchange(&app, &raw, EXT, None).await;
    assert_eq!(status, StatusCode::OK, "exchange: {body}");
    assert_eq!(body["issued_token_type"], ACCESS);
    assert_eq!(body["token_type"], "Bearer");
    assert!(
        body.get("refresh_token").is_none(),
        "no refresh token: {body}"
    );
    let expires_in = body["expires_in"].as_i64().expect("expires_in");
    assert!(
        (1..=300).contains(&expires_in),
        "at most five minutes: {expires_in}"
    );
    let exchanged = body["access_token"].as_str().expect("access_token");
    assert_ne!(exchanged, raw);

    assert_eq!(
        kernel_route_status(&app, exchanged).await,
        StatusCode::UNAUTHORIZED,
        "an extension-audience token must not be admitted on a kernel route"
    );

    let subj = jwt.validate_token(&raw).unwrap();
    let got = jwt
        .validate_token_for_audience(exchanged, EXT)
        .expect("the extension admits it");
    assert_eq!(got.aud, EXT);
    assert_eq!(got.sub, client);
    assert_eq!((got.sub, got.agent_id), (subj.sub, subj.agent_id));
    assert_eq!(got.scopes, subj.scopes);
    assert_eq!((got.fam, got.elv, got.dlg), (None, None, None));
    assert!(
        subj.fam.is_some(),
        "CONTROL: the human subject carries a family, the exchange drops it"
    );
}

/// Narrowing is honoured; widening, an unknown audience and the kernel's own
/// audience are refused with the RFC error, and no token is issued.
#[sqlx::test(migrations = "../../migrations")]
async fn the_exchange_refuses_a_wider_scope_and_an_unknown_audience(pool: PgPool) {
    let (app, jwt) = app(&pool).await;
    let (raw, _) = subject(&pool, &app).await;

    let (status, body) = exchange(&app, &raw, EXT, Some("claims:read")).await;
    assert_eq!(status, StatusCode::OK, "narrowing: {body}");
    assert_eq!(body["scope"], "claims:read");
    let narrowed = jwt
        .validate_token_for_audience(body["access_token"].as_str().unwrap(), EXT)
        .unwrap();
    assert_eq!(narrowed.scopes, vec!["claims:read"]);

    for (audience, scope, error) in [
        (EXT, Some("claims:read claims:write"), "invalid_scope"),
        (EXT, Some("claims:admin"), "invalid_scope"),
        ("not-a-configured-extension", None, "invalid_target"),
        ("epigraph-api", None, "invalid_target"),
    ] {
        let (status, body) = exchange(&app, &raw, audience, scope).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{audience} {scope:?}: {body}"
        );
        assert_eq!(body["error"], error, "{audience} {scope:?}: {body}");
        assert!(
            body.get("access_token").is_none(),
            "no token on a refusal: {body}"
        );
    }
}

/// The subject's LIVENESS is read at exchange time: a revoked subject and a
/// subject whose client was suspended get nothing, nor does a token that is
/// itself an exchanged one (an extension cannot re-exchange what it holds).
///
/// Mutation: drop the client-status read in `handle_token_exchange_grant` ->
/// the suspended client's token is exchanged and this fails; drop the
/// revocation read -> the revoked token is exchanged and this fails.
#[sqlx::test(migrations = "../../migrations")]
async fn the_exchange_refuses_a_revoked_or_suspended_or_already_exchanged_subject(pool: PgPool) {
    let (app, _jwt) = app(&pool).await;

    // Already exchanged.
    let (raw, _) = subject(&pool, &app).await;
    let (status, body) = exchange(&app, &raw, EXT, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let once = body["access_token"].as_str().unwrap().to_string();
    let (status, body) = exchange(&app, &once, EXT, None).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant")),
        "{body}"
    );

    // Revoked (RFC 7009 on the same router).
    let (raw, _) = subject(&pool, &app).await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/revoke")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(
            serde_urlencoded::to_string([("token", raw.as_str())]).unwrap(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        kernel_route_status(&app, &raw).await,
        StatusCode::UNAUTHORIZED,
        "CONTROL: the revocation took"
    );
    let (status, body) = exchange(&app, &raw, EXT, None).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant")),
        "{body}"
    );

    // Suspended client: its token is still signature-valid and unexpired.
    let (raw, client) = subject(&pool, &app).await;
    let (status, _) = exchange(&app, &raw, EXT, None).await;
    assert_eq!(status, StatusCode::OK, "CONTROL: exchangeable while active");
    sqlx::query("UPDATE oauth_clients SET status = 'suspended' WHERE id = $1")
        .bind(client)
        .execute(&pool)
        .await
        .expect("suspend");
    let (status, body) = exchange(&app, &raw, EXT, None).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant")),
        "{body}"
    );
}
