//! Migration 118 (batch W11), end to end: the token endpoint on a pool that
//! runs as the deployed application role (`SET SESSION AUTHORIZATION
//! epigraph_app`), which holds no UPDATE/DELETE on `oauth_clients`,
//! `oauth_authorization_codes` or `refresh_tokens` any more.
//!
//! Fixtures (clients, codes) are seeded on the superuser pool; every request
//! the router serves runs as the application role.

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
const VERIFIER: &str = "w11-fixed-pkce-code-verifier-of-adequate-length-0123456789";

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
async fn app_router(pool: &PgPool, max: u32) -> axum::Router {
    use sqlx::Executor;
    let app_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(max)
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
    // Every connection is open before the first request, so concurrent
    // requests race on rows, not on connection setup.
    let mut warm = Vec::new();
    for _ in 0..max {
        warm.push(app_pool.acquire().await.expect("warm connection"));
    }
    drop(warm);
    create_router(AppState::with_db(app_pool, config()))
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

/// An active human client plus one authorization code for it.
async fn seed_code(pool: &PgPool) -> (String, Uuid, String) {
    let unique = Uuid::new_v4().simple().to_string();
    let client_id = format!("w11_{unique}");
    let scopes = vec!["claims:read".to_string()];
    let id = OAuthClientRepository::create(
        pool,
        &client_id,
        None,
        "w11 connector",
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

fn code_grant(code: &str, client_id: &str) -> Value {
    serde_json::json!({
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": VERIFIER,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
    })
}

fn refresh_grant(token: &str) -> Value {
    serde_json::json!({ "grant_type": "refresh_token", "refresh_token": token })
}

async fn live_tokens(pool: &PgPool, client: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens WHERE client_id = $1 AND revoked_at IS NULL",
    )
    .bind(client)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Move a rotated refresh token's `revoked_at` `secs` seconds into the past on
/// the superuser pool, to stand past the grace window without sleeping.
async fn backdate_rotation(pool: &PgPool, token: &str, secs: i32) {
    let hash = blake3::hash(&hex::decode(token).expect("hex refresh token"));
    let n = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now() - make_interval(secs => $2) \
          WHERE token_hash = $1 AND revoked_reason = 'rotated'",
    )
    .bind(hash.as_bytes().as_slice())
    .bind(f64::from(secs))
    .execute(pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(n, 1, "backdate a rotated token");
}

#[sqlx::test(migrations = "../../migrations")]
async fn authorization_code_then_refresh_chain_on_the_app_role(pool: PgPool) {
    let (client_id, client, code) = seed_code(&pool).await;
    let app = app_router(&pool, 2).await;

    // authorization_code: consume (definer), principal materialised and the
    // client linked (lock + write-once link definers), refresh token minted.
    let (status, body) = post_token(app.clone(), code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    let r0 = body["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_string();
    let linked: Option<Uuid> =
        sqlx::query_scalar("SELECT agent_id FROM oauth_clients WHERE id = $1")
            .bind(client)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        linked.is_some(),
        "the mint linked the client to its principal"
    );
    // The code is spent.
    let (status, _) = post_token(app.clone(), code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a code is single use");

    // refresh_token: atomic rotation.
    let (status, body) = post_token(app.clone(), refresh_grant(&r0)).await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    let r1 = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(r0, r1);
    let (status, body) = post_token(app.clone(), refresh_grant(&r1)).await;
    assert_eq!(status, StatusCode::OK, "second refresh: {body}");
    let r2 = body["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(live_tokens(&pool, client).await, 1);

    // Re-presenting a token straight after its own rotation is inside the
    // grace window: 401, and the chain survives (r2 still refreshes).
    let (status, _) = post_token(app.clone(), refresh_grant(&r1)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "re-presented inside the window"
    );
    assert_eq!(
        live_tokens(&pool, client).await,
        1,
        "grace leaves the family live"
    );
    let (status, body) = post_token(app.clone(), refresh_grant(&r2)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "r2 survives a grace refusal: {body}"
    );
    let r3 = body["refresh_token"].as_str().unwrap().to_string();

    // Past the window, replaying a rotated token is reuse: 401, and the live r3
    // dies with its family.
    backdate_rotation(&pool, &r0, 31).await;
    let (status, _) = post_token(app.clone(), refresh_grant(&r0)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "replayed token");
    assert_eq!(
        live_tokens(&pool, client).await,
        0,
        "reuse revoked the family"
    );
    let (status, _) = post_token(app.clone(), refresh_grant(&r3)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "r3 was revoked with its family"
    );
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'oauth.refresh_token_reuse' \
            AND details->>'client_id' = $1::text",
    )
    .bind(client)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(events, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_refreshes_with_one_token_admit_exactly_one(pool: PgPool) {
    const N: usize = 6;
    let (client_id, client, code) = seed_code(&pool).await;
    let app = app_router(&pool, N as u32 + 1).await;
    let (status, body) = post_token(app.clone(), code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let r0 = body["refresh_token"].as_str().unwrap().to_string();

    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(N));
    let mut handles = Vec::new();
    for _ in 0..N {
        let (app, r0, barrier) = (app.clone(), r0.clone(), barrier.clone());
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            post_token(app, refresh_grant(&r0)).await
        }));
    }
    let mut statuses = Vec::new();
    let mut winner = None;
    for h in handles {
        let (status, body) = h.await.unwrap();
        if status == StatusCode::OK {
            winner = body["refresh_token"].as_str().map(str::to_string);
        }
        statuses.push(status);
    }
    let ok = statuses.iter().filter(|s| **s == StatusCode::OK).count();
    assert_eq!(ok, 1, "exactly one refresh may succeed: {statuses:?}");
    assert!(
        statuses
            .iter()
            .all(|s| *s == StatusCode::OK || *s == StatusCode::UNAUTHORIZED),
        "{statuses:?}"
    );
    let minted: i64 =
        sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE client_id = $1")
            .bind(client)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(minted, 2, "one successor, not one per request");

    // The race's losers were inside the grace window: the winner is not logged
    // out. Its successor is live and refreshes.
    assert_eq!(
        live_tokens(&pool, client).await,
        1,
        "the winner's successor is live"
    );
    let winner = winner.expect("the winning response carries a refresh token");
    let (status, body) = post_token(app.clone(), refresh_grant(&winner)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the winner refreshes after the race: {body}"
    );
    let reuse: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'oauth.refresh_token_reuse' \
            AND details->>'client_id' = $1::text",
    )
    .bind(client)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(reuse, 0, "a benign race is not reuse");
}

#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_and_revoke_on_the_app_role(pool: PgPool) {
    let secret = [7u8; 32];
    let client_id = format!("w11_svc_{}", Uuid::new_v4().simple());
    let scopes = vec!["claims:read".to_string()];
    let client = OAuthClientRepository::create(
        &pool,
        &client_id,
        Some(blake3::hash(&secret).as_bytes()),
        "w11 service",
        "service",
        &scopes,
        &scopes,
        "active",
        None,
        None,
        Some("W11 Test Entity"),
        Some("ops@example.test"),
        None,
    )
    .await
    .expect("seed service client");
    let app = app_router(&pool, 2).await;

    let (status, body) = post_token(
        app.clone(),
        serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": hex::encode(secret),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "client_credentials: {body}");

    // /oauth/revoke retires the issued refresh token through the definer; a
    // revoked token is a plain 401 afterwards, not reuse.
    let rt = body["refresh_token"]
        .as_str()
        .expect("client_credentials issues a refresh token");
    {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/oauth/revoke")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "token": rt, "token_type_hint": "refresh_token" }).to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert!(resp.status().is_success(), "revoke: {}", resp.status());
        let (status, _) = post_token(app.clone(), refresh_grant(rt)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let reason: Option<String> =
            sqlx::query_scalar("SELECT revoked_reason FROM refresh_tokens WHERE client_id = $1")
                .bind(client)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(reason.as_deref(), Some("revoked"));
        assert_eq!(live_tokens(&pool, client).await, 0);
    }
}
