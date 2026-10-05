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
    create_router(app_state(pool, max).await)
}

/// [`app_router`], plus the issuing state's JWT config, so a test validates an
/// access token under exactly the secret that signed it.
async fn app_router_and_jwt(
    pool: &PgPool,
    max: u32,
) -> (axum::Router, std::sync::Arc<epigraph_api::oauth::JwtConfig>) {
    let state = app_state(pool, max).await;
    let jwt = state.jwt_config.clone();
    (create_router(state), jwt)
}

/// The state [`app_router`] serves: a pool whose every connection is `epigraph_app`.
async fn app_state(pool: &PgPool, max: u32) -> AppState {
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
    AppState::with_db(app_pool, config())
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
    let scopes = vec!["claims:read".to_string()];
    seed_code_with(pool, &scopes, &scopes).await
}

/// [`seed_code`] with the client's grant (`allowed_scopes` = `granted_scopes`)
/// and the code's consented scopes chosen separately, the way
/// `authorize.rs::callback_endpoint` narrows a consent to `requested ∩ granted`.
async fn seed_code_with(
    pool: &PgPool,
    client_scopes: &[String],
    scopes: &[String],
) -> (String, Uuid, String) {
    let unique = Uuid::new_v4().simple().to_string();
    let client_id = format!("w11_{unique}");
    let id = OAuthClientRepository::create(
        pool,
        &client_id,
        None,
        "w11 connector",
        "human",
        client_scopes,
        client_scopes,
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
        scopes,
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

fn s(v: &str) -> String {
    v.to_string()
}

/// The successor refresh token's stored scopes, read on the superuser pool.
async fn live_scopes(pool: &PgPool, client: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT scopes FROM refresh_tokens WHERE client_id = $1 AND revoked_at IS NULL",
    )
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("exactly one live refresh token")
}

/// RFC 6749 section 6: a refreshed token "MUST NOT include any scope not
/// originally granted by the resource owner". The client here genuinely holds
/// `claims:write`; the consent (the authorization code) was narrowed to
/// `claims:read`. Before migration 140 the refresh grant re-read the client's
/// `granted_scopes`, so the FIRST refresh widened the connector to write.
/// Served on the application role, so the stored scopes must be readable
/// there for the narrowing to happen at all.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refresh_never_widens_a_narrowed_consent(pool: PgPool) {
    let (client_id, client, code) = seed_code_with(
        &pool,
        &[s("claims:read"), s("claims:write")],
        &[s("claims:read")],
    )
    .await;
    let (app, jwt) = app_router_and_jwt(&pool, 2).await;

    let (status, body) = post_token(app.clone(), code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    assert_eq!(body["scope"], "claims:read", "the consent was narrowed");
    let r0 = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(app.clone(), refresh_grant(&r0)).await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    assert_eq!(
        body["scope"], "claims:read",
        "the refresh must not widen the consent to the client's whole grant"
    );
    let claims = jwt
        .validate_token(body["access_token"].as_str().unwrap())
        .expect("the refreshed access token validates");
    assert_eq!(claims.scopes, vec![s("claims:read")], "access-token scopes");
    assert_eq!(
        live_scopes(&pool, client).await,
        vec![s("claims:read")],
        "the successor refresh token keeps the narrowed scopes"
    );

    let r1 = body["refresh_token"].as_str().unwrap().to_string();
    let (status, body) = post_token(app.clone(), refresh_grant(&r1)).await;
    assert_eq!(status, StatusCode::OK, "second refresh: {body}");
    assert_eq!(body["scope"], "claims:read", "nor does the second refresh");
}

/// The other direction, which must keep working: a scope revoked from the
/// client since the consent leaves the chain at its next refresh.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refresh_narrows_when_the_client_grant_shrinks(pool: PgPool) {
    let both = [s("claims:read"), s("claims:write")];
    let (client_id, client, code) = seed_code_with(&pool, &both, &both).await;
    let (app, jwt) = app_router_and_jwt(&pool, 2).await;
    let (status, body) = post_token(app.clone(), code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    assert_eq!(body["scope"], "claims:read claims:write");
    let r0 = body["refresh_token"].as_str().unwrap().to_string();

    sqlx::query("UPDATE oauth_clients SET granted_scopes = $2 WHERE id = $1")
        .bind(client)
        .bind(&[s("claims:read")][..])
        .execute(&pool)
        .await
        .unwrap();

    let (status, body) = post_token(app.clone(), refresh_grant(&r0)).await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    assert_eq!(body["scope"], "claims:read", "the revoked scope is gone");
    let claims = jwt
        .validate_token(body["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims.scopes, vec![s("claims:read")]);
    assert_eq!(live_scopes(&pool, client).await, vec![s("claims:read")]);
}

/// `client_credentials` mints its refresh token from `requested ∩ granted`;
/// refreshing it must not widen it to the whole grant either.
#[sqlx::test(migrations = "../../migrations")]
async fn a_client_credentials_refresh_never_widens_the_requested_scope(pool: PgPool) {
    let secret = [9u8; 32];
    let client_id = format!("u002_svc_{}", Uuid::new_v4().simple());
    let both = [s("claims:read"), s("claims:write")];
    let client = OAuthClientRepository::create(
        &pool,
        &client_id,
        Some(blake3::hash(&secret).as_bytes()),
        "u002 service",
        "service",
        &both,
        &both,
        "active",
        None,
        None,
        Some("U002 Test Entity"),
        Some("ops@example.test"),
        None,
    )
    .await
    .expect("seed service client");
    let (app, jwt) = app_router_and_jwt(&pool, 2).await;

    let (status, body) = post_token(
        app.clone(),
        serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": hex::encode(secret),
            "scope": "claims:read",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "client_credentials: {body}");
    assert_eq!(body["scope"], "claims:read");
    let rt = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(app.clone(), refresh_grant(&rt)).await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    assert_eq!(
        body["scope"], "claims:read",
        "the refresh must not widen a client_credentials token to the whole grant"
    );
    let claims = jwt
        .validate_token(body["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims.scopes, vec![s("claims:read")]);
    assert_eq!(live_scopes(&pool, client).await, vec![s("claims:read")]);
}

/// RFC 6749 section 6 lets a refresh request NARROW the access token with
/// `scope`; the new refresh token's scope stays identical to the presented
/// one's, so a later refresh without `scope` gets the full stored set back. A
/// requested scope outside the stored set is dropped, never added.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refresh_request_narrows_the_access_token_but_not_the_chain(pool: PgPool) {
    let both = [s("claims:read"), s("claims:write")];
    let (client_id, client, code) = seed_code_with(
        &pool,
        &[s("claims:read"), s("claims:write"), s("evidence:read")],
        &both,
    )
    .await;
    let (app, jwt) = app_router_and_jwt(&pool, 2).await;
    let (status, body) = post_token(app.clone(), code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    let r0 = body["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        app.clone(),
        serde_json::json!({
            "grant_type": "refresh_token",
            "refresh_token": r0,
            "scope": "claims:read  evidence:read",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "narrowing refresh: {body}");
    assert_eq!(
        body["scope"], "claims:read",
        "narrowed to the request, and evidence:read (granted to the client but never \
         consented) is not added"
    );
    let claims = jwt
        .validate_token(body["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims.scopes, vec![s("claims:read")]);
    assert_eq!(
        live_scopes(&pool, client).await,
        both.to_vec(),
        "the successor refresh token keeps the presented token's scopes"
    );

    let r1 = body["refresh_token"].as_str().unwrap().to_string();
    let (status, body) = post_token(app.clone(), refresh_grant(&r1)).await;
    assert_eq!(status, StatusCode::OK, "plain refresh: {body}");
    assert_eq!(body["scope"], "claims:read claims:write");
}

/// A refresh whose `scope` names none of the presented token's issuable scopes
/// is `invalid_scope` (RFC 6749 section 5.2), and it is refused BEFORE the
/// chain is spent: the same refresh token still works afterwards. Answering
/// 200 instead would rotate the chain into an access token that authorizes
/// nothing; on main the request's `scope` was ignored on refresh, so a client
/// sending an unrelated scope (`offline_access`) would fail silently.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refresh_scope_naming_nothing_issuable_is_refused_and_keeps_the_chain(pool: PgPool) {
    let (client_id, client, code) = seed_code_with(
        &pool,
        &[s("claims:read"), s("claims:write")],
        &[s("claims:read")],
    )
    .await;
    let app = app_router(&pool, 2).await;
    let (status, body) = post_token(app.clone(), code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    let r0 = body["refresh_token"].as_str().unwrap().to_string();

    for nothing in ["offline_access", "claims:write"] {
        let (status, body) = post_token(
            app.clone(),
            serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": r0,
                "scope": nothing,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "scope={nothing:?} names nothing this token can issue: {body}"
        );
        assert!(
            body.to_string().contains("invalid_scope"),
            "the refusal is invalid_scope: {body}"
        );
        assert!(
            body.get("access_token").is_none(),
            "no token issued: {body}"
        );
    }

    let (status, body) = post_token(app.clone(), refresh_grant(&r0)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refused requests did not spend the presented token: {body}"
    );
    assert_eq!(body["scope"], "claims:read");
    assert_eq!(live_scopes(&pool, client).await, vec![s("claims:read")]);
}

/// RFC 6749 section 5.1: a token response carries `Cache-Control: no-store`.
/// The whole anonymous `/oauth` router is marked so (the consent page carries
/// a single-use ticket; see `oauth_authorization_code.rs`).
#[sqlx::test(migrations = "../../migrations")]
async fn token_responses_are_not_cacheable(pool: PgPool) {
    let (client_id, _client, code) = seed_code(&pool).await;
    let app = app_router(&pool, 2).await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(code_grant(&code, &client_id).to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "a token response must not be cached"

/// POST `/oauth/revoke` for an access token.
async fn revoke_access_token(app: axum::Router, token: &str) -> StatusCode {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/revoke")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "token": token, "token_type_hint": "access_token" }).to_string(),
        ))
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

/// `GET /api/v1/webhooks` with `token`: behind `bearer_auth_middleware`, and
/// answered from the caller's principal alone (`RequirePrincipal`, no database
/// read), so an admitted token gets a plain 200 on this test's unscoped state.
async fn list_own_webhooks(app: axum::Router, token: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/webhooks")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// RFC 7009 access-token revocation is DURABLE (drain unit U003, review finding
/// on epigraph#282). It used to be an in-memory set inside one `AppState`, so a
/// revoked token worked again after a restart and on every other API process.
/// Router B is a second `AppState` on the same database and JWT secret: a
/// restart, or a second process. Its pool, like A's, is the application role,
/// so this also proves that role can write (through the definer) and read the
/// denylist.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_access_token_stays_revoked_in_another_process(pool: PgPool) {
    let (client_id, _client, code) = seed_code(&pool).await;
    let a = app_router(&pool, 2).await;
    let (status, body) = post_token(a.clone(), code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    let access = body["access_token"]
        .as_str()
        .expect("access token")
        .to_string();

    let b = app_router(&pool, 2).await;

    // CONTROL: before the revocation, B admits the token end to end.
    let (status, body) = list_own_webhooks(b.clone(), &access).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "control: an unrevoked token is admitted on B: {body}"
    );

    assert_eq!(
        revoke_access_token(a.clone(), &access).await,
        StatusCode::OK
    );

    // The control above admitted this very token, so a 401 now is the
    // revocation's; the body names it.
    let (status, body) = list_own_webhooks(b.clone(), &access).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a token revoked on A must be refused on B (another process / after a restart): {body}"
    );
    assert!(body.contains("revoked"), "refused AS revoked: {body}");
    // And on A itself, now that the in-memory set is gone.
    let (status, body) = list_own_webhooks(a, &access).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "refused on A too: {body}");
}

/// `/oauth/revoke` is on the anonymous OAuth router, so the access-token arm
/// must verify the token's signature before writing: otherwise anyone could
/// fill the denylist with chosen `jti`s. A validly signed token IS recorded
/// (calibration, so "nothing written" cannot pass because nothing ever is);
/// a token signed with another secret is answered 200 (RFC 7009) and is not.
#[sqlx::test(migrations = "../../migrations")]
async fn revoking_a_forged_access_token_writes_nothing(pool: PgPool) {
    use epigraph_db::RevokedAccessTokenRepository;
    let state = app_state(&pool, 2).await;
    let jwt = state.jwt_config.clone();
    let app = create_router(state);

    // CALIBRATION: a token this server signed is recorded.
    let (genuine, genuine_jti) = jwt
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:read".to_string()],
            "service",
            None,
            None,
            Duration::minutes(5),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("mint genuine");
    assert_eq!(
        revoke_access_token(app.clone(), &genuine).await,
        StatusCode::OK
    );
    assert!(
        RevokedAccessTokenRepository::is_revoked(&pool, genuine_jti)
            .await
            .expect("lookup"),
        "a validly signed token revoked through /oauth/revoke is recorded"
    );

    // A token signed with a different secret: 200, nothing recorded.
    let forger = epigraph_api::oauth::JwtConfig::from_secret(
        b"an-attacker-chosen-secret-of-at-least-32-bytes",
    );
    let (forged, forged_jti) = forger
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:admin".to_string()],
            "service",
            None,
            None,
            Duration::minutes(5),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("mint forged");
    assert_eq!(
        revoke_access_token(app.clone(), &forged).await,
        StatusCode::OK,
        "RFC 7009: an invalid token is answered 200"
    );
    assert!(
        !RevokedAccessTokenRepository::is_revoked(&pool, forged_jti)
            .await
            .expect("lookup"),
        "a token this server did not sign must not reach the denylist"
    );
    // Nor under any other key: the calibration row is the table's only row,
    // so a forged revoke that recorded a nil, random or derived jti fails here.
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM public.revoked_access_tokens")
        .fetch_one(&pool)
        .await
        .expect("count the denylist");
    assert_eq!(
        rows, 1,
        "only the genuine token's row: a forged revoke writes nothing at all"
    );
}

/// Clock skew on the REVOKING host (drain U003 follow-up). `/oauth/revoke` used
/// to gate the write on `validate_token`, which checks `exp` with zero leeway
/// on the revoking host's own clock. A revocation arriving just after `exp` by
/// that clock was answered 200 and recorded nothing, while a host lagging it
/// kept admitting the token. The endpoint now verifies signature, issuer and
/// audience only, and leaves expiry to the definer's 24-hour margin on the
/// database clock: a token 2 h past `exp` is recorded, one 25 h past is not.
#[sqlx::test(migrations = "../../migrations")]
async fn a_token_expired_on_the_revoking_host_is_still_recorded(pool: PgPool) {
    use epigraph_db::RevokedAccessTokenRepository;
    let state = app_state(&pool, 2).await;
    let jwt = state.jwt_config.clone();
    let app = create_router(state);

    let mint = |ttl: Duration| {
        jwt.issue_access_token(
            Uuid::new_v4(),
            vec!["claims:write".to_string()],
            "service",
            None,
            None,
            ttl,
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("mint")
    };
    let (recent, recent_jti) = mint(Duration::hours(-2));
    let (stale, stale_jti) = mint(Duration::hours(-25));

    // PRECONDITION: on this host's clock the token IS expired, so this is the
    // skew case (a lagging host may still admit it), not a live token.
    assert!(
        jwt.validate_token(&recent).is_err(),
        "precondition: a token 2 h past exp fails the strict admission check here"
    );

    assert_eq!(
        revoke_access_token(app.clone(), &recent).await,
        StatusCode::OK
    );
    assert!(
        RevokedAccessTokenRepository::is_revoked(&pool, recent_jti)
            .await
            .expect("lookup"),
        "a validly signed token 2 h past exp on the revoking host may still be \
         live on a lagging host: /oauth/revoke must record it"
    );

    // Beyond the margin the definer declines it: 200, nothing recorded.
    assert_eq!(revoke_access_token(app, &stale).await, StatusCode::OK);
    assert!(
        !RevokedAccessTokenRepository::is_revoked(&pool, stale_jti)
            .await
            .expect("lookup"),
        "a token 25 h past exp is outside the margin and is not recorded"
    );
}

/// `POST /oauth/introspect` with `token`: status and body, unasserted.
async fn introspect(app: axum::Router, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/introspect")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "token": token }).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// `POST /oauth/introspect` with `token`: the RFC 7662 `active` flag.
async fn introspect_active(app: axum::Router, token: &str) -> bool {
    let (status, body) = introspect(app, token).await;
    assert_eq!(status, StatusCode::OK, "introspection answers 200: {body}");
    body["active"].as_bool().expect("`active` is a boolean")
}

/// `GET /api/v1/openapi.json`, with `token` when given: a route on the
/// anonymous allowlist router, behind `optional_bearer_auth_middleware` (a
/// PRESENT token must still be valid there; an absent one is let through).
async fn openapi(app: axum::Router, token: Option<&str>) -> StatusCode {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/openapi.json");
    if let Some(token) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    app.oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

/// A token minted through the code grant on router A, and a second router B
/// (another `AppState`: a restart, or another process) on the same database.
async fn token_and_second_router(pool: &PgPool) -> (axum::Router, String, axum::Router) {
    let (client_id, _client, code) = seed_code(pool).await;
    let a = app_router(pool, 2).await;
    let (status, body) = post_token(a.clone(), code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    let access = body["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    let b = app_router(pool, 2).await;
    (a, access, b)
}

/// `/oauth/introspect` honours a revocation (RFC 7662 `active: false`).
/// Revoked on router A, observed on router B after a control on B that
/// introspects the same token active. On origin/main it stays active on B (the
/// in-memory set lived on A only).
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_access_token_is_inactive_on_introspection(pool: PgPool) {
    let (a, access, b) = token_and_second_router(&pool).await;

    assert!(
        introspect_active(b.clone(), &access).await,
        "control: an unrevoked token introspects active"
    );

    assert_eq!(revoke_access_token(a, &access).await, StatusCode::OK);

    assert!(
        !introspect_active(b, &access).await,
        "a revoked token introspects inactive (RFC 7662)"
    );
}

/// `optional_bearer_auth_middleware` (the anonymous allowlist router, where a
/// present token must be valid) honours a revocation. Its own test, so a
/// revocation check removed from this middleware alone fails here and nowhere
/// else.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_access_token_is_refused_on_the_allowlist_router(pool: PgPool) {
    let (a, access, b) = token_and_second_router(&pool).await;

    assert_eq!(
        openapi(b.clone(), Some(&access)).await,
        StatusCode::OK,
        "control: an unrevoked token passes the optional middleware"
    );

    assert_eq!(revoke_access_token(a, &access).await, StatusCode::OK);

    assert_eq!(
        openapi(b, Some(&access)).await,
        StatusCode::UNAUTHORIZED,
        "a revoked token presented on the allowlist router is refused, not ignored"
    );
}

/// A revocation lookup that cannot answer fails CLOSED on every API surface
/// that consults it: `bearer_auth_middleware`, `optional_bearer_auth_middleware`
/// and `/oauth/introspect` each answer 503, never admit the token and never
/// introspect it `active: true`.
///
/// The lookup is broken by renaming the denylist table on the owner pool (this
/// test's database only). Everything else the routes touch still works, so a
/// fail-OPEN mutation (an `Err` treated as "not revoked") turns each 503 into a
/// 200 here, rather than into some other error a dead pool would produce
/// further down. The three outcomes are asserted together so a run shows every
/// surface's answer at once.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unanswerable_revocation_lookup_fails_closed(pool: PgPool) {
    let (_a, access, b) = token_and_second_router(&pool).await;

    // CONTROLS on B: the token is valid, unrevoked and admitted everywhere.
    let (status, body) = list_own_webhooks(b.clone(), &access).await;
    assert_eq!(status, StatusCode::OK, "control: webhooks admits: {body}");
    assert_eq!(
        openapi(b.clone(), Some(&access)).await,
        StatusCode::OK,
        "control: the optional middleware admits"
    );
    assert!(
        introspect_active(b.clone(), &access).await,
        "control: introspects active"
    );

    sqlx::query("ALTER TABLE public.revoked_access_tokens RENAME TO revoked_access_tokens_gone")
        .execute(&pool)
        .await
        .expect("break the revocation lookup");

    // The server is otherwise up: the allowlist route still answers an
    // anonymous caller, so a 503 below can only be the revocation lookup's.
    assert_eq!(
        openapi(b.clone(), None).await,
        StatusCode::OK,
        "control: the allowlist router answers without a token"
    );

    let (webhooks, webhooks_body) = list_own_webhooks(b.clone(), &access).await;
    let allowlist = openapi(b.clone(), Some(&access)).await;
    let (introspection, introspection_body) = introspect(b, &access).await;
    assert_eq!(
        (webhooks, allowlist, introspection),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        "(bearer middleware, optional middleware, introspection) must fail closed with 503; \
         webhooks body: {webhooks_body}; introspection body: {introspection_body}"
    );
    assert_ne!(
        introspection_body["active"],
        Value::Bool(true),
        "an unknown revocation state never introspects active"
    );
}
