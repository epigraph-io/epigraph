#![cfg(feature = "db")]
//! Access tokens carry their refresh family (`fam`) and an elevation slot
//! (`elv`).
//!
//! The elevation stack binds an elevation session to the refresh-token family
//! of the human session that asked for it. That needs the family on the
//! ACCESS token, which until now carried only `{sub, iss, aud, exp, iat, nbf,
//! jti, scopes, client_type, owner_id, agent_id}`. Both new claims are
//! optional: a token minted by a binary that predates them must still decode,
//! and a token minted by this binary must still decode under the previous
//! struct, because API and MCP binaries roll one at a time (N-1, both ways).
//!
//! The claims are not authority. `elv` is not minted by anything yet, and
//! nothing reads `fam` or `elv` as a grant of anything: a later batch
//! resolves them against a live database row.
//!
//! Each test names the mutation it is there to catch.

mod oauth_providers;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use base64::Engine as _;
use chrono::Duration;
use ed25519_dalek::{Signer, SigningKey};
use epigraph_api::oauth::providers::{
    config::{ProviderConfig, ProviderFlow},
    google::GoogleProvider,
    jwks::JwksCache,
    ExternalIdentityProvider, OidcRedirectFlow, ProviderRegistry,
};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_auth::{AccessTokenBinding, AuthContext, EpiGraphClaims, JwtConfig};
use epigraph_db::repos::authorization_code::AuthorizationCodeRepository;
use epigraph_db::repos::oauth_client::OAuthClientRepository;
use http_body_util::BodyExt;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use oauth_providers::fixtures::ProviderFixture;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const SECRET: &[u8] = b"token-family-claim-test-secret-of-adequate-length";

/// A FROZEN copy of `epigraph_auth::EpiGraphClaims` as it was before `fam`
/// and `elv` existed (branch head before this batch). Never edit it to track
/// the live struct: it stands for the binary one release back.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct PreviousClaims {
    sub: Uuid,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    nbf: i64,
    jti: Uuid,
    scopes: Vec<String>,
    client_type: String,
    owner_id: Option<Uuid>,
    agent_id: Option<Uuid>,
}

fn validation() -> Validation {
    let mut v = Validation::new(Algorithm::HS256);
    v.set_issuer(&["epigraph"]);
    v.set_audience(&["epigraph-api"]);
    v.leeway = 0;
    v
}

/// The payload segment of a compact JWS, as JSON.
fn payload(token: &str) -> serde_json::Value {
    let seg = token
        .split('.')
        .nth(1)
        .expect("a compact JWS has a payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seg)
        .expect("base64url payload");
    serde_json::from_slice(&bytes).expect("JSON payload")
}

fn previous_claims_now() -> PreviousClaims {
    let now = chrono::Utc::now().timestamp();
    PreviousClaims {
        sub: Uuid::new_v4(),
        iss: "epigraph".into(),
        aud: "epigraph-api".into(),
        exp: now + 300,
        iat: now,
        nbf: now,
        jti: Uuid::new_v4(),
        scopes: vec!["claims:read".into()],
        client_type: "human".into(),
        owner_id: None,
        agent_id: Some(Uuid::new_v4()),
    }
}

// =============================================================================
// N-1, both ways, and the claim shape
// =============================================================================

/// An OLD binary decodes a NEW token carrying both claims, and reads every
/// claim it knows exactly as the new binary wrote it.
///
/// Catches: renaming or retyping an existing claim while adding the new ones
/// (e.g. `#[serde(rename = "scope")]` on `scopes`): the old struct then fails
/// to decode, or decodes a different value.
#[test]
fn a_token_with_fam_and_elv_decodes_under_the_previous_claims_struct() {
    let cfg = JwtConfig::from_secret(SECRET);
    let client = Uuid::new_v4();
    let agent = Uuid::new_v4();
    let fam = Uuid::new_v4();
    let elv = Uuid::new_v4();
    let binding = AccessTokenBinding {
        family_id: Some(fam),
        elevation_id: Some(elv),
    };
    let (token, jti) = cfg
        .issue_access_token(
            client,
            vec!["claims:read".into()],
            "human",
            Some(agent),
            Some(agent),
            Duration::minutes(5),
            binding,
        )
        .expect("mint");

    let old = decode::<PreviousClaims>(&token, &DecodingKey::from_secret(SECRET), &validation())
        .expect("the previous claims struct must decode a token carrying fam and elv")
        .claims;
    assert_eq!(old.sub, client);
    assert_eq!(old.jti, jti);
    assert_eq!(old.agent_id, Some(agent));
    assert_eq!(old.owner_id, Some(agent));
    assert_eq!(old.scopes, vec!["claims:read".to_string()]);
    assert_eq!(old.client_type, "human");

    // And the new binary reads the new claims back.
    let new = cfg.validate_token(&token).expect("current struct decodes");
    assert_eq!(new.fam, Some(fam));
    assert_eq!(new.elv, Some(elv));
}

/// A NEW binary decodes an OLD token (no `fam`, no `elv`): both read `None`.
///
/// Catches: a claim that demands its key, which would log out every live
/// session at deploy. Serde reads a missing plain `Option` as `None` on its
/// own, so the realistic way to get there is giving the claim a custom
/// `deserialize_with` and losing the `default` beside it (the mutation run
/// for this test), or retyping it to a bare `Uuid`.
#[test]
fn a_token_without_the_new_claims_decodes_under_the_current_struct() {
    let old = previous_claims_now();
    let token = encode(
        &Header::new(Algorithm::HS256),
        &old,
        &EncodingKey::from_secret(SECRET),
    )
    .expect("encode previous claims");

    let claims = JwtConfig::from_secret(SECRET)
        .validate_token(&token)
        .expect("the current struct must decode a token minted before fam/elv existed");
    assert_eq!(claims.fam, None);
    assert_eq!(claims.elv, None);
    assert_eq!(claims.agent_id, old.agent_id);
    assert_eq!(claims.jti, old.jti);
}

/// A claim this binary does not know is ignored, not refused. The next
/// binary (N+1) may add one, and this binary must keep serving its tokens.
///
/// Catches: `#[serde(deny_unknown_fields)]` on `EpiGraphClaims`.
#[test]
fn an_unknown_claim_is_ignored_by_the_current_struct() {
    let mut body = serde_json::to_value(previous_claims_now()).expect("to JSON");
    body["fam"] = serde_json::json!(Uuid::new_v4());
    body["a_claim_from_a_later_release"] = serde_json::json!({"anything": [1, 2, 3]});
    let token = encode(
        &Header::new(Algorithm::HS256),
        &body,
        &EncodingKey::from_secret(SECRET),
    )
    .expect("encode");

    JwtConfig::from_secret(SECRET)
        .validate_token(&token)
        .expect("an unknown claim must not make the token invalid");
}

/// A token with no family and no elevation does not carry the keys at all:
/// the wire shape of every token that does not need them is unchanged.
///
/// Catches: dropping `skip_serializing_if = "Option::is_none"` (the payload
/// would then carry `"fam": null` / `"elv": null`).
#[test]
fn a_token_with_no_binding_carries_neither_key() {
    let (token, _) = JwtConfig::from_secret(SECRET)
        .issue_access_token(
            Uuid::new_v4(),
            vec![],
            "agent",
            None,
            Some(Uuid::new_v4()),
            Duration::minutes(5),
            AccessTokenBinding::NONE,
        )
        .expect("mint");
    let body = payload(&token);
    let obj = body.as_object().expect("payload object");
    assert!(!obj.contains_key("fam"), "no family, no key: {body}");
    assert!(!obj.contains_key("elv"), "no elevation, no key: {body}");
}

/// The validated claims reach the request's `AuthContext` as CLAIMS:
/// `family_id` and `elevation_claim`.
///
/// Catches: a `From<EpiGraphClaims> for AuthContext` that drops either claim
/// (`family_id: None`), which would leave the later elevation resolution
/// with nothing to resolve.
#[test]
fn fam_and_elv_reach_the_auth_context() {
    let cfg = JwtConfig::from_secret(SECRET);
    let fam = Uuid::new_v4();
    let elv = Uuid::new_v4();
    let (token, _) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec![],
            "human",
            None,
            Some(Uuid::new_v4()),
            Duration::minutes(5),
            AccessTokenBinding {
                family_id: Some(fam),
                elevation_id: Some(elv),
            },
        )
        .expect("mint");
    let ctx: AuthContext = cfg.validate_token(&token).expect("valid").into();
    assert_eq!(ctx.family_id, Some(fam));
    assert_eq!(ctx.elevation_claim, Some(elv));

    let (token, _) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec![],
            "human",
            None,
            Some(Uuid::new_v4()),
            Duration::minutes(5),
            AccessTokenBinding::NONE,
        )
        .expect("mint");
    let ctx: AuthContext = cfg.validate_token(&token).expect("valid").into();
    assert_eq!(ctx.family_id, None);
    assert_eq!(ctx.elevation_claim, None);
}

// =============================================================================
// The grants: which tokens carry a family, and which family
// =============================================================================
//
// THE RULE: `fam` is stamped iff the response issues a refresh token AND the
// client is a `human` client, and it is that refresh token's family
// (`COALESCE(family_id, id)`, migration 118). Agents and services never carry
// one: an agent never elevates, so a family on its token could only ever cost
// the later elevation resolution a database round trip that answers "no".
//
// Every request below is served on a pool whose connections run as the
// deployed application role, so the family read goes through 118's column
// grant on `refresh_tokens`, not a superuser's.

const REDIRECT_URI: &str = "https://claude.ai/api/mcp/auth_callback";
const VERIFIER: &str = "el1-fixed-pkce-code-verifier-of-adequate-length-0123456789";

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

/// A pool whose every connection is `epigraph_app`.
async fn app_role_pool(pool: &PgPool) -> PgPool {
    use sqlx::Executor;
    sqlx::postgres::PgPoolOptions::new()
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
        .expect("application-role pool")
}

/// The router on the application role, plus the `JwtConfig` it mints with.
async fn app(pool: &PgPool) -> (axum::Router, Arc<JwtConfig>) {
    let state = AppState::with_db(app_role_pool(pool).await, config());
    let jwt = state.jwt_config.clone();
    (create_router(state), jwt)
}

async fn post_json(app: axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
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
async fn seed_code(pool: &PgPool) -> (String, String) {
    let unique = Uuid::new_v4().simple().to_string();
    let client_id = format!("el1_{unique}");
    let scopes = vec!["claims:read".to_string()];
    let id = OAuthClientRepository::create(
        pool,
        &client_id,
        None,
        "el1 connector",
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
        chrono::Utc::now() + Duration::minutes(5),
    )
    .await
    .expect("seed code");
    (client_id, code)
}

fn code_grant(code: &str, client_id: &str) -> Value {
    json!({
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": VERIFIER,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
    })
}

fn refresh_grant(token: &str) -> Value {
    json!({ "grant_type": "refresh_token", "refresh_token": token })
}

/// `(id, COALESCE(family_id, id))` of the refresh row a returned refresh
/// token names, read on the superuser pool by the token's hash.
async fn refresh_row(pool: &PgPool, refresh_token: &str) -> (Uuid, Uuid) {
    let hash = blake3::hash(&hex::decode(refresh_token).expect("hex refresh token"));
    sqlx::query_as("SELECT id, COALESCE(family_id, id) FROM refresh_tokens WHERE token_hash = $1")
        .bind(hash.as_bytes().as_slice())
        .fetch_one(pool)
        .await
        .expect("the returned refresh token has a row")
}

fn claims_of(jwt: &JwtConfig, body: &Value) -> EpiGraphClaims {
    let token = body["access_token"].as_str().expect("access_token");
    jwt.validate_token(token)
        .expect("the minted token validates")
}

/// The authorization-code grant stamps the family of the refresh token it
/// issues in the same response.
///
/// Catches: a `fam` that is not the issued refresh row's family, e.g. taken
/// from a fresh `Uuid::new_v4()`, or the code grant left unbound.
#[sqlx::test(migrations = "../../migrations")]
async fn code_exchange_stamps_the_family_of_the_refresh_it_issues(pool: PgPool) {
    let (client_id, code) = seed_code(&pool).await;
    let (app, jwt) = app(&pool).await;

    let (status, body) = post_json(app, "/oauth/token", code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    let (r0_id, r0_family) = refresh_row(&pool, body["refresh_token"].as_str().unwrap()).await;
    assert_eq!(
        r0_family, r0_id,
        "PREMISE: a fresh refresh row opens its own family"
    );

    let claims = claims_of(&jwt, &body);
    assert_eq!(
        claims.fam,
        Some(r0_family),
        "the code grant's access token names the family of the refresh it issued"
    );
    assert_eq!(
        claims.elv, None,
        "the code grant never mints elv (only the elevate grant does)"
    );
}

/// Rotation keeps the family: the access token minted by a refresh names the
/// family of the chain, not the id of the token presented or of its
/// successor. Two rotations, because on the FIRST one the presented token's
/// id IS the family.
///
/// Catches: a refresh grant that starts a new family (`fam` = the successor's
/// id) or that names the presented token (`fam` = its id), or a refresh grant
/// left unbound.
#[sqlx::test(migrations = "../../migrations")]
async fn refresh_rotation_keeps_the_family(pool: PgPool) {
    let (client_id, code) = seed_code(&pool).await;
    let (app, jwt) = app(&pool).await;

    let (status, body) =
        post_json(app.clone(), "/oauth/token", code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    let r0 = body["refresh_token"].as_str().unwrap().to_string();
    let (_, family) = refresh_row(&pool, &r0).await;

    let (status, body) = post_json(app.clone(), "/oauth/token", refresh_grant(&r0)).await;
    assert_eq!(status, StatusCode::OK, "first refresh: {body}");
    assert_eq!(claims_of(&jwt, &body).fam, Some(family), "first rotation");
    let r1 = body["refresh_token"].as_str().unwrap().to_string();
    let (r1_id, r1_family) = refresh_row(&pool, &r1).await;
    assert_eq!(r1_family, family, "PREMISE: 118 rotates within the family");
    assert_ne!(r1_id, family, "PREMISE: the successor is a new row");

    let (status, body) = post_json(app, "/oauth/token", refresh_grant(&r1)).await;
    assert_eq!(status, StatusCode::OK, "second refresh: {body}");
    let (r2_id, _) = refresh_row(&pool, body["refresh_token"].as_str().unwrap()).await;
    let claims = claims_of(&jwt, &body);
    assert_eq!(
        claims.fam,
        Some(family),
        "the second rotation still names the chain's family"
    );
    assert_ne!(claims.fam, Some(r1_id), "not the presented token");
    assert_ne!(claims.fam, Some(r2_id), "not the successor");
}

// ── Agents ───────────────────────────────────────────────────────────────────

/// An agent row whose public key is `key`'s, plus an ACTIVE agent-type OAuth
/// client for it (with the human owner client `agents_must_have_owner`
/// requires). Returns the client id (hex public key).
async fn agent_with_active_client(pool: &PgPool, key: &SigningKey) -> String {
    let public_key = key.verifying_key().to_bytes();
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(public_key.to_vec())
        .execute(pool)
        .await
        .expect("agent row");
    let owner: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status) \
         VALUES ($1, 'owner', 'human', ARRAY['claims:read'], ARRAY['claims:read'], 'active') \
         RETURNING id",
    )
    .bind(format!("owner-{agent}"))
    .fetch_one(pool)
    .await
    .expect("owner client");
    let client_id = hex::encode(public_key);
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id, owner_id) \
         VALUES ($1, 'el1-agent', 'agent', ARRAY['claims:read'], \
                 ARRAY['claims:read'], 'active', $2, $3)",
    )
    .bind(&client_id)
    .bind(agent)
    .bind(owner)
    .execute(pool)
    .await
    .expect("agent client");
    client_id
}

/// `timestamp(8B BE) || nonce(16B) || Ed25519(timestamp || nonce)`, base64.
fn assertion(key: &SigningKey) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let mut msg = Vec::with_capacity(88);
    msg.extend_from_slice(&ts.to_be_bytes());
    msg.extend_from_slice(Uuid::new_v4().as_bytes());
    let sig = key.sign(&msg);
    msg.extend_from_slice(&sig.to_bytes());
    base64::engine::general_purpose::STANDARD.encode(msg)
}

/// An agent's `client_credentials` token carries no family, although the
/// grant issues it a refresh token; and neither does the token that refresh
/// token later buys.
///
/// Catches: binding on "a refresh token was issued" instead of "a refresh
/// token was issued TO A HUMAN CLIENT", in either the client-credentials
/// grant or the refresh grant (the second half fails if the refresh grant
/// stamps every rotation).
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_token_carries_no_family_from_either_grant(pool: PgPool) {
    let key = SigningKey::from_bytes(&[0x51; 32]);
    let client_id = agent_with_active_client(&pool, &key).await;
    let (app, jwt) = app(&pool).await;

    let (status, body) = post_json(
        app.clone(),
        "/oauth/token",
        json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_assertion_type": "urn:epigraph:ed25519",
            "client_assertion": assertion(&key),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "agent assertion grant: {body}");
    let refresh = body["refresh_token"]
        .as_str()
        .expect("PREMISE: the agent grant issues a refresh token")
        .to_string();
    let claims = claims_of(&jwt, &body);
    assert_eq!(claims.client_type, "agent");
    assert_eq!(claims.fam, None, "an agent token carries no family");

    let (status, body) = post_json(app, "/oauth/token", refresh_grant(&refresh)).await;
    assert_eq!(status, StatusCode::OK, "agent refresh: {body}");
    let claims = claims_of(&jwt, &body);
    assert_eq!(
        claims.fam, None,
        "a refreshed agent token carries no family either"
    );
}

// ── The external-assertion grant ─────────────────────────────────────────────

fn google_registry(fx: &ProviderFixture) -> Arc<ProviderRegistry> {
    let cid_var = "TOKEN_FAMILY_CLAIM_GOOGLE_CLIENT_ID".to_string();
    let sec_var = "TOKEN_FAMILY_CLAIM_GOOGLE_CLIENT_SECRET".to_string();
    std::env::set_var(&cid_var, "test-audience");
    std::env::set_var(&sec_var, "test-secret");
    let cfg = ProviderConfig {
        name: "google".into(),
        flow: ProviderFlow::Redirect,
        grant_type: "google_id_token".into(),
        issuer: "https://accounts.google.com".into(),
        extra_issuers: vec![],
        jwks_url: fx.jwks_url.clone(),
        audience: None,
        audience_env: Some(cid_var.clone()),
        client_id_env: Some(cid_var),
        client_secret_env: Some(sec_var),
        auth_endpoint: Some("https://example/auth".into()),
        token_endpoint: Some("https://example/token".into()),
        redirect_uri: None,
        redirect_uri_env: None,
        auto_provision: true,
        default_scopes: vec!["claims:read".into()],
        allowed_emails: vec![],
        allowed_domains: vec![],
    };
    let provider = Arc::new(GoogleProvider::from_config(&cfg, JwksCache::new()).unwrap());
    let mut r = ProviderRegistry::empty();
    r.register(
        provider.clone() as Arc<dyn ExternalIdentityProvider>,
        Some(provider as Arc<dyn OidcRedirectFlow>),
    )
    .unwrap();
    Arc::new(r)
}

/// The external-assertion grant provisions a HUMAN client and issues it a
/// refresh token, so its access token names that refresh token's family.
///
/// Catches: the fourth mint site (`provision_external_user`) left unbound,
/// or bound to anything but the refresh row it issued.
#[sqlx::test(migrations = "../../migrations")]
async fn the_external_grant_stamps_the_family_of_the_refresh_it_issues(pool: PgPool) {
    let fx = ProviderFixture::new().await;
    let state = AppState::with_db(app_role_pool(&pool).await, config())
        .with_providers(google_registry(&fx));
    let jwt = state.jwt_config.clone();
    let now = chrono::Utc::now().timestamp();
    let id_token = fx.sign(&json!({
        "iss": "https://accounts.google.com",
        "aud": "test-audience",
        "sub": "el1-subject",
        "email": "el1@example.com",
        "email_verified": true,
        "name": "el1",
        "iat": now,
        "exp": now + 600,
    }));

    let (status, body) = post_json(
        create_router(state),
        "/oauth/token",
        json!({ "grant_type": "google_id_token", "assertion": id_token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "external grant: {body}");
    let (_, family) = refresh_row(&pool, body["refresh_token"].as_str().unwrap()).await;
    let claims = claims_of(&jwt, &body);
    assert_eq!(claims.client_type, "human");
    assert_eq!(claims.fam, Some(family));
    assert_eq!(
        claims.elv, None,
        "the external grant never mints elv (only the elevate grant does)"
    );
}

// ── Introspection ────────────────────────────────────────────────────────────

/// `/oauth/introspect` echoes `fam` for a token that carries one, and omits
/// it for one that does not.
///
/// Catches: an introspection response that drops the family (the field is
/// never set), or one that invents one for an unbound token.
#[sqlx::test(migrations = "../../migrations")]
async fn introspection_echoes_the_family(pool: PgPool) {
    let (client_id, code) = seed_code(&pool).await;
    let (app, jwt) = app(&pool).await;
    let (status, body) =
        post_json(app.clone(), "/oauth/token", code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    let family = claims_of(&jwt, &body).fam.expect("PREMISE: a bound token");

    let (status, intro) = post_json(
        app.clone(),
        "/oauth/introspect",
        json!({ "token": body["access_token"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{intro}");
    assert_eq!(intro["active"], json!(true), "{intro}");
    assert_eq!(intro["fam"], json!(family.to_string()), "{intro}");

    let (unbound, _) = jwt
        .issue_access_token(
            Uuid::new_v4(),
            vec![],
            "agent",
            None,
            Some(Uuid::new_v4()),
            Duration::minutes(5),
            AccessTokenBinding::NONE,
        )
        .expect("mint");
    let (status, intro) = post_json(app, "/oauth/introspect", json!({ "token": unbound })).await;
    assert_eq!(status, StatusCode::OK, "{intro}");
    assert_eq!(intro["active"], json!(true), "{intro}");
    assert!(
        intro.as_object().is_some_and(|o| !o.contains_key("fam")),
        "an unbound token's introspection carries no fam: {intro}"
    );
}

/// RFC 7662 answers the scopes a token HOLDS at this instant, as the API's
/// own check chokepoint (`AuthContext::has_scope`) grants them on an
/// UNELEVATED request (final review F1-SEC-02). Armed (migration 128's
/// switch), an admin-only scope the token still carries is not reported; and
/// `platform:admin` never is (introspection resolves no elevation, so it
/// under-reports an elevated token rather than vouch for a session that may
/// have ended). Calibration: unarmed, the admin-only scope is reported; the
/// ordinary scope always is; the token is active throughout.
///
/// Verified to fail with the token's raw `scopes` reported (the code before
/// this test): `platform:admin` is reported unarmed, and armed `claims:admin`
/// is still reported.
#[sqlx::test(migrations = "../../migrations")]
async fn introspection_reports_only_the_scopes_a_check_would_grant(pool: PgPool) {
    let state = AppState::with_db(app_role_pool(&pool).await, config())
        .with_admin_scope_arming_ttl(std::time::Duration::ZERO);
    let jwt = state.jwt_config.clone();
    let app = create_router(state);
    let (token, _) = jwt
        .issue_access_token(
            Uuid::new_v4(),
            vec![
                "claims:read".to_string(),
                "claims:admin".to_string(),
                "platform:admin".to_string(),
            ],
            "human",
            None,
            Some(Uuid::new_v4()),
            Duration::minutes(5),
            AccessTokenBinding {
                family_id: Some(Uuid::new_v4()),
                elevation_id: Some(Uuid::new_v4()),
            },
        )
        .expect("mint");
    assert!(
        jwt.validate_token(&token)
            .expect("valid")
            .scopes
            .contains(&"platform:admin".to_string()),
        "PREMISE: the token carries platform:admin (it names an elevation)"
    );
    let scopes = |intro: &Value| -> Vec<String> {
        let mut v: Vec<String> = intro["scope"]
            .as_str()
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect();
        v.sort();
        v
    };

    let (status, intro) =
        post_json(app.clone(), "/oauth/introspect", json!({ "token": token })).await;
    assert_eq!(status, StatusCode::OK, "{intro}");
    assert_eq!(intro["active"], json!(true), "{intro}");
    assert_eq!(
        scopes(&intro),
        vec!["claims:admin", "claims:read"],
        "unarmed: the admin-only scope is held; platform:admin never is: {intro}"
    );

    sqlx::query("SELECT * FROM public.epigraph_set_admin_scope_enforcement(true, 'f1 sec-02')")
        .execute(&pool)
        .await
        .expect("arm");
    let (status, intro) = post_json(app, "/oauth/introspect", json!({ "token": token })).await;
    assert_eq!(status, StatusCode::OK, "{intro}");
    assert_eq!(intro["active"], json!(true), "{intro}");
    assert_eq!(
        scopes(&intro),
        vec!["claims:read"],
        "armed: the admin-only scope counts for nothing on an unelevated check: {intro}"
    );
}
