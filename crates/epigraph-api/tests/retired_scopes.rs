#![cfg(feature = "db")]
//! Scopes retired from issuance (backlog 7b2e8e26): `claims:challenge`,
//! `claims:delete`, `evidence:read`, `ingest:write` and `policy:challenge`
//! are checked by no gate, so they are no longer minted, and clients and
//! chains that already hold one keep working. Driven through the real
//! `/oauth/token` route against a `#[sqlx::test]` database:
//!
//! * a refresh chain that HOLDS `claims:delete` (minted before the retirement)
//!   refreshes, and the access token does not carry it;
//! * a refresh that REQUESTS a retired scope narrows it away (with a live
//!   scope: that one; alone: as originally granted) instead of failing
//!   `invalid_scope`;
//! * a client whose grant still lists retired scopes mints without them, and
//!   the chain it opens does not store them.
//!
//! * no registration path, no external-provider provisioning and no
//!   `scopes_supported` hands one out;
//! * outside the two retired-scope lists, no crate source (tests aside) names
//!   one as a string literal.
//!
//! The delegated ceiling's tolerance is measured in `middleware::bearer`'s
//! unit tests (`delegated_ceiling_tests`) and in `epigraph-auth`.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use chrono::{Duration, Utc};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_auth::{EpiGraphClaims, JwtConfig};
use epigraph_db::repos::oauth_client::OAuthClientRepository;
use epigraph_db::repos::refresh_token::RefreshTokenRepository;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

// The external grant's fixture (shared with the provider suites).
mod oauth_providers;

use epigraph_api::oauth::providers::{
    config::{ProviderConfig, ProviderFlow},
    google::GoogleProvider,
    jwks::JwksCache,
    ExternalIdentityProvider, OidcRedirectFlow, ProviderRegistry,
};
use oauth_providers::fixtures::ProviderFixture;
use std::sync::Arc;

fn config() -> ApiConfig {
    ApiConfig {
        require_packet_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "https://test.example".to_string(),
        allow_all_identities: true,
    }
}

fn v(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| (*s).to_string()).collect()
}

async fn post_token(app: &axum::Router, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The access token's scopes, sorted.
fn token_scopes(jwt: &JwtConfig, body: &Value) -> Vec<String> {
    let token = body["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("access_token: {body}"));
    let claims: EpiGraphClaims = jwt.validate_token(token).expect("the token validates");
    let mut scopes = claims.scopes;
    scopes.sort();
    scopes
}

/// The `scope` member of a token response, sorted.
fn response_scopes(body: &Value) -> Vec<String> {
    let mut scopes: Vec<String> = body["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    scopes.sort();
    scopes
}

/// An active human client granted `scopes`, and one refresh token for it
/// whose chain HOLDS `scopes` (seeded directly: a chain opened before the
/// retirement). Returns the raw refresh token.
async fn legacy_human_chain(pool: &PgPool, scopes: &[String]) -> String {
    let client_id = format!("retired_{}", Uuid::new_v4().simple());
    let id = OAuthClientRepository::create(
        pool,
        &client_id,
        None,
        "retired-scope test",
        "human",
        scopes,
        scopes,
        "active",
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("seed client");
    let raw: [u8; 32] = rand::random();
    RefreshTokenRepository::create(
        pool,
        blake3::hash(&raw).as_bytes(),
        id,
        scopes,
        Utc::now() + Duration::days(1),
    )
    .await
    .expect("seed a refresh token");
    hex::encode(raw)
}

fn refresh(token: &str, scope: Option<&str>) -> Value {
    let mut body = json!({ "grant_type": "refresh_token", "refresh_token": token });
    if let Some(scope) = scope {
        body["scope"] = json!(scope);
    }
    body
}

/// `epigraph-auth` spells the retired scopes itself (it does not depend on
/// `epigraph-core`); the two lists are the same set.
#[test]
fn the_auth_crate_names_the_canonical_retired_scopes() {
    let mut auth: Vec<&str> = epigraph_auth::RETIRED_SCOPES.to_vec();
    let mut core: Vec<&str> = epigraph_core::canonical_scopes::RETIRED_SCOPES.to_vec();
    auth.sort_unstable();
    core.sort_unstable();
    assert_eq!(auth, core);
    assert_eq!(core.len(), 5);
}

/// Catches: a held retired scope being minted again on refresh. A chain that
/// holds `claims:delete` refreshes (200) and the access token, the response's
/// `scope` and the chain keep working without it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refresh_token_holding_claims_delete_refreshes_without_it(pool: PgPool) {
    let held = v(&["claims:read", "claims:delete", "edges:read"]);
    let r0 = legacy_human_chain(&pool, &held).await;
    let st = AppState::with_db(pool.clone(), config());
    let jwt = st.jwt_config.clone();
    let app = create_router(st);

    let (status, body) = post_token(&app, refresh(&r0, None)).await;
    assert_eq!(status, StatusCode::OK, "the refresh succeeds: {body}");
    assert_eq!(token_scopes(&jwt, &body), v(&["claims:read", "edges:read"]));
    assert_eq!(response_scopes(&body), v(&["claims:read", "edges:read"]));

    // The successor refreshes too.
    let r1 = body["refresh_token"]
        .as_str()
        .expect("successor")
        .to_string();
    let (status, body) = post_token(&app, refresh(&r1, None)).await;
    assert_eq!(status, StatusCode::OK, "the successor refreshes: {body}");
    assert_eq!(token_scopes(&jwt, &body), v(&["claims:read", "edges:read"]));
}

/// Catches: a refresh that NAMES a retired scope either minting it or
/// failing. Beside a live scope it narrows to the live one; alone it means
/// "as originally granted", not `invalid_scope`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refresh_requesting_a_retired_scope_narrows_it_away(pool: PgPool) {
    let held = v(&["claims:read", "claims:delete", "edges:read"]);
    let st = AppState::with_db(pool.clone(), config());
    let jwt = st.jwt_config.clone();
    let app = create_router(st);

    let r0 = legacy_human_chain(&pool, &held).await;
    let (status, body) = post_token(&app, refresh(&r0, Some("claims:read claims:delete"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(token_scopes(&jwt, &body), v(&["claims:read"]));

    let r0 = legacy_human_chain(&pool, &held).await;
    let (status, body) = post_token(&app, refresh(&r0, Some("claims:delete"))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a request naming only a retired scope is not invalid_scope: {body}"
    );
    assert_eq!(token_scopes(&jwt, &body), v(&["claims:read", "edges:read"]));

    // A retired scope the chain never held is ignored the same way.
    let r0 = legacy_human_chain(&pool, &held).await;
    let (status, body) = post_token(&app, refresh(&r0, Some("edges:read ingest:write"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(token_scopes(&jwt, &body), v(&["edges:read"]));
}

/// Catches: `client_credentials` minting a retired scope a client's grant
/// still lists, or storing it in the chain it opens. A request naming only a
/// retired scope mints the client's live grant.
#[sqlx::test(migrations = "../../migrations")]
async fn a_client_granted_retired_scopes_mints_without_them(pool: PgPool) {
    let granted = v(&[
        "claims:read",
        "evidence:read",
        "ingest:write",
        "policy:challenge",
        "claims:write",
    ]);
    let secret: [u8; 32] = rand::random();
    let client_id = format!("retired_svc_{}", Uuid::new_v4().simple());
    let id = OAuthClientRepository::create(
        &pool,
        &client_id,
        Some(blake3::hash(&secret).as_bytes()),
        "retired-scope service",
        "service",
        &granted,
        &granted,
        "active",
        None,
        None,
        Some("Retired Scope Test Org"),
        Some("retired@example.com"),
        None,
    )
    .await
    .expect("service client");
    let st = AppState::with_db(pool.clone(), config());
    let jwt = st.jwt_config.clone();
    let app = create_router(st);
    let grant = |scope: Option<&str>| {
        let mut body = json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": hex::encode(secret),
        });
        if let Some(scope) = scope {
            body["scope"] = json!(scope);
        }
        body
    };

    let (status, body) = post_token(&app, grant(None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        token_scopes(&jwt, &body),
        v(&["claims:read", "claims:write"])
    );
    let stored: Vec<Vec<String>> =
        sqlx::query_scalar("SELECT scopes FROM refresh_tokens WHERE client_id = $1")
            .bind(id)
            .fetch_all(&pool)
            .await
            .expect("the chain");
    assert_eq!(stored.len(), 1);
    assert!(
        !stored[0].iter().any(|s| epigraph_auth::is_retired_scope(s)),
        "the new chain stores no retired scope: {stored:?}"
    );

    let (status, body) = post_token(&app, grant(Some("ingest:write"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        token_scopes(&jwt, &body),
        v(&["claims:read", "claims:write"]),
        "a request naming only a retired scope mints the live grant"
    );

    let (status, body) = post_token(&app, grant(Some("claims:read evidence:read"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(token_scopes(&jwt, &body), v(&["claims:read"]));
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    let body = match body {
        Some(b) => {
            req = req.header(header::CONTENT_TYPE, "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn assert_none_retired(what: &str, scopes: &[String]) {
    let retired: Vec<&String> = scopes
        .iter()
        .filter(|s| epigraph_auth::is_retired_scope(s))
        .collect();
    assert!(
        retired.is_empty(),
        "{what} carries retired scopes {retired:?}"
    );
}

/// Catches: the authorization-server metadata still advertising a retired
/// scope.
#[sqlx::test(migrations = "../../migrations")]
async fn the_metadata_lists_no_retired_scope(pool: PgPool) {
    let app = create_router(AppState::with_db(pool, config()));
    let (status, body) = send(
        &app,
        Method::GET,
        "/.well-known/oauth-authorization-server",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: Vec<String> = body["scopes_supported"]
        .as_array()
        .unwrap_or_else(|| panic!("scopes_supported: {body}"))
        .iter()
        .map(|s| s.as_str().expect("a string").to_string())
        .collect();
    assert!(!listed.is_empty(), "{body}");
    assert_none_retired("scopes_supported", &listed);
}

/// Catches: a newly registered client receiving a retired scope. The DCR
/// arm's public read set, the pending service proposal and the agent arm's
/// proposed write set (`AGENT_PROVISION_SCOPES`, what an approval may grant).
#[sqlx::test(migrations = "../../migrations")]
async fn a_newly_registered_client_receives_no_retired_scope(pool: PgPool) {
    sqlx::query(
        "INSERT INTO oauth_clients \
            (client_id, client_name, client_type, allowed_scopes, granted_scopes, status) \
         VALUES ('retired_owner_human', 'Owner', 'human', '{}', '{}', 'active')",
    )
    .execute(&pool)
    .await
    .expect("seed owner human client");
    let app = create_router(AppState::with_db(pool.clone(), config()));
    let agent_key = hex::encode(blake3::hash(b"retired-scope-agent").as_bytes());
    for (what, body) in [
        (
            "dcr",
            json!({
                "client_name": "Claude",
                "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
                "token_endpoint_auth_method": "none",
            }),
        ),
        (
            "service",
            json!({
                "client_name": "retired-scope service",
                "client_type": "service",
                "legal_entity_name": "Retired Scope Test Org",
                "legal_contact_email": "retired@example.com",
                "scope": "claims:read evidence:read ingest:write",
            }),
        ),
        (
            "agent",
            json!({
                "client_name": "retired-scope agent",
                "client_type": "agent",
                "client_id": agent_key,
            }),
        ),
    ] {
        let (status, resp) = send(&app, Method::POST, "/oauth/register", Some(body)).await;
        assert_eq!(status, StatusCode::CREATED, "{what}: {resp}");
        let client_id = resp["client_id"].as_str().expect("client_id").to_string();
        let (allowed, granted): (Vec<String>, Vec<String>) = sqlx::query_as(
            "SELECT allowed_scopes, granted_scopes FROM oauth_clients WHERE client_id = $1",
        )
        .bind(&client_id)
        .fetch_one(&pool)
        .await
        .expect("the registered row");
        assert!(
            !allowed.is_empty() || !granted.is_empty(),
            "{what}: PREMISE, the registration records some scope"
        );
        assert_none_retired(&format!("{what} allowed_scopes"), &allowed);
        assert_none_retired(&format!("{what} granted_scopes"), &granted);
    }
}

/// A google provider whose `default_scopes` still list retired scopes (a
/// deployment's `providers.toml` written before the retirement).
fn google_registry(fx: &ProviderFixture) -> Arc<ProviderRegistry> {
    let cid_var = "RETIRED_SCOPES_GOOGLE_CLIENT_ID".to_string();
    let sec_var = "RETIRED_SCOPES_GOOGLE_CLIENT_SECRET".to_string();
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
        token_endpoint: Some(format!("{}/token", fx.mock_server.uri())),
        redirect_uri: None,
        redirect_uri_env: None,
        auto_provision: true,
        default_scopes: v(&[
            "claims:read",
            "policy:challenge",
            "evidence:read",
            "evidence:submit",
        ]),
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

/// Catches: external-provider auto-provisioning writing a retired scope from
/// `default_scopes` into a new client's grant (and so into its tokens).
#[sqlx::test(migrations = "../../migrations")]
async fn an_auto_provisioned_client_receives_no_retired_scope(pool: PgPool) {
    let fx = ProviderFixture::new().await;
    let st = AppState::with_db(pool.clone(), config()).with_providers(google_registry(&fx));
    let jwt = st.jwt_config.clone();
    let app = create_router(st);
    let now = Utc::now().timestamp();
    let id_token = fx.sign(&json!({
        "iss": "https://accounts.google.com",
        "aud": "test-audience",
        "sub": "retired-ext",
        "email": "retired-ext@example.com",
        "email_verified": true,
        "name": "retired-ext",
        "iat": now,
        "exp": now + 600,
    }));
    let (status, body) = post_token(
        &app,
        json!({ "grant_type": "google_id_token", "assertion": id_token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "external grant: {body}");
    assert_eq!(
        token_scopes(&jwt, &body),
        v(&["claims:read", "evidence:submit"])
    );
    let (allowed, granted): (Vec<String>, Vec<String>) = sqlx::query_as(
        "SELECT allowed_scopes, granted_scopes FROM oauth_clients WHERE client_id = $1",
    )
    .bind("google:retired-ext")
    .fetch_one(&pool)
    .await
    .expect("the provisioned row");
    assert_none_retired("provisioned allowed_scopes", &allowed);
    assert_none_retired("provisioned granted_scopes", &granted);
    assert!(
        granted.contains(&"evidence:submit".to_string()),
        "{granted:?}"
    );
}

/// `src` with every `#[cfg(test)] mod ... { ... }` block removed (brace
/// counted), and the body of every `RETIRED_SCOPES` list removed.
fn non_test_source_outside_retired_lists(src: &str) -> String {
    let mut out = String::new();
    let mut lines = src.lines().peekable();
    while let Some(line) = lines.next() {
        let t = line.trim();
        if t == "#[cfg(test)]" {
            if let Some(next) = lines.peek() {
                let n = next.trim_start();
                if (n.starts_with("mod ") || n.starts_with("pub(crate) mod ")) && n.ends_with('{') {
                    let mut depth: i64 = 0;
                    for body in lines.by_ref() {
                        depth += body.matches('{').count() as i64;
                        depth -= body.matches('}').count() as i64;
                        if depth <= 0 {
                            break;
                        }
                    }
                    continue;
                }
            }
        }
        if t.starts_with("pub const RETIRED_SCOPES") {
            for body in lines.by_ref() {
                if body.trim() == "];" {
                    break;
                }
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Catches: a retired scope re-entering a grant, a ceiling, a role or a gate.
/// No crate's `src/` (inline test modules aside) spells one as a string
/// literal outside the two `RETIRED_SCOPES` lists. `policy:challenge` is also
/// a claim LABEL, which `epigraph-db`'s label allowlist names; that file is
/// exempt for that literal only.
#[test]
fn no_crate_source_names_a_retired_scope_outside_the_retired_lists() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/");
    let mut files = Vec::new();
    for krate in std::fs::read_dir(crates).expect("crates/") {
        let src = krate.expect("entry").path().join("src");
        if src.is_dir() {
            rust_files(&src, &mut files);
        }
    }
    assert!(files.len() > 100, "PREMISE: the walk found the sources");
    let mut hits = Vec::new();
    let mut lists_seen = 0;
    for file in &files {
        let raw = std::fs::read_to_string(file).expect("read");
        if raw.contains("pub const RETIRED_SCOPES") {
            lists_seen += 1;
        }
        let src = non_test_source_outside_retired_lists(&raw);
        for scope in epigraph_auth::RETIRED_SCOPES {
            let literal = format!("\"{scope}\"");
            if !src.contains(&literal) {
                continue;
            }
            let label_list = file.ends_with("epigraph-db/src/label_validation.rs");
            if label_list && *scope == "policy:challenge" {
                continue;
            }
            hits.push(format!("{}: {literal}", file.display()));
        }
    }
    assert_eq!(lists_seen, 2, "PREMISE: the core and auth lists were read");
    assert!(
        hits.is_empty(),
        "retired scopes named outside the retired lists: {hits:#?}"
    );
}
