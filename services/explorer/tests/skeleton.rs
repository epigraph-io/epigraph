//! Skeleton behaviour every area builds on: health, headers, base-path
//! mounting, error pages, static assets, config validation, upstream error
//! mapping, degraded sections, and the 401 → refresh → retry policy.

mod common;

use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use common::{spawn, spawn_with, TestApp, BASE};
use epigraph_explorer::auth::SignedIn;
use epigraph_explorer::config::{
    Config, ConfigError, ENV_API_URL, ENV_DEV_BEARER, ENV_FRAME_ANCESTORS, ENV_PUBLIC_BASE_URL,
    ENV_UPSTREAM_CONCURRENCY, ENV_UPSTREAM_TIMEOUT_MS,
};
use epigraph_explorer::upstream::{degrade, Degraded, UpstreamError};
use epigraph_explorer::{AppError, AppState};
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

const CLAIM: &str = "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";

fn claim_id() -> Uuid {
    Uuid::parse_str(CLAIM).unwrap()
}

fn claim_json() -> Value {
    json!({
        "id": CLAIM,
        "content": "Water boils at 100 °C at sea level.",
        "truth_value": 0.8,
        "agent_id": "1b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10",
        "trace_id": null,
        "created_at": "2026-01-02T03:04:05Z",
        "updated_at": "2026-01-02T03:04:05Z"
    })
}

fn belief_json() -> Value {
    json!({
        "claim_id": CLAIM, "belief": 0.6, "plausibility": 0.9, "ignorance": 0.3,
        "mass_on_conflict": null, "mass_on_missing": null,
        "pignistic_prob": 0.75, "mass_function_count": 2
    })
}

async fn mount_claim(app: &TestApp) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(claim_json()))
        .mount(&app.upstream)
        .await;
}

/// A page handler written the way areas write them: a required call with
/// `?`, an optional section through `degrade`.
async fn probe(State(state): State<AppState>, user: SignedIn) -> Result<Json<Value>, AppError> {
    let api = user.api(&state);
    let (claim, belief) = tokio::join!(api.claim(claim_id()), api.belief(claim_id()));
    let claim = claim?;
    let belief = degrade(belief)?;
    Ok(Json(json!({ "claim": claim.id, "belief": belief })))
}

fn probe_routes() -> Router<AppState> {
    Router::new()
        .route("/probe", get(probe))
        .route("/bff/probe", get(probe))
}

// ---- health, headers, mounting ------------------------------------------------

#[tokio::test]
async fn health_reports_status_and_version() {
    let app = spawn().await;
    for uri in ["/explorer/health", "/health"] {
        let res = app.get(uri).await;
        assert_eq!(res.status, StatusCode::OK, "{uri}");
        assert_eq!(
            res.json(),
            json!({"status": "ok", "version": env!("CARGO_PKG_VERSION")})
        );
    }
}

#[tokio::test]
async fn security_headers_on_every_response() {
    let app = spawn().await;
    let expected_csp = "default-src 'self'; script-src 'self'; style-src 'self'; \
        img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; \
        frame-ancestors https://www.notion.so https://*.notion.so https://*.notion.site";
    let sid = app.sign_in("tok");
    for res in [
        app.get("/explorer/health").await,
        app.get(&format!("/explorer/claim/{CLAIM}")).await,
        app.get("/explorer/static/app.css").await,
        app.get("/explorer/no/such/page").await,
        app.get("/explorer/bff/themes").await,
        app.get("/explorer/search").await, // redirect
        app.get_as("/explorer/", &sid).await,
    ] {
        assert_eq!(res.header("content-security-policy"), Some(expected_csp));
        assert_eq!(res.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(res.header("referrer-policy"), Some("same-origin"));
        assert_eq!(res.header("x-frame-options"), None, "framing is CSP-only");
    }
}

#[tokio::test]
async fn frame_ancestors_come_from_config() {
    let app = spawn_with(
        &[(ENV_FRAME_ANCESTORS, "'self' https://notes.example.com")],
        Router::new(),
    )
    .await;
    let csp = app.get("/explorer/health").await;
    assert!(csp
        .header("content-security-policy")
        .unwrap()
        .ends_with("frame-ancestors 'self' https://notes.example.com"));
}

#[tokio::test]
async fn routes_answer_with_and_without_the_base_path() {
    let app = spawn().await;
    // Caddy `handle_path` strips the prefix; `handle` keeps it. Both work, and
    // generated links always carry the base path.
    for uri in [
        format!("/explorer/claim/{CLAIM}"),
        format!("/claim/{CLAIM}"),
    ] {
        let res = app.get(&uri).await;
        assert_eq!(res.status, StatusCode::OK, "{uri}");
        assert!(res.header("content-type").unwrap().starts_with("text/html"));
        assert!(res.body.contains("href=\"/explorer/\""), "home link: {uri}");
        assert!(res.body.contains("action=\"/explorer/search\""));
        assert!(
            res.body
                .contains(&format!("return_to=%2Fexplorer%2Fclaim%2F{CLAIM}")),
            "login link returns to the browser-visible path: {uri}"
        );
        assert!(res.body.contains(&format!(
            "content=\"https://explorer.example.com/explorer/claim/{CLAIM}\""
        )));
    }
}

#[tokio::test]
async fn landing_page_mounts_at_base_path_with_and_without_slash() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    for uri in ["/explorer", "/explorer/", "/explorer/?utm=x", "/"] {
        let res = app.get_as(uri, &sid).await;
        assert_eq!(res.status, StatusCode::OK, "{uri}");
        assert!(res.body.contains("not built yet"), "{uri}");
        assert!(
            res.body.contains("action=\"/explorer/auth/logout\""),
            "{uri}"
        );
    }
    // The browser-visible path survives the `{base}/` rewrite.
    let res = app.get("/explorer/?utm=x").await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(
        res.location(),
        Some("/explorer/auth/login?return_to=%2Fexplorer%2F%3Futm%3Dx")
    );
}

#[tokio::test]
async fn root_base_path_serves_at_root() {
    let app = spawn_with(
        &[(ENV_PUBLIC_BASE_URL, "https://explorer.example.com")],
        Router::new(),
    )
    .await;
    let res = app.get(&format!("/claim/{CLAIM}")).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("href=\"/\""));
    assert!(res.body.contains("href=\"/static/app.css?v="));
}

#[tokio::test]
async fn signed_in_pages_redirect_anonymous_viewers_to_login() {
    let app = spawn().await;
    let res = app.get("/explorer/search?q=water").await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(
        res.location(),
        Some("/explorer/auth/login?return_to=%2Fexplorer%2Fsearch%3Fq%3Dwater")
    );
    // The same route through a stripping proxy returns to the same place.
    let res = app.get("/search?q=water").await;
    assert_eq!(
        res.location(),
        Some("/explorer/auth/login?return_to=%2Fexplorer%2Fsearch%3Fq%3Dwater")
    );
    // BFF routes answer JSON instead of redirecting.
    let res = app.get("/explorer/bff/themes").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json()["error"], "unauthorized");
}

#[tokio::test]
async fn every_area_route_is_mounted() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    // Built areas leave this stub list; their mounting is pinned in their
    // own test file (entities: `entity_routes_answer_with_and_without_the_base_path`).
    let pages = [
        "/explorer/".to_string(),
        "/explorer/search?q=x".to_string(),
        format!("/explorer/claim/{CLAIM}"),
        format!("/explorer/claim/{CLAIM}/graph"),
        format!("/explorer/theme/{CLAIM}"),
        format!("/explorer/community/{CLAIM}"),
        format!("/explorer/neighborhood/{CLAIM}?mode=compound"),
        "/explorer/auth/login".to_string(),
        "/explorer/auth/callback?code=x&state=y".to_string(),
    ];
    for uri in &pages {
        let res = app.get_as(uri, &sid).await;
        assert_eq!(res.status, StatusCode::OK, "{uri}");
        assert!(res.body.contains("not built yet"), "{uri}");
    }
    for uri in ["/explorer/auth/logout", "/explorer/auth/redeem"] {
        let res = app.post_form(uri, "", Some(&sid)).await;
        assert_eq!(res.status, StatusCode::OK, "{uri}");
    }
    let bff = [
        format!("/explorer/bff/claim/{CLAIM}"),
        "/explorer/bff/search?q=x".to_string(),
        format!("/explorer/bff/graph/ego/{CLAIM}"),
        "/explorer/bff/themes".to_string(),
        "/explorer/bff/communities".to_string(),
        format!("/explorer/bff/neighborhood/{CLAIM}"),
    ];
    for uri in &bff {
        let res = app.get_as(uri, &sid).await;
        assert_eq!(res.status, StatusCode::NOT_IMPLEMENTED, "{uri}");
        assert_eq!(res.json()["error"], "not_built", "{uri}");
    }
}

// ---- error pages ---------------------------------------------------------------

#[tokio::test]
async fn unknown_routes_render_the_404_page() {
    let app = spawn().await;
    let res = app.get("/explorer/definitely/not/here").await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(res.header("content-type").unwrap().starts_with("text/html"));
    assert!(res.body.contains("Not found"));
    assert!(res.body.contains("Error 404"));
    assert!(
        res.body.contains("href=\"/explorer/\""),
        "inside the layout"
    );
    assert_eq!(res.header("cache-control"), Some("no-store"));

    // Outside the base path too (fallback is shared).
    assert_eq!(app.get("/nowhere").await.status, StatusCode::NOT_FOUND);

    // Wrong method: axum's bare 405 is re-rendered as a page, not text/plain.
    let res = app.post_form("/explorer/health", "", None).await;
    assert!(res.header("content-type").unwrap().starts_with("text/html"));
}

#[tokio::test]
async fn unknown_bff_routes_answer_json() {
    let app = spawn().await;
    for uri in ["/explorer/bff/nope", "/bff/nope"] {
        let res = app.get(uri).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{uri}");
        assert!(res
            .header("content-type")
            .unwrap()
            .starts_with("application/json"));
        assert_eq!(res.json()["error"], "not_found");
    }
}

// ---- static assets ------------------------------------------------------------

#[tokio::test]
async fn static_assets_are_served_with_cache_headers() {
    let app = spawn().await;
    let res = app.get("/explorer/static/app.css").await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.header("content-type"), Some("text/css; charset=utf-8"));
    assert_eq!(res.header("cache-control"), Some("public, max-age=300"));
    assert!(res.body.contains("prefers-color-scheme: dark"));
    let etag = res.header("etag").unwrap().to_string();

    // The versioned URL the templates emit is immutable.
    let versioned = app.state.links.static_asset("app.css");
    assert!(versioned.starts_with("/explorer/static/app.css?v="));
    let res = app.get(&versioned).await;
    assert_eq!(
        res.header("cache-control"),
        Some("public, max-age=31536000, immutable")
    );

    let res = app
        .get_with("/explorer/static/app.css", &[("if-none-match", &etag)])
        .await;
    assert_eq!(res.status, StatusCode::NOT_MODIFIED);
    assert!(res.body.is_empty());

    let res = app.get("/explorer/static/missing.js").await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    let res = app.get("/explorer/static/../Cargo.toml").await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
}

// ---- config ---------------------------------------------------------------------

#[test]
fn config_validation_is_enforced() {
    let none = |_: &str| None;
    assert_eq!(
        Config::from_lookup(none).unwrap_err(),
        ConfigError::Missing(ENV_PUBLIC_BASE_URL)
    );

    let dev_on_public_host = |k: &str| match k {
        ENV_PUBLIC_BASE_URL => Some("https://explorer.example.com/explorer".to_string()),
        ENV_DEV_BEARER => Some("t".to_string()),
        _ => None,
    };
    assert!(matches!(
        Config::from_lookup(dev_on_public_host).unwrap_err(),
        ConfigError::Invalid {
            var: ENV_DEV_BEARER,
            ..
        }
    ));
}

#[tokio::test]
async fn dev_bearer_signs_in_anonymous_requests_on_localhost() {
    let app = spawn_with(
        &[
            (ENV_PUBLIC_BASE_URL, "http://localhost:8096/explorer"),
            (ENV_DEV_BEARER, "dev-token"),
        ],
        probe_routes(),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}")))
        .and(header("authorization", "Bearer dev-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(claim_json()))
        .expect(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}/belief")))
        .respond_with(ResponseTemplate::new(200).set_body_json(belief_json()))
        .mount(&app.upstream)
        .await;
    let res = app.get("/explorer/probe").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
}

// ---- upstream error mapping ------------------------------------------------------

#[tokio::test]
async fn json_api_errors_map_to_typed_errors() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}")))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "NotFound",
            "message": format!("Claim with ID {CLAIM} not found"),
            "details": {"entity": "Claim", "id": CLAIM}
        })))
        .mount(&app.upstream)
        .await;
    let api = app
        .state
        .api(&epigraph_explorer::auth::RequestAuth::Anonymous);
    assert_eq!(
        api.claim(claim_id()).await.unwrap_err(),
        UpstreamError::NotFound {
            message: format!("Claim with ID {CLAIM} not found")
        }
    );
}

#[tokio::test]
async fn text_plain_400_maps_to_rejected() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/claims/not-a-uuid"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string("Invalid URL: Cannot parse `not-a-uuid` to a `Uuid`"),
        )
        .mount(&app.upstream)
        .await;
    let api = app
        .state
        .api(&epigraph_explorer::auth::RequestAuth::Anonymous);
    let err = api
        .get::<Value>("/api/v1/claims/not-a-uuid")
        .await
        .unwrap_err();
    assert_eq!(
        err,
        UpstreamError::Rejected {
            status: 400,
            kind: None,
            message: "Invalid URL: Cannot parse `not-a-uuid` to a `Uuid`".into()
        }
    );
}

#[tokio::test]
async fn server_errors_and_transport_failures_are_typed() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/stats"))
        .respond_with(ResponseTemplate::new(503).set_body_string("down"))
        .mount(&app.upstream)
        .await;
    let api = app
        .state
        .api(&epigraph_explorer::auth::RequestAuth::Anonymous);
    assert_eq!(
        api.stats().await.unwrap_err(),
        UpstreamError::Server {
            status: 503,
            message: "down".into()
        }
    );

    // Nothing listens on the discard port.
    let dead = spawn_with(&[(ENV_API_URL, "http://127.0.0.1:9")], Router::new()).await;
    let api = dead
        .state
        .api(&epigraph_explorer::auth::RequestAuth::Anonymous);
    assert!(matches!(
        api.stats().await.unwrap_err(),
        UpstreamError::Transport(_)
    ));
}

#[tokio::test]
async fn timeout_degrades_the_section_not_the_page() {
    let app = spawn_with(&[(ENV_UPSTREAM_TIMEOUT_MS, "300")], probe_routes()).await;
    mount_claim(&app).await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}/belief")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(belief_json())
                .set_delay(Duration::from_secs(2)),
        )
        .mount(&app.upstream)
        .await;

    let sid = app.sign_in("tok");
    let res = app.get_as("/explorer/probe", &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let body = res.json();
    assert_eq!(body["claim"], CLAIM);
    assert_eq!(body["belief"]["status"], "unavailable");
    assert_eq!(
        body["belief"]["reason"],
        UpstreamError::Timeout.user_message()
    );

    // The same call on its own is a typed timeout.
    let api = app.state.api(&app.session_auth(&sid, "tok"));
    assert_eq!(
        api.belief(claim_id()).await.unwrap_err(),
        UpstreamError::Timeout
    );
    let d: Degraded<_> = degrade(api.belief(claim_id()).await).unwrap();
    assert!(!d.is_available());
}

#[tokio::test]
async fn required_call_failure_renders_an_error_page() {
    let app = spawn_with(&[], probe_routes()).await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}")))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": "DatabaseError", "message": "pool timed out: secret detail"
        })))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as("/explorer/probe", &sid).await;
    assert_eq!(res.status, StatusCode::BAD_GATEWAY);
    assert!(res.header("content-type").unwrap().starts_with("text/html"));
    assert!(res.body.contains("EpiGraph is unavailable"));
    assert!(
        !res.body.contains("secret detail"),
        "upstream detail is logged, not shown"
    );

    let res = app.get_as("/explorer/bff/probe", &sid).await;
    assert_eq!(res.status, StatusCode::BAD_GATEWAY);
    assert_eq!(res.json()["error"], "upstream_unavailable");
}

#[tokio::test]
async fn bearer_is_forwarded_only_for_signed_in_callers() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/stats"))
        .and(header("authorization", "Bearer session-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"claims": 7})))
        .expect(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/stats"))
        .and(|req: &wiremock::Request| !req.headers.contains_key("authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"claims": 1})))
        .expect(1)
        .mount(&app.upstream)
        .await;

    let sid = app.sign_in("session-token");
    let signed = app.state.api(&app.session_auth(&sid, "session-token"));
    assert_eq!(signed.stats().await.unwrap().claims, 7);
    let anon = app
        .state
        .api(&epigraph_explorer::auth::RequestAuth::Anonymous);
    assert_eq!(anon.stats().await.unwrap().claims, 1);
}

#[tokio::test]
async fn upstream_calls_share_one_semaphore() {
    let app = spawn_with(
        &[
            (ENV_UPSTREAM_CONCURRENCY, "1"),
            (ENV_UPSTREAM_TIMEOUT_MS, "2000"),
        ],
        Router::new(),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/stats"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({}))
                .set_delay(Duration::from_millis(400)),
        )
        .mount(&app.upstream)
        .await;
    let api = app
        .state
        .api(&epigraph_explorer::auth::RequestAuth::Anonymous);
    let start = Instant::now();
    let (a, b) = tokio::join!(api.stats(), api.stats());
    assert!(a.is_ok() && b.is_ok());
    assert!(
        start.elapsed() >= Duration::from_millis(780),
        "calls ran concurrently despite concurrency=1: {:?}",
        start.elapsed()
    );
    assert_eq!(app.state.upstream.available_permits(), 1);
}

// ---- 401 policy ---------------------------------------------------------------

#[tokio::test]
async fn upstream_401_refreshes_once_and_retries_with_the_new_token() {
    let app = spawn().await;
    mount_claim_for_token(&app, "old-token", 401, 1).await;
    mount_claim_for_token(&app, "new-token", 200, 2).await;

    // The request started with `old-token`, but the session now holds
    // `new-token` (another request refreshed it): the hook's single-flight
    // check returns the stored token and the call is retried with it.
    let sid = app.sign_in("new-token");
    let api = app.state.api(&app.session_auth(&sid, "old-token"));
    let claim = api
        .claim(claim_id())
        .await
        .expect("retried with refreshed token");
    assert_eq!(claim.id, claim_id());

    // Later calls through the same Api use the refreshed token directly
    // (the `old-token` mock expects exactly one hit).
    api.claim(claim_id()).await.unwrap();
    assert!(app.state.sessions.get(&sid).is_some(), "session survives");
}

#[tokio::test]
async fn failed_refresh_ends_the_session() {
    let app = spawn().await;
    mount_claim_for_token(&app, "stale", 401, 1).await;

    // Stored token == failing token → the hook must call the refresh grant,
    // which the skeleton stubs as unavailable.
    let sid = app.sign_in("stale");
    let api = app.state.api(&app.session_auth(&sid, "stale"));
    assert_eq!(
        api.claim(claim_id()).await.unwrap_err(),
        UpstreamError::SessionExpired
    );
    assert!(app.state.sessions.get(&sid).is_none(), "session dropped");
}

#[tokio::test]
async fn second_401_after_refresh_ends_the_session() {
    let app = spawn().await;
    mount_claim_for_token(&app, "old-token", 401, 1).await;
    mount_claim_for_token(&app, "new-token", 401, 1).await;

    let sid = app.sign_in("new-token");
    let api = app.state.api(&app.session_auth(&sid, "old-token"));
    assert_eq!(
        api.claim(claim_id()).await.unwrap_err(),
        UpstreamError::SessionExpired
    );
    assert!(app.state.sessions.get(&sid).is_none());
}

#[tokio::test]
async fn anonymous_401_is_unauthorized_without_refresh() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/stats"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "Unauthorized", "message": "Missing Authorization header"
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let api = app
        .state
        .api(&epigraph_explorer::auth::RequestAuth::Anonymous);
    assert_eq!(
        api.stats().await.unwrap_err(),
        UpstreamError::Unauthorized {
            message: "Missing Authorization header".into()
        }
    );
}

#[tokio::test]
async fn session_expiry_mid_page_redirects_to_login_and_clears_the_cookie() {
    let app = spawn_with(&[], probe_routes()).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as("/explorer/probe?x=1", &sid).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(
        res.location(),
        Some("/explorer/auth/login?return_to=%2Fexplorer%2Fprobe%3Fx%3D1")
    );
    let cookies = res.header_all("set-cookie");
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("epx_session=;") && c.contains("Max-Age=0")),
        "{cookies:?}"
    );
    assert!(app.state.sessions.get(&sid).is_none());

    let sid = app.sign_in("tok");
    let res = app.get_as("/explorer/bff/probe", &sid).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json()["error"], "session_expired");
    assert!(!res.header_all("set-cookie").is_empty());
}

#[tokio::test]
async fn expired_token_without_refresh_reads_as_signed_out() {
    let app = spawn().await;
    // Token already expired; the stubbed refresh cannot renew it.
    let sid = app.sign_in_expiring("tok", chrono::Duration::seconds(-5));
    let res = app.get_as("/explorer/search", &sid).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert!(app.state.sessions.get(&sid).is_none());

    // Near expiry but still valid: kept, and the token is still used.
    let sid = app.sign_in_expiring("tok", chrono::Duration::seconds(30));
    let res = app.get_as("/explorer/search", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(app.state.sessions.get(&sid).is_some());
}

async fn mount_claim_for_token(app: &TestApp, token: &str, status: u16, times: u64) {
    let template = if status == 200 {
        ResponseTemplate::new(200).set_body_json(claim_json())
    } else {
        ResponseTemplate::new(status).set_body_json(json!({
            "error": "Unauthorized", "message": "Invalid token: ExpiredSignature"
        }))
    };
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}")))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(template)
        .expect(times)
        .mount(&app.upstream)
        .await;
}

#[test]
fn base_constant_matches_public_base() {
    assert!(common::PUBLIC_BASE.ends_with(BASE));
}
