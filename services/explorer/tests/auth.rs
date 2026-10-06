//! Sign-in, refresh, embed handoff and logout (plan §3.3) against a
//! wiremock `/oauth/token` and `/oauth/revoke` shaped like oauth-auth.md
//! §1.4, §3 and §6: form bodies in, `TokenResponse` or the non-RFC
//! `{error, message, details}` body out; revoke takes JSON only.

mod common;

use std::collections::HashMap;
use std::time::Duration as StdDuration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use common::{spawn, spawn_with, TestApp, TestResponse};
use epigraph_explorer::auth::flow::{Handoff, PendingLogin, MAX_PENDING_LOGINS};
use epigraph_explorer::auth::{oauth, RefreshError, SessionId, SignedIn};
use epigraph_explorer::config::{
    ENV_CLIENT_ID, ENV_INSECURE_COOKIES, ENV_OAUTH_BASE_URL, ENV_PUBLIC_BASE_URL,
    ENV_TOKEN_TIMEOUT_MS, ENV_UPSTREAM_TIMEOUT_MS,
};
use epigraph_explorer::{app as explorer_app, AppError, AppState};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use url::Url;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, ResponseTemplate};

const CLIENT_ID: &str = "epigraph_explorer_test";
const OAUTH_BASE: &str = "https://api.example.com";
const ORIGIN: &str = "https://explorer.example.com";
const REDIRECT_URI: &str = "https://explorer.example.com/explorer/auth/callback";
const CLAIM_PATH: &str = "/explorer/claim/0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";

// ---- harness ----------------------------------------------------------------------

/// A signed-in page and BFF route that makes one upstream call with the
/// viewer's bearer, so tests can see which token reached upstream.
async fn probe(State(state): State<AppState>, user: SignedIn) -> Result<Json<Value>, AppError> {
    let v: Value = user.api(&state).get("/api/v1/probe").await?;
    Ok(Json(v))
}

async fn app() -> TestApp {
    spawn_with(
        &[(ENV_CLIENT_ID, CLIENT_ID), (ENV_OAUTH_BASE_URL, OAUTH_BASE)],
        Router::new()
            .route("/probe", get(probe))
            .route("/bff/probe", get(probe)),
    )
    .await
}

fn token_json(access: &str, refresh: &str) -> Value {
    json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": refresh,
        "scope": "claims:read"
    })
}

fn form(req: &wiremock::Request) -> HashMap<String, String> {
    url::form_urlencoded::parse(&req.body)
        .into_owned()
        .collect()
}

fn is_form(req: &wiremock::Request) -> bool {
    req.headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"))
}

/// `POST /oauth/token` whose form body is exactly `expected`.
fn token_call(expected: &[(&str, &str)]) -> wiremock::MockBuilder {
    let expected: HashMap<String, String> = expected
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(move |req: &wiremock::Request| is_form(req) && form(req) == expected)
}

/// Any `POST /oauth/token` at all (for "never called" expectations).
fn any_token_call() -> wiremock::MockBuilder {
    Mock::given(method("POST")).and(path("/oauth/token"))
}

async fn mount_probe(app: &TestApp, token: &str, status: u16, times: u64) {
    let template = if status == 200 {
        ResponseTemplate::new(200).set_body_json(json!({ "token_seen": token }))
    } else {
        ResponseTemplate::new(status).set_body_json(json!({
            "error": "Unauthorized", "message": "Invalid token: ExpiredSignature"
        }))
    };
    Mock::given(method("GET"))
        .and(path("/api/v1/probe"))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(template)
        .expect(times)
        .mount(&app.upstream)
        .await;
}

/// The value of cookie `name` from a response's `Set-Cookie` headers, with
/// the whole header line.
fn set_cookie(res: &TestResponse, name: &str) -> Option<(String, String)> {
    let prefix = format!("{name}=");
    res.header_all("set-cookie").into_iter().find_map(|line| {
        let value = line.strip_prefix(&prefix)?.split(';').next()?.to_string();
        Some((value, line))
    })
}

async fn send_with(
    app: &TestApp,
    method_: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> TestResponse {
    let mut req = Request::builder().method(method_).uri(uri);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    app.send(req.body(Body::from(body.to_string())).unwrap())
        .await
}

/// A login started at `/auth/login{query}`: what the browser was sent to.
struct Started {
    state: String,
    binding: String,
    params: HashMap<String, String>,
    location: Url,
}

async fn start_login(app: &TestApp, query: &str) -> Started {
    let res = app.get(&format!("/explorer/auth/login{query}")).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let location = Url::parse(res.location().expect("Location")).unwrap();
    let params: HashMap<String, String> = location.query_pairs().into_owned().collect();
    let (binding, _) = set_cookie(&res, "epx_login").expect("pre-auth cookie set");
    Started {
        state: params["state"].clone(),
        binding,
        params,
        location,
    }
}

/// Run `/auth/callback` for a started login with this browser's cookies.
async fn finish_login(app: &TestApp, started: &Started, query: &str) -> TestResponse {
    let cookie = format!("epx_login={}", started.binding);
    app.get_with(
        &format!("/explorer/auth/callback?state={}{query}", started.state),
        &[("cookie", &cookie)],
    )
    .await
}

fn attr<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let start = body.find(&needle)? + needle.len();
    Some(&body[start..start + body[start..].find('"')?])
}

// ---- login ------------------------------------------------------------------------

#[tokio::test]
async fn login_redirects_to_authorize_with_pkce_s256() {
    let app = app().await;
    let started = start_login(&app, &format!("?return_to={CLAIM_PATH}")).await;

    let loc = &started.location;
    assert_eq!(
        format!(
            "{}://{}{}",
            loc.scheme(),
            loc.host_str().unwrap(),
            loc.path()
        ),
        format!("{OAUTH_BASE}/oauth/authorize"),
        "the browser goes to the browser-facing OAuth base, not the API URL"
    );
    let p = &started.params;
    assert_eq!(p["response_type"], "code");
    assert_eq!(p["client_id"], CLIENT_ID);
    assert_eq!(p["redirect_uri"], REDIRECT_URI);
    assert_eq!(p["code_challenge_method"], "S256");
    // Both scopes are asked for; the API grants only what the user holds
    // (requested ∩ granted), so asking is safe either way.
    assert_eq!(p["scope"], "claims:read audit:read");
    assert_eq!(p.len(), 7, "{p:?}");

    // challenge == base64url_nopad(sha256(verifier)), verifier = 32 random bytes.
    let pending = app
        .state
        .auth_flow
        .pending
        .get(&started.state)
        .expect("pending login stored under state");
    let verifier = &pending.pkce_verifier;
    assert_eq!(verifier.len(), 43);
    assert!(verifier
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    assert_eq!(
        p["code_challenge"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    );
    assert_eq!(pending.return_to, CLAIM_PATH);
    assert!(!pending.popup);
    assert_eq!(pending.binding, started.binding);

    // Fresh state and verifier every time.
    let again = start_login(&app, "").await;
    assert_ne!(again.state, started.state);
    let other = app.state.auth_flow.pending.get(&again.state).unwrap();
    assert_ne!(other.pkce_verifier, *verifier);
}

#[tokio::test]
async fn pre_auth_cookie_binds_the_login_to_this_browser() {
    let app = app().await;
    let res = app.get("/explorer/auth/login").await;
    let (binding, line) = set_cookie(&res, "epx_login").unwrap();
    assert_eq!(binding.len(), 43);
    for attr in [
        "HttpOnly",
        "SameSite=Lax",
        "Secure",
        "Path=/explorer/auth",
        "Max-Age=600",
    ] {
        assert!(line.contains(attr), "{attr} missing from {line}");
    }

    // A browser that already has a binding keeps it, so two tabs signing in
    // at once do not invalidate each other.
    let res = app
        .get_with(
            "/explorer/auth/login",
            &[("cookie", &format!("epx_login={binding}"))],
        )
        .await;
    assert_eq!(set_cookie(&res, "epx_login").unwrap().0, binding);
}

#[tokio::test]
async fn sign_in_is_disabled_without_a_client_id() {
    let app = spawn().await;
    let res = app.get("/explorer/auth/login").await;
    assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        res.body.contains("Sign-in is not configured"),
        "{}",
        res.body
    );
    assert!(app.state.auth_flow.pending.is_empty());
}

#[tokio::test]
async fn pending_logins_are_capped_by_eviction_not_refusal() {
    let app = app().await;
    let entry = |ttl| {
        for i in 0..MAX_PENDING_LOGINS {
            app.state.auth_flow.pending.insert(
                format!("filler-{i}"),
                PendingLogin {
                    pkce_verifier: "v".into(),
                    return_to: "/explorer/".into(),
                    popup: false,
                    binding: "b".into(),
                    created_at: std::time::Instant::now(),
                },
                ttl,
            );
        }
    };

    // Expired entries are purged to make room.
    entry(StdDuration::ZERO);
    let res = app.get("/explorer/auth/login").await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(app.state.auth_flow.pending.len(), 1);

    // A map full of *live* entries must not lock anyone out: the cap evicts
    // the oldest in-flight attempts and this sign-in still starts.
    entry(StdDuration::from_secs(600));
    let res = app.get("/explorer/auth/login").await;
    assert_eq!(
        res.status,
        StatusCode::SEE_OTHER,
        "a full pending map must not refuse sign-in: {}",
        res.body
    );
    let authorize = Url::parse(res.location().expect("Location")).unwrap();
    let oauth_state = authorize
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("state in the authorize URL");
    assert!(
        app.state.auth_flow.pending.get(&oauth_state).is_some(),
        "the new pending login was stored"
    );
    assert_eq!(
        app.state.auth_flow.pending.len(),
        MAX_PENDING_LOGINS,
        "memory stays bounded: one old entry was evicted to make room"
    );

    // And it keeps working under a sustained flood.
    for _ in 0..5 {
        let res = app.get("/explorer/auth/login").await;
        assert_eq!(res.status, StatusCode::SEE_OTHER);
        assert!(app.state.auth_flow.pending.len() <= MAX_PENDING_LOGINS);
    }
}

#[tokio::test]
async fn open_redirect_attempts_land_on_home() {
    let app = app().await;
    for bad in [
        "https://evil.example.net/explorer/",
        "//evil.example.net/explorer/",
        "/\\evil.example.net",
        "/explorer/../evil",
        "/explorer/%2e%2e/evil",
        "/%2F%2Fevil.example.net",
        "/explorer/%0d%0aSet-Cookie:x=y",
        "javascript:alert(1)",
        "/explorers",
        "/explorer/auth/logout",
    ] {
        let q = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("return_to", bad)
            .finish();
        let started = start_login(&app, &format!("?{q}")).await;
        let pending = app.state.auth_flow.pending.get(&started.state).unwrap();
        assert_eq!(pending.return_to, "/explorer/", "{bad:?}");
    }

    // End to end: the post-login redirect is home, not the attacker's URL.
    let started = start_login(&app, "?return_to=https%3A%2F%2Fevil.example.net%2F").await;
    token_call(&[
        ("grant_type", "authorization_code"),
        ("code", "c0de"),
        ("code_verifier", &pending_verifier(&app, &started)),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(token_json("a1", "r1")))
    .expect(1)
    .mount(&app.upstream)
    .await;
    let res = finish_login(&app, &started, "&code=c0de").await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(res.location(), Some("/explorer/"));
}

fn pending_verifier(app: &TestApp, started: &Started) -> String {
    app.state
        .auth_flow
        .pending
        .get(&started.state)
        .unwrap()
        .pkce_verifier
}

// ---- callback ---------------------------------------------------------------------

#[tokio::test]
async fn page_mode_sign_in_end_to_end() {
    let app = app().await;
    let return_to = "/explorer/search?q=a%20b&mode=label";
    let q = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("return_to", return_to)
        .finish();
    let started = start_login(&app, &format!("?{q}")).await;
    let verifier = pending_verifier(&app, &started);

    // Code redemption: form body, exactly these fields, no client secret.
    token_call(&[
        ("grant_type", "authorization_code"),
        ("code", "c0de"),
        ("code_verifier", &verifier),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(token_json("access-1", "refresh-1")))
    .expect(1)
    .mount(&app.upstream)
    .await;
    mount_probe(&app, "access-1", 200, 1).await;

    // The browser also carries an older session: it is replaced.
    let old = app.sign_in("old-access");
    let cookie = format!(
        "epx_login={}; epx_session={}",
        started.binding,
        old.as_str()
    );
    let res = app
        .get_with(
            &format!("/explorer/auth/callback?code=c0de&state={}", started.state),
            &[("cookie", &cookie)],
        )
        .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    assert_eq!(res.location(), Some(return_to));
    assert_eq!(res.header("cache-control"), Some("no-store"));

    let (sid, line) = set_cookie(&res, "epx_session").expect("session cookie");
    for attr in [
        "HttpOnly",
        "SameSite=Lax",
        "Secure",
        "Path=/explorer",
        "Max-Age=2592000",
    ] {
        assert!(line.contains(attr), "{attr} missing from {line}");
    }
    assert!(!line.contains("Partitioned"), "{line}");
    let sid = SessionId::parse(&sid).expect("well-formed session id");
    assert_ne!(sid, old, "a fresh id, never the old one");
    let session = app.state.sessions.get(&sid).expect("session stored");
    assert_eq!(session.access_token, "access-1");
    assert_eq!(session.refresh_token, "refresh-1");
    let left = (session.expires_at - Utc::now()).num_seconds();
    assert!((3590..=3600).contains(&left), "{left}");
    assert!(
        app.state.sessions.get(&old).is_none(),
        "old session dropped"
    );

    // The new session reaches upstream with its own bearer.
    let res = app.get_as("/explorer/probe", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json()["token_seen"], "access-1");

    // `state` is single use: replaying the callback is refused.
    let res = finish_login(&app, &started, "&code=c0de").await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_or_mismatched_state_is_refused_without_a_token_call() {
    let app = app().await;
    any_token_call()
        .respond_with(ResponseTemplate::new(200).set_body_json(token_json("a", "r")))
        .expect(0)
        .mount(&app.upstream)
        .await;
    let started = start_login(&app, &format!("?return_to={CLAIM_PATH}")).await;

    // A state we never issued, with this browser's binding.
    let res = app
        .get_with(
            &format!(
                "/explorer/auth/callback?code=c&state={}",
                epigraph_explorer::auth::random_token(32)
            ),
            &[("cookie", &format!("epx_login={}", started.binding))],
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(
        res.body.contains("expired or was already used"),
        "{}",
        res.body
    );
    assert!(res.body.contains("Sign in again"));

    // Missing and junk states.
    for q in ["?code=c", "?code=c&state=", "?code=c&state=../../x"] {
        let res = app.get(&format!("/explorer/auth/callback{q}")).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{q}");
    }
    assert_eq!(app.state.sessions.len(), 0);
}

#[tokio::test]
async fn callback_in_another_browser_is_refused() {
    let app = app().await;
    any_token_call()
        .respond_with(ResponseTemplate::new(200).set_body_json(token_json("a", "r")))
        .expect(0)
        .mount(&app.upstream)
        .await;

    // Login CSRF: the right state, but not the browser that started it.
    let started = start_login(&app, &format!("?return_to={CLAIM_PATH}")).await;
    let res = app
        .get(&format!(
            "/explorer/auth/callback?code=c&state={}",
            started.state
        ))
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.body.contains("started in this browser"), "{}", res.body);
    // The retry link keeps the original destination.
    assert!(
        res.body
            .contains("/explorer/auth/login?return_to=%2Fexplorer%2Fclaim%2F"),
        "{}",
        res.body
    );

    // A different binding cookie is no better, and the state is now spent.
    let started = start_login(&app, "").await;
    let res = app
        .get_with(
            &format!("/explorer/auth/callback?code=c&state={}", started.state),
            &[(
                "cookie",
                &format!("epx_login={}", epigraph_explorer::auth::random_token(32)),
            )],
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    let res = finish_login(&app, &started, "&code=c").await;
    assert!(res.body.contains("expired or was already used"));
    assert_eq!(app.state.sessions.len(), 0);
}

#[tokio::test]
async fn access_denied_is_reported_without_a_token_call() {
    let app = app().await;
    any_token_call()
        .respond_with(ResponseTemplate::new(200).set_body_json(token_json("a", "r")))
        .expect(0)
        .mount(&app.upstream)
        .await;
    let started = start_login(&app, "").await;
    // What upstream's consent POST sends back on "deny" (authorize.rs::consent_endpoint).
    let res = finish_login(&app, &started, "&error=access_denied").await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert!(res.body.contains("Sign-in was cancelled."), "{}", res.body);
    // The callback URL (state, code) is never reflected into og:url or links.
    assert!(!res.body.contains(&started.state), "{}", res.body);
    assert!(res
        .body
        .contains("og:url\" content=\"https://explorer.example.com/explorer/\""));
    assert!(set_cookie(&res, "epx_session").is_none());
    assert_eq!(app.state.sessions.len(), 0);

    // Other error codes are not echoed back to the page.
    let started = start_login(&app, "").await;
    let res = finish_login(&app, &started, "&error=%3Cscript%3Eboom").await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(!res.body.contains("boom"), "{}", res.body);
}

#[tokio::test]
async fn token_endpoint_errors_are_parsed_and_reported() {
    let app = app().await;
    let cases = [
        (
            400,
            json!({"error": "BadRequest", "message": "Bad request: invalid_grant: PKCE mismatch",
                   "details": {"message": "invalid_grant: PKCE mismatch"}}),
            StatusCode::BAD_REQUEST,
            "took too long or was already used",
        ),
        (
            403,
            json!({"error": "Forbidden", "message": "Forbidden: email not authorized for this provider"}),
            StatusCode::FORBIDDEN,
            "did not allow this account",
        ),
        (
            503,
            json!({"error": "ServiceUnavailable", "message": "database unavailable"}),
            StatusCode::BAD_GATEWAY,
            "sign-in service is unavailable",
        ),
    ];
    for (upstream_status, body, page_status, shown) in cases {
        app.upstream.reset().await;
        any_token_call()
            .respond_with(ResponseTemplate::new(upstream_status).set_body_json(body))
            .expect(1)
            .mount(&app.upstream)
            .await;
        let started = start_login(&app, "").await;
        let res = finish_login(&app, &started, "&code=c0de").await;
        assert_eq!(res.status, page_status, "upstream {upstream_status}");
        assert!(res.body.contains(shown), "{}", res.body);
        for detail in ["PKCE", "email", "database", "c0de", started.state.as_str()] {
            assert!(
                !res.body.contains(detail),
                "upstream detail leaked: {detail}"
            );
        }
        assert_eq!(app.state.sessions.len(), 0);
        // `reset` drops mocks unverified, so check this case's `expect` now.
        app.upstream.verify().await;
    }

    // A text/plain rejection and an unusable 200 body are failures too.
    app.upstream.reset().await;
    any_token_call()
        .respond_with(ResponseTemplate::new(422).set_body_raw(
            "Failed to deserialize the form body",
            "text/plain; charset=utf-8",
        ))
        .mount(&app.upstream)
        .await;
    let started = start_login(&app, "").await;
    let res = finish_login(&app, &started, "&code=c0de").await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);

    app.upstream.reset().await;
    any_token_call()
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"token_type": "Bearer"})))
        .mount(&app.upstream)
        .await;
    let started = start_login(&app, "").await;
    let res = finish_login(&app, &started, "&code=c0de").await;
    assert_eq!(res.status, StatusCode::BAD_GATEWAY);
    assert_eq!(app.state.sessions.len(), 0);
}

// ---- embed sign-in ----------------------------------------------------------------

#[tokio::test]
async fn iframe_navigation_gets_the_embed_sign_in_page() {
    let app = app().await;
    let res = app
        .get_with(
            &format!("/explorer/auth/login?return_to={CLAIM_PATH}"),
            &[("sec-fetch-dest", "iframe")],
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    assert!(res.header("content-security-policy").is_some());
    assert!(
        app.state.auth_flow.pending.is_empty(),
        "no login started yet"
    );
    assert!(set_cookie(&res, "epx_login").is_none());

    let body = &res.body;
    assert_eq!(attr(body, "data-return-to"), Some(CLAIM_PATH));
    assert_eq!(attr(body, "data-redeem"), Some("/explorer/auth/redeem"));
    let login = attr(body, "data-login").unwrap().replace("&#38;", "&");
    assert_eq!(
        login,
        "/explorer/auth/login?mode=popup&return_to=%2Fexplorer%2Fclaim%2F0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10"
    );
    assert!(body.contains("/explorer/static/embed.js?v="), "{body}");
    assert!(
        body.contains(&format!("{ORIGIN}{CLAIM_PATH}")),
        "new-tab link"
    );
    assert!(!body.contains("<script>"), "CSP: no inline script");
    assert!(!body.contains("style="), "CSP: no inline style");

    // The popup itself (mode=popup) is a normal top-level navigation.
    let started = start_login(&app, "?mode=popup").await;
    assert!(
        app.state
            .auth_flow
            .pending
            .get(&started.state)
            .unwrap()
            .popup
    );
}

#[tokio::test]
async fn popup_flow_hands_off_a_single_use_code() {
    let app = app().await;
    let started = start_login(&app, &format!("?mode=popup&return_to={CLAIM_PATH}")).await;
    token_call(&[
        ("grant_type", "authorization_code"),
        ("code", "c0de"),
        ("code_verifier", &pending_verifier(&app, &started)),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(token_json("access-1", "refresh-1")))
    .expect(1)
    .mount(&app.upstream)
    .await;

    let res = finish_login(&app, &started, "&code=c0de").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    assert!(
        set_cookie(&res, "epx_session").is_none(),
        "the popup's first-party jar is not the iframe's"
    );
    assert_eq!(attr(&res.body, "data-status"), Some("ok"));
    assert!(res.body.contains("/explorer/static/embed.js?v="));
    assert!(!res.body.contains("<script>"));
    let code = attr(&res.body, "data-handoff")
        .expect("handoff code")
        .to_string();
    assert_eq!(code.len(), 43);
    assert!(!res.body.contains("access-1") && !res.body.contains("refresh-1"));

    let redeem = |origin: Option<&'static str>, body: String| {
        let app = &app;
        async move {
            let mut h = vec![("content-type", "application/x-www-form-urlencoded")];
            if let Some(o) = origin {
                h.push(("origin", o));
            }
            send_with(app, Method::POST, "/explorer/auth/redeem", &h, &body).await
        }
    };

    // Cross-origin and Origin-less POSTs are refused before the code is read,
    // so they do not burn it.
    for origin in [None, Some("https://evil.example.net"), Some("null")] {
        let res = redeem(origin, format!("code={code}")).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{origin:?}");
    }

    let res = redeem(Some(ORIGIN), format!("code={code}")).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT, "{}", res.body);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let (sid, line) = set_cookie(&res, "epx_session").expect("embed cookie");
    for attr in [
        "HttpOnly",
        "SameSite=None",
        "Secure",
        "Partitioned",
        "Path=/explorer",
        "Max-Age=2592000",
    ] {
        assert!(line.contains(attr), "{attr} missing from {line}");
    }
    let sid = SessionId::parse(&sid).unwrap();
    assert_eq!(
        app.state.sessions.get(&sid).unwrap().access_token,
        "access-1"
    );

    // Single use.
    let res = redeem(Some(ORIGIN), format!("code={code}")).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(set_cookie(&res, "epx_session").is_none());

    // Junk, missing and expired codes.
    for body in [String::new(), "code=".into(), "code=nope".into()] {
        let res = redeem(Some(ORIGIN), body.clone()).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{body:?}");
    }
    let stale = epigraph_explorer::auth::random_token(32);
    app.state.auth_flow.handoffs.insert(
        stale.clone(),
        Handoff {
            tokens: held_tokens(""),
        },
        StdDuration::ZERO,
    );
    let res = redeem(Some(ORIGIN), format!("code={stale}")).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(app.state.sessions.len(), 1, "only the redeemed session");
}

/// A token set as a handoff holds it (`refresh_token` empty: nothing to
/// revoke).
fn held_tokens(refresh_token: &str) -> oauth::TokenSet {
    oauth::TokenSet {
        access_token: "held-access".into(),
        refresh_token: refresh_token.into(),
        expires_at: Utc::now() + Duration::hours(1),
        scope: Some("claims:read".into()),
        scope_widened: false,
    }
}

#[tokio::test]
async fn popup_failures_are_posted_back_not_rendered_as_pages() {
    let app = app().await;
    let started = start_login(&app, "?mode=popup").await;
    let res = finish_login(&app, &started, "&error=access_denied").await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(attr(&res.body, "data-status"), Some("error"));
    assert_eq!(
        attr(&res.body, "data-message"),
        Some("Sign-in was cancelled.")
    );
    assert!(attr(&res.body, "data-handoff").is_none());
    assert!(res.body.contains("/explorer/static/embed.js?v="));
    assert!(app.state.auth_flow.handoffs.is_empty());
}

// ---- refresh ----------------------------------------------------------------------

#[tokio::test]
async fn proactive_refresh_rotates_and_stores_both_tokens() {
    let app = app().await;
    // 30 s left: inside the 60 s proactive window.
    let sid =
        app.state
            .sessions
            .create("a1".into(), "r1".into(), Utc::now() + Duration::seconds(30));
    token_call(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "r1"),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(token_json("a2", "r2")))
    .expect(1)
    .mount(&app.upstream)
    .await;
    // The next refresh must present the ROTATED token, never r1 again.
    token_call(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "r2"),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(token_json("a3", "r3")))
    .expect(1)
    .mount(&app.upstream)
    .await;
    mount_probe(&app, "a2", 200, 1).await;
    mount_probe(&app, "a3", 200, 1).await;

    let res = app.get_as("/explorer/probe", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(
        res.json()["token_seen"],
        "a2",
        "the refreshed token was used"
    );
    let s = app.state.sessions.get(&sid).unwrap();
    assert_eq!(
        (s.access_token.as_str(), s.refresh_token.as_str()),
        ("a2", "r2")
    );
    assert!((s.expires_at - Utc::now()).num_seconds() > 3500);

    app.state.sessions.update_tokens(
        &sid,
        "a2".into(),
        "r2".into(),
        Utc::now() - Duration::seconds(1),
    );
    let res = app.get_as("/explorer/probe", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json()["token_seen"], "a3");
    let s = app.state.sessions.get(&sid).unwrap();
    assert_eq!(
        (s.access_token.as_str(), s.refresh_token.as_str()),
        ("a3", "r3")
    );
}

/// Send `n` signed-in page requests at once, each on its own task.
async fn concurrent_probes(app: &TestApp, sid: &SessionId, n: usize) -> Vec<StatusCode> {
    let tasks: Vec<_> = (0..n)
        .map(|_| {
            let router = app.router.clone();
            let cookie = TestApp::cookie(sid);
            tokio::spawn(async move {
                let req = Request::get("/explorer/probe")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap();
                router.oneshot(req).await.unwrap().status()
            })
        })
        .collect();
    futures::future::join_all(tasks)
        .await
        .into_iter()
        .map(|r| r.expect("request task"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_after_expiry_refresh_exactly_once() {
    let app = app().await;
    let sid =
        app.state
            .sessions
            .create("a1".into(), "r1".into(), Utc::now() - Duration::seconds(5));
    // Slow enough that every request arrives while the refresh is in flight.
    token_call(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "r1"),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(
        ResponseTemplate::new(200)
            .set_body_json(token_json("a2", "r2"))
            .set_delay(StdDuration::from_millis(300)),
    )
    .expect(1)
    .mount(&app.upstream)
    .await;
    mount_probe(&app, "a2", 200, 8).await;

    let statuses = concurrent_probes(&app, &sid, 8).await;
    assert!(
        statuses.iter().all(|s| *s == StatusCode::OK),
        "{statuses:?}"
    );
    let s = app.state.sessions.get(&sid).unwrap();
    assert_eq!(
        (s.access_token.as_str(), s.refresh_token.as_str()),
        ("a2", "r2")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_upstream_401s_share_one_refresh() {
    let app = app().await;
    let sid = app
        .state
        .sessions
        .create("a1".into(), "r1".into(), Utc::now() + Duration::hours(1));
    Mock::given(method("GET"))
        .and(path("/api/v1/probe"))
        .and(header("authorization", "Bearer a1"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "Unauthorized", "message": "Invalid token: revoked"
        })))
        .mount(&app.upstream)
        .await;
    token_call(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "r1"),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(
        ResponseTemplate::new(200)
            .set_body_json(token_json("a2", "r2"))
            .set_delay(StdDuration::from_millis(300)),
    )
    .expect(1)
    .mount(&app.upstream)
    .await;
    mount_probe(&app, "a2", 200, 6).await;

    let statuses = concurrent_probes(&app, &sid, 6).await;
    assert!(
        statuses.iter().all(|s| *s == StatusCode::OK),
        "{statuses:?}"
    );
    assert_eq!(app.state.sessions.get(&sid).unwrap().refresh_token, "r2");
}

#[tokio::test]
async fn upstream_401_refreshes_then_retries_with_the_new_token() {
    let app = app().await;
    let sid = app
        .state
        .sessions
        .create("a1".into(), "r1".into(), Utc::now() + Duration::hours(1));
    mount_probe(&app, "a1", 401, 1).await;
    token_call(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "r1"),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(token_json("a2", "r2")))
    .expect(1)
    .mount(&app.upstream)
    .await;
    mount_probe(&app, "a2", 200, 1).await;

    let res = app.get_as("/explorer/probe", &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.json()["token_seen"], "a2");
    let s = app.state.sessions.get(&sid).unwrap();
    assert_eq!(
        (s.access_token.as_str(), s.refresh_token.as_str()),
        ("a2", "r2")
    );
}

#[tokio::test]
async fn second_401_after_a_real_refresh_ends_the_session() {
    let app = app().await;
    let sid = app
        .state
        .sessions
        .create("a1".into(), "r1".into(), Utc::now() + Duration::hours(1));
    mount_probe(&app, "a1", 401, 1).await;
    token_call(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "r1"),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(token_json("a2", "r2")))
    .expect(1)
    .mount(&app.upstream)
    .await;
    mount_probe(&app, "a2", 401, 1).await;

    let res = app.get_as("/explorer/probe?x=1", &sid).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(
        res.location(),
        Some("/explorer/auth/login?return_to=%2Fexplorer%2Fprobe%3Fx%3D1")
    );
    let (value, line) = set_cookie(&res, "epx_session").expect("cookie cleared");
    assert!(value.is_empty() && line.contains("Max-Age=0"), "{line}");
    assert!(app.state.sessions.get(&sid).is_none());
}

#[tokio::test]
async fn rejected_refresh_ends_an_expired_session() {
    let app = app().await;
    let sid =
        app.state
            .sessions
            .create("a1".into(), "r1".into(), Utc::now() - Duration::seconds(5));
    any_token_call()
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "BadRequest",
            "message": "Bad request: invalid_grant: refresh token revoked",
            "details": {"message": "invalid_grant: refresh token revoked"}
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let res = app.get_as("/explorer/bff/probe", &sid).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert!(app.state.sessions.get(&sid).is_none());
}

#[tokio::test]
async fn refresh_grant_maps_upstream_failures() {
    let app = app().await;
    any_token_call()
        .and(|req: &wiremock::Request| {
            form(req).get("refresh_token").map(String::as_str) == Some("revoked")
        })
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "BadRequest",
            "message": "Bad request: invalid_grant: refresh token revoked",
            "details": {"message": "invalid_grant: refresh token revoked"}
        })))
        .mount(&app.upstream)
        .await;
    any_token_call()
        .and(|req: &wiremock::Request| {
            form(req).get("refresh_token").map(String::as_str) == Some("down")
        })
        .respond_with(ResponseTemplate::new(503).set_body_string(""))
        .mount(&app.upstream)
        .await;

    assert_eq!(
        oauth::refresh_grant(&app.state, "revoked")
            .await
            .unwrap_err(),
        RefreshError::Rejected("invalid_grant: refresh token revoked".into())
    );
    assert!(matches!(
        oauth::refresh_grant(&app.state, "down").await.unwrap_err(),
        RefreshError::Upstream(_)
    ));
    assert_eq!(
        oauth::refresh_grant(&app.state, "").await.unwrap_err(),
        RefreshError::Rejected("no refresh token stored".into()),
        "no network call without a refresh token"
    );

    // A response without a refresh token keeps the old one.
    app.upstream.reset().await;
    any_token_call()
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"access_token": "a9", "token_type": "Bearer", "expires_in": 60}),
            ),
        )
        .mount(&app.upstream)
        .await;
    let t = oauth::refresh_grant(&app.state, "r-old").await.unwrap();
    assert_eq!(
        (t.access_token.as_str(), t.refresh_token.as_str()),
        ("a9", "r-old")
    );
}

// ---- a lost refresh answer ---------------------------------------------------------

/// The auth test app with extra env (e.g. a short token timeout).
async fn app_with(env: &[(&str, &str)]) -> TestApp {
    let mut vars = vec![(ENV_CLIENT_ID, CLIENT_ID), (ENV_OAUTH_BASE_URL, OAUTH_BASE)];
    vars.extend_from_slice(env);
    spawn_with(
        &vars,
        Router::new()
            .route("/probe", get(probe))
            .route("/bff/probe", get(probe)),
    )
    .await
}

/// How many `POST /oauth/token` requests carried `refresh_token`. Only token
/// calls count: the revocation also names the token, at `/oauth/revoke`.
async fn token_posts_presenting(app: &TestApp, refresh_token: &str) -> usize {
    app.upstream
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/oauth/token")
        .filter(|r| form(r).get("refresh_token").map(String::as_str) == Some(refresh_token))
        .count()
}

/// How many `POST /oauth/revoke` requests named `refresh_token`.
async fn revocations_of(app: &TestApp, refresh_token: &str) -> usize {
    app.upstream
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/oauth/revoke")
        .filter(|r| {
            serde_json::from_slice::<Value>(&r.body).ok()
                == Some(json!({"token": refresh_token, "token_type_hint": "refresh_token"}))
        })
        .count()
}

/// `/oauth/token` stalls past the token timeout ONCE for `r1`, then answers
/// at once with a fresh pair, so a replay of `r1` would be seen (and would
/// succeed quickly) rather than hang. `/oauth/revoke` accepts anything.
async fn mount_lost_refresh(app: &TestApp) {
    token_call(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "r1"),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(
        ResponseTemplate::new(200)
            .set_body_json(token_json("a2", "r2"))
            .set_delay(StdDuration::from_secs(3)),
    )
    .up_to_n_times(1)
    .mount(&app.upstream)
    .await;
    token_call(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "r1"),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(token_json("a2", "r2")))
    .mount(&app.upstream)
    .await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&app.upstream)
        .await;
}

/// A refresh whose answer is lost (here: the token call outlives its
/// timeout) may already have rotated the token upstream. Presenting the old
/// refresh token again would read as token reuse and revoke the whole
/// rotation family, so the session ends at once: the held token is revoked
/// (at `/oauth/revoke`, never replayed to `/oauth/token`), the viewer is sent
/// to sign in, and no later request presents the old token again. Both entry
/// points: the proactive refresh of an expired token, and the refresh after
/// an upstream 401.
#[tokio::test]
async fn lost_refresh_response_ends_the_session_without_replaying() {
    // Proactive: the access token has expired, so the extractor refreshes.
    let app = app_with(&[(ENV_TOKEN_TIMEOUT_MS, "250")]).await;
    mount_lost_refresh(&app).await;
    let sid =
        app.state
            .sessions
            .create("a1".into(), "r1".into(), Utc::now() - Duration::seconds(5));
    for attempt in 0..2 {
        let res = app.get_as("/explorer/probe", &sid).await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "attempt {attempt}");
        assert_eq!(
            res.location(),
            Some("/explorer/auth/login?return_to=%2Fexplorer%2Fprobe"),
            "attempt {attempt}: sent to sign in"
        );
    }
    assert!(app.state.sessions.get(&sid).is_none(), "the session ended");
    assert_eq!(
        token_posts_presenting(&app, "r1").await,
        1,
        "the refresh token whose rotation answer was lost is never presented again"
    );
    assert_eq!(
        revocations_of(&app, "r1").await,
        1,
        "the held token is revoked"
    );

    // After an upstream 401 on a still-valid token.
    let app = app_with(&[(ENV_TOKEN_TIMEOUT_MS, "250")]).await;
    mount_lost_refresh(&app).await;
    mount_probe(&app, "a1", 401, 1).await;
    let sid = app
        .state
        .sessions
        .create("a1".into(), "r1".into(), Utc::now() + Duration::hours(1));
    let res = app.get_as("/explorer/probe", &sid).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    assert_eq!(
        res.location(),
        Some("/explorer/auth/login?return_to=%2Fexplorer%2Fprobe")
    );
    let (value, line) = set_cookie(&res, "epx_session").expect("cookie cleared");
    assert!(value.is_empty() && line.contains("Max-Age=0"), "{line}");
    assert!(app.state.sessions.get(&sid).is_none(), "the session ended");
    let res = app.get_as("/explorer/probe", &sid).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "still signed out");
    assert_eq!(token_posts_presenting(&app, "r1").await, 1);
    assert_eq!(revocations_of(&app, "r1").await, 1);
}

/// The session ends while the refresh lock is still held, so requests that
/// queued on that lock behind the lost refresh find the session gone. Had it
/// been ended after the lock was released, the next request in the queue
/// would re-read the session and replay the old refresh token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queued_requests_never_replay_a_lost_refresh() {
    let app = app_with(&[(ENV_TOKEN_TIMEOUT_MS, "250")]).await;
    mount_lost_refresh(&app).await;
    let sid =
        app.state
            .sessions
            .create("a1".into(), "r1".into(), Utc::now() - Duration::seconds(5));

    let statuses = concurrent_probes(&app, &sid, 6).await;
    assert!(
        statuses.iter().all(|s| *s == StatusCode::SEE_OTHER),
        "every request is sent to sign in: {statuses:?}"
    );
    assert!(app.state.sessions.get(&sid).is_none());
    assert_eq!(
        token_posts_presenting(&app, "r1").await,
        1,
        "one refresh attempt for the whole queue"
    );
    assert_eq!(revocations_of(&app, "r1").await, 1);
}

/// The token call has its own timeout: a refresh slower than the data
/// timeout but inside the token timeout succeeds, and the page renders with
/// the rotated token.
#[tokio::test]
async fn a_token_call_may_outlast_the_data_timeout() {
    let app = app_with(&[
        (ENV_UPSTREAM_TIMEOUT_MS, "250"),
        (ENV_TOKEN_TIMEOUT_MS, "5000"),
    ])
    .await;
    token_call(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "r1"),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(
        ResponseTemplate::new(200)
            .set_body_json(token_json("a2", "r2"))
            .set_delay(StdDuration::from_millis(1000)),
    )
    .expect(1)
    .mount(&app.upstream)
    .await;
    mount_probe(&app, "a2", 200, 1).await;
    let sid =
        app.state
            .sessions
            .create("a1".into(), "r1".into(), Utc::now() - Duration::seconds(5));

    let res = app.get_as("/explorer/probe", &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.json()["token_seen"], "a2");
    let s = app.state.sessions.get(&sid).expect("session kept");
    assert_eq!(
        (s.access_token.as_str(), s.refresh_token.as_str()),
        ("a2", "r2")
    );
}

// ---- logout -----------------------------------------------------------------------

async fn post_logout(app: &TestApp, sid: Option<&SessionId>, origin: Option<&str>) -> TestResponse {
    let cookie = sid.map(TestApp::cookie);
    let mut h: Vec<(&str, &str)> = vec![];
    if let Some(c) = cookie.as_deref() {
        h.push(("cookie", c));
    }
    if let Some(o) = origin {
        h.push(("origin", o));
    }
    send_with(app, Method::POST, "/explorer/auth/logout", &h, "").await
}

#[tokio::test]
async fn logout_revokes_the_refresh_token_and_clears_both_cookies() {
    let app = app().await;
    let sid = app
        .state
        .sessions
        .create("a1".into(), "r1".into(), Utc::now() + Duration::hours(1));
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .and(header("content-type", "application/json"))
        .and(body_json(
            json!({"token": "r1", "token_type_hint": "refresh_token"}),
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.upstream)
        .await;

    let res = post_logout(&app, Some(&sid), Some(ORIGIN)).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(res.location(), Some("/explorer/"));
    assert_eq!(res.header("cache-control"), Some("no-store"));
    assert!(app.state.sessions.get(&sid).is_none());
    let cleared = res.header_all("set-cookie");
    assert_eq!(cleared.len(), 2, "{cleared:?}");
    assert!(cleared
        .iter()
        .all(|c| c.starts_with("epx_session=;") && c.contains("Max-Age=0")));
    assert!(
        cleared.iter().any(|c| c.contains("Partitioned")),
        "the embed cookie is a separate jar entry: {cleared:?}"
    );
    assert!(cleared.iter().any(|c| !c.contains("Partitioned")));

    // Signed out already: still a clean redirect, nothing revoked.
    let res = post_logout(&app, None, Some(ORIGIN)).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn logout_refuses_cross_origin_posts() {
    let app = app().await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("a1");
    for origin in [
        None,
        Some("https://evil.example.net"),
        Some("http://explorer.example.com"),
        Some("https://explorer.example.com.evil.example.net"),
    ] {
        let res = post_logout(&app, Some(&sid), origin).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{origin:?}");
        assert!(res.header_all("set-cookie").is_empty());
    }
    assert!(app.state.sessions.get(&sid).is_some(), "session untouched");
}

#[tokio::test]
async fn logout_survives_a_failed_revocation() {
    let app = app().await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("a1");
    let res = post_logout(&app, Some(&sid), Some(ORIGIN)).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert!(app.state.sessions.get(&sid).is_none());
    assert_eq!(res.header_all("set-cookie").len(), 2);
}

// ---- housekeeping -----------------------------------------------------------------

#[tokio::test]
async fn housekeeping_evicts_expired_sign_in_state() {
    let app = app().await;
    let flow = &app.state.auth_flow;
    flow.pending.insert(
        "expired".into(),
        PendingLogin {
            pkce_verifier: "v".into(),
            return_to: "/explorer/".into(),
            popup: false,
            binding: "b".into(),
            created_at: std::time::Instant::now(),
        },
        StdDuration::ZERO,
    );
    flow.handoffs.insert(
        "expired".into(),
        Handoff {
            tokens: held_tokens(""),
        },
        StdDuration::ZERO,
    );
    flow.handoffs.insert(
        "live".into(),
        Handoff {
            tokens: held_tokens(""),
        },
        StdDuration::from_secs(60),
    );
    assert_eq!(flow.pending.len() + flow.handoffs.len(), 3);

    // The first tick runs immediately.
    let task = explorer_app::spawn_housekeeping(app.state.clone());
    tokio::time::sleep(StdDuration::from_millis(100)).await;
    task.abort();
    assert_eq!(flow.pending.len(), 0);
    assert_eq!(flow.handoffs.len(), 1, "live entries stay");
}

// ---- tokens nobody will use again -----------------------------------------------------

/// A popup sign-in through the real callback, whose code exchange mints
/// `access-1` / `refresh-1` with `scope`. Returns the handoff code the popup
/// page carries.
async fn popup_sign_in(app: &TestApp, scope: &str) -> String {
    let started = start_login(app, "?mode=popup").await;
    any_token_call()
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access-1",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-1",
            "scope": scope
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let res = finish_login(app, &started, "&code=c0de").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(attr(&res.body, "data-status"), Some("ok"));
    attr(&res.body, "data-handoff")
        .expect("handoff code")
        .to_string()
}

/// `/oauth/revoke` accepts anything, `times` times in all.
async fn mount_revoke(app: &TestApp, times: u64) {
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .expect(times)
        .mount(&app.upstream)
        .await;
}

/// Let a handoff's 60 s run out now: put it back with no time left.
fn expire_handoff(app: &TestApp, code: &str) {
    let handoffs = &app.state.auth_flow.handoffs;
    let held = handoffs.take(&code.to_string()).expect("handoff held");
    handoffs.insert(code.to_string(), held, StdDuration::ZERO);
}

async fn redeem_handoff(app: &TestApp, code: &str) -> TestResponse {
    send_with(
        app,
        Method::POST,
        "/explorer/auth/redeem",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("origin", ORIGIN),
        ],
        &format!("code={code}"),
    )
    .await
}

/// An embed sign-in whose handoff is never redeemed (the iframe was closed,
/// the redeem POST was lost) leaves no live refresh token behind: the
/// callback holds the minted tokens in the handoff, not in a session, and
/// when the handoff expires housekeeping revokes the refresh token it held.
#[tokio::test]
async fn an_unredeemed_handoff_leaves_no_live_refresh_token() {
    let app = app().await;
    mount_revoke(&app, 1).await;
    let code = popup_sign_in(&app, "claims:read").await;
    assert!(
        app.state.sessions.is_empty(),
        "no session exists before the handoff is redeemed"
    );
    assert_eq!(app.state.auth_flow.handoffs.len(), 1);

    // While the code is live, housekeeping leaves it and its token alone.
    explorer_app::housekeep(&app.state, explorer_app::SESSION_MAX_AGE).await;
    assert_eq!(app.state.auth_flow.handoffs.len(), 1);
    assert_eq!(revocations_of(&app, "refresh-1").await, 0);

    expire_handoff(&app, &code);
    explorer_app::housekeep(&app.state, explorer_app::SESSION_MAX_AGE).await;
    assert!(app.state.auth_flow.handoffs.is_empty());
    assert!(app.state.sessions.is_empty());
    assert_eq!(
        revocations_of(&app, "refresh-1").await,
        1,
        "the expired handoff's refresh token is revoked"
    );
    assert_eq!(
        token_posts_presenting(&app, "refresh-1").await,
        0,
        "and never presented to /oauth/token"
    );

    // Nothing is left to revoke on a later pass.
    explorer_app::housekeep(&app.state, explorer_app::SESSION_MAX_AGE).await;
    assert_eq!(revocations_of(&app, "refresh-1").await, 1);
}

/// The twin: redeeming the handoff creates exactly one session, from the
/// tokens the callback minted (scope flag included), and housekeeping then
/// revokes nothing, because the token now belongs to a live session.
#[tokio::test]
async fn a_redeemed_handoff_yields_exactly_one_session() {
    let app = app().await;
    mount_revoke(&app, 0).await;
    let code = popup_sign_in(&app, "claims:read claims:write").await;
    assert!(
        app.state.sessions.is_empty(),
        "the callback creates no session in popup mode"
    );

    let res = redeem_handoff(&app, &code).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT, "{}", res.body);
    let (sid, _) = set_cookie(&res, "epx_session").expect("embed cookie");
    let sid = SessionId::parse(&sid).unwrap();
    assert_eq!(app.state.sessions.len(), 1);
    let session = app.state.sessions.get(&sid).expect("the redeemed session");
    assert_eq!(
        (
            session.access_token.as_str(),
            session.refresh_token.as_str()
        ),
        ("access-1", "refresh-1")
    );
    assert!(
        session.scope_widened,
        "the minted token's wider-than-requested flag reaches the session"
    );

    // Single use: a second redeem is refused and creates nothing.
    let res = redeem_handoff(&app, &code).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(set_cookie(&res, "epx_session").is_none());
    assert_eq!(app.state.sessions.len(), 1);

    explorer_app::housekeep(&app.state, explorer_app::SESSION_MAX_AGE).await;
    assert!(app.state.sessions.get(&sid).is_some());
    assert!(app.state.auth_flow.handoffs.is_empty());
    assert_eq!(revocations_of(&app, "refresh-1").await, 0);
}

/// A handoff redeemed after it expired is refused, and the tokens it held
/// are revoked there and then rather than dropped unrevoked.
#[tokio::test]
async fn redeeming_an_expired_handoff_revokes_its_tokens() {
    let app = app().await;
    mount_revoke(&app, 1).await;
    let code = popup_sign_in(&app, "claims:read").await;
    expire_handoff(&app, &code);

    let res = redeem_handoff(&app, &code).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(set_cookie(&res, "epx_session").is_none());
    assert!(app.state.sessions.is_empty());
    assert!(app.state.auth_flow.handoffs.is_empty());
    assert_eq!(revocations_of(&app, "refresh-1").await, 1);
}

/// Housekeeping drops a session created longer ago than the maximum age.
/// Its refresh token may have been rotated recently and still be live
/// upstream, so it is revoked, not just forgotten.
#[tokio::test]
async fn a_purged_session_revokes_its_refresh_token() {
    let app = app().await;
    mount_revoke(&app, 1).await;
    let sid =
        app.state
            .sessions
            .create("a1".into(), "r-old".into(), Utc::now() + Duration::hours(1));

    // Calibration: within the age limit, the session and its token stay.
    explorer_app::housekeep(&app.state, explorer_app::SESSION_MAX_AGE).await;
    assert!(app.state.sessions.get(&sid).is_some());
    assert_eq!(revocations_of(&app, "r-old").await, 0);

    // A negative limit makes every session too old.
    explorer_app::housekeep(&app.state, Duration::seconds(-1)).await;
    assert!(app.state.sessions.get(&sid).is_none());
    assert_eq!(revocations_of(&app, "r-old").await, 1);
}

/// Signing in again in a browser that already has a session replaces that
/// session, and the refresh token the replaced session held is revoked: it
/// is live upstream and nothing will present it again.
#[tokio::test]
async fn signing_in_again_revokes_the_replaced_sessions_refresh_token() {
    let app = app().await;
    mount_revoke(&app, 1).await;
    let old = app.state.sessions.create(
        "a-old".into(),
        "r-old".into(),
        Utc::now() + Duration::hours(1),
    );

    let started = start_login(&app, "").await;
    let verifier = pending_verifier(&app, &started);
    token_call(&[
        ("grant_type", "authorization_code"),
        ("code", "c0de"),
        ("code_verifier", &verifier),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(token_json("a-new", "r-new")))
    .expect(1)
    .mount(&app.upstream)
    .await;
    let cookie = format!(
        "epx_login={}; epx_session={}",
        started.binding,
        old.as_str()
    );
    let res = app
        .get_with(
            &format!("/explorer/auth/callback?state={}&code=c0de", started.state),
            &[("cookie", &cookie)],
        )
        .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    let (new_sid, _) = set_cookie(&res, "epx_session").expect("new session cookie");
    assert_ne!(new_sid, old.as_str(), "a fresh session id");

    assert!(
        app.state.sessions.get(&old).is_none(),
        "the old session is gone"
    );
    assert_eq!(
        revocations_of(&app, "r-old").await,
        1,
        "the replaced session's refresh token is revoked"
    );
    assert_eq!(revocations_of(&app, "r-new").await, 0, "the new one is not");
    app.upstream.verify().await;
}

/// A refresh that succeeds but whose new token upstream still refuses ends
/// the session. The refresh just minted a live refresh token, and the
/// session ending holds it: it is revoked, not dropped.
#[tokio::test]
async fn a_session_refused_after_its_refresh_revokes_the_new_refresh_token() {
    let app = app().await;
    mount_probe(&app, "a1", 401, 1).await;
    token_call(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "r1"),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(token_json("a2", "r2")))
    .expect(1)
    .mount(&app.upstream)
    .await;
    mount_probe(&app, "a2", 401, 1).await;
    mount_revoke(&app, 1).await;
    let sid = app
        .state
        .sessions
        .create("a1".into(), "r1".into(), Utc::now() + Duration::hours(1));

    let res = app.get_as("/explorer/probe", &sid).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    assert!(app.state.sessions.get(&sid).is_none(), "the session ended");
    assert_eq!(
        revocations_of(&app, "r2").await,
        1,
        "the refresh token the session held when it ended is revoked"
    );
    assert_eq!(
        revocations_of(&app, "r1").await,
        0,
        "r1 was rotated, not abandoned"
    );
    app.upstream.verify().await;
}

/// A session that ends while its refresh is in flight (here housekeeping
/// purges it) does not drop the refresh token that refresh minted: upstream
/// has rotated, the new token is live, and no session will hold it, so it is
/// revoked. Housekeeping revokes the token the session held when purged.
#[tokio::test]
async fn a_session_ended_during_its_refresh_revokes_the_token_the_refresh_minted() {
    let app = app().await;
    token_call(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "r1"),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(
        ResponseTemplate::new(200)
            .set_body_json(token_json("a2", "r2"))
            .set_delay(StdDuration::from_millis(400)),
    )
    .expect(1)
    .mount(&app.upstream)
    .await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&app.upstream)
        .await;
    // Expired: the extractor refreshes before the page runs.
    let sid =
        app.state
            .sessions
            .create("a1".into(), "r1".into(), Utc::now() - Duration::seconds(5));

    let page = app.get_as("/explorer/probe", &sid);
    let purge = async {
        tokio::time::sleep(StdDuration::from_millis(100)).await;
        explorer_app::housekeep(&app.state, Duration::seconds(-1)).await;
    };
    let (res, ()) = tokio::join!(page, purge);
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    assert!(
        app.state.sessions.get(&sid).is_none(),
        "the session is gone"
    );
    assert_eq!(token_posts_presenting(&app, "r1").await, 1, "one refresh");
    assert_eq!(
        revocations_of(&app, "r2").await,
        1,
        "the token the refresh minted for a session that no longer exists is revoked"
    );
    assert_eq!(
        revocations_of(&app, "r1").await,
        1,
        "housekeeping revoked the token the session held when it was purged"
    );
    app.upstream.verify().await;
}

// ---- duplicated cookies -------------------------------------------------------------

/// Two `epx_session` values (one possibly tossed in by a sibling host) mean
/// the request cannot tell whose session it is: it is signed out, and both
/// jar entries this site owns are cleared.
#[tokio::test]
async fn two_session_cookies_mean_signed_out() {
    let app = app().await;
    let sid = app.sign_in("access-1");
    // One upstream call in total: the calibration below, never the
    // duplicated request.
    mount_probe(&app, "access-1", 200, 1).await;

    // Calibration: this session alone is signed in.
    let res = app.get_as("/explorer/probe", &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.header_all("set-cookie").is_empty());

    // The valid session FIRST, so a first-match reader would sign it in.
    let other = epigraph_explorer::auth::random_token(32);
    let cookie = format!("epx_session={}; epx_session={other}", sid.as_str());
    let res = app
        .get_with("/explorer/probe", &[("cookie", &cookie)])
        .await;
    assert_eq!(
        res.status,
        StatusCode::SEE_OTHER,
        "a duplicated session cookie must be treated as signed out: {}",
        res.body
    );
    assert!(
        res.location()
            .is_some_and(|l| l.starts_with("/explorer/auth/login?return_to=")),
        "{:?}",
        res.location()
    );
    let cleared = res.header_all("set-cookie");
    assert_eq!(cleared.len(), 2, "{cleared:?}");
    assert!(
        cleared
            .iter()
            .all(|c| c.starts_with("epx_session=;") && c.contains("Max-Age=0")),
        "{cleared:?}"
    );
    assert!(
        cleared.iter().any(|c| c.contains("Partitioned")),
        "the embed cookie is a separate jar entry: {cleared:?}"
    );
    assert!(cleared.iter().any(|c| !c.contains("Partitioned")));

    // In either order.
    let cookie = format!("epx_session={other}; epx_session={}", sid.as_str());
    let res = app
        .get_with("/explorer/probe", &[("cookie", &cookie)])
        .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(res.header_all("set-cookie").len(), 2);
}

/// Two `epx_login` bindings: the callback cannot tell which browser started
/// the login, so it is refused and the next login mints a fresh binding.
#[tokio::test]
async fn two_login_binding_cookies_restart_the_login() {
    let app = app().await;
    any_token_call()
        .respond_with(ResponseTemplate::new(200).set_body_json(token_json("a", "r")))
        .expect(0)
        .mount(&app.upstream)
        .await;
    let started = start_login(&app, &format!("?return_to={CLAIM_PATH}")).await;

    // This browser's own binding FIRST, so a first-match reader would accept.
    let other = epigraph_explorer::auth::random_token(32);
    let cookie = format!("epx_login={}; epx_login={other}", started.binding);
    let res = app
        .get_with(
            &format!("/explorer/auth/callback?code=c&state={}", started.state),
            &[("cookie", &cookie)],
        )
        .await;
    assert_eq!(
        res.status,
        StatusCode::BAD_REQUEST,
        "a duplicated login binding must refuse the callback: {}",
        res.body
    );
    assert!(res.body.contains("started in this browser"), "{}", res.body);
    assert!(
        res.body
            .contains("/explorer/auth/login?return_to=%2Fexplorer%2Fclaim%2F"),
        "the retry link restarts the same login: {}",
        res.body
    );
    assert_eq!(app.state.sessions.len(), 0);

    // The restart: a login with the same two cookies reuses neither.
    let res = app
        .get_with("/explorer/auth/login", &[("cookie", &cookie)])
        .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    let (binding, _) = set_cookie(&res, "epx_login").expect("a fresh binding is set");
    assert_ne!(binding, started.binding);
    assert_ne!(binding, other);
}

// ---- scope tripwire -----------------------------------------------------------------

/// A token wider than requested is recorded on the session at mint, and the
/// record follows each refresh (display only; nothing authorizes on it).
#[tokio::test]
async fn a_token_wider_than_requested_is_flagged_on_the_session() {
    let app = app().await;
    let started = start_login(&app, "").await;
    let verifier = pending_verifier(&app, &started);
    let mut wide = token_json("access-1", "refresh-1");
    wide["scope"] = json!("claims:read claims:write");
    token_call(&[
        ("grant_type", "authorization_code"),
        ("code", "c0de"),
        ("code_verifier", &verifier),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(wide))
    .expect(1)
    .mount(&app.upstream)
    .await;

    let res = finish_login(&app, &started, "&code=c0de").await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    let (sid, _) = set_cookie(&res, "epx_session").expect("session cookie");
    let sid = SessionId::parse(&sid).unwrap();
    assert!(
        app.state.sessions.get(&sid).unwrap().scope_widened,
        "minted wider than requested"
    );

    // The refreshed token carries exactly the requested scope: cleared.
    token_call(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "refresh-1"),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(token_json("access-2", "refresh-2")))
    .expect(1)
    .mount(&app.upstream)
    .await;
    mount_probe(&app, "access-2", 200, 1).await;
    app.state.sessions.update_tokens(
        &sid,
        "access-1".into(),
        "refresh-1".into(),
        Utc::now() - Duration::seconds(1),
    );
    let res = app.get_as("/explorer/probe", &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.json()["token_seen"], "access-2");
    assert!(
        !app.state.sessions.get(&sid).unwrap().scope_widened,
        "a refresh to the requested scope clears the flag"
    );
}

// ---- identity strip -----------------------------------------------------------------

/// Synthetic token subjects (what `/oauth/introspect` reports as `sub`).
const SUB_1: &str = "11111111-1111-4111-8111-111111111111";
const SUB_2: &str = "22222222-2222-4222-8222-222222222222";

/// `POST /oauth/introspect` presenting exactly `token` (JSON, as upstream's
/// `oauth/introspect.rs::introspect_endpoint` takes it).
fn introspect_call(token: &str) -> wiremock::MockBuilder {
    Mock::given(method("POST"))
        .and(path("/oauth/introspect"))
        .and(body_json(json!({ "token": token })))
}

/// An active token's introspection: upstream reports `client_id` = `sub`.
fn introspected(sub: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "active": true,
        "sub": sub,
        "client_id": sub,
        "scope": "claims:read",
        "exp": 4_102_444_800i64,
        "iat": 1_700_000_000i64,
        "token_type": "Bearer"
    }))
}

/// How many introspection calls presented `token`.
async fn introspections_of(app: &TestApp, token: &str) -> usize {
    app.upstream
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/oauth/introspect")
        .filter(|r| serde_json::from_slice::<Value>(&r.body).is_ok_and(|b| b["token"] == token))
        .count()
}

/// A page-mode sign-in through `/auth/login` and `/auth/callback` whose code
/// redemption answers `token_body`; the new session's id.
async fn sign_in_answering(app: &TestApp, token_body: Value) -> SessionId {
    let started = start_login(app, "").await;
    let verifier = pending_verifier(app, &started);
    token_call(&[
        ("grant_type", "authorization_code"),
        ("code", "c0de"),
        ("code_verifier", &verifier),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(token_body))
    .expect(1)
    .mount(&app.upstream)
    .await;
    let res = finish_login(app, &started, "&code=c0de").await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    let (sid, _) = set_cookie(&res, "epx_session").expect("session cookie");
    SessionId::parse(&sid).unwrap()
}

/// A signed-in HTML page that makes no upstream call (search, no query).
async fn header_of(app: &TestApp, sid: &SessionId) -> TestResponse {
    let res = app.get_as("/explorer/search", sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    res
}

/// The identity strip's markup in a page.
fn strip(body: &str) -> &str {
    let start = body
        .find("<p class=\"identity-strip\"")
        .unwrap_or_else(|| panic!("no identity strip in: {body}"));
    let len = body[start..].find("</p>").expect("strip closes");
    &body[start..start + len]
}

/// The text of the strip's `class` span (up to its first closing tag).
fn strip_part<'a>(strip: &'a str, class: &str) -> &'a str {
    let open = format!("<span class=\"identity-strip__{class}\">");
    let start = strip
        .find(&open)
        .unwrap_or_else(|| panic!("no {class} in: {strip}"))
        + open.len();
    let len = strip[start..].find("</span>").expect("span closes");
    &strip[start..start + len]
}

/// The header lists the scopes the token response granted, not the ones
/// the Explorer asked for: a user without `audit:read` sees `claims:read`.
#[tokio::test]
async fn identity_strip_shows_the_tokens_actual_scopes() {
    let app = app().await;
    introspect_call("access-1")
        .respond_with(introspected(SUB_1))
        .mount(&app.upstream)
        .await;
    // Granted: `claims:read` only (requested: claims:read audit:read).
    let sid = sign_in_answering(&app, token_json("access-1", "refresh-1")).await;

    let res = header_of(&app, &sid).await;
    let s = strip(&res.body);
    assert_eq!(strip_part(s, "scope"), "token scope: claims:read", "{s}");
    assert!(
        !s.contains("audit:read"),
        "the requested set is not shown: {s}"
    );
    assert!(!s.contains("wider than requested"), "{s}");
    assert!(
        strip_part(s, "client").contains(&SUB_1[..8]),
        "the introspected subject is shown as the sign-in client: {s}"
    );
    assert_eq!(
        strip_part(s, "principal"),
        "principal unavailable",
        "an opaque token names no agent, and the subject is not shown as one: {s}"
    );
    let expiry = strip_part(s, "expiry");
    assert!(
        expiry == "expires in 59 min" || expiry == "expires in 60 min",
        "{expiry}"
    );
    assert!(
        s.contains("the agent your access token names"),
        "what the principal is, stated: {s}"
    );
    // The sign-out button is still there.
    assert!(res.body.contains("action=\"/explorer/auth/logout\""));

    // Signed out: no strip.
    let anon = app.get(CLAIM_PATH).await;
    assert!(!anon.body.contains("identity-strip"), "{}", anon.body);
}

/// A token wider than requested is shown as neutral information until the
/// kernel stops widening on refresh: the words, never warning styling.
#[tokio::test]
async fn identity_strip_shows_a_widened_token_as_neutral_info() {
    let app = app().await;
    introspect_call("access-1")
        .respond_with(introspected(SUB_1))
        .mount(&app.upstream)
        .await;
    let mut wide = token_json("access-1", "refresh-1");
    wide["scope"] = json!("claims:read audit:read claims:write");
    let sid = sign_in_answering(&app, wide).await;

    let res = header_of(&app, &sid).await;
    let s = strip(&res.body);
    assert!(
        s.contains("token scope: claims:read audit:read claims:write"),
        "{s}"
    );
    assert_eq!(strip_part(s, "note"), "wider than requested", "{s}");
    assert!(!s.contains("warn"), "neutral, not a warning: {s}");
    assert!(!s.contains("notice"), "neutral, not a notice box: {s}");
}

/// Introspection is for the sign-in client only. When it fails, the client
/// reads "unavailable" and everything else still renders: the scope and
/// expiry come from the token response itself.
#[tokio::test]
async fn introspect_failure_degrades_the_client_not_the_page() {
    let app = app().await;
    introspect_call("access-1")
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": "InternalError", "message": "introspection failed"
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = sign_in_answering(&app, token_json("access-1", "refresh-1")).await;

    let res = header_of(&app, &sid).await;
    assert!(res.body.contains("role=\"search\""), "the page renders");
    let s = strip(&res.body);
    assert_eq!(strip_part(s, "client"), "sign-in client unavailable", "{s}");
    assert_eq!(strip_part(s, "scope"), "token scope: claims:read", "{s}");
    assert!(strip_part(s, "expiry").starts_with("expires in "), "{s}");
}

/// "Signed in as" names the agent the access token carries (its
/// `agent_id`), which is the kernel's principal and the id on the viewer's
/// own rows, not the token subject: the API sets `sub` to the OAuth client
/// record, and introspection reports that, so it is labelled the sign-in
/// client.
#[tokio::test]
async fn identity_strip_names_the_tokens_agent_and_labels_the_subject_as_the_client() {
    const AGENT_ID: &str = "1b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
    let app = app().await;
    let access = common::jwt_with_agent(AGENT_ID);
    introspect_call(&access)
        .respond_with(introspected(SUB_1))
        .mount(&app.upstream)
        .await;
    let sid = sign_in_answering(&app, token_json(&access, "refresh-1")).await;

    let res = header_of(&app, &sid).await;
    let s = strip(&res.body);
    let principal = strip_part(s, "principal");
    assert!(
        principal.starts_with(
            "signed in as <code title=\"1b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10\">1b9a5a4e</code>"
        ),
        "the token's agent is the principal: {s}"
    );
    assert!(!principal.contains(&SUB_1[..8]), "never the subject: {s}");
    let client = strip_part(s, "client");
    assert!(
        client.starts_with(&format!(
            "sign-in client <code title=\"{SUB_1}\">{}</code>",
            &SUB_1[..8]
        )),
        "the subject is the sign-in client: {s}"
    );
}

/// The principal is looked up once per token (at mint, and again for each
/// refreshed token), never per page.
#[tokio::test]
async fn introspect_is_called_once_per_token_not_per_page() {
    let app = app().await;
    introspect_call("access-1")
        .respond_with(introspected(SUB_1))
        .mount(&app.upstream)
        .await;
    introspect_call("access-2")
        .respond_with(introspected(SUB_2))
        .mount(&app.upstream)
        .await;
    let sid = sign_in_answering(&app, token_json("access-1", "refresh-1")).await;
    assert_eq!(introspections_of(&app, "access-1").await, 1, "at mint");

    for _ in 0..2 {
        let res = header_of(&app, &sid).await;
        assert!(strip(&res.body).contains(&SUB_1[..8]));
    }
    assert_eq!(
        introspections_of(&app, "access-1").await,
        1,
        "two page loads, no further call"
    );

    // The token is refreshed: the new token is introspected once.
    token_call(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "refresh-1"),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(token_json("access-2", "refresh-2")))
    .expect(1)
    .mount(&app.upstream)
    .await;
    app.state.sessions.update_tokens(
        &sid,
        "access-1".into(),
        "refresh-1".into(),
        Utc::now() - Duration::seconds(1),
    );
    for _ in 0..2 {
        let res = header_of(&app, &sid).await;
        let s = strip(&res.body);
        assert!(
            s.contains(&SUB_2[..8]),
            "the refreshed token's principal: {s}"
        );
        assert!(!s.contains(&SUB_1[..8]), "{s}");
    }
    assert_eq!(introspections_of(&app, "access-1").await, 1);
    assert_eq!(
        introspections_of(&app, "access-2").await,
        1,
        "once for the refreshed token, not per page"
    );
}

/// The strip is on every signed-in page header, not only on pages built by
/// the extractor: error pages (rendered by the error layer) and auth pages
/// build their own header context.
#[tokio::test]
async fn identity_strip_is_on_error_and_auth_pages() {
    let app = app().await;
    let sid = app.sign_in("access-1");
    app.state
        .sessions
        .set_token_scope(&sid, Some("claims:read".into()), false);
    app.state.sessions.set_principal(
        &sid,
        "access-1",
        epigraph_explorer::upstream::Degraded::ok(SUB_1.into()),
    );

    // An unknown path: the router fallback's 404 page.
    let res = app.get_as("/explorer/nowhere", &sid).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    let s = strip(&res.body);
    assert_eq!(strip_part(s, "scope"), "token scope: claims:read", "{s}");
    assert!(s.contains(&SUB_1[..8]), "{s}");

    // An auth page: a callback whose sign-in state is unknown.
    let res = app
        .get_as("/explorer/auth/callback?state=unknown&code=c", &sid)
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.body);
    assert!(strip(&res.body).contains(&SUB_1[..8]), "{}", res.body);
}

// ---- cookie names per deployment mode ---------------------------------------------

/// An app at `base` (a public base URL) with sign-in configured.
async fn app_at(base: &str, extra: &[(&str, &str)]) -> TestApp {
    let mut env = vec![
        (ENV_PUBLIC_BASE_URL, base),
        (ENV_CLIENT_ID, CLIENT_ID),
        (ENV_OAUTH_BASE_URL, OAUTH_BASE),
    ];
    env.extend_from_slice(extra);
    spawn_with(
        &env,
        Router::new()
            .route("/probe", get(probe))
            .route("/bff/probe", get(probe)),
    )
    .await
}

/// A `Set-Cookie` line's attributes, trimmed, so `Path=` compares exactly.
fn cookie_attrs(line: &str) -> Vec<&str> {
    line.split(';').skip(1).map(str::trim).collect()
}

/// A browser keeps a `__Host-` cookie only with `Secure`, exactly `Path=/`
/// and no `Domain`.
fn assert_host_prefix_rules(line: &str) {
    let a = cookie_attrs(line);
    assert!(line.starts_with("__Host-"), "{line}");
    assert!(a.contains(&"Secure"), "{line}");
    assert!(
        a.contains(&"Path=/"),
        "`__Host-` needs exactly Path=/: {line}"
    );
    assert!(
        !a.iter()
            .any(|x| x.to_ascii_lowercase().starts_with("domain")),
        "{line}"
    );
}

/// Run `/auth/login` then `/auth/callback` through the real routes of an app
/// served at `base_path`, sending back the binding under `login_name`.
/// Returns the session id and the two `Set-Cookie` lines (session, binding).
async fn sign_in_through_the_flow(
    app: &TestApp,
    base_path: &str,
    redirect_uri: &str,
    login_name: &str,
    session_name: &str,
) -> (SessionId, String, String) {
    let res = app.get(&format!("{base_path}/auth/login")).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    let (binding, login_line) = set_cookie(&res, login_name)
        .unwrap_or_else(|| panic!("no {login_name}: {:?}", res.header_all("set-cookie")));
    let location = Url::parse(res.location().expect("Location")).unwrap();
    let params: HashMap<String, String> = location.query_pairs().into_owned().collect();
    assert_eq!(params["redirect_uri"], redirect_uri);
    let verifier = app
        .state
        .auth_flow
        .pending
        .get(&params["state"])
        .expect("pending login")
        .pkce_verifier;
    token_call(&[
        ("grant_type", "authorization_code"),
        ("code", "c0de"),
        ("code_verifier", &verifier),
        ("redirect_uri", redirect_uri),
        ("client_id", CLIENT_ID),
    ])
    .respond_with(ResponseTemplate::new(200).set_body_json(token_json("access-1", "refresh-1")))
    .expect(1)
    .mount(&app.upstream)
    .await;

    let res = app
        .get_with(
            &format!(
                "{base_path}/auth/callback?code=c0de&state={}",
                params["state"]
            ),
            &[("cookie", &format!("{login_name}={binding}"))],
        )
        .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    let (sid, session_line) = set_cookie(&res, session_name)
        .unwrap_or_else(|| panic!("no {session_name}: {:?}", res.header_all("set-cookie")));
    let sid = SessionId::parse(&sid).expect("well-formed session id");
    (sid, session_line, login_line)
}

/// Secure at the root, both cookies carry `__Host-`: a sibling host can toss
/// a `Domain=` cookie of a plain name, never of a `__Host-` one, so the
/// session swap and login CSRF that tossing enables are closed.
#[tokio::test]
async fn session_cookie_is_host_prefixed_at_root_when_secure() {
    let app = app_at("https://explorer.example.com", &[]).await;
    let (sid, session_line, login_line) = sign_in_through_the_flow(
        &app,
        "",
        "https://explorer.example.com/auth/callback",
        "__Host-epx_login",
        "__Host-epx_session",
    )
    .await;
    for line in [&session_line, &login_line] {
        assert_host_prefix_rules(line);
        assert!(cookie_attrs(line).contains(&"HttpOnly"), "{line}");
        assert!(cookie_attrs(line).contains(&"SameSite=Lax"), "{line}");
    }

    // The session round-trips under the prefixed name. One upstream call in
    // total: none of the refused requests below reaches upstream.
    mount_probe(&app, "access-1", 200, 1).await;
    let prefixed = format!("__Host-epx_session={}", sid.as_str());
    let res = app.get_with("/probe", &[("cookie", &prefixed)]).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.json()["token_seen"], "access-1");

    // The plain name is not read in this mode, even carrying a live id.
    let plain = format!("epx_session={}", sid.as_str());
    let res = app.get_with("/probe", &[("cookie", &plain)]).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    assert!(
        res.location()
            .is_some_and(|l| l.starts_with("/auth/login?return_to=")),
        "{:?}",
        res.location()
    );

    // A duplicated prefixed cookie is still refused, and both prefixed jar
    // entries are cleared.
    let other = epigraph_explorer::auth::random_token(32);
    let twice = format!("{prefixed}; __Host-epx_session={other}");
    let res = app.get_with("/probe", &[("cookie", &twice)]).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    let cleared = res.header_all("set-cookie");
    assert_eq!(cleared.len(), 2, "{cleared:?}");
    for c in &cleared {
        assert!(c.starts_with("__Host-epx_session=;"), "{c}");
        assert!(cookie_attrs(c).contains(&"Max-Age=0"), "{c}");
        assert_host_prefix_rules(c);
    }

    // A login binding under the plain name is not this browser's.
    let res = app.get("/auth/login").await;
    let (binding, _) = set_cookie(&res, "__Host-epx_login").expect("prefixed binding");
    let state = Url::parse(res.location().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let res = app
        .get_with(
            &format!("/auth/callback?code=c0de&state={state}"),
            &[("cookie", &format!("epx_login={binding}"))],
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.body);
    assert!(res.body.contains("started in this browser"), "{}", res.body);

    // Logout reads the prefixed cookie and clears both prefixed entries.
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let res = send_with(
        &app,
        Method::POST,
        "/auth/logout",
        &[
            ("origin", "https://explorer.example.com"),
            ("cookie", &prefixed),
        ],
        "",
    )
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    assert!(app.state.sessions.get(&sid).is_none(), "session dropped");
    let cleared = res.header_all("set-cookie");
    assert_eq!(cleared.len(), 2, "{cleared:?}");
    for c in &cleared {
        assert!(c.starts_with("__Host-epx_session=;"), "{c}");
        assert_host_prefix_rules(c);
    }
}

/// Plain-http loopback dev keeps the plain names (a browser drops a `__Host-`
/// cookie without `Secure`), so local sign-in still works.
#[tokio::test]
async fn insecure_loopback_cookie_is_unprefixed_and_sign_in_works() {
    let app = app_at("http://localhost:8096", &[(ENV_INSECURE_COOKIES, "true")]).await;
    let (sid, session_line, login_line) = sign_in_through_the_flow(
        &app,
        "",
        "http://localhost:8096/auth/callback",
        "epx_login",
        "epx_session",
    )
    .await;
    assert!(
        cookie_attrs(&session_line).contains(&"Path=/"),
        "{session_line}"
    );
    assert!(
        cookie_attrs(&login_line).contains(&"Path=/auth"),
        "{login_line}"
    );
    for line in [&session_line, &login_line] {
        assert!(!cookie_attrs(line).contains(&"Secure"), "{line}");
    }

    mount_probe(&app, "access-1", 200, 1).await;
    let res = app
        .get_with(
            "/probe",
            &[("cookie", &format!("epx_session={}", sid.as_str()))],
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.json()["token_seen"], "access-1");
}

/// Under a base path `__Host-` is unavailable (it needs `Path=/`), so the
/// plain names, scoped to the base path, and sign-in still works.
#[tokio::test]
async fn base_path_deploy_uses_unprefixed_cookies() {
    let app = app().await;
    let (sid, session_line, login_line) =
        sign_in_through_the_flow(&app, "/explorer", REDIRECT_URI, "epx_login", "epx_session").await;
    assert!(
        cookie_attrs(&session_line).contains(&"Path=/explorer"),
        "{session_line}"
    );
    assert!(
        cookie_attrs(&login_line).contains(&"Path=/explorer/auth"),
        "{login_line}"
    );
    for line in [&session_line, &login_line] {
        assert!(cookie_attrs(line).contains(&"Secure"), "{line}");
    }

    mount_probe(&app, "access-1", 200, 1).await;
    let res = app
        .get_with(
            "/explorer/probe",
            &[("cookie", &format!("epx_session={}", sid.as_str()))],
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.json()["token_seen"], "access-1");
}
