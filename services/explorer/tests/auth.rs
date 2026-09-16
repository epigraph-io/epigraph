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
use epigraph_explorer::config::{ENV_CLIENT_ID, ENV_OAUTH_BASE_URL};
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
    assert_eq!(p["scope"], "claims:read");
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
async fn pending_logins_are_capped() {
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

    // Live ones are not: the next login is refused rather than stored.
    entry(StdDuration::from_secs(600));
    let res = app.get("/explorer/auth/login").await;
    assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        app.state.auth_flow.pending.len(),
        MAX_PENDING_LOGINS + 1,
        "nothing new was stored"
    );
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
    // What upstream's consent POST sends back on "deny" (authorize.rs:325-335).
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
            session_id: sid.clone(),
        },
        StdDuration::ZERO,
    );
    let res = redeem(Some(ORIGIN), format!("code={stale}")).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);

    // A code whose session has since ended is worthless.
    let orphan = epigraph_explorer::auth::random_token(32);
    let gone = app.sign_in("x");
    app.state.sessions.remove(&gone);
    app.state.auth_flow.handoffs.insert(
        orphan.clone(),
        Handoff { session_id: gone },
        StdDuration::from_secs(60),
    );
    let res = redeem(Some(ORIGIN), format!("code={orphan}")).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
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
            session_id: SessionId::generate(),
        },
        StdDuration::ZERO,
    );
    flow.handoffs.insert(
        "live".into(),
        Handoff {
            session_id: SessionId::generate(),
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
