//! Token refresh (plan §3.3) against a wiremock `/oauth/token` shaped like
//! oauth-auth.md §3 and §6: form bodies in, `TokenResponse` or the non-RFC
//! `{error, message, details}` body out.

mod common;

use std::collections::HashMap;
use std::time::Duration as StdDuration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{Duration, Utc};
use common::{spawn_with, TestApp, TestResponse};
use epigraph_explorer::auth::{oauth, RefreshError, SessionId, SignedIn};
use epigraph_explorer::config::{ENV_CLIENT_ID, ENV_OAUTH_BASE_URL};
use epigraph_explorer::{AppError, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

const CLIENT_ID: &str = "epigraph_explorer_test";
const OAUTH_BASE: &str = "https://api.example.com";

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
