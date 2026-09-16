//! Shared integration-test harness: the real router against a wiremock
//! upstream, driven in-process with `tower::ServiceExt::oneshot`.
//!
//! ```ignore
//! mod common;
//! let app = common::spawn().await;                  // base path /explorer
//! Mock::given(method("GET")).and(path("/api/v1/stats"))
//!     .respond_with(ResponseTemplate::new(200).set_body_json(json!({...})))
//!     .mount(&app.upstream).await;
//! let sid = app.sign_in("access-1");                // session straight into the store
//! let res = app.get_as("/explorer/", &sid).await;
//! assert_eq!(res.status, StatusCode::OK);
//! ```

#![allow(dead_code)] // each test binary uses a different subset

use std::collections::HashMap;

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use epigraph_explorer::auth::{RequestAuth, SessionId, SESSION_COOKIE};
use epigraph_explorer::config::{
    Config, ENV_API_URL, ENV_PUBLIC_BASE_URL, ENV_UPSTREAM_TIMEOUT_MS,
};
use epigraph_explorer::{app, AppState};
use tower::ServiceExt;
use wiremock::MockServer;

/// Public base URL every test app uses unless overridden.
pub const PUBLIC_BASE: &str = "https://explorer.example.com/explorer";
/// Its base path.
pub const BASE: &str = "/explorer";

pub struct TestApp {
    pub state: AppState,
    pub router: Router,
    /// The fake epigraph-api. Mount `wiremock::Mock`s on it.
    pub upstream: MockServer,
}

/// App at [`PUBLIC_BASE`] against a fresh mock upstream, 2 s upstream timeout.
pub async fn spawn() -> TestApp {
    spawn_with(&[], Router::new()).await
}

/// Like [`spawn`], with env overrides (applied after the defaults, so they
/// win) and extra routes merged into the app (probe handlers).
pub async fn spawn_with(env: &[(&str, &str)], extra: Router<AppState>) -> TestApp {
    let upstream = MockServer::start().await;
    let mut vars: HashMap<String, String> = HashMap::from([
        (ENV_PUBLIC_BASE_URL.to_string(), PUBLIC_BASE.to_string()),
        (ENV_API_URL.to_string(), upstream.uri()),
        (ENV_UPSTREAM_TIMEOUT_MS.to_string(), "2000".to_string()),
    ]);
    for (k, v) in env {
        vars.insert(k.to_string(), v.to_string());
    }
    let config = Config::from_lookup(|k| vars.get(k).cloned()).expect("test config is valid");
    let state = AppState::new(config).expect("state builds");
    let router = app::build_app_with(state.clone(), extra);
    TestApp {
        state,
        router,
        upstream,
    }
}

pub struct TestResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl TestResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Every value of a repeated header (e.g. `set-cookie`).
    pub fn header_all(&self, name: &str) -> Vec<String> {
        self.headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect()
    }

    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("body is not JSON ({e}): {}", self.body))
    }
}

impl TestApp {
    /// Put a signed-in session straight into the store (token valid 1 h).
    pub fn sign_in(&self, access_token: &str) -> SessionId {
        self.sign_in_expiring(access_token, Duration::hours(1))
    }

    /// As [`TestApp::sign_in`] with a chosen remaining lifetime (negative =
    /// already expired).
    pub fn sign_in_expiring(&self, access_token: &str, ttl: Duration) -> SessionId {
        self.state.sessions.create(
            access_token.to_string(),
            "refresh-token".to_string(),
            Utc::now() + ttl,
        )
    }

    /// `RequestAuth` for a session, as the extractor would build it.
    pub fn session_auth(&self, id: &SessionId, access_token: &str) -> RequestAuth {
        RequestAuth::Session {
            id: id.clone(),
            access_token: access_token.to_string(),
        }
    }

    /// `Cookie` header value for a session.
    pub fn cookie(id: &SessionId) -> String {
        format!("{SESSION_COOKIE}={}", id.as_str())
    }

    pub async fn send(&self, req: Request<Body>) -> TestResponse {
        let resp = self
            .router
            .clone()
            .oneshot(req)
            .await
            .expect("router is infallible");
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .expect("body reads");
        TestResponse {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    /// Anonymous GET.
    pub async fn get(&self, uri: &str) -> TestResponse {
        self.send(Request::get(uri).body(Body::empty()).unwrap())
            .await
    }

    /// GET with extra headers.
    pub async fn get_with(&self, uri: &str, headers: &[(&str, &str)]) -> TestResponse {
        let mut req = Request::get(uri);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        self.send(req.body(Body::empty()).unwrap()).await
    }

    /// GET as a signed-in session.
    pub async fn get_as(&self, uri: &str, id: &SessionId) -> TestResponse {
        self.get_with(uri, &[("cookie", &Self::cookie(id))]).await
    }

    /// POST an `application/x-www-form-urlencoded` body, optionally signed in.
    pub async fn post_form(&self, uri: &str, body: &str, id: Option<&SessionId>) -> TestResponse {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(id) = id {
            req = req.header(header::COOKIE, Self::cookie(id));
        }
        self.send(req.body(Body::from(body.to_string())).unwrap())
            .await
    }
}
