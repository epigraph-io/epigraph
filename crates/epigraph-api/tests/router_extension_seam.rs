#![cfg(feature = "db")]
//! The router extension seam, through the real router: an embedder's routes
//! sit under the authenticated router's layers, whatever state they carry.
//!
//! Every assertion that names a layer goes through the OWN-STATE extension,
//! the path most likely to end up outside the layers (`with_state` turns it
//! into a separately stated router before it is nested).
//! `#[sqlx::test]` gives each test a fresh migrated database: the bearer
//! layer's revocation lookup reads it.

use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use epigraph_api::middleware::bearer::RequireScopeWrite;
use epigraph_api::middleware::AuthContext;
use epigraph_api::{create_router_with_extensions, ApiConfig, AppState, RouterExtension};
use epigraph_auth::AccessTokenBinding;
use sqlx::PgPool;
use tower::ServiceExt as _;
use uuid::Uuid;

/// An embedder's own state, unrelated to `AppState`.
#[derive(Clone)]
struct EmbedderState {
    marker: &'static str,
}

const BODY_LIMIT: usize = 1024;

fn app(pool: &PgPool) -> (Router, AppState) {
    let state = AppState::with_db(
        pool.clone(),
        ApiConfig {
            max_request_size: BODY_LIMIT,
            ..ApiConfig::default()
        },
    );

    // Own-state extension: a read, a write with a path parameter, a body
    // reader, a scope-gated route, and its own fallback.
    let own = Router::new()
        .route(
            "/whoami",
            get(|State(s): State<EmbedderState>, Extension(auth): Extension<AuthContext>| async move {
                format!("{}:{}", s.marker, auth.agent_id.expect("agent token"))
            }),
        )
        .route(
            "/items/:id",
            post(|Path(id): Path<Uuid>| async move { format!("wrote {id}") }),
        )
        .route(
            "/echo",
            post(|Json(v): Json<serde_json::Value>| async move { Json(v) }),
        )
        .route(
            "/needs-write",
            get(|RequireScopeWrite(_auth): RequireScopeWrite| async { "ok" }),
        )
        .fallback(|| async { "extension fallback" });
    let own = RouterExtension::with_state("demo", own, EmbedderState { marker: "embedder" })
        .expect("valid name");

    // Kernel-state extension: reads AppState.
    let kernel = Router::new().route(
        "/limit",
        get(|State(s): State<AppState>| async move { s.config.max_request_size.to_string() }),
    );
    let kernel = RouterExtension::new("kstate", kernel).expect("valid name");

    let router = create_router_with_extensions(state.clone(), vec![own, kernel]);
    (router, state)
}

fn token(state: &AppState, agent: Uuid, scopes: &[&str], elevation: Option<Uuid>) -> String {
    state
        .jwt_config
        .issue_access_token(
            agent,
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "agent",
            None,
            Some(agent),
            chrono::Duration::minutes(10),
            AccessTokenBinding {
                family_id: elevation.map(|_| Uuid::new_v4()),
                elevation_id: elevation,
            },
        )
        .expect("mint")
        .0
}

async fn send(
    router: &Router,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<String>,
) -> (StatusCode, String, Option<String>) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b))
            .unwrap(),
        None => req.body(Body::empty()).unwrap(),
    };
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (
        status,
        String::from_utf8_lossy(&bytes).into_owned(),
        challenge,
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn extension_without_a_token_is_401_with_a_bearer_challenge(pool: PgPool) {
    let (router, _) = app(&pool);
    let (status, body, challenge) =
        send(&router, "GET", "/api/v1/ext/demo/whoami", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(
        challenge
            .as_deref()
            .is_some_and(|c| c.starts_with("Bearer")),
        "missing RFC 6750 challenge: {challenge:?}"
    );
    assert!(
        !body.contains("embedder"),
        "handler ran without a token: {body}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn own_state_extension_sees_its_state_and_the_callers_auth_context(pool: PgPool) {
    let (router, state) = app(&pool);
    let agent = Uuid::new_v4();
    let t = token(&state, agent, &["claims:read"], None);
    let (status, body, _) = send(&router, "GET", "/api/v1/ext/demo/whoami", Some(&t), None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body, format!("embedder:{agent}"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn kernel_state_extension_reads_app_state(pool: PgPool) {
    let (router, state) = app(&pool);
    let t = token(&state, Uuid::new_v4(), &["claims:read"], None);
    let (status, body, _) = send(&router, "GET", "/api/v1/ext/kstate/limit", Some(&t), None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body, BODY_LIMIT.to_string());
}

#[sqlx::test(migrations = "../../migrations")]
async fn kernel_state_extension_without_a_token_is_401(pool: PgPool) {
    let (router, _) = app(&pool);
    let (status, body, challenge) =
        send(&router, "GET", "/api/v1/ext/kstate/limit", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(
        challenge
            .as_deref()
            .is_some_and(|c| c.starts_with("Bearer")),
        "missing RFC 6750 challenge: {challenge:?}"
    );
    assert!(
        !body.contains(&BODY_LIMIT.to_string()),
        "handler ran without a token: {body}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn own_state_extension_can_enforce_a_kernel_scope(pool: PgPool) {
    let (router, state) = app(&pool);
    let reader = token(&state, Uuid::new_v4(), &["claims:read"], None);
    let writer = token(&state, Uuid::new_v4(), &["claims:write"], None);
    let (denied, body, _) = send(
        &router,
        "GET",
        "/api/v1/ext/demo/needs-write",
        Some(&reader),
        None,
    )
    .await;
    assert_eq!(denied, StatusCode::FORBIDDEN, "body: {body}");
    assert!(
        body.contains("Missing required scope: claims:write"),
        "not RequireScopeWrite's own rejection: {body}"
    );
    let (allowed, body, _) = send(
        &router,
        "GET",
        "/api/v1/ext/demo/needs-write",
        Some(&writer),
        None,
    )
    .await;
    assert_eq!(allowed, StatusCode::OK, "body: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn elevated_post_to_extension_is_refused_as_read_only(pool: PgPool) {
    let (router, state) = app(&pool);
    let elevated = token(
        &state,
        Uuid::new_v4(),
        &["claims:write"],
        Some(Uuid::new_v4()),
    );
    let path = format!("/api/v1/ext/demo/items/{}", Uuid::new_v4());
    let (status, body, _) = send(&router, "POST", &path, Some(&elevated), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert!(
        body.contains("ELEVATED READ-ONLY"),
        "not the recorder's refusal: {body}"
    );
    assert!(
        !body.contains("wrote"),
        "handler ran for an elevated write: {body}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn oversized_body_to_extension_is_413(pool: PgPool) {
    let (router, state) = app(&pool);
    let t = token(&state, Uuid::new_v4(), &["claims:write"], None);
    let big = format!("{{\"pad\":\"{}\"}}", "x".repeat(BODY_LIMIT * 4));
    let (status, body, _) = send(
        &router,
        "POST",
        "/api/v1/ext/demo/echo",
        Some(&t),
        Some(big),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "body: {body}");
    let (ok, body, _) = send(
        &router,
        "POST",
        "/api/v1/ext/demo/echo",
        Some(&t),
        Some("{\"pad\":\"x\"}".into()),
    )
    .await;
    assert_eq!(ok, StatusCode::OK, "a small body must pass: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn fallback_under_prefix_is_still_behind_bearer(pool: PgPool) {
    let (router, _) = app(&pool);
    let (status, body, _) =
        send(&router, "GET", "/api/v1/ext/demo/no-such-route", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(
        !body.contains("extension fallback"),
        "fallback served anonymously: {body}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn elevated_post_to_extension_fallback_is_refused(pool: PgPool) {
    let (router, state) = app(&pool);
    let elevated = token(
        &state,
        Uuid::new_v4(),
        &["claims:write"],
        Some(Uuid::new_v4()),
    );
    let (status, body, _) = send(
        &router,
        "POST",
        "/api/v1/ext/demo/no-such-route",
        Some(&elevated),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert!(
        body.contains("ELEVATED READ-ONLY"),
        "not the recorder's refusal: {body}"
    );
    assert!(
        !body.contains("extension fallback"),
        "elevated write reached the extension's fallback past the recorder: {body}"
    );
}

/// `create_router_with_extensions`'s own documented panic ("# Panics when two
/// extensions share a name"), exercised through the public entry point rather
/// than `extensions::assert_unique_names` directly.
///
/// `#[sqlx::test]` provisions a real, migrated database per test and its
/// macro-generated wrapper is itself async; `#[should_panic]` does not compose
/// with that. Nothing here needs a live database at all — `create_router_with_
/// extensions` panics before it would ever touch one — so this is a plain
/// `#[test]`. `PgPool::connect_lazy` only parses the DSN and defers any real
/// connection, but constructing the pool still asserts a Tokio context exists,
/// so a bare current-thread runtime is entered for just that call (mirrors
/// `middleware::bearer`'s and `routes::webhooks`'s own `connect_lazy`-against-
/// an-unreachable-DSN tests).
#[test]
fn create_router_with_extensions_panics_on_duplicate_names() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build a runtime to enter for connect_lazy");
    let _guard = rt.enter();
    let pool = PgPool::connect_lazy("postgres://nobody:nobody@127.0.0.1:1/nobody")
        .expect("connect_lazy only parses the DSN; it never connects");
    let state = AppState::with_db(pool, ApiConfig::default());

    let a = RouterExtension::new("demo", Router::new()).expect("valid name");
    let b = RouterExtension::new("demo", Router::new()).expect("valid name");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        create_router_with_extensions(state, vec![a, b])
    }));

    let payload = result.expect_err("two extensions named \"demo\" must panic");
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("<non-string panic payload>");
    assert!(
        message.contains("registered twice"),
        "not assert_unique_names's own refusal — axum's nest_service conflict \
         panic (should the uniqueness check ever be skipped) reads \
         differently and must not satisfy this assertion: {message}"
    );
}
