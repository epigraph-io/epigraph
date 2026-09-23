#![cfg(feature = "db")]
//! **Every former fail-open scope check refuses a request that carries no
//! `AuthContext`, observed over a router with no bearer layer.**
//!
//! # What this file pins that the lint cannot
//!
//! `viewer_route_table_lint.rs::fail_open_scope_check_sites_do_not_increase`
//! counts the SHAPE `if let Some(..) = auth_ctx { check_scopes(..) }` in the
//! source. It cannot see what a handler DOES when `auth_ctx` is `None`, and a
//! conversion that deleted the whole block would lower that count exactly as
//! far as one that made the check unconditional. This file asserts the
//! behaviour instead, per handler:
//!
//! * **No `AuthContext` → 401.** Before the conversion these handlers skipped
//!   authorization entirely when the extension was absent and went on to parse,
//!   validate and query. Here the pool can never connect, so a handler that
//!   falls open reaches it and answers 500 (or a 4xx from its own validation)
//!   rather than 401. That is the discriminating half.
//! * **An `AuthContext` holding no scopes → 403.** The positive control. A
//!   "conversion" that dropped `check_scopes` on the way to the `let ... else`
//!   shape would still 401 the anonymous request, and only this half notices.
//!
//! # Why the router carries no bearer layer
//!
//! In production every route here is registered on the `protected` router in
//! `routes/mod.rs::create_router`, which `bearer_auth_middleware` layers
//! unconditionally, so `auth_ctx` is always `Some` there today. That is a
//! ROUTER-level control. These handlers used to be correct only because of it;
//! the point of the conversion is that each handler now refuses on its own if
//! it is ever mounted anywhere else (a new sub-router, the allowlist router, a
//! test harness that later serves traffic). Mounting them bare is how that is
//! observed.
//!
//! # Why no database
//!
//! The pool points at a port nothing listens on and fails fast. Every assertion
//! in this file is about what happens BEFORE the handler touches storage, so a
//! reachable database would only make a fall-open look like a success.
//!
//! # The `ViewerExtractor` rows
//!
//! Some of the converted handlers also take `ViewerExtractor`, which already
//! 401s on a missing `AuthContext` before the handler body runs, so their 401
//! row is not what proves their conversion (the lint is). They are listed
//! anyway so that removing the extractor from one of them cannot silently put
//! its scope check back to being the only guard. They are skipped for the 403
//! control: with an `AuthContext` present the extractor resolves a `Viewer`
//! against the (unreachable) database before the scope check could run.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use epigraph_api::middleware::bearer::{AuthContext, ClientType};
use epigraph_api::routes;
use epigraph_api::{ApiConfig, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

/// State whose pool can never connect. See the module doc.
fn unreachable_state() -> AppState {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://nobody:nobody@127.0.0.1:1/nothing")
        .expect("a lazy pool does not connect at construction");
    AppState::with_db(pool, ApiConfig::default())
}

/// An authenticated principal that holds no scopes at all.
fn scopeless_auth() -> AuthContext {
    let id = Uuid::new_v4();
    AuthContext {
        client_id: id,
        agent_id: Some(id),
        owner_id: Some(id),
        client_type: ClientType::Service,
        scopes: vec![],
        jti: Uuid::new_v4(),
    }
}

struct Case {
    /// `file.rs::handler`, so a failure names the site.
    site: &'static str,
    method: Method,
    uri: String,
    /// A body the handler's `Json` extractor accepts, so a fall-open reaches
    /// the handler body rather than stopping at a 422.
    body: Option<Value>,
    /// The handler also takes `ViewerExtractor`. See the module doc.
    viewer: bool,
}

fn case(site: &'static str, method: Method, uri: String, body: Option<Value>) -> Case {
    Case {
        site,
        method,
        uri,
        body,
        viewer: false,
    }
}

fn viewer_case(site: &'static str, method: Method, uri: String, body: Option<Value>) -> Case {
    Case {
        site,
        method,
        uri,
        body,
        viewer: true,
    }
}

async fn status_of(router: &Router, c: &Case, auth: Option<AuthContext>) -> StatusCode {
    let mut builder = Request::builder().method(c.method.clone()).uri(&c.uri);
    let body = match &c.body {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(v).expect("serialize body"))
        }
        None => Body::empty(),
    };
    let mut req = builder.body(body).expect("build request");
    if let Some(a) = auth {
        req.extensions_mut().insert(a);
    }
    router
        .clone()
        .oneshot(req)
        .await
        .expect("router is infallible")
        .status()
}

/// Run both halves over every case and report every mismatch at once, so one
/// run names every site that still falls open rather than only the first.
async fn assert_refused(router: Router, cases: &[Case]) {
    assert!(!cases.is_empty(), "a file with no cases proves nothing");
    let mut failures = Vec::new();
    for c in cases {
        let anon = status_of(&router, c, None).await;
        if anon != StatusCode::UNAUTHORIZED {
            failures.push(format!(
                "  {} {} {}: no AuthContext -> {anon}, want 401 (the scope check \
                 is skipped when the extension is absent)",
                c.site, c.method, c.uri
            ));
        }
        if !c.viewer {
            let scopeless = status_of(&router, c, Some(scopeless_auth())).await;
            if scopeless != StatusCode::FORBIDDEN {
                failures.push(format!(
                    "  {} {} {}: AuthContext without scopes -> {scopeless}, want 403 \
                     (the scope check no longer runs)",
                    c.site, c.method, c.uri
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "\n{} site(s) do not refuse on their own:\n{}\n",
        failures.len(),
        failures.join("\n")
    );
}

#[tokio::test]
async fn tasks_rs_refuses_without_auth() {
    use routes::tasks;
    let router = Router::new()
        .route(
            "/api/v1/tasks",
            post(tasks::create_task).get(tasks::list_tasks),
        )
        .route("/api/v1/tasks/:id", get(tasks::get_task))
        .route("/api/v1/tasks/:id/assign", post(tasks::assign_task))
        .route("/api/v1/tasks/:id/complete", post(tasks::complete_task))
        .route("/api/v1/tasks/:id/fail", post(tasks::fail_task))
        .with_state(unreachable_state());
    let id = Uuid::new_v4();
    let cases = [
        case(
            "tasks.rs::create_task",
            Method::POST,
            "/api/v1/tasks".into(),
            Some(json!({"description": "d", "task_type": "t"})),
        ),
        case(
            "tasks.rs::get_task",
            Method::GET,
            format!("/api/v1/tasks/{id}"),
            None,
        ),
        case(
            "tasks.rs::list_tasks",
            Method::GET,
            "/api/v1/tasks".into(),
            None,
        ),
        case(
            "tasks.rs::assign_task",
            Method::POST,
            format!("/api/v1/tasks/{id}/assign"),
            Some(json!({"agent_id": Uuid::new_v4()})),
        ),
        case(
            "tasks.rs::complete_task",
            Method::POST,
            format!("/api/v1/tasks/{id}/complete"),
            Some(json!({"result": {}})),
        ),
        case(
            "tasks.rs::fail_task",
            Method::POST,
            format!("/api/v1/tasks/{id}/fail"),
            Some(json!({"error": "e"})),
        ),
    ];
    assert_refused(router, &cases).await;
}

#[tokio::test]
async fn agent_keys_rs_refuses_without_auth() {
    use routes::agent_keys;
    let router = Router::new()
        .route("/api/v1/agents/:id/keys", get(agent_keys::list_agent_keys))
        .route(
            "/api/v1/agents/:id/keys/rotate",
            post(agent_keys::rotate_agent_key),
        )
        .route(
            "/api/v1/agents/:id/keys/:key_id/revoke",
            post(agent_keys::revoke_agent_key),
        )
        .with_state(unreachable_state());
    let id = Uuid::new_v4();
    let cases = [
        case(
            "agent_keys.rs::list_agent_keys",
            Method::GET,
            format!("/api/v1/agents/{id}/keys"),
            None,
        ),
        case(
            "agent_keys.rs::rotate_agent_key",
            Method::POST,
            format!("/api/v1/agents/{id}/keys/rotate"),
            Some(json!({
                "new_public_key": "00".repeat(32),
                "old_key_signature": "00".repeat(64),
                "new_key_signature": "00".repeat(64),
            })),
        ),
        case(
            "agent_keys.rs::revoke_agent_key",
            Method::POST,
            format!("/api/v1/agents/{id}/keys/{}/revoke", Uuid::new_v4()),
            Some(json!({"reason": "r"})),
        ),
    ];
    assert_refused(router, &cases).await;
}

#[tokio::test]
async fn papers_rs_refuses_without_auth() {
    let router = Router::new()
        .route("/api/v1/papers", post(routes::papers::create_paper))
        .with_state(unreachable_state());
    let cases = [case(
        "papers.rs::create_paper",
        Method::POST,
        "/api/v1/papers".into(),
        Some(json!({"doi": "10.1234/example"})),
    )];
    assert_refused(router, &cases).await;
}

#[tokio::test]
async fn agents_rs_refuses_without_auth() {
    use routes::agents;
    let router = Router::new()
        .route("/api/v1/agents", post(agents::create_agent))
        .route(
            "/api/v1/agents/:id",
            axum::routing::put(agents::update_agent),
        )
        .with_state(unreachable_state());
    let cases = [
        case(
            "agents.rs::create_agent",
            Method::POST,
            "/api/v1/agents".into(),
            Some(json!({"public_key": "11".repeat(32)})),
        ),
        case(
            "agents.rs::update_agent",
            Method::PUT,
            format!("/api/v1/agents/{}", Uuid::new_v4()),
            Some(json!({"display_name": "x"})),
        ),
    ];
    assert_refused(router, &cases).await;
}

#[tokio::test]
async fn claims_rs_refuses_without_auth() {
    let router = Router::new()
        .route("/api/v1/claims", post(routes::claims::create_claim))
        .with_state(unreachable_state());
    let cases = [viewer_case(
        "claims.rs::create_claim",
        Method::POST,
        "/api/v1/claims".into(),
        Some(json!({"content": "c"})),
    )];
    assert_refused(router, &cases).await;
}
