#![cfg(feature = "db")]
//! A mutating handler refuses a request that carries no `AuthContext`
//! (backlog 3b560cfe).
//!
//! These eleven handlers checked their scope (and, for the agent routes, that
//! the caller is the target agent or an admin) only inside
//! `if let Some(..) = auth_ctx { .. }`. With no `AuthContext` the block was
//! skipped and the handler went on to write. Through `create_router` that
//! cannot happen, because `bearer_auth_middleware` wraps every one of these
//! routes; the handler's own authorization still depended on wiring that is
//! not visible at the handler. Here each handler is mounted on a bare router
//! with NO bearer layer, which is the case the conditional form let through.
//!
//! The state's pool points at a port nothing listens on, so a handler that
//! gets past its check fails on the database (or on validation) with some
//! status other than 401, and nothing is written anywhere. MEASURED: on the
//! tree before this change no arm answers 401. Ten answer 500 (they reached
//! the database) and `create_evidence` answers 400 (it reached validation).
//!
//! `crud.rs::create_reasoning_trace` had the same shape and is not here: it is
//! converted on another branch (`fix/backlog-b03`).

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::routing::{delete, post, put};
use axum::Router;
use epigraph_api::routes::{agent_keys, agents, crud, papers, tasks};
use epigraph_api::state::{ApiConfig, AppState};
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

fn bare_router() -> Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool construction does not connect");
    let state = AppState::with_db(pool, ApiConfig::default());
    Router::new()
        .route("/papers", post(papers::create_paper))
        .route("/agents", post(agents::create_agent))
        .route("/agents/:id", put(agents::update_agent))
        .route(
            "/agents/:id/keys/rotate",
            post(agent_keys::rotate_agent_key),
        )
        .route(
            "/agents/:id/keys/:key_id",
            delete(agent_keys::revoke_agent_key),
        )
        .route("/tasks", post(tasks::create_task))
        .route("/tasks/:id/assign", post(tasks::assign_task))
        .route("/tasks/:id/complete", post(tasks::complete_task))
        .route("/tasks/:id/fail", post(tasks::fail_task))
        .route("/evidence", post(crud::create_evidence))
        .route("/analyses", post(crud::create_analysis))
        .with_state(state)
}

#[tokio::test]
async fn a_mutating_handler_without_an_auth_context_is_401() {
    let id = Uuid::new_v4();
    let key = "ab".repeat(32);
    let sig = "cd".repeat(64);
    let arms: Vec<(Method, String, serde_json::Value)> = vec![
        (Method::POST, "/papers".into(), json!({"doi": "10.1000/x"})),
        (Method::POST, "/agents".into(), json!({"public_key": key})),
        (
            Method::PUT,
            format!("/agents/{id}"),
            json!({"display_name": "renamed"}),
        ),
        (
            Method::POST,
            format!("/agents/{id}/keys/rotate"),
            json!({"new_public_key": key, "old_key_signature": sig, "new_key_signature": sig}),
        ),
        (
            Method::DELETE,
            format!("/agents/{id}/keys/{id}"),
            json!({"reason": "test"}),
        ),
        (
            Method::POST,
            "/tasks".into(),
            json!({"description": "d", "task_type": "t"}),
        ),
        (
            Method::POST,
            format!("/tasks/{id}/assign"),
            json!({"agent_id": id}),
        ),
        (
            Method::POST,
            format!("/tasks/{id}/complete"),
            json!({"result": {}}),
        ),
        (
            Method::POST,
            format!("/tasks/{id}/fail"),
            json!({"error": "e"}),
        ),
        (
            Method::POST,
            "/evidence".into(),
            json!({"agent_id": id, "claim_id": id, "raw_content": "r", "evidence_type": {"type": "observation"}}),
        ),
        (
            Method::POST,
            "/analyses".into(),
            json!({"analysis_type": "a", "method_description": "m", "inference_path": "p",
                   "agent_id": id, "input_evidence_ids": []}),
        ),
    ];
    assert_eq!(arms.len(), 11);

    let app = bare_router();
    let mut wrong = Vec::new();
    for (method, uri, body) in arms {
        let request = Request::builder()
            .method(method.clone())
            .uri(&uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let status = app.clone().oneshot(request).await.unwrap().status();
        if status != StatusCode::UNAUTHORIZED {
            wrong.push(format!("{method} {uri} -> {status}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "a mutating handler ran without an AuthContext instead of answering 401:\n{}",
        wrong.join("\n")
    );
}
