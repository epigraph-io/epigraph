#![cfg(feature = "db")]
//! A read handler refuses a request that carries no `AuthContext`
//! (backlog 3b560cfe, read half).
//!
//! Sibling of `mutating_handlers_refuse_without_auth_context.rs`. These six
//! handlers checked their `*:read` scope only inside
//! `if let Some(..) = auth_ctx { .. }`, so a request with no `AuthContext`
//! skipped the check. All six are registered on the `protected` router in
//! `routes/mod.rs`, behind `bearer_auth_middleware`, so this was never
//! reachable through `create_router`; the handler's own authorization still
//! depended on wiring that is not visible at the handler. Each is mounted here
//! on a bare router with NO bearer layer.
//!
//! The state's pool points at a port nothing listens on, so a handler that
//! gets past its check answers with some status other than 401 (the database
//! is unreachable) and nothing is read anywhere.
//!
//! `get_boundary_claims`, `get_split_candidates` and `get_distant_claims` also
//! take `ViewerExtractor`, which already refuses a request with no
//! `AuthContext`; they answer 401 before and after this change, and their
//! conversion only removes the dead conditional. `list_agent_keys`, `get_task`
//! and `list_tasks` take no such extractor and are the arms that change.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use epigraph_api::routes::{agent_keys, crud, tasks};
use epigraph_api::state::{ApiConfig, AppState};
use tower::ServiceExt;
use uuid::Uuid;

fn bare_router() -> Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool construction does not connect");
    let state = AppState::with_db(pool, ApiConfig::default());
    Router::new()
        .route("/agents/:id/keys", get(agent_keys::list_agent_keys))
        .route("/tasks", get(tasks::list_tasks))
        .route("/tasks/:id", get(tasks::get_task))
        .route("/boundary-claims", get(crud::get_boundary_claims))
        .route("/split-candidates", get(crud::get_split_candidates))
        .route("/distant-claims", get(crud::get_distant_claims))
        .with_state(state)
}

#[tokio::test]
async fn a_read_handler_without_an_auth_context_is_401() {
    let id = Uuid::new_v4();
    let uris = [
        format!("/agents/{id}/keys"),
        "/tasks".to_string(),
        format!("/tasks/{id}"),
        "/boundary-claims".to_string(),
        "/split-candidates".to_string(),
        "/distant-claims".to_string(),
    ];

    let app = bare_router();
    let mut wrong = Vec::new();
    for uri in uris {
        let request = Request::builder()
            .method("GET")
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        let status = app.clone().oneshot(request).await.unwrap().status();
        if status != StatusCode::UNAUTHORIZED {
            wrong.push(format!("GET {uri} -> {status}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "a read handler ran without an AuthContext instead of answering 401:\n{}",
        wrong.join("\n")
    );
}
