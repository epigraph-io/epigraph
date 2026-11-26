#![cfg(feature = "db")]
//! `GET /api/v1/tasks?workflow_id=..` honours `limit` (backlog 716288f9).
//!
//! The state and pending listings were already capped; the `workflow_id`
//! branch ignored `limit` and returned every task of the workflow, and with
//! `state` also given it filtered in memory after the fetch. These tests drive
//! the handler over HTTP so they compile against the old source as well.
//!
//! Without `limit` a workflow listing still returns every task (no default
//! cap; one would silently truncate what callers get today), which the
//! `> MAX_PAGE_LIMIT` seed below pins.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Extension, Router};
use chrono::{Duration, Utc};
use epigraph_api::middleware::bearer::AuthContext;
use epigraph_api::routes::tasks;
use epigraph_api::state::{ApiConfig, AppState};
use tower::ServiceExt;
use uuid::Uuid;

fn reader() -> AuthContext {
    let principal = Uuid::new_v4();
    AuthContext {
        client_id: principal,
        agent_id: Some(principal),
        owner_id: Some(principal),
        client_type: epigraph_api::middleware::ClientType::Service,
        scopes: vec!["tasks:read".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

fn router(pool: sqlx::PgPool) -> Router {
    Router::new()
        .route("/tasks", get(tasks::list_tasks))
        .layer(Extension(reader()))
        .with_state(AppState::with_db(pool, ApiConfig::default()))
}

/// A workflow execution (and the agent that created it) for tasks to belong
/// to; `tasks.workflow_id` references `workflow_executions(id)`.
async fn workflow(pool: &sqlx::PgPool) -> Uuid {
    sqlx::query_scalar(
        r#"
        WITH a AS (
            INSERT INTO agents (public_key)
            VALUES (decode(md5(random()::text) || md5(random()::text), 'hex'))
            RETURNING id
        )
        INSERT INTO workflow_executions (name, created_by)
        SELECT 'test workflow', id FROM a
        RETURNING id
        "#,
    )
    .fetch_one(pool)
    .await
    .expect("seed a workflow execution")
}

/// Insert one task of `workflow_id` in `state`, `offset_secs` after a fixed
/// base time, and return its id.
async fn seed(pool: &sqlx::PgPool, workflow_id: Uuid, state: &str, offset_secs: i64) -> Uuid {
    let id = Uuid::new_v4();
    let at = Utc::now() - Duration::hours(1) + Duration::seconds(offset_secs);
    sqlx::query(
        "INSERT INTO tasks (id, description, task_type, state, workflow_id, created_at, updated_at) \
         VALUES ($1, 'seeded', 'test', $2, $3, $4, $4)",
    )
    .bind(id)
    .bind(state)
    .bind(workflow_id)
    .bind(at)
    .execute(pool)
    .await
    .expect("seed a task");
    id
}

/// The task ids of a `GET /tasks?<query>` answer, in response order.
async fn list(pool: &sqlx::PgPool, query: &str) -> Vec<Uuid> {
    let response = router(pool.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/tasks?{query}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "GET /tasks?{query}");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    rows.iter()
        .map(|r| r["id"].as_str().unwrap().parse().unwrap())
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_listing_honours_limit(pool: sqlx::PgPool) {
    let wf = workflow(&pool).await;
    let mut ids = Vec::new();
    for i in 0..5 {
        ids.push(seed(&pool, wf, "created", i).await);
    }
    let other = workflow(&pool).await;
    seed(&pool, other, "created", -10).await;

    assert_eq!(
        list(&pool, &format!("workflow_id={wf}&limit=2")).await,
        ids[..2]
    );
    // Clamped like the other listings: 0 and negatives become 1.
    assert_eq!(
        list(&pool, &format!("workflow_id={wf}&limit=0")).await,
        ids[..1]
    );
    assert_eq!(
        list(&pool, &format!("workflow_id={wf}&limit=-3")).await,
        ids[..1]
    );
    assert_eq!(list(&pool, &format!("workflow_id={wf}")).await, ids);
}

/// With `state` and `limit` both given, the state filter runs before the
/// cap: the oldest tasks are `created`, so a cap applied first and filtered
/// afterwards would return no `completed` task.
#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_and_state_listing_caps_after_filtering(pool: sqlx::PgPool) {
    let wf = workflow(&pool).await;
    seed(&pool, wf, "created", 0).await;
    seed(&pool, wf, "created", 1).await;
    let c1 = seed(&pool, wf, "completed", 2).await;
    let c2 = seed(&pool, wf, "completed", 3).await;
    let c3 = seed(&pool, wf, "completed", 4).await;

    assert_eq!(
        list(&pool, &format!("workflow_id={wf}&state=completed&limit=2")).await,
        vec![c1, c2]
    );
    assert_eq!(
        list(&pool, &format!("workflow_id={wf}&state=completed")).await,
        vec![c1, c2, c3]
    );
}

/// Without `limit` a workflow listing is not capped at the default page
/// size or at `MAX_PAGE_LIMIT`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_listing_without_limit_is_not_truncated(pool: sqlx::PgPool) {
    let wf = workflow(&pool).await;
    let n = epigraph_api::routes::claims::MAX_PAGE_LIMIT + 20;
    sqlx::query(
        "INSERT INTO tasks (description, task_type, workflow_id) \
         SELECT 'seeded', 'test', $1 FROM generate_series(1, $2::int)",
    )
    .bind(wf)
    .bind(n as i32)
    .execute(&pool)
    .await
    .expect("seed many tasks");

    assert_eq!(
        list(&pool, &format!("workflow_id={wf}")).await.len() as i64,
        n
    );
}
