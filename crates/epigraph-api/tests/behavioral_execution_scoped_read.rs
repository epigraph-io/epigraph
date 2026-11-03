#![cfg(feature = "db")]
//! `POST /api/v1/workflows/:id/behavioral-executions` checks that the workflow
//! exists through the CALLER's view (backlog 08061583), on the APPLICATION
//! ROLE where row security is in force.
//!
//! Before the fix the check was `SELECT id FROM claims WHERE id = $1 AND
//! 'workflow' = ANY(labels)` on the raw pool, with no viewer. On the app role
//! an unstamped session reads public rows only, so a group member's OWN
//! group-private workflow answered 404 (the functional half). On a session
//! that bypasses row security a hidden workflow answered 200 while a missing
//! one answered 404 (the existence oracle). Now a member records against its
//! group's workflow, and a non-member and a missing id get the same 404.
//!
//! No orphan permissive policy is installed: `FOR ALL USING (true)` would make
//! every claim visible and the non-member arm vacuous.

mod viewer_fixture;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group, seed_group_claim};

async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: the non-member arm is vacuous"
    );
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

/// A group-private workflow claim (the `workflow` label) owned by `group`.
async fn seed_group_workflow(pool: &PgPool, agent: Uuid, group: Uuid) -> Uuid {
    let id = seed_group_claim(
        pool,
        agent,
        group,
        &format!("a group-private workflow {}", Uuid::new_v4()),
    )
    .await;
    sqlx::query("UPDATE claims SET labels = ARRAY['workflow']::text[] WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("label the workflow");
    id
}

async fn record_as(
    pool: &PgPool,
    state: &AppState,
    caller: Uuid,
    workflow: Uuid,
    goal: &str,
) -> (StatusCode, String) {
    let viewer = Viewer::resolve(pool, caller).await.expect("viewer");
    let auth = AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(caller),
        owner_id: Some(caller),
        client_type: ClientType::Service,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    };
    let req: epigraph_api::routes::workflows::RecordBehavioralExecutionRequest =
        serde_json::from_value(serde_json::json!({
            "goal_text": goal,
            "success": true,
            "step_beliefs": {},
            "tool_pattern": ["t"],
            "quality": 0.9,
            "deviation_count": 0,
            "total_steps": 1
        }))
        .expect("request");
    let resp = epigraph_api::routes::workflows::record_behavioral_execution(
        ViewerExtractor(viewer),
        axum::extract::Path(workflow),
        State(state.clone()),
        Some(Extension(auth)),
        Json(req),
    )
    .await
    .into_response();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn rows_with_goal(pool: &PgPool, goal: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM behavioral_executions WHERE goal_text = $1")
        .bind(goal)
        .fetch_one(pool)
        .await
        .expect("count")
}

#[sqlx::test(migrations = "../../migrations")]
async fn behavioral_execution_existence_is_read_through_the_callers_view(pool: PgPool) {
    let (member, group) = seed_agent_with_group(&pool, "behav-member").await;
    let (outsider, _) = seed_agent_with_group(&pool, "behav-outsider").await;
    let workflow = seed_group_workflow(&pool, member, group).await;
    let state = app_role_state(&pool).await;

    // The member records against its own group's workflow.
    let goal = format!("member run {}", Uuid::new_v4());
    let (status, body) = record_as(&pool, &state, member, workflow, &goal).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a member records an execution of its group's workflow: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(json["workflow_id"], serde_json::json!(workflow));
    assert_eq!(rows_with_goal(&pool, &goal).await, 1, "one row written");

    // A non-member and a missing id are answered alike, and write nothing.
    let goal_hidden = format!("outsider run {}", Uuid::new_v4());
    let (status_hidden, body_hidden) =
        record_as(&pool, &state, outsider, workflow, &goal_hidden).await;
    let missing = Uuid::new_v4();
    let goal_missing = format!("missing run {}", Uuid::new_v4());
    let (status_missing, body_missing) =
        record_as(&pool, &state, outsider, missing, &goal_missing).await;
    assert_eq!(status_missing, StatusCode::NOT_FOUND, "{body_missing}");
    assert_eq!(
        status_hidden, status_missing,
        "a workflow the caller cannot read answers as a missing one: {body_hidden}"
    );
    assert_eq!(
        body_hidden.replace(&workflow.to_string(), "<id>"),
        body_missing.replace(&missing.to_string(), "<id>"),
        "the bodies differ only by the id the caller sent"
    );
    assert_eq!(rows_with_goal(&pool, &goal_hidden).await, 0);
    assert_eq!(rows_with_goal(&pool, &goal_missing).await, 0);

    // A readable claim WITHOUT the workflow label is not a workflow either.
    let plain = seed_group_claim(&pool, member, group, "a plain group claim").await;
    let goal_plain = format!("plain run {}", Uuid::new_v4());
    let (status_plain, body_plain) = record_as(&pool, &state, member, plain, &goal_plain).await;
    assert_eq!(
        body_plain.replace(&plain.to_string(), "<id>"),
        body_missing.replace(&missing.to_string(), "<id>"),
        "a non-workflow claim is the same not-found ({status_plain})"
    );
    assert_eq!(rows_with_goal(&pool, &goal_plain).await, 0);
}
