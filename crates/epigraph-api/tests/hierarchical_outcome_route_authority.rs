#![cfg(feature = "db")]
//! `POST /api/v1/workflows/hierarchical/:id/outcome` on the APPLICATION ROLE:
//! the caller must hold `claims:write`, and each `step_index` is resolved to a
//! step claim through the CALLER's viewer, with an explicit signal when it
//! cannot be.
//!
//! # The defects this pins
//!
//! 1. **No scope.** The handler took no `AuthContext` and called no
//!    `check_scopes`, so any authenticated bearer, a read-only client included,
//!    could move a workflow's `use_count` / `success_count` and append
//!    `behavioral_executions` rows. The MCP twin requires `claims:write`
//!    (`scope_map.rs`); this route now does too, and refuses a request with no
//!    `AuthContext` rather than skipping the check.
//! 2. **Unstamped step lookup.** The report ran on a plain transaction over
//!    `state.db_pool`. With no stamp, row security admits only public rows, so
//!    a group's own member reporting on a workflow whose steps are
//!    group-private got every row written with a NULL `step_claim_id`, a 200,
//!    and no log line. MEASURED on a throwaway database at the base commit.
//! 3. **No visibility gate on the counters.** `workflows` has no row security,
//!    so a `claims:write` holder that reads none of the plan still moved its
//!    counters and appended rows. Such a caller is now answered with the
//!    missing-id 404 and nothing is written.
//!
//! Both pools of the `AppState` are the application role (`epigraph_app`,
//! FORCE row security, no BYPASSRLS); the fixture is seeded on the superuser
//! pool. The schema is the clean, migrated one: no permissive `*_privacy`
//! policies.

mod viewer_fixture;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use epigraph_api::middleware::bearer::AuthContext;
use epigraph_api::middleware::ClientType;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group, seed_group_claim};

const ROUTE: &str = "/api/v1/workflows/hierarchical/:id/outcome";

struct PrivateWorkflow {
    workflow_id: Uuid,
    /// The step claims, in plan order.
    steps: Vec<Uuid>,
    member: Uuid,
    stranger: Uuid,
}

async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
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

async fn seed_private_workflow(pool: &PgPool, name: &str) -> PrivateWorkflow {
    let (member, group) = seed_agent_with_group(pool, &format!("{name}-member")).await;
    let (stranger, _) = seed_agent_with_group(pool, &format!("{name}-stranger")).await;
    let workflow_id = Uuid::new_v4();
    epigraph_db::WorkflowRepository::insert_root(
        pool,
        workflow_id,
        name,
        0,
        "A workflow whose steps only one group can read.",
        None,
        serde_json::json!({}),
    )
    .await
    .expect("insert workflow root");

    let mut steps = Vec::new();
    for i in 0..2 {
        let c = seed_group_claim(
            pool,
            member,
            group,
            &format!("{name} private step {i} {workflow_id}"),
        )
        .await;
        sqlx::query("UPDATE claims SET properties = jsonb_build_object('level', 2) WHERE id = $1")
            .bind(c)
            .execute(pool)
            .await
            .expect("level 2");
        steps.push(c);
    }
    let mut by_id = steps.clone();
    by_id.sort();
    if by_id == steps {
        steps.reverse();
    }
    for (i, c) in steps.iter().enumerate() {
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
             VALUES ($1, 'workflow', $2, 'claim', 'executes', jsonb_build_object('plan_index', $3::int))",
        )
        .bind(workflow_id)
        .bind(c)
        .bind(i as i32)
        .execute(pool)
        .await
        .expect("executes edge");
    }

    let shapes: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT visibility::text, owner_group_id FROM claims WHERE id = ANY($1) \
         UNION ALL \
         SELECT visibility::text, owner_group_id FROM edges \
          WHERE source_id = $2 AND relationship = 'executes'",
    )
    .bind(&steps)
    .bind(workflow_id)
    .fetch_all(pool)
    .await
    .expect("tenancy read-back");
    assert_eq!(shapes.len(), 4, "two step claims and two executes edges");
    for (vis, owner) in &shapes {
        assert_eq!(vis, "group", "fixture shape: {shapes:?}");
        assert_eq!(*owner, group, "fixture shape: {shapes:?}");
    }

    PrivateWorkflow {
        workflow_id,
        steps,
        member,
        stranger,
    }
}

fn token(agent: Uuid, scopes: &[&str]) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Agent,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

fn body(indices: &[usize]) -> serde_json::Value {
    let steps: Vec<serde_json::Value> = indices
        .iter()
        .map(|i| {
            serde_json::json!({
                "step_index": i,
                "planned": format!("planned {i}"),
                "actual": "done",
                "deviated": false
            })
        })
        .collect();
    serde_json::json!({
        "success": true,
        "outcome_details": "ok",
        "quality": 0.9,
        "step_executions": steps,
    })
}

async fn post(
    state: &AppState,
    workflow_id: Uuid,
    auth: Option<AuthContext>,
    payload: serde_json::Value,
) -> (StatusCode, String) {
    let app = axum::Router::new()
        .route(
            ROUTE,
            axum::routing::post(epigraph_api::routes::workflows::report_hierarchical_outcome),
        )
        .with_state(state.clone());
    let mut req = Request::builder()
        .uri(format!(
            "/api/v1/workflows/hierarchical/{workflow_id}/outcome"
        ))
        .method("POST")
        .header("content-type", "application/json");
    if let Some(auth) = auth {
        req = req.extension(auth);
    }
    let resp = app
        .oneshot(req.body(Body::from(payload.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// `(use_count, number of behavioral_executions rows)`.
async fn written(pool: &PgPool, workflow_id: Uuid) -> (Option<i64>, i64) {
    let use_count: Option<i64> =
        sqlx::query_scalar("SELECT (metadata->>'use_count')::bigint FROM workflows WHERE id = $1")
            .bind(workflow_id)
            .fetch_one(pool)
            .await
            .expect("metadata");
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM behavioral_executions WHERE workflow_id = $1")
            .bind(workflow_id)
            .fetch_one(pool)
            .await
            .expect("row count");
    (use_count, rows)
}

async fn step_rows(pool: &PgPool, workflow_id: Uuid) -> Vec<(String, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT tool_pattern[1], step_claim_id FROM behavioral_executions \
         WHERE workflow_id = $1 ORDER BY tool_pattern[1]",
    )
    .bind(workflow_id)
    .fetch_all(pool)
    .await
    .expect("rows")
}

fn unresolved(json: &serde_json::Value) -> Vec<u64> {
    json.get("unresolved_step_indices")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("the response names the unresolved indices: {json}"))
        .iter()
        .map(|v| v.as_u64().expect("an index"))
        .collect()
}

/// A token without `claims:write` is refused with 403, naming the scope, and a
/// request with no `AuthContext` at all is refused with 401. Neither moves a
/// counter or writes a row. The same body with the scope is then recorded, so
/// only the authority check stood in the way.
#[sqlx::test(migrations = "../../migrations")]
async fn the_route_requires_claims_write(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let w = seed_private_workflow(&pool, "outcome-route-scope").await;

    let (status, text) = post(
        &state,
        w.workflow_id,
        Some(token(w.member, &["claims:read", "edges:read"])),
        body(&[0, 1]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert!(
        text.contains("claims:write"),
        "the 403 names the scope: {text}"
    );
    assert_eq!(
        written(&pool, w.workflow_id).await,
        (None, 0),
        "nothing written"
    );

    let (status, text) = post(&state, w.workflow_id, None, body(&[0, 1])).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{text}");
    assert_eq!(
        written(&pool, w.workflow_id).await,
        (None, 0),
        "nothing written"
    );

    let (status, text) = post(
        &state,
        w.workflow_id,
        Some(token(w.member, &["claims:write"])),
        body(&[0, 1]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(written(&pool, w.workflow_id).await, (Some(1), 2));
}

/// A member of the owning group resolves each `step_index` to its planned
/// step, and an index it cannot resolve is recorded with a NULL
/// `step_claim_id` and disclosed. (A non-member, which reads none of the plan,
/// is refused outright: `non_member_cannot_move_a_group_private_workflows_counters`.)
#[sqlx::test(migrations = "../../migrations")]
async fn step_ids_resolve_through_the_callers_viewer(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let w = seed_private_workflow(&pool, "outcome-route-reads").await;

    let (status, text) = post(
        &state,
        w.workflow_id,
        Some(token(w.member, &["claims:write"])),
        body(&[0, 1]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let json: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert_eq!(
        step_rows(&pool, w.workflow_id).await,
        vec![
            ("planned 0".to_string(), Some(w.steps[0])),
            ("planned 1".to_string(), Some(w.steps[1])),
        ],
        "the member's rows carry its steps in plan order: {json}"
    );
    assert!(unresolved(&json).is_empty(), "{json}");
    assert!(json.get("warning").is_none(), "{json}");

    // An index past the plan: recorded unattributed, and disclosed.
    let (status, text) = post(
        &state,
        w.workflow_id,
        Some(token(w.member, &["claims:write"])),
        body(&[7]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let json: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert_eq!(unresolved(&json), vec![7], "{json}");
    assert!(
        json["warning"]
            .as_str()
            .is_some_and(|w| w.contains("step_claim_id")),
        "{json}"
    );
    assert_eq!(written(&pool, w.workflow_id).await, (Some(2), 3));
}

/// A caller holding `claims:write` that can read none of a workflow's
/// `executes` edges is answered exactly as for an id that does not exist
/// (404), and nothing is written: neither the `workflows.metadata` counters
/// nor any `behavioral_executions` row. `workflows` itself has no row
/// security, so the plan's visibility is the only thing that can say whether
/// the caller may report on it. Positive control: a member of the owning
/// group records the same report.
#[sqlx::test(migrations = "../../migrations")]
async fn non_member_cannot_move_a_group_private_workflows_counters(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let w = seed_private_workflow(&pool, "outcome-route-non-member").await;

    let (status, text) = post(
        &state,
        w.workflow_id,
        Some(token(w.stranger, &["claims:read", "claims:write"])),
        body(&[0, 1]),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{text}");
    assert_eq!(
        written(&pool, w.workflow_id).await,
        (None, 0),
        "a caller that reads none of the plan moves no counter and writes no row"
    );
    for step in &w.steps {
        assert!(
            !text.contains(&step.to_string()),
            "the refusal must not name a step: {text}"
        );
    }

    // Indistinguishable from an id that does not exist.
    let unknown = Uuid::new_v4();
    let (unknown_status, unknown_text) = post(
        &state,
        unknown,
        Some(token(w.stranger, &["claims:read", "claims:write"])),
        body(&[0, 1]),
    )
    .await;
    assert_eq!(unknown_status, StatusCode::NOT_FOUND, "{unknown_text}");
    assert_eq!(
        text.replace(&w.workflow_id.to_string(), "<id>"),
        unknown_text.replace(&unknown.to_string(), "<id>"),
        "an unreadable workflow and a missing one get the same answer"
    );

    // Positive control: the owning group's member records the run.
    let (status, text) = post(
        &state,
        w.workflow_id,
        Some(token(w.member, &["claims:write"])),
        body(&[0, 1]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(written(&pool, w.workflow_id).await, (Some(1), 2));
}
