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
        epigraph_core::TenancyDecl::inherited(),
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

/// Backlog c0ab097a (2): a reused, content-addressed level-3 atom is shared
/// across workflows, and the ingest executor links a PUBLIC one into a
/// group-private plan. Its `executes` edge is then public, so a non-member
/// reads one `executes` edge of a plan whose own claims (thesis, phases,
/// steps) it reads none of. Reading that edge must not admit it: the report is
/// refused with the not-found 404 and nothing is written. Positive control: a
/// member of the owning group still records the same report.
///
/// RED before the fix: the gate admitted any visible `executes` edge, so the
/// stranger got a 200 and moved `use_count` to 1.
#[sqlx::test(migrations = "../../migrations")]
async fn a_shared_public_atom_does_not_admit_a_non_member(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let w = seed_private_workflow(&pool, "outcome-route-public-atom").await;

    let atom = viewer_fixture::seed_public_claim(
        &pool,
        w.stranger,
        &format!("a shared operation atom {}", w.workflow_id),
    )
    .await;
    sqlx::query("UPDATE claims SET properties = jsonb_build_object('level', 3) WHERE id = $1")
        .bind(atom)
        .execute(&pool)
        .await
        .expect("level 3");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES ($1, 'workflow', $2, 'claim', 'executes', \
                 jsonb_build_object('level', 3, 'plan_index', 2))",
    )
    .bind(w.workflow_id)
    .bind(atom)
    .execute(&pool)
    .await
    .expect("executes edge to the atom");
    let atom_edge: String = sqlx::query_scalar(
        "SELECT visibility::text FROM edges \
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'executes'",
    )
    .bind(w.workflow_id)
    .bind(atom)
    .fetch_one(&pool)
    .await
    .expect("atom edge read-back");
    assert_eq!(
        atom_edge, "public",
        "fixture shape: the atom's executes edge is public"
    );

    let (status, text) = post(
        &state,
        w.workflow_id,
        Some(token(w.stranger, &["claims:read", "claims:write"])),
        body(&[0, 1]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a caller that reads only a shared atom of the plan must be refused: {text}"
    );
    assert_eq!(
        written(&pool, w.workflow_id).await,
        (None, 0),
        "a refused report moves no counter and writes no row"
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

/// Backlog c0ab097a (2), as ruled: a report is refused "when the caller can
/// see no step of a workflow that has steps". Fixture: a group-private plan
/// that executes a PUBLIC thesis (level 0) or phase (level 1) through a
/// public edge. A non-member reads that thesis or phase and none of the
/// plan's steps. That must not admit it: 404 as for an
/// unknown id, and nothing written. Positive control per level: a member of
/// the owning group still records the report.
///
/// RED before the fix: the gate counted level 0, 1 and 2 edges, so the
/// stranger got a 200 and moved `use_count` to 1.
#[sqlx::test(migrations = "../../migrations")]
async fn a_visible_public_thesis_or_phase_does_not_admit_a_non_member(pool: PgPool) {
    let state = app_role_state(&pool).await;
    for (level, what) in [(0, "thesis"), (1, "phase")] {
        let w = seed_private_workflow(&pool, &format!("outcome-route-public-{what}")).await;
        let shared = viewer_fixture::seed_public_claim(
            &pool,
            w.member,
            &format!(
                "a {what} an earlier public generation wrote {}",
                w.workflow_id
            ),
        )
        .await;
        sqlx::query(
            "UPDATE claims SET properties = jsonb_build_object('level', $2::int) WHERE id = $1",
        )
        .bind(shared)
        .bind(level)
        .execute(&pool)
        .await
        .expect("set level");
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
             VALUES ($1, 'workflow', $2, 'claim', 'executes', \
                     jsonb_build_object('level', $3::int, 'plan_index', 2))",
        )
        .bind(w.workflow_id)
        .bind(shared)
        .bind(level)
        .execute(&pool)
        .await
        .expect("executes edge to the shared claim");
        let edge: String = sqlx::query_scalar(
            "SELECT visibility::text FROM edges \
             WHERE source_id = $1 AND target_id = $2 AND relationship = 'executes'",
        )
        .bind(w.workflow_id)
        .bind(shared)
        .fetch_one(&pool)
        .await
        .expect("edge read-back");
        assert_eq!(
            edge, "public",
            "fixture shape: the {what}'s executes edge is public"
        );

        let (status, text) = post(
            &state,
            w.workflow_id,
            Some(token(w.stranger, &["claims:read", "claims:write"])),
            body(&[0, 1]),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a caller that reads the {what} but no step must be refused: {text}"
        );
        assert_eq!(
            written(&pool, w.workflow_id).await,
            (None, 0),
            "a refused report moves no counter and writes no row ({what})"
        );

        let (status, text) = post(
            &state,
            w.workflow_id,
            Some(token(w.member, &["claims:write"])),
            body(&[0, 1]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{what}: {text}");
        assert_eq!(written(&pool, w.workflow_id).await, (Some(1), 2), "{what}");
    }
}

/// Backlog ca30e645 / ruling R-38, REST twin of
/// `epigraph-mcp/tests/add_step_plan_position.rs`: after `add_step(position =
/// 1)` the inserted step's `executes` edge carries no `plan_index`, and the
/// `step_follows` chain is `s0 -> inserted -> s1`. A report against
/// `step_index` 1 must attach to the inserted step, and the old slot-1 step to
/// index 2: plan order is the chain, not the ordinal.
///
/// RED before the fix: `plan_step_claim_ids` sorted the unindexed step last, so
/// index 1 was attributed to `s1` and index 2 to the inserted step.
#[sqlx::test(migrations = "../../migrations")]
async fn a_report_resolves_step_index_through_the_step_follows_chain(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let w = seed_private_workflow(&pool, "outcome-route-chain-order").await;
    let group: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(w.steps[0])
        .fetch_one(&pool)
        .await
        .expect("group");

    // What `add_step(position = 1)` writes: an unindexed level-2 `executes`
    // edge, and the chain rewired around the new step.
    let inserted = viewer_fixture::seed_group_claim(
        &pool,
        w.member,
        group,
        &format!("inserted between the two steps {}", w.workflow_id),
    )
    .await;
    sqlx::query("UPDATE claims SET properties = jsonb_build_object('level', 2) WHERE id = $1")
        .bind(inserted)
        .execute(&pool)
        .await
        .expect("level 2");
    for (source, source_type, target, relationship, props) in [
        (
            w.workflow_id,
            "workflow",
            inserted,
            "executes",
            serde_json::json!({"level": 2}),
        ),
        (
            w.steps[0],
            "claim",
            inserted,
            "step_follows",
            serde_json::json!({}),
        ),
        (
            inserted,
            "claim",
            w.steps[1],
            "step_follows",
            serde_json::json!({}),
        ),
    ] {
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
             VALUES ($1, $2, $3, 'claim', $4, $5)",
        )
        .bind(source)
        .bind(source_type)
        .bind(target)
        .bind(relationship)
        .bind(props)
        .execute(&pool)
        .await
        .expect("edge");
    }

    let (status, text) = post(
        &state,
        w.workflow_id,
        Some(token(w.member, &["claims:write"])),
        body(&[0, 1, 2]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        step_rows(&pool, w.workflow_id).await,
        vec![
            ("planned 0".to_string(), Some(w.steps[0])),
            ("planned 1".to_string(), Some(inserted)),
            ("planned 2".to_string(), Some(w.steps[1])),
        ],
        "step_index follows the step_follows chain: {text}"
    );
}
