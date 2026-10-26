//! A hierarchical outcome report resolves each `step_index` to a step claim
//! through the REPORTER's viewer, on the application role, and says so when it
//! cannot.
//!
//! # The defect this pins
//!
//! `report_workflow_outcome` (hierarchical branch) and
//! `report_hierarchical_outcome` ran the whole report on a plain, UNSTAMPED
//! transaction. With no stamp, row security on `claims` and `edges` admits only
//! public rows, so for a workflow whose steps are group-private the step lookup
//! returned nothing for EVERY caller, the group's own members included. Each
//! `behavioral_executions` row was then written with a NULL `step_claim_id`,
//! the tool answered success, and nothing was logged: the out-of-range warning
//! fired only when at least one step had resolved. MEASURED on a throwaway
//! database at the base commit, as `epigraph_app` under FORCE row security:
//! two group-private steps reported by a member of their group were both
//! recorded with a NULL `step_claim_id`.
//!
//! # What is asserted
//!
//! * A member of the owning group gets every row attributed to its step, in
//!   plan order, and no unresolved indices.
//! * A caller that reads NONE of the plan's `executes` edges is refused on
//!   both tools with the hierarchical not-found error, which is exactly what
//!   the direct tool answers for an unknown id, and nothing is written:
//!   `workflows` has no row security, so this is the only gate on its
//!   counters. It learns no step id. (`report_workflow_outcome` answers an
//!   unknown id through the flat path's own error; a known, pre-existing
//!   difference, pinned in `a_non_member_cannot_report_on_a_plan_it_cannot_read`.)
//! * A reader of the plan whose `step_index` matches no step it can read gets
//!   that row recorded with a NULL `step_claim_id`, and the response NAMES the
//!   unresolved indices with a warning; an out-of-range index and a step hidden
//!   inside a partly visible plan get the SAME signal, so the response cannot
//!   be used to tell "hidden" from "absent".
//!
//! Both pools of the server are downgraded to `epigraph_app`; viewers are
//! resolved on the superuser pool first (see `viewer_fixture::downgraded_pool`).
//! The schema is the clean, migrated one: no permissive `*_privacy` policies.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::types::{ReportWorkflowOutcomeParams, StepExecution};
use sqlx::PgPool;
use uuid::Uuid;

struct PrivateWorkflow {
    workflow_id: Uuid,
    /// The step claims, in plan order.
    steps: Vec<Uuid>,
    member: Viewer,
    stranger: Viewer,
    member_id: Uuid,
    stranger_id: Uuid,
    group: Uuid,
}

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    build_scoped_test_server(plain, scoped)
}

/// A workflow root with two group-private level-2 steps, attached by
/// `executes` edges that carry their `plan_index`. The step claims are seeded
/// so that their ids are NOT in plan order, so a reader that ignored the
/// ordinal would be caught too.
async fn seed_private_workflow(pool: &PgPool, name: &str) -> PrivateWorkflow {
    let (member, group) = fixture::seed_agent_with_group(pool, &format!("{name}-member")).await;
    let (stranger, _) = fixture::seed_agent_with_group(pool, &format!("{name}-stranger")).await;
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
        let c = fixture::seed_group_claim(
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
    // Attach in REVERSE id order so plan order differs from both id order and
    // insertion order whenever the ids happen to sort ascending.
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

    // Fixture shape: steps AND their executes edges are owned by the group, so
    // only a stamped member session can read them.
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
        member_id: member,
        stranger_id: stranger,
        group,
        member: Viewer::resolve(pool, member).await.expect("member viewer"),
        stranger: Viewer::resolve(pool, stranger)
            .await
            .expect("stranger viewer"),
    }
}

fn execution_log(indices: &[usize]) -> Vec<StepExecution> {
    indices
        .iter()
        .map(|i| StepExecution {
            step_index: *i,
            planned: format!("planned {i}"),
            actual: "done".to_string(),
            deviated: false,
            deviation_reason: None,
        })
        .collect()
}

async fn report(
    server: &EpiGraphMcpFull,
    viewer: &Viewer,
    workflow_id: Uuid,
    indices: &[usize],
) -> serde_json::Value {
    let result = epigraph_mcp::tools::workflows::report_workflow_outcome(
        server,
        viewer,
        ReportWorkflowOutcomeParams {
            workflow_id: workflow_id.to_string(),
            success: true,
            execution_log: execution_log(indices),
            outcome_details: "stamped-read probe".to_string(),
            quality: Some(0.9),
            goal_text: None,
        },
        None,
    )
    .await
    .expect("the report is recorded");
    assert_eq!(result.is_error, Some(false), "{result:?}");
    first_text(&result)
}

/// `(planned text, step_claim_id)` for every row of this workflow.
async fn rows(pool: &PgPool, workflow_id: Uuid) -> Vec<(String, Option<Uuid>)> {
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

/// A member of the owning group reports a run: every row is attributed to its
/// planned step, and nothing is reported unresolved.
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_resolves_its_groups_private_steps(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let w = seed_private_workflow(&pool, "stamped-outcome-member").await;

    let json = report(&server, &w.member, w.workflow_id, &[0, 1]).await;

    assert_eq!(
        rows(&pool, w.workflow_id).await,
        vec![
            ("planned 0".to_string(), Some(w.steps[0])),
            ("planned 1".to_string(), Some(w.steps[1])),
        ],
        "each step_index is attributed to its planned step: {json}"
    );
    assert!(unresolved(&json).is_empty(), "{json}");
    assert!(json.get("warning").is_none(), "{json}");
    assert_eq!(json["step_executions_written"], 2, "{json}");
}

/// A reader of the plan whose `step_index` matches no step it can read (here
/// an index past the end) gets that row recorded with a NULL `step_claim_id`,
/// the response names the index with a warning, and the report is logged. A
/// caller that reads none of the plan is refused instead:
/// `a_non_member_cannot_report_on_a_plan_it_cannot_read`.
#[tracing_test::traced_test]
#[sqlx::test(migrations = "../../migrations")]
async fn an_unresolvable_step_index_is_recorded_unattributed_and_disclosed(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let w = seed_private_workflow(&pool, "stamped-outcome-unresolved").await;

    let json = report(&server, &w.member, w.workflow_id, &[1, 7]).await;

    assert_eq!(
        rows(&pool, w.workflow_id).await,
        vec![
            ("planned 1".to_string(), Some(w.steps[1])),
            ("planned 7".to_string(), None),
        ],
        "only the index that matches no readable step is unattributed: {json}"
    );
    assert_eq!(unresolved(&json), vec![7], "{json}");
    let warning = json["warning"]
        .as_str()
        .unwrap_or_else(|| panic!("an unresolved row is disclosed: {json}"));
    assert!(warning.contains("step_claim_id"), "{warning}");
    assert_eq!(json["use_count"], 1, "the run itself is recorded: {json}");
    assert!(
        logs_contain("unresolved_step_indices=[7]")
            && logs_contain("recorded with a NULL step_claim_id"),
        "an unattributed report is logged at WARN"
    );
}

// ── Partial visibility within one plan ──────────────────────────────────────

/// A group-private plan as the ingest executor writes it (a level-1 phase at
/// `plan_index` 0, two level-2 steps at 1 and 2, every row owned by the
/// group) followed by a PUBLIC step whose `executes` edge carries no ordinal:
/// the shape `add_step` leaves, since it declares its step public through the
/// system agent's default declaration and writes no `plan_index`. Returns the
/// workflow, the planned steps in order, and the appended step.
struct MixedPlan {
    workflow_id: Uuid,
    planned: Vec<Uuid>,
    appended: Uuid,
    member: Viewer,
    stranger: Viewer,
}

async fn executes(pool: &PgPool, workflow_id: Uuid, claim: Uuid, plan_index: Option<i32>) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES ($1, 'workflow', $2, 'claim', 'executes', \
                 CASE WHEN $3::int IS NULL THEN jsonb_build_object('level', 2) \
                      ELSE jsonb_build_object('plan_index', $3::int) END)",
    )
    .bind(workflow_id)
    .bind(claim)
    .bind(plan_index)
    .execute(pool)
    .await
    .expect("executes edge");
}

async fn set_level(pool: &PgPool, claim: Uuid, level: i32) {
    sqlx::query(
        "UPDATE claims SET properties = jsonb_build_object('level', $2::int) WHERE id = $1",
    )
    .bind(claim)
    .bind(level)
    .execute(pool)
    .await
    .expect("level");
}

async fn seed_mixed_plan(pool: &PgPool, name: &str) -> MixedPlan {
    let (member, group) = fixture::seed_agent_with_group(pool, &format!("{name}-member")).await;
    let (stranger, _) = fixture::seed_agent_with_group(pool, &format!("{name}-stranger")).await;
    let workflow_id = Uuid::new_v4();
    epigraph_db::WorkflowRepository::insert_root(
        pool,
        workflow_id,
        name,
        0,
        "A private plan with one public step appended.",
        None,
        serde_json::json!({}),
    )
    .await
    .expect("insert workflow root");

    let phase =
        fixture::seed_group_claim(pool, member, group, &format!("{name} phase {workflow_id}"))
            .await;
    set_level(pool, phase, 1).await;
    executes(pool, workflow_id, phase, Some(0)).await;
    let mut planned = Vec::new();
    for i in 0..2 {
        let c = fixture::seed_group_claim(
            pool,
            member,
            group,
            &format!("{name} step {i} {workflow_id}"),
        )
        .await;
        set_level(pool, c, 2).await;
        executes(pool, workflow_id, c, Some(i + 1)).await;
        planned.push(c);
    }
    let appended =
        fixture::seed_public_claim(pool, stranger, &format!("{name} appended {workflow_id}")).await;
    set_level(pool, appended, 2).await;
    executes(pool, workflow_id, appended, None).await;

    // Fixture shape: the plan's rows are the group's, the appended step and
    // its edge are public.
    let shapes: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT e.target_id, e.visibility::text, c.visibility::text \
           FROM edges e JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'executes'",
    )
    .bind(workflow_id)
    .fetch_all(pool)
    .await
    .expect("tenancy read-back");
    assert_eq!(shapes.len(), 4, "{shapes:?}");
    for (target, edge_vis, claim_vis) in &shapes {
        let want = if *target == appended {
            "public"
        } else {
            "group"
        };
        assert_eq!(
            (edge_vis.as_str(), claim_vis.as_str()),
            (want, want),
            "{shapes:?}"
        );
    }

    MixedPlan {
        workflow_id,
        planned,
        appended,
        member: Viewer::resolve(pool, member).await.expect("member viewer"),
        stranger: Viewer::resolve(pool, stranger)
            .await
            .expect("stranger viewer"),
    }
}

/// A non-member reads only the appended public step. Counting what it can see
/// would make that step "step 0" and attribute the reporter's first row to it
/// with no warning; its position is unknown to the reporter, so the row is
/// unattributed and disclosed instead.
///
/// RED before the provable-prefix rule: the row for index 0 carried the
/// appended step's id and `unresolved_step_indices` was empty.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_plan_does_not_shift_a_visible_appended_step(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let w = seed_mixed_plan(&pool, "stamped-outcome-mixed-stranger").await;

    let json = report(&server, &w.stranger, w.workflow_id, &[0]).await;

    assert_eq!(
        rows(&pool, w.workflow_id).await,
        vec![("planned 0".to_string(), None)],
        "step 0 is a private step; the visible appended step must not take its index: {json}"
    );
    assert_eq!(unresolved(&json), vec![0], "{json}");
    // The disclosure is built from the indices alone: the warning for a step
    // hidden inside the plan is word for word the one an out-of-range index
    // gets, and the response names none of the private steps.
    assert_eq!(
        json["warning"].as_str(),
        epigraph_mcp::tools::workflow_hierarchical::unresolved_steps_warning(&[0]).as_deref(),
        "a hidden step and an absent one get the same warning: {json}"
    );
    let body = json.to_string();
    for hidden in &w.planned {
        assert!(
            !body.contains(&hidden.to_string()),
            "the response must not name a step the reporter cannot read: {json}"
        );
    }
}

/// A member reads the whole plan, so the appended step's position (after
/// every planned step) is provable and every index resolves, through the
/// direct `report_hierarchical_outcome` tool function this time.
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_resolves_the_appended_step_after_the_plan(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let w = seed_mixed_plan(&pool, "stamped-outcome-mixed-member").await;

    let result = epigraph_mcp::tools::workflow_hierarchical::report_hierarchical_outcome(
        &server,
        &w.member,
        epigraph_mcp::types::ReportHierarchicalOutcomeParams {
            workflow_id: w.workflow_id.to_string(),
            success: true,
            step_executions: [0usize, 1, 2]
                .iter()
                .map(|i| epigraph_mcp::types::HierarchicalStepExecution {
                    step_index: *i,
                    planned: format!("planned {i}"),
                    actual: "done".to_string(),
                    deviated: false,
                    deviation_reason: None,
                })
                .collect(),
            outcome_details: "mixed-plan probe".to_string(),
            quality: Some(0.8),
            run_label: None,
            goal_text: None,
        },
    )
    .await
    .expect("the report is recorded");
    let json = first_text(&result);

    assert_eq!(
        rows(&pool, w.workflow_id).await,
        vec![
            ("planned 0".to_string(), Some(w.planned[0])),
            ("planned 1".to_string(), Some(w.planned[1])),
            ("planned 2".to_string(), Some(w.appended)),
        ],
        "{json}"
    );
    assert!(unresolved(&json).is_empty(), "{json}");
}

/// No regression for a plan written before the `plan_index` ordinal existed:
/// every edge is unordered, the phase is visible, and the steps resolve by
/// position for any reader, as they always did.
#[sqlx::test(migrations = "../../migrations")]
async fn a_plan_without_ordinals_still_resolves_by_position(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "stamped-outcome-legacy").await;
    let (reader, _) = fixture::seed_agent_with_group(&pool, "stamped-outcome-legacy-r").await;
    let workflow_id = Uuid::new_v4();
    epigraph_db::WorkflowRepository::insert_root(
        &pool,
        workflow_id,
        "stamped-outcome-legacy",
        0,
        "A public plan with no ordinals.",
        None,
        serde_json::json!({}),
    )
    .await
    .expect("insert workflow root");
    let phase =
        fixture::seed_public_claim(&pool, author, &format!("legacy phase {workflow_id}")).await;
    set_level(&pool, phase, 1).await;
    executes(&pool, workflow_id, phase, None).await;
    let mut steps = Vec::new();
    for i in 0..2 {
        let c =
            fixture::seed_public_claim(&pool, author, &format!("legacy step {i} {workflow_id}"))
                .await;
        set_level(&pool, c, 2).await;
        executes(&pool, workflow_id, c, None).await;
        steps.push(c);
    }
    let reader = Viewer::resolve(&pool, reader).await.expect("reader viewer");

    let json = report(&server, &reader, workflow_id, &[0, 1]).await;

    assert_eq!(
        rows(&pool, workflow_id).await,
        vec![
            ("planned 0".to_string(), Some(steps[0])),
            ("planned 1".to_string(), Some(steps[1])),
        ],
        "{json}"
    );
    assert!(unresolved(&json).is_empty(), "{json}");
}

// ── Through the transports ──────────────────────────────────────────────────
//
// The tests above call the tool functions with a viewer the test resolved. The
// two below go through the served tool router, so they also pin how each
// transport DERIVES the viewer: over HTTP from the bearer token's agent (the
// `AuthContext` the middleware attaches), over stdio from the server's own
// signing agent. A wrapper that passed a fixed or default viewer (for example
// `request_viewer(self, None)` in the HTTP arm, which resolves the server's
// own agent) records a member's rows with NULL step ids and fails here.

const HTTP_SECRET: &[u8] = b"outcome-transport-test-secret-at-least-32-bytes";

/// The streamable-HTTP listener `main` builds for `--listen --jwt-secret`,
/// with both pools on the application role and the production revocation
/// store, bound to an ephemeral port. The server's own signer belongs to no
/// group.
async fn http_listener(pool: &PgPool) -> String {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::sync::Arc;
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let app = fixture::downgraded_pool(pool, "epigraph_app").await;
    let revocation = Arc::new(epigraph_mcp::auth::DbAccessTokenRevocation::new(
        app.clone(),
    ));
    let signer = Arc::new(epigraph_crypto::AgentSigner::from_bytes(&[0x5D; 32]).expect("signer"));
    let embedder = Arc::new(
        epigraph_mcp::embed::McpEmbedder::new(app.clone(), None).with_scoped_pool(scoped.clone()),
    );
    let service = StreamableHttpService::new(
        move || {
            Ok(
                EpiGraphMcpFull::new_shared(app.clone(), signer.clone(), embedder.clone(), false)
                    .with_scoped_pool(scoped.clone()),
            )
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let state = epigraph_mcp::auth::McpAuthState {
        jwt_config: Arc::new(epigraph_auth::JwtConfig::from_secret(HTTP_SECRET)),
        resource_metadata_url: None,
        revocation,
    };
    let router = axum::Router::new().nest_service("/mcp", service).layer(
        axum::middleware::from_fn_with_state(state, epigraph_mcp::auth::bearer_auth_middleware),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://{addr}/mcp")
}

/// An agent token for `agent` holding `claims:write`, the scope both outcome
/// tools require.
fn agent_token(agent: Uuid) -> String {
    epigraph_auth::JwtConfig::from_secret(HTTP_SECRET)
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:read".to_string(), "claims:write".to_string()],
            "agent",
            None,
            Some(agent),
            chrono::Duration::minutes(10),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("mint")
        .0
}

async fn http_post(
    url: &str,
    token: &str,
    session: Option<&str>,
    body: serde_json::Value,
) -> reqwest::Response {
    let mut req = reqwest::Client::new()
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .json(&body);
    if let Some(s) = session {
        req = req.header("Mcp-Session-Id", s);
    }
    req.send().await.expect("POST")
}

/// The first non-empty SSE `data:` payload of `resp`, parsed.
async fn sse_json(resp: &mut reqwest::Response) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut acc = String::new();
    loop {
        if let Some(line) = acc
            .lines()
            .find(|l| l.starts_with("data:") && l.trim_end().len() > 5)
        {
            return serde_json::from_str(line["data:".len()..].trim()).expect("JSON-RPC payload");
        }
        match tokio::time::timeout_at(deadline, resp.chunk()).await {
            Ok(Ok(Some(bytes))) => acc.push_str(&String::from_utf8_lossy(&bytes)),
            other => panic!("no SSE data before the stream ended: {other:?} after {acc:?}"),
        }
    }
}

/// `tools/call` `tool` with `arguments` over a fresh HTTP MCP session as the
/// holder of `token`; returns the whole JSON-RPC response (a `result` or an
/// `error`).
async fn http_rpc(
    url: &str,
    token: &str,
    tool: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    let mut init = http_post(
        url,
        token,
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "outcome-transport-test", "version": "0"}}
        }),
    )
    .await;
    assert_eq!(init.status().as_u16(), 200, "initialize");
    let session = init
        .headers()
        .get("Mcp-Session-Id")
        .expect("session header")
        .to_str()
        .expect("ascii")
        .to_owned();
    let _ = sse_json(&mut init).await;
    let notif = http_post(
        url,
        token,
        Some(&session),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(notif.status().as_u16(), 202, "notifications/initialized");
    let mut resp = http_post(
        url,
        token,
        Some(&session),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments}
        }),
    )
    .await;
    sse_json(&mut resp).await
}

/// [`http_rpc`], for a call that must succeed; returns the tool's JSON
/// response.
async fn http_call(
    url: &str,
    token: &str,
    tool: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    let rpc = http_rpc(url, token, tool, arguments).await;
    let result = rpc
        .get("result")
        .unwrap_or_else(|| panic!("{tool}: JSON-RPC error: {rpc}"));
    assert_eq!(result["isError"], false, "{tool}: {rpc}");
    let text = result["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{tool}: no text content: {rpc}"));
    serde_json::from_str(text).expect("tool JSON")
}

/// The arguments for a two-step report on `workflow_id`, for each tool's
/// parameter shape.
fn transport_args(tool: &str, workflow_id: Uuid) -> serde_json::Value {
    let log: Vec<serde_json::Value> = (0..2)
        .map(|i| {
            serde_json::json!({"step_index": i, "planned": format!("planned {i}"),
                               "actual": "done", "deviated": false})
        })
        .collect();
    match tool {
        "report_hierarchical_outcome" => serde_json::json!({
            "workflow_id": workflow_id.to_string(), "success": true,
            "step_executions": log, "outcome_details": "transport probe", "quality": 0.9
        }),
        "report_workflow_outcome" => serde_json::json!({
            "workflow_id": workflow_id.to_string(), "success": true,
            "execution_log": log, "outcome_details": "transport probe", "quality": 0.9
        }),
        other => panic!("no arguments for {other}"),
    }
}

async fn delete_rows(pool: &PgPool, workflow_id: Uuid) {
    sqlx::query("DELETE FROM behavioral_executions WHERE workflow_id = $1")
        .bind(workflow_id)
        .execute(pool)
        .await
        .expect("reset rows");
}

/// Over HTTP MCP, each outcome tool resolves the steps through the TOKEN's
/// agent: a member's token attributes every row; a non-member's token, which
/// reads none of the plan, is refused as for an unknown id and writes nothing.
///
/// RED at the base commit: the member's rows carried NULL step ids (the report
/// ran unstamped) and the response named no unresolved indices.
#[sqlx::test(migrations = "../../migrations")]
async fn over_http_each_outcome_tool_reads_as_the_token_agent(pool: PgPool) {
    let w = seed_private_workflow(&pool, "stamped-outcome-http").await;
    let url = http_listener(&pool).await;

    for tool in ["report_hierarchical_outcome", "report_workflow_outcome"] {
        let json = http_call(
            &url,
            &agent_token(w.member_id),
            tool,
            transport_args(tool, w.workflow_id),
        )
        .await;
        assert_eq!(
            rows(&pool, w.workflow_id).await,
            vec![
                ("planned 0".to_string(), Some(w.steps[0])),
                ("planned 1".to_string(), Some(w.steps[1])),
            ],
            "{tool}: a member's token resolves its group's steps: {json}"
        );
        assert!(unresolved(&json).is_empty(), "{tool}: {json}");
        delete_rows(&pool, w.workflow_id).await;
        let (counter_before, _) = written(&pool, w.workflow_id).await;
        assert!(
            counter_before.is_some(),
            "{tool}: the member's report moved the counter"
        );

        let rpc = http_rpc(
            &url,
            &agent_token(w.stranger_id),
            tool,
            transport_args(tool, w.workflow_id),
        )
        .await;
        let message = rpc["error"]["message"]
            .as_str()
            .unwrap_or_else(|| panic!("{tool}: a non-member's report is refused: {rpc}"));
        assert!(
            message.contains("no hierarchical workflow with id"),
            "{tool}: refused as for an unknown id: {rpc}"
        );
        assert_eq!(
            written(&pool, w.workflow_id).await,
            (counter_before, 0),
            "{tool}: a non-member's token moves no counter and writes no row: {rpc}"
        );
    }
}

/// Over stdio there is no token: the process's own signing agent is the
/// principal. Served in-process over a duplex pipe (no `AuthContext` reaches
/// the router, as on a real stdio transport), with that agent made a member
/// of the plan's group, both tools resolve the group's steps.
#[sqlx::test(migrations = "../../migrations")]
async fn over_stdio_each_outcome_tool_reads_as_the_server_agent(pool: PgPool) {
    use rmcp::ServiceExt;
    let w = seed_private_workflow(&pool, "stamped-outcome-stdio").await;

    // The server's agent, made a writer of the plan's group.
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x6E; 32]).expect("signer");
    let server_agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(server_agent)
        .bind(&signer.public_key()[..])
        .execute(&pool)
        .await
        .expect("server agent");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(w.group)
    .bind(server_agent)
    .execute(&pool)
    .await
    .expect("server agent membership");

    let url = fixture::database_url_for(&pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(app.clone(), None).with_scoped_pool(scoped.clone());
    let server = EpiGraphMcpFull::new(app, signer, embedder, false).with_scoped_pool(scoped);

    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await.expect("stdio-shaped client");

    for tool in ["report_hierarchical_outcome", "report_workflow_outcome"] {
        let mut params = rmcp::model::CallToolRequestParams::new(tool.to_string());
        params.arguments = transport_args(tool, w.workflow_id).as_object().cloned();
        let result = client
            .call_tool(params)
            .await
            .unwrap_or_else(|e| panic!("{tool}: {e}"));
        assert_eq!(result.is_error, Some(false), "{tool}: {result:?}");
        let json = first_text(&result);
        assert_eq!(
            rows(&pool, w.workflow_id).await,
            vec![
                ("planned 0".to_string(), Some(w.steps[0])),
                ("planned 1".to_string(), Some(w.steps[1])),
            ],
            "{tool}: the server agent is a member and resolves the steps: {json}"
        );
        assert!(unresolved(&json).is_empty(), "{tool}: {json}");
        delete_rows(&pool, w.workflow_id).await;
    }
    let _ = client.cancel().await;
}

// ── A reporter that can read none of the plan ───────────────────────────────

/// `(use_count, number of behavioral_executions rows)` for `workflow_id`.
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

/// Both MCP entry points, as `viewer`, on `workflow_id`: the direct
/// `report_hierarchical_outcome` tool function and `report_workflow_outcome`'s
/// hierarchical branch. Returns each call's error as `(code, message)` with
/// the workflow id replaced by `<id>`, or panics if either call succeeded.
async fn refusals(
    server: &EpiGraphMcpFull,
    viewer: &Viewer,
    workflow_id: Uuid,
) -> Vec<(i32, String)> {
    let direct = epigraph_mcp::tools::workflow_hierarchical::report_hierarchical_outcome(
        server,
        viewer,
        epigraph_mcp::types::ReportHierarchicalOutcomeParams {
            workflow_id: workflow_id.to_string(),
            success: true,
            step_executions: [0usize, 1]
                .iter()
                .map(|i| epigraph_mcp::types::HierarchicalStepExecution {
                    step_index: *i,
                    planned: format!("planned {i}"),
                    actual: "done".to_string(),
                    deviated: false,
                    deviation_reason: None,
                })
                .collect(),
            outcome_details: "unreadable-plan probe".to_string(),
            quality: Some(0.9),
            run_label: None,
            goal_text: None,
        },
    )
    .await;
    let delegated = epigraph_mcp::tools::workflows::report_workflow_outcome(
        server,
        viewer,
        ReportWorkflowOutcomeParams {
            workflow_id: workflow_id.to_string(),
            success: true,
            execution_log: execution_log(&[0, 1]),
            outcome_details: "unreadable-plan probe".to_string(),
            quality: Some(0.9),
            goal_text: None,
        },
        None,
    )
    .await;
    [
        ("report_hierarchical_outcome", direct),
        ("report_workflow_outcome", delegated),
    ]
    .into_iter()
    .map(|(tool, r)| match r {
        Ok(ok) => panic!("{tool}: a report on {workflow_id} was accepted: {ok:?}"),
        Err(e) => (
            e.code.0,
            e.message.replace(&workflow_id.to_string(), "<id>"),
        ),
    })
    .collect()
}

/// A caller that can read none of a workflow's `executes` edges is refused on
/// both MCP entry points with exactly the error an unknown id gets, and
/// nothing is written: `workflows` has no row security, so without this
/// refusal any writer could move a group-private workflow's counters. A
/// member's report on the same plan is recorded (positive control).
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_cannot_report_on_a_plan_it_cannot_read(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let w = seed_private_workflow(&pool, "stamped-outcome-unreadable").await;

    let refused = refusals(&server, &w.stranger, w.workflow_id).await;
    assert_eq!(
        written(&pool, w.workflow_id).await,
        (None, 0),
        "a refused report moves no counter and writes no row"
    );
    // The direct tool answers an unreadable workflow exactly as an unknown id.
    // `report_workflow_outcome` does NOT: its routing probe sends an unknown
    // id to the legacy flat-claim path and that path's own error, while an
    // existing `workflows` row takes the hierarchical branch and gets the
    // hierarchical not-found error. That difference predates this gate and is
    // a known limitation: the row's existence is not secret (`workflows` has
    // no row security), but the delegated tool does tell "exists" from
    // "absent". Pinned below so that changing it is a deliberate decision.
    let unknown = refusals(&server, &w.stranger, Uuid::new_v4()).await;
    assert_eq!(
        refused[0], unknown[0],
        "direct tool: an unreadable workflow and a missing one get the same error"
    );
    assert_eq!(
        refused[1], refused[0],
        "the delegated tool refuses an unreadable hierarchical workflow as the direct tool does"
    );
    assert_eq!(
        unknown[1],
        (
            rmcp::model::ErrorCode::INVALID_PARAMS.0,
            "workflow <id> not found in `workflows` or `claims` tables".to_string()
        ),
        "the delegated tool's unknown-id answer (flat path; differs from refused[1])"
    );
    for (_, message) in &refused {
        for step in &w.steps {
            assert!(
                !message.contains(&step.to_string()),
                "the refusal must not name a step: {message}"
            );
        }
    }

    let json = report(&server, &w.member, w.workflow_id, &[0, 1]).await;
    assert!(unresolved(&json).is_empty(), "{json}");
    assert_eq!(written(&pool, w.workflow_id).await, (Some(1), 2));
}

/// A `workflows` row with NO `executes` edge (a legacy claim-less plan, or one
/// whose every edge was retracted) is refused like an unknown id for EVERY
/// reporter, here a group member with write access to nothing in particular,
/// and nothing is written. This is a deliberate consequence of the gate: there
/// is no plan row through which any caller could be shown to read it. The
/// stricter alternative (fall back to workflow authority when a plan has no
/// edges) is an operator decision, not taken here.
#[sqlx::test(migrations = "../../migrations")]
async fn a_root_with_no_executes_edge_is_refused_like_an_unknown_id(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "stamped-outcome-edgeless").await;
    let viewer = Viewer::resolve(&pool, agent).await.expect("viewer");
    let workflow_id = Uuid::new_v4();
    epigraph_db::WorkflowRepository::insert_root(
        &pool,
        workflow_id,
        "stamped-outcome-edgeless",
        0,
        "A workflow root with no plan claims.",
        None,
        serde_json::json!({}),
    )
    .await
    .expect("insert workflow root");

    let refused = refusals(&server, &viewer, workflow_id).await;
    let unknown = refusals(&server, &viewer, Uuid::new_v4()).await;
    assert_eq!(refused[0], unknown[0], "refused as for an unknown id");
    assert_eq!(refused[1], refused[0], "both tools refuse alike");
    assert_eq!(
        written(&pool, workflow_id).await,
        (None, 0),
        "a refused report moves no counter and writes no row"
    );
}

/// Backlog c0ab097a (2), MCP twin of the REST route's
/// `a_shared_public_atom_does_not_admit_a_non_member`: a public level-3 atom
/// reused by a group-private plan gives a non-member one visible `executes`
/// edge. Both MCP entry points must still refuse it as for an unknown id, and
/// nothing is written; a member's report is recorded (positive control).
///
/// RED before the fix: `refusals` panicked, the stranger's report was accepted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_shared_public_atom_does_not_admit_a_non_member(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let w = seed_private_workflow(&pool, "stamped-outcome-public-atom").await;

    let atom = fixture::seed_public_claim(
        &pool,
        w.stranger_id,
        &format!("a shared operation atom {}", w.workflow_id),
    )
    .await;
    set_level(&pool, atom, 3).await;
    executes(&pool, w.workflow_id, atom, Some(2)).await;
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

    let refused = refusals(&server, &w.stranger, w.workflow_id).await;
    let unknown = refusals(&server, &w.stranger, Uuid::new_v4()).await;
    assert_eq!(refused[0], unknown[0], "refused as for an unknown id");
    assert_eq!(refused[1], refused[0], "both tools refuse alike");
    assert_eq!(
        written(&pool, w.workflow_id).await,
        (None, 0),
        "a refused report moves no counter and writes no row"
    );

    let json = report(&server, &w.member, w.workflow_id, &[0, 1]).await;
    assert!(unresolved(&json).is_empty(), "{json}");
    assert_eq!(written(&pool, w.workflow_id).await, (Some(1), 2));
}
