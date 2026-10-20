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
//! * A non-member still records the run (the counters are not a read), but
//!   every row it writes has a NULL `step_claim_id`, and the response NAMES the
//!   unresolved indices with a warning. It learns no step id.
//! * An out-of-range index gets the SAME signal as an invisible step, so the
//!   response cannot be used to tell "hidden" from "absent".
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

/// A caller outside the group still records the run, but every row it writes
/// carries a NULL `step_claim_id` and the response says so, without naming any
/// step id. An out-of-range index from a member gets the same signal.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_is_told_its_rows_are_unattributed(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let w = seed_private_workflow(&pool, "stamped-outcome-stranger").await;

    let json = report(&server, &w.stranger, w.workflow_id, &[0, 1]).await;

    assert_eq!(
        rows(&pool, w.workflow_id).await,
        vec![
            ("planned 0".to_string(), None),
            ("planned 1".to_string(), None),
        ],
        "a non-member cannot attribute a row to a step it cannot read: {json}"
    );
    assert_eq!(unresolved(&json), vec![0, 1], "{json}");
    let warning = json["warning"]
        .as_str()
        .unwrap_or_else(|| panic!("an unresolved row is disclosed: {json}"));
    assert!(warning.contains("step_claim_id"), "{warning}");
    assert_eq!(json["use_count"], 1, "the run itself is recorded: {json}");
    let text = json.to_string();
    for step in &w.steps {
        assert!(
            !text.contains(&step.to_string()),
            "the response must not name a step the caller cannot read: {json}"
        );
    }

    // The same signal for an index that does not exist, from a member.
    let json = report(&server, &w.member, w.workflow_id, &[1, 7]).await;
    assert_eq!(unresolved(&json), vec![7], "{json}");
    assert_eq!(
        json["warning"]
            .as_str()
            .map(|w| w.contains("step_claim_id")),
        Some(true),
        "{json}"
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
    assert!(
        json["warning"].as_str().is_some(),
        "an unattributed row is disclosed: {json}"
    );
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
