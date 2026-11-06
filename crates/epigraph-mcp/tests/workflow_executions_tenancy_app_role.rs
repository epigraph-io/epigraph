//! `get_workflow_executions` and `evaluate_workflow_promotion` read a
//! workflow's behavioral executions as the CALLER, on a production-shaped
//! server.
//!
//! # The defect this pins
//!
//! `behavioral_executions` has no visibility columns and no row security, and
//! `epigraph_app` keeps `SELECT` on it (migration 118). `get_workflow_executions`
//! took no viewer and read it on the raw pool, so ANY caller got `goal_text`
//! and `step_beliefs` for ANY workflow UUID, a workflow private to a group the
//! caller is not in included. Its exemption in `tool_viewer_coverage.rs` said
//! `workflows` was outside `tier_a`, which stopped being true at migration 183.
//!
//! `evaluate_workflow_promotion` had a viewer but spent it on one read, on the
//! raw pool: row security there admits public edges only, so a group's own
//! private variant looked like a lineage root to its members (verdict `None`),
//! and `success_stats` counted any workflow's runs for any caller, so a public
//! `variant_of` edge to a private parent disclosed that parent's success rate.
//!
//! # Why the server is built from ONE pool
//!
//! Production runs `server.pool == scoped.inner()`: both are the restricted
//! application role. The default harness passes an independent SUPERUSER pool
//! as `server.pool`, and a raw-pool read on a superuser sees every row, so the
//! bug is invisible there in one direction and the member-side bug in the
//! other. Here the server is built ONLY from a `ScopedPool` connected as
//! `epigraph_app`; seeding and `Viewer::resolve` run on the separate superuser
//! harness pool (see `viewer_fixture::downgraded_pool` for why resolve must not
//! run on a downgraded pool).
//!
//! # What is asserted
//!
//! * A non-member gets no executions for another group's private workflow,
//!   flat (a workflow claim) or hierarchical (a `workflows` row), and the
//!   answer is the one an unknown id gets. The secret goal text never appears.
//! * A member gets its own group's runs (positive control), and a stranger
//!   still gets a PUBLIC workflow's runs (the filter is not "blank everything").
//! * Promotion: a member's own private variant resolves its private parent and
//!   both sides' counts; a stranger sees neither. A stranger following a public
//!   `variant_of` edge to a private parent gets `(0, 0)` for the parent.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{
    BehavioralExecutionRepository, BehavioralExecutionRow, ScopedPool, SessionGucMode,
    WorkflowRepository,
};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::types::{EvaluateWorkflowPromotionParams, GetWorkflowExecutionsParams};
use rmcp::model::ContentBlock;
use sqlx::PgPool;
use uuid::Uuid;

const SECRET: &str = "wfx-tenancy secret goal text";

/// The server exactly as production builds it: its plain pool IS the scoped
/// pool's inner pool, and both are `epigraph_app`.
async fn production_shaped_server(pool: &PgPool) -> EpiGraphMcpFull {
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
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(scoped.inner())
        .await
        .expect("current_user");
    assert_eq!(role, "epigraph_app", "the server pool must be the app role");
    build_scoped_test_server(scoped.inner().clone(), scoped)
}

fn result_json(out: rmcp::model::CallToolResult) -> (serde_json::Value, String) {
    let first = out.content.first().cloned().expect("first content");
    match first {
        ContentBlock::Text(t) => (
            serde_json::from_str(&t.text).expect("result is JSON"),
            t.text.clone(),
        ),
        other => panic!("expected text content, got {other:?}"),
    }
}

async fn seed_runs(pool: &PgPool, workflow_id: Uuid, successes: usize, failures: usize) {
    let base = chrono::Utc::now();
    for (i, success) in std::iter::repeat(true)
        .take(successes)
        .chain(std::iter::repeat(false).take(failures))
        .enumerate()
    {
        BehavioralExecutionRepository::create(
            pool,
            BehavioralExecutionRow {
                id: Uuid::new_v4(),
                workflow_id,
                goal_text: SECRET.to_string(),
                success,
                step_beliefs: serde_json::json!({"deviation_reason": SECRET}),
                tool_pattern: vec!["bash".into()],
                quality: Some(0.5),
                deviation_count: 0,
                total_steps: 1,
                created_at: base + chrono::Duration::seconds(i as i64),
                step_claim_id: None,
                run_label: None,
            },
            None,
        )
        .await
        .expect("seed behavioral execution");
    }
}

/// A `variant_of` edge `variant -> parent`, its tenancy as the 070 trigger
/// derives it from the endpoints, or forced to `forced` when given.
async fn seed_variant_of(
    pool: &PgPool,
    variant: Uuid,
    parent: Uuid,
    forced: Option<(&str, Uuid)>,
) -> (String, Uuid) {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'variant_of')",
    )
    .bind(id)
    .bind(variant)
    .bind(parent)
    .execute(pool)
    .await
    .expect("variant_of edge");
    if let Some((visibility, owner)) = forced {
        sqlx::query(
            "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
             WHERE id = $1",
        )
        .bind(id)
        .bind(visibility)
        .bind(owner)
        .execute(pool)
        .await
        .expect("force edge tenancy");
    }
    sqlx::query_as("SELECT visibility::text, owner_group_id FROM edges WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("edge tenancy read-back")
}

async fn executions(server: &EpiGraphMcpFull, viewer: &Viewer, wf: Uuid) -> serde_json::Value {
    let (json, text) = result_json(
        epigraph_mcp::tools::workflows::get_workflow_executions(
            server,
            viewer,
            GetWorkflowExecutionsParams {
                workflow_id: wf.to_string(),
                limit: Some(100),
            },
        )
        .await
        .expect("get_workflow_executions ok"),
    );
    // Keep the raw text so a caller can check the secret never left.
    let mut json = json;
    json["__text"] = serde_json::Value::String(text);
    json
}

async fn promotion(server: &EpiGraphMcpFull, viewer: &Viewer, variant: Uuid) -> serde_json::Value {
    result_json(
        epigraph_mcp::tools::workflows::evaluate_workflow_promotion(
            server,
            viewer,
            EvaluateWorkflowPromotionParams {
                workflow_id: variant.to_string(),
                window: Some(50),
            },
        )
        .await
        .expect("evaluate_workflow_promotion ok"),
    )
    .0
}

fn assert_nothing(json: &serde_json::Value, what: &str) {
    assert_eq!(json["returned"], 0, "{what}: {json}");
    assert_eq!(
        json["executions"].as_array().map(Vec::len),
        Some(0),
        "{what}: {json}"
    );
    assert_eq!(json["window_success_rate"], 0.0, "{what}: {json}");
    assert!(
        !json["__text"].as_str().unwrap_or_default().contains(SECRET),
        "{what}: the private goal text left the database: {json}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_gets_no_executions_of_another_groups_workflow(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "wfx-member").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "wfx-stranger").await;

    // A flat workflow claim private to `group`.
    let flat = fixture::seed_group_claim(
        &pool,
        member,
        group,
        &format!("wfx private flat workflow {}", Uuid::new_v4()),
    )
    .await;
    // A hierarchical `workflows` row declared into `group` (migration 183).
    let hier = Uuid::new_v4();
    WorkflowRepository::insert_root(
        &pool,
        hier,
        &format!("wfx-private-{hier}"),
        0,
        "a plan only one group reads",
        None,
        serde_json::json!({}),
        epigraph_core::TenancyDecl::group(group),
    )
    .await
    .expect("insert private workflows row");
    // A PUBLIC flat workflow, the stranger-side positive control.
    let public = fixture::seed_public_claim(
        &pool,
        member,
        &format!("wfx public flat workflow {}", Uuid::new_v4()),
    )
    .await;

    seed_runs(&pool, flat, 1, 1).await;
    seed_runs(&pool, hier, 1, 0).await;
    seed_runs(&pool, public, 1, 0).await;

    // Fixture shape: both private parents really are group-private, and the
    // runs table really is readable to an unstamped app-role session, so the
    // tool's own filter is the only thing between a stranger and the rows.
    let (flat_vis, flat_owner): (String, Uuid) =
        sqlx::query_as("SELECT visibility::text, owner_group_id FROM claims WHERE id = $1")
            .bind(flat)
            .fetch_one(&pool)
            .await
            .expect("flat tenancy");
    assert_eq!((flat_vis.as_str(), flat_owner), ("group", group));
    let (hier_vis, hier_owner): (String, Uuid) =
        sqlx::query_as("SELECT visibility::text, owner_group_id FROM workflows WHERE id = $1")
            .bind(hier)
            .fetch_one(&pool)
            .await
            .expect("hierarchical tenancy");
    assert_eq!((hier_vis.as_str(), hier_owner), ("group", group));
    let unstamped = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let raw: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM behavioral_executions WHERE workflow_id = ANY($1)",
    )
    .bind(vec![flat, hier])
    .fetch_one(&unstamped)
    .await
    .expect("unstamped app-role read of behavioral_executions");
    assert_eq!(
        raw, 3,
        "behavioral_executions has no row security: an unstamped app-role \
         session reads every run, so only the tool's filter can withhold them"
    );

    // Resolve on the SUPERUSER pool, then build the app-role server.
    let member_v = Viewer::resolve(&pool, member).await.expect("member viewer");
    let stranger_v = Viewer::resolve(&pool, stranger)
        .await
        .expect("stranger viewer");
    let server = production_shaped_server(&pool).await;

    // The stranger: nothing, for either store, and the same answer an unknown
    // id gets.
    let unknown = executions(&server, &stranger_v, Uuid::new_v4()).await;
    assert_nothing(&unknown, "unknown id");
    assert_nothing(
        &executions(&server, &stranger_v, flat).await,
        "stranger, private flat workflow",
    );
    assert_nothing(
        &executions(&server, &stranger_v, hier).await,
        "stranger, private hierarchical workflow",
    );

    // Positive control, stranger side: a public workflow's runs still read.
    let pub_json = executions(&server, &stranger_v, public).await;
    assert_eq!(pub_json["returned"], 1, "public workflow: {pub_json}");

    // Positive control, member side: the owning group reads its own runs.
    let flat_json = executions(&server, &member_v, flat).await;
    assert_eq!(flat_json["returned"], 2, "member, flat: {flat_json}");
    assert_eq!(flat_json["executions"][0]["goal_text"], SECRET);
    assert!(flat_json["executions"][0]["step_beliefs"].is_object());
    let hier_json = executions(&server, &member_v, hier).await;
    assert_eq!(
        hier_json["returned"], 1,
        "member, hierarchical: {hier_json}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn promotion_reads_lineage_and_counts_as_the_caller(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "wfp-member").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "wfp-stranger").await;
    let world = fixture::world_group(&pool).await;

    // A private lineage: variant -> parent, both private to `group`; the edge
    // takes the endpoints' group tenancy from the 070 trigger.
    let parent = fixture::seed_group_claim(
        &pool,
        member,
        group,
        &format!("wfp private parent {}", Uuid::new_v4()),
    )
    .await;
    let variant = fixture::seed_group_claim(
        &pool,
        member,
        group,
        &format!("wfp private variant {}", Uuid::new_v4()),
    )
    .await;
    let edge = seed_variant_of(&pool, variant, parent, None).await;
    assert_eq!(edge, ("group".to_string(), group), "fixture: private edge");

    // A PUBLIC variant whose public `variant_of` edge points at the private
    // parent: the edge is readable to anyone, the parent's runs are not.
    let public_variant = fixture::seed_public_claim(
        &pool,
        member,
        &format!("wfp public variant {}", Uuid::new_v4()),
    )
    .await;
    let pub_edge = seed_variant_of(&pool, public_variant, parent, Some(("public", world))).await;
    assert_eq!(
        pub_edge,
        ("public".to_string(), world),
        "fixture: public edge"
    );

    // Parent 5/10; both variants 12/12.
    seed_runs(&pool, parent, 5, 5).await;
    seed_runs(&pool, variant, 12, 0).await;
    seed_runs(&pool, public_variant, 12, 0).await;

    let member_v = Viewer::resolve(&pool, member).await.expect("member viewer");
    let stranger_v = Viewer::resolve(&pool, stranger)
        .await
        .expect("stranger viewer");
    let server = production_shaped_server(&pool).await;

    // Member: its own private variant has a parent, and both sides count.
    let m = promotion(&server, &member_v, variant).await;
    assert_eq!(m["parent_id"], parent.to_string(), "member: {m}");
    assert_eq!(m["variant"]["total"], 12, "member: {m}");
    assert_eq!(m["parent"]["total"], 10, "member: {m}");
    assert_eq!(m["parent"]["successes"], 5, "member: {m}");
    assert_eq!(m["promotable"], true, "member: {m}");

    // Stranger: the private lineage does not exist for it.
    let s = promotion(&server, &stranger_v, variant).await;
    assert!(s["parent_id"].is_null(), "stranger, private variant: {s}");
    assert_eq!(s["promotable"], false, "stranger, private variant: {s}");
    assert!(s.get("variant").is_none(), "stranger, private variant: {s}");
    assert!(s.get("parent").is_none(), "stranger, private variant: {s}");

    // Stranger following a PUBLIC edge to the private parent: the edge is its
    // to read, the parent's success record is not.
    let p = promotion(&server, &stranger_v, public_variant).await;
    assert_eq!(p["parent_id"], parent.to_string(), "public edge: {p}");
    assert_eq!(p["variant"]["total"], 12, "public variant's own runs: {p}");
    assert_eq!(
        (
            p["parent"]["successes"].clone(),
            p["parent"]["total"].clone()
        ),
        (serde_json::json!(0), serde_json::json!(0)),
        "a private parent's runs counted for a stranger: {p}"
    );

    // Member through the same public edge: the parent's runs count.
    let mp = promotion(&server, &member_v, public_variant).await;
    assert_eq!(mp["parent"]["total"], 10, "member, public edge: {mp}");
}
