//! `evolve_step(supersedes)` runs the Supersede admin cascade (backlog 8d3b4527).
//!
//! Before the fix the tool wrote the successor step and retired the parent but
//! moved no edge, and recorded no `claims.supersedes`, so the cascade (and its
//! deferred replay) refused the pair: on prod the live head of a workflow step
//! held only its `supersedes` edge while the decomposition parent, the children
//! and the `continues_argument` predecessor still pointed at retired versions.
//!
//! These arms drive the MCP tool end to end on the APPLICATION ROLE, ARMED
//! (migration 122/123/153's claims trigger sees the INSERT that now names
//! `supersedes`), over two hops of one lineage (prod's shape: the second hop
//! retires a row whose own `supersedes` is already set):
//!
//! * the tool reports a `cascade` that is DEFERRED (the test server has no
//!   maintenance connection), recorded with cause `supersede` and attributed
//!   to the caller;
//! * the replay, on the maintenance connection, carries `decomposes_to` (both
//!   directions) and `continues_argument` onto the live head, and leaves the
//!   workflow's `executes` and another agent's `asserts` on the frozen step;
//! * with a maintenance connection configured, the tool APPLIES the cascade in
//!   the request instead (`cascade.status` = `applied`, no deferral);
//! * the workflow's `step_follows` chain stays on the frozen steps its
//!   `executes` edges name, so `ordered_steps` keeps the step order;
//! * `revises` records no supersession and no cascade.
//!
//! Seeding, links and arming run on the harness pool (the maintenance role's
//! stand-in), as in `operator_binding_system_agent.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::evolve_step::{evolve_step, EvolveStepParams};
use sqlx::PgPool;
use uuid::Uuid;

/// An app-role stdio server whose own agent (the CALLER of every tool) is
/// pre-created and keyed by `seed`, so the test can bind it before arming.
/// It has no maintenance connection, so the cascade is DEFERRED.
async fn app_role_server(pool: &PgPool, seed: u8) -> (EpiGraphMcpFull, Uuid) {
    server_with(pool, seed, false).await
}

/// [`app_role_server`] whose ScopedPool also holds a maintenance pool (the
/// `epigraph_maintenance` role, as `replay_now` builds it), so the tool runs
/// the cascade IN THE REQUEST: the `applied` branch prod takes whenever the
/// maintenance DSN is configured.
async fn app_role_server_with_maintenance(pool: &PgPool, seed: u8) -> (EpiGraphMcpFull, Uuid) {
    server_with(pool, seed, true).await
}

async fn server_with(pool: &PgPool, seed: u8, maintenance: bool) -> (EpiGraphMcpFull, Uuid) {
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let caller: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'mcp-agent') RETURNING id",
    )
    .bind(signer.public_key().as_slice())
    .fetch_one(pool)
    .await
    .expect("the caller's agent row");
    let url = fixture::database_url_for(pool).await;
    let mut scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    if maintenance {
        scoped = scoped
            .with_maintenance_pool(fixture::downgraded_pool(pool, "epigraph_maintenance").await);
    }
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    let server = EpiGraphMcpFull::new(plain, signer, embedder, /* read_only */ false)
        .with_scoped_pool(scoped);
    (server, caller)
}

/// A human operator, the caller live-linked to it, and the database armed.
/// Returns the operator's group, which the caller writes.
async fn bind_and_arm(pool: &PgPool, caller: Uuid) -> Uuid {
    let (human, group) = fixture::seed_human_operator(pool, "evolve-cascade-human").await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, caller, human)
        .await
        .expect("live link");
    drop(conn);
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(pool)
        .await
        .expect("arm (the harness stands in for the maintenance role)");
    group
}

async fn seed_workflow(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal) VALUES ($1, $2, 'evolve cascade test')",
    )
    .bind(id)
    .bind(format!("evolve-cascade-{id}"))
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn seed_edge(
    pool: &PgPool,
    source: Uuid,
    source_type: &str,
    target: Uuid,
    relationship: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, 'claim', $5)",
    )
    .bind(id)
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {relationship} edge: {e}"));
    id
}

/// `(source_id, target_id)` of edge `id`.
async fn ends(pool: &PgPool, id: Uuid) -> (Uuid, Uuid) {
    sqlx::query_as("SELECT source_id, target_id FROM edges WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("edge")
}

fn params(parent: Uuid, edge_type: &str, content: &str) -> EvolveStepParams {
    EvolveStepParams {
        parent_id: parent.to_string(),
        canonical_name: None,
        step_index: None,
        step_lineage_id: String::new(),
        content: content.to_string(),
        edge_type: edge_type.to_string(),
        rationale: Some("cascade test".to_string()),
        level: Some(2),
    }
}

async fn evolve(server: &EpiGraphMcpFull, p: EvolveStepParams) -> serde_json::Value {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("stdio viewer");
    let r = evolve_step(server, &viewer, p, None)
        .await
        .map_err(|e| e.message.to_string())
        .expect("a bound caller evolves its step on the app role, armed");
    first_text(&r)
}

/// The deferral row a result names: `(agent_id, cause, old, new)`.
async fn deferral_of(
    pool: &PgPool,
    body: &serde_json::Value,
) -> (Option<Uuid>, String, String, String) {
    assert_eq!(body["cascade"]["status"], "deferred", "{body}");
    let id: Uuid = body["cascade"]["audit_event_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("the deferral carries its audit row id: {body}"));
    sqlx::query_as(
        "SELECT agent_id, details->>'cause', details#>>'{trigger,subject_id}', details#>>'{trigger,object_id}' \
           FROM security_events WHERE id = $1 AND event_type = 'cascade.deferred'",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("the cascade.deferred row")
}

async fn replay_now(pool: &PgPool, label: &str) -> epigraph_engine::admin_cascade::ReplayReport {
    let url = fixture::database_url_for(pool).await;
    let maintenance = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("ScopedPool")
            .with_maintenance_pool(maintenance);
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    session
        .assert_privileged()
        .await
        .expect("the replay's connection is privileged");
    let (conn, admin_viewer) = session.split();
    epigraph_engine::admin_cascade::replay_deferred(
        conn,
        admin_viewer,
        label,
        50,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("replay")
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_cascade_carries_structure_to_the_live_head_over_two_hops(
    pool: PgPool,
) {
    let (server, caller) = app_role_server(&pool, 0xC4).await;
    let group = bind_and_arm(&pool, caller).await;
    let (other_agent, _) = fixture::seed_agent_with_group(&pool, "evolve-cascade-other").await;

    let step = fixture::seed_group_claim(&pool, caller, group, "D3: measure the yield").await;
    let parent = fixture::seed_group_claim(&pool, caller, group, "the D-arm").await;
    let child = fixture::seed_group_claim(&pool, caller, group, "D3.1 prepare").await;
    let prior = fixture::seed_group_claim(&pool, caller, group, "the prior paragraph").await;
    let workflow = seed_workflow(&pool).await;

    let decomposed_from = seed_edge(&pool, parent, "claim", step, "decomposes_to").await;
    let to_child = seed_edge(&pool, step, "claim", child, "decomposes_to").await;
    let continued = seed_edge(&pool, prior, "claim", step, "continues_argument").await;
    let executes = seed_edge(&pool, workflow, "workflow", step, "executes").await;
    let asserted = seed_edge(&pool, other_agent, "agent", step, "asserts").await;

    // ── Hop 1: step -> head1 ──
    let body = evolve(&server, params(step, "supersedes", "D3 v2")).await;
    let head1 = parse_uuid_field(&body, "claim_id");
    let sup: Option<Uuid> = sqlx::query_scalar("SELECT supersedes FROM claims WHERE id = $1")
        .bind(head1)
        .fetch_one(&pool)
        .await
        .expect("head1");
    assert_eq!(sup, Some(step), "the successor records the supersession");
    let (who, cause, old, new) = deferral_of(&pool, &body).await;
    assert_eq!(cause, "supersede");
    assert_eq!(
        who,
        Some(caller),
        "the deferral is attributed to the caller"
    );
    assert_eq!(
        (old, new),
        (step.to_string(), head1.to_string()),
        "the deferral names the pair"
    );
    assert_eq!(
        ends(&pool, decomposed_from).await,
        (parent, step),
        "nothing moves before the replay"
    );

    let report = replay_now(&pool, "u047-hop1").await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    assert_eq!(ends(&pool, decomposed_from).await, (parent, head1));
    assert_eq!(ends(&pool, to_child).await, (head1, child));
    assert_eq!(ends(&pool, continued).await, (prior, head1));
    assert_eq!(
        ends(&pool, executes).await,
        (workflow, step),
        "executes stays on the frozen step"
    );
    assert_eq!(
        ends(&pool, asserted).await,
        (other_agent, step),
        "another agent's asserts stays on the content it asserted"
    );

    // ── Hop 2: head1 -> head2 (head1's own `supersedes` is already set) ──
    // An agent asserts head1's content between the hops: the carve-out must
    // also hold on a row that is itself a successor.
    let asserted_head1 = seed_edge(&pool, other_agent, "agent", head1, "asserts").await;
    let body = evolve(&server, params(head1, "supersedes", "D3 v3")).await;
    let head2 = parse_uuid_field(&body, "claim_id");
    let (_, cause, old, new) = deferral_of(&pool, &body).await;
    assert_eq!(
        (cause.as_str(), old, new),
        ("supersede", head1.to_string(), head2.to_string())
    );
    let report = replay_now(&pool, "u047-hop2").await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    assert_eq!(
        ends(&pool, decomposed_from).await,
        (parent, head2),
        "the decomposition parent reaches the live head"
    );
    assert_eq!(ends(&pool, to_child).await, (head2, child));
    assert_eq!(ends(&pool, continued).await, (prior, head2));
    assert_eq!(
        ends(&pool, asserted_head1).await,
        (other_agent, head1),
        "an agent's asserts of head1 stays on head1 when head1 is superseded"
    );
}

/// With a maintenance connection configured (prod's normal shape), the tool
/// runs the cascade IN THE REQUEST: `cascade.status` is `applied`, the edges
/// have moved before any replay, and nothing was deferred.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_applies_the_cascade_in_request_with_a_maintenance_session(
    pool: PgPool,
) {
    let (server, caller) = app_role_server_with_maintenance(&pool, 0xC6).await;
    let group = bind_and_arm(&pool, caller).await;
    let (other_agent, _) = fixture::seed_agent_with_group(&pool, "evolve-applied-other").await;

    let step = fixture::seed_group_claim(&pool, caller, group, "E2: weigh the sample").await;
    let parent = fixture::seed_group_claim(&pool, caller, group, "the E-arm").await;
    let child = fixture::seed_group_claim(&pool, caller, group, "E2.1 tare").await;
    let workflow = seed_workflow(&pool).await;

    let decomposed_from = seed_edge(&pool, parent, "claim", step, "decomposes_to").await;
    let to_child = seed_edge(&pool, step, "claim", child, "decomposes_to").await;
    let executes = seed_edge(&pool, workflow, "workflow", step, "executes").await;
    let asserted = seed_edge(&pool, other_agent, "agent", step, "asserts").await;

    let body = evolve(&server, params(step, "supersedes", "E2 v2")).await;
    let head = parse_uuid_field(&body, "claim_id");
    assert_eq!(
        body["cascade"]["status"], "applied",
        "a configured maintenance session applies the cascade in the request: {body}"
    );
    assert_eq!(
        ends(&pool, decomposed_from).await,
        (parent, head),
        "parent -decomposes_to-> head, with no replay"
    );
    assert_eq!(ends(&pool, to_child).await, (head, child));
    assert_eq!(
        ends(&pool, executes).await,
        (workflow, step),
        "executes stays on the frozen step"
    );
    assert_eq!(
        ends(&pool, asserted).await,
        (other_agent, step),
        "another agent's asserts stays on the content it asserted"
    );
    let deferrals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'cascade.deferred'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(deferrals, 0, "an applied cascade records no deferral");
}

/// A workflow's `step_follows` chain links the FROZEN steps its `executes`
/// edges name (`workflow_steps::ordered_steps` walks the chain inside that id
/// set), so a step-lineage supersession must leave the chain where it is.
///
/// The chain order differs from plan order on purpose: X was added
/// (an unindexed `add_step` insert, so plan order puts it last) between the
/// planned S1 and S2. If the cascade re-pointed `S1 -> X` and `X -> S2` onto
/// X's successor, the walk would stop at S1 and fall back to plan order,
/// reporting [S1, S2, X]; and a later `add_step` at that slot would find no
/// `prev -> next` row to remove and fork the chain.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_keeps_the_workflow_step_chain_on_the_frozen_steps(pool: PgPool) {
    let (server, caller) = app_role_server_with_maintenance(&pool, 0xC7).await;
    let group = bind_and_arm(&pool, caller).await;
    let workflow = seed_workflow(&pool).await;

    let s1 = fixture::seed_group_claim(&pool, caller, group, "S1: planned first").await;
    let s2 = fixture::seed_group_claim(&pool, caller, group, "S2: planned second").await;
    let x = fixture::seed_group_claim(&pool, caller, group, "X: added between").await;
    sqlx::query(
        "UPDATE claims SET properties = COALESCE(properties, '{}'::jsonb) || '{\"level\": 2}' \
          WHERE id = ANY($1)",
    )
    .bind(vec![s1, s2, x])
    .execute(&pool)
    .await
    .expect("mark the three claims level-2 steps");
    for (step, plan) in [(s1, Some(1)), (s2, Some(2)), (x, None)] {
        let props = match plan {
            Some(i) => serde_json::json!({ "plan_index": i }),
            None => serde_json::json!({}),
        };
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, \
                                relationship, properties) \
             VALUES (gen_random_uuid(), $1, 'workflow', $2, 'claim', 'executes', $3)",
        )
        .bind(workflow)
        .bind(step)
        .bind(props)
        .execute(&pool)
        .await
        .expect("seed executes");
    }
    let s1_to_x = seed_edge(&pool, s1, "claim", x, "step_follows").await;
    let x_to_s2 = seed_edge(&pool, x, "claim", s2, "step_follows").await;
    let ordered = |pool: PgPool| async move {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::workflow_steps::ordered_steps(&mut conn, workflow)
            .await
            .expect("ordered_steps")
    };
    assert_eq!(
        ordered(pool.clone()).await,
        vec![s1, x, s2],
        "fixture: the chain, not plan order, places X second"
    );

    let body = evolve(&server, params(x, "supersedes", "X v2: added, refined")).await;
    assert_eq!(body["cascade"]["status"], "applied", "{body}");
    let head = parse_uuid_field(&body, "claim_id");

    assert_eq!(
        ends(&pool, s1_to_x).await,
        (s1, x),
        "S1 -step_follows-> X stays on the frozen step"
    );
    assert_eq!(
        ends(&pool, x_to_s2).await,
        (x, s2),
        "X -step_follows-> S2 stays on the frozen step"
    );
    let on_head: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE relationship = 'step_follows' \
           AND (source_id = $1 OR target_id = $1)",
    )
    .bind(head)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(on_head, 0, "no step_follows edge reaches the successor");
    assert_eq!(
        ordered(pool.clone()).await,
        vec![s1, x, s2],
        "the workflow's step order survives the evolution"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_revises_runs_no_cascade(pool: PgPool) {
    let (server, caller) = app_role_server(&pool, 0xC5).await;
    let group = bind_and_arm(&pool, caller).await;
    let step = fixture::seed_group_claim(&pool, caller, group, "a step to branch").await;
    let parent = fixture::seed_group_claim(&pool, caller, group, "its parent").await;
    let decomposed_from = seed_edge(&pool, parent, "claim", step, "decomposes_to").await;

    let body = evolve(&server, params(step, "revises", "a parallel branch")).await;
    assert!(
        body.get("cascade").is_none(),
        "a revises branch supersedes nothing: {body}"
    );
    let deferrals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'cascade.deferred'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(deferrals, 0);
    assert_eq!(ends(&pool, decomposed_from).await, (parent, step));
}
