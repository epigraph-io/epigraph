//! `add_step`'s mid-chain `step_follows` rewire and `delete_step`'s soft
//! delete, driven through the MCP tools on the APPLICATION ROLE.
//!
//! # Why
//!
//! Under row security an UPDATE or DELETE whose USING clause refuses a row
//! matches ZERO rows and reports success. The rewire deletes `prev -> next`
//! and inserts `prev -> step` and `step -> next`; if the DELETE matched
//! nothing, the two INSERTs still landed and `prev` then had two successors: a
//! FORKED chain, which `ordered_steps` walks down one branch of (`LIMIT 1`),
//! appending the other as an orphan. The tools stamp their transaction as the
//! `workflow-ingest-system` agent, so a chain edge that agent may not delete
//! -- a legacy workflow whose steps are world-owned public claims, which no
//! session writes -- is exactly that case. `delete_step`'s `UPDATE claims SET
//! truth_value` has the same shape: on a step claim the stamp cannot write, it
//! changed nothing and reported the new truth value.
//!
//! Both pools of the server are downgraded to `epigraph_app` (see
//! `writer_owned_attach_app_role.rs` for why a superuser pool proves nothing
//! here); the fixture is seeded on the superuser pool.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::step_ops::{AddStepParams, DeleteStepParams};
use sqlx::PgPool;
use uuid::Uuid;

/// A server whose every connection is the application role.
/// The stdio viewer of `server`'s own agent: what a stdio `#[tool]` body
/// resolves (`request_viewer(self, None)`), and the principal `add_step` /
/// `delete_step` author as with no token (batch H-b).
async fn stdio_viewer(server: &EpiGraphMcpFull) -> epigraph_db::visibility::Viewer {
    epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("the server agent's stdio viewer")
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

/// A level-`level` public claim owned by `owner`, with a step lineage.
async fn step_claim(pool: &PgPool, owner: Uuid, level: i32, content: &str) -> (Uuid, Uuid) {
    let id = Uuid::new_v4();
    let lineage = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, labels, properties, step_lineage_id) \
         VALUES ($1, $2, $3, 0.99, (SELECT id FROM agents ORDER BY created_at LIMIT 1), true, \
                 'public', $4, ARRAY['claim','workflow_step'], $5, $6)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(owner)
    .bind(serde_json::json!({"level": level, "kind": "workflow_step"}))
    .bind(lineage)
    .execute(pool)
    .await
    .expect("step claim");
    (id, lineage)
}

async fn edge(
    pool: &PgPool,
    source: Uuid,
    source_type: &str,
    target: Uuid,
    rel: &str,
    props: serde_json::Value,
) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES (gen_random_uuid(), $1, $2, $3, 'claim', $4, $5)",
    )
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(rel)
    .bind(props)
    .execute(pool)
    .await
    .expect("edge");
}

struct Legacy {
    name: String,
    steps: Vec<(Uuid, Uuid)>,
}

/// A LEGACY hierarchical workflow: its phase and its three steps are public
/// claims owned by the WORLD group (the shape pre-tenancy rows were
/// backfilled to), chained `s0 -> s1 -> s2` by world-owned `step_follows`
/// edges. No application session writes the world group, so none may delete
/// those edges (migration 120: owner or co-owner only; 115's source-writer arm
/// is gone).
async fn legacy_workflow(pool: &PgPool) -> Legacy {
    fixture::seed_agent_with_group(pool, "legacy-author").await;
    let world = fixture::world_group(pool).await;
    let name = format!("legacy-wf-{}", Uuid::new_v4());
    let wf = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, metadata) \
         VALUES ($1, $2, 0, 'a legacy goal', '{}'::jsonb)",
    )
    .bind(wf)
    .bind(&name)
    .execute(pool)
    .await
    .expect("workflow");
    let (phase, _) = step_claim(pool, world, 1, &format!("{name} phase")).await;
    edge(
        pool,
        wf,
        "workflow",
        phase,
        "executes",
        serde_json::json!({"plan_index": 0}),
    )
    .await;
    let mut steps = Vec::new();
    for i in 0..3 {
        let s = step_claim(pool, world, 2, &format!("{name} step {i}")).await;
        edge(
            pool,
            wf,
            "workflow",
            s.0,
            "executes",
            serde_json::json!({"plan_index": i + 1}),
        )
        .await;
        edge(
            pool,
            phase,
            "claim",
            s.0,
            "decomposes_to",
            serde_json::json!({}),
        )
        .await;
        steps.push(s);
    }
    for w in steps.windows(2) {
        edge(
            pool,
            w[0].0,
            "claim",
            w[1].0,
            "step_follows",
            serde_json::json!({}),
        )
        .await;
    }
    let owners: Vec<Uuid> = sqlx::query_scalar(
        "SELECT owner_group_id FROM edges WHERE relationship = 'step_follows' AND source_id = ANY($1)",
    )
    .bind(steps.iter().map(|s| s.0).collect::<Vec<_>>())
    .fetch_all(pool)
    .await
    .expect("chain owners");
    assert_eq!(
        owners,
        vec![world, world],
        "fixture shape: world-owned chain edges"
    );
    Legacy { name, steps }
}

/// Every in-force `step_follows` edge out of `source`.
async fn successors(pool: &PgPool, source: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT target_id FROM edges WHERE source_id = $1 AND relationship = 'step_follows' \
           AND valid_to IS NULL ORDER BY target_id",
    )
    .bind(source)
    .fetch_all(pool)
    .await
    .expect("successors")
}

async fn step_count(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE content LIKE $1 || '%' OR content = 'inserted mid-chain'",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("count")
}

/// A mid-chain insert whose `prev -> next` edge the stamped session may not
/// delete is REFUSED, with nothing written: no fork, no orphan step claim.
#[sqlx::test(migrations = "../../migrations")]
async fn a_mid_chain_add_step_never_forks_the_chain(pool: PgPool) {
    let wf = legacy_workflow(&pool).await;
    let server = app_role_server(&pool).await;
    let (s0, s1) = (wf.steps[0].0, wf.steps[1].0);
    let before = step_count(&pool, &wf.name).await;

    let r = epigraph_mcp::tools::step_ops::add_step(
        &server,
        &stdio_viewer(&server).await,
        AddStepParams {
            canonical_name: wf.name.clone(),
            step_text: "inserted mid-chain".to_string(),
            position: Some(1),
        },
        None,
    )
    .await;

    assert_eq!(
        successors(&pool, s0).await,
        vec![s1],
        "s0 keeps exactly one successor, s1: the chain did not fork (result: {r:?})"
    );
    let e = r.expect_err("a rewire that cannot remove prev -> next is refused");
    assert!(
        e.message.contains("step_follows"),
        "the refusal names the chain edge: {e:?}"
    );
    assert_eq!(
        step_count(&pool, &wf.name).await,
        before,
        "nothing was written: no step claim left outside the chain"
    );
}

/// Appending (no DELETE) still works on the same legacy workflow, and a
/// mid-chain insert into a chain the system agent wrote itself (the ordinary
/// shape: `add_step` twice) rewires cleanly.
#[sqlx::test(migrations = "../../migrations")]
async fn add_step_appends_and_rewires_a_chain_the_system_agent_wrote(pool: PgPool) {
    let wf = legacy_workflow(&pool).await;
    let server = app_role_server(&pool).await;
    let s2 = wf.steps[2].0;
    let add = |text: &'static str, position: Option<u32>| {
        let server = &server;
        let name = wf.name.clone();
        async move {
            first_text(
                &epigraph_mcp::tools::step_ops::add_step(
                    server,
                    &stdio_viewer(server).await,
                    AddStepParams {
                        canonical_name: name,
                        step_text: text.to_string(),
                        position,
                    },
                    None,
                )
                .await
                .unwrap_or_else(|e| panic!("add_step {text}: {e:?}")),
            )
        }
    };
    let a = parse_uuid_field(&add("appended a", None).await, "step_claim_id");
    let b = parse_uuid_field(&add("appended b", None).await, "step_claim_id");
    assert_eq!(successors(&pool, s2).await, vec![a]);
    assert_eq!(successors(&pool, a).await, vec![b]);
    // The a -> b link carries an edge-keyed BBA (seeded privileged), so the
    // rewire's DELETE withdraws an edge factor: migration 120's cleanup must
    // close the row's window and record the `edge_retract` deferral (the
    // definer admits only an edge out of force) before the DELETE, in the act.
    let ab: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND target_id = $2 \
            AND relationship = 'step_follows'",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .expect("a -> b");
    sqlx::query("INSERT INTO perspectives (id, name, perspective_type) VALUES ($1, $2, 'edge')")
        .bind(ab)
        .bind(format!("w12b step edge {ab}"))
        .execute(&pool)
        .await
        .expect("edge-factor perspective");
    let frame = epigraph_db::FrameRepository::create(
        &pool,
        "binary_truth",
        Some("w12b"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id;
    let mut conn = pool.acquire().await.expect("conn");
    epigraph_db::MassFunctionRepository::store_with_perspective(
        &mut *conn,
        b,
        frame,
        None,
        Some(ab),
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("test"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("an edge-keyed BBA on the chain link");
    drop(conn);

    // Between a and b: both are the system agent's claims, so it may delete
    // a -> b and the insert lands.
    let mid = parse_uuid_field(&add("between a and b", Some(4)).await, "step_claim_id");
    assert_eq!(
        successors(&pool, a).await,
        vec![mid],
        "a -> mid, and a -> b is gone"
    );
    assert_eq!(successors(&pool, mid).await, vec![b]);
    let gone: bool = sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM edges WHERE id = $1)")
        .bind(ab)
        .fetch_one(&pool)
        .await
        .expect("a -> b row");
    assert!(gone, "the rewire deleted the a -> b row");
    let deferred: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type = 'cascade.deferred' AND details->>'cause' = 'edge_retract' \
            AND details->'trigger'->>'subject_id' = $1::text",
    )
    .bind(ab)
    .fetch_one(&pool)
    .await
    .expect("deferrals");
    assert_eq!(
        deferred, 1,
        "the deleted link's edge-keyed BBA cleanup was deferred in the act"
    );
}

/// `delete_step` on a step claim the stamped session may not write is
/// REFUSED; it used to report `truth_value: 0.05` while the claim kept its
/// value.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_step_on_a_claim_it_cannot_write_is_refused(pool: PgPool) {
    let wf = legacy_workflow(&pool).await;
    let server = app_role_server(&pool).await;
    let (s1, lineage) = wf.steps[1];

    let r = epigraph_mcp::tools::step_ops::delete_step(
        &server,
        &stdio_viewer(&server).await,
        DeleteStepParams {
            canonical_name: wf.name.clone(),
            step_lineage_id: lineage.to_string(),
        },
        None,
    )
    .await;
    let truth: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(s1)
        .fetch_one(&pool)
        .await
        .expect("truth");
    assert!(
        (truth - 0.99).abs() < 1e-9,
        "the world-owned step keeps its truth value (result: {r:?})"
    );
    let e = r.expect_err("a soft delete that changed nothing is refused");
    assert!(
        e.message.contains("not changed") || e.message.contains("cannot"),
        "the refusal says the step was not soft-deleted: {e:?}"
    );
}

/// Migration 120: the rewire's refusal probe counts a RETRACTED `prev -> next`
/// too, because `ordered_steps` follows retracted `step_follows` rows (`LIMIT
/// 1`, no `valid_to` filter). A legacy chain whose only `s0 -> s1` link is
/// retracted (and world-owned, so no session may delete it) still refuses a
/// mid-chain insert, with nothing written and the order unchanged.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_prev_to_next_alone_also_refuses_the_rewire(pool: PgPool) {
    let wf = legacy_workflow(&pool).await;
    let (s0, s1, s2) = (wf.steps[0].0, wf.steps[1].0, wf.steps[2].0);
    let retracted = sqlx::query(
        "UPDATE edges SET valid_to = now() - interval '1 hour' \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'step_follows'",
    )
    .bind(s0)
    .bind(s1)
    .execute(&pool)
    .await
    .expect("retract s0 -> s1 (privileged)")
    .rows_affected();
    assert_eq!(retracted, 1, "fixture shape");
    let workflow_id: Uuid =
        sqlx::query_scalar("SELECT id FROM workflows WHERE canonical_name = $1")
            .bind(&wf.name)
            .fetch_one(&pool)
            .await
            .expect("workflow id");
    let order = || async {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::workflow_steps::ordered_steps(&mut conn, workflow_id)
            .await
            .expect("ordered_steps")
    };
    assert_eq!(
        order().await,
        vec![s0, s1, s2],
        "calibration: the walk follows the retracted link"
    );
    let before = step_count(&pool, &wf.name).await;
    let server = app_role_server(&pool).await;

    let r = epigraph_mcp::tools::step_ops::add_step(
        &server,
        &stdio_viewer(&server).await,
        AddStepParams {
            canonical_name: wf.name.clone(),
            step_text: "inserted mid-chain".to_string(),
            position: Some(1),
        },
        None,
    )
    .await;
    let e = r.expect_err("a retracted prev -> next the session cannot remove is refused");
    assert!(e.message.contains("step_follows"), "{e:?}");
    let all_out: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'step_follows'",
    )
    .bind(s0)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(
        all_out, 1,
        "exactly one step_follows out of s0, retracted or not"
    );
    assert_eq!(step_count(&pool, &wf.name).await, before, "nothing written");
    assert_eq!(order().await, vec![s0, s1, s2], "the order is unchanged");
}

/// Operator default W12-OD2: `add_step` writes under the shared
/// `workflow-ingest-system` principal, so after migration 120 its chain edges
/// between two step claims (`step_follows`, `decomposes_to`) are owned by THAT
/// agent's writer group, whichever MCP caller asked, and `executes` (workflow
/// -> claim) is a structural edge outside D8's scope, so world-owned. Two
/// servers with different signing agents therefore share the chain: the second
/// rewires the first's links. The caller's AUTHORITY over the workflow is the
/// app-layer check the per-caller identity batch adds, which is not in this
/// branch's base; this pins the database half only.
#[sqlx::test(migrations = "../../migrations")]
async fn two_callers_chain_edges_share_the_workflow_ingest_owner(pool: PgPool) {
    let wf = legacy_workflow(&pool).await;
    let s2 = wf.steps[2].0;
    let url = fixture::database_url_for(&pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let first = build_scoped_test_server(plain.clone(), scoped.clone());
    let second = build_scoped_test_server_generated_signer(plain, scoped);
    let first_agent = first.server_agent_id().await.expect("agent");
    let second_agent = second.server_agent_id().await.expect("agent");
    assert_ne!(first_agent, second_agent, "two different callers");

    async fn add(server: &EpiGraphMcpFull, name: &str, text: &str, position: Option<u32>) -> Uuid {
        let r = epigraph_mcp::tools::step_ops::add_step(
            server,
            &stdio_viewer(server).await,
            AddStepParams {
                canonical_name: name.to_string(),
                step_text: text.to_string(),
                position,
            },
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("add_step {text}: {e:?}"));
        parse_uuid_field(&first_text(&r), "step_claim_id")
    }
    let a = add(&first, &wf.name, "by the first caller", None).await;
    let b = add(&second, &wf.name, "by the second caller", None).await;

    let system: Uuid =
        sqlx::query_scalar("SELECT id FROM agents WHERE display_name = 'workflow-ingest-system'")
            .fetch_one(&pool)
            .await
            .expect("the workflow-ingest-system agent");
    let shared = personal_group_of(&pool, system).await;
    let world = fixture::world_group(&pool).await;
    let owners: Vec<(String, Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT relationship, owner_group_id, writer_group_id FROM edges \
          WHERE target_id = ANY($1) ORDER BY relationship, target_id",
    )
    .bind(vec![a, b])
    .fetch_all(&pool)
    .await
    .expect("the new edges");
    assert!(!owners.is_empty());
    for (rel, owner, writer) in &owners {
        assert_eq!(
            *writer,
            Some(shared),
            "{rel}: the author record is the shared agent's"
        );
        let want = if rel == "executes" { world } else { shared };
        assert_eq!(*owner, want, "{rel}: {owners:?}");
    }
    for g in [
        personal_group_of(&pool, first_agent).await,
        personal_group_of(&pool, second_agent).await,
    ] {
        assert!(
            owners.iter().all(|(_, o, _)| *o != g),
            "no caller's own group owns a chain edge"
        );
    }
    assert_eq!(successors(&pool, s2).await, vec![a]);

    // The accepted residual: the second caller rewires the first caller's link.
    let mid = add(&second, &wf.name, "between the two callers", Some(4)).await;
    assert_eq!(
        successors(&pool, a).await,
        vec![mid],
        "a -> mid, a -> b gone"
    );
    assert_eq!(successors(&pool, mid).await, vec![b]);
}
